"""
RPC Endpoint Protection - Hardening for blockchain JSON-RPC interfaces.

Protects blockchain node RPC endpoints from:
1. Unauthorized access to sensitive methods
2. Resource exhaustion attacks (rate limiting)
3. Information disclosure
4. Method abuse and manipulation
5. MEV extraction attempts

SECURITY: This module acts as a security layer between external clients
and the node's RPC interface. It should be deployed as a reverse proxy
or integrated into the node's request handling.

Supports:
- Ethereum JSON-RPC (eth_*, debug_*, admin_*, personal_*, etc.)
- Tendermint/CometBFT RPC
- Cosmos SDK RPC
- Generic JSON-RPC 2.0
"""

import hashlib
import json
import logging
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class RPCRiskLevel(Enum):
    """Risk classification for RPC methods."""
    SAFE = "safe"           # Read-only, public data
    LOW = "low"             # Read-only, potentially sensitive
    MEDIUM = "medium"       # State-changing but limited impact
    HIGH = "high"           # Significant state changes or sensitive data
    CRITICAL = "critical"   # Administrative, key access, or dangerous
    BLOCKED = "blocked"     # Never allowed, even with auth


class AuthLevel(Enum):
    """Authentication levels for RPC access."""
    NONE = "none"           # No authentication required
    API_KEY = "api_key"     # Simple API key
    SIGNED = "signed"       # Cryptographically signed request
    LOCAL = "local"         # Local connections only (localhost)
    ADMIN = "admin"         # Full administrative access


@dataclass
class RPCMethodPolicy:
    """Policy for a specific RPC method."""
    name: str
    risk_level: RPCRiskLevel
    required_auth: AuthLevel = AuthLevel.NONE
    rate_limit_per_minute: int = 60
    log_calls: bool = False
    param_validators: List[Callable] = field(default_factory=list)


@dataclass
class RPCRequest:
    """Parsed RPC request."""
    method: str
    params: Any
    id: Any
    client_ip: str
    auth_token: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    raw_request: Optional[bytes] = None


@dataclass
class RPCResponse:
    """RPC protection response."""
    allowed: bool
    reason: str = ""
    modified_request: Optional[RPCRequest] = None
    should_log: bool = False
    rate_limit_remaining: int = -1


# Ethereum sensitive methods that require protection
ETHEREUM_DANGEROUS_METHODS = {
    # Administrative - BLOCKED
    'admin_addPeer': RPCRiskLevel.BLOCKED,
    'admin_removePeer': RPCRiskLevel.BLOCKED,
    'admin_datadir': RPCRiskLevel.BLOCKED,
    'admin_nodeInfo': RPCRiskLevel.CRITICAL,
    'admin_startRPC': RPCRiskLevel.BLOCKED,
    'admin_stopRPC': RPCRiskLevel.BLOCKED,
    'admin_startWS': RPCRiskLevel.BLOCKED,
    'admin_stopWS': RPCRiskLevel.BLOCKED,

    # Personal/Wallet - CRITICAL (key access)
    'personal_unlockAccount': RPCRiskLevel.CRITICAL,
    'personal_newAccount': RPCRiskLevel.CRITICAL,
    'personal_sendTransaction': RPCRiskLevel.CRITICAL,
    'personal_sign': RPCRiskLevel.CRITICAL,
    'personal_importRawKey': RPCRiskLevel.BLOCKED,
    'personal_listAccounts': RPCRiskLevel.HIGH,

    # Debug - HIGH/BLOCKED
    'debug_traceTransaction': RPCRiskLevel.HIGH,
    'debug_traceBlock': RPCRiskLevel.HIGH,
    'debug_setHead': RPCRiskLevel.BLOCKED,
    'debug_gcStats': RPCRiskLevel.MEDIUM,
    'debug_memStats': RPCRiskLevel.MEDIUM,
    'debug_dumpBlock': RPCRiskLevel.HIGH,
    'debug_seedHash': RPCRiskLevel.MEDIUM,

    # Miner - CRITICAL
    'miner_start': RPCRiskLevel.CRITICAL,
    'miner_stop': RPCRiskLevel.CRITICAL,
    'miner_setEtherbase': RPCRiskLevel.CRITICAL,
    'miner_setGasPrice': RPCRiskLevel.HIGH,

    # Transaction pool - MEV sensitive
    'txpool_content': RPCRiskLevel.HIGH,
    'txpool_inspect': RPCRiskLevel.HIGH,
    'txpool_status': RPCRiskLevel.MEDIUM,

    # Potentially dangerous reads
    'eth_getCode': RPCRiskLevel.LOW,
    'eth_getStorageAt': RPCRiskLevel.LOW,
    'eth_sign': RPCRiskLevel.HIGH,
    'eth_signTransaction': RPCRiskLevel.CRITICAL,
    'eth_sendRawTransaction': RPCRiskLevel.MEDIUM,
}

# Tendermint/CometBFT sensitive methods
TENDERMINT_DANGEROUS_METHODS = {
    'unsafe_flush_mempool': RPCRiskLevel.BLOCKED,
    'dial_seeds': RPCRiskLevel.CRITICAL,
    'dial_peers': RPCRiskLevel.CRITICAL,
    'broadcast_tx_commit': RPCRiskLevel.MEDIUM,
    'broadcast_tx_sync': RPCRiskLevel.MEDIUM,
    'broadcast_tx_async': RPCRiskLevel.MEDIUM,
    'validators': RPCRiskLevel.LOW,
    'dump_consensus_state': RPCRiskLevel.HIGH,
    'consensus_state': RPCRiskLevel.MEDIUM,
    'consensus_params': RPCRiskLevel.LOW,
}


class RPCFirewall:
    """
    Firewall for blockchain RPC endpoints.

    Provides defense-in-depth protection for JSON-RPC interfaces
    commonly exposed by blockchain nodes.

    Features:
    1. Method whitelisting/blacklisting with risk classification
    2. Per-client rate limiting
    3. Authentication enforcement for sensitive methods
    4. MEV protection (txpool method restrictions)
    5. Parameter validation
    6. Comprehensive audit logging
    """

    # Rate limit window
    RATE_LIMIT_WINDOW = 60  # seconds

    # Maximum request history per client
    MAX_CLIENT_HISTORY = 1000

    def __init__(
        self,
        chain_type: str = "ethereum",
        default_rate_limit: int = 100,
        allow_by_default: bool = False,
        event_logger=None,
    ):
        """
        Initialize RPC firewall.

        Args:
            chain_type: Type of chain ("ethereum", "tendermint", "generic")
            default_rate_limit: Default requests per minute per client
            allow_by_default: If True, allow unknown methods (dangerous!)
            event_logger: Optional event logger for audit trail
        """
        self.chain_type = chain_type
        self.default_rate_limit = default_rate_limit
        self.allow_by_default = allow_by_default
        self._event_logger = event_logger
        self._lock = threading.RLock()

        # Method policies
        self._policies: Dict[str, RPCMethodPolicy] = {}

        # Rate limiting state: client_ip -> deque of timestamps
        self._client_requests: Dict[str, deque] = {}

        # Blocked clients (temporary bans)
        self._blocked_clients: Dict[str, float] = {}

        # Whitelisted IPs (bypass most checks)
        self._whitelisted_ips: Set[str] = {"127.0.0.1", "::1"}

        # API keys: key -> AuthLevel
        self._api_keys: Dict[str, AuthLevel] = {}

        # Statistics
        self._stats = {
            'total_requests': 0,
            'allowed': 0,
            'denied': 0,
            'rate_limited': 0,
            'blocked_methods': 0,
        }

        # Initialize policies based on chain type
        self._init_policies()

        logger.info(f"RPCFirewall initialized for {chain_type} - allow_by_default={allow_by_default}")

    def _init_policies(self) -> None:
        """Initialize method policies based on chain type."""
        dangerous_methods = {}

        if self.chain_type == "ethereum":
            dangerous_methods = ETHEREUM_DANGEROUS_METHODS
        elif self.chain_type in ("tendermint", "cosmos"):
            dangerous_methods = TENDERMINT_DANGEROUS_METHODS

        # Create policies from dangerous method definitions
        for method, risk in dangerous_methods.items():
            auth = AuthLevel.NONE
            rate_limit = self.default_rate_limit
            log_calls = False

            if risk == RPCRiskLevel.BLOCKED:
                auth = AuthLevel.ADMIN  # Will still be blocked
                rate_limit = 0
                log_calls = True
            elif risk == RPCRiskLevel.CRITICAL:
                auth = AuthLevel.ADMIN
                rate_limit = 10
                log_calls = True
            elif risk == RPCRiskLevel.HIGH:
                auth = AuthLevel.SIGNED
                rate_limit = 30
                log_calls = True
            elif risk == RPCRiskLevel.MEDIUM:
                auth = AuthLevel.API_KEY
                rate_limit = 60

            self._policies[method] = RPCMethodPolicy(
                name=method,
                risk_level=risk,
                required_auth=auth,
                rate_limit_per_minute=rate_limit,
                log_calls=log_calls,
            )

    def add_policy(self, policy: RPCMethodPolicy) -> None:
        """Add or update a method policy."""
        with self._lock:
            self._policies[policy.name] = policy

    def add_api_key(self, key: str, level: AuthLevel) -> None:
        """Register an API key with a specific auth level."""
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        self._api_keys[key_hash] = level

    def whitelist_ip(self, ip: str) -> None:
        """Add IP to whitelist (trusted local services)."""
        with self._lock:
            self._whitelisted_ips.add(ip)

    def block_client(self, ip: str, duration: float = 300.0) -> None:
        """Temporarily block a client IP."""
        with self._lock:
            self._blocked_clients[ip] = time.time() + duration
            logger.warning(f"Blocked client {ip} for {duration}s")

    def check_request(self, request: RPCRequest) -> RPCResponse:
        """
        Check if an RPC request should be allowed.

        Args:
            request: The parsed RPC request

        Returns:
            RPCResponse indicating whether request is allowed
        """
        with self._lock:
            self._stats['total_requests'] += 1

            # Check for blocked client
            if request.client_ip in self._blocked_clients:
                if time.time() < self._blocked_clients[request.client_ip]:
                    self._stats['denied'] += 1
                    return RPCResponse(
                        allowed=False,
                        reason="Client temporarily blocked",
                        should_log=True,
                    )
                else:
                    del self._blocked_clients[request.client_ip]

            # Whitelisted IPs get through most checks
            is_whitelisted = request.client_ip in self._whitelisted_ips

            # Get method policy
            policy = self._policies.get(request.method)

            # Check if method is blocked
            if policy and policy.risk_level == RPCRiskLevel.BLOCKED:
                self._stats['blocked_methods'] += 1
                self._stats['denied'] += 1
                self._log_event("rpc_blocked_method", {
                    'method': request.method,
                    'client_ip': request.client_ip,
                })
                return RPCResponse(
                    allowed=False,
                    reason=f"Method {request.method} is blocked",
                    should_log=True,
                )

            # Unknown method handling
            if not policy and not self.allow_by_default:
                # Check if it matches safe patterns
                if self._is_safe_method(request.method):
                    pass  # Allow safe methods
                else:
                    self._stats['denied'] += 1
                    return RPCResponse(
                        allowed=False,
                        reason=f"Unknown method {request.method} not allowed",
                    )

            # Rate limiting (unless whitelisted)
            if not is_whitelisted:
                rate_limit = policy.rate_limit_per_minute if policy else self.default_rate_limit
                remaining = self._check_rate_limit(request.client_ip, rate_limit)

                if remaining <= 0:
                    self._stats['rate_limited'] += 1
                    self._stats['denied'] += 1
                    return RPCResponse(
                        allowed=False,
                        reason="Rate limit exceeded",
                        rate_limit_remaining=0,
                    )

            # Authentication check
            if policy and policy.required_auth != AuthLevel.NONE:
                if not self._check_auth(request, policy.required_auth, is_whitelisted):
                    self._stats['denied'] += 1
                    return RPCResponse(
                        allowed=False,
                        reason=f"Method {request.method} requires {policy.required_auth.value} authentication",
                        should_log=True,
                    )

            # Parameter validation
            if policy and policy.param_validators:
                for validator in policy.param_validators:
                    try:
                        if not validator(request.params):
                            self._stats['denied'] += 1
                            return RPCResponse(
                                allowed=False,
                                reason="Parameter validation failed",
                            )
                    except Exception as e:
                        logger.error(f"Validator error: {e}")
                        self._stats['denied'] += 1
                        return RPCResponse(
                            allowed=False,
                            reason="Parameter validation error",
                        )

            # Request allowed
            self._stats['allowed'] += 1

            should_log = policy.log_calls if policy else False
            if should_log:
                self._log_event("rpc_sensitive_call", {
                    'method': request.method,
                    'client_ip': request.client_ip,
                    'risk_level': policy.risk_level.value if policy else 'unknown',
                })

            remaining = self._get_rate_limit_remaining(
                request.client_ip,
                policy.rate_limit_per_minute if policy else self.default_rate_limit
            )

            return RPCResponse(
                allowed=True,
                reason="Request allowed",
                should_log=should_log,
                rate_limit_remaining=remaining,
            )

    def _is_safe_method(self, method: str) -> bool:
        """Check if a method is considered safe by pattern matching."""
        safe_patterns = [
            r'^eth_blockNumber$',
            r'^eth_chainId$',
            r'^eth_gasPrice$',
            r'^eth_getBalance$',
            r'^eth_getBlockBy(Hash|Number)$',
            r'^eth_getTransactionBy(Hash|BlockHashAndIndex|BlockNumberAndIndex)$',
            r'^eth_getTransactionReceipt$',
            r'^eth_call$',
            r'^eth_estimateGas$',
            r'^eth_getLogs$',
            r'^eth_getBlockTransactionCountBy(Hash|Number)$',
            r'^net_version$',
            r'^net_listening$',
            r'^net_peerCount$',
            r'^web3_clientVersion$',
            r'^web3_sha3$',
            # Tendermint safe methods
            r'^status$',
            r'^health$',
            r'^block$',
            r'^block_results$',
            r'^blockchain$',
            r'^commit$',
            r'^tx$',
            r'^tx_search$',
            r'^abci_info$',
            r'^abci_query$',
        ]

        for pattern in safe_patterns:
            if re.match(pattern, method):
                return True
        return False

    def _check_rate_limit(self, client_ip: str, limit: int) -> int:
        """
        Check and update rate limit for client.

        Returns remaining requests in window, -1 if unlimited.
        """
        if limit <= 0:
            return 0  # No requests allowed

        now = time.time()
        window_start = now - self.RATE_LIMIT_WINDOW

        if client_ip not in self._client_requests:
            self._client_requests[client_ip] = deque(maxlen=self.MAX_CLIENT_HISTORY)

        requests = self._client_requests[client_ip]

        # Remove old requests outside window
        while requests and requests[0] < window_start:
            requests.popleft()

        if len(requests) >= limit:
            return 0

        requests.append(now)
        return limit - len(requests)

    def _get_rate_limit_remaining(self, client_ip: str, limit: int) -> int:
        """Get remaining requests without updating counter."""
        if client_ip not in self._client_requests:
            return limit

        now = time.time()
        window_start = now - self.RATE_LIMIT_WINDOW
        requests = self._client_requests[client_ip]

        count = sum(1 for t in requests if t >= window_start)
        return max(0, limit - count)

    def _check_auth(self, request: RPCRequest, required: AuthLevel, is_whitelisted: bool) -> bool:
        """Check if request has required authentication."""
        if required == AuthLevel.NONE:
            return True

        if required == AuthLevel.LOCAL:
            return is_whitelisted

        if not request.auth_token:
            return False

        token_hash = hashlib.sha256(request.auth_token.encode()).hexdigest()
        token_level = self._api_keys.get(token_hash)

        if not token_level:
            return False

        # Check if token has sufficient access
        level_order = [AuthLevel.NONE, AuthLevel.API_KEY, AuthLevel.SIGNED, AuthLevel.LOCAL, AuthLevel.ADMIN]
        return level_order.index(token_level) >= level_order.index(required)

    def _log_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Log a security event."""
        if self._event_logger:
            try:
                self._event_logger.log_security_event(
                    event_type=f"rpc_{event_type}",
                    severity="warning" if "blocked" in event_type else "info",
                    details=details,
                )
            except Exception as e:
                logger.error(f"Failed to log event: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get firewall statistics."""
        with self._lock:
            return {
                **self._stats,
                'active_clients': len(self._client_requests),
                'blocked_clients': len(self._blocked_clients),
                'policies_loaded': len(self._policies),
            }

    def cleanup(self) -> None:
        """Clean up expired rate limit entries and block list."""
        with self._lock:
            now = time.time()
            window_start = now - self.RATE_LIMIT_WINDOW

            # Clean rate limit history
            empty_clients = []
            for client_ip, requests in self._client_requests.items():
                while requests and requests[0] < window_start:
                    requests.popleft()
                if not requests:
                    empty_clients.append(client_ip)

            for client_ip in empty_clients:
                del self._client_requests[client_ip]

            # Clean expired blocks
            expired = [ip for ip, exp in self._blocked_clients.items() if exp <= now]
            for ip in expired:
                del self._blocked_clients[ip]


class MEVProtector:
    """
    MEV (Maximal Extractable Value) attack protection.

    Protects against:
    - Sandwich attacks (front-running + back-running)
    - Transaction reordering
    - Mempool snooping
    - Private transaction leakage
    """

    def __init__(self, rpc_firewall: RPCFirewall):
        """Initialize MEV protector with RPC firewall."""
        self.firewall = rpc_firewall
        self._lock = threading.Lock()

        # Track pending transactions per sender
        self._pending_txs: Dict[str, deque] = {}

        # Configure MEV-sensitive method restrictions
        self._configure_mev_protection()

        logger.info("MEVProtector initialized")

    def _configure_mev_protection(self) -> None:
        """Configure strict policies for MEV-sensitive methods."""
        mev_methods = [
            # Txpool methods reveal pending transactions
            RPCMethodPolicy(
                name='txpool_content',
                risk_level=RPCRiskLevel.CRITICAL,
                required_auth=AuthLevel.LOCAL,
                rate_limit_per_minute=5,
                log_calls=True,
            ),
            RPCMethodPolicy(
                name='txpool_inspect',
                risk_level=RPCRiskLevel.HIGH,
                required_auth=AuthLevel.LOCAL,
                rate_limit_per_minute=10,
                log_calls=True,
            ),
            # eth_sendRawTransaction tracking
            RPCMethodPolicy(
                name='eth_sendRawTransaction',
                risk_level=RPCRiskLevel.MEDIUM,
                required_auth=AuthLevel.API_KEY,
                rate_limit_per_minute=30,
                log_calls=True,
            ),
        ]

        for policy in mev_methods:
            self.firewall.add_policy(policy)

    def check_sandwich_attack(
        self,
        sender: str,
        tx_hash: str,
        gas_price: int,
        block_number: int
    ) -> bool:
        """
        Check for potential sandwich attack patterns.

        Returns True if attack detected.
        """
        with self._lock:
            if sender not in self._pending_txs:
                self._pending_txs[sender] = deque(maxlen=100)

            pending = self._pending_txs[sender]

            # Look for suspicious patterns
            # (simplified - real implementation would analyze gas prices and timing)
            recent_same_block = [
                tx for tx in pending
                if tx['block'] == block_number
            ]

            if len(recent_same_block) >= 2:
                # Multiple transactions in same block could indicate sandwich
                gas_prices = [tx['gas_price'] for tx in recent_same_block]
                if gas_price > max(gas_prices) * 1.1:
                    # Significantly higher gas price transaction after others
                    logger.warning(f"Potential sandwich attack detected for sender {sender[:16]}...")
                    return True

            pending.append({
                'hash': tx_hash,
                'gas_price': gas_price,
                'block': block_number,
                'time': time.time(),
            })

            return False


# Convenience function
def create_rpc_firewall(
    chain_type: str = "ethereum",
    strict_mode: bool = True,
) -> RPCFirewall:
    """
    Create an RPC firewall with recommended settings.

    Args:
        chain_type: Type of blockchain ("ethereum", "tendermint", "cosmos")
        strict_mode: If True, block unknown methods (recommended)

    Returns:
        Configured RPCFirewall
    """
    return RPCFirewall(
        chain_type=chain_type,
        default_rate_limit=100,
        allow_by_default=not strict_mode,
    )


if __name__ == "__main__":
    print("RPC Firewall - Blockchain Endpoint Protection")
    print("=" * 60)

    # Create test firewall
    firewall = create_rpc_firewall("ethereum", strict_mode=True)

    # Test safe method
    safe_req = RPCRequest(
        method="eth_blockNumber",
        params=[],
        id=1,
        client_ip="192.168.1.100",
    )
    result = firewall.check_request(safe_req)
    print(f"eth_blockNumber: allowed={result.allowed}")

    # Test dangerous method
    danger_req = RPCRequest(
        method="personal_unlockAccount",
        params=["0x...", "password", 300],
        id=2,
        client_ip="192.168.1.100",
    )
    result = firewall.check_request(danger_req)
    print(f"personal_unlockAccount: allowed={result.allowed}, reason={result.reason}")

    # Test blocked method
    blocked_req = RPCRequest(
        method="admin_addPeer",
        params=["enode://..."],
        id=3,
        client_ip="192.168.1.100",
    )
    result = firewall.check_request(blocked_req)
    print(f"admin_addPeer: allowed={result.allowed}, reason={result.reason}")

    print(f"\nStats: {firewall.get_stats()}")
