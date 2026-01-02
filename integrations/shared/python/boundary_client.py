"""
Shared Boundary Daemon Client for Python Integrations

This is the base client that all Python integrations should use.
It provides fail-closed semantics, automatic retry, and token management.
"""

import json
import logging
import os
import socket
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar('T')


class BoundaryMode(Enum):
    """Boundary security modes."""
    OPEN = "open"
    RESTRICTED = "restricted"
    TRUSTED = "trusted"
    AIRGAP = "airgap"
    COLDROOM = "coldroom"
    LOCKDOWN = "lockdown"


class MemoryClass(Enum):
    """Memory classification levels."""
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3
    TOP_SECRET = 4
    CROWN_JEWEL = 5


@dataclass
class BoundaryStatus:
    """Current boundary daemon status."""
    mode: BoundaryMode
    online: bool
    network_state: str
    hardware_trust: str
    lockdown_active: bool
    tripwire_count: int
    uptime_seconds: float

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BoundaryStatus':
        return cls(
            mode=BoundaryMode(data.get('mode', 'lockdown').lower()),
            online=data.get('online', False),
            network_state=data.get('network_state', 'unknown'),
            hardware_trust=data.get('hardware_trust', 'low'),
            lockdown_active=data.get('lockdown_active', True),
            tripwire_count=data.get('tripwire_count', 0),
            uptime_seconds=data.get('uptime_seconds', 0),
        )


@dataclass
class PolicyDecision:
    """Result of a policy check."""
    permitted: bool
    reason: str
    mode: Optional[BoundaryMode] = None
    requires_ceremony: bool = False


class BoundaryDaemonError(Exception):
    """Base exception for boundary daemon errors."""
    pass


class DaemonUnavailableError(BoundaryDaemonError):
    """Raised when daemon is not reachable."""
    pass


class AuthenticationError(BoundaryDaemonError):
    """Raised when authentication fails."""
    pass


class PolicyDeniedError(BoundaryDaemonError):
    """Raised when policy denies an operation."""
    pass


def get_socket_path() -> str:
    """
    Get the boundary daemon socket path.

    Checks in order:
    1. BOUNDARY_DAEMON_SOCKET environment variable
    2. /var/run/boundary-daemon/boundary.sock (production)
    3. ~/.agent-os/api/boundary.sock (user mode)
    4. ./api/boundary.sock (development)
    """
    # Environment variable takes precedence
    env_path = os.environ.get('BOUNDARY_DAEMON_SOCKET')
    if env_path and os.path.exists(env_path):
        return env_path

    # Production path
    prod_path = '/var/run/boundary-daemon/boundary.sock'
    if os.path.exists(prod_path):
        return prod_path

    # User mode path
    user_path = os.path.expanduser('~/.agent-os/api/boundary.sock')
    if os.path.exists(user_path):
        return user_path

    # Development path
    dev_path = './api/boundary.sock'
    if os.path.exists(dev_path):
        return dev_path

    # Default to production path even if not exists (will fail with clear error)
    return prod_path


class BoundaryClient:
    """
    Universal Boundary Daemon Client.

    Provides fail-closed access to boundary daemon with automatic retry,
    token management, and comprehensive error handling.
    """

    def __init__(
        self,
        socket_path: Optional[str] = None,
        token: Optional[str] = None,
        token_file: Optional[str] = None,
        max_retries: int = 3,
        retry_delay: float = 0.5,
        timeout: float = 5.0,
        fail_closed: bool = True,
    ):
        """
        Initialize boundary client.

        Args:
            socket_path: Path to Unix socket (auto-detected if None)
            token: API token for authentication
            token_file: Path to file containing API token
            max_retries: Maximum retry attempts on connection failure
            retry_delay: Initial delay between retries (exponential backoff)
            timeout: Socket timeout in seconds
            fail_closed: If True, deny operations when daemon unavailable
        """
        self.socket_path = socket_path or get_socket_path()
        self._token = self._resolve_token(token, token_file)
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout = timeout
        self.fail_closed = fail_closed
        self._status_cache: Optional[Tuple[BoundaryStatus, float]] = None
        self._cache_ttl = 1.0  # Cache status for 1 second

    def _resolve_token(
        self,
        token: Optional[str],
        token_file: Optional[str],
    ) -> Optional[str]:
        """Resolve token from various sources."""
        if token:
            return token.strip()

        if token_file:
            try:
                with open(token_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            return line
            except (IOError, OSError) as e:
                logger.warning(f"Could not read token file: {e}")

        # Try environment variable
        env_token = os.environ.get('BOUNDARY_API_TOKEN')
        if env_token:
            return env_token.strip()

        return None

    def _send_request(
        self,
        command: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send request with retry logic."""
        request = {
            'command': command,
            'params': params or {},
        }
        if self._token:
            request['token'] = self._token

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                return self._send_once(request)
            except (ConnectionRefusedError, FileNotFoundError, socket.timeout) as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    delay = self.retry_delay * (2 ** attempt)
                    logger.debug(f"Retry {attempt + 1}/{self.max_retries} after {delay}s: {e}")
                    time.sleep(delay)

        # All retries failed
        if self.fail_closed:
            raise DaemonUnavailableError(
                f"Boundary daemon unavailable after {self.max_retries} attempts: {last_error}"
            )
        return {'success': False, 'error': str(last_error)}

    def _send_once(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send a single request."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
            sock.sendall(json.dumps(request).encode('utf-8'))
            data = sock.recv(65536)
            return json.loads(data.decode('utf-8'))
        finally:
            sock.close()

    def get_status(self, use_cache: bool = True) -> BoundaryStatus:
        """
        Get current daemon status.

        Args:
            use_cache: If True, return cached status if fresh

        Returns:
            Current boundary status
        """
        if use_cache and self._status_cache:
            status, timestamp = self._status_cache
            if time.time() - timestamp < self._cache_ttl:
                return status

        response = self._send_request('status')
        if not response.get('success'):
            if self.fail_closed:
                # Return locked down status
                return BoundaryStatus(
                    mode=BoundaryMode.LOCKDOWN,
                    online=False,
                    network_state='unknown',
                    hardware_trust='low',
                    lockdown_active=True,
                    tripwire_count=0,
                    uptime_seconds=0,
                )
            raise BoundaryDaemonError(response.get('error', 'Unknown error'))

        status = BoundaryStatus.from_dict(response.get('status', {}))
        self._status_cache = (status, time.time())
        return status

    def get_mode(self) -> BoundaryMode:
        """Get current boundary mode."""
        return self.get_status().mode

    def is_available(self) -> bool:
        """Check if daemon is available."""
        try:
            self.get_status(use_cache=False)
            return True
        except BoundaryDaemonError:
            return False

    def check_recall(
        self,
        memory_class: int,
        memory_id: Optional[str] = None,
    ) -> PolicyDecision:
        """
        Check if memory recall is permitted.

        Args:
            memory_class: Memory classification level (0-5)
            memory_id: Optional memory identifier for logging

        Returns:
            Policy decision with permit/deny and reason
        """
        params = {'memory_class': memory_class}
        if memory_id:
            params['memory_id'] = memory_id

        try:
            response = self._send_request('check_recall', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Boundary daemon unavailable - fail closed",
            )

        if response.get('auth_error'):
            raise AuthenticationError(response.get('error', 'Authentication failed'))

        return PolicyDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def check_tool(
        self,
        tool_name: str,
        requires_network: bool = False,
        requires_filesystem: bool = False,
        requires_usb: bool = False,
    ) -> PolicyDecision:
        """
        Check if tool execution is permitted.

        Args:
            tool_name: Name of the tool
            requires_network: Tool needs network access
            requires_filesystem: Tool needs filesystem access
            requires_usb: Tool needs USB access

        Returns:
            Policy decision with permit/deny and reason
        """
        params = {
            'tool_name': tool_name,
            'requires_network': requires_network,
            'requires_filesystem': requires_filesystem,
            'requires_usb': requires_usb,
        }

        try:
            response = self._send_request('check_tool', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Boundary daemon unavailable - fail closed",
            )

        return PolicyDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def check_message(
        self,
        content: str,
        source: str = 'unknown',
        context: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Check message content for policy compliance.

        Args:
            content: Message content to check
            source: Source system identifier
            context: Additional context

        Returns:
            Policy decision
        """
        params = {'content': content, 'source': source}
        if context:
            params['context'] = context

        try:
            response = self._send_request('check_message', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Boundary daemon unavailable - fail closed",
            )

        return PolicyDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def check_natlangchain(
        self,
        author: str,
        intent: str,
        timestamp: str,
        signature: Optional[str] = None,
        previous_hash: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Check a NatLangChain blockchain entry.

        Args:
            author: Entry author
            intent: Intent description (prose)
            timestamp: Entry timestamp (ISO format)
            signature: Cryptographic signature
            previous_hash: Hash of previous entry
            metadata: Additional metadata

        Returns:
            Policy decision
        """
        params = {
            'author': author,
            'intent': intent,
            'timestamp': timestamp,
        }
        if signature:
            params['signature'] = signature
        if previous_hash:
            params['previous_hash'] = previous_hash
        if metadata:
            params['metadata'] = metadata

        try:
            response = self._send_request('check_natlangchain', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Boundary daemon unavailable - fail closed",
            )

        return PolicyDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def check_agentos(
        self,
        sender_agent: str,
        recipient_agent: str,
        content: str,
        message_type: str = 'request',
        authority_level: int = 0,
        timestamp: Optional[str] = None,
        requires_consent: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Check an Agent-OS inter-agent message.

        Args:
            sender_agent: Sending agent identifier
            recipient_agent: Receiving agent identifier
            content: Message content
            message_type: Type of message
            authority_level: Authority level (0-5)
            timestamp: Message timestamp
            requires_consent: Whether consent is required
            metadata: Additional metadata

        Returns:
            Policy decision
        """
        params = {
            'sender_agent': sender_agent,
            'recipient_agent': recipient_agent,
            'content': content,
            'message_type': message_type,
            'authority_level': authority_level,
            'requires_consent': requires_consent,
        }
        if timestamp:
            params['timestamp'] = timestamp
        if metadata:
            params['metadata'] = metadata

        try:
            response = self._send_request('check_agentos', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Boundary daemon unavailable - fail closed",
            )

        return PolicyDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def set_mode(
        self,
        mode: BoundaryMode,
        operator: str = 'human',
        reason: str = '',
    ) -> Tuple[bool, str]:
        """
        Request mode change.

        Args:
            mode: Target boundary mode
            operator: Who is requesting (human|system)
            reason: Reason for change

        Returns:
            (success, message)
        """
        params = {
            'mode': mode.value,
            'operator': operator,
            'reason': reason,
        }
        response = self._send_request('set_mode', params)
        return (
            response.get('success', False),
            response.get('message', response.get('error', '')),
        )

    def verify_log(self) -> Tuple[bool, Optional[str]]:
        """
        Verify event log integrity.

        Returns:
            (is_valid, error_message)
        """
        response = self._send_request('verify_log')
        return (
            response.get('valid', False),
            response.get('error'),
        )

    # =========================================================================
    # ADVANCED GATES (v2.0)
    # =========================================================================

    def verify_merkle_proof(
        self,
        root_hash: str,
        leaf_hash: str,
        proof_path: List[str],
        leaf_index: int,
    ) -> PolicyDecision:
        """
        Verify a Merkle tree proof for tamper detection.

        Args:
            root_hash: Expected Merkle root
            leaf_hash: Hash of the leaf being verified
            proof_path: List of sibling hashes from leaf to root
            leaf_index: Index of the leaf in the tree

        Returns:
            PolicyDecision with verification result
        """
        params = {
            'root_hash': root_hash,
            'leaf_hash': leaf_hash,
            'proof_path': proof_path,
            'leaf_index': leaf_index,
        }
        try:
            response = self._send_request('verify_merkle_proof', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Daemon unavailable - cannot verify proof",
            )
        return PolicyDecision(
            permitted=response.get('valid', False),
            reason=response.get('reason', 'Unknown'),
        )

    def verify_cryptographic_signature(
        self,
        algorithm: str,
        message_hash: str,
        signature: str,
        public_key: str,
        require_hardware: bool = False,
    ) -> PolicyDecision:
        """
        Verify a cryptographic signature using daemon's HSM/TPM.

        Args:
            algorithm: Signature algorithm (ed25519, ecdsa-p256, rsa-pss, bls12-381)
            message_hash: Hash of the signed message
            signature: The signature to verify
            public_key: Public key for verification
            require_hardware: If True, requires TPM-bound key

        Returns:
            PolicyDecision with verification result
        """
        params = {
            'algorithm': algorithm,
            'message_hash': message_hash,
            'signature': signature,
            'public_key': public_key,
            'require_hardware': require_hardware,
        }
        try:
            response = self._send_request('verify_cryptographic_signature', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Daemon unavailable - cannot verify signature",
            )
        return PolicyDecision(
            permitted=response.get('valid', False),
            reason=response.get('reason', 'Unknown'),
        )

    def classify_intent_semantics(
        self,
        text: str,
        context: Optional[str] = None,
        author_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Classify text intent for policy decisions.

        Args:
            text: Text to classify
            context: Optional context (e.g., 'workplace', 'personal')
            author_id: Optional author identifier

        Returns:
            Classification result with threat_level, category, scores
        """
        params = {'text': text}
        if context:
            params['context'] = context
        if author_id:
            params['author_id'] = author_id

        try:
            response = self._send_request('classify_intent_semantics', params)
        except DaemonUnavailableError:
            return {
                'threat_level': 5,  # Fail-closed: assume highest threat
                'category': 'unknown',
                'manipulation_score': 1.0,
                'permitted': False,
                'reason': 'Daemon unavailable',
            }
        return response.get('classification', {})

    def check_reflection_intensity(
        self,
        intensity_level: int,
        reflection_type: str = 'meta',
        depth: int = 1,
        duration_seconds: int = 0,
    ) -> PolicyDecision:
        """
        Check if reflection intensity is permitted in current mode.

        Args:
            intensity_level: Intensity level (0-5)
            reflection_type: Type of reflection (meta, self, world)
            depth: Recursion depth
            duration_seconds: Expected duration

        Returns:
            PolicyDecision with mode-aware limits
        """
        params = {
            'intensity_level': intensity_level,
            'reflection_type': reflection_type,
            'depth': depth,
            'duration_seconds': duration_seconds,
        }
        try:
            response = self._send_request('check_reflection_intensity', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Daemon unavailable - reflection denied",
            )
        return PolicyDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
            requires_ceremony=response.get('requires_ceremony', False),
        )

    def check_agent_attestation(
        self,
        agent_id: str,
        capability: str,
        attestation_token: Optional[str] = None,
        peer_agent_id: Optional[str] = None,
    ) -> PolicyDecision:
        """
        Verify agent capability attestation for multi-agent operations.

        Args:
            agent_id: Agent requesting capability
            capability: Capability being requested (reflect, recall, communicate)
            attestation_token: Cryptographic attestation token
            peer_agent_id: For federation, the peer agent

        Returns:
            PolicyDecision with attestation result
        """
        params = {
            'agent_id': agent_id,
            'capability': capability,
        }
        if attestation_token:
            params['attestation_token'] = attestation_token
        if peer_agent_id:
            params['peer_agent_id'] = peer_agent_id

        try:
            response = self._send_request('check_agent_attestation', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Daemon unavailable - attestation failed",
            )
        return PolicyDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def verify_contract_signature(
        self,
        contract_id: str,
        contract_hash: str,
        issuer_signature: str,
        issuer_public_key: str,
    ) -> PolicyDecision:
        """
        Verify learning contract hasn't been tampered.

        Args:
            contract_id: Contract identifier
            contract_hash: Hash of contract content
            issuer_signature: Issuer's signature
            issuer_public_key: Issuer's public key

        Returns:
            PolicyDecision with verification result
        """
        params = {
            'contract_id': contract_id,
            'contract_hash': contract_hash,
            'issuer_signature': issuer_signature,
            'issuer_public_key': issuer_public_key,
        }
        try:
            response = self._send_request('verify_contract_signature', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Daemon unavailable - contract unverified",
            )
        return PolicyDecision(
            permitted=response.get('valid', False),
            reason=response.get('reason', 'Unknown'),
        )

    def verify_memory_not_revoked(
        self,
        memory_id: str,
        revocation_list_hash: Optional[str] = None,
    ) -> PolicyDecision:
        """
        Check memory against revocation list before allowing recall.

        Args:
            memory_id: Memory to check
            revocation_list_hash: Specific list version to check against

        Returns:
            PolicyDecision (permitted=True means NOT revoked)
        """
        params = {'memory_id': memory_id}
        if revocation_list_hash:
            params['revocation_list_hash'] = revocation_list_hash

        try:
            response = self._send_request('verify_memory_not_revoked', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Daemon unavailable - assuming revoked",
            )
        return PolicyDecision(
            permitted=response.get('not_revoked', False),
            reason=response.get('reason', 'Unknown'),
        )

    def verify_execution_confidence(
        self,
        intent_id: str,
        model_confidence: float,
        threshold: float = 0.95,
        model_id: Optional[str] = None,
    ) -> PolicyDecision:
        """
        Verify execution confidence meets threshold (Finite-Intent-Executor).

        Args:
            intent_id: Intent being executed
            model_confidence: Model's confidence score (0-1)
            threshold: Required threshold (default 0.95)
            model_id: Model providing the confidence

        Returns:
            PolicyDecision with confidence validation
        """
        params = {
            'intent_id': intent_id,
            'model_confidence': model_confidence,
            'threshold': threshold,
        }
        if model_id:
            params['model_id'] = model_id

        try:
            response = self._send_request('verify_execution_confidence', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Daemon unavailable - confidence unverified",
            )
        return PolicyDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def detect_political_activity(
        self,
        intended_action: str,
        beneficiaries: Optional[List[str]] = None,
        check_depth: str = 'comprehensive',
    ) -> Dict[str, Any]:
        """
        Detect political activity in intended actions (hard-coded prohibition).

        Args:
            intended_action: Description of intended action
            beneficiaries: List of beneficiary identifiers
            check_depth: 'basic' or 'comprehensive'

        Returns:
            Detection result with is_political, indicators, confidence
        """
        params = {
            'intended_action': intended_action,
            'check_depth': check_depth,
        }
        if beneficiaries:
            params['beneficiaries'] = beneficiaries

        try:
            response = self._send_request('detect_political_activity', params)
        except DaemonUnavailableError:
            return {
                'is_political': True,  # Fail-closed: assume political
                'confidence': 0.0,
                'reason': 'Daemon unavailable',
            }
        return response

    def verify_llm_consensus(
        self,
        entry_hash: str,
        model_signatures: List[Dict[str, str]],
        agreement_threshold: float = 0.67,
    ) -> PolicyDecision:
        """
        Validate multi-model agreement on intent interpretation.

        Args:
            entry_hash: Hash of the entry being validated
            model_signatures: List of {model, interpretation_hash, signature}
            agreement_threshold: Required agreement ratio (default 2/3)

        Returns:
            PolicyDecision with consensus validation
        """
        params = {
            'entry_hash': entry_hash,
            'model_signatures': model_signatures,
            'agreement_threshold': agreement_threshold,
        }
        try:
            response = self._send_request('verify_llm_consensus', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Daemon unavailable - consensus unverified",
            )
        return PolicyDecision(
            permitted=response.get('consensus_reached', False),
            reason=response.get('reason', 'Unknown'),
        )

    def verify_stake_burned(
        self,
        burn_tx_hash: str,
        chain: str,
        amount: float,
        burn_address: str,
    ) -> PolicyDecision:
        """
        Cryptographic proof that stake was burned on-chain.

        Args:
            burn_tx_hash: Transaction hash of the burn
            chain: Blockchain (ethereum, polygon, etc.)
            amount: Expected burn amount
            burn_address: Expected burn address

        Returns:
            PolicyDecision with burn verification
        """
        params = {
            'burn_tx_hash': burn_tx_hash,
            'chain': chain,
            'amount': amount,
            'burn_address': burn_address,
        }
        try:
            response = self._send_request('verify_stake_burned', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Daemon unavailable - burn unverified",
            )
        return PolicyDecision(
            permitted=response.get('verified', False),
            reason=response.get('reason', 'Unknown'),
        )

    def check_entity_rate_limit(
        self,
        entity_id: str,
        entity_type: str,
        operation: str,
        window_seconds: int = 86400,
        max_operations: int = 100,
    ) -> PolicyDecision:
        """
        Check per-entity operation rate limit.

        Args:
            entity_id: Entity identifier
            entity_type: Type (agent, mediator, user)
            operation: Operation being performed
            window_seconds: Rate limit window
            max_operations: Maximum operations in window

        Returns:
            PolicyDecision with rate limit status
        """
        params = {
            'entity_id': entity_id,
            'entity_type': entity_type,
            'operation': operation,
            'window_seconds': window_seconds,
            'max_operations': max_operations,
        }
        try:
            response = self._send_request('check_entity_rate_limit', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Daemon unavailable - rate limit check failed",
            )
        return PolicyDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def verify_memory_consent(
        self,
        memory_id: str,
        consent_token: str,
        consent_signature: str,
        consenter_public_key: str,
    ) -> PolicyDecision:
        """
        Verify human consent was obtained for memory access.

        Args:
            memory_id: Memory being accessed
            consent_token: Consent token
            consent_signature: Cryptographic signature
            consenter_public_key: Public key of consenter

        Returns:
            PolicyDecision with consent verification
        """
        params = {
            'memory_id': memory_id,
            'consent_token': consent_token,
            'consent_signature': consent_signature,
            'consenter_public_key': consenter_public_key,
        }
        try:
            response = self._send_request('verify_memory_consent', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Daemon unavailable - consent unverified",
            )
        return PolicyDecision(
            permitted=response.get('valid', False),
            reason=response.get('reason', 'Unknown'),
        )

    def check_dispute_class_mode_requirement(
        self,
        dispute_class: int,
    ) -> PolicyDecision:
        """
        Check if current mode allows processing this dispute class.

        Args:
            dispute_class: Dispute classification (0-5)

        Returns:
            PolicyDecision with mode-aware authorization
        """
        params = {'dispute_class': dispute_class}
        try:
            response = self._send_request('check_dispute_class_mode_requirement', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Daemon unavailable - dispute check failed",
            )
        return PolicyDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
            mode=BoundaryMode(response['current_mode']) if 'current_mode' in response else None,
        )

    def get_graduated_permission(
        self,
        operation: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Get mode-aware graduated permissions instead of binary allow/deny.

        Args:
            operation: Operation type
            params: Operation parameters

        Returns:
            Graduated permissions for all modes and current permission
        """
        request_params = {
            'operation': operation,
            'params': params or {},
        }
        try:
            response = self._send_request('get_graduated_permission', request_params)
        except DaemonUnavailableError:
            # Fail-closed: return most restrictive permissions
            return {
                'current_mode': 'LOCKDOWN',
                'current_permission': {'permitted': False, 'reason': 'Daemon unavailable'},
            }
        return response


# Decorators for easy integration

def require_boundary_check(
    operation_type: str = 'tool',
    **check_kwargs,
) -> Callable:
    """
    Decorator that requires boundary check before execution.

    Args:
        operation_type: 'tool', 'recall', or 'message'
        **check_kwargs: Arguments passed to the check function
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args, **kwargs) -> T:
            client = BoundaryClient()

            if operation_type == 'tool':
                decision = client.check_tool(
                    tool_name=func.__name__,
                    **check_kwargs,
                )
            elif operation_type == 'recall':
                decision = client.check_recall(**check_kwargs)
            elif operation_type == 'message':
                decision = client.check_message(**check_kwargs)
            else:
                raise ValueError(f"Unknown operation type: {operation_type}")

            if not decision.permitted:
                raise PolicyDeniedError(
                    f"Operation '{func.__name__}' denied: {decision.reason}"
                )

            return func(*args, **kwargs)
        return wrapper
    return decorator


def boundary_protected(
    requires_network: bool = False,
    requires_filesystem: bool = False,
    requires_usb: bool = False,
    memory_class: Optional[int] = None,
) -> Callable:
    """
    Decorator that enforces boundary policies on a function.

    Args:
        requires_network: Function needs network access
        requires_filesystem: Function needs filesystem access
        requires_usb: Function needs USB access
        memory_class: If set, check recall permission for this class
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args, **kwargs) -> T:
            client = BoundaryClient()

            # Check tool permissions
            tool_decision = client.check_tool(
                tool_name=func.__name__,
                requires_network=requires_network,
                requires_filesystem=requires_filesystem,
                requires_usb=requires_usb,
            )
            if not tool_decision.permitted:
                raise PolicyDeniedError(
                    f"Tool '{func.__name__}' denied: {tool_decision.reason}"
                )

            # Check memory permissions if specified
            if memory_class is not None:
                recall_decision = client.check_recall(memory_class=memory_class)
                if not recall_decision.permitted:
                    raise PolicyDeniedError(
                        f"Memory access denied: {recall_decision.reason}"
                    )

            return func(*args, **kwargs)
        return wrapper
    return decorator


# Context manager for boundary-aware operations

class BoundaryContext:
    """
    Context manager for boundary-aware operations.

    Usage:
        with BoundaryContext(requires_network=True) as ctx:
            if ctx.permitted:
                do_network_operation()
            else:
                handle_denial(ctx.reason)
    """

    def __init__(
        self,
        tool_name: str = 'context_operation',
        requires_network: bool = False,
        requires_filesystem: bool = False,
        requires_usb: bool = False,
        memory_class: Optional[int] = None,
        raise_on_deny: bool = False,
    ):
        self.tool_name = tool_name
        self.requires_network = requires_network
        self.requires_filesystem = requires_filesystem
        self.requires_usb = requires_usb
        self.memory_class = memory_class
        self.raise_on_deny = raise_on_deny
        self.client = BoundaryClient()
        self.permitted = False
        self.reason = ""
        self.mode: Optional[BoundaryMode] = None

    def __enter__(self) -> 'BoundaryContext':
        # Get current mode
        try:
            status = self.client.get_status()
            self.mode = status.mode
        except BoundaryDaemonError as e:
            self.permitted = False
            self.reason = str(e)
            if self.raise_on_deny:
                raise PolicyDeniedError(self.reason)
            return self

        # Check tool permission
        decision = self.client.check_tool(
            tool_name=self.tool_name,
            requires_network=self.requires_network,
            requires_filesystem=self.requires_filesystem,
            requires_usb=self.requires_usb,
        )

        if not decision.permitted:
            self.permitted = False
            self.reason = decision.reason
            if self.raise_on_deny:
                raise PolicyDeniedError(self.reason)
            return self

        # Check memory permission if specified
        if self.memory_class is not None:
            recall_decision = self.client.check_recall(memory_class=self.memory_class)
            if not recall_decision.permitted:
                self.permitted = False
                self.reason = recall_decision.reason
                if self.raise_on_deny:
                    raise PolicyDeniedError(self.reason)
                return self

        self.permitted = True
        self.reason = "Operation permitted"
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Log operation completion if needed
        pass
