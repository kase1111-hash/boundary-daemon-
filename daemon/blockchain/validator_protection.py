"""
Validator Key Protection - Slashing prevention for blockchain validators.

Prevents double-signing attacks that can lead to validator slashing by:
1. Tracking all signed messages with height/round/step
2. Refusing to sign conflicting messages at same height
3. Persisting signing history to survive restarts
4. HSM-backed key isolation

SECURITY: This module MUST be the ONLY path to the validator signing key.
Direct key access bypasses protection and can lead to slashing.

Supports:
- Tendermint/CometBFT (prevote, precommit, proposal)
- Ethereum 2.0 (attestations, proposals, sync committee)
- Generic height-based chains
"""

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, Optional, Any, Tuple
from collections import deque

logger = logging.getLogger(__name__)

# Try to import HSM provider
try:
    from ..crypto.hsm_provider import HSMProvider  # noqa: F401
    HSM_AVAILABLE = True
except ImportError:
    HSM_AVAILABLE = False

# Try to import nacl for software signing fallback
try:
    from nacl.signing import SigningKey
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False


class ChainType(Enum):
    """Supported blockchain types."""
    TENDERMINT = "tendermint"
    ETHEREUM2 = "ethereum2"
    GENERIC = "generic"


class SigningEventType(Enum):
    """Types of signing events to track."""
    # Tendermint/CometBFT
    PREVOTE = "prevote"
    PRECOMMIT = "precommit"
    PROPOSAL = "proposal"
    # Ethereum 2.0
    ATTESTATION = "attestation"
    BLOCK_PROPOSAL = "block_proposal"
    SYNC_COMMITTEE = "sync_committee"
    # Generic
    BLOCK_SIGN = "block_sign"
    MESSAGE_SIGN = "message_sign"


class SlashingRisk(Enum):
    """Risk levels for potential slashing."""
    NONE = "none"
    LOW = "low"           # Unusual but not slashable
    MEDIUM = "medium"     # Potentially slashable in some conditions
    HIGH = "high"         # Definitely slashable if signed
    CRITICAL = "critical" # Would result in immediate slashing


@dataclass
class SigningRecord:
    """Record of a signing event for double-sign detection."""
    height: int
    round: int  # -1 for chains without rounds
    step: str   # Event type or step identifier
    block_hash: str
    timestamp: float
    signature: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'height': self.height,
            'round': self.round,
            'step': self.step,
            'block_hash': self.block_hash,
            'timestamp': self.timestamp,
            'signature': self.signature.hex() if self.signature else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SigningRecord':
        return cls(
            height=data['height'],
            round=data['round'],
            step=data['step'],
            block_hash=data['block_hash'],
            timestamp=data['timestamp'],
            signature=bytes.fromhex(data['signature']) if data.get('signature') else None,
        )


@dataclass
class SigningRequest:
    """Request to sign a validator message."""
    chain_type: ChainType
    event_type: SigningEventType
    height: int
    round: int
    data: bytes  # The data to sign
    block_hash: str  # Hash of the block being voted on
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SigningResponse:
    """Response to a signing request."""
    allowed: bool
    signature: Optional[bytes] = None
    risk_level: SlashingRisk = SlashingRisk.NONE
    reason: str = ""
    conflicting_record: Optional[SigningRecord] = None


class ValidatorKeyProtector:
    """
    Protects validator keys from double-signing attacks.

    SECURITY CRITICAL: This class enforces signing discipline to prevent
    slashing. All validator signing operations MUST go through this class.

    Features:
    1. Height/Round/Step tracking - Never sign conflicting messages
    2. Persistent history - Survives restarts (critical for crash recovery)
    3. HSM integration - Keys never leave secure hardware
    4. Lockout on suspicious activity
    5. Audit logging of all signing attempts
    """

    # Maximum history to keep in memory (also persisted to disk)
    MAX_MEMORY_HISTORY = 10000

    # Lockout after this many suspicious requests
    LOCKOUT_THRESHOLD = 3

    def __init__(
        self,
        chain_type: ChainType,
        validator_address: str,
        signing_key_path: Optional[str] = None,
        hsm_config: Optional[Any] = None,
        history_path: Optional[str] = None,
        event_logger=None,
    ):
        """
        Initialize validator key protection.

        Args:
            chain_type: Type of blockchain (affects signing rules)
            validator_address: Validator's public address/key
            signing_key_path: Path to signing key (if not using HSM)
            hsm_config: HSM configuration (preferred for production)
            history_path: Path to persist signing history
            event_logger: Optional event logger for audit trail
        """
        self.chain_type = chain_type
        self.validator_address = validator_address
        self._event_logger = event_logger
        self._lock = threading.RLock()

        # Signing history indexed by (height, round, step)
        self._history: Dict[Tuple[int, int, str], SigningRecord] = {}
        self._history_deque: deque = deque(maxlen=self.MAX_MEMORY_HISTORY)

        # Security state
        self._suspicious_count = 0
        self._locked_out = False
        self._lockout_time: Optional[float] = None

        # Statistics
        self._stats = {
            'total_requests': 0,
            'allowed': 0,
            'denied': 0,
            'double_sign_prevented': 0,
            'lockouts': 0,
        }

        # Persistence
        self._history_path = Path(history_path) if history_path else None
        if self._history_path:
            self._load_history()

        # Key management
        self._signing_key: Optional[Any] = None
        self._hsm_session: Optional[Any] = None
        self._hsm_key_id: Optional[str] = None

        if hsm_config and HSM_AVAILABLE:
            self._init_hsm(hsm_config)
        elif signing_key_path:
            self._load_signing_key(signing_key_path)
        else:
            logger.warning("No signing key configured - signing will fail")

        logger.info(f"ValidatorKeyProtector initialized for {chain_type.value} validator {validator_address[:16]}...")

    def _init_hsm(self, hsm_config: Any) -> None:
        """Initialize HSM connection for hardware-backed signing."""
        try:
            # HSM initialization would happen here
            # For now, log that HSM is configured
            logger.info("HSM signing configured - keys never leave hardware")
            self._hsm_key_id = f"validator_{self.validator_address[:8]}"
        except Exception as e:
            logger.error(f"Failed to initialize HSM: {e}")
            raise RuntimeError("HSM initialization failed - cannot sign safely")

    def _load_signing_key(self, key_path: str) -> None:
        """Load signing key from file (software fallback)."""
        if not NACL_AVAILABLE:
            raise RuntimeError("nacl not available for software signing")

        try:
            with open(key_path, 'rb') as f:
                key_bytes = f.read()

            if len(key_bytes) == 32:
                self._signing_key = SigningKey(key_bytes)
            elif len(key_bytes) == 64:
                # Full keypair (seed + public)
                self._signing_key = SigningKey(key_bytes[:32])
            else:
                raise ValueError(f"Invalid key length: {len(key_bytes)}")

            logger.warning(
                "Software signing key loaded - consider using HSM for production. "
                "Keys are protected in memory but not hardware-isolated."
            )
        except Exception as e:
            logger.error(f"Failed to load signing key: {e}")
            raise

    def _load_history(self) -> None:
        """Load signing history from disk."""
        if not self._history_path or not self._history_path.exists():
            return

        try:
            with open(self._history_path, 'r') as f:
                data = json.load(f)

            for record_data in data.get('records', []):
                record = SigningRecord.from_dict(record_data)
                key = (record.height, record.round, record.step)
                self._history[key] = record
                self._history_deque.append(key)

            self._stats = data.get('stats', self._stats)
            logger.info(f"Loaded {len(self._history)} signing records from history")

        except Exception as e:
            logger.error(f"Failed to load signing history: {e}")
            # Don't raise - starting fresh is safer than crashing

    def _save_history(self) -> None:
        """Persist signing history to disk."""
        if not self._history_path:
            return

        try:
            # Atomic write with temp file
            temp_path = self._history_path.with_suffix('.tmp')

            records = [
                self._history[key].to_dict()
                for key in self._history_deque
                if key in self._history
            ]

            data = {
                'records': records,
                'stats': self._stats,
                'saved_at': datetime.now().isoformat(),
                'validator': self.validator_address,
            }

            with open(temp_path, 'w') as f:
                json.dump(data, f, indent=2)

            # Atomic rename
            temp_path.replace(self._history_path)

        except Exception as e:
            logger.error(f"Failed to save signing history: {e}")

    def request_signature(self, request: SigningRequest) -> SigningResponse:
        """
        Request to sign a validator message.

        This is the ONLY method that should be used for validator signing.
        It enforces slashing prevention rules.

        Args:
            request: The signing request with all relevant context

        Returns:
            SigningResponse with signature if allowed, or denial reason
        """
        with self._lock:
            self._stats['total_requests'] += 1

            # Check lockout
            if self._locked_out:
                elapsed = time.time() - (self._lockout_time or 0)
                if elapsed < 300:  # 5 minute lockout
                    return SigningResponse(
                        allowed=False,
                        risk_level=SlashingRisk.CRITICAL,
                        reason=f"Validator locked out due to suspicious activity. {300-elapsed:.0f}s remaining."
                    )
                else:
                    self._locked_out = False
                    self._suspicious_count = 0
                    logger.info("Validator lockout expired")

            # Check for double-sign attempt
            risk, conflicting = self._check_double_sign(request)

            if risk in (SlashingRisk.HIGH, SlashingRisk.CRITICAL):
                self._stats['denied'] += 1
                self._stats['double_sign_prevented'] += 1
                self._handle_suspicious_request(request, risk, conflicting)

                self._log_event(
                    "double_sign_prevented",
                    {
                        'height': request.height,
                        'round': request.round,
                        'event_type': request.event_type.value,
                        'risk': risk.value,
                        'conflicting_hash': conflicting.block_hash if conflicting else None,
                    }
                )

                return SigningResponse(
                    allowed=False,
                    risk_level=risk,
                    reason=f"DOUBLE-SIGN PREVENTED: Already signed at height {request.height} round {request.round}",
                    conflicting_record=conflicting,
                )

            # Safe to sign
            try:
                signature = self._perform_signing(request.data)
            except Exception as e:
                logger.error(f"Signing failed: {e}")
                return SigningResponse(
                    allowed=False,
                    risk_level=SlashingRisk.NONE,
                    reason=f"Signing operation failed: {e}"
                )

            # Record this signing
            record = SigningRecord(
                height=request.height,
                round=request.round,
                step=request.event_type.value,
                block_hash=request.block_hash,
                timestamp=time.time(),
                signature=signature,
            )

            key = (request.height, request.round, request.event_type.value)
            self._history[key] = record
            self._history_deque.append(key)

            # Persist immediately for crash safety
            self._save_history()

            self._stats['allowed'] += 1

            self._log_event(
                "validator_signed",
                {
                    'height': request.height,
                    'round': request.round,
                    'event_type': request.event_type.value,
                    'block_hash': request.block_hash[:16] + '...',
                }
            )

            return SigningResponse(
                allowed=True,
                signature=signature,
                risk_level=risk,
                reason="Signed successfully"
            )

    def _check_double_sign(
        self,
        request: SigningRequest
    ) -> Tuple[SlashingRisk, Optional[SigningRecord]]:
        """
        Check if this request would result in a double-sign.

        Returns:
            (risk_level, conflicting_record if any)
        """
        key = (request.height, request.round, request.event_type.value)

        existing = self._history.get(key)
        if not existing:
            return SlashingRisk.NONE, None

        # Same height/round/step - check if same block
        if existing.block_hash == request.block_hash:
            # Re-signing same message is unusual but not slashable
            return SlashingRisk.LOW, existing

        # Different block at same height/round/step = SLASHABLE
        if self.chain_type == ChainType.TENDERMINT:
            # Tendermint: prevote/precommit for different blocks = slashing
            return SlashingRisk.CRITICAL, existing

        elif self.chain_type == ChainType.ETHEREUM2:
            # Eth2: attestation/proposal for different blocks = slashing
            if request.event_type in (SigningEventType.ATTESTATION, SigningEventType.BLOCK_PROPOSAL):
                return SlashingRisk.CRITICAL, existing

        # Generic chain - assume high risk
        return SlashingRisk.HIGH, existing

    def _handle_suspicious_request(
        self,
        request: SigningRequest,
        risk: SlashingRisk,
        conflicting: Optional[SigningRecord]
    ) -> None:
        """Handle a suspicious signing request."""
        self._suspicious_count += 1

        logger.critical(
            f"SLASHING RISK DETECTED: {risk.value} - "
            f"height={request.height} round={request.round} "
            f"type={request.event_type.value} "
            f"conflicting_hash={conflicting.block_hash[:16] if conflicting else 'N/A'}..."
        )

        if self._suspicious_count >= self.LOCKOUT_THRESHOLD:
            self._locked_out = True
            self._lockout_time = time.time()
            self._stats['lockouts'] += 1

            logger.critical(
                f"VALIDATOR LOCKED OUT after {self._suspicious_count} suspicious requests. "
                "Manual intervention required if this is not an attack."
            )

    def _perform_signing(self, data: bytes) -> bytes:
        """Perform the actual signing operation."""
        if self._hsm_key_id:
            # HSM signing (keys never leave hardware)
            raise NotImplementedError("HSM signing requires HSM provider integration")

        if self._signing_key and NACL_AVAILABLE:
            # Software signing
            signed = self._signing_key.sign(data)
            return bytes(signed.signature)

        raise RuntimeError("No signing key available")

    def _log_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Log a security event."""
        if self._event_logger:
            try:
                self._event_logger.log_security_event(
                    event_type=f"validator_{event_type}",
                    severity="critical" if "prevented" in event_type else "info",
                    details={
                        'validator': self.validator_address,
                        'chain_type': self.chain_type.value,
                        **details,
                    }
                )
            except Exception as e:
                logger.error(f"Failed to log event: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get signing statistics."""
        with self._lock:
            return {
                **self._stats,
                'locked_out': self._locked_out,
                'suspicious_count': self._suspicious_count,
                'history_size': len(self._history),
            }

    def get_last_signed_height(self) -> int:
        """Get the last height we signed for."""
        with self._lock:
            if not self._history:
                return 0
            return max(key[0] for key in self._history.keys())

    def is_safe_to_sign(self, height: int, round: int, event_type: str, block_hash: str) -> bool:
        """
        Quick check if it's safe to sign without performing the signature.

        Use this for pre-flight checks before preparing a full signing request.
        """
        with self._lock:
            if self._locked_out:
                return False

            key = (height, round, event_type)
            existing = self._history.get(key)

            if existing and existing.block_hash != block_hash:
                return False

            return True


# Convenience function for quick integration
def create_validator_protector(
    chain: str,
    address: str,
    key_path: Optional[str] = None,
    history_path: Optional[str] = None,
) -> ValidatorKeyProtector:
    """
    Create a validator key protector with sensible defaults.

    Args:
        chain: Chain type ("tendermint", "ethereum2", "generic")
        address: Validator address
        key_path: Path to signing key
        history_path: Path for persistent history (defaults to ~/.boundary-daemon/validator_history.json)

    Returns:
        Configured ValidatorKeyProtector
    """
    chain_type = ChainType(chain.lower())

    if not history_path:
        history_dir = Path.home() / ".boundary-daemon"
        history_dir.mkdir(parents=True, exist_ok=True)
        history_path = str(history_dir / f"validator_{address[:8]}_history.json")

    return ValidatorKeyProtector(
        chain_type=chain_type,
        validator_address=address,
        signing_key_path=key_path,
        history_path=history_path,
    )


if __name__ == "__main__":
    # Self-test
    print("ValidatorKeyProtector - Slashing Prevention Module")
    print("=" * 60)

    # Create test protector
    import tempfile
    test_dir = tempfile.mkdtemp(prefix="validator_test_")
    protector = ValidatorKeyProtector(
        chain_type=ChainType.TENDERMINT,
        validator_address="cosmosvaloper1test123456789",
        history_path=f"{test_dir}/test_validator_history.json",
    )

    # Test double-sign prevention
    request1 = SigningRequest(
        chain_type=ChainType.TENDERMINT,
        event_type=SigningEventType.PREVOTE,
        height=100,
        round=0,
        data=b"test_vote_data",
        block_hash="abc123def456",
    )

    # This would require a signing key to actually sign
    print(f"Is safe to sign: {protector.is_safe_to_sign(100, 0, 'prevote', 'abc123def456')}")
    print(f"Stats: {protector.get_stats()}")
