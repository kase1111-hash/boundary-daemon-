"""
IntentLog Boundary Integration

Provides security integration between IntentLog and the Boundary Daemon
to prevent tampering, clock manipulation, and unauthorized logging attacks.

IntentLog is an immutable intent logging system that records agent intents
with cryptographic signatures and tamper-evident audit trails.

SECURITY FEATURES:
- Intent signature verification before logging
- Timestamp validation to prevent clock manipulation
- Hash chain integrity verification
- Mode-aware logging restrictions
- Rate limiting for logging operations

Attack Vectors Prevented:
- CONTRACT_TAMPERING: Hash chain and signature verification
- CLOCK_MANIPULATION: Timestamp validation and drift detection
- CRYPTO_BYPASS: Signature and proof verification

Usage:
    from boundary import IntentLogGate, AuditTrailValidator

    # Before logging an intent
    gate = IntentLogGate()
    if gate.can_log_intent(intent_hash, signature):
        intent_log.record(intent)

    # Validate audit trail integrity
    validator = AuditTrailValidator()
    is_valid, errors = validator.validate_chain(entries)
"""

import hashlib
import json
import logging
import os
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar('T')


class OperationalMode(Enum):
    """Boundary operational modes."""
    OPEN = "open"
    RESTRICTED = "restricted"
    TRUSTED = "trusted"
    AIRGAP = "airgap"
    COLDROOM = "coldroom"
    LOCKDOWN = "lockdown"


class IntentClassification(IntEnum):
    """Intent classification levels."""
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3
    TOP_SECRET = 4
    CROWN_JEWEL = 5


@dataclass
class LogDecision:
    """Result of a logging permission check."""
    permitted: bool
    reason: str
    mode: Optional[OperationalMode] = None
    requires_ceremony: bool = False
    timestamp_valid: bool = True
    signature_valid: bool = True


@dataclass
class IntegrityCheckResult:
    """Result of an integrity check."""
    valid: bool
    errors: List[str]
    entries_checked: int
    first_invalid_index: Optional[int] = None


class BoundaryError(Exception):
    """Base exception for boundary errors."""
    pass


class DaemonUnavailableError(BoundaryError):
    """Raised when daemon is not reachable."""
    pass


class LoggingDeniedError(BoundaryError):
    """Raised when logging is denied."""
    pass


class IntegrityError(BoundaryError):
    """Raised when integrity check fails."""
    pass


def get_socket_path() -> str:
    """Get the boundary daemon socket path."""
    paths = [
        os.environ.get('BOUNDARY_DAEMON_SOCKET'),
        '/var/run/boundary-daemon/boundary.sock',
        os.path.expanduser('~/.agent-os/api/boundary.sock'),
        './api/boundary.sock',
    ]

    for path in paths:
        if path and os.path.exists(path):
            return path

    return '/var/run/boundary-daemon/boundary.sock'


class BoundaryClient:
    """Boundary Daemon Client for IntentLog."""

    def __init__(
        self,
        socket_path: Optional[str] = None,
        token: Optional[str] = None,
        max_retries: int = 3,
        timeout: float = 5.0,
    ):
        self.socket_path = socket_path or get_socket_path()
        self._token = token or os.environ.get('BOUNDARY_API_TOKEN')
        self.max_retries = max_retries
        self.timeout = timeout

    def _send_request(
        self,
        command: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send request with retry logic."""
        request = {'command': command, 'params': params or {}}
        if self._token:
            request['token'] = self._token

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall(json.dumps(request).encode('utf-8'))
                data = sock.recv(65536)
                sock.close()
                return json.loads(data.decode('utf-8'))
            except (ConnectionRefusedError, FileNotFoundError, socket.timeout) as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    time.sleep(0.5 * (2 ** attempt))
            finally:
                try:
                    sock.close()
                except:
                    pass

        raise DaemonUnavailableError(f"Daemon unavailable: {last_error}")

    def get_status(self) -> Dict[str, Any]:
        """Get daemon status."""
        try:
            response = self._send_request('status')
            return response.get('status', {})
        except DaemonUnavailableError:
            return {'mode': 'lockdown', 'online': False}

    def get_mode(self) -> OperationalMode:
        """Get current operational mode."""
        status = self.get_status()
        mode_str = status.get('mode', 'lockdown').lower()
        return OperationalMode(mode_str)

    def check_tool(
        self,
        tool_name: str,
        requires_network: bool = False,
        requires_filesystem: bool = False,
    ) -> LogDecision:
        """Check if tool operation is permitted."""
        params = {
            'tool_name': tool_name,
            'requires_network': requires_network,
            'requires_filesystem': requires_filesystem,
        }

        try:
            response = self._send_request('check_tool', params)
        except DaemonUnavailableError:
            return LogDecision(
                permitted=False,
                reason="Boundary daemon unavailable - fail closed",
            )

        return LogDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def verify_cryptographic_signature(
        self,
        algorithm: str,
        message_hash: str,
        signature: str,
        public_key: str,
    ) -> LogDecision:
        """Verify a cryptographic signature."""
        params = {
            'algorithm': algorithm,
            'message_hash': message_hash,
            'signature': signature,
            'public_key': public_key,
        }

        try:
            response = self._send_request('verify_cryptographic_signature', params)
        except DaemonUnavailableError:
            return LogDecision(
                permitted=False,
                reason="Daemon unavailable - signature unverified",
                signature_valid=False,
            )

        return LogDecision(
            permitted=response.get('valid', False),
            reason=response.get('reason', 'Unknown'),
            signature_valid=response.get('valid', False),
        )

    def check_entity_rate_limit(
        self,
        entity_id: str,
        operation: str,
        window_seconds: int = 3600,
        max_operations: int = 100,
    ) -> LogDecision:
        """Check rate limit for entity."""
        params = {
            'entity_id': entity_id,
            'entity_type': 'intent_logger',
            'operation': operation,
            'window_seconds': window_seconds,
            'max_operations': max_operations,
        }

        try:
            response = self._send_request('check_entity_rate_limit', params)
        except DaemonUnavailableError:
            return LogDecision(
                permitted=False,
                reason="Daemon unavailable - rate limit check failed",
            )

        return LogDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def verify_merkle_proof(
        self,
        root_hash: str,
        leaf_hash: str,
        proof_path: List[str],
        leaf_index: int,
    ) -> LogDecision:
        """Verify Merkle proof for audit trail."""
        params = {
            'root_hash': root_hash,
            'leaf_hash': leaf_hash,
            'proof_path': proof_path,
            'leaf_index': leaf_index,
        }

        try:
            response = self._send_request('verify_merkle_proof', params)
        except DaemonUnavailableError:
            return LogDecision(
                permitted=False,
                reason="Daemon unavailable - proof unverified",
            )

        return LogDecision(
            permitted=response.get('valid', False),
            reason=response.get('reason', 'Unknown'),
        )


class IntentLogGate:
    """
    Gate for intent logging operations.

    MANDATORY: Must be called before any intent is logged.

    Usage:
        gate = IntentLogGate()

        # Check if logging is permitted
        if gate.can_log_intent(intent_data, signature, public_key):
            intent_log.record(intent)

        # Require logging permission (raises on denial)
        gate.require_log_permission(intent_data, signature, public_key)
        intent_log.record(intent)
    """

    def __init__(self, client: Optional[BoundaryClient] = None):
        self.client = client or BoundaryClient()
        self._last_decision: Optional[LogDecision] = None
        self._max_clock_drift_seconds = 300  # 5 minutes

    @property
    def last_decision(self) -> Optional[LogDecision]:
        """Get the last logging decision."""
        return self._last_decision

    def _validate_timestamp(self, timestamp: str) -> Tuple[bool, str]:
        """Validate that timestamp is within acceptable drift."""
        try:
            # Parse ISO format timestamp
            if timestamp.endswith('Z'):
                ts = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                ts = datetime.fromisoformat(timestamp)

            # Convert to UTC if not already
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            drift = abs((now - ts).total_seconds())

            if drift > self._max_clock_drift_seconds:
                return False, f"Timestamp drift {drift:.0f}s exceeds maximum {self._max_clock_drift_seconds}s"

            return True, "Timestamp valid"

        except ValueError as e:
            return False, f"Invalid timestamp format: {e}"

    def _compute_intent_hash(self, intent_data: Dict[str, Any]) -> str:
        """Compute hash of intent data for signature verification."""
        # Canonicalize JSON for consistent hashing
        canonical = json.dumps(intent_data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()

    def can_log_intent(
        self,
        intent_data: Dict[str, Any],
        signature: Optional[str] = None,
        public_key: Optional[str] = None,
        author_id: Optional[str] = None,
    ) -> bool:
        """
        Check if intent logging is permitted.

        Args:
            intent_data: The intent to log (must include 'timestamp')
            signature: Cryptographic signature of the intent
            public_key: Public key for signature verification
            author_id: Author identifier for rate limiting

        Returns:
            True if logging is permitted
        """
        # Check current mode
        mode = self.client.get_mode()
        if mode == OperationalMode.LOCKDOWN:
            self._last_decision = LogDecision(
                permitted=False,
                reason="Logging denied in LOCKDOWN mode",
                mode=mode,
            )
            return False

        # Validate timestamp
        timestamp = intent_data.get('timestamp', '')
        ts_valid, ts_reason = self._validate_timestamp(timestamp)
        if not ts_valid:
            self._last_decision = LogDecision(
                permitted=False,
                reason=f"Clock manipulation detected: {ts_reason}",
                mode=mode,
                timestamp_valid=False,
            )
            logger.warning(f"Intent logging denied: {ts_reason}")
            return False

        # Verify signature if provided
        sig_valid = True
        if signature and public_key:
            intent_hash = self._compute_intent_hash(intent_data)
            sig_decision = self.client.verify_cryptographic_signature(
                algorithm='ed25519',
                message_hash=intent_hash,
                signature=signature,
                public_key=public_key,
            )
            if not sig_decision.signature_valid:
                self._last_decision = LogDecision(
                    permitted=False,
                    reason=f"Invalid signature: {sig_decision.reason}",
                    mode=mode,
                    signature_valid=False,
                )
                logger.warning(f"Intent logging denied: invalid signature")
                return False

        # Check rate limit if author provided
        if author_id:
            rate_decision = self.client.check_entity_rate_limit(
                entity_id=author_id,
                operation='log_intent',
                max_operations=self._get_mode_rate_limit(mode),
            )
            if not rate_decision.permitted:
                self._last_decision = LogDecision(
                    permitted=False,
                    reason=f"Rate limit exceeded: {rate_decision.reason}",
                    mode=mode,
                )
                return False

        # Check tool permission for logging
        tool_decision = self.client.check_tool(
            tool_name='intent_log_write',
            requires_filesystem=True,
        )

        self._last_decision = LogDecision(
            permitted=tool_decision.permitted,
            reason=tool_decision.reason,
            mode=mode,
            timestamp_valid=ts_valid,
            signature_valid=sig_valid,
        )

        if tool_decision.permitted:
            logger.debug(f"Intent logging permitted: mode={mode.value}")
        else:
            logger.warning(f"Intent logging denied: {tool_decision.reason}")

        return tool_decision.permitted

    def _get_mode_rate_limit(self, mode: OperationalMode) -> int:
        """Get rate limit based on current mode."""
        limits = {
            OperationalMode.OPEN: 1000,
            OperationalMode.RESTRICTED: 500,
            OperationalMode.TRUSTED: 100,
            OperationalMode.AIRGAP: 50,
            OperationalMode.COLDROOM: 10,
            OperationalMode.LOCKDOWN: 0,
        }
        return limits.get(mode, 0)

    def require_log_permission(
        self,
        intent_data: Dict[str, Any],
        signature: Optional[str] = None,
        public_key: Optional[str] = None,
        author_id: Optional[str] = None,
    ) -> None:
        """
        Require logging permission, raising exception if denied.

        Raises:
            LoggingDeniedError: If logging is not permitted
        """
        if not self.can_log_intent(intent_data, signature, public_key, author_id):
            raise LoggingDeniedError(
                f"Intent logging denied: {self._last_decision.reason}"
            )


class AuditTrailValidator:
    """
    Validates the integrity of the intent audit trail.

    Checks:
    - Hash chain continuity (each entry links to previous)
    - Timestamp monotonicity (timestamps must be non-decreasing)
    - Signature validity (all signatures must be valid)
    - No gaps in sequence numbers

    Usage:
        validator = AuditTrailValidator()
        result = validator.validate_chain(entries)
        if not result.valid:
            print(f"Integrity violated at entry {result.first_invalid_index}")
            for error in result.errors:
                print(f"  - {error}")
    """

    def __init__(self, client: Optional[BoundaryClient] = None):
        self.client = client or BoundaryClient()

    def _compute_entry_hash(self, entry: Dict[str, Any]) -> str:
        """Compute hash of an entry."""
        # Include all fields except the hash itself
        data = {k: v for k, v in entry.items() if k != 'hash'}
        canonical = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()

    def validate_chain(
        self,
        entries: List[Dict[str, Any]],
        verify_signatures: bool = True,
    ) -> IntegrityCheckResult:
        """
        Validate the integrity of an audit trail chain.

        Args:
            entries: List of audit trail entries in order
            verify_signatures: Whether to verify cryptographic signatures

        Returns:
            IntegrityCheckResult with validation details
        """
        errors = []
        first_invalid = None

        if not entries:
            return IntegrityCheckResult(
                valid=True,
                errors=[],
                entries_checked=0,
            )

        prev_hash = None
        prev_timestamp = None

        for i, entry in enumerate(entries):
            entry_errors = []

            # Check hash chain
            if prev_hash is not None:
                expected_prev = entry.get('previous_hash')
                if expected_prev != prev_hash:
                    entry_errors.append(
                        f"Entry {i}: Hash chain broken. Expected prev_hash={prev_hash[:16]}..., "
                        f"got {expected_prev[:16] if expected_prev else 'None'}..."
                    )

            # Verify entry hash
            computed_hash = self._compute_entry_hash(entry)
            stored_hash = entry.get('hash')
            if stored_hash and stored_hash != computed_hash:
                entry_errors.append(
                    f"Entry {i}: Hash mismatch. Computed={computed_hash[:16]}..., "
                    f"Stored={stored_hash[:16]}..."
                )

            # Check timestamp monotonicity
            timestamp = entry.get('timestamp')
            if timestamp and prev_timestamp:
                try:
                    ts = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    prev_ts = datetime.fromisoformat(prev_timestamp.replace('Z', '+00:00'))
                    if ts < prev_ts:
                        entry_errors.append(
                            f"Entry {i}: Timestamp regression. {timestamp} < {prev_timestamp}"
                        )
                except ValueError:
                    entry_errors.append(f"Entry {i}: Invalid timestamp format")

            # Verify signature if requested
            if verify_signatures:
                signature = entry.get('signature')
                public_key = entry.get('public_key') or entry.get('author_public_key')
                if signature and public_key:
                    intent_hash = self._compute_entry_hash(
                        {k: v for k, v in entry.items() if k not in ['hash', 'signature']}
                    )
                    sig_decision = self.client.verify_cryptographic_signature(
                        algorithm='ed25519',
                        message_hash=intent_hash,
                        signature=signature,
                        public_key=public_key,
                    )
                    if not sig_decision.signature_valid:
                        entry_errors.append(
                            f"Entry {i}: Invalid signature"
                        )

            # Check sequence number if present
            seq = entry.get('sequence')
            if seq is not None and i != seq:
                entry_errors.append(
                    f"Entry {i}: Sequence mismatch. Expected {i}, got {seq}"
                )

            if entry_errors:
                if first_invalid is None:
                    first_invalid = i
                errors.extend(entry_errors)

            # Update for next iteration
            prev_hash = entry.get('hash') or computed_hash
            prev_timestamp = timestamp

        return IntegrityCheckResult(
            valid=len(errors) == 0,
            errors=errors,
            entries_checked=len(entries),
            first_invalid_index=first_invalid,
        )

    def verify_merkle_root(
        self,
        entries: List[Dict[str, Any]],
        expected_root: str,
    ) -> Tuple[bool, str]:
        """
        Verify the Merkle root of the audit trail.

        Args:
            entries: List of audit trail entries
            expected_root: Expected Merkle root hash

        Returns:
            (is_valid, message)
        """
        if not entries:
            return False, "Cannot verify empty entry list"

        # Build Merkle tree
        hashes = [
            entry.get('hash') or self._compute_entry_hash(entry)
            for entry in entries
        ]

        # Compute root
        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])  # Duplicate last for odd count

            new_hashes = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                new_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
                new_hashes.append(new_hash)
            hashes = new_hashes

        computed_root = hashes[0]

        if computed_root == expected_root:
            return True, "Merkle root verified"
        else:
            return False, f"Merkle root mismatch. Expected {expected_root[:16]}..., computed {computed_root[:16]}..."


# Convenience functions

def check_log_permission(
    intent_data: Dict[str, Any],
    signature: Optional[str] = None,
    public_key: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Check logging permission (convenience function).

    Returns:
        (permitted, reason)
    """
    gate = IntentLogGate()
    permitted = gate.can_log_intent(intent_data, signature, public_key)
    return permitted, gate.last_decision.reason if gate.last_decision else "Unknown"


def validate_audit_trail(entries: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """
    Validate audit trail integrity (convenience function).

    Returns:
        (is_valid, error_list)
    """
    validator = AuditTrailValidator()
    result = validator.validate_chain(entries)
    return result.valid, result.errors


# Decorator for protected logging

def require_log_check(
    classification: IntentClassification = IntentClassification.PUBLIC,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator that requires boundary check before logging.

    Usage:
        @require_log_check(classification=IntentClassification.CONFIDENTIAL)
        def log_sensitive_intent(intent_data):
            return intent_log.record(intent_data)
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args, **kwargs) -> T:
            gate = IntentLogGate()

            # Extract intent_data from first positional arg
            intent_data = args[0] if args else kwargs.get('intent_data', {})
            signature = kwargs.get('signature')
            public_key = kwargs.get('public_key')

            gate.require_log_permission(intent_data, signature, public_key)
            return func(*args, **kwargs)
        return wrapper
    return decorator


# IntentLog Integration Mixin

class IntentLogBoundaryMixin:
    """
    Mixin class for IntentLog to add boundary integration.

    Add this to your IntentLog class:

        class IntentLog(IntentLogBoundaryMixin, BaseIntentLog):
            pass
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._boundary_client = BoundaryClient()
        self._log_gate = IntentLogGate(self._boundary_client)
        self._trail_validator = AuditTrailValidator(self._boundary_client)

    def record(
        self,
        intent_data: Dict[str, Any],
        signature: Optional[str] = None,
        public_key: Optional[str] = None,
    ) -> Any:
        """
        Record intent with boundary check.

        This method adds boundary enforcement to the base record method.
        """
        # MANDATORY: Check with boundary daemon first
        self._log_gate.require_log_permission(intent_data, signature, public_key)

        # Add timestamp if not present
        if 'timestamp' not in intent_data:
            intent_data['timestamp'] = datetime.now(timezone.utc).isoformat()

        # Proceed with recording (call parent method)
        return super().record(intent_data)

    def validate_trail(self) -> IntegrityCheckResult:
        """Validate the current audit trail."""
        entries = self.get_all_entries()  # Assumes parent has this method
        return self._trail_validator.validate_chain(entries)

    def get_boundary_status(self) -> Dict[str, Any]:
        """Get current boundary daemon status."""
        return self._boundary_client.get_status()
