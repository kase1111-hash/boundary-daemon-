"""
Protection Persistence Manager - Maintains security protections across daemon lifecycle.

SECURITY: This module addresses the vulnerability:
"Cleanup on Shutdown Removes All Protection"

The problem: When the boundary daemon shuts down (crash, restart, update),
it cleans up all firewall rules, USB restrictions, and seccomp profiles.
This leaves the system completely unprotected during the gap.

Solution:
1. Persist protection state to disk
2. Make cleanup configurable (default: persist critical protections)
3. Support "sticky" modes that survive daemon restarts
4. Provide explicit cleanup commands requiring authentication
5. Re-apply protections immediately on daemon startup
6. Integration with systemd for gap-free restarts
"""

import json
import os
import time
import hashlib
import hmac
import threading
import logging
import fcntl
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

logger = logging.getLogger(__name__)


class ProtectionType(Enum):
    """Types of protections that can be persisted."""
    NETWORK_FIREWALL = "network_firewall"
    USB_RESTRICTIONS = "usb_restrictions"
    PROCESS_ISOLATION = "process_isolation"
    SECCOMP_PROFILES = "seccomp_profiles"
    DNS_BLOCKING = "dns_blocking"


class CleanupPolicy(Enum):
    """Policies for cleanup behavior on shutdown."""
    # NEVER clean up - protections remain active forever (most secure)
    NEVER = "never"

    # Only clean up with explicit authenticated request
    EXPLICIT_ONLY = "explicit_only"

    # Clean up only on graceful shutdown (not crash/kill)
    GRACEFUL_ONLY = "graceful_only"

    # Clean up after timeout (e.g., if daemon doesn't restart in 5 min)
    TIMEOUT = "timeout"

    # Always clean up on shutdown (legacy behavior - INSECURE)
    ALWAYS = "always"


class PersistenceReason(Enum):
    """Reasons why protections are being persisted."""
    DAEMON_STARTUP = "daemon_startup"
    MODE_CHANGE = "mode_change"
    EXPLICIT_PERSIST = "explicit_persist"
    EMERGENCY_LOCKDOWN = "emergency_lockdown"
    DAEMON_SHUTDOWN = "daemon_shutdown"
    DAEMON_CRASH = "daemon_crash"


@dataclass
class PersistedProtection:
    """Represents a persisted protection rule."""
    protection_type: str
    mode: str
    reason: str
    applied_at: str
    applied_by: str = "daemon"
    sticky: bool = False  # If True, survives explicit cleanup requests
    emergency: bool = False  # If True, was applied during emergency
    expires_at: Optional[str] = None  # Optional expiration
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> 'PersistedProtection':
        return cls(**data)

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            expires = datetime.fromisoformat(self.expires_at)
            return datetime.utcnow() > expires
        except ValueError:
            return False


@dataclass
class ProtectionState:
    """Complete state of all persisted protections."""
    version: int = 1
    last_updated: str = ""
    daemon_pid: Optional[int] = None
    daemon_started_at: Optional[str] = None
    cleanup_policy: str = CleanupPolicy.EXPLICIT_ONLY.value
    protections: Dict[str, PersistedProtection] = field(default_factory=dict)
    cleanup_timeout_seconds: int = 300  # 5 minutes default
    hmac_signature: str = ""

    def to_dict(self) -> Dict:
        result = {
            'version': self.version,
            'last_updated': self.last_updated,
            'daemon_pid': self.daemon_pid,
            'daemon_started_at': self.daemon_started_at,
            'cleanup_policy': self.cleanup_policy,
            'protections': {k: v.to_dict() for k, v in self.protections.items()},
            'cleanup_timeout_seconds': self.cleanup_timeout_seconds,
        }
        return result

    @classmethod
    def from_dict(cls, data: Dict) -> 'ProtectionState':
        protections = {}
        for k, v in data.get('protections', {}).items():
            protections[k] = PersistedProtection.from_dict(v)

        return cls(
            version=data.get('version', 1),
            last_updated=data.get('last_updated', ''),
            daemon_pid=data.get('daemon_pid'),
            daemon_started_at=data.get('daemon_started_at'),
            cleanup_policy=data.get('cleanup_policy', CleanupPolicy.EXPLICIT_ONLY.value),
            protections=protections,
            cleanup_timeout_seconds=data.get('cleanup_timeout_seconds', 300),
            hmac_signature=data.get('hmac_signature', ''),
        )


class ProtectionPersistenceManager:
    """
    Manages persistence of security protections across daemon lifecycle.

    Key features:
    1. Persists protection state to disk
    2. Re-applies protections on daemon startup
    3. Configurable cleanup policies
    4. Requires authentication for cleanup
    5. Supports sticky/emergency protections that resist cleanup
    """

    DEFAULT_STATE_DIR = "/var/lib/boundary-daemon"
    DEFAULT_STATE_FILE = "protection_state.json"
    HMAC_KEY_FILE = "protection_hmac.key"

    def __init__(
        self,
        state_dir: str = None,
        cleanup_policy: CleanupPolicy = CleanupPolicy.EXPLICIT_ONLY,
        cleanup_timeout: int = 300,
        event_logger=None,
        auth_manager=None,  # TokenManager for authenticated cleanup
    ):
        """
        Initialize the protection persistence manager.

        Args:
            state_dir: Directory for state files (default: /var/lib/boundary-daemon)
            cleanup_policy: Default cleanup policy
            cleanup_timeout: Timeout in seconds for TIMEOUT policy
            event_logger: EventLogger for audit logging
            auth_manager: TokenManager for authenticated operations
        """
        self.state_dir = Path(state_dir or self.DEFAULT_STATE_DIR)
        self.state_file = self.state_dir / self.DEFAULT_STATE_FILE
        self.hmac_key_file = self.state_dir / self.HMAC_KEY_FILE

        self.cleanup_policy = cleanup_policy
        self.cleanup_timeout = cleanup_timeout
        self._event_logger = event_logger
        self._auth_manager = auth_manager

        self._state: Optional[ProtectionState] = None
        self._lock = threading.RLock()
        self._hmac_key: Optional[bytes] = None

        # Ensure state directory exists with proper permissions
        self._init_state_directory()

        # Load or create HMAC key
        self._init_hmac_key()

        # Load existing state
        self._load_state()

    def _init_state_directory(self):
        """Initialize state directory with proper permissions."""
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            # Restrictive permissions: root only
            if os.geteuid() == 0:
                os.chmod(self.state_dir, 0o700)
        except Exception as e:
            logger.warning(f"Could not create state directory: {e}")

    def _init_hmac_key(self):
        """Initialize or load HMAC key for state integrity."""
        try:
            if self.hmac_key_file.exists():
                with open(self.hmac_key_file, 'rb') as f:
                    self._hmac_key = f.read()
            else:
                # Generate new key
                import secrets
                self._hmac_key = secrets.token_bytes(32)
                with open(self.hmac_key_file, 'wb') as f:
                    f.write(self._hmac_key)
                if os.geteuid() == 0:
                    os.chmod(self.hmac_key_file, 0o600)
        except Exception as e:
            logger.warning(f"HMAC key initialization failed: {e}")
            # Use fallback key (less secure but functional)
            self._hmac_key = b"boundary-daemon-fallback-key-do-not-use"

    def _compute_hmac(self, data: Dict) -> str:
        """Compute HMAC signature for state data."""
        if not self._hmac_key:
            return ""

        content = json.dumps(data, sort_keys=True).encode()
        return hmac.new(self._hmac_key, content, hashlib.sha256).hexdigest()

    def _verify_hmac(self, data: Dict, signature: str) -> bool:
        """Verify HMAC signature of state data."""
        if not self._hmac_key or not signature:
            return False

        expected = self._compute_hmac(data)
        return hmac.compare_digest(expected, signature)

    def _load_state(self):
        """Load protection state from disk."""
        with self._lock:
            if not self.state_file.exists():
                self._state = ProtectionState(
                    cleanup_policy=self.cleanup_policy.value,
                    cleanup_timeout_seconds=self.cleanup_timeout,
                )
                return

            try:
                with open(self.state_file, 'r') as f:
                    # Use file locking for safe concurrent access
                    fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                    try:
                        data = json.load(f)
                    finally:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

                # Verify integrity
                signature = data.pop('hmac_signature', '')
                if signature and not self._verify_hmac(data, signature):
                    logger.error("Protection state integrity check failed!")
                    self._log_event('state_tamper_detected', {
                        'file': str(self.state_file),
                    })
                    # Use default state but log tampering
                    self._state = ProtectionState(
                        cleanup_policy=self.cleanup_policy.value,
                        cleanup_timeout_seconds=self.cleanup_timeout,
                    )
                    return

                self._state = ProtectionState.from_dict(data)

                # Check for expired protections
                self._cleanup_expired()

            except Exception as e:
                logger.error(f"Failed to load protection state: {e}")
                self._state = ProtectionState(
                    cleanup_policy=self.cleanup_policy.value,
                    cleanup_timeout_seconds=self.cleanup_timeout,
                )

    def _save_state(self):
        """Save protection state to disk atomically."""
        with self._lock:
            if not self._state:
                return

            try:
                self._state.last_updated = datetime.utcnow().isoformat()
                self._state.daemon_pid = os.getpid()

                data = self._state.to_dict()
                data['hmac_signature'] = self._compute_hmac(data)

                # Atomic write with file locking
                temp_file = self.state_file.with_suffix('.tmp')
                with open(temp_file, 'w') as f:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                    try:
                        json.dump(data, f, indent=2)
                        f.flush()
                        os.fsync(f.fileno())
                    finally:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

                # Set permissions before rename
                if os.geteuid() == 0:
                    os.chmod(temp_file, 0o600)

                # Atomic rename
                temp_file.rename(self.state_file)

            except Exception as e:
                logger.error(f"Failed to save protection state: {e}")

    def _cleanup_expired(self):
        """Remove expired protections from state."""
        if not self._state:
            return

        expired = [
            ptype for ptype, prot in self._state.protections.items()
            if prot.is_expired()
        ]

        for ptype in expired:
            del self._state.protections[ptype]
            logger.info(f"Removed expired protection: {ptype}")

    def _log_event(self, event_type: str, data: Dict):
        """Log a protection event."""
        if not self._event_logger:
            return

        try:
            # Map to actual EventType if available
            self._event_logger.log_event(
                event_type=event_type,
                data=data,
            )
        except Exception:
            pass

    def persist_protection(
        self,
        protection_type: ProtectionType,
        mode: str,
        reason: PersistenceReason,
        applied_by: str = "daemon",
        sticky: bool = False,
        emergency: bool = False,
        expires_in_seconds: Optional[int] = None,
        metadata: Optional[Dict] = None,
    ) -> Tuple[bool, str]:
        """
        Persist a protection so it survives daemon restarts.

        Args:
            protection_type: Type of protection being persisted
            mode: The mode/level of protection (e.g., "LOCKDOWN", "AIRGAP")
            reason: Why the protection is being persisted
            applied_by: Who/what applied this protection
            sticky: If True, requires extra auth to remove
            emergency: If True, was applied during emergency (harder to remove)
            expires_in_seconds: Optional expiration
            metadata: Additional data to store

        Returns:
            (success, message)
        """
        with self._lock:
            if not self._state:
                self._state = ProtectionState()

            expires_at = None
            if expires_in_seconds:
                expires_at = (
                    datetime.utcnow() + timedelta(seconds=expires_in_seconds)
                ).isoformat()

            protection = PersistedProtection(
                protection_type=protection_type.value,
                mode=mode,
                reason=reason.value,
                applied_at=datetime.utcnow().isoformat(),
                applied_by=applied_by,
                sticky=sticky,
                emergency=emergency,
                expires_at=expires_at,
                metadata=metadata or {},
            )

            self._state.protections[protection_type.value] = protection
            self._save_state()

            self._log_event('protection_persisted', {
                'type': protection_type.value,
                'mode': mode,
                'reason': reason.value,
                'sticky': sticky,
                'emergency': emergency,
            })

            logger.info(f"Persisted protection: {protection_type.value} ({mode})")
            return True, f"Protection persisted: {protection_type.value}"

    def get_persisted_protections(self) -> Dict[str, PersistedProtection]:
        """Get all currently persisted protections."""
        with self._lock:
            if not self._state:
                return {}

            # Clean up expired first
            self._cleanup_expired()

            return dict(self._state.protections)

    def should_reapply_protection(self, protection_type: ProtectionType) -> Optional[PersistedProtection]:
        """
        Check if a protection should be re-applied on daemon startup.

        Returns the persisted protection if it should be re-applied, None otherwise.
        """
        with self._lock:
            if not self._state:
                return None

            protection = self._state.protections.get(protection_type.value)
            if not protection:
                return None

            if protection.is_expired():
                del self._state.protections[protection_type.value]
                self._save_state()
                return None

            return protection

    def request_cleanup(
        self,
        protection_type: ProtectionType,
        token: Optional[str] = None,
        force: bool = False,
        reason: str = "",
    ) -> Tuple[bool, str]:
        """
        Request cleanup of a specific protection.

        SECURITY: Cleanup requires authentication unless running in ALWAYS policy.
        Sticky and emergency protections require force=True and admin token.

        Args:
            protection_type: Which protection to clean up
            token: Authentication token (required for most policies)
            force: Force cleanup even for sticky/emergency protections
            reason: Reason for cleanup (for audit log)

        Returns:
            (success, message)
        """
        with self._lock:
            if not self._state:
                return False, "No protection state"

            protection = self._state.protections.get(protection_type.value)
            if not protection:
                return True, "No protection to clean up"

            # Check cleanup policy
            policy = CleanupPolicy(self._state.cleanup_policy)

            if policy == CleanupPolicy.NEVER:
                return False, "Cleanup policy is NEVER - protections cannot be removed"

            # Authenticate for non-ALWAYS policies
            if policy != CleanupPolicy.ALWAYS:
                if not token:
                    return False, "Authentication required for cleanup"

                if self._auth_manager:
                    is_valid, token_obj, msg = self._auth_manager.validate_token(token)
                    if not is_valid:
                        return False, f"Authentication failed: {msg}"

                    # Check for admin capability for sticky/emergency
                    if protection.sticky or protection.emergency:
                        if not force:
                            return False, "Force flag required for sticky/emergency protection"

                        from daemon.auth.api_auth import APICapability
                        if not token_obj.has_capability(APICapability.ADMIN):
                            return False, "Admin capability required for sticky/emergency cleanup"

            # Handle sticky protections
            if protection.sticky and not force:
                return False, "Protection is sticky - use force=True with admin token"

            # Handle emergency protections
            if protection.emergency and not force:
                return False, "Protection was applied during emergency - use force=True with admin token"

            # Remove protection
            del self._state.protections[protection_type.value]
            self._save_state()

            self._log_event('protection_cleaned', {
                'type': protection_type.value,
                'reason': reason,
                'forced': force,
            })

            logger.info(f"Cleaned up protection: {protection_type.value}")
            return True, f"Protection cleaned: {protection_type.value}"

    def on_daemon_shutdown(
        self,
        graceful: bool = True,
        cleanup_requested: bool = False,
    ) -> Dict[str, bool]:
        """
        Handle daemon shutdown - decide what to clean up.

        Args:
            graceful: Whether this is a graceful shutdown (not crash/kill)
            cleanup_requested: Whether explicit cleanup was requested

        Returns:
            Dict mapping protection type to whether it should be cleaned
        """
        with self._lock:
            if not self._state:
                return {}

            policy = CleanupPolicy(self._state.cleanup_policy)
            cleanup_map = {}

            for ptype, protection in self._state.protections.items():
                should_cleanup = False

                # Never clean sticky or emergency protections automatically
                if protection.sticky or protection.emergency:
                    should_cleanup = False
                elif policy == CleanupPolicy.ALWAYS:
                    should_cleanup = True
                elif policy == CleanupPolicy.NEVER:
                    should_cleanup = False
                elif policy == CleanupPolicy.EXPLICIT_ONLY:
                    should_cleanup = cleanup_requested
                elif policy == CleanupPolicy.GRACEFUL_ONLY:
                    should_cleanup = graceful and cleanup_requested
                elif policy == CleanupPolicy.TIMEOUT:
                    # For timeout, we don't clean up now - the timeout mechanism handles it
                    should_cleanup = False

                cleanup_map[ptype] = should_cleanup

            # Save updated state
            self._save_state()

            logger.info(f"Shutdown cleanup decisions: {cleanup_map}")
            return cleanup_map

    def set_cleanup_policy(
        self,
        policy: CleanupPolicy,
        token: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Set the cleanup policy.

        SECURITY: Changing to less secure policies requires authentication.
        """
        with self._lock:
            if not self._state:
                self._state = ProtectionState()

            current = CleanupPolicy(self._state.cleanup_policy)

            # Changing to less secure policy requires auth
            security_order = [
                CleanupPolicy.NEVER,
                CleanupPolicy.EXPLICIT_ONLY,
                CleanupPolicy.GRACEFUL_ONLY,
                CleanupPolicy.TIMEOUT,
                CleanupPolicy.ALWAYS,
            ]

            current_idx = security_order.index(current)
            new_idx = security_order.index(policy)

            if new_idx > current_idx:  # Less secure
                if not token and self._auth_manager:
                    return False, "Authentication required to reduce cleanup security"

                if token and self._auth_manager:
                    is_valid, token_obj, msg = self._auth_manager.validate_token(token)
                    if not is_valid:
                        return False, f"Authentication failed: {msg}"

            self._state.cleanup_policy = policy.value
            self._save_state()

            self._log_event('cleanup_policy_changed', {
                'old_policy': current.value,
                'new_policy': policy.value,
            })

            return True, f"Cleanup policy set to {policy.value}"

    def check_orphaned_protections(self) -> List[Dict]:
        """
        Check for protections that may have been orphaned (daemon died).

        Called on startup to detect if the previous daemon died unexpectedly.
        """
        with self._lock:
            if not self._state or not self._state.daemon_pid:
                return []

            orphaned = []

            # Check if the old daemon is still running
            old_pid = self._state.daemon_pid
            try:
                os.kill(old_pid, 0)  # Check if process exists
                # Process exists - not orphaned
            except ProcessLookupError:
                # Old daemon is dead - protections may be orphaned
                for ptype, protection in self._state.protections.items():
                    orphaned.append({
                        'type': ptype,
                        'mode': protection.mode,
                        'applied_at': protection.applied_at,
                        'reason': 'daemon_died',
                    })

                if orphaned:
                    logger.warning(f"Found {len(orphaned)} orphaned protections from dead daemon (PID {old_pid})")
                    self._log_event('orphaned_protections_found', {
                        'count': len(orphaned),
                        'old_pid': old_pid,
                    })
            except PermissionError:
                # Process exists but we can't signal it - assume not orphaned
                pass

            return orphaned

    def get_status(self) -> Dict:
        """Get current protection persistence status."""
        with self._lock:
            if not self._state:
                return {
                    'initialized': False,
                    'protections': [],
                    'cleanup_policy': self.cleanup_policy.value,
                }

            return {
                'initialized': True,
                'cleanup_policy': self._state.cleanup_policy,
                'cleanup_timeout_seconds': self._state.cleanup_timeout_seconds,
                'daemon_pid': self._state.daemon_pid,
                'daemon_started_at': self._state.daemon_started_at,
                'last_updated': self._state.last_updated,
                'protections': [
                    {
                        'type': prot.protection_type,
                        'mode': prot.mode,
                        'applied_at': prot.applied_at,
                        'sticky': prot.sticky,
                        'emergency': prot.emergency,
                        'expires_at': prot.expires_at,
                    }
                    for prot in self._state.protections.values()
                ],
            }

    def mark_daemon_started(self):
        """Mark that the daemon has started (for orphan detection)."""
        with self._lock:
            if not self._state:
                self._state = ProtectionState()

            self._state.daemon_pid = os.getpid()
            self._state.daemon_started_at = datetime.utcnow().isoformat()
            self._save_state()


class PersistentEnforcerMixin:
    """
    Mixin for enforcers to add protection persistence support.

    Add this to NetworkEnforcer, USBEnforcer, etc. to enable
    persisting their rules across daemon restarts.
    """

    _persistence_manager: Optional[ProtectionPersistenceManager] = None
    _protection_type: Optional[ProtectionType] = None

    def set_persistence_manager(
        self,
        manager: ProtectionPersistenceManager,
        protection_type: ProtectionType,
    ):
        """Configure persistence for this enforcer."""
        self._persistence_manager = manager
        self._protection_type = protection_type

    def persist_on_mode_change(
        self,
        mode: str,
        sticky: bool = False,
        emergency: bool = False,
    ):
        """Call after enforcing a mode to persist it."""
        if self._persistence_manager and self._protection_type:
            self._persistence_manager.persist_protection(
                protection_type=self._protection_type,
                mode=mode,
                reason=PersistenceReason.MODE_CHANGE,
                sticky=sticky,
                emergency=emergency,
            )

    def check_persisted_mode(self) -> Optional[str]:
        """Check if there's a persisted mode to re-apply."""
        if self._persistence_manager and self._protection_type:
            protection = self._persistence_manager.should_reapply_protection(
                self._protection_type
            )
            if protection:
                return protection.mode
        return None

    def cleanup_with_persistence(
        self,
        token: Optional[str] = None,
        force: bool = False,
    ) -> Tuple[bool, str]:
        """
        Clean up protection with persistence check.

        Returns:
            (should_cleanup, message)
        """
        if not self._persistence_manager or not self._protection_type:
            # No persistence - allow cleanup
            return True, "No persistence configured"

        return self._persistence_manager.request_cleanup(
            protection_type=self._protection_type,
            token=token,
            force=force,
        )


if __name__ == '__main__':
    import tempfile

    logging.basicConfig(level=logging.DEBUG)

    # Test in temp directory
    with tempfile.TemporaryDirectory() as tmpdir:
        print("Testing Protection Persistence Manager")
        print("=" * 50)

        manager = ProtectionPersistenceManager(
            state_dir=tmpdir,
            cleanup_policy=CleanupPolicy.EXPLICIT_ONLY,
        )

        print(f"\n1. Initial status: {manager.get_status()}")

        # Persist some protections
        print("\n2. Persisting network protection...")
        success, msg = manager.persist_protection(
            protection_type=ProtectionType.NETWORK_FIREWALL,
            mode="AIRGAP",
            reason=PersistenceReason.MODE_CHANGE,
        )
        print(f"   Result: {success} - {msg}")

        print("\n3. Persisting USB protection (sticky)...")
        success, msg = manager.persist_protection(
            protection_type=ProtectionType.USB_RESTRICTIONS,
            mode="LOCKDOWN",
            reason=PersistenceReason.EMERGENCY_LOCKDOWN,
            sticky=True,
            emergency=True,
        )
        print(f"   Result: {success} - {msg}")

        print(f"\n4. Status: {manager.get_status()}")

        # Try cleanup without auth
        print("\n5. Trying cleanup without auth...")
        success, msg = manager.request_cleanup(
            protection_type=ProtectionType.NETWORK_FIREWALL,
        )
        print(f"   Result: {success} - {msg}")

        # Shutdown behavior
        print("\n6. Shutdown cleanup decisions (graceful)...")
        decisions = manager.on_daemon_shutdown(graceful=True)
        print(f"   Decisions: {decisions}")

        print("\nTest complete!")
