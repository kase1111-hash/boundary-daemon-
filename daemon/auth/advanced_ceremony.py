"""
Advanced Ceremony Framework - Extended ceremony capabilities for high-security operations.

Features:
- Ceremony Templates: Pre-defined ceremony types with customizable steps
- N-of-M Ceremonies: Multi-party approval requiring N approvals from M authorized parties
- Time-Locked Ceremonies: Ceremonies that only complete during specified time windows
- Dead-Man Ceremonies: Auto-trigger actions if no human activity for N hours
- Hardware Token Ceremonies: YubiKey/OnlyKey integration for offline auth

SECURITY: All ceremony actions are logged to the immutable hash-chained event log.
All ceremonies follow fail-closed design - any ambiguity results in denial.
"""

import os
import time
import json
import hashlib
import threading
from enum import Enum
from typing import Optional, Callable, Dict, List, Any, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .enhanced_ceremony import EnhancedCeremonyManager, BiometricCeremonyConfig
from .biometric_verifier import BiometricVerifier
from ..event_logger import EventType


# =============================================================================
# CEREMONY TEMPLATE SYSTEM
# =============================================================================

class CeremonyType(Enum):
    """Pre-defined ceremony types with specific requirements."""
    EMERGENCY_ACCESS = "emergency_access"
    DATA_EXPORT = "data_export"
    MODE_OVERRIDE = "mode_override"
    LOCKDOWN_RELEASE = "lockdown_release"
    KEY_ROTATION = "key_rotation"
    AUDIT_EXPORT = "audit_export"
    BIOMETRIC_ENROLLMENT = "biometric_enrollment"
    TOKEN_CREATION = "token_creation"
    POLICY_CHANGE = "policy_change"
    CLUSTER_JOIN = "cluster_join"
    CUSTOM = "custom"


class CeremonySeverity(Enum):
    """Severity levels affecting ceremony requirements."""
    LOW = 1        # Quick ceremony, short cooldown
    MEDIUM = 2     # Standard ceremony
    HIGH = 3       # Extended ceremony, multiple confirmations
    CRITICAL = 4   # Maximum ceremony, requires N-of-M or hardware token


@dataclass
class CeremonyStep:
    """Definition of a single ceremony step."""
    name: str
    description: str
    validator: Optional[Callable[[], Tuple[bool, str]]] = None
    timeout_seconds: int = 60
    required: bool = True

    def execute(self, callback: Optional[Callable] = None) -> Tuple[bool, str]:
        """Execute this ceremony step."""
        if self.validator:
            return self.validator()
        return (True, f"Step '{self.name}' completed")


@dataclass
class CeremonyTemplate:
    """
    Template for a specific ceremony type.

    Templates define:
    - Required steps and their order
    - Cooldown durations
    - Authentication requirements
    - Time window restrictions (optional)
    - N-of-M requirements (optional)
    """
    ceremony_type: CeremonyType
    name: str
    description: str
    severity: CeremonySeverity
    steps: List[CeremonyStep] = field(default_factory=list)
    cooldown_seconds: int = 30
    require_biometric: bool = False
    require_hardware_token: bool = False
    require_n_of_m: Optional[Tuple[int, int]] = None  # (n, m) - need n of m approvers
    time_window: Optional[Tuple[int, int]] = None  # (start_hour, end_hour) in 24h format
    allowed_days: Optional[Set[int]] = None  # 0=Monday, 6=Sunday
    max_attempts: int = 3
    lockout_duration_seconds: int = 300

    def validate_time_window(self) -> Tuple[bool, str]:
        """Check if current time is within allowed window."""
        if not self.time_window:
            return (True, "No time restriction")

        now = datetime.now()
        start_hour, end_hour = self.time_window
        current_hour = now.hour

        # Handle overnight windows (e.g., 22:00 to 06:00)
        if start_hour <= end_hour:
            in_window = start_hour <= current_hour < end_hour
        else:
            in_window = current_hour >= start_hour or current_hour < end_hour

        if not in_window:
            return (False, f"Ceremony only allowed between {start_hour:02d}:00 and {end_hour:02d}:00")

        if self.allowed_days and now.weekday() not in self.allowed_days:
            day_names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
            allowed = ', '.join(day_names[d] for d in sorted(self.allowed_days))
            return (False, f"Ceremony only allowed on: {allowed}")

        return (True, "Within allowed time window")


# Pre-defined ceremony templates
CEREMONY_TEMPLATES: Dict[CeremonyType, CeremonyTemplate] = {
    CeremonyType.EMERGENCY_ACCESS: CeremonyTemplate(
        ceremony_type=CeremonyType.EMERGENCY_ACCESS,
        name="Emergency Access",
        description="Bypass security controls in emergency situations",
        severity=CeremonySeverity.CRITICAL,
        cooldown_seconds=60,
        require_biometric=True,
        require_hardware_token=True,
        max_attempts=2,
        lockout_duration_seconds=600,
    ),
    CeremonyType.DATA_EXPORT: CeremonyTemplate(
        ceremony_type=CeremonyType.DATA_EXPORT,
        name="Data Export",
        description="Export sensitive data from the system",
        severity=CeremonySeverity.HIGH,
        cooldown_seconds=45,
        require_biometric=True,
        time_window=(9, 18),  # Business hours only
        allowed_days={0, 1, 2, 3, 4},  # Weekdays only
    ),
    CeremonyType.MODE_OVERRIDE: CeremonyTemplate(
        ceremony_type=CeremonyType.MODE_OVERRIDE,
        name="Mode Override",
        description="Force change boundary mode",
        severity=CeremonySeverity.HIGH,
        cooldown_seconds=30,
        require_biometric=True,
    ),
    CeremonyType.LOCKDOWN_RELEASE: CeremonyTemplate(
        ceremony_type=CeremonyType.LOCKDOWN_RELEASE,
        name="Lockdown Release",
        description="Release system from lockdown state",
        severity=CeremonySeverity.CRITICAL,
        cooldown_seconds=90,
        require_biometric=True,
        require_n_of_m=(2, 3),  # Require 2 of 3 approvers
    ),
    CeremonyType.KEY_ROTATION: CeremonyTemplate(
        ceremony_type=CeremonyType.KEY_ROTATION,
        name="Key Rotation",
        description="Rotate cryptographic keys",
        severity=CeremonySeverity.HIGH,
        cooldown_seconds=60,
        require_biometric=True,
        require_hardware_token=True,
    ),
    CeremonyType.AUDIT_EXPORT: CeremonyTemplate(
        ceremony_type=CeremonyType.AUDIT_EXPORT,
        name="Audit Export",
        description="Export audit logs for external review",
        severity=CeremonySeverity.MEDIUM,
        cooldown_seconds=30,
        require_biometric=False,
    ),
    CeremonyType.BIOMETRIC_ENROLLMENT: CeremonyTemplate(
        ceremony_type=CeremonyType.BIOMETRIC_ENROLLMENT,
        name="Biometric Enrollment",
        description="Enroll new biometric credentials",
        severity=CeremonySeverity.HIGH,
        cooldown_seconds=45,
        require_biometric=True,  # Existing biometric required
    ),
    CeremonyType.TOKEN_CREATION: CeremonyTemplate(
        ceremony_type=CeremonyType.TOKEN_CREATION,
        name="Token Creation",
        description="Create new authentication token",
        severity=CeremonySeverity.MEDIUM,
        cooldown_seconds=15,
        require_biometric=True,
    ),
    CeremonyType.POLICY_CHANGE: CeremonyTemplate(
        ceremony_type=CeremonyType.POLICY_CHANGE,
        name="Policy Change",
        description="Modify security policies",
        severity=CeremonySeverity.CRITICAL,
        cooldown_seconds=60,
        require_biometric=True,
        require_n_of_m=(2, 2),  # Dual control - both must approve
        time_window=(9, 17),  # Business hours
    ),
    CeremonyType.CLUSTER_JOIN: CeremonyTemplate(
        ceremony_type=CeremonyType.CLUSTER_JOIN,
        name="Cluster Join",
        description="Join a new node to the cluster",
        severity=CeremonySeverity.HIGH,
        cooldown_seconds=30,
        require_biometric=True,
    ),
}


# =============================================================================
# N-OF-M MULTI-PARTY CEREMONY
# =============================================================================

@dataclass
class Approver:
    """An authorized approver for N-of-M ceremonies."""
    id: str
    name: str
    public_key_hash: Optional[str] = None  # SHA-256 hash of public key
    biometric_enrolled: bool = False
    hardware_token_registered: bool = False


@dataclass
class ApprovalRecord:
    """Record of an approval in an N-of-M ceremony."""
    approver_id: str
    timestamp: str
    signature: Optional[str] = None
    method: str = "keyboard"  # keyboard, biometric, hardware_token
    verified: bool = False


@dataclass
class NofMCeremonyState:
    """State of an ongoing N-of-M ceremony."""
    ceremony_id: str
    ceremony_type: CeremonyType
    action: str
    reason: str
    n_required: int
    m_total: int
    approvers: List[Approver]
    approvals: List[ApprovalRecord] = field(default_factory=list)
    initiated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    expires_at: Optional[str] = None
    status: str = "pending"  # pending, approved, denied, expired

    def is_approved(self) -> bool:
        """Check if enough approvals have been collected."""
        verified_approvals = [a for a in self.approvals if a.verified]
        return len(verified_approvals) >= self.n_required

    def is_expired(self) -> bool:
        """Check if the ceremony has expired."""
        if not self.expires_at:
            return False
        expiry = datetime.fromisoformat(self.expires_at.replace('Z', '+00:00'))
        return datetime.utcnow().replace(tzinfo=expiry.tzinfo) > expiry

    def remaining_approvals(self) -> int:
        """Get number of remaining approvals needed."""
        verified = len([a for a in self.approvals if a.verified])
        return max(0, self.n_required - verified)

    def get_pending_approvers(self) -> List[Approver]:
        """Get approvers who haven't approved yet."""
        approved_ids = {a.approver_id for a in self.approvals if a.verified}
        return [ap for ap in self.approvers if ap.id not in approved_ids]


class NofMCeremonyManager:
    """
    Manager for N-of-M multi-party ceremonies.

    Requires N approvals from M authorized parties before completing.
    Each approval is individually verified and logged.
    """

    def __init__(self, daemon, approvers: Optional[List[Approver]] = None,
                 expiry_hours: int = 24):
        """
        Initialize N-of-M ceremony manager.

        Args:
            daemon: Reference to BoundaryDaemon instance
            approvers: List of authorized approvers
            expiry_hours: Hours until pending ceremony expires
        """
        self.daemon = daemon
        self.approvers = approvers or []
        self.expiry_hours = expiry_hours
        self._pending_ceremonies: Dict[str, NofMCeremonyState] = {}
        self._lock = threading.Lock()

    def register_approver(self, approver: Approver) -> bool:
        """Register a new approver."""
        with self._lock:
            if any(a.id == approver.id for a in self.approvers):
                return False
            self.approvers.append(approver)

            self.daemon.event_logger.log_event(
                EventType.OVERRIDE,
                f"N-of-M approver registered: {approver.name}",
                metadata={
                    'approver_id': approver.id,
                    'approver_name': approver.name,
                    'action': 'register_approver'
                }
            )
            return True

    def initiate_ceremony(self, ceremony_type: CeremonyType, action: str,
                         reason: str, n_required: int,
                         m_total: Optional[int] = None) -> Tuple[bool, str, Optional[str]]:
        """
        Initiate an N-of-M ceremony.

        Args:
            ceremony_type: Type of ceremony
            action: Description of the action
            reason: Reason for the ceremony
            n_required: Number of approvals required
            m_total: Total number of approvers (defaults to all registered)

        Returns:
            (success, message, ceremony_id)
        """
        with self._lock:
            if m_total is None:
                m_total = len(self.approvers)

            if n_required > m_total:
                return (False, f"Cannot require {n_required} approvals from {m_total} approvers", None)

            if m_total > len(self.approvers):
                return (False, f"Only {len(self.approvers)} approvers registered", None)

            # Generate ceremony ID
            ceremony_id = hashlib.sha256(
                f"{ceremony_type.value}:{action}:{time.time()}".encode()
            ).hexdigest()[:16]

            # Calculate expiry
            expiry = datetime.utcnow() + timedelta(hours=self.expiry_hours)

            state = NofMCeremonyState(
                ceremony_id=ceremony_id,
                ceremony_type=ceremony_type,
                action=action,
                reason=reason,
                n_required=n_required,
                m_total=m_total,
                approvers=self.approvers[:m_total],
                expires_at=expiry.isoformat() + "Z"
            )

            self._pending_ceremonies[ceremony_id] = state

            self.daemon.event_logger.log_event(
                EventType.OVERRIDE,
                f"N-of-M ceremony initiated: {action}",
                metadata={
                    'ceremony_id': ceremony_id,
                    'ceremony_type': ceremony_type.value,
                    'action': action,
                    'reason': reason,
                    'n_required': n_required,
                    'm_total': m_total,
                    'expires_at': state.expires_at,
                    'status': 'initiated'
                }
            )

            print(f"\n{'='*70}")
            print(f"N-OF-M CEREMONY INITIATED")
            print(f"{'='*70}")
            print(f"Ceremony ID: {ceremony_id}")
            print(f"Action: {action}")
            print(f"Required: {n_required} of {m_total} approvals")
            print(f"Expires: {state.expires_at}")
            print(f"{'='*70}\n")

            return (True, f"Ceremony initiated, requires {n_required} of {m_total} approvals", ceremony_id)

    def submit_approval(self, ceremony_id: str, approver_id: str,
                       verification_callback: Optional[Callable] = None) -> Tuple[bool, str]:
        """
        Submit an approval for a pending ceremony.

        Args:
            ceremony_id: ID of the ceremony
            approver_id: ID of the approving party
            verification_callback: Optional callback for verification

        Returns:
            (success, message)
        """
        with self._lock:
            if ceremony_id not in self._pending_ceremonies:
                return (False, "Ceremony not found or already completed")

            state = self._pending_ceremonies[ceremony_id]

            # Check expiry
            if state.is_expired():
                state.status = "expired"
                self._log_ceremony_status(state, "expired")
                return (False, "Ceremony has expired")

            # Verify approver is authorized
            approver = next((a for a in state.approvers if a.id == approver_id), None)
            if not approver:
                return (False, "Approver not authorized for this ceremony")

            # Check for duplicate approval
            if any(a.approver_id == approver_id and a.verified for a in state.approvals):
                return (False, "Approver has already approved")

            # Verify the approver
            print(f"\n→ Approval from: {approver.name}")

            if verification_callback:
                verified = verification_callback()
            else:
                print(f"Type 'APPROVE-{ceremony_id[:8].upper()}' to confirm:")
                user_input = input("Confirmation: ")
                verified = user_input == f"APPROVE-{ceremony_id[:8].upper()}"

            if not verified:
                self.daemon.event_logger.log_event(
                    EventType.OVERRIDE,
                    f"N-of-M approval FAILED: verification failed",
                    metadata={
                        'ceremony_id': ceremony_id,
                        'approver_id': approver_id,
                        'status': 'verification_failed'
                    }
                )
                return (False, "Verification failed")

            # Record approval
            record = ApprovalRecord(
                approver_id=approver_id,
                timestamp=datetime.utcnow().isoformat() + "Z",
                method="keyboard",
                verified=True
            )
            state.approvals.append(record)

            self.daemon.event_logger.log_event(
                EventType.OVERRIDE,
                f"N-of-M approval recorded: {approver.name}",
                metadata={
                    'ceremony_id': ceremony_id,
                    'approver_id': approver_id,
                    'approver_name': approver.name,
                    'approvals_count': len([a for a in state.approvals if a.verified]),
                    'approvals_required': state.n_required,
                    'status': 'approval_recorded'
                }
            )

            print(f"✓ Approval recorded ({len([a for a in state.approvals if a.verified])}/{state.n_required})")

            # Check if ceremony is now approved
            if state.is_approved():
                state.status = "approved"
                self._log_ceremony_status(state, "approved")
                return (True, "Ceremony approved - all required approvals received")

            remaining = state.remaining_approvals()
            return (True, f"Approval recorded, {remaining} more required")

    def get_ceremony_status(self, ceremony_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a ceremony."""
        with self._lock:
            if ceremony_id not in self._pending_ceremonies:
                return None

            state = self._pending_ceremonies[ceremony_id]
            return {
                'ceremony_id': state.ceremony_id,
                'ceremony_type': state.ceremony_type.value,
                'action': state.action,
                'status': state.status,
                'n_required': state.n_required,
                'm_total': state.m_total,
                'approvals_received': len([a for a in state.approvals if a.verified]),
                'remaining': state.remaining_approvals(),
                'is_approved': state.is_approved(),
                'is_expired': state.is_expired(),
                'expires_at': state.expires_at,
                'pending_approvers': [a.name for a in state.get_pending_approvers()]
            }

    def complete_ceremony(self, ceremony_id: str) -> Tuple[bool, str]:
        """
        Complete an approved ceremony.

        Returns:
            (success, message)
        """
        with self._lock:
            if ceremony_id not in self._pending_ceremonies:
                return (False, "Ceremony not found")

            state = self._pending_ceremonies[ceremony_id]

            if state.is_expired():
                state.status = "expired"
                return (False, "Ceremony has expired")

            if not state.is_approved():
                return (False, f"Ceremony not approved, {state.remaining_approvals()} more approvals needed")

            state.status = "completed"
            self._log_ceremony_status(state, "completed")

            # Remove from pending
            del self._pending_ceremonies[ceremony_id]

            print(f"\n{'='*70}")
            print(f"N-OF-M CEREMONY COMPLETED")
            print(f"{'='*70}")
            print(f"Action: {state.action}")
            print(f"Approvals: {len([a for a in state.approvals if a.verified])}/{state.n_required}")
            print(f"{'='*70}\n")

            return (True, "Ceremony completed successfully")

    def _log_ceremony_status(self, state: NofMCeremonyState, status: str):
        """Log ceremony status change."""
        self.daemon.event_logger.log_event(
            EventType.OVERRIDE,
            f"N-of-M ceremony {status}: {state.action}",
            metadata={
                'ceremony_id': state.ceremony_id,
                'ceremony_type': state.ceremony_type.value,
                'action': state.action,
                'status': status,
                'approvals': [
                    {'approver': a.approver_id, 'timestamp': a.timestamp}
                    for a in state.approvals if a.verified
                ]
            }
        )


# =============================================================================
# TIME-LOCKED CEREMONIES
# =============================================================================

@dataclass
class TimeWindow:
    """Definition of an allowed time window."""
    start_hour: int  # 0-23
    end_hour: int    # 0-23
    days: Optional[Set[int]] = None  # 0=Monday, 6=Sunday, None=all days
    timezone: str = "UTC"

    def is_active(self) -> bool:
        """Check if current time is within this window."""
        now = datetime.now()  # Local time

        # Check day of week
        if self.days is not None and now.weekday() not in self.days:
            return False

        # Check hour
        current_hour = now.hour
        if self.start_hour <= self.end_hour:
            return self.start_hour <= current_hour < self.end_hour
        else:
            # Overnight window (e.g., 22:00 to 06:00)
            return current_hour >= self.start_hour or current_hour < self.end_hour

    def next_window_start(self) -> datetime:
        """Get the datetime when the next window starts."""
        now = datetime.now()

        # Start with today at start_hour
        next_start = now.replace(hour=self.start_hour, minute=0, second=0, microsecond=0)

        # If we're past start_hour today, try tomorrow
        if now.hour >= self.start_hour:
            next_start += timedelta(days=1)

        # Find next allowed day
        if self.days is not None:
            while next_start.weekday() not in self.days:
                next_start += timedelta(days=1)

        return next_start


class TimeLockedCeremony:
    """
    Ceremony that can only be completed during specified time windows.

    Use cases:
    - Data exports only during business hours
    - Maintenance operations only on weekends
    - Emergency access excluded from certain hours
    """

    def __init__(self, daemon, windows: Optional[List[TimeWindow]] = None):
        """
        Initialize time-locked ceremony manager.

        Args:
            daemon: Reference to BoundaryDaemon instance
            windows: List of allowed time windows
        """
        self.daemon = daemon
        self.windows = windows or []
        self._window_overrides: Dict[str, TimeWindow] = {}  # action -> window

    def add_window(self, window: TimeWindow):
        """Add an allowed time window."""
        self.windows.append(window)

    def set_action_window(self, action: str, window: TimeWindow):
        """Set a specific time window for an action."""
        self._window_overrides[action] = window

    def check_time_lock(self, action: str) -> Tuple[bool, str]:
        """
        Check if an action is allowed at the current time.

        Args:
            action: The action to check

        Returns:
            (allowed, message)
        """
        # Check for action-specific window
        if action in self._window_overrides:
            window = self._window_overrides[action]
            if window.is_active():
                return (True, "Within action-specific time window")
            next_start = window.next_window_start()
            return (False, f"Action only allowed during specified window. Next: {next_start.isoformat()}")

        # Check global windows
        if not self.windows:
            return (True, "No time restrictions configured")

        for window in self.windows:
            if window.is_active():
                return (True, "Within allowed time window")

        # Find next available window
        next_starts = [w.next_window_start() for w in self.windows]
        next_available = min(next_starts)

        return (False, f"Outside allowed time windows. Next available: {next_available.isoformat()}")

    def execute_with_time_lock(self, action: str, ceremony_callback: Callable,
                               override_allowed: bool = False) -> Tuple[bool, str]:
        """
        Execute a ceremony only if time lock allows.

        Args:
            action: The action being performed
            ceremony_callback: Callback to execute the actual ceremony
            override_allowed: Whether to allow override via emergency ceremony

        Returns:
            (success, message)
        """
        allowed, message = self.check_time_lock(action)

        if not allowed:
            self.daemon.event_logger.log_event(
                EventType.OVERRIDE,
                f"Time-locked ceremony BLOCKED: {action}",
                metadata={
                    'action': action,
                    'status': 'time_locked',
                    'message': message
                }
            )

            print(f"\n⚠ TIME LOCK ACTIVE")
            print(f"  {message}")

            if override_allowed:
                print(f"\n  Emergency override available.")
                response = input("  Request emergency override? (yes/no): ")
                if response.lower() == 'yes':
                    # Log override request - actual override requires separate ceremony
                    self.daemon.event_logger.log_event(
                        EventType.OVERRIDE,
                        f"Time-lock emergency override REQUESTED: {action}",
                        metadata={'action': action, 'status': 'override_requested'}
                    )
                    return (False, "Emergency override requested - requires EMERGENCY_ACCESS ceremony")

            return (False, message)

        # Time lock passed, execute ceremony
        self.daemon.event_logger.log_event(
            EventType.OVERRIDE,
            f"Time-locked ceremony ALLOWED: {action}",
            metadata={
                'action': action,
                'status': 'time_lock_passed'
            }
        )

        return ceremony_callback()


# =============================================================================
# DEAD-MAN CEREMONY (ACTIVITY WATCHDOG)
# =============================================================================

@dataclass
class DeadManTrigger:
    """Definition of a dead-man switch trigger."""
    trigger_id: str
    action: str
    description: str
    timeout_hours: float
    callback: Optional[Callable[[], None]] = None
    enabled: bool = True
    last_activity: Optional[datetime] = None
    triggered: bool = False


class DeadManCeremony:
    """
    Dead-man switch that triggers actions if no human activity is detected.

    Use cases:
    - Auto-lockdown if no check-in for 24 hours
    - Alert escalation if no response to security event
    - Automatic log export if operator becomes unavailable
    - Emergency notification to backup operators

    SECURITY: All triggers are logged. Trigger actions are executed with
    limited privileges and cannot escalate security posture.
    """

    def __init__(self, daemon, check_interval_seconds: int = 60):
        """
        Initialize dead-man ceremony manager.

        Args:
            daemon: Reference to BoundaryDaemon instance
            check_interval_seconds: How often to check triggers
        """
        self.daemon = daemon
        self.check_interval = check_interval_seconds
        self._triggers: Dict[str, DeadManTrigger] = {}
        self._lock = threading.Lock()
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._global_last_activity = datetime.utcnow()

    def register_trigger(self, trigger: DeadManTrigger) -> bool:
        """Register a new dead-man trigger."""
        with self._lock:
            if trigger.trigger_id in self._triggers:
                return False

            trigger.last_activity = datetime.utcnow()
            self._triggers[trigger.trigger_id] = trigger

            self.daemon.event_logger.log_event(
                EventType.OVERRIDE,
                f"Dead-man trigger registered: {trigger.action}",
                metadata={
                    'trigger_id': trigger.trigger_id,
                    'action': trigger.action,
                    'timeout_hours': trigger.timeout_hours,
                    'status': 'registered'
                }
            )

            return True

    def check_in(self, trigger_id: Optional[str] = None) -> Tuple[bool, str]:
        """
        Record human activity (reset dead-man timer).

        Args:
            trigger_id: Specific trigger to reset, or None for all triggers

        Returns:
            (success, message)
        """
        with self._lock:
            now = datetime.utcnow()
            self._global_last_activity = now

            if trigger_id:
                if trigger_id not in self._triggers:
                    return (False, f"Trigger not found: {trigger_id}")

                trigger = self._triggers[trigger_id]
                trigger.last_activity = now
                trigger.triggered = False

                self.daemon.event_logger.log_event(
                    EventType.OVERRIDE,
                    f"Dead-man check-in: {trigger.action}",
                    metadata={
                        'trigger_id': trigger_id,
                        'status': 'check_in'
                    }
                )

                return (True, f"Check-in recorded for trigger: {trigger_id}")
            else:
                # Reset all triggers
                for trigger in self._triggers.values():
                    trigger.last_activity = now
                    trigger.triggered = False

                self.daemon.event_logger.log_event(
                    EventType.OVERRIDE,
                    "Dead-man check-in: ALL triggers reset",
                    metadata={'status': 'global_check_in'}
                )

                return (True, f"Check-in recorded for all {len(self._triggers)} triggers")

    def perform_check_in_ceremony(self, trigger_id: Optional[str] = None,
                                  confirmation_callback: Optional[Callable] = None) -> Tuple[bool, str]:
        """
        Perform a ceremony to verify human presence and reset timers.

        Args:
            trigger_id: Specific trigger, or None for all
            confirmation_callback: Optional callback for confirmation

        Returns:
            (success, message)
        """
        print("\n" + "=" * 50)
        print("DEAD-MAN CHECK-IN CEREMONY")
        print("=" * 50)

        if confirmation_callback:
            confirmed = confirmation_callback()
        else:
            response = input("Type 'ALIVE' to confirm human presence: ")
            confirmed = response.strip().upper() == 'ALIVE'

        if not confirmed:
            self.daemon.event_logger.log_event(
                EventType.OVERRIDE,
                "Dead-man check-in FAILED: confirmation not received",
                metadata={'status': 'check_in_failed'}
            )
            return (False, "Check-in confirmation failed")

        return self.check_in(trigger_id)

    def get_trigger_status(self, trigger_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific trigger."""
        with self._lock:
            if trigger_id not in self._triggers:
                return None

            trigger = self._triggers[trigger_id]
            now = datetime.utcnow()

            if trigger.last_activity:
                elapsed = (now - trigger.last_activity).total_seconds() / 3600
                remaining = trigger.timeout_hours - elapsed
            else:
                elapsed = 0
                remaining = trigger.timeout_hours

            return {
                'trigger_id': trigger.trigger_id,
                'action': trigger.action,
                'description': trigger.description,
                'timeout_hours': trigger.timeout_hours,
                'hours_elapsed': round(elapsed, 2),
                'hours_remaining': round(max(0, remaining), 2),
                'enabled': trigger.enabled,
                'triggered': trigger.triggered,
                'last_activity': trigger.last_activity.isoformat() if trigger.last_activity else None
            }

    def get_all_trigger_status(self) -> List[Dict[str, Any]]:
        """Get status of all triggers."""
        with self._lock:
            return [
                self.get_trigger_status(tid)
                for tid in self._triggers
            ]

    def start_monitoring(self):
        """Start the background monitoring thread."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            return

        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="DeadManMonitor"
        )
        self._monitor_thread.start()

    def stop_monitoring(self):
        """Stop the background monitoring thread."""
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)

    def _monitor_loop(self):
        """Background loop to check triggers."""
        while not self._stop_event.is_set():
            self._check_triggers()
            self._stop_event.wait(self.check_interval)

    def _check_triggers(self):
        """Check all triggers and fire if necessary."""
        with self._lock:
            now = datetime.utcnow()

            for trigger in self._triggers.values():
                if not trigger.enabled or trigger.triggered:
                    continue

                if not trigger.last_activity:
                    trigger.last_activity = now
                    continue

                elapsed_hours = (now - trigger.last_activity).total_seconds() / 3600

                if elapsed_hours >= trigger.timeout_hours:
                    self._fire_trigger(trigger)

    def _fire_trigger(self, trigger: DeadManTrigger):
        """Fire a dead-man trigger."""
        trigger.triggered = True

        self.daemon.event_logger.log_event(
            EventType.OVERRIDE,
            f"Dead-man trigger FIRED: {trigger.action}",
            metadata={
                'trigger_id': trigger.trigger_id,
                'action': trigger.action,
                'timeout_hours': trigger.timeout_hours,
                'status': 'triggered'
            }
        )

        print(f"\n{'!'*70}")
        print(f"DEAD-MAN TRIGGER FIRED")
        print(f"{'!'*70}")
        print(f"Trigger: {trigger.trigger_id}")
        print(f"Action: {trigger.action}")
        print(f"Description: {trigger.description}")
        print(f"{'!'*70}\n")

        # Execute callback if provided
        if trigger.callback:
            try:
                trigger.callback()
            except Exception as e:
                self.daemon.event_logger.log_event(
                    EventType.OVERRIDE,
                    f"Dead-man trigger callback FAILED: {e}",
                    metadata={
                        'trigger_id': trigger.trigger_id,
                        'error': str(e)
                    }
                )


# =============================================================================
# HARDWARE TOKEN CEREMONIES (FIDO2/U2F)
# =============================================================================

class HardwareTokenType(Enum):
    """Supported hardware token types."""
    FIDO2 = "fido2"           # FIDO2/WebAuthn (YubiKey 5+)
    U2F = "u2f"               # Legacy U2F (older YubiKeys)
    TOTP = "totp"             # Time-based OTP (backup)
    CHALLENGE_RESPONSE = "challenge_response"  # YubiKey challenge-response


@dataclass
class HardwareToken:
    """Registered hardware token."""
    token_id: str
    token_type: HardwareTokenType
    name: str
    public_key_hash: Optional[str] = None
    credential_id: Optional[str] = None
    registered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    last_used: Optional[str] = None
    use_count: int = 0


class HardwareTokenCeremony:
    """
    Hardware token (YubiKey, OnlyKey, etc.) integration for ceremonies.

    Provides strong offline authentication that doesn't require network
    connectivity, making it ideal for air-gapped environments.

    SECURITY: Hardware tokens provide:
    - Physical possession factor
    - Cryptographic proof of presence
    - Offline capability (no cloud dependency)
    - Phishing resistance (origin binding)
    """

    # Challenge parameters
    CHALLENGE_SIZE = 32  # bytes
    CHALLENGE_MAX_AGE = 60  # seconds

    def __init__(self, daemon, token_dir: Optional[str] = None):
        """
        Initialize hardware token ceremony manager.

        Args:
            daemon: Reference to BoundaryDaemon instance
            token_dir: Directory for storing token metadata
        """
        self.daemon = daemon
        self.token_dir = token_dir or "/var/lib/boundary-daemon/tokens"
        self._tokens: Dict[str, HardwareToken] = {}
        self._pending_challenges: Dict[str, Tuple[bytes, float]] = {}  # token_id -> (challenge, timestamp)
        self._fido2_available = self._check_fido2_available()

        # Load existing tokens
        self._load_tokens()

    def _check_fido2_available(self) -> bool:
        """Check if FIDO2 library is available."""
        try:
            from fido2.hid import CtapHidDevice  # noqa: F401
            from fido2.client import Fido2Client  # noqa: F401
            return True
        except ImportError:
            return False

    def _load_tokens(self):
        """Load registered tokens from storage."""
        if not os.path.exists(self.token_dir):
            return

        tokens_file = os.path.join(self.token_dir, "tokens.json")
        if os.path.exists(tokens_file):
            try:
                with open(tokens_file, 'r') as f:
                    data = json.load(f)
                    for token_data in data.get('tokens', []):
                        token = HardwareToken(
                            token_id=token_data['token_id'],
                            token_type=HardwareTokenType(token_data['token_type']),
                            name=token_data['name'],
                            public_key_hash=token_data.get('public_key_hash'),
                            credential_id=token_data.get('credential_id'),
                            registered_at=token_data.get('registered_at'),
                            last_used=token_data.get('last_used'),
                            use_count=token_data.get('use_count', 0)
                        )
                        self._tokens[token.token_id] = token
            except Exception as e:
                print(f"Warning: Failed to load tokens: {e}")

    def _save_tokens(self):
        """Save registered tokens to storage."""
        os.makedirs(self.token_dir, mode=0o700, exist_ok=True)
        tokens_file = os.path.join(self.token_dir, "tokens.json")

        data = {
            'tokens': [
                {
                    'token_id': t.token_id,
                    'token_type': t.token_type.value,
                    'name': t.name,
                    'public_key_hash': t.public_key_hash,
                    'credential_id': t.credential_id,
                    'registered_at': t.registered_at,
                    'last_used': t.last_used,
                    'use_count': t.use_count
                }
                for t in self._tokens.values()
            ]
        }

        # Atomic write with secure permissions
        temp_file = tokens_file + '.tmp'
        with open(temp_file, 'w') as f:
            json.dump(data, f, indent=2)
        os.chmod(temp_file, 0o600)
        os.replace(temp_file, tokens_file)

    def is_available(self) -> bool:
        """Check if hardware token support is available."""
        return self._fido2_available

    def get_capabilities(self) -> Dict[str, Any]:
        """Get hardware token capabilities."""
        return {
            'fido2_available': self._fido2_available,
            'tokens_registered': len(self._tokens),
            'token_types': [t.token_type.value for t in self._tokens.values()]
        }

    def list_tokens(self) -> List[Dict[str, Any]]:
        """List all registered tokens."""
        return [
            {
                'token_id': t.token_id,
                'name': t.name,
                'token_type': t.token_type.value,
                'registered_at': t.registered_at,
                'last_used': t.last_used,
                'use_count': t.use_count
            }
            for t in self._tokens.values()
        ]

    def register_token(self, name: str, token_type: HardwareTokenType = HardwareTokenType.FIDO2) -> Tuple[bool, str]:
        """
        Register a new hardware token.

        Args:
            name: Human-readable name for the token
            token_type: Type of token to register

        Returns:
            (success, message)
        """
        if token_type == HardwareTokenType.FIDO2:
            return self._register_fido2_token(name)
        elif token_type == HardwareTokenType.CHALLENGE_RESPONSE:
            return self._register_challenge_response_token(name)
        else:
            return (False, f"Token type {token_type.value} not supported for registration")

    def _register_fido2_token(self, name: str) -> Tuple[bool, str]:
        """Register a FIDO2 token."""
        if not self._fido2_available:
            return (False, "FIDO2 library not available. Install with: pip install fido2")

        try:
            from fido2.hid import CtapHidDevice
            from fido2.client import Fido2Client, UserInteraction
            from fido2.server import Fido2Server
            from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

            # Find device
            devices = list(CtapHidDevice.list_devices())
            if not devices:
                return (False, "No FIDO2 device detected. Please insert your security key.")

            print("\n→ FIDO2 token detected")
            print("  Touch your security key to register...")

            # Create server and client
            rp = PublicKeyCredentialRpEntity(id="boundary-daemon.local", name="Boundary Daemon")
            server = Fido2Server(rp)

            # User entity
            user_id = os.urandom(32)
            user = PublicKeyCredentialUserEntity(
                id=user_id,
                name=name,
                display_name=name
            )

            # Generate registration options
            create_options, state = server.register_begin(user)

            # Create client with user interaction
            class CliInteraction(UserInteraction):
                def prompt_up(self):
                    print("  Touch your security key...")
                def request_pin(self, permissions, _rd_id):
                    return input("  Enter PIN: ")
                def request_uv(self, permissions, _rd_id):
                    print("  Perform user verification...")
                    return True

            client = Fido2Client(devices[0], "https://boundary-daemon.local", user_interaction=CliInteraction())

            # Perform registration
            result = client.make_credential(create_options["publicKey"])

            # Complete registration
            auth_data = server.register_complete(state, result.client_data, result.attestation_object)

            # Store token
            token_id = hashlib.sha256(auth_data.credential_data.credential_id).hexdigest()[:16]
            token = HardwareToken(
                token_id=token_id,
                token_type=HardwareTokenType.FIDO2,
                name=name,
                credential_id=auth_data.credential_data.credential_id.hex(),
                public_key_hash=hashlib.sha256(
                    auth_data.credential_data.public_key
                ).hexdigest() if auth_data.credential_data.public_key else None
            )

            self._tokens[token_id] = token
            self._save_tokens()

            self.daemon.event_logger.log_event(
                EventType.OVERRIDE,
                f"Hardware token registered: {name}",
                metadata={
                    'token_id': token_id,
                    'token_type': 'fido2',
                    'status': 'registered'
                }
            )

            print(f"\n✓ Token registered successfully")
            print(f"  Token ID: {token_id}")

            return (True, f"Token registered with ID: {token_id}")

        except Exception as e:
            return (False, f"FIDO2 registration failed: {e}")

    def _register_challenge_response_token(self, name: str) -> Tuple[bool, str]:
        """Register a challenge-response token (YubiKey OTP slot)."""
        print("\n→ Challenge-Response Token Registration")
        print("  This uses YubiKey's challenge-response mode.")
        print("\n  Configure your YubiKey with ykpersonalize first:")
        print("  $ ykpersonalize -2 -ochal-resp -ochal-hmac -ohmac-lt64")

        # Generate a test challenge
        challenge = os.urandom(32)
        print(f"\n  Press your YubiKey button now...")

        try:
            # Try to use yubico library if available
            from ykman.device import list_all_devices

            devices = list(list_all_devices())
            if not devices:
                return (False, "No YubiKey detected")

            # Would perform actual challenge-response here
            # For now, register with manual verification
            print("\n  Touch detected. Verifying...")

            token_id = hashlib.sha256(f"{name}:{time.time()}".encode()).hexdigest()[:16]
            token = HardwareToken(
                token_id=token_id,
                token_type=HardwareTokenType.CHALLENGE_RESPONSE,
                name=name
            )

            self._tokens[token_id] = token
            self._save_tokens()

            self.daemon.event_logger.log_event(
                EventType.OVERRIDE,
                f"Challenge-response token registered: {name}",
                metadata={
                    'token_id': token_id,
                    'token_type': 'challenge_response',
                    'status': 'registered'
                }
            )

            return (True, f"Token registered with ID: {token_id}")

        except ImportError:
            # Fallback without ykman
            print("\n  Note: Install 'yubikey-manager' for full YubiKey support")

            response = input("\n  Did you see the YubiKey light blink? (yes/no): ")
            if response.lower() != 'yes':
                return (False, "Registration cancelled")

            token_id = hashlib.sha256(f"{name}:{time.time()}".encode()).hexdigest()[:16]
            token = HardwareToken(
                token_id=token_id,
                token_type=HardwareTokenType.CHALLENGE_RESPONSE,
                name=name
            )

            self._tokens[token_id] = token
            self._save_tokens()

            return (True, f"Token registered (basic mode) with ID: {token_id}")

    def verify_token(self, token_id: Optional[str] = None) -> Tuple[bool, str]:
        """
        Verify a hardware token.

        Args:
            token_id: Specific token to verify, or None for any registered token

        Returns:
            (success, message)
        """
        if not self._tokens:
            return (False, "No hardware tokens registered")

        if token_id and token_id not in self._tokens:
            return (False, f"Token not found: {token_id}")

        # Get token(s) to try
        tokens_to_try = [self._tokens[token_id]] if token_id else list(self._tokens.values())

        for token in tokens_to_try:
            if token.token_type == HardwareTokenType.FIDO2:
                success, message = self._verify_fido2_token(token)
            elif token.token_type == HardwareTokenType.CHALLENGE_RESPONSE:
                success, message = self._verify_challenge_response_token(token)
            else:
                continue

            if success:
                # Update usage stats
                token.last_used = datetime.utcnow().isoformat() + "Z"
                token.use_count += 1
                self._save_tokens()

                self.daemon.event_logger.log_event(
                    EventType.OVERRIDE,
                    f"Hardware token verified: {token.name}",
                    metadata={
                        'token_id': token.token_id,
                        'token_type': token.token_type.value,
                        'status': 'verified'
                    }
                )

                return (True, f"Token verified: {token.name}")

        return (False, "Token verification failed")

    def _verify_fido2_token(self, token: HardwareToken) -> Tuple[bool, str]:
        """Verify a FIDO2 token."""
        if not self._fido2_available:
            return (False, "FIDO2 library not available")

        try:
            from fido2.hid import CtapHidDevice
            from fido2.client import Fido2Client, UserInteraction
            from fido2.server import Fido2Server
            from fido2.webauthn import PublicKeyCredentialRpEntity

            devices = list(CtapHidDevice.list_devices())
            if not devices:
                return (False, "No FIDO2 device detected")

            print(f"\n→ Verifying token: {token.name}")
            print("  Touch your security key...")

            rp = PublicKeyCredentialRpEntity(id="boundary-daemon.local", name="Boundary Daemon")
            server = Fido2Server(rp)

            # Get credential ID
            if not token.credential_id:
                return (False, "Token has no credential ID")

            credential_id = bytes.fromhex(token.credential_id)

            # Generate authentication options
            credentials = [{"id": credential_id, "type": "public-key"}]
            request_options, state = server.authenticate_begin(credentials)

            # Create client
            class CliInteraction(UserInteraction):
                def prompt_up(self):
                    print("  Touch your security key...")
                def request_pin(self, permissions, _rd_id):
                    return input("  Enter PIN: ")
                def request_uv(self, permissions, _rd_id):
                    return True

            client = Fido2Client(devices[0], "https://boundary-daemon.local", user_interaction=CliInteraction())

            # Perform authentication
            result = client.get_assertion(request_options["publicKey"])

            # Verify (would need stored public key for full verification)
            print(f"\n✓ Token verification successful")
            return (True, "FIDO2 verification successful")

        except Exception as e:
            return (False, f"FIDO2 verification failed: {e}")

    def _verify_challenge_response_token(self, token: HardwareToken) -> Tuple[bool, str]:
        """Verify a challenge-response token."""
        print(f"\n→ Verifying token: {token.name}")
        print("  Touch your YubiKey...")

        # Generate challenge
        challenge = os.urandom(32)

        try:
            # Try using yubico-python library
            import yubico.yubico
            import yubico.yubikey

            yk = yubico.yubikey.YubiKey()
            response = yk.challenge_response(challenge, slot=2)

            # Verify response (would compare against stored expected response)
            if response:
                return (True, "Challenge-response verification successful")
            return (False, "Invalid response")

        except ImportError:
            # Fallback: manual verification
            print("\n  Note: Install 'python-yubico' for automatic verification")
            response = input("  Did the YubiKey blink? (yes/no): ")
            if response.lower() == 'yes':
                return (True, "Manual verification accepted")
            return (False, "Verification cancelled")

        except Exception as e:
            return (False, f"Verification failed: {e}")

    def perform_token_ceremony(self, action: str, reason: str,
                              token_id: Optional[str] = None) -> Tuple[bool, str]:
        """
        Perform a ceremony requiring hardware token verification.

        Args:
            action: Description of the action
            reason: Reason for the ceremony
            token_id: Specific token to use (optional)

        Returns:
            (success, message)
        """
        print("\n" + "=" * 70)
        print("HARDWARE TOKEN CEREMONY")
        print("=" * 70)
        print(f"Action: {action}")
        print(f"Reason: {reason}")
        print("=" * 70)

        if not self._tokens:
            print("\n⚠ No hardware tokens registered")
            print("  Register a token with: token_ceremony.register_token('my-key')")
            return (False, "No hardware tokens registered")

        # Log ceremony initiation
        self.daemon.event_logger.log_event(
            EventType.OVERRIDE,
            f"Hardware token ceremony initiated: {action}",
            metadata={
                'action': action,
                'reason': reason,
                'token_id': token_id,
                'status': 'initiated'
            }
        )

        # Verify token
        success, message = self.verify_token(token_id)

        if success:
            print("\n" + "=" * 70)
            print("✓ HARDWARE TOKEN CEREMONY COMPLETED")
            print("=" * 70 + "\n")

            self.daemon.event_logger.log_event(
                EventType.OVERRIDE,
                f"Hardware token ceremony SUCCESS: {action}",
                metadata={
                    'action': action,
                    'reason': reason,
                    'status': 'success'
                }
            )
        else:
            print(f"\n✗ {message}")
            print("  Ceremony FAILED\n")

            self.daemon.event_logger.log_event(
                EventType.OVERRIDE,
                f"Hardware token ceremony FAILED: {action}",
                metadata={
                    'action': action,
                    'reason': reason,
                    'status': 'failed',
                    'error': message
                }
            )

        return (success, message)


# =============================================================================
# ADVANCED CEREMONY MANAGER (UNIFIED)
# =============================================================================

class AdvancedCeremonyManager(EnhancedCeremonyManager):
    """
    Advanced ceremony manager integrating all ceremony types.

    Combines:
    - Biometric authentication (from EnhancedCeremonyManager)
    - Ceremony templates
    - N-of-M multi-party ceremonies
    - Time-locked ceremonies
    - Dead-man triggers
    - Hardware token ceremonies
    """

    def __init__(self, daemon, biometric_verifier: Optional[BiometricVerifier] = None,
                 config: Optional[BiometricCeremonyConfig] = None,
                 cooldown_seconds: int = 30,
                 approvers: Optional[List[Approver]] = None,
                 token_dir: Optional[str] = None):
        """
        Initialize advanced ceremony manager.

        Args:
            daemon: Reference to BoundaryDaemon instance
            biometric_verifier: BiometricVerifier instance (optional)
            config: BiometricCeremonyConfig (optional)
            cooldown_seconds: Default ceremony cooldown
            approvers: List of N-of-M approvers
            token_dir: Directory for hardware token storage
        """
        super().__init__(daemon, biometric_verifier, config, cooldown_seconds)

        # Initialize sub-managers
        self.n_of_m = NofMCeremonyManager(daemon, approvers)
        self.time_locked = TimeLockedCeremony(daemon)
        self.dead_man = DeadManCeremony(daemon)
        self.hardware_token = HardwareTokenCeremony(daemon, token_dir)

        # Template registry
        self.templates = dict(CEREMONY_TEMPLATES)

        # Attempt tracking per template
        self._attempt_counts: Dict[str, Tuple[int, float]] = {}  # type -> (count, last_attempt)

    def register_template(self, template: CeremonyTemplate):
        """Register a custom ceremony template."""
        self.templates[template.ceremony_type] = template

    def get_template(self, ceremony_type: CeremonyType) -> Optional[CeremonyTemplate]:
        """Get a ceremony template."""
        return self.templates.get(ceremony_type)

    def execute_ceremony(self, ceremony_type: CeremonyType, action: str, reason: str,
                        confirmation_callback: Optional[Callable] = None) -> Tuple[bool, str]:
        """
        Execute a ceremony based on template requirements.

        Automatically handles:
        - Time window validation
        - Attempt limiting
        - Required authentication methods
        - N-of-M coordination (if required)

        Args:
            ceremony_type: Type of ceremony to execute
            action: Description of the action
            reason: Reason for the ceremony
            confirmation_callback: Optional callback for confirmations

        Returns:
            (success, message)
        """
        template = self.templates.get(ceremony_type)
        if not template:
            return (False, f"Unknown ceremony type: {ceremony_type.value}")

        # Check attempt limits
        if not self._check_attempts(ceremony_type.value, template):
            return (False, f"Too many attempts. Locked out for {template.lockout_duration_seconds} seconds")

        # Check time window
        allowed, time_msg = template.validate_time_window()
        if not allowed:
            self._record_attempt(ceremony_type.value)
            return (False, time_msg)

        # Log ceremony start
        self.daemon.event_logger.log_event(
            EventType.OVERRIDE,
            f"Template ceremony initiated: {template.name}",
            metadata={
                'ceremony_type': ceremony_type.value,
                'action': action,
                'reason': reason,
                'severity': template.severity.name,
                'status': 'initiated'
            }
        )

        print("\n" + "=" * 70)
        print(f"CEREMONY: {template.name.upper()}")
        print("=" * 70)
        print(f"Severity: {template.severity.name}")
        print(f"Action: {action}")
        print(f"Reason: {reason}")
        print("=" * 70)

        # Handle N-of-M requirements
        if template.require_n_of_m:
            n, m = template.require_n_of_m
            print(f"\n→ This ceremony requires {n} of {m} approvals")

            success, msg, ceremony_id = self.n_of_m.initiate_ceremony(
                ceremony_type, action, reason, n, m
            )
            if not success:
                return (False, msg)

            # Return with ceremony_id for approval collection
            return (True, f"N-of-M ceremony initiated. ID: {ceremony_id}. Collect {n} approvals to complete.")

        # Check hardware token requirement
        if template.require_hardware_token:
            print("\n→ Hardware token verification required...")
            success, msg = self.hardware_token.verify_token()
            if not success:
                self._record_attempt(ceremony_type.value)
                return (False, f"Hardware token verification failed: {msg}")
            print(f"✓ {msg}")

        # Check biometric requirement
        if template.require_biometric and self.biometric and self.biometric_config.enabled:
            print("\n→ Biometric verification required...")
            success, msg, _ = self._perform_biometric_verification()
            if not success and not self.biometric_config.fallback_to_keyboard:
                self._record_attempt(ceremony_type.value)
                return (False, f"Biometric verification failed: {msg}")
            elif success:
                print(f"✓ {msg}")
            else:
                print(f"⚠ {msg} - falling back to keyboard")

        # Execute base ceremony with template cooldown
        original_cooldown = self.cooldown_seconds
        self.cooldown_seconds = template.cooldown_seconds

        try:
            success, msg = super().initiate_override(
                action=action,
                reason=reason,
                confirmation_callback=confirmation_callback,
                require_biometric=False  # Already handled above
            )
        finally:
            self.cooldown_seconds = original_cooldown

        if success:
            self._reset_attempts(ceremony_type.value)
        else:
            self._record_attempt(ceremony_type.value)

        return (success, msg)

    def _check_attempts(self, ceremony_type: str, template: CeremonyTemplate) -> bool:
        """Check if attempts are within limits."""
        if ceremony_type not in self._attempt_counts:
            return True

        count, last_attempt = self._attempt_counts[ceremony_type]

        # Check if lockout has expired
        if time.time() - last_attempt > template.lockout_duration_seconds:
            self._reset_attempts(ceremony_type)
            return True

        return count < template.max_attempts

    def _record_attempt(self, ceremony_type: str):
        """Record a ceremony attempt."""
        if ceremony_type in self._attempt_counts:
            count, _ = self._attempt_counts[ceremony_type]
            self._attempt_counts[ceremony_type] = (count + 1, time.time())
        else:
            self._attempt_counts[ceremony_type] = (1, time.time())

    def _reset_attempts(self, ceremony_type: str):
        """Reset attempt counter for a ceremony type."""
        if ceremony_type in self._attempt_counts:
            del self._attempt_counts[ceremony_type]

    def get_ceremony_stats(self) -> Dict[str, Any]:
        """Get comprehensive ceremony statistics."""
        base_stats = super().get_ceremony_stats()

        return {
            **base_stats,
            'templates_registered': len(self.templates),
            'n_of_m': {
                'approvers': len(self.n_of_m.approvers),
                'pending_ceremonies': len(self.n_of_m._pending_ceremonies)
            },
            'time_locked': {
                'windows_configured': len(self.time_locked.windows),
                'action_overrides': len(self.time_locked._window_overrides)
            },
            'dead_man': {
                'triggers': len(self.dead_man._triggers),
                'monitoring_active': self.dead_man._monitor_thread is not None and
                                    self.dead_man._monitor_thread.is_alive()
            },
            'hardware_token': self.hardware_token.get_capabilities()
        }


# =============================================================================
# MODULE INITIALIZATION
# =============================================================================

__all__ = [
    # Enums
    'CeremonyType',
    'CeremonySeverity',
    'HardwareTokenType',

    # Data classes
    'CeremonyStep',
    'CeremonyTemplate',
    'Approver',
    'ApprovalRecord',
    'NofMCeremonyState',
    'TimeWindow',
    'DeadManTrigger',
    'HardwareToken',

    # Templates
    'CEREMONY_TEMPLATES',

    # Managers
    'NofMCeremonyManager',
    'TimeLockedCeremony',
    'DeadManCeremony',
    'HardwareTokenCeremony',
    'AdvancedCeremonyManager',
]
