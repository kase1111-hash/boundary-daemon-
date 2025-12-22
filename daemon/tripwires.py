"""
Tripwires - Security Violation Detection and Lockdown
Monitors for security violations and triggers immediate lockdown.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional, Callable
import threading

from .state_monitor import EnvironmentState, NetworkState
from .policy_engine import BoundaryMode


class ViolationType(Enum):
    """Types of security violations"""
    NETWORK_IN_AIRGAP = "network_in_airgap"
    USB_IN_COLDROOM = "usb_in_coldroom"
    UNAUTHORIZED_RECALL = "unauthorized_recall"
    DAEMON_TAMPERING = "daemon_tampering"
    MODE_INCOMPATIBLE = "mode_incompatible"
    EXTERNAL_MODEL_VIOLATION = "external_model_violation"
    SUSPICIOUS_PROCESS = "suspicious_process"
    HARDWARE_TRUST_DEGRADED = "hardware_trust_degraded"


@dataclass
class TripwireViolation:
    """Record of a tripwire violation"""
    violation_id: str
    timestamp: str
    violation_type: ViolationType
    details: str
    current_mode: BoundaryMode
    environment_snapshot: dict
    auto_lockdown: bool


class TripwireSystem:
    """
    Monitors for security violations and triggers immediate lockdown.

    Tripwires are fail-deadly: any violation triggers LOCKDOWN mode
    and requires human intervention to recover.
    """

    def __init__(self):
        """Initialize tripwire system"""
        self._lock = threading.Lock()
        self._violations: List[TripwireViolation] = []
        self._callbacks: List[Callable] = []
        self._enabled = True

        # Baseline tracking for change detection
        self._baseline_usb_devices: Optional[set] = None
        self._previous_mode: Optional[BoundaryMode] = None
        self._previous_network_state: Optional[NetworkState] = None

    def register_callback(self, callback: Callable):
        """
        Register a callback for tripwire violations.

        Args:
            callback: Function accepting (violation: TripwireViolation)
        """
        self._callbacks.append(callback)

    def enable(self):
        """Enable tripwire monitoring"""
        with self._lock:
            self._enabled = True

    def disable(self):
        """Disable tripwire monitoring (use with extreme caution)"""
        with self._lock:
            self._enabled = False

    def is_enabled(self) -> bool:
        """Check if tripwires are enabled"""
        with self._lock:
            return self._enabled

    def check_violations(self, current_mode: BoundaryMode,
                        env_state: EnvironmentState) -> Optional[TripwireViolation]:
        """
        Check for tripwire violations.

        Args:
            current_mode: Current boundary mode
            env_state: Current environment state

        Returns:
            TripwireViolation if violation detected, None otherwise
        """
        if not self._enabled:
            return None

        with self._lock:
            # Initialize baselines on first check
            first_check = False
            if self._baseline_usb_devices is None:
                self._baseline_usb_devices = env_state.usb_devices.copy()
                self._previous_mode = current_mode
                self._previous_network_state = env_state.network
                first_check = True
                # Don't return early - still check for obvious violations!

            # Check for network coming online in AIRGAP+ mode
            violation = self._check_network_in_airgap(current_mode, env_state)
            if violation:
                return self._record_violation(violation, current_mode, env_state)

            # Check for USB insertion in COLDROOM mode
            violation = self._check_usb_in_coldroom(current_mode, env_state)
            if violation:
                return self._record_violation(violation, current_mode, env_state)

            # Check for external model violations
            violation = self._check_external_model_violations(current_mode, env_state)
            if violation:
                return self._record_violation(violation, current_mode, env_state)

            # Check for suspicious processes
            violation = self._check_suspicious_processes(current_mode, env_state)
            if violation:
                return self._record_violation(violation, current_mode, env_state)

            # Check for hardware trust degradation
            violation = self._check_hardware_trust(current_mode, env_state)
            if violation:
                return self._record_violation(violation, current_mode, env_state)

            # Update state for next check
            self._previous_mode = current_mode
            self._previous_network_state = env_state.network

            return None

    def _check_network_in_airgap(self, mode: BoundaryMode,
                                 env_state: EnvironmentState) -> Optional[tuple]:
        """Check if network came online in AIRGAP+ mode"""
        if mode >= BoundaryMode.AIRGAP:
            # Check if network just came online
            if (self._previous_network_state == NetworkState.OFFLINE and
                env_state.network == NetworkState.ONLINE):
                return (
                    ViolationType.NETWORK_IN_AIRGAP,
                    f"Network came online while in {mode.name} mode. "
                    f"Interfaces: {env_state.active_interfaces}"
                )

            # Also check if currently online (shouldn't be in AIRGAP+)
            if env_state.network == NetworkState.ONLINE:
                return (
                    ViolationType.NETWORK_IN_AIRGAP,
                    f"Network is online while in {mode.name} mode. "
                    f"Interfaces: {env_state.active_interfaces}"
                )

        return None

    def _check_usb_in_coldroom(self, mode: BoundaryMode,
                               env_state: EnvironmentState) -> Optional[tuple]:
        """Check for USB insertion in COLDROOM mode"""
        if mode >= BoundaryMode.COLDROOM:
            # Check for new USB devices
            if self._baseline_usb_devices is not None:
                new_devices = env_state.usb_devices - self._baseline_usb_devices
                if new_devices:
                    return (
                        ViolationType.USB_IN_COLDROOM,
                        f"USB device(s) inserted in {mode.name} mode: {new_devices}"
                    )

            # Also check for new block devices (could be USB storage)
            # This would require tracking block device baseline too
            pass

        return None

    def _check_external_model_violations(self, mode: BoundaryMode,
                                        env_state: EnvironmentState) -> Optional[tuple]:
        """Check for external model endpoint violations"""
        if mode >= BoundaryMode.AIRGAP:
            # No external models allowed in AIRGAP+
            if env_state.external_model_endpoints:
                return (
                    ViolationType.EXTERNAL_MODEL_VIOLATION,
                    f"External model endpoints detected in {mode.name} mode: "
                    f"{env_state.external_model_endpoints}"
                )

        return None

    def _check_suspicious_processes(self, mode: BoundaryMode,
                                   env_state: EnvironmentState) -> Optional[tuple]:
        """Check for suspicious process activity"""
        # High threshold for shell escapes
        if env_state.shell_escapes_detected > 10:
            return (
                ViolationType.SUSPICIOUS_PROCESS,
                f"Excessive shell escape attempts detected: {env_state.shell_escapes_detected}"
            )

        # Check for privilege escalation in restricted modes
        if mode >= BoundaryMode.TRUSTED and env_state.suspicious_processes:
            return (
                ViolationType.SUSPICIOUS_PROCESS,
                f"Suspicious processes detected in {mode.name} mode: "
                f"{env_state.suspicious_processes}"
            )

        return None

    def _check_hardware_trust(self, mode: BoundaryMode,
                             env_state: EnvironmentState) -> Optional[tuple]:
        """Check for hardware trust degradation"""
        # In high-security modes, require high hardware trust
        if mode >= BoundaryMode.AIRGAP:
            from .state_monitor import HardwareTrust
            if env_state.hardware_trust == HardwareTrust.LOW:
                return (
                    ViolationType.HARDWARE_TRUST_DEGRADED,
                    f"Hardware trust degraded to LOW in {mode.name} mode"
                )

        return None

    def _record_violation(self, violation_info: tuple,
                         current_mode: BoundaryMode,
                         env_state: EnvironmentState) -> TripwireViolation:
        """Record a violation and notify callbacks"""
        violation_type, details = violation_info

        violation = TripwireViolation(
            violation_id=self._generate_violation_id(),
            timestamp=datetime.utcnow().isoformat() + "Z",
            violation_type=violation_type,
            details=details,
            current_mode=current_mode,
            environment_snapshot=env_state.to_dict(),
            auto_lockdown=True  # All violations trigger lockdown
        )

        self._violations.append(violation)

        # Notify all callbacks
        for callback in self._callbacks:
            try:
                callback(violation)
            except Exception as e:
                print(f"Error in tripwire callback: {e}")

        return violation

    def _generate_violation_id(self) -> str:
        """Generate a unique violation ID"""
        import uuid
        return str(uuid.uuid4())

    def get_violations(self) -> List[TripwireViolation]:
        """Get all recorded violations"""
        with self._lock:
            return self._violations.copy()

    def get_violation_count(self) -> int:
        """Get total number of violations"""
        with self._lock:
            return len(self._violations)

    def clear_violations(self):
        """Clear all recorded violations (requires human authorization)"""
        with self._lock:
            self._violations.clear()

    def check_daemon_health(self) -> bool:
        """
        Check if the daemon itself is healthy.
        This is called periodically to detect tampering.

        Returns:
            True if healthy, False if tampering detected
        """
        # Check if this process is still running with correct privileges
        # Check if configuration files haven't been modified
        # Check if critical files are intact
        # This is a placeholder for more sophisticated checks

        import os
        import sys

        # Basic sanity checks
        if not os.path.exists('/proc/self'):
            return False

        # Check if we're still running as expected
        try:
            pid = os.getpid()
            if pid <= 0:
                return False
        except Exception:
            return False

        return True

    def simulate_violation(self, violation_type: ViolationType,
                          details: str,
                          current_mode: BoundaryMode) -> TripwireViolation:
        """
        Simulate a violation for testing purposes.

        Args:
            violation_type: Type of violation
            details: Details about the violation
            current_mode: Current boundary mode

        Returns:
            The simulated violation
        """
        from .state_monitor import EnvironmentState, NetworkState, HardwareTrust

        # Create a dummy environment state
        env_state = EnvironmentState(
            timestamp=datetime.utcnow().isoformat() + "Z",
            network=NetworkState.OFFLINE,
            hardware_trust=HardwareTrust.MEDIUM,
            active_interfaces=[],
            has_internet=False,
            vpn_active=False,
            dns_available=False,
            usb_devices=set(),
            block_devices=set(),
            camera_available=False,
            mic_available=False,
            tpm_present=False,
            external_model_endpoints=[],
            suspicious_processes=[],
            shell_escapes_detected=0,
            keyboard_active=False,
            screen_unlocked=False,
            last_activity=None
        )

        return self._record_violation(
            (violation_type, details),
            current_mode,
            env_state
        )


class LockdownManager:
    """
    Manages lockdown state and recovery.
    When a tripwire is triggered, the system enters LOCKDOWN mode.
    """

    def __init__(self):
        """Initialize lockdown manager"""
        self._lock = threading.Lock()
        self._in_lockdown = False
        self._lockdown_reason: Optional[str] = None
        self._lockdown_timestamp: Optional[str] = None
        self._lockdown_violation: Optional[TripwireViolation] = None

    def trigger_lockdown(self, violation: TripwireViolation):
        """
        Trigger lockdown mode.

        Args:
            violation: The violation that triggered lockdown
        """
        with self._lock:
            if self._in_lockdown:
                # Already in lockdown
                return

            self._in_lockdown = True
            self._lockdown_reason = violation.details
            self._lockdown_timestamp = datetime.utcnow().isoformat() + "Z"
            self._lockdown_violation = violation

            print(f"\n{'='*70}")
            print(f"LOCKDOWN TRIGGERED")
            print(f"{'='*70}")
            print(f"Reason: {violation.violation_type.value}")
            print(f"Details: {violation.details}")
            print(f"Time: {self._lockdown_timestamp}")
            print(f"{'='*70}\n")

    def is_in_lockdown(self) -> bool:
        """Check if system is in lockdown"""
        with self._lock:
            return self._in_lockdown

    def get_lockdown_info(self) -> Optional[dict]:
        """Get lockdown information"""
        with self._lock:
            if not self._in_lockdown:
                return None

            return {
                'in_lockdown': True,
                'reason': self._lockdown_reason,
                'timestamp': self._lockdown_timestamp,
                'violation': {
                    'type': self._lockdown_violation.violation_type.value,
                    'details': self._lockdown_violation.details,
                    'violation_id': self._lockdown_violation.violation_id
                } if self._lockdown_violation else None
            }

    def release_lockdown(self, operator: str, reason: str) -> bool:
        """
        Release lockdown mode (requires human authorization).

        Args:
            operator: Who is releasing lockdown
            reason: Reason for release

        Returns:
            True if successful
        """
        with self._lock:
            if not self._in_lockdown:
                return False

            self._in_lockdown = False
            print(f"\nLockdown released by {operator}")
            print(f"Reason: {reason}\n")
            return True


if __name__ == '__main__':
    # Test tripwire system
    print("Testing Tripwire System...")

    tripwires = TripwireSystem()
    lockdown_mgr = LockdownManager()

    # Register callback to trigger lockdown
    def on_violation(violation: TripwireViolation):
        print(f"\n*** VIOLATION DETECTED ***")
        print(f"Type: {violation.violation_type.value}")
        print(f"Details: {violation.details}")
        lockdown_mgr.trigger_lockdown(violation)

    tripwires.register_callback(on_violation)

    # Simulate a violation
    print("\nSimulating network violation in AIRGAP mode...")
    violation = tripwires.simulate_violation(
        ViolationType.NETWORK_IN_AIRGAP,
        "Network interface eth0 came online",
        BoundaryMode.AIRGAP
    )

    # Check lockdown status
    print(f"\nIn lockdown: {lockdown_mgr.is_in_lockdown()}")
    info = lockdown_mgr.get_lockdown_info()
    if info:
        print(f"Lockdown info: {info}")

    print("\nTripwire system test complete.")
