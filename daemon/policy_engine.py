"""
Policy Engine - Boundary Mode and Policy Enforcement
Manages boundary modes and evaluates policies for recall gating and tool restrictions.
"""

import logging
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum, IntEnum
from typing import Optional, Dict, List, Tuple
import threading

from .state_monitor import NetworkState, HardwareTrust, EnvironmentState

logger = logging.getLogger(__name__)


class BoundaryMode(IntEnum):
    """
    Boundary modes define the trust level and restrictions.
    Higher numeric values = stricter security.
    """
    OPEN = 0         # Networked, low trust
    RESTRICTED = 1   # Network allowed, memory limited
    TRUSTED = 2      # Offline or verified LAN
    AIRGAP = 3       # Physically isolated
    COLDROOM = 4     # No IO except keyboard/display
    LOCKDOWN = 5     # Emergency freeze


class MemoryClass(IntEnum):
    """Memory classification levels (0-5)"""
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3
    TOP_SECRET = 4
    CROWN_JEWEL = 5


class Operator(Enum):
    """Who initiated a mode transition"""
    HUMAN = "human"
    SYSTEM = "system"


class PolicyDecision(Enum):
    """Policy evaluation result"""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_CEREMONY = "require_ceremony"


@dataclass
class BoundaryState:
    """Complete boundary state"""
    mode: BoundaryMode
    network: NetworkState
    hardware_trust: HardwareTrust
    external_models: bool
    last_transition: str
    operator: Operator

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'mode': self.mode.name.lower(),
            'network': self.network.value,
            'hardware_trust': self.hardware_trust.value,
            'external_models': self.external_models,
            'last_transition': self.last_transition,
            'operator': self.operator.value
        }


@dataclass
class PolicyRequest:
    """Request for policy evaluation"""
    request_type: str  # 'recall', 'tool', 'model', 'io'
    memory_class: Optional[MemoryClass] = None
    tool_name: Optional[str] = None
    requires_network: bool = False
    requires_filesystem: bool = False
    requires_usb: bool = False


class PolicyEngine:
    """
    Evaluates policies based on (mode × signal × request) → decision.
    Enforces fail-closed, deterministic policies.
    """

    def __init__(self, initial_mode: BoundaryMode = BoundaryMode.OPEN):
        """Initialize policy engine with a starting mode"""
        self._state_lock = threading.Lock()
        self._boundary_state = BoundaryState(
            mode=initial_mode,
            network=NetworkState.OFFLINE,
            hardware_trust=HardwareTrust.MEDIUM,
            external_models=False,
            last_transition=datetime.utcnow().isoformat() + "Z",
            operator=Operator.SYSTEM
        )
        self._transition_callbacks: Dict[int, callable] = {}  # Use dict for O(1) unregister
        self._next_callback_id = 0
        self._callback_lock = threading.Lock()  # Protect callback modifications

    def register_transition_callback(self, callback: callable) -> int:
        """
        Register callback for mode transitions.

        Args:
            callback: Function accepting (old_mode, new_mode, operator)

        Returns:
            Callback ID that can be used to unregister the callback
        """
        with self._callback_lock:
            callback_id = self._next_callback_id
            self._next_callback_id += 1
            self._transition_callbacks[callback_id] = callback
            return callback_id

    def unregister_transition_callback(self, callback_id: int) -> bool:
        """
        Unregister a previously registered transition callback.

        Args:
            callback_id: The ID returned from register_transition_callback

        Returns:
            True if callback was found and removed, False otherwise
        """
        with self._callback_lock:
            if callback_id in self._transition_callbacks:
                del self._transition_callbacks[callback_id]
                return True
            return False

    def cleanup(self):
        """Cleanup resources and clear callbacks to prevent memory leaks."""
        with self._callback_lock:
            self._transition_callbacks.clear()

    def get_current_state(self) -> BoundaryState:
        """Get current boundary state"""
        with self._state_lock:
            return self._boundary_state

    def get_current_mode(self) -> BoundaryMode:
        """Get current boundary mode"""
        with self._state_lock:
            return self._boundary_state.mode

    def transition_mode(self, new_mode: BoundaryMode, operator: Operator,
                       reason: str = "") -> Tuple[bool, str]:
        """
        Transition to a new boundary mode.

        Args:
            new_mode: Target mode
            operator: Who initiated the transition
            reason: Reason for transition

        Returns:
            (success, message)
        """
        with self._state_lock:
            old_mode = self._boundary_state.mode

            # Cannot transition from LOCKDOWN without human intervention
            if old_mode == BoundaryMode.LOCKDOWN and operator != Operator.HUMAN:
                return (False, "Cannot exit LOCKDOWN mode without human intervention")

            # Log the transition
            self._boundary_state.mode = new_mode
            self._boundary_state.last_transition = datetime.utcnow().isoformat() + "Z"
            self._boundary_state.operator = operator

            # Notify callbacks (copy to avoid modification during iteration)
            with self._callback_lock:
                callbacks = list(self._transition_callbacks.values())
            for callback in callbacks:
                try:
                    callback(old_mode, new_mode, operator, reason)
                except Exception as e:
                    logger.error(f"Error in transition callback: {e}")

            return (True, f"Transitioned from {old_mode.name} to {new_mode.name}")

    def update_environment(self, env_state: EnvironmentState):
        """
        Update the boundary state with current environment.
        This is called by the daemon when environment changes are detected.

        Args:
            env_state: Current environment state from StateMonitor
        """
        with self._state_lock:
            self._boundary_state.network = env_state.network
            self._boundary_state.hardware_trust = env_state.hardware_trust
            self._boundary_state.external_models = len(env_state.external_model_endpoints) > 0

    def evaluate_policy(self, request: PolicyRequest, env_state: EnvironmentState) -> PolicyDecision:
        """
        Evaluate a policy request against current mode and environment.

        Args:
            request: The policy request to evaluate
            env_state: Current environment state

        Returns:
            PolicyDecision (ALLOW, DENY, or REQUIRE_CEREMONY)
        """
        with self._state_lock:
            current_mode = self._boundary_state.mode

            # LOCKDOWN mode: deny everything
            if current_mode == BoundaryMode.LOCKDOWN:
                return PolicyDecision.DENY

            # Evaluate based on request type
            if request.request_type == 'recall':
                return self._evaluate_recall_policy(request, current_mode, env_state)
            elif request.request_type == 'tool':
                return self._evaluate_tool_policy(request, current_mode, env_state)
            elif request.request_type == 'model':
                return self._evaluate_model_policy(request, current_mode, env_state)
            elif request.request_type == 'io':
                return self._evaluate_io_policy(request, current_mode, env_state)
            else:
                # Unknown request type: fail closed
                return PolicyDecision.DENY

    def _evaluate_recall_policy(self, request: PolicyRequest,
                               mode: BoundaryMode,
                               env_state: EnvironmentState) -> PolicyDecision:
        """
        Evaluate memory recall policy.

        Memory Class → Minimum Mode mapping:
        0-1: Open
        2: Restricted
        3: Trusted
        4: Air-Gap
        5: Cold Room
        """
        if request.memory_class is None:
            return PolicyDecision.DENY

        # Map memory class to minimum required mode
        required_mode_map = {
            MemoryClass.PUBLIC: BoundaryMode.OPEN,
            MemoryClass.INTERNAL: BoundaryMode.OPEN,
            MemoryClass.CONFIDENTIAL: BoundaryMode.RESTRICTED,
            MemoryClass.SECRET: BoundaryMode.TRUSTED,
            MemoryClass.TOP_SECRET: BoundaryMode.AIRGAP,
            MemoryClass.CROWN_JEWEL: BoundaryMode.COLDROOM,
        }

        required_mode = required_mode_map.get(request.memory_class, BoundaryMode.LOCKDOWN)

        # Current mode must be >= required mode
        if mode >= required_mode:
            return PolicyDecision.ALLOW
        else:
            return PolicyDecision.DENY

    def _evaluate_tool_policy(self, request: PolicyRequest,
                             mode: BoundaryMode,
                             env_state: EnvironmentState) -> PolicyDecision:
        """Evaluate tool execution policy based on mode restrictions"""

        # COLDROOM: Minimal IO only
        if mode == BoundaryMode.COLDROOM:
            # Only allow display and keyboard
            if request.requires_network or request.requires_filesystem or request.requires_usb:
                return PolicyDecision.DENY
            return PolicyDecision.ALLOW

        # AIRGAP: No network, no USB
        if mode == BoundaryMode.AIRGAP:
            if request.requires_network or request.requires_usb:
                return PolicyDecision.DENY
            # Filesystem OK in airgap
            return PolicyDecision.ALLOW

        # TRUSTED: Offline or verified LAN only
        if mode == BoundaryMode.TRUSTED:
            # Check if we're actually offline
            if request.requires_network and env_state.network == NetworkState.ONLINE:
                # Allow if VPN active (trusted LAN)
                if not env_state.vpn_active:
                    return PolicyDecision.DENY
            return PolicyDecision.ALLOW

        # RESTRICTED: Limited tools
        if mode == BoundaryMode.RESTRICTED:
            # Some tools may require ceremony
            if request.requires_usb:
                return PolicyDecision.REQUIRE_CEREMONY
            return PolicyDecision.ALLOW

        # OPEN: Allow most things
        if mode == BoundaryMode.OPEN:
            return PolicyDecision.ALLOW

        # Default: fail closed
        return PolicyDecision.DENY

    def _evaluate_model_policy(self, request: PolicyRequest,
                               mode: BoundaryMode,
                               env_state: EnvironmentState) -> PolicyDecision:
        """Evaluate external model access policy"""

        # COLDROOM and AIRGAP: No external models
        if mode >= BoundaryMode.AIRGAP:
            return PolicyDecision.DENY

        # TRUSTED: External models only if offline/VPN
        if mode == BoundaryMode.TRUSTED:
            if env_state.network == NetworkState.ONLINE and not env_state.vpn_active:
                return PolicyDecision.DENY
            return PolicyDecision.ALLOW

        # RESTRICTED and OPEN: Allow with network
        if mode <= BoundaryMode.RESTRICTED:
            if env_state.network == NetworkState.ONLINE:
                return PolicyDecision.ALLOW
            return PolicyDecision.DENY

        return PolicyDecision.DENY

    def _evaluate_io_policy(self, request: PolicyRequest,
                           mode: BoundaryMode,
                           env_state: EnvironmentState) -> PolicyDecision:
        """Evaluate IO operation policy"""

        # COLDROOM: Minimal IO (keyboard/display only)
        if mode == BoundaryMode.COLDROOM:
            if request.requires_filesystem:
                return PolicyDecision.DENY
            return PolicyDecision.ALLOW

        # AIRGAP: Filesystem OK, no network/USB
        if mode == BoundaryMode.AIRGAP:
            if request.requires_network or request.requires_usb:
                return PolicyDecision.DENY
            return PolicyDecision.ALLOW

        # Lower modes: generally permissive
        return PolicyDecision.ALLOW

    def check_mode_environment_compatibility(self, env_state: EnvironmentState) -> Tuple[bool, Optional[str]]:
        """
        Check if current environment is compatible with current mode.
        Returns (is_compatible, violation_reason)

        This is used for automatic tripwire detection.
        """
        with self._state_lock:
            mode = self._boundary_state.mode

            # AIRGAP mode violations
            if mode >= BoundaryMode.AIRGAP:
                if env_state.network == NetworkState.ONLINE:
                    return (False, "Network came online in AIRGAP+ mode")

            # COLDROOM mode violations
            if mode >= BoundaryMode.COLDROOM:
                # USB insertion
                added_usb, _ = self._get_usb_changes(env_state)
                if added_usb:
                    return (False, f"USB device inserted in COLDROOM mode: {added_usb}")

            # All checks passed
            return (True, None)

    def _get_usb_changes(self, env_state: EnvironmentState) -> Tuple[set, set]:
        """Helper to detect USB changes (would need baseline storage)"""
        # This is a simplified version; real implementation would track baseline
        return (set(), set())

    def get_minimum_mode_for_memory(self, memory_class: MemoryClass) -> BoundaryMode:
        """Get the minimum boundary mode required for a memory class"""
        mode_map = {
            MemoryClass.PUBLIC: BoundaryMode.OPEN,
            MemoryClass.INTERNAL: BoundaryMode.OPEN,
            MemoryClass.CONFIDENTIAL: BoundaryMode.RESTRICTED,
            MemoryClass.SECRET: BoundaryMode.TRUSTED,
            MemoryClass.TOP_SECRET: BoundaryMode.AIRGAP,
            MemoryClass.CROWN_JEWEL: BoundaryMode.COLDROOM,
        }
        return mode_map.get(memory_class, BoundaryMode.LOCKDOWN)


if __name__ == '__main__':
    # Test the policy engine
    print("Testing Policy Engine...")

    engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)

    # Test recall policies at different modes
    for mode in [BoundaryMode.OPEN, BoundaryMode.RESTRICTED, BoundaryMode.AIRGAP]:
        engine.transition_mode(mode, Operator.HUMAN, "test")

        for mem_class in [MemoryClass.PUBLIC, MemoryClass.CONFIDENTIAL, MemoryClass.TOP_SECRET]:
            request = PolicyRequest(
                request_type='recall',
                memory_class=mem_class
            )

            # Create a mock environment state
            from state_monitor import EnvironmentState
            env = EnvironmentState(
                timestamp=datetime.utcnow().isoformat() + "Z",
                network=NetworkState.OFFLINE,
                hardware_trust=HardwareTrust.HIGH,
                active_interfaces=[],
                has_internet=False,
                vpn_active=False,
                dns_available=False,
                usb_devices=set(),
                block_devices=set(),
                camera_available=False,
                mic_available=False,
                tpm_present=True,
                external_model_endpoints=[],
                suspicious_processes=[],
                shell_escapes_detected=0,
                keyboard_active=True,
                screen_unlocked=True,
                last_activity=None
            )

            decision = engine.evaluate_policy(request, env)
            print(f"Mode: {mode.name:12} | Memory: {mem_class.name:15} | Decision: {decision.value}")

    print("\nPolicy engine test complete.")
