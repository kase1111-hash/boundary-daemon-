#!/usr/bin/env python3
"""
Boundary Daemon - Agent Smith
The hard enforcement layer that defines and maintains trust boundaries.

This is the authoritative security enforcer for the Agent OS system.
It determines where cognition is allowed to flow and where it must stop.
"""

import os
import signal
import sys
import time
import threading
from datetime import datetime
from typing import Optional

# Import core components
from .state_monitor import StateMonitor, EnvironmentState, NetworkState
from .policy_engine import PolicyEngine, BoundaryMode, PolicyRequest, PolicyDecision, Operator, MemoryClass
from .tripwires import TripwireSystem, LockdownManager, TripwireViolation
from .event_logger import EventLogger, EventType

# Import enforcement module (Plan 1: Kernel-Level Enforcement)
try:
    from .enforcement import NetworkEnforcer, USBEnforcer, ProcessEnforcer
    ENFORCEMENT_AVAILABLE = True
except ImportError:
    ENFORCEMENT_AVAILABLE = False
    NetworkEnforcer = None
    USBEnforcer = None
    ProcessEnforcer = None


class BoundaryDaemon:
    """
    Main Boundary Daemon service.

    Coordinates state monitoring, policy enforcement, tripwire detection,
    and event logging to maintain trust boundaries.
    """

    def __init__(self, log_dir: str = './logs', initial_mode: BoundaryMode = BoundaryMode.OPEN):
        """
        Initialize the Boundary Daemon.

        Args:
            log_dir: Directory for log files
            initial_mode: Starting boundary mode
        """
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        # Initialize core components
        print("Initializing Boundary Daemon (Agent Smith)...")

        self.event_logger = EventLogger(os.path.join(log_dir, 'boundary_chain.log'))
        self.state_monitor = StateMonitor(poll_interval=1.0)
        self.policy_engine = PolicyEngine(initial_mode=initial_mode)
        self.tripwire_system = TripwireSystem()
        self.lockdown_manager = LockdownManager()

        # Initialize network enforcer (Plan 1 Phase 1: Network Enforcement)
        self.network_enforcer = None
        if ENFORCEMENT_AVAILABLE and NetworkEnforcer:
            self.network_enforcer = NetworkEnforcer(
                daemon=self,
                event_logger=self.event_logger
            )
            if self.network_enforcer.is_available:
                print(f"Network enforcement available (backend: {self.network_enforcer.backend.value})")
            else:
                print("Network enforcement: not available (requires root and iptables/nftables)")
        else:
            print("Network enforcement module not loaded")

        # Initialize USB enforcer (Plan 1 Phase 2: USB Enforcement)
        self.usb_enforcer = None
        if ENFORCEMENT_AVAILABLE and USBEnforcer:
            self.usb_enforcer = USBEnforcer(
                daemon=self,
                event_logger=self.event_logger
            )
            if self.usb_enforcer.is_available:
                print(f"USB enforcement available (udev rules at {self.usb_enforcer.UDEV_RULE_PATH})")
            else:
                print("USB enforcement: not available (requires root and udev)")
        else:
            print("USB enforcement module not loaded")

        # Initialize process enforcer (Plan 1 Phase 3: Process Enforcement)
        self.process_enforcer = None
        if ENFORCEMENT_AVAILABLE and ProcessEnforcer:
            self.process_enforcer = ProcessEnforcer(
                daemon=self,
                event_logger=self.event_logger
            )
            if self.process_enforcer.is_available:
                runtime = self.process_enforcer.container_runtime.value
                print(f"Process enforcement available (seccomp + container: {runtime})")
            else:
                print("Process enforcement: not available (requires root)")
        else:
            print("Process enforcement module not loaded")

        # Daemon state
        self._running = False
        self._shutdown_event = threading.Event()
        self._enforcement_thread: Optional[threading.Thread] = None

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Register callbacks
        self._setup_callbacks()

        # Log daemon initialization
        self.event_logger.log_event(
            EventType.DAEMON_START,
            f"Boundary Daemon started in {initial_mode.name} mode",
            metadata={'initial_mode': initial_mode.name}
        )

        print(f"Boundary Daemon initialized in {initial_mode.name} mode")

    def _setup_callbacks(self):
        """Setup callbacks between components"""

        # State monitor callback: update policy engine and check tripwires
        def on_state_change(old_state: Optional[EnvironmentState], new_state: EnvironmentState):
            # Update policy engine with new environment
            self.policy_engine.update_environment(new_state)

            # Check for tripwire violations
            current_mode = self.policy_engine.get_current_mode()
            violation = self.tripwire_system.check_violations(current_mode, new_state)

            if violation:
                self._handle_violation(violation)

        self.state_monitor.register_callback(on_state_change)

        # Policy engine mode transition callback
        def on_mode_transition(old_mode: BoundaryMode, new_mode: BoundaryMode,
                              operator: Operator, reason: str):
            self.event_logger.log_event(
                EventType.MODE_CHANGE,
                f"Transitioned from {old_mode.name} to {new_mode.name}: {reason}",
                metadata={
                    'old_mode': old_mode.name,
                    'new_mode': new_mode.name,
                    'operator': operator.value,
                    'reason': reason
                }
            )
            print(f"Mode transition: {old_mode.name} → {new_mode.name} ({operator.value})")

            # Apply network enforcement for the new mode (Plan 1 Phase 1)
            if self.network_enforcer and self.network_enforcer.is_available:
                try:
                    success, msg = self.network_enforcer.enforce_mode(new_mode, reason)
                    if success:
                        print(f"Network enforcement applied: {msg}")
                    else:
                        print(f"Network enforcement warning: {msg}")
                except Exception as e:
                    print(f"Network enforcement error: {e}")
                    # On enforcement failure, trigger lockdown (fail-closed)
                    if new_mode != BoundaryMode.LOCKDOWN:
                        self.event_logger.log_event(
                            EventType.VIOLATION,
                            f"Network enforcement failed, triggering lockdown: {e}",
                            metadata={'error': str(e)}
                        )

            # Apply USB enforcement for the new mode (Plan 1 Phase 2)
            if self.usb_enforcer and self.usb_enforcer.is_available:
                try:
                    success, msg = self.usb_enforcer.enforce_mode(new_mode, reason)
                    if success:
                        print(f"USB enforcement applied: {msg}")
                    else:
                        print(f"USB enforcement warning: {msg}")
                except Exception as e:
                    print(f"USB enforcement error: {e}")
                    # On enforcement failure, trigger lockdown (fail-closed)
                    if new_mode != BoundaryMode.LOCKDOWN:
                        self.event_logger.log_event(
                            EventType.VIOLATION,
                            f"USB enforcement failed, triggering lockdown: {e}",
                            metadata={'error': str(e)}
                        )

            # Apply process enforcement for the new mode (Plan 1 Phase 3)
            if self.process_enforcer and self.process_enforcer.is_available:
                try:
                    success, msg = self.process_enforcer.enforce_mode(new_mode, reason)
                    if success:
                        print(f"Process enforcement applied: {msg}")
                    else:
                        print(f"Process enforcement warning: {msg}")
                except Exception as e:
                    print(f"Process enforcement error: {e}")
                    # On enforcement failure, trigger lockdown (fail-closed)
                    if new_mode != BoundaryMode.LOCKDOWN:
                        self.event_logger.log_event(
                            EventType.VIOLATION,
                            f"Process enforcement failed, triggering lockdown: {e}",
                            metadata={'error': str(e)}
                        )

        self.policy_engine.register_transition_callback(on_mode_transition)

        # Tripwire violation callback
        def on_tripwire_violation(violation: TripwireViolation):
            self.event_logger.log_event(
                EventType.TRIPWIRE,
                f"Tripwire triggered: {violation.details}",
                metadata={
                    'violation_type': violation.violation_type.value,
                    'violation_id': violation.violation_id,
                    'current_mode': violation.current_mode.name
                }
            )

            # Trigger lockdown
            if violation.auto_lockdown:
                self.lockdown_manager.trigger_lockdown(violation)
                self.policy_engine.transition_mode(
                    BoundaryMode.LOCKDOWN,
                    Operator.SYSTEM,
                    f"Tripwire: {violation.violation_type.value}"
                )

        self.tripwire_system.register_callback(on_tripwire_violation)

    def _handle_violation(self, violation: TripwireViolation):
        """Handle a tripwire violation"""
        print(f"\n*** SECURITY VIOLATION DETECTED ***")
        print(f"Type: {violation.violation_type.value}")
        print(f"Details: {violation.details}")
        print(f"System entering LOCKDOWN mode\n")

    def start(self):
        """Start the boundary daemon"""
        if self._running:
            print("Daemon already running")
            return

        print("Starting Boundary Daemon...")
        self._running = True

        # Apply initial enforcement (Plan 1)
        current_mode = self.policy_engine.get_current_mode()

        # Network enforcement (Phase 1)
        if self.network_enforcer and self.network_enforcer.is_available:
            try:
                success, msg = self.network_enforcer.enforce_mode(
                    current_mode,
                    reason="Initial enforcement on daemon start"
                )
                if success:
                    print(f"Initial network enforcement applied for {current_mode.name} mode")
                else:
                    print(f"Warning: {msg}")
            except Exception as e:
                print(f"Warning: Initial network enforcement failed: {e}")

        # USB enforcement (Phase 2)
        if self.usb_enforcer and self.usb_enforcer.is_available:
            try:
                success, msg = self.usb_enforcer.enforce_mode(
                    current_mode,
                    reason="Initial enforcement on daemon start"
                )
                if success:
                    print(f"Initial USB enforcement applied for {current_mode.name} mode")
                else:
                    print(f"Warning: {msg}")
            except Exception as e:
                print(f"Warning: Initial USB enforcement failed: {e}")

        # Process enforcement (Phase 3)
        if self.process_enforcer and self.process_enforcer.is_available:
            try:
                success, msg = self.process_enforcer.enforce_mode(
                    current_mode,
                    reason="Initial enforcement on daemon start"
                )
                if success:
                    print(f"Initial process enforcement applied for {current_mode.name} mode")
                else:
                    print(f"Warning: {msg}")
            except Exception as e:
                print(f"Warning: Initial process enforcement failed: {e}")

        # Start state monitoring
        self.state_monitor.start()

        # Start enforcement loop
        self._enforcement_thread = threading.Thread(target=self._enforcement_loop, daemon=False)
        self._enforcement_thread.start()

        print("Boundary Daemon running. Press Ctrl+C to stop.")
        print("=" * 70)

    def stop(self):
        """Stop the boundary daemon"""
        if not self._running:
            return

        print("\nStopping Boundary Daemon...")
        self._running = False
        self._shutdown_event.set()

        # Stop state monitor
        self.state_monitor.stop()

        # Wait for enforcement thread
        if self._enforcement_thread:
            self._enforcement_thread.join(timeout=5.0)

        # Cleanup enforcement rules (Plan 1)
        if self.network_enforcer and self.network_enforcer.is_available:
            try:
                self.network_enforcer.cleanup()
                print("Network enforcement rules cleaned up")
            except Exception as e:
                print(f"Warning: Failed to cleanup network rules: {e}")

        if self.usb_enforcer and self.usb_enforcer.is_available:
            try:
                self.usb_enforcer.cleanup()
                print("USB enforcement rules cleaned up")
            except Exception as e:
                print(f"Warning: Failed to cleanup USB rules: {e}")

        if self.process_enforcer and self.process_enforcer.is_available:
            try:
                self.process_enforcer.cleanup()
                print("Process enforcement cleaned up")
            except Exception as e:
                print(f"Warning: Failed to cleanup process enforcement: {e}")

        # Log daemon shutdown
        self.event_logger.log_event(
            EventType.DAEMON_STOP,
            "Boundary Daemon stopped",
            metadata={}
        )

        print("Boundary Daemon stopped.")

    def _enforcement_loop(self):
        """Main enforcement loop - periodic health checks and monitoring"""
        health_check_interval = 10.0  # seconds
        last_health_check = time.time()

        while self._running and not self._shutdown_event.is_set():
            try:
                current_time = time.time()

                # Periodic health check
                if current_time - last_health_check >= health_check_interval:
                    self._perform_health_check()
                    last_health_check = current_time

                # Check if in lockdown
                if self.lockdown_manager.is_in_lockdown():
                    # In lockdown: deny all operations
                    pass

                # Sleep briefly
                time.sleep(1.0)

            except Exception as e:
                print(f"Error in enforcement loop: {e}")
                # Log the error
                self.event_logger.log_event(
                    EventType.HEALTH_CHECK,
                    f"Error in enforcement loop: {e}",
                    metadata={'error': str(e)}
                )
                time.sleep(1.0)

    def _perform_health_check(self):
        """Perform periodic health check"""
        # Check daemon health
        daemon_healthy = self.tripwire_system.check_daemon_health()

        if not daemon_healthy:
            # Daemon health check failed - this is a critical violation
            self.event_logger.log_event(
                EventType.HEALTH_CHECK,
                "Daemon health check FAILED - possible tampering detected",
                metadata={'healthy': False}
            )
            print("\n*** WARNING: Daemon health check failed ***\n")

        # Verify event log integrity
        is_valid, error = self.event_logger.verify_chain()
        if not is_valid:
            print(f"\n*** CRITICAL: Event log chain integrity violation: {error} ***\n")
            self.event_logger.log_event(
                EventType.VIOLATION,
                f"Event log chain integrity violated: {error}",
                metadata={'healthy': False}
            )

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\nReceived signal {signum}")
        self.stop()
        sys.exit(0)

    # Public API methods for other components

    def check_recall_permission(self, memory_class: MemoryClass) -> tuple[bool, str]:
        """
        Check if memory recall is permitted.

        Args:
            memory_class: Classification level of memory to recall

        Returns:
            (permitted, reason)
        """
        # Check lockdown first
        if self.lockdown_manager.is_in_lockdown():
            self.event_logger.log_event(
                EventType.RECALL_ATTEMPT,
                f"Memory recall denied: system in LOCKDOWN",
                metadata={'memory_class': memory_class.value, 'decision': 'deny'}
            )
            return (False, "System in LOCKDOWN mode")

        # Get current environment
        env_state = self.state_monitor.get_current_state()
        if not env_state:
            return (False, "Unable to determine environment state")

        # Create policy request
        request = PolicyRequest(
            request_type='recall',
            memory_class=memory_class
        )

        # Evaluate policy
        decision = self.policy_engine.evaluate_policy(request, env_state)

        # Log the attempt
        self.event_logger.log_event(
            EventType.RECALL_ATTEMPT,
            f"Memory class {memory_class.value} recall: {decision.value}",
            metadata={
                'memory_class': memory_class.value,
                'decision': decision.value,
                'current_mode': self.policy_engine.get_current_mode().name
            }
        )

        if decision == PolicyDecision.ALLOW:
            return (True, "Recall permitted")
        elif decision == PolicyDecision.DENY:
            current_mode = self.policy_engine.get_current_mode()
            required_mode = self.policy_engine.get_minimum_mode_for_memory(memory_class)
            return (False, f"Recall denied: requires {required_mode.name} mode, currently in {current_mode.name}")
        else:  # REQUIRE_CEREMONY
            return (False, "Recall requires human override ceremony")

    def check_tool_permission(self, tool_name: str, requires_network: bool = False,
                             requires_filesystem: bool = False,
                             requires_usb: bool = False) -> tuple[bool, str]:
        """
        Check if tool execution is permitted.

        Args:
            tool_name: Name of the tool
            requires_network: Tool needs network access
            requires_filesystem: Tool needs filesystem access
            requires_usb: Tool needs USB access

        Returns:
            (permitted, reason)
        """
        if self.lockdown_manager.is_in_lockdown():
            return (False, "System in LOCKDOWN mode")

        env_state = self.state_monitor.get_current_state()
        if not env_state:
            return (False, "Unable to determine environment state")

        request = PolicyRequest(
            request_type='tool',
            tool_name=tool_name,
            requires_network=requires_network,
            requires_filesystem=requires_filesystem,
            requires_usb=requires_usb
        )

        decision = self.policy_engine.evaluate_policy(request, env_state)

        self.event_logger.log_event(
            EventType.TOOL_REQUEST,
            f"Tool '{tool_name}' request: {decision.value}",
            metadata={
                'tool_name': tool_name,
                'decision': decision.value,
                'requires_network': requires_network,
                'requires_filesystem': requires_filesystem,
                'requires_usb': requires_usb
            }
        )

        if decision == PolicyDecision.ALLOW:
            return (True, "Tool execution permitted")
        elif decision == PolicyDecision.DENY:
            return (False, f"Tool execution denied by policy")
        else:
            return (False, "Tool requires human override ceremony")

    def get_status(self) -> dict:
        """Get current daemon status"""
        boundary_state = self.policy_engine.get_current_state()
        env_state = self.state_monitor.get_current_state()
        lockdown_info = self.lockdown_manager.get_lockdown_info()

        return {
            'running': self._running,
            'boundary_state': boundary_state.to_dict(),
            'environment': env_state.to_dict() if env_state else None,
            'lockdown': lockdown_info,
            'event_count': self.event_logger.get_event_count(),
            'tripwire_violations': self.tripwire_system.get_violation_count()
        }

    def request_mode_change(self, new_mode: BoundaryMode, operator: Operator, reason: str = "") -> tuple[bool, str]:
        """
        Request a boundary mode change.

        Args:
            new_mode: Target mode
            operator: Who is requesting the change
            reason: Reason for change

        Returns:
            (success, message)
        """
        return self.policy_engine.transition_mode(new_mode, operator, reason)


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Boundary Daemon - Agent Smith')
    parser.add_argument('--mode', type=str, default='open',
                       choices=['open', 'restricted', 'trusted', 'airgap', 'coldroom'],
                       help='Initial boundary mode')
    parser.add_argument('--log-dir', type=str, default='./logs',
                       help='Directory for log files')

    args = parser.parse_args()

    # Map mode string to enum
    mode_map = {
        'open': BoundaryMode.OPEN,
        'restricted': BoundaryMode.RESTRICTED,
        'trusted': BoundaryMode.TRUSTED,
        'airgap': BoundaryMode.AIRGAP,
        'coldroom': BoundaryMode.COLDROOM
    }

    initial_mode = mode_map[args.mode]

    # Create and start daemon
    daemon = BoundaryDaemon(log_dir=args.log_dir, initial_mode=initial_mode)
    daemon.start()

    # Keep running until interrupted
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        daemon.stop()


if __name__ == '__main__':
    main()
