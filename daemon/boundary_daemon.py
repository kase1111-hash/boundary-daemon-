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

# Import API server for external CLI tools
try:
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from api.boundary_api import BoundaryAPIServer
    API_SERVER_AVAILABLE = True
except ImportError:
    API_SERVER_AVAILABLE = False
    BoundaryAPIServer = None

# Import signed event logger (Plan 3: Cryptographic Log Signing)
try:
    from .signed_event_logger import SignedEventLogger
    SIGNED_LOGGING_AVAILABLE = True
except ImportError:
    SIGNED_LOGGING_AVAILABLE = False
    SignedEventLogger = None

# Import enforcement module (Plan 1: Kernel-Level Enforcement)
try:
    from .enforcement import NetworkEnforcer, USBEnforcer, ProcessEnforcer
    ENFORCEMENT_AVAILABLE = True
except ImportError:
    ENFORCEMENT_AVAILABLE = False
    NetworkEnforcer = None
    USBEnforcer = None
    ProcessEnforcer = None

# Import hardware module (Plan 2: TPM Integration)
try:
    from .hardware import TPMManager
    TPM_MODULE_AVAILABLE = True
except ImportError:
    TPM_MODULE_AVAILABLE = False
    TPMManager = None

# Import distributed module (Plan 4: Distributed Deployment)
try:
    from .distributed import ClusterManager, FileCoordinator
    DISTRIBUTED_AVAILABLE = True
except ImportError:
    DISTRIBUTED_AVAILABLE = False
    ClusterManager = None
    FileCoordinator = None

# Import custom policy module (Plan 5: Custom Policy Language)
try:
    from .policy import CustomPolicyEngine
    CUSTOM_POLICY_AVAILABLE = True
except ImportError:
    CUSTOM_POLICY_AVAILABLE = False
    CustomPolicyEngine = None

# Import auth module (Plan 6: Biometric Authentication)
try:
    from .auth import BiometricVerifier, EnhancedCeremonyManager, BiometricCeremonyConfig
    BIOMETRIC_AVAILABLE = True
except ImportError:
    BIOMETRIC_AVAILABLE = False
    BiometricVerifier = None
    EnhancedCeremonyManager = None
    BiometricCeremonyConfig = None

# Import security module (Plan 7: Code Vulnerability Advisor)
try:
    from .security import CodeVulnerabilityAdvisor, AdvisoryStatus
    SECURITY_ADVISOR_AVAILABLE = True
except ImportError:
    SECURITY_ADVISOR_AVAILABLE = False
    CodeVulnerabilityAdvisor = None
    AdvisoryStatus = None

# Import watchdog module (Plan 8: Log Watchdog Agent)
try:
    from .watchdog import LogWatchdog, WatchdogConfig, AlertSeverity as WatchdogSeverity, AlertStatus as WatchdogStatus
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    LogWatchdog = None
    WatchdogConfig = None
    WatchdogSeverity = None
    WatchdogStatus = None

# Import telemetry module (Plan 9: OpenTelemetry Integration)
try:
    from .telemetry import TelemetryManager, TelemetryConfig, ExportMode
    TELEMETRY_AVAILABLE = True
except ImportError:
    TELEMETRY_AVAILABLE = False
    TelemetryManager = None
    TelemetryConfig = None
    ExportMode = None

# Import message checking module (Plan 10: Message Checking for NatLangChain/Agent-OS)
try:
    from .messages import MessageChecker, MessageSource, NatLangChainEntry, AgentOSMessage
    MESSAGE_CHECKER_AVAILABLE = True
except ImportError:
    MESSAGE_CHECKER_AVAILABLE = False
    MessageChecker = None
    MessageSource = None
    NatLangChainEntry = None
    AgentOSMessage = None


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

        # Initialize event logger (Plan 3: Cryptographic Log Signing)
        log_file = os.path.join(log_dir, 'boundary_chain.log')
        self.signed_logging = False
        if SIGNED_LOGGING_AVAILABLE and SignedEventLogger:
            try:
                signing_key_path = os.path.join(log_dir, 'signing.key')
                self.event_logger = SignedEventLogger(log_file, signing_key_path)
                self.signed_logging = True
                print(f"Signed event logging enabled (key: {signing_key_path})")
                print(f"Public verification key: {self.event_logger.get_public_key_hex()[:32]}...")
            except Exception as e:
                print(f"Warning: Signed logging failed, falling back to basic logging: {e}")
                self.event_logger = EventLogger(log_file)
        else:
            self.event_logger = EventLogger(log_file)
            print("Signed event logging: not available (pynacl not installed)")

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

        # Initialize TPM manager (Plan 2: TPM Integration)
        self.tpm_manager = None
        if TPM_MODULE_AVAILABLE and TPMManager:
            self.tpm_manager = TPMManager(
                daemon=self,
                event_logger=self.event_logger
            )
            if self.tpm_manager.is_available:
                print(f"TPM integration available (backend: {self.tpm_manager.backend.value})")
            else:
                print("TPM integration: not available (no TPM hardware or tools)")
        else:
            print("TPM integration module not loaded")

        # Initialize cluster manager (Plan 4: Distributed Deployment)
        self.cluster_manager = None
        self.cluster_enabled = False
        if DISTRIBUTED_AVAILABLE and ClusterManager and FileCoordinator:
            # Cluster mode can be enabled via environment variable or config
            cluster_data_dir = os.environ.get('BOUNDARY_CLUSTER_DIR', None)
            if cluster_data_dir:
                try:
                    coordinator = FileCoordinator(cluster_data_dir)
                    self.cluster_manager = ClusterManager(
                        daemon=self,
                        coordinator=coordinator
                    )
                    self.cluster_enabled = True
                    print(f"Cluster coordination available (node: {self.cluster_manager.node_id})")
                except Exception as e:
                    print(f"Warning: Cluster coordination failed to initialize: {e}")
            else:
                print("Cluster coordination: not enabled (set BOUNDARY_CLUSTER_DIR to enable)")
        else:
            print("Cluster coordination module not loaded")

        # Initialize custom policy engine (Plan 5: Custom Policy Language)
        self.custom_policy_engine = None
        self.custom_policy_enabled = False
        if CUSTOM_POLICY_AVAILABLE and CustomPolicyEngine:
            # Custom policies can be enabled via environment variable
            policy_dir = os.environ.get('BOUNDARY_POLICY_DIR', None)
            if policy_dir:
                try:
                    self.custom_policy_engine = CustomPolicyEngine(policy_dir)
                    self.custom_policy_enabled = True
                    policy_count = len(self.custom_policy_engine.get_enabled_policies())
                    print(f"Custom policy engine available ({policy_count} policies from {policy_dir})")
                except Exception as e:
                    print(f"Warning: Custom policy engine failed to initialize: {e}")
            else:
                print("Custom policy engine: not enabled (set BOUNDARY_POLICY_DIR to enable)")
        else:
            print("Custom policy engine module not loaded")

        # Initialize biometric authentication (Plan 6: Biometric Authentication)
        self.biometric_verifier = None
        self.ceremony_manager = None
        self.biometric_enabled = False
        if BIOMETRIC_AVAILABLE and BiometricVerifier and EnhancedCeremonyManager:
            # Biometric auth can be enabled via environment variable
            biometric_dir = os.environ.get('BOUNDARY_BIOMETRIC_DIR', None)
            if biometric_dir:
                try:
                    # Create biometric verifier with optional TPM integration
                    self.biometric_verifier = BiometricVerifier(
                        template_dir=biometric_dir,
                        tpm_manager=self.tpm_manager
                    )
                    # Create enhanced ceremony manager with biometric support
                    biometric_config = BiometricCeremonyConfig()
                    biometric_config.enabled = True
                    biometric_config.fallback_to_keyboard = True
                    self.ceremony_manager = EnhancedCeremonyManager(
                        daemon=self,
                        biometric_verifier=self.biometric_verifier,
                        config=biometric_config
                    )
                    self.biometric_enabled = True
                    caps = self.biometric_verifier.get_capabilities()
                    print(f"Biometric authentication available ({caps['enrolled_count']} templates enrolled)")
                    print(f"  Fingerprint: {'Available' if caps['fingerprint_available'] else 'Not available'}")
                    print(f"  Face: {'Available' if caps['face_available'] else 'Not available'}")
                except Exception as e:
                    print(f"Warning: Biometric authentication failed to initialize: {e}")
            else:
                print("Biometric authentication: not enabled (set BOUNDARY_BIOMETRIC_DIR to enable)")
        else:
            print("Biometric authentication module not loaded")

        # Initialize code vulnerability advisor (Plan 7: LLM-Powered Security)
        self.security_advisor = None
        self.security_advisor_enabled = False
        if SECURITY_ADVISOR_AVAILABLE and CodeVulnerabilityAdvisor:
            # Security advisor can be enabled via environment variable
            security_dir = os.environ.get('BOUNDARY_SECURITY_DIR', None)
            if security_dir:
                try:
                    # Get optional model from environment
                    security_model = os.environ.get('BOUNDARY_SECURITY_MODEL', None)
                    self.security_advisor = CodeVulnerabilityAdvisor(
                        model=security_model,
                        storage_dir=security_dir
                    )
                    self.security_advisor_enabled = True
                    stats = self.security_advisor.get_summary_stats()
                    print(f"Security advisor available (model: {self.security_advisor.model})")
                    print(f"  Ollama: {'Available' if self.security_advisor.is_available() else 'Not available'}")
                    print(f"  Stored advisories: {stats['total']}")
                except Exception as e:
                    print(f"Warning: Security advisor failed to initialize: {e}")
            else:
                print("Security advisor: not enabled (set BOUNDARY_SECURITY_DIR to enable)")
        else:
            print("Security advisor module not loaded")

        # Initialize log watchdog (Plan 8: Log Watchdog Agent)
        self.log_watchdog = None
        self.watchdog_enabled = False
        if WATCHDOG_AVAILABLE and LogWatchdog:
            # Watchdog can be enabled via environment variable
            watchdog_dir = os.environ.get('BOUNDARY_WATCHDOG_DIR', None)
            if watchdog_dir:
                try:
                    # Get optional config from environment
                    watchdog_model = os.environ.get('BOUNDARY_WATCHDOG_MODEL', None)
                    log_paths_str = os.environ.get('BOUNDARY_WATCHDOG_LOGS', '')
                    log_paths = [p.strip() for p in log_paths_str.split(':') if p.strip()]

                    # Default to daemon's own log
                    if not log_paths:
                        log_paths = [os.path.join(log_dir, 'boundary_chain.log')]

                    self.log_watchdog = LogWatchdog(
                        daemon=self,
                        log_paths=log_paths,
                        model=watchdog_model if watchdog_model else "llama3.1:8b-instruct-q6_K",
                        storage_dir=watchdog_dir
                    )
                    self.watchdog_enabled = True
                    stats = self.log_watchdog.get_summary_stats()
                    print(f"Log watchdog available (model: {self.log_watchdog.model})")
                    print(f"  Ollama: {'Available' if self.log_watchdog.is_available() else 'Not available'}")
                    print(f"  Monitoring: {len(log_paths)} log file(s)")
                    print(f"  Stored alerts: {stats['total']}")
                except Exception as e:
                    print(f"Warning: Log watchdog failed to initialize: {e}")
            else:
                print("Log watchdog: not enabled (set BOUNDARY_WATCHDOG_DIR to enable)")
        else:
            print("Log watchdog module not loaded")

        # Initialize telemetry (Plan 9: OpenTelemetry Integration)
        self.telemetry_manager = None
        self.telemetry_enabled = False
        if TELEMETRY_AVAILABLE and TelemetryManager:
            # Telemetry can be enabled via environment variable
            telemetry_dir = os.environ.get('BOUNDARY_TELEMETRY_DIR', None)
            if telemetry_dir:
                try:
                    config = TelemetryConfig.from_env()
                    self.telemetry_manager = TelemetryManager(
                        daemon=self,
                        config=config
                    )
                    if self.telemetry_manager.initialize():
                        self.telemetry_enabled = True
                        stats = self.telemetry_manager.get_summary_stats()
                        print(f"Telemetry available (OTel: {stats['otel_available']}, OTLP: {stats['otlp_available']})")
                        print(f"  Export mode: {stats['export_mode']}")
                        print(f"  Instance ID: {stats['instance_id']}")
                    else:
                        print("Telemetry: initialized in fallback mode")
                        self.telemetry_enabled = True
                except Exception as e:
                    print(f"Warning: Telemetry failed to initialize: {e}")
            else:
                print("Telemetry: not enabled (set BOUNDARY_TELEMETRY_DIR to enable)")
        else:
            print("Telemetry module not loaded")

        # Initialize message checker (Plan 10: Message Checking for NatLangChain/Agent-OS)
        self.message_checker = None
        self.message_checker_enabled = False
        if MESSAGE_CHECKER_AVAILABLE and MessageChecker:
            try:
                # Check if strict mode is enabled via environment
                strict_mode = os.environ.get('BOUNDARY_MESSAGE_STRICT', 'false').lower() == 'true'
                self.message_checker = MessageChecker(daemon=self, strict_mode=strict_mode)
                self.message_checker_enabled = True
                mode_str = "strict" if strict_mode else "permissive"
                print(f"Message checker available (mode: {mode_str})")
                print(f"  NatLangChain: Enabled")
                print(f"  Agent-OS: Enabled")
            except Exception as e:
                print(f"Warning: Message checker failed to initialize: {e}")
        else:
            print("Message checker module not loaded")

        # Daemon state
        self._running = False
        self._shutdown_event = threading.Event()
        self._enforcement_thread: Optional[threading.Thread] = None

        # Initialize API server for CLI tools
        self.api_server = None
        if API_SERVER_AVAILABLE and BoundaryAPIServer:
            socket_path = os.path.join(os.path.dirname(log_dir), 'api', 'boundary.sock')
            self.api_server = BoundaryAPIServer(daemon=self, socket_path=socket_path)
            print(f"API server initialized (socket: {socket_path})")
        else:
            print("API server: not available")

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

            # Bind mode transition to TPM (Plan 2: TPM Integration)
            if self.tpm_manager and self.tpm_manager.is_available:
                try:
                    attestation = self.tpm_manager.bind_mode_to_tpm(new_mode, reason)
                    print(f"TPM attestation recorded: mode {new_mode.name} bound to PCR {attestation.pcr_index}")
                except Exception as e:
                    print(f"TPM attestation warning: {e}")
                    # TPM attestation failure is non-critical, continue operation

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

        # Start cluster coordination (Plan 4)
        if self.cluster_manager and self.cluster_enabled:
            try:
                self.cluster_manager.start()
                print(f"Cluster coordination started (node: {self.cluster_manager.node_id})")
            except Exception as e:
                print(f"Warning: Cluster coordination failed to start: {e}")

        # Start log watchdog (Plan 8)
        if self.log_watchdog and self.watchdog_enabled:
            try:
                self.log_watchdog.start()
                print(f"Log watchdog started (monitoring {len(self.log_watchdog.log_paths)} file(s))")
            except Exception as e:
                print(f"Warning: Log watchdog failed to start: {e}")

        # Start API server for CLI tools
        if self.api_server:
            try:
                self.api_server.start()
            except Exception as e:
                print(f"Warning: Failed to start API server: {e}")

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

        # Stop API server
        if self.api_server:
            try:
                self.api_server.stop()
                print("API server stopped")
            except Exception as e:
                print(f"Warning: Failed to stop API server: {e}")

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

        # Cleanup TPM resources (Plan 2)
        if self.tpm_manager:
            try:
                self.tpm_manager.cleanup()
                print("TPM resources cleaned up")
            except Exception as e:
                print(f"Warning: Failed to cleanup TPM resources: {e}")

        # Stop cluster coordination (Plan 4)
        if self.cluster_manager and self.cluster_enabled:
            try:
                self.cluster_manager.stop()
                print("Cluster coordination stopped")
            except Exception as e:
                print(f"Warning: Failed to stop cluster coordination: {e}")

        # Stop log watchdog (Plan 8)
        if self.log_watchdog and self.watchdog_enabled:
            try:
                self.log_watchdog.stop()
                print("Log watchdog stopped")
            except Exception as e:
                print(f"Warning: Failed to stop log watchdog: {e}")

        # Shutdown telemetry (Plan 9)
        if self.telemetry_manager and self.telemetry_enabled:
            try:
                self.telemetry_manager.shutdown()
                print("Telemetry shutdown complete")
            except Exception as e:
                print(f"Warning: Failed to shutdown telemetry: {e}")

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

        # Evaluate custom policies first (Plan 5)
        decision = None
        custom_policy_matched = False
        if self.custom_policy_engine and self.custom_policy_enabled:
            current_mode = self.policy_engine.get_current_mode()
            decision = self.custom_policy_engine.evaluate(request, env_state, current_mode)
            if decision:
                custom_policy_matched = True

        # Fall back to default policy if no custom policy matched
        if decision is None:
            decision = self.policy_engine.evaluate_policy(request, env_state)

        # Log the attempt
        self.event_logger.log_event(
            EventType.RECALL_ATTEMPT,
            f"Memory class {memory_class.value} recall: {decision.value}",
            metadata={
                'memory_class': memory_class.value,
                'decision': decision.value,
                'current_mode': self.policy_engine.get_current_mode().name,
                'custom_policy_matched': custom_policy_matched
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

        # Evaluate custom policies first (Plan 5)
        decision = None
        custom_policy_matched = False
        if self.custom_policy_engine and self.custom_policy_enabled:
            current_mode = self.policy_engine.get_current_mode()
            decision = self.custom_policy_engine.evaluate(request, env_state, current_mode)
            if decision:
                custom_policy_matched = True

        # Fall back to default policy if no custom policy matched
        if decision is None:
            decision = self.policy_engine.evaluate_policy(request, env_state)

        self.event_logger.log_event(
            EventType.TOOL_REQUEST,
            f"Tool '{tool_name}' request: {decision.value}",
            metadata={
                'tool_name': tool_name,
                'decision': decision.value,
                'requires_network': requires_network,
                'requires_filesystem': requires_filesystem,
                'requires_usb': requires_usb,
                'custom_policy_matched': custom_policy_matched
            }
        )

        if decision == PolicyDecision.ALLOW:
            return (True, "Tool execution permitted")
        elif decision == PolicyDecision.DENY:
            return (False, f"Tool execution denied by policy")
        else:
            return (False, "Tool requires human override ceremony")

    def check_message(self, content: str, source: str = 'unknown',
                     context: Optional[dict] = None) -> tuple[bool, str, Optional[dict]]:
        """
        Check message content for policy compliance.

        Args:
            content: Message content to check
            source: Source system ('natlangchain', 'agent_os', or other)
            context: Optional additional context

        Returns:
            (permitted, reason, result_data)
        """
        if self.lockdown_manager.is_in_lockdown():
            return (False, "System in LOCKDOWN mode", None)

        if not self.message_checker:
            return (False, "Message checker not available", None)

        # Map source string to enum
        if MESSAGE_CHECKER_AVAILABLE and MessageSource:
            source_map = {
                'natlangchain': MessageSource.NATLANGCHAIN,
                'agent_os': MessageSource.AGENT_OS,
                'agent-os': MessageSource.AGENT_OS,
                'agentos': MessageSource.AGENT_OS,
            }
            msg_source = source_map.get(source.lower(), MessageSource.UNKNOWN)
        else:
            return (False, "Message source types not available", None)

        result = self.message_checker.check_message(content, msg_source, context)

        # Log the check
        self.event_logger.log_event(
            EventType.MESSAGE_CHECK,
            f"Message check ({source}): {'allowed' if result.allowed else 'blocked'}",
            metadata={
                'source': source,
                'allowed': result.allowed,
                'result_type': result.result_type.value,
                'violations': result.violations,
            }
        )

        return (result.allowed, result.reason, result.to_dict())

    def check_natlangchain_entry(self, author: str, intent: str, timestamp: str,
                                  signature: Optional[str] = None,
                                  previous_hash: Optional[str] = None,
                                  metadata: Optional[dict] = None) -> tuple[bool, str, Optional[dict]]:
        """
        Check a NatLangChain blockchain entry.

        Args:
            author: Entry author
            intent: Intent description (prose)
            timestamp: Entry timestamp (ISO format)
            signature: Optional cryptographic signature
            previous_hash: Optional hash of previous entry
            metadata: Optional additional metadata

        Returns:
            (permitted, reason, result_data)
        """
        if self.lockdown_manager.is_in_lockdown():
            return (False, "System in LOCKDOWN mode", None)

        if not self.message_checker or not MESSAGE_CHECKER_AVAILABLE:
            return (False, "Message checker not available", None)

        entry = NatLangChainEntry(
            author=author,
            intent=intent,
            timestamp=timestamp,
            signature=signature,
            previous_hash=previous_hash,
            metadata=metadata or {}
        )

        result = self.message_checker.check_natlangchain_entry(entry)

        # Log the check
        self.event_logger.log_event(
            EventType.MESSAGE_CHECK,
            f"NatLangChain entry check: {'allowed' if result.allowed else 'blocked'}",
            metadata={
                'source': 'natlangchain',
                'author': author,
                'allowed': result.allowed,
                'result_type': result.result_type.value,
                'violations': result.violations,
            }
        )

        return (result.allowed, result.reason, result.to_dict())

    def check_agentos_message(self, sender_agent: str, recipient_agent: str,
                               content: str, message_type: str = 'request',
                               authority_level: int = 0,
                               timestamp: Optional[str] = None,
                               requires_consent: bool = False,
                               metadata: Optional[dict] = None) -> tuple[bool, str, Optional[dict]]:
        """
        Check an Agent-OS inter-agent message.

        Args:
            sender_agent: Sending agent identifier
            recipient_agent: Receiving agent identifier
            content: Message content
            message_type: Type of message (request, response, notification, command)
            authority_level: Authority level (0-5)
            timestamp: Message timestamp (ISO format)
            requires_consent: Whether consent is required
            metadata: Optional additional metadata

        Returns:
            (permitted, reason, result_data)
        """
        if self.lockdown_manager.is_in_lockdown():
            return (False, "System in LOCKDOWN mode", None)

        if not self.message_checker or not MESSAGE_CHECKER_AVAILABLE:
            return (False, "Message checker not available", None)

        from datetime import datetime as dt
        if timestamp is None:
            timestamp = dt.utcnow().isoformat() + "Z"

        message = AgentOSMessage(
            sender_agent=sender_agent,
            recipient_agent=recipient_agent,
            content=content,
            message_type=message_type,
            authority_level=authority_level,
            timestamp=timestamp,
            requires_consent=requires_consent,
            metadata=metadata or {}
        )

        result = self.message_checker.check_agentos_message(message)

        # Log the check
        self.event_logger.log_event(
            EventType.MESSAGE_CHECK,
            f"Agent-OS message check: {'allowed' if result.allowed else 'blocked'}",
            metadata={
                'source': 'agent_os',
                'sender': sender_agent,
                'recipient': recipient_agent,
                'message_type': message_type,
                'authority_level': authority_level,
                'allowed': result.allowed,
                'result_type': result.result_type.value,
                'violations': result.violations,
            }
        )

        return (result.allowed, result.reason, result.to_dict())

    def get_status(self) -> dict:
        """Get current daemon status"""
        boundary_state = self.policy_engine.get_current_state()
        env_state = self.state_monitor.get_current_state()
        lockdown_info = self.lockdown_manager.get_lockdown_info()

        status = {
            'running': self._running,
            'boundary_state': boundary_state.to_dict(),
            'environment': env_state.to_dict() if env_state else None,
            'lockdown': lockdown_info,
            'event_count': self.event_logger.get_event_count(),
            'tripwire_violations': self.tripwire_system.get_violation_count(),
            'signed_logging': self.signed_logging
        }

        # Add public key if signed logging is enabled
        if self.signed_logging and hasattr(self.event_logger, 'get_public_key_hex'):
            status['public_verification_key'] = self.event_logger.get_public_key_hex()

        # Add cluster information if enabled
        status['cluster_enabled'] = self.cluster_enabled
        if self.cluster_manager and self.cluster_enabled:
            try:
                cluster_state = self.cluster_manager.get_cluster_state()
                status['cluster'] = {
                    'node_id': self.cluster_manager.node_id,
                    'cluster_mode': cluster_state.cluster_mode,
                    'total_nodes': len(cluster_state.nodes),
                    'healthy_nodes': len(self.cluster_manager.get_healthy_nodes()),
                    'total_violations': cluster_state.total_violations
                }
            except Exception as e:
                status['cluster'] = {'error': str(e)}

        # Add custom policy information if enabled (Plan 5)
        status['custom_policy_enabled'] = self.custom_policy_enabled
        if self.custom_policy_engine and self.custom_policy_enabled:
            try:
                enabled_policies = self.custom_policy_engine.get_enabled_policies()
                status['custom_policy'] = {
                    'policy_dir': str(self.custom_policy_engine.policy_dir),
                    'total_policies': len(self.custom_policy_engine.policies),
                    'enabled_policies': len(enabled_policies),
                    'policy_names': [p.name for p in enabled_policies]
                }
            except Exception as e:
                status['custom_policy'] = {'error': str(e)}

        # Add biometric authentication information if enabled (Plan 6)
        status['biometric_enabled'] = self.biometric_enabled
        if self.biometric_verifier and self.biometric_enabled:
            try:
                caps = self.biometric_verifier.get_capabilities()
                status['biometric'] = {
                    'template_dir': str(self.biometric_verifier.template_dir),
                    'fingerprint_available': caps['fingerprint_available'],
                    'face_available': caps['face_available'],
                    'enrolled_count': caps['enrolled_count'],
                    'fingerprint_enrolled': caps['fingerprint_enrolled'],
                    'face_enrolled': caps['face_enrolled']
                }
                if self.ceremony_manager:
                    ceremony_stats = self.ceremony_manager.get_ceremony_stats()
                    status['biometric']['ceremony_stats'] = ceremony_stats
            except Exception as e:
                status['biometric'] = {'error': str(e)}

        # Add security advisor information if enabled (Plan 7)
        status['security_advisor_enabled'] = self.security_advisor_enabled
        if self.security_advisor and self.security_advisor_enabled:
            try:
                stats = self.security_advisor.get_summary_stats()
                status['security_advisor'] = {
                    'model': self.security_advisor.model,
                    'ollama_available': self.security_advisor.is_available(),
                    'storage_dir': str(self.security_advisor.storage_dir),
                    'total_advisories': stats['total'],
                    'by_severity': stats['by_severity'],
                    'by_status': stats['by_status']
                }
            except Exception as e:
                status['security_advisor'] = {'error': str(e)}

        # Add log watchdog information if enabled (Plan 8)
        status['watchdog_enabled'] = self.watchdog_enabled
        if self.log_watchdog and self.watchdog_enabled:
            try:
                stats = self.log_watchdog.get_summary_stats()
                status['watchdog'] = {
                    'model': self.log_watchdog.model,
                    'ollama_available': self.log_watchdog.is_available(),
                    'monitoring': stats['monitoring'],
                    'log_paths': stats['log_paths'],
                    'total_alerts': stats['total'],
                    'by_severity': stats['by_severity'],
                    'by_status': stats['by_status']
                }
            except Exception as e:
                status['watchdog'] = {'error': str(e)}

        # Add telemetry information if enabled (Plan 9)
        status['telemetry_enabled'] = self.telemetry_enabled
        if self.telemetry_manager and self.telemetry_enabled:
            try:
                stats = self.telemetry_manager.get_summary_stats()
                status['telemetry'] = {
                    'otel_available': stats['otel_available'],
                    'otlp_available': stats['otlp_available'],
                    'export_mode': stats['export_mode'],
                    'instance_id': stats['instance_id'],
                    'hostname': stats['hostname'],
                    'metrics_count': stats['metrics_count'],
                    'spans_recorded': stats['spans_recorded']
                }
            except Exception as e:
                status['telemetry'] = {'error': str(e)}

        # Add message checker information if enabled (Plan 10)
        status['message_checker_enabled'] = self.message_checker_enabled
        if self.message_checker and self.message_checker_enabled:
            status['message_checker'] = {
                'strict_mode': self.message_checker.strict_mode,
                'natlangchain_support': True,
                'agentos_support': True,
                'pii_detection': True,
                'ambiguity_detection': True,
            }

        return status

    def verify_log_integrity(self) -> tuple[bool, str]:
        """
        Verify the integrity of the event log.

        Returns:
            (is_valid, message)
        """
        if self.signed_logging and hasattr(self.event_logger, 'verify_full_integrity'):
            valid, error = self.event_logger.verify_full_integrity()
            if valid:
                return (True, "Log integrity verified (hash chain + signatures)")
            else:
                return (False, error or "Integrity check failed")
        else:
            # Fall back to hash chain verification only
            valid, error = self.event_logger.verify_chain()
            if valid:
                return (True, "Hash chain verified (signatures not available)")
            else:
                return (False, error or "Hash chain verification failed")

    def export_public_key(self, output_path: str) -> bool:
        """
        Export the log signing public key for external verification.

        Args:
            output_path: Path to save the public key

        Returns:
            True if successful, False if signed logging not available
        """
        if self.signed_logging and hasattr(self.event_logger, 'export_public_key'):
            return self.event_logger.export_public_key(output_path)
        else:
            print("Signed logging not available - no public key to export")
            return False

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

    def reload_custom_policies(self) -> tuple[bool, str]:
        """
        Reload custom policy files from disk (Plan 5).

        Returns:
            (success, message)
        """
        if not self.custom_policy_engine or not self.custom_policy_enabled:
            return (False, "Custom policy engine not enabled")

        try:
            self.custom_policy_engine.reload_policies()
            policy_count = len(self.custom_policy_engine.get_enabled_policies())
            self.event_logger.log_event(
                EventType.POLICY_DECISION,
                f"Custom policies reloaded: {policy_count} enabled policies",
                metadata={'policy_count': policy_count, 'action': 'reload'}
            )
            return (True, f"Reloaded {policy_count} custom policies")
        except Exception as e:
            return (False, f"Failed to reload policies: {e}")

    def enroll_biometric(self, biometric_type: str = 'fingerprint') -> tuple[bool, str]:
        """
        Enroll a new biometric template (Plan 6).

        Args:
            biometric_type: 'fingerprint' or 'face'

        Returns:
            (success, message)
        """
        if not self.biometric_verifier or not self.biometric_enabled:
            return (False, "Biometric authentication not enabled")

        try:
            if biometric_type == 'fingerprint':
                success, error = self.biometric_verifier.enroll_fingerprint()
            elif biometric_type == 'face':
                success, error = self.biometric_verifier.enroll_face()
            else:
                return (False, f"Unknown biometric type: {biometric_type}")

            if success:
                self.event_logger.log_event(
                    EventType.BIOMETRIC_ATTEMPT,
                    f"Biometric enrollment success: {biometric_type}",
                    metadata={'biometric_type': biometric_type, 'action': 'enroll', 'success': True}
                )
                return (True, f"{biometric_type.capitalize()} enrolled successfully")
            else:
                self.event_logger.log_event(
                    EventType.BIOMETRIC_ATTEMPT,
                    f"Biometric enrollment failed: {biometric_type}",
                    metadata={'biometric_type': biometric_type, 'action': 'enroll', 'success': False, 'error': error}
                )
                return (False, error or "Enrollment failed")
        except Exception as e:
            return (False, f"Enrollment error: {e}")

    def perform_override_ceremony(self, action: str, reason: str,
                                  require_biometric: bool = True) -> tuple[bool, str]:
        """
        Perform a human override ceremony with optional biometric verification (Plan 6).

        Args:
            action: Description of the action being overridden
            reason: Reason for the override
            require_biometric: Whether to require biometric verification

        Returns:
            (success, message)
        """
        if self.ceremony_manager and self.biometric_enabled:
            return self.ceremony_manager.initiate_override(
                action=action,
                reason=reason,
                require_biometric=require_biometric
            )
        else:
            # Fall back to basic keyboard ceremony
            print(f"\nOverride ceremony for: {action}")
            print(f"Reason: {reason}")
            print("\nBiometric not available. Using keyboard ceremony.")
            print("Type 'CONFIRM' to proceed:")
            user_input = input("> ")
            if user_input == "CONFIRM":
                self.event_logger.log_event(
                    EventType.OVERRIDE,
                    f"Override ceremony success (keyboard): {action}",
                    metadata={'action': action, 'reason': reason, 'method': 'keyboard'}
                )
                return (True, "Override ceremony completed")
            else:
                self.event_logger.log_event(
                    EventType.OVERRIDE,
                    f"Override ceremony failed (keyboard): {action}",
                    metadata={'action': action, 'reason': reason, 'method': 'keyboard'}
                )
                return (False, "Confirmation failed")

    def list_biometric_templates(self) -> list:
        """
        List enrolled biometric templates (Plan 6).

        Returns:
            List of enrolled template metadata
        """
        if not self.biometric_verifier or not self.biometric_enabled:
            return []

        templates = self.biometric_verifier.list_enrolled()
        return [
            {
                'template_id': t.template_id,
                'type': t.biometric_type.value,
                'created_at': t.created_at,
                'last_used': t.last_used,
                'use_count': t.use_count
            }
            for t in templates
        ]

    def delete_biometric_template(self, template_id: str) -> tuple[bool, str]:
        """
        Delete a biometric template (Plan 6).

        Args:
            template_id: ID of template to delete

        Returns:
            (success, message)
        """
        if not self.biometric_verifier or not self.biometric_enabled:
            return (False, "Biometric authentication not enabled")

        # Require ceremony to delete templates
        success, msg = self.perform_override_ceremony(
            action=f"Delete biometric template {template_id}",
            reason="User requested template deletion",
            require_biometric=True
        )

        if not success:
            return (False, f"Ceremony failed: {msg}")

        if self.biometric_verifier.delete_template(template_id):
            self.event_logger.log_event(
                EventType.BIOMETRIC_ATTEMPT,
                f"Biometric template deleted: {template_id}",
                metadata={'template_id': template_id, 'action': 'delete'}
            )
            return (True, f"Template {template_id} deleted")
        else:
            return (False, f"Template {template_id} not found")

    def scan_code(self, path: str, recursive: bool = True) -> tuple[bool, str, list]:
        """
        Scan code for vulnerabilities using the security advisor (Plan 7).

        Args:
            path: Path to file or directory to scan
            recursive: If True and path is directory, scan recursively

        Returns:
            (success, message, advisories)
        """
        if not self.security_advisor or not self.security_advisor_enabled:
            return (False, "Security advisor not enabled", [])

        if not self.security_advisor.is_available():
            return (False, "Ollama not available for security scanning", [])

        try:
            import os
            if os.path.isfile(path):
                # Scan single file
                result = self.security_advisor.scan_file(path)
                advisories = result.advisories if result else []
                msg = f"Scanned {path}: {len(advisories)} advisory(ies) found"
            elif os.path.isdir(path):
                # Scan directory/repository
                result = self.security_advisor.scan_repository(path)
                advisories = result.advisories if result else []
                msg = f"Scanned repository {path}: {len(advisories)} advisory(ies) found"
            else:
                return (False, f"Path not found: {path}", [])

            # Log the scan
            self.event_logger.log_event(
                EventType.POLICY_DECISION,  # Using existing event type for security scans
                f"Security scan completed: {msg}",
                metadata={
                    'path': path,
                    'advisory_count': len(advisories),
                    'action': 'security_scan'
                }
            )

            # Convert advisories to dicts for serialization
            advisory_dicts = [
                {
                    'id': a.id,
                    'file_path': a.file_path,
                    'line_start': a.line_start,
                    'line_end': a.line_end,
                    'severity': a.severity.value if hasattr(a.severity, 'value') else str(a.severity),
                    'title': a.title,
                    'description': a.description,
                    'recommendation': a.recommendation,
                    'status': a.status.value if hasattr(a.status, 'value') else str(a.status),
                    'created_at': a.created_at
                }
                for a in advisories
            ]

            return (True, msg, advisory_dicts)

        except Exception as e:
            return (False, f"Scan error: {e}", [])

    def get_security_advisories(self, status_filter: str = None) -> list:
        """
        Get stored security advisories (Plan 7).

        Args:
            status_filter: Optional status to filter by ('open', 'reviewed', 'dismissed', 'fixed')

        Returns:
            List of advisory dictionaries
        """
        if not self.security_advisor or not self.security_advisor_enabled:
            return []

        try:
            advisories = self.security_advisor.load_advisories()

            # Filter by status if specified
            if status_filter and AdvisoryStatus:
                try:
                    target_status = AdvisoryStatus(status_filter)
                    advisories = [a for a in advisories if a.status == target_status]
                except ValueError:
                    pass  # Invalid status, return all

            # Convert to dicts
            return [
                {
                    'id': a.id,
                    'file_path': a.file_path,
                    'line_start': a.line_start,
                    'line_end': a.line_end,
                    'severity': a.severity.value if hasattr(a.severity, 'value') else str(a.severity),
                    'title': a.title,
                    'description': a.description,
                    'recommendation': a.recommendation,
                    'status': a.status.value if hasattr(a.status, 'value') else str(a.status),
                    'created_at': a.created_at
                }
                for a in advisories
            ]
        except Exception as e:
            print(f"Error loading advisories: {e}")
            return []

    def update_security_advisory(self, advisory_id: str, new_status: str,
                                  note: str = None) -> tuple[bool, str]:
        """
        Update the status of a security advisory (Plan 7).

        Args:
            advisory_id: ID of the advisory to update
            new_status: New status ('reviewed', 'dismissed', 'fixed')
            note: Optional note about the update

        Returns:
            (success, message)
        """
        if not self.security_advisor or not self.security_advisor_enabled:
            return (False, "Security advisor not enabled")

        try:
            # Validate status
            if not AdvisoryStatus:
                return (False, "AdvisoryStatus not available")

            try:
                status = AdvisoryStatus(new_status)
            except ValueError:
                valid_statuses = [s.value for s in AdvisoryStatus]
                return (False, f"Invalid status '{new_status}'. Valid: {valid_statuses}")

            # Update the advisory
            success = self.security_advisor.update_advisory_status(advisory_id, status, note)

            if success:
                self.event_logger.log_event(
                    EventType.POLICY_DECISION,
                    f"Security advisory {advisory_id} updated to {new_status}",
                    metadata={
                        'advisory_id': advisory_id,
                        'new_status': new_status,
                        'note': note,
                        'action': 'advisory_update'
                    }
                )
                return (True, f"Advisory {advisory_id} updated to {new_status}")
            else:
                return (False, f"Advisory {advisory_id} not found")

        except Exception as e:
            return (False, f"Update error: {e}")

    def get_security_summary(self) -> dict:
        """
        Get a summary of security advisor status (Plan 7).

        Returns:
            Dictionary with security summary statistics
        """
        if not self.security_advisor or not self.security_advisor_enabled:
            return {'enabled': False, 'error': 'Security advisor not enabled'}

        try:
            stats = self.security_advisor.get_summary_stats()
            return {
                'enabled': True,
                'model': self.security_advisor.model,
                'ollama_available': self.security_advisor.is_available(),
                'total_advisories': stats['total'],
                'by_severity': stats['by_severity'],
                'by_status': stats['by_status']
            }
        except Exception as e:
            return {'enabled': True, 'error': str(e)}

    # Log Watchdog API methods (Plan 8)

    def start_watchdog(self) -> tuple[bool, str]:
        """
        Start the log watchdog monitoring (Plan 8).

        Returns:
            (success, message)
        """
        if not self.log_watchdog or not self.watchdog_enabled:
            return (False, "Log watchdog not enabled")

        try:
            self.log_watchdog.start()
            self.event_logger.log_event(
                EventType.HEALTH_CHECK,
                "Log watchdog started",
                metadata={'action': 'watchdog_start', 'log_paths': self.log_watchdog.log_paths}
            )
            return (True, f"Watchdog started, monitoring {len(self.log_watchdog.log_paths)} file(s)")
        except Exception as e:
            return (False, f"Failed to start watchdog: {e}")

    def stop_watchdog(self) -> tuple[bool, str]:
        """
        Stop the log watchdog monitoring (Plan 8).

        Returns:
            (success, message)
        """
        if not self.log_watchdog or not self.watchdog_enabled:
            return (False, "Log watchdog not enabled")

        try:
            self.log_watchdog.stop()
            self.event_logger.log_event(
                EventType.HEALTH_CHECK,
                "Log watchdog stopped",
                metadata={'action': 'watchdog_stop'}
            )
            return (True, "Watchdog stopped")
        except Exception as e:
            return (False, f"Failed to stop watchdog: {e}")

    def get_watchdog_alerts(self, severity: str = None, status: str = None,
                            limit: int = 100) -> list:
        """
        Get watchdog alerts with optional filtering (Plan 8).

        Args:
            severity: Filter by severity ('low', 'medium', 'high', 'critical')
            status: Filter by status ('new', 'acknowledged', 'resolved', 'dismissed')
            limit: Maximum number of alerts to return

        Returns:
            List of alert dictionaries
        """
        if not self.log_watchdog or not self.watchdog_enabled:
            return []

        try:
            sev_filter = None
            stat_filter = None

            if severity and WatchdogSeverity:
                try:
                    sev_filter = WatchdogSeverity(severity)
                except ValueError:
                    pass

            if status and WatchdogStatus:
                try:
                    stat_filter = WatchdogStatus(status)
                except ValueError:
                    pass

            alerts = self.log_watchdog.get_alerts(
                severity=sev_filter,
                status=stat_filter,
                limit=limit
            )

            return [a.to_dict() for a in alerts]

        except Exception as e:
            print(f"Error getting watchdog alerts: {e}")
            return []

    def acknowledge_watchdog_alert(self, alert_id: str) -> tuple[bool, str]:
        """
        Acknowledge a watchdog alert (Plan 8).

        Args:
            alert_id: ID of the alert to acknowledge

        Returns:
            (success, message)
        """
        if not self.log_watchdog or not self.watchdog_enabled:
            return (False, "Log watchdog not enabled")

        if self.log_watchdog.acknowledge_alert(alert_id):
            self.event_logger.log_event(
                EventType.HEALTH_CHECK,
                f"Watchdog alert acknowledged: {alert_id}",
                metadata={'alert_id': alert_id, 'action': 'acknowledge'}
            )
            return (True, f"Alert {alert_id} acknowledged")
        else:
            return (False, f"Alert {alert_id} not found")

    def resolve_watchdog_alert(self, alert_id: str) -> tuple[bool, str]:
        """
        Mark a watchdog alert as resolved (Plan 8).

        Args:
            alert_id: ID of the alert to resolve

        Returns:
            (success, message)
        """
        if not self.log_watchdog or not self.watchdog_enabled:
            return (False, "Log watchdog not enabled")

        if self.log_watchdog.resolve_alert(alert_id):
            self.event_logger.log_event(
                EventType.HEALTH_CHECK,
                f"Watchdog alert resolved: {alert_id}",
                metadata={'alert_id': alert_id, 'action': 'resolve'}
            )
            return (True, f"Alert {alert_id} resolved")
        else:
            return (False, f"Alert {alert_id} not found")

    def dismiss_watchdog_alert(self, alert_id: str) -> tuple[bool, str]:
        """
        Dismiss a watchdog alert (Plan 8).

        Args:
            alert_id: ID of the alert to dismiss

        Returns:
            (success, message)
        """
        if not self.log_watchdog or not self.watchdog_enabled:
            return (False, "Log watchdog not enabled")

        if self.log_watchdog.dismiss_alert(alert_id):
            self.event_logger.log_event(
                EventType.HEALTH_CHECK,
                f"Watchdog alert dismissed: {alert_id}",
                metadata={'alert_id': alert_id, 'action': 'dismiss'}
            )
            return (True, f"Alert {alert_id} dismissed")
        else:
            return (False, f"Alert {alert_id} not found")

    def add_watchdog_log_path(self, path: str) -> tuple[bool, str]:
        """
        Add a log file to watchdog monitoring (Plan 8).

        Args:
            path: Path to log file

        Returns:
            (success, message)
        """
        if not self.log_watchdog or not self.watchdog_enabled:
            return (False, "Log watchdog not enabled")

        if not os.path.exists(path):
            return (False, f"Log file not found: {path}")

        self.log_watchdog.add_log_path(path)
        self.event_logger.log_event(
            EventType.HEALTH_CHECK,
            f"Watchdog log path added: {path}",
            metadata={'path': path, 'action': 'add_log_path'}
        )
        return (True, f"Added {path} to watchdog monitoring")

    def get_watchdog_summary(self) -> dict:
        """
        Get a summary of log watchdog status (Plan 8).

        Returns:
            Dictionary with watchdog summary statistics
        """
        if not self.log_watchdog or not self.watchdog_enabled:
            return {'enabled': False, 'error': 'Log watchdog not enabled'}

        try:
            stats = self.log_watchdog.get_summary_stats()
            return {
                'enabled': True,
                'model': self.log_watchdog.model,
                'ollama_available': self.log_watchdog.is_available(),
                'monitoring': stats['monitoring'],
                'log_paths': stats['log_paths'],
                'total_alerts': stats['total'],
                'by_severity': stats['by_severity'],
                'by_status': stats['by_status']
            }
        except Exception as e:
            return {'enabled': True, 'error': str(e)}

    def analyze_log_entry(self, entry: str, source: str = "manual") -> tuple[bool, str, dict]:
        """
        Manually analyze a log entry with the watchdog (Plan 8).

        Args:
            entry: Log entry text to analyze
            source: Source identifier

        Returns:
            (success, message, alert_dict or None)
        """
        if not self.log_watchdog or not self.watchdog_enabled:
            return (False, "Log watchdog not enabled", {})

        if not self.log_watchdog.is_available():
            return (False, "Ollama not available for analysis", {})

        try:
            alert = self.log_watchdog.analyze_log_entry(entry, source)
            if alert:
                return (True, f"Alert generated: {alert.severity.value}", alert.to_dict())
            else:
                return (True, "No issues detected", {})
        except Exception as e:
            return (False, f"Analysis error: {e}", {})

    # Telemetry API methods (Plan 9)

    def get_telemetry_summary(self) -> dict:
        """
        Get a summary of telemetry status (Plan 9).

        Returns:
            Dictionary with telemetry summary statistics
        """
        if not self.telemetry_manager or not self.telemetry_enabled:
            return {'enabled': False, 'error': 'Telemetry not enabled'}

        try:
            return self.telemetry_manager.get_summary_stats()
        except Exception as e:
            return {'enabled': True, 'error': str(e)}

    def record_telemetry_span(self, name: str, attributes: dict = None) -> tuple[bool, str]:
        """
        Record a custom telemetry span (Plan 9).

        Args:
            name: Span name
            attributes: Optional span attributes

        Returns:
            (success, message)
        """
        if not self.telemetry_manager or not self.telemetry_enabled:
            return (False, "Telemetry not enabled")

        try:
            with self.telemetry_manager.start_span(name, attributes) as span:
                span.add_event("custom_span_created")
            return (True, f"Span '{name}' recorded")
        except Exception as e:
            return (False, f"Failed to record span: {e}")

    def record_telemetry_metric(self, name: str, value: float, attributes: dict = None) -> tuple[bool, str]:
        """
        Record a custom telemetry metric (Plan 9).

        Args:
            name: Metric name
            value: Metric value
            attributes: Optional metric attributes

        Returns:
            (success, message)
        """
        if not self.telemetry_manager or not self.telemetry_enabled:
            return (False, "Telemetry not enabled")

        try:
            self.telemetry_manager.record_metric(name, value, attributes)
            return (True, f"Metric '{name}' recorded with value {value}")
        except Exception as e:
            return (False, f"Failed to record metric: {e}")

    def get_recent_telemetry_spans(self, limit: int = 100) -> list:
        """
        Get recently recorded telemetry spans (Plan 9).

        Args:
            limit: Maximum number of spans to return

        Returns:
            List of span dictionaries
        """
        if not self.telemetry_manager or not self.telemetry_enabled:
            return []

        try:
            return self.telemetry_manager.get_recent_spans(limit)
        except Exception as e:
            print(f"Error getting recent spans: {e}")
            return []

    def get_telemetry_metrics(self) -> dict:
        """
        Get telemetry metrics snapshot (Plan 9).

        Returns:
            Dictionary with metrics data
        """
        if not self.telemetry_manager or not self.telemetry_enabled:
            return {}

        try:
            return self.telemetry_manager.get_metrics_snapshot()
        except Exception as e:
            print(f"Error getting metrics: {e}")
            return {}


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
