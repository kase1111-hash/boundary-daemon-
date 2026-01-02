#!/usr/bin/env python3
"""
Boundary Daemon - Agent Smith
The hard enforcement layer that defines and maintains trust boundaries.

This is the authoritative security enforcer for the Agent OS system.
It determines where cognition is allowed to flow and where it must stop.
"""

import os
import gc
import signal
import sys
import time
import threading
from datetime import datetime
from typing import Optional, Tuple
import logging

logger = logging.getLogger(__name__)

# Cross-platform detection
IS_WINDOWS = sys.platform == 'win32'

# Import core components
from .state_monitor import StateMonitor, EnvironmentState, NetworkState
from .policy_engine import PolicyEngine, BoundaryMode, PolicyRequest, PolicyDecision, Operator, MemoryClass
from .tripwires import TripwireSystem, LockdownManager, TripwireViolation
from .event_logger import EventLogger, EventType
from .constants import Paths

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

# Import protection persistence (Critical: Survives Daemon Restarts)
try:
    from .enforcement import (
        ProtectionPersistenceManager,
        CleanupPolicy,
    )
    PROTECTION_PERSISTENCE_AVAILABLE = True
except ImportError:
    PROTECTION_PERSISTENCE_AVAILABLE = False
    ProtectionPersistenceManager = None
    CleanupPolicy = None

# Import privilege manager (Critical: Prevents Silent Enforcement Failures)
try:
    from .privilege_manager import (
        PrivilegeManager,
        EnforcementModule,
        set_privilege_manager,
    )
    PRIVILEGE_MANAGER_AVAILABLE = True
except ImportError:
    PRIVILEGE_MANAGER_AVAILABLE = False
    PrivilegeManager = None
    EnforcementModule = None

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

# Import hardened watchdog (SECURITY: Addresses "External Watchdog Can Be Killed")
try:
    from .watchdog import (
        DaemonWatchdogEndpoint,
        generate_shared_secret,
        WatchdogState,
    )
    HARDENED_WATCHDOG_AVAILABLE = True
except ImportError:
    HARDENED_WATCHDOG_AVAILABLE = False
    DaemonWatchdogEndpoint = None
    generate_shared_secret = None
    WatchdogState = None

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

# Import clock monitor module (Clock Drift Protection)
try:
    from .security.clock_monitor import ClockMonitor, ClockStatus, TimeJumpEvent
    CLOCK_MONITOR_AVAILABLE = True
except ImportError:
    CLOCK_MONITOR_AVAILABLE = False
    ClockMonitor = None
    ClockStatus = None
    TimeJumpEvent = None

# Import daemon integrity protection (SECURITY: Binary tampering prevention)
try:
    from .security.daemon_integrity import (
        DaemonIntegrityProtector,
        IntegrityConfig,
        IntegrityAction,
        verify_daemon_integrity,
    )
    DAEMON_INTEGRITY_AVAILABLE = True
except ImportError:
    DAEMON_INTEGRITY_AVAILABLE = False
    DaemonIntegrityProtector = None
    IntegrityConfig = None
    IntegrityAction = None
    verify_daemon_integrity = None

# Import network attestation (Phase 1: Network Trust Verification)
try:
    from .security.network_attestation import (
        NetworkAttestor,
        NetworkAttestationConfig,
        NetworkTrustLevel,
        AttestationResult,
    )
    NETWORK_ATTESTATION_AVAILABLE = True
except ImportError:
    NETWORK_ATTESTATION_AVAILABLE = False
    NetworkAttestor = None
    NetworkAttestationConfig = None
    NetworkTrustLevel = None
    AttestationResult = None

# Import secure config storage (SECURITY: Configuration encryption)
try:
    from .config import (
        SecureConfigStorage,
        SecureConfigOptions,
        EncryptionMode,
        load_secure_config,
    )
    SECURE_CONFIG_AVAILABLE = True
except ImportError:
    SECURE_CONFIG_AVAILABLE = False
    SecureConfigStorage = None
    SecureConfigOptions = None
    EncryptionMode = None
    load_secure_config = None

# Import redundant event logger (SECURITY: Logging redundancy)
try:
    from .redundant_event_logger import (
        RedundantEventLogger,
        RedundantLoggerConfig,
        BackendConfig,
        LogBackendType,
        create_redundant_logger,
    )
    REDUNDANT_LOGGING_AVAILABLE = True
except ImportError:
    REDUNDANT_LOGGING_AVAILABLE = False
    RedundantEventLogger = None
    RedundantLoggerConfig = None
    BackendConfig = None
    LogBackendType = None
    create_redundant_logger = None

# Import memory monitor (Plan 11: Memory Leak Monitoring)
try:
    from .memory_monitor import (
        MemoryMonitor,
        MemoryMonitorConfig,
        MemoryAlertLevel,
        LeakIndicator,
        TraceMallocDebugger,
        LeakReport,
        create_memory_monitor,
    )
    MEMORY_MONITOR_AVAILABLE = True
except ImportError:
    MEMORY_MONITOR_AVAILABLE = False
    MemoryMonitor = None
    MemoryMonitorConfig = None
    MemoryAlertLevel = None
    LeakIndicator = None
    TraceMallocDebugger = None
    LeakReport = None
    create_memory_monitor = None

# Import resource monitor (Plan 11: Resource Monitoring)
try:
    from .resource_monitor import (
        ResourceMonitor,
        ResourceMonitorConfig,
        ResourceAlertLevel,
        ResourceType,
        create_resource_monitor,
    )
    RESOURCE_MONITOR_AVAILABLE = True
except ImportError:
    RESOURCE_MONITOR_AVAILABLE = False
    ResourceMonitor = None
    ResourceMonitorConfig = None
    ResourceAlertLevel = None
    ResourceType = None
    create_resource_monitor = None

# Import health monitor (Plan 11: Health Monitoring)
try:
    from .health_monitor import (
        HealthMonitor,
        HealthMonitorConfig,
        HealthStatus,
        ComponentStatus,
        create_health_monitor,
    )
    HEALTH_MONITOR_AVAILABLE = True
except ImportError:
    HEALTH_MONITOR_AVAILABLE = False
    HealthMonitor = None
    HealthMonitorConfig = None
    HealthStatus = None
    ComponentStatus = None
    create_health_monitor = None

# Import queue monitor (Plan 11: Queue Monitoring)
try:
    from .queue_monitor import (
        QueueMonitor,
        QueueMonitorConfig,
        QueueConfig,
        QueueAlertLevel,
        BackpressureState,
        create_queue_monitor,
    )
    QUEUE_MONITOR_AVAILABLE = True
except ImportError:
    QUEUE_MONITOR_AVAILABLE = False
    QueueMonitor = None
    QueueMonitorConfig = None
    QueueConfig = None
    QueueAlertLevel = None
    BackpressureState = None
    create_queue_monitor = None

# Import monitoring report generator (Plan 11: Report Generation)
try:
    from .monitoring_report import (
        MonitoringReportGenerator,
        OllamaConfig,
        ReportType,
        create_report_generator,
    )
    REPORT_GENERATOR_AVAILABLE = True
except ImportError:
    REPORT_GENERATOR_AVAILABLE = False
    MonitoringReportGenerator = None
    OllamaConfig = None
    ReportType = None
    create_report_generator = None

# Import detection event publisher (Attack Detection Integration)
try:
    from .detection import (
        EventPublisher,
        get_event_publisher,
        configure_event_publisher,
    )
    EVENT_PUBLISHER_AVAILABLE = True
except ImportError:
    EVENT_PUBLISHER_AVAILABLE = False
    EventPublisher = None
    get_event_publisher = None
    configure_event_publisher = None

# Import SIEM integration (SECURITY: Security event forwarding)
try:
    from .security.siem_integration import (
        SIEMIntegration,
        SIEMConfig,
        SIEMTransport,
        SIEMFormat,
        SecurityEventSeverity,
        init_siem,
    )
    from .utils.error_handling import set_siem_integration
    SIEM_AVAILABLE = True
except ImportError:
    SIEM_AVAILABLE = False
    SIEMIntegration = None
    SIEMConfig = None
    SIEMTransport = None
    SIEMFormat = None
    SecurityEventSeverity = None
    init_siem = None
    set_siem_integration = None

# Import dreaming status reporter (CLI status updates)
try:
    from .dreaming import (
        DreamingReporter,
        DreamPhase,
        create_dreaming_reporter,
        set_dreaming_reporter,
    )
    DREAMING_AVAILABLE = True
except ImportError:
    DREAMING_AVAILABLE = False
    DreamingReporter = None
    DreamPhase = None
    create_dreaming_reporter = None
    set_dreaming_reporter = None


class BoundaryDaemon:
    """
    Main Boundary Daemon service.

    Coordinates state monitoring, policy enforcement, tripwire detection,
    and event logging to maintain trust boundaries.
    """

    def __init__(self, log_dir: str = './logs', initial_mode: BoundaryMode = BoundaryMode.OPEN,
                 skip_integrity_check: bool = False):
        """
        Initialize the Boundary Daemon.

        Args:
            log_dir: Directory for log files
            initial_mode: Starting boundary mode
            skip_integrity_check: Skip integrity verification (DANGEROUS - dev only)
        """
        # SECURITY: Verify daemon integrity BEFORE any other initialization
        # This prevents execution of tampered code
        self._integrity_protector = None
        self._integrity_verified = False

        if not skip_integrity_check and DAEMON_INTEGRITY_AVAILABLE:
            logger.info("Verifying daemon integrity...")
            # Determine config paths using centralized path resolution
            # This handles PyInstaller frozen executables, local dev, and system installs
            config_dir = Paths.get_config_dir()
            manifest_path = Paths.get_manifest_path()
            signing_key_path = Paths.get_signing_key_path()
            logger.info(f"Using config directory: {config_dir}")
            logger.info(f"Manifest path: {manifest_path}")
            logger.info(f"Signing key path: {signing_key_path}")
            self._integrity_protector = DaemonIntegrityProtector(
                config=IntegrityConfig(
                    # In production, use restrictive settings:
                    # failure_action=IntegrityAction.BLOCK_STARTUP,
                    # allow_missing_manifest=False,
                    # For development, allow missing manifest:
                    failure_action=IntegrityAction.WARN_ONLY,
                    allow_missing_manifest=True,
                    signing_key_path=signing_key_path,
                    manifest_path=manifest_path,
                ),
            )
            should_continue, message = self._integrity_protector.verify_startup()

            if not should_continue:
                logger.critical(f"Daemon integrity check failed: {message}")
                logger.critical("Refusing to start - daemon files may have been tampered with!")
                raise RuntimeError(f"Daemon integrity verification failed: {message}")

            if "LOCKDOWN" in message:
                logger.warning(f"Starting in lockdown mode: {message}")
                initial_mode = BoundaryMode.AIRGAP  # Force most restrictive mode
            elif "WARNING" in message:
                logger.warning(f"SECURITY: {message}")
            else:
                logger.info(f"Integrity verified: {message}")
                self._integrity_verified = True
        elif skip_integrity_check:
            logger.warning("Daemon integrity check SKIPPED - this is insecure!")
        else:
            logger.info("Daemon integrity protection: not available")

        self.log_dir = os.path.normpath(log_dir)
        os.makedirs(self.log_dir, exist_ok=True)

        # Initialize core components
        logger.info("Initializing Boundary Daemon (Agent Smith)...")

        # Initialize event logger (Plan 3: Cryptographic Log Signing)
        log_file = os.path.join(self.log_dir, 'boundary_chain.log')
        self.signed_logging = False
        self.redundant_logging = False
        self._redundant_logger = None

        if SIGNED_LOGGING_AVAILABLE and SignedEventLogger:
            try:
                signing_key_path = os.path.join(self.log_dir, 'signing.key')
                self.event_logger = SignedEventLogger(log_file, signing_key_path)
                self.signed_logging = True
                logger.info(f"Signed event logging enabled (key: {signing_key_path})")
                logger.info(f"Public verification key: {self.event_logger.get_public_key_hex()[:32]}...")
            except Exception as e:
                logger.warning(f"Signed logging failed, falling back to basic logging: {e}")
                self.event_logger = EventLogger(log_file)
        else:
            self.event_logger = EventLogger(log_file)
            logger.info("Signed event logging: not available (pynacl not installed)")

        # Initialize redundant logger (SECURITY: Addresses single logger dependency)
        if REDUNDANT_LOGGING_AVAILABLE and create_redundant_logger:
            try:
                self._redundant_logger = create_redundant_logger(
                    log_dir=log_dir,
                    enable_syslog=True,
                    enable_memory_buffer=True,
                )
                self.redundant_logging = True
                healthy_count = self._redundant_logger.get_healthy_backend_count()
                logger.info(f"Redundant logging enabled ({healthy_count} backends available)")
            except Exception as e:
                logger.warning(f"Redundant logging failed: {e}")
        else:
            logger.info("Redundant logging: not available")

        self.state_monitor = StateMonitor(poll_interval=1.0)
        self.policy_engine = PolicyEngine(initial_mode=initial_mode)
        self.tripwire_system = TripwireSystem()
        self.lockdown_manager = LockdownManager()

        # Phase 1: Mode freeze state for clock manipulation protection
        # When set, mode transitions are blocked until a ceremony clears it
        self._mode_frozen_reason: Optional[str] = None

        # Initialize Event Publisher (Attack Detection Integration)
        # Connects tripwire/boundary events to YARA, Sigma, MITRE, IOC detection engines
        self.event_publisher = None
        if EVENT_PUBLISHER_AVAILABLE and get_event_publisher:
            try:
                self.event_publisher = get_event_publisher()
                logger.info("Event publisher initialized for attack detection")
            except Exception as e:
                logger.warning(f"Event publisher initialization failed: {e}")
        else:
            logger.info("Event publisher: not available")

        # Initialize Privilege Manager (SECURITY: Prevents Silent Enforcement Failures)
        # This addresses Critical Finding: "Root Privilege Required = Silent Failure"
        self.privilege_manager = None
        if PRIVILEGE_MANAGER_AVAILABLE and PrivilegeManager:
            self.privilege_manager = PrivilegeManager(
                event_logger=self.event_logger,
                on_critical_callback=self._on_privilege_critical,
            )
            set_privilege_manager(self.privilege_manager)

            # Check root status early with clear warning
            if not self.privilege_manager.check_root():
                logger.warning("!" * 70)
                logger.warning("  SECURITY WARNING: Running without elevated privileges")
                logger.warning("  Some enforcement features will be UNAVAILABLE.")
                if IS_WINDOWS:
                    logger.warning("  For full security enforcement, run as: Administrator")
                else:
                    logger.warning("  For full security enforcement, run as: sudo boundary-daemon")
                logger.warning("!" * 70)
        else:
            logger.info("Privilege manager not available - enforcement status may not be tracked")

        # Initialize network enforcer (Plan 1 Phase 1: Network Enforcement)
        self.network_enforcer = None
        if ENFORCEMENT_AVAILABLE and NetworkEnforcer:
            self.network_enforcer = NetworkEnforcer(
                daemon=self,
                event_logger=self.event_logger
            )
            if self.network_enforcer.is_available:
                logger.info(f"Network enforcement available (backend: {self.network_enforcer.backend.value})")
                if self.privilege_manager:
                    self.privilege_manager.register_module(
                        EnforcementModule.NETWORK, True
                    )
            else:
                logger.warning("Network enforcement: NOT AVAILABLE (requires root and iptables/nftables)")
                if self.privilege_manager:
                    self.privilege_manager.register_module(
                        EnforcementModule.NETWORK, False,
                        "Requires root and iptables/nftables"
                    )
        else:
            if IS_WINDOWS:
                logger.info("Network enforcement: Windows mode (iptables/nftables not available)")
                if self.privilege_manager:
                    self.privilege_manager.register_module(
                        EnforcementModule.NETWORK, False, "Linux-only (uses iptables/nftables)"
                    )
            else:
                logger.info("Network enforcement module not loaded")
                if self.privilege_manager:
                    self.privilege_manager.register_module(
                        EnforcementModule.NETWORK, False, "Module not loaded"
                    )

        # Initialize USB enforcer (Plan 1 Phase 2: USB Enforcement)
        self.usb_enforcer = None
        if ENFORCEMENT_AVAILABLE and USBEnforcer:
            self.usb_enforcer = USBEnforcer(
                daemon=self,
                event_logger=self.event_logger
            )
            if self.usb_enforcer.is_available:
                logger.info(f"USB enforcement available (udev rules at {self.usb_enforcer.UDEV_RULE_PATH})")
                if self.privilege_manager:
                    self.privilege_manager.register_module(
                        EnforcementModule.USB, True
                    )
            else:
                logger.warning("USB enforcement: NOT AVAILABLE (requires root and udev)")
                if self.privilege_manager:
                    self.privilege_manager.register_module(
                        EnforcementModule.USB, False,
                        "Requires root and udev"
                    )
        else:
            if IS_WINDOWS:
                logger.info("USB enforcement: Windows mode (udev not available)")
                if self.privilege_manager:
                    self.privilege_manager.register_module(
                        EnforcementModule.USB, False, "Linux-only (uses udev)"
                    )
            else:
                logger.info("USB enforcement module not loaded")
                if self.privilege_manager:
                    self.privilege_manager.register_module(
                        EnforcementModule.USB, False, "Module not loaded"
                    )

        # Initialize process enforcer (Plan 1 Phase 3: Process Enforcement)
        self.process_enforcer = None
        if ENFORCEMENT_AVAILABLE and ProcessEnforcer:
            self.process_enforcer = ProcessEnforcer(
                daemon=self,
                event_logger=self.event_logger
            )
            if self.process_enforcer.is_available:
                runtime = self.process_enforcer.container_runtime.value
                logger.info(f"Process enforcement available (seccomp + container: {runtime})")
                if self.privilege_manager:
                    self.privilege_manager.register_module(
                        EnforcementModule.PROCESS, True
                    )
            else:
                logger.warning("Process enforcement: NOT AVAILABLE (requires root)")
                if self.privilege_manager:
                    self.privilege_manager.register_module(
                        EnforcementModule.PROCESS, False,
                        "Requires root"
                    )
        else:
            if IS_WINDOWS:
                logger.info("Process enforcement: Windows mode (seccomp not available)")
                if self.privilege_manager:
                    self.privilege_manager.register_module(
                        EnforcementModule.PROCESS, False, "Linux-only (uses seccomp)"
                    )
            else:
                logger.info("Process enforcement module not loaded")
                if self.privilege_manager:
                    self.privilege_manager.register_module(
                        EnforcementModule.PROCESS, False, "Module not loaded"
                    )

        # Initialize protection persistence manager (Critical: Survives Restarts)
        # SECURITY: This addresses "Cleanup on Shutdown Removes All Protection"
        self.protection_persistence = None
        if PROTECTION_PERSISTENCE_AVAILABLE and ProtectionPersistenceManager:
            try:
                self.protection_persistence = ProtectionPersistenceManager(
                    cleanup_policy=CleanupPolicy.EXPLICIT_ONLY,
                    event_logger=self.event_logger,
                )
                logger.info("Protection persistence enabled (protections survive restarts)")

                # Check for orphaned protections from crashed daemon
                orphaned = self.protection_persistence.check_orphaned_protections()
                if orphaned:
                    logger.info(f"  Found {len(orphaned)} orphaned protections from previous daemon")

                # Mark daemon started
                self.protection_persistence.mark_daemon_started()

                # Set persistence manager on enforcers
                if self.network_enforcer:
                    self.network_enforcer.set_persistence_manager(self.protection_persistence)
                if self.usb_enforcer:
                    self.usb_enforcer.set_persistence_manager(self.protection_persistence)

                # Re-apply persisted protections
                self._reapply_persisted_protections()

            except Exception as e:
                logger.warning(f"Protection persistence failed to initialize: {e}")
                logger.warning("  Protections will NOT survive daemon restarts!")
        else:
            logger.info("Protection persistence: not available")
            logger.warning("  Protections will be removed on daemon shutdown!")

        # Initialize TPM manager (Plan 2: TPM Integration)
        self.tpm_manager = None
        if TPM_MODULE_AVAILABLE and TPMManager:
            self.tpm_manager = TPMManager(
                daemon=self,
                event_logger=self.event_logger
            )
            if self.tpm_manager.is_available:
                logger.info(f"TPM integration available (backend: {self.tpm_manager.backend.value})")
            else:
                logger.info("TPM integration: not available (no TPM hardware or tools)")
        else:
            logger.info("TPM integration module not loaded")

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
                    logger.info(f"Cluster coordination available (node: {self.cluster_manager.node_id})")
                except Exception as e:
                    logger.warning(f"Cluster coordination failed to initialize: {e}")
            else:
                logger.info("Cluster coordination: not enabled (set BOUNDARY_CLUSTER_DIR to enable)")
        else:
            logger.info("Cluster coordination module not loaded")

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
                    logger.info(f"Custom policy engine available ({policy_count} policies from {policy_dir})")
                except Exception as e:
                    logger.warning(f"Custom policy engine failed to initialize: {e}")
            else:
                logger.info("Custom policy engine: not enabled (set BOUNDARY_POLICY_DIR to enable)")
        else:
            logger.info("Custom policy engine module not loaded")

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
                    logger.info(f"Biometric authentication available ({caps['enrolled_count']} templates enrolled)")
                    logger.info(f"  Fingerprint: {'Available' if caps['fingerprint_available'] else 'Not available'}")
                    logger.info(f"  Face: {'Available' if caps['face_available'] else 'Not available'}")
                except Exception as e:
                    logger.warning(f"Biometric authentication failed to initialize: {e}")
            else:
                logger.info("Biometric authentication: not enabled (set BOUNDARY_BIOMETRIC_DIR to enable)")
        else:
            logger.info("Biometric authentication module not loaded")

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
                    logger.info(f"Security advisor available (model: {self.security_advisor.model})")
                    logger.info(f"  Ollama: {'Available' if self.security_advisor.is_available() else 'Not available'}")
                    logger.info(f"  Stored advisories: {stats['total']}")
                except Exception as e:
                    logger.warning(f"Security advisor failed to initialize: {e}")
            else:
                logger.info("Security advisor: not enabled (set BOUNDARY_SECURITY_DIR to enable)")
        else:
            logger.info("Security advisor module not loaded")

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
                    logger.info(f"Log watchdog available (model: {self.log_watchdog.model})")
                    logger.info(f"  Ollama: {'Available' if self.log_watchdog.is_available() else 'Not available'}")
                    logger.info(f"  Monitoring: {len(log_paths)} log file(s)")
                    logger.info(f"  Stored alerts: {stats['total']}")
                except Exception as e:
                    logger.warning(f"Log watchdog failed to initialize: {e}")
            else:
                logger.info("Log watchdog: not enabled (set BOUNDARY_WATCHDOG_DIR to enable)")
        else:
            logger.info("Log watchdog module not loaded")

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
                        logger.info(f"Telemetry available (OTel: {stats['otel_available']}, OTLP: {stats['otlp_available']})")
                        logger.info(f"  Export mode: {stats['export_mode']}")
                        logger.info(f"  Instance ID: {stats['instance_id']}")
                    else:
                        logger.info("Telemetry: initialized in fallback mode")
                        self.telemetry_enabled = True
                except Exception as e:
                    logger.warning(f"Telemetry failed to initialize: {e}")
            else:
                logger.info("Telemetry: not enabled (set BOUNDARY_TELEMETRY_DIR to enable)")
        else:
            logger.info("Telemetry module not loaded")

        # Initialize SIEM integration (SECURITY: Security event forwarding to SIEM)
        self.siem = None
        self.siem_enabled = False
        if SIEM_AVAILABLE and SIEMIntegration:
            # SIEM can be enabled via environment variable
            siem_host = os.environ.get('BOUNDARY_SIEM_HOST', None)
            if siem_host:
                try:
                    siem_port = int(os.environ.get('BOUNDARY_SIEM_PORT', '514'))
                    siem_transport = os.environ.get('BOUNDARY_SIEM_TRANSPORT', 'tls').lower()
                    siem_format = os.environ.get('BOUNDARY_SIEM_FORMAT', 'json').lower()

                    # Map transport string to enum
                    transport_map = {
                        'udp': SIEMTransport.UDP,
                        'tcp': SIEMTransport.TCP,
                        'tls': SIEMTransport.TLS,
                        'http': SIEMTransport.HTTP,
                        'https': SIEMTransport.HTTPS,
                    }
                    transport = transport_map.get(siem_transport, SIEMTransport.TLS)

                    # Map format string to enum
                    format_map = {
                        'json': SIEMFormat.JSON,
                        'cef': SIEMFormat.CEF,
                        'leef': SIEMFormat.LEEF,
                        'syslog': SIEMFormat.SYSLOG,
                    }
                    fmt = format_map.get(siem_format, SIEMFormat.JSON)

                    siem_config = SIEMConfig(
                        enabled=True,
                        host=siem_host,
                        port=siem_port,
                        transport=transport,
                        format=fmt,
                        tls_verify=os.environ.get('BOUNDARY_SIEM_TLS_VERIFY', 'true').lower() == 'true',
                        http_token=os.environ.get('BOUNDARY_SIEM_TOKEN', None),
                    )

                    self.siem = SIEMIntegration(siem_config, event_logger=self.event_logger)
                    success, message = self.siem.start()

                    if success:
                        self.siem_enabled = True
                        # Wire error handling to SIEM
                        if set_siem_integration:
                            set_siem_integration(self.siem)
                        logger.info(f"SIEM integration enabled ({siem_host}:{siem_port})")
                        logger.info(f"  Transport: {transport.value}, Format: {fmt.value}")
                    else:
                        logger.warning(f"SIEM connection failed: {message}")
                except Exception as e:
                    logger.warning(f"SIEM integration failed to initialize: {e}")
            else:
                logger.info("SIEM integration: not enabled (set BOUNDARY_SIEM_HOST to enable)")
        else:
            logger.info("SIEM integration module not loaded")

        # Initialize memory monitor (Plan 11: Memory Leak Monitoring)
        self.memory_monitor = None
        self.memory_monitor_enabled = False
        if MEMORY_MONITOR_AVAILABLE and MemoryMonitor:
            try:
                # Get optional config from environment
                sample_interval = float(os.environ.get('BOUNDARY_MEMORY_INTERVAL', '5.0'))
                rss_warning_mb = float(os.environ.get('BOUNDARY_MEMORY_WARNING_MB', '500'))
                rss_critical_mb = float(os.environ.get('BOUNDARY_MEMORY_CRITICAL_MB', '1000'))
                leak_detection = os.environ.get('BOUNDARY_MEMORY_LEAK_DETECT', 'true').lower() == 'true'

                # Debug mode (tracemalloc) - WARNING: performance overhead
                debug_enabled = os.environ.get('BOUNDARY_MEMORY_DEBUG', 'false').lower() == 'true'
                debug_auto_disable = int(os.environ.get('BOUNDARY_MEMORY_DEBUG_TIMEOUT', '300'))

                config = MemoryMonitorConfig(
                    sample_interval=sample_interval,
                    rss_warning_mb=rss_warning_mb,
                    rss_critical_mb=rss_critical_mb,
                    leak_detection_enabled=leak_detection,
                    debug_enabled=debug_enabled,
                    debug_auto_disable_after=debug_auto_disable,
                )

                self.memory_monitor = MemoryMonitor(
                    daemon=self,
                    config=config,
                    on_alert=self._on_memory_alert,
                )

                # Connect telemetry if available
                if self.telemetry_manager:
                    self.memory_monitor.set_telemetry_manager(self.telemetry_manager)

                self.memory_monitor_enabled = self.memory_monitor.is_available
                if self.memory_monitor_enabled:
                    logger.info(f"Memory monitor available (interval: {sample_interval}s)")
                    logger.info(f"  RSS warning: {rss_warning_mb} MB, critical: {rss_critical_mb} MB")
                    logger.info(f"  Leak detection: {'enabled' if leak_detection else 'disabled'}")
                    if debug_enabled:
                        logger.info(f"  DEBUG MODE: enabled (auto-disable: {debug_auto_disable}s)")
                        logger.warning("  tracemalloc causes performance overhead")
                else:
                    logger.info("Memory monitor: psutil not available")
            except Exception as e:
                logger.warning(f"Memory monitor failed to initialize: {e}")
        else:
            logger.info("Memory monitor module not loaded")

        # Initialize resource monitor (Plan 11: Resource Monitoring - FD, Threads, Disk, CPU)
        self.resource_monitor = None
        self.resource_monitor_enabled = False
        if RESOURCE_MONITOR_AVAILABLE and ResourceMonitor:
            try:
                sample_interval = float(os.environ.get('BOUNDARY_RESOURCE_INTERVAL', '10.0'))
                fd_warning = float(os.environ.get('BOUNDARY_FD_WARNING_PERCENT', '70'))
                disk_warning = float(os.environ.get('BOUNDARY_DISK_WARNING_PERCENT', '90'))

                # Get log directory for disk monitoring
                # nosec B108 - monitoring paths, not writing to them
                disk_paths = [log_dir, '/var/log', '/tmp']

                config = ResourceMonitorConfig(
                    sample_interval=sample_interval,
                    fd_warning_percent=fd_warning,
                    disk_warning_percent=disk_warning,
                    disk_paths=disk_paths,
                )

                self.resource_monitor = ResourceMonitor(
                    daemon=self,
                    config=config,
                    on_alert=self._on_resource_alert,
                )

                # Connect telemetry if available
                if self.telemetry_manager:
                    self.resource_monitor.set_telemetry_manager(self.telemetry_manager)

                self.resource_monitor_enabled = self.resource_monitor.is_available
                if self.resource_monitor_enabled:
                    logger.info(f"Resource monitor available (interval: {sample_interval}s)")
                    logger.info(f"  FD warning: {fd_warning}%, Disk warning: {disk_warning}%")
                else:
                    logger.info("Resource monitor: psutil not available")
            except Exception as e:
                logger.warning(f"Resource monitor failed to initialize: {e}")
        else:
            logger.info("Resource monitor module not loaded")

        # Initialize health monitor (Plan 11: Health Monitoring)
        self.health_monitor = None
        self.health_monitor_enabled = False
        if HEALTH_MONITOR_AVAILABLE and HealthMonitor:
            try:
                check_interval = float(os.environ.get('BOUNDARY_HEALTH_INTERVAL', '30.0'))
                heartbeat_timeout = float(os.environ.get('BOUNDARY_HEARTBEAT_TIMEOUT', '60.0'))

                config = HealthMonitorConfig(
                    check_interval=check_interval,
                    heartbeat_timeout=heartbeat_timeout,
                )

                self.health_monitor = HealthMonitor(
                    daemon=self,
                    config=config,
                    on_alert=self._on_health_alert,
                )

                # Connect telemetry if available
                if self.telemetry_manager:
                    self.health_monitor.set_telemetry_manager(self.telemetry_manager)

                self.health_monitor_enabled = True
                logger.info(f"Health monitor available (check interval: {check_interval}s)")
                logger.info(f"  Heartbeat timeout: {heartbeat_timeout}s")
            except Exception as e:
                logger.warning(f"Health monitor failed to initialize: {e}")
        else:
            logger.info("Health monitor module not loaded")

        # Initialize queue monitor (Plan 11: Queue Monitoring)
        self.queue_monitor = None
        self.queue_monitor_enabled = False
        if QUEUE_MONITOR_AVAILABLE and QueueMonitor:
            try:
                sample_interval = float(os.environ.get('BOUNDARY_QUEUE_INTERVAL', '5.0'))
                warning_depth = int(os.environ.get('BOUNDARY_QUEUE_WARNING', '100'))
                critical_depth = int(os.environ.get('BOUNDARY_QUEUE_CRITICAL', '500'))

                config = QueueMonitorConfig(
                    sample_interval=sample_interval,
                    default_warning_depth=warning_depth,
                    default_critical_depth=critical_depth,
                )

                self.queue_monitor = QueueMonitor(
                    daemon=self,
                    config=config,
                    on_alert=self._on_queue_alert,
                )

                # Connect telemetry if available
                if self.telemetry_manager:
                    self.queue_monitor.set_telemetry_manager(self.telemetry_manager)

                self.queue_monitor_enabled = True
                logger.info(f"Queue monitor available (sample interval: {sample_interval}s)")
                logger.info(f"  Warning depth: {warning_depth}, Critical depth: {critical_depth}")
            except Exception as e:
                logger.warning(f"Queue monitor failed to initialize: {e}")
        else:
            logger.info("Queue monitor module not loaded")

        # Initialize report generator (Plan 11: Report Generation with Ollama)
        self.report_generator = None
        if REPORT_GENERATOR_AVAILABLE and MonitoringReportGenerator:
            try:
                # Get Ollama config from environment
                ollama_endpoint = os.environ.get('OLLAMA_ENDPOINT', 'http://localhost:11434')
                ollama_model = os.environ.get('OLLAMA_MODEL', 'llama3.2')

                ollama_config = OllamaConfig(
                    endpoint=ollama_endpoint,
                    model=ollama_model,
                )

                self.report_generator = MonitoringReportGenerator(
                    daemon=self,
                    ollama_config=ollama_config,
                )
                logger.info(f"Report generator available (Ollama: {ollama_endpoint}, model: {ollama_model})")
            except Exception as e:
                logger.warning(f"Report generator failed to initialize: {e}")
        else:
            logger.info("Report generator module not loaded")

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
                logger.info(f"Message checker available (mode: {mode_str})")
                logger.info(f"  NatLangChain: Enabled")
                logger.info(f"  Agent-OS: Enabled")
            except Exception as e:
                logger.warning(f"Message checker failed to initialize: {e}")
        else:
            logger.info("Message checker module not loaded")

        # Initialize clock monitor (Clock Drift Protection)
        self.clock_monitor = None
        self.clock_monitor_enabled = False
        if CLOCK_MONITOR_AVAILABLE and ClockMonitor:
            try:
                self.clock_monitor = ClockMonitor(
                    check_interval=10.0,
                    on_time_jump=self._on_time_jump,
                    on_ntp_lost=self._on_ntp_lost,
                    on_manipulation=self._on_clock_manipulation,
                )
                self.clock_monitor_enabled = True
                logger.info("Clock monitor available")
            except Exception as e:
                logger.warning(f"Clock monitor failed to initialize: {e}")
        else:
            logger.info("Clock monitor module not loaded")

        # Initialize Network Attestor (Phase 1: Network Trust Verification)
        self.network_attestor = None
        self.network_attestation_enabled = False
        if NETWORK_ATTESTATION_AVAILABLE and NetworkAttestor:
            try:
                self.network_attestor = NetworkAttestor(
                    config=NetworkAttestationConfig(
                        require_vpn_for_trusted=True,
                        lockdown_on_trust_loss=True,
                    ),
                    event_logger=self.event_logger,
                    on_trust_change=self._on_network_trust_change,
                    on_violation=self._on_network_trust_violation,
                )
                self.network_attestation_enabled = True
                logger.info("Network attestation available")
            except Exception as e:
                logger.warning(f"Network attestation failed to initialize: {e}")
        else:
            logger.info("Network attestation module not loaded")

        # Initialize hardened watchdog endpoint (SECURITY: Resilient Daemon Monitoring)
        # This addresses Critical Finding #6: "External Watchdog Can Be Killed"
        self.watchdog_endpoint = None
        self.hardened_watchdog_enabled = False
        if HARDENED_WATCHDOG_AVAILABLE and DaemonWatchdogEndpoint:
            try:
                # Generate shared secret for watchdog authentication
                shared_secret = generate_shared_secret()

                # Health check callback
                def daemon_health_check():
                    try:
                        # Verify daemon is functional
                        _ = self.policy_engine.get_current_mode()
                        return self._running
                    except Exception:
                        return False

                self.watchdog_endpoint = DaemonWatchdogEndpoint(
                    shared_secret=shared_secret,
                    health_checker=daemon_health_check,
                )
                self.hardened_watchdog_enabled = True
                logger.info("Hardened watchdog endpoint available")
                logger.info("  SECURITY: External watchdogs can now monitor daemon health")
                logger.info("  Run 'boundary-watchdog' as a separate service for protection")
            except Exception as e:
                logger.warning(f"Hardened watchdog endpoint failed to initialize: {e}")
        else:
            logger.info("Hardened watchdog: not available (watchdog module not loaded)")

        # Daemon state
        self._running = False
        self._shutdown_event = threading.Event()
        self._enforcement_thread: Optional[threading.Thread] = None

        # Cache cleanup state (prevents memory leaks from caches)
        self._last_cache_cleanup = time.time()
        self._cache_cleanup_interval = 300.0  # 5 minutes

        # Initialize API server for CLI tools
        self.api_server = None
        if API_SERVER_AVAILABLE and BoundaryAPIServer:
            socket_path = os.path.join(os.path.dirname(log_dir), 'api', 'boundary.sock')
            self.api_server = BoundaryAPIServer(daemon=self, socket_path=socket_path)

            # Connect telemetry for API latency monitoring (Plan 11)
            if self.telemetry_manager:
                self.api_server.set_telemetry_manager(self.telemetry_manager)

            logger.info(f"API server initialized (socket: {socket_path})")
        else:
            logger.info("API server: not available")

        # Initialize dreaming status reporter (CLI status updates)
        self._dreaming_reporter = None
        self.dreaming_enabled = True  # Can be disabled via config
        if DREAMING_AVAILABLE and self.dreaming_enabled:
            try:
                self._dreaming_reporter = create_dreaming_reporter(
                    interval=5.0,  # Report every 5 seconds
                    use_colors=True,
                )
                # Register state callback for mode display
                if self._dreaming_reporter:
                    self._dreaming_reporter.register_state_callback(
                        'mode',
                        lambda: f"mode:{self.policy_engine.get_current_mode().name}"
                    )
                    logger.info("Dreaming status reporter initialized (5s interval)")
            except Exception as e:
                logger.warning(f"Failed to initialize dreaming reporter: {e}")
        else:
            logger.info("Dreaming reporter: not available")

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

        logger.info(f"Boundary Daemon initialized in {initial_mode.name} mode")

        # Print security enforcement status (SECURITY: No more silent failures)
        if self.privilege_manager:
            self.privilege_manager.print_security_status()

            # Check if initial mode can be enforced
            can_enforce, missing = self.privilege_manager.can_enforce_mode(initial_mode.name)
            if not can_enforce:
                self.event_logger.log_event(
                    EventType.VIOLATION,
                    f"Starting in {initial_mode.name} mode with DEGRADED enforcement",
                    metadata={
                        'mode': initial_mode.name,
                        'missing_enforcement': missing,
                    }
                )

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
            logger.info(f"Mode transition: {old_mode.name} → {new_mode.name} ({operator.value})")

            # Publish mode change to attack detection engines
            if self.event_publisher:
                try:
                    self.event_publisher.publish_mode_change(
                        old_mode=old_mode.name,
                        new_mode=new_mode.name,
                        operator=operator.value,
                        reason=reason,
                    )
                except Exception as e:
                    logger.warning(f"Failed to publish mode change event: {e}")

            # SECURITY: Check if we can properly enforce security-critical modes
            # Addresses Critical Finding: "Root Privilege Required = Silent Failure"
            if self.privilege_manager:
                can_enforce, message = self.privilege_manager.assert_mode_enforceable(new_mode.name)
                if not can_enforce:
                    # Log the enforcement gap as a security event
                    self.event_logger.log_event(
                        EventType.VIOLATION,
                        f"DEGRADED SECURITY: {new_mode.name} mode cannot be fully enforced",
                        metadata={
                            'mode': new_mode.name,
                            'enforcement_available': False,
                            'message': message,
                        }
                    )

            # Apply network enforcement for the new mode (Plan 1 Phase 1)
            if self.network_enforcer and self.network_enforcer.is_available:
                try:
                    success, msg = self.network_enforcer.enforce_mode(new_mode, reason)
                    if success:
                        logger.info(f"Network enforcement applied: {msg}")
                    else:
                        logger.warning(f"Network enforcement warning: {msg}")
                except Exception as e:
                    logger.error(f"Network enforcement error: {e}")
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
                        logger.info(f"USB enforcement applied: {msg}")
                    else:
                        logger.warning(f"USB enforcement warning: {msg}")
                except Exception as e:
                    logger.error(f"USB enforcement error: {e}")
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
                        logger.info(f"Process enforcement applied: {msg}")
                    else:
                        logger.warning(f"Process enforcement warning: {msg}")
                except Exception as e:
                    logger.error(f"Process enforcement error: {e}")
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
                    logger.info(f"TPM attestation recorded: mode {new_mode.name} bound to PCR {attestation.pcr_index}")
                except Exception as e:
                    logger.warning(f"TPM attestation warning: {e}")
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

            # Publish to attack detection engines (YARA, Sigma, MITRE, IOC)
            if self.event_publisher:
                try:
                    self.event_publisher.publish_tripwire_event(violation)
                except Exception as e:
                    logger.warning(f"Failed to publish tripwire event: {e}")

            # Trigger lockdown
            if violation.auto_lockdown:
                self.lockdown_manager.trigger_lockdown(violation)
                self.policy_engine.transition_mode(
                    BoundaryMode.LOCKDOWN,
                    Operator.SYSTEM,
                    f"Tripwire: {violation.violation_type.value}"
                )

                # Publish lockdown event to detection engines
                if self.event_publisher:
                    try:
                        self.event_publisher.publish_lockdown(
                            reason=f"Tripwire: {violation.violation_type.value}",
                            trigger=violation.violation_id,
                        )
                    except Exception as e:
                        logger.warning(f"Failed to publish lockdown event: {e}")

        self.tripwire_system.register_callback(on_tripwire_violation)

    def _handle_violation(self, violation: TripwireViolation):
        """Handle a tripwire violation"""
        logger.critical("*** SECURITY VIOLATION DETECTED ***")
        logger.critical(f"Type: {violation.violation_type.value}")
        logger.critical(f"Details: {violation.details}")
        logger.critical("System entering LOCKDOWN mode")

    def _on_privilege_critical(self, issue):
        """
        Handle critical privilege issues.

        This callback is invoked when security enforcement is compromised
        due to insufficient privileges. It ensures operators are clearly
        alerted rather than failures being silent.

        Addresses Critical Finding: "Root Privilege Required = Silent Failure"
        """
        logger.critical("!" * 70)
        logger.critical("  CRITICAL PRIVILEGE ISSUE")
        logger.critical("!" * 70)
        logger.critical(f"  Module:    {issue.module.value}")
        logger.critical(f"  Operation: {issue.operation}")
        logger.critical(f"  Message:   {issue.message}")
        logger.critical("  Security enforcement is DEGRADED.")
        if IS_WINDOWS:
            logger.critical("  To fix: Run daemon as Administrator")
        else:
            logger.critical("  To fix: Run daemon as root (sudo boundary-daemon)")
        logger.critical("!" * 70)

        # Log to event logger
        self.event_logger.log_event(
            EventType.VIOLATION,
            f"Privilege issue: {issue.module.value} - {issue.message}",
            metadata={
                'module': issue.module.value,
                'operation': issue.operation,
                'alert_level': issue.alert_level.value,
                'required_privilege': issue.required_privilege.value,
            }
        )

    def _reapply_persisted_protections(self):
        """
        Re-apply any protections that were persisted from a previous daemon run.

        SECURITY: This ensures that protections survive daemon restarts.
        Called during daemon initialization to restore the security state.
        """
        if not self.protection_persistence:
            return

        logger.info("Checking for persisted protections...")

        reapplied = []

        # Re-apply network protections
        if self.network_enforcer and self.network_enforcer.is_available:
            mode = self.network_enforcer.check_and_reapply_persisted_mode()
            if mode:
                reapplied.append(f"Network: {mode}")

        # Re-apply USB protections
        if self.usb_enforcer and self.usb_enforcer.is_available:
            mode = self.usb_enforcer.check_and_reapply_persisted_mode()
            if mode:
                reapplied.append(f"USB: {mode}")

        if reapplied:
            logger.info(f"  Re-applied {len(reapplied)} persisted protections:")
            for prot in reapplied:
                logger.info(f"    - {prot}")
            self.event_logger.log_event(
                EventType.DAEMON_START,
                f"Re-applied {len(reapplied)} persisted protections from previous run",
                metadata={'protections': reapplied}
            )
        else:
            logger.info("  No persisted protections to re-apply")

    def request_cleanup_all(self, token: str, force: bool = False) -> Tuple[bool, str]:
        """
        Request cleanup of all protections with authentication.

        This is the only authorized way to remove protections.

        Args:
            token: Admin authentication token
            force: Force cleanup of sticky/emergency protections

        Returns:
            (success, message)
        """
        if not self.protection_persistence:
            return False, "Protection persistence not available"

        results = []

        # Request cleanup for each enforcer
        if self.network_enforcer and self.network_enforcer.is_available:
            success, msg = self.network_enforcer.cleanup(token=token, force=force)
            results.append(f"Network: {msg}")

        if self.usb_enforcer and self.usb_enforcer.is_available:
            success, msg = self.usb_enforcer.cleanup(token=token, force=force)
            results.append(f"USB: {msg}")

        self._cleanup_on_shutdown_requested = True

        return True, "\n".join(results)

    def _on_time_jump(self, event: 'TimeJumpEvent'):
        """Handle detected time jump (clock manipulation).

        Phase 1 Enhancement: HIGH/CRITICAL severity triggers LOCKDOWN via tripwire.
        This protects against time-based attacks like token expiration bypass.
        """
        direction = "forward" if event.direction.name == "FORWARD" else "backward"
        self.event_logger.log_event(
            EventType.CLOCK_JUMP,
            f"Time jump detected: {abs(event.jump_seconds):.1f}s {direction}",
            metadata={
                'direction': event.direction.name,
                'jump_seconds': event.jump_seconds,
                'severity': event.severity,
                'time_before': event.timestamp_before.isoformat(),
                'time_after': event.timestamp_after.isoformat(),
            }
        )

        # Phase 1: HIGH/CRITICAL severity triggers tripwire -> LOCKDOWN
        if event.severity in ("HIGH", "CRITICAL"):
            logger.critical("*** TIME MANIPULATION DETECTED - TRIGGERING LOCKDOWN ***")
            logger.critical(f"Direction: {direction}")
            logger.critical(f"Jump: {abs(event.jump_seconds):.1f} seconds")
            logger.critical(f"Severity: {event.severity}")
            logger.critical("This indicates an attempt to bypass time-based security controls.")

            # Freeze mode transitions until time stabilizes
            self._mode_frozen_reason = f"Clock manipulation: {abs(event.jump_seconds):.1f}s {direction} jump"

            # Trigger tripwire violation -> automatic LOCKDOWN
            from .tripwires import ViolationType
            violation = self.tripwire_system.trigger_violation(
                violation_type=ViolationType.CLOCK_MANIPULATION,
                details=f"Time jump {direction}: {abs(event.jump_seconds):.1f}s (severity: {event.severity})",
                current_mode=self.policy_engine.current_mode,
                environment_snapshot={
                    'time_before': event.timestamp_before.isoformat(),
                    'time_after': event.timestamp_after.isoformat(),
                    'jump_seconds': event.jump_seconds,
                    'direction': direction,
                },
                auto_lockdown=True,  # Automatically enter LOCKDOWN
            )

            if violation:
                # Enter lockdown mode
                self._handle_violation(violation)

    def _on_ntp_lost(self):
        """Handle NTP synchronization loss."""
        self.event_logger.log_event(
            EventType.NTP_SYNC_LOST,
            "NTP synchronization lost - system clock may drift",
            metadata={'timestamp': datetime.utcnow().isoformat()}
        )
        logger.warning("[CLOCK] NTP synchronization lost")

    def _on_clock_manipulation(self, reason: str):
        """Handle confirmed clock manipulation.

        Phase 1 Enhancement: Triggers immediate LOCKDOWN via tripwire.
        """
        self.event_logger.log_event(
            EventType.CLOCK_JUMP,
            f"Clock manipulation detected: {reason}",
            metadata={
                'reason': reason,
                'timestamp': datetime.utcnow().isoformat(),
                'action': 'lockdown_triggered',
            }
        )
        logger.critical(f"[CLOCK] MANIPULATION CONFIRMED: {reason} - TRIGGERING LOCKDOWN")

        # Freeze mode transitions
        self._mode_frozen_reason = f"Clock manipulation confirmed: {reason}"

        # Trigger tripwire violation -> automatic LOCKDOWN
        from .tripwires import ViolationType
        violation = self.tripwire_system.trigger_violation(
            violation_type=ViolationType.CLOCK_MANIPULATION,
            details=f"Confirmed clock manipulation: {reason}",
            current_mode=self.policy_engine.current_mode,
            environment_snapshot={
                'reason': reason,
                'timestamp': datetime.utcnow().isoformat(),
            },
            auto_lockdown=True,
        )

        if violation:
            self._handle_violation(violation)

    def _on_network_trust_change(self, result: 'AttestationResult'):
        """Handle network trust level change.

        Phase 1 Enhancement: Tracks network trust changes and validates
        mode-network binding requirements.
        """
        trust_level = result.trust_level.name if hasattr(result.trust_level, 'name') else str(result.trust_level)
        self.event_logger.log_event(
            EventType.INFO,
            f"Network trust level changed to {trust_level}",
            metadata={
                'trust_level': trust_level,
                'vpn_connected': result.vpn_connection is not None,
                'reason': result.reason,
                'timestamp': result.timestamp,
            }
        )
        logger.info(f"[NETWORK] Trust level: {trust_level}")

        # Validate mode-network binding
        if self.network_attestor and self.network_attestor.requires_vpn_for_mode(self.policy_engine.current_mode):
            is_valid, reason = self.network_attestor.validate_mode_network_binding(self.policy_engine.current_mode)
            if not is_valid:
                logger.warning(f"[NETWORK] Mode-network binding violation: {reason}")
                self._on_network_trust_violation(f"Mode requires VPN but {reason}")

    def _on_network_trust_violation(self, reason: str):
        """Handle network trust violation.

        Phase 1 Enhancement: Triggers LOCKDOWN on network trust degradation.
        """
        self.event_logger.log_event(
            EventType.VIOLATION,
            f"Network trust violation: {reason}",
            metadata={
                'reason': reason,
                'timestamp': datetime.utcnow().isoformat(),
                'action': 'lockdown_triggered',
            }
        )
        logger.critical(f"[NETWORK] TRUST VIOLATION: {reason} - TRIGGERING LOCKDOWN")

        # Freeze mode transitions
        self._mode_frozen_reason = f"Network trust violation: {reason}"

        # Trigger tripwire violation -> automatic LOCKDOWN
        from .tripwires import ViolationType
        violation = self.tripwire_system.trigger_violation(
            violation_type=ViolationType.NETWORK_TRUST_VIOLATION,
            details=f"Network trust violation: {reason}",
            current_mode=self.policy_engine.current_mode,
            environment_snapshot={
                'reason': reason,
                'timestamp': datetime.utcnow().isoformat(),
            },
            auto_lockdown=True,
        )

        if violation:
            self._handle_violation(violation)

    def _on_memory_alert(self, alert):
        """Handle memory alert from memory monitor."""
        # Log to event logger
        event_type = EventType.ALERT if alert.level.value == 'critical' else EventType.INFO
        self.event_logger.log_event(
            event_type,
            f"Memory alert [{alert.level.value}]: {alert.message}",
            metadata={
                'alert_type': alert.alert_type,
                'level': alert.level.value,
                'current_value': alert.current_value,
                'threshold': alert.threshold,
                **alert.metadata,
            }
        )

        # Log to telemetry if available
        if self.telemetry_manager and self.telemetry_enabled:
            self.telemetry_manager.record_memory_alert(
                alert_type=alert.alert_type,
                level=alert.level.value,
                current_value=alert.current_value,
                threshold=alert.threshold,
            )

        # Log to console
        if alert.level.value == 'critical':
            logger.critical(f"[MEMORY] {alert.message}")
        elif alert.level.value == 'warning':
            logger.warning(f"[MEMORY] {alert.message}")
        else:
            logger.info(f"[MEMORY] {alert.message}")

        # For critical memory alerts (confirmed leaks or very high usage),
        # consider taking action
        if alert.level.value == 'critical' and 'confirmed' in alert.alert_type:
            logger.critical("[MEMORY] Confirmed memory leak detected - consider restarting daemon")

    def _on_resource_alert(self, alert):
        """Handle resource alert from resource monitor."""
        # Log to event logger
        event_type = EventType.ALERT if alert.level.value == 'critical' else EventType.INFO
        self.event_logger.log_event(
            event_type,
            f"Resource alert [{alert.level.value}]: {alert.message}",
            metadata={
                'alert_type': alert.alert_type,
                'resource_type': alert.resource_type.value,
                'level': alert.level.value,
                'current_value': alert.current_value,
                'threshold': alert.threshold,
                **alert.metadata,
            }
        )

        # Log to telemetry if available
        if self.telemetry_manager and self.telemetry_enabled:
            self.telemetry_manager.record_resource_alert(
                resource_type=alert.resource_type.value,
                alert_type=alert.alert_type,
                level=alert.level.value,
                current_value=alert.current_value,
            )

        # Log to console
        if alert.level.value == 'critical':
            logger.critical(f"[RESOURCE] {alert.message}")
        elif alert.level.value == 'warning':
            logger.warning(f"[RESOURCE] {alert.message}")
        else:
            logger.info(f"[RESOURCE] {alert.message}")

    def _on_health_alert(self, alert):
        """Handle health alert from health monitor."""
        # Log to event logger
        self.event_logger.log_event(
            EventType.ALERT,
            f"Health alert [{alert.component}]: {alert.message}",
            metadata={
                'component': alert.component,
                'previous_status': alert.previous_status.value,
                'new_status': alert.new_status.value,
            }
        )

        # Log to console
        if alert.new_status.value in ('error', 'unresponsive'):
            logger.error(f"[HEALTH] ALERT: {alert.component} - {alert.message}")
        else:
            logger.info(f"[HEALTH] {alert.component} - {alert.message}")

    def _on_queue_alert(self, alert):
        """Handle alert from queue monitor."""
        # Log to event logger
        self.event_logger.log_event(
            EventType.ALERT if alert.level.value == 'critical' else EventType.INFO,
            f"Queue alert [{alert.queue_name}]: {alert.message}",
            metadata={
                'queue_name': alert.queue_name,
                'alert_type': alert.alert_type,
                'level': alert.level.value,
                'current_depth': alert.current_depth,
                'threshold': alert.threshold,
            }
        )

        # Log to console
        if alert.level.value == 'critical':
            logger.critical(f"[QUEUE] {alert.queue_name} - {alert.message}")
        elif alert.level.value == 'warning':
            logger.warning(f"[QUEUE] {alert.queue_name} - {alert.message}")
        else:
            logger.info(f"[QUEUE] {alert.queue_name} - {alert.message}")

    def start(self):
        """Start the boundary daemon"""
        if self._running:
            logger.warning("Daemon already running")
            return

        logger.info("Starting Boundary Daemon...")
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
                    logger.info(f"Initial network enforcement applied for {current_mode.name} mode")
                else:
                    logger.warning(f"{msg}")
            except Exception as e:
                logger.warning(f"Initial network enforcement failed: {e}")

        # USB enforcement (Phase 2)
        if self.usb_enforcer and self.usb_enforcer.is_available:
            try:
                success, msg = self.usb_enforcer.enforce_mode(
                    current_mode,
                    reason="Initial enforcement on daemon start"
                )
                if success:
                    logger.info(f"Initial USB enforcement applied for {current_mode.name} mode")
                else:
                    logger.warning(f"{msg}")
            except Exception as e:
                logger.warning(f"Initial USB enforcement failed: {e}")

        # Process enforcement (Phase 3)
        if self.process_enforcer and self.process_enforcer.is_available:
            try:
                success, msg = self.process_enforcer.enforce_mode(
                    current_mode,
                    reason="Initial enforcement on daemon start"
                )
                if success:
                    logger.info(f"Initial process enforcement applied for {current_mode.name} mode")
                else:
                    logger.warning(f"{msg}")
            except Exception as e:
                logger.warning(f"Initial process enforcement failed: {e}")

        # Start state monitoring
        self.state_monitor.start()

        # Start dreaming status reporter
        if self._dreaming_reporter:
            self._dreaming_reporter.start()
            self._dreaming_reporter.set_phase(DreamPhase.WATCHING)
            logger.info("Dreaming status reporter started")

        # Start enforcement loop
        self._enforcement_thread = threading.Thread(target=self._enforcement_loop, daemon=False)
        self._enforcement_thread.start()

        # Start cluster coordination (Plan 4)
        if self.cluster_manager and self.cluster_enabled:
            try:
                self.cluster_manager.start()
                logger.info(f"Cluster coordination started (node: {self.cluster_manager.node_id})")
            except Exception as e:
                logger.warning(f"Cluster coordination failed to start: {e}")

        # Start log watchdog (Plan 8)
        if self.log_watchdog and self.watchdog_enabled:
            try:
                self.log_watchdog.start()
                logger.info(f"Log watchdog started (monitoring {len(self.log_watchdog.log_paths)} file(s))")
            except Exception as e:
                logger.warning(f"Log watchdog failed to start: {e}")

        # Start clock monitor (Clock Drift Protection)
        if self.clock_monitor and self.clock_monitor_enabled:
            try:
                self.clock_monitor.start()
                state = self.clock_monitor.get_state()
                ntp_status = "synced" if state['is_ntp_synced'] else "not synced"
                logger.info(f"Clock monitor started (NTP: {ntp_status})")
            except Exception as e:
                logger.warning(f"Clock monitor failed to start: {e}")

        # Start network attestor (Phase 1: Network Trust Verification)
        if self.network_attestor and self.network_attestation_enabled:
            try:
                self.network_attestor.start()
                result = self.network_attestor.get_attestation_result()
                if result:
                    trust_level = result.trust_level.name
                    vpn_status = "VPN connected" if result.vpn_connection else "No VPN"
                    logger.info(f"Network attestor started (Trust: {trust_level}, {vpn_status})")
            except Exception as e:
                logger.warning(f"Network attestor failed to start: {e}")

        # Start hardened watchdog endpoint (SECURITY: Resilient Monitoring)
        if self.watchdog_endpoint and self.hardened_watchdog_enabled:
            try:
                self.watchdog_endpoint.start()
                # Check if it actually started (returns early on Windows)
                if getattr(self.watchdog_endpoint, '_running', False):
                    logger.info(f"Hardened watchdog endpoint started (socket: {self.watchdog_endpoint.socket_path})")
            except Exception as e:
                logger.warning(f"Hardened watchdog endpoint failed to start: {e}")

        # Start API server for CLI tools
        if self.api_server:
            try:
                self.api_server.start()
            except Exception as e:
                logger.warning(f"Failed to start API server: {e}")

        # Start daemon integrity runtime monitoring (SECURITY: Continuous protection)
        if self._integrity_protector:
            try:
                self._integrity_protector.start_monitoring()
                logger.info("Daemon integrity monitoring started")
            except Exception as e:
                logger.warning(f"Daemon integrity monitoring failed to start: {e}")

        # Start redundant logger health monitoring (SECURITY: Logging redundancy)
        if self._redundant_logger and self.redundant_logging:
            try:
                self._redundant_logger.start_health_monitoring()
                logger.info("Redundant logger health monitoring started")
            except Exception as e:
                logger.warning(f"Redundant logger health monitoring failed: {e}")

        # Start memory monitor (Plan 11: Memory Leak Monitoring)
        if self.memory_monitor and self.memory_monitor_enabled:
            try:
                self.memory_monitor.start()
                logger.info("Memory monitor started")
            except Exception as e:
                logger.warning(f"Memory monitor failed to start: {e}")

        # Start resource monitor (Plan 11: Resource Monitoring)
        if self.resource_monitor and self.resource_monitor_enabled:
            try:
                self.resource_monitor.start()
                logger.info("Resource monitor started")
            except Exception as e:
                logger.warning(f"Resource monitor failed to start: {e}")

        # Start health monitor (Plan 11: Health Monitoring)
        if self.health_monitor and self.health_monitor_enabled:
            try:
                self.health_monitor.start()
                logger.info("Health monitor started")
            except Exception as e:
                logger.warning(f"Health monitor failed to start: {e}")

        # Start queue monitor (Plan 11: Queue Monitoring)
        if self.queue_monitor and self.queue_monitor_enabled:
            try:
                self.queue_monitor.start()
                logger.info("Queue monitor started")
            except Exception as e:
                logger.warning(f"Queue monitor failed to start: {e}")

        if IS_WINDOWS:
            logger.info("Boundary Daemon running. Close this window or press Ctrl+Break to stop.")
        else:
            logger.info("Boundary Daemon running. Press Ctrl+C to stop.")
        logger.info("=" * 70)

    def stop(self):
        """Stop the boundary daemon"""
        if not self._running:
            return

        logger.info("Stopping Boundary Daemon...")
        self._running = False
        self._shutdown_event.set()

        # Stop state monitor
        self.state_monitor.stop()

        # Cleanup policy engine callbacks to prevent memory leaks
        if self.policy_engine:
            try:
                self.policy_engine.cleanup()
                logger.info("Policy engine callbacks cleaned up")
            except Exception as e:
                logger.warning(f"Failed to cleanup policy engine: {e}")

        # Cleanup tripwire system callbacks to prevent memory leaks
        if self.tripwire_system:
            try:
                self.tripwire_system.cleanup()
                logger.info("Tripwire system callbacks cleaned up")
            except Exception as e:
                logger.warning(f"Failed to cleanup tripwire system: {e}")

        # Stop dreaming status reporter
        if self._dreaming_reporter:
            try:
                self._dreaming_reporter.stop()
                logger.info("Dreaming status reporter stopped")
            except Exception as e:
                logger.warning(f"Failed to stop dreaming reporter: {e}")

        # Stop API server
        if self.api_server:
            try:
                self.api_server.stop()
                logger.info("API server stopped")
            except Exception as e:
                logger.warning(f"Failed to stop API server: {e}")

        # Stop daemon integrity monitoring
        if self._integrity_protector:
            try:
                self._integrity_protector.stop_monitoring()
                logger.info("Daemon integrity monitoring stopped")
            except Exception as e:
                logger.warning(f"Failed to stop integrity monitoring: {e}")

        # Stop redundant logger health monitoring
        if self._redundant_logger and self.redundant_logging:
            try:
                self._redundant_logger.stop_health_monitoring()
                logger.info("Redundant logger health monitoring stopped")
            except Exception as e:
                logger.warning(f"Failed to stop redundant logger: {e}")

        # Stop memory monitor (Plan 11: Memory Leak Monitoring)
        if self.memory_monitor and self.memory_monitor_enabled:
            try:
                # Log final memory stats before shutdown
                stats = self.memory_monitor.get_summary_stats()
                if stats.get('current'):
                    current = stats['current']
                    logger.info(f"Memory at shutdown: RSS={current['rss_mb']:.1f} MB, "
                                f"Leak indicator={stats.get('leak_indicator', 'none')}")
                self.memory_monitor.stop()
                logger.info("Memory monitor stopped")
            except Exception as e:
                logger.warning(f"Failed to stop memory monitor: {e}")

        # Stop resource monitor (Plan 11: Resource Monitoring)
        if self.resource_monitor and self.resource_monitor_enabled:
            try:
                # Log final resource stats
                stats = self.resource_monitor.get_summary_stats()
                if stats.get('current'):
                    current = stats['current']
                    fd_info = current.get('file_descriptors', {})
                    logger.info(f"Resources at shutdown: FD={fd_info.get('count', 0)}, "
                                f"Threads={current.get('threads', {}).get('count', 0)}")
                self.resource_monitor.stop()
                logger.info("Resource monitor stopped")
            except Exception as e:
                logger.warning(f"Failed to stop resource monitor: {e}")

        # Stop health monitor (Plan 11: Health Monitoring)
        if self.health_monitor and self.health_monitor_enabled:
            try:
                # Log final health status
                summary = self.health_monitor.get_summary()
                logger.info(f"Health at shutdown: {summary['status']}, "
                            f"Uptime: {summary['uptime_formatted']}")
                self.health_monitor.stop()
                logger.info("Health monitor stopped")
            except Exception as e:
                logger.warning(f"Failed to stop health monitor: {e}")

        # Stop queue monitor (Plan 11: Queue Monitoring)
        if self.queue_monitor and self.queue_monitor_enabled:
            try:
                # Log final queue status
                summary = self.queue_monitor.get_summary()
                logger.info(f"Queues at shutdown: {summary['queue_count']} monitored, "
                            f"total depth: {summary['total_depth']}")
                self.queue_monitor.stop()
                logger.info("Queue monitor stopped")
            except Exception as e:
                logger.warning(f"Failed to stop queue monitor: {e}")

        # Stop hardened watchdog endpoint
        if self.watchdog_endpoint and self.hardened_watchdog_enabled:
            try:
                self.watchdog_endpoint.stop()
                logger.info("Hardened watchdog endpoint stopped")
            except Exception as e:
                logger.warning(f"Failed to stop watchdog endpoint: {e}")

        # Stop clock monitor
        if self.clock_monitor and self.clock_monitor_enabled:
            try:
                self.clock_monitor.stop()
                logger.info("Clock monitor stopped")
            except Exception as e:
                logger.warning(f"Failed to stop clock monitor: {e}")

        # Stop network attestor (Phase 1: Network Trust Verification)
        if self.network_attestor and self.network_attestation_enabled:
            try:
                self.network_attestor.stop()
                logger.info("Network attestor stopped")
            except Exception as e:
                logger.warning(f"Failed to stop network attestor: {e}")

        # Wait for enforcement thread
        if self._enforcement_thread:
            self._enforcement_thread.join(timeout=5.0)

        # Cleanup enforcement rules (Plan 1)
        # SECURITY: By default, protections are NOT cleaned up on shutdown
        # This addresses "Cleanup on Shutdown Removes All Protection"
        cleanup_requested = getattr(self, '_cleanup_on_shutdown_requested', False)

        if self.network_enforcer and self.network_enforcer.is_available:
            try:
                if cleanup_requested or not self.protection_persistence:
                    success, msg = self.network_enforcer.cleanup(graceful=True)
                    if success:
                        logger.info("Network enforcement rules cleaned up")
                    else:
                        logger.info(f"Network rules preserved: {msg}")
                else:
                    logger.info("Network enforcement rules PRESERVED (protection persistence enabled)")
            except Exception as e:
                logger.warning(f"Failed to cleanup network rules: {e}")

        if self.usb_enforcer and self.usb_enforcer.is_available:
            try:
                if cleanup_requested or not self.protection_persistence:
                    success, msg = self.usb_enforcer.cleanup(graceful=True)
                    if success:
                        logger.info("USB enforcement rules cleaned up")
                    else:
                        logger.info(f"USB rules preserved: {msg}")
                else:
                    logger.info("USB enforcement rules PRESERVED (protection persistence enabled)")
            except Exception as e:
                logger.warning(f"Failed to cleanup USB rules: {e}")

        if self.process_enforcer and self.process_enforcer.is_available:
            try:
                self.process_enforcer.cleanup()
                logger.info("Process enforcement cleaned up")
            except Exception as e:
                logger.warning(f"Failed to cleanup process enforcement: {e}")

        # Cleanup TPM resources (Plan 2)
        if self.tpm_manager:
            try:
                self.tpm_manager.cleanup()
                logger.info("TPM resources cleaned up")
            except Exception as e:
                logger.warning(f"Failed to cleanup TPM resources: {e}")

        # Stop cluster coordination (Plan 4)
        if self.cluster_manager and self.cluster_enabled:
            try:
                self.cluster_manager.stop()
                logger.info("Cluster coordination stopped")
            except Exception as e:
                logger.warning(f"Failed to stop cluster coordination: {e}")

        # Stop log watchdog (Plan 8)
        if self.log_watchdog and self.watchdog_enabled:
            try:
                self.log_watchdog.stop()
                logger.info("Log watchdog stopped")
            except Exception as e:
                logger.warning(f"Failed to stop log watchdog: {e}")

        # Shutdown telemetry (Plan 9)
        if self.telemetry_manager and self.telemetry_enabled:
            try:
                self.telemetry_manager.shutdown()
                logger.info("Telemetry shutdown complete")
            except Exception as e:
                logger.warning(f"Failed to shutdown telemetry: {e}")

        # Log daemon shutdown
        self.event_logger.log_event(
            EventType.DAEMON_STOP,
            "Boundary Daemon stopped",
            metadata={}
        )

        logger.info("Boundary Daemon stopped.")

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

                # Periodic cache cleanup (prevents memory leaks)
                if current_time - self._last_cache_cleanup >= self._cache_cleanup_interval:
                    self._perform_cache_cleanup()
                    self._last_cache_cleanup = current_time

                # Check if in lockdown
                if self.lockdown_manager.is_in_lockdown():
                    # In lockdown: deny all operations
                    pass

                # Sleep briefly
                time.sleep(1.0)

            except Exception as e:
                logger.error(f"Error in enforcement loop: {e}")
                # Log the error
                self.event_logger.log_event(
                    EventType.HEALTH_CHECK,
                    f"Error in enforcement loop: {e}",
                    metadata={'error': str(e)}
                )
                time.sleep(1.0)

    def _perform_health_check(self):
        """Perform periodic health check"""
        # Update dreaming phase
        if self._dreaming_reporter:
            self._dreaming_reporter.set_phase(DreamPhase.VERIFYING)

        # Check daemon health (tripwire system)
        if self._dreaming_reporter:
            self._dreaming_reporter.start_operation("check:daemon_health")
        daemon_healthy = self.tripwire_system.check_daemon_health()
        if self._dreaming_reporter:
            self._dreaming_reporter.complete_operation("check:daemon_health", success=daemon_healthy)

        if not daemon_healthy:
            # Daemon health check failed - this is a critical violation
            self.event_logger.log_event(
                EventType.HEALTH_CHECK,
                "Daemon health check FAILED - possible tampering detected",
                metadata={'healthy': False}
            )
            logger.warning("*** Daemon health check failed ***")

        # Verify event log integrity
        if self._dreaming_reporter:
            self._dreaming_reporter.start_operation("check:event_log_integrity")
        is_valid, error = self.event_logger.verify_chain()
        if self._dreaming_reporter:
            self._dreaming_reporter.complete_operation("check:event_log_integrity", success=is_valid)

        if not is_valid:
            logger.critical(f"*** Event log chain integrity violation: {error} ***")
            self.event_logger.log_event(
                EventType.VIOLATION,
                f"Event log chain integrity violated: {error}",
                metadata={'healthy': False}
            )

        # Return to watching phase
        if self._dreaming_reporter:
            self._dreaming_reporter.set_phase(DreamPhase.WATCHING)

    def _perform_cache_cleanup(self):
        """
        Perform periodic cache cleanup to prevent memory leaks.

        This method clears caches that can be safely reset without losing
        essential state. It also forces garbage collection to reclaim memory.
        """
        if self._dreaming_reporter:
            self._dreaming_reporter.start_operation("cleanup:caches")

        try:
            # Get memory before cleanup (if available)
            mem_before = None
            try:
                import psutil
                process = psutil.Process(os.getpid())
                mem_before = process.memory_info().rss / (1024 * 1024)  # MB
            except Exception:
                pass

            caches_cleared = 0

            # Clear threat intel cache (can be repopulated on demand)
            if hasattr(self, '_threat_intel') and self._threat_intel:
                try:
                    self._threat_intel._threat_cache.clear()
                    self._threat_intel._cache_timestamps.clear()
                    caches_cleared += 1
                except Exception:
                    pass

            # Clear identity cache (sessions will re-authenticate)
            if hasattr(self, '_identity_manager') and self._identity_manager:
                try:
                    self._identity_manager._identity_cache.clear()
                    caches_cleared += 1
                except Exception:
                    pass

            # Clear TPM PCR cache (will be re-read on next check)
            if hasattr(self, '_tpm_manager') and self._tpm_manager:
                try:
                    self._tpm_manager._pcr_cache.clear()
                    caches_cleared += 1
                except Exception:
                    pass

            # Clear antivirus hash cache (will be re-queried on demand)
            if hasattr(self, '_antivirus') and self._antivirus:
                try:
                    self._antivirus._cache.clear()
                    caches_cleared += 1
                except Exception:
                    pass

            # Clear LDAP caches (will be re-queried on demand)
            if hasattr(self, '_ldap_mapper') and self._ldap_mapper:
                try:
                    self._ldap_mapper._user_cache.clear()
                    self._ldap_mapper._group_cache.clear()
                    caches_cleared += 1
                except Exception:
                    pass

            # Clear OIDC token cache (tokens will be re-validated)
            if hasattr(self, '_oidc_validator') and self._oidc_validator:
                try:
                    self._oidc_validator._token_cache.clear()
                    caches_cleared += 1
                except Exception:
                    pass

            # Force full garbage collection
            gc.collect(generation=2)  # Full collection

            # Get memory after cleanup
            mem_after = None
            mem_freed = 0
            try:
                import psutil
                process = psutil.Process(os.getpid())
                mem_after = process.memory_info().rss / (1024 * 1024)  # MB
                if mem_before:
                    mem_freed = mem_before - mem_after
            except Exception:
                pass

            # Log the cleanup
            log_msg = f"Cache cleanup: cleared {caches_cleared} caches"
            if mem_before and mem_after:
                log_msg += f", memory: {mem_before:.1f}MB -> {mem_after:.1f}MB"
                if mem_freed > 0:
                    log_msg += f" (freed {mem_freed:.1f}MB)"

            logger.info(log_msg)

            if self._dreaming_reporter:
                self._dreaming_reporter.complete_operation("cleanup:caches", success=True)

        except Exception as e:
            logger.error(f"Error during cache cleanup: {e}")
            if self._dreaming_reporter:
                self._dreaming_reporter.complete_operation("cleanup:caches", success=False)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}")
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

        # Add clock monitor information (Clock Drift Protection)
        status['clock_monitor_enabled'] = self.clock_monitor_enabled
        if self.clock_monitor and self.clock_monitor_enabled:
            try:
                clock_state = self.clock_monitor.get_state()
                is_trustworthy, trust_reason = self.clock_monitor.is_time_trustworthy()
                status['clock'] = {
                    'status': clock_state['status'],
                    'is_ntp_synced': clock_state['is_ntp_synced'],
                    'ntp_server': clock_state['ntp_server'],
                    'drift_ppm': clock_state['drift_ppm'],
                    'jump_count': clock_state['jump_count'],
                    'is_trustworthy': is_trustworthy,
                    'trust_reason': trust_reason,
                    'uptime_seconds': round(clock_state['uptime_seconds'], 1),
                }
                if clock_state.get('last_jump'):
                    status['clock']['last_jump'] = clock_state['last_jump']
            except Exception as e:
                status['clock'] = {'error': str(e)}

        # Add memory monitor information (Plan 11: Memory Leak Monitoring)
        status['memory_monitor_enabled'] = self.memory_monitor_enabled
        if self.memory_monitor and self.memory_monitor_enabled:
            try:
                mem_stats = self.memory_monitor.get_summary_stats()
                status['memory'] = {
                    'available': mem_stats.get('available', False),
                    'running': mem_stats.get('running', False),
                    'samples_collected': mem_stats.get('samples_collected', 0),
                    'alerts_total': mem_stats.get('alerts_total', 0),
                    'leak_indicator': mem_stats.get('leak_indicator', 'none'),
                }
                if mem_stats.get('current'):
                    current = mem_stats['current']
                    status['memory']['current_rss_mb'] = current.get('rss_mb', 0)
                    status['memory']['current_vms_mb'] = current.get('vms_mb', 0)
                    status['memory']['gc_objects'] = current.get('gc_objects', 0)
                    status['memory']['gc_garbage'] = current.get('gc_garbage', 0)
                if mem_stats.get('baseline_rss_mb'):
                    status['memory']['baseline_rss_mb'] = mem_stats['baseline_rss_mb']
                if mem_stats.get('growth_since_baseline_percent'):
                    status['memory']['growth_percent'] = mem_stats['growth_since_baseline_percent']
            except Exception as e:
                status['memory'] = {'error': str(e)}

        # Add resource monitor information (Plan 11: Resource Monitoring)
        status['resource_monitor_enabled'] = self.resource_monitor_enabled
        if self.resource_monitor and self.resource_monitor_enabled:
            try:
                res_stats = self.resource_monitor.get_summary_stats()
                status['resources'] = {
                    'available': res_stats.get('available', False),
                    'running': res_stats.get('running', False),
                    'samples_collected': res_stats.get('samples_collected', 0),
                    'alerts_total': res_stats.get('alerts_total', 0),
                }
                if res_stats.get('current'):
                    current = res_stats['current']
                    fd_info = current.get('file_descriptors', {})
                    status['resources']['fd_count'] = fd_info.get('count', 0)
                    status['resources']['fd_limit'] = fd_info.get('limit', 0)
                    status['resources']['fd_percent'] = fd_info.get('percent_used', 0)
                    status['resources']['thread_count'] = current.get('threads', {}).get('count', 0)
                    status['resources']['cpu_percent'] = current.get('cpu', {}).get('percent', 0)
                    status['resources']['connection_count'] = current.get('connections', {}).get('count', 0)
                if res_stats.get('fd_growth'):
                    status['resources']['fd_growth'] = res_stats['fd_growth']
                if res_stats.get('thread_growth'):
                    status['resources']['thread_growth'] = res_stats['thread_growth']
            except Exception as e:
                status['resources'] = {'error': str(e)}

        # Add health monitor information (Plan 11: Health Monitoring)
        status['health_monitor_enabled'] = self.health_monitor_enabled
        if self.health_monitor and self.health_monitor_enabled:
            try:
                health_summary = self.health_monitor.get_summary()
                status['health'] = {
                    'status': health_summary['status'],
                    'uptime_seconds': health_summary['uptime_seconds'],
                    'uptime_formatted': health_summary['uptime_formatted'],
                    'heartbeat_count': health_summary['heartbeat_count'],
                    'seconds_since_heartbeat': health_summary['seconds_since_heartbeat'],
                    'components': health_summary['component_summary'],
                    'alerts_count': health_summary['alerts_count'],
                }
            except Exception as e:
                status['health'] = {'error': str(e)}

        # Add queue monitor information (Plan 11: Queue Monitoring)
        status['queue_monitor_enabled'] = self.queue_monitor_enabled
        if self.queue_monitor and self.queue_monitor_enabled:
            try:
                queue_summary = self.queue_monitor.get_summary()
                status['queues'] = {
                    'queue_count': queue_summary['queue_count'],
                    'queues': queue_summary['queues'],
                    'total_depth': queue_summary['total_depth'],
                    'queues_with_backpressure': queue_summary['queues_with_backpressure'],
                    'alerts_count': queue_summary['alerts_count'],
                    'sample_count': queue_summary['sample_count'],
                }
            except Exception as e:
                status['queues'] = {'error': str(e)}

        # Add privilege/enforcement status (SECURITY: Addresses silent failure issue)
        if self.privilege_manager:
            try:
                priv_status = self.privilege_manager.get_status()
                status['privilege'] = {
                    'has_root': priv_status.has_root,
                    'effective_uid': priv_status.effective_uid,
                    'can_enforce_airgap': priv_status.can_enforce_airgap,
                    'can_enforce_lockdown': priv_status.can_enforce_lockdown,
                    'modules_available': priv_status.modules_available,
                    'modules_degraded': priv_status.modules_degraded,
                    'critical_issues_count': len(priv_status.critical_issues),
                }
            except Exception as e:
                status['privilege'] = {'error': str(e)}
        else:
            if IS_WINDOWS:
                try:
                    import ctypes
                    has_root = ctypes.windll.shell32.IsUserAnAdmin() != 0
                    effective_uid = 0 if has_root else 1000
                except Exception:
                    has_root = False
                    effective_uid = 1000
            else:
                has_root = os.geteuid() == 0
                effective_uid = os.geteuid()
            status['privilege'] = {
                'has_root': has_root,
                'effective_uid': effective_uid,
                'manager_available': False,
            }

        # Add secure config status
        status['secure_config_available'] = SECURE_CONFIG_AVAILABLE
        if self._integrity_protector:
            status['integrity_verified'] = self._integrity_verified

        # Add redundant logging status
        status['redundant_logging'] = self.redundant_logging
        if self._redundant_logger:
            try:
                logger_status = self._redundant_logger.get_status()
                status['redundant_logger'] = {
                    'running': logger_status['running'],
                    'event_count': logger_status['event_count'],
                    'healthy_backends': self._redundant_logger.get_healthy_backend_count(),
                    'stats': logger_status['stats'],
                }
            except Exception as e:
                status['redundant_logger'] = {'error': str(e)}

        return status

    def load_config_secure(self, config_path: str) -> dict:
        """
        Load a configuration file with encryption support.

        SECURITY: Automatically decrypts encrypted configuration files
        using machine-derived keys.

        Args:
            config_path: Path to configuration file

        Returns:
            Decrypted configuration dictionary
        """
        if not SECURE_CONFIG_AVAILABLE:
            # Fall back to basic JSON/YAML loading
            import json
            with open(config_path) as f:
                content = f.read()
                if content.strip().startswith('{'):
                    return json.loads(content)
                else:
                    # Try YAML if available
                    try:
                        import yaml
                        return yaml.safe_load(content)
                    except ImportError:
                        raise RuntimeError("Config loading requires pyyaml")

        return load_secure_config(config_path)

    def save_config_secure(self, config: dict, config_path: str, encrypt: bool = True):
        """
        Save a configuration file with optional encryption.

        SECURITY: Encrypts sensitive fields in the configuration.

        Args:
            config: Configuration dictionary
            config_path: Path to save configuration
            encrypt: Whether to encrypt sensitive fields
        """
        if not SECURE_CONFIG_AVAILABLE:
            # Fall back to basic JSON saving
            import json
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            return

        from .config import save_secure_config
        save_secure_config(config, config_path, encrypt=encrypt)

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
            logger.info("Signed logging not available - no public key to export")
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
            logger.info(f"Override ceremony for: {action}")
            logger.info(f"Reason: {reason}")
            logger.info("Biometric not available. Using keyboard ceremony.")
            logger.info("Type 'CONFIRM' to proceed:")
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
            logger.error(f"Error loading advisories: {e}")
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
            logger.error(f"Error getting watchdog alerts: {e}")
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
            logger.error(f"Error getting recent spans: {e}")
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
            logger.error(f"Error getting metrics: {e}")
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
    parser.add_argument('--dev-mode', action='store_true',
                       help='Development mode - bypass cryptography requirement (NOT for production)')

    args = parser.parse_args()

    # SECURITY: Check cryptography requirements before starting
    # Production requires the cryptography library; dev-mode allows bypass
    try:
        from .config.secure_config import require_crypto_or_exit
        require_crypto_or_exit(dev_mode=args.dev_mode)
    except ImportError:
        # Config module not available - continue without check
        pass

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
