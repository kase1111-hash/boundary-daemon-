"""
Boundary Daemon - Core Components
"""

# Import centralized constants (SECURITY: Addresses hardcoded magic values)
from .constants import (
    Timeouts,
    BufferSizes,
    Permissions,
    Paths,
    Crypto,
    TimeThresholds,
    RateLimits,
    Retries,
    NetworkConstants,
    DetectionThresholds,
    Limits,
    EssentialProcesses,
    RuntimeConfig,
    DEFAULT_TIMEOUT,
    SECURE_FILE_MODE,
    SECURE_DIR_MODE,
    KDF_ITERATIONS,
)

from .state_monitor import StateMonitor, EnvironmentState, NetworkState, HardwareTrust
from .policy_engine import PolicyEngine, BoundaryMode, PolicyRequest, PolicyDecision, Operator, MemoryClass
from .tripwires import TripwireSystem, LockdownManager, TripwireViolation, ViolationType
from .event_logger import EventLogger, EventType, BoundaryEvent
from .signed_event_logger import SignedEventLogger
from .boundary_daemon import BoundaryDaemon

# Import enforcement module (Plan 1: Kernel-Level Enforcement)
try:
    from .enforcement import (
        NetworkEnforcer, FirewallBackend, NetworkEnforcementError,
        USBEnforcer, USBEnforcementError, USBDeviceClass,
        ProcessEnforcer, ProcessEnforcementError, ContainerRuntime, IsolationLevel, ContainerConfig, ExternalWatchdog
    )
    ENFORCEMENT_AVAILABLE = True
except ImportError:
    ENFORCEMENT_AVAILABLE = False
    NetworkEnforcer = None
    FirewallBackend = None
    NetworkEnforcementError = None
    USBEnforcer = None
    USBEnforcementError = None
    USBDeviceClass = None
    ProcessEnforcer = None
    ProcessEnforcementError = None
    ContainerRuntime = None
    IsolationLevel = None
    ContainerConfig = None
    ExternalWatchdog = None

# Import hardware module (Plan 2: TPM Integration)
try:
    from .hardware import (
        TPMManager, TPMError, TPMNotAvailableError,
        TPMSealingError, TPMUnsealingError, TPMAttestationError, SealedSecret
    )
    TPM_AVAILABLE = True
except ImportError:
    TPM_AVAILABLE = False
    TPMManager = None
    TPMError = None
    TPMNotAvailableError = None
    TPMSealingError = None
    TPMUnsealingError = None
    TPMAttestationError = None
    SealedSecret = None

# Import distributed module (Plan 4: Distributed Deployment)
try:
    from .distributed import (
        ClusterManager, ClusterNode, ClusterState,
        FileCoordinator, Coordinator
    )
    DISTRIBUTED_AVAILABLE = True
except ImportError:
    DISTRIBUTED_AVAILABLE = False
    ClusterManager = None
    ClusterNode = None
    ClusterState = None
    FileCoordinator = None
    Coordinator = None

# Import custom policy module (Plan 5: Custom Policy Language)
try:
    from .policy import (
        CustomPolicyEngine, PolicyRule, PolicyAction
    )
    CUSTOM_POLICY_AVAILABLE = True
except ImportError:
    CUSTOM_POLICY_AVAILABLE = False
    CustomPolicyEngine = None
    PolicyRule = None
    PolicyAction = None

# Import auth module (Plan 6: Biometric Authentication)
try:
    from .auth import (
        BiometricVerifier, BiometricType, BiometricResult,
        EnhancedCeremonyManager, BiometricCeremonyConfig
    )
    BIOMETRIC_AVAILABLE = True
except ImportError:
    BIOMETRIC_AVAILABLE = False
    BiometricVerifier = None
    BiometricType = None
    BiometricResult = None
    EnhancedCeremonyManager = None
    BiometricCeremonyConfig = None

# Import security module (Plan 7: Code Vulnerability Advisor)
try:
    from .security import (
        CodeVulnerabilityAdvisor, SecurityAdvisory,
        AdvisorySeverity, AdvisoryStatus, ScanResult
    )
    SECURITY_ADVISOR_AVAILABLE = True
except ImportError:
    SECURITY_ADVISOR_AVAILABLE = False
    CodeVulnerabilityAdvisor = None
    SecurityAdvisory = None
    AdvisorySeverity = None
    AdvisoryStatus = None
    ScanResult = None

# Import watchdog module (Plan 8: Log Watchdog Agent)
try:
    from .watchdog import (
        LogWatchdog, WatchdogAlert, WatchdogConfig,
        AlertSeverity, AlertStatus
    )
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    LogWatchdog = None
    WatchdogAlert = None
    WatchdogConfig = None
    AlertSeverity = None
    AlertStatus = None

# Import telemetry module (Plan 9: OpenTelemetry Integration)
try:
    from .telemetry import (
        TelemetryManager, TelemetryConfig, ExportMode,
        RedactionProcessor, instrument,
        OTEL_AVAILABLE, OTLP_AVAILABLE
    )
    TELEMETRY_AVAILABLE = True
except ImportError:
    TELEMETRY_AVAILABLE = False
    TelemetryManager = None
    TelemetryConfig = None
    ExportMode = None
    RedactionProcessor = None
    instrument = None
    OTEL_AVAILABLE = False
    OTLP_AVAILABLE = False

__all__ = [
    'StateMonitor', 'EnvironmentState', 'NetworkState', 'HardwareTrust',
    'PolicyEngine', 'BoundaryMode', 'PolicyRequest', 'PolicyDecision', 'Operator', 'MemoryClass',
    'TripwireSystem', 'LockdownManager', 'TripwireViolation', 'ViolationType',
    'EventLogger', 'EventType', 'BoundaryEvent',
    'SignedEventLogger',  # Plan 3: Cryptographic Log Signing
    'BoundaryDaemon',
    # Enforcement (Plan 1)
    'NetworkEnforcer', 'FirewallBackend', 'NetworkEnforcementError',
    'USBEnforcer', 'USBEnforcementError', 'USBDeviceClass',
    'ProcessEnforcer', 'ProcessEnforcementError', 'ContainerRuntime', 'IsolationLevel', 'ContainerConfig', 'ExternalWatchdog',
    'ENFORCEMENT_AVAILABLE',
    # Hardware (Plan 2: TPM)
    'TPMManager', 'TPMError', 'TPMNotAvailableError',
    'TPMSealingError', 'TPMUnsealingError', 'TPMAttestationError', 'SealedSecret',
    'TPM_AVAILABLE',
    # Distributed (Plan 4)
    'ClusterManager', 'ClusterNode', 'ClusterState',
    'FileCoordinator', 'Coordinator',
    'DISTRIBUTED_AVAILABLE',
    # Custom Policy (Plan 5)
    'CustomPolicyEngine', 'PolicyRule', 'PolicyAction',
    'CUSTOM_POLICY_AVAILABLE',
    # Biometric Authentication (Plan 6)
    'BiometricVerifier', 'BiometricType', 'BiometricResult',
    'EnhancedCeremonyManager', 'BiometricCeremonyConfig',
    'BIOMETRIC_AVAILABLE',
    # Security Advisor (Plan 7)
    'CodeVulnerabilityAdvisor', 'SecurityAdvisory',
    'AdvisorySeverity', 'AdvisoryStatus', 'ScanResult',
    'SECURITY_ADVISOR_AVAILABLE',
    # Log Watchdog (Plan 8)
    'LogWatchdog', 'WatchdogAlert', 'WatchdogConfig',
    'AlertSeverity', 'AlertStatus',
    'WATCHDOG_AVAILABLE',
    # Telemetry (Plan 9)
    'TelemetryManager', 'TelemetryConfig', 'ExportMode',
    'RedactionProcessor', 'instrument',
    'OTEL_AVAILABLE', 'OTLP_AVAILABLE',
    'TELEMETRY_AVAILABLE'
]
