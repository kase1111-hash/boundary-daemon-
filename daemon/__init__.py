"""
Boundary Daemon - Core Components
"""

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
    'TPM_AVAILABLE'
]
