"""
Boundary Daemon - Core Components
"""

from .state_monitor import StateMonitor, EnvironmentState, NetworkState, HardwareTrust
from .policy_engine import PolicyEngine, BoundaryMode, PolicyRequest, PolicyDecision, Operator, MemoryClass
from .tripwires import TripwireSystem, LockdownManager, TripwireViolation, ViolationType
from .event_logger import EventLogger, EventType, BoundaryEvent
from .boundary_daemon import BoundaryDaemon

# Import enforcement module (Plan 1: Kernel-Level Enforcement)
try:
    from .enforcement import NetworkEnforcer, FirewallBackend, NetworkEnforcementError
    ENFORCEMENT_AVAILABLE = True
except ImportError:
    ENFORCEMENT_AVAILABLE = False
    NetworkEnforcer = None
    FirewallBackend = None
    NetworkEnforcementError = None

__all__ = [
    'StateMonitor', 'EnvironmentState', 'NetworkState', 'HardwareTrust',
    'PolicyEngine', 'BoundaryMode', 'PolicyRequest', 'PolicyDecision', 'Operator', 'MemoryClass',
    'TripwireSystem', 'LockdownManager', 'TripwireViolation', 'ViolationType',
    'EventLogger', 'EventType', 'BoundaryEvent',
    'BoundaryDaemon',
    # Enforcement (Plan 1)
    'NetworkEnforcer', 'FirewallBackend', 'NetworkEnforcementError',
    'ENFORCEMENT_AVAILABLE'
]
