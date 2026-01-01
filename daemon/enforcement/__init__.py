"""
Enforcement Module - Kernel-Level Security Enforcement

This module provides actual OS-level enforcement mechanisms that go beyond
detection and logging to actually prevent unauthorized operations.

Components:
- NetworkEnforcer: iptables/nftables firewall management for network isolation (Linux)
- WindowsFirewallEnforcer: Windows Firewall with Advanced Security (Windows)
- USBEnforcer: udev rules for USB device prevention
- ProcessEnforcer: seccomp/container isolation for process restriction
- SecureProfileManager: Cryptographically signed seccomp profiles with integrity verification
- ProtectionPersistenceManager: Ensures protections survive daemon restarts
- SecureProcessTerminator: Safe process termination without broad pattern matching

SECURITY: SecureProfileManager addresses "Seccomp Profiles Stored in Writable Directory"
by providing HMAC integrity verification, restrictive permissions, and optional immutable flags.

SECURITY: ProtectionPersistenceManager addresses "Cleanup on Shutdown Removes All Protection"
by persisting protection state to disk and requiring authentication for cleanup.

SECURITY: SecureProcessTerminator addresses "Process Termination Uses Broad Pattern Matching"
by using precise PID-based termination with verification and essential process protection.

SECURITY: WindowsFirewallEnforcer addresses "No Windows Firewall API integration"
by providing Windows Firewall rule management via netsh and PowerShell.
"""

from .network_enforcer import (
    NetworkEnforcer,
    FirewallBackend,
    NetworkEnforcementError,
)

# Windows Firewall enforcement (SECURITY: Windows network enforcement)
try:
    from .windows_firewall import (
        WindowsFirewallEnforcer,
        WindowsFirewallError,
        WindowsFirewallRule,
        FirewallProfile,
        FirewallAction,
        FirewallDirection,
        RuleProtocol,
        get_windows_firewall_enforcer,
    )
    WINDOWS_FIREWALL_AVAILABLE = True
except ImportError:
    WINDOWS_FIREWALL_AVAILABLE = False
    WindowsFirewallEnforcer = None
    WindowsFirewallError = None
    WindowsFirewallRule = None
    FirewallProfile = None
    FirewallAction = None
    FirewallDirection = None
    RuleProtocol = None
    get_windows_firewall_enforcer = None

from .usb_enforcer import (
    USBEnforcer,
    USBEnforcementError,
    USBDeviceClass,
)

from .process_enforcer import (
    ProcessEnforcer,
    ProcessEnforcementError,
    ContainerRuntime,
    IsolationLevel,
    ContainerConfig,
    ExternalWatchdog,
)

from .secure_profile_manager import (
    SecureProfileManager,
    ProfileIntegrity,
    SECURE_PROFILE_TEMPLATES,
)

from .protection_persistence import (
    ProtectionPersistenceManager,
    ProtectionType,
    CleanupPolicy,
    PersistenceReason,
    PersistedProtection,
    ProtectionState,
)

from .secure_process_termination import (
    SecureProcessTerminator,
    ProcessInfo,
    ProcessVerificationMethod,
    TerminationReason,
    TerminationResult,
    TerminationAttempt,
)

__all__ = [
    # Network Enforcement (Plan 1 Phase 1)
    'NetworkEnforcer',
    'FirewallBackend',
    'NetworkEnforcementError',
    # Windows Firewall Enforcement (Windows network enforcement)
    'WindowsFirewallEnforcer',
    'WindowsFirewallError',
    'WindowsFirewallRule',
    'FirewallProfile',
    'FirewallAction',
    'FirewallDirection',
    'RuleProtocol',
    'get_windows_firewall_enforcer',
    'WINDOWS_FIREWALL_AVAILABLE',
    # USB Enforcement (Plan 1 Phase 2)
    'USBEnforcer',
    'USBEnforcementError',
    'USBDeviceClass',
    # Process Enforcement (Plan 1 Phase 3)
    'ProcessEnforcer',
    'ProcessEnforcementError',
    'ContainerRuntime',
    'IsolationLevel',
    'ContainerConfig',
    'ExternalWatchdog',
    # Secure Profile Management (Seccomp Profile Integrity)
    'SecureProfileManager',
    'ProfileIntegrity',
    'SECURE_PROFILE_TEMPLATES',
    # Protection Persistence (Survives Restarts)
    'ProtectionPersistenceManager',
    'ProtectionType',
    'CleanupPolicy',
    'PersistenceReason',
    'PersistedProtection',
    'ProtectionState',
    # Secure Process Termination (No Pattern Matching)
    'SecureProcessTerminator',
    'ProcessInfo',
    'ProcessVerificationMethod',
    'TerminationReason',
    'TerminationResult',
    'TerminationAttempt',
]
