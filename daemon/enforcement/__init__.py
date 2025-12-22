"""
Enforcement Module - Kernel-Level Security Enforcement

This module provides actual OS-level enforcement mechanisms that go beyond
detection and logging to actually prevent unauthorized operations.

Components:
- NetworkEnforcer: iptables/nftables firewall management for network isolation
- USBEnforcer: udev rules for USB device prevention
- ProcessEnforcer: seccomp/container isolation for process restriction
"""

from .network_enforcer import (
    NetworkEnforcer,
    FirewallBackend,
    NetworkEnforcementError,
)

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

__all__ = [
    # Network Enforcement (Plan 1 Phase 1)
    'NetworkEnforcer',
    'FirewallBackend',
    'NetworkEnforcementError',
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
]
