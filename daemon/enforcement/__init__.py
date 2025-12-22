"""
Enforcement Module - Kernel-Level Security Enforcement

This module provides actual OS-level enforcement mechanisms that go beyond
detection and logging to actually prevent unauthorized operations.

Components:
- NetworkEnforcer: iptables/nftables firewall management for network isolation
- USBEnforcer: udev rules for USB device prevention (planned)
- ProcessEnforcer: seccomp/container isolation (planned)
"""

from .network_enforcer import (
    NetworkEnforcer,
    FirewallBackend,
    NetworkEnforcementError,
)

__all__ = [
    'NetworkEnforcer',
    'FirewallBackend',
    'NetworkEnforcementError',
]
