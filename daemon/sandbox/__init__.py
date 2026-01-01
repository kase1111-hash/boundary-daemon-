"""
Sandbox Module for Boundary Daemon

Provides process isolation and confinement that integrates with
the daemon's policy engine and boundary modes.

Components:
- namespace: Linux namespace isolation (PID, network, mount, user)
- seccomp_filter: seccomp-bpf syscall filtering
- cgroups: cgroups v2 resource limits
- network_policy: Per-sandbox iptables/nftables firewall rules
- sandbox_manager: Policy-integrated sandbox orchestration

Boundary Mode Integration:
- OPEN: Minimal sandbox (basic resource limits)
- RESTRICTED: Namespace isolation (PID, mount)
- TRUSTED: Full namespace isolation
- AIRGAP: Strict network isolation + filesystem restrictions
- COLDROOM: Maximum isolation, minimal syscalls
- LOCKDOWN: No new processes allowed

Usage:
    from daemon.sandbox import SandboxManager, SandboxProfile

    manager = SandboxManager(policy_engine)

    # Run a command in sandbox
    result = manager.run_sandboxed(
        command=["/usr/bin/python3", "script.py"],
        profile=SandboxProfile.RESTRICTED,
    )

    # Or create a sandbox and manage it
    sandbox = manager.create_sandbox(
        name="worker-1",
        profile=SandboxProfile.from_boundary_mode(BoundaryMode.AIRGAP),
    )
    sandbox.run(["python3", "script.py"])
    sandbox.terminate()
"""

from .namespace import (
    NamespaceManager,
    NamespaceFlags,
    NamespaceConfig,
    IsolatedProcess,
)

from .seccomp_filter import (
    SeccompFilter,
    SeccompAction,
    SyscallRule,
    SeccompProfile,
)

from .cgroups import (
    CgroupManager,
    CgroupLimits,
    ResourceUsage,
)

from .network_policy import (
    NetworkPolicy,
    SandboxFirewall,
    NetworkAction,
    HostRule,
    get_sandbox_firewall,
)

from .sandbox_manager import (
    SandboxManager,
    Sandbox,
    SandboxProfile,
    SandboxResult,
    SandboxError,
)

from .mac_profiles import (
    MACProfileGenerator,
    MACSystem,
    ProfileMode,
    MACProfileConfig,
    get_mac_generator,
)

from .profile_config import (
    ProfileConfigLoader,
    SandboxProfileConfig,
    CgroupLimitsConfig,
    NetworkPolicyConfig,
    get_profile_loader,
    YAML_AVAILABLE,
)

__all__ = [
    # Namespace
    'NamespaceManager',
    'NamespaceFlags',
    'NamespaceConfig',
    'IsolatedProcess',
    # Seccomp
    'SeccompFilter',
    'SeccompAction',
    'SyscallRule',
    'SeccompProfile',
    # Cgroups
    'CgroupManager',
    'CgroupLimits',
    'ResourceUsage',
    # Network Policy
    'NetworkPolicy',
    'SandboxFirewall',
    'NetworkAction',
    'HostRule',
    'get_sandbox_firewall',
    # Manager
    'SandboxManager',
    'Sandbox',
    'SandboxProfile',
    'SandboxResult',
    'SandboxError',
    # MAC Profiles
    'MACProfileGenerator',
    'MACSystem',
    'ProfileMode',
    'MACProfileConfig',
    'get_mac_generator',
    # Profile Config
    'ProfileConfigLoader',
    'SandboxProfileConfig',
    'CgroupLimitsConfig',
    'NetworkPolicyConfig',
    'get_profile_loader',
    'YAML_AVAILABLE',
]
