"""
eBPF Observability Module for Boundary Daemon

Provides kernel-level visibility WITHOUT requiring a kernel driver:
- Process execution monitoring
- File access monitoring
- Network connection monitoring
- System call tracing

Features:
- Read-only observation for policy decisions
- Graceful degradation on older kernels
- Optional module (daemon works without it)

Requirements:
- Linux kernel 4.15+ (for BPF CO-RE)
- bcc or bpftrace installed
- CAP_SYS_ADMIN or CAP_BPF capability
"""

from .ebpf_observer import (
    eBPFObserver,
    eBPFCapability,
    ObservationEvent,
    ProcessEvent,
    FileEvent,
    NetworkEvent,
    SyscallEvent,
)

from .probes import (
    ProbeType,
    ProbeConfig,
    ProbeManager,
    ExecProbe,
    OpenProbe,
    ConnectProbe,
)

from .policy_integration import (
    eBPFPolicyProvider,
    ObservationBasedPolicy,
    RealTimeEnforcement,
)

__all__ = [
    # Observer
    'eBPFObserver',
    'eBPFCapability',
    'ObservationEvent',
    'ProcessEvent',
    'FileEvent',
    'NetworkEvent',
    'SyscallEvent',

    # Probes
    'ProbeType',
    'ProbeConfig',
    'ProbeManager',
    'ExecProbe',
    'OpenProbe',
    'ConnectProbe',

    # Policy integration
    'eBPFPolicyProvider',
    'ObservationBasedPolicy',
    'RealTimeEnforcement',
]
