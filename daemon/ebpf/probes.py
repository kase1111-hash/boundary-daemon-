"""
eBPF Probes for Specific Observation Points

Provides configurable probes for:
- Process execution (execve)
- File operations (open, read, write)
- Network connections (connect, accept)
- Custom syscall tracing

All probes are read-only and do not modify kernel behavior.
"""

import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Any, Callable

logger = logging.getLogger(__name__)

# Try to import BCC
try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False


class ProbeType(Enum):
    """Types of eBPF probes."""
    KPROBE = auto()  # Kernel function probe
    KRETPROBE = auto()  # Kernel function return probe
    TRACEPOINT = auto()  # Static kernel tracepoint
    UPROBE = auto()  # User-space probe
    URETPROBE = auto()  # User-space return probe
    RAW_TRACEPOINT = auto()  # Raw tracepoint


class ProbeTarget(Enum):
    """Common probe targets."""
    EXEC = "execve"
    OPEN = "open"
    OPENAT = "openat"
    READ = "read"
    WRITE = "write"
    CLOSE = "close"
    CONNECT = "connect"
    ACCEPT = "accept"
    BIND = "bind"
    LISTEN = "listen"
    SEND = "send"
    RECV = "recv"
    CLONE = "clone"
    FORK = "fork"
    EXIT = "exit"
    KILL = "kill"
    MMAP = "mmap"
    MPROTECT = "mprotect"


@dataclass
class ProbeConfig:
    """Configuration for a probe."""
    name: str
    probe_type: ProbeType
    target: str  # Function or tracepoint name

    # Filtering
    filter_pids: Set[int] = field(default_factory=set)
    filter_uids: Set[int] = field(default_factory=set)
    filter_comms: Set[str] = field(default_factory=set)
    exclude_pids: Set[int] = field(default_factory=set)

    # Sampling
    sample_rate: int = 1  # 1 = every event, 10 = every 10th

    # Enabled
    enabled: bool = True


@dataclass
class ProbeEvent:
    """Event from a probe."""
    probe_name: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    pid: int = 0
    tid: int = 0
    uid: int = 0
    comm: str = ""
    data: Dict[str, Any] = field(default_factory=dict)


class BaseProbe:
    """Base class for probe implementations."""

    def __init__(self, config: ProbeConfig):
        self.config = config
        self._running = False
        self._event_count = 0

    def start(self) -> bool:
        """Start the probe."""
        raise NotImplementedError

    def stop(self) -> None:
        """Stop the probe."""
        raise NotImplementedError

    def get_events(self) -> List[ProbeEvent]:
        """Get pending events."""
        raise NotImplementedError


class ExecProbe(BaseProbe):
    """
    Probe for process execution.

    Traces execve syscall to observe all process starts.
    """

    BPF_TEXT = """
    #include <uapi/linux/ptrace.h>
    #include <linux/sched.h>
    #include <linux/fs.h>

    struct event_t {
        u32 pid;
        u32 ppid;
        u32 uid;
        char comm[16];
        char filename[256];
        int retval;
    };

    BPF_PERF_OUTPUT(events);

    TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
        struct event_t event = {};

        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.uid = bpf_get_current_uid_gid();

        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        event.ppid = task->real_parent->tgid;

        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

        events.perf_submit(args, &event, sizeof(event));
        return 0;
    }
    """

    def __init__(self, config: Optional[ProbeConfig] = None):
        if config is None:
            config = ProbeConfig(
                name="exec_probe",
                probe_type=ProbeType.TRACEPOINT,
                target="syscalls/sys_enter_execve",
            )
        super().__init__(config)
        self._bpf = None
        self._events: List[ProbeEvent] = []
        self._lock = threading.Lock()

    def start(self) -> bool:
        """Start exec probe."""
        if not BCC_AVAILABLE:
            logger.warning("BCC not available - exec probe disabled")
            return False

        try:
            self._bpf = BPF(text=self.BPF_TEXT)

            def handle_event(cpu, data, size):
                event = self._bpf["events"].event(data)
                probe_event = ProbeEvent(
                    probe_name=self.config.name,
                    pid=event.pid,
                    uid=event.uid,
                    comm=event.comm.decode('utf-8', errors='replace'),
                    data={
                        'ppid': event.ppid,
                        'filename': event.filename.decode('utf-8', errors='replace'),
                    },
                )

                with self._lock:
                    self._events.append(probe_event)
                    self._event_count += 1

            self._bpf["events"].open_perf_buffer(handle_event)
            self._running = True

            # Start polling thread
            self._poll_thread = threading.Thread(
                target=self._poll_loop, daemon=True
            )
            self._poll_thread.start()

            logger.info("Exec probe started")
            return True

        except Exception as e:
            logger.error(f"Failed to start exec probe: {e}")
            return False

    def _poll_loop(self) -> None:
        """Poll for events."""
        while self._running:
            try:
                self._bpf.perf_buffer_poll(timeout=100)
            except Exception:
                pass

    def stop(self) -> None:
        """Stop exec probe."""
        self._running = False
        if self._bpf:
            self._bpf.cleanup()
            self._bpf = None
        logger.info("Exec probe stopped")

    def get_events(self) -> List[ProbeEvent]:
        """Get pending events."""
        with self._lock:
            events = self._events.copy()
            self._events.clear()
        return events


class OpenProbe(BaseProbe):
    """
    Probe for file open operations.

    Traces openat syscall to observe file access.
    """

    BPF_TEXT = """
    #include <uapi/linux/ptrace.h>

    struct event_t {
        u32 pid;
        u32 uid;
        char comm[16];
        char filename[256];
        int flags;
    };

    BPF_PERF_OUTPUT(events);

    TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
        struct event_t event = {};

        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.uid = bpf_get_current_uid_gid();
        event.flags = args->flags;

        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

        events.perf_submit(args, &event, sizeof(event));
        return 0;
    }
    """

    def __init__(self, config: Optional[ProbeConfig] = None):
        if config is None:
            config = ProbeConfig(
                name="open_probe",
                probe_type=ProbeType.TRACEPOINT,
                target="syscalls/sys_enter_openat",
            )
        super().__init__(config)
        self._bpf = None
        self._events: List[ProbeEvent] = []
        self._lock = threading.Lock()

    def start(self) -> bool:
        """Start open probe."""
        if not BCC_AVAILABLE:
            return False

        try:
            self._bpf = BPF(text=self.BPF_TEXT)

            def handle_event(cpu, data, size):
                event = self._bpf["events"].event(data)
                probe_event = ProbeEvent(
                    probe_name=self.config.name,
                    pid=event.pid,
                    uid=event.uid,
                    comm=event.comm.decode('utf-8', errors='replace'),
                    data={
                        'filename': event.filename.decode('utf-8', errors='replace'),
                        'flags': event.flags,
                    },
                )

                with self._lock:
                    self._events.append(probe_event)
                    self._event_count += 1

            self._bpf["events"].open_perf_buffer(handle_event)
            self._running = True

            self._poll_thread = threading.Thread(
                target=self._poll_loop, daemon=True
            )
            self._poll_thread.start()

            return True

        except Exception as e:
            logger.error(f"Failed to start open probe: {e}")
            return False

    def _poll_loop(self) -> None:
        while self._running:
            try:
                self._bpf.perf_buffer_poll(timeout=100)
            except Exception:
                pass

    def stop(self) -> None:
        self._running = False
        if self._bpf:
            self._bpf.cleanup()

    def get_events(self) -> List[ProbeEvent]:
        with self._lock:
            events = self._events.copy()
            self._events.clear()
        return events


class ConnectProbe(BaseProbe):
    """
    Probe for network connections.

    Traces connect syscall to observe outbound connections.
    """

    BPF_TEXT = """
    #include <uapi/linux/ptrace.h>
    #include <net/sock.h>
    #include <linux/socket.h>
    #include <linux/in.h>

    struct event_t {
        u32 pid;
        u32 uid;
        char comm[16];
        u32 daddr;
        u16 dport;
        u16 family;
    };

    BPF_PERF_OUTPUT(events);

    int trace_connect(struct pt_regs *ctx, int fd, struct sockaddr *addr, int addrlen) {
        struct event_t event = {};

        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.uid = bpf_get_current_uid_gid();
        bpf_get_current_comm(&event.comm, sizeof(event.comm));

        u16 family;
        bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
        event.family = family;

        if (family == AF_INET) {
            struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
            bpf_probe_read_user(&event.daddr, sizeof(event.daddr), &addr4->sin_addr);
            bpf_probe_read_user(&event.dport, sizeof(event.dport), &addr4->sin_port);
        }

        events.perf_submit(ctx, &event, sizeof(event));
        return 0;
    }
    """

    def __init__(self, config: Optional[ProbeConfig] = None):
        if config is None:
            config = ProbeConfig(
                name="connect_probe",
                probe_type=ProbeType.KPROBE,
                target="__sys_connect",
            )
        super().__init__(config)
        self._bpf = None
        self._events: List[ProbeEvent] = []
        self._lock = threading.Lock()

    def start(self) -> bool:
        if not BCC_AVAILABLE:
            return False

        try:
            self._bpf = BPF(text=self.BPF_TEXT)
            self._bpf.attach_kprobe(
                event="__sys_connect",
                fn_name="trace_connect"
            )

            def handle_event(cpu, data, size):
                event = self._bpf["events"].event(data)

                # Convert IP address
                import socket
                import struct
                if event.family == socket.AF_INET:
                    daddr = socket.inet_ntoa(struct.pack("I", event.daddr))
                    dport = socket.ntohs(event.dport)
                else:
                    daddr = ""
                    dport = 0

                probe_event = ProbeEvent(
                    probe_name=self.config.name,
                    pid=event.pid,
                    uid=event.uid,
                    comm=event.comm.decode('utf-8', errors='replace'),
                    data={
                        'dst_addr': daddr,
                        'dst_port': dport,
                        'family': event.family,
                    },
                )

                with self._lock:
                    self._events.append(probe_event)
                    self._event_count += 1

            self._bpf["events"].open_perf_buffer(handle_event)
            self._running = True

            self._poll_thread = threading.Thread(
                target=self._poll_loop, daemon=True
            )
            self._poll_thread.start()

            return True

        except Exception as e:
            logger.error(f"Failed to start connect probe: {e}")
            return False

    def _poll_loop(self) -> None:
        while self._running:
            try:
                self._bpf.perf_buffer_poll(timeout=100)
            except Exception:
                pass

    def stop(self) -> None:
        self._running = False
        if self._bpf:
            self._bpf.cleanup()

    def get_events(self) -> List[ProbeEvent]:
        with self._lock:
            events = self._events.copy()
            self._events.clear()
        return events


class ProbeManager:
    """
    Manages multiple eBPF probes.

    Usage:
        manager = ProbeManager()
        manager.add_probe(ExecProbe())
        manager.add_probe(OpenProbe())
        manager.start_all()

        events = manager.get_all_events()
        manager.stop_all()
    """

    def __init__(self):
        self._probes: Dict[str, BaseProbe] = {}
        self._running = False

    def add_probe(self, probe: BaseProbe) -> None:
        """Add a probe."""
        self._probes[probe.config.name] = probe

    def remove_probe(self, name: str) -> None:
        """Remove a probe."""
        if name in self._probes:
            self._probes[name].stop()
            del self._probes[name]

    def start_all(self) -> Dict[str, bool]:
        """Start all probes."""
        results = {}
        for name, probe in self._probes.items():
            results[name] = probe.start()
        self._running = True
        return results

    def stop_all(self) -> None:
        """Stop all probes."""
        for probe in self._probes.values():
            probe.stop()
        self._running = False

    def get_all_events(self) -> Dict[str, List[ProbeEvent]]:
        """Get events from all probes."""
        events = {}
        for name, probe in self._probes.items():
            probe_events = probe.get_events()
            if probe_events:
                events[name] = probe_events
        return events

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics for all probes."""
        return {
            'probes': {
                name: {
                    'running': probe._running,
                    'events': probe._event_count,
                }
                for name, probe in self._probes.items()
            },
            'total_probes': len(self._probes),
        }


if __name__ == '__main__':
    print("Testing eBPF Probes...")
    print(f"BCC Available: {BCC_AVAILABLE}")

    if BCC_AVAILABLE and os.geteuid() == 0:
        manager = ProbeManager()
        manager.add_probe(ExecProbe())

        print("\nStarting probes...")
        results = manager.start_all()
        print(f"Start results: {results}")

        print("\nCollecting events for 5 seconds...")
        import time
        end_time = time.time() + 5

        while time.time() < end_time:
            events = manager.get_all_events()
            for probe_name, probe_events in events.items():
                for event in probe_events:
                    print(f"  [{probe_name}] {event.comm} (PID {event.pid})")
            time.sleep(0.5)

        print(f"\nStats: {manager.get_stats()}")
        manager.stop_all()
        print("Probes stopped")
    else:
        print("\nNote: Full probe testing requires root and BCC")
        print("Probe module loaded successfully")

    print("\nProbe test complete.")
