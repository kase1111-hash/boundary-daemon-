"""
eBPF Observer for Kernel-Level Visibility

Provides read-only observation of kernel events for policy decisions:
- Process execution (exec* syscalls)
- File access (open, read, write)
- Network connections (connect, accept, bind)
- System calls (configurable tracing)

This is READ-ONLY observation - it does not block or modify behavior.
Policy decisions are made by the daemon based on observations.

Graceful degradation: If eBPF is not available, the module provides
limited functionality using /proc and other interfaces.
"""

import ctypes
import logging
import os
import queue
import struct
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Callable, Union

logger = logging.getLogger(__name__)

# Check eBPF availability
EBPF_AVAILABLE = False
BCC_AVAILABLE = False

try:
    from bcc import BPF
    BCC_AVAILABLE = True
    EBPF_AVAILABLE = True
except ImportError:
    logger.info("BCC not available - eBPF features limited")

# Check kernel version
def get_kernel_version() -> tuple:
    """Get kernel version as tuple (major, minor, patch)."""
    try:
        with open('/proc/version', 'r') as f:
            version_str = f.read()
        # Parse "Linux version X.Y.Z..."
        import re
        match = re.search(r'(\d+)\.(\d+)\.(\d+)', version_str)
        if match:
            return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except Exception:
        pass
    return (0, 0, 0)

KERNEL_VERSION = get_kernel_version()
KERNEL_SUPPORTS_BPF = KERNEL_VERSION >= (4, 15, 0)


class eBPFCapability(Enum):
    """eBPF capabilities available on this system."""
    NONE = auto()
    BASIC = auto()  # Limited /proc-based observation
    TRACEPOINTS = auto()  # Kernel tracepoints
    KPROBES = auto()  # Kernel probes
    UPROBES = auto()  # User-space probes
    XDP = auto()  # eXpress Data Path (network)
    FULL = auto()  # All capabilities


@dataclass
class ObservationEvent:
    """Base class for observation events."""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_type: str = ""
    pid: int = 0
    tid: int = 0
    uid: int = 0
    gid: int = 0
    comm: str = ""  # Process name

    # Source tracking
    source: str = "unknown"  # "ebpf", "proc", "audit"


@dataclass
class ProcessEvent(ObservationEvent):
    """Process execution event."""
    event_type: str = "process"
    parent_pid: int = 0
    parent_comm: str = ""
    filename: str = ""
    argv: List[str] = field(default_factory=list)
    envp: Dict[str, str] = field(default_factory=dict)
    cwd: str = ""
    exit_code: Optional[int] = None


@dataclass
class FileEvent(ObservationEvent):
    """File access event."""
    event_type: str = "file"
    operation: str = ""  # open, read, write, unlink, etc.
    path: str = ""
    flags: int = 0
    mode: int = 0
    size: int = 0
    success: bool = True


@dataclass
class NetworkEvent(ObservationEvent):
    """Network connection event."""
    event_type: str = "network"
    operation: str = ""  # connect, accept, bind, listen
    protocol: str = ""  # tcp, udp, unix
    src_addr: str = ""
    src_port: int = 0
    dst_addr: str = ""
    dst_port: int = 0
    success: bool = True


@dataclass
class SyscallEvent(ObservationEvent):
    """System call event."""
    event_type: str = "syscall"
    syscall_name: str = ""
    syscall_nr: int = 0
    args: List[int] = field(default_factory=list)
    ret: int = 0
    duration_ns: int = 0


class BaseObserver(ABC):
    """Abstract base class for observers."""

    @abstractmethod
    def start(self) -> bool:
        """Start observation."""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop observation."""
        pass

    @abstractmethod
    def get_events(self, timeout: float = 0.1) -> List[ObservationEvent]:
        """Get pending events."""
        pass


class ProcObserver(BaseObserver):
    """
    Fallback observer using /proc filesystem.

    Provides limited visibility when eBPF is not available.
    """

    def __init__(self, poll_interval: float = 1.0):
        self.poll_interval = poll_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._event_queue: queue.Queue = queue.Queue(maxsize=10000)

        # Track known processes
        self._known_pids: Set[int] = set()

    def start(self) -> bool:
        """Start /proc polling."""
        if self._running:
            return True

        self._running = True
        self._known_pids = self._get_current_pids()

        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

        logger.info("Started /proc observer (fallback mode)")
        return True

    def stop(self) -> None:
        """Stop /proc polling."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.info("Stopped /proc observer")

    def _poll_loop(self) -> None:
        """Poll /proc for changes."""
        while self._running:
            try:
                self._check_processes()
            except Exception as e:
                logger.debug(f"Poll error: {e}")

            time.sleep(self.poll_interval)

    def _get_current_pids(self) -> Set[int]:
        """Get set of current PIDs."""
        pids = set()
        try:
            for entry in os.listdir('/proc'):
                if entry.isdigit():
                    pids.add(int(entry))
        except Exception:
            pass
        return pids

    def _check_processes(self) -> None:
        """Check for new processes."""
        current_pids = self._get_current_pids()
        new_pids = current_pids - self._known_pids

        for pid in new_pids:
            event = self._get_process_info(pid)
            if event:
                try:
                    self._event_queue.put_nowait(event)
                except queue.Full:
                    pass

        self._known_pids = current_pids

    def _get_process_info(self, pid: int) -> Optional[ProcessEvent]:
        """Get process information from /proc."""
        try:
            proc_path = Path(f'/proc/{pid}')

            # Read comm
            comm = (proc_path / 'comm').read_text().strip()

            # Read cmdline
            cmdline = (proc_path / 'cmdline').read_text()
            argv = cmdline.split('\x00') if cmdline else []

            # Read status for uid/gid
            status = {}
            for line in (proc_path / 'status').read_text().split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    status[key.strip()] = value.strip()

            uid = int(status.get('Uid', '0').split()[0])
            gid = int(status.get('Gid', '0').split()[0])
            ppid = int(status.get('PPid', '0'))

            # Read cwd
            try:
                cwd = os.readlink(proc_path / 'cwd')
            except Exception:
                cwd = ""

            # Read exe
            try:
                exe = os.readlink(proc_path / 'exe')
            except Exception:
                exe = ""

            return ProcessEvent(
                pid=pid,
                tid=pid,
                uid=uid,
                gid=gid,
                comm=comm,
                parent_pid=ppid,
                filename=exe,
                argv=argv,
                cwd=cwd,
                source="proc",
            )

        except Exception:
            return None

    def get_events(self, timeout: float = 0.1) -> List[ObservationEvent]:
        """Get pending events."""
        events = []
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                event = self._event_queue.get(timeout=0.01)
                events.append(event)
            except queue.Empty:
                break

        return events


class eBPFObserverImpl(BaseObserver):
    """
    eBPF-based observer using BCC.

    Provides high-performance kernel-level observation.
    """

    # BPF program for process execution tracing
    BPF_PROGRAM = """
    #include <uapi/linux/ptrace.h>
    #include <linux/sched.h>

    struct exec_event {
        u32 pid;
        u32 ppid;
        u32 uid;
        u32 gid;
        char comm[16];
        char filename[256];
    };

    BPF_PERF_OUTPUT(exec_events);

    int trace_execve(struct pt_regs *ctx,
                     const char __user *filename,
                     const char __user *const __user *argv,
                     const char __user *const __user *envp) {
        struct exec_event event = {};

        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.uid = bpf_get_current_uid_gid();
        event.gid = bpf_get_current_uid_gid() >> 32;

        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        event.ppid = task->real_parent->tgid;

        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

        exec_events.perf_submit(ctx, &event, sizeof(event));
        return 0;
    }
    """

    def __init__(self):
        self._bpf = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._event_queue: queue.Queue = queue.Queue(maxsize=10000)

    def start(self) -> bool:
        """Start eBPF observation."""
        if not BCC_AVAILABLE:
            logger.error("BCC not available")
            return False

        if self._running:
            return True

        try:
            self._bpf = BPF(text=self.BPF_PROGRAM)
            self._bpf.attach_kprobe(
                event="__x64_sys_execve",
                fn_name="trace_execve"
            )

            # Set up perf buffer callback
            def handle_event(cpu, data, size):
                event = self._bpf["exec_events"].event(data)
                proc_event = ProcessEvent(
                    pid=event.pid,
                    parent_pid=event.ppid,
                    uid=event.uid,
                    gid=event.gid,
                    comm=event.comm.decode('utf-8', errors='replace'),
                    filename=event.filename.decode('utf-8', errors='replace'),
                    source="ebpf",
                )
                try:
                    self._event_queue.put_nowait(proc_event)
                except queue.Full:
                    pass

            self._bpf["exec_events"].open_perf_buffer(handle_event)

            self._running = True
            self._thread = threading.Thread(target=self._poll_loop, daemon=True)
            self._thread.start()

            logger.info("Started eBPF observer")
            return True

        except Exception as e:
            logger.error(f"Failed to start eBPF observer: {e}")
            return False

    def stop(self) -> None:
        """Stop eBPF observation."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        if self._bpf:
            self._bpf.cleanup()
            self._bpf = None
        logger.info("Stopped eBPF observer")

    def _poll_loop(self) -> None:
        """Poll perf buffer for events."""
        while self._running:
            try:
                self._bpf.perf_buffer_poll(timeout=100)
            except Exception as e:
                logger.debug(f"Poll error: {e}")
                time.sleep(0.1)

    def get_events(self, timeout: float = 0.1) -> List[ObservationEvent]:
        """Get pending events."""
        events = []
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                event = self._event_queue.get(timeout=0.01)
                events.append(event)
            except queue.Empty:
                break

        return events


class eBPFObserver:
    """
    Main eBPF observation interface.

    Automatically selects best available observation method:
    1. Full eBPF (if BCC available and kernel supports it)
    2. /proc fallback (always available on Linux)

    Usage:
        observer = eBPFObserver()
        observer.start()

        # In event loop
        events = observer.get_events()
        for event in events:
            print(f"Process: {event.comm} ({event.pid})")

        observer.stop()
    """

    def __init__(
        self,
        prefer_ebpf: bool = True,
        poll_interval: float = 1.0,
    ):
        self.prefer_ebpf = prefer_ebpf
        self.poll_interval = poll_interval

        # Determine capabilities
        self.capability = self._detect_capability()

        # Select observer implementation
        self._observer: Optional[BaseObserver] = None

        # Event callbacks
        self._callbacks: List[Callable[[ObservationEvent], None]] = []

        # Stats
        self._events_received = 0
        self._events_processed = 0

    def _detect_capability(self) -> eBPFCapability:
        """Detect available eBPF capabilities."""
        if not KERNEL_SUPPORTS_BPF:
            logger.info(f"Kernel {KERNEL_VERSION} does not support eBPF CO-RE")
            return eBPFCapability.BASIC

        if not BCC_AVAILABLE:
            logger.info("BCC not installed - using basic observation")
            return eBPFCapability.BASIC

        # Check if we have required permissions
        if os.geteuid() != 0:
            # Check for CAP_BPF
            try:
                # Try to create a simple BPF program
                from bcc import BPF
                test_prog = BPF(text='int test(void *ctx) { return 0; }')
                test_prog.cleanup()
                return eBPFCapability.FULL
            except Exception:
                logger.info("Insufficient permissions for eBPF")
                return eBPFCapability.BASIC

        return eBPFCapability.FULL

    def add_callback(self, callback: Callable[[ObservationEvent], None]) -> None:
        """Add callback for events."""
        self._callbacks.append(callback)

    def start(self) -> bool:
        """Start observation."""
        if self._observer:
            return True

        # Select observer based on capability
        if self.capability == eBPFCapability.FULL and self.prefer_ebpf:
            self._observer = eBPFObserverImpl()
            if not self._observer.start():
                # Fall back to /proc
                logger.info("Falling back to /proc observer")
                self._observer = ProcObserver(self.poll_interval)
                self._observer.start()
        else:
            self._observer = ProcObserver(self.poll_interval)
            self._observer.start()

        return True

    def stop(self) -> None:
        """Stop observation."""
        if self._observer:
            self._observer.stop()
            self._observer = None

    def get_events(self, timeout: float = 0.1) -> List[ObservationEvent]:
        """Get pending observation events."""
        if not self._observer:
            return []

        events = self._observer.get_events(timeout)
        self._events_received += len(events)

        # Invoke callbacks
        for event in events:
            for callback in self._callbacks:
                try:
                    callback(event)
                except Exception as e:
                    logger.error(f"Callback error: {e}")
            self._events_processed += 1

        return events

    def get_stats(self) -> Dict[str, Any]:
        """Get observer statistics."""
        return {
            'capability': self.capability.name,
            'observer_type': type(self._observer).__name__ if self._observer else None,
            'kernel_version': '.'.join(map(str, KERNEL_VERSION)),
            'ebpf_available': EBPF_AVAILABLE,
            'bcc_available': BCC_AVAILABLE,
            'events_received': self._events_received,
            'events_processed': self._events_processed,
        }


if __name__ == '__main__':
    print("Testing eBPF Observer...")

    print(f"\nSystem Info:")
    print(f"  Kernel Version: {'.'.join(map(str, KERNEL_VERSION))}")
    print(f"  eBPF Available: {EBPF_AVAILABLE}")
    print(f"  BCC Available: {BCC_AVAILABLE}")

    observer = eBPFObserver()
    print(f"\nCapability: {observer.capability.name}")

    # Start observer
    if observer.start():
        print("Observer started")
        print("\nWatching for events (5 seconds)...")

        # Collect events for 5 seconds
        end_time = time.time() + 5
        event_count = 0

        while time.time() < end_time:
            events = observer.get_events(timeout=0.5)
            for event in events:
                event_count += 1
                if isinstance(event, ProcessEvent):
                    print(f"  Process: {event.comm} (PID {event.pid}) - {event.filename}")

        print(f"\nReceived {event_count} events")
        print(f"Stats: {observer.get_stats()}")

        observer.stop()
        print("Observer stopped")
    else:
        print("Failed to start observer")

    print("\neBPF observer test complete.")
