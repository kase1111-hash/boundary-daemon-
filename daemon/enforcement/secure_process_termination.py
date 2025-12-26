"""
Secure Process Termination - Safe and precise process management.

SECURITY: This module addresses the vulnerability:
"Process Termination Uses Broad Pattern Matching"

Problems with broad pattern matching (pkill -f 'pattern'):
1. Can kill legitimate processes (e.g., 'nc' matches 'finance', 'dance', 'cancel')
2. Attackers can evade by renaming processes
3. No verification of process identity before termination
4. Full command line matching is overly broad
5. No protection for essential system processes

Solution:
1. Use precise process identification via /proc filesystem
2. Verify process identity (exe path, not just name)
3. Maintain allowlists for essential processes
4. Require explicit PID-based termination with verification
5. Log all termination attempts with full process details
6. Use graduated termination (SIGTERM then SIGKILL)
7. Verify termination success
"""

import os
import re
import signal
import time
import hashlib
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Callable

logger = logging.getLogger(__name__)


class ProcessVerificationMethod(Enum):
    """Methods for verifying process identity."""
    EXE_PATH = "exe_path"  # /proc/PID/exe symlink
    EXE_HASH = "exe_hash"  # SHA256 of executable
    CMDLINE = "cmdline"    # /proc/PID/cmdline
    CGROUP = "cgroup"      # /proc/PID/cgroup
    UID = "uid"            # Process owner
    PARENT = "parent"      # Parent process verification


class TerminationReason(Enum):
    """Reasons for process termination."""
    SECURITY_THREAT = "security_threat"
    POLICY_VIOLATION = "policy_violation"
    EMERGENCY_LOCKDOWN = "emergency_lockdown"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    MANUAL_REQUEST = "manual_request"
    MALWARE_DETECTED = "malware_detected"


class TerminationResult(Enum):
    """Results of termination attempt."""
    SUCCESS = "success"
    PROCESS_NOT_FOUND = "process_not_found"
    PERMISSION_DENIED = "permission_denied"
    VERIFICATION_FAILED = "verification_failed"
    ESSENTIAL_PROCESS = "essential_process"
    ALREADY_DEAD = "already_dead"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class ProcessInfo:
    """Detailed information about a process."""
    pid: int
    name: str
    exe_path: Optional[str] = None
    exe_hash: Optional[str] = None
    cmdline: Optional[str] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    ppid: Optional[int] = None
    cgroup: Optional[str] = None
    start_time: Optional[float] = None
    state: Optional[str] = None

    @classmethod
    def from_pid(cls, pid: int) -> Optional['ProcessInfo']:
        """Get process info from /proc filesystem."""
        proc_path = Path(f"/proc/{pid}")
        if not proc_path.exists():
            return None

        try:
            info = cls(pid=pid, name="unknown")

            # Get process name from comm
            comm_file = proc_path / "comm"
            if comm_file.exists():
                info.name = comm_file.read_text().strip()

            # Get exe path (resolves symlink)
            exe_link = proc_path / "exe"
            try:
                info.exe_path = str(exe_link.resolve())
            except (OSError, PermissionError):
                pass

            # Get exe hash if we can read it
            if info.exe_path and os.path.exists(info.exe_path):
                try:
                    with open(info.exe_path, 'rb') as f:
                        # Only hash first 1MB for performance
                        data = f.read(1024 * 1024)
                        info.exe_hash = hashlib.sha256(data).hexdigest()[:16]
                except (OSError, PermissionError):
                    pass

            # Get command line
            cmdline_file = proc_path / "cmdline"
            if cmdline_file.exists():
                try:
                    cmdline_bytes = cmdline_file.read_bytes()
                    info.cmdline = cmdline_bytes.replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
                except (OSError, PermissionError):
                    pass

            # Get UID/GID from status
            status_file = proc_path / "status"
            if status_file.exists():
                try:
                    status = status_file.read_text()
                    for line in status.split('\n'):
                        if line.startswith('Uid:'):
                            parts = line.split()
                            if len(parts) >= 2:
                                info.uid = int(parts[1])
                        elif line.startswith('Gid:'):
                            parts = line.split()
                            if len(parts) >= 2:
                                info.gid = int(parts[1])
                        elif line.startswith('PPid:'):
                            parts = line.split()
                            if len(parts) >= 2:
                                info.ppid = int(parts[1])
                        elif line.startswith('State:'):
                            parts = line.split()
                            if len(parts) >= 2:
                                info.state = parts[1]
                except (OSError, PermissionError):
                    pass

            # Get cgroup
            cgroup_file = proc_path / "cgroup"
            if cgroup_file.exists():
                try:
                    info.cgroup = cgroup_file.read_text().strip()
                except (OSError, PermissionError):
                    pass

            # Get start time from stat
            stat_file = proc_path / "stat"
            if stat_file.exists():
                try:
                    stat = stat_file.read_text()
                    # Start time is field 22 (0-indexed: 21)
                    parts = stat.split()
                    if len(parts) > 21:
                        # This is in clock ticks since boot
                        info.start_time = float(parts[21])
                except (OSError, PermissionError, ValueError):
                    pass

            return info

        except Exception as e:
            logger.debug(f"Error getting process info for PID {pid}: {e}")
            return None


@dataclass
class TerminationAttempt:
    """Record of a termination attempt."""
    pid: int
    process_info: Optional[ProcessInfo]
    reason: TerminationReason
    result: TerminationResult
    timestamp: datetime
    signals_sent: List[int] = field(default_factory=list)
    error_message: Optional[str] = None
    requested_by: str = "system"

    def to_dict(self) -> Dict:
        return {
            'pid': self.pid,
            'process_name': self.process_info.name if self.process_info else 'unknown',
            'exe_path': self.process_info.exe_path if self.process_info else None,
            'reason': self.reason.value,
            'result': self.result.value,
            'timestamp': self.timestamp.isoformat(),
            'signals_sent': self.signals_sent,
            'error_message': self.error_message,
            'requested_by': self.requested_by,
        }


class SecureProcessTerminator:
    """
    Secure process termination with verification.

    Key security features:
    1. Precise PID-based termination (no pattern matching)
    2. Process verification before termination
    3. Essential process protection
    4. Graduated termination (SIGTERM then SIGKILL)
    5. Full audit logging
    6. Verification of termination success
    """

    # Essential processes that should NEVER be killed
    ESSENTIAL_PROCESSES = {
        # Init and systemd
        'init', 'systemd', 'systemd-journald', 'systemd-logind',
        'systemd-udevd', 'systemd-resolved', 'systemd-timesyncd',
        # Core system
        'kthreadd', 'ksoftirqd', 'kworker', 'rcu_sched', 'migration',
        # Security/authentication
        'sshd', 'polkitd', 'dbus-daemon', 'dbus-broker',
        # This daemon
        'boundary-daemon', 'boundary-watchdog',
    }

    # Essential exe paths (more reliable than names)
    ESSENTIAL_EXE_PATHS = {
        '/sbin/init',
        '/lib/systemd/systemd',
        '/usr/lib/systemd/systemd',
        '/usr/lib/systemd/systemd-journald',
        '/usr/lib/systemd/systemd-logind',
        '/usr/lib/systemd/systemd-udevd',
        '/usr/sbin/sshd',
    }

    # Essential UIDs (system processes)
    ESSENTIAL_UIDS = {0}  # Only root is unconditionally essential

    # Known malicious exe patterns (must match full path)
    KNOWN_MALICIOUS_PATHS = {
        '/tmp/',           # Executables in /tmp are suspicious
        '/dev/shm/',       # Memory-mapped executables
        '/var/tmp/',       # Temp files
        '(deleted)',       # Deleted executables still running
    }

    def __init__(
        self,
        event_logger=None,
        allow_essential_termination: bool = False,
        require_verification: bool = True,
        termination_timeout: float = 5.0,
    ):
        """
        Initialize the secure process terminator.

        Args:
            event_logger: Optional event logger for audit logging
            allow_essential_termination: If True, allows killing essential processes (DANGEROUS)
            require_verification: Require process verification before termination
            termination_timeout: Timeout for SIGTERM before SIGKILL
        """
        self._event_logger = event_logger
        self._allow_essential = allow_essential_termination
        self._require_verification = require_verification
        self._termination_timeout = termination_timeout
        self._lock = threading.Lock()
        self._termination_history: List[TerminationAttempt] = []

    def is_essential_process(self, process_info: ProcessInfo) -> Tuple[bool, str]:
        """
        Check if a process is essential and should not be terminated.

        Returns:
            (is_essential, reason)
        """
        # Check by name
        if process_info.name in self.ESSENTIAL_PROCESSES:
            return True, f"Essential process by name: {process_info.name}"

        # Check by exe path
        if process_info.exe_path:
            for essential_path in self.ESSENTIAL_EXE_PATHS:
                if process_info.exe_path == essential_path:
                    return True, f"Essential process by path: {process_info.exe_path}"

        # Check by UID
        if process_info.uid in self.ESSENTIAL_UIDS:
            # Root processes need additional verification
            # Not all root processes are essential, but PID 1 always is
            if process_info.pid == 1:
                return True, "PID 1 (init) is always essential"
            if process_info.ppid == 0 or process_info.ppid == 1:
                return True, f"Direct child of init with UID {process_info.uid}"

        # Check kernel threads (no exe path)
        if process_info.exe_path is None and process_info.uid == 0:
            return True, "Kernel thread (no exe, UID 0)"

        return False, ""

    def is_suspicious_process(self, process_info: ProcessInfo) -> Tuple[bool, str]:
        """
        Check if a process appears suspicious.

        Returns:
            (is_suspicious, reason)
        """
        reasons = []

        # Check for executables in suspicious locations
        if process_info.exe_path:
            for suspicious_path in self.KNOWN_MALICIOUS_PATHS:
                if suspicious_path in process_info.exe_path:
                    reasons.append(f"Executable in suspicious location: {process_info.exe_path}")

        # Check for deleted executables
        if process_info.exe_path and '(deleted)' in process_info.exe_path:
            reasons.append("Executable has been deleted (possible evasion)")

        # Check for processes with no exe path running as non-root non-kernel
        if process_info.exe_path is None and process_info.uid and process_info.uid > 0:
            reasons.append("No executable path for non-root process")

        return len(reasons) > 0, "; ".join(reasons)

    def verify_process(
        self,
        pid: int,
        expected_name: Optional[str] = None,
        expected_exe_path: Optional[str] = None,
        expected_uid: Optional[int] = None,
    ) -> Tuple[bool, ProcessInfo, str]:
        """
        Verify a process identity before termination.

        Args:
            pid: Process ID to verify
            expected_name: Expected process name (optional)
            expected_exe_path: Expected executable path (optional)
            expected_uid: Expected user ID (optional)

        Returns:
            (verified, process_info, message)
        """
        process_info = ProcessInfo.from_pid(pid)
        if not process_info:
            return False, None, f"Process {pid} not found"

        # Verify name if specified
        if expected_name and process_info.name != expected_name:
            return False, process_info, f"Name mismatch: expected '{expected_name}', got '{process_info.name}'"

        # Verify exe path if specified
        if expected_exe_path:
            if not process_info.exe_path:
                return False, process_info, "Cannot verify exe path (not readable)"
            if process_info.exe_path != expected_exe_path:
                return False, process_info, f"Exe path mismatch: expected '{expected_exe_path}', got '{process_info.exe_path}'"

        # Verify UID if specified
        if expected_uid is not None:
            if process_info.uid != expected_uid:
                return False, process_info, f"UID mismatch: expected {expected_uid}, got {process_info.uid}"

        return True, process_info, "Verification passed"

    def terminate_process(
        self,
        pid: int,
        reason: TerminationReason,
        requested_by: str = "system",
        expected_name: Optional[str] = None,
        expected_exe_path: Optional[str] = None,
        force: bool = False,
        graceful_timeout: Optional[float] = None,
    ) -> Tuple[TerminationResult, str]:
        """
        Terminate a process with verification and safety checks.

        SECURITY: This method uses precise PID-based termination with
        verification, NOT pattern matching.

        Args:
            pid: Process ID to terminate
            reason: Reason for termination
            requested_by: Who requested termination (for audit)
            expected_name: Expected process name (for verification)
            expected_exe_path: Expected exe path (for verification)
            force: Force termination even if essential
            graceful_timeout: Timeout before SIGKILL (default: self._termination_timeout)

        Returns:
            (result, message)
        """
        timeout = graceful_timeout or self._termination_timeout

        with self._lock:
            # Get process info
            process_info = ProcessInfo.from_pid(pid)
            attempt = TerminationAttempt(
                pid=pid,
                process_info=process_info,
                reason=reason,
                result=TerminationResult.ERROR,
                timestamp=datetime.utcnow(),
                requested_by=requested_by,
            )

            try:
                # Check if process exists
                if not process_info:
                    attempt.result = TerminationResult.PROCESS_NOT_FOUND
                    attempt.error_message = f"Process {pid} not found"
                    self._record_attempt(attempt)
                    return TerminationResult.PROCESS_NOT_FOUND, attempt.error_message

                # Verify process identity if required
                if self._require_verification and (expected_name or expected_exe_path):
                    verified, _, msg = self.verify_process(
                        pid,
                        expected_name=expected_name,
                        expected_exe_path=expected_exe_path,
                    )
                    if not verified:
                        attempt.result = TerminationResult.VERIFICATION_FAILED
                        attempt.error_message = msg
                        self._record_attempt(attempt)
                        return TerminationResult.VERIFICATION_FAILED, msg

                # Check if essential
                is_essential, essential_reason = self.is_essential_process(process_info)
                if is_essential and not force:
                    if not self._allow_essential:
                        attempt.result = TerminationResult.ESSENTIAL_PROCESS
                        attempt.error_message = essential_reason
                        self._record_attempt(attempt)
                        return TerminationResult.ESSENTIAL_PROCESS, f"Cannot kill essential process: {essential_reason}"

                # Log the termination attempt
                logger.info(
                    f"Terminating process: PID={pid}, name={process_info.name}, "
                    f"exe={process_info.exe_path}, reason={reason.value}"
                )

                # Send SIGTERM first for graceful shutdown
                try:
                    os.kill(pid, signal.SIGTERM)
                    attempt.signals_sent.append(signal.SIGTERM)
                except ProcessLookupError:
                    attempt.result = TerminationResult.ALREADY_DEAD
                    self._record_attempt(attempt)
                    return TerminationResult.ALREADY_DEAD, "Process already dead"
                except PermissionError:
                    attempt.result = TerminationResult.PERMISSION_DENIED
                    attempt.error_message = "Permission denied"
                    self._record_attempt(attempt)
                    return TerminationResult.PERMISSION_DENIED, "Permission denied to kill process"

                # Wait for graceful termination
                start_time = time.monotonic()
                while time.monotonic() - start_time < timeout:
                    if not self._process_exists(pid):
                        attempt.result = TerminationResult.SUCCESS
                        self._record_attempt(attempt)
                        return TerminationResult.SUCCESS, f"Process {pid} terminated gracefully"
                    time.sleep(0.1)

                # Still running - send SIGKILL
                try:
                    os.kill(pid, signal.SIGKILL)
                    attempt.signals_sent.append(signal.SIGKILL)
                except ProcessLookupError:
                    attempt.result = TerminationResult.SUCCESS
                    self._record_attempt(attempt)
                    return TerminationResult.SUCCESS, f"Process {pid} terminated"
                except PermissionError:
                    attempt.result = TerminationResult.PERMISSION_DENIED
                    attempt.error_message = "Permission denied for SIGKILL"
                    self._record_attempt(attempt)
                    return TerminationResult.PERMISSION_DENIED, "Permission denied for SIGKILL"

                # Wait for forced termination
                time.sleep(0.5)
                if not self._process_exists(pid):
                    attempt.result = TerminationResult.SUCCESS
                    self._record_attempt(attempt)
                    return TerminationResult.SUCCESS, f"Process {pid} force terminated"

                # Failed to terminate
                attempt.result = TerminationResult.TIMEOUT
                attempt.error_message = "Process did not terminate"
                self._record_attempt(attempt)
                return TerminationResult.TIMEOUT, f"Process {pid} did not terminate (zombie?)"

            except Exception as e:
                attempt.result = TerminationResult.ERROR
                attempt.error_message = str(e)
                self._record_attempt(attempt)
                return TerminationResult.ERROR, f"Error terminating process: {e}"

    def _process_exists(self, pid: int) -> bool:
        """Check if a process exists."""
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, OSError):
            return False

    def _record_attempt(self, attempt: TerminationAttempt):
        """Record a termination attempt for audit."""
        self._termination_history.append(attempt)

        # Keep only last 1000 attempts
        if len(self._termination_history) > 1000:
            self._termination_history = self._termination_history[-1000:]

        # Log to event logger
        if self._event_logger:
            try:
                self._event_logger.log_event(
                    event_type='PROCESS_TERMINATION',
                    data=attempt.to_dict(),
                )
            except Exception:
                pass

    def find_processes_by_criteria(
        self,
        name_pattern: Optional[str] = None,
        exe_path_prefix: Optional[str] = None,
        uid: Optional[int] = None,
        exclude_essential: bool = True,
    ) -> List[ProcessInfo]:
        """
        Find processes matching criteria (for identification, not termination).

        SECURITY: This method is for IDENTIFICATION only. Termination must
        be done via terminate_process() with explicit PID.

        Args:
            name_pattern: Regex pattern for process name
            exe_path_prefix: Prefix for executable path
            uid: User ID to match
            exclude_essential: Exclude essential processes

        Returns:
            List of matching ProcessInfo objects
        """
        matches = []

        try:
            for entry in os.listdir('/proc'):
                if not entry.isdigit():
                    continue

                pid = int(entry)
                process_info = ProcessInfo.from_pid(pid)
                if not process_info:
                    continue

                # Check criteria
                if name_pattern:
                    if not re.match(name_pattern, process_info.name):
                        continue

                if exe_path_prefix:
                    if not process_info.exe_path:
                        continue
                    if not process_info.exe_path.startswith(exe_path_prefix):
                        continue

                if uid is not None:
                    if process_info.uid != uid:
                        continue

                # Check essential
                if exclude_essential:
                    is_essential, _ = self.is_essential_process(process_info)
                    if is_essential:
                        continue

                matches.append(process_info)

        except Exception as e:
            logger.error(f"Error finding processes: {e}")

        return matches

    def terminate_by_exact_exe(
        self,
        exe_path: str,
        reason: TerminationReason,
        requested_by: str = "system",
        exclude_essential: bool = True,
    ) -> List[Tuple[int, TerminationResult, str]]:
        """
        Terminate all processes with an exact executable path.

        SECURITY: Uses exact path matching, not pattern matching.

        Args:
            exe_path: Exact path to executable
            reason: Reason for termination
            requested_by: Who requested termination
            exclude_essential: Skip essential processes

        Returns:
            List of (pid, result, message) tuples
        """
        results = []

        # Find all matching processes
        processes = self.find_processes_by_criteria(
            exe_path_prefix=exe_path,
            exclude_essential=exclude_essential,
        )

        # Filter to exact matches
        exact_matches = [p for p in processes if p.exe_path == exe_path]

        # Terminate each
        for process_info in exact_matches:
            result, msg = self.terminate_process(
                pid=process_info.pid,
                reason=reason,
                requested_by=requested_by,
                expected_exe_path=exe_path,
            )
            results.append((process_info.pid, result, msg))

        return results

    def get_termination_history(
        self,
        limit: int = 100,
        result_filter: Optional[TerminationResult] = None,
    ) -> List[Dict]:
        """Get termination history for audit."""
        with self._lock:
            history = self._termination_history[-limit:]
            if result_filter:
                history = [h for h in history if h.result == result_filter]
            return [h.to_dict() for h in history]

    def get_running_suspicious_processes(self) -> List[Tuple[ProcessInfo, str]]:
        """
        Find all currently running suspicious processes.

        Returns:
            List of (process_info, reason) tuples
        """
        suspicious = []

        try:
            for entry in os.listdir('/proc'):
                if not entry.isdigit():
                    continue

                pid = int(entry)
                process_info = ProcessInfo.from_pid(pid)
                if not process_info:
                    continue

                is_suspicious, reason = self.is_suspicious_process(process_info)
                if is_suspicious:
                    suspicious.append((process_info, reason))

        except Exception as e:
            logger.error(f"Error finding suspicious processes: {e}")

        return suspicious


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    print("Testing Secure Process Terminator")
    print("=" * 50)

    terminator = SecureProcessTerminator()

    # Get current process info
    my_pid = os.getpid()
    print(f"\n1. Current process info (PID {my_pid}):")
    my_info = ProcessInfo.from_pid(my_pid)
    if my_info:
        print(f"   Name: {my_info.name}")
        print(f"   Exe: {my_info.exe_path}")
        print(f"   UID: {my_info.uid}")
        print(f"   Command: {my_info.cmdline[:50]}..." if my_info.cmdline else "   Command: N/A")

    # Check if essential
    print("\n2. Essential process check:")
    if my_info:
        is_essential, reason = terminator.is_essential_process(my_info)
        print(f"   Is essential: {is_essential}")
        if reason:
            print(f"   Reason: {reason}")

    # Find suspicious processes
    print("\n3. Suspicious processes:")
    suspicious = terminator.get_running_suspicious_processes()
    if suspicious:
        for proc, reason in suspicious[:5]:
            print(f"   PID {proc.pid} ({proc.name}): {reason}")
    else:
        print("   No suspicious processes found")

    # Find python processes
    print("\n4. Python processes (for demo):")
    python_procs = terminator.find_processes_by_criteria(
        name_pattern=r'python.*',
        exclude_essential=True,
    )
    for proc in python_procs[:5]:
        print(f"   PID {proc.pid}: {proc.name} -> {proc.exe_path}")

    print("\nTest complete!")
