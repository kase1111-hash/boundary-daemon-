"""
Process Security Module

Detects suspicious process activity including:
- Process injection attempts (ptrace, LD_PRELOAD, etc.)
- Unusual parent-child process relationships
- Hidden/orphaned processes
- Privilege escalation patterns
- Suspicious process behavior
"""

import os
import re
import time
import threading
import subprocess
from enum import Enum
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict


class ProcessSecurityAlert(Enum):
    """Types of process security alerts"""
    # Process injection
    PTRACE_ATTACH = "ptrace_attach"
    LD_PRELOAD_INJECTION = "ld_preload_injection"
    PROCESS_HOLLOWING = "process_hollowing"
    DLL_INJECTION = "dll_injection"
    CODE_INJECTION = "code_injection"

    # Parent-child anomalies
    UNUSUAL_PARENT = "unusual_parent"
    ORPHANED_PROCESS = "orphaned_process"
    SHELL_SPAWN_FROM_SERVICE = "shell_spawn_from_service"
    BROWSER_SPAWN_SHELL = "browser_spawn_shell"
    OFFICE_SPAWN_SHELL = "office_spawn_shell"

    # Hidden processes
    HIDDEN_PROCESS = "hidden_process"
    PID_MISMATCH = "pid_mismatch"
    PROC_HIDING = "proc_hiding"

    # Privilege escalation
    SUID_EXECUTION = "suid_execution"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CAPABILITY_ABUSE = "capability_abuse"

    # Suspicious behavior
    MEMORY_MANIPULATION = "memory_manipulation"
    SUSPICIOUS_CMDLINE = "suspicious_cmdline"
    DELETED_EXECUTABLE = "deleted_executable"
    MASQUERADING = "masquerading"


class ProcessSeverity(Enum):
    """Severity levels for process alerts"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProcessCategory(Enum):
    """Categories of process security issues"""
    INJECTION = "injection"
    HIERARCHY = "hierarchy"
    HIDING = "hiding"
    PRIVILEGE = "privilege"
    BEHAVIORAL = "behavioral"


@dataclass
class ProcessSecurityConfig:
    """Configuration for process security monitoring"""
    # Detection toggles
    detect_injection: bool = True
    detect_hierarchy_anomalies: bool = True
    detect_hidden_processes: bool = True
    detect_privilege_escalation: bool = True

    # Monitoring settings
    check_interval_seconds: int = 30
    track_process_history: bool = True
    history_window_minutes: int = 60

    # Known safe processes (won't trigger alerts)
    safe_processes: Set[str] = field(default_factory=lambda: {
        'systemd', 'init', 'kthreadd', 'rcu_sched', 'migration',
        'ksoftirqd', 'kworker', 'watchdog', 'cpuhp'
    })

    # Suspicious command patterns
    suspicious_cmdline_patterns: List[str] = field(default_factory=lambda: [
        r'base64\s+-d',  # Base64 decode (common in obfuscation)
        r'python.*-c.*exec',  # Python one-liner execution
        r'perl.*-e.*',  # Perl one-liner
        r'bash\s+-i.*>&\s*/dev/tcp',  # Reverse shell
        r'nc\s+-e',  # Netcat shell
        r'curl.*\|\s*sh',  # Download and execute
        r'wget.*\|\s*sh',
        r'/dev/shm/',  # Execution from shared memory
        r'/tmp/\..*',  # Hidden files in /tmp
        r'nohup.*&$',  # Background persistence
        r'chmod\s+\+s',  # SUID bit setting
    ])

    # Services that shouldn't spawn shells
    services_no_shell: Set[str] = field(default_factory=lambda: {
        'nginx', 'apache', 'httpd', 'mysql', 'postgres', 'redis',
        'mongodb', 'elasticsearch', 'docker', 'containerd'
    })

    # Browsers that shouldn't spawn shells
    browsers: Set[str] = field(default_factory=lambda: {
        'chrome', 'chromium', 'firefox', 'opera', 'brave', 'edge',
        'safari', 'electron'
    })

    # Shell executables
    shells: Set[str] = field(default_factory=lambda: {
        'sh', 'bash', 'zsh', 'fish', 'ksh', 'csh', 'tcsh', 'dash', 'ash'
    })


@dataclass
class ProcessInfo:
    """Information about a process"""
    pid: int
    ppid: int
    name: str
    cmdline: str
    exe: str
    uid: int
    gid: int
    state: str
    start_time: float
    memory_rss: int = 0
    threads: int = 1
    capabilities: str = ""
    cwd: str = ""
    environ: Dict[str, str] = field(default_factory=dict)


@dataclass
class ProcessAlert:
    """Represents a detected process security issue"""
    alert_type: ProcessSecurityAlert
    severity: ProcessSeverity
    category: ProcessCategory
    timestamp: datetime
    pid: int
    process_name: str
    details: Dict = field(default_factory=dict)

    def to_alert_string(self) -> str:
        """Convert to alert message string"""
        msg = f"[{self.severity.value.upper()}] {self.alert_type.value}"
        msg += f" - PID {self.pid} ({self.process_name})"
        if self.details:
            detail_str = ", ".join(f"{k}={v}" for k, v in list(self.details.items())[:3])
            msg += f" ({detail_str})"
        return msg


@dataclass
class ProcessSecurityStatus:
    """Current process security monitoring status"""
    is_monitoring: bool = False
    total_processes: int = 0
    suspicious_processes: int = 0
    active_alerts: List[ProcessAlert] = field(default_factory=list)
    alerts: List[str] = field(default_factory=list)
    last_check: Optional[datetime] = None


class ProcessSecurityMonitor:
    """
    Monitors system processes for security threats including
    injection, hiding, and privilege escalation.
    """

    def __init__(self, config: Optional[ProcessSecurityConfig] = None):
        self.config = config or ProcessSecurityConfig()

        # Process tracking
        self._known_processes: Dict[int, ProcessInfo] = {}
        self._process_history: List[Tuple[datetime, int, str]] = []

        # Detection state
        self._alerts: List[ProcessAlert] = []
        self._alert_strings: List[str] = []

        # Compiled patterns
        self._suspicious_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in self.config.suspicious_cmdline_patterns
        ]

        # Thread safety
        self._lock = threading.RLock()

        # Monitoring state
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._last_check = None

    def start(self):
        """Start background process monitoring"""
        with self._lock:
            if self._running:
                return

            self._running = True
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop,
                daemon=True
            )
            self._monitor_thread.start()

    def stop(self):
        """Stop background monitoring"""
        with self._lock:
            self._running = False
            if self._monitor_thread:
                self._monitor_thread.join(timeout=5)
                self._monitor_thread = None

    def _monitor_loop(self):
        """Background monitoring loop"""
        while self._running:
            try:
                self.scan_processes()
                self._cleanup_old_data()
                self._last_check = datetime.utcnow()
            except Exception as e:
                print(f"Error in process monitoring: {e}")

            time.sleep(self.config.check_interval_seconds)

    def scan_processes(self) -> List[ProcessAlert]:
        """
        Scan all running processes for security issues.

        Returns:
            List of detected alerts
        """
        alerts = []

        with self._lock:
            try:
                current_processes = self._get_all_processes()

                for pid, proc_info in current_processes.items():
                    # Check for various security issues
                    if self.config.detect_injection:
                        alerts.extend(self._check_injection(proc_info))

                    if self.config.detect_hierarchy_anomalies:
                        alerts.extend(self._check_hierarchy(proc_info, current_processes))

                    if self.config.detect_privilege_escalation:
                        alerts.extend(self._check_privilege(proc_info))

                    # Check for suspicious command lines
                    alerts.extend(self._check_suspicious_cmdline(proc_info))

                # Check for hidden processes
                if self.config.detect_hidden_processes:
                    alerts.extend(self._check_hidden_processes(current_processes))

                # Update known processes
                self._known_processes = current_processes

                # Store alerts
                for alert in alerts:
                    self._alerts.append(alert)
                    self._alert_strings.append(alert.to_alert_string())

            except Exception as e:
                print(f"Error scanning processes: {e}")

        return alerts

    def analyze_process(
        self,
        pid: int,
        name: str,
        ppid: int,
        cmdline: str = "",
        exe: str = "",
        uid: int = 0,
        environ: Optional[Dict[str, str]] = None
    ) -> List[ProcessAlert]:
        """
        Analyze a specific process for security issues.

        Args:
            pid: Process ID
            name: Process name
            ppid: Parent process ID
            cmdline: Full command line
            exe: Executable path
            uid: User ID
            environ: Environment variables

        Returns:
            List of detected alerts
        """
        alerts = []
        now = datetime.utcnow()

        with self._lock:
            proc_info = ProcessInfo(
                pid=pid,
                ppid=ppid,
                name=name,
                cmdline=cmdline,
                exe=exe,
                uid=uid,
                gid=0,
                state="running",
                start_time=time.time(),
                environ=environ or {}
            )

            # Check for injection indicators
            if self.config.detect_injection:
                alerts.extend(self._check_injection(proc_info))

            # Check suspicious command line
            alerts.extend(self._check_suspicious_cmdline(proc_info))

            # Check for privilege issues
            if self.config.detect_privilege_escalation:
                alerts.extend(self._check_privilege(proc_info))

            # Store alerts
            for alert in alerts:
                self._alerts.append(alert)
                self._alert_strings.append(alert.to_alert_string())

        return alerts

    def detect_injection(
        self,
        target_pid: int,
        injection_type: str,
        source_pid: Optional[int] = None,
        details: Optional[Dict] = None
    ) -> ProcessAlert:
        """
        Report a detected process injection attempt.

        Args:
            target_pid: Target process being injected
            injection_type: Type of injection (ptrace, ld_preload, etc.)
            source_pid: Source process performing injection
            details: Additional details

        Returns:
            Created alert
        """
        now = datetime.utcnow()

        # Map injection type to alert type
        type_map = {
            'ptrace': ProcessSecurityAlert.PTRACE_ATTACH,
            'ld_preload': ProcessSecurityAlert.LD_PRELOAD_INJECTION,
            'hollowing': ProcessSecurityAlert.PROCESS_HOLLOWING,
            'dll': ProcessSecurityAlert.DLL_INJECTION,
            'code': ProcessSecurityAlert.CODE_INJECTION,
        }

        alert_type = type_map.get(injection_type.lower(), ProcessSecurityAlert.CODE_INJECTION)

        alert_details = details or {}
        if source_pid:
            alert_details['source_pid'] = source_pid

        alert = ProcessAlert(
            alert_type=alert_type,
            severity=ProcessSeverity.CRITICAL,
            category=ProcessCategory.INJECTION,
            timestamp=now,
            pid=target_pid,
            process_name=f"PID_{target_pid}",
            details=alert_details
        )

        with self._lock:
            self._alerts.append(alert)
            self._alert_strings.append(alert.to_alert_string())

        return alert

    def detect_unusual_parent(
        self,
        child_pid: int,
        child_name: str,
        parent_pid: int,
        parent_name: str,
        reason: str = ""
    ) -> ProcessAlert:
        """
        Report an unusual parent-child process relationship.

        Args:
            child_pid: Child process ID
            child_name: Child process name
            parent_pid: Parent process ID
            parent_name: Parent process name
            reason: Reason this is suspicious

        Returns:
            Created alert
        """
        now = datetime.utcnow()

        # Determine specific alert type
        alert_type = ProcessSecurityAlert.UNUSUAL_PARENT
        if parent_name.lower() in self.config.browsers:
            alert_type = ProcessSecurityAlert.BROWSER_SPAWN_SHELL
        elif parent_name.lower() in self.config.services_no_shell:
            alert_type = ProcessSecurityAlert.SHELL_SPAWN_FROM_SERVICE

        alert = ProcessAlert(
            alert_type=alert_type,
            severity=ProcessSeverity.HIGH,
            category=ProcessCategory.HIERARCHY,
            timestamp=now,
            pid=child_pid,
            process_name=child_name,
            details={
                'parent_pid': parent_pid,
                'parent_name': parent_name,
                'reason': reason
            }
        )

        with self._lock:
            self._alerts.append(alert)
            self._alert_strings.append(alert.to_alert_string())

        return alert

    def detect_hidden_process(
        self,
        pid: int,
        detection_method: str,
        details: Optional[Dict] = None
    ) -> ProcessAlert:
        """
        Report a detected hidden process.

        Args:
            pid: Process ID (or suspected PID)
            detection_method: How the hidden process was detected
            details: Additional details

        Returns:
            Created alert
        """
        now = datetime.utcnow()

        alert = ProcessAlert(
            alert_type=ProcessSecurityAlert.HIDDEN_PROCESS,
            severity=ProcessSeverity.CRITICAL,
            category=ProcessCategory.HIDING,
            timestamp=now,
            pid=pid,
            process_name="hidden",
            details={
                'detection_method': detection_method,
                **(details or {})
            }
        )

        with self._lock:
            self._alerts.append(alert)
            self._alert_strings.append(alert.to_alert_string())

        return alert

    def _get_all_processes(self) -> Dict[int, ProcessInfo]:
        """Get information about all running processes"""
        processes = {}

        try:
            # Read from /proc filesystem
            if os.path.exists('/proc'):
                for entry in os.listdir('/proc'):
                    if entry.isdigit():
                        pid = int(entry)
                        proc_info = self._get_process_info(pid)
                        if proc_info:
                            processes[pid] = proc_info
        except Exception as e:
            print(f"Error reading processes: {e}")

        return processes

    def _get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """Get detailed information about a specific process"""
        proc_dir = f'/proc/{pid}'

        try:
            if not os.path.exists(proc_dir):
                return None

            # Read status file
            status = {}
            status_path = f'{proc_dir}/status'
            if os.path.exists(status_path):
                with open(status_path, 'r') as f:
                    for line in f:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            status[key.strip()] = value.strip()

            # Read cmdline
            cmdline = ""
            cmdline_path = f'{proc_dir}/cmdline'
            if os.path.exists(cmdline_path):
                with open(cmdline_path, 'rb') as f:
                    cmdline = f.read().decode('utf-8', errors='replace').replace('\x00', ' ').strip()

            # Read exe link
            exe = ""
            exe_path = f'{proc_dir}/exe'
            try:
                if os.path.exists(exe_path):
                    exe = os.readlink(exe_path)
            except (OSError, PermissionError):
                pass

            # Get stat for ppid and start time
            ppid = 0
            start_time = 0.0
            stat_path = f'{proc_dir}/stat'
            if os.path.exists(stat_path):
                try:
                    with open(stat_path, 'r') as f:
                        stat_line = f.read()
                        # Parse stat - format: pid (comm) state ppid ...
                        # comm can contain spaces and parentheses
                        match = re.match(r'(\d+)\s+\((.+)\)\s+(\S+)\s+(\d+)\s+', stat_line)
                        if match:
                            ppid = int(match.group(4))
                except Exception:
                    pass

            # Read environ
            environ = {}
            environ_path = f'{proc_dir}/environ'
            try:
                if os.path.exists(environ_path):
                    with open(environ_path, 'rb') as f:
                        env_data = f.read().decode('utf-8', errors='replace')
                        for item in env_data.split('\x00'):
                            if '=' in item:
                                key, value = item.split('=', 1)
                                environ[key] = value
            except (OSError, PermissionError):
                pass

            return ProcessInfo(
                pid=pid,
                ppid=ppid,
                name=status.get('Name', ''),
                cmdline=cmdline,
                exe=exe,
                uid=int(status.get('Uid', '0').split()[0]),
                gid=int(status.get('Gid', '0').split()[0]),
                state=status.get('State', 'unknown').split()[0],
                start_time=start_time,
                threads=int(status.get('Threads', '1')),
                environ=environ
            )

        except (IOError, OSError, PermissionError) as e:
            return None

    def _check_injection(self, proc_info: ProcessInfo) -> List[ProcessAlert]:
        """Check for process injection indicators"""
        alerts = []
        now = datetime.utcnow()

        # Check for LD_PRELOAD injection
        if 'LD_PRELOAD' in proc_info.environ:
            ld_preload = proc_info.environ['LD_PRELOAD']
            # Ignore some known safe preloads
            if not any(safe in ld_preload for safe in ['/lib/', 'libasan', 'libtsan']):
                alert = ProcessAlert(
                    alert_type=ProcessSecurityAlert.LD_PRELOAD_INJECTION,
                    severity=ProcessSeverity.HIGH,
                    category=ProcessCategory.INJECTION,
                    timestamp=now,
                    pid=proc_info.pid,
                    process_name=proc_info.name,
                    details={'ld_preload': ld_preload}
                )
                alerts.append(alert)

        # Check for deleted executable (possible hollowing)
        if '(deleted)' in proc_info.exe:
            alert = ProcessAlert(
                alert_type=ProcessSecurityAlert.DELETED_EXECUTABLE,
                severity=ProcessSeverity.HIGH,
                category=ProcessCategory.INJECTION,
                timestamp=now,
                pid=proc_info.pid,
                process_name=proc_info.name,
                details={'exe': proc_info.exe}
            )
            alerts.append(alert)

        # Check for memory-only execution (memfd)
        if 'memfd:' in proc_info.exe:
            alert = ProcessAlert(
                alert_type=ProcessSecurityAlert.CODE_INJECTION,
                severity=ProcessSeverity.HIGH,
                category=ProcessCategory.INJECTION,
                timestamp=now,
                pid=proc_info.pid,
                process_name=proc_info.name,
                details={'exe': proc_info.exe, 'reason': 'memfd execution'}
            )
            alerts.append(alert)

        return alerts

    def _check_hierarchy(
        self,
        proc_info: ProcessInfo,
        all_processes: Dict[int, ProcessInfo]
    ) -> List[ProcessAlert]:
        """Check for unusual parent-child relationships"""
        alerts = []
        now = datetime.utcnow()

        # Skip kernel threads and safe processes
        if proc_info.name in self.config.safe_processes:
            return alerts

        parent = all_processes.get(proc_info.ppid)
        if not parent:
            # Check for orphaned process (ppid=1 but wasn't started by init)
            if proc_info.ppid == 1 and proc_info.name not in self.config.safe_processes:
                # This could be normal for daemons, check if it's a shell
                if proc_info.name in self.config.shells:
                    alert = ProcessAlert(
                        alert_type=ProcessSecurityAlert.ORPHANED_PROCESS,
                        severity=ProcessSeverity.MEDIUM,
                        category=ProcessCategory.HIERARCHY,
                        timestamp=now,
                        pid=proc_info.pid,
                        process_name=proc_info.name,
                        details={'reason': 'orphaned shell process'}
                    )
                    alerts.append(alert)
            return alerts

        parent_name = parent.name.lower()
        child_name = proc_info.name.lower()

        # Check for browser spawning shell
        if parent_name in self.config.browsers and child_name in self.config.shells:
            alert = ProcessAlert(
                alert_type=ProcessSecurityAlert.BROWSER_SPAWN_SHELL,
                severity=ProcessSeverity.CRITICAL,
                category=ProcessCategory.HIERARCHY,
                timestamp=now,
                pid=proc_info.pid,
                process_name=proc_info.name,
                details={
                    'parent_name': parent.name,
                    'parent_pid': parent.pid,
                    'reason': 'browser spawned shell'
                }
            )
            alerts.append(alert)

        # Check for service spawning shell
        if parent_name in self.config.services_no_shell and child_name in self.config.shells:
            alert = ProcessAlert(
                alert_type=ProcessSecurityAlert.SHELL_SPAWN_FROM_SERVICE,
                severity=ProcessSeverity.HIGH,
                category=ProcessCategory.HIERARCHY,
                timestamp=now,
                pid=proc_info.pid,
                process_name=proc_info.name,
                details={
                    'parent_name': parent.name,
                    'parent_pid': parent.pid,
                    'reason': 'service spawned shell'
                }
            )
            alerts.append(alert)

        return alerts

    def _check_privilege(self, proc_info: ProcessInfo) -> List[ProcessAlert]:
        """Check for privilege escalation indicators"""
        alerts = []
        now = datetime.utcnow()

        # Check for SUID execution
        if proc_info.exe and os.path.exists(proc_info.exe):
            try:
                stat = os.stat(proc_info.exe)
                if stat.st_mode & 0o4000:  # SUID bit set
                    # Alert if running as root but owned by non-root
                    if proc_info.uid == 0 and stat.st_uid != 0:
                        alert = ProcessAlert(
                            alert_type=ProcessSecurityAlert.SUID_EXECUTION,
                            severity=ProcessSeverity.MEDIUM,
                            category=ProcessCategory.PRIVILEGE,
                            timestamp=now,
                            pid=proc_info.pid,
                            process_name=proc_info.name,
                            details={
                                'exe': proc_info.exe,
                                'file_owner': stat.st_uid,
                                'running_as': proc_info.uid
                            }
                        )
                        alerts.append(alert)
            except (OSError, PermissionError):
                pass

        return alerts

    def _check_suspicious_cmdline(self, proc_info: ProcessInfo) -> List[ProcessAlert]:
        """Check for suspicious command line patterns"""
        alerts = []
        now = datetime.utcnow()

        if not proc_info.cmdline:
            return alerts

        for pattern in self._suspicious_patterns:
            if pattern.search(proc_info.cmdline):
                alert = ProcessAlert(
                    alert_type=ProcessSecurityAlert.SUSPICIOUS_CMDLINE,
                    severity=ProcessSeverity.HIGH,
                    category=ProcessCategory.BEHAVIORAL,
                    timestamp=now,
                    pid=proc_info.pid,
                    process_name=proc_info.name,
                    details={
                        'cmdline': proc_info.cmdline[:200],
                        'pattern': pattern.pattern
                    }
                )
                alerts.append(alert)
                break  # One alert per process

        # Check for process name masquerading (name doesn't match exe)
        if proc_info.exe and proc_info.name:
            exe_basename = os.path.basename(proc_info.exe).replace('(deleted)', '').strip()
            if exe_basename and proc_info.name != exe_basename:
                # Allow some known cases
                if not any(x in proc_info.exe for x in ['busybox', 'python', 'perl', 'ruby', 'node']):
                    # Check if it's significantly different
                    if exe_basename.lower() not in proc_info.name.lower():
                        alert = ProcessAlert(
                            alert_type=ProcessSecurityAlert.MASQUERADING,
                            severity=ProcessSeverity.MEDIUM,
                            category=ProcessCategory.BEHAVIORAL,
                            timestamp=now,
                            pid=proc_info.pid,
                            process_name=proc_info.name,
                            details={
                                'claimed_name': proc_info.name,
                                'actual_exe': exe_basename
                            }
                        )
                        alerts.append(alert)

        return alerts

    def _check_hidden_processes(
        self,
        proc_processes: Dict[int, ProcessInfo]
    ) -> List[ProcessAlert]:
        """Check for hidden processes using multiple methods"""
        alerts = []
        now = datetime.utcnow()

        try:
            # Method 1: Compare /proc with ps output
            ps_pids = set()
            try:
                result = subprocess.run(
                    ['ps', '-e', '-o', 'pid='],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    for line in result.stdout.decode().strip().split('\n'):
                        line = line.strip()
                        if line.isdigit():
                            ps_pids.add(int(line))
            except Exception:
                pass

            if ps_pids:
                proc_pids = set(proc_processes.keys())

                # Processes in /proc but not in ps (hidden from ps)
                hidden_from_ps = proc_pids - ps_pids
                for pid in hidden_from_ps:
                    if pid > 10:  # Skip very low PIDs (kernel threads)
                        alert = ProcessAlert(
                            alert_type=ProcessSecurityAlert.HIDDEN_PROCESS,
                            severity=ProcessSeverity.CRITICAL,
                            category=ProcessCategory.HIDING,
                            timestamp=now,
                            pid=pid,
                            process_name=proc_processes.get(pid, ProcessInfo(
                                pid=pid, ppid=0, name="unknown", cmdline="",
                                exe="", uid=0, gid=0, state="", start_time=0
                            )).name,
                            details={'detection_method': 'proc_vs_ps'}
                        )
                        alerts.append(alert)

            # Method 2: Check for PID gaps (can indicate rootkit)
            # This is a simple heuristic - large gaps might be suspicious
            if len(proc_processes) > 100:
                pids = sorted(proc_processes.keys())
                for i in range(len(pids) - 1):
                    gap = pids[i + 1] - pids[i]
                    # Very large gap might indicate hidden processes
                    if gap > 1000 and pids[i] > 100:
                        alert = ProcessAlert(
                            alert_type=ProcessSecurityAlert.PID_MISMATCH,
                            severity=ProcessSeverity.LOW,
                            category=ProcessCategory.HIDING,
                            timestamp=now,
                            pid=pids[i],
                            process_name="gap_detected",
                            details={
                                'gap_start': pids[i],
                                'gap_end': pids[i + 1],
                                'gap_size': gap
                            }
                        )
                        alerts.append(alert)
                        break  # Only one gap alert

        except Exception as e:
            print(f"Error checking for hidden processes: {e}")

        return alerts

    def _cleanup_old_data(self):
        """Remove old data outside the history window"""
        cutoff = datetime.utcnow() - timedelta(minutes=self.config.history_window_minutes)

        with self._lock:
            # Clean alerts
            self._alerts = [a for a in self._alerts if a.timestamp > cutoff]

            # Limit alert strings
            if len(self._alert_strings) > 100:
                self._alert_strings = self._alert_strings[-100:]

    def get_status(self) -> ProcessSecurityStatus:
        """Get current monitoring status"""
        with self._lock:
            return ProcessSecurityStatus(
                is_monitoring=self._running,
                total_processes=len(self._known_processes),
                suspicious_processes=len([
                    a for a in self._alerts
                    if a.severity in [ProcessSeverity.HIGH, ProcessSeverity.CRITICAL]
                ]),
                active_alerts=list(self._alerts),
                alerts=list(self._alert_strings),
                last_check=self._last_check
            )

    def get_recent_alerts(self, limit: int = 10) -> List[ProcessAlert]:
        """Get most recent alerts"""
        with self._lock:
            return sorted(
                self._alerts,
                key=lambda a: a.timestamp,
                reverse=True
            )[:limit]

    def clear_alerts(self):
        """Clear all alerts"""
        with self._lock:
            self._alerts.clear()
            self._alert_strings.clear()
