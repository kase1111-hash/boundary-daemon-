"""
Antivirus Scanner - Keylogger and Malware Detection

This module provides a simple antivirus utility focused on detecting:
- Keyloggers (hardware and software-based indicators)
- Screen capture malware
- Clipboard hijackers
- Input hooking malware
- Suspicious process behaviors

This is a defensive security tool for the boundary-daemon project.

Usage:
    scanner = AntivirusScanner()
    results = scanner.full_scan()

    # Or scan specific areas
    process_threats = scanner.scan_processes()
    file_threats = scanner.scan_filesystem(['/usr/bin', '/tmp'])
"""

import os
import re
import hashlib
import logging
import subprocess
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Severity levels for detected threats"""
    INFO = "info"           # Informational, not necessarily malicious
    LOW = "low"             # Low risk, possibly unwanted
    MEDIUM = "medium"       # Medium risk, likely malicious
    HIGH = "high"           # High risk, definitely malicious
    CRITICAL = "critical"   # Critical, active threat


class ThreatCategory(Enum):
    """Categories of detected threats"""
    KEYLOGGER = "keylogger"
    SCREEN_CAPTURE = "screen_capture"
    CLIPBOARD_HIJACKER = "clipboard_hijacker"
    INPUT_HOOK = "input_hook"
    ROOTKIT = "rootkit"
    TROJAN = "trojan"
    SUSPICIOUS_PROCESS = "suspicious_process"
    SUSPICIOUS_FILE = "suspicious_file"
    NETWORK_SNIFFER = "network_sniffer"
    PERSISTENCE_MECHANISM = "persistence_mechanism"
    REMOTE_VIEW = "remote_view"  # Screen sharing / remote desktop


@dataclass
class ThreatIndicator:
    """Represents a potential threat indicator"""
    name: str
    category: ThreatCategory
    level: ThreatLevel
    description: str
    location: str
    evidence: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    remediation: str = ""

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'category': self.category.value,
            'level': self.level.value,
            'description': self.description,
            'location': self.location,
            'evidence': self.evidence,
            'timestamp': self.timestamp,
            'remediation': self.remediation
        }


@dataclass
class ScanResult:
    """Results from a scan operation"""
    scan_type: str
    start_time: str
    end_time: str = ""
    threats_found: List[ThreatIndicator] = field(default_factory=list)
    items_scanned: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def threat_count(self) -> int:
        return len(self.threats_found)

    @property
    def has_critical(self) -> bool:
        return any(t.level == ThreatLevel.CRITICAL for t in self.threats_found)

    @property
    def has_high(self) -> bool:
        return any(t.level == ThreatLevel.HIGH for t in self.threats_found)

    def to_dict(self) -> Dict:
        return {
            'scan_type': self.scan_type,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'threats_found': [t.to_dict() for t in self.threats_found],
            'items_scanned': self.items_scanned,
            'threat_count': self.threat_count,
            'has_critical': self.has_critical,
            'has_high': self.has_high,
            'errors': self.errors
        }


class KeyloggerSignatures:
    """Known keylogger signatures and patterns"""

    # Process names commonly associated with keyloggers
    SUSPICIOUS_PROCESS_NAMES = {
        # Known keylogger names
        'logkeys', 'lkl', 'pykeylogger', 'keylogger',
        'xspy', 'xinput', 'showkey', 'xev',
        # Commercial/known keyloggers
        'spyrix', 'revealer', 'actual-keylogger',
        'ardamax', 'refog', 'spytector',
        # Generic suspicious patterns
        'keylog', 'keycap', 'keygrab', 'inputlog',
        'keystroke', 'klog', 'keysniff'
    }

    # Suspicious file patterns (regex)
    SUSPICIOUS_FILE_PATTERNS = [
        r'.*keylog.*',
        r'.*keystroke.*',
        r'.*keycap.*',
        r'.*\.klog$',
        r'.*inputlog.*',
        r'.*keyboard.*hook.*',
        r'.*xspy.*',
        r'.*logkeys.*',
    ]

    # Directories where keyloggers commonly hide
    SUSPICIOUS_DIRECTORIES = [
        '/tmp/.X11-unix',
        '/dev/shm',
        '/var/tmp',
        '/tmp',
        os.path.expanduser('~/.local/share'),
        os.path.expanduser('~/.config'),
        os.path.expanduser('~/.cache'),
    ]

    # Suspicious libraries loaded by processes
    SUSPICIOUS_LIBRARIES = {
        'libxkbfile', 'libxi', 'libxtst',  # X11 input libraries
        'libevdev', 'libudev',  # Device input libraries
        'pynput', 'keyboard', 'pyhook',  # Python input libraries
    }

    # Known keylogger hashes (SHA256) - examples
    KNOWN_MALWARE_HASHES = {
        # Add known malicious file hashes here
        # These are placeholders for demonstration
        'd41d8cd98f00b204e9800998ecf8427e': 'empty_file_test',
    }

    # Suspicious /proc patterns for keyloggers
    SUSPICIOUS_PROC_PATTERNS = [
        r'/dev/input/event\d+',  # Direct input device access
        r'/dev/uinput',  # User input device
        r'/proc/.*/fd/.*event',  # File descriptors to input events
    ]


class ScreenSharingSignatures:
    """Signatures for detecting screen sharing and remote viewing"""

    # Known screen sharing / remote desktop processes
    SCREEN_SHARING_PROCESSES = {
        # VNC servers
        'x11vnc', 'tigervnc', 'tightvnc', 'realvnc', 'vncserver',
        'Xvnc', 'x0vncserver', 'vino-server', 'krfb', 'vinagre',
        # Remote desktop
        'xrdp', 'xrdp-sesman', 'xfreerdp', 'rdesktop', 'remmina',
        # Commercial remote access
        'teamviewer', 'TeamViewer', 'teamviewerd',
        'anydesk', 'AnyDesk', 'anydesk-service',
        'rustdesk', 'RustDesk',
        'nomachine', 'nxserver', 'nxnode',
        'chrome-remote-desktop', 'chrome_remote_desktop',
        # Screen recording/streaming
        'obs', 'obs-studio', 'ffmpeg',  # Note: ffmpeg can be legitimate
        'simplescreenrecorder', 'kazam', 'peek',
        # Wayland screen sharing
        'xdg-desktop-portal', 'pipewire', 'wireplumber',
        # Other
        'sshd',  # SSH with X forwarding
        'spice-vdagent', 'spice-client',
        'parsec', 'moonlight', 'sunshine',
    }

    # Network ports used by remote desktop/screen sharing
    REMOTE_DESKTOP_PORTS = {
        5900: 'VNC (display :0)',
        5901: 'VNC (display :1)',
        5902: 'VNC (display :2)',
        5903: 'VNC (display :3)',
        5800: 'VNC HTTP',
        3389: 'RDP (Windows Remote Desktop)',
        3350: 'xrdp',
        4000: 'NoMachine',
        5938: 'TeamViewer',
        7070: 'AnyDesk',
        21118: 'RustDesk',
        6568: 'AnyDesk (alt)',
        8080: 'VNC HTTP (alt)',
        22: 'SSH (potential X forwarding)',
    }

    # X11 extensions used for screen capture
    X11_CAPTURE_EXTENSIONS = [
        'MIT-SHM',      # Shared memory - used by screen capture
        'DAMAGE',       # Tracks screen changes - used by VNC
        'XFIXES',       # Screen capture cursors
        'Composite',    # Compositing - can be used for capture
        'RECORD',       # Input recording extension
    ]

    # D-Bus interfaces for screen sharing (GNOME/KDE)
    DBUS_SCREEN_SHARE_INTERFACES = [
        'org.gnome.Mutter.ScreenCast',
        'org.gnome.Mutter.RemoteDesktop',
        'org.freedesktop.portal.ScreenCast',
        'org.freedesktop.portal.RemoteDesktop',
        'org.kde.KWin.ScreenCast',
    ]


class AntivirusScanner:
    """
    Simple antivirus scanner focused on keylogger detection.

    This scanner checks for:
    1. Suspicious processes that may be keyloggers
    2. Known malicious file signatures
    3. Suspicious file locations and names
    4. Process memory patterns
    5. Input device access patterns
    6. Persistence mechanisms
    """

    def __init__(self, event_logger=None):
        """
        Initialize the antivirus scanner.

        Args:
            event_logger: Optional event logger for audit trails
        """
        self.event_logger = event_logger
        self._lock = threading.Lock()
        self._scan_running = False
        self.signatures = KeyloggerSignatures()
        self.screen_sharing_sigs = ScreenSharingSignatures()

    def full_scan(self) -> ScanResult:
        """
        Perform a comprehensive scan for keyloggers and related threats.

        Returns:
            ScanResult with all detected threats
        """
        start_time = datetime.utcnow().isoformat() + "Z"
        result = ScanResult(scan_type="full", start_time=start_time)

        with self._lock:
            if self._scan_running:
                result.errors.append("Scan already in progress")
                return result
            self._scan_running = True

        try:
            logger.info("Starting full antivirus scan")

            # Run all scan types
            process_result = self.scan_processes()
            file_result = self.scan_filesystem()
            input_result = self.scan_input_devices()
            persistence_result = self.scan_persistence_mechanisms()
            screen_result = self.scan_screen_sharing()

            # Aggregate results
            result.threats_found.extend(process_result.threats_found)
            result.threats_found.extend(file_result.threats_found)
            result.threats_found.extend(input_result.threats_found)
            result.threats_found.extend(persistence_result.threats_found)
            result.threats_found.extend(screen_result.threats_found)

            result.items_scanned = (
                process_result.items_scanned +
                file_result.items_scanned +
                input_result.items_scanned +
                persistence_result.items_scanned +
                screen_result.items_scanned
            )

            result.errors.extend(process_result.errors)
            result.errors.extend(file_result.errors)
            result.errors.extend(input_result.errors)
            result.errors.extend(persistence_result.errors)
            result.errors.extend(screen_result.errors)

        except Exception as e:
            logger.error(f"Full scan error: {e}")
            result.errors.append(str(e))
        finally:
            result.end_time = datetime.utcnow().isoformat() + "Z"
            self._scan_running = False

        logger.info(f"Full scan complete: {result.threat_count} threats found")
        return result

    def scan_processes(self) -> ScanResult:
        """
        Scan running processes for keylogger indicators.

        Checks:
        - Process names matching known keyloggers
        - Command lines with suspicious patterns
        - Processes accessing input devices
        - Suspicious library loading

        Returns:
            ScanResult with process-related threats
        """
        start_time = datetime.utcnow().isoformat() + "Z"
        result = ScanResult(scan_type="process", start_time=start_time)

        try:
            processes = self._get_running_processes()
            result.items_scanned = len(processes)

            for proc in processes:
                threats = self._analyze_process(proc)
                result.threats_found.extend(threats)

        except Exception as e:
            logger.error(f"Process scan error: {e}")
            result.errors.append(str(e))
        finally:
            result.end_time = datetime.utcnow().isoformat() + "Z"

        return result

    def scan_filesystem(self, paths: List[str] = None) -> ScanResult:
        """
        Scan filesystem for suspicious files.

        Args:
            paths: List of paths to scan (defaults to suspicious directories)

        Returns:
            ScanResult with file-related threats
        """
        start_time = datetime.utcnow().isoformat() + "Z"
        result = ScanResult(scan_type="filesystem", start_time=start_time)

        if paths is None:
            paths = self.signatures.SUSPICIOUS_DIRECTORIES

        try:
            for path in paths:
                if not os.path.exists(path):
                    continue

                file_threats = self._scan_directory(path, result)
                result.threats_found.extend(file_threats)

        except Exception as e:
            logger.error(f"Filesystem scan error: {e}")
            result.errors.append(str(e))
        finally:
            result.end_time = datetime.utcnow().isoformat() + "Z"

        return result

    def scan_input_devices(self) -> ScanResult:
        """
        Check for suspicious access to input devices.

        Scans:
        - /dev/input/* access patterns
        - Processes with input device file descriptors
        - uinput device usage

        Returns:
            ScanResult with input-related threats
        """
        start_time = datetime.utcnow().isoformat() + "Z"
        result = ScanResult(scan_type="input_devices", start_time=start_time)

        try:
            # Check who has input devices open
            input_threats = self._check_input_device_access()
            result.threats_found.extend(input_threats)
            result.items_scanned = len(input_threats) + 1

            # Check for uinput access
            uinput_threats = self._check_uinput_access()
            result.threats_found.extend(uinput_threats)

        except Exception as e:
            logger.error(f"Input device scan error: {e}")
            result.errors.append(str(e))
        finally:
            result.end_time = datetime.utcnow().isoformat() + "Z"

        return result

    def scan_persistence_mechanisms(self) -> ScanResult:
        """
        Check for keylogger persistence mechanisms.

        Scans:
        - Startup scripts and services
        - Cron jobs
        - X11 session scripts
        - Systemd user services

        Returns:
            ScanResult with persistence-related threats
        """
        start_time = datetime.utcnow().isoformat() + "Z"
        result = ScanResult(scan_type="persistence", start_time=start_time)

        try:
            # Check autostart locations
            persistence_locations = [
                os.path.expanduser('~/.config/autostart'),
                os.path.expanduser('~/.xinitrc'),
                os.path.expanduser('~/.xsession'),
                os.path.expanduser('~/.bashrc'),
                os.path.expanduser('~/.profile'),
                '/etc/xdg/autostart',
                '/etc/init.d',
                '/etc/systemd/system',
            ]

            for loc in persistence_locations:
                threats = self._check_persistence_location(loc)
                result.threats_found.extend(threats)
                result.items_scanned += 1

            # Check crontabs
            cron_threats = self._check_crontabs()
            result.threats_found.extend(cron_threats)

        except Exception as e:
            logger.error(f"Persistence scan error: {e}")
            result.errors.append(str(e))
        finally:
            result.end_time = datetime.utcnow().isoformat() + "Z"

        return result

    def scan_screen_sharing(self) -> ScanResult:
        """
        Detect active screen sharing and remote viewing.

        Checks for:
        - Running screen sharing processes (VNC, RDP, TeamViewer, etc.)
        - Network connections on remote desktop ports
        - X11 screen capture indicators
        - Wayland/D-Bus screen sharing sessions
        - SSH X11 forwarding

        Returns:
            ScanResult with screen sharing indicators
        """
        start_time = datetime.utcnow().isoformat() + "Z"
        result = ScanResult(scan_type="screen_sharing", start_time=start_time)

        try:
            # Check for screen sharing processes
            process_threats = self._check_screen_sharing_processes()
            result.threats_found.extend(process_threats)

            # Check network ports for remote desktop connections
            port_threats = self._check_remote_desktop_ports()
            result.threats_found.extend(port_threats)

            # Check for X11 DAMAGE extension usage (VNC indicator)
            x11_threats = self._check_x11_screen_capture()
            result.threats_found.extend(x11_threats)

            # Check for D-Bus screen sharing sessions
            dbus_threats = self._check_dbus_screen_sharing()
            result.threats_found.extend(dbus_threats)

            # Check for SSH X11 forwarding
            ssh_threats = self._check_ssh_x11_forwarding()
            result.threats_found.extend(ssh_threats)

            result.items_scanned = 5  # Number of check types

        except Exception as e:
            logger.error(f"Screen sharing scan error: {e}")
            result.errors.append(str(e))
        finally:
            result.end_time = datetime.utcnow().isoformat() + "Z"

        return result

    def is_screen_being_shared(self) -> Tuple[bool, List[Dict]]:
        """
        Quick check if screen is currently being shared.

        Returns:
            Tuple of (is_shared: bool, details: List[Dict])
        """
        result = self.scan_screen_sharing()
        is_shared = result.threat_count > 0
        details = [t.to_dict() for t in result.threats_found]
        return (is_shared, details)

    def quick_scan(self) -> ScanResult:
        """
        Perform a quick scan of high-risk areas only.

        Returns:
            ScanResult with detected threats
        """
        start_time = datetime.utcnow().isoformat() + "Z"
        result = ScanResult(scan_type="quick", start_time=start_time)

        try:
            # Quick process check
            processes = self._get_running_processes()
            for proc in processes:
                name = proc.get('name', '').lower()
                if any(sig in name for sig in self.signatures.SUSPICIOUS_PROCESS_NAMES):
                    result.threats_found.append(ThreatIndicator(
                        name=f"Suspicious process: {name}",
                        category=ThreatCategory.KEYLOGGER,
                        level=ThreatLevel.HIGH,
                        description=f"Process matches known keylogger signature",
                        location=f"PID: {proc.get('pid', 'unknown')}",
                        evidence=proc.get('cmdline', ''),
                        remediation="Terminate the process and investigate its origin"
                    ))
            result.items_scanned = len(processes)

            # Quick input device check
            input_threats = self._check_input_device_access()
            result.threats_found.extend(input_threats)

        except Exception as e:
            result.errors.append(str(e))
        finally:
            result.end_time = datetime.utcnow().isoformat() + "Z"

        return result

    # ==================== Internal Methods ====================

    def _get_running_processes(self) -> List[Dict]:
        """Get list of running processes with details"""
        processes = []

        try:
            # Use /proc filesystem for detailed info
            for pid_dir in os.listdir('/proc'):
                if not pid_dir.isdigit():
                    continue

                proc_info = self._get_process_info(pid_dir)
                if proc_info:
                    processes.append(proc_info)

        except Exception as e:
            logger.debug(f"Error reading processes: {e}")

            # Fallback to ps command
            try:
                result = subprocess.run(
                    ['ps', 'aux', '--no-headers'],
                    capture_output=True,
                    timeout=10
                )
                if result.returncode == 0:
                    for line in result.stdout.decode().split('\n'):
                        if line.strip():
                            parts = line.split(None, 10)
                            if len(parts) >= 11:
                                processes.append({
                                    'user': parts[0],
                                    'pid': parts[1],
                                    'name': os.path.basename(parts[10].split()[0]),
                                    'cmdline': parts[10]
                                })
            except Exception:
                pass

        return processes

    def _get_process_info(self, pid: str) -> Optional[Dict]:
        """Get detailed information about a specific process"""
        proc_path = f'/proc/{pid}'

        try:
            # Read command line
            cmdline_path = f'{proc_path}/cmdline'
            cmdline = ""
            if os.path.exists(cmdline_path):
                with open(cmdline_path, 'r') as f:
                    cmdline = f.read().replace('\x00', ' ').strip()

            # Read executable name
            exe_path = f'{proc_path}/exe'
            exe_name = ""
            try:
                exe_name = os.path.basename(os.readlink(exe_path))
            except Exception:
                pass

            # Read file descriptors to check device access
            fds = []
            fd_path = f'{proc_path}/fd'
            if os.path.exists(fd_path):
                try:
                    for fd in os.listdir(fd_path):
                        try:
                            link = os.readlink(f'{fd_path}/{fd}')
                            fds.append(link)
                        except Exception:
                            pass
                except PermissionError:
                    pass

            # Read maps for loaded libraries
            maps = []
            maps_path = f'{proc_path}/maps'
            if os.path.exists(maps_path):
                try:
                    with open(maps_path, 'r') as f:
                        for line in f:
                            if '.so' in line:
                                parts = line.split()
                                if len(parts) >= 6:
                                    maps.append(parts[-1])
                except PermissionError:
                    pass

            return {
                'pid': pid,
                'name': exe_name or os.path.basename(cmdline.split()[0]) if cmdline else '',
                'cmdline': cmdline,
                'exe': exe_name,
                'fds': fds,
                'maps': maps
            }

        except Exception:
            return None

    def _analyze_process(self, proc: Dict) -> List[ThreatIndicator]:
        """Analyze a process for keylogger indicators"""
        threats = []
        name = proc.get('name', '').lower()
        cmdline = proc.get('cmdline', '').lower()
        pid = proc.get('pid', 'unknown')
        fds = proc.get('fds', [])
        maps = proc.get('maps', [])

        # Check process name against known keyloggers
        for sig in self.signatures.SUSPICIOUS_PROCESS_NAMES:
            if sig in name or sig in cmdline:
                threats.append(ThreatIndicator(
                    name=f"Known keylogger process: {sig}",
                    category=ThreatCategory.KEYLOGGER,
                    level=ThreatLevel.HIGH,
                    description=f"Process '{name}' matches known keylogger signature '{sig}'",
                    location=f"PID: {pid}",
                    evidence=cmdline[:200],
                    remediation="Kill the process with 'kill -9 {pid}' and remove the executable"
                ))
                break

        # Check for direct input device access
        for fd in fds:
            if '/dev/input/event' in fd or '/dev/uinput' in fd:
                threats.append(ThreatIndicator(
                    name=f"Input device access: {name}",
                    category=ThreatCategory.INPUT_HOOK,
                    level=ThreatLevel.MEDIUM,
                    description=f"Process has open file descriptor to input device",
                    location=f"PID: {pid}",
                    evidence=fd,
                    remediation="Verify this is a legitimate input handler"
                ))

        # Check for suspicious library loading
        for lib in maps:
            lib_name = os.path.basename(lib).lower()
            for sus_lib in self.signatures.SUSPICIOUS_LIBRARIES:
                if sus_lib in lib_name:
                    # Skip if it's a known legitimate process
                    if name not in ['xorg', 'x11', 'gnome-shell', 'kwin', 'mutter']:
                        threats.append(ThreatIndicator(
                            name=f"Suspicious library: {sus_lib}",
                            category=ThreatCategory.INPUT_HOOK,
                            level=ThreatLevel.LOW,
                            description=f"Process loads input handling library",
                            location=f"PID: {pid}, Library: {lib}",
                            evidence=f"Process '{name}' loaded '{lib_name}'",
                            remediation="Verify the process legitimately needs input access"
                        ))
                    break

        return threats

    def _scan_directory(self, path: str, result: ScanResult) -> List[ThreatIndicator]:
        """Scan a directory for suspicious files"""
        threats = []

        try:
            for root, dirs, files in os.walk(path):
                # Skip if we've scanned too many items
                if result.items_scanned > 100000:
                    break

                for filename in files:
                    result.items_scanned += 1
                    filepath = os.path.join(root, filename)

                    # Check filename patterns
                    for pattern in self.signatures.SUSPICIOUS_FILE_PATTERNS:
                        if re.match(pattern, filename.lower()):
                            threats.append(ThreatIndicator(
                                name=f"Suspicious file: {filename}",
                                category=ThreatCategory.SUSPICIOUS_FILE,
                                level=ThreatLevel.MEDIUM,
                                description=f"Filename matches keylogger pattern",
                                location=filepath,
                                evidence=f"Matched pattern: {pattern}",
                                remediation="Inspect the file contents and remove if malicious"
                            ))
                            break

                    # Check file hashes for known malware (expensive, skip large files)
                    try:
                        file_stat = os.stat(filepath)
                        if file_stat.st_size < 10 * 1024 * 1024:  # < 10MB
                            file_hash = self._get_file_hash(filepath)
                            if file_hash in self.signatures.KNOWN_MALWARE_HASHES:
                                threats.append(ThreatIndicator(
                                    name=f"Known malware: {filename}",
                                    category=ThreatCategory.KEYLOGGER,
                                    level=ThreatLevel.CRITICAL,
                                    description=f"File hash matches known malware",
                                    location=filepath,
                                    evidence=f"SHA256: {file_hash}",
                                    remediation="Delete the file immediately"
                                ))
                    except Exception:
                        pass

        except PermissionError:
            result.errors.append(f"Permission denied: {path}")
        except Exception as e:
            result.errors.append(f"Error scanning {path}: {e}")

        return threats

    def _get_file_hash(self, filepath: str) -> str:
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return ""

    def _check_input_device_access(self) -> List[ThreatIndicator]:
        """Check which processes have input devices open"""
        threats = []

        # Known legitimate processes that access input devices
        legitimate_input_users = {
            'xorg', 'x11', 'wayland', 'libinput', 'mutter',
            'gnome-shell', 'kwin', 'sway', 'systemd',
            'logind', 'acpid', 'inputattach'
        }

        try:
            # Use lsof to find processes with input devices open
            result = subprocess.run(
                ['lsof', '+D', '/dev/input', '-F', 'pcn'],
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0:
                current_pid = None
                current_name = None

                for line in result.stdout.decode().split('\n'):
                    if line.startswith('p'):
                        current_pid = line[1:]
                    elif line.startswith('c'):
                        current_name = line[1:]
                    elif line.startswith('n') and current_name:
                        device = line[1:]

                        # Check if this is a legitimate process
                        if current_name.lower() not in legitimate_input_users:
                            threats.append(ThreatIndicator(
                                name=f"Unauthorized input access: {current_name}",
                                category=ThreatCategory.INPUT_HOOK,
                                level=ThreatLevel.MEDIUM,
                                description=f"Process accessing input device",
                                location=f"PID: {current_pid}, Device: {device}",
                                evidence=f"Process '{current_name}' has {device} open",
                                remediation="Investigate why this process needs input access"
                            ))

        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            # lsof not available, use /proc
            pass
        except Exception as e:
            logger.debug(f"Error checking input access: {e}")

        return threats

    def _check_uinput_access(self) -> List[ThreatIndicator]:
        """Check for uinput device access (virtual input injection)"""
        threats = []

        uinput_path = '/dev/uinput'
        if not os.path.exists(uinput_path):
            return threats

        try:
            result = subprocess.run(
                ['lsof', uinput_path],
                capture_output=True,
                timeout=5
            )

            if result.returncode == 0 and result.stdout:
                # Someone has uinput open - potential for keystroke injection
                threats.append(ThreatIndicator(
                    name="uinput device in use",
                    category=ThreatCategory.INPUT_HOOK,
                    level=ThreatLevel.MEDIUM,
                    description="Process has uinput open (can inject keystrokes)",
                    location=uinput_path,
                    evidence=result.stdout.decode()[:500],
                    remediation="Verify the process is legitimate"
                ))

        except Exception:
            pass

        return threats

    def _check_persistence_location(self, location: str) -> List[ThreatIndicator]:
        """Check a persistence location for suspicious entries"""
        threats = []

        if not os.path.exists(location):
            return threats

        try:
            if os.path.isdir(location):
                for item in os.listdir(location):
                    item_path = os.path.join(location, item)
                    threats.extend(self._check_startup_file(item_path))
            else:
                threats.extend(self._check_startup_file(location))

        except PermissionError:
            pass
        except Exception as e:
            logger.debug(f"Error checking {location}: {e}")

        return threats

    def _check_startup_file(self, filepath: str) -> List[ThreatIndicator]:
        """Check a startup/config file for suspicious content"""
        threats = []

        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read().lower()

            # Check for keylogger-related terms
            suspicious_terms = [
                'keylog', 'logkeys', 'xinput test',
                'xev', 'xspy', 'showkey', '/dev/input',
                'keyboard hook', 'pynput', 'pyhook'
            ]

            for term in suspicious_terms:
                if term in content:
                    threats.append(ThreatIndicator(
                        name=f"Suspicious startup entry",
                        category=ThreatCategory.PERSISTENCE_MECHANISM,
                        level=ThreatLevel.HIGH,
                        description=f"Startup file contains keylogger-related term",
                        location=filepath,
                        evidence=f"Found term: '{term}'",
                        remediation="Remove the suspicious entry from the startup file"
                    ))
                    break

        except Exception:
            pass

        return threats

    def _check_crontabs(self) -> List[ThreatIndicator]:
        """Check crontabs for suspicious entries"""
        threats = []

        crontab_locations = [
            '/etc/crontab',
            '/var/spool/cron',
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
        ]

        for location in crontab_locations:
            if not os.path.exists(location):
                continue

            try:
                if os.path.isdir(location):
                    for item in os.listdir(location):
                        threats.extend(self._check_startup_file(os.path.join(location, item)))
                else:
                    threats.extend(self._check_startup_file(location))
            except PermissionError:
                pass

        return threats

    # ==================== Screen Sharing Detection ====================

    def _check_screen_sharing_processes(self) -> List[ThreatIndicator]:
        """Check for running screen sharing processes"""
        threats = []

        try:
            processes = self._get_running_processes()

            for proc in processes:
                name = proc.get('name', '').lower()
                cmdline = proc.get('cmdline', '').lower()
                pid = proc.get('pid', 'unknown')

                # Check against known screen sharing processes
                for sig in self.screen_sharing_sigs.SCREEN_SHARING_PROCESSES:
                    sig_lower = sig.lower()
                    if sig_lower in name or sig_lower in cmdline:
                        # Determine threat level based on process type
                        level = ThreatLevel.INFO
                        description = "Screen sharing software detected"

                        # Higher concern for remote access tools
                        if any(x in sig_lower for x in ['vnc', 'rdp', 'xrdp', 'teamviewer', 'anydesk', 'rustdesk']):
                            level = ThreatLevel.MEDIUM
                            description = "Remote desktop/viewing software active"

                        threats.append(ThreatIndicator(
                            name=f"Screen sharing: {sig}",
                            category=ThreatCategory.REMOTE_VIEW,
                            level=level,
                            description=description,
                            location=f"PID: {pid}",
                            evidence=cmdline[:200] if cmdline else name,
                            remediation="Verify this is an authorized screen sharing session"
                        ))
                        break

        except Exception as e:
            logger.debug(f"Error checking screen sharing processes: {e}")

        return threats

    def _check_remote_desktop_ports(self) -> List[ThreatIndicator]:
        """Check for listening/connected remote desktop ports"""
        threats = []

        try:
            # Use ss (socket statistics) to check listening ports
            result = subprocess.run(
                ['ss', '-tlnp'],
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0:
                output = result.stdout.decode()

                for port, service in self.screen_sharing_sigs.REMOTE_DESKTOP_PORTS.items():
                    # Skip SSH as it's very common
                    if port == 22:
                        continue

                    port_str = f":{port} "
                    if port_str in output or f":{port}\t" in output:
                        threats.append(ThreatIndicator(
                            name=f"Remote desktop port open: {port}",
                            category=ThreatCategory.REMOTE_VIEW,
                            level=ThreatLevel.MEDIUM,
                            description=f"{service} port is listening",
                            location=f"Port {port}/tcp",
                            evidence=f"Service: {service}",
                            remediation="Verify this remote access service is authorized"
                        ))

            # Check for established connections on these ports
            result = subprocess.run(
                ['ss', '-tnp', 'state', 'established'],
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0:
                output = result.stdout.decode()

                for port, service in self.screen_sharing_sigs.REMOTE_DESKTOP_PORTS.items():
                    if port == 22:
                        continue

                    if f":{port} " in output or f":{port}\t" in output:
                        threats.append(ThreatIndicator(
                            name=f"Active remote connection on port {port}",
                            category=ThreatCategory.REMOTE_VIEW,
                            level=ThreatLevel.HIGH,
                            description=f"Active {service} connection detected",
                            location=f"Port {port}/tcp",
                            evidence=f"Established connection to {service}",
                            remediation="Verify this is an authorized remote session"
                        ))

        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            # ss not available, try netstat
            try:
                result = subprocess.run(
                    ['netstat', '-tlnp'],
                    capture_output=True,
                    timeout=10
                )
                if result.returncode == 0:
                    output = result.stdout.decode()
                    for port, service in self.screen_sharing_sigs.REMOTE_DESKTOP_PORTS.items():
                        if port == 22:
                            continue
                        if f":{port} " in output:
                            threats.append(ThreatIndicator(
                                name=f"Remote desktop port open: {port}",
                                category=ThreatCategory.REMOTE_VIEW,
                                level=ThreatLevel.MEDIUM,
                                description=f"{service} port is listening",
                                location=f"Port {port}/tcp",
                                evidence=f"Service: {service}",
                                remediation="Verify this remote access service is authorized"
                            ))
            except Exception:
                pass
        except Exception as e:
            logger.debug(f"Error checking remote desktop ports: {e}")

        return threats

    def _check_x11_screen_capture(self) -> List[ThreatIndicator]:
        """Check for X11 screen capture indicators"""
        threats = []

        # Check if DISPLAY is set (X11 is in use)
        display = os.environ.get('DISPLAY')
        if not display:
            return threats

        try:
            # Check for processes using DAMAGE extension (used by VNC)
            # The DAMAGE extension is used to track screen changes
            result = subprocess.run(
                ['xdpyinfo', '-display', display],
                capture_output=True,
                timeout=5,
                env={**os.environ, 'DISPLAY': display}
            )

            if result.returncode == 0:
                output = result.stdout.decode()

                # Check if RECORD extension is active (can record input)
                if 'RECORD' in output:
                    # Check who is using it
                    record_result = subprocess.run(
                        ['xlsclients', '-l'],
                        capture_output=True,
                        timeout=5,
                        env={**os.environ, 'DISPLAY': display}
                    )

                    if record_result.returncode == 0:
                        clients = record_result.stdout.decode()
                        # Look for VNC or screen capture clients
                        for sig in ['vnc', 'x11vnc', 'vino', 'screencap', 'record']:
                            if sig in clients.lower():
                                threats.append(ThreatIndicator(
                                    name=f"X11 screen capture client detected",
                                    category=ThreatCategory.REMOTE_VIEW,
                                    level=ThreatLevel.MEDIUM,
                                    description="X11 client using screen capture capabilities",
                                    location=f"DISPLAY={display}",
                                    evidence=f"Client matching '{sig}' found",
                                    remediation="Investigate the X11 client"
                                ))

        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            # xdpyinfo not available
            pass
        except Exception as e:
            logger.debug(f"Error checking X11 screen capture: {e}")

        return threats

    def _check_dbus_screen_sharing(self) -> List[ThreatIndicator]:
        """Check for D-Bus screen sharing sessions (GNOME/KDE)"""
        threats = []

        try:
            # Check for active portal screen cast sessions
            result = subprocess.run(
                ['busctl', 'tree', 'org.freedesktop.portal.Desktop'],
                capture_output=True,
                timeout=5
            )

            if result.returncode == 0:
                output = result.stdout.decode()

                # Look for active ScreenCast sessions
                if '/org/freedesktop/portal/desktop/session/' in output:
                    threats.append(ThreatIndicator(
                        name="Active portal screen sharing session",
                        category=ThreatCategory.REMOTE_VIEW,
                        level=ThreatLevel.MEDIUM,
                        description="XDG Desktop Portal has active screen sharing session",
                        location="org.freedesktop.portal.Desktop",
                        evidence="Active session found in D-Bus",
                        remediation="Check which application requested screen sharing"
                    ))

            # Check GNOME Mutter ScreenCast
            result = subprocess.run(
                ['busctl', 'introspect', 'org.gnome.Mutter.ScreenCast',
                 '/org/gnome/Mutter/ScreenCast'],
                capture_output=True,
                timeout=5
            )

            if result.returncode == 0:
                # The service exists and is running
                # Check for active sessions
                session_result = subprocess.run(
                    ['busctl', 'tree', 'org.gnome.Mutter.ScreenCast'],
                    capture_output=True,
                    timeout=5
                )

                if session_result.returncode == 0:
                    session_output = session_result.stdout.decode()
                    if '/org/gnome/Mutter/ScreenCast/Session/' in session_output:
                        threats.append(ThreatIndicator(
                            name="GNOME screen cast session active",
                            category=ThreatCategory.REMOTE_VIEW,
                            level=ThreatLevel.MEDIUM,
                            description="GNOME Mutter has active screen cast session",
                            location="org.gnome.Mutter.ScreenCast",
                            evidence="Active session in Mutter ScreenCast",
                            remediation="Check GNOME screen sharing settings"
                        ))

        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            # busctl not available
            pass
        except Exception as e:
            logger.debug(f"Error checking D-Bus screen sharing: {e}")

        return threats

    def _check_ssh_x11_forwarding(self) -> List[ThreatIndicator]:
        """Check for SSH X11 forwarding"""
        threats = []

        try:
            # Check for SSH connections with X11 forwarding
            # This is indicated by DISPLAY being set to localhost:10.0 or similar
            display = os.environ.get('DISPLAY', '')

            if display.startswith('localhost:') or display.startswith(':10'):
                # Likely X11 forwarding
                threats.append(ThreatIndicator(
                    name="SSH X11 forwarding detected",
                    category=ThreatCategory.REMOTE_VIEW,
                    level=ThreatLevel.INFO,
                    description="Display suggests SSH X11 forwarding is active",
                    location=f"DISPLAY={display}",
                    evidence="Display variable indicates remote X11",
                    remediation="Verify SSH X11 forwarding is authorized"
                ))

            # Check for sshd processes with X11 forwarding
            result = subprocess.run(
                ['pgrep', '-a', 'sshd'],
                capture_output=True,
                timeout=5
            )

            if result.returncode == 0:
                output = result.stdout.decode()
                # Check if any SSH session has X11 socket
                for line in output.split('\n'):
                    if 'sshd:' in line and '@' in line:
                        # Active SSH session
                        pid = line.split()[0]
                        # Check if this session has X11 forwarding
                        try:
                            fd_path = f'/proc/{pid}/fd'
                            if os.path.exists(fd_path):
                                for fd in os.listdir(fd_path):
                                    try:
                                        link = os.readlink(f'{fd_path}/{fd}')
                                        if 'X11-unix' in link or ':6010' in link:
                                            threats.append(ThreatIndicator(
                                                name="SSH session with X11 forwarding",
                                                category=ThreatCategory.REMOTE_VIEW,
                                                level=ThreatLevel.INFO,
                                                description="SSH session has X11 forwarding enabled",
                                                location=f"SSHD PID: {pid}",
                                                evidence=line.strip()[:100],
                                                remediation="Verify SSH X11 forwarding is authorized"
                                            ))
                                            break
                                    except Exception:
                                        pass
                        except PermissionError:
                            pass

        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.debug(f"Error checking SSH X11 forwarding: {e}")

        return threats

    def get_status(self) -> Dict:
        """Get scanner status"""
        return {
            'scan_running': self._scan_running,
            'signatures_loaded': len(self.signatures.SUSPICIOUS_PROCESS_NAMES),
            'file_patterns': len(self.signatures.SUSPICIOUS_FILE_PATTERNS),
            'monitored_dirs': len(self.signatures.SUSPICIOUS_DIRECTORIES),
            'screen_sharing_sigs': len(self.screen_sharing_sigs.SCREEN_SHARING_PROCESSES)
        }


class RealTimeMonitor:
    """
    Real-time monitoring for keylogger activity.

    Watches for:
    - New processes matching keylogger signatures
    - Changes to input device access
    - New files in suspicious locations
    """

    def __init__(self, scanner: AntivirusScanner, callback=None):
        """
        Initialize real-time monitor.

        Args:
            scanner: AntivirusScanner instance to use
            callback: Function to call when threats detected
        """
        self.scanner = scanner
        self.callback = callback
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._known_processes: Set[str] = set()
        self._check_interval = 5.0  # seconds

    def start(self):
        """Start real-time monitoring"""
        if self._running:
            return

        self._running = True

        # Get baseline of running processes
        procs = self.scanner._get_running_processes()
        self._known_processes = {p.get('pid', '') for p in procs}

        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="AV-RealTimeMonitor"
        )
        self._thread.start()
        logger.info("Real-time antivirus monitor started")

    def stop(self):
        """Stop real-time monitoring"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        logger.info("Real-time antivirus monitor stopped")

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                # Check for new processes
                current_procs = self.scanner._get_running_processes()
                current_pids = {p.get('pid', '') for p in current_procs}

                # Find new processes
                new_pids = current_pids - self._known_processes

                for proc in current_procs:
                    if proc.get('pid', '') in new_pids:
                        threats = self.scanner._analyze_process(proc)
                        if threats and self.callback:
                            self.callback(threats)

                self._known_processes = current_pids

            except Exception as e:
                logger.debug(f"Monitor loop error: {e}")

            # Wait for next check
            for _ in range(int(self._check_interval * 10)):
                if not self._running:
                    break
                threading.Event().wait(0.1)

    @property
    def is_running(self) -> bool:
        return self._running


# CLI interface for standalone usage
if __name__ == '__main__':
    import argparse
    import json as json_module

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description='Keylogger and Malware Scanner')
    parser.add_argument('--full', action='store_true', help='Run full scan')
    parser.add_argument('--quick', action='store_true', help='Run quick scan')
    parser.add_argument('--processes', action='store_true', help='Scan processes only')
    parser.add_argument('--files', action='store_true', help='Scan filesystem only')
    parser.add_argument('--input', action='store_true', help='Check input devices')
    parser.add_argument('--persistence', action='store_true', help='Check persistence mechanisms')
    parser.add_argument('--screen', action='store_true', help='Check for screen sharing/remote viewing')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--paths', nargs='+', help='Specific paths to scan')

    args = parser.parse_args()

    scanner = AntivirusScanner()
    result = None

    if args.full:
        print("Running full scan...")
        result = scanner.full_scan()
    elif args.quick:
        print("Running quick scan...")
        result = scanner.quick_scan()
    elif args.processes:
        print("Scanning processes...")
        result = scanner.scan_processes()
    elif args.files:
        print("Scanning filesystem...")
        result = scanner.scan_filesystem(args.paths)
    elif args.input:
        print("Checking input devices...")
        result = scanner.scan_input_devices()
    elif args.persistence:
        print("Checking persistence mechanisms...")
        result = scanner.scan_persistence_mechanisms()
    elif args.screen:
        print("Checking for screen sharing/remote viewing...")
        result = scanner.scan_screen_sharing()
    else:
        print("Running quick scan (default)...")
        result = scanner.quick_scan()

    if result:
        if args.json:
            print(json_module.dumps(result.to_dict(), indent=2))
        else:
            print(f"\n{'='*60}")
            print(f"Scan Type: {result.scan_type}")
            print(f"Items Scanned: {result.items_scanned}")
            print(f"Threats Found: {result.threat_count}")
            print(f"Has Critical: {result.has_critical}")
            print(f"Has High: {result.has_high}")
            print(f"{'='*60}")

            if result.threats_found:
                print("\nTHREATS DETECTED:")
                for threat in result.threats_found:
                    print(f"\n[{threat.level.value.upper()}] {threat.name}")
                    print(f"  Category: {threat.category.value}")
                    print(f"  Location: {threat.location}")
                    print(f"  Description: {threat.description}")
                    if threat.evidence:
                        print(f"  Evidence: {threat.evidence[:100]}")
                    if threat.remediation:
                        print(f"  Remediation: {threat.remediation}")
            else:
                print("\n✓ No threats detected")

            if result.errors:
                print(f"\nErrors during scan:")
                for err in result.errors:
                    print(f"  - {err}")
