"""
Antivirus Scanner - Keylogger and Malware Detection AND REMOVAL

This module provides a simple antivirus utility focused on detecting AND REMOVING:
- Keyloggers (hardware and software-based indicators) -> KILLED/QUARANTINED
- Screen capture malware -> KILLED/BLOCKED
- Clipboard hijackers -> KILLED/QUARANTINED
- Input hooking malware -> KILLED/BLOCKED
- Suspicious process behaviors -> KILLED/NETWORK BLOCKED

NEW ENFORCEMENT FEATURES:
- Process termination (kill suspicious processes)
- File quarantine (move malicious files to quarantine)
- Network blocking (block C2 connections via iptables)
- Persistence removal (disable malicious startup entries)

SECURITY: This module now provides ACTUAL ENFORCEMENT, not just detection.
Addresses Critical Finding: "Detection Without Enforcement"

SECURITY: MalwareBazaar API calls are blocked in AIRGAP/COLDROOM/LOCKDOWN modes
to prevent hash exfiltration to external services.
Addresses Critical Finding: "AIRGAP Mode Leaks Network Traffic"

Usage:
    scanner = AntivirusScanner()
    results = scanner.full_scan()

    # Scan and auto-remediate
    results = scanner.full_scan(auto_remediate=True)

    # Manual enforcement
    scanner.kill_process(pid=1234, reason="Keylogger detected")
    scanner.quarantine_file("/path/to/malware")
"""

import os
import sys
import re
import hashlib
import hmac
import logging
import shutil
import signal
import subprocess
import threading
import base64
import json
import time
import urllib.request
import urllib.parse
import urllib.error
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Callable
from datetime import datetime
from collections import deque

logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = sys.platform == 'win32'


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
    # Network monitoring categories
    REMOTE_SHELL = "remote_shell"  # SSH, telnet, reverse shells
    FILE_TRANSFER = "file_transfer"  # FTP, SMB, rsync
    C2_CHANNEL = "c2_channel"  # Command & control
    DATA_EXFIL = "data_exfiltration"  # Data exfiltration
    REVERSE_SHELL = "reverse_shell"  # Reverse shell connections
    TUNNELING = "tunneling"  # Network tunneling


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


class NetworkMonitoringSignatures:
    """Signatures for network connection monitoring"""

    # Ports to monitor for remote access
    MONITORED_PORTS = {
        # SSH
        22: {'name': 'SSH', 'category': 'remote_shell', 'level': 'info'},
        2222: {'name': 'SSH (alt)', 'category': 'remote_shell', 'level': 'medium'},
        # FTP
        21: {'name': 'FTP Control', 'category': 'file_transfer', 'level': 'medium'},
        20: {'name': 'FTP Data', 'category': 'file_transfer', 'level': 'medium'},
        990: {'name': 'FTPS', 'category': 'file_transfer', 'level': 'info'},
        # Telnet (insecure)
        23: {'name': 'Telnet', 'category': 'remote_shell', 'level': 'high'},
        # Remote shells
        4444: {'name': 'Metasploit default', 'category': 'reverse_shell', 'level': 'critical'},
        5555: {'name': 'Common backdoor', 'category': 'reverse_shell', 'level': 'critical'},
        6666: {'name': 'Common backdoor', 'category': 'reverse_shell', 'level': 'critical'},
        6667: {'name': 'IRC (C2 channel)', 'category': 'c2', 'level': 'high'},
        1337: {'name': 'Leet backdoor', 'category': 'reverse_shell', 'level': 'critical'},
        31337: {'name': 'Elite backdoor', 'category': 'reverse_shell', 'level': 'critical'},
        # File sharing
        139: {'name': 'NetBIOS/SMB', 'category': 'file_transfer', 'level': 'medium'},
        445: {'name': 'SMB', 'category': 'file_transfer', 'level': 'medium'},
        873: {'name': 'rsync', 'category': 'file_transfer', 'level': 'info'},
        # Remote admin
        3389: {'name': 'RDP', 'category': 'remote_desktop', 'level': 'medium'},
        5985: {'name': 'WinRM HTTP', 'category': 'remote_admin', 'level': 'high'},
        5986: {'name': 'WinRM HTTPS', 'category': 'remote_admin', 'level': 'medium'},
        # Database (potential data exfil)
        3306: {'name': 'MySQL', 'category': 'database', 'level': 'info'},
        5432: {'name': 'PostgreSQL', 'category': 'database', 'level': 'info'},
        27017: {'name': 'MongoDB', 'category': 'database', 'level': 'info'},
        6379: {'name': 'Redis', 'category': 'database', 'level': 'info'},
        # Web (potential C2)
        8080: {'name': 'HTTP Proxy', 'category': 'proxy', 'level': 'info'},
        8443: {'name': 'HTTPS Alt', 'category': 'web', 'level': 'info'},
        9001: {'name': 'Tor/Common C2', 'category': 'c2', 'level': 'high'},
        9050: {'name': 'Tor SOCKS', 'category': 'anonymizer', 'level': 'high'},
        9051: {'name': 'Tor Control', 'category': 'anonymizer', 'level': 'high'},
    }

    # Suspicious process names for network activity
    SUSPICIOUS_NETWORK_PROCESSES = {
        # Reverse shells
        'nc', 'netcat', 'ncat', 'socat',
        'cryptcat', 'powercat',
        # Network recon
        'nmap', 'masscan', 'zmap',
        # Tunneling
        'chisel', 'ligolo', 'ngrok', 'frp', 'frpc', 'frps',
        'cloudflared', 'bore',
        # Proxy tools
        'proxychains', 'redsocks', 'torsocks',
        # Data exfil
        'rclone', 'restic', 'duplicity',
        # Remote access
        'meterpreter', 'beacon', 'cobaltstrike',
        'empire', 'sliver',
    }

    # Known C2 framework indicators in process names
    C2_INDICATORS = {
        'meterpreter', 'beacon', 'cobaltstrike', 'cobalt',
        'empire', 'sliver', 'mythic', 'havoc',
        'bruteratel', 'nighthawk', 'poshc2',
    }

    # Suspicious outbound ports (data exfiltration risk)
    EXFIL_RISK_PORTS = {
        53: 'DNS (tunneling risk)',
        443: 'HTTPS (encrypted exfil)',
        80: 'HTTP (unencrypted exfil)',
        8080: 'HTTP Proxy',
        8443: 'HTTPS Alt',
    }


@dataclass
class MalwareBazaarResult:
    """Result from MalwareBazaar API query"""
    is_malware: bool
    sha256_hash: str
    file_type: str = ""
    file_name: str = ""
    signature: str = ""  # Malware family/signature name
    tags: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    intelligence: Dict = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> Dict:
        return {
            'is_malware': self.is_malware,
            'sha256_hash': self.sha256_hash,
            'file_type': self.file_type,
            'file_name': self.file_name,
            'signature': self.signature,
            'tags': self.tags,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'intelligence': self.intelligence,
            'error': self.error
        }


class MalwareBazaarClient:
    """
    Client for querying the MalwareBazaar API (abuse.ch).

    MalwareBazaar is a public malware sample repository that provides
    hash lookups to identify known malware samples.

    API Documentation: https://bazaar.abuse.ch/api/

    SECURITY: API calls are blocked in AIRGAP/COLDROOM/LOCKDOWN modes
    to prevent hash exfiltration.
    """

    API_URL = "https://mb-api.abuse.ch/api/v1/"
    TIMEOUT = 10  # seconds

    # Modes that block all external network access
    NETWORK_BLOCKED_MODES = {'AIRGAP', 'COLDROOM', 'LOCKDOWN'}

    def __init__(
        self,
        cache_ttl: int = 3600,
        max_cache_size: int = 10000,
        mode_getter: Optional[Callable[[], str]] = None,
    ):
        """
        Initialize the MalwareBazaar client.

        Args:
            cache_ttl: Time-to-live for cache entries in seconds (default 1 hour)
            max_cache_size: Maximum number of entries to cache
            mode_getter: Callback to get current boundary mode (e.g., 'AIRGAP')
        """
        self._cache: Dict[str, Tuple[MalwareBazaarResult, float]] = {}
        self._cache_ttl = cache_ttl
        self._max_cache_size = max_cache_size
        self._cache_lock = threading.Lock()
        self._enabled = True
        self._last_error: Optional[str] = None

        # SECURITY: Mode getter for network isolation enforcement
        self._get_mode = mode_getter

        # Track blocked API calls for security auditing (bounded to prevent memory leak)
        self._blocked_api_calls: deque = deque(maxlen=500)

    def set_mode_getter(self, getter: Callable[[], str]):
        """Set the mode getter callback."""
        self._get_mode = getter

    def _is_network_blocked(self) -> bool:
        """
        Check if external network access is blocked in current mode.

        Returns:
            True if network access should be blocked (AIRGAP, COLDROOM, LOCKDOWN)
        """
        if not self._get_mode:
            return False  # No mode getter, assume network allowed

        try:
            current_mode = self._get_mode()
            if current_mode and current_mode.upper() in self.NETWORK_BLOCKED_MODES:
                return True
        except Exception:
            pass

        return False

    def _log_blocked_api_call(self, target: str, reason: str):
        """Log a blocked API call for security auditing."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'api': 'MalwareBazaar',
            'target': target,
            'reason': reason,
            'mode': self._get_mode() if self._get_mode else 'unknown',
        }
        self._blocked_api_calls.append(entry)
        logging.warning(f"SECURITY: Blocked MalwareBazaar API call for {target}: {reason}")

    def get_blocked_api_calls(self) -> List[Dict]:
        """Get list of API calls blocked due to network isolation."""
        return list(self._blocked_api_calls)

    def set_enabled(self, enabled: bool):
        """Enable or disable API lookups"""
        self._enabled = enabled

    def is_enabled(self) -> bool:
        """Check if API lookups are enabled"""
        return self._enabled

    def get_last_error(self) -> Optional[str]:
        """Get the last error message, if any"""
        return self._last_error

    def _clean_cache(self):
        """Remove expired cache entries"""
        current_time = time.time()
        with self._cache_lock:
            expired = [
                h for h, (_, ts) in self._cache.items()
                if current_time - ts > self._cache_ttl
            ]
            for h in expired:
                del self._cache[h]

            # If still too large, remove oldest entries
            if len(self._cache) > self._max_cache_size:
                sorted_entries = sorted(
                    self._cache.items(),
                    key=lambda x: x[1][1]
                )
                for h, _ in sorted_entries[:len(self._cache) - self._max_cache_size]:
                    del self._cache[h]

    def _get_cached(self, sha256_hash: str) -> Optional[MalwareBazaarResult]:
        """Get cached result if available and not expired"""
        with self._cache_lock:
            if sha256_hash in self._cache:
                result, timestamp = self._cache[sha256_hash]
                if time.time() - timestamp < self._cache_ttl:
                    return result
                else:
                    del self._cache[sha256_hash]
        return None

    def _set_cached(self, sha256_hash: str, result: MalwareBazaarResult):
        """Cache a result"""
        with self._cache_lock:
            self._cache[sha256_hash] = (result, time.time())

        # Periodic cleanup
        if len(self._cache) > self._max_cache_size:
            self._clean_cache()

    def query_hash(self, sha256_hash: str) -> MalwareBazaarResult:
        """
        Query MalwareBazaar for a SHA256 hash.

        SECURITY: This method is blocked in AIRGAP/COLDROOM/LOCKDOWN modes
        to prevent hash exfiltration to external services.

        Args:
            sha256_hash: The SHA256 hash to look up

        Returns:
            MalwareBazaarResult with malware information if found
        """
        # Validate hash format
        if not sha256_hash or len(sha256_hash) != 64:
            return MalwareBazaarResult(
                is_malware=False,
                sha256_hash=sha256_hash,
                error="Invalid SHA256 hash format"
            )

        # SECURITY: Block external API calls in network-isolated modes
        if self._is_network_blocked():
            self._log_blocked_api_call(
                sha256_hash[:16] + "...",
                'Network blocked in current security mode'
            )
            return MalwareBazaarResult(
                is_malware=False,
                sha256_hash=sha256_hash,
                error="API blocked: Network isolated mode active"
            )

        # Check if disabled
        if not self._enabled:
            return MalwareBazaarResult(
                is_malware=False,
                sha256_hash=sha256_hash,
                error="MalwareBazaar lookups disabled"
            )

        # Check cache first
        cached = self._get_cached(sha256_hash)
        if cached is not None:
            return cached

        # Query the API
        try:
            data = urllib.parse.urlencode({
                'query': 'get_info',
                'hash': sha256_hash
            }).encode('utf-8')

            request = urllib.request.Request(
                self.API_URL,
                data=data,
                headers={
                    'User-Agent': 'BoundaryDaemon-Antivirus/1.0',
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            )

            with urllib.request.urlopen(request, timeout=self.TIMEOUT) as response:
                response_data = json.loads(response.read().decode('utf-8'))

            # Parse response
            if response_data.get('query_status') == 'hash_not_found':
                result = MalwareBazaarResult(
                    is_malware=False,
                    sha256_hash=sha256_hash
                )
            elif response_data.get('query_status') == 'ok':
                # Hash found - it's known malware
                sample_data = response_data.get('data', [{}])[0]
                result = MalwareBazaarResult(
                    is_malware=True,
                    sha256_hash=sha256_hash,
                    file_type=sample_data.get('file_type', ''),
                    file_name=sample_data.get('file_name', ''),
                    signature=sample_data.get('signature', 'Unknown'),
                    tags=sample_data.get('tags', []),
                    first_seen=sample_data.get('first_seen', ''),
                    last_seen=sample_data.get('last_seen', ''),
                    intelligence={
                        'reporter': sample_data.get('reporter', ''),
                        'delivery_method': sample_data.get('delivery_method', ''),
                        'intelligence': sample_data.get('intelligence', {})
                    }
                )
            else:
                # Unexpected response
                error_msg = response_data.get('query_status', 'Unknown error')
                self._last_error = error_msg
                result = MalwareBazaarResult(
                    is_malware=False,
                    sha256_hash=sha256_hash,
                    error=f"API error: {error_msg}"
                )

            # Cache the result
            self._set_cached(sha256_hash, result)
            self._last_error = None
            return result

        except urllib.error.URLError as e:
            self._last_error = f"Network error: {e}"
            return MalwareBazaarResult(
                is_malware=False,
                sha256_hash=sha256_hash,
                error=f"Network error: {e}"
            )
        except json.JSONDecodeError as e:
            self._last_error = f"Invalid JSON response: {e}"
            return MalwareBazaarResult(
                is_malware=False,
                sha256_hash=sha256_hash,
                error=f"Invalid response: {e}"
            )
        except Exception as e:
            self._last_error = f"Unexpected error: {e}"
            return MalwareBazaarResult(
                is_malware=False,
                sha256_hash=sha256_hash,
                error=f"Error: {e}"
            )

    def query_hash_batch(self, hashes: List[str]) -> Dict[str, MalwareBazaarResult]:
        """
        Query multiple hashes (with rate limiting).

        Note: MalwareBazaar doesn't have a batch API, so this queries
        hashes one at a time with a small delay to avoid rate limiting.

        Args:
            hashes: List of SHA256 hashes to query

        Returns:
            Dict mapping hash to MalwareBazaarResult
        """
        results = {}
        for i, h in enumerate(hashes):
            results[h] = self.query_hash(h)
            # Small delay to avoid rate limiting (except for last item)
            if i < len(hashes) - 1:
                time.sleep(0.1)
        return results

    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        with self._cache_lock:
            return {
                'cached_entries': len(self._cache),
                'max_size': self._max_cache_size,
                'ttl_seconds': self._cache_ttl
            }

    def clear_cache(self):
        """Clear the cache"""
        with self._cache_lock:
            self._cache.clear()


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

    def __init__(self, event_logger=None, enable_malwarebazaar: bool = True):
        """
        Initialize the antivirus scanner.

        Args:
            event_logger: Optional event logger for audit trails
            enable_malwarebazaar: Enable MalwareBazaar API lookups (default True)
        """
        self.event_logger = event_logger
        self._lock = threading.Lock()
        self._scan_running = False
        self.signatures = KeyloggerSignatures()
        self.screen_sharing_sigs = ScreenSharingSignatures()
        self.network_sigs = NetworkMonitoringSignatures()
        self.malware_bazaar = MalwareBazaarClient()
        self.malware_bazaar.set_enabled(enable_malwarebazaar)

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
            network_result = self.scan_network_connections()

            # Aggregate results
            result.threats_found.extend(process_result.threats_found)
            result.threats_found.extend(file_result.threats_found)
            result.threats_found.extend(input_result.threats_found)
            result.threats_found.extend(persistence_result.threats_found)
            result.threats_found.extend(screen_result.threats_found)
            result.threats_found.extend(network_result.threats_found)

            result.items_scanned = (
                process_result.items_scanned +
                file_result.items_scanned +
                input_result.items_scanned +
                persistence_result.items_scanned +
                screen_result.items_scanned +
                network_result.items_scanned
            )

            result.errors.extend(process_result.errors)
            result.errors.extend(file_result.errors)
            result.errors.extend(input_result.errors)
            result.errors.extend(persistence_result.errors)
            result.errors.extend(screen_result.errors)
            result.errors.extend(network_result.errors)

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

    def scan_filesystem(self, paths: Optional[List[str]] = None) -> ScanResult:
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

        if IS_WINDOWS:
            # Windows: Use psutil for process enumeration
            try:
                import psutil
                for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'exe']):
                    try:
                        info = proc.info
                        cmdline = ' '.join(info.get('cmdline') or [])
                        processes.append({
                            'user': info.get('username', ''),
                            'pid': str(info.get('pid', '')),
                            'name': info.get('name', ''),
                            'cmdline': cmdline,
                            'exe': info.get('exe', '')
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except ImportError:
                logger.debug("psutil not available for process enumeration")
            return processes

        # Linux: Use /proc filesystem for detailed info
        try:
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
        # Windows: Use psutil for process info
        if IS_WINDOWS:
            try:
                import psutil
                proc = psutil.Process(int(pid))
                cmdline = ' '.join(proc.cmdline())
                return {
                    'pid': pid,
                    'name': proc.name(),
                    'cmdline': cmdline,
                    'exe': proc.exe() if proc.exe() else '',
                    'fds': [],  # Not available on Windows
                    'maps': []  # Not available on Windows
                }
            except Exception:
                return None

        # Linux: Use /proc filesystem
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

                            # First check local signature database
                            if file_hash in self.signatures.KNOWN_MALWARE_HASHES:
                                threats.append(ThreatIndicator(
                                    name=f"Known malware: {filename}",
                                    category=ThreatCategory.KEYLOGGER,
                                    level=ThreatLevel.CRITICAL,
                                    description=f"File hash matches known malware (local DB)",
                                    location=filepath,
                                    evidence=f"SHA256: {file_hash}",
                                    remediation="Delete the file immediately"
                                ))
                            # Then query MalwareBazaar for unknown hashes
                            elif file_hash and self.malware_bazaar.is_enabled():
                                bazaar_result = self.malware_bazaar.query_hash(file_hash)
                                if bazaar_result.is_malware:
                                    # Determine threat category from tags
                                    category = ThreatCategory.SUSPICIOUS_FILE
                                    tags_lower = [t.lower() for t in bazaar_result.tags]
                                    if any(t in tags_lower for t in ['keylogger', 'spyware']):
                                        category = ThreatCategory.KEYLOGGER
                                    elif any(t in tags_lower for t in ['trojan', 'rat']):
                                        category = ThreatCategory.TROJAN
                                    elif any(t in tags_lower for t in ['rootkit']):
                                        category = ThreatCategory.ROOTKIT

                                    threats.append(ThreatIndicator(
                                        name=f"MalwareBazaar match: {bazaar_result.signature or filename}",
                                        category=category,
                                        level=ThreatLevel.CRITICAL,
                                        description=f"File identified as malware by MalwareBazaar: {bazaar_result.signature}",
                                        location=filepath,
                                        evidence=f"SHA256: {file_hash}, Tags: {', '.join(bazaar_result.tags)}, First seen: {bazaar_result.first_seen}",
                                        remediation="Delete the file immediately - confirmed malware sample"
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

    def check_hash(self, sha256_hash: str) -> MalwareBazaarResult:
        """
        Manually check a SHA256 hash against MalwareBazaar.

        Args:
            sha256_hash: The SHA256 hash to check

        Returns:
            MalwareBazaarResult with malware information
        """
        return self.malware_bazaar.query_hash(sha256_hash)

    def check_file(self, filepath: str) -> Tuple[str, MalwareBazaarResult]:
        """
        Calculate hash and check a file against MalwareBazaar.

        Args:
            filepath: Path to the file to check

        Returns:
            Tuple of (sha256_hash, MalwareBazaarResult)
        """
        file_hash = self._get_file_hash(filepath)
        if not file_hash:
            return ("", MalwareBazaarResult(
                is_malware=False,
                sha256_hash="",
                error=f"Could not calculate hash for {filepath}"
            ))
        return (file_hash, self.malware_bazaar.query_hash(file_hash))

    def get_malwarebazaar_status(self) -> Dict:
        """
        Get MalwareBazaar client status and cache statistics.

        Returns:
            Dict with enabled status, last error, and cache stats
        """
        return {
            'enabled': self.malware_bazaar.is_enabled(),
            'last_error': self.malware_bazaar.get_last_error(),
            'cache': self.malware_bazaar.get_cache_stats()
        }

    def set_malwarebazaar_enabled(self, enabled: bool):
        """Enable or disable MalwareBazaar lookups"""
        self.malware_bazaar.set_enabled(enabled)

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

    # ==================== Network Connection Monitoring ====================

    def scan_network_connections(self) -> ScanResult:
        """
        Monitor active network connections for suspicious activity.

        Checks for:
        - SSH connections (incoming and outgoing)
        - FTP connections
        - Telnet connections (insecure)
        - Reverse shell indicators
        - C2 channel indicators
        - Suspicious tunneling
        - Data exfiltration patterns

        Returns:
            ScanResult with network-related threats
        """
        start_time = datetime.utcnow().isoformat() + "Z"
        result = ScanResult(scan_type="network_connections", start_time=start_time)

        try:
            # Check listening ports
            listen_threats = self._check_listening_ports()
            result.threats_found.extend(listen_threats)

            # Check established connections
            conn_threats = self._check_established_connections()
            result.threats_found.extend(conn_threats)

            # Check for suspicious network processes
            proc_threats = self._check_network_processes()
            result.threats_found.extend(proc_threats)

            # Check for reverse shell indicators
            shell_threats = self._check_reverse_shells()
            result.threats_found.extend(shell_threats)

            # Check for tunneling tools
            tunnel_threats = self._check_tunneling()
            result.threats_found.extend(tunnel_threats)

            result.items_scanned = 5  # Number of check types

        except Exception as e:
            logger.error(f"Network scan error: {e}")
            result.errors.append(str(e))
        finally:
            result.end_time = datetime.utcnow().isoformat() + "Z"

        return result

    def get_active_connections(self) -> Dict:
        """
        Get a summary of all active network connections.

        Returns:
            Dict with connection summaries by category
        """
        connections = {
            'ssh': [],
            'ftp': [],
            'remote_desktop': [],
            'suspicious': [],
            'other': []
        }

        try:
            result = subprocess.run(
                ['ss', '-tunap'],
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0:
                for line in result.stdout.decode().split('\n')[1:]:  # Skip header
                    if not line.strip():
                        continue

                    parts = line.split()
                    if len(parts) < 5:
                        continue

                    proto = parts[0]
                    state = parts[1] if len(parts) > 1 else ''
                    local = parts[4] if len(parts) > 4 else ''
                    remote = parts[5] if len(parts) > 5 else ''
                    process = parts[-1] if len(parts) > 6 else ''

                    # Extract port from local address
                    local_port = 0
                    if ':' in local:
                        try:
                            local_port = int(local.rsplit(':', 1)[1])
                        except ValueError:
                            pass

                    conn_info = {
                        'protocol': proto,
                        'state': state,
                        'local': local,
                        'remote': remote,
                        'process': process
                    }

                    # Categorize
                    if local_port == 22 or ':22' in remote:
                        connections['ssh'].append(conn_info)
                    elif local_port in [20, 21] or any(f':{p}' in remote for p in [20, 21]):
                        connections['ftp'].append(conn_info)
                    elif local_port in [3389, 5900, 5901]:
                        connections['remote_desktop'].append(conn_info)
                    elif local_port in [4444, 5555, 6666, 1337, 31337]:
                        connections['suspicious'].append(conn_info)
                    else:
                        connections['other'].append(conn_info)

        except Exception as e:
            logger.debug(f"Error getting connections: {e}")

        return connections

    def _check_listening_ports(self) -> List[ThreatIndicator]:
        """Check for suspicious listening ports"""
        threats = []

        try:
            result = subprocess.run(
                ['ss', '-tlnp'],
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0:
                output = result.stdout.decode()

                for port, info in self.network_sigs.MONITORED_PORTS.items():
                    port_patterns = [f':{port} ', f':{port}\t', f':{port}\n']
                    if any(p in output for p in port_patterns):
                        level = getattr(ThreatLevel, info['level'].upper(), ThreatLevel.INFO)

                        # Determine category
                        cat_map = {
                            'remote_shell': ThreatCategory.REMOTE_SHELL,
                            'file_transfer': ThreatCategory.FILE_TRANSFER,
                            'reverse_shell': ThreatCategory.REVERSE_SHELL,
                            'c2': ThreatCategory.C2_CHANNEL,
                            'database': ThreatCategory.DATA_EXFIL,
                            'remote_desktop': ThreatCategory.REMOTE_VIEW,
                            'remote_admin': ThreatCategory.REMOTE_SHELL,
                            'anonymizer': ThreatCategory.TUNNELING,
                            'proxy': ThreatCategory.TUNNELING,
                            'web': ThreatCategory.SUSPICIOUS_PROCESS,
                        }
                        category = cat_map.get(info['category'], ThreatCategory.SUSPICIOUS_PROCESS)

                        threats.append(ThreatIndicator(
                            name=f"Listening: {info['name']} (port {port})",
                            category=category,
                            level=level,
                            description=f"{info['name']} service is listening",
                            location=f"Port {port}/tcp",
                            evidence=f"Category: {info['category']}",
                            remediation="Verify this service is authorized"
                        ))

        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"Error checking listening ports: {e}")

        return threats

    def _check_established_connections(self) -> List[ThreatIndicator]:
        """Check for suspicious established connections"""
        threats = []

        try:
            result = subprocess.run(
                ['ss', '-tnp', 'state', 'established'],
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0:
                for line in result.stdout.decode().split('\n'):
                    if not line.strip() or line.startswith('Recv-Q'):
                        continue

                    parts = line.split()
                    if len(parts) < 5:
                        continue

                    local = parts[3] if len(parts) > 3 else ''
                    remote = parts[4] if len(parts) > 4 else ''
                    process = parts[-1] if 'users:' in line else ''

                    # Check remote port
                    remote_port = 0
                    if ':' in remote:
                        try:
                            remote_port = int(remote.rsplit(':', 1)[1])
                        except ValueError:
                            pass

                    # Check local port
                    local_port = 0
                    if ':' in local:
                        try:
                            local_port = int(local.rsplit(':', 1)[1])
                        except ValueError:
                            pass

                    # Check for suspicious ports
                    for port, info in self.network_sigs.MONITORED_PORTS.items():
                        if port in [local_port, remote_port]:
                            level = getattr(ThreatLevel, info['level'].upper(), ThreatLevel.INFO)

                            # Skip SSH inbound unless high level
                            if port == 22 and info['level'] == 'info':
                                # Only report outbound SSH or if it's on a non-standard port
                                if local_port == 22:
                                    continue  # Normal incoming SSH

                            cat_map = {
                                'remote_shell': ThreatCategory.REMOTE_SHELL,
                                'file_transfer': ThreatCategory.FILE_TRANSFER,
                                'reverse_shell': ThreatCategory.REVERSE_SHELL,
                                'c2': ThreatCategory.C2_CHANNEL,
                            }
                            category = cat_map.get(info['category'], ThreatCategory.SUSPICIOUS_PROCESS)

                            direction = "outbound" if remote_port == port else "inbound"
                            threats.append(ThreatIndicator(
                                name=f"Active {info['name']} connection ({direction})",
                                category=category,
                                level=level,
                                description=f"Established {info['name']} connection",
                                location=f"{local} -> {remote}",
                                evidence=process[:100] if process else f"Port {port}",
                                remediation="Verify this connection is authorized"
                            ))
                            break

        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.debug(f"Error checking established connections: {e}")

        return threats

    def _check_network_processes(self) -> List[ThreatIndicator]:
        """Check for suspicious network-related processes"""
        threats = []

        try:
            processes = self._get_running_processes()

            for proc in processes:
                name = proc.get('name', '').lower()
                cmdline = proc.get('cmdline', '').lower()
                pid = proc.get('pid', 'unknown')

                # Check for suspicious network processes
                for sig in self.network_sigs.SUSPICIOUS_NETWORK_PROCESSES:
                    if sig in name or f'/{sig}' in cmdline or f' {sig} ' in cmdline:
                        # Determine threat level based on process type
                        level = ThreatLevel.MEDIUM
                        category = ThreatCategory.SUSPICIOUS_PROCESS

                        if sig in ['nc', 'netcat', 'ncat', 'socat']:
                            level = ThreatLevel.HIGH
                            category = ThreatCategory.REVERSE_SHELL
                        elif sig in self.network_sigs.C2_INDICATORS:
                            level = ThreatLevel.CRITICAL
                            category = ThreatCategory.C2_CHANNEL
                        elif sig in ['chisel', 'ligolo', 'ngrok', 'frp', 'frpc', 'frps']:
                            level = ThreatLevel.HIGH
                            category = ThreatCategory.TUNNELING
                        elif sig in ['nmap', 'masscan', 'zmap']:
                            level = ThreatLevel.MEDIUM
                            category = ThreatCategory.NETWORK_SNIFFER

                        threats.append(ThreatIndicator(
                            name=f"Suspicious network process: {sig}",
                            category=category,
                            level=level,
                            description=f"Process '{name}' matches suspicious network tool",
                            location=f"PID: {pid}",
                            evidence=cmdline[:200] if cmdline else name,
                            remediation="Investigate why this network tool is running"
                        ))
                        break

        except Exception as e:
            logger.debug(f"Error checking network processes: {e}")

        return threats

    def _check_reverse_shells(self) -> List[ThreatIndicator]:
        """Check for reverse shell indicators"""
        threats = []

        try:
            # Check for common reverse shell patterns in processes
            result = subprocess.run(
                ['ps', 'auxww'],
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0:
                output = result.stdout.decode().lower()

                # Common reverse shell patterns
                shell_patterns = [
                    ('bash -i', 'Bash interactive reverse shell'),
                    ('bash -c.*>/dev/tcp', 'Bash /dev/tcp reverse shell'),
                    ('sh -i', 'Shell interactive mode'),
                    ('python.*socket.*connect', 'Python socket connection'),
                    ('python.*pty.spawn', 'Python PTY spawn'),
                    ('perl.*socket', 'Perl socket'),
                    ('ruby.*socket', 'Ruby socket'),
                    ('nc -e', 'Netcat with -e (execute)'),
                    ('nc.*-c', 'Netcat with -c'),
                    ('ncat.*--exec', 'Ncat with exec'),
                    ('socat.*exec', 'Socat with exec'),
                    ('mkfifo', 'Named pipe (potential shell)'),
                    ('msfvenom', 'Metasploit payload generator'),
                    ('meterpreter', 'Meterpreter session'),
                ]

                for pattern, description in shell_patterns:
                    if pattern in output:
                        threats.append(ThreatIndicator(
                            name=f"Reverse shell indicator: {pattern}",
                            category=ThreatCategory.REVERSE_SHELL,
                            level=ThreatLevel.CRITICAL,
                            description=description,
                            location="Process list",
                            evidence=f"Pattern '{pattern}' found in running processes",
                            remediation="Immediately investigate and terminate suspicious processes"
                        ))

            # Check for processes with network connections and shell
            result = subprocess.run(
                ['ss', '-tnp'],
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0:
                output = result.stdout.decode().lower()
                shell_processes = ['bash', 'sh', 'zsh', 'fish', 'dash']

                for shell in shell_processes:
                    if f'"{shell}"' in output or f"({shell})" in output:
                        # Shell with network connection is suspicious
                        threats.append(ThreatIndicator(
                            name=f"Shell with network connection: {shell}",
                            category=ThreatCategory.REVERSE_SHELL,
                            level=ThreatLevel.HIGH,
                            description=f"Shell process has network connection",
                            location="Network connections",
                            evidence=f"Shell '{shell}' has active network socket",
                            remediation="Verify this is not a reverse shell"
                        ))

        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.debug(f"Error checking reverse shells: {e}")

        return threats

    def _check_tunneling(self) -> List[ThreatIndicator]:
        """Check for network tunneling tools"""
        threats = []

        try:
            # Check for SSH tunnels
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0:
                output = result.stdout.decode()

                # SSH tunnel patterns
                tunnel_patterns = [
                    ('ssh.*-L', 'SSH local port forward', ThreatLevel.INFO),
                    ('ssh.*-R', 'SSH remote port forward', ThreatLevel.MEDIUM),
                    ('ssh.*-D', 'SSH dynamic (SOCKS) tunnel', ThreatLevel.MEDIUM),
                    ('ssh.*-w', 'SSH tunnel interface', ThreatLevel.HIGH),
                    ('autossh', 'Persistent SSH tunnel', ThreatLevel.MEDIUM),
                    ('sshuttle', 'SSH-based VPN', ThreatLevel.MEDIUM),
                ]

                for pattern, description, level in tunnel_patterns:
                    # Use simple string matching
                    pattern_parts = pattern.replace('.*', ' ').split()
                    lines = output.split('\n')
                    for line in lines:
                        if all(p in line for p in pattern_parts):
                            threats.append(ThreatIndicator(
                                name=f"Tunnel: {description}",
                                category=ThreatCategory.TUNNELING,
                                level=level,
                                description=description,
                                location="Process list",
                                evidence=line.strip()[:150],
                                remediation="Verify this tunnel is authorized"
                            ))
                            break

            # Check for VPN processes
            vpn_processes = ['openvpn', 'wireguard', 'wg', 'wg-quick', 'tailscale']
            processes = self._get_running_processes()

            for proc in processes:
                name = proc.get('name', '').lower()
                if name in vpn_processes:
                    threats.append(ThreatIndicator(
                        name=f"VPN: {name}",
                        category=ThreatCategory.TUNNELING,
                        level=ThreatLevel.INFO,
                        description=f"VPN software detected",
                        location=f"PID: {proc.get('pid', 'unknown')}",
                        evidence=proc.get('cmdline', name)[:100],
                        remediation="Verify VPN usage is authorized"
                    ))

        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.debug(f"Error checking tunneling: {e}")

        return threats

    def get_ssh_sessions(self) -> List[Dict]:
        """Get active SSH sessions (both incoming and outgoing)"""
        sessions = []

        try:
            # Check for SSH client connections (outgoing)
            result = subprocess.run(
                ['pgrep', '-a', 'ssh'],
                capture_output=True,
                timeout=5
            )

            if result.returncode == 0:
                for line in result.stdout.decode().split('\n'):
                    if line.strip() and 'sshd' not in line:
                        parts = line.split(None, 1)
                        if len(parts) >= 2:
                            sessions.append({
                                'type': 'outgoing',
                                'pid': parts[0],
                                'command': parts[1],
                            })

            # Check for sshd sessions (incoming)
            result = subprocess.run(
                ['who'],
                capture_output=True,
                timeout=5
            )

            if result.returncode == 0:
                for line in result.stdout.decode().split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            sessions.append({
                                'type': 'incoming',
                                'user': parts[0],
                                'terminal': parts[1],
                                'time': ' '.join(parts[2:4]) if len(parts) > 3 else parts[2],
                                'from': parts[4].strip('()') if len(parts) > 4 else 'local'
                            })

        except Exception as e:
            logger.debug(f"Error getting SSH sessions: {e}")

        return sessions

    def get_ftp_connections(self) -> List[Dict]:
        """Get active FTP connections"""
        connections = []

        try:
            # Check for FTP connections on ports 20, 21
            result = subprocess.run(
                ['ss', '-tnp', 'sport', '=', ':21', 'or', 'sport', '=', ':20',
                 'or', 'dport', '=', ':21', 'or', 'dport', '=', ':20'],
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0:
                for line in result.stdout.decode().split('\n')[1:]:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 5:
                            connections.append({
                                'state': parts[0],
                                'local': parts[3],
                                'remote': parts[4],
                                'process': parts[-1] if 'users:' in line else ''
                            })

            # Also check for FTP client processes
            ftp_clients = ['ftp', 'sftp', 'lftp', 'ncftp', 'curl', 'wget']
            processes = self._get_running_processes()

            for proc in processes:
                name = proc.get('name', '').lower()
                cmdline = proc.get('cmdline', '').lower()
                if name in ftp_clients or any(f'{c} ftp' in cmdline for c in ftp_clients):
                    if 'ftp' in cmdline or name in ['ftp', 'sftp', 'lftp', 'ncftp']:
                        connections.append({
                            'type': 'client',
                            'process': name,
                            'pid': proc.get('pid'),
                            'command': proc.get('cmdline', '')[:100]
                        })

        except Exception as e:
            logger.debug(f"Error getting FTP connections: {e}")

        return connections

    # ==================== ENFORCEMENT METHODS (NEW) ====================

    # Quarantine directory
    QUARANTINE_DIR = "/var/lib/boundary-daemon/quarantine"
    IPTABLES_CHAIN = "BOUNDARY_AV_BLOCK"

    def kill_process(self, pid: int, reason: str = "") -> Tuple[bool, str]:
        """
        Kill a malicious process.

        Args:
            pid: Process ID to kill
            reason: Reason for killing (for logging)

        Returns:
            (success, message)
        """
        try:
            if IS_WINDOWS:
                # Windows: Use psutil for process management
                try:
                    import psutil
                    proc = psutil.Process(pid)
                    proc_info = f"{proc.name()}: {' '.join(proc.cmdline())[:200]}"
                    proc.terminate()
                    try:
                        proc.wait(timeout=1)
                    except psutil.TimeoutExpired:
                        proc.kill()
                except psutil.NoSuchProcess:
                    return (False, f"Process {pid} does not exist")
                except psutil.AccessDenied:
                    return (False, f"Access denied to kill process {pid}")
                except Exception as e:
                    return (False, f"Failed to kill process {pid}: {e}")
            else:
                # Linux: Verify process exists
                if not os.path.exists(f"/proc/{pid}"):
                    return (False, f"Process {pid} does not exist")

                # Get process info before killing
                proc_info = ""
                try:
                    with open(f"/proc/{pid}/comm", 'r') as f:
                        proc_name = f.read().strip()
                    with open(f"/proc/{pid}/cmdline", 'r') as f:
                        proc_cmdline = f.read().replace('\x00', ' ').strip()[:200]
                    proc_info = f"{proc_name}: {proc_cmdline}"
                except Exception:
                    proc_info = f"PID {pid}"

                # First try SIGTERM
                os.kill(pid, signal.SIGTERM)

                # Wait a moment for graceful shutdown
                time.sleep(0.5)

                # Check if still running
                if os.path.exists(f"/proc/{pid}"):
                    # Force kill with SIGKILL
                    os.kill(pid, signal.SIGKILL)
                    time.sleep(0.2)

                # Verify killed
                if os.path.exists(f"/proc/{pid}"):
                    return (False, f"Failed to kill process {pid}")

            # Log the kill
            self._log_enforcement_action("process_killed", {
                'pid': pid,
                'process': proc_info,
                'reason': reason
            })

            logger.warning(f"KILLED malicious process: {proc_info} (PID {pid}) - {reason}")
            return (True, f"Killed process {pid}: {proc_info}")

        except PermissionError:
            return (False, f"Permission denied to kill process {pid}. Need root.")
        except ProcessLookupError:
            return (True, f"Process {pid} already terminated")
        except Exception as e:
            logger.error(f"Error killing process {pid}: {e}")
            return (False, str(e))

    def quarantine_file(self, file_path: str, reason: str = "") -> Tuple[bool, str]:
        """
        Move a malicious file to quarantine.

        Args:
            file_path: Path to file to quarantine
            reason: Reason for quarantine (for logging)

        Returns:
            (success, message)
        """
        try:
            if not os.path.exists(file_path):
                return (False, f"File does not exist: {file_path}")

            # Create quarantine directory if needed
            os.makedirs(self.QUARANTINE_DIR, mode=0o700, exist_ok=True)

            # Generate quarantine filename
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            original_name = os.path.basename(file_path)
            quarantine_name = f"{timestamp}_{original_name}"
            quarantine_path = os.path.join(self.QUARANTINE_DIR, quarantine_name)

            # Get file info
            file_stat = os.stat(file_path)
            file_hash = ""
            try:
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
            except Exception:
                pass

            # Save metadata
            metadata = {
                'original_path': file_path,
                'quarantine_time': datetime.utcnow().isoformat() + "Z",
                'reason': reason,
                'size': file_stat.st_size,
                'mode': oct(file_stat.st_mode),
                'sha256': file_hash,
            }
            metadata_path = quarantine_path + ".meta.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            os.chmod(metadata_path, 0o600)

            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            os.chmod(quarantine_path, 0o000)  # Remove all permissions

            # Log the quarantine
            self._log_enforcement_action("file_quarantined", {
                'original_path': file_path,
                'quarantine_path': quarantine_path,
                'sha256': file_hash,
                'reason': reason
            })

            logger.warning(f"QUARANTINED: {file_path} -> {quarantine_path} - {reason}")
            return (True, f"Quarantined {file_path} to {quarantine_path}")

        except PermissionError:
            return (False, f"Permission denied to quarantine {file_path}. Need root.")
        except Exception as e:
            logger.error(f"Error quarantining file {file_path}: {e}")
            return (False, str(e))

    def restore_from_quarantine(self, quarantine_name: str) -> Tuple[bool, str]:
        """
        Restore a file from quarantine.

        Args:
            quarantine_name: Name of file in quarantine directory

        Returns:
            (success, message)
        """
        try:
            quarantine_path = os.path.join(self.QUARANTINE_DIR, quarantine_name)
            metadata_path = quarantine_path + ".meta.json"

            if not os.path.exists(quarantine_path):
                return (False, f"Quarantine file not found: {quarantine_name}")

            if not os.path.exists(metadata_path):
                return (False, f"Metadata not found for: {quarantine_name}")

            # Read metadata
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)

            original_path = metadata.get('original_path')
            if not original_path:
                return (False, "Original path not found in metadata")

            # Restore file
            os.chmod(quarantine_path, 0o644)  # Restore basic permissions
            shutil.move(quarantine_path, original_path)
            os.remove(metadata_path)

            logger.info(f"RESTORED from quarantine: {quarantine_name} -> {original_path}")
            return (True, f"Restored {quarantine_name} to {original_path}")

        except Exception as e:
            logger.error(f"Error restoring from quarantine: {e}")
            return (False, str(e))

    def block_network_connection(self, ip: str, port: Optional[int] = None,
                                 reason: str = "") -> Tuple[bool, str]:
        """
        Block a network connection using iptables.

        Args:
            ip: IP address to block
            port: Optional port to block (blocks all if not specified)
            reason: Reason for blocking

        Returns:
            (success, message)
        """
        # Check for root/admin privileges (cross-platform)
        if IS_WINDOWS:
            # Windows doesn't use iptables
            return (False, "iptables not available on Windows")

        if os.geteuid() != 0:
            return (False, "Need root for iptables rules")

        if not shutil.which('iptables'):
            return (False, "iptables not available")

        try:
            # Ensure our chain exists
            subprocess.run(
                ['iptables', '-N', self.IPTABLES_CHAIN],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ['iptables', '-C', 'OUTPUT', '-j', self.IPTABLES_CHAIN],
                capture_output=True, timeout=5
            )
            result = subprocess.run(
                ['iptables', '-C', 'OUTPUT', '-j', self.IPTABLES_CHAIN],
                capture_output=True, timeout=5
            )
            if result.returncode != 0:
                subprocess.run(
                    ['iptables', '-I', 'OUTPUT', '1', '-j', self.IPTABLES_CHAIN],
                    capture_output=True, timeout=5
                )

            # Build block rule
            cmd = ['iptables', '-A', self.IPTABLES_CHAIN, '-d', ip]
            if port:
                cmd.extend(['-p', 'tcp', '--dport', str(port)])
            cmd.extend(['-j', 'DROP', '-m', 'comment', '--comment',
                       f'boundary-av-block-{ip}'])

            result = subprocess.run(cmd, capture_output=True, timeout=5)
            if result.returncode != 0:
                return (False, f"iptables error: {result.stderr.decode()}")

            # Log the block
            self._log_enforcement_action("network_blocked", {
                'ip': ip,
                'port': port,
                'reason': reason
            })

            logger.warning(f"BLOCKED network: {ip}:{port or '*'} - {reason}")
            return (True, f"Blocked connections to {ip}:{port or '*'}")

        except Exception as e:
            logger.error(f"Error blocking network connection: {e}")
            return (False, str(e))

    def disable_persistence(self, location: str, reason: str = "") -> Tuple[bool, str]:
        """
        Disable a malicious persistence mechanism.

        Args:
            location: Path to persistence mechanism (startup script, service, etc.)
            reason: Reason for disabling

        Returns:
            (success, message)
        """
        try:
            if not os.path.exists(location):
                return (False, f"Persistence location not found: {location}")

            # Determine type and disable appropriately
            if location.endswith('.service') and '/systemd/' in location:
                # Systemd service - disable it
                service_name = os.path.basename(location)
                subprocess.run(['systemctl', 'stop', service_name],
                              capture_output=True, timeout=10)
                subprocess.run(['systemctl', 'disable', service_name],
                              capture_output=True, timeout=10)
                # Quarantine the service file
                self.quarantine_file(location, reason)
                logger.warning(f"DISABLED systemd service: {service_name}")

            elif '/cron' in location or location.endswith('crontab'):
                # Cron job - quarantine
                self.quarantine_file(location, reason)
                logger.warning(f"REMOVED cron job: {location}")

            elif '/autostart' in location or location.endswith('.desktop'):
                # Desktop autostart - quarantine
                self.quarantine_file(location, reason)
                logger.warning(f"REMOVED autostart entry: {location}")

            elif '.bashrc' in location or '.profile' in location or '.bash_profile' in location:
                # Shell startup - backup and remove malicious lines
                # For safety, just quarantine the whole file
                # User will need to recreate it
                backup_path = location + ".boundary-backup"
                shutil.copy2(location, backup_path)
                logger.warning(f"BACKED UP and needs review: {location}")
                return (True, f"Backed up {location}. Manual review required.")

            else:
                # Generic - quarantine
                self.quarantine_file(location, reason)

            self._log_enforcement_action("persistence_disabled", {
                'location': location,
                'reason': reason
            })

            return (True, f"Disabled persistence mechanism: {location}")

        except PermissionError:
            return (False, f"Permission denied. Need root.")
        except Exception as e:
            logger.error(f"Error disabling persistence: {e}")
            return (False, str(e))

    def remediate_threat(self, threat: ThreatIndicator) -> Tuple[bool, str]:
        """
        Automatically remediate a detected threat.

        Args:
            threat: ThreatIndicator to remediate

        Returns:
            (success, message)
        """
        location = threat.location
        category = threat.category

        # Handle based on category
        if category in (ThreatCategory.KEYLOGGER, ThreatCategory.SCREEN_CAPTURE,
                       ThreatCategory.CLIPBOARD_HIJACKER, ThreatCategory.INPUT_HOOK,
                       ThreatCategory.SUSPICIOUS_PROCESS):
            # Try to extract PID from location or evidence
            pid = self._extract_pid(threat)
            if pid:
                return self.kill_process(pid, threat.description)
            else:
                return (False, "Could not extract PID from threat info")

        elif category == ThreatCategory.SUSPICIOUS_FILE:
            if os.path.isfile(location):
                return self.quarantine_file(location, threat.description)
            else:
                return (False, f"File not found: {location}")

        elif category == ThreatCategory.PERSISTENCE_MECHANISM:
            return self.disable_persistence(location, threat.description)

        elif category in (ThreatCategory.C2_CHANNEL, ThreatCategory.REVERSE_SHELL,
                         ThreatCategory.DATA_EXFIL):
            # Block network connection
            ip, port = self._extract_connection_info(threat)
            if ip:
                return self.block_network_connection(ip, port, threat.description)
            else:
                return (False, "Could not extract connection info from threat")

        elif category == ThreatCategory.REMOTE_SHELL:
            pid = self._extract_pid(threat)
            if pid:
                return self.kill_process(pid, threat.description)
            return (False, "Could not extract PID")

        else:
            return (False, f"No remediation available for category: {category.value}")

    def _extract_pid(self, threat: ThreatIndicator) -> Optional[int]:
        """Extract PID from threat info."""
        # Try location first (might be like "process:1234")
        if threat.location.startswith("process:"):
            try:
                return int(threat.location.split(":")[1])
            except (ValueError, IndexError):
                pass

        # Try evidence
        import re
        pid_match = re.search(r'\bpid[:\s]*(\d+)', threat.evidence, re.I)
        if pid_match:
            return int(pid_match.group(1))

        pid_match = re.search(r'\bPID[:\s]*(\d+)', threat.description, re.I)
        if pid_match:
            return int(pid_match.group(1))

        return None

    def _extract_connection_info(self, threat: ThreatIndicator) -> Tuple[Optional[str], Optional[int]]:
        """Extract IP and port from threat info."""
        import re

        # Try to find IP:port pattern
        ip_port_match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', threat.location)
        if ip_port_match:
            return ip_port_match.group(1), int(ip_port_match.group(2))

        ip_port_match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', threat.evidence)
        if ip_port_match:
            return ip_port_match.group(1), int(ip_port_match.group(2))

        # Try just IP
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', threat.location)
        if ip_match:
            return ip_match.group(1), None

        return None, None

    def remediate_all_threats(self, scan_result: ScanResult,
                             min_level: ThreatLevel = ThreatLevel.HIGH) -> Dict:
        """
        Remediate all threats from a scan result.

        Args:
            scan_result: ScanResult containing threats
            min_level: Minimum threat level to remediate

        Returns:
            Dict with remediation results
        """
        results = {
            'remediated': [],
            'failed': [],
            'skipped': []
        }

        level_order = [ThreatLevel.INFO, ThreatLevel.LOW, ThreatLevel.MEDIUM,
                      ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        min_index = level_order.index(min_level)

        for threat in scan_result.threats_found:
            threat_index = level_order.index(threat.level)

            if threat_index < min_index:
                results['skipped'].append({
                    'threat': threat.name,
                    'level': threat.level.value,
                    'reason': 'Below minimum level'
                })
                continue

            success, msg = self.remediate_threat(threat)
            if success:
                results['remediated'].append({
                    'threat': threat.name,
                    'location': threat.location,
                    'message': msg
                })
            else:
                results['failed'].append({
                    'threat': threat.name,
                    'location': threat.location,
                    'error': msg
                })

        logger.info(f"Remediation complete: {len(results['remediated'])} remediated, "
                   f"{len(results['failed'])} failed, {len(results['skipped'])} skipped")
        return results

    def get_quarantine_list(self) -> List[Dict]:
        """Get list of quarantined files."""
        quarantined = []

        if not os.path.exists(self.QUARANTINE_DIR):
            return quarantined

        for filename in os.listdir(self.QUARANTINE_DIR):
            if filename.endswith('.meta.json'):
                continue

            metadata_path = os.path.join(self.QUARANTINE_DIR, filename + ".meta.json")
            entry = {'name': filename}

            if os.path.exists(metadata_path):
                try:
                    with open(metadata_path, 'r') as f:
                        entry.update(json.load(f))
                except Exception:
                    pass

            quarantined.append(entry)

        return quarantined

    def cleanup_quarantine(self, days_old: int = 30) -> int:
        """
        Remove quarantined files older than specified days.

        Args:
            days_old: Remove files older than this many days

        Returns:
            Number of files removed
        """
        removed = 0
        cutoff = datetime.utcnow().timestamp() - (days_old * 86400)

        if not os.path.exists(self.QUARANTINE_DIR):
            return 0

        for filename in os.listdir(self.QUARANTINE_DIR):
            filepath = os.path.join(self.QUARANTINE_DIR, filename)
            try:
                if os.path.getmtime(filepath) < cutoff:
                    os.remove(filepath)
                    removed += 1
            except Exception:
                pass

        logger.info(f"Quarantine cleanup: removed {removed} files older than {days_old} days")
        return removed

    def _log_enforcement_action(self, action: str, details: Dict):
        """Log an enforcement action."""
        if self.event_logger:
            try:
                from ..event_logger import EventType
                self.event_logger.log_event(
                    event_type=EventType.VIOLATION,
                    data={
                        'event': f'antivirus_{action}',
                        'details': details,
                        'timestamp': datetime.utcnow().isoformat() + "Z"
                    }
                )
            except Exception:
                pass

    # ==================== END ENFORCEMENT METHODS ====================

    def get_status(self) -> Dict:
        """Get scanner status"""
        quarantine_count = 0
        if os.path.exists(self.QUARANTINE_DIR):
            quarantine_count = len([f for f in os.listdir(self.QUARANTINE_DIR)
                                   if not f.endswith('.meta.json')])

        return {
            'scan_running': self._scan_running,
            'signatures_loaded': len(self.signatures.SUSPICIOUS_PROCESS_NAMES),
            'file_patterns': len(self.signatures.SUSPICIOUS_FILE_PATTERNS),
            'monitored_dirs': len(self.signatures.SUSPICIOUS_DIRECTORIES),
            'screen_sharing_sigs': len(self.screen_sharing_sigs.SCREEN_SHARING_PROCESSES),
            'network_ports_monitored': len(self.network_sigs.MONITORED_PORTS),
            'network_process_sigs': len(self.network_sigs.SUSPICIOUS_NETWORK_PROCESSES),
            # Enforcement status
            'quarantine_dir': self.QUARANTINE_DIR,
            'quarantined_files': quarantine_count,
            'enforcement_available': self._has_admin_privileges(),
        }

    def _has_admin_privileges(self) -> bool:
        """Check if running with admin/root privileges (cross-platform)."""
        if IS_WINDOWS:
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0


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


class StartupMonitor:
    """
    Monitors startup programs and alerts on new additions.

    Features:
    - Scans all startup locations (autostart, systemd, cron, etc.)
    - Maintains an encrypted persistent list of known programs
    - Checks hourly for newly added programs
    - Provides friendly (non-scary) notifications

    The goal is to catch unwanted programs that add themselves to startup
    while reassuring users when they see programs they may have forgotten
    they installed.
    """

    # Default locations to monitor for startup programs
    STARTUP_LOCATIONS = {
        'user_autostart': os.path.expanduser('~/.config/autostart'),
        'system_autostart': '/etc/xdg/autostart',
        'xinitrc': os.path.expanduser('~/.xinitrc'),
        'xprofile': os.path.expanduser('~/.xprofile'),
        'xsession': os.path.expanduser('~/.xsession'),
        'bashrc': os.path.expanduser('~/.bashrc'),
        'bash_profile': os.path.expanduser('~/.bash_profile'),
        'profile': os.path.expanduser('~/.profile'),
        'zshrc': os.path.expanduser('~/.zshrc'),
        'user_systemd': os.path.expanduser('~/.config/systemd/user'),
        'system_systemd': '/etc/systemd/system',
        'user_systemd_enabled': os.path.expanduser('~/.config/systemd/user/default.target.wants'),
        'system_systemd_enabled': '/etc/systemd/system/multi-user.target.wants',
        'init_d': '/etc/init.d',
        'rc_local': '/etc/rc.local',
        'cron_d': '/etc/cron.d',
        'user_crontab': '/var/spool/cron/crontabs',
    }

    def __init__(self,
                 data_dir: Optional[str] = None,
                 notification_callback: Optional[Callable[[str, Dict], None]] = None,
                 check_interval_hours: float = 1.0):
        """
        Initialize the startup monitor.

        Args:
            data_dir: Directory to store encrypted program list (default: ~/.local/share/boundary-daemon)
            notification_callback: Function to call when new programs are detected
                                   Signature: callback(message: str, program_info: Dict)
            check_interval_hours: How often to check for new programs (default: 1 hour)
        """
        self.data_dir = data_dir or os.path.expanduser('~/.local/share/boundary-daemon')
        self.data_file = os.path.join(self.data_dir, '.startup_programs.enc')
        self.notification_callback = notification_callback
        self.check_interval = check_interval_hours * 3600  # Convert to seconds

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._known_programs: Dict[str, Dict] = {}
        self._encryption_key = self._derive_key()

        # Ensure data directory exists
        os.makedirs(self.data_dir, mode=0o700, exist_ok=True)

        # Load existing program list
        self._load_known_programs()

    def _derive_key(self) -> bytes:
        """
        Derive an encryption key from machine-specific information.
        This keeps the data tied to this machine.
        """
        # Collect machine identifiers
        machine_info = []

        # Machine ID (if available)
        for path in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        machine_info.append(f.read().strip())
                        break
                except Exception:
                    pass

        # Fallback: use hostname + username
        machine_info.append(os.environ.get('HOSTNAME', 'localhost'))
        machine_info.append(os.environ.get('USER', 'user'))

        # Create a key using PBKDF2-like derivation
        key_material = ':'.join(machine_info).encode()
        key = hashlib.pbkdf2_hmac(
            'sha256',
            key_material,
            b'boundary-daemon-startup-monitor',
            100000,
            dklen=32
        )
        return key

    def _encrypt(self, data: str) -> str:
        """Simple encryption using XOR with derived key and HMAC for integrity"""
        data_bytes = data.encode('utf-8')

        # Extend key to match data length
        extended_key = (self._encryption_key * ((len(data_bytes) // 32) + 1))[:len(data_bytes)]

        # XOR encrypt
        encrypted = bytes(a ^ b for a, b in zip(data_bytes, extended_key))

        # Add HMAC for integrity
        hmac_digest = hmac.new(self._encryption_key, encrypted, 'sha256').digest()

        # Combine and encode
        combined = hmac_digest + encrypted
        return base64.b64encode(combined).decode('ascii')

    def _decrypt(self, encrypted_data: str) -> Optional[str]:
        """Decrypt data and verify integrity"""
        try:
            combined = base64.b64decode(encrypted_data.encode('ascii'))

            # Split HMAC and data
            stored_hmac = combined[:32]
            encrypted = combined[32:]

            # Verify HMAC
            expected_hmac = hmac.new(self._encryption_key, encrypted, 'sha256').digest()
            if not hmac.compare_digest(stored_hmac, expected_hmac):
                logger.warning("Startup program list integrity check failed")
                return None

            # Extend key to match data length
            extended_key = (self._encryption_key * ((len(encrypted) // 32) + 1))[:len(encrypted)]

            # XOR decrypt
            decrypted = bytes(a ^ b for a, b in zip(encrypted, extended_key))
            return decrypted.decode('utf-8')

        except Exception as e:
            logger.debug(f"Decryption error: {e}")
            return None

    def _load_known_programs(self):
        """Load the encrypted list of known programs"""
        if not os.path.exists(self.data_file):
            self._known_programs = {}
            return

        try:
            with open(self.data_file, 'r') as f:
                encrypted_data = f.read()

            decrypted = self._decrypt(encrypted_data)
            if decrypted:
                self._known_programs = json.loads(decrypted)
                logger.debug(f"Loaded {len(self._known_programs)} known startup programs")
            else:
                self._known_programs = {}

        except Exception as e:
            logger.debug(f"Error loading known programs: {e}")
            self._known_programs = {}

    def _save_known_programs(self):
        """Save the encrypted list of known programs"""
        try:
            data_json = json.dumps(self._known_programs, indent=2)
            encrypted = self._encrypt(data_json)

            with open(self.data_file, 'w') as f:
                f.write(encrypted)

            # Set restrictive permissions
            os.chmod(self.data_file, 0o600)
            logger.debug(f"Saved {len(self._known_programs)} known startup programs")

        except Exception as e:
            logger.error(f"Error saving known programs: {e}")

    def scan_startup_programs(self) -> Dict[str, Dict]:
        """
        Scan all startup locations and return discovered programs.

        Returns:
            Dict mapping program identifiers to their info
        """
        programs = {}

        for location_name, location_path in self.STARTUP_LOCATIONS.items():
            if not os.path.exists(location_path):
                continue

            try:
                if os.path.isdir(location_path):
                    programs.update(self._scan_directory(location_name, location_path))
                else:
                    programs.update(self._scan_file(location_name, location_path))
            except PermissionError:
                logger.debug(f"Permission denied: {location_path}")
            except Exception as e:
                logger.debug(f"Error scanning {location_path}: {e}")

        # Also check systemd user services
        programs.update(self._scan_systemd_user_services())

        # Check crontab
        programs.update(self._scan_user_crontab())

        return programs

    def _scan_directory(self, location_name: str, dir_path: str) -> Dict[str, Dict]:
        """Scan a directory for startup entries"""
        programs = {}

        try:
            for entry in os.listdir(dir_path):
                entry_path = os.path.join(dir_path, entry)

                # Skip if not a file or if hidden (except .desktop files)
                if not os.path.isfile(entry_path):
                    continue

                program_id = f"{location_name}:{entry}"

                # Get file info
                try:
                    stat_info = os.stat(entry_path)
                    mtime = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                except Exception:
                    mtime = "unknown"

                # Parse .desktop files for more info
                display_name = entry
                exec_cmd = ""

                if entry.endswith('.desktop'):
                    desktop_info = self._parse_desktop_file(entry_path)
                    display_name = desktop_info.get('Name', entry.replace('.desktop', ''))
                    exec_cmd = desktop_info.get('Exec', '')

                # For systemd services
                elif entry.endswith('.service'):
                    service_info = self._parse_systemd_service(entry_path)
                    display_name = entry.replace('.service', '')
                    exec_cmd = service_info.get('ExecStart', '')

                programs[program_id] = {
                    'name': display_name,
                    'path': entry_path,
                    'location': location_name,
                    'type': self._get_entry_type(entry),
                    'exec': exec_cmd,
                    'modified': mtime,
                    'first_seen': datetime.utcnow().isoformat() + "Z"
                }

        except Exception as e:
            logger.debug(f"Error scanning directory {dir_path}: {e}")

        return programs

    def _scan_file(self, location_name: str, file_path: str) -> Dict[str, Dict]:
        """Scan a config file for startup entries (e.g., .bashrc, .xinitrc)"""
        programs = {}

        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()

            # Look for common patterns that start programs
            # This is a simplified detection - could be expanded
            patterns = [
                (r'^\s*exec\s+(.+?)(?:\s*&\s*)?$', 'exec'),
                (r'^\s*(?:nohup\s+)?(/\S+)\s*(?:&|$)', 'command'),
                (r'^\s*\(\s*(.+?)\s*\)\s*&\s*$', 'background'),
            ]

            for line_num, line in enumerate(content.split('\n'), 1):
                # Skip comments
                if line.strip().startswith('#'):
                    continue

                for pattern, entry_type in patterns:
                    import re
                    match = re.match(pattern, line, re.MULTILINE)
                    if match:
                        cmd = match.group(1).strip()
                        # Skip common non-program lines
                        if cmd and not any(skip in cmd for skip in ['$', 'source', '.', 'export', 'alias']):
                            program_id = f"{location_name}:line{line_num}"
                            programs[program_id] = {
                                'name': os.path.basename(cmd.split()[0]) if cmd else 'unknown',
                                'path': file_path,
                                'location': location_name,
                                'type': entry_type,
                                'exec': cmd,
                                'line': line_num,
                                'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
                                'first_seen': datetime.utcnow().isoformat() + "Z"
                            }
                            break

        except Exception as e:
            logger.debug(f"Error scanning file {file_path}: {e}")

        return programs

    def _scan_systemd_user_services(self) -> Dict[str, Dict]:
        """Scan systemd user services"""
        programs = {}

        try:
            # Get list of enabled user services
            result = subprocess.run(
                ['systemctl', '--user', 'list-unit-files', '--type=service', '--state=enabled', '--no-pager'],
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0:
                for line in result.stdout.decode().split('\n'):
                    if '.service' in line and 'enabled' in line:
                        parts = line.split()
                        if parts:
                            service_name = parts[0]
                            program_id = f"systemd_user:{service_name}"
                            programs[program_id] = {
                                'name': service_name.replace('.service', ''),
                                'path': f"systemd user service",
                                'location': 'systemd_user',
                                'type': 'systemd_service',
                                'exec': '',
                                'modified': 'unknown',
                                'first_seen': datetime.utcnow().isoformat() + "Z"
                            }

        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            # systemctl not available
            pass
        except Exception as e:
            logger.debug(f"Error scanning systemd user services: {e}")

        return programs

    def _scan_user_crontab(self) -> Dict[str, Dict]:
        """Scan user's crontab for scheduled programs"""
        programs = {}

        try:
            result = subprocess.run(
                ['crontab', '-l'],
                capture_output=True,
                timeout=5
            )

            if result.returncode == 0:
                for line_num, line in enumerate(result.stdout.decode().split('\n'), 1):
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue

                    # Cron format: min hour day month weekday command
                    parts = line.split(None, 5)
                    if len(parts) >= 6:
                        cmd = parts[5]
                        program_id = f"crontab:line{line_num}"
                        programs[program_id] = {
                            'name': os.path.basename(cmd.split()[0]) if cmd else 'unknown',
                            'path': 'crontab',
                            'location': 'crontab',
                            'type': 'cron_job',
                            'exec': cmd,
                            'schedule': ' '.join(parts[:5]),
                            'first_seen': datetime.utcnow().isoformat() + "Z"
                        }

        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.debug(f"Error scanning crontab: {e}")

        return programs

    def _parse_desktop_file(self, path: str) -> Dict[str, str]:
        """Parse a .desktop file for relevant info"""
        info = {}
        try:
            with open(path, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line:
                        key, value = line.split('=', 1)
                        if key in ['Name', 'Exec', 'Icon', 'Comment']:
                            info[key] = value
        except Exception:
            pass
        return info

    def _parse_systemd_service(self, path: str) -> Dict[str, str]:
        """Parse a systemd service file for relevant info"""
        info = {}
        try:
            with open(path, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line:
                        key, value = line.split('=', 1)
                        if key in ['ExecStart', 'Description', 'After']:
                            info[key] = value
        except Exception:
            pass
        return info

    def _get_entry_type(self, filename: str) -> str:
        """Determine the type of startup entry"""
        if filename.endswith('.desktop'):
            return 'desktop_entry'
        elif filename.endswith('.service'):
            return 'systemd_service'
        elif filename.endswith('.timer'):
            return 'systemd_timer'
        elif filename.endswith('.sh'):
            return 'shell_script'
        else:
            return 'other'

    def check_for_new_programs(self) -> List[Dict]:
        """
        Check for newly added startup programs.

        Returns:
            List of new programs detected
        """
        current_programs = self.scan_startup_programs()
        new_programs = []

        for prog_id, prog_info in current_programs.items():
            if prog_id not in self._known_programs:
                new_programs.append({
                    'id': prog_id,
                    **prog_info
                })
                # Add to known programs
                self._known_programs[prog_id] = prog_info

        # Check for removed programs (informational only)
        removed = set(self._known_programs.keys()) - set(current_programs.keys())
        for prog_id in removed:
            logger.debug(f"Program removed from startup: {prog_id}")
            del self._known_programs[prog_id]

        # Save updated list if there were changes
        if new_programs or removed:
            self._save_known_programs()

        return new_programs

    def _generate_friendly_message(self, program: Dict) -> str:
        """
        Generate a friendly, non-scary notification message.
        """
        name = program.get('name', 'Unknown program')
        location = program.get('location', 'startup')

        # Different messages based on type
        messages = {
            'desktop_entry': f"A new application has been added to your startup: '{name}'",
            'systemd_service': f"A new service has been enabled: '{name}'",
            'cron_job': f"A new scheduled task has been added: '{name}'",
            'shell_script': f"A new script will run at startup: '{name}'",
            'default': f"A new startup program was detected: '{name}'"
        }

        prog_type = program.get('type', 'default')
        base_message = messages.get(prog_type, messages['default'])

        # Add helpful context
        reminder = (
            f"\n\nThis is just a friendly heads-up! If you recently installed "
            f"'{name}' or added it to startup yourself, you can safely ignore this. "
            f"If you don't recognize this program, you may want to investigate."
        )

        location_info = f"\n\nLocation: {program.get('path', 'unknown')}"

        if program.get('exec'):
            location_info += f"\nCommand: {program['exec'][:100]}"

        return base_message + reminder + location_info

    def _notify_new_program(self, program: Dict):
        """Send notification about a new startup program"""
        message = self._generate_friendly_message(program)

        # Use callback if provided
        if self.notification_callback is not None:
            try:
                self.notification_callback(message, program)
            except Exception as e:
                logger.debug(f"Notification callback error: {e}")

        # Also log it
        logger.info(f"New startup program detected: {program.get('name', 'unknown')}")

        # Try to show desktop notification if available
        self._show_desktop_notification(program)

    def _show_desktop_notification(self, program: Dict):
        """Try to show a desktop notification"""
        name = program.get('name', 'Unknown')

        try:
            # Try notify-send (common on Linux)
            subprocess.run(
                [
                    'notify-send',
                    '--urgency=low',
                    '--icon=dialog-information',
                    'New Startup Program Detected',
                    f"'{name}' has been added to startup.\n\n"
                    f"If you installed this recently, no action needed!"
                ],
                capture_output=True,
                timeout=5
            )
        except FileNotFoundError:
            # notify-send not available
            pass
        except Exception:
            pass

    def initialize_baseline(self) -> int:
        """
        Perform initial scan and save all current programs as known.
        Call this when first setting up the monitor.

        Returns:
            Number of programs found
        """
        current_programs = self.scan_startup_programs()
        self._known_programs = current_programs
        self._save_known_programs()

        logger.info(f"Initialized startup monitor with {len(current_programs)} programs")
        return len(current_programs)

    def start(self):
        """Start the hourly monitoring thread"""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="StartupMonitor"
        )
        self._thread.start()
        logger.info("Startup program monitor started (checking every hour)")

    def stop(self):
        """Stop the monitoring thread"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        logger.info("Startup program monitor stopped")

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                # Check for new programs
                new_programs = self.check_for_new_programs()

                # Notify for each new program
                for program in new_programs:
                    self._notify_new_program(program)

            except Exception as e:
                logger.debug(f"Startup monitor loop error: {e}")

            # Wait for next check (default: 1 hour)
            # Use small increments so we can stop quickly
            wait_seconds = int(self.check_interval)
            for _ in range(wait_seconds):
                if not self._running:
                    break
                time.sleep(1)

    @property
    def is_running(self) -> bool:
        return self._running

    def get_known_programs(self) -> Dict[str, Dict]:
        """Get the current list of known startup programs"""
        return self._known_programs.copy()

    def get_status(self) -> Dict:
        """Get monitor status"""
        return {
            'running': self._running,
            'known_programs': len(self._known_programs),
            'data_file': self.data_file,
            'check_interval_hours': self.check_interval / 3600,
            'locations_monitored': len(self.STARTUP_LOCATIONS)
        }


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
    parser.add_argument('--network', action='store_true', help='Check network connections (SSH, FTP, etc.)')
    parser.add_argument('--ssh', action='store_true', help='Show SSH sessions only')
    parser.add_argument('--ftp', action='store_true', help='Show FTP connections only')
    parser.add_argument('--connections', action='store_true', help='Show all active connections summary')
    parser.add_argument('--startup', action='store_true', help='Scan and list all startup programs')
    parser.add_argument('--startup-init', action='store_true', help='Initialize baseline of known startup programs')
    parser.add_argument('--startup-check', action='store_true', help='Check for newly added startup programs')
    parser.add_argument('--startup-monitor', action='store_true', help='Start hourly startup program monitoring')
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
    elif args.network:
        print("Scanning network connections...")
        result = scanner.scan_network_connections()
    elif args.ssh:
        print("Getting SSH sessions...")
        sessions = scanner.get_ssh_sessions()
        if args.json:
            print(json_module.dumps(sessions, indent=2))
        else:
            print(f"\n{'='*60}")
            print("SSH SESSIONS")
            print(f"{'='*60}")
            if sessions:
                for s in sessions:
                    if s.get('type') == 'incoming':
                        print(f"\n[INCOMING] User: {s.get('user')}")
                        print(f"  Terminal: {s.get('terminal')}")
                        print(f"  Time: {s.get('time')}")
                        print(f"  From: {s.get('from')}")
                    else:
                        print(f"\n[OUTGOING] PID: {s.get('pid')}")
                        print(f"  Command: {s.get('command')}")
            else:
                print("\nNo active SSH sessions")
        result = None
    elif args.ftp:
        print("Getting FTP connections...")
        connections = scanner.get_ftp_connections()
        if args.json:
            print(json_module.dumps(connections, indent=2))
        else:
            print(f"\n{'='*60}")
            print("FTP CONNECTIONS")
            print(f"{'='*60}")
            if connections:
                for c in connections:
                    if c.get('type') == 'client':
                        print(f"\n[CLIENT] Process: {c.get('process')} (PID: {c.get('pid')})")
                        print(f"  Command: {c.get('command')}")
                    else:
                        print(f"\n[CONNECTION] {c.get('local')} -> {c.get('remote')}")
                        print(f"  State: {c.get('state')}")
                        if c.get('process'):
                            print(f"  Process: {c.get('process')}")
            else:
                print("\nNo active FTP connections")
        result = None
    elif args.connections:
        print("Getting all active connections...")
        connections = scanner.get_active_connections()
        if args.json:
            print(json_module.dumps(connections, indent=2))
        else:
            print(f"\n{'='*60}")
            print("ACTIVE CONNECTIONS SUMMARY")
            print(f"{'='*60}")
            for category, conns in connections.items():
                if conns:
                    print(f"\n{category.upper()} ({len(conns)} connections):")
                    for c in conns[:5]:  # Show first 5
                        print(f"  {c.get('local', 'N/A')} -> {c.get('remote', 'N/A')} [{c.get('state', 'N/A')}]")
                    if len(conns) > 5:
                        print(f"  ... and {len(conns) - 5} more")
        result = None
    elif args.startup:
        print("Scanning startup programs...")
        startup_monitor = StartupMonitor()
        programs = startup_monitor.scan_startup_programs()
        if args.json:
            print(json_module.dumps(programs, indent=2))
        else:
            print(f"\n{'='*60}")
            print("STARTUP PROGRAMS")
            print(f"{'='*60}")
            print(f"\nFound {len(programs)} startup programs:\n")

            # Group by location
            by_location = {}
            for prog_id, prog in programs.items():
                loc = prog.get('location', 'unknown')
                if loc not in by_location:
                    by_location[loc] = []
                by_location[loc].append(prog)

            for location, progs in sorted(by_location.items()):
                print(f"\n[{location.upper()}] ({len(progs)} programs)")
                for p in progs:
                    print(f"  - {p.get('name', 'unknown')}")
                    if p.get('exec'):
                        print(f"    Command: {p['exec'][:60]}...")
        result = None
    elif args.startup_init:
        print("Initializing startup program baseline...")
        startup_monitor = StartupMonitor()
        count = startup_monitor.initialize_baseline()
        print(f"\n{'='*60}")
        print("STARTUP BASELINE INITIALIZED")
        print(f"{'='*60}")
        print(f"\nRecorded {count} startup programs as known.")
        print(f"The encrypted list is saved at: {startup_monitor.data_file}")
        print("\nFuture checks will alert you when new programs are added.")
        result = None
    elif args.startup_check:
        print("Checking for new startup programs...")
        startup_monitor = StartupMonitor()

        # If no baseline exists, initialize first
        if not startup_monitor.get_known_programs():
            print("No baseline found. Initializing...")
            startup_monitor.initialize_baseline()
            print("Baseline created. Run --startup-check again to check for changes.")
        else:
            new_programs = startup_monitor.check_for_new_programs()
            print(f"\n{'='*60}")
            print("STARTUP PROGRAM CHECK")
            print(f"{'='*60}")

            if new_programs:
                print(f"\nFound {len(new_programs)} NEW startup programs:\n")
                for prog in new_programs:
                    print(f"\n  New: {prog.get('name', 'unknown')}")
                    print(f"  Type: {prog.get('type', 'unknown')}")
                    print(f"  Location: {prog.get('path', 'unknown')}")
                    if prog.get('exec'):
                        print(f"  Command: {prog['exec'][:80]}")
                    print("")
                    print("  If you recently installed this program, you can safely")
                    print("  ignore this message. Otherwise, you may want to investigate.")
            else:
                print("\nNo new startup programs detected.")
                print("All programs match the known baseline.")

            status = startup_monitor.get_status()
            print(f"\nKnown programs: {status['known_programs']}")
        result = None
    elif args.startup_monitor:
        print("Starting startup program monitor...")
        print("(Press Ctrl+C to stop)")
        print("")

        def on_new_program(message, program):
            print(f"\n{'='*60}")
            print("NEW STARTUP PROGRAM DETECTED")
            print(f"{'='*60}")
            print(message)
            print(f"{'='*60}\n")

        startup_monitor = StartupMonitor(notification_callback=on_new_program)

        # Initialize if needed
        if not startup_monitor.get_known_programs():
            count = startup_monitor.initialize_baseline()
            print(f"Initialized with {count} known programs.")
        else:
            print(f"Loaded {len(startup_monitor.get_known_programs())} known programs.")

        # Do an immediate check
        new_progs = startup_monitor.check_for_new_programs()
        if new_progs:
            for prog in new_progs:
                on_new_program(startup_monitor._generate_friendly_message(prog), prog)

        print(f"\nMonitor started. Checking every hour for new programs...")
        print("Monitoring locations:")
        for loc in list(startup_monitor.STARTUP_LOCATIONS.keys())[:5]:
            print(f"  - {loc}")
        print(f"  ... and {len(startup_monitor.STARTUP_LOCATIONS) - 5} more")

        startup_monitor.start()

        try:
            # Keep running until Ctrl+C
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\nStopping monitor...")
            startup_monitor.stop()
            print("Monitor stopped.")

        result = None
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
