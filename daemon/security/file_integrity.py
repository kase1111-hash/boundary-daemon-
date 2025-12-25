"""
File Integrity Monitoring (FIM) Module

Provides file integrity monitoring capabilities including:
- Critical system file hash verification
- Config file change detection
- Binary modification alerts
- Real-time file watching
- Baseline management
"""

import os
import stat
import hashlib
import threading
import time
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum
from datetime import datetime
from pathlib import Path


class FileIntegrityAlert(Enum):
    """Types of file integrity alerts"""
    FILE_MODIFIED = "file_modified"
    FILE_CREATED = "file_created"
    FILE_DELETED = "file_deleted"
    HASH_MISMATCH = "hash_mismatch"
    PERMISSION_CHANGED = "permission_changed"
    OWNER_CHANGED = "owner_changed"
    BINARY_MODIFIED = "binary_modified"
    CONFIG_MODIFIED = "config_modified"
    SUID_ADDED = "suid_added"
    WORLD_WRITABLE = "world_writable"


class FileSeverity(Enum):
    """Severity levels for file changes"""
    CRITICAL = "critical"  # System binaries, security configs
    HIGH = "high"          # Important configs, executables
    MEDIUM = "medium"      # Application configs, scripts
    LOW = "low"            # Logs, temp files
    INFO = "info"          # Informational only


class FileCategory(Enum):
    """Categories of monitored files"""
    SYSTEM_BINARY = "system_binary"
    SECURITY_CONFIG = "security_config"
    SYSTEM_CONFIG = "system_config"
    APPLICATION_CONFIG = "application_config"
    SCRIPT = "script"
    LIBRARY = "library"
    KERNEL = "kernel"
    BOOT = "boot"
    CUSTOM = "custom"


@dataclass
class FileIntegrityConfig:
    """Configuration for file integrity monitoring"""
    # Hash algorithm
    hash_algorithm: str = "sha256"

    # Monitoring settings
    check_interval_seconds: int = 300  # 5 minutes
    enable_realtime: bool = False  # Requires inotify

    # What to monitor
    monitor_permissions: bool = True
    monitor_ownership: bool = True
    monitor_timestamps: bool = True
    monitor_size: bool = True
    monitor_hash: bool = True

    # Alert settings
    alert_on_new_suid: bool = True
    alert_on_world_writable: bool = True

    # Exclusion patterns (regex)
    exclude_patterns: List[str] = field(default_factory=lambda: [
        r".*\.log$",
        r".*\.tmp$",
        r".*\.swp$",
        r".*\.pid$",
        r"/proc/.*",
        r"/sys/.*",
        r"/dev/.*",
        r"/run/.*",
    ])

    # Custom paths to monitor
    custom_paths: List[str] = field(default_factory=list)

    # Baseline file location
    baseline_file: Optional[str] = None


@dataclass
class FileInfo:
    """Information about a monitored file"""
    path: str
    hash: str
    size: int
    mode: int
    uid: int
    gid: int
    mtime: float
    ctime: float
    category: FileCategory
    exists: bool = True

    def to_dict(self) -> Dict:
        return {
            'path': self.path,
            'hash': self.hash,
            'size': self.size,
            'mode': self.mode,
            'uid': self.uid,
            'gid': self.gid,
            'mtime': self.mtime,
            'ctime': self.ctime,
            'category': self.category.value,
            'exists': self.exists
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'FileInfo':
        return cls(
            path=data['path'],
            hash=data['hash'],
            size=data['size'],
            mode=data['mode'],
            uid=data['uid'],
            gid=data['gid'],
            mtime=data['mtime'],
            ctime=data['ctime'],
            category=FileCategory(data['category']),
            exists=data.get('exists', True)
        )


@dataclass
class FileChange:
    """Represents a detected file change"""
    path: str
    alert_type: FileIntegrityAlert
    severity: FileSeverity
    category: FileCategory
    old_value: Optional[str]
    new_value: Optional[str]
    timestamp: datetime
    details: Dict = field(default_factory=dict)


@dataclass
class FileIntegrityStatus:
    """Current file integrity monitoring status"""
    is_monitoring: bool = False
    baseline_loaded: bool = False
    files_monitored: int = 0
    last_check: Optional[datetime] = None
    alerts: List[str] = field(default_factory=list)
    changes_detected: int = 0
    files_added: int = 0
    files_removed: int = 0
    files_modified: int = 0


class FileIntegrityMonitor:
    """Monitors file integrity and detects unauthorized changes"""

    # Critical system paths to monitor
    CRITICAL_PATHS = {
        # System binaries
        '/bin': FileCategory.SYSTEM_BINARY,
        '/sbin': FileCategory.SYSTEM_BINARY,
        '/usr/bin': FileCategory.SYSTEM_BINARY,
        '/usr/sbin': FileCategory.SYSTEM_BINARY,

        # Security configs
        '/etc/passwd': FileCategory.SECURITY_CONFIG,
        '/etc/shadow': FileCategory.SECURITY_CONFIG,
        '/etc/group': FileCategory.SECURITY_CONFIG,
        '/etc/sudoers': FileCategory.SECURITY_CONFIG,
        '/etc/ssh/sshd_config': FileCategory.SECURITY_CONFIG,
        '/etc/pam.d': FileCategory.SECURITY_CONFIG,

        # System configs
        '/etc/hosts': FileCategory.SYSTEM_CONFIG,
        '/etc/resolv.conf': FileCategory.SYSTEM_CONFIG,
        '/etc/fstab': FileCategory.SYSTEM_CONFIG,
        '/etc/crontab': FileCategory.SYSTEM_CONFIG,
        '/etc/cron.d': FileCategory.SYSTEM_CONFIG,
        '/etc/init.d': FileCategory.SYSTEM_CONFIG,
        '/etc/systemd': FileCategory.SYSTEM_CONFIG,

        # Libraries
        '/lib': FileCategory.LIBRARY,
        '/lib64': FileCategory.LIBRARY,
        '/usr/lib': FileCategory.LIBRARY,
        '/usr/lib64': FileCategory.LIBRARY,

        # Kernel/Boot
        '/boot': FileCategory.BOOT,
    }

    # Binary file extensions
    BINARY_EXTENSIONS = {
        '.so', '.ko', '.o', '.a',
        '', '.bin', '.elf',
    }

    # Config file extensions
    CONFIG_EXTENSIONS = {
        '.conf', '.cfg', '.ini', '.yaml', '.yml', '.json', '.xml',
        '.properties', '.env',
    }

    # Script extensions
    SCRIPT_EXTENSIONS = {
        '.sh', '.bash', '.py', '.pl', '.rb', '.php',
    }

    def __init__(self, config: Optional[FileIntegrityConfig] = None):
        self.config = config or FileIntegrityConfig()
        self.status = FileIntegrityStatus()
        self._lock = threading.RLock()

        # Baseline: path -> FileInfo
        self._baseline: Dict[str, FileInfo] = {}

        # Current state
        self._current_state: Dict[str, FileInfo] = {}

        # Detected changes
        self._changes: List[FileChange] = []

        # Compiled exclusion patterns
        self._exclude_patterns = [
            re.compile(p) for p in self.config.exclude_patterns
        ]

        # Monitoring thread
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None

    def scan_file(self, path: str) -> Optional[FileInfo]:
        """
        Scan a single file and return its information

        Args:
            path: Path to the file

        Returns:
            FileInfo if file exists and is accessible, None otherwise
        """
        try:
            if not os.path.exists(path):
                return None

            if os.path.islink(path):
                # For symlinks, get info about the link itself
                stat_info = os.lstat(path)
            else:
                stat_info = os.stat(path)

            # Calculate hash for regular files
            file_hash = ""
            if os.path.isfile(path) and not os.path.islink(path):
                file_hash = self._calculate_hash(path)

            # Determine category
            category = self._determine_category(path)

            return FileInfo(
                path=path,
                hash=file_hash,
                size=stat_info.st_size,
                mode=stat_info.st_mode,
                uid=stat_info.st_uid,
                gid=stat_info.st_gid,
                mtime=stat_info.st_mtime,
                ctime=stat_info.st_ctime,
                category=category,
                exists=True
            )

        except (OSError, PermissionError, IOError) as e:
            # Can't access file
            return None

    def _calculate_hash(self, path: str) -> str:
        """Calculate file hash"""
        try:
            if self.config.hash_algorithm == "sha256":
                hasher = hashlib.sha256()
            elif self.config.hash_algorithm == "sha512":
                hasher = hashlib.sha512()
            elif self.config.hash_algorithm == "md5":
                hasher = hashlib.md5()
            else:
                hasher = hashlib.sha256()

            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    hasher.update(chunk)

            return hasher.hexdigest()

        except (OSError, PermissionError, IOError):
            return ""

    def _determine_category(self, path: str) -> FileCategory:
        """Determine the category of a file"""
        # Check against known critical paths
        for critical_path, category in self.CRITICAL_PATHS.items():
            if path.startswith(critical_path):
                # If it's a directory path, use the category
                if os.path.isdir(critical_path):
                    return category
                elif path == critical_path:
                    return category

        # Check by extension
        ext = os.path.splitext(path)[1].lower()

        if ext in self.SCRIPT_EXTENSIONS:
            return FileCategory.SCRIPT
        elif ext in self.CONFIG_EXTENSIONS:
            return FileCategory.APPLICATION_CONFIG
        elif ext in self.BINARY_EXTENSIONS:
            return FileCategory.LIBRARY

        # Check if it's an executable
        try:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return FileCategory.SYSTEM_BINARY
        except (OSError, PermissionError):
            pass

        return FileCategory.CUSTOM

    def _should_exclude(self, path: str) -> bool:
        """Check if path should be excluded from monitoring"""
        for pattern in self._exclude_patterns:
            if pattern.match(path):
                return True
        return False

    def _get_severity(self, category: FileCategory, alert_type: FileIntegrityAlert) -> FileSeverity:
        """Determine severity based on file category and alert type"""
        # SUID changes are always critical
        if alert_type == FileIntegrityAlert.SUID_ADDED:
            return FileSeverity.CRITICAL

        # Severity by category
        severity_map = {
            FileCategory.SECURITY_CONFIG: FileSeverity.CRITICAL,
            FileCategory.SYSTEM_BINARY: FileSeverity.CRITICAL,
            FileCategory.KERNEL: FileSeverity.CRITICAL,
            FileCategory.BOOT: FileSeverity.CRITICAL,
            FileCategory.LIBRARY: FileSeverity.HIGH,
            FileCategory.SYSTEM_CONFIG: FileSeverity.HIGH,
            FileCategory.SCRIPT: FileSeverity.MEDIUM,
            FileCategory.APPLICATION_CONFIG: FileSeverity.MEDIUM,
            FileCategory.CUSTOM: FileSeverity.LOW,
        }

        return severity_map.get(category, FileSeverity.INFO)

    def create_baseline(self, paths: Optional[List[str]] = None) -> Dict[str, FileInfo]:
        """
        Create a baseline of file states

        Args:
            paths: Optional list of paths to baseline. If None, uses default critical paths.

        Returns:
            Dictionary of path -> FileInfo
        """
        baseline = {}

        with self._lock:
            if paths is None:
                paths = list(self.CRITICAL_PATHS.keys()) + self.config.custom_paths

            for path in paths:
                if self._should_exclude(path):
                    continue

                if os.path.isdir(path):
                    # Scan directory recursively
                    for root, dirs, files in os.walk(path):
                        for filename in files:
                            filepath = os.path.join(root, filename)
                            if not self._should_exclude(filepath):
                                info = self.scan_file(filepath)
                                if info:
                                    baseline[filepath] = info

                        # Also scan the directories themselves
                        for dirname in dirs:
                            dirpath = os.path.join(root, dirname)
                            if not self._should_exclude(dirpath):
                                info = self.scan_file(dirpath)
                                if info:
                                    baseline[dirpath] = info
                else:
                    info = self.scan_file(path)
                    if info:
                        baseline[path] = info

            self._baseline = baseline
            self.status.baseline_loaded = True
            self.status.files_monitored = len(baseline)

        return baseline

    def check_integrity(self) -> List[FileChange]:
        """
        Check current file states against baseline

        Returns:
            List of detected changes
        """
        changes = []

        with self._lock:
            if not self._baseline:
                return changes

            current_paths = set()

            # Check all baselined files
            for path, baseline_info in self._baseline.items():
                current_info = self.scan_file(path)
                current_paths.add(path)

                if current_info is None:
                    # File was deleted
                    change = FileChange(
                        path=path,
                        alert_type=FileIntegrityAlert.FILE_DELETED,
                        severity=self._get_severity(baseline_info.category,
                                                   FileIntegrityAlert.FILE_DELETED),
                        category=baseline_info.category,
                        old_value=baseline_info.hash,
                        new_value=None,
                        timestamp=datetime.now(),
                        details={'was_size': baseline_info.size}
                    )
                    changes.append(change)
                    self.status.files_removed += 1
                    continue

                # Check for modifications
                file_changes = self._compare_files(baseline_info, current_info)
                changes.extend(file_changes)

                self._current_state[path] = current_info

            # Check for new files in monitored directories
            # (This is simplified - full implementation would re-scan directories)

            # Update status
            self.status.last_check = datetime.now()
            self.status.changes_detected = len(changes)

            # Record alerts
            for change in changes:
                alert_msg = f"{change.alert_type.value}: {change.path}"
                if alert_msg not in self.status.alerts:
                    self.status.alerts.append(alert_msg)

            self._changes.extend(changes)

        return changes

    def _compare_files(self, baseline: FileInfo, current: FileInfo) -> List[FileChange]:
        """Compare baseline and current file info"""
        changes = []
        path = baseline.path

        # Check hash
        if self.config.monitor_hash and baseline.hash and current.hash:
            if baseline.hash != current.hash:
                alert_type = FileIntegrityAlert.HASH_MISMATCH

                # Check if it's a binary
                if baseline.category in [FileCategory.SYSTEM_BINARY, FileCategory.LIBRARY]:
                    alert_type = FileIntegrityAlert.BINARY_MODIFIED
                elif baseline.category in [FileCategory.SECURITY_CONFIG,
                                          FileCategory.SYSTEM_CONFIG,
                                          FileCategory.APPLICATION_CONFIG]:
                    alert_type = FileIntegrityAlert.CONFIG_MODIFIED

                changes.append(FileChange(
                    path=path,
                    alert_type=alert_type,
                    severity=self._get_severity(baseline.category, alert_type),
                    category=baseline.category,
                    old_value=baseline.hash[:16] + "...",
                    new_value=current.hash[:16] + "...",
                    timestamp=datetime.now(),
                    details={'full_old_hash': baseline.hash, 'full_new_hash': current.hash}
                ))
                self.status.files_modified += 1

        # Check permissions
        if self.config.monitor_permissions and baseline.mode != current.mode:
            changes.append(FileChange(
                path=path,
                alert_type=FileIntegrityAlert.PERMISSION_CHANGED,
                severity=self._get_severity(baseline.category,
                                           FileIntegrityAlert.PERMISSION_CHANGED),
                category=baseline.category,
                old_value=oct(baseline.mode),
                new_value=oct(current.mode),
                timestamp=datetime.now()
            ))

            # Check for SUID bit added
            if self.config.alert_on_new_suid:
                old_suid = baseline.mode & stat.S_ISUID
                new_suid = current.mode & stat.S_ISUID
                if not old_suid and new_suid:
                    changes.append(FileChange(
                        path=path,
                        alert_type=FileIntegrityAlert.SUID_ADDED,
                        severity=FileSeverity.CRITICAL,
                        category=baseline.category,
                        old_value="no SUID",
                        new_value="SUID set",
                        timestamp=datetime.now()
                    ))

            # Check for world-writable
            if self.config.alert_on_world_writable:
                old_ww = baseline.mode & stat.S_IWOTH
                new_ww = current.mode & stat.S_IWOTH
                if not old_ww and new_ww:
                    changes.append(FileChange(
                        path=path,
                        alert_type=FileIntegrityAlert.WORLD_WRITABLE,
                        severity=FileSeverity.HIGH,
                        category=baseline.category,
                        old_value="not world-writable",
                        new_value="world-writable",
                        timestamp=datetime.now()
                    ))

        # Check ownership
        if self.config.monitor_ownership:
            if baseline.uid != current.uid or baseline.gid != current.gid:
                changes.append(FileChange(
                    path=path,
                    alert_type=FileIntegrityAlert.OWNER_CHANGED,
                    severity=self._get_severity(baseline.category,
                                               FileIntegrityAlert.OWNER_CHANGED),
                    category=baseline.category,
                    old_value=f"{baseline.uid}:{baseline.gid}",
                    new_value=f"{current.uid}:{current.gid}",
                    timestamp=datetime.now()
                ))

        return changes

    def verify_file(self, path: str, expected_hash: Optional[str] = None) -> Tuple[bool, Optional[FileChange]]:
        """
        Verify a single file's integrity

        Args:
            path: Path to the file
            expected_hash: Optional expected hash. If None, uses baseline.

        Returns:
            (is_valid, change_if_any)
        """
        with self._lock:
            current_info = self.scan_file(path)

            if current_info is None:
                return False, FileChange(
                    path=path,
                    alert_type=FileIntegrityAlert.FILE_DELETED,
                    severity=FileSeverity.HIGH,
                    category=FileCategory.CUSTOM,
                    old_value=expected_hash,
                    new_value=None,
                    timestamp=datetime.now()
                )

            if expected_hash:
                target_hash = expected_hash
            elif path in self._baseline:
                target_hash = self._baseline[path].hash
            else:
                # No baseline, just return current hash
                return True, None

            if current_info.hash != target_hash:
                return False, FileChange(
                    path=path,
                    alert_type=FileIntegrityAlert.HASH_MISMATCH,
                    severity=FileSeverity.HIGH,
                    category=current_info.category,
                    old_value=target_hash[:16] + "...",
                    new_value=current_info.hash[:16] + "...",
                    timestamp=datetime.now()
                )

            return True, None

    def add_to_baseline(self, path: str) -> Optional[FileInfo]:
        """Add a file to the baseline"""
        with self._lock:
            info = self.scan_file(path)
            if info:
                self._baseline[path] = info
                self.status.files_monitored = len(self._baseline)
            return info

    def remove_from_baseline(self, path: str):
        """Remove a file from the baseline"""
        with self._lock:
            if path in self._baseline:
                del self._baseline[path]
                self.status.files_monitored = len(self._baseline)

    def save_baseline(self, filepath: str):
        """Save baseline to a file"""
        with self._lock:
            data = {
                'version': '1.0',
                'timestamp': datetime.now().isoformat(),
                'hash_algorithm': self.config.hash_algorithm,
                'files': {path: info.to_dict() for path, info in self._baseline.items()}
            }

            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)

    def load_baseline(self, filepath: str) -> bool:
        """Load baseline from a file"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

            with self._lock:
                self._baseline = {
                    path: FileInfo.from_dict(info)
                    for path, info in data.get('files', {}).items()
                }
                self.status.baseline_loaded = True
                self.status.files_monitored = len(self._baseline)

            return True

        except (OSError, json.JSONDecodeError, KeyError) as e:
            return False

    def scan_for_suid_binaries(self) -> List[FileChange]:
        """Scan for SUID binaries (potential privilege escalation)"""
        alerts = []
        suid_paths = ['/usr/bin', '/usr/sbin', '/bin', '/sbin', '/usr/local/bin']

        with self._lock:
            for base_path in suid_paths:
                if not os.path.exists(base_path):
                    continue

                try:
                    for filename in os.listdir(base_path):
                        filepath = os.path.join(base_path, filename)
                        try:
                            stat_info = os.stat(filepath)
                            if stat_info.st_mode & stat.S_ISUID:
                                # Check if this SUID binary is in our baseline
                                if filepath in self._baseline:
                                    baseline_info = self._baseline[filepath]
                                    if not (baseline_info.mode & stat.S_ISUID):
                                        # SUID was added!
                                        alerts.append(FileChange(
                                            path=filepath,
                                            alert_type=FileIntegrityAlert.SUID_ADDED,
                                            severity=FileSeverity.CRITICAL,
                                            category=FileCategory.SYSTEM_BINARY,
                                            old_value="no SUID",
                                            new_value="SUID set",
                                            timestamp=datetime.now()
                                        ))

                        except (OSError, PermissionError):
                            continue

                except (OSError, PermissionError):
                    continue

        return alerts

    def scan_for_world_writable(self) -> List[FileChange]:
        """Scan for world-writable files in sensitive locations"""
        alerts = []
        sensitive_paths = ['/etc', '/usr/bin', '/usr/sbin', '/bin', '/sbin']

        with self._lock:
            for base_path in sensitive_paths:
                if not os.path.exists(base_path):
                    continue

                try:
                    for root, dirs, files in os.walk(base_path):
                        for filename in files:
                            filepath = os.path.join(root, filename)
                            try:
                                stat_info = os.stat(filepath)
                                if stat_info.st_mode & stat.S_IWOTH:
                                    alerts.append(FileChange(
                                        path=filepath,
                                        alert_type=FileIntegrityAlert.WORLD_WRITABLE,
                                        severity=FileSeverity.HIGH,
                                        category=self._determine_category(filepath),
                                        old_value=None,
                                        new_value="world-writable",
                                        timestamp=datetime.now()
                                    ))

                            except (OSError, PermissionError):
                                continue

                except (OSError, PermissionError):
                    continue

        return alerts

    def get_status(self) -> FileIntegrityStatus:
        """Get current monitoring status"""
        with self._lock:
            return self.status

    def get_changes(self) -> List[FileChange]:
        """Get all detected changes"""
        with self._lock:
            return self._changes.copy()

    def clear_alerts(self):
        """Clear all alerts"""
        with self._lock:
            self.status.alerts = []
            self._changes = []
            self.status.changes_detected = 0

    def get_summary(self) -> Dict:
        """Get a summary of file integrity status"""
        with self._lock:
            return {
                "is_monitoring": self.status.is_monitoring,
                "baseline_loaded": self.status.baseline_loaded,
                "files_monitored": self.status.files_monitored,
                "last_check": self.status.last_check.isoformat() if self.status.last_check else None,
                "changes_detected": self.status.changes_detected,
                "files_added": self.status.files_added,
                "files_removed": self.status.files_removed,
                "files_modified": self.status.files_modified,
                "active_alerts": len(self.status.alerts)
            }
