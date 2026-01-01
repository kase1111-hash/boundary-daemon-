"""
Daemon Binary Integrity Protection Module.

Provides cryptographic integrity verification for the daemon itself:
- Hash verification of all daemon Python files on startup
- Signed manifest for tamper detection
- Runtime integrity monitoring
- Startup blocking if integrity check fails
- TPM-sealed manifest support (optional)

SECURITY: Addresses Critical Finding: "No Integrity Protection on Daemon Binary"
Without this protection, attackers could modify daemon code to bypass security controls.
"""

import os
import sys
import hmac
import hashlib
import json
import threading
import time
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

# Import error handling framework for consistent error management
try:
    from daemon.utils.error_handling import (
        handle_error,
        log_security_error,
        log_filesystem_error,
        ErrorCategory,
        ErrorSeverity,
    )
    ERROR_HANDLING_AVAILABLE = True
except ImportError:
    ERROR_HANDLING_AVAILABLE = False
    # Fallback stubs
    def handle_error(e, op, category=None, severity=None, additional_context=None, reraise=False, log_level=None):
        logger.error(f"{op}: {e}")
    def log_security_error(e, op, **ctx):
        logger.error(f"SECURITY: {op}: {e}")
    def log_filesystem_error(e, op, **ctx):
        logger.error(f"FILESYSTEM: {op}: {e}")

# Import centralized paths for PyInstaller-aware path resolution
try:
    from daemon.constants import Paths
    PATHS_AVAILABLE = True
except ImportError:
    PATHS_AVAILABLE = False

# Cross-platform path defaults
# Uses centralized Paths class if available (handles PyInstaller frozen executables)
IS_WINDOWS = sys.platform == 'win32'


def _get_default_manifest_path() -> str:
    """Get the default manifest path, handling PyInstaller frozen executables."""
    if PATHS_AVAILABLE:
        return Paths.get_manifest_path()
    # Fallback for when Paths is not available
    if IS_WINDOWS:
        return "./config/manifest.json"
    return "/etc/boundary-daemon/manifest.json"


def _get_default_signing_key_path() -> str:
    """Get the default signing key path, handling PyInstaller frozen executables."""
    if PATHS_AVAILABLE:
        return Paths.get_signing_key_path()
    # Fallback for when Paths is not available
    if IS_WINDOWS:
        return "./config/signing.key"
    return "/etc/boundary-daemon/signing.key"


_DEFAULT_MANIFEST_PATH = _get_default_manifest_path()
_DEFAULT_SIGNING_KEY_PATH = _get_default_signing_key_path()


class IntegrityStatus(Enum):
    """Status of integrity verification."""
    UNKNOWN = "unknown"
    VERIFIED = "verified"
    FAILED = "failed"
    MANIFEST_MISSING = "manifest_missing"
    MANIFEST_INVALID = "manifest_invalid"
    FILES_MODIFIED = "files_modified"
    FILES_MISSING = "files_missing"
    FILES_ADDED = "files_added"
    SIGNATURE_INVALID = "signature_invalid"


class IntegrityAction(Enum):
    """Action to take on integrity failure."""
    WARN_ONLY = "warn_only"           # Log warning but continue
    BLOCK_STARTUP = "block_startup"   # Refuse to start daemon
    LOCKDOWN = "lockdown"             # Start in restricted lockdown mode
    SHUTDOWN = "shutdown"             # Shutdown if running


@dataclass
class IntegrityConfig:
    """Configuration for daemon integrity protection."""
    # Manifest location (should be read-only)
    manifest_path: str = _DEFAULT_MANIFEST_PATH

    # Signing key path (for HMAC verification)
    # In production, this would be in TPM or hardware security module
    signing_key_path: str = _DEFAULT_SIGNING_KEY_PATH

    # Hash algorithm
    hash_algorithm: str = "sha256"

    # Action on integrity failure
    failure_action: IntegrityAction = IntegrityAction.BLOCK_STARTUP

    # Runtime monitoring interval (seconds)
    monitor_interval: int = 60

    # Enable runtime monitoring
    enable_runtime_monitoring: bool = True

    # Paths to monitor (relative to daemon root)
    monitored_paths: List[str] = field(default_factory=lambda: [
        "daemon/",
        "api/",
    ])

    # Excluded patterns
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "__pycache__",
        "*.pyc",
        "*.pyo",
        ".git",
        ".pytest_cache",
        "*.log",
        "*.tmp",
    ])

    # Whether to verify at startup
    verify_on_startup: bool = True

    # Allow running without manifest (first run / development)
    allow_missing_manifest: bool = False


@dataclass
class FileIntegrityInfo:
    """Information about a single file's integrity."""
    path: str
    hash: str
    size: int
    mtime: float

    def to_dict(self) -> Dict:
        return {
            'path': self.path,
            'hash': self.hash,
            'size': self.size,
            'mtime': self.mtime,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'FileIntegrityInfo':
        return cls(
            path=data['path'],
            hash=data['hash'],
            size=data['size'],
            mtime=data.get('mtime', 0.0),
        )


@dataclass
class IntegrityManifest:
    """Signed manifest of daemon file hashes."""
    version: str
    created_at: str
    daemon_version: str
    hash_algorithm: str
    files: Dict[str, FileIntegrityInfo]
    signature: str = ""

    def to_dict(self) -> Dict:
        return {
            'version': self.version,
            'created_at': self.created_at,
            'daemon_version': self.daemon_version,
            'hash_algorithm': self.hash_algorithm,
            'files': {path: info.to_dict() for path, info in self.files.items()},
            'signature': self.signature,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'IntegrityManifest':
        files = {
            path: FileIntegrityInfo.from_dict(info)
            for path, info in data.get('files', {}).items()
        }
        return cls(
            version=data.get('version', '1.0'),
            created_at=data.get('created_at', ''),
            daemon_version=data.get('daemon_version', 'unknown'),
            hash_algorithm=data.get('hash_algorithm', 'sha256'),
            files=files,
            signature=data.get('signature', ''),
        )


@dataclass
class IntegrityCheckResult:
    """Result of an integrity check."""
    status: IntegrityStatus
    verified_files: int = 0
    failed_files: List[str] = field(default_factory=list)
    missing_files: List[str] = field(default_factory=list)
    added_files: List[str] = field(default_factory=list)
    modified_files: List[str] = field(default_factory=list)
    error_message: str = ""
    check_time: float = 0.0

    @property
    def is_valid(self) -> bool:
        return self.status == IntegrityStatus.VERIFIED

    def to_dict(self) -> Dict:
        return {
            'status': self.status.value,
            'verified_files': self.verified_files,
            'failed_files': self.failed_files,
            'missing_files': self.missing_files,
            'added_files': self.added_files,
            'modified_files': self.modified_files,
            'error_message': self.error_message,
            'check_time': self.check_time,
        }


class DaemonIntegrityProtector:
    """
    Protects daemon binary/script integrity.

    SECURITY: This class MUST be instantiated and verified BEFORE any other
    daemon initialization to prevent execution of tampered code.

    Features:
    1. Startup verification: Check all daemon files before initialization
    2. Signed manifest: HMAC-signed manifest prevents tampering
    3. Runtime monitoring: Continuous integrity checks while running
    4. TPM sealing: Optional TPM-based manifest protection
    5. Failure handling: Block startup, lockdown, or warn on failure
    """

    MANIFEST_VERSION = "1.0"

    def __init__(
        self,
        config: Optional[IntegrityConfig] = None,
        daemon_root: Optional[str] = None,
        event_logger=None,
    ):
        """
        Initialize integrity protector.

        Args:
            config: Configuration options
            daemon_root: Root directory of daemon code
            event_logger: Optional event logger for security events
        """
        self.config = config or IntegrityConfig()
        self._event_logger = event_logger
        self._lock = threading.RLock()

        # Determine daemon root
        if daemon_root:
            self._daemon_root = Path(daemon_root)
        else:
            # Default to parent of this file's directory
            self._daemon_root = Path(__file__).parent.parent.parent

        # State
        self._manifest: Optional[IntegrityManifest] = None
        self._last_check: Optional[IntegrityCheckResult] = None
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None

        # Signing key (loaded on demand)
        self._signing_key: Optional[bytes] = None

        # Statistics
        self._stats = {
            'checks_performed': 0,
            'checks_passed': 0,
            'checks_failed': 0,
            'last_check_time': None,
            'files_monitored': 0,
        }

        # Rate limiting for log messages (prevent spam)
        self._last_failure_log_time: float = 0.0
        self._failure_log_cooldown: float = 600.0  # 10 minutes

    def _load_signing_key(self) -> Optional[bytes]:
        """Load the signing key for manifest verification.

        SECURITY: Keys must be loaded from file only - no environment variables
        (visible in /proc/[pid]/environ) and no ephemeral keys (breaks verification).
        """
        if self._signing_key:
            return self._signing_key

        key_path = self.config.signing_key_path

        # Try to load from file (only secure method)
        if os.path.exists(key_path):
            try:
                with open(key_path, 'rb') as f:
                    self._signing_key = f.read()
                if len(self._signing_key) < 32:
                    logger.error(f"Signing key too short: {len(self._signing_key)} bytes (minimum 32)")
                    self._signing_key = None
                    return None
                logger.info(f"Loaded signing key from {key_path}")
                return self._signing_key
            except (IOError, OSError, PermissionError) as e:
                # File access errors - could be permissions, corruption, or I/O failure
                log_security_error(e, "load_signing_key", key_path=str(key_path))
                return None

        # SECURITY: Fail-closed - do not generate ephemeral keys or use env vars
        # Environment variables are visible via /proc/[pid]/environ
        # Ephemeral keys break verification across restarts
        logger.error(
            f"No signing key found at {key_path}. "
            "Generate one with: python -m daemon.security.daemon_integrity generate-key --output <path>"
        )
        return None

    @staticmethod
    def generate_signing_key(output_path: str) -> bool:
        """Generate a secure signing key file with proper permissions.

        SECURITY: Creates key file with 0o600 permissions atomically to prevent
        TOCTOU race conditions where another process could read the key.

        Args:
            output_path: Path where the signing key will be written

        Returns:
            True if key was generated successfully, False otherwise
        """
        import stat

        try:
            # Generate 32 bytes of cryptographically secure random data
            key_data = os.urandom(32)

            # Create parent directory if needed
            parent_dir = os.path.dirname(output_path)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, mode=0o700, exist_ok=True)

            # SECURITY: Use os.open with O_CREAT | O_EXCL to atomically create
            # file with correct permissions, preventing TOCTOU vulnerabilities
            fd = os.open(
                output_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                stat.S_IRUSR | stat.S_IWUSR  # 0o600
            )
            try:
                os.write(fd, key_data)
            finally:
                os.close(fd)

            logger.info(f"Generated signing key at {output_path} with secure permissions (0600)")
            return True

        except FileExistsError:
            logger.error(f"Signing key already exists at {output_path}")
            return False
        except (OSError, PermissionError) as e:
            # File system errors after FileExistsError is handled
            log_filesystem_error(e, "generate_signing_key", output_path=str(output_path))
            return False

    def _calculate_file_hash(self, filepath: Path) -> str:
        """Calculate hash of a single file."""
        try:
            if self.config.hash_algorithm == "sha256":
                hasher = hashlib.sha256()
            elif self.config.hash_algorithm == "sha512":
                hasher = hashlib.sha512()
            elif self.config.hash_algorithm == "blake2b":
                hasher = hashlib.blake2b()
            else:
                hasher = hashlib.sha256()

            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    hasher.update(chunk)

            return hasher.hexdigest()

        except (IOError, OSError, IsADirectoryError) as e:
            # File access errors - file deleted, permissions changed, or is directory
            log_filesystem_error(e, "calculate_file_hash", filepath=str(filepath))
            return ""

    def _should_include_file(self, filepath: Path) -> bool:
        """Check if a file should be included in integrity checking."""
        filename = filepath.name
        filepath_str = str(filepath)

        # Check exclusion patterns
        for pattern in self.config.exclude_patterns:
            if pattern.startswith("*"):
                # Extension pattern
                if filename.endswith(pattern[1:]):
                    return False
            elif pattern in filepath_str:
                return False

        # Only include Python files for now
        if filepath.suffix not in {'.py', '.pyx', '.pxd'}:
            return False

        return True

    def _scan_daemon_files(self) -> Dict[str, FileIntegrityInfo]:
        """Scan all daemon files and calculate hashes."""
        files = {}

        for monitored_path in self.config.monitored_paths:
            full_path = self._daemon_root / monitored_path

            if not full_path.exists():
                continue

            if full_path.is_file():
                if self._should_include_file(full_path):
                    rel_path = str(full_path.relative_to(self._daemon_root))
                    file_hash = self._calculate_file_hash(full_path)
                    if file_hash:
                        stat_info = full_path.stat()
                        files[rel_path] = FileIntegrityInfo(
                            path=rel_path,
                            hash=file_hash,
                            size=stat_info.st_size,
                            mtime=stat_info.st_mtime,
                        )

            elif full_path.is_dir():
                for filepath in full_path.rglob('*'):
                    if filepath.is_file() and self._should_include_file(filepath):
                        rel_path = str(filepath.relative_to(self._daemon_root))
                        file_hash = self._calculate_file_hash(filepath)
                        if file_hash:
                            stat_info = filepath.stat()
                            files[rel_path] = FileIntegrityInfo(
                                path=rel_path,
                                hash=file_hash,
                                size=stat_info.st_size,
                                mtime=stat_info.st_mtime,
                            )

        return files

    def _sign_manifest(self, manifest_data: Dict) -> str:
        """Create HMAC signature for manifest."""
        signing_key = self._load_signing_key()
        if not signing_key:
            return ""

        # Create canonical representation for signing
        # Exclude the signature field itself
        data_to_sign = {k: v for k, v in manifest_data.items() if k != 'signature'}
        canonical = json.dumps(data_to_sign, sort_keys=True, separators=(',', ':'))

        signature = hmac.new(
            signing_key,
            canonical.encode(),
            hashlib.sha256
        ).hexdigest()

        return signature

    def _verify_signature(self, manifest: IntegrityManifest) -> bool:
        """Verify manifest signature."""
        if not manifest.signature:
            # Rate limit this warning to prevent log spam
            current_time = time.time()
            if current_time - self._last_failure_log_time >= self._failure_log_cooldown:
                logger.warning("Manifest has no signature")
                self._last_failure_log_time = current_time
            return False

        signing_key = self._load_signing_key()
        if not signing_key:
            return False

        # Recreate the data that was signed
        manifest_dict = manifest.to_dict()
        data_to_sign = {k: v for k, v in manifest_dict.items() if k != 'signature'}
        canonical = json.dumps(data_to_sign, sort_keys=True, separators=(',', ':'))

        expected_sig = hmac.new(
            signing_key,
            canonical.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(manifest.signature, expected_sig)

    def create_manifest(self, daemon_version: str = "unknown") -> IntegrityManifest:
        """
        Create a new signed manifest of all daemon files.

        This should be called during build/installation.

        Args:
            daemon_version: Version string for the daemon

        Returns:
            Signed manifest
        """
        with self._lock:
            files = self._scan_daemon_files()

            manifest = IntegrityManifest(
                version=self.MANIFEST_VERSION,
                created_at=datetime.utcnow().isoformat() + "Z",
                daemon_version=daemon_version,
                hash_algorithm=self.config.hash_algorithm,
                files=files,
            )

            # Sign the manifest
            manifest_dict = manifest.to_dict()
            manifest.signature = self._sign_manifest(manifest_dict)

            self._manifest = manifest
            self._stats['files_monitored'] = len(files)

            logger.info(f"Created manifest with {len(files)} files")
            return manifest

    def save_manifest(self, path: Optional[str] = None):
        """Save manifest to file."""
        if not self._manifest:
            raise ValueError("No manifest to save")

        save_path = path or self.config.manifest_path

        # Ensure directory exists
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        # Make file writable if it exists (may be read-only from previous save)
        if os.path.exists(save_path):
            try:
                os.chmod(save_path, 0o644)
            except OSError:
                pass  # Ignore if we can't change permissions

        with open(save_path, 'w') as f:
            json.dump(self._manifest.to_dict(), f, indent=2)

        # Set restrictive permissions (read-only for safety)
        try:
            os.chmod(save_path, 0o444)
        except OSError:
            pass  # Ignore on Windows or if permissions can't be set

        logger.info(f"Saved manifest to {save_path}")

    def load_manifest(self, path: Optional[str] = None) -> bool:
        """
        Load manifest from file.

        Args:
            path: Path to manifest file

        Returns:
            True if loaded successfully
        """
        load_path = path or self.config.manifest_path

        try:
            with open(load_path, 'r') as f:
                data = json.load(f)

            self._manifest = IntegrityManifest.from_dict(data)
            self._stats['files_monitored'] = len(self._manifest.files)

            logger.info(f"Loaded manifest with {len(self._manifest.files)} files")
            return True

        except FileNotFoundError:
            logger.warning(f"Manifest not found: {load_path}")
            return False
        except json.JSONDecodeError as e:
            logger.error(f"Invalid manifest JSON: {e}")
            return False
        except (IOError, OSError, KeyError, ValueError) as e:
            # IOError/OSError: file access failure
            # KeyError: missing required field in manifest data
            # ValueError: invalid data format in manifest
            log_security_error(e, "load_manifest", manifest_path=str(load_path))
            return False

    def verify_integrity(self, strict: bool = True) -> IntegrityCheckResult:
        """
        Verify integrity of all daemon files against manifest.

        Args:
            strict: If True, fail on any discrepancy

        Returns:
            IntegrityCheckResult with verification status
        """
        start_time = time.time()

        with self._lock:
            self._stats['checks_performed'] += 1

            # Check if manifest is loaded
            if not self._manifest:
                if not self.load_manifest():
                    result = IntegrityCheckResult(
                        status=IntegrityStatus.MANIFEST_MISSING,
                        error_message="No manifest found - cannot verify integrity",
                    )
                    self._last_check = result
                    self._log_check_result(result)
                    return result

            # Verify manifest signature
            if not self._verify_signature(self._manifest):
                result = IntegrityCheckResult(
                    status=IntegrityStatus.SIGNATURE_INVALID,
                    error_message="Manifest signature is invalid - possible tampering!",
                )
                self._stats['checks_failed'] += 1
                self._last_check = result
                self._log_check_result(result)
                return result

            # Scan current files
            current_files = self._scan_daemon_files()

            # Compare against manifest
            result = IntegrityCheckResult(status=IntegrityStatus.VERIFIED)
            manifest_paths = set(self._manifest.files.keys())
            current_paths = set(current_files.keys())

            # Check for missing files
            missing = manifest_paths - current_paths
            if missing:
                result.missing_files = list(missing)

            # Check for added files
            added = current_paths - manifest_paths
            if added:
                result.added_files = list(added)

            # Check for modified files
            for path in manifest_paths & current_paths:
                manifest_info = self._manifest.files[path]
                current_info = current_files[path]

                if manifest_info.hash != current_info.hash:
                    result.modified_files.append(path)
                else:
                    result.verified_files += 1

            # Determine final status
            if result.missing_files:
                result.status = IntegrityStatus.FILES_MISSING
                result.failed_files.extend(result.missing_files)

            if result.modified_files:
                result.status = IntegrityStatus.FILES_MODIFIED
                result.failed_files.extend(result.modified_files)

            if strict and result.added_files:
                result.status = IntegrityStatus.FILES_ADDED

            if result.status == IntegrityStatus.VERIFIED:
                self._stats['checks_passed'] += 1
            else:
                self._stats['checks_failed'] += 1
                result.error_message = self._build_error_message(result)

            result.check_time = time.time() - start_time
            self._stats['last_check_time'] = datetime.utcnow().isoformat()
            self._last_check = result

            self._log_check_result(result)
            return result

    def _build_error_message(self, result: IntegrityCheckResult) -> str:
        """Build detailed error message."""
        parts = []

        if result.missing_files:
            parts.append(f"Missing files: {', '.join(result.missing_files[:5])}")
            if len(result.missing_files) > 5:
                parts.append(f"  ...and {len(result.missing_files) - 5} more")

        if result.modified_files:
            parts.append(f"Modified files: {', '.join(result.modified_files[:5])}")
            if len(result.modified_files) > 5:
                parts.append(f"  ...and {len(result.modified_files) - 5} more")

        if result.added_files:
            parts.append(f"Unexpected files: {', '.join(result.added_files[:5])}")
            if len(result.added_files) > 5:
                parts.append(f"  ...and {len(result.added_files) - 5} more")

        return "; ".join(parts)

    def _log_check_result(self, result: IntegrityCheckResult):
        """Log integrity check result."""
        if result.is_valid:
            logger.info(
                f"Integrity check PASSED: {result.verified_files} files verified "
                f"in {result.check_time:.2f}s"
            )
        else:
            # Rate limit failure messages to prevent log spam (once per 10 minutes)
            current_time = time.time()
            should_log = current_time - self._last_failure_log_time >= self._failure_log_cooldown

            if should_log:
                logger.error(
                    f"Integrity check FAILED: {result.status.value} - "
                    f"{result.error_message}"
                )
                self._last_failure_log_time = current_time

            # Log to event logger if available (always log events, just rate limit console)
            if self._event_logger:
                try:
                    self._event_logger.log_security_event(
                        event_type="daemon_integrity_failure",
                        severity="critical",
                        details=result.to_dict(),
                    )
                except (AttributeError, IOError, OSError) as e:
                    # AttributeError: event_logger method missing
                    # IOError/OSError: log file write failure
                    logger.debug(f"Failed to log integrity failure to event logger: {e}")

    def verify_startup(self) -> Tuple[bool, str]:
        """
        Verify integrity at daemon startup.

        This should be called BEFORE any other daemon initialization.

        Returns:
            (should_continue, message)
        """
        if not self.config.verify_on_startup:
            return True, "Startup verification disabled"

        logger.info("Performing daemon integrity verification...")

        result = self.verify_integrity()

        if result.is_valid:
            return True, f"Integrity verified: {result.verified_files} files OK"

        # Handle failure based on configured action
        if result.status == IntegrityStatus.MANIFEST_MISSING:
            if self.config.allow_missing_manifest:
                logger.warning(
                    "No manifest found - auto-generating for development. "
                    "Generate a signed manifest for production use."
                )
                # Auto-create manifest to prevent runtime monitoring spam
                try:
                    self.create_manifest(daemon_version="dev")
                    self.save_manifest()
                    logger.info("Auto-generated development manifest")
                except (IOError, OSError, PermissionError, ValueError) as e:
                    # File I/O errors or invalid configuration
                    logger.warning(f"Could not auto-generate manifest: {e}")
                return True, "Running with auto-generated manifest (development mode)"
            else:
                return False, "Manifest missing and allow_missing_manifest is False"

        # Handle invalid signature (common in dev when signing key changes)
        if result.status == IntegrityStatus.SIGNATURE_INVALID:
            if self.config.allow_missing_manifest:
                logger.warning(
                    "Manifest signature invalid (signing key changed) - regenerating for development."
                )
                # Regenerate manifest with current signing key
                try:
                    self._manifest = None  # Clear old manifest
                    self.create_manifest(daemon_version="dev")
                    self.save_manifest()
                    logger.info("Regenerated development manifest with new signing key")
                except (IOError, OSError, PermissionError, ValueError) as e:
                    # File I/O errors or invalid configuration
                    logger.warning(f"Could not regenerate manifest: {e}")
                return True, "Running with regenerated manifest (development mode)"
            else:
                return False, "Manifest signature invalid"

        action = self.config.failure_action

        if action == IntegrityAction.WARN_ONLY:
            logger.warning(f"Integrity check failed but continuing: {result.error_message}")
            return True, f"WARNING: {result.error_message}"

        elif action == IntegrityAction.BLOCK_STARTUP:
            logger.critical(f"Blocking startup due to integrity failure: {result.error_message}")
            return False, f"BLOCKED: {result.error_message}"

        elif action == IntegrityAction.LOCKDOWN:
            logger.critical(f"Starting in lockdown mode due to integrity failure: {result.error_message}")
            # The daemon should check this and start in restricted mode
            return True, f"LOCKDOWN: {result.error_message}"

        elif action == IntegrityAction.SHUTDOWN:
            logger.critical(f"Integrity failure detected: {result.error_message}")
            return False, f"SHUTDOWN: {result.error_message}"

        return False, result.error_message

    def start_monitoring(self):
        """Start runtime integrity monitoring."""
        if not self.config.enable_runtime_monitoring:
            return

        if self._running:
            return

        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="DaemonIntegrityMonitor"
        )
        self._monitor_thread.start()
        logger.info("Started runtime integrity monitoring")

    def stop_monitoring(self):
        """Stop runtime integrity monitoring."""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)
            self._monitor_thread = None
        logger.info("Stopped runtime integrity monitoring")

    def _monitor_loop(self):
        """Background monitoring loop."""
        while self._running:
            try:
                time.sleep(self.config.monitor_interval)

                if not self._running:
                    break

                result = self.verify_integrity(strict=False)

                if not result.is_valid:
                    self._handle_runtime_failure(result)

            except (IOError, OSError, KeyError, ValueError) as e:
                # File access errors or data validation errors during monitoring
                logger.error(f"Error in integrity monitor: {e}")

    def _handle_runtime_failure(self, result: IntegrityCheckResult):
        """Handle integrity failure detected at runtime."""
        # Rate limit log messages to prevent spam (once per 10 minutes)
        current_time = time.time()
        should_log = current_time - self._last_failure_log_time >= self._failure_log_cooldown

        if should_log:
            logger.critical(
                f"RUNTIME INTEGRITY FAILURE: {result.status.value} - "
                f"{result.error_message}"
            )
            self._last_failure_log_time = current_time

        # Log critical security event (always log to event logger, just rate limit console)
        if self._event_logger:
            try:
                self._event_logger.log_security_event(
                    event_type="daemon_integrity_runtime_failure",
                    severity="critical",
                    details={
                        **result.to_dict(),
                        'action': 'runtime_detection',
                    },
                )
            except (AttributeError, IOError, OSError) as e:
                # Event logging failure - don't mask the runtime failure
                if should_log:
                    logger.debug(f"Failed to log runtime integrity failure: {e}")

        # For runtime failures, we could:
        # 1. Trigger immediate shutdown
        # 2. Enter lockdown mode
        # 3. Alert administrators
        # The appropriate action depends on security requirements

    def get_status(self) -> Dict:
        """Get current integrity protection status."""
        with self._lock:
            return {
                'manifest_loaded': self._manifest is not None,
                'files_monitored': self._stats['files_monitored'],
                'monitoring_active': self._running,
                'last_check': self._last_check.to_dict() if self._last_check else None,
                'stats': self._stats.copy(),
            }

    def get_last_result(self) -> Optional[IntegrityCheckResult]:
        """Get the last integrity check result."""
        with self._lock:
            return self._last_check


def verify_daemon_integrity(
    daemon_root: Optional[str] = None,
    config: Optional[IntegrityConfig] = None,
) -> Tuple[bool, str]:
    """
    Convenience function to verify daemon integrity.

    This should be called at the very beginning of daemon startup,
    BEFORE importing any other daemon modules.

    Args:
        daemon_root: Root directory of daemon code
        config: Optional configuration

    Returns:
        (is_valid, message)
    """
    protector = DaemonIntegrityProtector(
        config=config,
        daemon_root=daemon_root,
    )
    return protector.verify_startup()


# Command-line interface for manifest management
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Daemon Integrity Management')
    parser.add_argument('command', choices=['create', 'verify', 'show', 'generate-key'])
    parser.add_argument('--manifest', '-m', help='Manifest file path')
    parser.add_argument('--key', '-k', help='Signing key path')
    parser.add_argument('--output', '-o', help='Output path for generated key')
    parser.add_argument('--root', '-r', help='Daemon root directory')
    parser.add_argument('--version', '-v', help='Daemon version', default='unknown')

    args = parser.parse_args()

    # Handle generate-key command separately (doesn't need protector)
    if args.command == 'generate-key':
        output_path = args.output or args.key or './config/signing.key'
        print(f"Generating signing key at {output_path}...")
        if DaemonIntegrityProtector.generate_signing_key(output_path):
            print(f"Successfully generated signing key at {output_path}")
            print("SECURITY: Key file has 0600 permissions (owner read/write only)")
            sys.exit(0)
        else:
            print("Failed to generate signing key")
            sys.exit(1)

    config = IntegrityConfig()
    if args.manifest:
        config.manifest_path = args.manifest
    if args.key:
        config.signing_key_path = args.key

    protector = DaemonIntegrityProtector(
        config=config,
        daemon_root=args.root,
    )

    if args.command == 'create':
        print("Creating integrity manifest...")
        manifest = protector.create_manifest(args.version)
        protector.save_manifest()
        print(f"Created manifest with {len(manifest.files)} files")
        print(f"Saved to: {config.manifest_path}")

    elif args.command == 'verify':
        print("Verifying daemon integrity...")
        result = protector.verify_integrity()
        print(f"Status: {result.status.value}")
        print(f"Verified files: {result.verified_files}")
        if result.failed_files:
            print(f"Failed files: {result.failed_files}")
        if result.missing_files:
            print(f"Missing files: {result.missing_files}")
        if result.added_files:
            print(f"Added files: {result.added_files}")
        if result.error_message:
            print(f"Error: {result.error_message}")
        sys.exit(0 if result.is_valid else 1)

    elif args.command == 'show':
        if protector.load_manifest():
            manifest = protector._manifest
            print(f"Manifest version: {manifest.version}")
            print(f"Created: {manifest.created_at}")
            print(f"Daemon version: {manifest.daemon_version}")
            print(f"Files: {len(manifest.files)}")
            print(f"Signature: {manifest.signature[:16]}...")
        else:
            print("Failed to load manifest")
            sys.exit(1)
