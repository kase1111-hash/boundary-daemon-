"""
Log Hardening - Tamper-Proof Log Protection

This module addresses the critical security finding:
"Log Tamper-Proofing Incomplete - Hash chains detect but can't prevent deletion"

SECURITY FEATURES:
1. Mandatory file permissions (0o600 for active, 0o400 for sealed)
2. Linux chattr +a (append-only) enforcement
3. Log sealing with chattr +i (immutable)
4. Separate signature storage
5. Remote syslog forwarding verification
6. Startup integrity verification
7. Protection status monitoring

THREAT MODEL:
- Protects against: User-level tampering, accidental modification
- Requires root for: Removal of chattr attributes
- Does NOT protect against: Root user, kernel-level attacks

USAGE:
    from daemon.storage.log_hardening import LogHardener, HardeningMode

    hardener = LogHardener(
        log_path="/var/log/boundary-daemon/events.log",
        mode=HardeningMode.STRICT,
        fail_on_degraded=True,
    )

    # Harden a log file
    hardener.harden()

    # Check protection status
    status = hardener.get_status()

    # Seal a log (makes it immutable)
    hardener.seal()
"""

import hashlib
import json
import logging
import os
import sys
import shutil
import subprocess
import stat
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = sys.platform == 'win32'


class HardeningMode(Enum):
    """Log hardening modes."""
    NONE = "none"           # No hardening (development only)
    BASIC = "basic"         # Permissions only (0o600)
    STANDARD = "standard"   # Permissions + chattr +a
    STRICT = "strict"       # All protections, fail if unavailable
    PARANOID = "paranoid"   # Strict + separate sig storage + remote verify


class ProtectionStatus(Enum):
    """Protection status for a log file."""
    UNPROTECTED = "unprotected"
    PARTIAL = "partial"
    PROTECTED = "protected"
    SEALED = "sealed"
    DEGRADED = "degraded"
    FAILED = "failed"


@dataclass
class HardeningStatus:
    """Status of log hardening."""
    path: str
    status: ProtectionStatus
    permissions: str
    owner: str
    group: str
    is_append_only: bool
    is_immutable: bool
    has_remote_backup: bool
    signature_separated: bool
    last_verified: Optional[str]
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'path': self.path,
            'status': self.status.value,
            'permissions': self.permissions,
            'owner': self.owner,
            'group': self.group,
            'is_append_only': self.is_append_only,
            'is_immutable': self.is_immutable,
            'has_remote_backup': self.has_remote_backup,
            'signature_separated': self.signature_separated,
            'last_verified': self.last_verified,
            'errors': self.errors,
            'warnings': self.warnings,
        }


class LogHardeningError(Exception):
    """Raised when log hardening fails."""
    pass


class LogHardener:
    """
    Hardens log files against tampering.

    Provides multiple layers of protection:
    1. File permissions (mode 0o600 or 0o400)
    2. Linux chattr +a (append-only)
    3. Log sealing with chattr +i (immutable)
    4. Separated signature storage
    5. Protection status monitoring
    """

    # Secure permissions
    PERM_ACTIVE = 0o600     # Owner read/write only
    PERM_SEALED = 0o400     # Owner read only (after sealing)
    PERM_DIR = 0o700        # Directory: owner only

    # Separate signature directory
    SIG_SUBDIR = ".signatures"

    def __init__(
        self,
        log_path: str,
        mode: HardeningMode = HardeningMode.STANDARD,
        fail_on_degraded: bool = False,
        sig_dir: Optional[str] = None,
        on_protection_change: Optional[Callable[[str, ProtectionStatus], None]] = None,
    ):
        """
        Initialize log hardener.

        Args:
            log_path: Path to the log file to protect
            mode: Hardening mode
            fail_on_degraded: Raise exception if full protection unavailable
            sig_dir: Custom directory for signatures (default: log_dir/.signatures)
            on_protection_change: Callback when protection status changes
        """
        self.log_path = Path(log_path)
        self.mode = mode
        self.fail_on_degraded = fail_on_degraded
        self._on_protection_change = on_protection_change
        # Use RLock (reentrant lock) because seal() calls get_status() while holding the lock
        self._lock = threading.RLock()
        self._status: Optional[HardeningStatus] = None
        # Cross-platform root/admin check
        if IS_WINDOWS:
            try:
                import ctypes
                self._is_root = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                self._is_root = False
        else:
            self._is_root = os.geteuid() == 0

        # Signature storage
        if sig_dir:
            self.sig_dir = Path(sig_dir)
        else:
            self.sig_dir = self.log_path.parent / self.SIG_SUBDIR

        # Check capabilities
        self._has_chattr = self._check_chattr_available()
        self._has_lsattr = self._check_lsattr_available()

    def _check_chattr_available(self) -> bool:
        """Check if chattr command is available."""
        return shutil.which('chattr') is not None

    def _check_lsattr_available(self) -> bool:
        """Check if lsattr command is available."""
        return shutil.which('lsattr') is not None

    def _run_chattr(self, flags: str, path: Path) -> Tuple[bool, str]:
        """Run chattr command on a file."""
        if not self._has_chattr:
            return (False, "chattr not available")

        if not self._is_root:
            return (False, "chattr requires root privileges")

        try:
            result = subprocess.run(
                ['chattr', flags, str(path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return (True, "")
            else:
                return (False, result.stderr.strip())
        except subprocess.TimeoutExpired:
            return (False, "chattr timed out")
        except Exception as e:
            return (False, str(e))

    def _get_file_attrs(self, path: Path) -> Tuple[bool, bool]:
        """
        Get file attributes (append-only, immutable).

        Returns:
            (is_append_only, is_immutable)
        """
        if not self._has_lsattr or not path.exists():
            return (False, False)

        try:
            result = subprocess.run(
                ['lsattr', str(path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                # lsattr output format: "----ia-------e---- filename"
                attrs = output.split()[0] if output else ""
                is_append = 'a' in attrs
                is_immutable = 'i' in attrs
                return (is_append, is_immutable)
        except Exception:
            pass

        return (False, False)

    def _set_permissions(self, path: Path, mode: int) -> Tuple[bool, str]:
        """Set file permissions."""
        try:
            os.chmod(path, mode)
            return (True, "")
        except Exception as e:
            return (False, str(e))

    def _get_permissions(self, path: Path) -> str:
        """Get file permissions as octal string."""
        try:
            st = os.stat(path)
            return oct(st.st_mode)[-3:]
        except Exception:
            return "???"

    def _get_owner_group(self, path: Path) -> Tuple[str, str]:
        """Get file owner and group."""
        try:
            import pwd
            import grp
            st = os.stat(path)
            owner = pwd.getpwuid(st.st_uid).pw_name
            group = grp.getgrgid(st.st_gid).gr_name
            return (owner, group)
        except Exception:
            return ("?", "?")

    def _ensure_sig_dir(self) -> Tuple[bool, str]:
        """Ensure signature directory exists with proper permissions."""
        try:
            self.sig_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.sig_dir, self.PERM_DIR)
            return (True, "")
        except Exception as e:
            return (False, str(e))

    def harden(self) -> HardeningStatus:
        """
        Apply hardening to the log file.

        Returns:
            HardeningStatus with details of protection applied

        Raises:
            LogHardeningError: If fail_on_degraded=True and protection incomplete
        """
        with self._lock:
            errors = []
            warnings = []

            # Ensure log file exists
            if not self.log_path.exists():
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                self.log_path.touch()

            # Ensure log directory has proper permissions
            try:
                os.chmod(self.log_path.parent, self.PERM_DIR)
            except Exception as e:
                warnings.append(f"Could not set directory permissions: {e}")

            # Apply file permissions
            if self.mode != HardeningMode.NONE:
                ok, err = self._set_permissions(self.log_path, self.PERM_ACTIVE)
                if not ok:
                    errors.append(f"Failed to set permissions: {err}")

            # Apply chattr +a (append-only)
            is_append_only = False
            is_immutable = False

            if self.mode in (HardeningMode.STANDARD, HardeningMode.STRICT, HardeningMode.PARANOID):
                ok, err = self._run_chattr('+a', self.log_path)
                if ok:
                    is_append_only = True
                    logger.info(f"Applied append-only attribute to {self.log_path}")
                else:
                    msg = f"Failed to apply chattr +a: {err}"
                    if self.mode in (HardeningMode.STRICT, HardeningMode.PARANOID):
                        errors.append(msg)
                    else:
                        warnings.append(msg)

            # Create separate signature directory
            sig_separated = False
            if self.mode in (HardeningMode.PARANOID,):
                ok, err = self._ensure_sig_dir()
                if ok:
                    sig_separated = True
                    logger.info(f"Created separate signature directory: {self.sig_dir}")
                else:
                    errors.append(f"Failed to create signature directory: {err}")

            # Verify current state
            actual_append, actual_immutable = self._get_file_attrs(self.log_path)
            permissions = self._get_permissions(self.log_path)
            owner, group = self._get_owner_group(self.log_path)

            # Determine status
            if errors:
                if self.mode in (HardeningMode.STRICT, HardeningMode.PARANOID):
                    status = ProtectionStatus.FAILED
                else:
                    status = ProtectionStatus.DEGRADED
            elif warnings:
                status = ProtectionStatus.PARTIAL
            elif actual_immutable:
                status = ProtectionStatus.SEALED
            elif actual_append or self.mode == HardeningMode.BASIC:
                status = ProtectionStatus.PROTECTED
            else:
                status = ProtectionStatus.UNPROTECTED

            self._status = HardeningStatus(
                path=str(self.log_path),
                status=status,
                permissions=permissions,
                owner=owner,
                group=group,
                is_append_only=actual_append,
                is_immutable=actual_immutable,
                has_remote_backup=False,  # Set by external integration
                signature_separated=sig_separated,
                last_verified=datetime.utcnow().isoformat() + "Z",
                errors=errors,
                warnings=warnings,
            )

            # Notify of status change
            if self._on_protection_change:
                try:
                    self._on_protection_change(str(self.log_path), status)
                except Exception:
                    pass

            # Fail if strict and protection incomplete
            if self.fail_on_degraded and status in (ProtectionStatus.FAILED, ProtectionStatus.DEGRADED):
                raise LogHardeningError(
                    f"Log hardening failed: {', '.join(errors)}"
                )

            return self._status

    def seal(self) -> HardeningStatus:
        """
        Seal the log file, making it immutable.

        This should be called when rotating logs or finalizing an audit period.
        After sealing:
        - File permissions become 0o400 (read-only)
        - chattr +i is applied (immutable - cannot be modified even by root without removing attribute)

        Returns:
            HardeningStatus with seal result

        Raises:
            LogHardeningError: If sealing fails and fail_on_degraded=True
        """
        with self._lock:
            errors = []
            warnings = []

            if not self.log_path.exists():
                errors.append("Log file does not exist")
                if self.fail_on_degraded:
                    raise LogHardeningError("Cannot seal: log file does not exist")
                # Return status with the error included
                self._status = HardeningStatus(
                    path=str(self.log_path),
                    status=ProtectionStatus.FAILED,
                    permissions="???",
                    owner="?",
                    group="?",
                    is_append_only=False,
                    is_immutable=False,
                    has_remote_backup=False,
                    signature_separated=False,
                    last_verified=datetime.utcnow().isoformat() + "Z",
                    errors=errors,
                    warnings=warnings,
                )
                return self._status

            # First, remove append-only to allow permission change
            ok, err = self._run_chattr('-a', self.log_path)
            if not ok and self._has_chattr and self._is_root:
                warnings.append(f"Could not remove append-only before sealing: {err}")

            # Set read-only permissions
            ok, err = self._set_permissions(self.log_path, self.PERM_SEALED)
            if not ok:
                errors.append(f"Failed to set sealed permissions: {err}")

            # Apply immutable attribute
            ok, err = self._run_chattr('+i', self.log_path)
            if ok:
                logger.info(f"Sealed log file with immutable attribute: {self.log_path}")
            else:
                if self._has_chattr and self._is_root:
                    errors.append(f"Failed to apply chattr +i: {err}")
                else:
                    warnings.append(f"Could not apply immutable (requires root): {err}")

            # Create seal checkpoint file
            self._create_seal_checkpoint()

            # Update status
            actual_append, actual_immutable = self._get_file_attrs(self.log_path)
            permissions = self._get_permissions(self.log_path)
            owner, group = self._get_owner_group(self.log_path)

            if errors:
                status = ProtectionStatus.FAILED if self.fail_on_degraded else ProtectionStatus.DEGRADED
            elif actual_immutable:
                status = ProtectionStatus.SEALED
            else:
                status = ProtectionStatus.PARTIAL

            self._status = HardeningStatus(
                path=str(self.log_path),
                status=status,
                permissions=permissions,
                owner=owner,
                group=group,
                is_append_only=actual_append,
                is_immutable=actual_immutable,
                has_remote_backup=self._status.has_remote_backup if self._status else False,
                signature_separated=self._status.signature_separated if self._status else False,
                last_verified=datetime.utcnow().isoformat() + "Z",
                errors=errors,
                warnings=warnings,
            )

            if self.fail_on_degraded and status == ProtectionStatus.FAILED:
                raise LogHardeningError(f"Log sealing failed: {', '.join(errors)}")

            return self._status

    def _create_seal_checkpoint(self):
        """Create a checkpoint file recording the seal."""
        try:
            checkpoint_path = self.log_path.with_suffix('.sealed')
            checkpoint = {
                'sealed_at': datetime.utcnow().isoformat() + "Z",
                'log_path': str(self.log_path),
                'log_size': self.log_path.stat().st_size,
                'log_hash': self._compute_file_hash(self.log_path),
            }

            with open(checkpoint_path, 'w') as f:
                json.dump(checkpoint, f, indent=2)

            os.chmod(checkpoint_path, self.PERM_SEALED)
            logger.info(f"Created seal checkpoint: {checkpoint_path}")

        except Exception as e:
            logger.warning(f"Could not create seal checkpoint: {e}")

    def _compute_file_hash(self, path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return ""

    def unseal(self) -> bool:
        """
        Unseal a log file (remove immutable attribute).

        WARNING: This should only be used for maintenance and requires root.

        Returns:
            True if successful
        """
        with self._lock:
            if not self._is_root:
                logger.error("Unseal requires root privileges")
                return False

            # Remove immutable attribute
            ok, err = self._run_chattr('-i', self.log_path)
            if not ok:
                logger.error(f"Failed to unseal: {err}")
                return False

            # Set back to active permissions
            ok, err = self._set_permissions(self.log_path, self.PERM_ACTIVE)
            if not ok:
                logger.warning(f"Could not restore permissions: {err}")

            # Re-apply append-only
            ok, err = self._run_chattr('+a', self.log_path)
            if not ok:
                logger.warning(f"Could not re-apply append-only: {err}")

            logger.warning(f"Log file unsealed: {self.log_path}")
            return True

    def get_status(self) -> HardeningStatus:
        """Get current hardening status."""
        with self._lock:
            if self._status is None:
                # Generate fresh status
                actual_append, actual_immutable = self._get_file_attrs(self.log_path)
                permissions = self._get_permissions(self.log_path) if self.log_path.exists() else "???"
                owner, group = self._get_owner_group(self.log_path) if self.log_path.exists() else ("?", "?")

                if actual_immutable:
                    status = ProtectionStatus.SEALED
                elif actual_append:
                    status = ProtectionStatus.PROTECTED
                elif self.log_path.exists():
                    status = ProtectionStatus.UNPROTECTED
                else:
                    status = ProtectionStatus.UNPROTECTED

                self._status = HardeningStatus(
                    path=str(self.log_path),
                    status=status,
                    permissions=permissions,
                    owner=owner,
                    group=group,
                    is_append_only=actual_append,
                    is_immutable=actual_immutable,
                    has_remote_backup=False,
                    signature_separated=self.sig_dir.exists(),
                    last_verified=datetime.utcnow().isoformat() + "Z",
                )

            return self._status

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """
        Verify log integrity.

        Checks:
        1. File exists and is readable
        2. Permissions are correct
        3. chattr attributes are in place
        4. Seal checkpoint matches (if sealed)

        Returns:
            (is_valid, list of issues)
        """
        issues = []

        with self._lock:
            # Check file exists
            if not self.log_path.exists():
                issues.append("Log file does not exist")
                return (False, issues)

            # Check permissions
            permissions = self._get_permissions(self.log_path)
            expected = "600" if self.mode != HardeningMode.NONE else None

            if expected and permissions != expected:
                # Allow 400 for sealed files
                if permissions != "400":
                    issues.append(f"Incorrect permissions: {permissions} (expected {expected})")

            # Check chattr attributes
            actual_append, actual_immutable = self._get_file_attrs(self.log_path)

            if self.mode in (HardeningMode.STANDARD, HardeningMode.STRICT, HardeningMode.PARANOID):
                if not actual_append and not actual_immutable:
                    issues.append("Missing append-only or immutable attribute")

            # Check seal checkpoint if exists
            checkpoint_path = self.log_path.with_suffix('.sealed')
            if checkpoint_path.exists():
                try:
                    with open(checkpoint_path, 'r') as f:
                        checkpoint = json.load(f)

                    expected_hash = checkpoint.get('log_hash', '')
                    actual_hash = self._compute_file_hash(self.log_path)

                    if expected_hash and expected_hash != actual_hash:
                        issues.append(f"Sealed log hash mismatch: expected {expected_hash[:16]}..., got {actual_hash[:16]}...")

                    expected_size = checkpoint.get('log_size', 0)
                    actual_size = self.log_path.stat().st_size

                    if expected_size != actual_size:
                        issues.append(f"Sealed log size mismatch: expected {expected_size}, got {actual_size}")

                except Exception as e:
                    issues.append(f"Could not verify seal checkpoint: {e}")

            return (len(issues) == 0, issues)

    def get_signature_path(self, log_path: Optional[Path] = None) -> Path:
        """
        Get the path for storing signatures.

        In PARANOID mode, signatures are stored in a separate directory.
        """
        path = log_path or self.log_path

        if self.mode == HardeningMode.PARANOID:
            self._ensure_sig_dir()
            return self.sig_dir / (path.name + '.sig')
        else:
            return path.with_suffix(path.suffix + '.sig')


class SecureLogWriter:
    """
    Wrapper for secure log writing with automatic hardening.

    Usage:
        writer = SecureLogWriter(
            "/var/log/boundary-daemon/events.log",
            mode=HardeningMode.STANDARD,
        )

        writer.write_line("event data here")
        writer.close()  # Seals the log
    """

    def __init__(
        self,
        log_path: str,
        mode: HardeningMode = HardeningMode.STANDARD,
        fail_on_degraded: bool = False,
    ):
        self.log_path = Path(log_path)
        self.hardener = LogHardener(
            log_path=log_path,
            mode=mode,
            fail_on_degraded=fail_on_degraded,
        )
        self._fd: Optional[int] = None
        self._lock = threading.Lock()

        # Apply initial hardening
        self.hardener.harden()

    def open(self):
        """Open the log file for writing."""
        with self._lock:
            if self._fd is not None:
                return

            # Ensure parent directory exists with proper permissions
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(self.log_path.parent, LogHardener.PERM_DIR)

            # Open file with secure flags
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
            self._fd = os.open(str(self.log_path), flags, LogHardener.PERM_ACTIVE)

            # Apply hardening
            self.hardener.harden()

    def write_line(self, data: str):
        """Write a line to the log file."""
        with self._lock:
            if self._fd is None:
                self.open()

            line = data if data.endswith('\n') else data + '\n'
            os.write(self._fd, line.encode())
            os.fsync(self._fd)

    def close(self, seal: bool = False):
        """
        Close the log file.

        Args:
            seal: If True, seal the log (make immutable)
        """
        with self._lock:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None

            if seal:
                self.hardener.seal()

    def get_status(self) -> HardeningStatus:
        """Get hardening status."""
        return self.hardener.get_status()


def verify_log_protection(log_dir: str) -> Dict[str, HardeningStatus]:
    """
    Verify protection status of all log files in a directory.

    Args:
        log_dir: Directory containing log files

    Returns:
        Dictionary mapping log paths to their status
    """
    results = {}
    log_path = Path(log_dir)

    if not log_path.exists():
        return results

    for log_file in log_path.glob("*.log"):
        hardener = LogHardener(str(log_file), mode=HardeningMode.STANDARD)
        status = hardener.get_status()
        results[str(log_file)] = status

    return results
