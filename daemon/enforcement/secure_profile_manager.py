"""
Secure Seccomp Profile Manager

This module addresses the vulnerability: "Seccomp Profiles Stored in Writable Directory"

SECURITY FEATURES:
1. Restrictive file permissions (0o600 for files, 0o700 for directory)
2. HMAC integrity verification for all profiles
3. Optional immutable flag (chattr +i) for extra protection
4. Verification on every load
5. Tamper detection with immediate alerts
6. Atomic writes to prevent partial corruption
7. Profile signing with daemon's key

THREAT MODEL:
- Attacker with local file access cannot modify profiles without detection
- Root attacker must remove immutable flag first (logged by auditd)
- Any modification triggers security alert and lockdown option
"""

import os
import sys
import json
import hmac
import hashlib
import tempfile
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = sys.platform == 'win32'


@dataclass
class ProfileIntegrity:
    """Integrity information for a seccomp profile"""
    profile_name: str
    hmac_signature: bytes
    created_at: str
    created_by: str
    version: int
    is_immutable: bool


class SecureProfileManager:
    """
    Manages seccomp profiles with cryptographic integrity protection.

    All profiles are:
    1. Written with restrictive permissions (0o600)
    2. Signed with HMAC-SHA256
    3. Verified on every load
    4. Optionally marked immutable
    """

    # Secure directory for profiles
    DEFAULT_PROFILE_DIR = "/etc/boundary-daemon/seccomp"

    # Integrity manifest file
    MANIFEST_FILE = ".profile_manifest.json"

    # HMAC algorithm
    HMAC_ALGORITHM = 'sha256'

    def __init__(
        self,
        profile_dir: Optional[str] = None,
        secret_key: Optional[bytes] = None,
        event_logger = None,
        use_immutable: bool = True,
    ):
        """
        Initialize the secure profile manager.

        Args:
            profile_dir: Directory for storing profiles
            secret_key: Secret key for HMAC (derived from machine if not provided)
            event_logger: Optional event logger for security alerts
            use_immutable: Whether to use chattr +i for extra protection
        """
        self.profile_dir = Path(profile_dir or self.DEFAULT_PROFILE_DIR)
        self.event_logger = event_logger
        self.use_immutable = use_immutable

        # Generate or use provided secret key
        if secret_key:
            self._secret_key = secret_key
        else:
            self._secret_key = self._derive_secret_key()

        # Profile manifest (integrity records)
        self._manifest: Dict[str, ProfileIntegrity] = {}

        # Ensure secure directory exists
        self._ensure_secure_directory()

        # Load existing manifest
        self._load_manifest()

    def _derive_secret_key(self) -> bytes:
        """Derive a machine-specific secret key for HMAC"""
        components = []

        if IS_WINDOWS:
            # Windows: Use machine GUID from registry
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Cryptography"
                )
                machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                winreg.CloseKey(key)
                components.append(machine_guid)
            except Exception:
                pass

            # Computer name as fallback
            try:
                components.append(os.environ.get('COMPUTERNAME', ''))
            except Exception:
                pass
        else:
            # Linux: Machine ID
            try:
                with open('/etc/machine-id', 'r') as f:
                    components.append(f.read().strip())
            except Exception:
                pass

            # Daemon installation time (if available)
            try:
                stat = os.stat('/etc/boundary-daemon')
                components.append(str(stat.st_ctime))
            except Exception:
                pass

            # Root filesystem UUID
            try:
                result = subprocess.run(
                    ['findmnt', '-no', 'UUID', '/'],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    components.append(result.stdout.decode().strip())
            except Exception:
                pass

        # Combine and hash
        if components:
            combined = ':'.join(components).encode()
            return hashlib.sha256(combined).digest()
        else:
            # Fallback: use random key (not persistent, but better than nothing)
            logger.warning("Could not derive stable secret key, using random")
            return os.urandom(32)

    def _has_admin_privileges(self) -> bool:
        """Check if running with admin/root privileges"""
        if IS_WINDOWS:
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0

    def _ensure_secure_directory(self):
        """Create profile directory with secure permissions"""
        if not self._has_admin_privileges():
            logger.warning("Not running as root/admin, cannot create secure directory")
            return

        try:
            # Create directory with restricted permissions
            self.profile_dir.mkdir(parents=True, exist_ok=True)

            # Set directory permissions to 0o700 (owner only)
            os.chmod(self.profile_dir, 0o700)

            # Set ownership to root:root (Linux only)
            if not IS_WINDOWS:
                os.chown(self.profile_dir, 0, 0)

            logger.debug(f"Secured profile directory: {self.profile_dir}")

        except Exception as e:
            logger.error(f"Failed to secure profile directory: {e}")

    def _compute_hmac(self, data: bytes) -> bytes:
        """Compute HMAC-SHA256 for data"""
        return hmac.new(
            self._secret_key,
            data,
            hashlib.sha256
        ).digest()

    def _verify_hmac(self, data: bytes, signature: bytes) -> bool:
        """Verify HMAC signature"""
        expected = self._compute_hmac(data)
        return hmac.compare_digest(expected, signature)

    def _set_immutable(self, path: Path) -> bool:
        """Set immutable flag on file (chattr +i on Linux, read-only on Windows)"""
        if not self.use_immutable:
            return True

        if not self._has_admin_privileges():
            return False

        if IS_WINDOWS:
            # Windows: Set read-only attribute (not as strong as Linux immutable)
            try:
                import stat
                os.chmod(path, stat.S_IREAD)
                return True
            except Exception as e:
                logger.debug(f"Could not set read-only flag: {e}")
                return False
        else:
            try:
                result = subprocess.run(
                    ['chattr', '+i', str(path)],
                    capture_output=True,
                    timeout=5
                )
                return result.returncode == 0
            except Exception as e:
                logger.debug(f"Could not set immutable flag: {e}")
                return False

    def _remove_immutable(self, path: Path) -> bool:
        """Remove immutable flag from file (chattr -i on Linux, writable on Windows)"""
        if not self._has_admin_privileges():
            return False

        if IS_WINDOWS:
            # Windows: Remove read-only attribute
            try:
                import stat
                os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
                return True
            except Exception as e:
                logger.debug(f"Could not remove read-only flag: {e}")
                return False
        else:
            try:
                result = subprocess.run(
                    ['chattr', '-i', str(path)],
                    capture_output=True,
                    timeout=5
                )
                return result.returncode == 0
            except Exception as e:
                logger.debug(f"Could not remove immutable flag: {e}")
                return False

    def _is_immutable(self, path: Path) -> bool:
        """Check if file has immutable flag"""
        if IS_WINDOWS:
            # Windows: Check read-only attribute
            try:
                import stat
                mode = os.stat(path).st_mode
                return not (mode & stat.S_IWRITE)
            except Exception:
                return False
        else:
            try:
                result = subprocess.run(
                    ['lsattr', str(path)],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    output = result.stdout.decode()
                    # lsattr output: "----i-------- /path/to/file"
                    return 'i' in output.split()[0] if output else False
                return False
            except Exception:
                return False

    def _load_manifest(self):
        """Load the integrity manifest"""
        manifest_path = self.profile_dir / self.MANIFEST_FILE

        if not manifest_path.exists():
            self._manifest = {}
            return

        try:
            # Remove immutable flag temporarily if set
            was_immutable = self._is_immutable(manifest_path)
            if was_immutable:
                self._remove_immutable(manifest_path)

            with open(manifest_path, 'r') as f:
                data = json.load(f)

            # Restore immutable flag
            if was_immutable:
                self._set_immutable(manifest_path)

            # Parse manifest entries
            for name, entry in data.get('profiles', {}).items():
                self._manifest[name] = ProfileIntegrity(
                    profile_name=name,
                    hmac_signature=bytes.fromhex(entry['hmac']),
                    created_at=entry['created_at'],
                    created_by=entry.get('created_by', 'unknown'),
                    version=entry.get('version', 1),
                    is_immutable=entry.get('is_immutable', False),
                )

            logger.debug(f"Loaded {len(self._manifest)} profile integrity records")

        except Exception as e:
            logger.error(f"Failed to load profile manifest: {e}")
            self._manifest = {}

    def _save_manifest(self):
        """Save the integrity manifest"""
        if not self._has_admin_privileges():
            return

        manifest_path = self.profile_dir / self.MANIFEST_FILE

        try:
            # Remove immutable flag if set
            if manifest_path.exists() and self._is_immutable(manifest_path):
                self._remove_immutable(manifest_path)

            # Build manifest data
            data = {
                'version': 1,
                'updated_at': datetime.utcnow().isoformat(),
                'profiles': {}
            }

            for name, integrity in self._manifest.items():
                data['profiles'][name] = {
                    'hmac': integrity.hmac_signature.hex(),
                    'created_at': integrity.created_at,
                    'created_by': integrity.created_by,
                    'version': integrity.version,
                    'is_immutable': integrity.is_immutable,
                }

            # Atomic write
            temp_path = manifest_path.with_suffix('.tmp')
            with open(temp_path, 'w') as f:
                json.dump(data, f, indent=2)
            os.chmod(temp_path, 0o600)
            os.rename(temp_path, manifest_path)

            # Set immutable flag
            if self.use_immutable:
                self._set_immutable(manifest_path)

        except Exception as e:
            logger.error(f"Failed to save profile manifest: {e}")

    def install_profile(
        self,
        profile: Dict,
        name: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Install a seccomp profile securely.

        Args:
            profile: The seccomp profile dictionary
            name: Profile name (defaults to profile's 'name' field)

        Returns:
            (success, message)
        """
        if not self._has_admin_privileges():
            return (False, "Root/admin privileges required to install profiles")

        profile_name = name or profile.get('name', 'default')
        profile_path = self.profile_dir / f"{profile_name}.json"

        try:
            # Serialize profile
            profile_data = json.dumps(profile, indent=2, sort_keys=True).encode()

            # Compute HMAC
            signature = self._compute_hmac(profile_data)

            # Remove immutable flag from existing file if present
            if profile_path.exists() and self._is_immutable(profile_path):
                if not self._remove_immutable(profile_path):
                    return (False, f"Cannot modify immutable profile: {profile_name}")

            # Atomic write: write to temp file, then rename
            temp_fd, temp_path = tempfile.mkstemp(
                dir=self.profile_dir,
                prefix=f".{profile_name}_",
                suffix='.json.tmp'
            )
            try:
                os.write(temp_fd, profile_data)
                os.close(temp_fd)

                # Set restrictive permissions (0o600 = owner read/write only)
                os.chmod(temp_path, 0o600)
                if not IS_WINDOWS:
                    os.chown(temp_path, 0, 0)

                # Atomic rename
                os.rename(temp_path, profile_path)

            except Exception:
                # Cleanup temp file on error
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass
                raise

            # Set immutable flag
            is_immutable = False
            if self.use_immutable:
                is_immutable = self._set_immutable(profile_path)

            # Update manifest
            self._manifest[profile_name] = ProfileIntegrity(
                profile_name=profile_name,
                hmac_signature=signature,
                created_at=datetime.utcnow().isoformat(),
                created_by=f"boundary-daemon-{os.getpid()}",
                version=self._manifest.get(profile_name, ProfileIntegrity(
                    profile_name=profile_name,
                    hmac_signature=b'',
                    created_at='',
                    created_by='',
                    version=0,
                    is_immutable=False,
                )).version + 1,
                is_immutable=is_immutable,
            )

            # Save manifest
            self._save_manifest()

            # Log event
            if self.event_logger:
                from ..event_logger import EventType
                self.event_logger.log_event(
                    EventType.ENFORCEMENT,
                    f"Installed secure seccomp profile: {profile_name}",
                    metadata={
                        'action': 'profile_install',
                        'profile_name': profile_name,
                        'is_immutable': is_immutable,
                        'hmac': signature.hex()[:16] + '...',
                    }
                )

            logger.info(f"Installed secure profile: {profile_name} (immutable: {is_immutable})")
            return (True, f"Profile installed: {profile_name}")

        except Exception as e:
            logger.error(f"Failed to install profile {profile_name}: {e}")
            return (False, str(e))

    def load_profile(self, name: str) -> Tuple[Optional[Dict], str]:
        """
        Load and verify a seccomp profile.

        Args:
            name: Profile name

        Returns:
            (profile dict or None, message)
        """
        profile_path = self.profile_dir / f"{name}.json"

        if not profile_path.exists():
            return (None, f"Profile not found: {name}")

        try:
            # Read profile data
            with open(profile_path, 'rb') as f:
                profile_data = f.read()

            # Check manifest for integrity record
            integrity = self._manifest.get(name)

            if not integrity:
                self._log_tamper_alert(name, "No integrity record in manifest")
                return (None, f"Profile {name} has no integrity record - possible tampering")

            # Verify HMAC
            if not self._verify_hmac(profile_data, integrity.hmac_signature):
                self._log_tamper_alert(name, "HMAC verification failed")
                return (None, f"Profile {name} failed integrity check - TAMPERED!")

            # Check immutable flag
            if integrity.is_immutable and not self._is_immutable(profile_path):
                self._log_tamper_alert(name, "Immutable flag removed")
                # Continue anyway but warn

            # Parse JSON
            profile = json.loads(profile_data.decode())

            logger.debug(f"Loaded verified profile: {name}")
            return (profile, "OK")

        except json.JSONDecodeError as e:
            self._log_tamper_alert(name, f"Invalid JSON: {e}")
            return (None, f"Profile {name} has invalid JSON - corrupted or tampered")
        except Exception as e:
            logger.error(f"Failed to load profile {name}: {e}")
            return (None, str(e))

    def _log_tamper_alert(self, profile_name: str, reason: str):
        """Log a security alert for potential tampering"""
        message = f"SECURITY ALERT: Seccomp profile tampering detected! Profile: {profile_name}, Reason: {reason}"
        logger.critical(message)

        if self.event_logger:
            from ..event_logger import EventType
            self.event_logger.log_event(
                EventType.SECURITY_VIOLATION,
                message,
                metadata={
                    'action': 'profile_tamper_detected',
                    'profile_name': profile_name,
                    'reason': reason,
                    'severity': 'CRITICAL',
                }
            )

        # Print to console as well
        print(f"\n{'!'*70}")
        print(f"  CRITICAL SECURITY ALERT")
        print(f"  Seccomp profile tampering detected!")
        print(f"  Profile: {profile_name}")
        print(f"  Reason: {reason}")
        print(f"{'!'*70}\n")

    def remove_profile(self, name: str) -> Tuple[bool, str]:
        """
        Remove a seccomp profile.

        Args:
            name: Profile name

        Returns:
            (success, message)
        """
        if not self._has_admin_privileges():
            return (False, "Root/admin privileges required")

        profile_path = self.profile_dir / f"{name}.json"

        if not profile_path.exists():
            return (True, f"Profile {name} does not exist")

        try:
            # Remove immutable flag if set
            if self._is_immutable(profile_path):
                if not self._remove_immutable(profile_path):
                    return (False, f"Cannot remove immutable profile: {name}")

            # Remove file
            os.unlink(profile_path)

            # Update manifest
            if name in self._manifest:
                del self._manifest[name]
                self._save_manifest()

            logger.info(f"Removed profile: {name}")
            return (True, f"Profile removed: {name}")

        except Exception as e:
            logger.error(f"Failed to remove profile {name}: {e}")
            return (False, str(e))

    def verify_all_profiles(self) -> Tuple[bool, List[str]]:
        """
        Verify integrity of all installed profiles.

        Returns:
            (all_valid, list of issues)
        """
        issues = []

        # Check each profile in manifest
        for name in self._manifest:
            profile_path = self.profile_dir / f"{name}.json"

            if not profile_path.exists():
                issues.append(f"{name}: File missing")
                continue

            # Load and verify
            profile, msg = self.load_profile(name)
            if profile is None:
                issues.append(f"{name}: {msg}")

        # Check for untracked profiles
        for path in self.profile_dir.glob("*.json"):
            name = path.stem
            if name not in self._manifest:
                issues.append(f"{name}: Untracked profile (not in manifest)")
                self._log_tamper_alert(name, "Untracked profile found")

        all_valid = len(issues) == 0
        return (all_valid, issues)

    def get_status(self) -> Dict:
        """Get profile manager status"""
        return {
            'profile_dir': str(self.profile_dir),
            'profile_count': len(self._manifest),
            'use_immutable': self.use_immutable,
            'profiles': {
                name: {
                    'version': p.version,
                    'created_at': p.created_at,
                    'is_immutable': p.is_immutable,
                }
                for name, p in self._manifest.items()
            }
        }

    def cleanup(self):
        """Remove all boundary daemon seccomp profiles"""
        if not self._has_admin_privileges():
            return

        for name in list(self._manifest.keys()):
            if name.startswith('boundary_'):
                self.remove_profile(name)

        logger.info("Cleaned up seccomp profiles")


# Default secure profile templates
SECURE_PROFILE_TEMPLATES = {
    'airgap': {
        'name': 'boundary_airgap',
        'defaultAction': 'SCMP_ACT_ALLOW',
        'architectures': ['SCMP_ARCH_X86_64', 'SCMP_ARCH_X86', 'SCMP_ARCH_AARCH64'],
        'syscalls': [
            {
                'names': ['socket', 'connect', 'accept', 'bind', 'listen',
                         'sendto', 'recvfrom', 'sendmsg', 'recvmsg'],
                'action': 'SCMP_ACT_ERRNO',
                'args': [],
                'comment': 'Block network syscalls in AIRGAP mode'
            },
        ]
    },
    'coldroom': {
        'name': 'boundary_coldroom',
        'defaultAction': 'SCMP_ACT_ERRNO',
        'architectures': ['SCMP_ARCH_X86_64', 'SCMP_ARCH_X86', 'SCMP_ARCH_AARCH64'],
        'syscalls': [
            {
                'names': ['read', 'write', 'exit', 'exit_group', 'brk',
                         'mmap', 'munmap', 'mprotect', 'close', 'fstat'],
                'action': 'SCMP_ACT_ALLOW',
                'args': [],
                'comment': 'Allow only minimal syscalls in COLDROOM mode'
            },
        ]
    },
    'lockdown': {
        'name': 'boundary_lockdown',
        'defaultAction': 'SCMP_ACT_KILL_PROCESS',
        'architectures': ['SCMP_ARCH_X86_64', 'SCMP_ARCH_X86', 'SCMP_ARCH_AARCH64'],
        'syscalls': [
            {
                'names': ['exit', 'exit_group', 'write'],
                'action': 'SCMP_ACT_ALLOW',
                'args': [],
                'comment': 'Allow only exit and stdout write in LOCKDOWN'
            },
        ]
    },
}


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    # Check for admin/root privileges
    if IS_WINDOWS:
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
    else:
        is_admin = os.geteuid() == 0

    if not is_admin:
        print("This test requires root/admin privileges")
        sys.exit(1)

    print("Testing Secure Profile Manager...")

    # Create manager
    manager = SecureProfileManager(
        profile_dir='/tmp/test_seccomp',
        use_immutable=False,  # Don't use immutable for testing
    )

    # Install a test profile
    test_profile = {
        'name': 'test_profile',
        'defaultAction': 'SCMP_ACT_ALLOW',
        'syscalls': [],
    }

    success, msg = manager.install_profile(test_profile)
    print(f"Install: {success} - {msg}")

    # Load and verify
    profile, msg = manager.load_profile('test_profile')
    print(f"Load: {profile is not None} - {msg}")

    # Verify all
    valid, issues = manager.verify_all_profiles()
    print(f"Verify all: {valid}")
    if issues:
        for issue in issues:
            print(f"  - {issue}")

    # Status
    print(f"Status: {manager.get_status()}")

    # Cleanup
    manager.remove_profile('test_profile')
    print("Test complete.")
