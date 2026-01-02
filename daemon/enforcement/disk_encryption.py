"""
Disk Encryption Status Checker

Verifies disk encryption status for data-at-rest protection.
Supports LUKS (Linux), BitLocker (Windows), and FileVault (macOS).

Usage:
    from daemon.enforcement.disk_encryption import (
        EncryptionChecker,
        get_encryption_checker,
    )

    checker = get_encryption_checker()

    # Check all volumes
    status = checker.check_all_volumes()

    # Check specific path
    is_encrypted = checker.is_path_encrypted("/var/log/boundary-daemon")

    # Get detailed status
    details = checker.get_encryption_details("/dev/sda1")

Security Note:
    This module only checks encryption status - it does not
    enable or manage encryption. Use system tools for that.
"""

import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == 'win32'
IS_LINUX = sys.platform.startswith('linux')
IS_MACOS = sys.platform == 'darwin'


class EncryptionType(Enum):
    """Types of disk encryption."""
    LUKS = "luks"           # Linux Unified Key Setup
    LUKS2 = "luks2"         # LUKS version 2
    BITLOCKER = "bitlocker" # Windows BitLocker
    FILEVAULT = "filevault" # macOS FileVault
    VERACRYPT = "veracrypt" # Cross-platform VeraCrypt
    ECRYPTFS = "ecryptfs"   # Linux eCryptfs
    FSCRYPT = "fscrypt"     # Linux fscrypt (ext4/f2fs)
    UNKNOWN = "unknown"
    NONE = "none"


class EncryptionStatus(Enum):
    """Encryption status."""
    ENCRYPTED = "encrypted"
    NOT_ENCRYPTED = "not_encrypted"
    PARTIALLY_ENCRYPTED = "partially"  # BitLocker can be partial
    ENCRYPTING = "encrypting"
    DECRYPTING = "decrypting"
    SUSPENDED = "suspended"
    UNKNOWN = "unknown"


@dataclass
class VolumeInfo:
    """Information about an encrypted volume."""
    device: str
    mount_point: str
    encryption_type: EncryptionType
    status: EncryptionStatus
    cipher: str = ""
    key_size: int = 0
    uuid: str = ""
    label: str = ""
    size_bytes: int = 0
    details: Dict[str, Any] = field(default_factory=dict)


class EncryptionChecker:
    """
    Checks disk encryption status across platforms.

    Provides visibility into data-at-rest encryption for
    compliance and security monitoring.
    """

    def __init__(self, event_logger=None, siem=None):
        self._event_logger = event_logger
        self._siem = siem

    def check_all_volumes(self) -> List[VolumeInfo]:
        """Check encryption status of all mounted volumes."""
        volumes = []

        if IS_LINUX:
            volumes = self._check_linux_volumes()
        elif IS_WINDOWS:
            volumes = self._check_windows_volumes()
        elif IS_MACOS:
            volumes = self._check_macos_volumes()

        return volumes

    def _check_linux_volumes(self) -> List[VolumeInfo]:
        """Check Linux volumes for encryption."""
        volumes = []

        # Get mounted filesystems
        try:
            with open('/proc/mounts', 'r') as f:
                mounts = f.readlines()
        except IOError:
            mounts = []

        for line in mounts:
            parts = line.split()
            if len(parts) < 2:
                continue

            device = parts[0]
            mount_point = parts[1]

            # Skip virtual filesystems
            if device.startswith(('/proc', '/sys', '/dev/pts', '/run')):
                continue
            if mount_point.startswith(('/proc', '/sys', '/dev')):
                continue

            volume = self._check_linux_device(device, mount_point)
            if volume:
                volumes.append(volume)

        return volumes

    def _check_linux_device(self, device: str, mount_point: str) -> Optional[VolumeInfo]:
        """Check a single Linux device for encryption."""
        encryption_type = EncryptionType.NONE
        status = EncryptionStatus.NOT_ENCRYPTED
        cipher = ""
        key_size = 0
        details = {}

        try:
            # Check if device is a dm-crypt device
            device_name = Path(device).name
            dm_path = Path(f"/sys/block/{device_name}/dm")

            if dm_path.exists():
                # Check for LUKS
                uuid_path = dm_path / "uuid"
                if uuid_path.exists():
                    uuid = uuid_path.read_text().strip()
                    if uuid.startswith("CRYPT-LUKS"):
                        encryption_type = EncryptionType.LUKS2 if "LUKS2" in uuid else EncryptionType.LUKS
                        status = EncryptionStatus.ENCRYPTED

            # Try cryptsetup for more details
            if shutil.which("cryptsetup"):
                result = subprocess.run(
                    ["cryptsetup", "status", device_name],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    output = result.stdout
                    if "cipher:" in output:
                        encryption_type = EncryptionType.LUKS
                        status = EncryptionStatus.ENCRYPTED

                        for line in output.split('\n'):
                            if 'cipher:' in line:
                                cipher = line.split(':')[1].strip()
                            if 'keysize:' in line:
                                key_size = int(line.split(':')[1].strip().split()[0])

                        details['cryptsetup_output'] = output

            # Check for eCryptfs
            if mount_point and Path(mount_point).exists():
                try:
                    with open('/proc/mounts', 'r') as f:
                        mtab_line = [m for m in f.readlines() if mount_point in m]
                except IOError:
                    mtab_line = []
                if mtab_line and 'ecryptfs' in mtab_line[0]:
                    encryption_type = EncryptionType.ECRYPTFS
                    status = EncryptionStatus.ENCRYPTED

            # Check for fscrypt
            if shutil.which("fscrypt"):
                result = subprocess.run(
                    ["fscrypt", "status", mount_point],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0 and "encrypted" in result.stdout.lower():
                    encryption_type = EncryptionType.FSCRYPT
                    status = EncryptionStatus.ENCRYPTED
                    details['fscrypt_output'] = result.stdout

        except Exception as e:
            logger.debug(f"Error checking {device}: {e}")
            status = EncryptionStatus.UNKNOWN

        return VolumeInfo(
            device=device,
            mount_point=mount_point,
            encryption_type=encryption_type,
            status=status,
            cipher=cipher,
            key_size=key_size,
            details=details,
        )

    def _check_windows_volumes(self) -> List[VolumeInfo]:
        """Check Windows volumes for BitLocker."""
        volumes = []

        if not shutil.which("manage-bde"):
            return volumes

        try:
            # Get all drive letters
            result = subprocess.run(
                ["wmic", "logicaldisk", "get", "caption"],
                capture_output=True,
                text=True,
            )

            drives = [d.strip() for d in result.stdout.split('\n') if d.strip() and ':' in d]

            for drive in drives:
                volume = self._check_bitlocker_drive(drive)
                if volume:
                    volumes.append(volume)

        except Exception as e:
            logger.error(f"Error checking Windows volumes: {e}")

        return volumes

    def _check_bitlocker_drive(self, drive: str) -> Optional[VolumeInfo]:
        """Check a Windows drive for BitLocker."""
        try:
            result = subprocess.run(
                ["manage-bde", "-status", drive],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return None

            output = result.stdout
            status = EncryptionStatus.NOT_ENCRYPTED
            encryption_type = EncryptionType.NONE

            if "Protection Status:" in output:
                if "Protection On" in output:
                    status = EncryptionStatus.ENCRYPTED
                    encryption_type = EncryptionType.BITLOCKER
                elif "Encryption in Progress" in output:
                    status = EncryptionStatus.ENCRYPTING
                    encryption_type = EncryptionType.BITLOCKER
                elif "Decryption in Progress" in output:
                    status = EncryptionStatus.DECRYPTING
                    encryption_type = EncryptionType.BITLOCKER
                elif "Protection Status:    Protection Off" in output and "Percentage Encrypted" in output:
                    # Check if actually encrypted but suspended
                    for line in output.split('\n'):
                        if "Percentage Encrypted:" in line and "100" in line:
                            status = EncryptionStatus.SUSPENDED
                            encryption_type = EncryptionType.BITLOCKER

            cipher = ""
            for line in output.split('\n'):
                if "Encryption Method:" in line:
                    cipher = line.split(':')[1].strip()

            return VolumeInfo(
                device=drive,
                mount_point=drive,
                encryption_type=encryption_type,
                status=status,
                cipher=cipher,
                details={'manage_bde_output': output},
            )

        except Exception as e:
            logger.debug(f"Error checking BitLocker for {drive}: {e}")
            return None

    def _check_macos_volumes(self) -> List[VolumeInfo]:
        """Check macOS volumes for FileVault."""
        volumes = []

        try:
            # Check FileVault status
            result = subprocess.run(
                ["fdesetup", "status"],
                capture_output=True,
                text=True,
            )

            is_filevault = "FileVault is On" in result.stdout

            # Get disk info
            result = subprocess.run(
                ["diskutil", "list", "-plist"],
                capture_output=True,
            )

            if result.returncode == 0:
                import plistlib
                data = plistlib.loads(result.stdout)

                for disk in data.get('AllDisksAndPartitions', []):
                    device = f"/dev/{disk.get('DeviceIdentifier', '')}"
                    mount = disk.get('MountPoint', '')

                    if mount == '/':
                        volumes.append(VolumeInfo(
                            device=device,
                            mount_point=mount,
                            encryption_type=EncryptionType.FILEVAULT if is_filevault else EncryptionType.NONE,
                            status=EncryptionStatus.ENCRYPTED if is_filevault else EncryptionStatus.NOT_ENCRYPTED,
                            details={'fdesetup_output': result.stdout},
                        ))

        except Exception as e:
            logger.error(f"Error checking macOS volumes: {e}")

        return volumes

    def is_path_encrypted(self, path: str) -> bool:
        """
        Check if a specific path is on an encrypted volume.

        Args:
            path: File or directory path to check

        Returns:
            True if path is on encrypted volume
        """
        path = Path(path).resolve()

        # Find the mount point for this path
        volumes = self.check_all_volumes()

        for volume in volumes:
            if not volume.mount_point:
                continue

            mount = Path(volume.mount_point)
            try:
                if path == mount or mount in path.parents:
                    return volume.status == EncryptionStatus.ENCRYPTED
            except (ValueError, TypeError):
                continue

        return False

    def get_encryption_details(self, device_or_path: str) -> Optional[VolumeInfo]:
        """Get detailed encryption info for a device or path."""
        volumes = self.check_all_volumes()

        for volume in volumes:
            if volume.device == device_or_path or volume.mount_point == device_or_path:
                return volume

        # Check if it's a path on a volume
        path = Path(device_or_path)
        if path.exists():
            for volume in volumes:
                if volume.mount_point and Path(volume.mount_point) in path.parents:
                    return volume

        return None

    def get_security_report(self) -> Dict[str, Any]:
        """
        Generate a security report on disk encryption status.

        Returns dict with:
        - overall_status: encrypted, partial, none
        - volumes: list of volume info
        - recommendations: list of security recommendations
        """
        volumes = self.check_all_volumes()

        encrypted_count = sum(1 for v in volumes if v.status == EncryptionStatus.ENCRYPTED)
        total_count = len(volumes)

        if encrypted_count == total_count and total_count > 0:
            overall = "encrypted"
        elif encrypted_count > 0:
            overall = "partial"
        else:
            overall = "none"

        recommendations = []

        if overall != "encrypted":
            if IS_LINUX:
                recommendations.append("Enable LUKS encryption: cryptsetup luksFormat /dev/sdX")
                recommendations.append("For home directories, consider ecryptfs or fscrypt")
            elif IS_WINDOWS:
                recommendations.append("Enable BitLocker: manage-bde -on C:")
                recommendations.append("Ensure TPM is enabled for key protection")
            elif IS_MACOS:
                recommendations.append("Enable FileVault: fdesetup enable")

        # Check for weak ciphers
        for volume in volumes:
            if volume.cipher and 'aes-128' in volume.cipher.lower():
                recommendations.append(f"{volume.device}: Consider upgrading to AES-256")

        report = {
            'overall_status': overall,
            'encrypted_count': encrypted_count,
            'total_count': total_count,
            'volumes': [
                {
                    'device': v.device,
                    'mount_point': v.mount_point,
                    'type': v.encryption_type.value,
                    'status': v.status.value,
                    'cipher': v.cipher,
                    'key_size': v.key_size,
                }
                for v in volumes
            ],
            'recommendations': recommendations,
        }

        # Log to SIEM if not fully encrypted
        if overall != "encrypted" and self._siem:
            try:
                self._siem.log_security_error(
                    error_type="disk_encryption",
                    error_message=f"Disk encryption status: {overall}",
                    details=report,
                )
            except Exception:
                pass

        return report

    def verify_log_encryption(self, log_dir: str = "/var/log/boundary-daemon") -> Tuple[bool, str]:
        """
        Verify that log directory is on encrypted storage.

        Returns:
            (is_encrypted, message)
        """
        if not Path(log_dir).exists():
            return False, f"Log directory does not exist: {log_dir}"

        is_encrypted = self.is_path_encrypted(log_dir)

        if is_encrypted:
            return True, f"Log directory {log_dir} is on encrypted storage"
        else:
            return False, f"WARNING: Log directory {log_dir} is NOT on encrypted storage"


# Global instance
_encryption_checker: Optional[EncryptionChecker] = None


def get_encryption_checker(event_logger=None, siem=None) -> EncryptionChecker:
    """Get or create the global encryption checker."""
    global _encryption_checker
    if _encryption_checker is None:
        _encryption_checker = EncryptionChecker(event_logger, siem)
    return _encryption_checker


__all__ = [
    'EncryptionChecker',
    'EncryptionType',
    'EncryptionStatus',
    'VolumeInfo',
    'get_encryption_checker',
]
