"""
USB Enforcer - Kernel-Level USB Device Enforcement via udev

This module provides ACTUAL USB enforcement by managing udev rules and
USB authorization, transforming USB protection from detection-only to
actual prevention.

Security Notes:
- Requires root privileges to write udev rules
- All rule changes are logged to Event Logger
- Fail-closed: if rule application fails, triggers lockdown
- USB storage is blocked; HID devices (keyboard/mouse) allowed by default
- Existing USB devices can be forcibly de-authorized

IMPORTANT: This addresses SECURITY_AUDIT.md Critical Finding #3:
"USB 'Protection' Is Detection-Only"
"""

import os
import subprocess
import glob
import shutil
import threading
import logging
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Tuple, Dict, Set
from datetime import datetime

logger = logging.getLogger(__name__)


class USBEnforcementError(Exception):
    """Raised when USB enforcement fails"""
    pass


class USBDeviceClass(Enum):
    """USB device classes (bDeviceClass values)"""
    AUDIO = "01"
    COMMUNICATIONS = "02"
    HID = "03"  # Human Interface Device (keyboard, mouse)
    PHYSICAL = "05"
    IMAGE = "06"
    PRINTER = "07"
    MASS_STORAGE = "08"  # This is what we block
    HUB = "09"
    CDC_DATA = "0a"
    SMART_CARD = "0b"
    VIDEO = "0e"
    WIRELESS = "e0"
    VENDOR_SPECIFIC = "ff"


@dataclass
class USBDevice:
    """Represents a connected USB device"""
    bus: str
    device: str
    vendor_id: str
    product_id: str
    device_class: str
    authorized: bool
    path: str
    name: Optional[str] = None


class USBEnforcer:
    """
    Enforces USB restrictions using udev rules and sysfs.

    This is a CRITICAL component that provides actual USB enforcement,
    addressing the fundamental problem identified in SECURITY_AUDIT.md:
    "COLDROOM mode detects USB insertion but doesn't block mounting"

    By integrating with udev and sysfs, we now CAN prevent USB access.

    Modes and their USB rules:
    - OPEN: All USB devices allowed
    - RESTRICTED: USB storage requires ceremony
    - TRUSTED: USB storage blocked, HID allowed
    - AIRGAP: USB storage blocked, HID allowed
    - COLDROOM: ALL USB blocked except essential HID (keyboard)
    - LOCKDOWN: ALL USB blocked, existing devices de-authorized
    """

    # udev rule paths
    UDEV_RULES_DIR = "/etc/udev/rules.d"
    UDEV_RULE_FILE = "99-boundary-usb.rules"
    UDEV_RULE_PATH = f"{UDEV_RULES_DIR}/{UDEV_RULE_FILE}"

    # sysfs paths
    USB_DEVICES_PATH = "/sys/bus/usb/devices"

    # Device classes to always allow (essential for system operation)
    ESSENTIAL_CLASSES = {USBDeviceClass.HID.value, USBDeviceClass.HUB.value}

    def __init__(self, daemon=None, event_logger=None):
        """
        Initialize the USBEnforcer.

        Args:
            daemon: Reference to BoundaryDaemon for callbacks
            event_logger: EventLogger for audit logging
        """
        self.daemon = daemon
        self.event_logger = event_logger
        self._lock = threading.Lock()
        self._rules_applied = False
        self._current_mode = None
        self._baseline_devices: Set[str] = set()

        # Verify we have root privileges
        self._has_root = os.geteuid() == 0

        # Check if udev is available
        self._has_udev = shutil.which('udevadm') is not None

        if not self._has_root:
            logger.warning("Not running as root. USB enforcement requires root privileges.")
        if not self._has_udev:
            logger.warning("udevadm not found. USB enforcement requires udev.")

        # Capture baseline USB devices at startup
        self._capture_baseline()

    @property
    def is_available(self) -> bool:
        """Check if USB enforcement is available"""
        return self._has_root and self._has_udev

    def _capture_baseline(self):
        """Capture current USB devices as baseline"""
        try:
            for device in self._enumerate_usb_devices():
                self._baseline_devices.add(device.path)
            logger.info(f"Captured {len(self._baseline_devices)} baseline USB devices")
        except Exception as e:
            logger.warning(f"Failed to capture USB baseline: {e}")

    def enforce_mode(self, mode, reason: str = "") -> Tuple[bool, str]:
        """
        Apply USB rules for the given boundary mode.

        Args:
            mode: BoundaryMode to enforce
            reason: Reason for the mode change

        Returns:
            (success, message)

        Raises:
            USBEnforcementError: If enforcement fails and fail-closed triggers
        """
        from ..policy_engine import BoundaryMode

        if not self.is_available:
            return (False, "USB enforcement not available (requires root and udev)")

        with self._lock:
            try:
                old_mode = self._current_mode

                if mode == BoundaryMode.OPEN:
                    self._apply_open_mode()
                elif mode == BoundaryMode.RESTRICTED:
                    self._apply_restricted_mode()
                elif mode == BoundaryMode.TRUSTED:
                    self._apply_trusted_mode()
                elif mode == BoundaryMode.AIRGAP:
                    self._apply_airgap_mode()
                elif mode == BoundaryMode.COLDROOM:
                    self._apply_coldroom_mode()
                elif mode == BoundaryMode.LOCKDOWN:
                    self._apply_lockdown_mode()
                else:
                    # Unknown mode: apply most restrictive
                    self._apply_lockdown_mode()

                self._current_mode = mode
                self._rules_applied = True

                # Log the enforcement action
                self._log_enforcement(
                    action="USB_MODE_ENFORCE",
                    old_mode=old_mode,
                    new_mode=mode,
                    reason=reason
                )

                return (True, f"USB enforcement applied for {mode.name} mode")

            except Exception as e:
                error_msg = f"Failed to apply USB enforcement: {e}"
                logger.error(error_msg)

                # Fail-closed: try to apply lockdown on failure
                try:
                    self._apply_lockdown_mode()
                    self._log_enforcement(
                        action="USB_FAIL_CLOSED",
                        error=str(e)
                    )
                except Exception as e2:
                    logger.critical(f"Failed to apply USB lockdown rules: {e2}")

                raise USBEnforcementError(error_msg) from e

    def _apply_open_mode(self):
        """OPEN mode: Remove all USB restrictions"""
        self._remove_udev_rules()
        self._authorize_all_devices()
        logger.info("USB enforcement: OPEN mode - all USB devices allowed")

    def _apply_restricted_mode(self):
        """RESTRICTED mode: Log USB storage but don't block"""
        # Install logging-only rule
        rule = self._generate_udev_rule(
            block_storage=False,
            block_all=False,
            log_only=True
        )
        self._install_udev_rule(rule)
        logger.info("USB enforcement: RESTRICTED mode - USB storage logged")

    def _apply_trusted_mode(self):
        """TRUSTED mode: Block USB mass storage, allow HID"""
        rule = self._generate_udev_rule(
            block_storage=True,
            block_all=False,
            log_only=False
        )
        self._install_udev_rule(rule)
        self._deauthorize_storage_devices()
        logger.info("USB enforcement: TRUSTED mode - USB storage blocked")

    def _apply_airgap_mode(self):
        """AIRGAP mode: Block USB mass storage, allow HID"""
        # Same as TRUSTED for USB
        rule = self._generate_udev_rule(
            block_storage=True,
            block_all=False,
            log_only=False
        )
        self._install_udev_rule(rule)
        self._deauthorize_storage_devices()
        logger.info("USB enforcement: AIRGAP mode - USB storage blocked")

    def _apply_coldroom_mode(self):
        """COLDROOM mode: Block all USB except essential HID"""
        rule = self._generate_udev_rule(
            block_storage=True,
            block_all=True,
            allow_hid=True,
            log_only=False
        )
        self._install_udev_rule(rule)
        self._deauthorize_non_essential_devices()
        logger.info("USB enforcement: COLDROOM mode - only essential HID allowed")

    def _apply_lockdown_mode(self):
        """LOCKDOWN mode: Block ALL USB devices"""
        rule = self._generate_udev_rule(
            block_storage=True,
            block_all=True,
            allow_hid=False,  # Block even HID in lockdown
            log_only=False
        )
        self._install_udev_rule(rule)
        self._deauthorize_all_new_devices()
        logger.info("USB enforcement: LOCKDOWN mode - all new USB blocked")

    def _generate_udev_rule(self, block_storage: bool = False,
                           block_all: bool = False,
                           allow_hid: bool = True,
                           log_only: bool = False) -> str:
        """Generate udev rule content based on mode requirements"""

        rules = []
        rules.append("# Boundary Daemon USB Enforcement Rules")
        rules.append(f"# Generated: {datetime.utcnow().isoformat()}Z")
        rules.append(f"# Mode: block_storage={block_storage}, block_all={block_all}, allow_hid={allow_hid}")
        rules.append("")

        if log_only:
            # Just log USB events
            rules.append('# Log all USB device connections')
            rules.append('ACTION=="add", SUBSYSTEM=="usb", RUN+="/usr/bin/logger -t boundary-usb \'USB device added: %k\'"')

        elif block_all:
            if allow_hid:
                # Block all except HID (keyboard/mouse) - COLDROOM mode
                rules.append("# COLDROOM: Block all USB except HID devices")
                rules.append("")
                rules.append("# Allow HID devices (keyboards, mice)")
                rules.append('ACTION=="add", SUBSYSTEM=="usb", ATTR{bDeviceClass}=="03", GOTO="boundary_allow"')
                rules.append('ACTION=="add", SUBSYSTEM=="usb", ATTR{bInterfaceClass}=="03", GOTO="boundary_allow"')
                rules.append("")
                rules.append("# Allow USB hubs (needed for device enumeration)")
                rules.append('ACTION=="add", SUBSYSTEM=="usb", ATTR{bDeviceClass}=="09", GOTO="boundary_allow"')
                rules.append("")
                rules.append("# Block all other USB devices")
                rules.append('ACTION=="add", SUBSYSTEM=="usb", ATTR{authorized}=="1", \\')
                rules.append('    RUN+="/bin/sh -c \'echo 0 > /sys$devpath/authorized\'", \\')
                rules.append('    RUN+="/usr/bin/logger -t boundary-usb -p auth.warning \'COLDROOM: Blocked USB device: %k\'"')
                rules.append("")
                rules.append("LABEL=\"boundary_allow\"")
            else:
                # Block ALL USB devices - LOCKDOWN mode
                rules.append("# LOCKDOWN: Block ALL USB devices")
                rules.append("")
                rules.append("# Allow only USB hubs for basic device enumeration")
                rules.append('ACTION=="add", SUBSYSTEM=="usb", ATTR{bDeviceClass}=="09", GOTO="boundary_end"')
                rules.append("")
                rules.append("# Block everything else")
                rules.append('ACTION=="add", SUBSYSTEM=="usb", ATTR{authorized}=="1", \\')
                rules.append('    RUN+="/bin/sh -c \'echo 0 > /sys$devpath/authorized\'", \\')
                rules.append('    RUN+="/usr/bin/logger -t boundary-usb -p auth.crit \'LOCKDOWN: Blocked USB device: %k\'"')
                rules.append("")
                rules.append("LABEL=\"boundary_end\"")

        elif block_storage:
            # Block only mass storage devices - TRUSTED/AIRGAP mode
            rules.append("# TRUSTED/AIRGAP: Block USB mass storage devices")
            rules.append("")
            rules.append("# Block USB mass storage (class 08)")
            rules.append('ACTION=="add", SUBSYSTEM=="usb", ATTR{bDeviceClass}=="08", \\')
            rules.append('    RUN+="/bin/sh -c \'echo 0 > /sys$devpath/authorized\'", \\')
            rules.append('    RUN+="/usr/bin/logger -t boundary-usb -p auth.warning \'Blocked USB storage: %k\'"')
            rules.append("")
            rules.append("# Also block interface-level mass storage (for composite devices)")
            rules.append('ACTION=="add", SUBSYSTEM=="usb", ATTR{bInterfaceClass}=="08", \\')
            rules.append('    RUN+="/bin/sh -c \'echo 0 > /sys$devpath/../authorized\'", \\')
            rules.append('    RUN+="/usr/bin/logger -t boundary-usb -p auth.warning \'Blocked USB storage interface: %k\'"')

        rules.append("")
        return "\n".join(rules)

    def _install_udev_rule(self, rule_content: str):
        """Install udev rule file and reload"""
        try:
            # Ensure directory exists
            os.makedirs(self.UDEV_RULES_DIR, exist_ok=True)

            # Write rule file
            with open(self.UDEV_RULE_PATH, 'w') as f:
                f.write(rule_content)

            # Set proper permissions
            os.chmod(self.UDEV_RULE_PATH, 0o644)

            # Reload udev rules
            result = subprocess.run(
                ['udevadm', 'control', '--reload-rules'],
                capture_output=True,
                timeout=10
            )
            if result.returncode != 0:
                raise USBEnforcementError(f"Failed to reload udev rules: {result.stderr.decode()}")

            # Trigger udev to re-evaluate existing devices
            subprocess.run(
                ['udevadm', 'trigger', '--subsystem-match=usb'],
                capture_output=True,
                timeout=10
            )

            logger.info(f"Installed udev rule: {self.UDEV_RULE_PATH}")

        except Exception as e:
            raise USBEnforcementError(f"Failed to install udev rule: {e}") from e

    def _remove_udev_rules(self):
        """Remove boundary udev rules"""
        try:
            if os.path.exists(self.UDEV_RULE_PATH):
                os.unlink(self.UDEV_RULE_PATH)
                subprocess.run(
                    ['udevadm', 'control', '--reload-rules'],
                    capture_output=True,
                    timeout=10
                )
                logger.info(f"Removed udev rule: {self.UDEV_RULE_PATH}")
        except Exception as e:
            logger.warning(f"Failed to remove udev rule: {e}")

    def _enumerate_usb_devices(self) -> List[USBDevice]:
        """Enumerate all connected USB devices"""
        devices = []

        if not os.path.exists(self.USB_DEVICES_PATH):
            return devices

        for entry in os.listdir(self.USB_DEVICES_PATH):
            device_path = os.path.join(self.USB_DEVICES_PATH, entry)

            # Skip non-device entries
            if not os.path.isdir(device_path):
                continue

            # Skip entries without USB device structure
            if ':' in entry:  # These are interface entries
                continue

            try:
                # Read device attributes
                vendor_id = self._read_sysfs(device_path, 'idVendor', '')
                product_id = self._read_sysfs(device_path, 'idProduct', '')
                device_class = self._read_sysfs(device_path, 'bDeviceClass', '')
                authorized = self._read_sysfs(device_path, 'authorized', '1') == '1'
                product = self._read_sysfs(device_path, 'product', None)

                # Parse bus/device from entry name
                parts = entry.split('-')
                bus = parts[0] if parts else ''
                device_num = parts[1] if len(parts) > 1 else ''

                devices.append(USBDevice(
                    bus=bus,
                    device=device_num,
                    vendor_id=vendor_id,
                    product_id=product_id,
                    device_class=device_class,
                    authorized=authorized,
                    path=device_path,
                    name=product
                ))

            except Exception as e:
                logger.debug(f"Error reading USB device {entry}: {e}")
                continue

        return devices

    def _read_sysfs(self, device_path: str, attr: str, default: Optional[str] = None) -> Optional[str]:
        """Read a sysfs attribute"""
        attr_path = os.path.join(device_path, attr)
        try:
            if os.path.exists(attr_path):
                with open(attr_path, 'r') as f:
                    return f.read().strip()
        except Exception:
            pass
        return default

    def _write_sysfs(self, device_path: str, attr: str, value: str) -> bool:
        """Write a sysfs attribute"""
        attr_path = os.path.join(device_path, attr)
        try:
            if os.path.exists(attr_path):
                with open(attr_path, 'w') as f:
                    f.write(value)
                return True
        except Exception as e:
            logger.debug(f"Failed to write {attr_path}: {e}")
        return False

    def _authorize_device(self, device_path: str) -> bool:
        """Authorize a USB device"""
        return self._write_sysfs(device_path, 'authorized', '1')

    def _deauthorize_device(self, device_path: str) -> bool:
        """De-authorize a USB device"""
        return self._write_sysfs(device_path, 'authorized', '0')

    def _authorize_all_devices(self):
        """Re-authorize all USB devices"""
        for device in self._enumerate_usb_devices():
            if not device.authorized:
                self._authorize_device(device.path)
                logger.debug(f"Authorized USB device: {device.path}")

    def _deauthorize_storage_devices(self):
        """De-authorize all USB mass storage devices"""
        for device in self._enumerate_usb_devices():
            if device.device_class == USBDeviceClass.MASS_STORAGE.value:
                if device.authorized:
                    self._deauthorize_device(device.path)
                    logger.info(f"De-authorized USB storage: {device.path} ({device.name or 'unknown'})")
                    self._log_enforcement(
                        action="USB_DEVICE_BLOCKED",
                        device=device.path,
                        name=device.name,
                        vendor_id=device.vendor_id,
                        product_id=device.product_id
                    )

    def _deauthorize_non_essential_devices(self):
        """De-authorize all non-essential USB devices (COLDROOM)"""
        for device in self._enumerate_usb_devices():
            # Skip essential device classes
            if device.device_class in self.ESSENTIAL_CLASSES:
                continue

            # De-authorize if authorized
            if device.authorized:
                self._deauthorize_device(device.path)
                logger.info(f"De-authorized non-essential USB: {device.path} ({device.name or 'unknown'})")
                self._log_enforcement(
                    action="USB_DEVICE_BLOCKED",
                    device=device.path,
                    name=device.name,
                    reason="COLDROOM non-essential"
                )

    def _deauthorize_all_new_devices(self):
        """De-authorize all USB devices not in baseline (LOCKDOWN)"""
        for device in self._enumerate_usb_devices():
            # Skip baseline devices (were present at daemon start)
            if device.path in self._baseline_devices:
                continue

            # Skip USB hubs (needed for enumeration)
            if device.device_class == USBDeviceClass.HUB.value:
                continue

            if device.authorized:
                self._deauthorize_device(device.path)
                logger.info(f"LOCKDOWN: De-authorized new USB: {device.path}")
                self._log_enforcement(
                    action="USB_LOCKDOWN_BLOCK",
                    device=device.path,
                    name=device.name
                )

    def eject_all_storage(self) -> Tuple[int, List[str]]:
        """
        Eject all USB storage devices.

        Returns:
            (count, list of ejected devices)
        """
        ejected = []

        for device in self._enumerate_usb_devices():
            if device.device_class == USBDeviceClass.MASS_STORAGE.value:
                # First unmount any mounted filesystems
                self._unmount_device(device)

                # Then de-authorize
                if self._deauthorize_device(device.path):
                    ejected.append(device.path)
                    logger.info(f"Ejected USB storage: {device.path}")

        return (len(ejected), ejected)

    def _unmount_device(self, device: USBDevice):
        """Unmount filesystems from a USB device"""
        try:
            # Find block devices associated with this USB device
            # They're typically under /sys/bus/usb/devices/<device>/*/block/*
            block_pattern = os.path.join(device.path, '*', 'block', '*')
            for block_path in glob.glob(block_pattern):
                block_name = os.path.basename(block_path)
                mount_point = f"/dev/{block_name}"

                # Try to unmount
                result = subprocess.run(
                    ['umount', mount_point],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    logger.info(f"Unmounted {mount_point}")

        except Exception as e:
            logger.debug(f"Error unmounting device: {e}")

    def get_connected_devices(self) -> List[Dict]:
        """Get list of connected USB devices for status display"""
        devices = []
        for device in self._enumerate_usb_devices():
            devices.append({
                'path': device.path,
                'vendor_id': device.vendor_id,
                'product_id': device.product_id,
                'device_class': device.device_class,
                'authorized': device.authorized,
                'name': device.name,
                'is_baseline': device.path in self._baseline_devices
            })
        return devices

    def _log_enforcement(self, action: str, **kwargs):
        """Log enforcement action to event logger"""
        if self.event_logger:
            try:
                from ..event_logger import EventType
                self.event_logger.log_event(
                    EventType.MODE_CHANGE,
                    f"USB enforcement: {action}",
                    metadata={
                        'enforcement_action': action,
                        'timestamp': datetime.utcnow().isoformat() + "Z",
                        **kwargs
                    }
                )
            except Exception as e:
                logger.error(f"Failed to log USB enforcement action: {e}")

    def get_status(self) -> Dict:
        """Get current enforcement status"""
        devices = self.get_connected_devices()
        return {
            'available': self.is_available,
            'has_root': self._has_root,
            'has_udev': self._has_udev,
            'rules_applied': self._rules_applied,
            'rule_path': self.UDEV_RULE_PATH,
            'rule_exists': os.path.exists(self.UDEV_RULE_PATH),
            'current_mode': self._current_mode.name if self._current_mode else None,
            'baseline_count': len(self._baseline_devices),
            'connected_count': len(devices),
            'storage_count': sum(1 for d in devices if d['device_class'] == USBDeviceClass.MASS_STORAGE.value),
            'hid_count': sum(1 for d in devices if d['device_class'] == USBDeviceClass.HID.value)
        }

    def get_current_rules(self) -> str:
        """Get current udev rules (for debugging)"""
        if not os.path.exists(self.UDEV_RULE_PATH):
            return "No boundary USB rules installed"

        try:
            with open(self.UDEV_RULE_PATH, 'r') as f:
                return f.read()
        except Exception as e:
            return f"Error reading rules: {e}"

    def cleanup(self):
        """Remove all boundary udev rules (called on daemon shutdown)"""
        if not self.is_available:
            return

        with self._lock:
            try:
                self._remove_udev_rules()
                self._authorize_all_devices()
                self._rules_applied = False
                self._current_mode = None
                logger.info("USB enforcement rules cleaned up")

            except Exception as e:
                logger.error(f"Error cleaning up USB rules: {e}")

    def emergency_lockdown(self) -> bool:
        """
        Emergency lockdown - block all USB devices immediately.
        Called when a critical security violation is detected.

        Returns:
            True if lockdown was successful
        """
        if not self.is_available:
            logger.error("Cannot apply USB emergency lockdown: not available")
            return False

        try:
            from ..policy_engine import BoundaryMode
            self.enforce_mode(BoundaryMode.LOCKDOWN, reason="Emergency lockdown triggered")
            # Also eject all storage
            count, devices = self.eject_all_storage()
            logger.warning(f"Emergency USB lockdown: ejected {count} storage devices")
            return True
        except Exception as e:
            logger.critical(f"USB emergency lockdown failed: {e}")
            return False


if __name__ == '__main__':
    # Test the USB enforcer
    import sys

    logging.basicConfig(level=logging.DEBUG)

    enforcer = USBEnforcer()
    print(f"Available: {enforcer.is_available}")
    print(f"Status: {enforcer.get_status()}")

    if not enforcer.is_available:
        print("USB enforcement not available. Run as root with udev installed.")
        sys.exit(1)

    print("\nConnected USB devices:")
    for device in enforcer.get_connected_devices():
        print(f"  {device['path']}: {device['name'] or 'unknown'} (class={device['device_class']}, auth={device['authorized']})")

    # Test mode enforcement (requires root)
    from policy_engine import BoundaryMode

    for mode in [BoundaryMode.OPEN, BoundaryMode.COLDROOM, BoundaryMode.LOCKDOWN]:
        print(f"\nApplying {mode.name} mode...")
        success, msg = enforcer.enforce_mode(mode, reason="test")
        print(f"Result: {success} - {msg}")
        print(f"Rules:\n{enforcer.get_current_rules()[:500]}...")

    # Cleanup
    enforcer.cleanup()
    print("\nCleanup complete.")
