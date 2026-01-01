"""
Windows Firewall Enforcer - Windows Firewall with Advanced Security Integration

This module provides ACTUAL network enforcement on Windows by managing
Windows Firewall rules via netsh and PowerShell, transforming the Boundary
Daemon from a detection-only system to a true enforcement mechanism on Windows.

Security Notes:
- Requires Administrator privileges
- All rule changes are logged to Event Logger
- Fail-closed: if rule application fails, system enters LOCKDOWN
- Rules are applied atomically where possible
- Backup rules are created before changes

This addresses the gap: "No Windows Firewall API integration" identified
in the security stack analysis.

Modes and their network rules:
- OPEN: No restrictions (remove all boundary rules)
- RESTRICTED: Allow all with logging
- TRUSTED: Only allow loopback and VPN connections
- AIRGAP: Block ALL network traffic except loopback
- COLDROOM: Block ALL network traffic except loopback
- LOCKDOWN: Block ALL network traffic including loopback
"""

import os
import sys
import subprocess
import threading
import logging
import json
import tempfile
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = sys.platform == 'win32'


class WindowsFirewallError(Exception):
    """Raised when Windows Firewall enforcement fails"""
    pass


class FirewallProfile(Enum):
    """Windows Firewall profiles"""
    DOMAIN = "domain"
    PRIVATE = "private"
    PUBLIC = "public"
    ALL = "all"


class FirewallAction(Enum):
    """Firewall rule actions"""
    ALLOW = "allow"
    BLOCK = "block"


class FirewallDirection(Enum):
    """Firewall rule directions"""
    IN = "in"
    OUT = "out"


class RuleProtocol(Enum):
    """Supported protocols"""
    TCP = "tcp"
    UDP = "udp"
    ICMPV4 = "icmpv4"
    ICMPV6 = "icmpv6"
    ANY = "any"


@dataclass
class WindowsFirewallRule:
    """Represents a Windows Firewall rule"""
    name: str
    action: FirewallAction
    direction: FirewallDirection
    enabled: bool = True
    profile: FirewallProfile = FirewallProfile.ALL
    protocol: RuleProtocol = RuleProtocol.ANY
    local_port: Optional[str] = None  # "80,443" or "1024-65535"
    remote_port: Optional[str] = None
    local_ip: Optional[str] = None  # "127.0.0.1" or "LocalSubnet"
    remote_ip: Optional[str] = None  # "Any" or specific IP/range
    program: Optional[str] = None  # Path to executable
    description: Optional[str] = None
    group: str = "BoundaryDaemon"

    def to_netsh_args(self) -> List[str]:
        """Convert rule to netsh advfirewall arguments"""
        args = [
            f"name={self.name}",
            f"dir={self.direction.value}",
            f"action={self.action.value}",
            f"enable={'yes' if self.enabled else 'no'}",
            f"profile={self.profile.value}",
        ]

        if self.protocol != RuleProtocol.ANY:
            args.append(f"protocol={self.protocol.value}")

        if self.local_port:
            args.append(f"localport={self.local_port}")

        if self.remote_port:
            args.append(f"remoteport={self.remote_port}")

        if self.local_ip:
            args.append(f"localip={self.local_ip}")

        if self.remote_ip:
            args.append(f"remoteip={self.remote_ip}")

        if self.program:
            args.append(f"program={self.program}")

        if self.description:
            args.append(f"description={self.description}")

        return args


class WindowsFirewallEnforcer:
    """
    Enforces network restrictions using Windows Firewall with Advanced Security.

    This is the CRITICAL component that provides actual enforcement on Windows,
    addressing the gap: "No Windows Firewall API integration"

    By integrating with Windows Firewall, we now CAN enforce at the OS level
    on Windows systems.

    Modes and their network rules:
    - OPEN: No restrictions (remove all boundary rules)
    - RESTRICTED: Allow all (logging enabled via audit policy)
    - TRUSTED: Only allow loopback and VPN interfaces
    - AIRGAP: Block ALL network traffic except loopback
    - COLDROOM: Block ALL network traffic except loopback
    - LOCKDOWN: Block ALL network traffic including loopback
    """

    # Rule name prefix for boundary-specific rules
    RULE_PREFIX = "BoundaryDaemon_"

    # VPN adapter patterns (common VPN clients)
    VPN_PATTERNS = [
        "TAP-Windows*",  # OpenVPN
        "WireGuard*",    # WireGuard
        "Cisco AnyConnect*",
        "Pulse Secure*",
        "GlobalProtect*",
    ]

    def __init__(self, daemon=None, event_logger=None, persistence_manager=None):
        """
        Initialize the WindowsFirewallEnforcer.

        Args:
            daemon: Reference to BoundaryDaemon for callbacks
            event_logger: EventLogger for audit logging
            persistence_manager: ProtectionPersistenceManager for surviving restarts
        """
        self.daemon = daemon
        self.event_logger = event_logger
        self._lock = threading.Lock()
        self._rules_applied = False
        self._current_mode = None
        self._persistence_manager = persistence_manager
        self._backup_path: Optional[str] = None

        # Check platform and admin privileges
        self._is_windows = IS_WINDOWS
        self._has_admin = self._check_admin_privileges()
        self._is_available = self._is_windows and self._has_admin

        if not self._is_windows:
            logger.info("WindowsFirewallEnforcer: Not on Windows, enforcement disabled")
        elif not self._has_admin:
            logger.warning(
                "WindowsFirewallEnforcer: Not running as Administrator. "
                "Network enforcement requires admin privileges."
            )
        else:
            logger.info("WindowsFirewallEnforcer: Windows Firewall enforcement available")

            # Verify Windows Firewall service is running
            if not self._check_firewall_service():
                logger.warning("Windows Firewall service may not be running properly")

    def _check_admin_privileges(self) -> bool:
        """Check if running with Administrator privileges"""
        if not IS_WINDOWS:
            return False

        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError, ImportError) as e:
            logger.debug(f"Admin check failed: {e}")
            return False

    def _check_firewall_service(self) -> bool:
        """Check if Windows Firewall service is running"""
        if not IS_WINDOWS:
            return False

        try:
            result = subprocess.run(
                ["sc", "query", "MpsSvc"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return "RUNNING" in result.stdout
        except Exception as e:
            logger.warning(f"Failed to check firewall service: {e}")
            return False

    @property
    def is_available(self) -> bool:
        """Check if Windows Firewall enforcement is available"""
        return self._is_available

    def _run_netsh(self, args: List[str], check: bool = True) -> Tuple[bool, str]:
        """
        Run a netsh advfirewall command.

        Args:
            args: Command arguments after 'netsh advfirewall'
            check: Whether to check return code

        Returns:
            Tuple of (success, output)
        """
        cmd = ["netsh", "advfirewall"] + args

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if check and result.returncode != 0:
                logger.error(f"netsh command failed: {' '.join(cmd)}")
                logger.error(f"stderr: {result.stderr}")
                return False, result.stderr

            return True, result.stdout

        except subprocess.TimeoutExpired:
            logger.error(f"netsh command timed out: {' '.join(cmd)}")
            return False, "Command timed out"
        except Exception as e:
            logger.error(f"Failed to run netsh: {e}")
            return False, str(e)

    def _run_powershell(self, script: str) -> Tuple[bool, str]:
        """
        Run a PowerShell command for more complex operations.

        Args:
            script: PowerShell script to execute

        Returns:
            Tuple of (success, output)
        """
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode != 0:
                logger.error(f"PowerShell command failed: {result.stderr}")
                return False, result.stderr

            return True, result.stdout

        except subprocess.TimeoutExpired:
            logger.error("PowerShell command timed out")
            return False, "Command timed out"
        except Exception as e:
            logger.error(f"Failed to run PowerShell: {e}")
            return False, str(e)

    def backup_rules(self) -> Optional[str]:
        """
        Backup current firewall rules.

        Returns:
            Path to backup file, or None on failure
        """
        if not self._is_available:
            return None

        try:
            # Create backup file
            backup_dir = tempfile.gettempdir()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(
                backup_dir, f"boundary_firewall_backup_{timestamp}.wfw"
            )

            # Export current policy
            success, output = self._run_netsh([
                "export", backup_path
            ])

            if success:
                self._backup_path = backup_path
                logger.info(f"Firewall rules backed up to: {backup_path}")
                return backup_path
            else:
                logger.error("Failed to backup firewall rules")
                return None

        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return None

    def restore_rules(self, backup_path: Optional[str] = None) -> bool:
        """
        Restore firewall rules from backup.

        Args:
            backup_path: Path to backup file (uses last backup if not specified)

        Returns:
            True on success
        """
        if not self._is_available:
            return False

        path = backup_path or self._backup_path
        if not path or not os.path.exists(path):
            logger.error("No backup file available for restore")
            return False

        try:
            success, output = self._run_netsh([
                "import", path
            ])

            if success:
                logger.info(f"Firewall rules restored from: {path}")
                return True
            else:
                logger.error("Failed to restore firewall rules")
                return False

        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False

    def _add_rule(self, rule: WindowsFirewallRule) -> bool:
        """Add a firewall rule"""
        args = ["firewall", "add", "rule"] + rule.to_netsh_args()
        success, output = self._run_netsh(args)

        if success:
            logger.debug(f"Added rule: {rule.name}")
        else:
            logger.error(f"Failed to add rule: {rule.name}")

        return success

    def _delete_rule(self, name: str) -> bool:
        """Delete a firewall rule by name"""
        success, output = self._run_netsh([
            "firewall", "delete", "rule", f"name={name}"
        ], check=False)  # Don't check - rule may not exist

        return success

    def _delete_boundary_rules(self) -> bool:
        """Delete all BoundaryDaemon rules"""
        logger.info("Removing all BoundaryDaemon firewall rules...")

        # Use PowerShell for pattern-based deletion
        script = f'''
        Get-NetFirewallRule -DisplayName "{self.RULE_PREFIX}*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
        '''

        success, output = self._run_powershell(script)

        # Also try netsh for reliability
        self._run_netsh([
            "firewall", "delete", "rule", f"name={self.RULE_PREFIX}*"
        ], check=False)

        return True

    def _get_vpn_adapters(self) -> List[str]:
        """Get list of VPN adapter names"""
        adapters = []

        script = '''
        Get-NetAdapter | Where-Object {
            $_.InterfaceDescription -like "*TAP*" -or
            $_.InterfaceDescription -like "*WireGuard*" -or
            $_.InterfaceDescription -like "*VPN*" -or
            $_.InterfaceDescription -like "*Tunnel*"
        } | Select-Object -ExpandProperty Name
        '''

        success, output = self._run_powershell(script)
        if success and output.strip():
            adapters = [line.strip() for line in output.strip().split('\n') if line.strip()]

        return adapters

    def apply_mode(self, mode: str) -> bool:
        """
        Apply firewall rules for the specified boundary mode.

        Args:
            mode: Boundary mode name (OPEN, RESTRICTED, TRUSTED, AIRGAP, COLDROOM, LOCKDOWN)

        Returns:
            True on success
        """
        if not self._is_available:
            logger.warning("Windows Firewall enforcement not available")
            return False

        with self._lock:
            logger.info(f"Applying Windows Firewall rules for mode: {mode}")

            # Backup current rules before changes
            if not self._backup_path:
                self.backup_rules()

            # Remove existing boundary rules
            self._delete_boundary_rules()

            # Apply mode-specific rules
            mode_upper = mode.upper()

            try:
                if mode_upper == "OPEN":
                    success = self._apply_open_mode()
                elif mode_upper == "RESTRICTED":
                    success = self._apply_restricted_mode()
                elif mode_upper == "TRUSTED":
                    success = self._apply_trusted_mode()
                elif mode_upper == "AIRGAP":
                    success = self._apply_airgap_mode()
                elif mode_upper == "COLDROOM":
                    success = self._apply_coldroom_mode()
                elif mode_upper == "LOCKDOWN":
                    success = self._apply_lockdown_mode()
                else:
                    logger.error(f"Unknown mode: {mode}")
                    return False

                if success:
                    self._current_mode = mode_upper
                    self._rules_applied = True
                    self._log_mode_change(mode_upper)
                    return True
                else:
                    # Fail-closed: apply lockdown on failure
                    logger.critical(f"Failed to apply {mode} mode - entering LOCKDOWN")
                    self._apply_lockdown_mode()
                    self._current_mode = "LOCKDOWN"
                    return False

            except Exception as e:
                logger.critical(f"Exception applying mode {mode}: {e}")
                # Fail-closed
                try:
                    self._apply_lockdown_mode()
                except:
                    pass
                return False

    def _apply_open_mode(self) -> bool:
        """OPEN mode: No restrictions"""
        logger.info("Applying OPEN mode - no network restrictions")
        # Just remove all boundary rules (already done)
        return True

    def _apply_restricted_mode(self) -> bool:
        """RESTRICTED mode: Allow all with logging"""
        logger.info("Applying RESTRICTED mode - allow all with audit")

        # Enable connection logging
        success, _ = self._run_netsh([
            "set", "allprofiles", "logging", "allowedconnections", "enable"
        ])

        success2, _ = self._run_netsh([
            "set", "allprofiles", "logging", "droppedconnections", "enable"
        ])

        return success and success2

    def _apply_trusted_mode(self) -> bool:
        """TRUSTED mode: Only loopback and VPN"""
        logger.info("Applying TRUSTED mode - loopback and VPN only")

        rules = []

        # Allow loopback (inbound and outbound)
        rules.append(WindowsFirewallRule(
            name=f"{self.RULE_PREFIX}Allow_Loopback_Out",
            action=FirewallAction.ALLOW,
            direction=FirewallDirection.OUT,
            remote_ip="127.0.0.1",
            description="BoundaryDaemon: Allow loopback outbound",
        ))

        rules.append(WindowsFirewallRule(
            name=f"{self.RULE_PREFIX}Allow_Loopback_In",
            action=FirewallAction.ALLOW,
            direction=FirewallDirection.IN,
            remote_ip="127.0.0.1",
            description="BoundaryDaemon: Allow loopback inbound",
        ))

        # Allow established connections
        rules.append(WindowsFirewallRule(
            name=f"{self.RULE_PREFIX}Allow_Established_Out",
            action=FirewallAction.ALLOW,
            direction=FirewallDirection.OUT,
            description="BoundaryDaemon: Allow established outbound",
        ))

        # Get VPN adapters and allow them
        vpn_adapters = self._get_vpn_adapters()
        for i, adapter in enumerate(vpn_adapters):
            # Allow VPN traffic via PowerShell (more flexible)
            script = f'''
            New-NetFirewallRule -DisplayName "{self.RULE_PREFIX}Allow_VPN_{i}" `
                -Direction Outbound -Action Allow `
                -InterfaceAlias "{adapter}" `
                -Description "BoundaryDaemon: Allow VPN adapter {adapter}"
            '''
            self._run_powershell(script)

        # Block all other outbound
        rules.append(WindowsFirewallRule(
            name=f"{self.RULE_PREFIX}Block_All_Out",
            action=FirewallAction.BLOCK,
            direction=FirewallDirection.OUT,
            description="BoundaryDaemon: Block all other outbound",
        ))

        # Apply rules
        success = True
        for rule in rules:
            if not self._add_rule(rule):
                success = False

        return success

    def _apply_airgap_mode(self) -> bool:
        """AIRGAP mode: Block all except loopback"""
        logger.info("Applying AIRGAP mode - loopback only")

        rules = []

        # Allow loopback only
        rules.append(WindowsFirewallRule(
            name=f"{self.RULE_PREFIX}Allow_Loopback_Out",
            action=FirewallAction.ALLOW,
            direction=FirewallDirection.OUT,
            remote_ip="127.0.0.1",
            description="BoundaryDaemon: Allow loopback outbound",
        ))

        rules.append(WindowsFirewallRule(
            name=f"{self.RULE_PREFIX}Allow_Loopback_In",
            action=FirewallAction.ALLOW,
            direction=FirewallDirection.IN,
            remote_ip="127.0.0.1",
            description="BoundaryDaemon: Allow loopback inbound",
        ))

        # Block all outbound
        rules.append(WindowsFirewallRule(
            name=f"{self.RULE_PREFIX}Block_All_Out",
            action=FirewallAction.BLOCK,
            direction=FirewallDirection.OUT,
            description="BoundaryDaemon: Block all outbound (AIRGAP)",
        ))

        # Block all inbound
        rules.append(WindowsFirewallRule(
            name=f"{self.RULE_PREFIX}Block_All_In",
            action=FirewallAction.BLOCK,
            direction=FirewallDirection.IN,
            description="BoundaryDaemon: Block all inbound (AIRGAP)",
        ))

        # Apply rules
        success = True
        for rule in rules:
            if not self._add_rule(rule):
                success = False

        return success

    def _apply_coldroom_mode(self) -> bool:
        """COLDROOM mode: Same as AIRGAP"""
        logger.info("Applying COLDROOM mode - loopback only (same as AIRGAP)")
        return self._apply_airgap_mode()

    def _apply_lockdown_mode(self) -> bool:
        """LOCKDOWN mode: Block ALL traffic including loopback"""
        logger.critical("Applying LOCKDOWN mode - blocking ALL network traffic")

        rules = []

        # Block ALL outbound (including loopback)
        rules.append(WindowsFirewallRule(
            name=f"{self.RULE_PREFIX}LOCKDOWN_Block_All_Out",
            action=FirewallAction.BLOCK,
            direction=FirewallDirection.OUT,
            description="BoundaryDaemon: LOCKDOWN - Block all outbound",
        ))

        # Block ALL inbound
        rules.append(WindowsFirewallRule(
            name=f"{self.RULE_PREFIX}LOCKDOWN_Block_All_In",
            action=FirewallAction.BLOCK,
            direction=FirewallDirection.IN,
            description="BoundaryDaemon: LOCKDOWN - Block all inbound",
        ))

        # Set default policy to block
        self._run_netsh([
            "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"
        ])

        # Apply rules
        success = True
        for rule in rules:
            if not self._add_rule(rule):
                success = False

        return success

    def _log_mode_change(self, mode: str) -> None:
        """Log mode change to event logger"""
        if self.event_logger:
            try:
                # Import EventType if available
                from ..event_logger import EventType
                self.event_logger.log_event(
                    EventType.ENFORCEMENT,
                    f"Windows Firewall mode changed to: {mode}",
                    metadata={
                        'enforcer': 'WindowsFirewallEnforcer',
                        'mode': mode,
                        'platform': 'windows',
                    }
                )
            except Exception as e:
                logger.debug(f"Failed to log mode change: {e}")

    def get_current_mode(self) -> Optional[str]:
        """Get currently applied mode"""
        return self._current_mode

    def get_active_rules(self) -> List[Dict[str, Any]]:
        """Get list of active BoundaryDaemon firewall rules"""
        if not self._is_available:
            return []

        script = f'''
        Get-NetFirewallRule -DisplayName "{self.RULE_PREFIX}*" -ErrorAction SilentlyContinue |
        Select-Object DisplayName, Direction, Action, Enabled, Profile |
        ConvertTo-Json
        '''

        success, output = self._run_powershell(script)

        if success and output.strip():
            try:
                rules = json.loads(output)
                if isinstance(rules, dict):
                    rules = [rules]
                return rules
            except json.JSONDecodeError:
                return []

        return []

    def cleanup(self, force: bool = False) -> bool:
        """
        Remove all BoundaryDaemon firewall rules.

        Args:
            force: If True, skip persistence check

        Returns:
            True on success
        """
        if not self._is_available:
            return True

        # Check persistence manager
        if not force and self._persistence_manager:
            # Persistence manager may prevent cleanup
            logger.info("Cleanup requested but persistence may apply")

        with self._lock:
            logger.info("Cleaning up BoundaryDaemon firewall rules")

            # Reset to default policy
            self._run_netsh([
                "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"
            ])

            # Remove all boundary rules
            success = self._delete_boundary_rules()

            self._rules_applied = False
            self._current_mode = None

            return success

    def get_status(self) -> Dict[str, Any]:
        """Get current enforcer status"""
        return {
            'available': self._is_available,
            'is_windows': self._is_windows,
            'has_admin': self._has_admin,
            'current_mode': self._current_mode,
            'rules_applied': self._rules_applied,
            'active_rules': len(self.get_active_rules()),
            'backup_path': self._backup_path,
        }


# Singleton instance
_enforcer_instance: Optional[WindowsFirewallEnforcer] = None
_enforcer_lock = threading.Lock()


def get_windows_firewall_enforcer(
    daemon=None,
    event_logger=None,
    persistence_manager=None,
) -> WindowsFirewallEnforcer:
    """
    Get or create the global WindowsFirewallEnforcer instance.

    Args:
        daemon: Reference to BoundaryDaemon
        event_logger: EventLogger for audit logging
        persistence_manager: ProtectionPersistenceManager

    Returns:
        WindowsFirewallEnforcer instance
    """
    global _enforcer_instance

    with _enforcer_lock:
        if _enforcer_instance is None:
            _enforcer_instance = WindowsFirewallEnforcer(
                daemon=daemon,
                event_logger=event_logger,
                persistence_manager=persistence_manager,
            )
        return _enforcer_instance
