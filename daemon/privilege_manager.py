"""
Privilege Manager - Tracks and alerts on privilege-related security issues.

This module addresses the Critical Finding: "Root Privilege Required = Silent Failure"

Previously, security enforcement modules would silently disable when running
without root privileges, leaving the system unprotected without clear alerting.

This module provides:
- Centralized privilege tracking across all enforcement modules
- Critical alerts when enforcement is unavailable
- Fail-closed behavior for security-critical boundary modes
- Security status reporting for operators
- Event logging of all privilege-related issues

SECURITY: Systems in AIRGAP, COLDROOM, or LOCKDOWN modes MUST have
working enforcement. This module ensures operators are clearly alerted
when this is not the case.
"""

import os
import sys
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# Cross-platform privilege detection
def _is_windows() -> bool:
    """Check if running on Windows."""
    return sys.platform == 'win32'


def _is_admin_windows() -> bool:
    """Check if running as admin on Windows."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def is_elevated() -> bool:
    """Check if running with elevated/root privileges (cross-platform)."""
    if _is_windows():
        return _is_admin_windows()
    else:
        return os.geteuid() == 0


def get_effective_uid() -> int:
    """Get effective user ID (cross-platform)."""
    if _is_windows():
        # On Windows, return 0 if admin, 1000 otherwise
        return 0 if _is_admin_windows() else 1000
    else:
        return os.geteuid()


def get_effective_gid() -> int:
    """Get effective group ID (cross-platform)."""
    if _is_windows():
        # On Windows, return 0 if admin, 1000 otherwise
        return 0 if _is_admin_windows() else 1000
    else:
        return os.getegid()


class PrivilegeLevel(Enum):
    """Privilege levels for operations"""
    NONE = "none"           # No special privileges needed
    ELEVATED = "elevated"   # CAP_NET_ADMIN, CAP_SYS_ADMIN, etc.
    ROOT = "root"           # Full root access (euid=0)


class EnforcementModule(Enum):
    """Security enforcement modules that may require privileges"""
    NETWORK = "network"         # iptables/nftables network isolation
    USB = "usb"                 # USB device blocking
    PROCESS = "process"         # Seccomp syscall filtering
    ARP = "arp"                 # ARP spoofing protection
    DNS = "dns"                 # DNS blocking/filtering
    ANTIVIRUS = "antivirus"     # Process killing, file quarantine
    LOG_PROTECTION = "log_protection"  # chattr append-only logs
    FILE_INTEGRITY = "file_integrity"  # File system monitoring


class PrivilegeAlert(Enum):
    """Types of privilege-related alerts"""
    INFO = "info"               # Informational
    WARNING = "warning"         # Degraded but acceptable
    CRITICAL = "critical"       # Security enforcement disabled
    FATAL = "fatal"             # Cannot operate safely in requested mode


@dataclass
class PrivilegeIssue:
    """Record of a privilege-related issue"""
    module: EnforcementModule
    required_privilege: PrivilegeLevel
    actual_privilege: PrivilegeLevel
    operation: str
    alert_level: PrivilegeAlert
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    boundary_mode: str = ""


@dataclass
class PrivilegeStatus:
    """Overall privilege status for the daemon"""
    has_root: bool = False
    effective_uid: int = -1
    effective_gid: int = -1
    modules_available: Dict[str, bool] = field(default_factory=dict)
    modules_degraded: Dict[str, str] = field(default_factory=dict)
    critical_issues: List[PrivilegeIssue] = field(default_factory=list)
    can_enforce_airgap: bool = False
    can_enforce_lockdown: bool = False


class PrivilegeManager:
    """
    Manages privilege checking and alerting for security enforcement.

    SECURITY: This class ensures that privilege issues are never silent.
    All enforcement failures due to insufficient privileges are logged,
    tracked, and surfaced to operators.
    """

    # Boundary modes that REQUIRE working enforcement
    ENFORCEMENT_REQUIRED_MODES = {'AIRGAP', 'COLDROOM', 'LOCKDOWN'}

    # Modules required for each security-critical mode
    MODE_REQUIREMENTS = {
        'AIRGAP': {EnforcementModule.NETWORK, EnforcementModule.USB, EnforcementModule.DNS},
        'COLDROOM': {EnforcementModule.NETWORK, EnforcementModule.USB, EnforcementModule.PROCESS},
        'LOCKDOWN': {EnforcementModule.NETWORK, EnforcementModule.USB, EnforcementModule.PROCESS,
                     EnforcementModule.ARP, EnforcementModule.DNS},
    }

    def __init__(self, event_logger=None, on_critical_callback: Optional[Callable] = None):
        """
        Initialize the privilege manager.

        Args:
            event_logger: Event logger for recording privilege issues
            on_critical_callback: Called when critical privilege issues occur
        """
        self._event_logger = event_logger
        self._on_critical = on_critical_callback

        # Track privileges (cross-platform)
        self._has_root = is_elevated()
        self._effective_uid = get_effective_uid()
        self._effective_gid = get_effective_gid()

        # Track module status
        self._module_status: Dict[EnforcementModule, bool] = {}
        self._module_reasons: Dict[EnforcementModule, str] = {}

        # Track all privilege issues
        self._issues: List[PrivilegeIssue] = []
        self._critical_count = 0

        # Log initial privilege status
        self._log_initial_status()

    def _log_initial_status(self):
        """Log the initial privilege status."""
        if self._has_root:
            logger.info("Privilege Manager: Running with root privileges (euid=0)")
        else:
            logger.warning(
                f"Privilege Manager: Running WITHOUT root (euid={self._effective_uid}). "
                "Some enforcement features will be unavailable."
            )

    def check_root(self) -> bool:
        """Check if running as root."""
        return self._has_root

    def register_module(
        self,
        module: EnforcementModule,
        is_available: bool,
        reason: str = "",
    ):
        """
        Register an enforcement module's availability status.

        Args:
            module: The enforcement module
            is_available: Whether the module is fully functional
            reason: Reason if not available
        """
        self._module_status[module] = is_available
        self._module_reasons[module] = reason

        if not is_available:
            issue = PrivilegeIssue(
                module=module,
                required_privilege=PrivilegeLevel.ROOT,
                actual_privilege=PrivilegeLevel.NONE if not self._has_root else PrivilegeLevel.ROOT,
                operation="module_initialization",
                alert_level=PrivilegeAlert.CRITICAL if module in self._get_critical_modules() else PrivilegeAlert.WARNING,
                message=f"Module {module.value} unavailable: {reason}",
            )
            self._issues.append(issue)

            if issue.alert_level == PrivilegeAlert.CRITICAL:
                self._critical_count += 1
                self._log_critical_issue(issue)

    def _get_critical_modules(self) -> Set[EnforcementModule]:
        """Get modules that are critical for security enforcement."""
        critical = set()
        for mode, modules in self.MODE_REQUIREMENTS.items():
            critical.update(modules)
        return critical

    def _log_critical_issue(self, issue: PrivilegeIssue):
        """Log a critical privilege issue."""
        message = (
            f"CRITICAL PRIVILEGE ISSUE: {issue.module.value} - {issue.message}"
        )
        logger.critical(message)

        if self._event_logger:
            try:
                self._event_logger.log(
                    event_type="privilege_critical",
                    severity="critical",
                    details={
                        'module': issue.module.value,
                        'operation': issue.operation,
                        'message': issue.message,
                        'required_privilege': issue.required_privilege.value,
                        'actual_privilege': issue.actual_privilege.value,
                        'has_root': self._has_root,
                        'euid': self._effective_uid,
                    }
                )
            except Exception:
                pass  # Event logger might not be initialized yet

        if self._on_critical:
            try:
                self._on_critical(issue)
            except Exception:
                pass

    def log_privilege_failure(
        self,
        module: EnforcementModule,
        operation: str,
        required: PrivilegeLevel = PrivilegeLevel.ROOT,
        boundary_mode: str = "",
    ) -> PrivilegeIssue:
        """
        Log a privilege failure for an operation.

        This method should be called whenever an operation fails due to
        insufficient privileges. It ensures the failure is properly tracked
        and logged, never silent.

        Args:
            module: The enforcement module
            operation: What operation failed
            required: What privilege level was required
            boundary_mode: Current boundary mode (if applicable)

        Returns:
            The created PrivilegeIssue record
        """
        # Determine alert level based on context
        alert_level = PrivilegeAlert.WARNING

        # Critical if in enforcement-required mode
        if boundary_mode.upper() in self.ENFORCEMENT_REQUIRED_MODES:
            required_modules = self.MODE_REQUIREMENTS.get(boundary_mode.upper(), set())
            if module in required_modules:
                alert_level = PrivilegeAlert.CRITICAL

        issue = PrivilegeIssue(
            module=module,
            required_privilege=required,
            actual_privilege=PrivilegeLevel.NONE if not self._has_root else PrivilegeLevel.ELEVATED,
            operation=operation,
            alert_level=alert_level,
            message=f"Operation '{operation}' requires {required.value} privileges",
            boundary_mode=boundary_mode,
        )
        self._issues.append(issue)

        # Log appropriately based on severity
        if alert_level == PrivilegeAlert.CRITICAL:
            self._critical_count += 1
            logger.critical(
                f"PRIVILEGE FAILURE [{boundary_mode}]: {module.value}/{operation} - "
                f"Requires {required.value}, running as euid={self._effective_uid}"
            )
            if self._event_logger:
                try:
                    self._event_logger.log(
                        event_type="privilege_failure",
                        severity="critical",
                        details={
                            'module': module.value,
                            'operation': operation,
                            'boundary_mode': boundary_mode,
                            'required_privilege': required.value,
                            'euid': self._effective_uid,
                        }
                    )
                except Exception:
                    pass
        else:
            logger.warning(
                f"Privilege failure: {module.value}/{operation} requires {required.value}"
            )

        return issue

    def can_enforce_mode(self, mode: str) -> Tuple[bool, List[str]]:
        """
        Check if a boundary mode can be properly enforced.

        Args:
            mode: The boundary mode to check (e.g., 'AIRGAP', 'LOCKDOWN')

        Returns:
            (can_enforce, list of missing modules/capabilities)
        """
        mode_upper = mode.upper()

        if mode_upper not in self.MODE_REQUIREMENTS:
            return (True, [])  # Mode doesn't have specific requirements

        required_modules = self.MODE_REQUIREMENTS[mode_upper]
        missing = []

        for module in required_modules:
            if not self._module_status.get(module, False):
                reason = self._module_reasons.get(module, "Not initialized")
                missing.append(f"{module.value}: {reason}")

        can_enforce = len(missing) == 0
        return (can_enforce, missing)

    def assert_mode_enforceable(self, mode: str) -> Tuple[bool, str]:
        """
        Assert that a mode can be enforced, logging critical alert if not.

        This should be called when transitioning to a security-critical mode.
        If enforcement is not possible, a critical alert is generated.

        Args:
            mode: The boundary mode being entered

        Returns:
            (is_enforceable, message)
        """
        can_enforce, missing = self.can_enforce_mode(mode)

        if can_enforce:
            return (True, f"Mode {mode} can be fully enforced")

        # Generate critical alert
        missing_str = "; ".join(missing)
        message = (
            f"SECURITY CRITICAL: Cannot fully enforce {mode} mode. "
            f"Missing: [{missing_str}]. "
            f"System is vulnerable to attacks that these modules would prevent."
        )

        logger.critical(message)
        print(f"\n{'='*70}")
        print(f"  CRITICAL SECURITY WARNING")
        print(f"{'='*70}")
        print(f"  Cannot enforce {mode} mode - missing enforcement capabilities:")
        for m in missing:
            print(f"    - {m}")
        print(f"\n  The system will operate in DEGRADED SECURITY mode.")
        print(f"  To fix: Run the daemon as root (sudo) or with required capabilities.")
        print(f"{'='*70}\n")

        if self._event_logger:
            try:
                self._event_logger.log(
                    event_type="mode_enforcement_failure",
                    severity="critical",
                    details={
                        'mode': mode,
                        'missing_modules': missing,
                        'has_root': self._has_root,
                        'euid': self._effective_uid,
                    }
                )
            except Exception:
                pass

        return (False, message)

    def get_status(self) -> PrivilegeStatus:
        """Get the current privilege status."""
        # Check which modes can be enforced
        can_airgap, _ = self.can_enforce_mode('AIRGAP')
        can_lockdown, _ = self.can_enforce_mode('LOCKDOWN')

        return PrivilegeStatus(
            has_root=self._has_root,
            effective_uid=self._effective_uid,
            effective_gid=self._effective_gid,
            modules_available={m.value: v for m, v in self._module_status.items()},
            modules_degraded={m.value: r for m, r in self._module_reasons.items() if not self._module_status.get(m, True)},
            critical_issues=[i for i in self._issues if i.alert_level == PrivilegeAlert.CRITICAL],
            can_enforce_airgap=can_airgap,
            can_enforce_lockdown=can_lockdown,
        )

    def get_issues(self, severity: Optional[PrivilegeAlert] = None) -> List[PrivilegeIssue]:
        """Get all privilege issues, optionally filtered by severity."""
        if severity:
            return [i for i in self._issues if i.alert_level == severity]
        return list(self._issues)

    def get_critical_count(self) -> int:
        """Get the count of critical privilege issues."""
        return self._critical_count

    def print_security_status(self):
        """Print a security status report to stdout."""
        status = self.get_status()

        print(f"\n{'='*60}")
        print("  SECURITY ENFORCEMENT STATUS")
        print(f"{'='*60}")
        print(f"  Effective UID:     {status.effective_uid} {'(root)' if status.has_root else '(NOT ROOT)'}")
        print(f"  Effective GID:     {status.effective_gid}")
        print(f"  Can enforce AIRGAP:   {'YES' if status.can_enforce_airgap else 'NO - DEGRADED'}")
        print(f"  Can enforce LOCKDOWN: {'YES' if status.can_enforce_lockdown else 'NO - DEGRADED'}")

        print(f"\n  Module Status:")
        for module, available in status.modules_available.items():
            status_str = "AVAILABLE" if available else f"UNAVAILABLE ({status.modules_degraded.get(module, 'unknown')})"
            print(f"    {module:<20} {status_str}")

        if status.critical_issues:
            print(f"\n  CRITICAL ISSUES ({len(status.critical_issues)}):")
            for issue in status.critical_issues[:5]:  # Show first 5
                print(f"    - {issue.module.value}: {issue.message}")

        print(f"{'='*60}\n")

    def require_root_or_warn(self, operation: str) -> bool:
        """
        Check for root and print warning if not available.

        Args:
            operation: Description of the operation requiring root

        Returns:
            True if running as root, False otherwise
        """
        if self._has_root:
            return True

        print(f"\n  WARNING: '{operation}' requires root privileges.")
        print(f"  Running as euid={self._effective_uid}. Some features will be unavailable.")
        print(f"  To fix: Run with sudo or as root.\n")

        return False


# Global privilege manager instance
_privilege_manager: Optional[PrivilegeManager] = None


def get_privilege_manager() -> Optional[PrivilegeManager]:
    """Get the global privilege manager instance."""
    return _privilege_manager


def set_privilege_manager(manager: PrivilegeManager):
    """Set the global privilege manager instance."""
    global _privilege_manager
    _privilege_manager = manager


def check_root_or_log(
    module: EnforcementModule,
    operation: str,
    boundary_mode: str = "",
) -> bool:
    """
    Convenience function to check root and log failure if not.

    Args:
        module: The enforcement module
        operation: What operation requires root
        boundary_mode: Current boundary mode

    Returns:
        True if running as root/admin, False otherwise (with logging)
    """
    if is_elevated():
        return True

    manager = get_privilege_manager()
    if manager:
        manager.log_privilege_failure(
            module=module,
            operation=operation,
            boundary_mode=boundary_mode,
        )
    else:
        logger.warning(f"Root/admin required for {module.value}/{operation} but running without elevation")

    return False
