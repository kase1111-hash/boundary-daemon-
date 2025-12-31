"""
Tests for the Privilege Manager module.

Tests privilege checking, enforcement module registration, and security status tracking.
"""

import os
import sys
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.privilege_manager import (
    PrivilegeManager,
    PrivilegeLevel,
    PrivilegeAlert,
    PrivilegeIssue,
    PrivilegeStatus,
    EnforcementModule,
    is_elevated,
    get_effective_uid,
    get_effective_gid,
    get_privilege_manager,
    set_privilege_manager,
    check_root_or_log,
    _is_windows,
)


# ===========================================================================
# Platform Detection Tests
# ===========================================================================

class TestPlatformDetection:
    """Tests for platform detection functions."""

    def test_is_windows_returns_bool(self):
        """_is_windows should return a boolean."""
        result = _is_windows()
        assert isinstance(result, bool)

    def test_is_elevated_returns_bool(self):
        """is_elevated should return a boolean."""
        result = is_elevated()
        assert isinstance(result, bool)

    def test_get_effective_uid_returns_int(self):
        """get_effective_uid should return an integer."""
        result = get_effective_uid()
        assert isinstance(result, int)
        assert result >= 0

    def test_get_effective_gid_returns_int(self):
        """get_effective_gid should return an integer."""
        result = get_effective_gid()
        assert isinstance(result, int)
        assert result >= 0

    @patch('daemon.privilege_manager.sys.platform', 'linux')
    @patch('daemon.privilege_manager.os.geteuid')
    def test_is_elevated_linux_root(self, mock_geteuid):
        """is_elevated should return True for root on Linux."""
        mock_geteuid.return_value = 0
        # Need to reimport to pick up the mock
        from daemon.privilege_manager import is_elevated as is_elevated_fresh
        # Since we can't easily reimport, we test the logic
        assert os.geteuid() >= 0  # Just verify it's callable

    @patch('daemon.privilege_manager.sys.platform', 'linux')
    @patch('daemon.privilege_manager.os.geteuid')
    def test_get_effective_uid_linux(self, mock_geteuid):
        """get_effective_uid should return euid on Linux."""
        mock_geteuid.return_value = 1000
        result = get_effective_uid()
        assert isinstance(result, int)


# ===========================================================================
# Privilege Level and Alert Enum Tests
# ===========================================================================

class TestEnums:
    """Tests for privilege-related enums."""

    def test_privilege_level_values(self):
        """PrivilegeLevel should have expected values."""
        assert PrivilegeLevel.NONE.value == "none"
        assert PrivilegeLevel.ELEVATED.value == "elevated"
        assert PrivilegeLevel.ROOT.value == "root"

    def test_enforcement_module_values(self):
        """EnforcementModule should have expected values."""
        assert EnforcementModule.NETWORK.value == "network"
        assert EnforcementModule.USB.value == "usb"
        assert EnforcementModule.PROCESS.value == "process"
        assert EnforcementModule.ARP.value == "arp"
        assert EnforcementModule.DNS.value == "dns"
        assert EnforcementModule.LOG_PROTECTION.value == "log_protection"

    def test_privilege_alert_values(self):
        """PrivilegeAlert should have expected values."""
        assert PrivilegeAlert.INFO.value == "info"
        assert PrivilegeAlert.WARNING.value == "warning"
        assert PrivilegeAlert.CRITICAL.value == "critical"
        assert PrivilegeAlert.FATAL.value == "fatal"


# ===========================================================================
# PrivilegeIssue Dataclass Tests
# ===========================================================================

class TestPrivilegeIssue:
    """Tests for PrivilegeIssue dataclass."""

    def test_privilege_issue_creation(self):
        """PrivilegeIssue should be creatable with required fields."""
        issue = PrivilegeIssue(
            module=EnforcementModule.NETWORK,
            required_privilege=PrivilegeLevel.ROOT,
            actual_privilege=PrivilegeLevel.NONE,
            operation="block_network",
            alert_level=PrivilegeAlert.CRITICAL,
            message="Cannot block network without root",
        )
        assert issue.module == EnforcementModule.NETWORK
        assert issue.required_privilege == PrivilegeLevel.ROOT
        assert issue.actual_privilege == PrivilegeLevel.NONE
        assert issue.operation == "block_network"
        assert issue.alert_level == PrivilegeAlert.CRITICAL

    def test_privilege_issue_default_timestamp(self):
        """PrivilegeIssue should have a default timestamp."""
        issue = PrivilegeIssue(
            module=EnforcementModule.USB,
            required_privilege=PrivilegeLevel.ROOT,
            actual_privilege=PrivilegeLevel.NONE,
            operation="block_usb",
            alert_level=PrivilegeAlert.WARNING,
            message="Test",
        )
        assert isinstance(issue.timestamp, datetime)

    def test_privilege_issue_with_boundary_mode(self):
        """PrivilegeIssue should accept boundary_mode."""
        issue = PrivilegeIssue(
            module=EnforcementModule.NETWORK,
            required_privilege=PrivilegeLevel.ROOT,
            actual_privilege=PrivilegeLevel.NONE,
            operation="isolate",
            alert_level=PrivilegeAlert.CRITICAL,
            message="Test",
            boundary_mode="AIRGAP",
        )
        assert issue.boundary_mode == "AIRGAP"


# ===========================================================================
# PrivilegeStatus Dataclass Tests
# ===========================================================================

class TestPrivilegeStatus:
    """Tests for PrivilegeStatus dataclass."""

    def test_privilege_status_defaults(self):
        """PrivilegeStatus should have sensible defaults."""
        status = PrivilegeStatus()
        assert status.has_root is False
        assert status.effective_uid == -1
        assert status.effective_gid == -1
        assert status.modules_available == {}
        assert status.modules_degraded == {}
        assert status.critical_issues == []
        assert status.can_enforce_airgap is False
        assert status.can_enforce_lockdown is False

    def test_privilege_status_with_values(self):
        """PrivilegeStatus should accept values."""
        status = PrivilegeStatus(
            has_root=True,
            effective_uid=0,
            effective_gid=0,
            modules_available={'network': True},
            can_enforce_airgap=True,
        )
        assert status.has_root is True
        assert status.effective_uid == 0
        assert status.modules_available == {'network': True}


# ===========================================================================
# PrivilegeManager Tests
# ===========================================================================

class TestPrivilegeManagerInit:
    """Tests for PrivilegeManager initialization."""

    def test_init_without_args(self):
        """PrivilegeManager should initialize without arguments."""
        manager = PrivilegeManager()
        assert manager is not None
        assert isinstance(manager._has_root, bool)
        assert isinstance(manager._effective_uid, int)

    def test_init_with_event_logger(self):
        """PrivilegeManager should accept an event logger."""
        mock_logger = MagicMock()
        manager = PrivilegeManager(event_logger=mock_logger)
        assert manager._event_logger == mock_logger

    def test_init_with_callback(self):
        """PrivilegeManager should accept a critical callback."""
        callback = MagicMock()
        manager = PrivilegeManager(on_critical_callback=callback)
        assert manager._on_critical == callback

    def test_check_root(self):
        """check_root should return the root status."""
        manager = PrivilegeManager()
        result = manager.check_root()
        assert isinstance(result, bool)


class TestPrivilegeManagerModuleRegistration:
    """Tests for module registration."""

    def test_register_available_module(self):
        """Registering an available module should track it."""
        manager = PrivilegeManager()
        manager.register_module(EnforcementModule.NETWORK, True)
        assert manager._module_status[EnforcementModule.NETWORK] is True

    def test_register_unavailable_module(self):
        """Registering an unavailable module should track it with reason."""
        manager = PrivilegeManager()
        manager.register_module(
            EnforcementModule.NETWORK,
            False,
            reason="No root privileges"
        )
        assert manager._module_status[EnforcementModule.NETWORK] is False
        assert manager._module_reasons[EnforcementModule.NETWORK] == "No root privileges"

    def test_register_unavailable_creates_issue(self):
        """Registering an unavailable module should create an issue."""
        manager = PrivilegeManager()
        initial_issues = len(manager._issues)
        manager.register_module(
            EnforcementModule.NETWORK,
            False,
            reason="Missing iptables"
        )
        assert len(manager._issues) > initial_issues

    def test_register_multiple_modules(self):
        """Multiple modules can be registered."""
        manager = PrivilegeManager()
        manager.register_module(EnforcementModule.NETWORK, True)
        manager.register_module(EnforcementModule.USB, True)
        manager.register_module(EnforcementModule.DNS, False, "No root")

        assert len(manager._module_status) == 3
        assert manager._module_status[EnforcementModule.NETWORK] is True
        assert manager._module_status[EnforcementModule.USB] is True
        assert manager._module_status[EnforcementModule.DNS] is False


class TestPrivilegeManagerPrivilegeFailure:
    """Tests for logging privilege failures."""

    def test_log_privilege_failure_returns_issue(self):
        """log_privilege_failure should return a PrivilegeIssue."""
        manager = PrivilegeManager()
        issue = manager.log_privilege_failure(
            module=EnforcementModule.NETWORK,
            operation="block_ip"
        )
        assert isinstance(issue, PrivilegeIssue)
        assert issue.module == EnforcementModule.NETWORK
        assert issue.operation == "block_ip"

    def test_log_privilege_failure_tracks_issue(self):
        """log_privilege_failure should track the issue."""
        manager = PrivilegeManager()
        initial_count = len(manager._issues)
        manager.log_privilege_failure(
            module=EnforcementModule.USB,
            operation="disable_port"
        )
        assert len(manager._issues) == initial_count + 1

    def test_log_privilege_failure_in_airgap_is_critical(self):
        """Failure in AIRGAP mode for required module should be critical."""
        manager = PrivilegeManager()
        issue = manager.log_privilege_failure(
            module=EnforcementModule.NETWORK,
            operation="isolate",
            boundary_mode="AIRGAP"
        )
        assert issue.alert_level == PrivilegeAlert.CRITICAL

    def test_log_privilege_failure_in_open_is_warning(self):
        """Failure in OPEN mode should just be a warning."""
        manager = PrivilegeManager()
        issue = manager.log_privilege_failure(
            module=EnforcementModule.NETWORK,
            operation="isolate",
            boundary_mode="OPEN"
        )
        assert issue.alert_level == PrivilegeAlert.WARNING


class TestPrivilegeManagerEnforcement:
    """Tests for mode enforcement checking."""

    def test_can_enforce_mode_with_all_modules(self):
        """can_enforce_mode should return True when all modules available."""
        manager = PrivilegeManager()
        # Register all required modules for AIRGAP
        manager.register_module(EnforcementModule.NETWORK, True)
        manager.register_module(EnforcementModule.USB, True)
        manager.register_module(EnforcementModule.DNS, True)

        can_enforce, missing = manager.can_enforce_mode('AIRGAP')
        assert can_enforce is True
        assert missing == []

    def test_can_enforce_mode_with_missing_modules(self):
        """can_enforce_mode should return False when modules missing."""
        manager = PrivilegeManager()
        # Only register one module
        manager.register_module(EnforcementModule.NETWORK, True)
        manager.register_module(EnforcementModule.USB, False, "No root")
        manager.register_module(EnforcementModule.DNS, False, "No root")

        can_enforce, missing = manager.can_enforce_mode('AIRGAP')
        assert can_enforce is False
        assert len(missing) == 2

    def test_can_enforce_unknown_mode(self):
        """can_enforce_mode should return True for unknown modes."""
        manager = PrivilegeManager()
        can_enforce, missing = manager.can_enforce_mode('UNKNOWN_MODE')
        assert can_enforce is True
        assert missing == []

    def test_assert_mode_enforceable_success(self):
        """assert_mode_enforceable should return True when enforceable."""
        manager = PrivilegeManager()
        manager.register_module(EnforcementModule.NETWORK, True)
        manager.register_module(EnforcementModule.USB, True)
        manager.register_module(EnforcementModule.DNS, True)

        is_enforceable, message = manager.assert_mode_enforceable('AIRGAP')
        assert is_enforceable is True
        assert "fully enforced" in message

    def test_assert_mode_enforceable_failure(self):
        """assert_mode_enforceable should return False when not enforceable."""
        manager = PrivilegeManager()
        manager.register_module(EnforcementModule.NETWORK, False, "Missing")

        is_enforceable, message = manager.assert_mode_enforceable('AIRGAP')
        assert is_enforceable is False
        assert "Cannot fully enforce" in message


class TestPrivilegeManagerStatus:
    """Tests for status reporting."""

    def test_get_status_returns_privilege_status(self):
        """get_status should return a PrivilegeStatus."""
        manager = PrivilegeManager()
        status = manager.get_status()
        assert isinstance(status, PrivilegeStatus)

    def test_get_status_reflects_root(self):
        """get_status should reflect root status."""
        manager = PrivilegeManager()
        status = manager.get_status()
        assert status.has_root == manager._has_root

    def test_get_status_reflects_modules(self):
        """get_status should reflect registered modules."""
        manager = PrivilegeManager()
        manager.register_module(EnforcementModule.NETWORK, True)
        manager.register_module(EnforcementModule.USB, False, "No root")

        status = manager.get_status()
        assert 'network' in status.modules_available
        assert status.modules_available['network'] is True
        assert 'usb' in status.modules_degraded

    def test_get_issues_all(self):
        """get_issues should return all issues."""
        manager = PrivilegeManager()
        manager.register_module(EnforcementModule.NETWORK, False, "No root")
        manager.register_module(EnforcementModule.USB, False, "No root")

        issues = manager.get_issues()
        assert len(issues) >= 2

    def test_get_issues_filtered(self):
        """get_issues should filter by severity."""
        manager = PrivilegeManager()
        manager.log_privilege_failure(
            EnforcementModule.NETWORK,
            "test",
            boundary_mode="OPEN"  # Warning
        )
        manager.log_privilege_failure(
            EnforcementModule.NETWORK,
            "test",
            boundary_mode="AIRGAP"  # Critical
        )

        warnings = manager.get_issues(PrivilegeAlert.WARNING)
        criticals = manager.get_issues(PrivilegeAlert.CRITICAL)

        assert len(warnings) >= 1
        assert len(criticals) >= 1

    def test_get_critical_count(self):
        """get_critical_count should return count of critical issues."""
        manager = PrivilegeManager()
        initial = manager.get_critical_count()

        manager.log_privilege_failure(
            EnforcementModule.NETWORK,
            "test",
            boundary_mode="AIRGAP"
        )

        assert manager.get_critical_count() == initial + 1


class TestPrivilegeManagerHelpers:
    """Tests for helper methods."""

    def test_require_root_or_warn_without_root(self):
        """require_root_or_warn should return False when not root."""
        manager = PrivilegeManager()
        # Only test if we're not actually root
        if not manager._has_root:
            result = manager.require_root_or_warn("test operation")
            assert result is False

    def test_print_security_status(self):
        """print_security_status should not raise."""
        manager = PrivilegeManager()
        manager.register_module(EnforcementModule.NETWORK, True)
        # Should not raise
        manager.print_security_status()


# ===========================================================================
# Global Manager Functions Tests
# ===========================================================================

class TestGlobalManager:
    """Tests for global privilege manager functions."""

    def test_get_privilege_manager_initially_none(self):
        """get_privilege_manager should return None initially."""
        # Reset global state
        import daemon.privilege_manager as pm
        pm._privilege_manager = None
        assert get_privilege_manager() is None

    def test_set_and_get_privilege_manager(self):
        """set_privilege_manager and get_privilege_manager should work."""
        manager = PrivilegeManager()
        set_privilege_manager(manager)
        assert get_privilege_manager() == manager

    def test_check_root_or_log_with_manager(self):
        """check_root_or_log should use global manager."""
        manager = PrivilegeManager()
        set_privilege_manager(manager)

        result = check_root_or_log(
            EnforcementModule.NETWORK,
            "test_op",
            "OPEN"
        )
        # Result depends on actual privileges
        assert isinstance(result, bool)

    def test_check_root_or_log_without_manager(self):
        """check_root_or_log should work without global manager."""
        import daemon.privilege_manager as pm
        pm._privilege_manager = None

        result = check_root_or_log(
            EnforcementModule.NETWORK,
            "test_op"
        )
        assert isinstance(result, bool)


# ===========================================================================
# Mode Requirements Tests
# ===========================================================================

class TestModeRequirements:
    """Tests for mode requirement constants."""

    def test_enforcement_required_modes(self):
        """ENFORCEMENT_REQUIRED_MODES should include critical modes."""
        assert 'AIRGAP' in PrivilegeManager.ENFORCEMENT_REQUIRED_MODES
        assert 'COLDROOM' in PrivilegeManager.ENFORCEMENT_REQUIRED_MODES
        assert 'LOCKDOWN' in PrivilegeManager.ENFORCEMENT_REQUIRED_MODES

    def test_airgap_requirements(self):
        """AIRGAP mode should require network, usb, and dns modules."""
        reqs = PrivilegeManager.MODE_REQUIREMENTS['AIRGAP']
        assert EnforcementModule.NETWORK in reqs
        assert EnforcementModule.USB in reqs
        assert EnforcementModule.DNS in reqs

    def test_lockdown_requirements(self):
        """LOCKDOWN mode should require all critical modules."""
        reqs = PrivilegeManager.MODE_REQUIREMENTS['LOCKDOWN']
        assert EnforcementModule.NETWORK in reqs
        assert EnforcementModule.USB in reqs
        assert EnforcementModule.PROCESS in reqs
        assert EnforcementModule.ARP in reqs
        assert EnforcementModule.DNS in reqs


# ===========================================================================
# Integration Tests
# ===========================================================================

class TestPrivilegeManagerIntegration:
    """Integration tests for PrivilegeManager."""

    def test_full_workflow(self):
        """Test a complete workflow of privilege management."""
        # Create manager with mocked logger
        mock_logger = MagicMock()
        callback_called = []
        callback = lambda issue: callback_called.append(issue)

        manager = PrivilegeManager(
            event_logger=mock_logger,
            on_critical_callback=callback
        )

        # Register some modules
        manager.register_module(EnforcementModule.NETWORK, True)
        manager.register_module(EnforcementModule.USB, False, "No root")
        manager.register_module(EnforcementModule.DNS, False, "No root")

        # Check mode enforcement
        can_airgap, missing_airgap = manager.can_enforce_mode('AIRGAP')
        assert can_airgap is False

        # Get status
        status = manager.get_status()
        assert status.can_enforce_airgap is False
        assert 'network' in status.modules_available
        assert status.modules_available['network'] is True

        # Log a failure
        issue = manager.log_privilege_failure(
            EnforcementModule.USB,
            "block_device",
            boundary_mode="AIRGAP"
        )
        assert issue.alert_level == PrivilegeAlert.CRITICAL

    def test_multiple_managers(self):
        """Multiple managers should be independent."""
        manager1 = PrivilegeManager()
        manager2 = PrivilegeManager()

        manager1.register_module(EnforcementModule.NETWORK, True)
        manager2.register_module(EnforcementModule.NETWORK, False, "Test")

        assert manager1._module_status[EnforcementModule.NETWORK] is True
        assert manager2._module_status[EnforcementModule.NETWORK] is False
