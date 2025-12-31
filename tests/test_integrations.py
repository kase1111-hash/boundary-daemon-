"""
Tests for the Integrations module.

Tests high-level integration interfaces for Memory Vault, Tool Enforcement, etc.
"""

import os
import sys
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.policy_engine import (
    PolicyEngine, BoundaryMode, MemoryClass, PolicyDecision, Operator
)
from daemon.event_logger import EventLogger, EventType


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def mock_daemon():
    """Create a mock daemon for integration testing."""
    daemon = MagicMock()
    daemon.policy_engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
    daemon.event_logger = MagicMock()
    daemon.check_recall_permission = MagicMock(return_value=(True, "Allowed"))
    return daemon


@pytest.fixture
def mock_daemon_restricted():
    """Create a mock daemon in RESTRICTED mode."""
    daemon = MagicMock()
    daemon.policy_engine = PolicyEngine(initial_mode=BoundaryMode.RESTRICTED)
    daemon.event_logger = MagicMock()
    daemon.check_recall_permission = MagicMock(return_value=(False, "Denied"))
    return daemon


# ===========================================================================
# RecallGate Tests
# ===========================================================================

class TestRecallGate:
    """Tests for RecallGate integration interface."""

    def test_recall_gate_import(self):
        """RecallGate should be importable."""
        from daemon.integrations import RecallGate
        assert RecallGate is not None

    def test_recall_gate_init(self, mock_daemon):
        """RecallGate should initialize with daemon reference."""
        from daemon.integrations import RecallGate
        gate = RecallGate(mock_daemon)
        assert gate.daemon == mock_daemon

    def test_check_recall_calls_daemon(self, mock_daemon):
        """check_recall should call daemon's check_recall_permission."""
        from daemon.integrations import RecallGate
        gate = RecallGate(mock_daemon)
        gate.check_recall(MemoryClass.PUBLIC)
        mock_daemon.check_recall_permission.assert_called_once()

    def test_check_recall_returns_tuple(self, mock_daemon):
        """check_recall should return (permitted, reason) tuple."""
        from daemon.integrations import RecallGate
        gate = RecallGate(mock_daemon)
        result = gate.check_recall(MemoryClass.PUBLIC)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_check_recall_with_memory_id(self, mock_daemon):
        """check_recall should log with memory_id if provided."""
        from daemon.integrations import RecallGate
        gate = RecallGate(mock_daemon)
        gate.check_recall(MemoryClass.CONFIDENTIAL, memory_id="mem-123")
        mock_daemon.event_logger.log_event.assert_called()

    def test_get_minimum_mode(self, mock_daemon):
        """get_minimum_mode should return minimum required mode."""
        from daemon.integrations import RecallGate
        gate = RecallGate(mock_daemon)
        # Set up the daemon to return a mode
        mock_daemon.policy_engine.get_minimum_mode_for_memory = MagicMock(
            return_value=BoundaryMode.RESTRICTED
        )
        mode = gate.get_minimum_mode(MemoryClass.CONFIDENTIAL)
        assert mode == BoundaryMode.RESTRICTED

    def test_is_accessible_public(self, mock_daemon):
        """is_accessible should return True for accessible memory."""
        from daemon.integrations import RecallGate
        mock_daemon.check_recall_permission.return_value = (True, "Allowed")
        gate = RecallGate(mock_daemon)
        assert gate.is_accessible(MemoryClass.PUBLIC) is True

    def test_is_accessible_denied(self, mock_daemon_restricted):
        """is_accessible should return False for inaccessible memory."""
        from daemon.integrations import RecallGate
        gate = RecallGate(mock_daemon_restricted)
        assert gate.is_accessible(MemoryClass.TOP_SECRET) is False


# ===========================================================================
# ToolGate Tests
# ===========================================================================

class TestToolGate:
    """Tests for ToolGate integration interface."""

    def test_tool_gate_import(self):
        """ToolGate should be importable."""
        from daemon.integrations import ToolGate
        assert ToolGate is not None

    def test_tool_gate_init(self, mock_daemon):
        """ToolGate should initialize with daemon reference."""
        from daemon.integrations import ToolGate
        gate = ToolGate(mock_daemon)
        assert gate.daemon == mock_daemon


# ===========================================================================
# CeremonyManager Tests
# ===========================================================================

class TestCeremonyManager:
    """Tests for CeremonyManager integration interface."""

    def test_ceremony_manager_import(self):
        """CeremonyManager should be importable."""
        from daemon.integrations import CeremonyManager
        assert CeremonyManager is not None

    def test_ceremony_manager_init(self, mock_daemon):
        """CeremonyManager should initialize with daemon reference."""
        from daemon.integrations import CeremonyManager
        manager = CeremonyManager(mock_daemon)
        assert manager.daemon == mock_daemon


# ===========================================================================
# MessageChecker Availability Tests
# ===========================================================================

class TestMessageCheckerAvailability:
    """Tests for MessageChecker availability checking."""

    def test_message_checker_available_flag(self):
        """MESSAGE_CHECKER_AVAILABLE should be defined."""
        from daemon.integrations import MESSAGE_CHECKER_AVAILABLE
        assert isinstance(MESSAGE_CHECKER_AVAILABLE, bool)


# ===========================================================================
# Integration Module Level Tests
# ===========================================================================

class TestIntegrationsModule:
    """Tests for the integrations module as a whole."""

    def test_module_imports(self):
        """All main classes should be importable."""
        from daemon.integrations import RecallGate, ToolGate, CeremonyManager
        assert RecallGate is not None
        assert ToolGate is not None
        assert CeremonyManager is not None

    def test_memory_class_import(self):
        """MemoryClass should be imported from policy_engine."""
        from daemon.integrations import MemoryClass
        assert MemoryClass.PUBLIC is not None
        assert MemoryClass.CROWN_JEWEL is not None

    def test_boundary_mode_import(self):
        """BoundaryMode should be imported from policy_engine."""
        from daemon.integrations import BoundaryMode
        assert BoundaryMode.OPEN is not None
        assert BoundaryMode.LOCKDOWN is not None
