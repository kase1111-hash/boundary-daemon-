"""
Pytest configuration and shared fixtures for Boundary Daemon tests.

This module provides common fixtures for testing the boundary daemon components.
"""

import json
import os
import shutil
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Generator, Dict, Any
from unittest.mock import MagicMock, patch

import pytest

# Add the parent directory to the path for imports
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.event_logger import EventLogger, EventType, BoundaryEvent
from daemon.policy_engine import (
    PolicyEngine, BoundaryMode, PolicyRequest, PolicyDecision,
    MemoryClass, Operator
)


# ===========================================================================
# Temporary Directory Fixtures
# ===========================================================================

@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory that is cleaned up after the test."""
    tmpdir = tempfile.mkdtemp(prefix="boundary_test_")
    yield Path(tmpdir)
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def temp_log_file(temp_dir: Path) -> Path:
    """Provide a temporary log file path."""
    return temp_dir / "test_events.log"


@pytest.fixture
def temp_log_dir(temp_dir: Path) -> Path:
    """Provide a temporary log directory."""
    log_dir = temp_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


# ===========================================================================
# Event Logger Fixtures
# ===========================================================================

@pytest.fixture
def event_logger(temp_log_file: Path) -> Generator[EventLogger, None, None]:
    """Provide an EventLogger instance with a temporary log file."""
    logger = EventLogger(str(temp_log_file), secure_permissions=False)
    yield logger


@pytest.fixture
def event_logger_secure(temp_log_file: Path) -> Generator[EventLogger, None, None]:
    """Provide an EventLogger instance with secure permissions enabled."""
    logger = EventLogger(str(temp_log_file), secure_permissions=True)
    yield logger


@pytest.fixture
def sample_event() -> Dict[str, Any]:
    """Provide sample event data for testing."""
    return {
        'event_type': EventType.MODE_CHANGE,
        'details': "Mode changed from OPEN to RESTRICTED",
        'metadata': {
            'old_mode': 'open',
            'new_mode': 'restricted',
            'operator': 'system'
        }
    }


@pytest.fixture
def populated_event_logger(event_logger: EventLogger) -> EventLogger:
    """Provide an EventLogger with some pre-existing events."""
    events = [
        (EventType.DAEMON_START, "Daemon started", {"version": "1.0.0"}),
        (EventType.MODE_CHANGE, "Initial mode set", {"mode": "open"}),
        (EventType.POLICY_DECISION, "Tool access granted", {"tool": "file_read"}),
        (EventType.HEALTH_CHECK, "System healthy", {"cpu": 25, "memory": 45}),
    ]
    for event_type, details, metadata in events:
        event_logger.log_event(event_type, details, metadata)
    return event_logger


# ===========================================================================
# Policy Engine Fixtures
# ===========================================================================

@pytest.fixture
def policy_engine() -> PolicyEngine:
    """Provide a PolicyEngine instance in OPEN mode."""
    return PolicyEngine(initial_mode=BoundaryMode.OPEN)


@pytest.fixture
def policy_engine_restricted() -> PolicyEngine:
    """Provide a PolicyEngine instance in RESTRICTED mode."""
    return PolicyEngine(initial_mode=BoundaryMode.RESTRICTED)


@pytest.fixture
def policy_engine_lockdown() -> PolicyEngine:
    """Provide a PolicyEngine instance in LOCKDOWN mode."""
    return PolicyEngine(initial_mode=BoundaryMode.LOCKDOWN)


@pytest.fixture
def recall_request() -> PolicyRequest:
    """Provide a sample memory recall request."""
    return PolicyRequest(
        request_type='recall',
        memory_class=MemoryClass.CONFIDENTIAL,
        requires_network=False,
        requires_filesystem=True
    )


@pytest.fixture
def tool_request() -> PolicyRequest:
    """Provide a sample tool execution request."""
    return PolicyRequest(
        request_type='tool',
        tool_name='shell_execute',
        requires_network=True,
        requires_filesystem=True
    )


# ===========================================================================
# Log Hardening Fixtures
# ===========================================================================

@pytest.fixture
def mock_chattr():
    """Mock the chattr command for testing without root."""
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        yield mock_run


@pytest.fixture
def mock_lsattr():
    """Mock the lsattr command for testing."""
    with patch('subprocess.run') as mock_run:
        def lsattr_side_effect(args, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stdout = '----a--------e-- test.log\n'
            result.stderr = ''
            return result
        mock_run.side_effect = lsattr_side_effect
        yield mock_run


# ===========================================================================
# Network State Fixtures
# ===========================================================================

@pytest.fixture
def mock_network_offline():
    """Mock network being offline."""
    with patch('daemon.state_monitor.StateMonitor') as mock:
        instance = MagicMock()
        instance.get_network_state.return_value = 'offline'
        instance.is_airgapped.return_value = True
        mock.return_value = instance
        yield instance


@pytest.fixture
def mock_network_online():
    """Mock network being online."""
    with patch('daemon.state_monitor.StateMonitor') as mock:
        instance = MagicMock()
        instance.get_network_state.return_value = 'online'
        instance.is_airgapped.return_value = False
        mock.return_value = instance
        yield instance


# ===========================================================================
# Utility Functions
# ===========================================================================

def create_test_log_file(path: Path, events: list) -> None:
    """Create a test log file with the given events."""
    with open(path, 'w') as f:
        for event in events:
            f.write(json.dumps(event) + '\n')


def read_log_events(path: Path) -> list:
    """Read all events from a log file."""
    events = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


# ===========================================================================
# Markers Registration
# ===========================================================================

def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests (fast, isolated)")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "security: Security-specific tests")
    config.addinivalue_line("markers", "slow: Slow tests (>1s)")
    config.addinivalue_line("markers", "enforcement: Tests requiring root")
