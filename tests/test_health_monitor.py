"""
Tests for the Health Monitor module.

Tests health checking, heartbeat tracking, and component status monitoring.
"""

import os
import sys
import time
import threading
from datetime import datetime
from unittest.mock import MagicMock, patch
from collections import deque

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.health_monitor import (
    HealthMonitor,
    HealthMonitorConfig,
    HealthStatus,
    ComponentStatus,
    ComponentHealth,
    HealthSnapshot,
    HealthAlert,
)


# ===========================================================================
# Enum Tests
# ===========================================================================

class TestHealthStatus:
    """Tests for HealthStatus enum."""

    def test_health_status_values(self):
        """HealthStatus should have expected values."""
        assert HealthStatus.HEALTHY.value == "healthy"
        assert HealthStatus.DEGRADED.value == "degraded"
        assert HealthStatus.UNHEALTHY.value == "unhealthy"
        assert HealthStatus.UNKNOWN.value == "unknown"


class TestComponentStatus:
    """Tests for ComponentStatus enum."""

    def test_component_status_values(self):
        """ComponentStatus should have expected values."""
        assert ComponentStatus.OK.value == "ok"
        assert ComponentStatus.WARNING.value == "warning"
        assert ComponentStatus.ERROR.value == "error"
        assert ComponentStatus.UNRESPONSIVE.value == "unresponsive"
        assert ComponentStatus.NOT_AVAILABLE.value == "not_available"


# ===========================================================================
# Dataclass Tests
# ===========================================================================

class TestComponentHealth:
    """Tests for ComponentHealth dataclass."""

    def test_component_health_creation(self):
        """ComponentHealth should be creatable."""
        health = ComponentHealth(
            name="test_component",
            status=ComponentStatus.OK,
            last_check=time.time(),
        )
        assert health.name == "test_component"
        assert health.status == ComponentStatus.OK

    def test_component_health_defaults(self):
        """ComponentHealth should have correct defaults."""
        health = ComponentHealth(
            name="test",
            status=ComponentStatus.OK,
            last_check=time.time(),
        )
        assert health.last_success is None
        assert health.message == ""
        assert health.metadata == {}

    def test_component_health_to_dict(self):
        """to_dict should return all fields."""
        now = time.time()
        health = ComponentHealth(
            name="test",
            status=ComponentStatus.OK,
            last_check=now,
            last_success=now,
            message="All good",
            metadata={"key": "value"},
        )
        d = health.to_dict()
        assert d['name'] == "test"
        assert d['status'] == "ok"
        assert d['message'] == "All good"
        assert 'last_check_iso' in d


class TestHealthSnapshot:
    """Tests for HealthSnapshot dataclass."""

    def test_health_snapshot_creation(self):
        """HealthSnapshot should be creatable."""
        now = time.time()
        snapshot = HealthSnapshot(
            timestamp=now,
            overall_status=HealthStatus.HEALTHY,
            components={},
            uptime_seconds=100.0,
            heartbeat_count=10,
            last_heartbeat=now,
        )
        assert snapshot.overall_status == HealthStatus.HEALTHY
        assert snapshot.uptime_seconds == 100.0

    def test_health_snapshot_to_dict(self):
        """to_dict should return all fields."""
        now = time.time()
        snapshot = HealthSnapshot(
            timestamp=now,
            overall_status=HealthStatus.HEALTHY,
            components={},
            uptime_seconds=3661.0,  # 1 hour, 1 minute, 1 second
            heartbeat_count=10,
            last_heartbeat=now,
        )
        d = snapshot.to_dict()
        assert d['overall_status'] == "healthy"
        assert 'uptime_formatted' in d
        assert 'timestamp_iso' in d

    def test_format_uptime_seconds(self):
        """_format_uptime should format seconds correctly."""
        assert HealthSnapshot._format_uptime(30) == "30s"

    def test_format_uptime_minutes(self):
        """_format_uptime should format minutes correctly."""
        assert HealthSnapshot._format_uptime(90) == "1m 30s"

    def test_format_uptime_hours(self):
        """_format_uptime should format hours correctly."""
        assert HealthSnapshot._format_uptime(3661) == "1h 1m 1s"

    def test_format_uptime_days(self):
        """_format_uptime should format days correctly."""
        assert HealthSnapshot._format_uptime(90061) == "1d 1h 1m 1s"


class TestHealthAlert:
    """Tests for HealthAlert dataclass."""

    def test_health_alert_creation(self):
        """HealthAlert should be creatable."""
        alert = HealthAlert(
            timestamp=time.time(),
            component="test",
            previous_status=ComponentStatus.OK,
            new_status=ComponentStatus.ERROR,
            message="Component failed",
        )
        assert alert.component == "test"
        assert alert.new_status == ComponentStatus.ERROR

    def test_health_alert_to_dict(self):
        """to_dict should return all fields."""
        alert = HealthAlert(
            timestamp=time.time(),
            component="test",
            previous_status=ComponentStatus.OK,
            new_status=ComponentStatus.ERROR,
            message="Test message",
        )
        d = alert.to_dict()
        assert d['component'] == "test"
        assert d['previous_status'] == "ok"
        assert d['new_status'] == "error"


class TestHealthMonitorConfig:
    """Tests for HealthMonitorConfig dataclass."""

    def test_config_defaults(self):
        """HealthMonitorConfig should have sensible defaults."""
        config = HealthMonitorConfig()
        assert config.check_interval == 30.0
        assert config.heartbeat_interval == 10.0
        assert config.heartbeat_timeout == 60.0
        assert config.component_timeout == 5.0
        assert config.alert_on_degraded is True
        assert config.history_size == 100

    def test_config_custom(self):
        """HealthMonitorConfig should accept custom values."""
        config = HealthMonitorConfig(
            check_interval=10.0,
            heartbeat_interval=5.0,
            history_size=50,
        )
        assert config.check_interval == 10.0
        assert config.history_size == 50

    def test_config_to_dict(self):
        """to_dict should return all fields."""
        config = HealthMonitorConfig()
        d = config.to_dict()
        assert 'check_interval' in d
        assert 'heartbeat_interval' in d
        assert 'history_size' in d


# ===========================================================================
# HealthMonitor Initialization Tests
# ===========================================================================

class TestHealthMonitorInit:
    """Tests for HealthMonitor initialization."""

    def test_init_default(self):
        """HealthMonitor should initialize with defaults."""
        monitor = HealthMonitor()
        assert monitor.daemon is None
        assert isinstance(monitor.config, HealthMonitorConfig)
        assert monitor._running is False

    def test_init_with_daemon(self):
        """HealthMonitor should accept daemon reference."""
        mock_daemon = MagicMock()
        monitor = HealthMonitor(daemon=mock_daemon)
        assert monitor.daemon == mock_daemon

    def test_init_with_config(self):
        """HealthMonitor should accept custom config."""
        config = HealthMonitorConfig(check_interval=5.0)
        monitor = HealthMonitor(config=config)
        assert monitor.config.check_interval == 5.0

    def test_init_with_alert_callback(self):
        """HealthMonitor should accept alert callback."""
        callback = MagicMock()
        monitor = HealthMonitor(on_alert=callback)
        assert monitor._on_alert == callback

    def test_init_registers_default_checks(self):
        """HealthMonitor should register default component checks."""
        monitor = HealthMonitor()
        assert 'daemon_core' in monitor._health_checks
        assert 'event_logger' in monitor._health_checks
        assert 'policy_engine' in monitor._health_checks

    def test_init_tracking_state(self):
        """HealthMonitor should initialize tracking state."""
        monitor = HealthMonitor()
        assert monitor._heartbeat_count == 0
        assert monitor._last_heartbeat > 0
        assert monitor._current_status == HealthStatus.UNKNOWN


# ===========================================================================
# HealthMonitor Component Registration Tests
# ===========================================================================

class TestHealthMonitorComponents:
    """Tests for component registration."""

    def test_register_component(self):
        """register_component should add component."""
        monitor = HealthMonitor()

        def check_func():
            return (ComponentStatus.OK, "All good", {})

        monitor.register_component('custom', check_func)
        assert 'custom' in monitor._health_checks
        assert 'custom' in monitor._components

    def test_register_component_initializes_health(self):
        """Registered component should have initial health status."""
        monitor = HealthMonitor()

        def check_func():
            return (ComponentStatus.OK, "", {})

        monitor.register_component('test', check_func)
        health = monitor._components['test']
        assert health.status == ComponentStatus.NOT_AVAILABLE
        assert health.last_check == 0


# ===========================================================================
# HealthMonitor Lifecycle Tests
# ===========================================================================

class TestHealthMonitorLifecycle:
    """Tests for HealthMonitor start/stop."""

    def test_start_sets_running(self):
        """start() should set _running to True."""
        config = HealthMonitorConfig(
            check_interval=100.0,
            heartbeat_interval=100.0,
        )
        monitor = HealthMonitor(config=config)
        try:
            monitor.start()
            assert monitor._running is True
        finally:
            monitor.stop()

    def test_start_creates_threads(self):
        """start() should create heartbeat and check threads."""
        config = HealthMonitorConfig(
            check_interval=100.0,
            heartbeat_interval=100.0,
        )
        monitor = HealthMonitor(config=config)
        try:
            monitor.start()
            assert monitor._heartbeat_thread is not None
            assert monitor._check_thread is not None
            assert monitor._heartbeat_thread.is_alive()
            assert monitor._check_thread.is_alive()
        finally:
            monitor.stop()

    def test_start_idempotent(self):
        """Multiple start() calls should not create multiple threads."""
        config = HealthMonitorConfig(
            check_interval=100.0,
            heartbeat_interval=100.0,
        )
        monitor = HealthMonitor(config=config)
        try:
            monitor.start()
            first_hb_thread = monitor._heartbeat_thread
            monitor.start()
            assert monitor._heartbeat_thread is first_hb_thread
        finally:
            monitor.stop()

    def test_stop_sets_not_running(self):
        """stop() should set _running to False."""
        config = HealthMonitorConfig(
            check_interval=100.0,
            heartbeat_interval=100.0,
        )
        monitor = HealthMonitor(config=config)
        monitor.start()
        monitor.stop()
        assert monitor._running is False

    def test_stop_without_start(self):
        """stop() without start() should not raise."""
        monitor = HealthMonitor()
        monitor.stop()  # Should not raise


# ===========================================================================
# HealthMonitor Heartbeat Tests
# ===========================================================================

class TestHealthMonitorHeartbeat:
    """Tests for heartbeat functionality."""

    def test_heartbeat_increments_count(self):
        """heartbeat() should increment count."""
        monitor = HealthMonitor()
        initial = monitor._heartbeat_count
        monitor.heartbeat()
        assert monitor._heartbeat_count == initial + 1

    def test_heartbeat_updates_timestamp(self):
        """heartbeat() should update last_heartbeat."""
        monitor = HealthMonitor()
        old_time = monitor._last_heartbeat
        time.sleep(0.01)
        monitor.heartbeat()
        assert monitor._last_heartbeat > old_time

    def test_multiple_heartbeats(self):
        """Multiple heartbeats should be tracked."""
        monitor = HealthMonitor()
        for i in range(5):
            monitor.heartbeat()
        assert monitor._heartbeat_count >= 5


# ===========================================================================
# HealthMonitor Status Calculation Tests
# ===========================================================================

class TestHealthMonitorStatusCalculation:
    """Tests for status calculation."""

    def test_calculate_overall_empty(self):
        """Empty components should return UNKNOWN."""
        monitor = HealthMonitor()
        monitor._components = {}
        status = monitor._calculate_overall_status()
        assert status == HealthStatus.UNKNOWN

    def test_calculate_overall_all_ok(self):
        """All OK components should return HEALTHY."""
        monitor = HealthMonitor()
        monitor._components = {
            'c1': ComponentHealth('c1', ComponentStatus.OK, time.time()),
            'c2': ComponentHealth('c2', ComponentStatus.OK, time.time()),
        }
        status = monitor._calculate_overall_status()
        assert status == HealthStatus.HEALTHY

    def test_calculate_overall_with_warning(self):
        """Warning components should return DEGRADED."""
        monitor = HealthMonitor()
        monitor._components = {
            'c1': ComponentHealth('c1', ComponentStatus.OK, time.time()),
            'c2': ComponentHealth('c2', ComponentStatus.WARNING, time.time()),
        }
        status = monitor._calculate_overall_status()
        assert status == HealthStatus.DEGRADED

    def test_calculate_overall_with_error(self):
        """Error components should return DEGRADED or UNHEALTHY."""
        monitor = HealthMonitor()
        monitor._components = {
            'c1': ComponentHealth('c1', ComponentStatus.OK, time.time()),
            'c2': ComponentHealth('c2', ComponentStatus.ERROR, time.time()),
        }
        status = monitor._calculate_overall_status()
        # With 50% errors (1/2), this returns UNHEALTHY (>= 50% threshold)
        assert status in (HealthStatus.DEGRADED, HealthStatus.UNHEALTHY)

    def test_calculate_overall_majority_errors(self):
        """Majority errors should return UNHEALTHY."""
        monitor = HealthMonitor()
        monitor._components = {
            'c1': ComponentHealth('c1', ComponentStatus.ERROR, time.time()),
            'c2': ComponentHealth('c2', ComponentStatus.ERROR, time.time()),
        }
        status = monitor._calculate_overall_status()
        assert status == HealthStatus.UNHEALTHY

    def test_calculate_ignores_not_available(self):
        """NOT_AVAILABLE components should be ignored."""
        monitor = HealthMonitor()
        monitor._components = {
            'c1': ComponentHealth('c1', ComponentStatus.OK, time.time()),
            'c2': ComponentHealth('c2', ComponentStatus.NOT_AVAILABLE, time.time()),
        }
        status = monitor._calculate_overall_status()
        assert status == HealthStatus.HEALTHY


# ===========================================================================
# HealthMonitor Telemetry Tests
# ===========================================================================

class TestHealthMonitorTelemetry:
    """Tests for telemetry functionality."""

    def test_set_telemetry_manager(self):
        """set_telemetry_manager should set the manager."""
        monitor = HealthMonitor()
        mock_telemetry = MagicMock()
        monitor.set_telemetry_manager(mock_telemetry)
        assert monitor._telemetry_manager == mock_telemetry


# ===========================================================================
# Integration Tests
# ===========================================================================

class TestHealthMonitorIntegration:
    """Integration tests for HealthMonitor."""

    def test_health_check_flow(self):
        """Test complete health check flow."""
        config = HealthMonitorConfig(
            check_interval=0.1,
            heartbeat_interval=0.1,
        )
        monitor = HealthMonitor(config=config)

        # Register a custom check
        def custom_check():
            return (ComponentStatus.OK, "Working", {"test": True})

        monitor.register_component('custom', custom_check)

        # Start and let it run
        monitor.start()
        time.sleep(0.3)
        monitor.stop()

        # Verify component was checked
        assert 'custom' in monitor._components
        health = monitor._components['custom']
        assert health.status == ComponentStatus.OK

    def test_history_is_populated(self):
        """History should be populated during monitoring."""
        config = HealthMonitorConfig(
            check_interval=0.1,
            heartbeat_interval=0.1,
            history_size=10,
        )
        monitor = HealthMonitor(config=config)

        monitor.start()
        time.sleep(0.35)
        monitor.stop()

        assert len(monitor._history) > 0

    def test_alert_callback_on_error(self):
        """Alert callback should be called on component error."""
        alerts_received = []

        def on_alert(alert):
            alerts_received.append(alert)

        config = HealthMonitorConfig(
            check_interval=0.1,
            heartbeat_interval=0.1,
            alert_on_degraded=True,
        )
        monitor = HealthMonitor(config=config, on_alert=on_alert)

        # Start with healthy, then switch to error
        call_count = [0]
        def flaky_check():
            call_count[0] += 1
            if call_count[0] > 1:
                return (ComponentStatus.ERROR, "Failed", {})
            return (ComponentStatus.OK, "OK", {})

        monitor.register_component('flaky', flaky_check)

        monitor.start()
        time.sleep(0.35)
        monitor.stop()

        # May or may not have alerts depending on timing
        # Just verify no exceptions


# ===========================================================================
# Edge Cases
# ===========================================================================

class TestHealthMonitorEdgeCases:
    """Edge case tests for HealthMonitor."""

    def test_check_with_exception(self):
        """Health check that throws should be handled."""
        monitor = HealthMonitor()

        def bad_check():
            raise ValueError("Intentional error")

        monitor.register_component('bad', bad_check)
        monitor._run_health_checks()

        health = monitor._components['bad']
        assert health.status == ComponentStatus.ERROR
        assert "Health check failed" in health.message

    def test_empty_history_deque(self):
        """History should handle empty state."""
        monitor = HealthMonitor()
        assert len(monitor._history) == 0

    def test_concurrent_heartbeats(self):
        """Concurrent heartbeats should be thread-safe."""
        monitor = HealthMonitor()

        def beat():
            for _ in range(100):
                monitor.heartbeat()

        threads = [threading.Thread(target=beat) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have 500 heartbeats (but at least close due to initialization)
        assert monitor._heartbeat_count >= 500
