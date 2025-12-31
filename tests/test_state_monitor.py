"""
Tests for the State Monitor module.

Tests environment sensing, network detection, and state tracking.
"""

import os
import sys
import threading
import time
from datetime import datetime
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.state_monitor import (
    StateMonitor,
    MonitoringConfig,
    EnvironmentState,
    SpecialtyNetworkStatus,
    NetworkState,
    NetworkType,
    CellularSecurityAlert,
    HardwareTrust,
)


# ===========================================================================
# Enum Tests
# ===========================================================================

class TestNetworkState:
    """Tests for NetworkState enum."""

    def test_network_state_values(self):
        """NetworkState should have expected values."""
        assert NetworkState.OFFLINE.value == "offline"
        assert NetworkState.ONLINE.value == "online"

    def test_network_state_members(self):
        """NetworkState should have exactly two members."""
        assert len(NetworkState) == 2


class TestNetworkType:
    """Tests for NetworkType enum."""

    def test_network_type_common_values(self):
        """NetworkType should have common network types."""
        assert NetworkType.ETHERNET.value == "ethernet"
        assert NetworkType.WIFI.value == "wifi"
        assert NetworkType.VPN.value == "vpn"
        assert NetworkType.CELLULAR_4G.value == "cellular_4g"
        assert NetworkType.CELLULAR_5G.value == "cellular_5g"

    def test_network_type_iot_values(self):
        """NetworkType should have IoT network types."""
        assert NetworkType.LORA.value == "lora"
        assert NetworkType.THREAD.value == "thread"
        assert NetworkType.ANT_PLUS.value == "ant_plus"

    def test_network_type_unknown(self):
        """NetworkType should have an unknown type."""
        assert NetworkType.UNKNOWN.value == "unknown"


class TestCellularSecurityAlert:
    """Tests for CellularSecurityAlert enum."""

    def test_cellular_alert_values(self):
        """CellularSecurityAlert should have expected values."""
        assert CellularSecurityAlert.NONE.value == "none"
        assert CellularSecurityAlert.TOWER_CHANGE.value == "tower_change"
        assert CellularSecurityAlert.WEAK_ENCRYPTION.value == "weak_encryption"
        assert CellularSecurityAlert.SIGNAL_ANOMALY.value == "signal_anomaly"
        assert CellularSecurityAlert.IMSI_CATCHER.value == "imsi_catcher"
        assert CellularSecurityAlert.DOWNGRADE_ATTACK.value == "downgrade_attack"


class TestHardwareTrust:
    """Tests for HardwareTrust enum."""

    def test_hardware_trust_values(self):
        """HardwareTrust should have expected values."""
        assert HardwareTrust.LOW.value == "low"
        assert HardwareTrust.MEDIUM.value == "medium"
        assert HardwareTrust.HIGH.value == "high"


# ===========================================================================
# MonitoringConfig Tests
# ===========================================================================

class TestMonitoringConfig:
    """Tests for MonitoringConfig dataclass."""

    def test_default_config(self):
        """MonitoringConfig should have sensible defaults."""
        config = MonitoringConfig()
        assert config.monitor_lora is True
        assert config.monitor_thread is True
        assert config.monitor_cellular_security is True
        assert config.monitor_wimax is False  # Disabled by default (obsolete)
        assert config.monitor_irda is False   # Disabled by default (legacy)
        assert config.monitor_ant_plus is True

    def test_security_monitoring_defaults(self):
        """Security monitoring should be enabled by default."""
        config = MonitoringConfig()
        assert config.monitor_dns_security is True
        assert config.monitor_arp_security is True
        assert config.monitor_wifi_security is True
        assert config.monitor_threat_intel is True
        assert config.monitor_file_integrity is True
        assert config.monitor_traffic_anomaly is True
        assert config.monitor_process_security is True

    def test_custom_config(self):
        """MonitoringConfig should accept custom values."""
        config = MonitoringConfig(
            monitor_lora=False,
            monitor_wimax=True,
            monitor_dns_security=False,
        )
        assert config.monitor_lora is False
        assert config.monitor_wimax is True
        assert config.monitor_dns_security is False

    def test_to_dict(self):
        """to_dict should return all config options."""
        config = MonitoringConfig()
        d = config.to_dict()
        assert 'monitor_lora' in d
        assert 'monitor_thread' in d
        assert 'monitor_cellular_security' in d
        assert 'monitor_dns_security' in d
        assert isinstance(d['monitor_lora'], bool)


# ===========================================================================
# SpecialtyNetworkStatus Tests
# ===========================================================================

class TestSpecialtyNetworkStatus:
    """Tests for SpecialtyNetworkStatus dataclass."""

    def test_creation(self):
        """SpecialtyNetworkStatus should be creatable."""
        status = SpecialtyNetworkStatus(
            lora_devices=['lora0'],
            thread_devices=[],
            wimax_interfaces=[],
            irda_devices=[],
            ant_plus_devices=['ant0'],
            cellular_alerts=['tower_change'],
        )
        assert status.lora_devices == ['lora0']
        assert status.ant_plus_devices == ['ant0']
        assert status.cellular_alerts == ['tower_change']

    def test_to_dict(self):
        """to_dict should return all fields."""
        status = SpecialtyNetworkStatus(
            lora_devices=[],
            thread_devices=['thread0'],
            wimax_interfaces=[],
            irda_devices=[],
            ant_plus_devices=[],
            cellular_alerts=[],
        )
        d = status.to_dict()
        assert 'lora_devices' in d
        assert 'thread_devices' in d
        assert d['thread_devices'] == ['thread0']


# ===========================================================================
# EnvironmentState Tests
# ===========================================================================

class TestEnvironmentState:
    """Tests for EnvironmentState dataclass."""

    @pytest.fixture
    def sample_specialty_networks(self):
        """Provide sample specialty networks status."""
        return SpecialtyNetworkStatus(
            lora_devices=[],
            thread_devices=[],
            wimax_interfaces=[],
            irda_devices=[],
            ant_plus_devices=[],
            cellular_alerts=[],
        )

    @pytest.fixture
    def sample_environment_state(self, sample_specialty_networks):
        """Provide a sample EnvironmentState."""
        return EnvironmentState(
            timestamp=datetime.utcnow().isoformat() + "Z",
            network=NetworkState.OFFLINE,
            hardware_trust=HardwareTrust.HIGH,
            active_interfaces=['lo'],
            interface_types={'lo': NetworkType.UNKNOWN},
            has_internet=False,
            vpn_active=False,
            dns_available=False,
            specialty_networks=sample_specialty_networks,
            dns_security_alerts=[],
            arp_security_alerts=[],
            wifi_security_alerts=[],
            threat_intel_alerts=[],
            file_integrity_alerts=[],
            traffic_anomaly_alerts=[],
            process_security_alerts=[],
            usb_devices=set(),
            block_devices=set(),
            camera_available=False,
            mic_available=False,
            tpm_present=True,
            external_model_endpoints=[],
            suspicious_processes=[],
            shell_escapes_detected=0,
            keyboard_active=True,
            screen_unlocked=True,
            last_activity=None,
        )

    def test_environment_state_creation(self, sample_environment_state):
        """EnvironmentState should be creatable with all fields."""
        assert sample_environment_state.network == NetworkState.OFFLINE
        assert sample_environment_state.hardware_trust == HardwareTrust.HIGH
        assert sample_environment_state.tpm_present is True

    def test_environment_state_to_dict(self, sample_environment_state):
        """to_dict should serialize all fields."""
        d = sample_environment_state.to_dict()
        assert d['network'] == 'offline'
        assert d['hardware_trust'] == 'high'
        assert 'active_interfaces' in d
        assert 'usb_devices' in d
        assert isinstance(d['usb_devices'], list)


# ===========================================================================
# StateMonitor Initialization Tests
# ===========================================================================

class TestStateMonitorInit:
    """Tests for StateMonitor initialization."""

    def test_init_default(self):
        """StateMonitor should initialize with defaults."""
        monitor = StateMonitor()
        assert monitor.poll_interval == 1.0
        assert monitor._running is False
        assert monitor._current_state is None

    def test_init_custom_interval(self):
        """StateMonitor should accept custom poll interval."""
        monitor = StateMonitor(poll_interval=0.5)
        assert monitor.poll_interval == 0.5

    def test_init_with_config(self):
        """StateMonitor should accept monitoring config."""
        config = MonitoringConfig(monitor_lora=False)
        monitor = StateMonitor(monitoring_config=config)
        assert monitor.monitoring_config.monitor_lora is False

    def test_default_monitoring_config(self):
        """StateMonitor should create default config if none provided."""
        monitor = StateMonitor()
        assert isinstance(monitor.monitoring_config, MonitoringConfig)


# ===========================================================================
# StateMonitor Configuration Tests
# ===========================================================================

class TestStateMonitorConfig:
    """Tests for StateMonitor configuration methods."""

    def test_get_monitoring_config(self):
        """get_monitoring_config should return current config."""
        config = MonitoringConfig(monitor_lora=False)
        monitor = StateMonitor(monitoring_config=config)
        assert monitor.get_monitoring_config() == config

    def test_set_monitoring_config(self):
        """set_monitoring_config should update config."""
        monitor = StateMonitor()
        new_config = MonitoringConfig(monitor_lora=False)
        monitor.set_monitoring_config(new_config)
        assert monitor.monitoring_config.monitor_lora is False

    def test_set_monitor_lora(self):
        """set_monitor_lora should update LoRa monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_lora(False)
        assert monitor.monitoring_config.monitor_lora is False
        monitor.set_monitor_lora(True)
        assert monitor.monitoring_config.monitor_lora is True

    def test_set_monitor_thread(self):
        """set_monitor_thread should update Thread monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_thread(False)
        assert monitor.monitoring_config.monitor_thread is False

    def test_set_monitor_cellular_security(self):
        """set_monitor_cellular_security should update cellular monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_cellular_security(False)
        assert monitor.monitoring_config.monitor_cellular_security is False

    def test_set_monitor_wimax(self):
        """set_monitor_wimax should update WiMAX monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_wimax(True)
        assert monitor.monitoring_config.monitor_wimax is True

    def test_set_monitor_irda(self):
        """set_monitor_irda should update IrDA monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_irda(True)
        assert monitor.monitoring_config.monitor_irda is True

    def test_set_monitor_ant_plus(self):
        """set_monitor_ant_plus should update ANT+ monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_ant_plus(False)
        assert monitor.monitoring_config.monitor_ant_plus is False

    def test_set_monitor_dns_security(self):
        """set_monitor_dns_security should update DNS security monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_dns_security(False)
        assert monitor.monitoring_config.monitor_dns_security is False

    def test_set_monitor_arp_security(self):
        """set_monitor_arp_security should update ARP security monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_arp_security(False)
        assert monitor.monitoring_config.monitor_arp_security is False

    def test_set_monitor_wifi_security(self):
        """set_monitor_wifi_security should update WiFi security monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_wifi_security(False)
        assert monitor.monitoring_config.monitor_wifi_security is False

    def test_set_monitor_threat_intel(self):
        """set_monitor_threat_intel should update threat intel monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_threat_intel(False)
        assert monitor.monitoring_config.monitor_threat_intel is False

    def test_set_monitor_file_integrity(self):
        """set_monitor_file_integrity should update file integrity monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_file_integrity(False)
        assert monitor.monitoring_config.monitor_file_integrity is False

    def test_set_monitor_traffic_anomaly(self):
        """set_monitor_traffic_anomaly should update traffic anomaly monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_traffic_anomaly(False)
        assert monitor.monitoring_config.monitor_traffic_anomaly is False

    def test_set_monitor_process_security(self):
        """set_monitor_process_security should update process security monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_process_security(False)
        assert monitor.monitoring_config.monitor_process_security is False


# ===========================================================================
# StateMonitor Callback Tests
# ===========================================================================

class TestStateMonitorCallbacks:
    """Tests for StateMonitor callback functionality."""

    def test_register_callback(self):
        """register_callback should add callback to list."""
        monitor = StateMonitor()
        callback = MagicMock()
        monitor.register_callback(callback)
        assert callback in monitor._callbacks

    def test_register_multiple_callbacks(self):
        """Multiple callbacks can be registered."""
        monitor = StateMonitor()
        callback1 = MagicMock()
        callback2 = MagicMock()
        monitor.register_callback(callback1)
        monitor.register_callback(callback2)
        assert len(monitor._callbacks) == 2


# ===========================================================================
# StateMonitor Start/Stop Tests
# ===========================================================================

class TestStateMonitorLifecycle:
    """Tests for StateMonitor start/stop functionality."""

    def test_start_sets_running(self):
        """start() should set _running to True."""
        monitor = StateMonitor(poll_interval=10.0)  # Long interval to avoid rapid polling
        try:
            monitor.start()
            assert monitor._running is True
        finally:
            monitor.stop()

    def test_start_creates_thread(self):
        """start() should create a monitoring thread."""
        monitor = StateMonitor(poll_interval=10.0)
        try:
            monitor.start()
            assert monitor._thread is not None
            assert monitor._thread.is_alive()
        finally:
            monitor.stop()

    def test_start_idempotent(self):
        """Calling start() twice should not create multiple threads."""
        monitor = StateMonitor(poll_interval=10.0)
        try:
            monitor.start()
            first_thread = monitor._thread
            monitor.start()  # Second call
            assert monitor._thread is first_thread
        finally:
            monitor.stop()

    def test_stop_sets_not_running(self):
        """stop() should set _running to False."""
        monitor = StateMonitor(poll_interval=10.0)
        monitor.start()
        monitor.stop()
        assert monitor._running is False

    def test_stop_without_start(self):
        """stop() without start() should not raise."""
        monitor = StateMonitor()
        monitor.stop()  # Should not raise


# ===========================================================================
# StateMonitor State Access Tests
# ===========================================================================

class TestStateMonitorStateAccess:
    """Tests for StateMonitor state access."""

    def test_get_current_state_initially_none(self):
        """get_current_state should return None before first sample."""
        monitor = StateMonitor()
        assert monitor.get_current_state() is None

    def test_get_current_state_thread_safe(self):
        """get_current_state should be thread-safe."""
        monitor = StateMonitor()

        # Start monitor briefly
        monitor.start()
        time.sleep(0.1)  # Give it time to sample

        # Access state from multiple threads
        results = []
        def access_state():
            for _ in range(10):
                state = monitor.get_current_state()
                results.append(state)

        threads = [threading.Thread(target=access_state) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        monitor.stop()

        # Should have 30 results (10 per thread)
        assert len(results) == 30


# ===========================================================================
# StateMonitor Lazy Initialization Tests
# ===========================================================================

class TestStateMonitorLazyInit:
    """Tests for lazy initialization of security monitors."""

    def test_dns_security_monitor_lazy_init(self):
        """DNS security monitor should be lazily initialized."""
        monitor = StateMonitor()
        assert monitor._dns_security_monitor is None
        # Calling the getter should initialize it (or return None if import fails)
        result = monitor._get_dns_security_monitor()
        # After call, it should either be set or still None (if import fails)
        assert monitor._dns_security_monitor is result

    def test_arp_security_monitor_lazy_init(self):
        """ARP security monitor should be lazily initialized."""
        monitor = StateMonitor()
        assert monitor._arp_security_monitor is None

    def test_wifi_security_monitor_lazy_init(self):
        """WiFi security monitor should be lazily initialized."""
        monitor = StateMonitor()
        assert monitor._wifi_security_monitor is None

    def test_threat_intel_monitor_lazy_init(self):
        """Threat intel monitor should be lazily initialized."""
        monitor = StateMonitor()
        assert monitor._threat_intel_monitor is None

    def test_file_integrity_monitor_lazy_init(self):
        """File integrity monitor should be lazily initialized."""
        monitor = StateMonitor()
        assert monitor._file_integrity_monitor is None

    def test_traffic_anomaly_monitor_lazy_init(self):
        """Traffic anomaly monitor should be lazily initialized."""
        monitor = StateMonitor()
        assert monitor._traffic_anomaly_monitor is None

    def test_process_security_monitor_lazy_init(self):
        """Process security monitor should be lazily initialized."""
        monitor = StateMonitor()
        assert monitor._process_security_monitor is None


# ===========================================================================
# StateMonitor Baseline Tracking Tests
# ===========================================================================

class TestStateMonitorBaseline:
    """Tests for baseline state tracking."""

    def test_baseline_usb_initially_none(self):
        """Baseline USB devices should initially be None."""
        monitor = StateMonitor()
        assert monitor._baseline_usb is None

    def test_baseline_block_devices_initially_none(self):
        """Baseline block devices should initially be None."""
        monitor = StateMonitor()
        assert monitor._baseline_block_devices is None

    def test_last_network_state_initially_none(self):
        """Last network state should initially be None."""
        monitor = StateMonitor()
        assert monitor._last_network_state is None

    def test_cellular_security_tracking(self):
        """Cellular security tracking should be initialized."""
        monitor = StateMonitor()
        assert monitor._last_cell_tower is None
        assert monitor._cell_tower_history == []
        assert monitor._signal_strength_history == []


# ===========================================================================
# Integration Tests
# ===========================================================================

class TestStateMonitorIntegration:
    """Integration tests for StateMonitor."""

    def test_full_lifecycle(self):
        """Test complete monitor lifecycle."""
        callback_called = []
        def on_state_change(old, new):
            callback_called.append((old, new))

        monitor = StateMonitor(poll_interval=0.1)
        monitor.register_callback(on_state_change)

        # Start monitoring
        monitor.start()
        assert monitor._running is True

        # Wait for at least one sample
        time.sleep(0.3)

        # Should have a current state
        state = monitor.get_current_state()
        # State might be None in some test environments
        # but the monitor should have run without errors

        # Stop monitoring
        monitor.stop()
        assert monitor._running is False

    def test_config_changes_during_monitoring(self):
        """Configuration can be changed during monitoring."""
        monitor = StateMonitor(poll_interval=0.1)
        monitor.start()

        # Change config while running
        monitor.set_monitor_lora(False)
        assert monitor.monitoring_config.monitor_lora is False

        monitor.set_monitor_dns_security(False)
        assert monitor.monitoring_config.monitor_dns_security is False

        monitor.stop()


# ===========================================================================
# Edge Cases
# ===========================================================================

class TestStateMonitorEdgeCases:
    """Edge case tests for StateMonitor."""

    def test_zero_poll_interval(self):
        """Monitor should handle very small poll interval."""
        monitor = StateMonitor(poll_interval=0.01)
        monitor.start()
        time.sleep(0.1)
        monitor.stop()
        # Should not crash

    def test_callback_error_handling(self):
        """Monitor should handle callback errors gracefully."""
        def bad_callback(old, new):
            raise ValueError("Intentional error")

        monitor = StateMonitor(poll_interval=0.1)
        monitor.register_callback(bad_callback)
        monitor.start()
        time.sleep(0.3)
        monitor.stop()
        # Should not crash despite callback error

    def test_multiple_start_stop_cycles(self):
        """Monitor should handle multiple start/stop cycles."""
        monitor = StateMonitor(poll_interval=0.1)

        for _ in range(3):
            monitor.start()
            time.sleep(0.1)
            monitor.stop()
            time.sleep(0.05)

        # Should not crash or leak threads
        assert monitor._running is False
