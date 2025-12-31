"""
Tests for the Append-Only Storage module.

Tests immutable audit log protection and integrity features.
"""

import os
import sys
import tempfile
import time
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.storage.append_only import (
    AppendOnlyStorage,
    AppendOnlyConfig,
    AppendOnlyMode,
    SyslogFacility,
    SyslogSeverity,
    RemoteSyslogConfig,
    IntegrityCheckpoint,
)


# ===========================================================================
# Enum Tests
# ===========================================================================

class TestAppendOnlyMode:
    """Tests for AppendOnlyMode enum."""

    def test_append_only_mode_values(self):
        """AppendOnlyMode should have expected values."""
        assert AppendOnlyMode.NONE.value == "none"
        assert AppendOnlyMode.CHATTR.value == "chattr"
        assert AppendOnlyMode.COPY_ON_WRITE.value == "cow"
        assert AppendOnlyMode.REMOTE_ONLY.value == "remote"
        assert AppendOnlyMode.FULL.value == "full"


class TestSyslogFacility:
    """Tests for SyslogFacility enum."""

    def test_syslog_facility_values(self):
        """SyslogFacility should have expected values."""
        assert SyslogFacility.KERN.value == 0
        assert SyslogFacility.USER.value == 1
        assert SyslogFacility.DAEMON.value == 3
        assert SyslogFacility.AUTH.value == 4
        assert SyslogFacility.LOCAL0.value == 16
        assert SyslogFacility.LOCAL7.value == 23


class TestSyslogSeverity:
    """Tests for SyslogSeverity enum."""

    def test_syslog_severity_values(self):
        """SyslogSeverity should have expected values."""
        assert SyslogSeverity.EMERGENCY.value == 0
        assert SyslogSeverity.ALERT.value == 1
        assert SyslogSeverity.CRITICAL.value == 2
        assert SyslogSeverity.ERROR.value == 3
        assert SyslogSeverity.WARNING.value == 4
        assert SyslogSeverity.NOTICE.value == 5
        assert SyslogSeverity.INFO.value == 6
        assert SyslogSeverity.DEBUG.value == 7


# ===========================================================================
# Dataclass Tests
# ===========================================================================

class TestRemoteSyslogConfig:
    """Tests for RemoteSyslogConfig dataclass."""

    def test_remote_syslog_config_creation(self):
        """RemoteSyslogConfig should be creatable."""
        config = RemoteSyslogConfig(host="syslog.example.com")
        assert config.host == "syslog.example.com"
        assert config.port == 514
        assert config.protocol == "udp"

    def test_remote_syslog_config_defaults(self):
        """RemoteSyslogConfig should have correct defaults."""
        config = RemoteSyslogConfig(host="test")
        assert config.facility == SyslogFacility.LOCAL0
        assert config.app_name == "boundary-daemon"
        assert config.use_tls is False
        assert config.tls_verify is True
        assert config.timeout == 5.0
        assert config.retry_count == 3

    def test_remote_syslog_config_custom(self):
        """RemoteSyslogConfig should accept custom values."""
        config = RemoteSyslogConfig(
            host="secure.example.com",
            port=6514,
            protocol="tls",
            use_tls=True,
            tls_ca_cert="/path/to/ca.crt",
        )
        assert config.port == 6514
        assert config.use_tls is True


class TestIntegrityCheckpoint:
    """Tests for IntegrityCheckpoint dataclass."""

    def test_integrity_checkpoint_creation(self):
        """IntegrityCheckpoint should be creatable."""
        checkpoint = IntegrityCheckpoint(
            checkpoint_id="cp-001",
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_count=100,
            last_event_hash="abc123",
            checkpoint_hash="def456",
        )
        assert checkpoint.checkpoint_id == "cp-001"
        assert checkpoint.event_count == 100
        assert checkpoint.signature is None

    def test_integrity_checkpoint_with_signature(self):
        """IntegrityCheckpoint should accept signature."""
        checkpoint = IntegrityCheckpoint(
            checkpoint_id="cp-002",
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_count=200,
            last_event_hash="hash1",
            checkpoint_hash="hash2",
            signature="sig123",
        )
        assert checkpoint.signature == "sig123"


class TestAppendOnlyConfig:
    """Tests for AppendOnlyConfig dataclass."""

    def test_config_defaults(self):
        """AppendOnlyConfig should have sensible defaults."""
        config = AppendOnlyConfig()
        assert config.mode == AppendOnlyMode.CHATTR
        assert config.log_path == "./logs/boundary_chain.log"
        assert config.checkpoint_interval == 3600
        assert config.auto_protect is True
        assert config.backup_count == 5

    def test_config_custom(self):
        """AppendOnlyConfig should accept custom values."""
        config = AppendOnlyConfig(
            mode=AppendOnlyMode.NONE,
            log_path="/var/log/boundary.log",
            checkpoint_interval=1800,
        )
        assert config.mode == AppendOnlyMode.NONE
        assert config.log_path == "/var/log/boundary.log"

    def test_config_with_remote_syslog(self):
        """AppendOnlyConfig should accept remote syslog config."""
        remote = RemoteSyslogConfig(host="syslog.example.com")
        config = AppendOnlyConfig(remote_syslog=remote)
        assert config.remote_syslog is not None
        assert config.remote_syslog.host == "syslog.example.com"


# ===========================================================================
# AppendOnlyStorage Initialization Tests
# ===========================================================================

class TestAppendOnlyStorageInit:
    """Tests for AppendOnlyStorage initialization."""

    def test_init_default(self):
        """AppendOnlyStorage should initialize with defaults."""
        storage = AppendOnlyStorage()
        assert isinstance(storage.config, AppendOnlyConfig)
        assert storage._initialized is False
        assert storage._protected is False

    def test_init_with_config(self):
        """AppendOnlyStorage should accept custom config."""
        config = AppendOnlyConfig(mode=AppendOnlyMode.NONE)
        storage = AppendOnlyStorage(config=config)
        assert storage.config.mode == AppendOnlyMode.NONE

    def test_init_creates_lock(self):
        """AppendOnlyStorage should create thread lock."""
        storage = AppendOnlyStorage()
        assert storage._lock is not None


# ===========================================================================
# AppendOnlyStorage Mode Tests
# ===========================================================================

class TestAppendOnlyStorageModes:
    """Tests for different append-only modes."""

    def test_mode_none(self):
        """NONE mode should be supported."""
        config = AppendOnlyConfig(mode=AppendOnlyMode.NONE)
        storage = AppendOnlyStorage(config=config)
        assert storage.config.mode == AppendOnlyMode.NONE

    def test_mode_chattr(self):
        """CHATTR mode should be supported."""
        config = AppendOnlyConfig(mode=AppendOnlyMode.CHATTR)
        storage = AppendOnlyStorage(config=config)
        assert storage.config.mode == AppendOnlyMode.CHATTR

    def test_mode_full(self):
        """FULL mode should be supported."""
        config = AppendOnlyConfig(mode=AppendOnlyMode.FULL)
        storage = AppendOnlyStorage(config=config)
        assert storage.config.mode == AppendOnlyMode.FULL


# ===========================================================================
# Syslog Priority Calculation Tests
# ===========================================================================

class TestSyslogPriority:
    """Tests for syslog priority calculation."""

    def test_facility_codes(self):
        """Facility codes should be correct for priority calculation."""
        # Priority = (facility * 8) + severity
        # LOCAL0 (16) + INFO (6) = 134
        priority = SyslogFacility.LOCAL0.value * 8 + SyslogSeverity.INFO.value
        assert priority == 134

    def test_priority_range(self):
        """Priority should be in valid range (0-191)."""
        for facility in SyslogFacility:
            for severity in SyslogSeverity:
                priority = facility.value * 8 + severity.value
                assert 0 <= priority <= 191


# ===========================================================================
# Integration Tests
# ===========================================================================

class TestAppendOnlyStorageIntegration:
    """Integration tests for AppendOnlyStorage."""

    def test_create_storage_with_temp_path(self):
        """Storage should work with temporary paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = AppendOnlyConfig(
                mode=AppendOnlyMode.NONE,
                log_path=os.path.join(tmpdir, "test.log"),
                wal_path=os.path.join(tmpdir, "test_wal.log"),
                checkpoint_path=os.path.join(tmpdir, "checkpoints"),
            )
            storage = AppendOnlyStorage(config=config)
            assert storage is not None

    def test_multiple_storage_instances(self):
        """Multiple storage instances should be independent."""
        config1 = AppendOnlyConfig(mode=AppendOnlyMode.NONE)
        config2 = AppendOnlyConfig(mode=AppendOnlyMode.CHATTR)

        storage1 = AppendOnlyStorage(config=config1)
        storage2 = AppendOnlyStorage(config=config2)

        assert storage1.config.mode != storage2.config.mode


# ===========================================================================
# Edge Cases
# ===========================================================================

class TestAppendOnlyStorageEdgeCases:
    """Edge case tests for AppendOnlyStorage."""

    def test_none_config(self):
        """Storage should handle None config."""
        storage = AppendOnlyStorage(config=None)
        assert storage.config is not None

    def test_empty_checkpoint_path(self):
        """Storage should handle default checkpoint path."""
        config = AppendOnlyConfig()
        assert config.checkpoint_path is not None

    def test_config_path_types(self):
        """Config paths should be strings."""
        config = AppendOnlyConfig()
        assert isinstance(config.log_path, str)
        assert isinstance(config.wal_path, str)
        assert isinstance(config.checkpoint_path, str)


# ===========================================================================
# Remote Syslog Configuration Tests
# ===========================================================================

class TestRemoteSyslogIntegration:
    """Tests for remote syslog configuration."""

    def test_syslog_udp_config(self):
        """UDP syslog config should be valid."""
        config = RemoteSyslogConfig(
            host="127.0.0.1",
            port=514,
            protocol="udp",
        )
        assert config.protocol == "udp"
        assert config.use_tls is False

    def test_syslog_tcp_config(self):
        """TCP syslog config should be valid."""
        config = RemoteSyslogConfig(
            host="127.0.0.1",
            port=514,
            protocol="tcp",
        )
        assert config.protocol == "tcp"

    def test_syslog_tls_config(self):
        """TLS syslog config should be valid."""
        config = RemoteSyslogConfig(
            host="secure.example.com",
            port=6514,
            protocol="tls",
            use_tls=True,
            tls_ca_cert="/etc/ssl/certs/ca.crt",
            tls_verify=True,
        )
        assert config.use_tls is True
        assert config.tls_verify is True
