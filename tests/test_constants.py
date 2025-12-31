"""
Tests for the Constants module.

Tests centralized configuration values and constants.
"""

import os
import sys

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.constants import (
    Timeouts,
    BufferSizes,
    Permissions,
)


# ===========================================================================
# Timeout Constants Tests
# ===========================================================================

class TestTimeouts:
    """Tests for Timeouts dataclass."""

    def test_subprocess_timeouts_positive(self):
        """Subprocess timeouts should be positive."""
        assert Timeouts.SUBPROCESS_SHORT > 0
        assert Timeouts.SUBPROCESS_DEFAULT > 0
        assert Timeouts.SUBPROCESS_MEDIUM > 0
        assert Timeouts.SUBPROCESS_LONG > 0
        assert Timeouts.SUBPROCESS_EXTENDED > 0

    def test_subprocess_timeouts_ordered(self):
        """Subprocess timeouts should be in ascending order."""
        assert Timeouts.SUBPROCESS_SHORT < Timeouts.SUBPROCESS_DEFAULT
        assert Timeouts.SUBPROCESS_DEFAULT < Timeouts.SUBPROCESS_MEDIUM
        assert Timeouts.SUBPROCESS_MEDIUM < Timeouts.SUBPROCESS_LONG
        assert Timeouts.SUBPROCESS_LONG < Timeouts.SUBPROCESS_EXTENDED

    def test_network_timeouts_positive(self):
        """Network timeouts should be positive."""
        assert Timeouts.SOCKET_CONNECT > 0
        assert Timeouts.SOCKET_READ > 0
        assert Timeouts.DNS_QUERY > 0
        assert Timeouts.HTTP_REQUEST > 0

    def test_thread_join_timeouts_positive(self):
        """Thread join timeouts should be positive."""
        assert Timeouts.THREAD_JOIN_SHORT > 0
        assert Timeouts.THREAD_JOIN_DEFAULT > 0
        assert Timeouts.THREAD_JOIN_LONG > 0

    def test_monitoring_intervals_positive(self):
        """Monitoring intervals should be positive."""
        assert Timeouts.HEALTH_CHECK_INTERVAL > 0
        assert Timeouts.STATE_POLL_INTERVAL > 0
        assert Timeouts.ENFORCEMENT_INTERVAL > 0
        assert Timeouts.INTEGRITY_CHECK_INTERVAL > 0

    def test_challenge_timeouts(self):
        """Challenge and ceremony timeouts should be defined."""
        assert Timeouts.CHALLENGE_MAX_AGE > 0
        assert Timeouts.CEREMONY_COOLDOWN > 0

    def test_sleep_intervals(self):
        """Sleep intervals should be defined and ordered."""
        assert Timeouts.SLEEP_SHORT > 0
        assert Timeouts.SLEEP_DEFAULT > 0
        assert Timeouts.SLEEP_LONG > 0
        assert Timeouts.SLEEP_SHORT < Timeouts.SLEEP_DEFAULT < Timeouts.SLEEP_LONG

    def test_timeouts_are_class_attributes(self):
        """Timeout values should be class attributes."""
        # Verify we can access values
        assert hasattr(Timeouts, 'SUBPROCESS_DEFAULT')
        assert hasattr(Timeouts, 'SOCKET_CONNECT')


# ===========================================================================
# Buffer Size Constants Tests
# ===========================================================================

class TestBufferSizes:
    """Tests for BufferSizes dataclass."""

    def test_socket_buffers_positive(self):
        """Socket buffer sizes should be positive."""
        assert BufferSizes.SOCKET_RECV > 0
        assert BufferSizes.SOCKET_SEND > 0

    def test_file_chunk_sizes_positive(self):
        """File chunk sizes should be positive."""
        assert BufferSizes.FILE_CHUNK > 0
        assert BufferSizes.FILE_CHUNK_SMALL > 0
        assert BufferSizes.FILE_CHUNK_LARGE > 0

    def test_file_chunk_sizes_ordered(self):
        """File chunk sizes should be in ascending order."""
        assert BufferSizes.FILE_CHUNK_SMALL < BufferSizes.FILE_CHUNK
        assert BufferSizes.FILE_CHUNK < BufferSizes.FILE_CHUNK_LARGE

    def test_message_limits_positive(self):
        """Message size limits should be positive."""
        assert BufferSizes.MESSAGE_MAX_LENGTH > 0
        assert BufferSizes.LOG_LINE_MAX > 0

    def test_event_buffer_sizes_ordered(self):
        """Event buffer sizes should be in ascending order."""
        assert BufferSizes.EVENT_BUFFER_SMALL < BufferSizes.EVENT_BUFFER_DEFAULT
        assert BufferSizes.EVENT_BUFFER_DEFAULT < BufferSizes.EVENT_BUFFER_LARGE

    def test_max_file_sizes_ordered(self):
        """Max file sizes should be in ascending order."""
        assert BufferSizes.MAX_FILE_SIZE_SMALL < BufferSizes.MAX_FILE_SIZE_MEDIUM
        assert BufferSizes.MAX_FILE_SIZE_MEDIUM < BufferSizes.MAX_FILE_SIZE_LARGE

    def test_buffers_are_class_attributes(self):
        """Buffer size values should be class attributes."""
        assert hasattr(BufferSizes, 'SOCKET_RECV')
        assert hasattr(BufferSizes, 'FILE_CHUNK')


# ===========================================================================
# Permission Constants Tests
# ===========================================================================

class TestPermissions:
    """Tests for Permissions IntEnum."""

    def test_owner_permissions(self):
        """Owner-only permissions should be correct."""
        assert Permissions.OWNER_READ_ONLY == 0o400
        assert Permissions.OWNER_READ_WRITE == 0o600
        assert Permissions.OWNER_READ_WRITE_EXEC == 0o700

    def test_secure_permissions(self):
        """Secure file/dir permissions should be correct."""
        assert Permissions.SECURE_FILE == 0o600
        assert Permissions.SECURE_DIR == 0o700

    def test_standard_permissions(self):
        """Standard permissions should be correct."""
        assert Permissions.STANDARD_FILE == 0o644
        assert Permissions.STANDARD_DIR == 0o755

    def test_special_permissions(self):
        """Special permission values should be correct."""
        assert Permissions.NO_ACCESS == 0o000
        assert Permissions.READ_ONLY_ALL == 0o444

    def test_suid_sgid_bits(self):
        """SUID/SGID/Sticky bits should be correct."""
        assert Permissions.SUID_BIT == 0o4000
        assert Permissions.SGID_BIT == 0o2000
        assert Permissions.STICKY_BIT == 0o1000

    def test_permissions_are_integers(self):
        """All permissions should be integers."""
        for perm in Permissions:
            assert isinstance(perm.value, int)

    def test_secure_more_restrictive_than_standard(self):
        """Secure permissions should be more restrictive than standard."""
        # SECURE_FILE (0o600) should not allow group/other access
        # STANDARD_FILE (0o644) allows read by group/other
        assert Permissions.SECURE_FILE < Permissions.STANDARD_FILE

    def test_permission_octal_format(self):
        """Permissions should be valid Unix permission values."""
        for perm in Permissions:
            # All bits should be in valid range (0-7 for each octal digit)
            # This validates they're proper permission values
            assert 0 <= perm.value <= 0o7777


# ===========================================================================
# Integration Tests
# ===========================================================================

class TestConstantsIntegration:
    """Integration tests for constants module."""

    def test_timeout_reasonable_for_security(self):
        """Timeouts should be reasonable for security operations."""
        # Challenge should expire quickly to prevent replay attacks
        assert Timeouts.CHALLENGE_MAX_AGE <= 60

        # Socket operations shouldn't hang forever
        assert Timeouts.SOCKET_CONNECT <= 30
        assert Timeouts.SOCKET_READ <= 60

    def test_buffer_sizes_reasonable(self):
        """Buffer sizes should be reasonable values."""
        # File chunks should be reasonable
        assert BufferSizes.FILE_CHUNK >= 1024
        assert BufferSizes.FILE_CHUNK_LARGE >= BufferSizes.FILE_CHUNK

    def test_all_constants_accessible(self):
        """All constant classes should be importable and accessible."""
        # These should not raise
        _ = Timeouts.SUBPROCESS_DEFAULT
        _ = BufferSizes.SOCKET_RECV
        _ = Permissions.SECURE_FILE
