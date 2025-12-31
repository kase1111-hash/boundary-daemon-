"""
Tests for the API Authentication module.

Tests token-based authentication, capabilities, and rate limiting.
"""

import os
import sys
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.auth.api_auth import (
    APICapability,
    APIToken,
    CAPABILITY_SETS,
    COMMAND_CAPABILITIES,
    COMMAND_RATE_LIMITS,
    CommandRateLimitEntry,
)


# ===========================================================================
# APICapability Enum Tests
# ===========================================================================

class TestAPICapability:
    """Tests for APICapability enum."""

    def test_read_only_capabilities(self):
        """Read-only capabilities should exist."""
        assert APICapability.STATUS is not None
        assert APICapability.READ_EVENTS is not None
        assert APICapability.VERIFY_LOG is not None
        assert APICapability.CHECK_RECALL is not None
        assert APICapability.CHECK_TOOL is not None
        assert APICapability.CHECK_MESSAGE is not None

    def test_write_capabilities(self):
        """Write capabilities should exist."""
        assert APICapability.SET_MODE is not None

    def test_admin_capabilities(self):
        """Admin capabilities should exist."""
        assert APICapability.MANAGE_TOKENS is not None
        assert APICapability.ADMIN is not None

    def test_all_capabilities_unique(self):
        """All capability values should be unique."""
        values = [c.value for c in APICapability]
        assert len(values) == len(set(values))


# ===========================================================================
# Capability Sets Tests
# ===========================================================================

class TestCapabilitySets:
    """Tests for predefined capability sets."""

    def test_readonly_set_exists(self):
        """Readonly capability set should exist."""
        assert 'readonly' in CAPABILITY_SETS
        readonly = CAPABILITY_SETS['readonly']
        assert APICapability.STATUS in readonly
        assert APICapability.READ_EVENTS in readonly

    def test_readonly_no_write(self):
        """Readonly set should not include write capabilities."""
        readonly = CAPABILITY_SETS['readonly']
        assert APICapability.SET_MODE not in readonly
        assert APICapability.MANAGE_TOKENS not in readonly
        assert APICapability.ADMIN not in readonly

    def test_operator_set_exists(self):
        """Operator capability set should exist."""
        assert 'operator' in CAPABILITY_SETS
        operator = CAPABILITY_SETS['operator']
        assert APICapability.SET_MODE in operator

    def test_operator_includes_readonly(self):
        """Operator set should include all readonly capabilities."""
        readonly = CAPABILITY_SETS['readonly']
        operator = CAPABILITY_SETS['operator']
        for cap in readonly:
            assert cap in operator

    def test_admin_set_exists(self):
        """Admin capability set should exist."""
        assert 'admin' in CAPABILITY_SETS
        admin = CAPABILITY_SETS['admin']
        assert APICapability.ADMIN in admin


# ===========================================================================
# Command Capabilities Tests
# ===========================================================================

class TestCommandCapabilities:
    """Tests for command-to-capability mapping."""

    def test_status_command(self):
        """status command should require STATUS capability."""
        assert COMMAND_CAPABILITIES['status'] == APICapability.STATUS

    def test_get_events_command(self):
        """get_events command should require READ_EVENTS capability."""
        assert COMMAND_CAPABILITIES['get_events'] == APICapability.READ_EVENTS

    def test_set_mode_command(self):
        """set_mode command should require SET_MODE capability."""
        assert COMMAND_CAPABILITIES['set_mode'] == APICapability.SET_MODE

    def test_token_management_commands(self):
        """Token management commands should require MANAGE_TOKENS."""
        assert COMMAND_CAPABILITIES['create_token'] == APICapability.MANAGE_TOKENS
        assert COMMAND_CAPABILITIES['revoke_token'] == APICapability.MANAGE_TOKENS
        assert COMMAND_CAPABILITIES['list_tokens'] == APICapability.MANAGE_TOKENS

    def test_all_commands_have_capability(self):
        """All defined commands should have a capability mapping."""
        for cmd, cap in COMMAND_CAPABILITIES.items():
            assert isinstance(cap, APICapability)


# ===========================================================================
# Command Rate Limits Tests
# ===========================================================================

class TestCommandRateLimits:
    """Tests for command-specific rate limits."""

    def test_rate_limit_format(self):
        """Rate limits should be (max_requests, window_seconds) tuples."""
        for cmd, limit in COMMAND_RATE_LIMITS.items():
            assert isinstance(limit, tuple)
            assert len(limit) == 2
            assert isinstance(limit[0], int)
            assert isinstance(limit[1], int)

    def test_rate_limits_positive(self):
        """Rate limits should have positive values."""
        for cmd, (max_req, window) in COMMAND_RATE_LIMITS.items():
            assert max_req > 0
            assert window > 0

    def test_read_commands_higher_limits(self):
        """Read commands should have higher rate limits than write."""
        status_limit = COMMAND_RATE_LIMITS['status'][0]
        set_mode_limit = COMMAND_RATE_LIMITS['set_mode'][0]
        assert status_limit > set_mode_limit

    def test_token_commands_strict_limits(self):
        """Token management should have strict limits."""
        create_limit = COMMAND_RATE_LIMITS['create_token'][0]
        assert create_limit <= 10  # Very limited


# ===========================================================================
# CommandRateLimitEntry Tests
# ===========================================================================

class TestCommandRateLimitEntry:
    """Tests for CommandRateLimitEntry dataclass."""

    def test_entry_creation(self):
        """CommandRateLimitEntry should be creatable."""
        entry = CommandRateLimitEntry()
        assert entry.request_times == []
        assert entry.blocked_until is None

    def test_entry_with_times(self):
        """CommandRateLimitEntry should track request times."""
        now = time.monotonic()
        entry = CommandRateLimitEntry(request_times=[now])
        assert len(entry.request_times) == 1

    def test_entry_with_block(self):
        """CommandRateLimitEntry should track block time."""
        block_time = time.monotonic() + 60
        entry = CommandRateLimitEntry(blocked_until=block_time)
        assert entry.blocked_until == block_time


# ===========================================================================
# APIToken Tests
# ===========================================================================

class TestAPIToken:
    """Tests for APIToken dataclass."""

    def test_token_creation(self):
        """APIToken should be creatable with required fields."""
        token = APIToken(
            token_id="abc12345",
            token_hash="hash_value",
            name="test_token",
            capabilities={APICapability.STATUS},
            created_at=datetime.now(),
        )
        assert token.token_id == "abc12345"
        assert token.name == "test_token"

    def test_token_defaults(self):
        """APIToken should have correct defaults."""
        token = APIToken(
            token_id="test",
            token_hash="hash",
            name="test",
            capabilities={APICapability.STATUS},
            created_at=datetime.now(),
        )
        assert token.expires_at is None
        assert token.last_used is None
        assert token.created_by == "system"
        assert token.revoked is False
        assert token.use_count == 0
        assert token.metadata == {}

    def test_token_with_expiry(self):
        """APIToken should accept expiry time."""
        expiry = datetime.now() + timedelta(hours=24)
        token = APIToken(
            token_id="test",
            token_hash="hash",
            name="test",
            capabilities={APICapability.STATUS},
            created_at=datetime.now(),
            expires_at=expiry,
        )
        assert token.expires_at == expiry

    def test_token_is_valid_active(self):
        """is_valid should return True for active token."""
        token = APIToken(
            token_id="test",
            token_hash="hash",
            name="test",
            capabilities={APICapability.STATUS},
            created_at=datetime.now(),
        )
        valid, message = token.is_valid()
        assert valid is True

    def test_token_is_valid_revoked(self):
        """is_valid should return False for revoked token."""
        token = APIToken(
            token_id="test",
            token_hash="hash",
            name="test",
            capabilities={APICapability.STATUS},
            created_at=datetime.now(),
            revoked=True,
        )
        valid, message = token.is_valid()
        assert valid is False
        assert "revoked" in message.lower()

    def test_token_is_valid_expired(self):
        """is_valid should return False for expired token."""
        token = APIToken(
            token_id="test",
            token_hash="hash",
            name="test",
            capabilities={APICapability.STATUS},
            created_at=datetime.now() - timedelta(hours=48),
            expires_at=datetime.now() - timedelta(hours=24),
        )
        valid, message = token.is_valid()
        assert valid is False
        assert "expired" in message.lower()

    def test_token_with_capabilities(self):
        """APIToken should store capabilities correctly."""
        caps = {APICapability.STATUS, APICapability.READ_EVENTS}
        token = APIToken(
            token_id="test",
            token_hash="hash",
            name="test",
            capabilities=caps,
            created_at=datetime.now(),
        )
        assert APICapability.STATUS in token.capabilities
        assert APICapability.READ_EVENTS in token.capabilities
        assert APICapability.SET_MODE not in token.capabilities


# ===========================================================================
# Integration Tests
# ===========================================================================

class TestAPIAuthIntegration:
    """Integration tests for API authentication."""

    def test_readonly_token_workflow(self):
        """Readonly token should not allow write operations."""
        readonly_caps = CAPABILITY_SETS['readonly']
        token = APIToken(
            token_id="readonly",
            token_hash="hash",
            name="Readonly Token",
            capabilities=readonly_caps,
            created_at=datetime.now(),
        )

        # Should be valid
        valid, _ = token.is_valid()
        assert valid is True

        # Should have readonly caps
        assert APICapability.STATUS in token.capabilities
        assert APICapability.SET_MODE not in token.capabilities

    def test_operator_token_workflow(self):
        """Operator token should allow mode changes."""
        operator_caps = CAPABILITY_SETS['operator']
        token = APIToken(
            token_id="operator",
            token_hash="hash",
            name="Operator Token",
            capabilities=operator_caps,
            created_at=datetime.now(),
        )

        # Should have SET_MODE
        assert APICapability.SET_MODE in token.capabilities

    def test_admin_token_workflow(self):
        """Admin token should have full access."""
        admin_caps = CAPABILITY_SETS['admin']
        token = APIToken(
            token_id="admin",
            token_hash="hash",
            name="Admin Token",
            capabilities=admin_caps,
            created_at=datetime.now(),
        )

        # Should have ADMIN
        assert APICapability.ADMIN in token.capabilities


# ===========================================================================
# Edge Cases
# ===========================================================================

class TestAPIAuthEdgeCases:
    """Edge case tests for API authentication."""

    def test_empty_capabilities(self):
        """Token with empty capabilities should be valid but useless."""
        token = APIToken(
            token_id="empty",
            token_hash="hash",
            name="Empty Token",
            capabilities=set(),
            created_at=datetime.now(),
        )
        valid, _ = token.is_valid()
        assert valid is True
        assert len(token.capabilities) == 0

    def test_token_with_metadata(self):
        """Token should store arbitrary metadata."""
        token = APIToken(
            token_id="test",
            token_hash="hash",
            name="test",
            capabilities={APICapability.STATUS},
            created_at=datetime.now(),
            metadata={'client': 'test', 'version': '1.0'},
        )
        assert token.metadata['client'] == 'test'
        assert token.metadata['version'] == '1.0'

    def test_token_use_count(self):
        """Token use count should be trackable."""
        token = APIToken(
            token_id="test",
            token_hash="hash",
            name="test",
            capabilities={APICapability.STATUS},
            created_at=datetime.now(),
            use_count=42,
        )
        assert token.use_count == 42
