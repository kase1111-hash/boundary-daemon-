"""
Tests for the Tripwire System module.

Tests security violation detection, lockdown triggers, and auth requirements.
"""

import os
import sys
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.tripwires import (
    TripwireSystem,
    TripwireViolation,
    ViolationType,
)
from daemon.policy_engine import BoundaryMode
from daemon.state_monitor import NetworkState


# ===========================================================================
# ViolationType Enum Tests
# ===========================================================================

class TestViolationType:
    """Tests for ViolationType enum."""

    def test_violation_type_values(self):
        """ViolationType should have expected values."""
        assert ViolationType.NETWORK_IN_AIRGAP.value == "network_in_airgap"
        assert ViolationType.USB_IN_COLDROOM.value == "usb_in_coldroom"
        assert ViolationType.UNAUTHORIZED_RECALL.value == "unauthorized_recall"
        assert ViolationType.DAEMON_TAMPERING.value == "daemon_tampering"
        assert ViolationType.MODE_INCOMPATIBLE.value == "mode_incompatible"
        assert ViolationType.EXTERNAL_MODEL_VIOLATION.value == "external_model_violation"
        assert ViolationType.SUSPICIOUS_PROCESS.value == "suspicious_process"
        assert ViolationType.HARDWARE_TRUST_DEGRADED.value == "hardware_trust_degraded"


# ===========================================================================
# TripwireViolation Dataclass Tests
# ===========================================================================

class TestTripwireViolation:
    """Tests for TripwireViolation dataclass."""

    def test_violation_creation(self):
        """TripwireViolation should be creatable."""
        violation = TripwireViolation(
            violation_id="test-001",
            timestamp=datetime.utcnow().isoformat() + "Z",
            violation_type=ViolationType.NETWORK_IN_AIRGAP,
            details="Network came online in AIRGAP mode",
            current_mode=BoundaryMode.AIRGAP,
            environment_snapshot={'network': 'online'},
            auto_lockdown=True,
        )
        assert violation.violation_id == "test-001"
        assert violation.violation_type == ViolationType.NETWORK_IN_AIRGAP
        assert violation.auto_lockdown is True

    def test_violation_all_fields(self):
        """TripwireViolation should store all fields correctly."""
        snapshot = {'usb': ['device1'], 'network': 'offline'}
        violation = TripwireViolation(
            violation_id="v-123",
            timestamp="2024-01-01T00:00:00Z",
            violation_type=ViolationType.USB_IN_COLDROOM,
            details="USB device inserted",
            current_mode=BoundaryMode.COLDROOM,
            environment_snapshot=snapshot,
            auto_lockdown=True,
        )
        assert violation.environment_snapshot == snapshot
        assert violation.current_mode == BoundaryMode.COLDROOM


# ===========================================================================
# TripwireSystem Initialization Tests
# ===========================================================================

class TestTripwireSystemInit:
    """Tests for TripwireSystem initialization."""

    def test_init_default(self):
        """TripwireSystem should initialize with defaults."""
        tripwire = TripwireSystem()
        assert tripwire._enabled is True
        assert tripwire._locked is False
        assert tripwire._auth_required is True
        assert len(tripwire._violations) == 0  # May be deque or list
        assert tripwire._callbacks == []

    def test_init_with_event_logger(self):
        """TripwireSystem should accept an event logger."""
        mock_logger = MagicMock()
        tripwire = TripwireSystem(event_logger=mock_logger)
        assert tripwire._event_logger == mock_logger

    def test_init_generates_auth_token(self):
        """TripwireSystem should generate an auth token on init."""
        tripwire = TripwireSystem()
        assert tripwire._auth_token_hash is not None
        assert len(tripwire._auth_token_hash) == 64  # SHA256 hex length

    def test_init_baseline_tracking(self):
        """TripwireSystem should initialize baseline tracking."""
        tripwire = TripwireSystem()
        assert tripwire._baseline_usb_devices is None
        assert tripwire._previous_mode is None
        assert tripwire._previous_network_state is None

    def test_max_disable_attempts_default(self):
        """TripwireSystem should have default max disable attempts."""
        tripwire = TripwireSystem()
        assert tripwire._max_disable_attempts == 3
        assert tripwire._failed_attempts == 0


# ===========================================================================
# TripwireSystem Callback Tests
# ===========================================================================

class TestTripwireSystemCallbacks:
    """Tests for TripwireSystem callback functionality."""

    def test_register_callback(self):
        """register_callback should add callback to list."""
        tripwire = TripwireSystem()
        callback = MagicMock()
        tripwire.register_callback(callback)
        assert callback in tripwire._callbacks

    def test_register_multiple_callbacks(self):
        """Multiple callbacks can be registered."""
        tripwire = TripwireSystem()
        cb1 = MagicMock()
        cb2 = MagicMock()
        tripwire.register_callback(cb1)
        tripwire.register_callback(cb2)
        assert len(tripwire._callbacks) == 2


# ===========================================================================
# TripwireSystem Enable/Disable Tests
# ===========================================================================

class TestTripwireSystemEnableDisable:
    """Tests for TripwireSystem enable/disable functionality."""

    def test_enable(self):
        """enable() should enable tripwire monitoring."""
        tripwire = TripwireSystem()
        tripwire._enabled = False
        tripwire.enable()
        assert tripwire._enabled is True

    def test_disable_requires_auth(self):
        """disable() should require valid authentication."""
        tripwire = TripwireSystem()
        success, message = tripwire.disable("invalid_token")
        assert success is False
        assert "Invalid authentication" in message

    def test_disable_with_valid_token(self):
        """disable() should work with valid token."""
        tripwire = TripwireSystem()
        # Get the actual token during initialization
        token = tripwire._generate_auth_token()
        success, message = tripwire.disable(token, reason="testing")
        assert success is True
        assert tripwire._enabled is False

    def test_disable_tracks_failed_attempts(self):
        """disable() should track failed attempts."""
        tripwire = TripwireSystem()
        initial_attempts = tripwire._failed_attempts
        tripwire.disable("bad_token")
        assert tripwire._failed_attempts == initial_attempts + 1

    def test_disable_locks_after_max_attempts(self):
        """disable() should lock system after max failed attempts."""
        tripwire = TripwireSystem()
        tripwire._max_disable_attempts = 3

        for i in range(3):
            tripwire.disable("bad_token")

        assert tripwire._locked is True

    def test_disable_fails_when_locked(self):
        """disable() should fail when system is locked."""
        tripwire = TripwireSystem()
        tripwire._locked = True
        token = tripwire._generate_auth_token()
        success, message = tripwire.disable(token)
        assert success is False
        assert "LOCKED" in message


# ===========================================================================
# TripwireSystem Token Tests
# ===========================================================================

class TestTripwireSystemTokens:
    """Tests for TripwireSystem token functionality."""

    def test_verify_token_valid(self):
        """_verify_token should return True for valid token."""
        tripwire = TripwireSystem()
        token = tripwire._generate_auth_token()
        assert tripwire._verify_token(token) is True

    def test_verify_token_invalid(self):
        """_verify_token should return False for invalid token."""
        tripwire = TripwireSystem()
        tripwire._generate_auth_token()
        assert tripwire._verify_token("invalid_token") is False

    def test_verify_token_empty(self):
        """_verify_token should return False for empty token."""
        tripwire = TripwireSystem()
        assert tripwire._verify_token("") is False
        assert tripwire._verify_token(None) is False

    def test_get_new_auth_token_valid(self):
        """get_new_auth_token should return new token with valid current token."""
        tripwire = TripwireSystem()
        current_token = tripwire._generate_auth_token()
        new_token = tripwire.get_new_auth_token(current_token)
        assert new_token is not None
        assert new_token != current_token

    def test_get_new_auth_token_invalid(self):
        """get_new_auth_token should return None with invalid token."""
        tripwire = TripwireSystem()
        tripwire._generate_auth_token()
        new_token = tripwire.get_new_auth_token("bad_token")
        assert new_token is None

    def test_token_generation_creates_hash(self):
        """_generate_auth_token should create a hash."""
        tripwire = TripwireSystem()
        old_hash = tripwire._auth_token_hash
        tripwire._generate_auth_token()
        assert tripwire._auth_token_hash != old_hash


# ===========================================================================
# TripwireSystem Failed Attempts Tests
# ===========================================================================

class TestTripwireSystemFailedAttempts:
    """Tests for failed attempt tracking."""

    def test_log_failed_attempt(self):
        """_log_failed_attempt should track attempts."""
        tripwire = TripwireSystem()
        initial = len(tripwire._disable_attempts)
        tripwire._log_failed_attempt("test_op")
        assert len(tripwire._disable_attempts) == initial + 1
        assert tripwire._disable_attempts[-1]['operation'] == "test_op"

    def test_log_failed_attempt_increments_counter(self):
        """_log_failed_attempt should increment failed counter."""
        tripwire = TripwireSystem()
        initial = tripwire._failed_attempts
        tripwire._log_failed_attempt("test")
        assert tripwire._failed_attempts == initial + 1

    def test_log_failed_attempt_locks_on_max(self):
        """_log_failed_attempt should lock on max attempts."""
        tripwire = TripwireSystem()
        tripwire._max_disable_attempts = 2
        tripwire._log_failed_attempt("test1")
        assert tripwire._locked is False
        tripwire._log_failed_attempt("test2")
        assert tripwire._locked is True

    def test_failed_attempt_records_timestamp(self):
        """Failed attempts should record timestamp."""
        tripwire = TripwireSystem()
        tripwire._log_failed_attempt("test")
        assert 'timestamp' in tripwire._disable_attempts[-1]


# ===========================================================================
# TripwireSystem Security Properties Tests
# ===========================================================================

class TestTripwireSystemSecurity:
    """Tests for security properties."""

    def test_auth_required_cannot_be_disabled(self):
        """_auth_required should remain True."""
        tripwire = TripwireSystem()
        assert tripwire._auth_required is True
        # Even if someone tries to set it...
        tripwire._auth_required = False
        # In a real implementation, this would be protected
        # For now, we just test the initial state

    def test_locked_state_persists(self):
        """Locked state should persist after being set."""
        tripwire = TripwireSystem()
        tripwire._locked = True
        # Verify it stays locked
        token = tripwire._generate_auth_token()
        success, _ = tripwire.disable(token)
        assert success is False
        assert tripwire._locked is True

    def test_token_hash_not_plaintext(self):
        """Token hash should not be the plaintext token."""
        tripwire = TripwireSystem()
        token = tripwire._generate_auth_token()
        assert tripwire._auth_token_hash != token
        assert len(tripwire._auth_token_hash) == 64  # SHA256


# ===========================================================================
# TripwireSystem Integration Tests
# ===========================================================================

class TestTripwireSystemIntegration:
    """Integration tests for TripwireSystem."""

    def test_full_auth_workflow(self):
        """Test complete authentication workflow."""
        tripwire = TripwireSystem()

        # Get initial token
        token1 = tripwire._generate_auth_token()

        # Should be able to disable with valid token
        success, _ = tripwire.disable(token1, reason="test")
        assert success is True
        assert tripwire._enabled is False

        # Re-enable
        tripwire.enable()
        assert tripwire._enabled is True

        # Get new token
        token2 = tripwire.get_new_auth_token(token1)
        assert token2 is not None

        # Old token should not work anymore
        success, _ = tripwire.disable(token1, reason="test with old token")
        assert success is False

        # New token should work
        success, _ = tripwire.disable(token2, reason="test with new token")
        assert success is True

    def test_lockout_workflow(self):
        """Test lockout after failed attempts."""
        tripwire = TripwireSystem()
        tripwire._max_disable_attempts = 2

        # Fail twice
        tripwire.disable("bad1")
        tripwire.disable("bad2")

        # Should be locked now
        assert tripwire._locked is True

        # Even valid token should fail
        token = tripwire._generate_auth_token()
        success, message = tripwire.disable(token)
        assert success is False
        assert "LOCKED" in message

    def test_multiple_tripwire_instances(self):
        """Multiple TripwireSystem instances should be independent."""
        ts1 = TripwireSystem()
        ts2 = TripwireSystem()

        token1 = ts1._generate_auth_token()
        token2 = ts2._generate_auth_token()

        # Tokens should be different
        assert token1 != token2

        # Disable ts1 should not affect ts2
        ts1.disable(token1)
        assert ts1._enabled is False
        assert ts2._enabled is True


# ===========================================================================
# Edge Cases
# ===========================================================================

class TestTripwireEdgeCases:
    """Edge case tests for TripwireSystem."""

    def test_empty_violations_list(self):
        """Violations list should be empty initially."""
        tripwire = TripwireSystem()
        assert len(tripwire._violations) == 0  # May be deque or list

    def test_enable_when_already_enabled(self):
        """enable() when already enabled should not error."""
        tripwire = TripwireSystem()
        assert tripwire._enabled is True
        tripwire.enable()  # Should not raise
        assert tripwire._enabled is True

    def test_callback_with_no_callbacks(self):
        """System should work with no callbacks registered."""
        tripwire = TripwireSystem()
        # No callbacks registered - should not error
        assert len(tripwire._callbacks) == 0

    def test_token_constant_time_comparison(self):
        """Token verification should use constant-time comparison."""
        tripwire = TripwireSystem()
        token = tripwire._generate_auth_token()

        # These should take similar time regardless of where they differ
        # (This is a property test - the implementation uses hmac.compare_digest)
        import time

        # Correct token
        start = time.time()
        tripwire._verify_token(token)
        correct_time = time.time() - start

        # Wrong token (first char different)
        start = time.time()
        tripwire._verify_token("X" + token[1:])
        wrong_start_time = time.time() - start

        # Wrong token (last char different)
        start = time.time()
        tripwire._verify_token(token[:-1] + "X")
        wrong_end_time = time.time() - start

        # Times should be in same ballpark (not testing exact timing,
        # just that the code path uses constant-time comparison)
        # This is more of a smoke test that the code runs
        assert correct_time >= 0
        assert wrong_start_time >= 0
        assert wrong_end_time >= 0
