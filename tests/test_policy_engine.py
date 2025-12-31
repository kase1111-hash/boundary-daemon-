"""
Tests for daemon/policy_engine.py - Boundary Mode and Policy Enforcement

Tests cover:
- Boundary mode transitions
- Policy evaluation for different request types
- Memory class to mode mapping
- Environment compatibility checks
- Thread safety
- Edge cases and error handling
"""

import os
import sys
import threading
from datetime import datetime
from typing import List
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.policy_engine import (
    PolicyEngine, BoundaryMode, BoundaryState, PolicyRequest,
    PolicyDecision, MemoryClass, Operator
)
from daemon.state_monitor import (
    NetworkState, HardwareTrust, EnvironmentState, NetworkType,
    SpecialtyNetworkStatus
)


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def mock_env_state() -> EnvironmentState:
    """Provide a default mock environment state."""
    return EnvironmentState(
        timestamp=datetime.utcnow().isoformat() + "Z",
        network=NetworkState.OFFLINE,
        hardware_trust=HardwareTrust.HIGH,
        active_interfaces=[],
        interface_types={},
        has_internet=False,
        vpn_active=False,
        dns_available=False,
        specialty_networks=SpecialtyNetworkStatus(
            lora_devices=[],
            thread_devices=[],
            wimax_interfaces=[],
            irda_devices=[],
            ant_plus_devices=[],
            cellular_alerts=[]
        ),
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
        last_activity=None
    )


@pytest.fixture
def online_env_state(mock_env_state) -> EnvironmentState:
    """Provide an online environment state."""
    mock_env_state.network = NetworkState.ONLINE
    mock_env_state.has_internet = True
    mock_env_state.active_interfaces = ['eth0']
    return mock_env_state


@pytest.fixture
def vpn_env_state(mock_env_state) -> EnvironmentState:
    """Provide an environment with VPN active."""
    mock_env_state.network = NetworkState.ONLINE
    mock_env_state.has_internet = True
    mock_env_state.vpn_active = True
    mock_env_state.active_interfaces = ['tun0', 'eth0']
    return mock_env_state


# ===========================================================================
# Boundary Mode Tests
# ===========================================================================

class TestBoundaryMode:
    """Tests for BoundaryMode enum and ordering."""

    @pytest.mark.unit
    def test_mode_ordering(self):
        """Test that modes have correct numeric ordering."""
        assert BoundaryMode.OPEN < BoundaryMode.RESTRICTED
        assert BoundaryMode.RESTRICTED < BoundaryMode.TRUSTED
        assert BoundaryMode.TRUSTED < BoundaryMode.AIRGAP
        assert BoundaryMode.AIRGAP < BoundaryMode.COLDROOM
        assert BoundaryMode.COLDROOM < BoundaryMode.LOCKDOWN

    @pytest.mark.unit
    def test_mode_values(self):
        """Test that modes have expected integer values."""
        assert BoundaryMode.OPEN.value == 0
        assert BoundaryMode.RESTRICTED.value == 1
        assert BoundaryMode.TRUSTED.value == 2
        assert BoundaryMode.AIRGAP.value == 3
        assert BoundaryMode.COLDROOM.value == 4
        assert BoundaryMode.LOCKDOWN.value == 5


class TestPolicyEngineInitialization:
    """Tests for PolicyEngine initialization."""

    @pytest.mark.unit
    def test_default_initialization(self):
        """Test default initialization."""
        engine = PolicyEngine()
        assert engine.get_current_mode() == BoundaryMode.OPEN

    @pytest.mark.unit
    def test_custom_initial_mode(self):
        """Test initialization with custom mode."""
        engine = PolicyEngine(initial_mode=BoundaryMode.RESTRICTED)
        assert engine.get_current_mode() == BoundaryMode.RESTRICTED

    @pytest.mark.unit
    def test_get_current_state(self, policy_engine):
        """Test getting complete state."""
        state = policy_engine.get_current_state()
        assert isinstance(state, BoundaryState)
        assert state.mode == BoundaryMode.OPEN
        assert isinstance(state.network, NetworkState)
        assert isinstance(state.hardware_trust, HardwareTrust)


class TestModeTransitions:
    """Tests for mode transitions."""

    @pytest.mark.unit
    def test_transition_success(self, policy_engine):
        """Test successful mode transition."""
        success, msg = policy_engine.transition_mode(
            BoundaryMode.RESTRICTED,
            Operator.HUMAN,
            "Manual upgrade"
        )
        assert success is True
        assert policy_engine.get_current_mode() == BoundaryMode.RESTRICTED
        assert "RESTRICTED" in msg

    @pytest.mark.unit
    def test_transition_callback(self, policy_engine):
        """Test that transition callbacks are called."""
        callback_calls = []

        def callback(old_mode, new_mode, operator, reason):
            callback_calls.append((old_mode, new_mode, operator, reason))

        policy_engine.register_transition_callback(callback)
        policy_engine.transition_mode(
            BoundaryMode.TRUSTED,
            Operator.SYSTEM,
            "Auto-upgrade"
        )

        assert len(callback_calls) == 1
        assert callback_calls[0][0] == BoundaryMode.OPEN
        assert callback_calls[0][1] == BoundaryMode.TRUSTED
        assert callback_calls[0][2] == Operator.SYSTEM

    @pytest.mark.unit
    def test_lockdown_exit_requires_human(self, policy_engine_lockdown):
        """Test that LOCKDOWN exit requires human intervention."""
        success, msg = policy_engine_lockdown.transition_mode(
            BoundaryMode.OPEN,
            Operator.SYSTEM,
            "System recovery"
        )
        assert success is False
        assert "human" in msg.lower()
        assert policy_engine_lockdown.get_current_mode() == BoundaryMode.LOCKDOWN

    @pytest.mark.unit
    def test_lockdown_exit_with_human(self, policy_engine_lockdown):
        """Test that LOCKDOWN exit works with human intervention."""
        success, msg = policy_engine_lockdown.transition_mode(
            BoundaryMode.OPEN,
            Operator.HUMAN,
            "Manual recovery"
        )
        assert success is True
        assert policy_engine_lockdown.get_current_mode() == BoundaryMode.OPEN

    @pytest.mark.unit
    def test_transition_all_modes(self, policy_engine):
        """Test transitions to all modes."""
        modes = [
            BoundaryMode.RESTRICTED,
            BoundaryMode.TRUSTED,
            BoundaryMode.AIRGAP,
            BoundaryMode.COLDROOM,
            BoundaryMode.LOCKDOWN,
            BoundaryMode.OPEN,  # Back to open (requires human)
        ]

        for mode in modes:
            success, _ = policy_engine.transition_mode(
                mode,
                Operator.HUMAN,  # Human to allow LOCKDOWN exit
                f"Transition to {mode.name}"
            )
            assert success is True
            assert policy_engine.get_current_mode() == mode


class TestMemoryRecallPolicy:
    """Tests for memory recall policy evaluation."""

    @pytest.mark.unit
    def test_public_memory_in_open_mode(self, policy_engine, mock_env_state):
        """Test that PUBLIC memory is accessible in OPEN mode."""
        request = PolicyRequest(
            request_type='recall',
            memory_class=MemoryClass.PUBLIC
        )
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_confidential_memory_denied_in_open(self, policy_engine, mock_env_state):
        """Test that CONFIDENTIAL memory is denied in OPEN mode."""
        request = PolicyRequest(
            request_type='recall',
            memory_class=MemoryClass.CONFIDENTIAL
        )
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_confidential_memory_allowed_in_restricted(
        self, policy_engine_restricted, mock_env_state
    ):
        """Test that CONFIDENTIAL memory is allowed in RESTRICTED mode."""
        request = PolicyRequest(
            request_type='recall',
            memory_class=MemoryClass.CONFIDENTIAL
        )
        decision = policy_engine_restricted.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_secret_memory_requires_trusted(self, policy_engine, mock_env_state):
        """Test that SECRET memory requires TRUSTED mode."""
        engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)
        request = PolicyRequest(
            request_type='recall',
            memory_class=MemoryClass.SECRET
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_top_secret_requires_airgap(self, mock_env_state):
        """Test that TOP_SECRET memory requires AIRGAP mode."""
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(
            request_type='recall',
            memory_class=MemoryClass.TOP_SECRET
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_crown_jewel_requires_coldroom(self, mock_env_state):
        """Test that CROWN_JEWEL memory requires COLDROOM mode."""
        engine = PolicyEngine(initial_mode=BoundaryMode.COLDROOM)
        request = PolicyRequest(
            request_type='recall',
            memory_class=MemoryClass.CROWN_JEWEL
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_recall_with_none_memory_class(self, policy_engine, mock_env_state):
        """Test that recall with None memory class is denied."""
        request = PolicyRequest(
            request_type='recall',
            memory_class=None
        )
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_all_memory_denied_in_lockdown(self, policy_engine_lockdown, mock_env_state):
        """Test that all memory is denied in LOCKDOWN mode."""
        for mem_class in MemoryClass:
            request = PolicyRequest(
                request_type='recall',
                memory_class=mem_class
            )
            decision = policy_engine_lockdown.evaluate_policy(request, mock_env_state)
            assert decision == PolicyDecision.DENY


class TestToolPolicy:
    """Tests for tool execution policy evaluation."""

    @pytest.mark.unit
    def test_basic_tool_allowed_in_open(self, policy_engine, mock_env_state):
        """Test that basic tools are allowed in OPEN mode."""
        request = PolicyRequest(
            request_type='tool',
            tool_name='file_read',
            requires_network=False,
            requires_filesystem=True
        )
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_network_tool_denied_in_airgap(self, mock_env_state):
        """Test that network tools are denied in AIRGAP mode."""
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(
            request_type='tool',
            tool_name='http_request',
            requires_network=True
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_usb_tool_denied_in_airgap(self, mock_env_state):
        """Test that USB tools are denied in AIRGAP mode."""
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(
            request_type='tool',
            tool_name='usb_read',
            requires_usb=True
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_filesystem_allowed_in_airgap(self, mock_env_state):
        """Test that filesystem tools are allowed in AIRGAP mode."""
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(
            request_type='tool',
            tool_name='file_write',
            requires_filesystem=True
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_all_io_denied_in_coldroom(self, mock_env_state):
        """Test that all IO is denied in COLDROOM mode."""
        engine = PolicyEngine(initial_mode=BoundaryMode.COLDROOM)

        # Network
        request = PolicyRequest(request_type='tool', requires_network=True)
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY

        # Filesystem
        request = PolicyRequest(request_type='tool', requires_filesystem=True)
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY

        # USB
        request = PolicyRequest(request_type='tool', requires_usb=True)
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY

    @pytest.mark.unit
    def test_usb_requires_ceremony_in_restricted(
        self, policy_engine_restricted, mock_env_state
    ):
        """Test that USB access requires ceremony in RESTRICTED mode."""
        request = PolicyRequest(
            request_type='tool',
            tool_name='usb_write',
            requires_usb=True
        )
        decision = policy_engine_restricted.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.REQUIRE_CEREMONY

    @pytest.mark.unit
    def test_network_tool_in_trusted_offline(self, mock_env_state):
        """Test network tool in TRUSTED mode when offline."""
        engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)
        mock_env_state.network = NetworkState.OFFLINE

        request = PolicyRequest(
            request_type='tool',
            tool_name='http_request',
            requires_network=True
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_network_tool_in_trusted_with_vpn(self, vpn_env_state):
        """Test network tool in TRUSTED mode with VPN."""
        engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)

        request = PolicyRequest(
            request_type='tool',
            tool_name='http_request',
            requires_network=True
        )
        decision = engine.evaluate_policy(request, vpn_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_network_tool_in_trusted_without_vpn(self, online_env_state):
        """Test network tool in TRUSTED mode without VPN."""
        engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)

        request = PolicyRequest(
            request_type='tool',
            tool_name='http_request',
            requires_network=True
        )
        decision = engine.evaluate_policy(request, online_env_state)
        assert decision == PolicyDecision.DENY


class TestModelPolicy:
    """Tests for external model access policy."""

    @pytest.mark.unit
    def test_model_allowed_in_open_online(self, policy_engine, online_env_state):
        """Test that external model access is allowed in OPEN mode online."""
        request = PolicyRequest(request_type='model')
        decision = policy_engine.evaluate_policy(request, online_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_model_denied_in_open_offline(self, policy_engine, mock_env_state):
        """Test that external model access is denied when offline."""
        request = PolicyRequest(request_type='model')
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_model_denied_in_airgap(self, mock_env_state):
        """Test that external models are denied in AIRGAP mode."""
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(request_type='model')
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_model_denied_in_coldroom(self, mock_env_state):
        """Test that external models are denied in COLDROOM mode."""
        engine = PolicyEngine(initial_mode=BoundaryMode.COLDROOM)
        request = PolicyRequest(request_type='model')
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY


class TestIOPolicy:
    """Tests for IO operation policy."""

    @pytest.mark.unit
    def test_filesystem_denied_in_coldroom(self, mock_env_state):
        """Test that filesystem IO is denied in COLDROOM mode."""
        engine = PolicyEngine(initial_mode=BoundaryMode.COLDROOM)
        request = PolicyRequest(
            request_type='io',
            requires_filesystem=True
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_network_denied_in_airgap(self, mock_env_state):
        """Test that network IO is denied in AIRGAP mode."""
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(
            request_type='io',
            requires_network=True
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_io_allowed_in_open(self, policy_engine, mock_env_state):
        """Test that IO is generally allowed in OPEN mode."""
        request = PolicyRequest(
            request_type='io',
            requires_network=True,
            requires_filesystem=True
        )
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW


class TestUnknownRequests:
    """Tests for unknown request types."""

    @pytest.mark.unit
    def test_unknown_request_type_denied(self, policy_engine, mock_env_state):
        """Test that unknown request types are denied (fail-closed)."""
        request = PolicyRequest(request_type='unknown')
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_invalid_request_type_denied(self, policy_engine, mock_env_state):
        """Test that invalid request types are denied."""
        request = PolicyRequest(request_type='')
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY


class TestMinimumModeForMemory:
    """Tests for get_minimum_mode_for_memory method."""

    @pytest.mark.unit
    def test_public_minimum_mode(self, policy_engine):
        """Test minimum mode for PUBLIC memory."""
        mode = policy_engine.get_minimum_mode_for_memory(MemoryClass.PUBLIC)
        assert mode == BoundaryMode.OPEN

    @pytest.mark.unit
    def test_internal_minimum_mode(self, policy_engine):
        """Test minimum mode for INTERNAL memory."""
        mode = policy_engine.get_minimum_mode_for_memory(MemoryClass.INTERNAL)
        assert mode == BoundaryMode.OPEN

    @pytest.mark.unit
    def test_confidential_minimum_mode(self, policy_engine):
        """Test minimum mode for CONFIDENTIAL memory."""
        mode = policy_engine.get_minimum_mode_for_memory(MemoryClass.CONFIDENTIAL)
        assert mode == BoundaryMode.RESTRICTED

    @pytest.mark.unit
    def test_secret_minimum_mode(self, policy_engine):
        """Test minimum mode for SECRET memory."""
        mode = policy_engine.get_minimum_mode_for_memory(MemoryClass.SECRET)
        assert mode == BoundaryMode.TRUSTED

    @pytest.mark.unit
    def test_top_secret_minimum_mode(self, policy_engine):
        """Test minimum mode for TOP_SECRET memory."""
        mode = policy_engine.get_minimum_mode_for_memory(MemoryClass.TOP_SECRET)
        assert mode == BoundaryMode.AIRGAP

    @pytest.mark.unit
    def test_crown_jewel_minimum_mode(self, policy_engine):
        """Test minimum mode for CROWN_JEWEL memory."""
        mode = policy_engine.get_minimum_mode_for_memory(MemoryClass.CROWN_JEWEL)
        assert mode == BoundaryMode.COLDROOM


class TestEnvironmentCompatibility:
    """Tests for environment compatibility checks."""

    @pytest.mark.unit
    def test_airgap_compatible_offline(self, mock_env_state):
        """Test that AIRGAP is compatible with offline environment."""
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        is_compatible, violation = engine.check_mode_environment_compatibility(
            mock_env_state
        )
        assert is_compatible is True
        assert violation is None

    @pytest.mark.unit
    def test_airgap_incompatible_online(self, online_env_state):
        """Test that AIRGAP is incompatible with online environment."""
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        is_compatible, violation = engine.check_mode_environment_compatibility(
            online_env_state
        )
        assert is_compatible is False
        assert "Network came online" in violation

    @pytest.mark.unit
    def test_open_mode_always_compatible(self, policy_engine, online_env_state):
        """Test that OPEN mode is compatible with any environment."""
        is_compatible, violation = policy_engine.check_mode_environment_compatibility(
            online_env_state
        )
        assert is_compatible is True


class TestThreadSafety:
    """Tests for thread safety of PolicyEngine."""

    @pytest.mark.unit
    def test_concurrent_policy_evaluation(self, mock_env_state):
        """Test concurrent policy evaluation."""
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
        results = []

        def evaluate():
            for _ in range(50):
                request = PolicyRequest(
                    request_type='recall',
                    memory_class=MemoryClass.PUBLIC
                )
                decision = engine.evaluate_policy(request, mock_env_state)
                results.append(decision)

        threads = [threading.Thread(target=evaluate) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should be ALLOW
        assert len(results) == 500
        assert all(d == PolicyDecision.ALLOW for d in results)

    @pytest.mark.unit
    def test_concurrent_mode_transitions(self):
        """Test concurrent mode transitions."""
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
        transition_results = []

        def transition_loop():
            for mode in [BoundaryMode.RESTRICTED, BoundaryMode.TRUSTED,
                        BoundaryMode.OPEN]:
                success, _ = engine.transition_mode(mode, Operator.HUMAN, "test")
                transition_results.append(success)

        threads = [threading.Thread(target=transition_loop) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All transitions should succeed
        assert len(transition_results) == 15
        assert all(r is True for r in transition_results)


class TestBoundaryStateToDict:
    """Tests for BoundaryState serialization."""

    @pytest.mark.unit
    def test_state_to_dict(self, policy_engine):
        """Test that state converts to dictionary correctly."""
        state = policy_engine.get_current_state()
        d = state.to_dict()

        assert d['mode'] == 'open'
        assert 'network' in d
        assert 'hardware_trust' in d
        assert 'last_transition' in d
        assert 'operator' in d
