"""
RRA-Module Boundary Integration

Provides security integration between the Risk/Reward Analysis Module and
the Boundary Daemon to prevent unauthorized decision manipulation.

RRA-Module performs risk/reward analysis for agent decision-making.
All analysis must be validated through the boundary daemon to ensure:
- Decision integrity via hash chains
- Semantic coherence of analysis
- Mode-appropriate analysis scope
- Audit trail for all decisions

SECURITY FEATURES:
- Decision hash chain verification
- Semantic coherence checking
- Mode-aware analysis scope limiting
- Risk score validation
- Audit trail with tamper detection

Attack Vectors Prevented:
- PRIVILEGE_ESCALATION: Scope limiting per mode
- SEMANTIC_DRIFT: Coherence checking
- CRYPTO_BYPASS: Hash chain and signature verification

Usage:
    from boundary import RiskGate, RewardGate, AnalysisAuditGate

    # Before performing risk analysis
    gate = RiskGate()
    if gate.can_analyze_risk(context):
        result = rra.analyze_risk(context)

    # Validate decision integrity
    audit = AnalysisAuditGate()
    is_valid = audit.verify_decision_chain(decisions)
"""

import hashlib
import json
import logging
import os
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar('T')


class OperationalMode(Enum):
    """Boundary operational modes."""
    OPEN = "open"
    RESTRICTED = "restricted"
    TRUSTED = "trusted"
    AIRGAP = "airgap"
    COLDROOM = "coldroom"
    LOCKDOWN = "lockdown"


class AnalysisScope(Enum):
    """Scope of analysis permitted per mode."""
    UNLIMITED = "unlimited"      # OPEN: No restrictions
    BROAD = "broad"              # RESTRICTED: Most contexts
    FOCUSED = "focused"          # TRUSTED: Limited context
    MINIMAL = "minimal"          # AIRGAP: Essential only
    CRITICAL = "critical"        # COLDROOM: Critical decisions only
    NONE = "none"                # LOCKDOWN: No analysis


class RiskLevel(IntEnum):
    """Risk classification levels."""
    NEGLIGIBLE = 0
    LOW = 1
    MODERATE = 2
    HIGH = 3
    CRITICAL = 4
    CATASTROPHIC = 5


@dataclass
class AnalysisDecision:
    """Result of an analysis permission check."""
    permitted: bool
    reason: str
    mode: Optional[OperationalMode] = None
    scope: AnalysisScope = AnalysisScope.NONE
    requires_ceremony: bool = False
    max_risk_level: RiskLevel = RiskLevel.NEGLIGIBLE


@dataclass
class CoherenceCheckResult:
    """Result of semantic coherence check."""
    coherent: bool
    coherence_score: float
    anomalies: List[str]
    recommendation: str


@dataclass
class DecisionIntegrityResult:
    """Result of decision integrity verification."""
    valid: bool
    errors: List[str]
    decisions_checked: int
    first_invalid_index: Optional[int] = None
    hash_chain_intact: bool = True


class BoundaryError(Exception):
    """Base exception for boundary errors."""
    pass


class DaemonUnavailableError(BoundaryError):
    """Raised when daemon is not reachable."""
    pass


class AnalysisDeniedError(BoundaryError):
    """Raised when analysis is denied."""
    pass


class IntegrityError(BoundaryError):
    """Raised when integrity check fails."""
    pass


class ScopeExceededError(BoundaryError):
    """Raised when analysis exceeds permitted scope."""
    pass


def get_socket_path() -> str:
    """Get the boundary daemon socket path."""
    paths = [
        os.environ.get('BOUNDARY_DAEMON_SOCKET'),
        '/var/run/boundary-daemon/boundary.sock',
        os.path.expanduser('~/.agent-os/api/boundary.sock'),
        './api/boundary.sock',
    ]

    for path in paths:
        if path and os.path.exists(path):
            return path

    return '/var/run/boundary-daemon/boundary.sock'


class BoundaryClient:
    """Boundary Daemon Client for RRA-Module."""

    def __init__(
        self,
        socket_path: Optional[str] = None,
        token: Optional[str] = None,
        max_retries: int = 3,
        timeout: float = 5.0,
    ):
        self.socket_path = socket_path or get_socket_path()
        self._token = token or os.environ.get('BOUNDARY_API_TOKEN')
        self.max_retries = max_retries
        self.timeout = timeout

    def _send_request(
        self,
        command: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send request with retry logic."""
        request = {'command': command, 'params': params or {}}
        if self._token:
            request['token'] = self._token

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall(json.dumps(request).encode('utf-8'))
                data = sock.recv(65536)
                sock.close()
                return json.loads(data.decode('utf-8'))
            except (ConnectionRefusedError, FileNotFoundError, socket.timeout) as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    time.sleep(0.5 * (2 ** attempt))
            finally:
                try:
                    sock.close()
                except:
                    pass

        raise DaemonUnavailableError(f"Daemon unavailable: {last_error}")

    def get_status(self) -> Dict[str, Any]:
        """Get daemon status."""
        try:
            response = self._send_request('status')
            return response.get('status', {})
        except DaemonUnavailableError:
            return {'mode': 'lockdown', 'online': False}

    def get_mode(self) -> OperationalMode:
        """Get current operational mode."""
        status = self.get_status()
        mode_str = status.get('mode', 'lockdown').lower()
        return OperationalMode(mode_str)

    def check_tool(
        self,
        tool_name: str,
        requires_network: bool = False,
        requires_filesystem: bool = False,
        context: Optional[Dict[str, Any]] = None,
    ) -> AnalysisDecision:
        """Check if tool operation is permitted."""
        params = {
            'tool_name': tool_name,
            'requires_network': requires_network,
            'requires_filesystem': requires_filesystem,
        }
        if context:
            params['context'] = context

        try:
            response = self._send_request('check_tool', params)
        except DaemonUnavailableError:
            return AnalysisDecision(
                permitted=False,
                reason="Boundary daemon unavailable - fail closed",
            )

        return AnalysisDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def classify_intent_semantics(
        self,
        text: str,
        context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Classify text for semantic analysis."""
        params = {'text': text}
        if context:
            params['context'] = context

        try:
            response = self._send_request('classify_intent_semantics', params)
        except DaemonUnavailableError:
            return {
                'threat_level': 5,
                'category': 'unknown',
                'manipulation_score': 1.0,
                'coherence_score': 0.0,
            }

        return response.get('classification', {})

    def verify_merkle_proof(
        self,
        root_hash: str,
        leaf_hash: str,
        proof_path: List[str],
        leaf_index: int,
    ) -> AnalysisDecision:
        """Verify Merkle proof for decision chain."""
        params = {
            'root_hash': root_hash,
            'leaf_hash': leaf_hash,
            'proof_path': proof_path,
            'leaf_index': leaf_index,
        }

        try:
            response = self._send_request('verify_merkle_proof', params)
        except DaemonUnavailableError:
            return AnalysisDecision(
                permitted=False,
                reason="Daemon unavailable - proof unverified",
            )

        return AnalysisDecision(
            permitted=response.get('valid', False),
            reason=response.get('reason', 'Unknown'),
        )

    def check_reflection_intensity(
        self,
        intensity_level: int,
        reflection_type: str = 'analysis',
        depth: int = 1,
    ) -> AnalysisDecision:
        """Check if analysis intensity is permitted."""
        params = {
            'intensity_level': intensity_level,
            'reflection_type': reflection_type,
            'depth': depth,
        }

        try:
            response = self._send_request('check_reflection_intensity', params)
        except DaemonUnavailableError:
            return AnalysisDecision(
                permitted=False,
                reason="Daemon unavailable - intensity check failed",
            )

        return AnalysisDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
            requires_ceremony=response.get('requires_ceremony', False),
        )


class RiskGate:
    """
    Gate for risk analysis operations.

    Controls what level of risk analysis is permitted based on
    current boundary mode.

    Usage:
        gate = RiskGate()

        # Check if analysis is permitted
        if gate.can_analyze_risk(context, risk_level=RiskLevel.HIGH):
            result = rra.analyze_risk(context)

        # Get permitted scope
        scope = gate.get_permitted_scope()
    """

    MODE_SCOPE_MAP = {
        OperationalMode.OPEN: AnalysisScope.UNLIMITED,
        OperationalMode.RESTRICTED: AnalysisScope.BROAD,
        OperationalMode.TRUSTED: AnalysisScope.FOCUSED,
        OperationalMode.AIRGAP: AnalysisScope.MINIMAL,
        OperationalMode.COLDROOM: AnalysisScope.CRITICAL,
        OperationalMode.LOCKDOWN: AnalysisScope.NONE,
    }

    MODE_MAX_RISK = {
        OperationalMode.OPEN: RiskLevel.CATASTROPHIC,
        OperationalMode.RESTRICTED: RiskLevel.CRITICAL,
        OperationalMode.TRUSTED: RiskLevel.HIGH,
        OperationalMode.AIRGAP: RiskLevel.MODERATE,
        OperationalMode.COLDROOM: RiskLevel.LOW,
        OperationalMode.LOCKDOWN: RiskLevel.NEGLIGIBLE,
    }

    def __init__(self, client: Optional[BoundaryClient] = None):
        self.client = client or BoundaryClient()
        self._last_decision: Optional[AnalysisDecision] = None

    @property
    def last_decision(self) -> Optional[AnalysisDecision]:
        """Get the last analysis decision."""
        return self._last_decision

    def get_permitted_scope(self) -> AnalysisScope:
        """Get the permitted analysis scope for current mode."""
        mode = self.client.get_mode()
        return self.MODE_SCOPE_MAP.get(mode, AnalysisScope.NONE)

    def get_max_risk_level(self) -> RiskLevel:
        """Get the maximum risk level that can be analyzed in current mode."""
        mode = self.client.get_mode()
        return self.MODE_MAX_RISK.get(mode, RiskLevel.NEGLIGIBLE)

    def can_analyze_risk(
        self,
        context: Dict[str, Any],
        risk_level: RiskLevel = RiskLevel.MODERATE,
        requires_external_data: bool = False,
    ) -> bool:
        """
        Check if risk analysis is permitted.

        Args:
            context: Analysis context
            risk_level: Level of risk being analyzed
            requires_external_data: Whether analysis needs network access

        Returns:
            True if analysis is permitted
        """
        mode = self.client.get_mode()
        scope = self.MODE_SCOPE_MAP.get(mode, AnalysisScope.NONE)
        max_risk = self.MODE_MAX_RISK.get(mode, RiskLevel.NEGLIGIBLE)

        # Check if any analysis is allowed
        if scope == AnalysisScope.NONE:
            self._last_decision = AnalysisDecision(
                permitted=False,
                reason="Analysis denied in LOCKDOWN mode",
                mode=mode,
                scope=scope,
            )
            return False

        # Check risk level limit
        if risk_level > max_risk:
            self._last_decision = AnalysisDecision(
                permitted=False,
                reason=f"Risk level {risk_level.name} exceeds maximum {max_risk.name} for mode {mode.value}",
                mode=mode,
                scope=scope,
                max_risk_level=max_risk,
            )
            return False

        # Check tool permission
        tool_decision = self.client.check_tool(
            tool_name='risk_analysis',
            requires_network=requires_external_data,
            context={'risk_level': risk_level.value, 'scope': scope.value},
        )

        if not tool_decision.permitted:
            self._last_decision = AnalysisDecision(
                permitted=False,
                reason=tool_decision.reason,
                mode=mode,
                scope=scope,
            )
            return False

        # Check intensity for deep analysis
        if risk_level >= RiskLevel.HIGH:
            intensity_decision = self.client.check_reflection_intensity(
                intensity_level=risk_level.value,
                reflection_type='risk_analysis',
                depth=2,
            )
            if not intensity_decision.permitted:
                self._last_decision = AnalysisDecision(
                    permitted=False,
                    reason=intensity_decision.reason,
                    mode=mode,
                    scope=scope,
                    requires_ceremony=intensity_decision.requires_ceremony,
                )
                return False

        self._last_decision = AnalysisDecision(
            permitted=True,
            reason="Risk analysis permitted",
            mode=mode,
            scope=scope,
            max_risk_level=max_risk,
        )

        logger.debug(f"Risk analysis permitted: mode={mode.value}, scope={scope.value}")
        return True

    def require_analysis_permission(
        self,
        context: Dict[str, Any],
        risk_level: RiskLevel = RiskLevel.MODERATE,
        requires_external_data: bool = False,
    ) -> None:
        """
        Require analysis permission, raising exception if denied.

        Raises:
            AnalysisDeniedError: If analysis is not permitted
        """
        if not self.can_analyze_risk(context, risk_level, requires_external_data):
            raise AnalysisDeniedError(
                f"Risk analysis denied: {self._last_decision.reason}"
            )


class RewardGate:
    """
    Gate for reward/benefit analysis operations.

    Controls what level of reward analysis is permitted based on
    current boundary mode.
    """

    def __init__(self, client: Optional[BoundaryClient] = None):
        self.client = client or BoundaryClient()
        self._last_decision: Optional[AnalysisDecision] = None

    @property
    def last_decision(self) -> Optional[AnalysisDecision]:
        """Get the last analysis decision."""
        return self._last_decision

    def can_analyze_reward(
        self,
        context: Dict[str, Any],
        requires_valuation: bool = False,
    ) -> bool:
        """
        Check if reward analysis is permitted.

        Args:
            context: Analysis context
            requires_valuation: Whether analysis needs value calculations

        Returns:
            True if analysis is permitted
        """
        mode = self.client.get_mode()

        if mode == OperationalMode.LOCKDOWN:
            self._last_decision = AnalysisDecision(
                permitted=False,
                reason="Analysis denied in LOCKDOWN mode",
                mode=mode,
            )
            return False

        # Check tool permission
        tool_decision = self.client.check_tool(
            tool_name='reward_analysis',
            requires_filesystem=requires_valuation,
        )

        self._last_decision = AnalysisDecision(
            permitted=tool_decision.permitted,
            reason=tool_decision.reason,
            mode=mode,
        )

        return tool_decision.permitted

    def require_analysis_permission(
        self,
        context: Dict[str, Any],
        requires_valuation: bool = False,
    ) -> None:
        """Require analysis permission."""
        if not self.can_analyze_reward(context, requires_valuation):
            raise AnalysisDeniedError(
                f"Reward analysis denied: {self._last_decision.reason}"
            )


class AnalysisAuditGate:
    """
    Gate for auditing analysis decisions.

    Validates:
    - Decision hash chain integrity
    - Semantic coherence of decision sequence
    - No unauthorized modifications

    Usage:
        audit = AnalysisAuditGate()

        # Verify decision chain
        result = audit.verify_decision_chain(decisions)
        if not result.valid:
            print(f"Integrity violation: {result.errors}")

        # Check coherence
        coherence = audit.check_semantic_coherence(decisions)
        if not coherence.coherent:
            print(f"Coherence issues: {coherence.anomalies}")
    """

    def __init__(self, client: Optional[BoundaryClient] = None):
        self.client = client or BoundaryClient()

    def _compute_decision_hash(self, decision: Dict[str, Any]) -> str:
        """Compute hash of a decision."""
        data = {k: v for k, v in decision.items() if k != 'hash'}
        canonical = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()

    def verify_decision_chain(
        self,
        decisions: List[Dict[str, Any]],
    ) -> DecisionIntegrityResult:
        """
        Verify the integrity of a decision chain.

        Args:
            decisions: List of decisions in order

        Returns:
            DecisionIntegrityResult with validation details
        """
        errors = []
        first_invalid = None
        hash_chain_intact = True

        if not decisions:
            return DecisionIntegrityResult(
                valid=True,
                errors=[],
                decisions_checked=0,
            )

        prev_hash = None

        for i, decision in enumerate(decisions):
            decision_errors = []

            # Verify hash chain
            if prev_hash is not None:
                expected_prev = decision.get('previous_hash')
                if expected_prev != prev_hash:
                    decision_errors.append(
                        f"Decision {i}: Hash chain broken"
                    )
                    hash_chain_intact = False

            # Verify decision hash
            computed_hash = self._compute_decision_hash(decision)
            stored_hash = decision.get('hash')
            if stored_hash and stored_hash != computed_hash:
                decision_errors.append(
                    f"Decision {i}: Hash mismatch - decision may have been tampered"
                )
                hash_chain_intact = False

            # Verify risk-reward ratio is valid
            risk = decision.get('risk_score', 0)
            reward = decision.get('reward_score', 0)
            if risk > 0 and reward > 0:
                ratio = reward / risk
                if ratio < 0.1:  # Minimum acceptable ratio
                    decision_errors.append(
                        f"Decision {i}: Risk/reward ratio {ratio:.2f} below minimum 0.1"
                    )

            if decision_errors:
                if first_invalid is None:
                    first_invalid = i
                errors.extend(decision_errors)

            prev_hash = decision.get('hash') or computed_hash

        return DecisionIntegrityResult(
            valid=len(errors) == 0,
            errors=errors,
            decisions_checked=len(decisions),
            first_invalid_index=first_invalid,
            hash_chain_intact=hash_chain_intact,
        )

    def check_semantic_coherence(
        self,
        decisions: List[Dict[str, Any]],
        coherence_threshold: float = 0.7,
    ) -> CoherenceCheckResult:
        """
        Check semantic coherence of decision sequence.

        Detects:
        - Sudden changes in decision rationale
        - Contradictory assessments
        - Semantic drift over time

        Args:
            decisions: List of decisions to check
            coherence_threshold: Minimum coherence score (0-1)

        Returns:
            CoherenceCheckResult with analysis
        """
        anomalies = []

        if len(decisions) < 2:
            return CoherenceCheckResult(
                coherent=True,
                coherence_score=1.0,
                anomalies=[],
                recommendation="Insufficient data for coherence analysis",
            )

        total_coherence = 0.0
        comparisons = 0

        for i in range(1, len(decisions)):
            prev = decisions[i - 1]
            curr = decisions[i]

            # Check for sudden risk assessment changes
            prev_risk = prev.get('risk_score', 0)
            curr_risk = curr.get('risk_score', 0)
            if prev_risk > 0:
                risk_change = abs(curr_risk - prev_risk) / prev_risk
                if risk_change > 0.5:  # >50% change
                    anomalies.append(
                        f"Decision {i}: Sudden risk change {risk_change*100:.0f}%"
                    )

            # Check for contradictory recommendations
            prev_action = prev.get('recommended_action', '')
            curr_action = curr.get('recommended_action', '')
            if prev_action and curr_action:
                if prev_action.lower().startswith('proceed') and curr_action.lower().startswith('abort'):
                    anomalies.append(
                        f"Decision {i}: Contradictory action (proceed -> abort)"
                    )
                elif prev_action.lower().startswith('abort') and curr_action.lower().startswith('proceed'):
                    anomalies.append(
                        f"Decision {i}: Contradictory action (abort -> proceed)"
                    )

            # Check rationale coherence using daemon
            prev_rationale = prev.get('rationale', '')
            curr_rationale = curr.get('rationale', '')
            if prev_rationale and curr_rationale:
                prev_class = self.client.classify_intent_semantics(prev_rationale)
                curr_class = self.client.classify_intent_semantics(curr_rationale)

                prev_coherence = 1.0 - prev_class.get('manipulation_score', 0)
                curr_coherence = 1.0 - curr_class.get('manipulation_score', 0)

                pair_coherence = (prev_coherence + curr_coherence) / 2
                total_coherence += pair_coherence
                comparisons += 1

                if pair_coherence < coherence_threshold:
                    anomalies.append(
                        f"Decision {i}: Low coherence score {pair_coherence:.2f}"
                    )

        avg_coherence = total_coherence / comparisons if comparisons > 0 else 1.0
        is_coherent = avg_coherence >= coherence_threshold and len(anomalies) == 0

        recommendation = ""
        if not is_coherent:
            if len(anomalies) > 3:
                recommendation = "Multiple coherence issues detected. Review decision chain for manipulation."
            elif avg_coherence < coherence_threshold:
                recommendation = "Overall coherence below threshold. Consider re-evaluation."
            else:
                recommendation = "Specific anomalies detected. Review flagged decisions."
        else:
            recommendation = "Decision chain passes coherence checks."

        return CoherenceCheckResult(
            coherent=is_coherent,
            coherence_score=avg_coherence,
            anomalies=anomalies,
            recommendation=recommendation,
        )

    def verify_decision_integrity(
        self,
        decision: Dict[str, Any],
        expected_hash: str,
    ) -> Tuple[bool, str]:
        """
        Verify a single decision's integrity.

        Args:
            decision: The decision to verify
            expected_hash: Expected hash of the decision

        Returns:
            (is_valid, message)
        """
        computed_hash = self._compute_decision_hash(decision)

        if computed_hash == expected_hash:
            return True, "Decision integrity verified"
        else:
            return False, f"Hash mismatch: expected {expected_hash[:16]}..., computed {computed_hash[:16]}..."


# Convenience functions

def check_risk_analysis_permission(
    context: Dict[str, Any],
    risk_level: RiskLevel = RiskLevel.MODERATE,
) -> Tuple[bool, str]:
    """Check risk analysis permission (convenience function)."""
    gate = RiskGate()
    permitted = gate.can_analyze_risk(context, risk_level)
    return permitted, gate.last_decision.reason if gate.last_decision else "Unknown"


def verify_decisions(decisions: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """Verify decision chain (convenience function)."""
    audit = AnalysisAuditGate()
    result = audit.verify_decision_chain(decisions)
    return result.valid, result.errors


# Decorators

def require_risk_check(
    risk_level: RiskLevel = RiskLevel.MODERATE,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator that requires risk check before analysis.

    Usage:
        @require_risk_check(risk_level=RiskLevel.HIGH)
        def analyze_high_risk_scenario(context):
            return rra.deep_analysis(context)
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args, **kwargs) -> T:
            gate = RiskGate()
            context = args[0] if args else kwargs.get('context', {})
            gate.require_analysis_permission(context, risk_level)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def scope_limited(
    max_scope: AnalysisScope = AnalysisScope.FOCUSED,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator that limits analysis scope.

    Usage:
        @scope_limited(max_scope=AnalysisScope.MINIMAL)
        def analyze_minimal_context(context):
            return rra.quick_analysis(context)
    """
    scope_order = [
        AnalysisScope.NONE,
        AnalysisScope.CRITICAL,
        AnalysisScope.MINIMAL,
        AnalysisScope.FOCUSED,
        AnalysisScope.BROAD,
        AnalysisScope.UNLIMITED,
    ]

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args, **kwargs) -> T:
            gate = RiskGate()
            current_scope = gate.get_permitted_scope()

            current_idx = scope_order.index(current_scope)
            max_idx = scope_order.index(max_scope)

            if current_idx < max_idx:
                raise ScopeExceededError(
                    f"Current scope {current_scope.value} insufficient for {max_scope.value}"
                )

            return func(*args, **kwargs)
        return wrapper
    return decorator


# RRA-Module Integration Mixin

class RRABoundaryMixin:
    """
    Mixin class for RRA-Module to add boundary integration.

    Add this to your RRA class:

        class RiskRewardAnalyzer(RRABoundaryMixin, BaseRRA):
            pass
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._boundary_client = BoundaryClient()
        self._risk_gate = RiskGate(self._boundary_client)
        self._reward_gate = RewardGate(self._boundary_client)
        self._audit_gate = AnalysisAuditGate(self._boundary_client)

    def analyze_risk(
        self,
        context: Dict[str, Any],
        risk_level: RiskLevel = RiskLevel.MODERATE,
    ) -> Any:
        """
        Analyze risk with boundary check.

        This method adds boundary enforcement to the base analysis method.
        """
        self._risk_gate.require_analysis_permission(context, risk_level)
        return super().analyze_risk(context)

    def analyze_reward(
        self,
        context: Dict[str, Any],
        requires_valuation: bool = False,
    ) -> Any:
        """
        Analyze reward with boundary check.
        """
        self._reward_gate.require_analysis_permission(context, requires_valuation)
        return super().analyze_reward(context)

    def get_permitted_scope(self) -> AnalysisScope:
        """Get currently permitted analysis scope."""
        return self._risk_gate.get_permitted_scope()

    def verify_decision_chain(
        self,
        decisions: Optional[List[Dict[str, Any]]] = None,
    ) -> DecisionIntegrityResult:
        """Verify decision chain integrity."""
        if decisions is None:
            decisions = self.get_all_decisions()  # Assumes parent has this
        return self._audit_gate.verify_decision_chain(decisions)

    def get_boundary_status(self) -> Dict[str, Any]:
        """Get current boundary daemon status."""
        return self._boundary_client.get_status()
