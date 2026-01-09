"""
Predictive Boundary Mode Advisor - Context-aware mode recommendations.

Phase 3 Cutting-Edge Innovation: Suggests optimal boundary mode based on
current context using deterministic, explainable rules.

Key Design Principles:
- Deterministic rules (not ML black box)
- Explainable recommendations with specific rule citations
- Human always approves via ceremony
- Conservative by default (recommends stricter modes)

Context Factors:
- Time of day / day of week
- Active users and their roles
- Network location and trust level
- Recent alert patterns
- Sandbox activity
- External threat intelligence

Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │                    MODE ADVISOR ENGINE                          │
    ├─────────────────────────────────────────────────────────────────┤
    │  Context Collectors                                             │
    │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐  │
    │  │  Time   │ │ Network │ │ Alerts  │ │ Sandbox │ │ Threat  │  │
    │  │ Context │ │ Context │ │ Context │ │ Context │ │  Intel  │  │
    │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘  │
    │       │           │           │           │           │        │
    │       ▼           ▼           ▼           ▼           ▼        │
    │  ┌─────────────────────────────────────────────────────────┐   │
    │  │                    RULE ENGINE                          │   │
    │  │  • Evaluate all rules against current context           │   │
    │  │  • Calculate weighted recommendation                    │   │
    │  │  • Generate human-readable explanation                  │   │
    │  └─────────────────────────────────────────────────────────┘   │
    │                              │                                  │
    │                              ▼                                  │
    │  ┌─────────────────────────────────────────────────────────┐   │
    │  │              RECOMMENDATION OUTPUT                       │   │
    │  │  Mode: TRUSTED → RESTRICTED                             │   │
    │  │  Confidence: HIGH (87%)                                 │   │
    │  │  Reason: Rules #12, #47, #51 triggered                  │   │
    │  │  Action: Ceremony required to apply                     │   │
    │  └─────────────────────────────────────────────────────────┘   │
    └─────────────────────────────────────────────────────────────────┘
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any, Callable

logger = logging.getLogger(__name__)


class RecommendationConfidence(Enum):
    """Confidence levels for recommendations."""
    LOW = "low"         # 0-40%: Weak signal, informational only
    MEDIUM = "medium"   # 40-70%: Moderate signal, consider action
    HIGH = "high"       # 70-90%: Strong signal, action recommended
    CRITICAL = "critical"  # 90-100%: Urgent, immediate action needed


class ContextFactor(Enum):
    """Types of context factors."""
    TIME = "time"
    NETWORK = "network"
    ALERTS = "alerts"
    SANDBOX = "sandbox"
    THREAT_INTEL = "threat_intel"
    USER_ACTIVITY = "user_activity"
    RESOURCE_USAGE = "resource_usage"
    POLICY = "policy"


@dataclass
class ThreatIndicator:
    """An indicator of potential threat."""
    indicator_id: str
    factor: ContextFactor
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    detected_at: datetime
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if the indicator has expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at


@dataclass
class ModeRecommendation:
    """A recommendation to change boundary mode."""
    recommendation_id: str
    current_mode: str
    recommended_mode: str
    confidence: RecommendationConfidence
    confidence_score: float  # 0.0 - 1.0
    reasons: List[str]
    triggered_rules: List[str]
    indicators: List[ThreatIndicator]
    created_at: datetime
    expires_at: datetime
    auto_escalate: bool = False  # If True, automatically initiate ceremony

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'recommendation_id': self.recommendation_id,
            'current_mode': self.current_mode,
            'recommended_mode': self.recommended_mode,
            'confidence': self.confidence.value,
            'confidence_score': self.confidence_score,
            'reasons': self.reasons,
            'triggered_rules': self.triggered_rules,
            'indicators': [
                {
                    'id': ind.indicator_id,
                    'factor': ind.factor.value,
                    'severity': ind.severity,
                    'description': ind.description,
                }
                for ind in self.indicators
            ],
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'auto_escalate': self.auto_escalate,
        }


@dataclass
class AdvisorRule:
    """A rule in the advisory engine."""
    rule_id: str
    name: str
    description: str
    factor: ContextFactor
    condition: Callable[[Dict[str, Any]], bool]
    weight: float  # 0.0 - 1.0, contribution to confidence
    recommended_mode: str
    severity: str = "MEDIUM"
    enabled: bool = True


class ModeAdvisor:
    """
    Predictive Mode Advisor - recommends optimal boundary mode.

    Uses deterministic rules to analyze context and recommend mode changes.
    All recommendations require human approval via ceremony.
    """

    # Mode hierarchy (lower index = more restrictive)
    MODE_HIERARCHY = [
        'lockdown',
        'coldroom',
        'airgap',
        'restricted',
        'trusted',
        'open',
    ]

    def __init__(
        self,
        current_mode_provider: Callable[[], str],
        alert_provider: Optional[Callable[[], List[Dict]]] = None,
        sandbox_provider: Optional[Callable[[], Dict]] = None,
        network_provider: Optional[Callable[[], Dict]] = None,
        auto_escalate_threshold: float = 0.9,
        evaluation_interval: float = 60.0,
    ):
        """
        Initialize the Mode Advisor.

        Args:
            current_mode_provider: Callable that returns current mode
            alert_provider: Callable that returns recent alerts
            sandbox_provider: Callable that returns sandbox status
            network_provider: Callable that returns network status
            auto_escalate_threshold: Confidence threshold for auto-escalation
            evaluation_interval: Seconds between evaluations
        """
        self.current_mode_provider = current_mode_provider
        self.alert_provider = alert_provider
        self.sandbox_provider = sandbox_provider
        self.network_provider = network_provider
        self.auto_escalate_threshold = auto_escalate_threshold
        self.evaluation_interval = evaluation_interval

        # Rules engine
        self._rules: Dict[str, AdvisorRule] = {}
        self._load_default_rules()

        # Active indicators
        self._indicators: Dict[str, ThreatIndicator] = {}
        self._indicator_lock = threading.RLock()

        # Recommendation history
        self._recommendations: List[ModeRecommendation] = []
        self._recommendation_lock = threading.RLock()

        # Event handlers - use dict for O(1) unregister to prevent memory leaks
        self._on_recommendation: Dict[int, Callable[[ModeRecommendation], None]] = {}
        self._on_auto_escalate: Dict[int, Callable[[ModeRecommendation], None]] = {}
        self._next_handler_id = 0
        self._handler_lock = threading.RLock()

        # Background evaluation
        self._eval_thread: Optional[threading.Thread] = None
        self._running = False

        logger.info("ModeAdvisor initialized")

    def _load_default_rules(self) -> None:
        """Load the default advisory rules."""

        # Time-based rules
        self._rules['TIME_001'] = AdvisorRule(
            rule_id='TIME_001',
            name='Off-hours operation',
            description='Operating outside normal business hours (9PM-6AM)',
            factor=ContextFactor.TIME,
            condition=lambda ctx: self._is_off_hours(ctx.get('time', {})),
            weight=0.2,
            recommended_mode='restricted',
            severity='LOW',
        )

        self._rules['TIME_002'] = AdvisorRule(
            rule_id='TIME_002',
            name='Weekend operation',
            description='Operating on weekend',
            factor=ContextFactor.TIME,
            condition=lambda ctx: self._is_weekend(ctx.get('time', {})),
            weight=0.15,
            recommended_mode='restricted',
            severity='LOW',
        )

        # Alert-based rules
        self._rules['ALERT_001'] = AdvisorRule(
            rule_id='ALERT_001',
            name='High alert volume',
            description='More than 5 alerts in the last hour',
            factor=ContextFactor.ALERTS,
            condition=lambda ctx: ctx.get('alerts', {}).get('last_hour_count', 0) > 5,
            weight=0.4,
            recommended_mode='restricted',
            severity='MEDIUM',
        )

        self._rules['ALERT_002'] = AdvisorRule(
            rule_id='ALERT_002',
            name='Critical alerts unacknowledged',
            description='Unacknowledged CRITICAL severity alerts',
            factor=ContextFactor.ALERTS,
            condition=lambda ctx: ctx.get('alerts', {}).get('unacked_critical', 0) > 0,
            weight=0.7,
            recommended_mode='airgap',
            severity='HIGH',
        )

        self._rules['ALERT_003'] = AdvisorRule(
            rule_id='ALERT_003',
            name='Prompt injection detected',
            description='Prompt injection attempts in last hour',
            factor=ContextFactor.ALERTS,
            condition=lambda ctx: ctx.get('alerts', {}).get('prompt_injections', 0) > 0,
            weight=0.5,
            recommended_mode='restricted',
            severity='HIGH',
        )

        self._rules['ALERT_004'] = AdvisorRule(
            rule_id='ALERT_004',
            name='Multiple prompt injections',
            description='3+ prompt injection attempts in last hour',
            factor=ContextFactor.ALERTS,
            condition=lambda ctx: ctx.get('alerts', {}).get('prompt_injections', 0) >= 3,
            weight=0.8,
            recommended_mode='airgap',
            severity='CRITICAL',
        )

        # Sandbox rules
        self._rules['SANDBOX_001'] = AdvisorRule(
            rule_id='SANDBOX_001',
            name='High sandbox resource usage',
            description='Sandbox memory or CPU above 80%',
            factor=ContextFactor.SANDBOX,
            condition=lambda ctx: (
                ctx.get('sandbox', {}).get('memory_percent', 0) > 80 or
                ctx.get('sandbox', {}).get('cpu_percent', 0) > 80
            ),
            weight=0.3,
            recommended_mode='restricted',
            severity='MEDIUM',
        )

        self._rules['SANDBOX_002'] = AdvisorRule(
            rule_id='SANDBOX_002',
            name='Sandbox escape attempt',
            description='Detected sandbox escape attempt',
            factor=ContextFactor.SANDBOX,
            condition=lambda ctx: ctx.get('sandbox', {}).get('escape_attempts', 0) > 0,
            weight=0.9,
            recommended_mode='lockdown',
            severity='CRITICAL',
        )

        self._rules['SANDBOX_003'] = AdvisorRule(
            rule_id='SANDBOX_003',
            name='Unusual tool call pattern',
            description='Tool call frequency 3x above baseline',
            factor=ContextFactor.SANDBOX,
            condition=lambda ctx: ctx.get('sandbox', {}).get('tool_call_ratio', 1.0) > 3.0,
            weight=0.4,
            recommended_mode='restricted',
            severity='MEDIUM',
        )

        # Network rules
        self._rules['NETWORK_001'] = AdvisorRule(
            rule_id='NETWORK_001',
            name='Untrusted network',
            description='Connected to untrusted network',
            factor=ContextFactor.NETWORK,
            condition=lambda ctx: ctx.get('network', {}).get('trust_level', 'trusted') == 'untrusted',
            weight=0.5,
            recommended_mode='restricted',
            severity='MEDIUM',
        )

        self._rules['NETWORK_002'] = AdvisorRule(
            rule_id='NETWORK_002',
            name='VPN disconnected',
            description='VPN connection lost while in TRUSTED mode',
            factor=ContextFactor.NETWORK,
            condition=lambda ctx: (
                ctx.get('network', {}).get('vpn_connected', True) is False and
                ctx.get('current_mode', '') == 'trusted'
            ),
            weight=0.6,
            recommended_mode='restricted',
            severity='HIGH',
        )

        self._rules['NETWORK_003'] = AdvisorRule(
            rule_id='NETWORK_003',
            name='Network anomaly',
            description='Unusual network traffic patterns detected',
            factor=ContextFactor.NETWORK,
            condition=lambda ctx: ctx.get('network', {}).get('anomaly_detected', False),
            weight=0.5,
            recommended_mode='restricted',
            severity='MEDIUM',
        )

        # Threat intelligence rules
        self._rules['THREAT_001'] = AdvisorRule(
            rule_id='THREAT_001',
            name='Active threat campaign',
            description='Active threat campaign targeting similar systems',
            factor=ContextFactor.THREAT_INTEL,
            condition=lambda ctx: ctx.get('threat_intel', {}).get('active_campaigns', 0) > 0,
            weight=0.5,
            recommended_mode='restricted',
            severity='HIGH',
        )

        self._rules['THREAT_002'] = AdvisorRule(
            rule_id='THREAT_002',
            name='Zero-day vulnerability',
            description='Unpatched zero-day affecting dependencies',
            factor=ContextFactor.THREAT_INTEL,
            condition=lambda ctx: ctx.get('threat_intel', {}).get('zero_days', 0) > 0,
            weight=0.7,
            recommended_mode='airgap',
            severity='CRITICAL',
        )

        # Policy rules
        self._rules['POLICY_001'] = AdvisorRule(
            rule_id='POLICY_001',
            name='Compliance window',
            description='Within compliance audit window',
            factor=ContextFactor.POLICY,
            condition=lambda ctx: ctx.get('policy', {}).get('in_audit_window', False),
            weight=0.3,
            recommended_mode='restricted',
            severity='LOW',
        )

        self._rules['POLICY_002'] = AdvisorRule(
            rule_id='POLICY_002',
            name='Data handling mode required',
            description='Sensitive data handling in progress',
            factor=ContextFactor.POLICY,
            condition=lambda ctx: ctx.get('policy', {}).get('sensitive_data_active', False),
            weight=0.4,
            recommended_mode='coldroom',
            severity='MEDIUM',
        )

        logger.info(f"Loaded {len(self._rules)} advisory rules")

    def _is_off_hours(self, time_ctx: Dict) -> bool:
        """Check if current time is off-hours."""
        hour = time_ctx.get('hour', datetime.now().hour)
        return hour < 6 or hour >= 21

    def _is_weekend(self, time_ctx: Dict) -> bool:
        """Check if current day is weekend."""
        weekday = time_ctx.get('weekday', datetime.now().weekday())
        return weekday >= 5  # Saturday = 5, Sunday = 6

    def start(self) -> None:
        """Start the advisor background evaluation."""
        self._running = True
        self._eval_thread = threading.Thread(target=self._evaluation_loop, daemon=True)
        self._eval_thread.start()
        logger.info("ModeAdvisor started")

    def stop(self) -> None:
        """Stop the advisor."""
        self._running = False
        if self._eval_thread:
            self._eval_thread.join(timeout=5.0)
        logger.info("ModeAdvisor stopped")

    def _evaluation_loop(self) -> None:
        """Background evaluation loop."""
        while self._running:
            try:
                self._cleanup_expired_indicators()
                recommendation = self.evaluate()
                if recommendation:
                    self._handle_recommendation(recommendation)
            except Exception as e:
                logger.error(f"Evaluation error: {e}")
            time.sleep(self.evaluation_interval)

    def _cleanup_expired_indicators(self) -> None:
        """Remove expired threat indicators."""
        with self._indicator_lock:
            expired = [
                ind_id for ind_id, ind in self._indicators.items()
                if ind.is_expired()
            ]
            for ind_id in expired:
                del self._indicators[ind_id]

    def add_indicator(self, indicator: ThreatIndicator) -> None:
        """
        Add a threat indicator.

        Args:
            indicator: The threat indicator to add
        """
        with self._indicator_lock:
            self._indicators[indicator.indicator_id] = indicator
        logger.info(f"Added threat indicator: {indicator.indicator_id}")

    def remove_indicator(self, indicator_id: str) -> bool:
        """
        Remove a threat indicator.

        Args:
            indicator_id: ID of indicator to remove

        Returns:
            True if removed, False if not found
        """
        with self._indicator_lock:
            if indicator_id in self._indicators:
                del self._indicators[indicator_id]
                return True
            return False

    def _gather_context(self) -> Dict[str, Any]:
        """Gather all context for evaluation."""
        context = {
            'current_mode': self.current_mode_provider(),
            'time': {
                'hour': datetime.now().hour,
                'weekday': datetime.now().weekday(),
                'timestamp': datetime.now().isoformat(),
            },
        }

        # Gather alerts context
        if self.alert_provider:
            try:
                alerts = self.alert_provider()
                context['alerts'] = self._analyze_alerts(alerts)
            except Exception as e:
                logger.warning(f"Failed to gather alert context: {e}")
                context['alerts'] = {}

        # Gather sandbox context
        if self.sandbox_provider:
            try:
                context['sandbox'] = self.sandbox_provider()
            except Exception as e:
                logger.warning(f"Failed to gather sandbox context: {e}")
                context['sandbox'] = {}

        # Gather network context
        if self.network_provider:
            try:
                context['network'] = self.network_provider()
            except Exception as e:
                logger.warning(f"Failed to gather network context: {e}")
                context['network'] = {}

        # Add indicators
        with self._indicator_lock:
            context['indicators'] = list(self._indicators.values())

        return context

    def _analyze_alerts(self, alerts: List[Dict]) -> Dict[str, Any]:
        """Analyze alerts to extract context."""
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)

        recent_alerts = [
            a for a in alerts
            if datetime.fromisoformat(a.get('timestamp', now.isoformat())) > hour_ago
        ]

        return {
            'last_hour_count': len(recent_alerts),
            'unacked_critical': len([
                a for a in recent_alerts
                if a.get('severity') == 'CRITICAL' and not a.get('acknowledged', False)
            ]),
            'prompt_injections': len([
                a for a in recent_alerts
                if 'prompt_injection' in a.get('type', '').lower()
            ]),
        }

    def evaluate(self) -> Optional[ModeRecommendation]:
        """
        Evaluate current context and generate recommendation.

        Returns:
            ModeRecommendation if mode change is recommended, None otherwise
        """
        context = self._gather_context()
        current_mode = context['current_mode']

        triggered_rules: List[AdvisorRule] = []
        mode_scores: Dict[str, float] = {}

        # Evaluate each rule
        for rule in self._rules.values():
            if not rule.enabled:
                continue

            try:
                if rule.condition(context):
                    triggered_rules.append(rule)
                    mode = rule.recommended_mode
                    mode_scores[mode] = mode_scores.get(mode, 0) + rule.weight
            except Exception as e:
                logger.warning(f"Rule {rule.rule_id} evaluation failed: {e}")

        if not triggered_rules:
            return None

        # Find the most restrictive recommended mode
        recommended_mode = None
        highest_score = 0

        for mode, score in mode_scores.items():
            if score > highest_score:
                # Only recommend if more restrictive than current
                if self._is_more_restrictive(mode, current_mode):
                    recommended_mode = mode
                    highest_score = score

        if not recommended_mode:
            return None

        # Calculate confidence
        max_possible_score = sum(r.weight for r in self._rules.values() if r.enabled)
        confidence_score = min(1.0, highest_score / max(max_possible_score * 0.5, 0.1))

        # Determine confidence level
        if confidence_score >= 0.9:
            confidence = RecommendationConfidence.CRITICAL
        elif confidence_score >= 0.7:
            confidence = RecommendationConfidence.HIGH
        elif confidence_score >= 0.4:
            confidence = RecommendationConfidence.MEDIUM
        else:
            confidence = RecommendationConfidence.LOW

        # Generate recommendation
        recommendation_id = f"rec_{int(time.time() * 1000)}"

        # Build reasons
        reasons = []
        for rule in triggered_rules:
            if rule.recommended_mode == recommended_mode:
                reasons.append(rule.description)

        # Get relevant indicators
        relevant_indicators = [
            ind for ind in context.get('indicators', [])
            if not ind.is_expired()
        ]

        recommendation = ModeRecommendation(
            recommendation_id=recommendation_id,
            current_mode=current_mode,
            recommended_mode=recommended_mode,
            confidence=confidence,
            confidence_score=confidence_score,
            reasons=reasons,
            triggered_rules=[r.rule_id for r in triggered_rules],
            indicators=relevant_indicators,
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(minutes=30),
            auto_escalate=confidence_score >= self.auto_escalate_threshold,
        )

        with self._recommendation_lock:
            self._recommendations.append(recommendation)
            # Keep only last 100 recommendations
            if len(self._recommendations) > 100:
                self._recommendations = self._recommendations[-100:]

        return recommendation

    def _is_more_restrictive(self, mode: str, than_mode: str) -> bool:
        """Check if a mode is more restrictive than another."""
        try:
            mode_idx = self.MODE_HIERARCHY.index(mode.lower())
            than_idx = self.MODE_HIERARCHY.index(than_mode.lower())
            return mode_idx < than_idx
        except ValueError:
            return False

    def _handle_recommendation(self, recommendation: ModeRecommendation) -> None:
        """Handle a new recommendation."""
        logger.info(
            f"Mode recommendation: {recommendation.current_mode} → "
            f"{recommendation.recommended_mode} "
            f"(confidence: {recommendation.confidence.value}, "
            f"score: {recommendation.confidence_score:.2f})"
        )

        # Notify handlers - copy values to avoid modification during iteration
        with self._handler_lock:
            handlers = list(self._on_recommendation.values())
        for handler in handlers:
            try:
                handler(recommendation)
            except Exception as e:
                logger.error(f"Recommendation handler error: {e}")

        # Auto-escalate if threshold met
        if recommendation.auto_escalate:
            logger.warning(
                f"Auto-escalation triggered for recommendation {recommendation.recommendation_id}"
            )
            with self._handler_lock:
                escalate_handlers = list(self._on_auto_escalate.values())
            for handler in escalate_handlers:
                try:
                    handler(recommendation)
                except Exception as e:
                    logger.error(f"Auto-escalate handler error: {e}")

    def on_recommendation(self, handler: Callable[[ModeRecommendation], None]) -> int:
        """Register a handler for new recommendations.

        Returns:
            Handler ID that can be used to unregister the handler
        """
        with self._handler_lock:
            handler_id = self._next_handler_id
            self._next_handler_id += 1
            self._on_recommendation[handler_id] = handler
            return handler_id

    def unregister_recommendation_handler(self, handler_id: int) -> bool:
        """Unregister a recommendation handler.

        Args:
            handler_id: The ID returned from on_recommendation

        Returns:
            True if handler was found and removed, False otherwise
        """
        with self._handler_lock:
            if handler_id in self._on_recommendation:
                del self._on_recommendation[handler_id]
                return True
            return False

    def on_auto_escalate(self, handler: Callable[[ModeRecommendation], None]) -> int:
        """Register a handler for auto-escalation events.

        Returns:
            Handler ID that can be used to unregister the handler
        """
        with self._handler_lock:
            handler_id = self._next_handler_id
            self._next_handler_id += 1
            self._on_auto_escalate[handler_id] = handler
            return handler_id

    def unregister_auto_escalate_handler(self, handler_id: int) -> bool:
        """Unregister an auto-escalate handler.

        Args:
            handler_id: The ID returned from on_auto_escalate

        Returns:
            True if handler was found and removed, False otherwise
        """
        with self._handler_lock:
            if handler_id in self._on_auto_escalate:
                del self._on_auto_escalate[handler_id]
                return True
            return False

    def add_rule(self, rule: AdvisorRule) -> None:
        """Add a custom advisory rule."""
        self._rules[rule.rule_id] = rule
        logger.info(f"Added advisory rule: {rule.rule_id}")

    def remove_rule(self, rule_id: str) -> bool:
        """Remove an advisory rule."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False

    def enable_rule(self, rule_id: str) -> bool:
        """Enable an advisory rule."""
        if rule_id in self._rules:
            self._rules[rule_id].enabled = True
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable an advisory rule."""
        if rule_id in self._rules:
            self._rules[rule_id].enabled = False
            return True
        return False

    def get_rules(self) -> List[Dict[str, Any]]:
        """Get all rules and their status."""
        return [
            {
                'rule_id': rule.rule_id,
                'name': rule.name,
                'description': rule.description,
                'factor': rule.factor.value,
                'weight': rule.weight,
                'recommended_mode': rule.recommended_mode,
                'severity': rule.severity,
                'enabled': rule.enabled,
            }
            for rule in self._rules.values()
        ]

    def get_recent_recommendations(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent recommendations."""
        with self._recommendation_lock:
            return [
                r.to_dict()
                for r in self._recommendations[-limit:]
            ]

    def get_current_threat_level(self) -> Tuple[str, float, List[str]]:
        """
        Calculate current overall threat level.

        Returns:
            Tuple of (level_name, score, active_factors)
        """
        with self._indicator_lock:
            active_indicators = [
                ind for ind in self._indicators.values()
                if not ind.is_expired()
            ]

        if not active_indicators:
            return ('LOW', 0.0, [])

        # Calculate threat score
        severity_weights = {
            'LOW': 0.1,
            'MEDIUM': 0.3,
            'HIGH': 0.6,
            'CRITICAL': 1.0,
        }

        total_weight = sum(
            severity_weights.get(ind.severity, 0.1)
            for ind in active_indicators
        )

        # Normalize to 0-1
        score = min(1.0, total_weight / 3.0)

        # Determine level
        if score >= 0.8:
            level = 'CRITICAL'
        elif score >= 0.5:
            level = 'HIGH'
        elif score >= 0.2:
            level = 'MEDIUM'
        else:
            level = 'LOW'

        # Get active factors
        factors = list(set(ind.factor.value for ind in active_indicators))

        return (level, score, factors)

    def force_evaluate(self) -> Optional[ModeRecommendation]:
        """Force an immediate evaluation."""
        return self.evaluate()

    def explain_recommendation(self, recommendation: ModeRecommendation) -> str:
        """
        Generate a human-readable explanation of a recommendation.

        Args:
            recommendation: The recommendation to explain

        Returns:
            Formatted explanation string
        """
        lines = [
            "MODE RECOMMENDATION",
            "=" * 50,
            "",
            f"Current Mode:     {recommendation.current_mode.upper()}",
            f"Recommended Mode: {recommendation.recommended_mode.upper()}",
            "",
            f"Confidence: {recommendation.confidence.value.upper()} "
            f"({recommendation.confidence_score * 100:.1f}%)",
            "",
            "TRIGGERED RULES:",
        ]

        for rule_id in recommendation.triggered_rules:
            rule = self._rules.get(rule_id)
            if rule:
                lines.append(f"  [{rule_id}] {rule.name}")
                lines.append(f"           {rule.description}")

        lines.extend([
            "",
            "REASONS:",
        ])
        for reason in recommendation.reasons:
            lines.append(f"  • {reason}")

        if recommendation.indicators:
            lines.extend([
                "",
                "ACTIVE THREAT INDICATORS:",
            ])
            for ind in recommendation.indicators:
                lines.append(
                    f"  [{ind.severity}] {ind.description} "
                    f"({ind.factor.value})"
                )

        lines.extend([
            "",
            "ACTION REQUIRED:",
        ])
        if recommendation.auto_escalate:
            lines.append(
                "  Ceremony will be automatically initiated due to "
                "HIGH confidence."
            )
        else:
            lines.append(
                f"  Run 'boundaryctl mode {recommendation.recommended_mode} --ceremony' "
                f"to apply."
            )

        lines.extend([
            "",
            f"Generated: {recommendation.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Expires:   {recommendation.expires_at.strftime('%Y-%m-%d %H:%M:%S')}",
        ])

        return '\n'.join(lines)
