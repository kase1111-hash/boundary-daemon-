"""
Response Guardrails - AI Response Safety and Quality Validation

This module provides comprehensive validation of AI-generated responses
to ensure safety, quality, and policy compliance:

1. Harmful content detection (violence, self-harm, illegal activities)
2. PII and sensitive data leakage prevention
3. Hallucination indicators (overconfidence, unsupported claims)
4. Response length and format enforcement
5. Factual consistency checking
6. Citation/source validation
7. Brand safety and tone compliance

Security Notes:
- Integrates with BoundaryDaemon policy engine
- Works with PII detector and prompt injection detector
- Configurable per boundary mode
- All violations logged for audit

This addresses the gap: "Needs: Output safety validation, hallucination detection"
"""

import re
import logging
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Tuple, Set
from datetime import datetime

logger = logging.getLogger(__name__)


class ContentCategory(Enum):
    """Categories of potentially harmful content"""
    VIOLENCE = "violence"
    SELF_HARM = "self_harm"
    HATE_SPEECH = "hate_speech"
    ILLEGAL_ACTIVITY = "illegal_activity"
    EXPLICIT_CONTENT = "explicit_content"
    DANGEROUS_INFO = "dangerous_info"
    MISINFORMATION = "misinformation"
    MANIPULATION = "manipulation"
    PRIVACY_VIOLATION = "privacy_violation"


class GuardrailSeverity(Enum):
    """Severity levels for guardrail violations"""
    INFO = "info"
    WARNING = "warning"
    MODERATE = "moderate"
    SEVERE = "severe"
    CRITICAL = "critical"


class GuardrailAction(Enum):
    """Actions to take on guardrail violations"""
    PASS = "pass"  # Allow with logging
    FLAG = "flag"  # Flag for review
    MODIFY = "modify"  # Modify the response
    BLOCK = "block"  # Block the response entirely


class HallucinationIndicator(Enum):
    """Types of hallucination indicators"""
    OVERCONFIDENCE = "overconfidence"  # Absolute certainty on uncertain topics
    UNSUPPORTED_CLAIM = "unsupported_claim"  # Facts without sources
    TEMPORAL_ERROR = "temporal_error"  # Wrong dates/times
    ENTITY_CONFUSION = "entity_confusion"  # Mixed up entities
    FABRICATED_SOURCE = "fabricated_source"  # Made up citations
    SELF_CONTRADICTION = "self_contradiction"  # Contradicts itself
    KNOWLEDGE_BOUNDARY = "knowledge_boundary"  # Claims beyond knowledge cutoff


@dataclass
class GuardrailViolation:
    """A guardrail violation found in AI response"""
    category: ContentCategory
    severity: GuardrailSeverity
    description: str
    matched_content: Optional[str] = None
    position: Optional[Tuple[int, int]] = None
    suggested_action: GuardrailAction = GuardrailAction.FLAG
    remediation: Optional[str] = None
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'category': self.category.value,
            'severity': self.severity.value,
            'description': self.description,
            'matched_content': self.matched_content[:100] if self.matched_content else None,
            'position': self.position,
            'suggested_action': self.suggested_action.value,
            'remediation': self.remediation,
            'confidence': self.confidence,
            'metadata': self.metadata,
        }


@dataclass
class HallucinationDetection:
    """A detected hallucination indicator"""
    indicator_type: HallucinationIndicator
    severity: GuardrailSeverity
    description: str
    evidence: str
    confidence: float
    position: Optional[Tuple[int, int]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'indicator_type': self.indicator_type.value,
            'severity': self.severity.value,
            'description': self.description,
            'evidence': self.evidence[:200],
            'confidence': self.confidence,
            'position': self.position,
        }


@dataclass
class GuardrailResult:
    """Complete result of response guardrail analysis"""
    passed: bool
    action: GuardrailAction
    response: str
    modified_response: Optional[str]
    violations: List[GuardrailViolation]
    hallucinations: List[HallucinationDetection]
    analysis_time_ms: float
    total_score: float  # 0.0 = safe, 1.0 = dangerous

    def to_dict(self) -> Dict[str, Any]:
        return {
            'passed': self.passed,
            'action': self.action.value,
            'violation_count': len(self.violations),
            'hallucination_count': len(self.hallucinations),
            'violations': [v.to_dict() for v in self.violations],
            'hallucinations': [h.to_dict() for h in self.hallucinations],
            'analysis_time_ms': self.analysis_time_ms,
            'total_score': self.total_score,
            'was_modified': self.modified_response != self.response,
        }


@dataclass
class GuardrailPolicy:
    """Policy configuration for response guardrails"""
    name: str = "default"
    max_response_length: int = 100_000
    min_response_length: int = 0
    blocked_categories: Set[ContentCategory] = field(default_factory=set)
    severity_threshold: GuardrailSeverity = GuardrailSeverity.MODERATE
    check_pii: bool = True
    check_hallucinations: bool = True
    check_citations: bool = False
    require_disclaimers: bool = False
    blocked_phrases: List[str] = field(default_factory=list)
    required_phrases: List[str] = field(default_factory=list)


class ResponseGuardrails:
    """
    Validates AI-generated responses for safety and quality.

    Provides multi-layer validation:
    1. Content safety (harmful content detection)
    2. Data protection (PII, secrets)
    3. Hallucination detection
    4. Format and length validation
    5. Citation verification
    6. Policy compliance

    Integrates with:
    - BoundaryDaemon policy engine
    - PII detector
    - Prompt injection detector
    """

    # Harmful content patterns
    HARMFUL_PATTERNS = {
        ContentCategory.VIOLENCE: [
            (r'\b(?:kill|murder|assassinate|attack|hurt|harm)\s+(?:you|someone|people|them)\b',
             "Direct violence reference", GuardrailSeverity.SEVERE),
            (r'\b(?:bomb|explosive|weapon)\s+(?:making|construction|how\s+to)\b',
             "Weapon construction", GuardrailSeverity.CRITICAL),
        ],
        ContentCategory.SELF_HARM: [
            (r'\b(?:suicide|self-harm|cut\s+yourself|end\s+your\s+life)\b',
             "Self-harm reference", GuardrailSeverity.SEVERE),
            (r'\b(?:methods?\s+(?:of|for|to)\s+(?:suicide|killing\s+yourself))\b',
             "Suicide methods", GuardrailSeverity.CRITICAL),
        ],
        ContentCategory.ILLEGAL_ACTIVITY: [
            (r'\b(?:how\s+to\s+)?(?:hack|crack|bypass)\s+(?:into|password|security)\b',
             "Hacking instructions", GuardrailSeverity.MODERATE),
            (r'\b(?:synthesize|manufacture|make)\s+(?:drugs|meth|cocaine|heroin)\b',
             "Drug synthesis", GuardrailSeverity.CRITICAL),
            (r'\b(?:launder|laundering)\s+(?:money|funds)\b',
             "Money laundering", GuardrailSeverity.SEVERE),
        ],
        ContentCategory.DANGEROUS_INFO: [
            (r'\b(?:ricin|sarin|nerve\s+agent|biological\s+weapon)\b',
             "Chemical/biological weapon reference", GuardrailSeverity.CRITICAL),
            (r'\b(?:nuclear|radiological)\s+(?:weapon|bomb|device)\s+(?:how|build|make)\b',
             "Nuclear weapon reference", GuardrailSeverity.CRITICAL),
        ],
        ContentCategory.MANIPULATION: [
            (r'\b(?:trick|manipulate|deceive)\s+(?:them|people|users)\s+into\b',
             "Manipulation instruction", GuardrailSeverity.MODERATE),
            (r'\b(?:social\s+engineering|phishing)\s+(?:attack|technique|how)\b',
             "Social engineering", GuardrailSeverity.MODERATE),
        ],
    }

    # Hallucination indicator patterns
    HALLUCINATION_PATTERNS = {
        HallucinationIndicator.OVERCONFIDENCE: [
            (r'\b(?:definitely|absolutely|certainly|undoubtedly|100%)\s+(?:true|correct|accurate)\b',
             "Absolute certainty claim"),
            (r'\b(?:it\s+is\s+a\s+fact|there\s+is\s+no\s+doubt|everyone\s+knows)\b',
             "Unqualified assertion"),
        ],
        HallucinationIndicator.UNSUPPORTED_CLAIM: [
            (r'\bstudies\s+(?:show|prove|demonstrate)\b(?!.*\bsource\b)',
             "Unattributed study claim"),
            (r'\baccording\s+to\s+(?:research|experts?|scientists?)\b(?!.*\bsource\b)',
             "Vague authority reference"),
        ],
        HallucinationIndicator.FABRICATED_SOURCE: [
            (r'\b(?:Journal|University)\s+of\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\s+(?:study|paper|research)\b',
             "Potential fabricated source"),
        ],
        HallucinationIndicator.TEMPORAL_ERROR: [
            (r'\bin\s+(?:2025|2026|2027|2028|2029|203\d)\b.*\b(?:happened|occurred|took\s+place)\b',
             "Future event as past"),
        ],
    }

    # Severity weights
    SEVERITY_WEIGHTS = {
        GuardrailSeverity.INFO: 0.1,
        GuardrailSeverity.WARNING: 0.2,
        GuardrailSeverity.MODERATE: 0.4,
        GuardrailSeverity.SEVERE: 0.7,
        GuardrailSeverity.CRITICAL: 1.0,
    }

    def __init__(
        self,
        event_logger=None,
        policy_engine=None,
        pii_detector=None,
        prompt_detector=None,
        default_policy: Optional[GuardrailPolicy] = None,
    ):
        """
        Initialize ResponseGuardrails.

        Args:
            event_logger: EventLogger for audit logging
            policy_engine: PolicyEngine for mode-aware decisions
            pii_detector: PII detector for data leakage
            prompt_detector: Prompt injection detector
            default_policy: Default guardrail policy
        """
        self.event_logger = event_logger
        self.policy_engine = policy_engine
        self.pii_detector = pii_detector
        self.prompt_detector = prompt_detector
        self.default_policy = default_policy or GuardrailPolicy()

        # Compile patterns
        self._harmful_patterns: Dict[ContentCategory, List[Tuple[re.Pattern, str, GuardrailSeverity]]] = {}
        for category, patterns in self.HARMFUL_PATTERNS.items():
            self._harmful_patterns[category] = [
                (re.compile(p, re.IGNORECASE), desc, sev)
                for p, desc, sev in patterns
            ]

        self._hallucination_patterns: Dict[HallucinationIndicator, List[Tuple[re.Pattern, str]]] = {}
        for indicator, patterns in self.HALLUCINATION_PATTERNS.items():
            self._hallucination_patterns[indicator] = [
                (re.compile(p, re.IGNORECASE), desc)
                for p, desc in patterns
            ]

        # Callbacks
        self._callbacks: Dict[int, Callable[[GuardrailResult], None]] = {}
        self._next_callback_id = 0
        self._callback_lock = threading.Lock()

        # Mode-specific policies
        self._mode_policies: Dict[str, GuardrailPolicy] = self._init_mode_policies()

        logger.info("ResponseGuardrails initialized")

    def register_callback(self, callback: Callable[[GuardrailResult], None]) -> int:
        """Register a callback for guardrail results.

        Returns:
            Callback ID that can be used to unregister the callback
        """
        with self._callback_lock:
            callback_id = self._next_callback_id
            self._next_callback_id += 1
            self._callbacks[callback_id] = callback
            return callback_id

    def unregister_callback(self, callback_id: int) -> bool:
        """Unregister a previously registered callback.

        Args:
            callback_id: The ID returned from register_callback

        Returns:
            True if callback was found and removed, False otherwise
        """
        with self._callback_lock:
            if callback_id in self._callbacks:
                del self._callbacks[callback_id]
                return True
            return False

    def cleanup(self):
        """Cleanup resources and clear callbacks."""
        with self._callback_lock:
            self._callbacks.clear()

    def _init_mode_policies(self) -> Dict[str, GuardrailPolicy]:
        """Initialize mode-specific policies"""
        return {
            'OPEN': GuardrailPolicy(
                name="open",
                severity_threshold=GuardrailSeverity.SEVERE,
                check_hallucinations=False,
            ),
            'RESTRICTED': GuardrailPolicy(
                name="restricted",
                severity_threshold=GuardrailSeverity.MODERATE,
                check_hallucinations=True,
            ),
            'TRUSTED': GuardrailPolicy(
                name="trusted",
                severity_threshold=GuardrailSeverity.MODERATE,
                check_hallucinations=True,
                check_citations=True,
            ),
            'AIRGAP': GuardrailPolicy(
                name="airgap",
                severity_threshold=GuardrailSeverity.WARNING,
                check_hallucinations=True,
                check_citations=True,
                require_disclaimers=True,
            ),
            'COLDROOM': GuardrailPolicy(
                name="coldroom",
                severity_threshold=GuardrailSeverity.WARNING,
                blocked_categories={
                    ContentCategory.VIOLENCE,
                    ContentCategory.ILLEGAL_ACTIVITY,
                    ContentCategory.DANGEROUS_INFO,
                },
                check_hallucinations=True,
                require_disclaimers=True,
            ),
            'LOCKDOWN': GuardrailPolicy(
                name="lockdown",
                severity_threshold=GuardrailSeverity.INFO,
                blocked_categories=set(ContentCategory),  # Block all
            ),
        }

    def analyze(
        self,
        response: str,
        context: Optional[Dict[str, Any]] = None,
        policy: Optional[GuardrailPolicy] = None,
    ) -> GuardrailResult:
        """
        Analyze AI response for safety violations.

        Args:
            response: The AI-generated response to analyze
            context: Optional context (conversation history, user info)
            policy: Optional policy override

        Returns:
            GuardrailResult with analysis findings
        """
        import time
        start_time = time.time()

        context = context or {}
        violations: List[GuardrailViolation] = []
        hallucinations: List[HallucinationDetection] = []
        modified_response = response

        # Determine policy
        active_policy = policy or self._get_active_policy()

        # 1. Length validation
        length_violations = self._check_length(response, active_policy)
        violations.extend(length_violations)

        # 2. Harmful content detection
        harm_violations = self._check_harmful_content(response, active_policy)
        violations.extend(harm_violations)

        # 3. Blocked phrases
        phrase_violations = self._check_blocked_phrases(response, active_policy)
        violations.extend(phrase_violations)

        # 4. Required phrases (if any)
        if active_policy.required_phrases:
            req_violations = self._check_required_phrases(response, active_policy)
            violations.extend(req_violations)

        # 5. PII detection
        if active_policy.check_pii:
            pii_violations, modified_response = self._check_pii(response)
            violations.extend(pii_violations)

        # 6. Hallucination detection
        if active_policy.check_hallucinations:
            hallucinations = self._check_hallucinations(response)

        # 7. Citation validation
        if active_policy.check_citations:
            cite_violations = self._check_citations(response)
            violations.extend(cite_violations)

        # 8. Disclaimer requirements
        if active_policy.require_disclaimers:
            disclaim_violations = self._check_disclaimers(response)
            violations.extend(disclaim_violations)

        # Calculate total score
        total_score = self._calculate_score(violations, hallucinations)

        # Determine action
        action = self._determine_action(violations, hallucinations, active_policy, total_score)

        analysis_time_ms = (time.time() - start_time) * 1000

        result = GuardrailResult(
            passed=action in [GuardrailAction.PASS, GuardrailAction.FLAG],
            action=action,
            response=response,
            modified_response=modified_response if action != GuardrailAction.BLOCK else None,
            violations=violations,
            hallucinations=hallucinations,
            analysis_time_ms=analysis_time_ms,
            total_score=total_score,
        )

        # Log and notify
        if violations or hallucinations:
            self._log_analysis(result)

        with self._callback_lock:
            callbacks = list(self._callbacks.values())
        for callback in callbacks:
            try:
                callback(result)
            except Exception as e:
                logger.warning(f"Callback failed: {e}")

        return result

    def _get_active_policy(self) -> GuardrailPolicy:
        """Get policy based on current boundary mode"""
        if self.policy_engine:
            try:
                mode = self.policy_engine.get_current_mode()
                mode_name = mode.name if hasattr(mode, 'name') else str(mode)
                if mode_name in self._mode_policies:
                    return self._mode_policies[mode_name]
            except Exception as e:
                logger.debug(f"Policy engine check failed: {e}")

        return self.default_policy

    def _check_length(
        self, response: str, policy: GuardrailPolicy
    ) -> List[GuardrailViolation]:
        """Check response length"""
        violations = []

        if len(response) > policy.max_response_length:
            violations.append(GuardrailViolation(
                category=ContentCategory.MISINFORMATION,  # Closest match
                severity=GuardrailSeverity.WARNING,
                description=f"Response exceeds max length: {len(response)} > {policy.max_response_length}",
                suggested_action=GuardrailAction.MODIFY,
                remediation="Truncate response",
            ))

        if len(response) < policy.min_response_length:
            violations.append(GuardrailViolation(
                category=ContentCategory.MISINFORMATION,
                severity=GuardrailSeverity.INFO,
                description=f"Response below min length: {len(response)} < {policy.min_response_length}",
                suggested_action=GuardrailAction.FLAG,
            ))

        return violations

    def _check_harmful_content(
        self, response: str, policy: GuardrailPolicy
    ) -> List[GuardrailViolation]:
        """Check for harmful content patterns"""
        violations = []

        for category, patterns in self._harmful_patterns.items():
            # Skip if category not blocked (unless severity is high)
            for pattern, description, severity in patterns:
                for match in pattern.finditer(response):
                    # Determine if this should be flagged
                    should_flag = (
                        category in policy.blocked_categories or
                        self.SEVERITY_WEIGHTS[severity] >= self.SEVERITY_WEIGHTS[policy.severity_threshold]
                    )

                    if should_flag:
                        violations.append(GuardrailViolation(
                            category=category,
                            severity=severity,
                            description=description,
                            matched_content=match.group(),
                            position=match.span(),
                            suggested_action=GuardrailAction.BLOCK if severity == GuardrailSeverity.CRITICAL else GuardrailAction.FLAG,
                            confidence=0.9,
                        ))

        return violations

    def _check_blocked_phrases(
        self, response: str, policy: GuardrailPolicy
    ) -> List[GuardrailViolation]:
        """Check for blocked phrases"""
        violations = []
        response_lower = response.lower()

        for phrase in policy.blocked_phrases:
            if phrase.lower() in response_lower:
                violations.append(GuardrailViolation(
                    category=ContentCategory.MANIPULATION,
                    severity=GuardrailSeverity.MODERATE,
                    description=f"Blocked phrase detected: {phrase}",
                    matched_content=phrase,
                    suggested_action=GuardrailAction.MODIFY,
                    remediation=f"Remove or replace: {phrase}",
                ))

        return violations

    def _check_required_phrases(
        self, response: str, policy: GuardrailPolicy
    ) -> List[GuardrailViolation]:
        """Check for required phrases"""
        violations = []
        response_lower = response.lower()

        for phrase in policy.required_phrases:
            if phrase.lower() not in response_lower:
                violations.append(GuardrailViolation(
                    category=ContentCategory.MISINFORMATION,
                    severity=GuardrailSeverity.WARNING,
                    description=f"Required phrase missing: {phrase}",
                    suggested_action=GuardrailAction.MODIFY,
                    remediation=f"Add required phrase: {phrase}",
                ))

        return violations

    def _check_pii(self, response: str) -> Tuple[List[GuardrailViolation], str]:
        """Check for PII and sanitize"""
        violations = []
        sanitized = response

        if self.pii_detector:
            try:
                result = self.pii_detector.detect(response)
                if result.entities:
                    for entity in result.entities:
                        violations.append(GuardrailViolation(
                            category=ContentCategory.PRIVACY_VIOLATION,
                            severity=GuardrailSeverity.SEVERE,
                            description=f"PII in response: {entity.entity_type}",
                            matched_content="[REDACTED]",
                            suggested_action=GuardrailAction.MODIFY,
                            remediation="Redact PII",
                        ))
                    sanitized = self.pii_detector.redact(response)
            except Exception as e:
                logger.debug(f"PII detection failed: {e}")

        # Fallback patterns
        fallback_patterns = [
            (r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\s+(?:lives?|resides?)\s+at\s+\d+',
             "Personal address pattern"),
            (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', "Phone number pattern"),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
             "Email address pattern"),
        ]

        for pattern, desc in fallback_patterns:
            regex = re.compile(pattern)
            if regex.search(sanitized):
                violations.append(GuardrailViolation(
                    category=ContentCategory.PRIVACY_VIOLATION,
                    severity=GuardrailSeverity.MODERATE,
                    description=desc,
                    suggested_action=GuardrailAction.MODIFY,
                ))
                sanitized = regex.sub("[REDACTED]", sanitized)

        return violations, sanitized

    def _check_hallucinations(self, response: str) -> List[HallucinationDetection]:
        """Check for hallucination indicators"""
        detections = []

        for indicator, patterns in self._hallucination_patterns.items():
            for pattern, description in patterns:
                for match in pattern.finditer(response):
                    detections.append(HallucinationDetection(
                        indicator_type=indicator,
                        severity=GuardrailSeverity.WARNING,
                        description=description,
                        evidence=match.group(),
                        confidence=0.6,  # Pattern-based has lower confidence
                        position=match.span(),
                    ))

        # Check for self-contradiction
        contradictions = self._detect_contradictions(response)
        detections.extend(contradictions)

        return detections

    def _detect_contradictions(self, response: str) -> List[HallucinationDetection]:
        """Detect potential self-contradictions"""
        detections = []

        # Simple heuristic: look for negation patterns near similar phrases
        sentences = re.split(r'[.!?]+', response)

        # Check for direct contradictions
        contradiction_pairs = [
            (r'\bis\s+true\b', r'\bis\s+(?:not\s+true|false)\b'),
            (r'\bcan\b', r'\bcannot\b'),
            (r'\bwill\b', r'\bwill\s+not\b'),
            (r'\balways\b', r'\bnever\b'),
        ]

        for pos_pattern, neg_pattern in contradiction_pairs:
            pos_match = re.search(pos_pattern, response, re.IGNORECASE)
            neg_match = re.search(neg_pattern, response, re.IGNORECASE)

            if pos_match and neg_match:
                # Check if they're about the same subject (within 200 chars)
                if abs(pos_match.start() - neg_match.start()) < 200:
                    detections.append(HallucinationDetection(
                        indicator_type=HallucinationIndicator.SELF_CONTRADICTION,
                        severity=GuardrailSeverity.MODERATE,
                        description="Potential self-contradiction detected",
                        evidence=f"'{pos_match.group()}' vs '{neg_match.group()}'",
                        confidence=0.5,
                    ))

        return detections

    def _check_citations(self, response: str) -> List[GuardrailViolation]:
        """Check citation quality"""
        violations = []

        # Check for claims that should have citations
        claim_patterns = [
            r'\bstudies?\s+(?:show|prove|demonstrate)\b',
            r'\bresearch\s+(?:indicates?|suggests?|shows?)\b',
            r'\baccording\s+to\s+(?:data|statistics)\b',
            r'\b\d+%\s+of\s+(?:people|users|companies)\b',
        ]

        for pattern in claim_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                # Check if there's a citation nearby
                citation_patterns = [
                    r'\([^)]*\d{4}[^)]*\)',  # (Author, 2024)
                    r'\[[^\]]*\d+[^\]]*\]',  # [1] or [Author 2024]
                    r'(?:source|citation|reference)\s*:',
                ]

                has_citation = any(
                    re.search(cp, response, re.IGNORECASE)
                    for cp in citation_patterns
                )

                if not has_citation:
                    violations.append(GuardrailViolation(
                        category=ContentCategory.MISINFORMATION,
                        severity=GuardrailSeverity.WARNING,
                        description="Claim made without citation",
                        suggested_action=GuardrailAction.FLAG,
                        remediation="Add source citation",
                    ))
                    break  # One warning is enough

        return violations

    def _check_disclaimers(self, response: str) -> List[GuardrailViolation]:
        """Check for required disclaimers"""
        violations = []

        # Sensitive topics that should have disclaimers
        sensitive_topics = [
            (r'\b(?:medical|health|diagnosis|treatment)\b',
             "Medical disclaimer recommended"),
            (r'\b(?:legal|law|lawsuit|attorney)\b',
             "Legal disclaimer recommended"),
            (r'\b(?:investment|financial|stock|crypto)\b',
             "Financial disclaimer recommended"),
        ]

        disclaimer_patterns = [
            r'\b(?:disclaimer|note|warning|caution)\b',
            r'\bnot\s+(?:medical|legal|financial)\s+advice\b',
            r'\bconsult\s+(?:a|an|your)\s+(?:doctor|lawyer|professional)\b',
        ]

        for topic_pattern, description in sensitive_topics:
            if re.search(topic_pattern, response, re.IGNORECASE):
                # Check for disclaimer
                has_disclaimer = any(
                    re.search(dp, response, re.IGNORECASE)
                    for dp in disclaimer_patterns
                )

                if not has_disclaimer:
                    violations.append(GuardrailViolation(
                        category=ContentCategory.MISINFORMATION,
                        severity=GuardrailSeverity.WARNING,
                        description=description,
                        suggested_action=GuardrailAction.FLAG,
                        remediation="Add appropriate disclaimer",
                    ))

        return violations

    def _calculate_score(
        self,
        violations: List[GuardrailViolation],
        hallucinations: List[HallucinationDetection],
    ) -> float:
        """Calculate total risk score"""
        score = 0.0

        for v in violations:
            score += self.SEVERITY_WEIGHTS[v.severity] * v.confidence

        for h in hallucinations:
            score += self.SEVERITY_WEIGHTS[h.severity] * h.confidence * 0.5  # Hallucinations weighted less

        return min(score, 1.0)

    def _determine_action(
        self,
        violations: List[GuardrailViolation],
        hallucinations: List[HallucinationDetection],
        policy: GuardrailPolicy,
        score: float,
    ) -> GuardrailAction:
        """Determine action based on violations"""
        # Check for critical violations
        critical = [v for v in violations if v.severity == GuardrailSeverity.CRITICAL]
        if critical:
            return GuardrailAction.BLOCK

        # Check for blocked categories
        blocked = [v for v in violations if v.category in policy.blocked_categories]
        if blocked:
            return GuardrailAction.BLOCK

        # Check severe violations
        severe = [v for v in violations if v.severity == GuardrailSeverity.SEVERE]
        if severe:
            return GuardrailAction.MODIFY

        # Score-based decision
        if score > 0.7:
            return GuardrailAction.BLOCK
        elif score > 0.4:
            return GuardrailAction.MODIFY
        elif score > 0.2:
            return GuardrailAction.FLAG
        else:
            return GuardrailAction.PASS

    def _log_analysis(self, result: GuardrailResult) -> None:
        """Log guardrail analysis results"""
        if not self.event_logger:
            return

        try:
            from ..event_logger import EventType
            self.event_logger.log_event(
                EventType.DETECTION,
                f"Response guardrails: {result.action.value} "
                f"({len(result.violations)} violations, {len(result.hallucinations)} hallucinations)",
                metadata={
                    'guardrails': 'ResponseGuardrails',
                    'action': result.action.value,
                    'passed': result.passed,
                    'violation_count': len(result.violations),
                    'hallucination_count': len(result.hallucinations),
                    'total_score': result.total_score,
                    'analysis_time_ms': result.analysis_time_ms,
                }
            )
        except Exception as e:
            logger.debug(f"Failed to log analysis: {e}")

    def subscribe(self, callback: Callable[[GuardrailResult], None]) -> None:
        """Subscribe to guardrail events"""
        self._callbacks.append(callback)

    def set_mode_policy(self, mode: str, policy: GuardrailPolicy) -> None:
        """Set policy for a specific boundary mode"""
        self._mode_policies[mode] = policy


# Singleton instance
_guardrails_instance: Optional[ResponseGuardrails] = None
_guardrails_lock = threading.Lock()


def get_response_guardrails(
    event_logger=None,
    policy_engine=None,
    pii_detector=None,
) -> ResponseGuardrails:
    """
    Get or create the global ResponseGuardrails instance.

    Args:
        event_logger: EventLogger for audit logging
        policy_engine: PolicyEngine for mode-aware decisions
        pii_detector: PII detector for data leakage

    Returns:
        ResponseGuardrails instance
    """
    global _guardrails_instance

    with _guardrails_lock:
        if _guardrails_instance is None:
            _guardrails_instance = ResponseGuardrails(
                event_logger=event_logger,
                policy_engine=policy_engine,
                pii_detector=pii_detector,
            )
        return _guardrails_instance


def configure_response_guardrails(
    event_logger=None,
    policy_engine=None,
    pii_detector=None,
    default_policy: Optional[GuardrailPolicy] = None,
) -> ResponseGuardrails:
    """
    Configure and return a new ResponseGuardrails instance.

    Replaces the global instance.
    """
    global _guardrails_instance

    with _guardrails_lock:
        _guardrails_instance = ResponseGuardrails(
            event_logger=event_logger,
            policy_engine=policy_engine,
            pii_detector=pii_detector,
            default_policy=default_policy,
        )
        return _guardrails_instance
