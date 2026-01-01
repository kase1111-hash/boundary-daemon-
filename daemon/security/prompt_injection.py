"""
Prompt Injection Detector - Advanced Jailbreak and Injection Defense

This module provides comprehensive prompt injection detection for AI/Agent
systems, specifically designed for NatLangChain and Agent-OS integration.

Detection Categories:
1. Jailbreak Attempts: DAN, roleplay bypasses, "ignore instructions"
2. Instruction Injection: Embedded instructions in user content
3. Context Manipulation: Attempts to redefine system context
4. System Prompt Extraction: Attempts to reveal system prompts
5. Delimiter Injection: Breaking out of delimited sections
6. Encoding Bypasses: Base64, Unicode, homograph attacks

Security Notes:
- All detections are logged to the event logger
- Integrates with BoundaryDaemon policy engine
- Works with MessageChecker for NatLangChain validation
- Supports configurable sensitivity levels
- Pattern library is extensible

This addresses the gap: "Needs: Semantic analysis, jailbreak pattern library"
"""

import re
import hashlib
import logging
import unicodedata
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple, Callable
from datetime import datetime

logger = logging.getLogger(__name__)


class InjectionType(Enum):
    """Types of prompt injection attacks"""
    JAILBREAK = "jailbreak"
    INSTRUCTION_INJECTION = "instruction_injection"
    CONTEXT_MANIPULATION = "context_manipulation"
    PROMPT_EXTRACTION = "prompt_extraction"
    DELIMITER_INJECTION = "delimiter_injection"
    ENCODING_BYPASS = "encoding_bypass"
    ROLEPLAY_BYPASS = "roleplay_bypass"
    AUTHORITY_ESCALATION = "authority_escalation"
    TOOL_ABUSE = "tool_abuse"
    MEMORY_POISONING = "memory_poisoning"


class DetectionSeverity(Enum):
    """Severity levels for detections"""
    INFO = "info"           # Suspicious but likely benign
    LOW = "low"             # Minor concern
    MEDIUM = "medium"       # Should be reviewed
    HIGH = "high"           # Likely attack
    CRITICAL = "critical"   # Definite attack, block immediately


class DetectionAction(Enum):
    """Actions to take on detection"""
    ALLOW = "allow"         # Allow with logging
    WARN = "warn"           # Allow with prominent warning
    REDACT = "redact"       # Remove/modify the injection
    BLOCK = "block"         # Block the message entirely
    ESCALATE = "escalate"   # Require ceremony/approval


@dataclass
class InjectionPattern:
    """A pattern for detecting prompt injection"""
    name: str
    pattern: str  # Regex pattern
    injection_type: InjectionType
    severity: DetectionSeverity
    description: str
    case_sensitive: bool = False
    require_word_boundary: bool = True
    compiled: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        flags = 0 if self.case_sensitive else re.IGNORECASE
        if self.require_word_boundary:
            self.compiled = re.compile(rf'\b{self.pattern}\b', flags)
        else:
            self.compiled = re.compile(self.pattern, flags)


@dataclass
class InjectionDetection:
    """Result of an injection detection"""
    injection_type: InjectionType
    severity: DetectionSeverity
    pattern_name: str
    matched_text: str
    position: Tuple[int, int]  # Start and end position
    context: str  # Surrounding text
    description: str
    confidence: float  # 0.0 to 1.0
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'injection_type': self.injection_type.value,
            'severity': self.severity.value,
            'pattern_name': self.pattern_name,
            'matched_text': self.matched_text[:100],  # Truncate for safety
            'position': self.position,
            'context': self.context[:200],  # Truncate
            'description': self.description,
            'confidence': self.confidence,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata,
        }


@dataclass
class DetectionResult:
    """Complete result of prompt injection analysis"""
    is_safe: bool
    action: DetectionAction
    detections: List[InjectionDetection]
    total_score: float  # Aggregate risk score
    highest_severity: Optional[DetectionSeverity]
    analysis_time_ms: float
    input_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'is_safe': self.is_safe,
            'action': self.action.value,
            'detection_count': len(self.detections),
            'detections': [d.to_dict() for d in self.detections],
            'total_score': self.total_score,
            'highest_severity': self.highest_severity.value if self.highest_severity else None,
            'analysis_time_ms': self.analysis_time_ms,
            'input_hash': self.input_hash,
        }


class PromptInjectionDetector:
    """
    Advanced prompt injection detection for AI/Agent systems.

    Provides multi-layer detection:
    1. Pattern-based detection (regex patterns)
    2. Structural analysis (delimiter injection, formatting)
    3. Semantic indicators (instruction-like language)
    4. Encoding detection (base64, unicode tricks)
    5. Context analysis (authority claims, role confusion)

    Integrates with:
    - BoundaryDaemon policy engine
    - MessageChecker for NatLangChain
    - Event Publisher for detection alerts
    """

    # Severity weights for scoring
    SEVERITY_WEIGHTS = {
        DetectionSeverity.INFO: 0.1,
        DetectionSeverity.LOW: 0.3,
        DetectionSeverity.MEDIUM: 0.5,
        DetectionSeverity.HIGH: 0.8,
        DetectionSeverity.CRITICAL: 1.0,
    }

    # Threshold for action decisions
    THRESHOLDS = {
        'allow': 0.0,
        'warn': 0.3,
        'redact': 0.5,
        'block': 0.7,
        'escalate': 0.9,
    }

    def __init__(
        self,
        event_logger=None,
        policy_engine=None,
        sensitivity: str = "medium",
        custom_patterns: Optional[List[InjectionPattern]] = None,
    ):
        """
        Initialize the PromptInjectionDetector.

        Args:
            event_logger: EventLogger for audit logging
            policy_engine: PolicyEngine for mode-aware decisions
            sensitivity: Detection sensitivity (low, medium, high, paranoid)
            custom_patterns: Additional patterns to include
        """
        self.event_logger = event_logger
        self.policy_engine = policy_engine
        self.sensitivity = sensitivity
        self._patterns: List[InjectionPattern] = []
        self._callbacks: List[Callable[[DetectionResult], None]] = []

        # Load default patterns
        self._load_default_patterns()

        # Add custom patterns
        if custom_patterns:
            self._patterns.extend(custom_patterns)

        # Adjust thresholds based on sensitivity
        self._adjust_sensitivity()

        logger.info(
            f"PromptInjectionDetector initialized with {len(self._patterns)} patterns, "
            f"sensitivity={sensitivity}"
        )

    def _adjust_sensitivity(self) -> None:
        """Adjust thresholds based on sensitivity level"""
        if self.sensitivity == "low":
            self.THRESHOLDS = {
                'allow': 0.0, 'warn': 0.5, 'redact': 0.7, 'block': 0.85, 'escalate': 0.95
            }
        elif self.sensitivity == "high":
            self.THRESHOLDS = {
                'allow': 0.0, 'warn': 0.2, 'redact': 0.4, 'block': 0.6, 'escalate': 0.8
            }
        elif self.sensitivity == "paranoid":
            self.THRESHOLDS = {
                'allow': 0.0, 'warn': 0.1, 'redact': 0.25, 'block': 0.4, 'escalate': 0.6
            }

    def _load_default_patterns(self) -> None:
        """Load the default pattern library"""

        # ============================================================
        # JAILBREAK PATTERNS
        # ============================================================

        # DAN (Do Anything Now) patterns
        self._patterns.extend([
            InjectionPattern(
                name="dan_jailbreak",
                pattern=r"(?:DAN|do\s+anything\s+now)",
                injection_type=InjectionType.JAILBREAK,
                severity=DetectionSeverity.CRITICAL,
                description="DAN jailbreak attempt detected",
            ),
            InjectionPattern(
                name="dan_mode",
                pattern=r"(?:enable|activate|switch\s+to)\s+(?:DAN|jailbreak|unrestricted)\s*mode",
                injection_type=InjectionType.JAILBREAK,
                severity=DetectionSeverity.CRITICAL,
                description="DAN mode activation attempt",
            ),
            InjectionPattern(
                name="dan_personality",
                pattern=r"you\s+are\s+(?:now\s+)?DAN",
                injection_type=InjectionType.JAILBREAK,
                severity=DetectionSeverity.CRITICAL,
                description="DAN personality injection",
            ),
        ])

        # Ignore instructions patterns
        self._patterns.extend([
            InjectionPattern(
                name="ignore_previous",
                pattern=r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|guidelines?|prompts?)",
                injection_type=InjectionType.JAILBREAK,
                severity=DetectionSeverity.CRITICAL,
                description="Attempt to ignore previous instructions",
            ),
            InjectionPattern(
                name="disregard_instructions",
                pattern=r"(?:disregard|forget|override|bypass)\s+(?:all\s+)?(?:instructions?|rules?|guidelines?|restrictions?)",
                injection_type=InjectionType.JAILBREAK,
                severity=DetectionSeverity.CRITICAL,
                description="Attempt to disregard instructions",
            ),
            InjectionPattern(
                name="new_instructions",
                pattern=r"(?:your\s+)?new\s+instructions?\s+(?:are|is|:)",
                injection_type=InjectionType.JAILBREAK,
                severity=DetectionSeverity.HIGH,
                description="Attempt to inject new instructions",
            ),
        ])

        # Roleplay bypass patterns
        self._patterns.extend([
            InjectionPattern(
                name="pretend_no_restrictions",
                pattern=r"pretend\s+(?:you\s+)?(?:have\s+)?no\s+(?:restrictions?|limits?|rules?|guidelines?)",
                injection_type=InjectionType.ROLEPLAY_BYPASS,
                severity=DetectionSeverity.HIGH,
                description="Roleplay without restrictions attempt",
            ),
            InjectionPattern(
                name="act_as_unrestricted",
                pattern=r"(?:act|behave|respond)\s+(?:as\s+if|like)\s+(?:you\s+)?(?:have\s+)?no\s+(?:restrictions?|filters?)",
                injection_type=InjectionType.ROLEPLAY_BYPASS,
                severity=DetectionSeverity.HIGH,
                description="Act as unrestricted AI attempt",
            ),
            InjectionPattern(
                name="hypothetical_bypass",
                pattern=r"(?:hypothetically|theoretically|in\s+theory)\s+(?:if\s+)?you\s+(?:could|were\s+able\s+to)\s+(?:ignore|bypass)",
                injection_type=InjectionType.ROLEPLAY_BYPASS,
                severity=DetectionSeverity.MEDIUM,
                description="Hypothetical restriction bypass",
            ),
            InjectionPattern(
                name="character_play",
                pattern=r"(?:roleplay|pretend|act)\s+as\s+(?:an?\s+)?(?:evil|malicious|unrestricted|unfiltered)\s+(?:AI|assistant|version)",
                injection_type=InjectionType.ROLEPLAY_BYPASS,
                severity=DetectionSeverity.HIGH,
                description="Malicious character roleplay attempt",
            ),
        ])

        # ============================================================
        # INSTRUCTION INJECTION PATTERNS
        # ============================================================

        self._patterns.extend([
            InjectionPattern(
                name="system_instruction",
                pattern=r"(?:system\s*:?\s*|<\s*system\s*>)",
                injection_type=InjectionType.INSTRUCTION_INJECTION,
                severity=DetectionSeverity.HIGH,
                description="System instruction injection attempt",
            ),
            InjectionPattern(
                name="assistant_override",
                pattern=r"(?:assistant\s*:?\s*|<\s*assistant\s*>)\s*(?:I\s+will|I\s+must|I\s+should)",
                injection_type=InjectionType.INSTRUCTION_INJECTION,
                severity=DetectionSeverity.HIGH,
                description="Assistant response injection",
            ),
            InjectionPattern(
                name="developer_mode",
                pattern=r"(?:developer|debug|admin|root)\s+mode\s+(?:enabled|activated|on)",
                injection_type=InjectionType.INSTRUCTION_INJECTION,
                severity=DetectionSeverity.HIGH,
                description="Developer mode injection attempt",
            ),
            InjectionPattern(
                name="sudo_instruction",
                pattern=r"(?:sudo|admin|superuser)\s+(?:mode|command|instruction)\s*:",
                injection_type=InjectionType.INSTRUCTION_INJECTION,
                severity=DetectionSeverity.HIGH,
                description="Privileged instruction injection",
            ),
        ])

        # ============================================================
        # PROMPT EXTRACTION PATTERNS
        # ============================================================

        self._patterns.extend([
            InjectionPattern(
                name="reveal_prompt",
                pattern=r"(?:reveal|show|display|print|output|tell\s+me)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)",
                injection_type=InjectionType.PROMPT_EXTRACTION,
                severity=DetectionSeverity.HIGH,
                description="System prompt extraction attempt",
            ),
            InjectionPattern(
                name="repeat_instructions",
                pattern=r"(?:repeat|recite|echo)\s+(?:your\s+)?(?:original\s+)?(?:instructions?|prompt|guidelines?)",
                injection_type=InjectionType.PROMPT_EXTRACTION,
                severity=DetectionSeverity.HIGH,
                description="Instruction repetition attempt",
            ),
            InjectionPattern(
                name="what_were_you_told",
                pattern=r"what\s+(?:were\s+you|have\s+you\s+been)\s+(?:told|instructed|programmed|trained)\s+to",
                injection_type=InjectionType.PROMPT_EXTRACTION,
                severity=DetectionSeverity.MEDIUM,
                description="Prompt probing attempt",
            ),
            InjectionPattern(
                name="initial_prompt",
                pattern=r"(?:initial|original|first|starting)\s+(?:system\s+)?prompt",
                injection_type=InjectionType.PROMPT_EXTRACTION,
                severity=DetectionSeverity.MEDIUM,
                description="Initial prompt query",
            ),
        ])

        # ============================================================
        # CONTEXT MANIPULATION PATTERNS
        # ============================================================

        self._patterns.extend([
            InjectionPattern(
                name="end_context",
                pattern=r"(?:end\s+of\s+(?:context|conversation|session)|---+\s*END\s*---+)",
                injection_type=InjectionType.CONTEXT_MANIPULATION,
                severity=DetectionSeverity.HIGH,
                description="Context termination attempt",
            ),
            InjectionPattern(
                name="new_conversation",
                pattern=r"(?:start\s+)?new\s+conversation\s*(?::|begins?|starts?)",
                injection_type=InjectionType.CONTEXT_MANIPULATION,
                severity=DetectionSeverity.MEDIUM,
                description="Conversation reset attempt",
            ),
            InjectionPattern(
                name="context_switch",
                pattern=r"(?:from\s+now\s+on|starting\s+now|henceforth)\s+(?:you\s+)?(?:are|will\s+be|must)",
                injection_type=InjectionType.CONTEXT_MANIPULATION,
                severity=DetectionSeverity.HIGH,
                description="Context switching attempt",
            ),
        ])

        # ============================================================
        # DELIMITER INJECTION PATTERNS
        # ============================================================

        self._patterns.extend([
            InjectionPattern(
                name="xml_injection",
                pattern=r"</?(?:system|user|assistant|human|ai|bot|instruction)>",
                injection_type=InjectionType.DELIMITER_INJECTION,
                severity=DetectionSeverity.HIGH,
                description="XML tag injection",
                require_word_boundary=False,
            ),
            InjectionPattern(
                name="markdown_injection",
                pattern=r"```(?:system|instruction|prompt)",
                injection_type=InjectionType.DELIMITER_INJECTION,
                severity=DetectionSeverity.MEDIUM,
                description="Markdown code block injection",
                require_word_boundary=False,
            ),
            InjectionPattern(
                name="bracket_injection",
                pattern=r"\[\[(?:SYSTEM|INSTRUCTION|ADMIN|DEVELOPER)\]\]",
                injection_type=InjectionType.DELIMITER_INJECTION,
                severity=DetectionSeverity.HIGH,
                description="Bracket delimiter injection",
                require_word_boundary=False,
            ),
            InjectionPattern(
                name="separator_injection",
                pattern=r"(?:={5,}|#{5,}|-{5,})\s*(?:END|STOP|IGNORE)",
                injection_type=InjectionType.DELIMITER_INJECTION,
                severity=DetectionSeverity.MEDIUM,
                description="Separator injection",
                require_word_boundary=False,
            ),
        ])

        # ============================================================
        # AUTHORITY ESCALATION PATTERNS
        # ============================================================

        self._patterns.extend([
            InjectionPattern(
                name="claim_authority",
                pattern=r"(?:I\s+am|this\s+is)\s+(?:the\s+)?(?:admin|administrator|developer|owner|creator|operator)",
                injection_type=InjectionType.AUTHORITY_ESCALATION,
                severity=DetectionSeverity.HIGH,
                description="Authority claim attempt",
            ),
            InjectionPattern(
                name="special_permissions",
                pattern=r"(?:I\s+have|grant\s+me)\s+(?:special|elevated|admin|root)\s+(?:permissions?|access|privileges?)",
                injection_type=InjectionType.AUTHORITY_ESCALATION,
                severity=DetectionSeverity.HIGH,
                description="Permission escalation attempt",
            ),
            InjectionPattern(
                name="authorized_override",
                pattern=r"(?:I\s+am\s+)?authorized\s+to\s+(?:override|bypass|disable)\s+(?:restrictions?|safety|filters?)",
                injection_type=InjectionType.AUTHORITY_ESCALATION,
                severity=DetectionSeverity.HIGH,
                description="Authorization claim for override",
            ),
        ])

        # ============================================================
        # TOOL ABUSE PATTERNS
        # ============================================================

        self._patterns.extend([
            InjectionPattern(
                name="recursive_tool",
                pattern=r"(?:call|invoke|execute)\s+(?:yourself|this\s+tool|the\s+same\s+function)\s+(?:again|repeatedly|infinitely)",
                injection_type=InjectionType.TOOL_ABUSE,
                severity=DetectionSeverity.HIGH,
                description="Recursive tool invocation attempt",
            ),
            InjectionPattern(
                name="tool_chain_injection",
                pattern=r"(?:first|then|next|after\s+that)\s+(?:use|call|invoke)\s+(?:the\s+)?(?:bash|execute|shell|system)\s+tool",
                injection_type=InjectionType.TOOL_ABUSE,
                severity=DetectionSeverity.MEDIUM,
                description="Tool chain injection attempt",
            ),
            InjectionPattern(
                name="hidden_tool_call",
                pattern=r"(?:secretly|silently|without\s+telling|don't\s+mention)\s+(?:use|call|execute)",
                injection_type=InjectionType.TOOL_ABUSE,
                severity=DetectionSeverity.HIGH,
                description="Hidden tool call attempt",
            ),
        ])

        # ============================================================
        # MEMORY POISONING PATTERNS
        # ============================================================

        self._patterns.extend([
            InjectionPattern(
                name="remember_instruction",
                pattern=r"(?:remember|memorize|store)\s+(?:this|that|the\s+following)\s*:\s*(?:you\s+must|always|never)",
                injection_type=InjectionType.MEMORY_POISONING,
                severity=DetectionSeverity.HIGH,
                description="Memory poisoning attempt",
            ),
            InjectionPattern(
                name="update_knowledge",
                pattern=r"(?:update|modify|change)\s+your\s+(?:knowledge|memory|understanding)\s*:",
                injection_type=InjectionType.MEMORY_POISONING,
                severity=DetectionSeverity.HIGH,
                description="Knowledge base poisoning attempt",
            ),
            InjectionPattern(
                name="fact_injection",
                pattern=r"(?:fact|truth|reality)\s*:\s*(?:you\s+(?:are|must|should|can)|the\s+system)",
                injection_type=InjectionType.MEMORY_POISONING,
                severity=DetectionSeverity.MEDIUM,
                description="Fact injection attempt",
            ),
        ])

    def analyze(self, text: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        """
        Analyze text for prompt injection attacks.

        Args:
            text: The text to analyze
            context: Optional context (user_id, message_type, etc.)

        Returns:
            DetectionResult with findings
        """
        import time
        start_time = time.time()

        context = context or {}
        detections: List[InjectionDetection] = []

        # Compute input hash for tracking
        input_hash = hashlib.sha256(text.encode()).hexdigest()[:16]

        # 1. Pattern-based detection
        detections.extend(self._pattern_scan(text))

        # 2. Encoding bypass detection
        detections.extend(self._encoding_scan(text))

        # 3. Structural analysis
        detections.extend(self._structural_scan(text))

        # 4. Semantic indicators
        detections.extend(self._semantic_scan(text))

        # Calculate total score
        total_score = sum(
            self.SEVERITY_WEIGHTS[d.severity] * d.confidence
            for d in detections
        )

        # Normalize score (cap at 1.0)
        total_score = min(total_score, 1.0)

        # Determine highest severity
        highest_severity = None
        if detections:
            severity_order = [
                DetectionSeverity.INFO,
                DetectionSeverity.LOW,
                DetectionSeverity.MEDIUM,
                DetectionSeverity.HIGH,
                DetectionSeverity.CRITICAL,
            ]
            highest_severity = max(
                (d.severity for d in detections),
                key=lambda s: severity_order.index(s)
            )

        # Determine action
        action = self._determine_action(total_score, highest_severity, context)

        # Calculate analysis time
        analysis_time_ms = (time.time() - start_time) * 1000

        result = DetectionResult(
            is_safe=action in [DetectionAction.ALLOW, DetectionAction.WARN],
            action=action,
            detections=detections,
            total_score=total_score,
            highest_severity=highest_severity,
            analysis_time_ms=analysis_time_ms,
            input_hash=input_hash,
        )

        # Log detections
        if detections:
            self._log_detections(result, context)

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(result)
            except Exception as e:
                logger.warning(f"Callback failed: {e}")

        return result

    def _pattern_scan(self, text: str) -> List[InjectionDetection]:
        """Scan text against all patterns"""
        detections = []

        for pattern in self._patterns:
            if pattern.compiled:
                for match in pattern.compiled.finditer(text):
                    start, end = match.span()

                    # Get context (50 chars before and after)
                    context_start = max(0, start - 50)
                    context_end = min(len(text), end + 50)
                    context = text[context_start:context_end]

                    detection = InjectionDetection(
                        injection_type=pattern.injection_type,
                        severity=pattern.severity,
                        pattern_name=pattern.name,
                        matched_text=match.group(),
                        position=(start, end),
                        context=context,
                        description=pattern.description,
                        confidence=0.9,  # High confidence for pattern matches
                    )
                    detections.append(detection)

        return detections

    def _encoding_scan(self, text: str) -> List[InjectionDetection]:
        """Detect encoding-based bypass attempts"""
        detections = []

        # Check for base64 encoded content
        base64_pattern = re.compile(
            r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
        )
        for match in base64_pattern.finditer(text):
            if len(match.group()) > 20:  # Suspicious length
                try:
                    import base64
                    decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
                    # Check if decoded content looks like injection
                    if self._looks_like_injection(decoded):
                        detections.append(InjectionDetection(
                            injection_type=InjectionType.ENCODING_BYPASS,
                            severity=DetectionSeverity.HIGH,
                            pattern_name="base64_encoded_injection",
                            matched_text=match.group()[:50],
                            position=match.span(),
                            context=f"Decoded: {decoded[:100]}",
                            description="Base64 encoded injection attempt",
                            confidence=0.85,
                        ))
                except Exception:
                    pass

        # Check for Unicode homographs
        homograph_chars = self._detect_homographs(text)
        if homograph_chars:
            detections.append(InjectionDetection(
                injection_type=InjectionType.ENCODING_BYPASS,
                severity=DetectionSeverity.MEDIUM,
                pattern_name="unicode_homograph",
                matched_text=str(homograph_chars),
                position=(0, len(text)),
                context=f"Found {len(homograph_chars)} suspicious Unicode characters",
                description="Unicode homograph attack attempt",
                confidence=0.7,
            ))

        # Check for zero-width characters
        zero_width_pattern = re.compile(r'[\u200b\u200c\u200d\ufeff]')
        zero_width_matches = list(zero_width_pattern.finditer(text))
        if len(zero_width_matches) > 2:
            detections.append(InjectionDetection(
                injection_type=InjectionType.ENCODING_BYPASS,
                severity=DetectionSeverity.MEDIUM,
                pattern_name="zero_width_chars",
                matched_text=f"{len(zero_width_matches)} zero-width chars",
                position=(0, len(text)),
                context="Multiple zero-width characters detected",
                description="Zero-width character injection attempt",
                confidence=0.6,
            ))

        return detections

    def _detect_homographs(self, text: str) -> List[str]:
        """Detect Unicode homograph characters"""
        suspicious = []

        # Characters that look like ASCII but aren't
        homograph_ranges = [
            (0x0400, 0x04FF),  # Cyrillic
            (0x0370, 0x03FF),  # Greek
            (0xFF00, 0xFFEF),  # Fullwidth forms
        ]

        for char in text:
            code = ord(char)
            for start, end in homograph_ranges:
                if start <= code <= end:
                    # Check if it has an ASCII lookalike
                    normalized = unicodedata.normalize('NFKD', char)
                    if normalized != char and normalized.isascii():
                        suspicious.append(char)
                        break

        return suspicious

    def _looks_like_injection(self, text: str) -> bool:
        """Quick check if text contains injection-like content"""
        injection_indicators = [
            r'ignore\s+instructions',
            r'system\s*:',
            r'you\s+are\s+now',
            r'DAN',
            r'jailbreak',
        ]

        text_lower = text.lower()
        return any(re.search(p, text_lower) for p in injection_indicators)

    def _structural_scan(self, text: str) -> List[InjectionDetection]:
        """Analyze structural patterns that may indicate injection"""
        detections = []

        # Check for excessive role markers
        role_markers = len(re.findall(
            r'(?:user|assistant|system|human|ai)\s*:', text, re.IGNORECASE
        ))
        if role_markers > 3:
            detections.append(InjectionDetection(
                injection_type=InjectionType.DELIMITER_INJECTION,
                severity=DetectionSeverity.MEDIUM,
                pattern_name="excessive_role_markers",
                matched_text=f"{role_markers} role markers",
                position=(0, len(text)),
                context="Multiple role transition markers detected",
                description="Excessive role markers may indicate prompt manipulation",
                confidence=0.6,
            ))

        # Check for instruction-like formatting
        instruction_patterns = [
            (r'^\s*\d+\.\s+(?:you\s+must|always|never)\b', "Numbered instructions"),
            (r'^\s*[-*]\s+(?:do\s+not|always|must)\b', "Bulleted instructions"),
            (r'IMPORTANT:\s*(?:ignore|disregard|override)', "Important directive"),
        ]

        for pattern, desc in instruction_patterns:
            if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                detections.append(InjectionDetection(
                    injection_type=InjectionType.INSTRUCTION_INJECTION,
                    severity=DetectionSeverity.MEDIUM,
                    pattern_name="instruction_formatting",
                    matched_text=desc,
                    position=(0, len(text)),
                    context="Text contains instruction-like formatting",
                    description=f"{desc} detected in user input",
                    confidence=0.5,
                ))

        return detections

    def _semantic_scan(self, text: str) -> List[InjectionDetection]:
        """Analyze semantic indicators of injection"""
        detections = []

        # High concentration of imperative verbs directed at "you"
        imperative_to_you = len(re.findall(
            r'\byou\s+(?:must|should|will|shall|need\s+to|have\s+to)\b',
            text, re.IGNORECASE
        ))

        if imperative_to_you > 3:
            detections.append(InjectionDetection(
                injection_type=InjectionType.INSTRUCTION_INJECTION,
                severity=DetectionSeverity.LOW,
                pattern_name="imperative_concentration",
                matched_text=f"{imperative_to_you} imperative phrases",
                position=(0, len(text)),
                context="High concentration of imperatives directed at AI",
                description="Text contains many instruction-like imperatives",
                confidence=0.4,
            ))

        # Meta-references to AI behavior
        meta_references = len(re.findall(
            r'\b(?:your\s+(?:instructions?|programming|training|rules?)|'
            r'how\s+you\s+(?:work|operate|respond)|'
            r'your\s+(?:limitations?|restrictions?|constraints?))\b',
            text, re.IGNORECASE
        ))

        if meta_references > 2:
            detections.append(InjectionDetection(
                injection_type=InjectionType.PROMPT_EXTRACTION,
                severity=DetectionSeverity.LOW,
                pattern_name="meta_references",
                matched_text=f"{meta_references} meta-references",
                position=(0, len(text)),
                context="Multiple references to AI behavior/instructions",
                description="Text probes AI behavior or limitations",
                confidence=0.4,
            ))

        return detections

    def _determine_action(
        self,
        score: float,
        severity: Optional[DetectionSeverity],
        context: Dict[str, Any],
    ) -> DetectionAction:
        """Determine the appropriate action based on score and severity"""

        # Critical severity always blocks
        if severity == DetectionSeverity.CRITICAL:
            return DetectionAction.BLOCK

        # Check policy engine if available
        if self.policy_engine:
            try:
                mode = self.policy_engine.get_current_mode()
                mode_name = mode.name if hasattr(mode, 'name') else str(mode)

                # Stricter in higher security modes
                if mode_name in ['COLDROOM', 'LOCKDOWN']:
                    if score > 0.2:
                        return DetectionAction.BLOCK
                elif mode_name in ['AIRGAP', 'TRUSTED']:
                    if score > 0.4:
                        return DetectionAction.BLOCK

            except Exception as e:
                logger.debug(f"Policy engine check failed: {e}")

        # Threshold-based decision
        if score >= self.THRESHOLDS['escalate']:
            return DetectionAction.ESCALATE
        elif score >= self.THRESHOLDS['block']:
            return DetectionAction.BLOCK
        elif score >= self.THRESHOLDS['redact']:
            return DetectionAction.REDACT
        elif score >= self.THRESHOLDS['warn']:
            return DetectionAction.WARN
        else:
            return DetectionAction.ALLOW

    def _log_detections(
        self,
        result: DetectionResult,
        context: Dict[str, Any],
    ) -> None:
        """Log detection results"""
        if not self.event_logger:
            return

        try:
            from ..event_logger import EventType
            self.event_logger.log_event(
                EventType.DETECTION,
                f"Prompt injection analysis: {len(result.detections)} detections, "
                f"score={result.total_score:.2f}, action={result.action.value}",
                metadata={
                    'detector': 'PromptInjectionDetector',
                    'input_hash': result.input_hash,
                    'detection_count': len(result.detections),
                    'total_score': result.total_score,
                    'highest_severity': result.highest_severity.value if result.highest_severity else None,
                    'action': result.action.value,
                    'analysis_time_ms': result.analysis_time_ms,
                    'context': context,
                }
            )
        except Exception as e:
            logger.debug(f"Failed to log detections: {e}")

    def add_pattern(self, pattern: InjectionPattern) -> None:
        """Add a custom pattern"""
        self._patterns.append(pattern)
        logger.info(f"Added custom pattern: {pattern.name}")

    def remove_pattern(self, name: str) -> bool:
        """Remove a pattern by name"""
        for i, p in enumerate(self._patterns):
            if p.name == name:
                del self._patterns[i]
                logger.info(f"Removed pattern: {name}")
                return True
        return False

    def subscribe(self, callback: Callable[[DetectionResult], None]) -> None:
        """Subscribe to detection events"""
        self._callbacks.append(callback)

    def get_pattern_count(self) -> int:
        """Get the number of loaded patterns"""
        return len(self._patterns)

    def get_patterns_by_type(self, injection_type: InjectionType) -> List[InjectionPattern]:
        """Get patterns filtered by injection type"""
        return [p for p in self._patterns if p.injection_type == injection_type]


# Singleton instance
_detector_instance: Optional[PromptInjectionDetector] = None


def get_prompt_injection_detector(
    event_logger=None,
    policy_engine=None,
    sensitivity: str = "medium",
) -> PromptInjectionDetector:
    """
    Get or create the global PromptInjectionDetector instance.

    Args:
        event_logger: EventLogger for audit logging
        policy_engine: PolicyEngine for mode-aware decisions
        sensitivity: Detection sensitivity level

    Returns:
        PromptInjectionDetector instance
    """
    global _detector_instance

    if _detector_instance is None:
        _detector_instance = PromptInjectionDetector(
            event_logger=event_logger,
            policy_engine=policy_engine,
            sensitivity=sensitivity,
        )

    return _detector_instance


def configure_prompt_injection_detector(
    event_logger=None,
    policy_engine=None,
    sensitivity: str = "medium",
    custom_patterns: Optional[List[InjectionPattern]] = None,
) -> PromptInjectionDetector:
    """
    Configure and return a new PromptInjectionDetector instance.

    Replaces the global instance.

    Args:
        event_logger: EventLogger for audit logging
        policy_engine: PolicyEngine for mode-aware decisions
        sensitivity: Detection sensitivity level
        custom_patterns: Additional patterns to include

    Returns:
        PromptInjectionDetector instance
    """
    global _detector_instance

    _detector_instance = PromptInjectionDetector(
        event_logger=event_logger,
        policy_engine=policy_engine,
        sensitivity=sensitivity,
        custom_patterns=custom_patterns,
    )

    return _detector_instance
