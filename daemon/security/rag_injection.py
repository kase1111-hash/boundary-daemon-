"""
RAG Injection Detector - Retrieval-Augmented Generation Security

This module provides detection and prevention of attacks targeting
RAG (Retrieval-Augmented Generation) systems:

1. Poisoned document detection in retrieved context
2. Indirect prompt injection via retrieved documents
3. Context window manipulation attacks
4. Data exfiltration via crafted queries
5. Embedding space attacks
6. Document integrity verification

Security Notes:
- Analyzes retrieved documents before they reach the LLM
- Detects instruction injection hidden in legitimate-looking content
- Tracks document provenance and trust levels
- Integrates with prompt injection detector for multi-layer defense

This addresses the gap: "Needs: RAG injection detection, context window poisoning"
"""

import re
import hashlib
import logging
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Set, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


class RAGThreatType(Enum):
    """Types of RAG-specific threats"""
    POISONED_DOCUMENT = "poisoned_document"
    INDIRECT_INJECTION = "indirect_injection"
    CONTEXT_MANIPULATION = "context_manipulation"
    EXFILTRATION_QUERY = "exfiltration_query"
    EMBEDDING_ATTACK = "embedding_attack"
    INTEGRITY_VIOLATION = "integrity_violation"
    AUTHORITY_CLAIM = "authority_claim"
    INSTRUCTION_OVERRIDE = "instruction_override"


class DocumentTrustLevel(Enum):
    """Trust levels for retrieved documents"""
    VERIFIED = "verified"      # Cryptographically verified, known good
    TRUSTED = "trusted"        # From trusted source, not verified
    UNKNOWN = "unknown"        # Unknown provenance
    SUSPICIOUS = "suspicious"  # Contains suspicious patterns
    BLOCKED = "blocked"        # Known malicious or blocked


class ThreatSeverity(Enum):
    """Severity of detected threats"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RetrievedDocument:
    """A document retrieved for RAG context"""
    content: str
    source: str
    document_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    trust_level: DocumentTrustLevel = DocumentTrustLevel.UNKNOWN
    content_hash: Optional[str] = None
    embedding_hash: Optional[str] = None
    retrieval_score: float = 0.0

    def __post_init__(self):
        if not self.content_hash:
            self.content_hash = hashlib.sha256(self.content.encode()).hexdigest()[:16]


@dataclass
class RAGThreat:
    """A detected RAG-related threat"""
    threat_type: RAGThreatType
    severity: ThreatSeverity
    description: str
    document_id: Optional[str] = None
    matched_content: Optional[str] = None
    position: Optional[Tuple[int, int]] = None
    confidence: float = 0.0
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'threat_type': self.threat_type.value,
            'severity': self.severity.value,
            'description': self.description,
            'document_id': self.document_id,
            'matched_content': self.matched_content[:100] if self.matched_content else None,
            'position': self.position,
            'confidence': self.confidence,
            'remediation': self.remediation,
            'metadata': self.metadata,
        }


@dataclass
class RAGAnalysisResult:
    """Complete result of RAG security analysis"""
    is_safe: bool
    documents_analyzed: int
    documents_blocked: int
    safe_documents: List[RetrievedDocument]
    blocked_documents: List[RetrievedDocument]
    threats: List[RAGThreat]
    total_risk_score: float
    analysis_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            'is_safe': self.is_safe,
            'documents_analyzed': self.documents_analyzed,
            'documents_blocked': self.documents_blocked,
            'safe_count': len(self.safe_documents),
            'blocked_count': len(self.blocked_documents),
            'threat_count': len(self.threats),
            'threats': [t.to_dict() for t in self.threats],
            'total_risk_score': self.total_risk_score,
            'analysis_time_ms': self.analysis_time_ms,
        }


class RAGInjectionDetector:
    """
    Detects and prevents injection attacks in RAG systems.

    Provides multi-layer protection:
    1. Document content analysis for injection patterns
    2. Trust level verification for document sources
    3. Context manipulation detection
    4. Query analysis for exfiltration attempts
    5. Embedding integrity verification

    Integrates with:
    - PromptInjectionDetector for content analysis
    - BoundaryDaemon policy engine
    - Document verification systems
    """

    # Indirect injection patterns (hidden in documents)
    INDIRECT_INJECTION_PATTERNS = [
        # Hidden instructions in documents
        (r'(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|other)\s+(?:context|documents?|information)',
         "Instruction to ignore other context", ThreatSeverity.HIGH),
        (r'(?:the\s+)?(?:system|assistant|AI)\s+(?:must|should|will)\s+(?:now|always)',
         "Instruction targeting system behavior", ThreatSeverity.HIGH),
        (r'(?:important|critical|urgent)\s*:\s*(?:ignore|override|replace)',
         "Urgency-based override attempt", ThreatSeverity.HIGH),

        # Authority claims in documents
        (r'(?:this\s+)?document\s+(?:has|grants|provides)\s+(?:admin|root|elevated)\s+(?:access|privileges?)',
         "False authority claim", ThreatSeverity.CRITICAL),
        (r'(?:authorized|verified)\s+(?:by|from)\s+(?:admin|system|security)',
         "Fake authorization claim", ThreatSeverity.HIGH),

        # Instruction injection patterns
        (r'<\s*(?:system|instruction|command)\s*>.*?<\s*/\s*(?:system|instruction|command)\s*>',
         "XML-style instruction injection", ThreatSeverity.HIGH),
        (r'\[\[\s*(?:SYSTEM|ADMIN|INSTRUCTION)\s*\]\]',
         "Bracket instruction marker", ThreatSeverity.HIGH),
        (r'```(?:system|instruction|override)[\s\S]*?```',
         "Code block instruction injection", ThreatSeverity.MEDIUM),

        # Hidden text patterns
        (r'(?:<!--.*?(?:ignore|instruction|override).*?-->)',
         "HTML comment injection", ThreatSeverity.MEDIUM),
        (r'(?:\x00|\x01|\x02).*?(?:instruction|override)',
         "Null byte injection", ThreatSeverity.CRITICAL),
    ]

    # Context manipulation patterns
    CONTEXT_MANIPULATION_PATTERNS = [
        # Context boundary attacks
        (r'(?:end\s+of\s+(?:context|document|section)|---+\s*END\s*---+)',
         "Context termination attempt", ThreatSeverity.MEDIUM),
        (r'(?:new\s+)?(?:context|conversation|session)\s*(?:starts?|begins?)\s*(?:here|now|:)',
         "Context reset attempt", ThreatSeverity.HIGH),

        # Priority manipulation
        (r'(?:this\s+)?(?:information|document)\s+(?:overrides?|replaces?|supersedes?)\s+(?:all|any|other)',
         "Priority manipulation", ThreatSeverity.HIGH),
        (r'(?:highest|maximum|top)\s+priority\s*:',
         "Priority escalation", ThreatSeverity.MEDIUM),

        # Confusion injection
        (r'(?:actually|in\s+fact|correction)\s*:\s*(?:the\s+)?(?:previous|above)\s+(?:is|was)\s+(?:wrong|incorrect|false)',
         "Contradiction injection", ThreatSeverity.MEDIUM),
    ]

    # Exfiltration patterns in queries
    EXFILTRATION_PATTERNS = [
        # Data extraction attempts
        (r'(?:list|show|reveal|extract)\s+(?:all|every)\s+(?:user|customer|employee|password|secret|key)',
         "Data extraction query", ThreatSeverity.HIGH),
        (r'(?:send|transmit|export|email)\s+(?:to|results?\s+to)\s+(?:\S+@\S+|\S+\.com)',
         "Data exfiltration attempt", ThreatSeverity.CRITICAL),

        # System probing
        (r'(?:what|list)\s+(?:are\s+)?(?:the\s+)?(?:system|internal|private)\s+(?:prompts?|instructions?|rules?)',
         "System probing query", ThreatSeverity.MEDIUM),
    ]

    # Suspicious content patterns
    SUSPICIOUS_CONTENT_PATTERNS = [
        # Encoded content that might hide instructions
        (r'(?:[A-Za-z0-9+/]{50,}={0,2})',  # Long base64
         "Potentially encoded content", ThreatSeverity.LOW),

        # Unusual Unicode
        (r'[\u200b\u200c\u200d\ufeff]{2,}',  # Zero-width chars
         "Zero-width character sequence", ThreatSeverity.MEDIUM),

        # Homograph characters
        (r'[\u0400-\u04FF]+',  # Cyrillic in otherwise ASCII
         "Mixed script (potential homograph)", ThreatSeverity.LOW),
    ]

    def __init__(
        self,
        event_logger=None,
        policy_engine=None,
        prompt_detector=None,
        trusted_sources: Optional[Set[str]] = None,
        block_threshold: float = 0.7,
    ):
        """
        Initialize RAGInjectionDetector.

        Args:
            event_logger: EventLogger for audit logging
            policy_engine: PolicyEngine for mode-aware decisions
            prompt_detector: PromptInjectionDetector for content analysis
            trusted_sources: Set of trusted document sources
            block_threshold: Risk score threshold for blocking documents
        """
        self.event_logger = event_logger
        self.policy_engine = policy_engine
        self.prompt_detector = prompt_detector
        self.trusted_sources = trusted_sources or set()
        self.block_threshold = block_threshold

        # Compile patterns
        self._indirect_patterns = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), desc, sev)
            for p, desc, sev in self.INDIRECT_INJECTION_PATTERNS
        ]
        self._context_patterns = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), desc, sev)
            for p, desc, sev in self.CONTEXT_MANIPULATION_PATTERNS
        ]
        self._exfil_patterns = [
            (re.compile(p, re.IGNORECASE), desc, sev)
            for p, desc, sev in self.EXFILTRATION_PATTERNS
        ]
        self._suspicious_patterns = [
            (re.compile(p), desc, sev)
            for p, desc, sev in self.SUSPICIOUS_CONTENT_PATTERNS
        ]

        # Document integrity tracking
        self._verified_hashes: Set[str] = set()
        self._blocked_hashes: Set[str] = set()

        # Callbacks
        self._callbacks: List[Callable[[RAGAnalysisResult], None]] = []

        # Thread safety
        self._lock = threading.Lock()

        logger.info(f"RAGInjectionDetector initialized with {len(self.trusted_sources)} trusted sources")

    def analyze_documents(
        self,
        documents: List[RetrievedDocument],
        query: Optional[str] = None,
    ) -> RAGAnalysisResult:
        """
        Analyze retrieved documents for RAG injection attacks.

        Args:
            documents: List of retrieved documents to analyze
            query: Optional query that retrieved these documents

        Returns:
            RAGAnalysisResult with findings and safe documents
        """
        import time
        start_time = time.time()

        threats: List[RAGThreat] = []
        safe_docs: List[RetrievedDocument] = []
        blocked_docs: List[RetrievedDocument] = []

        # 1. Analyze query for exfiltration attempts
        if query:
            query_threats = self._analyze_query(query)
            threats.extend(query_threats)

        # 2. Analyze each document
        for doc in documents:
            doc_threats, doc_score = self._analyze_document(doc)
            threats.extend(doc_threats)

            # Update trust level based on analysis
            if doc_score >= self.block_threshold:
                doc.trust_level = DocumentTrustLevel.BLOCKED
                blocked_docs.append(doc)
            elif doc_score > 0.3:
                doc.trust_level = DocumentTrustLevel.SUSPICIOUS
                safe_docs.append(doc)  # Still allow but flagged
            else:
                if doc.source in self.trusted_sources:
                    doc.trust_level = DocumentTrustLevel.TRUSTED
                safe_docs.append(doc)

        # 3. Cross-document analysis
        cross_threats = self._analyze_cross_document(documents)
        threats.extend(cross_threats)

        # Calculate total risk
        total_risk = self._calculate_risk(threats)

        analysis_time_ms = (time.time() - start_time) * 1000

        result = RAGAnalysisResult(
            is_safe=len(blocked_docs) == 0 and total_risk < self.block_threshold,
            documents_analyzed=len(documents),
            documents_blocked=len(blocked_docs),
            safe_documents=safe_docs,
            blocked_documents=blocked_docs,
            threats=threats,
            total_risk_score=total_risk,
            analysis_time_ms=analysis_time_ms,
        )

        # Log and notify
        if threats:
            self._log_analysis(result)

        for callback in self._callbacks:
            try:
                callback(result)
            except Exception as e:
                logger.warning(f"Callback failed: {e}")

        return result

    def _analyze_query(self, query: str) -> List[RAGThreat]:
        """Analyze query for exfiltration attempts"""
        threats = []

        for pattern, description, severity in self._exfil_patterns:
            for match in pattern.finditer(query):
                threats.append(RAGThreat(
                    threat_type=RAGThreatType.EXFILTRATION_QUERY,
                    severity=severity,
                    description=description,
                    matched_content=match.group(),
                    position=match.span(),
                    confidence=0.85,
                    remediation="Block or sanitize query",
                ))

        return threats

    def _analyze_document(
        self, doc: RetrievedDocument
    ) -> Tuple[List[RAGThreat], float]:
        """Analyze a single document for threats"""
        threats = []
        risk_score = 0.0

        # Check if document hash is blocked
        if doc.content_hash in self._blocked_hashes:
            threats.append(RAGThreat(
                threat_type=RAGThreatType.INTEGRITY_VIOLATION,
                severity=ThreatSeverity.CRITICAL,
                description="Document hash matches known malicious content",
                document_id=doc.document_id,
                confidence=1.0,
            ))
            return threats, 1.0

        # Check if document is verified
        if doc.content_hash in self._verified_hashes:
            return threats, 0.0

        # 1. Check indirect injection patterns
        for pattern, description, severity in self._indirect_patterns:
            for match in pattern.finditer(doc.content):
                threats.append(RAGThreat(
                    threat_type=RAGThreatType.INDIRECT_INJECTION,
                    severity=severity,
                    description=description,
                    document_id=doc.document_id,
                    matched_content=match.group(),
                    position=match.span(),
                    confidence=0.9,
                    remediation="Remove document from context",
                ))
                risk_score += self._severity_weight(severity)

        # 2. Check context manipulation patterns
        for pattern, description, severity in self._context_patterns:
            for match in pattern.finditer(doc.content):
                threats.append(RAGThreat(
                    threat_type=RAGThreatType.CONTEXT_MANIPULATION,
                    severity=severity,
                    description=description,
                    document_id=doc.document_id,
                    matched_content=match.group(),
                    position=match.span(),
                    confidence=0.85,
                ))
                risk_score += self._severity_weight(severity)

        # 3. Check suspicious content
        for pattern, description, severity in self._suspicious_patterns:
            for match in pattern.finditer(doc.content):
                threats.append(RAGThreat(
                    threat_type=RAGThreatType.POISONED_DOCUMENT,
                    severity=severity,
                    description=description,
                    document_id=doc.document_id,
                    matched_content=match.group()[:50],
                    confidence=0.6,
                ))
                risk_score += self._severity_weight(severity) * 0.5

        # 4. Use prompt injection detector if available
        if self.prompt_detector:
            try:
                injection_result = self.prompt_detector.analyze(doc.content)
                if not injection_result.is_safe:
                    for detection in injection_result.detections:
                        threats.append(RAGThreat(
                            threat_type=RAGThreatType.INDIRECT_INJECTION,
                            severity=ThreatSeverity.HIGH,
                            description=f"Prompt injection in document: {detection.description}",
                            document_id=doc.document_id,
                            matched_content=detection.matched_text,
                            confidence=detection.confidence,
                        ))
                        risk_score += 0.4
            except Exception as e:
                logger.debug(f"Prompt detector failed: {e}")

        # 5. Check source trust
        if doc.source not in self.trusted_sources:
            # Untrusted sources get a small risk bump
            risk_score += 0.1

        return threats, min(risk_score, 1.0)

    def _analyze_cross_document(
        self, documents: List[RetrievedDocument]
    ) -> List[RAGThreat]:
        """Analyze patterns across multiple documents"""
        threats = []

        if len(documents) < 2:
            return threats

        # Check for coordinated injection (multiple docs with similar injection patterns)
        injection_docs = []
        for doc in documents:
            for pattern, _, _ in self._indirect_patterns:
                if pattern.search(doc.content):
                    injection_docs.append(doc.document_id)
                    break

        if len(injection_docs) >= 2:
            threats.append(RAGThreat(
                threat_type=RAGThreatType.CONTEXT_MANIPULATION,
                severity=ThreatSeverity.CRITICAL,
                description=f"Coordinated injection detected across {len(injection_docs)} documents",
                confidence=0.9,
                metadata={'affected_documents': injection_docs},
                remediation="Block all affected documents",
            ))

        # Check for context flooding (too many similar documents)
        if len(documents) > 10:
            # Check if documents are suspiciously similar
            hashes = [doc.content_hash for doc in documents]
            unique_hashes = set(hashes)
            if len(unique_hashes) < len(documents) * 0.5:
                threats.append(RAGThreat(
                    threat_type=RAGThreatType.CONTEXT_MANIPULATION,
                    severity=ThreatSeverity.MEDIUM,
                    description="Context flooding detected: many duplicate/similar documents",
                    confidence=0.7,
                ))

        return threats

    def _severity_weight(self, severity: ThreatSeverity) -> float:
        """Get weight for severity level"""
        weights = {
            ThreatSeverity.INFO: 0.05,
            ThreatSeverity.LOW: 0.1,
            ThreatSeverity.MEDIUM: 0.25,
            ThreatSeverity.HIGH: 0.5,
            ThreatSeverity.CRITICAL: 1.0,
        }
        return weights.get(severity, 0.1)

    def _calculate_risk(self, threats: List[RAGThreat]) -> float:
        """Calculate total risk score from threats"""
        if not threats:
            return 0.0

        score = sum(
            self._severity_weight(t.severity) * t.confidence
            for t in threats
        )
        return min(score, 1.0)

    def _log_analysis(self, result: RAGAnalysisResult) -> None:
        """Log analysis results"""
        if not self.event_logger:
            return

        try:
            from ..event_logger import EventType
            self.event_logger.log_event(
                EventType.DETECTION,
                f"RAG injection analysis: {len(result.threats)} threats, "
                f"{result.documents_blocked} blocked",
                metadata={
                    'detector': 'RAGInjectionDetector',
                    'documents_analyzed': result.documents_analyzed,
                    'documents_blocked': result.documents_blocked,
                    'threat_count': len(result.threats),
                    'risk_score': result.total_risk_score,
                    'is_safe': result.is_safe,
                }
            )
        except Exception as e:
            logger.debug(f"Failed to log analysis: {e}")

    def add_trusted_source(self, source: str) -> None:
        """Add a trusted document source"""
        with self._lock:
            self.trusted_sources.add(source)

    def add_verified_hash(self, content_hash: str) -> None:
        """Add a verified document hash"""
        with self._lock:
            self._verified_hashes.add(content_hash)

    def block_hash(self, content_hash: str) -> None:
        """Block a document by hash"""
        with self._lock:
            self._blocked_hashes.add(content_hash)

    def subscribe(self, callback: Callable[[RAGAnalysisResult], None]) -> None:
        """Subscribe to analysis events"""
        self._callbacks.append(callback)

    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics"""
        with self._lock:
            return {
                'trusted_sources': len(self.trusted_sources),
                'verified_hashes': len(self._verified_hashes),
                'blocked_hashes': len(self._blocked_hashes),
                'block_threshold': self.block_threshold,
            }


# Singleton instance
_detector_instance: Optional[RAGInjectionDetector] = None
_detector_lock = threading.Lock()


def get_rag_detector(
    event_logger=None,
    policy_engine=None,
    prompt_detector=None,
) -> RAGInjectionDetector:
    """
    Get or create the global RAGInjectionDetector instance.

    Args:
        event_logger: EventLogger for audit logging
        policy_engine: PolicyEngine for mode-aware decisions
        prompt_detector: PromptInjectionDetector for content analysis

    Returns:
        RAGInjectionDetector instance
    """
    global _detector_instance

    with _detector_lock:
        if _detector_instance is None:
            _detector_instance = RAGInjectionDetector(
                event_logger=event_logger,
                policy_engine=policy_engine,
                prompt_detector=prompt_detector,
            )
        return _detector_instance


def configure_rag_detector(
    event_logger=None,
    policy_engine=None,
    prompt_detector=None,
    trusted_sources: Optional[Set[str]] = None,
    block_threshold: float = 0.7,
) -> RAGInjectionDetector:
    """
    Configure and return a new RAGInjectionDetector instance.

    Replaces the global instance.
    """
    global _detector_instance

    with _detector_lock:
        _detector_instance = RAGInjectionDetector(
            event_logger=event_logger,
            policy_engine=policy_engine,
            prompt_detector=prompt_detector,
            trusted_sources=trusted_sources,
            block_threshold=block_threshold,
        )
        return _detector_instance
