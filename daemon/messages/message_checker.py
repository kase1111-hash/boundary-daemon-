"""
Message Checker - Content Validation for NatLangChain and Agent-OS

Provides mandatory message checking for:
- NatLangChain: Prose-based blockchain entries with intent validation
- Agent-OS: Constitutional governance with role-based agent communication

All messages flowing through the system MUST pass boundary checks.
"""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, List, Any, Union


class MessageSource(Enum):
    """Source system for the message"""
    NATLANGCHAIN = "natlangchain"
    AGENT_OS = "agent_os"
    UNKNOWN = "unknown"


class CheckResultType(Enum):
    """Result of a message check"""
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    REDACTED = "redacted"
    REQUIRES_CEREMONY = "requires_ceremony"


@dataclass
class NatLangChainEntry:
    """
    NatLangChain blockchain entry structure.

    Based on NatLangChain's prose-based blockchain protocol where
    natural language is the core substrate for recording intent.
    """
    author: str
    intent: str
    timestamp: str
    signature: Optional[str] = None
    previous_hash: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of the entry"""
        data = f"{self.author}:{self.intent}:{self.timestamp}"
        if self.previous_hash:
            data += f":{self.previous_hash}"
        return hashlib.sha256(data.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'author': self.author,
            'intent': self.intent,
            'timestamp': self.timestamp,
            'signature': self.signature,
            'previous_hash': self.previous_hash,
            'metadata': self.metadata,
        }


@dataclass
class AgentOSMessage:
    """
    Agent-OS message structure.

    Based on Agent-OS's constitutional governance model where
    natural language rules direct agent behavior.
    """
    sender_agent: str
    recipient_agent: str
    content: str
    message_type: str  # 'request', 'response', 'notification', 'command'
    authority_level: int  # 0-5 matching memory classification
    timestamp: str
    requires_consent: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'sender_agent': self.sender_agent,
            'recipient_agent': self.recipient_agent,
            'content': self.content,
            'message_type': self.message_type,
            'authority_level': self.authority_level,
            'timestamp': self.timestamp,
            'requires_consent': self.requires_consent,
            'metadata': self.metadata,
        }


@dataclass
class MessageCheckResult:
    """Result of a message check operation"""
    allowed: bool
    result_type: CheckResultType
    source: MessageSource
    reason: str
    original_content: Optional[str] = None
    redacted_content: Optional[str] = None
    violations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'allowed': self.allowed,
            'result_type': self.result_type.value,
            'source': self.source.value,
            'reason': self.reason,
            'redacted_content': self.redacted_content,
            'violations': self.violations,
            'metadata': self.metadata,
        }


class MessageChecker:
    """
    Message validation and content checking for NatLangChain and Agent-OS.

    Enforces boundary policy on all messages, checking for:
    - PII exposure (SSN, credit cards, emails, etc.)
    - Ambiguous or unclear intent (NatLangChain)
    - Constitutional compliance (Agent-OS)
    - Authority level violations
    - Blocked patterns and keywords
    """

    # PII detection patterns (simplified - full implementation would use Presidio)
    PII_PATTERNS = {
        'US_SSN': r'\b\d{3}-\d{2}-\d{4}\b',
        'CREDIT_CARD': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'PHONE_US': r'\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        'IP_ADDRESS': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    }

    # Ambiguity indicators for NatLangChain intent validation
    AMBIGUITY_INDICATORS = [
        r'\b(maybe|perhaps|possibly|might|could be|uncertain|unclear)\b',
        r'\b(etc|and so on|and more|stuff|things)\b',
        r'\b(someone|something|somewhere|somehow)\b',
        r'\b(it|this|that)\b(?!\s+(?:is|was|will|should|must|can))',  # Unclear pronouns
    ]

    # Dangerous command patterns for Agent-OS
    DANGEROUS_PATTERNS = [
        r'\b(rm\s+-rf|del\s+/[sq]|format\s+c:)\b',
        r'\b(sudo|su\s+root|admin|escalate)\b',
        r'\b(password|secret|credential|token|api.?key)\b',
        r'\b(exfiltrate|steal|hack|exploit|inject)\b',
    ]

    def __init__(self, daemon=None, strict_mode: bool = False):
        """
        Initialize message checker.

        Args:
            daemon: Reference to BoundaryDaemon instance
            strict_mode: If True, block on any ambiguity or potential issue
        """
        self.daemon = daemon
        self.strict_mode = strict_mode
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile regex patterns for efficiency"""
        self._pii_compiled = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.PII_PATTERNS.items()
        }
        self._ambiguity_compiled = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.AMBIGUITY_INDICATORS
        ]
        self._dangerous_compiled = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.DANGEROUS_PATTERNS
        ]

    def check_message(
        self,
        content: str,
        source: MessageSource,
        context: Optional[Dict[str, Any]] = None
    ) -> MessageCheckResult:
        """
        Check a message from any source.

        Args:
            content: Message content to check
            source: Source system (NatLangChain or Agent-OS)
            context: Additional context for the check

        Returns:
            MessageCheckResult with check outcome
        """
        context = context or {}
        violations = []

        # Check for PII
        pii_found = self._detect_pii(content)
        if pii_found:
            violations.extend([f"PII detected: {pii_type}" for pii_type in pii_found])

        # Check for dangerous patterns
        dangerous = self._detect_dangerous_patterns(content)
        if dangerous:
            violations.extend([f"Dangerous pattern: {pattern}" for pattern in dangerous])

        # Source-specific checks
        if source == MessageSource.NATLANGCHAIN:
            ambiguity = self._check_natlangchain_ambiguity(content)
            if ambiguity:
                violations.extend(ambiguity)
        elif source == MessageSource.AGENT_OS:
            authority_issues = self._check_agentos_authority(content, context)
            if authority_issues:
                violations.extend(authority_issues)

        # Determine result
        if violations:
            if pii_found:
                # Redact PII and allow with warning
                redacted = self._redact_pii(content)
                return MessageCheckResult(
                    allowed=not self.strict_mode,
                    result_type=CheckResultType.REDACTED,
                    source=source,
                    reason=f"Content redacted: {', '.join(violations)}",
                    original_content=content,
                    redacted_content=redacted,
                    violations=violations,
                    metadata={'pii_types': list(pii_found.keys())}
                )
            elif dangerous:
                return MessageCheckResult(
                    allowed=False,
                    result_type=CheckResultType.BLOCKED,
                    source=source,
                    reason=f"Dangerous content blocked: {', '.join(violations)}",
                    violations=violations,
                )
            else:
                # Other violations (ambiguity, authority)
                return MessageCheckResult(
                    allowed=not self.strict_mode,
                    result_type=CheckResultType.ALLOWED if not self.strict_mode else CheckResultType.BLOCKED,
                    source=source,
                    reason=f"Potential issues: {', '.join(violations)}",
                    violations=violations,
                )

        return MessageCheckResult(
            allowed=True,
            result_type=CheckResultType.ALLOWED,
            source=source,
            reason="Message passed all checks",
        )

    def check_natlangchain_entry(self, entry: NatLangChainEntry) -> MessageCheckResult:
        """
        Check a NatLangChain blockchain entry.

        Validates:
        - Intent clarity (no ambiguous language)
        - Author format
        - Timestamp validity
        - Signature presence (if required)
        - PII in content

        Args:
            entry: NatLangChain entry to check

        Returns:
            MessageCheckResult with check outcome
        """
        violations = []

        # Validate required fields
        if not entry.author:
            violations.append("Missing author field")
        if not entry.intent:
            violations.append("Missing intent field")
        if not entry.timestamp:
            violations.append("Missing timestamp field")

        # Check intent content
        intent_result = self.check_message(
            entry.intent,
            MessageSource.NATLANGCHAIN,
            context={'author': entry.author}
        )
        violations.extend(intent_result.violations)

        # Validate intent is not too vague (NatLangChain specific)
        if entry.intent and len(entry.intent.split()) < 3:
            violations.append("Intent too brief - provide more context")

        # Validate timestamp format
        if entry.timestamp:
            try:
                datetime.fromisoformat(entry.timestamp.replace('Z', '+00:00'))
            except ValueError:
                violations.append("Invalid timestamp format")

        if violations:
            return MessageCheckResult(
                allowed=False,
                result_type=CheckResultType.BLOCKED,
                source=MessageSource.NATLANGCHAIN,
                reason=f"NatLangChain entry validation failed: {', '.join(violations)}",
                violations=violations,
                metadata={'entry': entry.to_dict()}
            )

        return MessageCheckResult(
            allowed=True,
            result_type=CheckResultType.ALLOWED,
            source=MessageSource.NATLANGCHAIN,
            reason="NatLangChain entry passed validation",
            metadata={'entry_hash': entry.compute_hash()}
        )

    def check_agentos_message(self, message: AgentOSMessage) -> MessageCheckResult:
        """
        Check an Agent-OS inter-agent message.

        Validates:
        - Authority level compliance
        - Constitutional rules adherence
        - Consent requirements
        - PII in content

        Args:
            message: Agent-OS message to check

        Returns:
            MessageCheckResult with check outcome
        """
        violations = []

        # Validate required fields
        if not message.sender_agent:
            violations.append("Missing sender_agent field")
        if not message.recipient_agent:
            violations.append("Missing recipient_agent field")
        if not message.content:
            violations.append("Missing content field")

        # Check content
        content_result = self.check_message(
            message.content,
            MessageSource.AGENT_OS,
            context={
                'sender': message.sender_agent,
                'recipient': message.recipient_agent,
                'authority_level': message.authority_level,
            }
        )
        violations.extend(content_result.violations)

        # Validate authority level (0-5)
        if not 0 <= message.authority_level <= 5:
            violations.append(f"Invalid authority level: {message.authority_level} (must be 0-5)")

        # Check if consent is required but not indicated
        if message.message_type == 'command' and not message.requires_consent:
            if message.authority_level >= 3:
                violations.append("Commands with authority level >= 3 require explicit consent")

        # Validate message type
        valid_types = ['request', 'response', 'notification', 'command']
        if message.message_type not in valid_types:
            violations.append(f"Invalid message type: {message.message_type}")

        # Check for boundary mode compatibility (if daemon available)
        if self.daemon:
            current_mode = self.daemon.policy_engine.get_current_mode()
            mode_value = current_mode.value if hasattr(current_mode, 'value') else 0

            # Authority level must not exceed what current mode allows
            max_authority = self._get_max_authority_for_mode(mode_value)
            if message.authority_level > max_authority:
                violations.append(
                    f"Authority level {message.authority_level} exceeds mode limit {max_authority}"
                )

        if violations:
            return MessageCheckResult(
                allowed=False,
                result_type=CheckResultType.BLOCKED,
                source=MessageSource.AGENT_OS,
                reason=f"Agent-OS message validation failed: {', '.join(violations)}",
                violations=violations,
                metadata={'message': message.to_dict()}
            )

        return MessageCheckResult(
            allowed=True,
            result_type=CheckResultType.ALLOWED,
            source=MessageSource.AGENT_OS,
            reason="Agent-OS message passed validation",
        )

    def _detect_pii(self, content: str) -> Dict[str, List[str]]:
        """Detect PII in content"""
        found = {}
        for pii_type, pattern in self._pii_compiled.items():
            matches = pattern.findall(content)
            if matches:
                found[pii_type] = matches
        return found

    def _redact_pii(self, content: str) -> str:
        """Redact detected PII from content"""
        redacted = content
        for pii_type, pattern in self._pii_compiled.items():
            redacted = pattern.sub(f'[REDACTED:{pii_type}]', redacted)
        return redacted

    def _detect_dangerous_patterns(self, content: str) -> List[str]:
        """Detect dangerous command patterns"""
        found = []
        for pattern in self._dangerous_compiled:
            if pattern.search(content):
                found.append(pattern.pattern)
        return found

    def _check_natlangchain_ambiguity(self, content: str) -> List[str]:
        """Check for ambiguous language in NatLangChain intents"""
        issues = []
        for pattern in self._ambiguity_compiled:
            matches = pattern.findall(content)
            if matches:
                issues.append(f"Ambiguous language detected: '{matches[0]}'")
        return issues

    def _check_agentos_authority(
        self,
        content: str,
        context: Dict[str, Any]
    ) -> List[str]:
        """Check Agent-OS authority compliance"""
        issues = []
        authority_level = context.get('authority_level', 0)

        # Check for authority escalation attempts
        if 'escalate' in content.lower() or 'override' in content.lower():
            if authority_level < 3:
                issues.append("Authority escalation detected without sufficient level")

        # Check for direct agent-to-agent without central routing mention
        if 'direct' in content.lower() and 'route' not in content.lower():
            issues.append("Direct agent communication may bypass central routing")

        return issues

    def _get_max_authority_for_mode(self, mode_value: int) -> int:
        """Get maximum authority level for a boundary mode"""
        # Maps boundary mode to max memory/authority class
        # OPEN=0, RESTRICTED=1, TRUSTED=2, AIRGAP=3, COLDROOM=4, LOCKDOWN=5
        mode_to_authority = {
            0: 1,  # OPEN: 0-1
            1: 2,  # RESTRICTED: 0-2
            2: 3,  # TRUSTED: 0-3
            3: 4,  # AIRGAP: 0-4
            4: 5,  # COLDROOM: 0-5
            5: 0,  # LOCKDOWN: none
        }
        return mode_to_authority.get(mode_value, 1)

    def batch_check(
        self,
        messages: List[Union[NatLangChainEntry, AgentOSMessage, str]],
        source: Optional[MessageSource] = None
    ) -> List[MessageCheckResult]:
        """
        Check multiple messages in batch.

        Args:
            messages: List of messages to check
            source: Source system (if all are strings)

        Returns:
            List of check results
        """
        results = []
        for msg in messages:
            if isinstance(msg, NatLangChainEntry):
                results.append(self.check_natlangchain_entry(msg))
            elif isinstance(msg, AgentOSMessage):
                results.append(self.check_agentos_message(msg))
            elif isinstance(msg, str):
                src = source or MessageSource.UNKNOWN
                results.append(self.check_message(msg, src))
            else:
                results.append(MessageCheckResult(
                    allowed=False,
                    result_type=CheckResultType.BLOCKED,
                    source=MessageSource.UNKNOWN,
                    reason=f"Unknown message type: {type(msg).__name__}",
                    violations=[f"Unsupported message type: {type(msg).__name__}"]
                ))
        return results


if __name__ == '__main__':
    # Test message checker
    print("Testing Message Checker...")

    checker = MessageChecker(strict_mode=False)

    # Test NatLangChain entry
    print("\n--- NatLangChain Entry Test ---")
    entry = NatLangChainEntry(
        author="user@example.com",
        intent="I want to transfer funds to account 1234-5678-9012-3456",
        timestamp=datetime.utcnow().isoformat() + "Z"
    )
    result = checker.check_natlangchain_entry(entry)
    print(f"Allowed: {result.allowed}")
    print(f"Result type: {result.result_type.value}")
    print(f"Reason: {result.reason}")
    print(f"Violations: {result.violations}")

    # Test Agent-OS message
    print("\n--- Agent-OS Message Test ---")
    message = AgentOSMessage(
        sender_agent="orchestrator",
        recipient_agent="executor",
        content="Execute the task with elevated privileges",
        message_type="command",
        authority_level=2,
        timestamp=datetime.utcnow().isoformat() + "Z",
        requires_consent=False
    )
    result = checker.check_agentos_message(message)
    print(f"Allowed: {result.allowed}")
    print(f"Result type: {result.result_type.value}")
    print(f"Reason: {result.reason}")
    print(f"Violations: {result.violations}")

    # Test raw message with PII
    print("\n--- Raw Message with PII Test ---")
    result = checker.check_message(
        "My SSN is 123-45-6789 and email is test@example.com",
        MessageSource.UNKNOWN
    )
    print(f"Allowed: {result.allowed}")
    print(f"Result type: {result.result_type.value}")
    print(f"Redacted: {result.redacted_content}")

    print("\nMessage checker test complete.")
