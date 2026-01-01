"""
Tool Output Validator - Validate and Sanitize AI Tool Responses

This module provides comprehensive validation of tool outputs in AI/Agent
systems to prevent:
1. Sensitive data leakage in tool responses
2. Command injection via tool outputs
3. Recursive/infinite tool call chains
4. Schema violations and unexpected output formats
5. Resource exhaustion via large outputs

Security Notes:
- Integrates with BoundaryDaemon policy engine
- Works with PII detector for data leakage prevention
- Tracks tool execution chains for recursion detection
- Configurable validation policies per tool

This addresses the gap: "Needs: Tool output validation"
"""

import re
import json
import hashlib
import logging
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import (
    List, Dict, Any, Optional, Set, Tuple,
    Callable, Pattern, Union
)
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)


class ValidationResult(Enum):
    """Result of tool output validation"""
    VALID = "valid"
    SANITIZED = "sanitized"
    BLOCKED = "blocked"
    ERROR = "error"


class ViolationType(Enum):
    """Types of validation violations"""
    SENSITIVE_DATA = "sensitive_data"
    COMMAND_INJECTION = "command_injection"
    RECURSIVE_CALL = "recursive_call"
    SCHEMA_VIOLATION = "schema_violation"
    SIZE_EXCEEDED = "size_exceeded"
    RATE_LIMITED = "rate_limited"
    BLOCKED_PATTERN = "blocked_pattern"
    DANGEROUS_CONTENT = "dangerous_content"
    UNTRUSTED_SOURCE = "untrusted_source"


class SanitizationAction(Enum):
    """Actions for sanitizing outputs"""
    REDACT = "redact"
    TRUNCATE = "truncate"
    ESCAPE = "escape"
    REMOVE = "remove"
    REPLACE = "replace"


@dataclass
class ToolPolicy:
    """Policy configuration for a specific tool"""
    name: str
    max_output_size: int = 1_000_000  # 1MB default
    max_calls_per_minute: int = 60
    max_chain_depth: int = 10
    allowed_output_patterns: List[Pattern] = field(default_factory=list)
    blocked_output_patterns: List[Pattern] = field(default_factory=list)
    require_schema: bool = False
    output_schema: Optional[Dict[str, Any]] = None
    sanitize_pii: bool = True
    sanitize_commands: bool = True
    trusted: bool = False
    description: str = ""

    def __post_init__(self):
        # Compile patterns if strings
        if self.allowed_output_patterns:
            self.allowed_output_patterns = [
                re.compile(p) if isinstance(p, str) else p
                for p in self.allowed_output_patterns
            ]
        if self.blocked_output_patterns:
            self.blocked_output_patterns = [
                re.compile(p) if isinstance(p, str) else p
                for p in self.blocked_output_patterns
            ]


@dataclass
class ToolCall:
    """Record of a tool call in the execution chain"""
    tool_name: str
    call_id: str
    timestamp: datetime
    input_hash: str
    output_hash: Optional[str] = None
    parent_call_id: Optional[str] = None
    depth: int = 0
    validated: bool = False


@dataclass
class ValidationViolation:
    """A validation violation found in tool output"""
    violation_type: ViolationType
    severity: str  # low, medium, high, critical
    description: str
    matched_content: Optional[str] = None
    position: Optional[Tuple[int, int]] = None
    sanitization_applied: Optional[SanitizationAction] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'violation_type': self.violation_type.value,
            'severity': self.severity,
            'description': self.description,
            'matched_content': self.matched_content[:100] if self.matched_content else None,
            'position': self.position,
            'sanitization_applied': self.sanitization_applied.value if self.sanitization_applied else None,
            'metadata': self.metadata,
        }


@dataclass
class ToolValidationResult:
    """Complete result of tool output validation"""
    result: ValidationResult
    original_output: str
    sanitized_output: Optional[str]
    violations: List[ValidationViolation]
    tool_name: str
    call_id: str
    validation_time_ms: float
    chain_depth: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            'result': self.result.value,
            'violation_count': len(self.violations),
            'violations': [v.to_dict() for v in self.violations],
            'tool_name': self.tool_name,
            'call_id': self.call_id,
            'validation_time_ms': self.validation_time_ms,
            'chain_depth': self.chain_depth,
            'was_sanitized': self.sanitized_output != self.original_output,
        }


class ToolOutputValidator:
    """
    Validates and sanitizes AI tool outputs.

    Provides multi-layer validation:
    1. Size and rate limiting
    2. Recursive call chain detection
    3. Sensitive data detection (PII, secrets)
    4. Command injection detection
    5. Pattern-based allow/block lists
    6. Schema validation

    Integrates with:
    - BoundaryDaemon policy engine
    - PII detector for data leakage prevention
    - Prompt injection detector for output validation
    """

    # Default dangerous patterns in tool outputs
    DANGEROUS_PATTERNS = [
        # Shell command injection indicators
        (r';\s*(?:rm|del|format|mkfs|dd)\s+', "Destructive command detected"),
        (r'\$\([^)]+\)', "Command substitution detected"),
        (r'`[^`]+`', "Backtick command execution detected"),
        (r'\|\s*(?:bash|sh|cmd|powershell)', "Pipe to shell detected"),

        # Script injection
        (r'<script[^>]*>.*?</script>', "Script tag detected"),
        (r'javascript:', "JavaScript URL detected"),
        (r'on\w+\s*=\s*["\'][^"\']*["\']', "Event handler detected"),

        # SQL injection indicators
        (r"(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\s+", "SQL keyword detected"),

        # Path traversal
        (r'\.\./|\.\.\\',"Path traversal detected"),

        # Credential patterns
        (r'(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S+', "Credential pattern detected"),
    ]

    # Patterns for detecting recursive/infinite loops
    RECURSION_INDICATORS = [
        r'call\s+(?:this|self|same)\s+(?:tool|function)',
        r'execute\s+again',
        r'repeat\s+(?:this|the)\s+(?:call|operation)',
        r'infinite\s+loop',
        r'recursively\s+(?:call|invoke)',
    ]

    def __init__(
        self,
        event_logger=None,
        policy_engine=None,
        pii_detector=None,
        max_chain_depth: int = 10,
        max_output_size: int = 10_000_000,  # 10MB
        rate_limit_window: int = 60,  # seconds
        default_rate_limit: int = 100,  # calls per window
    ):
        """
        Initialize the ToolOutputValidator.

        Args:
            event_logger: EventLogger for audit logging
            policy_engine: PolicyEngine for mode-aware decisions
            pii_detector: PII detector for sensitive data detection
            max_chain_depth: Maximum tool call chain depth
            max_output_size: Maximum output size in bytes
            rate_limit_window: Rate limit window in seconds
            default_rate_limit: Default rate limit per tool
        """
        self.event_logger = event_logger
        self.policy_engine = policy_engine
        self.pii_detector = pii_detector
        self.max_chain_depth = max_chain_depth
        self.max_output_size = max_output_size
        self.rate_limit_window = rate_limit_window
        self.default_rate_limit = default_rate_limit

        # Tool policies
        self._policies: Dict[str, ToolPolicy] = {}

        # Execution chain tracking
        self._call_chains: Dict[str, List[ToolCall]] = {}
        self._active_calls: Dict[str, ToolCall] = {}

        # Rate limiting
        self._call_counts: Dict[str, List[datetime]] = defaultdict(list)

        # Compiled patterns
        self._dangerous_patterns = [
            (re.compile(p, re.IGNORECASE), desc)
            for p, desc in self.DANGEROUS_PATTERNS
        ]
        self._recursion_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.RECURSION_INDICATORS
        ]

        # Callbacks
        self._callbacks: Dict[int, Callable[[ToolValidationResult], None]] = {}
        self._next_callback_id = 0
        self._callback_lock = threading.Lock()

        # Thread safety
        self._lock = threading.Lock()

        logger.info(
            f"ToolOutputValidator initialized: max_chain_depth={max_chain_depth}, "
            f"max_output_size={max_output_size}"
        )

    def register_policy(self, policy: ToolPolicy) -> None:
        """Register a validation policy for a tool"""
        with self._lock:
            self._policies[policy.name] = policy
            logger.info(f"Registered policy for tool: {policy.name}")

    def get_policy(self, tool_name: str) -> ToolPolicy:
        """Get policy for a tool, or create default"""
        with self._lock:
            if tool_name not in self._policies:
                self._policies[tool_name] = ToolPolicy(name=tool_name)
            return self._policies[tool_name]

    def register_callback(self, callback: Callable[[ToolValidationResult], None]) -> int:
        """Register a callback for validation results.

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

    def start_tool_call(
        self,
        tool_name: str,
        tool_input: Any,
        parent_call_id: Optional[str] = None,
    ) -> Tuple[str, Optional[ValidationViolation]]:
        """
        Register the start of a tool call.

        Returns:
            Tuple of (call_id, violation) - violation if call should be blocked
        """
        import uuid
        call_id = str(uuid.uuid4())[:8]

        # Compute input hash
        input_str = json.dumps(tool_input, sort_keys=True, default=str)
        input_hash = hashlib.sha256(input_str.encode()).hexdigest()[:16]

        # Determine chain depth
        depth = 0
        if parent_call_id and parent_call_id in self._active_calls:
            parent = self._active_calls[parent_call_id]
            depth = parent.depth + 1

        # Check chain depth
        policy = self.get_policy(tool_name)
        max_depth = min(policy.max_chain_depth, self.max_chain_depth)

        if depth > max_depth:
            violation = ValidationViolation(
                violation_type=ViolationType.RECURSIVE_CALL,
                severity="high",
                description=f"Tool call chain depth {depth} exceeds maximum {max_depth}",
                metadata={'tool': tool_name, 'depth': depth},
            )
            return call_id, violation

        # Check rate limit
        violation = self._check_rate_limit(tool_name, policy)
        if violation:
            return call_id, violation

        # Record the call
        call = ToolCall(
            tool_name=tool_name,
            call_id=call_id,
            timestamp=datetime.now(),
            input_hash=input_hash,
            parent_call_id=parent_call_id,
            depth=depth,
        )

        with self._lock:
            self._active_calls[call_id] = call
            if parent_call_id:
                if parent_call_id not in self._call_chains:
                    self._call_chains[parent_call_id] = []
                self._call_chains[parent_call_id].append(call)

        return call_id, None

    def _check_rate_limit(
        self, tool_name: str, policy: ToolPolicy
    ) -> Optional[ValidationViolation]:
        """Check if tool is rate limited"""
        now = datetime.now()
        window_start = now - timedelta(seconds=self.rate_limit_window)

        with self._lock:
            # Clean old entries
            self._call_counts[tool_name] = [
                t for t in self._call_counts[tool_name]
                if t > window_start
            ]

            # Check limit
            limit = policy.max_calls_per_minute
            if len(self._call_counts[tool_name]) >= limit:
                return ValidationViolation(
                    violation_type=ViolationType.RATE_LIMITED,
                    severity="medium",
                    description=f"Tool {tool_name} rate limited: {limit} calls per minute",
                    metadata={'tool': tool_name, 'limit': limit},
                )

            # Record this call
            self._call_counts[tool_name].append(now)

        return None

    def validate_output(
        self,
        tool_name: str,
        output: Union[str, Dict, Any],
        call_id: Optional[str] = None,
    ) -> ToolValidationResult:
        """
        Validate tool output.

        Args:
            tool_name: Name of the tool
            output: Tool output to validate
            call_id: Optional call ID from start_tool_call

        Returns:
            ToolValidationResult with validation status and any violations
        """
        import time
        start_time = time.time()

        # Convert output to string for analysis
        if isinstance(output, dict):
            output_str = json.dumps(output, default=str)
        elif isinstance(output, str):
            output_str = output
        else:
            output_str = str(output)

        policy = self.get_policy(tool_name)
        violations: List[ValidationViolation] = []
        sanitized_output = output_str

        # Get chain depth
        chain_depth = 0
        if call_id and call_id in self._active_calls:
            chain_depth = self._active_calls[call_id].depth

        # 1. Size validation
        if len(output_str) > policy.max_output_size:
            violations.append(ValidationViolation(
                violation_type=ViolationType.SIZE_EXCEEDED,
                severity="medium",
                description=f"Output size {len(output_str)} exceeds limit {policy.max_output_size}",
                metadata={'size': len(output_str), 'limit': policy.max_output_size},
                sanitization_applied=SanitizationAction.TRUNCATE,
            ))
            sanitized_output = output_str[:policy.max_output_size] + "\n[TRUNCATED]"

        # 2. Dangerous pattern detection
        violations.extend(self._check_dangerous_patterns(output_str, policy))

        # 3. Blocked pattern check
        violations.extend(self._check_blocked_patterns(output_str, policy))

        # 4. Recursion indicator detection
        violations.extend(self._check_recursion_indicators(output_str))

        # 5. PII/Sensitive data detection
        if policy.sanitize_pii:
            pii_violations, sanitized_output = self._check_pii(sanitized_output)
            violations.extend(pii_violations)

        # 6. Command injection detection
        if policy.sanitize_commands:
            cmd_violations, sanitized_output = self._check_command_injection(sanitized_output)
            violations.extend(cmd_violations)

        # 7. Schema validation
        if policy.require_schema and policy.output_schema:
            schema_violations = self._validate_schema(output, policy.output_schema)
            violations.extend(schema_violations)

        # Determine result
        critical_violations = [v for v in violations if v.severity == "critical"]
        high_violations = [v for v in violations if v.severity == "high"]

        if critical_violations:
            result = ValidationResult.BLOCKED
        elif high_violations and not policy.trusted:
            result = ValidationResult.BLOCKED
        elif violations:
            result = ValidationResult.SANITIZED if sanitized_output != output_str else ValidationResult.VALID
        else:
            result = ValidationResult.VALID

        validation_time_ms = (time.time() - start_time) * 1000

        # Update call record
        if call_id and call_id in self._active_calls:
            call = self._active_calls[call_id]
            call.output_hash = hashlib.sha256(output_str.encode()).hexdigest()[:16]
            call.validated = True

        validation_result = ToolValidationResult(
            result=result,
            original_output=output_str,
            sanitized_output=sanitized_output if result != ValidationResult.BLOCKED else None,
            violations=violations,
            tool_name=tool_name,
            call_id=call_id or "unknown",
            validation_time_ms=validation_time_ms,
            chain_depth=chain_depth,
        )

        # Log and notify
        if violations:
            self._log_violations(validation_result)

        with self._callback_lock:
            callbacks = list(self._callbacks.values())
        for callback in callbacks:
            try:
                callback(validation_result)
            except Exception as e:
                logger.warning(f"Callback failed: {e}")

        return validation_result

    def _check_dangerous_patterns(
        self, output: str, policy: ToolPolicy
    ) -> List[ValidationViolation]:
        """Check for dangerous patterns in output"""
        violations = []

        for pattern, description in self._dangerous_patterns:
            for match in pattern.finditer(output):
                violations.append(ValidationViolation(
                    violation_type=ViolationType.DANGEROUS_CONTENT,
                    severity="high" if not policy.trusted else "medium",
                    description=description,
                    matched_content=match.group()[:100],
                    position=match.span(),
                ))

        return violations

    def _check_blocked_patterns(
        self, output: str, policy: ToolPolicy
    ) -> List[ValidationViolation]:
        """Check against blocked patterns"""
        violations = []

        for pattern in policy.blocked_output_patterns:
            for match in pattern.finditer(output):
                violations.append(ValidationViolation(
                    violation_type=ViolationType.BLOCKED_PATTERN,
                    severity="high",
                    description=f"Blocked pattern matched: {pattern.pattern}",
                    matched_content=match.group()[:100],
                    position=match.span(),
                ))

        return violations

    def _check_recursion_indicators(self, output: str) -> List[ValidationViolation]:
        """Check for recursion indicators in output"""
        violations = []

        for pattern in self._recursion_patterns:
            if pattern.search(output):
                violations.append(ValidationViolation(
                    violation_type=ViolationType.RECURSIVE_CALL,
                    severity="medium",
                    description="Output contains recursion indicators",
                    matched_content=pattern.pattern,
                ))

        return violations

    def _check_pii(self, output: str) -> Tuple[List[ValidationViolation], str]:
        """Check for PII and sanitize"""
        violations = []
        sanitized = output

        if self.pii_detector:
            try:
                # Use PII detector if available
                result = self.pii_detector.detect(output)
                if result.entities:
                    for entity in result.entities:
                        violations.append(ValidationViolation(
                            violation_type=ViolationType.SENSITIVE_DATA,
                            severity="high",
                            description=f"PII detected: {entity.entity_type}",
                            matched_content="[REDACTED]",
                            sanitization_applied=SanitizationAction.REDACT,
                        ))
                    sanitized = self.pii_detector.redact(output)
            except Exception as e:
                logger.debug(f"PII detection failed: {e}")

        # Fallback: basic credential patterns
        credential_patterns = [
            (r'(?:api[_-]?key|token|secret|password)\s*[:=]\s*["\']?([A-Za-z0-9+/=_-]{20,})["\']?',
             "API key/token detected"),
            (r'(?:Bearer|Basic)\s+[A-Za-z0-9+/=_-]{20,}', "Authorization header detected"),
            (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "Private key detected"),
        ]

        for pattern, desc in credential_patterns:
            regex = re.compile(pattern, re.IGNORECASE)
            for match in regex.finditer(sanitized):
                violations.append(ValidationViolation(
                    violation_type=ViolationType.SENSITIVE_DATA,
                    severity="critical",
                    description=desc,
                    matched_content="[REDACTED]",
                    sanitization_applied=SanitizationAction.REDACT,
                ))
                sanitized = regex.sub("[REDACTED]", sanitized)

        return violations, sanitized

    def _check_command_injection(
        self, output: str
    ) -> Tuple[List[ValidationViolation], str]:
        """Check for command injection patterns and sanitize"""
        violations = []
        sanitized = output

        # Shell metacharacters that could be dangerous
        shell_patterns = [
            (r'\$\(([^)]+)\)', r'$(BLOCKED)'),  # Command substitution
            (r'`([^`]+)`', r'`BLOCKED`'),  # Backtick execution
            (r'\|\s*(?:bash|sh|zsh|ksh|cmd|powershell)\b', '|BLOCKED'),  # Pipe to shell
        ]

        for pattern, replacement in shell_patterns:
            regex = re.compile(pattern, re.IGNORECASE)
            if regex.search(sanitized):
                violations.append(ValidationViolation(
                    violation_type=ViolationType.COMMAND_INJECTION,
                    severity="high",
                    description="Command injection pattern detected and sanitized",
                    matched_content=pattern,
                    sanitization_applied=SanitizationAction.REPLACE,
                ))
                sanitized = regex.sub(replacement, sanitized)

        return violations, sanitized

    def _validate_schema(
        self, output: Any, schema: Dict[str, Any]
    ) -> List[ValidationViolation]:
        """Validate output against schema"""
        violations = []

        try:
            # Basic type checking
            expected_type = schema.get('type')
            if expected_type:
                type_map = {
                    'string': str,
                    'number': (int, float),
                    'integer': int,
                    'boolean': bool,
                    'array': list,
                    'object': dict,
                }

                if expected_type in type_map:
                    expected = type_map[expected_type]
                    if not isinstance(output, expected):
                        violations.append(ValidationViolation(
                            violation_type=ViolationType.SCHEMA_VIOLATION,
                            severity="medium",
                            description=f"Expected type {expected_type}, got {type(output).__name__}",
                        ))

            # Required fields for objects
            if isinstance(output, dict) and 'required' in schema:
                for field in schema['required']:
                    if field not in output:
                        violations.append(ValidationViolation(
                            violation_type=ViolationType.SCHEMA_VIOLATION,
                            severity="medium",
                            description=f"Missing required field: {field}",
                        ))

        except Exception as e:
            violations.append(ValidationViolation(
                violation_type=ViolationType.SCHEMA_VIOLATION,
                severity="low",
                description=f"Schema validation error: {e}",
            ))

        return violations

    def _log_violations(self, result: ToolValidationResult) -> None:
        """Log validation violations"""
        if not self.event_logger:
            return

        try:
            from ..event_logger import EventType
            self.event_logger.log_event(
                EventType.DETECTION,
                f"Tool output validation: {result.result.value} for {result.tool_name} "
                f"({len(result.violations)} violations)",
                metadata={
                    'validator': 'ToolOutputValidator',
                    'tool_name': result.tool_name,
                    'call_id': result.call_id,
                    'result': result.result.value,
                    'violation_count': len(result.violations),
                    'chain_depth': result.chain_depth,
                    'validation_time_ms': result.validation_time_ms,
                }
            )
        except Exception as e:
            logger.debug(f"Failed to log violations: {e}")

    def end_tool_call(self, call_id: str) -> None:
        """Mark a tool call as complete"""
        with self._lock:
            if call_id in self._active_calls:
                del self._active_calls[call_id]

    def get_chain_depth(self, call_id: str) -> int:
        """Get current chain depth for a call"""
        if call_id in self._active_calls:
            return self._active_calls[call_id].depth
        return 0

    def subscribe(self, callback: Callable[[ToolValidationResult], None]) -> None:
        """Subscribe to validation events"""
        self._callbacks.append(callback)

    def get_stats(self) -> Dict[str, Any]:
        """Get validator statistics"""
        with self._lock:
            return {
                'active_calls': len(self._active_calls),
                'registered_policies': len(self._policies),
                'call_chains': len(self._call_chains),
                'rate_limit_window': self.rate_limit_window,
                'max_chain_depth': self.max_chain_depth,
            }


# Singleton instance
_validator_instance: Optional[ToolOutputValidator] = None
_validator_lock = threading.Lock()


def get_tool_validator(
    event_logger=None,
    policy_engine=None,
    pii_detector=None,
) -> ToolOutputValidator:
    """
    Get or create the global ToolOutputValidator instance.

    Args:
        event_logger: EventLogger for audit logging
        policy_engine: PolicyEngine for mode-aware decisions
        pii_detector: PII detector for sensitive data

    Returns:
        ToolOutputValidator instance
    """
    global _validator_instance

    with _validator_lock:
        if _validator_instance is None:
            _validator_instance = ToolOutputValidator(
                event_logger=event_logger,
                policy_engine=policy_engine,
                pii_detector=pii_detector,
            )
        return _validator_instance


def configure_tool_validator(
    event_logger=None,
    policy_engine=None,
    pii_detector=None,
    max_chain_depth: int = 10,
    max_output_size: int = 10_000_000,
) -> ToolOutputValidator:
    """
    Configure and return a new ToolOutputValidator instance.

    Replaces the global instance.
    """
    global _validator_instance

    with _validator_lock:
        _validator_instance = ToolOutputValidator(
            event_logger=event_logger,
            policy_engine=policy_engine,
            pii_detector=pii_detector,
            max_chain_depth=max_chain_depth,
            max_output_size=max_output_size,
        )
        return _validator_instance
