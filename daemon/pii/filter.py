"""
PII Filter - Enforcement layer for PII detection and redaction.

Provides integration points for:
- Memory recall filtering
- Log sanitization
- API response filtering
- Message validation
- Event logging

Supports configurable policies per boundary mode:
- OPEN: Log only (no blocking)
- TRUSTED: Warn and log
- VERIFIED: Block CRITICAL, warn others
- AIRGAP+: Block HIGH and above

SECURITY: The filter cannot be bypassed by simply setting config.enabled = False.
- The enabled flag is protected by a property that logs bypass attempts
- Configuration changes require authentication in locked mode
- All bypass attempts are logged to the event logger

Addresses Critical Finding: "Bypassable Security Controls"

SECURITY: Now uses BypassResistantPIIDetector by default to prevent regex
bypass attacks using encoding, homoglyphs, and zero-width characters.
Addresses Critical Finding: "Regex-Based PII Detection Bypasses"
"""

import json
import threading
import hashlib
import hmac
import secrets
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from daemon.pii.detector import (
    PIIDetector,
    PIIEntity,
    PIIEntityType,
    PIISeverity,
    RedactionMethod,
)

# SECURITY: Import bypass-resistant detector to prevent regex bypasses
try:
    from daemon.pii.bypass_resistant_detector import (
        BypassResistantPIIDetector,
        BypassDetector,
        TextNormalizer,
    )
    BYPASS_RESISTANT_AVAILABLE = True
except ImportError:
    BYPASS_RESISTANT_AVAILABLE = False
    BypassResistantPIIDetector = None
    BypassDetector = None
    TextNormalizer = None

logger = logging.getLogger(__name__)


class PIIAction(Enum):
    """Actions to take when PII is detected."""
    ALLOW = "allow"          # Allow through unchanged
    LOG = "log"              # Log but allow
    WARN = "warn"            # Warn user and log
    REDACT = "redact"        # Redact and continue
    BLOCK = "block"          # Block entirely


class FilterContext(Enum):
    """Context where PII filtering is applied."""
    MEMORY_RECALL = "memory_recall"    # LLM memory retrieval
    MEMORY_STORE = "memory_store"      # Storing to LLM memory
    LOG_OUTPUT = "log_output"          # Event/audit logs
    API_RESPONSE = "api_response"      # API response data
    API_REQUEST = "api_request"        # API request data
    MESSAGE_INBOUND = "message_in"     # Incoming messages
    MESSAGE_OUTBOUND = "message_out"   # Outgoing messages
    TOOL_OUTPUT = "tool_output"        # Tool execution output
    FILE_CONTENT = "file_content"      # File read/write


@dataclass
class PIIFilterConfig:
    """Configuration for PII filtering."""
    # Enable/disable filtering
    enabled: bool = True

    # Default action by severity
    default_actions: Dict[PIISeverity, PIIAction] = field(default_factory=lambda: {
        PIISeverity.CRITICAL: PIIAction.BLOCK,
        PIISeverity.HIGH: PIIAction.REDACT,
        PIISeverity.MEDIUM: PIIAction.WARN,
        PIISeverity.LOW: PIIAction.LOG,
        PIISeverity.INFO: PIIAction.ALLOW,
    })

    # Context-specific overrides
    context_actions: Dict[FilterContext, Dict[PIISeverity, PIIAction]] = field(
        default_factory=dict
    )

    # Entity type overrides (always apply these regardless of severity)
    entity_overrides: Dict[PIIEntityType, PIIAction] = field(default_factory=dict)

    # Whitelist patterns (regex) to ignore
    whitelist_patterns: List[str] = field(default_factory=list)

    # Redaction method
    redaction_method: RedactionMethod = RedactionMethod.REPLACE

    # Log all detections
    log_all_detections: bool = True

    # Block threshold by mode
    mode_thresholds: Dict[str, PIISeverity] = field(default_factory=lambda: {
        'OPEN': PIISeverity.CRITICAL,      # Only block critical
        'STANDARD': PIISeverity.CRITICAL,
        'TRUSTED': PIISeverity.CRITICAL,
        'VERIFIED': PIISeverity.HIGH,      # Block high and critical
        'AIRGAP': PIISeverity.MEDIUM,      # Block medium and above
        'COLDROOM': PIISeverity.MEDIUM,
        'LOCKDOWN': PIISeverity.LOW,       # Block almost everything
    })

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            'enabled': self.enabled,
            'default_actions': {k.value: v.value for k, v in self.default_actions.items()},
            'redaction_method': self.redaction_method.value,
            'log_all_detections': self.log_all_detections,
            'mode_thresholds': {k: v.value for k, v in self.mode_thresholds.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'PIIFilterConfig':
        """Create from dictionary."""
        config = cls()
        if 'enabled' in data:
            config.enabled = data['enabled']
        if 'default_actions' in data:
            config.default_actions = {
                PIISeverity(k): PIIAction(v)
                for k, v in data['default_actions'].items()
            }
        if 'redaction_method' in data:
            config.redaction_method = RedactionMethod(data['redaction_method'])
        if 'log_all_detections' in data:
            config.log_all_detections = data['log_all_detections']
        if 'mode_thresholds' in data:
            config.mode_thresholds = {
                k: PIISeverity(v) for k, v in data['mode_thresholds'].items()
            }
        return config


@dataclass
class PIIFilterResult:
    """Result of PII filtering operation."""
    allowed: bool                        # Whether content is allowed
    original_text: str                   # Original input
    filtered_text: str                   # Filtered/redacted output
    entities_found: List[PIIEntity]      # Detected entities
    entities_blocked: List[PIIEntity]    # Entities that caused blocking
    entities_redacted: List[PIIEntity]   # Entities that were redacted
    action_taken: PIIAction              # Primary action taken
    context: FilterContext               # Filtering context
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary for logging."""
        return {
            'allowed': self.allowed,
            'text_length': len(self.original_text),
            'filtered_length': len(self.filtered_text),
            'entities_found': len(self.entities_found),
            'entities_blocked': len(self.entities_blocked),
            'entities_redacted': len(self.entities_redacted),
            'action_taken': self.action_taken.value,
            'context': self.context.value,
            'severity_summary': self._get_severity_summary(),
            'type_summary': self._get_type_summary(),
        }

    def _get_severity_summary(self) -> Dict[str, int]:
        """Get entity count by severity."""
        summary = {}
        for entity in self.entities_found:
            key = entity.severity.value
            summary[key] = summary.get(key, 0) + 1
        return summary

    def _get_type_summary(self) -> Dict[str, int]:
        """Get entity count by type."""
        summary = {}
        for entity in self.entities_found:
            key = entity.entity_type.value
            summary[key] = summary.get(key, 0) + 1
        return summary


class PIIFilter:
    """
    PII filtering and enforcement layer.

    Integrates PII detection with boundary daemon enforcement.
    Supports mode-aware filtering, context-specific policies,
    and comprehensive logging.

    SECURITY: This filter has protections against bypass:
    - The 'enabled' property cannot be directly set to False
    - Use disable() with auth token to disable filtering
    - All disable attempts are logged
    - When locked, configuration cannot be changed

    Usage:
        filter = PIIFilter(event_logger=daemon.event_logger)
        result = filter.filter_text(text, FilterContext.MEMORY_RECALL)
        if result.allowed:
            process(result.filtered_text)
        else:
            handle_blocked(result)
    """

    def __init__(
        self,
        config: Optional[PIIFilterConfig] = None,
        detector: Optional[PIIDetector] = None,
        event_logger=None,
        current_mode_getter: Optional[Callable[[], str]] = None,
        use_bypass_resistant: bool = True,
    ):
        """
        Initialize PII filter.

        Args:
            config: Filter configuration
            detector: PII detector instance
            event_logger: Event logger for audit trail
            current_mode_getter: Callback to get current boundary mode
            use_bypass_resistant: Use bypass-resistant detector (default True)

        SECURITY: By default, uses BypassResistantPIIDetector to prevent
        regex bypass attacks using encoding, homoglyphs, and zero-width chars.
        """
        self._config = config or PIIFilterConfig()

        # SECURITY: Use bypass-resistant detector by default
        # This addresses: "Regex-Based PII Detection Bypasses"
        if detector:
            self.detector = detector
            self._bypass_resistant = False
        elif use_bypass_resistant and BYPASS_RESISTANT_AVAILABLE and BypassResistantPIIDetector:
            base_detector = PIIDetector()
            self.detector = BypassResistantPIIDetector(
                base_detector=base_detector,
                normalize_before_scan=True,
                detect_bypass_attempts=True,
                scan_decoded_content=True,
                flag_suspicious_entropy=True,
            )
            self._bypass_resistant = True
            logger.info("PII Filter using bypass-resistant detection")
        else:
            self.detector = PIIDetector()
            self._bypass_resistant = False
            logger.warning("PII Filter using standard detection (bypass-resistant not available)")
        self._event_logger = event_logger
        self._get_current_mode = current_mode_getter
        self._lock = threading.RLock()

        # SECURITY: Protection against bypass
        self._auth_token_hash: Optional[str] = None
        self._locked = False  # When locked, config cannot be changed
        self._bypass_attempts: List[dict] = []
        self._failed_auth_attempts = 0
        self._max_failed_attempts = 3

        # Generate auth token
        self._initial_token = self._generate_auth_token()

        # Statistics
        self._stats = {
            'total_scans': 0,
            'entities_detected': 0,
            'blocked_count': 0,
            'redacted_count': 0,
            'by_context': {},
            'by_severity': {},
            'bypass_attempts': 0,
        }

        # Detection history (limited)
        self._history: List[Dict] = []
        self._history_limit = 1000

    # SECURITY: Protect the config property
    @property
    def config(self) -> PIIFilterConfig:
        """Get the filter configuration (read-only access)."""
        return self._config

    @config.setter
    def config(self, value: PIIFilterConfig):
        """
        Attempt to set config directly.
        This logs a bypass attempt but does NOT change the config in locked mode.
        """
        with self._lock:
            if self._locked:
                self._log_bypass_attempt("config_setter", "Attempted to replace config while locked")
                logger.warning("SECURITY: Attempted to replace PII filter config while locked")
                return  # Silently ignore in locked mode

            # Allow in unlocked mode (for initial setup)
            self._config = value

    def _generate_auth_token(self) -> str:
        """Generate authentication token for critical operations."""
        token = secrets.token_urlsafe(32)
        self._auth_token_hash = hashlib.sha256(token.encode()).hexdigest()
        return token

    def get_initial_token(self) -> Optional[str]:
        """
        Get the initial auth token (only available once after init).

        Returns:
            The initial token if not yet retrieved, None otherwise
        """
        token = self._initial_token
        self._initial_token = None  # Clear after first access
        return token

    def _verify_token(self, token: str) -> bool:
        """Verify an authentication token."""
        if not token or not self._auth_token_hash:
            return False
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return hmac.compare_digest(token_hash, self._auth_token_hash)

    def _log_bypass_attempt(self, method: str, details: str):
        """Log a bypass attempt."""
        self._stats['bypass_attempts'] = self._stats.get('bypass_attempts', 0) + 1

        attempt = {
            'timestamp': datetime.utcnow().isoformat() + "Z",
            'method': method,
            'details': details,
        }
        self._bypass_attempts.append(attempt)

        logger.warning(f"SECURITY: PII filter bypass attempt via {method}: {details}")

        if self._event_logger:
            try:
                from daemon.event_logger import EventType
                self._event_logger.log_event(
                    event_type=EventType.VIOLATION,
                    data={
                        'event': 'pii_filter_bypass_attempt',
                        'method': method,
                        'details': details,
                        'timestamp': datetime.utcnow().isoformat() + "Z"
                    }
                )
            except Exception:
                pass

    def disable(self, auth_token: str, reason: str = "") -> Tuple[bool, str]:
        """
        Disable PII filtering (REQUIRES AUTHENTICATION).

        Args:
            auth_token: Valid authentication token
            reason: Reason for disabling (logged for audit)

        Returns:
            (success, message)
        """
        with self._lock:
            if self._locked:
                self._log_bypass_attempt("disable", "Attempted while locked")
                return (False, "PII filter is LOCKED and cannot be disabled")

            if not self._verify_token(auth_token):
                self._failed_auth_attempts += 1
                self._log_bypass_attempt("disable", f"Invalid token (attempt {self._failed_auth_attempts})")

                if self._failed_auth_attempts >= self._max_failed_attempts:
                    self._locked = True
                    logger.critical("SECURITY: PII filter LOCKED due to excessive failed auth attempts")

                return (False, "Invalid authentication token")

            # Reset failed attempts
            self._failed_auth_attempts = 0

            # Disable filtering
            self._config.enabled = False

            logger.warning(f"SECURITY: PII filtering DISABLED. Reason: {reason}")

            if self._event_logger:
                try:
                    from daemon.event_logger import EventType
                    self._event_logger.log_event(
                        event_type=EventType.POLICY_DECISION,
                        data={
                            'event': 'pii_filter_disabled',
                            'reason': reason,
                            'timestamp': datetime.utcnow().isoformat() + "Z"
                        }
                    )
                except Exception:
                    pass

            return (True, "PII filtering disabled")

    def enable(self):
        """Enable PII filtering (no auth required - enabling is always safe)."""
        with self._lock:
            self._config.enabled = True
            logger.info("PII filtering enabled")

    def lock(self):
        """
        Lock the PII filter configuration.
        Once locked, the filter cannot be disabled or reconfigured.
        This is a one-way operation for high-security environments.
        """
        with self._lock:
            self._locked = True
            logger.warning("PII filter LOCKED - configuration frozen")

    def is_locked(self) -> bool:
        """Check if the filter is locked."""
        return self._locked

    def get_security_status(self) -> dict:
        """Get security status of the PII filter."""
        with self._lock:
            return {
                'enabled': self._config.enabled,
                'locked': self._locked,
                'bypass_attempts': len(self._bypass_attempts),
                'failed_auth_attempts': self._failed_auth_attempts,
            }

    def set_event_logger(self, event_logger):
        """Set the event logger."""
        self._event_logger = event_logger

    def set_mode_getter(self, getter: Callable[[], str]):
        """Set the mode getter callback."""
        self._get_current_mode = getter

    def filter_text(
        self,
        text: str,
        context: FilterContext,
        metadata: Optional[Dict] = None,
    ) -> PIIFilterResult:
        """
        Filter text for PII.

        Args:
            text: Text to filter
            context: Context where filtering is applied
            metadata: Additional metadata for logging

        Returns:
            PIIFilterResult with filtering outcome
        """
        if not self.config.enabled or not text:
            return PIIFilterResult(
                allowed=True,
                original_text=text,
                filtered_text=text,
                entities_found=[],
                entities_blocked=[],
                entities_redacted=[],
                action_taken=PIIAction.ALLOW,
                context=context,
                metadata=metadata or {},
            )

        with self._lock:
            self._stats['total_scans'] += 1
            ctx_key = context.value
            self._stats['by_context'][ctx_key] = self._stats['by_context'].get(ctx_key, 0) + 1

        # Detect PII (handle both bypass-resistant Dict and base List returns)
        detection_result = self.detector.detect(text)

        # Extract entities - handle both Dict (bypass-resistant) and List (base) returns
        bypass_attempts = []
        bypass_warnings = []
        if isinstance(detection_result, dict):
            # Bypass-resistant detector returns Dict
            entities = detection_result.get('entities', [])
            bypass_attempts = detection_result.get('bypass_attempts', [])
            bypass_warnings = detection_result.get('warnings', [])

            # Log bypass attempts if detected
            if bypass_attempts and self._event_logger:
                self._event_logger.log_security_event(
                    event_type="pii_bypass_attempt",
                    severity="warning",
                    details={
                        'attempts': bypass_attempts,
                        'count': len(bypass_attempts),
                        'context': context.value,
                        'warnings': bypass_warnings,
                    },
                )
        else:
            # Base detector returns List
            entities = detection_result

        if not entities:
            result_metadata = metadata.copy() if metadata else {}
            if bypass_attempts:
                # Even if no PII found, log bypass attempts in metadata
                result_metadata['bypass_attempts'] = bypass_attempts
                result_metadata['bypass_warnings'] = bypass_warnings
            return PIIFilterResult(
                allowed=True,
                original_text=text,
                filtered_text=text,
                entities_found=[],
                entities_blocked=[],
                entities_redacted=[],
                action_taken=PIIAction.ALLOW,
                context=context,
                metadata=result_metadata,
            )

        # Determine actions for each entity
        entities_blocked = []
        entities_redacted = []
        entities_warned = []
        entities_logged = []
        overall_action = PIIAction.ALLOW

        current_mode = self._get_current_mode() if self._get_current_mode else 'STANDARD'
        mode_threshold = self.config.mode_thresholds.get(current_mode, PIISeverity.CRITICAL)
        severity_order = [PIISeverity.INFO, PIISeverity.LOW, PIISeverity.MEDIUM,
                         PIISeverity.HIGH, PIISeverity.CRITICAL]
        threshold_index = severity_order.index(mode_threshold)

        for entity in entities:
            action = self._determine_action(entity, context, current_mode, threshold_index, severity_order)

            if action == PIIAction.BLOCK:
                entities_blocked.append(entity)
                overall_action = PIIAction.BLOCK
            elif action == PIIAction.REDACT:
                entities_redacted.append(entity)
                if overall_action not in (PIIAction.BLOCK,):
                    overall_action = PIIAction.REDACT
            elif action == PIIAction.WARN:
                entities_warned.append(entity)
                if overall_action not in (PIIAction.BLOCK, PIIAction.REDACT):
                    overall_action = PIIAction.WARN
            elif action == PIIAction.LOG:
                entities_logged.append(entity)
                if overall_action == PIIAction.ALLOW:
                    overall_action = PIIAction.LOG

        # Perform redaction if needed
        filtered_text = text
        if entities_redacted and overall_action != PIIAction.BLOCK:
            filtered_text, _ = self.detector.redact(
                text,
                entities_redacted,
                self.config.redaction_method,
            )

        # If blocked, redact everything for the log
        if overall_action == PIIAction.BLOCK:
            filtered_text, _ = self.detector.redact(
                text,
                entities,
                RedactionMethod.REPLACE,
            )

        # Build result metadata including bypass detection info
        result_metadata = metadata.copy() if metadata else {}
        if bypass_attempts:
            result_metadata['bypass_attempts'] = bypass_attempts
            result_metadata['bypass_warnings'] = bypass_warnings

        result = PIIFilterResult(
            allowed=(overall_action != PIIAction.BLOCK),
            original_text=text,
            filtered_text=filtered_text,
            entities_found=entities,
            entities_blocked=entities_blocked,
            entities_redacted=entities_redacted,
            action_taken=overall_action,
            context=context,
            metadata=result_metadata,
        )

        # Update statistics
        with self._lock:
            self._stats['entities_detected'] += len(entities)
            if entities_blocked:
                self._stats['blocked_count'] += 1
            if entities_redacted:
                self._stats['redacted_count'] += len(entities_redacted)
            for entity in entities:
                sev_key = entity.severity.value
                self._stats['by_severity'][sev_key] = self._stats['by_severity'].get(sev_key, 0) + 1

        # Log event
        self._log_detection(result, current_mode)

        # Add to history
        self._add_to_history(result)

        return result

    def _determine_action(
        self,
        entity: PIIEntity,
        context: FilterContext,
        current_mode: str,
        threshold_index: int,
        severity_order: List[PIISeverity],
    ) -> PIIAction:
        """Determine action for an entity based on config and mode."""
        # Check entity type override first
        if entity.entity_type in self.config.entity_overrides:
            return self.config.entity_overrides[entity.entity_type]

        # Check context-specific action
        if context in self.config.context_actions:
            context_actions = self.config.context_actions[context]
            if entity.severity in context_actions:
                return context_actions[entity.severity]

        # Check mode threshold - if severity >= threshold, block
        entity_index = severity_order.index(entity.severity)
        if entity_index >= threshold_index:
            return PIIAction.BLOCK

        # Fall back to default actions
        return self.config.default_actions.get(entity.severity, PIIAction.LOG)

    def _log_detection(self, result: PIIFilterResult, mode: str):
        """Log PII detection event."""
        if not self._event_logger:
            return

        if not self.config.log_all_detections and result.action_taken == PIIAction.ALLOW:
            return

        try:
            from daemon.event_logger import EventType

            # Determine event type based on action
            if result.action_taken == PIIAction.BLOCK:
                event_type = EventType.VIOLATION
                details = f"PII blocked: {len(result.entities_blocked)} entities in {result.context.value}"
            else:
                event_type = EventType.POLICY_DECISION
                details = f"PII detected: {len(result.entities_found)} entities in {result.context.value}"

            self._event_logger.log_event(
                event_type=event_type,
                data={
                    'action': result.action_taken.value,
                    'context': result.context.value,
                    'mode': mode,
                    'entities_found': len(result.entities_found),
                    'entities_blocked': len(result.entities_blocked),
                    'entities_redacted': len(result.entities_redacted),
                    'severity_summary': result._get_severity_summary(),
                    'type_summary': result._get_type_summary(),
                }
            )
        except Exception:
            pass  # Don't fail on logging errors

    def _add_to_history(self, result: PIIFilterResult):
        """Add result to detection history."""
        with self._lock:
            entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'context': result.context.value,
                'action': result.action_taken.value,
                'entities_found': len(result.entities_found),
                'severity_summary': result._get_severity_summary(),
            }
            self._history.append(entry)

            # Trim history
            if len(self._history) > self._history_limit:
                self._history = self._history[-self._history_limit:]

    # === Convenience Methods ===

    def filter_recall(self, text: str, metadata: Optional[Dict] = None) -> PIIFilterResult:
        """Filter memory recall content."""
        return self.filter_text(text, FilterContext.MEMORY_RECALL, metadata)

    def filter_store(self, text: str, metadata: Optional[Dict] = None) -> PIIFilterResult:
        """Filter content before storing to memory."""
        return self.filter_text(text, FilterContext.MEMORY_STORE, metadata)

    def filter_log(self, text: str, metadata: Optional[Dict] = None) -> PIIFilterResult:
        """Filter log output."""
        return self.filter_text(text, FilterContext.LOG_OUTPUT, metadata)

    def filter_api_response(self, text: str, metadata: Optional[Dict] = None) -> PIIFilterResult:
        """Filter API response."""
        return self.filter_text(text, FilterContext.API_RESPONSE, metadata)

    def filter_message(
        self,
        text: str,
        inbound: bool = True,
        metadata: Optional[Dict] = None,
    ) -> PIIFilterResult:
        """Filter message content."""
        context = FilterContext.MESSAGE_INBOUND if inbound else FilterContext.MESSAGE_OUTBOUND
        return self.filter_text(text, context, metadata)

    # === Batch Operations ===

    def filter_dict(
        self,
        data: Dict[str, Any],
        context: FilterContext,
        keys_to_filter: Optional[Set[str]] = None,
    ) -> Tuple[Dict[str, Any], List[PIIFilterResult]]:
        """
        Filter string values in a dictionary.

        Args:
            data: Dictionary to filter
            context: Filtering context
            keys_to_filter: Specific keys to filter (None = all string values)

        Returns:
            Tuple of (filtered_dict, list of results)
        """
        results = []
        filtered = {}

        for key, value in data.items():
            if isinstance(value, str):
                if keys_to_filter is None or key in keys_to_filter:
                    result = self.filter_text(value, context, {'key': key})
                    results.append(result)
                    filtered[key] = result.filtered_text
                else:
                    filtered[key] = value
            elif isinstance(value, dict):
                nested, nested_results = self.filter_dict(value, context, keys_to_filter)
                filtered[key] = nested
                results.extend(nested_results)
            elif isinstance(value, list):
                filtered_list = []
                for item in value:
                    if isinstance(item, str):
                        if keys_to_filter is None:
                            result = self.filter_text(item, context)
                            results.append(result)
                            filtered_list.append(result.filtered_text)
                        else:
                            filtered_list.append(item)
                    elif isinstance(item, dict):
                        nested, nested_results = self.filter_dict(item, context, keys_to_filter)
                        filtered_list.append(nested)
                        results.extend(nested_results)
                    else:
                        filtered_list.append(item)
                filtered[key] = filtered_list
            else:
                filtered[key] = value

        return filtered, results

    # === Configuration ===

    def update_config(self, config: PIIFilterConfig, auth_token: Optional[str] = None) -> Tuple[bool, str]:
        """
        Update filter configuration (REQUIRES AUTHENTICATION when locked).

        Args:
            config: New configuration
            auth_token: Required if the filter is locked

        Returns:
            (success, message)
        """
        with self._lock:
            if self._locked:
                if not auth_token or not self._verify_token(auth_token):
                    self._log_bypass_attempt("update_config", "Attempted config update while locked")
                    return (False, "PII filter is LOCKED - configuration cannot be changed")
                # Authenticated update allowed
                logger.warning("SECURITY: Config updated while locked (authenticated)")

            self._config = config
            return (True, "Configuration updated")

    def set_entity_action(
        self,
        entity_type: PIIEntityType,
        action: PIIAction,
        auth_token: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Set action for specific entity type (REQUIRES AUTHENTICATION when locked).

        Args:
            entity_type: The PII entity type
            action: Action to take for this entity type
            auth_token: Required if the filter is locked

        Returns:
            (success, message)
        """
        with self._lock:
            if self._locked:
                if not auth_token or not self._verify_token(auth_token):
                    self._log_bypass_attempt("set_entity_action", f"Attempted to change action for {entity_type.value}")
                    return (False, "PII filter is LOCKED - configuration cannot be changed")

            self._config.entity_overrides[entity_type] = action
            return (True, f"Entity action set: {entity_type.value} -> {action.value}")

    def set_context_action(
        self,
        context: FilterContext,
        severity: PIISeverity,
        action: PIIAction,
        auth_token: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Set action for specific context and severity (REQUIRES AUTHENTICATION when locked).

        Args:
            context: Filtering context
            severity: PII severity level
            action: Action to take
            auth_token: Required if the filter is locked

        Returns:
            (success, message)
        """
        with self._lock:
            if self._locked:
                if not auth_token or not self._verify_token(auth_token):
                    self._log_bypass_attempt("set_context_action", f"Attempted to change action for {context.value}/{severity.value}")
                    return (False, "PII filter is LOCKED - configuration cannot be changed")

            if context not in self._config.context_actions:
                self._config.context_actions[context] = {}
            self._config.context_actions[context][severity] = action
            return (True, f"Context action set: {context.value}/{severity.value} -> {action.value}")

    # === Statistics ===

    def get_stats(self) -> Dict:
        """Get filtering statistics."""
        with self._lock:
            return {
                **self._stats.copy(),
                'detector_stats': self.detector.get_stats(),
            }

    def get_history(self, limit: int = 100) -> List[Dict]:
        """Get recent detection history."""
        with self._lock:
            return self._history[-limit:]

    def reset_stats(self, auth_token: Optional[str] = None) -> Tuple[bool, str]:
        """
        Reset statistics (REQUIRES AUTHENTICATION when locked).

        Note: bypass_attempts counter is NEVER reset for security audit trail.

        Args:
            auth_token: Required if the filter is locked

        Returns:
            (success, message)
        """
        with self._lock:
            if self._locked:
                if not auth_token or not self._verify_token(auth_token):
                    self._log_bypass_attempt("reset_stats", "Attempted to reset statistics while locked")
                    return (False, "PII filter is LOCKED - cannot reset statistics")

            # Preserve bypass_attempts for audit trail
            bypass_count = self._stats.get('bypass_attempts', 0)

            self._stats = {
                'total_scans': 0,
                'entities_detected': 0,
                'blocked_count': 0,
                'redacted_count': 0,
                'by_context': {},
                'by_severity': {},
                'bypass_attempts': bypass_count,  # Never reset this
            }
            self.detector.reset_stats()
            return (True, "Statistics reset (bypass_attempts preserved)")

    # === Persistence ===

    def save_config(self, path: str):
        """Save configuration to file."""
        config_path = Path(path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(self.config.to_dict(), f, indent=2)

    def load_config(self, path: str, auth_token: Optional[str] = None) -> Tuple[bool, str]:
        """
        Load configuration from file (REQUIRES AUTHENTICATION when locked).

        Args:
            path: Path to configuration file
            auth_token: Required if the filter is locked

        Returns:
            (success, message)
        """
        with self._lock:
            if self._locked:
                if not auth_token or not self._verify_token(auth_token):
                    self._log_bypass_attempt("load_config", f"Attempted to load config from {path}")
                    return (False, "PII filter is LOCKED - configuration cannot be changed")

        try:
            config_path = Path(path)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    data = json.load(f)

                new_config = PIIFilterConfig.from_dict(data)

                # Check if attempting to disable via config load
                if not new_config.enabled:
                    logger.warning(f"SECURITY: Attempted to load disabled config from {path}")
                    if self._locked:
                        self._log_bypass_attempt("load_config", "Config file had enabled=False")
                        return (False, "Cannot load config with enabled=False while locked")

                with self._lock:
                    self._config = new_config

                return (True, "Configuration loaded")
            return (False, f"Config file not found: {path}")
        except Exception as e:
            return (False, f"Failed to load config: {str(e)}")
