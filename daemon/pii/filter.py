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
"""

import json
import threading
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
    ):
        """
        Initialize PII filter.

        Args:
            config: Filter configuration
            detector: PII detector instance
            event_logger: Event logger for audit trail
            current_mode_getter: Callback to get current boundary mode
        """
        self.config = config or PIIFilterConfig()
        self.detector = detector or PIIDetector()
        self._event_logger = event_logger
        self._get_current_mode = current_mode_getter
        self._lock = threading.RLock()

        # Statistics
        self._stats = {
            'total_scans': 0,
            'entities_detected': 0,
            'blocked_count': 0,
            'redacted_count': 0,
            'by_context': {},
            'by_severity': {},
        }

        # Detection history (limited)
        self._history: List[Dict] = []
        self._history_limit = 1000

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

        # Detect PII
        entities = self.detector.detect(text)

        if not entities:
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

        result = PIIFilterResult(
            allowed=(overall_action != PIIAction.BLOCK),
            original_text=text,
            filtered_text=filtered_text,
            entities_found=entities,
            entities_blocked=entities_blocked,
            entities_redacted=entities_redacted,
            action_taken=overall_action,
            context=context,
            metadata=metadata or {},
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

    def update_config(self, config: PIIFilterConfig):
        """Update filter configuration."""
        with self._lock:
            self.config = config

    def set_entity_action(self, entity_type: PIIEntityType, action: PIIAction):
        """Set action for specific entity type."""
        with self._lock:
            self.config.entity_overrides[entity_type] = action

    def set_context_action(
        self,
        context: FilterContext,
        severity: PIISeverity,
        action: PIIAction,
    ):
        """Set action for specific context and severity."""
        with self._lock:
            if context not in self.config.context_actions:
                self.config.context_actions[context] = {}
            self.config.context_actions[context][severity] = action

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

    def reset_stats(self):
        """Reset statistics."""
        with self._lock:
            self._stats = {
                'total_scans': 0,
                'entities_detected': 0,
                'blocked_count': 0,
                'redacted_count': 0,
                'by_context': {},
                'by_severity': {},
            }
            self.detector.reset_stats()

    # === Persistence ===

    def save_config(self, path: str):
        """Save configuration to file."""
        config_path = Path(path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(self.config.to_dict(), f, indent=2)

    def load_config(self, path: str) -> bool:
        """Load configuration from file."""
        try:
            config_path = Path(path)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    data = json.load(f)
                self.config = PIIFilterConfig.from_dict(data)
                return True
        except Exception:
            pass
        return False
