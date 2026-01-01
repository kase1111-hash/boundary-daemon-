"""
Event Publisher for Attack Detection Integration

Provides a unified event publishing system that connects BoundaryDaemon
security events to the detection engines (YARA, Sigma, MITRE ATT&CK, IOC).

This module enables:
- Real-time correlation of tripwire events with known attack patterns
- IOC matching against security events
- MITRE ATT&CK technique identification
- Sigma rule matching for log-based detection
- Unified alert generation for SOC integration

Usage:
    from daemon.detection import EventPublisher, get_event_publisher

    # In BoundaryDaemon initialization
    self._event_publisher = get_event_publisher()

    # In _handle_violation
    self._event_publisher.publish_tripwire_event(violation)

    # The publisher will automatically correlate with detection engines
"""

import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Set

logger = logging.getLogger(__name__)


class EventType(Enum):
    """Types of security events."""
    TRIPWIRE = "tripwire"
    MODE_CHANGE = "mode_change"
    POLICY_VIOLATION = "policy_violation"
    LOCKDOWN = "lockdown"
    NETWORK_ANOMALY = "network_anomaly"
    PROCESS_ANOMALY = "process_anomaly"
    FILE_INTEGRITY = "file_integrity"
    AUTH_FAILURE = "auth_failure"
    SANDBOX_ESCAPE = "sandbox_escape"
    SYSCALL_VIOLATION = "syscall_violation"
    FIREWALL_BLOCKED = "firewall_blocked"


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class SecurityEvent:
    """A security event to be published to detection engines."""
    event_id: str
    event_type: EventType
    timestamp: str
    severity: AlertSeverity
    source: str
    details: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_data: Optional[bytes] = None

    @classmethod
    def from_tripwire(cls, violation: Any) -> 'SecurityEvent':
        """Create SecurityEvent from TripwireViolation."""
        return cls(
            event_id=f"trip_{int(time.time() * 1000)}",
            event_type=EventType.TRIPWIRE,
            timestamp=datetime.utcnow().isoformat() + 'Z',
            severity=AlertSeverity.CRITICAL,
            source="tripwire_system",
            details=violation.details if hasattr(violation, 'details') else str(violation),
            metadata={
                'violation_type': violation.violation_type.value if hasattr(violation, 'violation_type') else 'unknown',
            },
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'timestamp': self.timestamp,
            'severity': self.severity.value,
            'source': self.source,
            'details': self.details,
            'metadata': self.metadata,
        }

    def to_log_entry(self) -> Dict[str, Any]:
        """Convert to log entry format for Sigma matching."""
        entry = self.to_dict()
        entry['message'] = self.details
        entry['level'] = self.severity.value.upper()
        return entry


@dataclass
class DetectionResult:
    """Result from a detection engine."""
    engine: str
    matched: bool
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    severity: AlertSeverity = AlertSeverity.MEDIUM
    description: str = ""
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    ioc_matches: List[str] = field(default_factory=list)
    raw_match: Optional[Any] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'engine': self.engine,
            'matched': self.matched,
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'severity': self.severity.value,
            'description': self.description,
            'mitre_tactics': self.mitre_tactics,
            'mitre_techniques': self.mitre_techniques,
            'ioc_matches': self.ioc_matches,
        }


@dataclass
class SecurityAlert:
    """A correlated security alert from detection engines."""
    alert_id: str
    timestamp: str
    event: SecurityEvent
    detections: List[DetectionResult]
    correlated_events: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)

    @property
    def max_severity(self) -> AlertSeverity:
        """Get the maximum severity from all detections."""
        severity_order = [
            AlertSeverity.INFO,
            AlertSeverity.LOW,
            AlertSeverity.MEDIUM,
            AlertSeverity.HIGH,
            AlertSeverity.CRITICAL,
            AlertSeverity.EMERGENCY,
        ]
        max_sev = self.event.severity
        for det in self.detections:
            if severity_order.index(det.severity) > severity_order.index(max_sev):
                max_sev = det.severity
        return max_sev

    @property
    def all_mitre_techniques(self) -> List[str]:
        """Get all MITRE techniques from detections."""
        techniques = []
        for det in self.detections:
            techniques.extend(det.mitre_techniques)
        return list(set(techniques))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'alert_id': self.alert_id,
            'timestamp': self.timestamp,
            'severity': self.max_severity.value,
            'event': self.event.to_dict(),
            'detections': [d.to_dict() for d in self.detections],
            'mitre_techniques': self.all_mitre_techniques,
            'correlated_events': self.correlated_events,
            'recommended_actions': self.recommended_actions,
        }


class EventPublisher:
    """
    Unified event publisher that connects security events to detection engines.

    Maintains a queue of events and processes them through:
    - YARA engine (if available) - for pattern matching
    - Sigma engine (if available) - for log-based detection
    - MITRE ATT&CK detector (if available) - for technique identification
    - IOC feed manager (if available) - for IOC matching
    """

    def __init__(self):
        self._event_queue: queue.Queue = queue.Queue()
        self._alert_handlers: Dict[int, Callable[[SecurityAlert], None]] = {}  # Use dict for O(1) unregister
        self._event_handlers: Dict[int, Callable[[SecurityEvent], None]] = {}  # Use dict for O(1) unregister
        self._next_handler_id = 0
        self._handler_lock = threading.Lock()  # Protect handler modifications
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None

        # Detection engines (lazy loaded)
        self._yara_engine = None
        self._sigma_engine = None
        self._mitre_detector = None
        self._ioc_manager = None

        # Event correlation
        self._recent_events: List[SecurityEvent] = []
        self._max_correlation_window = 300  # 5 minutes

        # Statistics
        self._events_published = 0
        self._alerts_generated = 0
        self._lock = threading.Lock()

        logger.info("EventPublisher initialized")

    def _load_detection_engines(self) -> None:
        """Lazy-load detection engines."""
        try:
            from .yara_engine import YARAEngine
            self._yara_engine = YARAEngine()
            logger.info("YARA engine loaded")
        except ImportError:
            logger.debug("YARA engine not available")

        try:
            from .sigma_engine import SigmaEngine
            self._sigma_engine = SigmaEngine()
            logger.info("Sigma engine loaded")
        except ImportError:
            logger.debug("Sigma engine not available")

        try:
            from .mitre_attack import MITREDetector
            self._mitre_detector = MITREDetector()
            logger.info("MITRE ATT&CK detector loaded")
        except ImportError:
            logger.debug("MITRE detector not available")

        try:
            from .ioc_feeds import IOCFeedManager
            self._ioc_manager = IOCFeedManager()
            logger.info("IOC Feed Manager loaded")
        except ImportError:
            logger.debug("IOC Feed Manager not available")

    def start(self) -> None:
        """Start the event processing worker."""
        if self._running:
            return

        self._load_detection_engines()
        self._running = True
        self._worker_thread = threading.Thread(
            target=self._process_events,
            daemon=True,
        )
        self._worker_thread.start()
        logger.info("EventPublisher started")

    def stop(self) -> None:
        """Stop the event processing worker and cleanup resources."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
        # Clear handlers to prevent memory leaks
        with self._handler_lock:
            self._alert_handlers.clear()
            self._event_handlers.clear()
        logger.info("EventPublisher stopped")

    def register_alert_handler(self, handler: Callable[[SecurityAlert], None]) -> int:
        """Register a handler for security alerts.

        Returns:
            Handler ID that can be used to unregister the handler
        """
        with self._handler_lock:
            handler_id = self._next_handler_id
            self._next_handler_id += 1
            self._alert_handlers[handler_id] = handler
            return handler_id

    def unregister_alert_handler(self, handler_id: int) -> bool:
        """Unregister a previously registered alert handler.

        Args:
            handler_id: The ID returned from register_alert_handler

        Returns:
            True if handler was found and removed, False otherwise
        """
        with self._handler_lock:
            if handler_id in self._alert_handlers:
                del self._alert_handlers[handler_id]
                return True
            return False

    def register_event_handler(self, handler: Callable[[SecurityEvent], None]) -> int:
        """Register a handler for raw security events.

        Returns:
            Handler ID that can be used to unregister the handler
        """
        with self._handler_lock:
            handler_id = self._next_handler_id
            self._next_handler_id += 1
            self._event_handlers[handler_id] = handler
            return handler_id

    def unregister_event_handler(self, handler_id: int) -> bool:
        """Unregister a previously registered event handler.

        Args:
            handler_id: The ID returned from register_event_handler

        Returns:
            True if handler was found and removed, False otherwise
        """
        with self._handler_lock:
            if handler_id in self._event_handlers:
                del self._event_handlers[handler_id]
                return True
            return False

    def publish_event(self, event: SecurityEvent) -> None:
        """Publish a security event for processing."""
        self._event_queue.put(event)
        with self._lock:
            self._events_published += 1

        # Call raw event handlers (copy to avoid modification during iteration)
        with self._handler_lock:
            handlers = list(self._event_handlers.values())
        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                logger.warning(f"Event handler failed: {e}")

    def publish_tripwire_event(self, violation: Any) -> None:
        """Publish a tripwire violation event."""
        event = SecurityEvent.from_tripwire(violation)
        self.publish_event(event)
        logger.info(f"Published tripwire event: {event.event_id}")

    def publish_mode_change(
        self,
        old_mode: str,
        new_mode: str,
        reason: str,
        operator: str,
    ) -> None:
        """Publish a mode change event."""
        event = SecurityEvent(
            event_id=f"mode_{int(time.time() * 1000)}",
            event_type=EventType.MODE_CHANGE,
            timestamp=datetime.utcnow().isoformat() + 'Z',
            severity=AlertSeverity.MEDIUM,
            source="policy_engine",
            details=f"Mode changed from {old_mode} to {new_mode}: {reason}",
            metadata={
                'old_mode': old_mode,
                'new_mode': new_mode,
                'reason': reason,
                'operator': operator,
            },
        )
        self.publish_event(event)

    def publish_lockdown(self, reason: str, trigger: str) -> None:
        """Publish a lockdown event."""
        event = SecurityEvent(
            event_id=f"lock_{int(time.time() * 1000)}",
            event_type=EventType.LOCKDOWN,
            timestamp=datetime.utcnow().isoformat() + 'Z',
            severity=AlertSeverity.EMERGENCY,
            source="lockdown_manager",
            details=f"LOCKDOWN triggered: {reason}",
            metadata={
                'reason': reason,
                'trigger': trigger,
            },
        )
        self.publish_event(event)

    def publish_sandbox_event(
        self,
        sandbox_id: str,
        event_type: EventType,
        details: str,
        severity: AlertSeverity = AlertSeverity.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Publish a sandbox-related security event."""
        event = SecurityEvent(
            event_id=f"sbx_{int(time.time() * 1000)}",
            event_type=event_type,
            timestamp=datetime.utcnow().isoformat() + 'Z',
            severity=severity,
            source=f"sandbox:{sandbox_id}",
            details=details,
            metadata=metadata or {},
        )
        self.publish_event(event)

    def _process_events(self) -> None:
        """Worker thread: process events through detection engines."""
        while self._running:
            try:
                # Get event with timeout
                try:
                    event = self._event_queue.get(timeout=1.0)
                except queue.Empty:
                    continue

                # Add to recent events for correlation
                self._add_to_correlation_window(event)

                # Run through detection engines
                detections = self._run_detections(event)

                # If any detection matched, create alert
                if any(d.matched for d in detections):
                    alert = self._create_alert(event, detections)
                    self._emit_alert(alert)

            except Exception as e:
                logger.error(f"Error processing event: {e}")

    def _add_to_correlation_window(self, event: SecurityEvent) -> None:
        """Add event to correlation window and prune old events."""
        now = time.time()
        cutoff = now - self._max_correlation_window

        # Parse timestamps and prune old events
        self._recent_events = [
            e for e in self._recent_events
            if self._parse_timestamp(e.timestamp) > cutoff
        ]

        self._recent_events.append(event)

    def _parse_timestamp(self, ts: str) -> float:
        """Parse ISO timestamp to epoch seconds."""
        try:
            dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
            return dt.timestamp()
        except Exception:
            return time.time()

    def _run_detections(self, event: SecurityEvent) -> List[DetectionResult]:
        """Run event through all detection engines."""
        results = []

        # YARA detection (if we have raw data)
        if self._yara_engine and event.raw_data:
            try:
                yara_result = self._yara_engine.scan_data(event.raw_data)
                if yara_result.matches:
                    for match in yara_result.matches:
                        results.append(DetectionResult(
                            engine="yara",
                            matched=True,
                            rule_id=match.rule_name,
                            rule_name=match.rule_name,
                            severity=self._yara_severity_to_alert(match.metadata.get('severity', 'medium')),
                            description=match.metadata.get('description', ''),
                            raw_match=match,
                        ))
            except Exception as e:
                logger.debug(f"YARA scan failed: {e}")

        # Sigma detection (log-based)
        if self._sigma_engine:
            try:
                log_entry = event.to_log_entry()
                sigma_matches = self._sigma_engine.match_log_entry(log_entry)
                for match in sigma_matches:
                    results.append(DetectionResult(
                        engine="sigma",
                        matched=True,
                        rule_id=match.rule_id,
                        rule_name=match.rule_name,
                        severity=self._sigma_level_to_severity(match.level),
                        description=match.description,
                        mitre_tactics=match.mitre_tactics if hasattr(match, 'mitre_tactics') else [],
                        mitre_techniques=match.mitre_techniques if hasattr(match, 'mitre_techniques') else [],
                        raw_match=match,
                    ))
            except Exception as e:
                logger.debug(f"Sigma matching failed: {e}")

        # MITRE ATT&CK detection
        if self._mitre_detector:
            try:
                attack_matches = self._mitre_detector.detect_techniques(event.to_dict())
                for match in attack_matches:
                    results.append(DetectionResult(
                        engine="mitre",
                        matched=True,
                        rule_id=match.technique_id,
                        rule_name=match.technique_name,
                        severity=AlertSeverity.HIGH,
                        description=match.description,
                        mitre_tactics=[match.tactic.value if hasattr(match.tactic, 'value') else str(match.tactic)],
                        mitre_techniques=[match.technique_id],
                        raw_match=match,
                    ))
            except Exception as e:
                logger.debug(f"MITRE detection failed: {e}")

        # IOC matching
        if self._ioc_manager:
            try:
                # Extract potential IOCs from event
                iocs_to_check = self._extract_iocs(event)
                for ioc_value, ioc_type in iocs_to_check:
                    ioc_matches = self._ioc_manager.check_ioc(ioc_value, ioc_type)
                    for match in ioc_matches:
                        results.append(DetectionResult(
                            engine="ioc",
                            matched=True,
                            rule_id=match.feed_name,
                            rule_name=f"IOC: {ioc_value}",
                            severity=AlertSeverity.HIGH,
                            description=match.description,
                            ioc_matches=[ioc_value],
                            raw_match=match,
                        ))
            except Exception as e:
                logger.debug(f"IOC matching failed: {e}")

        return results

    def _extract_iocs(self, event: SecurityEvent) -> List[tuple]:
        """Extract potential IOCs from event for matching."""
        iocs = []

        # Look for IPs in metadata
        metadata = event.metadata
        for key in ['source_ip', 'destination_ip', 'ip', 'remote_ip']:
            if key in metadata:
                iocs.append((metadata[key], 'ip'))

        # Look for domains
        for key in ['domain', 'hostname', 'host']:
            if key in metadata:
                iocs.append((metadata[key], 'domain'))

        # Look for hashes
        for key in ['file_hash', 'hash', 'sha256', 'md5']:
            if key in metadata:
                iocs.append((metadata[key], 'hash'))

        return iocs

    def _yara_severity_to_alert(self, yara_sev: str) -> AlertSeverity:
        """Convert YARA severity to AlertSeverity."""
        mapping = {
            'low': AlertSeverity.LOW,
            'medium': AlertSeverity.MEDIUM,
            'high': AlertSeverity.HIGH,
            'critical': AlertSeverity.CRITICAL,
        }
        return mapping.get(yara_sev.lower(), AlertSeverity.MEDIUM)

    def _sigma_level_to_severity(self, sigma_level: str) -> AlertSeverity:
        """Convert Sigma level to AlertSeverity."""
        mapping = {
            'informational': AlertSeverity.INFO,
            'low': AlertSeverity.LOW,
            'medium': AlertSeverity.MEDIUM,
            'high': AlertSeverity.HIGH,
            'critical': AlertSeverity.CRITICAL,
        }
        return mapping.get(sigma_level.lower(), AlertSeverity.MEDIUM)

    def _create_alert(
        self,
        event: SecurityEvent,
        detections: List[DetectionResult],
    ) -> SecurityAlert:
        """Create a security alert from event and detections."""
        matched_detections = [d for d in detections if d.matched]

        # Find correlated events
        correlated = self._find_correlated_events(event)

        # Generate recommended actions
        actions = self._generate_recommendations(event, matched_detections)

        alert = SecurityAlert(
            alert_id=f"alert_{int(time.time() * 1000)}",
            timestamp=datetime.utcnow().isoformat() + 'Z',
            event=event,
            detections=matched_detections,
            correlated_events=[e.event_id for e in correlated],
            recommended_actions=actions,
        )

        with self._lock:
            self._alerts_generated += 1

        return alert

    def _find_correlated_events(self, event: SecurityEvent) -> List[SecurityEvent]:
        """Find events that might be correlated with this one."""
        correlated = []

        for recent in self._recent_events:
            if recent.event_id == event.event_id:
                continue

            # Same source within window
            if recent.source == event.source:
                correlated.append(recent)

            # Same type within window
            elif recent.event_type == event.event_type:
                correlated.append(recent)

        return correlated[:10]  # Limit to 10 correlated events

    def _generate_recommendations(
        self,
        event: SecurityEvent,
        detections: List[DetectionResult],
    ) -> List[str]:
        """Generate recommended actions based on event and detections."""
        recommendations = []

        # Based on event type
        if event.event_type == EventType.TRIPWIRE:
            recommendations.append("Review tripwire violation details")
            recommendations.append("Verify system integrity")
            recommendations.append("Check for unauthorized changes")

        if event.event_type == EventType.LOCKDOWN:
            recommendations.append("Initiate incident response procedure")
            recommendations.append("Preserve system state for forensics")
            recommendations.append("Notify security team immediately")

        if event.event_type == EventType.SANDBOX_ESCAPE:
            recommendations.append("Terminate affected sandbox immediately")
            recommendations.append("Review sandbox configuration")
            recommendations.append("Check for privilege escalation")

        # Based on MITRE techniques detected
        for det in detections:
            if 'T1059' in det.mitre_techniques:  # Command and Scripting Interpreter
                recommendations.append("Review command execution logs")
            if 'T1055' in det.mitre_techniques:  # Process Injection
                recommendations.append("Investigate process memory for injection")
            if 'T1003' in det.mitre_techniques:  # Credential Dumping
                recommendations.append("Rotate affected credentials immediately")

        # Based on severity
        if event.severity in (AlertSeverity.CRITICAL, AlertSeverity.EMERGENCY):
            recommendations.append("Escalate to security leadership")

        return list(set(recommendations))  # Deduplicate

    def _emit_alert(self, alert: SecurityAlert) -> None:
        """Emit alert to all registered handlers."""
        logger.warning(
            f"Security Alert [{alert.max_severity.value.upper()}]: "
            f"{alert.event.details} "
            f"(techniques: {', '.join(alert.all_mitre_techniques) or 'none'})"
        )

        # Copy handlers to avoid modification during iteration
        with self._handler_lock:
            handlers = list(self._alert_handlers.values())
        for handler in handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Alert handler failed: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get publisher statistics."""
        with self._lock:
            return {
                'events_published': self._events_published,
                'alerts_generated': self._alerts_generated,
                'events_in_queue': self._event_queue.qsize(),
                'recent_events': len(self._recent_events),
                'engines_loaded': {
                    'yara': self._yara_engine is not None,
                    'sigma': self._sigma_engine is not None,
                    'mitre': self._mitre_detector is not None,
                    'ioc': self._ioc_manager is not None,
                },
            }


# Global publisher instance
_global_publisher: Optional[EventPublisher] = None
_publisher_lock = threading.Lock()


def get_event_publisher() -> EventPublisher:
    """Get the global event publisher."""
    global _global_publisher

    if _global_publisher is None:
        with _publisher_lock:
            if _global_publisher is None:
                _global_publisher = EventPublisher()

    return _global_publisher


def configure_event_publisher() -> EventPublisher:
    """Configure and start the global event publisher."""
    publisher = get_event_publisher()
    publisher.start()
    return publisher


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    print("Testing Event Publisher...")

    publisher = EventPublisher()

    # Register alert handler
    def on_alert(alert):
        print(f"ALERT: {alert.alert_id} - {alert.event.details}")
        print(f"  Severity: {alert.max_severity.value}")
        print(f"  Detections: {len(alert.detections)}")

    publisher.register_alert_handler(on_alert)

    # Start publisher
    publisher.start()

    # Publish test events
    publisher.publish_lockdown("Test lockdown", "manual")

    class MockViolation:
        violation_type = type('obj', (object,), {'value': 'network_in_airgap'})()
        details = "Network activity detected in AIRGAP mode"

    publisher.publish_tripwire_event(MockViolation())

    # Give time for processing
    time.sleep(2)

    # Print stats
    print(f"\nStatistics: {publisher.get_statistics()}")

    publisher.stop()
    print("\nEvent Publisher test complete.")
