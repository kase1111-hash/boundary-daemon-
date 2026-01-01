"""
SIEM Integration Module - Security Information and Event Management Integration

Provides comprehensive security event forwarding to SIEM systems with:
- CEF (Common Event Format) support
- LEEF (Log Event Extended Format) support
- JSON structured logging
- Syslog forwarding (RFC 5424)
- Event correlation and aggregation
- Alert escalation
- Configurable severity mapping

Supported SIEM Systems:
- Splunk (via HEC or syslog)
- IBM QRadar (via LEEF)
- ArcSight (via CEF)
- Elastic SIEM (via JSON)
- Any syslog-compatible system

Security Note:
    This module is designed to complement, not replace, proper security controls.
    SIEM integration provides visibility and detection but not prevention.
"""

import json
import logging
import hashlib
import socket
import ssl
import threading
import time
import queue
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


class SIEMFormat(Enum):
    """Output format for SIEM integration."""
    JSON = "json"           # Structured JSON (Elastic, Splunk)
    CEF = "cef"             # Common Event Format (ArcSight)
    LEEF = "leef"           # Log Event Extended Format (QRadar)
    SYSLOG = "syslog"       # RFC 5424 syslog


class SIEMTransport(Enum):
    """Transport protocol for SIEM forwarding."""
    UDP = "udp"
    TCP = "tcp"
    TLS = "tls"
    HTTP = "http"           # For Splunk HEC
    HTTPS = "https"


class SecurityEventSeverity(IntEnum):
    """CEF/SIEM severity levels (0-10 scale)."""
    UNKNOWN = 0
    LOW = 1
    LOW_MEDIUM = 2
    MEDIUM = 3
    MEDIUM_HIGH = 4
    HIGH = 5
    HIGH_CRITICAL = 6
    CRITICAL = 7
    CRITICAL_EMERGENCY = 8
    EMERGENCY = 9
    CATASTROPHIC = 10


class SecurityEventCategory(Enum):
    """Categories for security events."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    POLICY_VIOLATION = "policy_violation"
    DATA_ACCESS = "data_access"
    DATA_EXFILTRATION = "data_exfiltration"
    CONFIGURATION_CHANGE = "configuration_change"
    MODE_TRANSITION = "mode_transition"
    TRIPWIRE_TRIGGERED = "tripwire_triggered"
    INTEGRITY_VIOLATION = "integrity_violation"
    INJECTION_ATTEMPT = "injection_attempt"
    RATE_LIMIT = "rate_limit"
    ANOMALY = "anomaly"
    SYSTEM_ERROR = "system_error"
    AUDIT = "audit"


@dataclass
class SecurityEvent:
    """
    Structured security event for SIEM integration.

    Follows the structure needed for CEF, LEEF, and JSON formats.
    """
    # Core identification
    event_id: str
    timestamp: str

    # Classification
    category: SecurityEventCategory
    severity: SecurityEventSeverity
    event_type: str

    # Source information
    source_component: str
    source_host: str = ""
    source_ip: str = ""
    source_user: str = ""
    source_process: str = ""

    # Target/destination (if applicable)
    target_resource: str = ""
    target_action: str = ""

    # Event details
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    # Correlation
    correlation_id: str = ""
    parent_event_id: str = ""
    session_id: str = ""

    # Outcome
    outcome: str = "unknown"  # success, failure, unknown
    reason: str = ""

    # Additional context
    mode: str = ""
    operator: str = ""
    tags: List[str] = field(default_factory=list)

    # Raw data (for forensics)
    raw_data: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data['category'] = self.category.value
        data['severity'] = int(self.severity)
        return data


@dataclass
class SIEMConfig:
    """Configuration for SIEM integration."""
    # Connection settings
    enabled: bool = True
    host: str = "localhost"
    port: int = 514
    transport: SIEMTransport = SIEMTransport.TLS
    format: SIEMFormat = SIEMFormat.JSON

    # TLS settings
    tls_verify: bool = True
    tls_ca_cert: Optional[str] = None
    tls_client_cert: Optional[str] = None
    tls_client_key: Optional[str] = None

    # HTTP settings (for Splunk HEC)
    http_token: Optional[str] = None
    http_endpoint: str = "/services/collector/event"

    # Buffering
    buffer_size: int = 1000
    flush_interval: float = 5.0
    retry_count: int = 3
    retry_delay: float = 1.0

    # Filtering
    min_severity: SecurityEventSeverity = SecurityEventSeverity.LOW
    include_categories: Optional[Set[SecurityEventCategory]] = None
    exclude_categories: Optional[Set[SecurityEventCategory]] = None

    # Enrichment
    add_hostname: bool = True
    add_ip_address: bool = True
    add_process_info: bool = True

    # CEF/LEEF specific
    vendor: str = "BoundaryDaemon"
    product: str = "AgentSmith"
    version: str = "1.0"

    # Facility for syslog (RFC 5424)
    syslog_facility: int = 16  # LOCAL0


class SIEMConnector:
    """
    Connector for forwarding events to SIEM systems.

    Handles connection management, buffering, and retry logic.
    """

    def __init__(self, config: SIEMConfig):
        self.config = config
        self._socket: Optional[socket.socket] = None
        self._buffer: queue.Queue = queue.Queue(maxsize=config.buffer_size)
        self._running = False
        self._flush_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._stats = {
            'events_sent': 0,
            'events_failed': 0,
            'events_dropped': 0,
            'reconnections': 0,
            'last_error': None,
        }

    def connect(self) -> Tuple[bool, str]:
        """Establish connection to SIEM."""
        if not self.config.enabled:
            return True, "SIEM integration disabled"

        try:
            if self.config.transport in (SIEMTransport.HTTP, SIEMTransport.HTTPS):
                # HTTP connections are made per-request
                return True, "HTTP mode - connections made per request"

            # Create socket
            if self.config.transport == SIEMTransport.UDP:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(10.0)
                self._socket.connect((self.config.host, self.config.port))

                if self.config.transport == SIEMTransport.TLS:
                    context = ssl.create_default_context()

                    if self.config.tls_ca_cert:
                        context.load_verify_locations(self.config.tls_ca_cert)

                    if self.config.tls_client_cert and self.config.tls_client_key:
                        context.load_cert_chain(
                            self.config.tls_client_cert,
                            self.config.tls_client_key
                        )

                    if not self.config.tls_verify:
                        logger.warning(
                            "SECURITY WARNING: TLS verification disabled for SIEM. "
                            "This allows MITM attacks on security event transmission."
                        )
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE

                    self._socket = context.wrap_socket(
                        self._socket,
                        server_hostname=self.config.host
                    )

            return True, f"Connected to SIEM at {self.config.host}:{self.config.port}"

        except Exception as e:
            self._stats['last_error'] = str(e)
            return False, f"Failed to connect to SIEM: {e}"

    def disconnect(self):
        """Close SIEM connection."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

    def start(self):
        """Start background flush thread."""
        if self._running:
            return

        self._running = True
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()

    def stop(self):
        """Stop background flush thread."""
        self._running = False
        if self._flush_thread:
            self._flush_thread.join(timeout=5.0)
        self.flush()
        self.disconnect()

    def _flush_loop(self):
        """Background thread to periodically flush buffer."""
        while self._running:
            time.sleep(self.config.flush_interval)
            try:
                self.flush()
            except Exception as e:
                logger.error(f"Error in SIEM flush loop: {e}")

    def send_event(self, event: SecurityEvent) -> bool:
        """
        Queue an event for sending to SIEM.

        Returns True if queued, False if dropped due to full buffer.
        """
        if not self.config.enabled:
            return True

        # Filter by severity
        if event.severity < self.config.min_severity:
            return True

        # Filter by category
        if self.config.include_categories:
            if event.category not in self.config.include_categories:
                return True
        if self.config.exclude_categories:
            if event.category in self.config.exclude_categories:
                return True

        try:
            self._buffer.put_nowait(event)
            return True
        except queue.Full:
            self._stats['events_dropped'] += 1
            logger.warning("SIEM buffer full, event dropped")
            return False

    def flush(self) -> int:
        """Flush buffered events to SIEM. Returns count of events sent."""
        if not self.config.enabled:
            return 0

        events = []
        while not self._buffer.empty():
            try:
                events.append(self._buffer.get_nowait())
            except queue.Empty:
                break

        if not events:
            return 0

        sent = 0
        for event in events:
            if self._send_single_event(event):
                sent += 1
                self._stats['events_sent'] += 1
            else:
                self._stats['events_failed'] += 1

        return sent

    def _send_single_event(self, event: SecurityEvent) -> bool:
        """Send a single event to SIEM."""
        try:
            message = self._format_event(event)

            if self.config.transport in (SIEMTransport.HTTP, SIEMTransport.HTTPS):
                return self._send_http(message)
            else:
                return self._send_socket(message)

        except Exception as e:
            self._stats['last_error'] = str(e)
            logger.error(f"Failed to send event to SIEM: {e}")
            return False

    def _format_event(self, event: SecurityEvent) -> str:
        """Format event according to configured format."""
        if self.config.format == SIEMFormat.JSON:
            return self._format_json(event)
        elif self.config.format == SIEMFormat.CEF:
            return self._format_cef(event)
        elif self.config.format == SIEMFormat.LEEF:
            return self._format_leef(event)
        else:
            return self._format_syslog(event)

    def _format_json(self, event: SecurityEvent) -> str:
        """Format as structured JSON."""
        data = event.to_dict()
        data['@timestamp'] = event.timestamp
        data['host'] = {'name': event.source_host or socket.gethostname()}
        data['observer'] = {
            'vendor': self.config.vendor,
            'product': self.config.product,
            'version': self.config.version,
        }
        return json.dumps(data)

    def _format_cef(self, event: SecurityEvent) -> str:
        """Format as CEF (Common Event Format) for ArcSight."""
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

        # Map severity to CEF scale (0-10)
        severity = int(event.severity)

        # Build extension (key=value pairs)
        ext_parts = []
        if event.source_ip:
            ext_parts.append(f"src={event.source_ip}")
        if event.source_host:
            ext_parts.append(f"shost={event.source_host}")
        if event.source_user:
            ext_parts.append(f"suser={event.source_user}")
        if event.target_resource:
            ext_parts.append(f"dst={event.target_resource}")
        if event.outcome:
            ext_parts.append(f"outcome={event.outcome}")
        if event.reason:
            ext_parts.append(f"reason={self._cef_escape(event.reason)}")
        if event.message:
            ext_parts.append(f"msg={self._cef_escape(event.message)}")
        if event.mode:
            ext_parts.append(f"cs1={event.mode}")
            ext_parts.append("cs1Label=SecurityMode")
        if event.correlation_id:
            ext_parts.append(f"externalId={event.correlation_id}")

        extension = " ".join(ext_parts)

        return (
            f"CEF:0|{self.config.vendor}|{self.config.product}|{self.config.version}|"
            f"{event.event_type}|{event.category.value}|{severity}|{extension}"
        )

    def _format_leef(self, event: SecurityEvent) -> str:
        """Format as LEEF (Log Event Extended Format) for QRadar."""
        # LEEF:Version|Vendor|Product|Version|EventID|

        # Build attributes
        attrs = []
        attrs.append(f"cat={event.category.value}")
        attrs.append(f"sev={int(event.severity)}")
        if event.source_ip:
            attrs.append(f"src={event.source_ip}")
        if event.source_host:
            attrs.append(f"srcHostName={event.source_host}")
        if event.source_user:
            attrs.append(f"usrName={event.source_user}")
        if event.target_resource:
            attrs.append(f"dst={event.target_resource}")
        if event.outcome:
            attrs.append(f"outcome={event.outcome}")
        if event.message:
            attrs.append(f"msg={self._leef_escape(event.message)}")
        if event.mode:
            attrs.append(f"securityMode={event.mode}")

        attribute_string = "\t".join(attrs)

        return (
            f"LEEF:2.0|{self.config.vendor}|{self.config.product}|{self.config.version}|"
            f"{event.event_type}|{attribute_string}"
        )

    def _format_syslog(self, event: SecurityEvent) -> str:
        """Format as RFC 5424 syslog."""
        # Map severity to syslog severity (0-7)
        syslog_sev = min(7, max(0, 7 - (int(event.severity) // 2)))
        priority = (self.config.syslog_facility * 8) + syslog_sev

        timestamp = event.timestamp
        hostname = event.source_host or socket.gethostname()
        app_name = self.config.product
        proc_id = "-"
        msg_id = event.event_type

        # Structured data
        sd = f'[boundary@{hash(self.config.vendor) % 65535} '
        sd += f'cat="{event.category.value}" '
        sd += f'severity="{int(event.severity)}" '
        if event.mode:
            sd += f'mode="{event.mode}" '
        if event.outcome:
            sd += f'outcome="{event.outcome}" '
        sd += ']'

        message = event.message or f"{event.category.value}: {event.event_type}"

        return f"<{priority}>1 {timestamp} {hostname} {app_name} {proc_id} {msg_id} {sd} {message}"

    def _cef_escape(self, value: str) -> str:
        """Escape value for CEF format."""
        return value.replace('\\', '\\\\').replace('=', '\\=').replace('\n', '\\n')

    def _leef_escape(self, value: str) -> str:
        """Escape value for LEEF format."""
        return value.replace('\t', ' ').replace('\n', ' ')

    def _send_socket(self, message: str) -> bool:
        """Send message via socket."""
        if not self._socket:
            success, _ = self.connect()
            if not success:
                return False

        try:
            data = (message + '\n').encode('utf-8')

            if self.config.transport == SIEMTransport.UDP:
                self._socket.sendto(data, (self.config.host, self.config.port))
            else:
                self._socket.sendall(data)

            return True

        except (socket.error, BrokenPipeError, ConnectionResetError) as e:
            logger.warning(f"Socket error, reconnecting: {e}")
            self.disconnect()
            self._stats['reconnections'] += 1

            # Retry once
            success, _ = self.connect()
            if success and self._socket:
                try:
                    self._socket.sendall(data)
                    return True
                except Exception:
                    pass
            return False

    def _send_http(self, message: str) -> bool:
        """Send message via HTTP (Splunk HEC)."""
        import urllib.request
        import urllib.error

        try:
            url = f"{self.config.transport.value}://{self.config.host}:{self.config.port}{self.config.http_endpoint}"

            # Wrap in Splunk HEC format
            payload = json.dumps({'event': json.loads(message)})

            request = urllib.request.Request(
                url,
                data=payload.encode('utf-8'),
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Splunk {self.config.http_token}' if self.config.http_token else '',
                }
            )

            # Handle TLS verification
            if not self.config.tls_verify:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            else:
                context = None

            with urllib.request.urlopen(request, timeout=10, context=context) as response:
                return response.status == 200

        except urllib.error.URLError as e:
            logger.error(f"HTTP error sending to SIEM: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get connector statistics."""
        return {
            **self._stats.copy(),
            'buffer_size': self._buffer.qsize(),
            'buffer_capacity': self.config.buffer_size,
            'connected': self._socket is not None,
        }


class SIEMIntegration:
    """
    High-level SIEM integration manager.

    Provides:
    - Event creation helpers
    - Automatic enrichment
    - Event correlation
    - Alert management

    Usage:
        siem = SIEMIntegration(config)
        siem.start()

        # Log security event
        siem.log_authentication_failure(
            user="alice",
            reason="invalid_password",
            source_ip="192.168.1.100"
        )

        # Log policy violation
        siem.log_policy_violation(
            violation_type="unauthorized_data_access",
            details={"resource": "secret_file.txt"}
        )
    """

    def __init__(
        self,
        config: Optional[SIEMConfig] = None,
        event_logger=None,
    ):
        self.config = config or SIEMConfig()
        self.connector = SIEMConnector(self.config)
        self._event_logger = event_logger
        self._correlation_window: Dict[str, List[SecurityEvent]] = {}
        self._alert_callbacks: Dict[int, Callable[[SecurityEvent], None]] = {}
        self._next_callback_id = 0
        self._callback_lock = threading.Lock()
        self._lock = threading.Lock()

        # Auto-detected context
        self._hostname = socket.gethostname()
        try:
            self._ip_address = socket.gethostbyname(self._hostname)
        except socket.gaierror:
            self._ip_address = "127.0.0.1"

    def start(self) -> Tuple[bool, str]:
        """Start SIEM integration."""
        success, message = self.connector.connect()
        if success:
            self.connector.start()
        return success, message

    def stop(self):
        """Stop SIEM integration and cleanup resources."""
        self.connector.stop()
        with self._callback_lock:
            self._alert_callbacks.clear()

    def register_alert_callback(self, callback: Callable[[SecurityEvent], None]) -> int:
        """Register callback for high-severity events.

        Returns:
            Callback ID that can be used to unregister the callback
        """
        with self._callback_lock:
            callback_id = self._next_callback_id
            self._next_callback_id += 1
            self._alert_callbacks[callback_id] = callback
            return callback_id

    def unregister_alert_callback(self, callback_id: int) -> bool:
        """Unregister a previously registered alert callback.

        Args:
            callback_id: The ID returned from register_alert_callback

        Returns:
            True if callback was found and removed, False otherwise
        """
        with self._callback_lock:
            if callback_id in self._alert_callbacks:
                del self._alert_callbacks[callback_id]
                return True
            return False

    def _create_event(
        self,
        category: SecurityEventCategory,
        severity: SecurityEventSeverity,
        event_type: str,
        message: str = "",
        details: Optional[Dict[str, Any]] = None,
        source_user: str = "",
        source_ip: str = "",
        target_resource: str = "",
        target_action: str = "",
        outcome: str = "unknown",
        reason: str = "",
        mode: str = "",
        operator: str = "",
        tags: Optional[List[str]] = None,
        correlation_id: str = "",
    ) -> SecurityEvent:
        """Create a security event with auto-enrichment."""
        event_id = hashlib.sha256(
            f"{time.time()}:{event_type}:{message}".encode()
        ).hexdigest()[:16]

        timestamp = datetime.now(timezone.utc).isoformat()

        event = SecurityEvent(
            event_id=event_id,
            timestamp=timestamp,
            category=category,
            severity=severity,
            event_type=event_type,
            source_component="boundary-daemon",
            source_host=self._hostname if self.config.add_hostname else "",
            source_ip=source_ip or (self._ip_address if self.config.add_ip_address else ""),
            source_user=source_user,
            source_process=str(os.getpid()) if self.config.add_process_info else "",
            target_resource=target_resource,
            target_action=target_action,
            message=message,
            details=details or {},
            correlation_id=correlation_id,
            outcome=outcome,
            reason=reason,
            mode=mode,
            operator=operator,
            tags=tags or [],
        )

        return event

    def _send_event(self, event: SecurityEvent):
        """Send event and trigger alerts if needed."""
        # Send to SIEM
        self.connector.send_event(event)

        # Trigger alert callbacks for high severity
        if event.severity >= SecurityEventSeverity.HIGH:
            with self._callback_lock:
                callbacks = list(self._alert_callbacks.values())
            for callback in callbacks:
                try:
                    callback(event)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")

        # Also log to event logger if available
        if self._event_logger:
            try:
                from daemon.event_logger import EventType
                self._event_logger.log_event(
                    event_type=EventType.SECURITY_VIOLATION
                        if event.severity >= SecurityEventSeverity.HIGH
                        else EventType.SECURITY_EVENT,
                    data=event.to_dict()
                )
            except Exception:
                pass

    # === Authentication Events ===

    def log_authentication_success(
        self,
        user: str,
        method: str = "token",
        source_ip: str = "",
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log successful authentication."""
        event = self._create_event(
            category=SecurityEventCategory.AUTHENTICATION,
            severity=SecurityEventSeverity.LOW,
            event_type="auth_success",
            message=f"User '{user}' authenticated successfully via {method}",
            source_user=user,
            source_ip=source_ip,
            outcome="success",
            details=details or {"method": method},
        )
        self._send_event(event)

    def log_authentication_failure(
        self,
        user: str = "",
        reason: str = "invalid_credentials",
        source_ip: str = "",
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log authentication failure."""
        event = self._create_event(
            category=SecurityEventCategory.AUTHENTICATION,
            severity=SecurityEventSeverity.MEDIUM,
            event_type="auth_failure",
            message=f"Authentication failed for user '{user}': {reason}",
            source_user=user,
            source_ip=source_ip,
            outcome="failure",
            reason=reason,
            details=details or {},
            tags=["authentication", "failure"],
        )
        self._send_event(event)

    def log_token_created(
        self,
        token_id: str,
        token_name: str,
        created_by: str,
        capabilities: List[str],
    ):
        """Log API token creation."""
        event = self._create_event(
            category=SecurityEventCategory.AUTHORIZATION,
            severity=SecurityEventSeverity.MEDIUM,
            event_type="token_created",
            message=f"API token '{token_name}' created by {created_by}",
            source_user=created_by,
            outcome="success",
            details={
                "token_id": token_id,
                "token_name": token_name,
                "capabilities": capabilities,
            },
        )
        self._send_event(event)

    def log_token_revoked(
        self,
        token_id: str,
        revoked_by: str,
        reason: str = "",
    ):
        """Log API token revocation."""
        event = self._create_event(
            category=SecurityEventCategory.AUTHORIZATION,
            severity=SecurityEventSeverity.MEDIUM,
            event_type="token_revoked",
            message=f"API token '{token_id}' revoked by {revoked_by}",
            source_user=revoked_by,
            outcome="success",
            reason=reason,
            details={"token_id": token_id},
        )
        self._send_event(event)

    # === Authorization Events ===

    def log_authorization_denied(
        self,
        user: str,
        resource: str,
        action: str,
        reason: str = "",
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log authorization denial."""
        event = self._create_event(
            category=SecurityEventCategory.AUTHORIZATION,
            severity=SecurityEventSeverity.MEDIUM,
            event_type="authz_denied",
            message=f"Access denied: {user} attempted {action} on {resource}",
            source_user=user,
            target_resource=resource,
            target_action=action,
            outcome="failure",
            reason=reason,
            details=details or {},
            tags=["authorization", "denied"],
        )
        self._send_event(event)

    # === Policy Events ===

    def log_policy_violation(
        self,
        violation_type: str,
        severity: SecurityEventSeverity = SecurityEventSeverity.HIGH,
        details: Optional[Dict[str, Any]] = None,
        mode: str = "",
        user: str = "",
    ):
        """Log policy violation."""
        event = self._create_event(
            category=SecurityEventCategory.POLICY_VIOLATION,
            severity=severity,
            event_type=f"policy_violation_{violation_type}",
            message=f"Policy violation detected: {violation_type}",
            source_user=user,
            mode=mode,
            outcome="failure",
            details=details or {},
            tags=["policy", "violation"],
        )
        self._send_event(event)

    def log_mode_transition(
        self,
        from_mode: str,
        to_mode: str,
        operator: str,
        reason: str = "",
        success: bool = True,
    ):
        """Log security mode transition."""
        severity = SecurityEventSeverity.MEDIUM
        if to_mode.lower() in ("lockdown", "coldroom"):
            severity = SecurityEventSeverity.HIGH

        event = self._create_event(
            category=SecurityEventCategory.MODE_TRANSITION,
            severity=severity,
            event_type="mode_transition",
            message=f"Mode transition: {from_mode} -> {to_mode}",
            mode=to_mode,
            operator=operator,
            outcome="success" if success else "failure",
            reason=reason,
            details={
                "from_mode": from_mode,
                "to_mode": to_mode,
            },
        )
        self._send_event(event)

    # === Tripwire Events ===

    def log_tripwire_triggered(
        self,
        tripwire_type: str,
        severity: SecurityEventSeverity = SecurityEventSeverity.CRITICAL,
        details: Optional[Dict[str, Any]] = None,
        mode: str = "",
    ):
        """Log tripwire activation."""
        event = self._create_event(
            category=SecurityEventCategory.TRIPWIRE_TRIGGERED,
            severity=severity,
            event_type=f"tripwire_{tripwire_type}",
            message=f"TRIPWIRE TRIGGERED: {tripwire_type}",
            mode=mode,
            outcome="detected",
            details=details or {},
            tags=["tripwire", "alert", "critical"],
        )
        self._send_event(event)

    # === Data Access Events ===

    def log_data_access(
        self,
        resource: str,
        access_type: str,
        user: str = "",
        memory_class: int = 0,
        permitted: bool = True,
        reason: str = "",
    ):
        """Log data access attempt."""
        severity = SecurityEventSeverity.LOW if permitted else SecurityEventSeverity.MEDIUM
        if memory_class >= 4:  # SECRET or TOP_SECRET
            severity = SecurityEventSeverity.MEDIUM if permitted else SecurityEventSeverity.HIGH

        event = self._create_event(
            category=SecurityEventCategory.DATA_ACCESS,
            severity=severity,
            event_type=f"data_access_{access_type}",
            message=f"Data access: {access_type} on {resource}",
            source_user=user,
            target_resource=resource,
            target_action=access_type,
            outcome="success" if permitted else "denied",
            reason=reason,
            details={"memory_class": memory_class},
        )
        self._send_event(event)

    # === Injection/Attack Events ===

    def log_injection_attempt(
        self,
        injection_type: str,
        content_preview: str = "",
        source: str = "",
        source_ip: str = "",
        blocked: bool = True,
    ):
        """Log injection attempt detection."""
        event = self._create_event(
            category=SecurityEventCategory.INJECTION_ATTEMPT,
            severity=SecurityEventSeverity.HIGH,
            event_type=f"injection_{injection_type}",
            message=f"Injection attempt detected: {injection_type}",
            source_ip=source_ip,
            outcome="blocked" if blocked else "detected",
            details={
                "injection_type": injection_type,
                "source": source,
                "content_preview": content_preview[:100] if content_preview else "",
            },
            tags=["injection", "attack", injection_type],
        )
        self._send_event(event)

    # === Rate Limiting Events ===

    def log_rate_limit_exceeded(
        self,
        token_id: str = "",
        limit_type: str = "request",
        source_ip: str = "",
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log rate limit exceeded."""
        event = self._create_event(
            category=SecurityEventCategory.RATE_LIMIT,
            severity=SecurityEventSeverity.MEDIUM,
            event_type="rate_limit_exceeded",
            message=f"Rate limit exceeded: {limit_type}",
            source_ip=source_ip,
            outcome="blocked",
            details={
                "token_id": token_id,
                "limit_type": limit_type,
                **(details or {}),
            },
            tags=["rate_limit"],
        )
        self._send_event(event)

    # === Integrity Events ===

    def log_integrity_violation(
        self,
        violation_type: str,
        resource: str = "",
        expected: str = "",
        actual: str = "",
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log integrity violation."""
        event = self._create_event(
            category=SecurityEventCategory.INTEGRITY_VIOLATION,
            severity=SecurityEventSeverity.CRITICAL,
            event_type=f"integrity_{violation_type}",
            message=f"Integrity violation: {violation_type}",
            target_resource=resource,
            outcome="detected",
            details={
                "expected": expected,
                "actual": actual,
                **(details or {}),
            },
            tags=["integrity", "critical"],
        )
        self._send_event(event)

    # === Configuration Events ===

    def log_config_change(
        self,
        config_type: str,
        changed_by: str = "",
        old_value: str = "",
        new_value: str = "",
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log configuration change."""
        event = self._create_event(
            category=SecurityEventCategory.CONFIGURATION_CHANGE,
            severity=SecurityEventSeverity.MEDIUM,
            event_type=f"config_change_{config_type}",
            message=f"Configuration changed: {config_type}",
            source_user=changed_by,
            outcome="success",
            details={
                "old_value": old_value,
                "new_value": new_value,
                **(details or {}),
            },
        )
        self._send_event(event)

    # === Error Events ===

    def log_security_error(
        self,
        error_type: str,
        error_message: str,
        component: str = "",
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log security-related error."""
        event = self._create_event(
            category=SecurityEventCategory.SYSTEM_ERROR,
            severity=SecurityEventSeverity.HIGH,
            event_type=f"security_error_{error_type}",
            message=f"Security error: {error_message}",
            source_component=component or "boundary-daemon",
            outcome="error",
            details=details or {},
            tags=["error", "security"],
        )
        self._send_event(event)

    def get_stats(self) -> Dict[str, Any]:
        """Get SIEM integration statistics."""
        return {
            'connector': self.connector.get_stats(),
            'enabled': self.config.enabled,
            'format': self.config.format.value,
            'transport': self.config.transport.value,
            'target': f"{self.config.host}:{self.config.port}",
        }


# Import os for process ID
import os


# Singleton instance for global access
_siem_instance: Optional[SIEMIntegration] = None


def get_siem() -> Optional[SIEMIntegration]:
    """Get global SIEM integration instance."""
    return _siem_instance


def init_siem(config: Optional[SIEMConfig] = None, event_logger=None) -> SIEMIntegration:
    """Initialize global SIEM integration instance."""
    global _siem_instance
    _siem_instance = SIEMIntegration(config, event_logger)
    return _siem_instance


if __name__ == '__main__':
    print("Testing SIEM Integration Module...")

    # Create test config
    config = SIEMConfig(
        enabled=True,
        host="localhost",
        port=514,
        transport=SIEMTransport.UDP,
        format=SIEMFormat.JSON,
    )

    siem = SIEMIntegration(config)
    success, message = siem.start()
    print(f"SIEM Start: {success} - {message}")

    # Test events
    print("\nGenerating test events...")

    siem.log_authentication_failure(
        user="testuser",
        reason="invalid_password",
        source_ip="192.168.1.100"
    )

    siem.log_policy_violation(
        violation_type="unauthorized_network_access",
        details={"attempted_host": "external.com"}
    )

    siem.log_mode_transition(
        from_mode="OPEN",
        to_mode="RESTRICTED",
        operator="human",
        reason="User initiated"
    )

    siem.log_tripwire_triggered(
        tripwire_type="usb_insertion",
        details={"device": "/dev/sdb1"}
    )

    # Flush and get stats
    siem.connector.flush()
    stats = siem.get_stats()
    print(f"\nStats: {json.dumps(stats, indent=2)}")

    siem.stop()
    print("\nSIEM Integration test complete.")
