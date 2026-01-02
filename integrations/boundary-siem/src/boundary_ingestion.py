"""
Boundary-SIEM Event Ingestion

Enhanced integration for consuming events from the Boundary Daemon.
Supports CEF, LEEF, and JSON formats with proper correlation.
"""

import json
import logging
import os
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union
from queue import Queue
from threading import Thread

logger = logging.getLogger(__name__)


class EventFormat(Enum):
    """Supported event formats."""
    CEF = "cef"
    LEEF = "leef"
    JSON = "json"


class Severity(Enum):
    """CEF severity levels."""
    UNKNOWN = 0
    LOW = 3
    MEDIUM = 5
    HIGH = 7
    VERY_HIGH = 8
    CRITICAL = 10


@dataclass
class BoundaryEvent:
    """Parsed boundary daemon event."""
    event_id: str
    timestamp: datetime
    event_type: str
    severity: Severity
    mode: str
    description: str
    source_component: str
    data: Dict[str, Any] = field(default_factory=dict)
    hash_chain: Optional[str] = None
    signature: Optional[str] = None

    def to_cef(self) -> str:
        """Convert to CEF format."""
        cef_severity = self.severity.value
        extension = " ".join(
            f"{k}={v}" for k, v in self.data.items() if v is not None
        )
        return (
            f"CEF:0|AgentOS|BoundaryDaemon|1.0|{self.event_type}|"
            f"{self.description}|{cef_severity}|{extension}"
        )

    def to_leef(self) -> str:
        """Convert to LEEF format."""
        attrs = "|".join(f"{k}={v}" for k, v in self.data.items() if v is not None)
        return (
            f"LEEF:2.0|AgentOS|BoundaryDaemon|1.0|{self.event_type}|"
            f"sev={self.severity.value}|{attrs}"
        )

    def to_json(self) -> str:
        """Convert to JSON format."""
        return json.dumps({
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "severity": self.severity.name,
            "mode": self.mode,
            "description": self.description,
            "source": self.source_component,
            "data": self.data,
            "hash_chain": self.hash_chain,
            "signature": self.signature,
        })


def get_socket_path() -> str:
    """Get boundary daemon socket path."""
    paths = [
        os.environ.get('BOUNDARY_DAEMON_SOCKET'),
        '/var/run/boundary-daemon/boundary.sock',
        os.path.expanduser('~/.agent-os/api/boundary.sock'),
        './api/boundary.sock',
    ]
    for path in paths:
        if path and os.path.exists(path):
            return path
    return '/var/run/boundary-daemon/boundary.sock'


class BoundaryEventClient:
    """Client for retrieving events from boundary daemon."""

    def __init__(
        self,
        socket_path: Optional[str] = None,
        token: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.socket_path = socket_path or get_socket_path()
        self._token = token or os.environ.get('BOUNDARY_API_TOKEN')
        self.timeout = timeout

    def _send_request(self, command: str, params: Dict = None) -> Dict:
        """Send request to daemon."""
        request = {'command': command, 'params': params or {}}
        if self._token:
            request['token'] = self._token

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
            sock.sendall(json.dumps(request).encode('utf-8'))
            data = sock.recv(65536)
            return json.loads(data.decode('utf-8'))
        finally:
            sock.close()

    def get_events(
        self,
        count: int = 100,
        event_type: Optional[str] = None,
    ) -> List[BoundaryEvent]:
        """Retrieve recent events."""
        params = {'count': count}
        if event_type:
            params['event_type'] = event_type

        response = self._send_request('get_events', params)

        if not response.get('success'):
            return []

        events = []
        for event_data in response.get('events', []):
            try:
                events.append(self._parse_event(event_data))
            except Exception as e:
                logger.warning(f"Failed to parse event: {e}")

        return events

    def verify_log_integrity(self) -> tuple[bool, Optional[str]]:
        """Verify log integrity via hash chain."""
        response = self._send_request('verify_log')
        return response.get('valid', False), response.get('error')

    def get_status(self) -> Dict[str, Any]:
        """Get daemon status."""
        response = self._send_request('status')
        return response.get('status', {})

    def _parse_event(self, data: Dict) -> BoundaryEvent:
        """Parse event data into BoundaryEvent."""
        severity_map = {
            'info': Severity.LOW,
            'warning': Severity.MEDIUM,
            'error': Severity.HIGH,
            'critical': Severity.CRITICAL,
        }

        return BoundaryEvent(
            event_id=data.get('id', ''),
            timestamp=datetime.fromisoformat(data.get('timestamp', datetime.now().isoformat())),
            event_type=data.get('event_type', 'UNKNOWN'),
            severity=severity_map.get(data.get('severity', 'info'), Severity.UNKNOWN),
            mode=data.get('mode', 'unknown'),
            description=data.get('description', ''),
            source_component=data.get('source', 'boundary-daemon'),
            data=data.get('data', {}),
            hash_chain=data.get('hash_chain'),
            signature=data.get('signature'),
        )


class EventIngestionPipeline:
    """
    Pipeline for ingesting events from boundary daemon into SIEM.

    Features:
    - Continuous polling with configurable interval
    - Event format conversion (CEF/LEEF/JSON)
    - Buffering with backpressure
    - Hash chain verification
    """

    def __init__(
        self,
        client: Optional[BoundaryEventClient] = None,
        output_format: EventFormat = EventFormat.CEF,
        buffer_size: int = 100000,
        poll_interval: float = 1.0,
    ):
        self.client = client or BoundaryEventClient()
        self.output_format = output_format
        self.buffer_size = buffer_size
        self.poll_interval = poll_interval

        self.event_queue: Queue[BoundaryEvent] = Queue(maxsize=buffer_size)
        self._running = False
        self._poll_thread: Optional[Thread] = None
        self._handlers: List[Callable[[BoundaryEvent], None]] = []
        self._last_event_id: Optional[str] = None

    def add_handler(self, handler: Callable[[BoundaryEvent], None]) -> None:
        """Add event handler."""
        self._handlers.append(handler)

    def start(self) -> None:
        """Start the ingestion pipeline."""
        if self._running:
            return

        self._running = True
        self._poll_thread = Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()
        logger.info("Event ingestion pipeline started")

    def stop(self) -> None:
        """Stop the ingestion pipeline."""
        self._running = False
        if self._poll_thread:
            self._poll_thread.join(timeout=5.0)
        logger.info("Event ingestion pipeline stopped")

    def _poll_loop(self) -> None:
        """Main polling loop."""
        while self._running:
            try:
                events = self.client.get_events(count=100)

                for event in events:
                    # Skip already processed events
                    if self._last_event_id and event.event_id <= self._last_event_id:
                        continue

                    # Add to queue (blocks if full = backpressure)
                    self.event_queue.put(event, timeout=1.0)
                    self._last_event_id = event.event_id

                    # Call handlers
                    for handler in self._handlers:
                        try:
                            handler(event)
                        except Exception as e:
                            logger.error(f"Handler error: {e}")

            except Exception as e:
                logger.error(f"Poll error: {e}")

            time.sleep(self.poll_interval)

    def get_formatted_events(self, count: int = 10) -> List[str]:
        """Get formatted events from queue."""
        events = []
        for _ in range(min(count, self.event_queue.qsize())):
            try:
                event = self.event_queue.get_nowait()
                if self.output_format == EventFormat.CEF:
                    events.append(event.to_cef())
                elif self.output_format == EventFormat.LEEF:
                    events.append(event.to_leef())
                else:
                    events.append(event.to_json())
            except:
                break
        return events

    def verify_integrity(self) -> tuple[bool, Optional[str]]:
        """Verify log integrity."""
        return self.client.verify_log_integrity()


class SIEMForwarder:
    """
    Forward events to external SIEM systems.

    Supports:
    - Syslog (UDP/TCP)
    - HTTP webhook
    - Kafka
    """

    def __init__(
        self,
        pipeline: EventIngestionPipeline,
        syslog_host: Optional[str] = None,
        syslog_port: int = 514,
        http_endpoint: Optional[str] = None,
    ):
        self.pipeline = pipeline
        self.syslog_host = syslog_host
        self.syslog_port = syslog_port
        self.http_endpoint = http_endpoint

        # Register as handler
        self.pipeline.add_handler(self._forward_event)

    def _forward_event(self, event: BoundaryEvent) -> None:
        """Forward event to configured destinations."""
        if self.syslog_host:
            self._send_syslog(event)
        if self.http_endpoint:
            self._send_http(event)

    def _send_syslog(self, event: BoundaryEvent) -> None:
        """Send event via syslog."""
        try:
            message = event.to_cef()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message.encode(), (self.syslog_host, self.syslog_port))
            sock.close()
        except Exception as e:
            logger.error(f"Syslog send failed: {e}")

    def _send_http(self, event: BoundaryEvent) -> None:
        """Send event via HTTP."""
        try:
            import urllib.request
            import urllib.error

            data = event.to_json().encode()
            req = urllib.request.Request(
                self.http_endpoint,
                data=data,
                headers={'Content-Type': 'application/json'},
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            logger.error(f"HTTP send failed: {e}")


# =============================================================================
# Convenience Functions
# =============================================================================

def create_ingestion_pipeline(
    output_format: str = 'cef',
    poll_interval: float = 1.0,
) -> EventIngestionPipeline:
    """Create and configure an ingestion pipeline."""
    format_map = {
        'cef': EventFormat.CEF,
        'leef': EventFormat.LEEF,
        'json': EventFormat.JSON,
    }

    return EventIngestionPipeline(
        output_format=format_map.get(output_format.lower(), EventFormat.CEF),
        poll_interval=poll_interval,
    )


def start_siem_forwarding(
    syslog_host: Optional[str] = None,
    http_endpoint: Optional[str] = None,
    output_format: str = 'cef',
) -> tuple[EventIngestionPipeline, SIEMForwarder]:
    """Start SIEM forwarding with configured destinations."""
    pipeline = create_ingestion_pipeline(output_format)

    forwarder = SIEMForwarder(
        pipeline=pipeline,
        syslog_host=syslog_host,
        http_endpoint=http_endpoint,
    )

    pipeline.start()
    return pipeline, forwarder
