"""
Redundant Event Logger - Multi-backend event logging with failover.

Provides resilient event logging through multiple backends:
- Primary file logger with hash chain
- Syslog for system-level auditing
- In-memory buffer for crash recovery
- Remote logging endpoint support
- Automatic failover between backends

SECURITY: Addresses Critical Finding "Single Event Logger Dependency"
Without redundancy, a single logger failure or compromise could result
in lost or manipulated security events.
"""

import hashlib
import json
import logging
import os
import queue
import socket
import struct
import syslog
import tempfile
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .event_logger import EventLogger, EventType, BoundaryEvent

logger = logging.getLogger(__name__)


class LogBackendType(Enum):
    """Types of logging backends."""
    FILE = "file"
    SYSLOG = "syslog"
    MEMORY = "memory"
    REMOTE = "remote"
    JOURNAL = "journal"  # systemd journal


class LogBackendStatus(Enum):
    """Status of a logging backend."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    DISABLED = "disabled"


class LogPriority(Enum):
    """Priority levels for events (maps to syslog priorities)."""
    EMERGENCY = 0  # System is unusable
    ALERT = 1      # Action must be taken immediately
    CRITICAL = 2   # Critical conditions
    ERROR = 3      # Error conditions
    WARNING = 4    # Warning conditions
    NOTICE = 5     # Normal but significant
    INFO = 6       # Informational
    DEBUG = 7      # Debug messages


@dataclass
class BackendConfig:
    """Configuration for a logging backend."""
    backend_type: LogBackendType
    enabled: bool = True
    primary: bool = False  # Is this the primary backend?
    path: Optional[str] = None  # File path or remote URL
    buffer_size: int = 1000  # In-memory buffer size
    retry_count: int = 3
    retry_delay: float = 1.0
    timeout: float = 5.0


@dataclass
class RedundantLoggerConfig:
    """Configuration for the redundant logger."""
    # Backend configurations
    backends: List[BackendConfig] = field(default_factory=list)

    # Minimum healthy backends required
    min_healthy_backends: int = 1

    # Event priority threshold for multi-write
    # Events at or above this priority are written to ALL backends
    critical_priority: LogPriority = LogPriority.WARNING

    # Memory buffer settings
    memory_buffer_size: int = 10000
    memory_buffer_persist_path: Optional[str] = None

    # Health check settings
    health_check_interval: float = 60.0

    # Alerting
    alert_on_backend_failure: bool = True
    alert_callback: Optional[Callable[[str, str], None]] = None


class LogBackend(ABC):
    """Abstract base class for logging backends."""

    def __init__(self, config: BackendConfig):
        self.config = config
        self.status = LogBackendStatus.HEALTHY
        self._failure_count = 0
        self._last_failure: Optional[datetime] = None
        self._last_success: Optional[datetime] = None
        self._events_logged = 0
        self._lock = threading.Lock()

    @abstractmethod
    def write_event(self, event: BoundaryEvent, priority: LogPriority) -> bool:
        """Write an event to the backend."""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Check if backend is healthy."""
        pass

    def record_success(self):
        """Record successful write."""
        with self._lock:
            self._last_success = datetime.utcnow()
            self._events_logged += 1
            self._failure_count = 0
            if self.status == LogBackendStatus.DEGRADED:
                self.status = LogBackendStatus.HEALTHY

    def record_failure(self, error: str):
        """Record failed write."""
        with self._lock:
            self._last_failure = datetime.utcnow()
            self._failure_count += 1
            if self._failure_count >= self.config.retry_count:
                self.status = LogBackendStatus.FAILED
            else:
                self.status = LogBackendStatus.DEGRADED
            logger.error(f"Backend {self.config.backend_type.value} failure: {error}")

    def get_status(self) -> Dict[str, Any]:
        """Get backend status."""
        with self._lock:
            return {
                'type': self.config.backend_type.value,
                'status': self.status.value,
                'enabled': self.config.enabled,
                'primary': self.config.primary,
                'events_logged': self._events_logged,
                'failure_count': self._failure_count,
                'last_success': self._last_success.isoformat() if self._last_success else None,
                'last_failure': self._last_failure.isoformat() if self._last_failure else None,
            }


class FileBackend(LogBackend):
    """File-based logging backend with hash chain."""

    def __init__(self, config: BackendConfig, base_logger: Optional[EventLogger] = None):
        super().__init__(config)
        self.path = Path(config.path) if config.path else Path('./logs/redundant.log')
        self._base_logger = base_logger
        self._file_lock = threading.Lock()

        # Ensure directory exists
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write_event(self, event: BoundaryEvent, priority: LogPriority) -> bool:
        """Write event to file."""
        try:
            with self._file_lock:
                # If we have a base logger, use it (preserves hash chain)
                if self._base_logger:
                    self._base_logger.log_event(
                        event.event_type,
                        event.details,
                        event.metadata
                    )
                else:
                    # Direct file write
                    with open(self.path, 'a') as f:
                        f.write(event.to_json() + '\n')
                        f.flush()
                        os.fsync(f.fileno())

            self.record_success()
            return True

        except Exception as e:
            self.record_failure(str(e))
            return False

    def health_check(self) -> bool:
        """Check if file is writable."""
        try:
            # Check if we can write to the directory
            test_file = self.path.parent / '.health_check'
            with open(test_file, 'w') as f:
                f.write('ok')
            test_file.unlink()
            return True
        except Exception:
            return False


class SyslogBackend(LogBackend):
    """Syslog logging backend for system-level auditing."""

    # Map our priorities to syslog priorities
    PRIORITY_MAP = {
        LogPriority.EMERGENCY: syslog.LOG_EMERG,
        LogPriority.ALERT: syslog.LOG_ALERT,
        LogPriority.CRITICAL: syslog.LOG_CRIT,
        LogPriority.ERROR: syslog.LOG_ERR,
        LogPriority.WARNING: syslog.LOG_WARNING,
        LogPriority.NOTICE: syslog.LOG_NOTICE,
        LogPriority.INFO: syslog.LOG_INFO,
        LogPriority.DEBUG: syslog.LOG_DEBUG,
    }

    def __init__(self, config: BackendConfig):
        super().__init__(config)
        self._initialized = False
        self._init_syslog()

    def _init_syslog(self):
        """Initialize syslog connection."""
        try:
            syslog.openlog(
                ident='boundary-daemon',
                logoption=syslog.LOG_PID | syslog.LOG_CONS,
                facility=syslog.LOG_AUTH  # Use auth facility for security events
            )
            self._initialized = True
        except Exception as e:
            logger.error(f"Failed to initialize syslog: {e}")
            self.status = LogBackendStatus.FAILED

    def write_event(self, event: BoundaryEvent, priority: LogPriority) -> bool:
        """Write event to syslog."""
        if not self._initialized:
            self._init_syslog()
            if not self._initialized:
                return False

        try:
            syslog_priority = self.PRIORITY_MAP.get(priority, syslog.LOG_INFO)

            # Format message for syslog
            message = (
                f"[{event.event_type.value}] {event.details} "
                f"(id={event.event_id}, chain={event.hash_chain[:16]}...)"
            )

            syslog.syslog(syslog_priority, message)
            self.record_success()
            return True

        except Exception as e:
            self.record_failure(str(e))
            return False

    def health_check(self) -> bool:
        """Check if syslog is available."""
        try:
            syslog.syslog(syslog.LOG_DEBUG, "boundary-daemon health check")
            return True
        except Exception:
            return False


class MemoryBackend(LogBackend):
    """In-memory buffer for crash recovery and failover."""

    def __init__(self, config: BackendConfig):
        super().__init__(config)
        self._buffer: List[Tuple[BoundaryEvent, LogPriority, datetime]] = []
        self._max_size = config.buffer_size
        self._persist_path = Path(config.path) if config.path else None

        # Load persisted events if available
        if self._persist_path:
            self._load_persisted()

    def _load_persisted(self):
        """Load persisted events from disk."""
        if not self._persist_path or not self._persist_path.exists():
            return

        try:
            with open(self._persist_path, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        event = BoundaryEvent(
                            event_id=data['event']['event_id'],
                            timestamp=data['event']['timestamp'],
                            event_type=EventType(data['event']['event_type']),
                            details=data['event']['details'],
                            metadata=data['event'].get('metadata', {}),
                            hash_chain=data['event']['hash_chain'],
                        )
                        priority = LogPriority(data['priority'])
                        buffered_at = datetime.fromisoformat(data['buffered_at'])
                        self._buffer.append((event, priority, buffered_at))
                    except Exception:
                        continue

            logger.info(f"Loaded {len(self._buffer)} events from memory buffer persist file")

        except Exception as e:
            logger.error(f"Failed to load persisted buffer: {e}")

    def _persist_buffer(self):
        """Persist buffer to disk."""
        if not self._persist_path:
            return

        try:
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._persist_path, 'w') as f:
                for event, priority, buffered_at in self._buffer:
                    data = {
                        'event': event.to_dict(),
                        'priority': priority.value,
                        'buffered_at': buffered_at.isoformat(),
                    }
                    f.write(json.dumps(data) + '\n')
        except Exception as e:
            logger.error(f"Failed to persist buffer: {e}")

    def write_event(self, event: BoundaryEvent, priority: LogPriority) -> bool:
        """Add event to memory buffer."""
        try:
            with self._lock:
                # Remove oldest if at capacity
                while len(self._buffer) >= self._max_size:
                    self._buffer.pop(0)

                self._buffer.append((event, priority, datetime.utcnow()))

                # Persist periodically
                if len(self._buffer) % 100 == 0:
                    self._persist_buffer()

            self.record_success()
            return True

        except Exception as e:
            self.record_failure(str(e))
            return False

    def health_check(self) -> bool:
        """Memory backend is always healthy if not full."""
        return len(self._buffer) < self._max_size

    def get_buffered_events(self) -> List[Tuple[BoundaryEvent, LogPriority]]:
        """Get all buffered events."""
        with self._lock:
            return [(e, p) for e, p, _ in self._buffer]

    def clear_buffer(self):
        """Clear the buffer after events have been replayed."""
        with self._lock:
            self._buffer.clear()
            if self._persist_path and self._persist_path.exists():
                self._persist_path.unlink()

    def get_buffer_size(self) -> int:
        """Get current buffer size."""
        return len(self._buffer)


class RemoteBackend(LogBackend):
    """Remote logging backend for off-site event storage."""

    def __init__(self, config: BackendConfig):
        super().__init__(config)
        self._url = config.path
        self._queue: queue.Queue = queue.Queue(maxsize=config.buffer_size)
        self._send_thread: Optional[threading.Thread] = None
        self._running = False

        # Parse URL for connection
        self._parse_url()

    def _parse_url(self):
        """Parse remote URL."""
        if not self._url:
            self.status = LogBackendStatus.DISABLED
            return

        # Simple UDP/TCP URL parsing: udp://host:port or tcp://host:port
        if self._url.startswith('udp://'):
            self._protocol = 'udp'
            addr = self._url[6:]
        elif self._url.startswith('tcp://'):
            self._protocol = 'tcp'
            addr = self._url[6:]
        else:
            self.status = LogBackendStatus.FAILED
            return

        try:
            host, port = addr.split(':')
            self._host = host
            self._port = int(port)
        except Exception:
            self.status = LogBackendStatus.FAILED

    def start(self):
        """Start background sender thread."""
        if self._running:
            return

        self._running = True
        self._send_thread = threading.Thread(
            target=self._send_loop,
            daemon=True,
            name="RemoteLogSender"
        )
        self._send_thread.start()

    def stop(self):
        """Stop background sender."""
        self._running = False
        if self._send_thread:
            self._send_thread.join(timeout=5.0)

    def _send_loop(self):
        """Background loop to send queued events."""
        while self._running:
            try:
                # Get event from queue with timeout
                try:
                    event_data = self._queue.get(timeout=1.0)
                except queue.Empty:
                    continue

                # Send event
                self._send_event(event_data)

            except Exception as e:
                logger.error(f"Remote sender error: {e}")

    def _send_event(self, event_data: bytes):
        """Send event to remote server."""
        try:
            if self._protocol == 'udp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.config.timeout)
                sock.sendto(event_data, (self._host, self._port))
                sock.close()
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.timeout)
                sock.connect((self._host, self._port))
                # Send length-prefixed message
                sock.sendall(struct.pack('>I', len(event_data)) + event_data)
                sock.close()

            self.record_success()

        except Exception as e:
            self.record_failure(str(e))

    def write_event(self, event: BoundaryEvent, priority: LogPriority) -> bool:
        """Queue event for remote sending."""
        if self.status == LogBackendStatus.DISABLED:
            return False

        try:
            event_data = json.dumps({
                'event': event.to_dict(),
                'priority': priority.value,
                'sent_at': datetime.utcnow().isoformat(),
            }).encode()

            self._queue.put_nowait(event_data)
            return True

        except queue.Full:
            self.record_failure("Queue full")
            return False
        except Exception as e:
            self.record_failure(str(e))
            return False

    def health_check(self) -> bool:
        """Check if remote endpoint is reachable."""
        try:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM if self._protocol == 'udp' else socket.SOCK_STREAM
            )
            sock.settimeout(2.0)
            sock.connect((self._host, self._port))
            sock.close()
            return True
        except Exception:
            return False


class RedundantEventLogger:
    """
    Multi-backend event logger with automatic failover.

    SECURITY: Provides logging redundancy to ensure security events
    are never lost due to single point of failure.

    Features:
    - Multiple logging backends (file, syslog, memory, remote)
    - Automatic failover on backend failure
    - Critical events logged to ALL backends
    - Memory buffer for crash recovery
    - Health monitoring with alerting
    - Event replay from memory buffer
    """

    def __init__(
        self,
        config: Optional[RedundantLoggerConfig] = None,
        base_logger: Optional[EventLogger] = None,
    ):
        """
        Initialize redundant logger.

        Args:
            config: Logger configuration
            base_logger: Optional base EventLogger for primary file backend
        """
        self.config = config or self._default_config()
        self._base_logger = base_logger
        self._backends: Dict[LogBackendType, LogBackend] = {}
        self._lock = threading.Lock()
        self._running = False
        self._health_thread: Optional[threading.Thread] = None

        # Statistics
        self._stats = {
            'events_logged': 0,
            'events_failed': 0,
            'failovers': 0,
            'backend_failures': 0,
        }

        # Last hash for chain continuity
        self._last_hash = "0" * 64
        self._event_count = 0

        # Initialize backends
        self._init_backends()

    def _default_config(self) -> RedundantLoggerConfig:
        """Create default configuration."""
        return RedundantLoggerConfig(
            backends=[
                BackendConfig(
                    backend_type=LogBackendType.FILE,
                    primary=True,
                    path='./logs/boundary_chain.log',
                ),
                BackendConfig(
                    backend_type=LogBackendType.SYSLOG,
                    enabled=True,
                ),
                BackendConfig(
                    backend_type=LogBackendType.MEMORY,
                    enabled=True,
                    buffer_size=10000,
                    path='./logs/.event_buffer.json',
                ),
            ],
        )

    def _init_backends(self):
        """Initialize all configured backends."""
        for backend_config in self.config.backends:
            if not backend_config.enabled:
                continue

            try:
                backend = self._create_backend(backend_config)
                if backend:
                    self._backends[backend_config.backend_type] = backend
                    logger.info(f"Initialized {backend_config.backend_type.value} backend")

            except Exception as e:
                logger.error(f"Failed to init {backend_config.backend_type.value}: {e}")

    def _create_backend(self, config: BackendConfig) -> Optional[LogBackend]:
        """Create a backend instance."""
        if config.backend_type == LogBackendType.FILE:
            return FileBackend(config, self._base_logger)
        elif config.backend_type == LogBackendType.SYSLOG:
            return SyslogBackend(config)
        elif config.backend_type == LogBackendType.MEMORY:
            return MemoryBackend(config)
        elif config.backend_type == LogBackendType.REMOTE:
            backend = RemoteBackend(config)
            backend.start()
            return backend
        else:
            return None

    def _get_priority_for_event(self, event_type: EventType) -> LogPriority:
        """Determine priority based on event type."""
        critical_events = {
            EventType.VIOLATION,
            EventType.TRIPWIRE,
            EventType.CLOCK_JUMP,
            EventType.PII_BLOCKED,
        }
        warning_events = {
            EventType.OVERRIDE,
            EventType.CLOCK_DRIFT,
            EventType.NTP_SYNC_LOST,
            EventType.RATE_LIMIT_GLOBAL,
        }
        info_events = {
            EventType.MODE_CHANGE,
            EventType.POLICY_DECISION,
            EventType.DAEMON_START,
            EventType.DAEMON_STOP,
        }

        if event_type in critical_events:
            return LogPriority.CRITICAL
        elif event_type in warning_events:
            return LogPriority.WARNING
        elif event_type in info_events:
            return LogPriority.INFO
        else:
            return LogPriority.NOTICE

    def log_event(
        self,
        event_type: EventType,
        details: str,
        metadata: Optional[Dict] = None,
        priority: Optional[LogPriority] = None,
    ) -> Optional[BoundaryEvent]:
        """
        Log an event to all appropriate backends.

        Args:
            event_type: Type of event
            details: Event details
            metadata: Optional metadata
            priority: Optional priority override

        Returns:
            The logged event, or None if all backends failed
        """
        # Determine priority
        if priority is None:
            priority = self._get_priority_for_event(event_type)

        # Create event
        with self._lock:
            event = BoundaryEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.utcnow().isoformat() + 'Z',
                event_type=event_type,
                details=details,
                metadata=metadata or {},
                hash_chain=self._last_hash,
            )
            self._last_hash = event.compute_hash()
            self._event_count += 1

        # Determine which backends to write to
        backends_to_use = self._select_backends(priority)

        if not backends_to_use:
            logger.error("No healthy backends available for logging!")
            self._stats['events_failed'] += 1
            return None

        # Write to selected backends
        success_count = 0
        for backend in backends_to_use:
            try:
                if backend.write_event(event, priority):
                    success_count += 1
            except Exception as e:
                logger.error(f"Backend write failed: {e}")
                backend.record_failure(str(e))

        if success_count > 0:
            self._stats['events_logged'] += 1
            return event
        else:
            self._stats['events_failed'] += 1
            self._handle_all_backends_failed(event, priority)
            return None

    def _select_backends(self, priority: LogPriority) -> List[LogBackend]:
        """Select backends to write to based on priority."""
        backends = []

        # For critical events, use all healthy backends
        if priority.value <= self.config.critical_priority.value:
            for backend in self._backends.values():
                if backend.status != LogBackendStatus.FAILED:
                    backends.append(backend)
        else:
            # For non-critical, use primary + memory buffer
            for backend in self._backends.values():
                if backend.config.primary and backend.status != LogBackendStatus.FAILED:
                    backends.append(backend)

            # Always include memory backend for recovery
            if LogBackendType.MEMORY in self._backends:
                mem_backend = self._backends[LogBackendType.MEMORY]
                if mem_backend not in backends:
                    backends.append(mem_backend)

        return backends

    def _handle_all_backends_failed(self, event: BoundaryEvent, priority: LogPriority):
        """Handle case where all backends fail."""
        self._stats['backend_failures'] += 1

        # Try emergency fallback: write to stderr and temp file
        try:
            import sys
            sys.stderr.write(f"EMERGENCY LOG: {event.to_json()}\n")
            sys.stderr.flush()

            # Write to temp file
            emergency_path = Path(tempfile.gettempdir()) / 'boundary-daemon-emergency.log'
            with open(emergency_path, 'a') as f:
                f.write(event.to_json() + '\n')

        except Exception:
            pass

        # Alert if configured
        if self.config.alert_on_backend_failure and self.config.alert_callback:
            try:
                self.config.alert_callback(
                    "All logging backends failed",
                    f"Event {event.event_id} could not be logged"
                )
            except Exception:
                pass

    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        import hashlib
        import time
        data = f"{time.time()}-{self._event_count}-{os.getpid()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def log_security_event(
        self,
        event_type: str,
        severity: str,
        details: Dict[str, Any],
    ) -> Optional[BoundaryEvent]:
        """
        Log a security event (convenience method).

        Args:
            event_type: Type of security event
            severity: Severity level (critical, warning, info)
            details: Event details

        Returns:
            The logged event
        """
        # Map severity to priority
        severity_map = {
            'critical': LogPriority.CRITICAL,
            'high': LogPriority.ALERT,
            'warning': LogPriority.WARNING,
            'medium': LogPriority.NOTICE,
            'info': LogPriority.INFO,
            'low': LogPriority.DEBUG,
        }
        priority = severity_map.get(severity.lower(), LogPriority.NOTICE)

        # Map to EventType or use generic
        try:
            evt_type = EventType(event_type)
        except ValueError:
            evt_type = EventType.SECURITY_SCAN

        return self.log_event(
            event_type=evt_type,
            details=json.dumps(details) if isinstance(details, dict) else str(details),
            metadata={'security_event_type': event_type, 'severity': severity},
            priority=priority,
        )

    def start_health_monitoring(self):
        """Start background health monitoring."""
        if self._running:
            return

        self._running = True
        self._health_thread = threading.Thread(
            target=self._health_loop,
            daemon=True,
            name="LoggerHealthMonitor"
        )
        self._health_thread.start()

    def stop_health_monitoring(self):
        """Stop health monitoring."""
        self._running = False
        if self._health_thread:
            self._health_thread.join(timeout=5.0)

    def _health_loop(self):
        """Background health check loop."""
        while self._running:
            try:
                time.sleep(self.config.health_check_interval)

                if not self._running:
                    break

                self._check_backends_health()
                self._replay_buffered_if_needed()

            except Exception as e:
                logger.error(f"Health check error: {e}")

    def _check_backends_health(self):
        """Check health of all backends."""
        healthy_count = 0

        for backend_type, backend in self._backends.items():
            if backend.status == LogBackendStatus.DISABLED:
                continue

            try:
                is_healthy = backend.health_check()
                if is_healthy and backend.status == LogBackendStatus.FAILED:
                    # Backend recovered
                    backend.status = LogBackendStatus.HEALTHY
                    logger.info(f"Backend {backend_type.value} recovered")

                if backend.status == LogBackendStatus.HEALTHY:
                    healthy_count += 1

            except Exception as e:
                backend.record_failure(str(e))

        if healthy_count < self.config.min_healthy_backends:
            logger.warning(
                f"Only {healthy_count} healthy backends "
                f"(minimum: {self.config.min_healthy_backends})"
            )

    def _replay_buffered_if_needed(self):
        """Replay buffered events if primary backend is back."""
        if LogBackendType.MEMORY not in self._backends:
            return

        memory_backend = self._backends[LogBackendType.MEMORY]
        if not isinstance(memory_backend, MemoryBackend):
            return

        # Check if primary backend is healthy
        primary_healthy = False
        for backend in self._backends.values():
            if backend.config.primary and backend.status == LogBackendStatus.HEALTHY:
                primary_healthy = True
                break

        if not primary_healthy:
            return

        # Replay buffered events
        buffered = memory_backend.get_buffered_events()
        if not buffered:
            return

        logger.info(f"Replaying {len(buffered)} buffered events")
        for event, priority in buffered:
            for backend in self._backends.values():
                if backend.config.primary:
                    backend.write_event(event, priority)

        memory_backend.clear_buffer()

    def get_status(self) -> Dict[str, Any]:
        """Get logger status."""
        return {
            'running': self._running,
            'stats': self._stats.copy(),
            'event_count': self._event_count,
            'backends': {
                bt.value: b.get_status()
                for bt, b in self._backends.items()
            },
        }

    def get_event_count(self) -> int:
        """Get total event count."""
        return self._event_count

    def get_healthy_backend_count(self) -> int:
        """Get count of healthy backends."""
        return sum(
            1 for b in self._backends.values()
            if b.status == LogBackendStatus.HEALTHY
        )


# Factory function for easy creation
def create_redundant_logger(
    log_dir: str = './logs',
    enable_syslog: bool = True,
    enable_memory_buffer: bool = True,
    remote_url: Optional[str] = None,
) -> RedundantEventLogger:
    """
    Create a redundant logger with common configuration.

    Args:
        log_dir: Directory for log files
        enable_syslog: Enable syslog backend
        enable_memory_buffer: Enable memory buffer
        remote_url: Optional remote logging URL (udp://host:port or tcp://host:port)

    Returns:
        Configured RedundantEventLogger
    """
    backends = [
        BackendConfig(
            backend_type=LogBackendType.FILE,
            primary=True,
            path=os.path.join(log_dir, 'boundary_chain.log'),
        ),
    ]

    if enable_syslog:
        backends.append(BackendConfig(
            backend_type=LogBackendType.SYSLOG,
            enabled=True,
        ))

    if enable_memory_buffer:
        backends.append(BackendConfig(
            backend_type=LogBackendType.MEMORY,
            enabled=True,
            buffer_size=10000,
            path=os.path.join(log_dir, '.event_buffer.json'),
        ))

    if remote_url:
        backends.append(BackendConfig(
            backend_type=LogBackendType.REMOTE,
            enabled=True,
            path=remote_url,
        ))

    config = RedundantLoggerConfig(backends=backends)
    return RedundantEventLogger(config=config)
