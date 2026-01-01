"""
Sandbox Event Emitter for SIEM Integration

Provides real-time event streaming from sandbox operations to SIEM systems.
Events are formatted in CEF/LEEF and shipped via configured transport.

Usage:
    from daemon.integrations.siem.sandbox_events import SandboxEventEmitter, get_sandbox_emitter

    # Get global emitter (configured via environment)
    emitter = get_sandbox_emitter()

    # Emit events
    emitter.sandbox_created("sandbox-001", "RESTRICTED")
    emitter.firewall_blocked("sandbox-001", "192.168.1.100", 443)
    emitter.seccomp_violation("sandbox-001", "mount", 165)
"""

import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Callable

from .cef_leef import (
    CEFExporter,
    LEEFExporter,
    SIEMFormat,
    CEFSeverity,
    SIEMEventTransformer,
)
from .log_shipper import (
    LogShipper,
    ShipperConfig,
    ShipperProtocol,
    create_shipper,
)

logger = logging.getLogger(__name__)


class SandboxEventType(Enum):
    """Sandbox event types for SIEM."""
    CREATED = "SANDBOX_CREATED"
    STARTED = "SANDBOX_STARTED"
    STOPPED = "SANDBOX_STOPPED"
    TERMINATED = "SANDBOX_TERMINATED"
    ERROR = "SANDBOX_ERROR"
    TIMEOUT = "SANDBOX_TIMEOUT"
    OOM_KILLED = "SANDBOX_OOM_KILLED"
    SECCOMP_VIOLATION = "SANDBOX_SECCOMP_VIOLATION"
    NAMESPACE_SETUP = "SANDBOX_NAMESPACE_SETUP"
    CGROUP_LIMIT = "SANDBOX_CGROUP_LIMIT"
    FIREWALL_BLOCKED = "SANDBOX_FIREWALL_BLOCKED"
    FIREWALL_ALLOWED = "SANDBOX_FIREWALL_ALLOWED"
    SYSCALL_DENIED = "SANDBOX_SYSCALL_DENIED"
    ESCAPE_ATTEMPT = "SANDBOX_ESCAPE_ATTEMPT"
    RESOURCE_EXCEEDED = "SANDBOX_RESOURCE_EXCEEDED"


@dataclass
class SandboxEventEmitterConfig:
    """Configuration for sandbox event emitter."""
    # SIEM format
    siem_format: SIEMFormat = SIEMFormat.CEF

    # Shipper configuration
    shipper_config: Optional[ShipperConfig] = None

    # Event filtering
    min_severity: CEFSeverity = CEFSeverity.LOW
    enabled_event_types: Optional[List[SandboxEventType]] = None
    disabled_event_types: List[SandboxEventType] = field(default_factory=list)

    # Enrichment
    include_resource_usage: bool = True
    include_cgroup_path: bool = True
    include_process_tree: bool = False

    # Local event hooks
    event_hooks: List[Callable[[Dict[str, Any]], None]] = field(default_factory=list)

    # Hostname for events
    hostname: Optional[str] = None

    @classmethod
    def from_environment(cls) -> 'SandboxEventEmitterConfig':
        """Load configuration from environment variables."""
        config = cls()

        # SIEM format
        format_str = os.environ.get('BOUNDARY_SIEM_FORMAT', 'cef').lower()
        if format_str == 'leef':
            config.siem_format = SIEMFormat.LEEF
        elif format_str == 'json':
            config.siem_format = SIEMFormat.JSON
        else:
            config.siem_format = SIEMFormat.CEF

        # Min severity
        severity_str = os.environ.get('BOUNDARY_SIEM_MIN_SEVERITY', 'low').upper()
        try:
            config.min_severity = CEFSeverity[severity_str]
        except KeyError:
            config.min_severity = CEFSeverity.LOW

        # Shipper protocol
        protocol_str = os.environ.get('BOUNDARY_SIEM_PROTOCOL', 'file').lower()
        try:
            protocol = ShipperProtocol(protocol_str)
        except ValueError:
            protocol = ShipperProtocol.FILE

        # Build shipper config
        config.shipper_config = ShipperConfig(
            protocol=protocol,
            kafka_bootstrap_servers=os.environ.get(
                'BOUNDARY_KAFKA_SERVERS', 'localhost:9092'
            ),
            kafka_topic=os.environ.get(
                'BOUNDARY_KAFKA_TOPIC', 'boundary-sandbox-events'
            ),
            s3_bucket=os.environ.get('BOUNDARY_S3_BUCKET', ''),
            s3_prefix=os.environ.get(
                'BOUNDARY_S3_PREFIX', 'boundary-daemon/sandbox-events/'
            ),
            gcs_bucket=os.environ.get('BOUNDARY_GCS_BUCKET', ''),
            http_endpoint=os.environ.get('BOUNDARY_HTTP_ENDPOINT', ''),
            file_path=os.environ.get(
                'BOUNDARY_LOG_PATH', '/var/log/boundary-daemon/sandbox-events/'
            ),
        )

        # Hostname
        config.hostname = os.environ.get('HOSTNAME', None)
        if not config.hostname:
            import socket
            try:
                config.hostname = socket.gethostname()
            except Exception:
                config.hostname = 'unknown'

        return config


class SandboxEventEmitter:
    """
    Emit sandbox events to SIEM systems.

    Provides convenience methods for common sandbox events and
    handles formatting, enrichment, and shipping.
    """

    def __init__(self, config: Optional[SandboxEventEmitterConfig] = None):
        self.config = config or SandboxEventEmitterConfig()

        # Initialize formatter
        self._transformer = SIEMEventTransformer(
            format_type=self.config.siem_format,
            vendor="BoundaryDaemon",
            product="Sandbox",
            version="1.0",
        )
        self._transformer.set_min_severity(self.config.min_severity)

        # Initialize shipper
        self._shipper: Optional[LogShipper] = None
        if self.config.shipper_config:
            try:
                self._shipper = create_shipper(self.config.shipper_config)
            except Exception as e:
                logger.warning(f"Failed to create log shipper: {e}")

        # Event counter for IDs
        self._event_counter = 0
        self._counter_lock = threading.Lock()

        # Start shipper
        if self._shipper:
            self._shipper.start()

        logger.info(
            f"Sandbox event emitter initialized "
            f"(format={self.config.siem_format.value}, "
            f"min_severity={self.config.min_severity.name})"
        )

    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        with self._counter_lock:
            self._event_counter += 1
            counter = self._event_counter
        timestamp = int(time.time() * 1000)
        return f"sbx_{timestamp}_{counter:06d}"

    def _should_emit(self, event_type: SandboxEventType) -> bool:
        """Check if event type should be emitted."""
        # Check disabled list
        if event_type in self.config.disabled_event_types:
            return False

        # Check enabled list (if specified)
        if self.config.enabled_event_types is not None:
            return event_type in self.config.enabled_event_types

        return True

    def _emit_event(self, event: Dict[str, Any]) -> None:
        """Emit an event to SIEM and hooks."""
        # Call hooks
        for hook in self.config.event_hooks:
            try:
                hook(event)
            except Exception as e:
                logger.warning(f"Event hook failed: {e}")

        # Ship event
        if self._shipper:
            self._shipper.add_event(event)

    def _build_base_event(
        self,
        event_type: SandboxEventType,
        sandbox_id: str,
        details: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """Build base event structure."""
        event = {
            'event_id': self._generate_event_id(),
            'event_type': event_type.value,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'details': details,
            'sandbox_id': sandbox_id,
            'metadata': {
                'hostname': self.config.hostname,
            },
        }

        # Add optional fields
        for key, value in kwargs.items():
            if value is not None:
                if key.startswith('meta_'):
                    event['metadata'][key[5:]] = value
                else:
                    event[key] = value

        return event

    # Convenience methods for common events

    def sandbox_created(
        self,
        sandbox_id: str,
        profile: str,
        command: Optional[List[str]] = None,
        cgroup_path: Optional[str] = None,
        namespaces: Optional[List[str]] = None,
    ) -> None:
        """Emit sandbox created event."""
        if not self._should_emit(SandboxEventType.CREATED):
            return

        details = f"Sandbox {sandbox_id} created with profile {profile}"
        event = self._build_base_event(
            SandboxEventType.CREATED,
            sandbox_id,
            details,
            sandbox_profile=profile,
            cgroup_path=cgroup_path if self.config.include_cgroup_path else None,
            meta_command=command,
            meta_namespaces=namespaces,
        )
        self._emit_event(event)

    def sandbox_started(
        self,
        sandbox_id: str,
        pid: int,
        command: Optional[List[str]] = None,
    ) -> None:
        """Emit sandbox started event."""
        if not self._should_emit(SandboxEventType.STARTED):
            return

        details = f"Sandbox {sandbox_id} started (PID {pid})"
        event = self._build_base_event(
            SandboxEventType.STARTED,
            sandbox_id,
            details,
            process_id=pid,
            meta_command=command,
        )
        self._emit_event(event)

    def sandbox_stopped(
        self,
        sandbox_id: str,
        exit_code: int,
        runtime_seconds: Optional[float] = None,
    ) -> None:
        """Emit sandbox stopped event."""
        if not self._should_emit(SandboxEventType.STOPPED):
            return

        details = f"Sandbox {sandbox_id} stopped (exit code {exit_code})"
        event = self._build_base_event(
            SandboxEventType.STOPPED,
            sandbox_id,
            details,
            meta_exit_code=exit_code,
            meta_runtime_seconds=runtime_seconds,
        )
        self._emit_event(event)

    def sandbox_terminated(
        self,
        sandbox_id: str,
        reason: str,
        signal: Optional[int] = None,
    ) -> None:
        """Emit sandbox terminated event."""
        if not self._should_emit(SandboxEventType.TERMINATED):
            return

        details = f"Sandbox {sandbox_id} terminated: {reason}"
        event = self._build_base_event(
            SandboxEventType.TERMINATED,
            sandbox_id,
            details,
            reason=reason,
            meta_signal=signal,
        )
        self._emit_event(event)

    def sandbox_error(
        self,
        sandbox_id: str,
        error: str,
        error_type: Optional[str] = None,
    ) -> None:
        """Emit sandbox error event."""
        if not self._should_emit(SandboxEventType.ERROR):
            return

        details = f"Sandbox {sandbox_id} error: {error}"
        event = self._build_base_event(
            SandboxEventType.ERROR,
            sandbox_id,
            details,
            reason=error,
            meta_error_type=error_type,
        )
        self._emit_event(event)

    def sandbox_timeout(
        self,
        sandbox_id: str,
        timeout_seconds: float,
    ) -> None:
        """Emit sandbox timeout event."""
        if not self._should_emit(SandboxEventType.TIMEOUT):
            return

        details = f"Sandbox {sandbox_id} timed out after {timeout_seconds}s"
        event = self._build_base_event(
            SandboxEventType.TIMEOUT,
            sandbox_id,
            details,
            meta_timeout_seconds=timeout_seconds,
        )
        self._emit_event(event)

    def sandbox_oom_killed(
        self,
        sandbox_id: str,
        memory_limit_bytes: int,
        memory_usage_bytes: Optional[int] = None,
    ) -> None:
        """Emit sandbox OOM killed event."""
        if not self._should_emit(SandboxEventType.OOM_KILLED):
            return

        limit_mb = memory_limit_bytes / (1024 * 1024)
        details = f"Sandbox {sandbox_id} killed by OOM (limit: {limit_mb:.0f}MB)"
        event = self._build_base_event(
            SandboxEventType.OOM_KILLED,
            sandbox_id,
            details,
            memory_usage_bytes=memory_usage_bytes,
            meta_memory_limit_bytes=memory_limit_bytes,
        )
        self._emit_event(event)

    def seccomp_violation(
        self,
        sandbox_id: str,
        syscall_name: str,
        syscall_number: int,
        action_taken: str = "KILL",
    ) -> None:
        """Emit seccomp violation event."""
        if not self._should_emit(SandboxEventType.SECCOMP_VIOLATION):
            return

        details = f"Sandbox {sandbox_id} seccomp violation: {syscall_name} (#{syscall_number})"
        event = self._build_base_event(
            SandboxEventType.SECCOMP_VIOLATION,
            sandbox_id,
            details,
            syscall_name=syscall_name,
            action=action_taken,
            meta_syscall_number=syscall_number,
        )
        self._emit_event(event)

    def syscall_denied(
        self,
        sandbox_id: str,
        syscall_name: str,
        syscall_number: int,
        action_taken: str = "ERRNO",
    ) -> None:
        """Emit syscall denied event (ERRNO vs KILL)."""
        if not self._should_emit(SandboxEventType.SYSCALL_DENIED):
            return

        details = f"Sandbox {sandbox_id} syscall denied: {syscall_name} (#{syscall_number})"
        event = self._build_base_event(
            SandboxEventType.SYSCALL_DENIED,
            sandbox_id,
            details,
            syscall_name=syscall_name,
            action=action_taken,
            meta_syscall_number=syscall_number,
        )
        self._emit_event(event)

    def firewall_blocked(
        self,
        sandbox_id: str,
        destination: str,
        port: Optional[int] = None,
        protocol: str = "tcp",
    ) -> None:
        """Emit firewall blocked event."""
        if not self._should_emit(SandboxEventType.FIREWALL_BLOCKED):
            return

        dest_str = f"{destination}:{port}" if port else destination
        details = f"Sandbox {sandbox_id} firewall blocked: {dest_str} ({protocol})"
        event = self._build_base_event(
            SandboxEventType.FIREWALL_BLOCKED,
            sandbox_id,
            details,
            destination_ip=destination,
            meta_port=port,
            meta_protocol=protocol,
        )
        self._emit_event(event)

    def firewall_allowed(
        self,
        sandbox_id: str,
        destination: str,
        port: Optional[int] = None,
        protocol: str = "tcp",
        rule: Optional[str] = None,
    ) -> None:
        """Emit firewall allowed event (for audit trail)."""
        if not self._should_emit(SandboxEventType.FIREWALL_ALLOWED):
            return

        dest_str = f"{destination}:{port}" if port else destination
        details = f"Sandbox {sandbox_id} firewall allowed: {dest_str} ({protocol})"
        event = self._build_base_event(
            SandboxEventType.FIREWALL_ALLOWED,
            sandbox_id,
            details,
            destination_ip=destination,
            meta_port=port,
            meta_protocol=protocol,
            meta_rule=rule,
        )
        self._emit_event(event)

    def cgroup_limit_exceeded(
        self,
        sandbox_id: str,
        resource_type: str,
        limit: float,
        current: float,
        action_taken: str = "throttled",
    ) -> None:
        """Emit cgroup limit exceeded event."""
        if not self._should_emit(SandboxEventType.CGROUP_LIMIT):
            return

        details = f"Sandbox {sandbox_id} {resource_type} limit exceeded: {current}/{limit}"
        event = self._build_base_event(
            SandboxEventType.CGROUP_LIMIT,
            sandbox_id,
            details,
            resource_type=resource_type,
            action=action_taken,
            meta_limit=limit,
            meta_current=current,
        )
        self._emit_event(event)

    def resource_exceeded(
        self,
        sandbox_id: str,
        resource_type: str,
        limit: Any,
        current: Any,
    ) -> None:
        """Emit generic resource exceeded event."""
        if not self._should_emit(SandboxEventType.RESOURCE_EXCEEDED):
            return

        details = f"Sandbox {sandbox_id} resource exceeded: {resource_type}"
        event = self._build_base_event(
            SandboxEventType.RESOURCE_EXCEEDED,
            sandbox_id,
            details,
            resource_type=resource_type,
            meta_limit=limit,
            meta_current=current,
        )
        self._emit_event(event)

    def escape_attempt(
        self,
        sandbox_id: str,
        method: str,
        details_str: str,
        blocked: bool = True,
    ) -> None:
        """Emit sandbox escape attempt event (critical)."""
        if not self._should_emit(SandboxEventType.ESCAPE_ATTEMPT):
            return

        status = "blocked" if blocked else "DETECTED"
        details = f"Sandbox {sandbox_id} escape attempt {status}: {method}"
        event = self._build_base_event(
            SandboxEventType.ESCAPE_ATTEMPT,
            sandbox_id,
            details,
            action=status,
            reason=details_str,
            meta_escape_method=method,
        )
        self._emit_event(event)

    def custom_event(
        self,
        event_type: SandboxEventType,
        sandbox_id: str,
        details: str,
        **kwargs,
    ) -> None:
        """Emit a custom sandbox event."""
        if not self._should_emit(event_type):
            return

        event = self._build_base_event(event_type, sandbox_id, details, **kwargs)
        self._emit_event(event)

    def flush(self) -> None:
        """Flush pending events."""
        if self._shipper:
            self._shipper.flush()

    def stop(self) -> None:
        """Stop the emitter and flush events."""
        if self._shipper:
            self._shipper.stop()
        logger.info("Sandbox event emitter stopped")


# Global emitter instance
_global_emitter: Optional[SandboxEventEmitter] = None
_emitter_lock = threading.Lock()


def get_sandbox_emitter() -> SandboxEventEmitter:
    """
    Get the global sandbox event emitter.

    Initializes from environment on first call.
    """
    global _global_emitter

    if _global_emitter is None:
        with _emitter_lock:
            if _global_emitter is None:
                config = SandboxEventEmitterConfig.from_environment()
                _global_emitter = SandboxEventEmitter(config)

    return _global_emitter


def configure_sandbox_emitter(config: SandboxEventEmitterConfig) -> SandboxEventEmitter:
    """
    Configure and return the global sandbox event emitter.

    Replaces any existing emitter.
    """
    global _global_emitter

    with _emitter_lock:
        if _global_emitter:
            _global_emitter.stop()
        _global_emitter = SandboxEventEmitter(config)

    return _global_emitter


if __name__ == '__main__':
    import tempfile

    print("Testing Sandbox Event Emitter...")

    # Create test config with file shipper
    with tempfile.TemporaryDirectory() as tmpdir:
        config = SandboxEventEmitterConfig(
            siem_format=SIEMFormat.CEF,
            shipper_config=ShipperConfig(
                protocol=ShipperProtocol.FILE,
                file_path=tmpdir,
                batch_size=3,
                compress=False,
            ),
        )

        emitter = SandboxEventEmitter(config)

        # Emit various events
        emitter.sandbox_created("sbx-001", "RESTRICTED", ["/bin/bash"])
        emitter.sandbox_started("sbx-001", 12345)
        emitter.firewall_blocked("sbx-001", "10.0.0.1", 443)
        emitter.seccomp_violation("sbx-001", "mount", 165)
        emitter.sandbox_stopped("sbx-001", 0, 5.2)

        emitter.flush()
        emitter.stop()

        # Show files
        print(f"\nEvents written to {tmpdir}:")
        import os
        for root, dirs, files in os.walk(tmpdir):
            for f in files:
                path = os.path.join(root, f)
                with open(path, 'r') as fp:
                    print(f"\n{path}:")
                    print(fp.read()[:500])

    print("\nSandbox event emitter test complete.")
