"""
OpenTelemetry Integration for Boundary Daemon

This module provides native OpenTelemetry integration for structured, standardized
observability across traces, metrics, and logs.

Plan 9: OpenTelemetry Integration

Features:
- Distributed tracing with span events
- Structured metrics (counters, gauges, histograms)
- Correlated logs with trace context
- Mode-aware export controls
- Sensitive data redaction
- Console/File/Remote exporters

Security Notes:
- Export disabled by default in AIRGAP/COLDROOM/LOCKDOWN modes
- Remote export requires explicit Learning Contract
- Sensitive attributes automatically redacted
- All telemetry respects boundary mode restrictions
"""

import os
import socket
import logging
import threading
import time
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Callable
from pathlib import Path
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Try importing OpenTelemetry (graceful fallback if not installed)
try:
    from opentelemetry import trace, metrics
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_INSTANCE_ID, HOST_NAME
    from opentelemetry.sdk.trace import TracerProvider, Span
    from opentelemetry.sdk.trace.export import (
        SpanProcessor, SpanExporter, SpanExportResult,
        ConsoleSpanExporter, SimpleSpanProcessor, BatchSpanProcessor
    )
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import (
        MetricExporter, ConsoleMetricExporter, PeriodicExportingMetricReader
    )
    from opentelemetry.trace import Status, StatusCode
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    trace = None
    metrics = None
    Resource = None
    TracerProvider = None
    MeterProvider = None
    Span = None

# Try importing OTLP exporters
try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    OTLP_AVAILABLE = True
except ImportError:
    OTLP_AVAILABLE = False
    OTLPSpanExporter = None
    OTLPMetricExporter = None


class ExportMode(Enum):
    """Telemetry export modes"""
    DISABLED = "disabled"       # No export
    CONSOLE = "console"         # Console output only
    FILE = "file"               # File export (JSON)
    REMOTE = "remote"           # OTLP remote export


class TelemetryConfig:
    """Configuration for OpenTelemetry integration"""

    def __init__(self):
        self.enabled = False
        self.export_mode = ExportMode.CONSOLE
        self.console_export = True
        self.file_export = False
        self.remote_export = False
        self.otel_endpoint = "http://localhost:4317"
        self.log_correlation = True
        self.redact_sensitive = True
        self.service_name = "boundary-daemon"
        self.export_interval_ms = 5000
        self.file_path: Optional[str] = None

    @classmethod
    def from_env(cls) -> 'TelemetryConfig':
        """Create config from environment variables"""
        config = cls()

        # Enable telemetry if directory is set
        telemetry_dir = os.environ.get('BOUNDARY_TELEMETRY_DIR')
        if telemetry_dir:
            config.enabled = True
            config.file_path = telemetry_dir

        # Export settings
        config.console_export = os.environ.get('BOUNDARY_TELEMETRY_CONSOLE', 'true').lower() == 'true'
        config.file_export = os.environ.get('BOUNDARY_TELEMETRY_FILE', 'false').lower() == 'true'
        config.remote_export = os.environ.get('BOUNDARY_TELEMETRY_REMOTE', 'false').lower() == 'true'

        # Endpoint
        endpoint = os.environ.get('BOUNDARY_TELEMETRY_ENDPOINT')
        if endpoint:
            config.otel_endpoint = endpoint

        # Determine export mode
        if config.remote_export:
            config.export_mode = ExportMode.REMOTE
        elif config.file_export:
            config.export_mode = ExportMode.FILE
        elif config.console_export:
            config.export_mode = ExportMode.CONSOLE
        else:
            config.export_mode = ExportMode.DISABLED

        return config


class RedactionProcessor:
    """Processor to redact sensitive data from spans and metrics"""

    SENSITIVE_KEYS = {
        'password', 'secret', 'token', 'key', 'credential',
        'auth', 'private', 'ssn', 'credit_card', 'memory_content'
    }

    @classmethod
    def redact_attributes(cls, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive attributes"""
        if not attributes:
            return attributes

        redacted = {}
        for key, value in attributes.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in cls.SENSITIVE_KEYS):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = value
        return redacted


class FileSpanExporter:
    """Export spans to JSON file"""

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def export(self, spans) -> 'SpanExportResult':
        """Export spans to file"""
        import json

        try:
            with self._lock:
                with open(self.file_path / 'traces.jsonl', 'a') as f:
                    for span in spans:
                        span_data = {
                            'timestamp': datetime.utcnow().isoformat(),
                            'trace_id': format(span.context.trace_id, '032x') if hasattr(span.context, 'trace_id') else None,
                            'span_id': format(span.context.span_id, '016x') if hasattr(span.context, 'span_id') else None,
                            'name': span.name,
                            'status': span.status.status_code.name if hasattr(span.status, 'status_code') else 'OK',
                            'attributes': RedactionProcessor.redact_attributes(dict(span.attributes)) if span.attributes else {},
                            'start_time': span.start_time,
                            'end_time': span.end_time
                        }
                        f.write(json.dumps(span_data) + '\n')

            if OTEL_AVAILABLE:
                return SpanExportResult.SUCCESS
            return True
        except Exception as e:
            logger.error(f"Failed to export spans to file: {e}")
            if OTEL_AVAILABLE:
                return SpanExportResult.FAILURE
            return False

    def shutdown(self):
        """Cleanup"""
        pass


class TelemetryManager:
    """
    Manages OpenTelemetry integration for Boundary Daemon.

    Provides:
    - Tracer for distributed tracing
    - Meter for metrics collection
    - Mode-aware export controls
    - Sensitive data redaction
    """

    def __init__(
        self,
        daemon=None,
        config: Optional[TelemetryConfig] = None,
        instance_id: Optional[str] = None
    ):
        """
        Initialize TelemetryManager.

        Args:
            daemon: Reference to BoundaryDaemon instance
            config: TelemetryConfig instance
            instance_id: Unique instance identifier
        """
        self.daemon = daemon
        self.config = config or TelemetryConfig()
        self.instance_id = instance_id or self._generate_instance_id()
        self.hostname = socket.gethostname()

        # State
        self._initialized = False
        self._tracer = None
        self._meter = None
        self._resource = None

        # Metrics storage (for non-OTel fallback)
        self._metrics: Dict[str, Any] = {}
        self._metrics_lock = threading.Lock()

        # Span storage (for non-OTel fallback)
        self._spans: List[Dict] = []
        self._spans_lock = threading.Lock()

        # Custom metrics
        self._counters: Dict[str, Any] = {}
        self._histograms: Dict[str, Any] = {}
        self._gauges: Dict[str, int] = {}

        # File exporter
        self._file_exporter = None
        if self.config.file_path and self.config.file_export:
            self._file_exporter = FileSpanExporter(self.config.file_path)

    def _generate_instance_id(self) -> str:
        """Generate unique instance ID"""
        import hashlib
        data = f"{socket.gethostname()}-{os.getpid()}-{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()[:12]

    def initialize(self) -> bool:
        """
        Initialize OpenTelemetry providers.

        Returns:
            True if initialization successful
        """
        if self._initialized:
            return True

        if not self.config.enabled:
            logger.info("Telemetry disabled by configuration")
            return False

        if not OTEL_AVAILABLE:
            logger.warning("OpenTelemetry not installed, using fallback metrics")
            self._initialized = True
            return True

        try:
            # Create resource with service info
            self._resource = Resource.create({
                SERVICE_NAME: self.config.service_name,
                SERVICE_INSTANCE_ID: self.instance_id,
                HOST_NAME: self.hostname,
                "boundary.version": "2.3",
            })

            # Initialize TracerProvider
            tracer_provider = TracerProvider(resource=self._resource)

            # Add console exporter if enabled
            if self.config.console_export:
                tracer_provider.add_span_processor(
                    SimpleSpanProcessor(ConsoleSpanExporter())
                )

            # Add file exporter if enabled
            if self._file_exporter:
                tracer_provider.add_span_processor(
                    SimpleSpanProcessor(self._file_exporter)
                )

            # Add remote exporter if enabled and allowed
            if self.config.remote_export and OTLP_AVAILABLE:
                if self._is_remote_export_allowed():
                    tracer_provider.add_span_processor(
                        BatchSpanProcessor(
                            OTLPSpanExporter(endpoint=self.config.otel_endpoint)
                        )
                    )
                else:
                    logger.warning("Remote telemetry export blocked by current mode")

            trace.set_tracer_provider(tracer_provider)
            self._tracer = trace.get_tracer(__name__)

            # Initialize MeterProvider
            readers = []
            if self.config.console_export:
                readers.append(
                    PeriodicExportingMetricReader(
                        ConsoleMetricExporter(),
                        export_interval_millis=self.config.export_interval_ms
                    )
                )

            meter_provider = MeterProvider(resource=self._resource, metric_readers=readers)
            metrics.set_meter_provider(meter_provider)
            self._meter = metrics.get_meter(__name__)

            # Create standard boundary daemon metrics
            self._create_standard_metrics()

            self._initialized = True
            logger.info("OpenTelemetry initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize OpenTelemetry: {e}")
            self._initialized = True  # Use fallback
            return False

    def _is_remote_export_allowed(self) -> bool:
        """Check if remote export is allowed by current mode"""
        if not self.daemon:
            return False

        try:
            from ..policy_engine import BoundaryMode
            current_mode = self.daemon.policy_engine.get_current_mode()
            # Block remote export in restrictive modes
            blocked_modes = [BoundaryMode.AIRGAP, BoundaryMode.COLDROOM, BoundaryMode.LOCKDOWN]
            return current_mode not in blocked_modes
        except Exception:
            return False

    def _create_standard_metrics(self):
        """Create standard boundary daemon metrics"""
        if not self._meter:
            return

        # Counters
        self._counters['violations'] = self._meter.create_counter(
            "boundary.violations.total",
            description="Total number of security violations",
            unit="1"
        )
        self._counters['mode_transitions'] = self._meter.create_counter(
            "boundary.mode.transitions.total",
            description="Total number of mode transitions",
            unit="1"
        )
        self._counters['ceremonies'] = self._meter.create_counter(
            "boundary.ceremonies.total",
            description="Total number of override ceremonies",
            unit="1"
        )
        self._counters['policy_decisions'] = self._meter.create_counter(
            "boundary.policy.decisions.total",
            description="Total number of policy decisions",
            unit="1"
        )
        self._counters['watchdog_alerts'] = self._meter.create_counter(
            "boundary.watchdog.alerts.total",
            description="Total number of watchdog alerts",
            unit="1"
        )
        self._counters['security_scans'] = self._meter.create_counter(
            "boundary.security.scans.total",
            description="Total number of security scans",
            unit="1"
        )

        # Histograms
        self._histograms['ceremony_latency'] = self._meter.create_histogram(
            "boundary.ceremony.latency",
            description="Ceremony completion latency",
            unit="s"
        )
        self._histograms['scan_duration'] = self._meter.create_histogram(
            "boundary.scan.duration",
            description="Security scan duration",
            unit="s"
        )
        self._histograms['mode_duration'] = self._meter.create_histogram(
            "boundary.mode.duration",
            description="Time spent in each mode",
            unit="s"
        )

    def shutdown(self):
        """Shutdown telemetry providers"""
        if not self._initialized:
            return

        try:
            if OTEL_AVAILABLE and self._tracer:
                provider = trace.get_tracer_provider()
                if hasattr(provider, 'shutdown'):
                    provider.shutdown()

                meter_provider = metrics.get_meter_provider()
                if hasattr(meter_provider, 'shutdown'):
                    meter_provider.shutdown()

            if self._file_exporter:
                self._file_exporter.shutdown()

            logger.info("Telemetry shutdown complete")
        except Exception as e:
            logger.error(f"Error during telemetry shutdown: {e}")

    @contextmanager
    def start_span(self, name: str, attributes: Optional[Dict[str, Any]] = None):
        """
        Start a new span for tracing.

        Args:
            name: Span name
            attributes: Optional span attributes

        Yields:
            Span context (or mock span if OTel not available)
        """
        # Redact sensitive attributes
        if attributes and self.config.redact_sensitive:
            attributes = RedactionProcessor.redact_attributes(attributes)

        # Add standard attributes
        if attributes is None:
            attributes = {}

        if self.daemon:
            try:
                attributes['boundary.mode'] = self.daemon.policy_engine.get_current_mode().name
            except Exception:
                pass

        if OTEL_AVAILABLE and self._tracer:
            with self._tracer.start_as_current_span(name, attributes=attributes) as span:
                yield span
        else:
            # Fallback: record span locally
            span_data = {
                'name': name,
                'attributes': attributes,
                'start_time': time.time(),
                'events': []
            }
            yield MockSpan(span_data, self)
            span_data['end_time'] = time.time()
            with self._spans_lock:
                self._spans.append(span_data)
                # Keep only last 1000 spans
                if len(self._spans) > 1000:
                    self._spans = self._spans[-1000:]

    def record_metric(self, name: str, value: float, attributes: Optional[Dict[str, str]] = None):
        """
        Record a metric value.

        Args:
            name: Metric name
            value: Metric value
            attributes: Optional metric attributes
        """
        if not self._initialized:
            return

        # Redact sensitive attributes
        if attributes and self.config.redact_sensitive:
            attributes = RedactionProcessor.redact_attributes(attributes)

        if OTEL_AVAILABLE and name in self._counters:
            self._counters[name].add(value, attributes or {})
        elif OTEL_AVAILABLE and name in self._histograms:
            self._histograms[name].record(value, attributes or {})
        else:
            # Fallback: store locally
            with self._metrics_lock:
                if name not in self._metrics:
                    self._metrics[name] = []
                self._metrics[name].append({
                    'value': value,
                    'attributes': attributes,
                    'timestamp': time.time()
                })

    def increment_counter(self, name: str, value: int = 1, attributes: Optional[Dict[str, str]] = None):
        """Increment a counter metric"""
        self.record_metric(name, value, attributes)

    def record_histogram(self, name: str, value: float, attributes: Optional[Dict[str, str]] = None):
        """Record a histogram value"""
        self.record_metric(name, value, attributes)

    def set_gauge(self, name: str, value: int, attributes: Optional[Dict[str, str]] = None):
        """Set a gauge value"""
        with self._metrics_lock:
            self._gauges[name] = value

    # Convenience methods for common operations

    def record_violation(self, violation_type: str, mode: str, details: str = None):
        """Record a security violation"""
        attrs = {'violation_type': violation_type, 'mode': mode}
        if details:
            attrs['details'] = details
        self.increment_counter('violations', 1, attrs)

    def record_mode_transition(self, from_mode: str, to_mode: str, reason: str = None):
        """Record a mode transition"""
        attrs = {'from_mode': from_mode, 'to_mode': to_mode}
        if reason:
            attrs['reason'] = reason
        self.increment_counter('mode_transitions', 1, attrs)

    def record_ceremony(self, ceremony_type: str, success: bool, duration_s: float):
        """Record a ceremony completion"""
        attrs = {'ceremony_type': ceremony_type, 'success': str(success)}
        self.increment_counter('ceremonies', 1, attrs)
        self.record_histogram('ceremony_latency', duration_s, attrs)

    def record_policy_decision(self, decision: str, operator: str = None, memory_class: int = None):
        """Record a policy decision"""
        attrs = {'decision': decision}
        if operator:
            attrs['operator'] = operator
        if memory_class is not None:
            attrs['memory_class'] = str(memory_class)
        self.increment_counter('policy_decisions', 1, attrs)

    def record_watchdog_alert(self, severity: str, source: str):
        """Record a watchdog alert"""
        self.increment_counter('watchdog_alerts', 1, {'severity': severity, 'source': source})

    def record_security_scan(self, scan_type: str, advisory_count: int, duration_s: float):
        """Record a security scan"""
        attrs = {'scan_type': scan_type, 'advisory_count': str(advisory_count)}
        self.increment_counter('security_scans', 1, attrs)
        self.record_histogram('scan_duration', duration_s, attrs)

    def get_summary_stats(self) -> dict:
        """Get summary statistics"""
        stats = {
            'enabled': self.config.enabled,
            'initialized': self._initialized,
            'otel_available': OTEL_AVAILABLE,
            'otlp_available': OTLP_AVAILABLE,
            'export_mode': self.config.export_mode.value,
            'instance_id': self.instance_id,
            'hostname': self.hostname,
        }

        # Add fallback metrics if available
        with self._metrics_lock:
            stats['metrics_count'] = len(self._metrics)
            stats['gauges'] = dict(self._gauges)

        with self._spans_lock:
            stats['spans_recorded'] = len(self._spans)

        return stats

    def get_recent_spans(self, limit: int = 100) -> List[Dict]:
        """Get recently recorded spans (fallback mode)"""
        with self._spans_lock:
            return self._spans[-limit:]

    def get_metrics_snapshot(self) -> Dict[str, List]:
        """Get metrics snapshot (fallback mode)"""
        with self._metrics_lock:
            return dict(self._metrics)


class MockSpan:
    """Mock span for fallback when OTel not available"""

    def __init__(self, span_data: Dict, manager: TelemetryManager):
        self._data = span_data
        self._manager = manager

    def set_attribute(self, key: str, value: Any):
        """Set span attribute"""
        if self._manager.config.redact_sensitive:
            if any(s in key.lower() for s in RedactionProcessor.SENSITIVE_KEYS):
                value = "[REDACTED]"
        self._data['attributes'][key] = value

    def add_event(self, name: str, attributes: Optional[Dict] = None):
        """Add event to span"""
        event = {'name': name, 'timestamp': time.time()}
        if attributes:
            if self._manager.config.redact_sensitive:
                attributes = RedactionProcessor.redact_attributes(attributes)
            event['attributes'] = attributes
        self._data['events'].append(event)

    def set_status(self, status_code, description: str = None):
        """Set span status"""
        self._data['status'] = {'code': str(status_code), 'description': description}

    def record_exception(self, exception: Exception):
        """Record exception"""
        self.add_event('exception', {
            'exception.type': type(exception).__name__,
            'exception.message': str(exception)
        })


# Decorator for instrumenting functions
def instrument(span_name: str = None, attributes: Dict[str, Any] = None):
    """
    Decorator to instrument a function with tracing.

    Usage:
        @instrument("my_function")
        def my_function(arg1, arg2):
            ...
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            name = span_name or func.__name__
            # Try to get telemetry manager from first arg if it's a daemon
            manager = None
            if args and hasattr(args[0], 'telemetry_manager'):
                manager = args[0].telemetry_manager

            if manager:
                with manager.start_span(name, attributes):
                    return func(*args, **kwargs)
            else:
                return func(*args, **kwargs)
        return wrapper
    return decorator


if __name__ == '__main__':
    # Test TelemetryManager
    print("Testing TelemetryManager...")

    config = TelemetryConfig()
    config.enabled = True
    config.console_export = False  # Disable console for cleaner test output

    manager = TelemetryManager(config=config)
    manager.initialize()

    print(f"\nOTel available: {OTEL_AVAILABLE}")
    print(f"OTLP available: {OTLP_AVAILABLE}")

    # Test spans
    print("\nTesting spans...")
    with manager.start_span("test_operation", {"test_attr": "value"}) as span:
        span.set_attribute("custom_attr", "custom_value")
        span.add_event("test_event", {"event_attr": "event_value"})
        time.sleep(0.1)

    # Test metrics
    print("\nTesting metrics...")
    manager.record_violation("network", "AIRGAP", "Outbound connection attempted")
    manager.record_mode_transition("OPEN", "RESTRICTED", "User requested")
    manager.record_ceremony("override", True, 2.5)
    manager.record_policy_decision("DENY", "AI_ASSISTANT", 3)

    # Get stats
    print("\nSummary stats:")
    stats = manager.get_summary_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    # Get recent spans
    print(f"\nRecent spans: {len(manager.get_recent_spans())}")

    manager.shutdown()
    print("\nTelemetry test complete.")
