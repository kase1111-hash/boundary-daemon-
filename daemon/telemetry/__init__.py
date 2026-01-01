"""
Telemetry Module for Boundary Daemon
Provides OpenTelemetry integration for observability and Prometheus metrics.

Plan 9: OpenTelemetry Integration
Plan 10: Prometheus Metrics
"""

from .otel_setup import (
    TelemetryManager,
    TelemetryConfig,
    ExportMode,
    RedactionProcessor,
    instrument,
    OTEL_AVAILABLE,
    OTLP_AVAILABLE
)

from .prometheus_metrics import (
    BoundaryMetrics,
    MetricsExporter,
    Counter,
    Gauge,
    Histogram,
    get_metrics_exporter,
    PROMETHEUS_AVAILABLE,
)

__all__ = [
    # OpenTelemetry
    'TelemetryManager',
    'TelemetryConfig',
    'ExportMode',
    'RedactionProcessor',
    'instrument',
    'OTEL_AVAILABLE',
    'OTLP_AVAILABLE',
    # Prometheus
    'BoundaryMetrics',
    'MetricsExporter',
    'Counter',
    'Gauge',
    'Histogram',
    'get_metrics_exporter',
    'PROMETHEUS_AVAILABLE',
]
