"""
Telemetry Module for Boundary Daemon
Provides OpenTelemetry integration for observability.

Plan 9: OpenTelemetry Integration
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

__all__ = [
    'TelemetryManager',
    'TelemetryConfig',
    'ExportMode',
    'RedactionProcessor',
    'instrument',
    'OTEL_AVAILABLE',
    'OTLP_AVAILABLE',
]
