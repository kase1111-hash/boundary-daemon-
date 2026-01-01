"""
Prometheus Metrics Exporter for Boundary Daemon

Exposes metrics in Prometheus format for monitoring:
- Sandbox lifecycle and resource usage
- Policy decisions and violations
- Firewall blocked connections
- Daemon health and performance

Metrics are exposed via HTTP endpoint (default :9090/metrics).

Usage:
    from daemon.telemetry.prometheus_metrics import MetricsExporter

    exporter = MetricsExporter(port=9090)
    exporter.start()

    # Update metrics
    exporter.sandbox_created("worker-1", "standard")
    exporter.policy_decision("recall", "allow")
    exporter.firewall_blocked("10.0.0.1", 443)

    # In Prometheus config:
    # scrape_configs:
    #   - job_name: 'boundary-daemon'
    #     static_configs:
    #       - targets: ['localhost:9090']
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional, Any
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class MetricValue:
    """A single metric value with labels."""
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: Optional[float] = None


class Counter:
    """A monotonically increasing counter."""

    def __init__(self, name: str, help_text: str, labels: List[str] = None):
        self.name = name
        self.help_text = help_text
        self.label_names = labels or []
        self._values: Dict[tuple, float] = defaultdict(float)
        self._lock = threading.Lock()

    def inc(self, value: float = 1.0, **labels) -> None:
        """Increment the counter."""
        label_values = tuple(labels.get(l, "") for l in self.label_names)
        with self._lock:
            self._values[label_values] += value

    def get(self, **labels) -> float:
        """Get current value."""
        label_values = tuple(labels.get(l, "") for l in self.label_names)
        with self._lock:
            return self._values[label_values]

    def collect(self) -> List[MetricValue]:
        """Collect all values for export."""
        with self._lock:
            return [
                MetricValue(
                    value=v,
                    labels=dict(zip(self.label_names, k)),
                )
                for k, v in self._values.items()
            ]


class Gauge:
    """A metric that can go up and down."""

    def __init__(self, name: str, help_text: str, labels: List[str] = None):
        self.name = name
        self.help_text = help_text
        self.label_names = labels or []
        self._values: Dict[tuple, float] = {}
        self._lock = threading.Lock()

    def set(self, value: float, **labels) -> None:
        """Set the gauge value."""
        label_values = tuple(labels.get(l, "") for l in self.label_names)
        with self._lock:
            self._values[label_values] = value

    def inc(self, value: float = 1.0, **labels) -> None:
        """Increment the gauge."""
        label_values = tuple(labels.get(l, "") for l in self.label_names)
        with self._lock:
            self._values[label_values] = self._values.get(label_values, 0) + value

    def dec(self, value: float = 1.0, **labels) -> None:
        """Decrement the gauge."""
        self.inc(-value, **labels)

    def get(self, **labels) -> float:
        """Get current value."""
        label_values = tuple(labels.get(l, "") for l in self.label_names)
        with self._lock:
            return self._values.get(label_values, 0)

    def collect(self) -> List[MetricValue]:
        """Collect all values for export."""
        with self._lock:
            return [
                MetricValue(
                    value=v,
                    labels=dict(zip(self.label_names, k)),
                )
                for k, v in self._values.items()
            ]


class Histogram:
    """A histogram for measuring distributions."""

    DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

    def __init__(
        self,
        name: str,
        help_text: str,
        labels: List[str] = None,
        buckets: tuple = None,
    ):
        self.name = name
        self.help_text = help_text
        self.label_names = labels or []
        self.buckets = buckets or self.DEFAULT_BUCKETS
        self._counts: Dict[tuple, Dict[float, int]] = defaultdict(lambda: defaultdict(int))
        self._sums: Dict[tuple, float] = defaultdict(float)
        self._totals: Dict[tuple, int] = defaultdict(int)
        self._lock = threading.Lock()

    def observe(self, value: float, **labels) -> None:
        """Observe a value."""
        label_values = tuple(labels.get(l, "") for l in self.label_names)
        with self._lock:
            self._sums[label_values] += value
            self._totals[label_values] += 1
            for bucket in self.buckets:
                if value <= bucket:
                    self._counts[label_values][bucket] += 1

    def collect(self) -> List[MetricValue]:
        """Collect all values for export."""
        result = []
        with self._lock:
            for label_values in set(self._sums.keys()) | set(self._totals.keys()):
                labels = dict(zip(self.label_names, label_values))

                # Bucket values (cumulative)
                cumulative = 0
                for bucket in self.buckets:
                    cumulative += self._counts[label_values][bucket]
                    result.append(MetricValue(
                        value=cumulative,
                        labels={**labels, 'le': str(bucket)},
                    ))
                # +Inf bucket
                result.append(MetricValue(
                    value=self._totals[label_values],
                    labels={**labels, 'le': '+Inf'},
                ))

                # Sum and count
                result.append(MetricValue(
                    value=self._sums[label_values],
                    labels={**labels, '_type': 'sum'},
                ))
                result.append(MetricValue(
                    value=self._totals[label_values],
                    labels={**labels, '_type': 'count'},
                ))

        return result


class BoundaryMetrics:
    """
    All metrics for Boundary Daemon.

    Naming convention: boundary_<subsystem>_<metric>_<unit>
    """

    def __init__(self):
        # Sandbox metrics
        self.sandbox_active = Gauge(
            "boundary_sandbox_active",
            "Number of currently active sandboxes",
            labels=["profile"],
        )
        self.sandbox_created_total = Counter(
            "boundary_sandbox_created_total",
            "Total number of sandboxes created",
            labels=["profile"],
        )
        self.sandbox_completed_total = Counter(
            "boundary_sandbox_completed_total",
            "Total number of sandboxes completed",
            labels=["profile", "exit_status"],
        )
        self.sandbox_failed_total = Counter(
            "boundary_sandbox_failed_total",
            "Total number of sandbox failures",
            labels=["profile", "reason"],
        )
        self.sandbox_runtime_seconds = Histogram(
            "boundary_sandbox_runtime_seconds",
            "Sandbox runtime duration in seconds",
            labels=["profile"],
            buckets=(0.1, 0.5, 1, 5, 10, 30, 60, 120, 300, 600),
        )

        # Resource usage (from cgroups)
        self.sandbox_cpu_seconds = Counter(
            "boundary_sandbox_cpu_seconds_total",
            "Total CPU time consumed by sandboxes",
            labels=["sandbox_id"],
        )
        self.sandbox_memory_bytes = Gauge(
            "boundary_sandbox_memory_bytes",
            "Current memory usage of sandboxes",
            labels=["sandbox_id"],
        )
        self.sandbox_memory_peak_bytes = Gauge(
            "boundary_sandbox_memory_peak_bytes",
            "Peak memory usage of sandboxes",
            labels=["sandbox_id"],
        )

        # Policy metrics
        self.policy_decisions_total = Counter(
            "boundary_policy_decisions_total",
            "Total policy decisions made",
            labels=["request_type", "result"],
        )
        self.policy_violations_total = Counter(
            "boundary_policy_violations_total",
            "Total policy violations detected",
            labels=["violation_type"],
        )

        # Firewall metrics
        self.firewall_rules_active = Gauge(
            "boundary_firewall_rules_active",
            "Number of active firewall rules",
            labels=["sandbox_id"],
        )
        self.firewall_blocked_total = Counter(
            "boundary_firewall_blocked_total",
            "Total blocked connections",
            labels=["sandbox_id", "destination"],
        )

        # Ceremony metrics
        self.ceremony_requests_total = Counter(
            "boundary_ceremony_requests_total",
            "Total ceremony requests",
            labels=["ceremony_type", "result"],
        )
        self.ceremony_duration_seconds = Histogram(
            "boundary_ceremony_duration_seconds",
            "Ceremony completion duration",
            labels=["ceremony_type"],
            buckets=(1, 5, 10, 30, 60, 120, 300),
        )

        # Mode metrics
        self.boundary_mode = Gauge(
            "boundary_mode_current",
            "Current boundary mode (0=OPEN to 5=LOCKDOWN)",
        )
        self.mode_transitions_total = Counter(
            "boundary_mode_transitions_total",
            "Total mode transitions",
            labels=["from_mode", "to_mode", "operator"],
        )

        # Daemon health
        self.daemon_uptime_seconds = Gauge(
            "boundary_daemon_uptime_seconds",
            "Daemon uptime in seconds",
        )
        self.daemon_events_total = Counter(
            "boundary_daemon_events_total",
            "Total events logged",
            labels=["event_type"],
        )

        # Detection metrics (YARA, Sigma, IOC)
        self.detection_matches_total = Counter(
            "boundary_detection_matches_total",
            "Total detection rule matches",
            labels=["engine", "rule_name", "severity"],
        )

        # Store all metrics for collection
        self._all_metrics = [
            self.sandbox_active,
            self.sandbox_created_total,
            self.sandbox_completed_total,
            self.sandbox_failed_total,
            self.sandbox_runtime_seconds,
            self.sandbox_cpu_seconds,
            self.sandbox_memory_bytes,
            self.sandbox_memory_peak_bytes,
            self.policy_decisions_total,
            self.policy_violations_total,
            self.firewall_rules_active,
            self.firewall_blocked_total,
            self.ceremony_requests_total,
            self.ceremony_duration_seconds,
            self.boundary_mode,
            self.mode_transitions_total,
            self.daemon_uptime_seconds,
            self.daemon_events_total,
            self.detection_matches_total,
        ]

    def collect_all(self) -> str:
        """Collect all metrics in Prometheus text format."""
        lines = []

        for metric in self._all_metrics:
            # Add HELP and TYPE
            metric_type = "gauge"
            if isinstance(metric, Counter):
                metric_type = "counter"
            elif isinstance(metric, Histogram):
                metric_type = "histogram"

            lines.append(f"# HELP {metric.name} {metric.help_text}")
            lines.append(f"# TYPE {metric.name} {metric_type}")

            # Add values
            for mv in metric.collect():
                if isinstance(metric, Histogram):
                    # Handle histogram special cases
                    if '_type' in mv.labels:
                        suffix = '_' + mv.labels.pop('_type')
                        metric_name = metric.name + suffix
                    elif 'le' in mv.labels:
                        metric_name = metric.name + '_bucket'
                    else:
                        metric_name = metric.name
                else:
                    metric_name = metric.name

                if mv.labels:
                    label_str = ','.join(
                        f'{k}="{v}"' for k, v in mv.labels.items()
                    )
                    lines.append(f'{metric_name}{{{label_str}}} {mv.value}')
                else:
                    lines.append(f'{metric_name} {mv.value}')

            lines.append('')  # Empty line between metrics

        return '\n'.join(lines)


class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler for /metrics endpoint."""

    metrics: BoundaryMetrics = None

    def do_GET(self):
        if self.path == '/metrics':
            content = self.metrics.collect_all()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content.encode('utf-8'))
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress default logging
        pass


class MetricsExporter:
    """
    Prometheus metrics exporter for Boundary Daemon.

    Starts an HTTP server that exposes metrics at /metrics endpoint.
    """

    def __init__(self, port: int = 9090, host: str = "0.0.0.0"):
        self.port = port
        self.host = host
        self.metrics = BoundaryMetrics()
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._start_time = time.time()

    def start(self) -> bool:
        """Start the metrics server."""
        try:
            MetricsHandler.metrics = self.metrics

            self._server = HTTPServer(
                (self.host, self.port),
                MetricsHandler,
            )

            self._thread = threading.Thread(
                target=self._server.serve_forever,
                daemon=True,
            )
            self._thread.start()

            logger.info(f"Prometheus metrics server started on {self.host}:{self.port}")
            return True

        except Exception as e:
            logger.error(f"Failed to start metrics server: {e}")
            return False

    def stop(self) -> None:
        """Stop the metrics server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        logger.info("Prometheus metrics server stopped")

    def update_uptime(self) -> None:
        """Update daemon uptime metric."""
        self.metrics.daemon_uptime_seconds.set(time.time() - self._start_time)

    # Convenience methods for common operations

    def sandbox_created(self, sandbox_id: str, profile: str) -> None:
        """Record sandbox creation."""
        self.metrics.sandbox_created_total.inc(profile=profile)
        self.metrics.sandbox_active.inc(profile=profile)

    def sandbox_completed(
        self,
        sandbox_id: str,
        profile: str,
        runtime_seconds: float,
        exit_code: int,
    ) -> None:
        """Record sandbox completion."""
        exit_status = "success" if exit_code == 0 else "failed"
        self.metrics.sandbox_completed_total.inc(profile=profile, exit_status=exit_status)
        self.metrics.sandbox_active.dec(profile=profile)
        self.metrics.sandbox_runtime_seconds.observe(runtime_seconds, profile=profile)

    def sandbox_failed(self, sandbox_id: str, profile: str, reason: str) -> None:
        """Record sandbox failure."""
        self.metrics.sandbox_failed_total.inc(profile=profile, reason=reason)
        self.metrics.sandbox_active.dec(profile=profile)

    def sandbox_resource_usage(
        self,
        sandbox_id: str,
        cpu_seconds: float,
        memory_bytes: int,
        memory_peak_bytes: int,
    ) -> None:
        """Update sandbox resource metrics."""
        self.metrics.sandbox_cpu_seconds.inc(cpu_seconds, sandbox_id=sandbox_id)
        self.metrics.sandbox_memory_bytes.set(memory_bytes, sandbox_id=sandbox_id)
        self.metrics.sandbox_memory_peak_bytes.set(memory_peak_bytes, sandbox_id=sandbox_id)

    def policy_decision(self, request_type: str, result: str) -> None:
        """Record a policy decision."""
        self.metrics.policy_decisions_total.inc(
            request_type=request_type,
            result=result,
        )

    def policy_violation(self, violation_type: str) -> None:
        """Record a policy violation."""
        self.metrics.policy_violations_total.inc(violation_type=violation_type)

    def firewall_blocked(self, sandbox_id: str, destination: str) -> None:
        """Record a blocked connection."""
        self.metrics.firewall_blocked_total.inc(
            sandbox_id=sandbox_id,
            destination=destination,
        )

    def ceremony_completed(
        self,
        ceremony_type: str,
        result: str,
        duration_seconds: float,
    ) -> None:
        """Record ceremony completion."""
        self.metrics.ceremony_requests_total.inc(
            ceremony_type=ceremony_type,
            result=result,
        )
        self.metrics.ceremony_duration_seconds.observe(
            duration_seconds,
            ceremony_type=ceremony_type,
        )

    def mode_transition(
        self,
        from_mode: str,
        to_mode: str,
        operator: str,
    ) -> None:
        """Record mode transition."""
        self.metrics.mode_transitions_total.inc(
            from_mode=from_mode,
            to_mode=to_mode,
            operator=operator,
        )
        # Map mode names to numbers
        mode_values = {
            'OPEN': 0, 'RESTRICTED': 1, 'TRUSTED': 2,
            'AIRGAP': 3, 'COLDROOM': 4, 'LOCKDOWN': 5,
        }
        self.metrics.boundary_mode.set(mode_values.get(to_mode, -1))

    def detection_match(
        self,
        engine: str,
        rule_name: str,
        severity: str,
    ) -> None:
        """Record a detection match."""
        self.metrics.detection_matches_total.inc(
            engine=engine,
            rule_name=rule_name,
            severity=severity,
        )

    def event_logged(self, event_type: str) -> None:
        """Record an event being logged."""
        self.metrics.daemon_events_total.inc(event_type=event_type)


# Global exporter instance
_metrics_exporter: Optional[MetricsExporter] = None


def get_metrics_exporter(port: int = 9090) -> MetricsExporter:
    """Get or create the global metrics exporter."""
    global _metrics_exporter
    if _metrics_exporter is None:
        _metrics_exporter = MetricsExporter(port=port)
    return _metrics_exporter


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    print("Testing Prometheus Metrics Exporter...")

    exporter = MetricsExporter(port=9090)

    if exporter.start():
        print(f"\nMetrics available at http://localhost:9090/metrics")
        print("Health check at http://localhost:9090/health")

        # Simulate some activity
        exporter.sandbox_created("sandbox-1", "standard")
        exporter.sandbox_created("sandbox-2", "strict")
        exporter.policy_decision("recall", "allow")
        exporter.policy_decision("recall", "deny")
        exporter.policy_decision("tool", "allow")
        exporter.firewall_blocked("sandbox-1", "evil.com:443")
        exporter.mode_transition("OPEN", "RESTRICTED", "human")
        exporter.sandbox_completed("sandbox-1", "standard", 5.2, 0)

        print("\nSample metrics output:")
        print("-" * 50)
        print(exporter.metrics.collect_all()[:2000])
        print("...")

        print("\nPress Ctrl+C to stop")
        try:
            while True:
                exporter.update_uptime()
                time.sleep(1)
        except KeyboardInterrupt:
            pass

        exporter.stop()
    else:
        print("Failed to start metrics server")

    print("\nMetrics exporter test complete.")
