"""
Health Check API for Boundary Daemon

Provides health check endpoints for:
- Kubernetes liveness/readiness probes
- systemd watchdog integration
- Docker HEALTHCHECK
- Generic monitoring systems

Endpoints:
- /health - Basic health status
- /health/live - Liveness probe (is process alive?)
- /health/ready - Readiness probe (can accept traffic?)
- /health/startup - Startup probe (has initialization completed?)

Usage:
    from daemon.api.health import HealthCheckServer, get_health_server

    server = get_health_server()
    server.start(port=8080)

    # Check health programmatically
    status = server.get_health_status()
"""

import json
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional, Any, Callable

logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health check status values."""
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DEGRADED = "degraded"
    STARTING = "starting"
    UNKNOWN = "unknown"


@dataclass
class ComponentHealth:
    """Health status of a single component."""
    name: str
    status: HealthStatus
    message: str = ""
    last_check: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthCheckResult:
    """Complete health check result."""
    status: HealthStatus
    timestamp: str
    uptime_seconds: float
    version: str = "1.0.0"
    components: List[ComponentHealth] = field(default_factory=list)
    checks_passed: int = 0
    checks_failed: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'status': self.status.value,
            'timestamp': self.timestamp,
            'uptime_seconds': self.uptime_seconds,
            'version': self.version,
            'checks_passed': self.checks_passed,
            'checks_failed': self.checks_failed,
            'components': [
                {
                    'name': c.name,
                    'status': c.status.value,
                    'message': c.message,
                    'last_check': c.last_check,
                    'details': c.details,
                }
                for c in self.components
            ],
        }


class HealthChecker:
    """
    Manages health checks for the Boundary Daemon.

    Supports custom health check functions for different components.
    """

    def __init__(self):
        self._start_time = time.time()
        self._checks: Dict[str, Callable[[], ComponentHealth]] = {}
        self._startup_complete = False
        self._startup_time: Optional[float] = None
        self._last_results: Dict[str, ComponentHealth] = {}
        self._lock = threading.Lock()

        # Register default checks
        self._register_default_checks()

    def _register_default_checks(self) -> None:
        """Register default health checks."""
        self.register_check("daemon", self._check_daemon)
        self.register_check("memory", self._check_memory)
        self.register_check("disk", self._check_disk)

    def register_check(self, name: str, check_fn: Callable[[], ComponentHealth]) -> None:
        """Register a custom health check."""
        with self._lock:
            self._checks[name] = check_fn
            logger.debug(f"Registered health check: {name}")

    def unregister_check(self, name: str) -> None:
        """Unregister a health check."""
        with self._lock:
            if name in self._checks:
                del self._checks[name]

    def mark_startup_complete(self) -> None:
        """Mark that startup has completed."""
        self._startup_complete = True
        self._startup_time = time.time()
        logger.info("Startup marked as complete")

    def is_startup_complete(self) -> bool:
        """Check if startup is complete."""
        return self._startup_complete

    def get_uptime(self) -> float:
        """Get daemon uptime in seconds."""
        return time.time() - self._start_time

    def _check_daemon(self) -> ComponentHealth:
        """Check daemon health."""
        try:
            # Basic process health check
            import psutil
            process = psutil.Process()

            return ComponentHealth(
                name="daemon",
                status=HealthStatus.HEALTHY,
                message="Daemon is running",
                last_check=datetime.utcnow().isoformat() + 'Z',
                details={
                    'pid': process.pid,
                    'cpu_percent': process.cpu_percent(),
                    'memory_mb': process.memory_info().rss / (1024 * 1024),
                    'threads': process.num_threads(),
                },
            )
        except ImportError:
            return ComponentHealth(
                name="daemon",
                status=HealthStatus.HEALTHY,
                message="Daemon is running (psutil not available)",
                last_check=datetime.utcnow().isoformat() + 'Z',
            )
        except Exception as e:
            return ComponentHealth(
                name="daemon",
                status=HealthStatus.UNHEALTHY,
                message=str(e),
                last_check=datetime.utcnow().isoformat() + 'Z',
            )

    def _check_memory(self) -> ComponentHealth:
        """Check memory usage."""
        try:
            import psutil
            memory = psutil.virtual_memory()

            # Consider unhealthy if memory usage > 90%
            if memory.percent > 90:
                status = HealthStatus.UNHEALTHY
                message = f"Memory usage critical: {memory.percent}%"
            elif memory.percent > 80:
                status = HealthStatus.DEGRADED
                message = f"Memory usage high: {memory.percent}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Memory usage normal: {memory.percent}%"

            return ComponentHealth(
                name="memory",
                status=status,
                message=message,
                last_check=datetime.utcnow().isoformat() + 'Z',
                details={
                    'total_mb': memory.total / (1024 * 1024),
                    'available_mb': memory.available / (1024 * 1024),
                    'percent': memory.percent,
                },
            )
        except ImportError:
            return ComponentHealth(
                name="memory",
                status=HealthStatus.UNKNOWN,
                message="psutil not available",
                last_check=datetime.utcnow().isoformat() + 'Z',
            )
        except Exception as e:
            return ComponentHealth(
                name="memory",
                status=HealthStatus.UNKNOWN,
                message=str(e),
                last_check=datetime.utcnow().isoformat() + 'Z',
            )

    def _check_disk(self) -> ComponentHealth:
        """Check disk space."""
        try:
            import psutil
            # Check the partition where logs are stored
            disk = psutil.disk_usage('/var/log')

            if disk.percent > 95:
                status = HealthStatus.UNHEALTHY
                message = f"Disk usage critical: {disk.percent}%"
            elif disk.percent > 85:
                status = HealthStatus.DEGRADED
                message = f"Disk usage high: {disk.percent}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Disk usage normal: {disk.percent}%"

            return ComponentHealth(
                name="disk",
                status=status,
                message=message,
                last_check=datetime.utcnow().isoformat() + 'Z',
                details={
                    'total_gb': disk.total / (1024 * 1024 * 1024),
                    'free_gb': disk.free / (1024 * 1024 * 1024),
                    'percent': disk.percent,
                },
            )
        except ImportError:
            return ComponentHealth(
                name="disk",
                status=HealthStatus.UNKNOWN,
                message="psutil not available",
                last_check=datetime.utcnow().isoformat() + 'Z',
            )
        except Exception as e:
            return ComponentHealth(
                name="disk",
                status=HealthStatus.UNKNOWN,
                message=str(e),
                last_check=datetime.utcnow().isoformat() + 'Z',
            )

    def run_checks(self) -> HealthCheckResult:
        """Run all health checks and return result."""
        timestamp = datetime.utcnow().isoformat() + 'Z'
        components = []
        passed = 0
        failed = 0

        with self._lock:
            for name, check_fn in self._checks.items():
                try:
                    result = check_fn()
                    components.append(result)
                    self._last_results[name] = result

                    if result.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED):
                        passed += 1
                    else:
                        failed += 1
                except Exception as e:
                    logger.warning(f"Health check '{name}' failed: {e}")
                    components.append(ComponentHealth(
                        name=name,
                        status=HealthStatus.UNHEALTHY,
                        message=str(e),
                        last_check=timestamp,
                    ))
                    failed += 1

        # Determine overall status
        if failed > 0:
            overall_status = HealthStatus.UNHEALTHY
        elif any(c.status == HealthStatus.DEGRADED for c in components):
            overall_status = HealthStatus.DEGRADED
        elif not self._startup_complete:
            overall_status = HealthStatus.STARTING
        else:
            overall_status = HealthStatus.HEALTHY

        return HealthCheckResult(
            status=overall_status,
            timestamp=timestamp,
            uptime_seconds=self.get_uptime(),
            components=components,
            checks_passed=passed,
            checks_failed=failed,
        )

    def check_liveness(self) -> Tuple[bool, str]:
        """
        Liveness check - is the process alive and responsive?

        Used by Kubernetes livenessProbe.
        Returns True if process should stay alive.
        """
        # Simple liveness - can we run code?
        try:
            # Check daemon component
            daemon_health = self._checks.get('daemon')
            if daemon_health:
                result = daemon_health()
                return result.status != HealthStatus.UNHEALTHY, result.message
            return True, "Process is alive"
        except Exception as e:
            return False, str(e)

    def check_readiness(self) -> Tuple[bool, str]:
        """
        Readiness check - can we accept traffic?

        Used by Kubernetes readinessProbe.
        Returns True if daemon can handle requests.
        """
        if not self._startup_complete:
            return False, "Startup not complete"

        # Run full health check
        result = self.run_checks()
        is_ready = result.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED)
        return is_ready, f"Status: {result.status.value}"

    def check_startup(self) -> Tuple[bool, str]:
        """
        Startup check - has initialization completed?

        Used by Kubernetes startupProbe.
        Returns True once startup is complete.
        """
        if self._startup_complete:
            return True, "Startup complete"
        return False, "Starting up..."


class HealthRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for health endpoints."""

    def __init__(self, *args, checker: HealthChecker, **kwargs):
        self.checker = checker
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args) -> None:
        """Suppress default logging."""
        pass

    def _send_json_response(self, status_code: int, data: Dict[str, Any]) -> None:
        """Send JSON response."""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-cache, no-store')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_GET(self) -> None:
        """Handle GET requests."""
        if self.path == '/health' or self.path == '/':
            self._handle_health()
        elif self.path == '/health/live' or self.path == '/livez':
            self._handle_liveness()
        elif self.path == '/health/ready' or self.path == '/readyz':
            self._handle_readiness()
        elif self.path == '/health/startup' or self.path == '/startupz':
            self._handle_startup()
        else:
            self.send_error(404, "Not Found")

    def _handle_health(self) -> None:
        """Handle /health endpoint."""
        result = self.checker.run_checks()
        status_code = 200 if result.status != HealthStatus.UNHEALTHY else 503
        self._send_json_response(status_code, result.to_dict())

    def _handle_liveness(self) -> None:
        """Handle /health/live endpoint."""
        is_alive, message = self.checker.check_liveness()
        status_code = 200 if is_alive else 503
        self._send_json_response(status_code, {
            'status': 'ok' if is_alive else 'fail',
            'message': message,
        })

    def _handle_readiness(self) -> None:
        """Handle /health/ready endpoint."""
        is_ready, message = self.checker.check_readiness()
        status_code = 200 if is_ready else 503
        self._send_json_response(status_code, {
            'status': 'ok' if is_ready else 'fail',
            'message': message,
        })

    def _handle_startup(self) -> None:
        """Handle /health/startup endpoint."""
        is_started, message = self.checker.check_startup()
        status_code = 200 if is_started else 503
        self._send_json_response(status_code, {
            'status': 'ok' if is_started else 'fail',
            'message': message,
        })


class HealthCheckServer:
    """
    HTTP server for health check endpoints.

    Supports:
    - Kubernetes probes (liveness, readiness, startup)
    - systemd watchdog (via sd_notify)
    - Docker HEALTHCHECK
    """

    def __init__(self, checker: Optional[HealthChecker] = None):
        self.checker = checker or HealthChecker()
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._port = 8080
        self._systemd_watchdog = False

    def start(self, port: int = 8080, host: str = "0.0.0.0") -> bool:
        """Start the health check server."""
        if self._running:
            return True

        self._port = port

        try:
            # Create handler factory with checker
            def handler_factory(*args, **kwargs):
                return HealthRequestHandler(*args, checker=self.checker, **kwargs)

            self._server = HTTPServer((host, port), handler_factory)
            self._running = True

            self._thread = threading.Thread(
                target=self._server.serve_forever,
                daemon=True,
            )
            self._thread.start()

            logger.info(f"Health check server started on {host}:{port}")

            # Start systemd watchdog if available
            self._start_systemd_watchdog()

            return True
        except Exception as e:
            logger.error(f"Failed to start health server: {e}")
            return False

    def stop(self) -> None:
        """Stop the health check server."""
        self._running = False

        if self._server:
            self._server.shutdown()
            self._server = None

        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

        logger.info("Health check server stopped")

    def _start_systemd_watchdog(self) -> None:
        """Start systemd watchdog integration."""
        watchdog_usec = os.environ.get('WATCHDOG_USEC')
        if not watchdog_usec:
            return

        try:
            interval = int(watchdog_usec) / 2_000_000  # Half the interval, in seconds
            self._systemd_watchdog = True

            def watchdog_loop():
                while self._running:
                    # Notify systemd
                    self._sd_notify("WATCHDOG=1")
                    time.sleep(interval)

            thread = threading.Thread(target=watchdog_loop, daemon=True)
            thread.start()
            logger.info(f"Systemd watchdog started (interval: {interval}s)")
        except Exception as e:
            logger.warning(f"Failed to start systemd watchdog: {e}")

    def _sd_notify(self, state: str) -> None:
        """Send notification to systemd."""
        notify_socket = os.environ.get('NOTIFY_SOCKET')
        if not notify_socket:
            return

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            if notify_socket.startswith('@'):
                notify_socket = '\0' + notify_socket[1:]
            sock.connect(notify_socket)
            sock.sendall(state.encode('utf-8'))
            sock.close()
        except Exception as e:
            logger.debug(f"sd_notify failed: {e}")

    def notify_ready(self) -> None:
        """Notify systemd that daemon is ready."""
        self.checker.mark_startup_complete()
        self._sd_notify("READY=1")

    def notify_stopping(self) -> None:
        """Notify systemd that daemon is stopping."""
        self._sd_notify("STOPPING=1")

    def get_health_status(self) -> HealthCheckResult:
        """Get current health status."""
        return self.checker.run_checks()

    def register_check(self, name: str, check_fn: Callable[[], ComponentHealth]) -> None:
        """Register a custom health check."""
        self.checker.register_check(name, check_fn)

    @property
    def port(self) -> int:
        """Get the server port."""
        return self._port


# Global server instance
_global_server: Optional[HealthCheckServer] = None
_server_lock = threading.Lock()


def get_health_server() -> HealthCheckServer:
    """Get the global health check server."""
    global _global_server

    if _global_server is None:
        with _server_lock:
            if _global_server is None:
                _global_server = HealthCheckServer()

    return _global_server


def create_health_server(checker: Optional[HealthChecker] = None) -> HealthCheckServer:
    """Create a new health check server instance."""
    return HealthCheckServer(checker)


# Convenience type alias
from typing import Tuple


if __name__ == '__main__':
    print("Testing Health Check API...")

    # Create server
    server = HealthCheckServer()

    # Register custom check
    def check_sandbox():
        return ComponentHealth(
            name="sandbox",
            status=HealthStatus.HEALTHY,
            message="Sandbox module ready",
            last_check=datetime.utcnow().isoformat() + 'Z',
            details={'active_sandboxes': 0},
        )

    server.register_check("sandbox", check_sandbox)

    # Start server
    server.start(port=8080)
    print("Server started on http://localhost:8080")

    # Mark startup complete
    server.notify_ready()

    # Get status
    status = server.get_health_status()
    print(f"\nHealth Status: {status.status.value}")
    print(f"Uptime: {status.uptime_seconds:.1f}s")
    print(f"Components: {len(status.components)}")

    for comp in status.components:
        print(f"  - {comp.name}: {comp.status.value} ({comp.message})")

    print("\nEndpoints available:")
    print("  GET /health       - Full health status")
    print("  GET /health/live  - Liveness probe")
    print("  GET /health/ready - Readiness probe")
    print("  GET /health/startup - Startup probe")

    print("\nPress Ctrl+C to stop...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
        print("\nServer stopped.")
