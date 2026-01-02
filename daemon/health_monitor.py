"""
Health Monitor - Process Health and Heartbeat Monitoring
Monitors daemon health, component responsiveness, and provides health status.

Features:
- Heartbeat tracking for daemon liveness
- Component health checks
- Watchdog timer for hang detection
- Health status API
- Degraded state detection and alerts
- Uptime tracking
"""

import os
import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Callable, Any
from datetime import datetime
from enum import Enum
from collections import deque

from .dreaming import dream_operation_start, dream_operation_complete

logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Overall health status levels"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ComponentStatus(Enum):
    """Individual component status"""
    OK = "ok"
    WARNING = "warning"
    ERROR = "error"
    UNRESPONSIVE = "unresponsive"
    NOT_AVAILABLE = "not_available"


@dataclass
class ComponentHealth:
    """Health status of a single component"""
    name: str
    status: ComponentStatus
    last_check: float
    last_success: Optional[float] = None
    message: str = ""
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'status': self.status.value,
            'last_check': self.last_check,
            'last_check_iso': datetime.fromtimestamp(self.last_check).isoformat(),
            'last_success': self.last_success,
            'last_success_iso': datetime.fromtimestamp(self.last_success).isoformat() if self.last_success else None,
            'message': self.message,
            'metadata': self.metadata,
        }


@dataclass
class HealthSnapshot:
    """Point-in-time health status"""
    timestamp: float
    overall_status: HealthStatus
    components: Dict[str, ComponentHealth]
    uptime_seconds: float
    heartbeat_count: int
    last_heartbeat: float

    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'timestamp_iso': datetime.fromtimestamp(self.timestamp).isoformat(),
            'overall_status': self.overall_status.value,
            'components': {name: c.to_dict() for name, c in self.components.items()},
            'uptime_seconds': self.uptime_seconds,
            'uptime_formatted': self._format_uptime(self.uptime_seconds),
            'heartbeat_count': self.heartbeat_count,
            'last_heartbeat': self.last_heartbeat,
            'seconds_since_heartbeat': self.timestamp - self.last_heartbeat,
        }

    @staticmethod
    def _format_uptime(seconds: float) -> str:
        """Format uptime as human-readable string"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)

        if days > 0:
            return f"{days}d {hours}h {minutes}m {secs}s"
        elif hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"


@dataclass
class HealthAlert:
    """Health-related alert"""
    timestamp: float
    component: str
    previous_status: ComponentStatus
    new_status: ComponentStatus
    message: str

    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'timestamp_iso': datetime.fromtimestamp(self.timestamp).isoformat(),
            'component': self.component,
            'previous_status': self.previous_status.value,
            'new_status': self.new_status.value,
            'message': self.message,
        }


@dataclass
class HealthMonitorConfig:
    """Configuration for health monitoring"""
    check_interval: float = 30.0        # Seconds between health checks
    heartbeat_interval: float = 10.0    # Seconds between heartbeats
    heartbeat_timeout: float = 60.0     # Seconds before considering daemon unresponsive
    component_timeout: float = 5.0      # Seconds for component check timeout
    alert_on_degraded: bool = True      # Alert when status degrades
    history_size: int = 100             # Health snapshots to keep

    def to_dict(self) -> Dict:
        return {
            'check_interval': self.check_interval,
            'heartbeat_interval': self.heartbeat_interval,
            'heartbeat_timeout': self.heartbeat_timeout,
            'component_timeout': self.component_timeout,
            'alert_on_degraded': self.alert_on_degraded,
            'history_size': self.history_size,
        }


# Type for component health check functions
HealthCheckFunc = Callable[[], tuple[ComponentStatus, str, Dict]]


class HealthMonitor:
    """
    Monitors daemon health and component status.

    Provides:
    - Heartbeat mechanism for liveness detection
    - Component health checks
    - Overall health status
    - Health history and alerts
    - Uptime tracking
    """

    def __init__(
        self,
        daemon=None,
        config: Optional[HealthMonitorConfig] = None,
        on_alert: Optional[Callable[[HealthAlert], None]] = None,
    ):
        """
        Initialize HealthMonitor.

        Args:
            daemon: Reference to BoundaryDaemon instance
            config: HealthMonitorConfig instance
            on_alert: Callback for health alerts
        """
        self.daemon = daemon
        self.config = config or HealthMonitorConfig()
        self._on_alert = on_alert

        # State
        self._running = False
        self._check_thread: Optional[threading.Thread] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Tracking
        self._start_time: float = time.time()
        self._heartbeat_count: int = 0
        self._last_heartbeat: float = time.time()
        self._last_check: float = 0

        # Component registry
        self._components: Dict[str, ComponentHealth] = {}
        self._health_checks: Dict[str, HealthCheckFunc] = {}

        # History
        self._history: deque = deque(maxlen=self.config.history_size)
        self._alerts: List[HealthAlert] = []
        self._alert_history_size = 50

        # Current status
        self._current_status: HealthStatus = HealthStatus.UNKNOWN

        # Telemetry
        self._telemetry_manager = None

        # Register default daemon component checks
        self._register_default_checks()

    def _register_default_checks(self):
        """Register default component health checks"""
        # These will check daemon components if available
        self.register_component('daemon_core', self._check_daemon_core)
        self.register_component('event_logger', self._check_event_logger)
        self.register_component('policy_engine', self._check_policy_engine)
        self.register_component('state_monitor', self._check_state_monitor)
        self.register_component('api_server', self._check_api_server)
        self.register_component('memory_monitor', self._check_memory_monitor)
        self.register_component('resource_monitor', self._check_resource_monitor)

    def register_component(self, name: str, check_func: HealthCheckFunc):
        """
        Register a component health check.

        Args:
            name: Component name
            check_func: Function that returns (status, message, metadata)
        """
        self._health_checks[name] = check_func
        self._components[name] = ComponentHealth(
            name=name,
            status=ComponentStatus.NOT_AVAILABLE,
            last_check=0,
        )

    def set_telemetry_manager(self, telemetry_manager):
        """Set telemetry manager for metrics export"""
        self._telemetry_manager = telemetry_manager

    def start(self):
        """Start health monitoring"""
        if self._running:
            return

        self._running = True
        self._start_time = time.time()
        self._last_heartbeat = time.time()

        # Start heartbeat thread
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

        # Start health check thread
        self._check_thread = threading.Thread(target=self._check_loop, daemon=True)
        self._check_thread.start()

        logger.info(f"Health monitor started (check interval: {self.config.check_interval}s)")

    def stop(self):
        """Stop health monitoring"""
        self._running = False
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5.0)
        if self._check_thread:
            self._check_thread.join(timeout=5.0)
        logger.info("Health monitor stopped")

    def heartbeat(self):
        """
        Record a heartbeat.
        Call this periodically to indicate the daemon is alive.
        """
        with self._lock:
            self._last_heartbeat = time.time()
            self._heartbeat_count += 1

    def _heartbeat_loop(self):
        """Internal heartbeat loop"""
        while self._running:
            self.heartbeat()
            time.sleep(self.config.heartbeat_interval)

    def _check_loop(self):
        """Main health check loop"""
        while self._running:
            try:
                self._run_health_checks()
                time.sleep(self.config.check_interval)
            except Exception as e:
                logger.error(f"Error in health check loop: {e}")
                time.sleep(self.config.check_interval)

    def _run_health_checks(self):
        """Run all registered health checks"""
        now = time.time()
        self._last_check = now

        # Report to dreaming reporter
        dream_operation_start("check:component_health")
        all_healthy = True

        # Check each component
        for name, check_func in self._health_checks.items():
            try:
                status, message, metadata = check_func()
                previous = self._components.get(name)
                previous_status = previous.status if previous else ComponentStatus.NOT_AVAILABLE

                self._components[name] = ComponentHealth(
                    name=name,
                    status=status,
                    last_check=now,
                    last_success=now if status == ComponentStatus.OK else (
                        previous.last_success if previous else None
                    ),
                    message=message,
                    metadata=metadata,
                )

                # Track health status for dreaming reporter
                if status != ComponentStatus.OK:
                    all_healthy = False

                # Alert on status change
                if status != previous_status and self.config.alert_on_degraded:
                    if status in (ComponentStatus.ERROR, ComponentStatus.UNRESPONSIVE):
                        self._raise_alert(name, previous_status, status, message)
                    elif previous_status in (ComponentStatus.ERROR, ComponentStatus.UNRESPONSIVE):
                        # Component recovered
                        self._raise_alert(name, previous_status, status, f"Component recovered: {message}")

            except Exception as e:
                all_healthy = False
                self._components[name] = ComponentHealth(
                    name=name,
                    status=ComponentStatus.ERROR,
                    last_check=now,
                    message=f"Health check failed: {e}",
                )

        # Report completion to dreaming reporter
        dream_operation_complete("check:component_health", success=all_healthy)

        # Calculate overall status
        overall = self._calculate_overall_status()

        # Check heartbeat timeout
        seconds_since_heartbeat = now - self._last_heartbeat
        if seconds_since_heartbeat > self.config.heartbeat_timeout:
            overall = HealthStatus.UNHEALTHY

        # Update current status
        previous_overall = self._current_status
        self._current_status = overall

        # Create snapshot
        snapshot = HealthSnapshot(
            timestamp=now,
            overall_status=overall,
            components=dict(self._components),
            uptime_seconds=now - self._start_time,
            heartbeat_count=self._heartbeat_count,
            last_heartbeat=self._last_heartbeat,
        )

        with self._lock:
            self._history.append(snapshot)

        # Export metrics
        self._export_metrics(snapshot)

        # Alert on overall status change
        if overall != previous_overall and previous_overall != HealthStatus.UNKNOWN:
            if overall == HealthStatus.UNHEALTHY:
                self._raise_alert('daemon', ComponentStatus.OK, ComponentStatus.ERROR,
                                  f"Daemon health degraded to UNHEALTHY")
            elif overall == HealthStatus.DEGRADED:
                self._raise_alert('daemon', ComponentStatus.OK, ComponentStatus.WARNING,
                                  f"Daemon health degraded to DEGRADED")
            elif previous_overall in (HealthStatus.UNHEALTHY, HealthStatus.DEGRADED):
                self._raise_alert('daemon', ComponentStatus.WARNING, ComponentStatus.OK,
                                  f"Daemon health recovered to HEALTHY")

    def _calculate_overall_status(self) -> HealthStatus:
        """Calculate overall health status from components"""
        if not self._components:
            return HealthStatus.UNKNOWN

        statuses = [c.status for c in self._components.values()]

        # Count by status
        error_count = sum(1 for s in statuses if s in (ComponentStatus.ERROR, ComponentStatus.UNRESPONSIVE))
        warning_count = sum(1 for s in statuses if s == ComponentStatus.WARNING)
        ok_count = sum(1 for s in statuses if s == ComponentStatus.OK)
        total_available = len([s for s in statuses if s != ComponentStatus.NOT_AVAILABLE])

        if total_available == 0:
            return HealthStatus.UNKNOWN

        # Determine overall status
        if error_count > 0:
            if error_count >= total_available / 2:
                return HealthStatus.UNHEALTHY
            return HealthStatus.DEGRADED
        elif warning_count > 0:
            return HealthStatus.DEGRADED
        else:
            return HealthStatus.HEALTHY

    def _raise_alert(
        self,
        component: str,
        previous_status: ComponentStatus,
        new_status: ComponentStatus,
        message: str,
    ):
        """Raise a health alert"""
        alert = HealthAlert(
            timestamp=time.time(),
            component=component,
            previous_status=previous_status,
            new_status=new_status,
            message=message,
        )

        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > self._alert_history_size:
                self._alerts = self._alerts[-self._alert_history_size:]

        logger.warning(f"Health alert [{component}]: {message}")

        if self._on_alert:
            try:
                self._on_alert(alert)
            except Exception as e:
                logger.error(f"Error in health alert callback: {e}")

        # Log to daemon event logger if available
        if self.daemon and hasattr(self.daemon, 'event_logger'):
            try:
                from .event_logger import EventType
                self.daemon.event_logger.log_event(
                    EventType.ALERT,
                    message,
                    metadata={
                        'component': component,
                        'previous_status': previous_status.value,
                        'new_status': new_status.value,
                    }
                )
            except Exception:
                pass

    def _export_metrics(self, snapshot: HealthSnapshot):
        """Export health metrics to telemetry"""
        if not self._telemetry_manager:
            return

        try:
            # Overall status as numeric (0=unknown, 1=unhealthy, 2=degraded, 3=healthy)
            status_values = {
                HealthStatus.UNKNOWN: 0,
                HealthStatus.UNHEALTHY: 1,
                HealthStatus.DEGRADED: 2,
                HealthStatus.HEALTHY: 3,
            }
            self._telemetry_manager.set_gauge(
                "health.overall_status",
                status_values.get(snapshot.overall_status, 0)
            )

            # Uptime
            self._telemetry_manager.set_gauge("health.uptime_seconds", int(snapshot.uptime_seconds))

            # Heartbeat
            self._telemetry_manager.set_gauge("health.heartbeat_count", snapshot.heartbeat_count)
            self._telemetry_manager.set_gauge(
                "health.seconds_since_heartbeat",
                int(snapshot.timestamp - snapshot.last_heartbeat)
            )

            # Component counts
            ok_count = sum(1 for c in snapshot.components.values() if c.status == ComponentStatus.OK)
            error_count = sum(1 for c in snapshot.components.values()
                              if c.status in (ComponentStatus.ERROR, ComponentStatus.UNRESPONSIVE))
            self._telemetry_manager.set_gauge("health.components_ok", ok_count)
            self._telemetry_manager.set_gauge("health.components_error", error_count)

        except Exception as e:
            logger.debug(f"Failed to export health metrics: {e}")

    # Default component health checks

    def _check_daemon_core(self) -> tuple[ComponentStatus, str, Dict]:
        """Check daemon core health"""
        if not self.daemon:
            return ComponentStatus.NOT_AVAILABLE, "Daemon not available", {}

        try:
            # Check if daemon is running
            if hasattr(self.daemon, '_running') and self.daemon._running:
                # Get basic stats
                mode = getattr(self.daemon, 'current_mode', None)
                return ComponentStatus.OK, f"Running in {mode.name if mode else 'unknown'} mode", {
                    'mode': mode.name if mode else 'unknown',
                }
            else:
                return ComponentStatus.WARNING, "Daemon not in running state", {}
        except Exception as e:
            return ComponentStatus.ERROR, f"Check failed: {e}", {}

    def _check_event_logger(self) -> tuple[ComponentStatus, str, Dict]:
        """Check event logger health"""
        if not self.daemon or not hasattr(self.daemon, 'event_logger'):
            return ComponentStatus.NOT_AVAILABLE, "Event logger not available", {}

        try:
            logger_obj = self.daemon.event_logger
            if logger_obj:
                event_count = len(logger_obj.get_recent_events(10))
                return ComponentStatus.OK, f"Operational ({event_count} recent events)", {
                    'recent_events': event_count,
                }
            return ComponentStatus.WARNING, "Event logger exists but not operational", {}
        except Exception as e:
            return ComponentStatus.ERROR, f"Check failed: {e}", {}

    def _check_policy_engine(self) -> tuple[ComponentStatus, str, Dict]:
        """Check policy engine health"""
        if not self.daemon or not hasattr(self.daemon, 'policy_engine'):
            return ComponentStatus.NOT_AVAILABLE, "Policy engine not available", {}

        try:
            engine = self.daemon.policy_engine
            if engine:
                mode = getattr(engine, 'current_mode', None)
                return ComponentStatus.OK, f"Active in {mode.name if mode else 'unknown'} mode", {
                    'mode': mode.name if mode else 'unknown',
                }
            return ComponentStatus.WARNING, "Policy engine not active", {}
        except Exception as e:
            return ComponentStatus.ERROR, f"Check failed: {e}", {}

    def _check_state_monitor(self) -> tuple[ComponentStatus, str, Dict]:
        """Check state monitor health"""
        if not self.daemon or not hasattr(self.daemon, 'state_monitor'):
            return ComponentStatus.NOT_AVAILABLE, "State monitor not available", {}

        try:
            monitor = self.daemon.state_monitor
            if monitor:
                state = monitor.get_current_state() if hasattr(monitor, 'get_current_state') else None
                return ComponentStatus.OK, "Operational", {
                    'has_state': state is not None,
                }
            return ComponentStatus.WARNING, "State monitor not operational", {}
        except Exception as e:
            return ComponentStatus.ERROR, f"Check failed: {e}", {}

    def _check_api_server(self) -> tuple[ComponentStatus, str, Dict]:
        """Check API server health"""
        if not self.daemon or not hasattr(self.daemon, 'api_server'):
            return ComponentStatus.NOT_AVAILABLE, "API server not available", {}

        try:
            server = self.daemon.api_server
            if server and hasattr(server, '_running') and server._running:
                socket_path = getattr(server, 'socket_path', 'unknown')
                return ComponentStatus.OK, f"Listening on {socket_path}", {
                    'socket_path': socket_path,
                }
            elif server:
                return ComponentStatus.WARNING, "API server exists but not running", {}
            return ComponentStatus.NOT_AVAILABLE, "API server not configured", {}
        except Exception as e:
            return ComponentStatus.ERROR, f"Check failed: {e}", {}

    def _check_memory_monitor(self) -> tuple[ComponentStatus, str, Dict]:
        """Check memory monitor health"""
        if not self.daemon or not hasattr(self.daemon, 'memory_monitor'):
            return ComponentStatus.NOT_AVAILABLE, "Memory monitor not available", {}

        try:
            monitor = self.daemon.memory_monitor
            if monitor and hasattr(monitor, '_running') and monitor._running:
                stats = monitor.get_summary_stats() if hasattr(monitor, 'get_summary_stats') else {}
                return ComponentStatus.OK, "Monitoring active", {
                    'samples': stats.get('samples_collected', 0),
                }
            elif monitor:
                return ComponentStatus.WARNING, "Memory monitor not running", {}
            return ComponentStatus.NOT_AVAILABLE, "Memory monitor not configured", {}
        except Exception as e:
            return ComponentStatus.ERROR, f"Check failed: {e}", {}

    def _check_resource_monitor(self) -> tuple[ComponentStatus, str, Dict]:
        """Check resource monitor health"""
        if not self.daemon or not hasattr(self.daemon, 'resource_monitor'):
            return ComponentStatus.NOT_AVAILABLE, "Resource monitor not available", {}

        try:
            monitor = self.daemon.resource_monitor
            if monitor and hasattr(monitor, '_running') and monitor._running:
                stats = monitor.get_summary_stats() if hasattr(monitor, 'get_summary_stats') else {}
                return ComponentStatus.OK, "Monitoring active", {
                    'samples': stats.get('samples_collected', 0),
                }
            elif monitor:
                return ComponentStatus.WARNING, "Resource monitor not running", {}
            return ComponentStatus.NOT_AVAILABLE, "Resource monitor not configured", {}
        except Exception as e:
            return ComponentStatus.ERROR, f"Check failed: {e}", {}

    # Public API

    def get_health(self) -> HealthSnapshot:
        """Get current health status"""
        now = time.time()
        return HealthSnapshot(
            timestamp=now,
            overall_status=self._current_status,
            components=dict(self._components),
            uptime_seconds=now - self._start_time,
            heartbeat_count=self._heartbeat_count,
            last_heartbeat=self._last_heartbeat,
        )

    def get_component_health(self, name: str) -> Optional[ComponentHealth]:
        """Get health status of a specific component"""
        return self._components.get(name)

    def get_history(self, limit: Optional[int] = None) -> List[HealthSnapshot]:
        """Get health history"""
        with self._lock:
            if limit:
                return list(self._history)[-limit:]
            return list(self._history)

    def get_alerts(self, limit: Optional[int] = None) -> List[HealthAlert]:
        """Get recent health alerts"""
        with self._lock:
            if limit:
                return self._alerts[-limit:]
            return list(self._alerts)

    def get_uptime(self) -> float:
        """Get daemon uptime in seconds"""
        return time.time() - self._start_time

    def get_summary(self) -> Dict:
        """Get health summary"""
        now = time.time()
        health = self.get_health()

        return {
            'status': health.overall_status.value,
            'uptime_seconds': health.uptime_seconds,
            'uptime_formatted': health._format_uptime(health.uptime_seconds),
            'heartbeat_count': health.heartbeat_count,
            'seconds_since_heartbeat': now - health.last_heartbeat,
            'last_check': self._last_check,
            'seconds_since_check': now - self._last_check if self._last_check > 0 else None,
            'components': {
                name: {
                    'status': c.status.value,
                    'message': c.message,
                }
                for name, c in health.components.items()
            },
            'component_summary': {
                'total': len(health.components),
                'ok': sum(1 for c in health.components.values() if c.status == ComponentStatus.OK),
                'warning': sum(1 for c in health.components.values() if c.status == ComponentStatus.WARNING),
                'error': sum(1 for c in health.components.values()
                             if c.status in (ComponentStatus.ERROR, ComponentStatus.UNRESPONSIVE)),
                'not_available': sum(1 for c in health.components.values()
                                     if c.status == ComponentStatus.NOT_AVAILABLE),
            },
            'alerts_count': len(self._alerts),
            'config': self.config.to_dict(),
        }

    def is_healthy(self) -> bool:
        """Quick check if daemon is healthy"""
        return self._current_status == HealthStatus.HEALTHY

    def is_alive(self) -> bool:
        """Check if daemon is alive (heartbeat not timed out)"""
        return (time.time() - self._last_heartbeat) < self.config.heartbeat_timeout


# Convenience function
def create_health_monitor(
    daemon=None,
    check_interval: float = 30.0,
    heartbeat_timeout: float = 60.0,
) -> HealthMonitor:
    """
    Create a configured health monitor.

    Args:
        daemon: BoundaryDaemon instance
        check_interval: Seconds between health checks
        heartbeat_timeout: Seconds before daemon is considered unresponsive

    Returns:
        Configured HealthMonitor instance
    """
    config = HealthMonitorConfig(
        check_interval=check_interval,
        heartbeat_timeout=heartbeat_timeout,
    )

    return HealthMonitor(daemon=daemon, config=config)


if __name__ == '__main__':
    # Test the health monitor
    print("Testing Health Monitor...")

    # Create monitor without daemon for basic testing
    config = HealthMonitorConfig(
        check_interval=5.0,
        heartbeat_interval=2.0,
    )

    def on_alert(alert: HealthAlert):
        print(f"\n[ALERT] {alert.component}: {alert.message}")

    monitor = HealthMonitor(config=config, on_alert=on_alert)
    monitor.start()

    try:
        print("\nMonitoring health. Press Ctrl+C to stop...")
        for i in range(10):
            time.sleep(3)
            summary = monitor.get_summary()
            print(f"\n[{i:2d}] Status: {summary['status']}, "
                  f"Uptime: {summary['uptime_formatted']}, "
                  f"Heartbeats: {summary['heartbeat_count']}")

            # Show component status
            for name, comp in summary['components'].items():
                print(f"     - {name}: {comp['status']}")

    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        monitor.stop()
        print("Health monitor test complete.")
