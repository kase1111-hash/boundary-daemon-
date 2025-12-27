"""
Queue Monitor - Queue Depth and Backpressure Monitoring
Monitors internal queues for depth, processing rates, and backpressure.

Features:
- Queue depth tracking with configurable thresholds
- Backpressure detection (queue growth, processing delays)
- Processing rate monitoring (items/second)
- Queue latency tracking (time items spend in queue)
- Alert generation for queue issues
- Integration with OpenTelemetry metrics
"""

import os
import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Callable, Any, Deque
from datetime import datetime
from enum import Enum
from collections import deque
from queue import Queue, Empty
import weakref

logger = logging.getLogger(__name__)


class QueueAlertLevel(Enum):
    """Queue alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class BackpressureState(Enum):
    """Backpressure state"""
    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class QueueSnapshot:
    """Point-in-time queue measurement"""
    timestamp: float
    name: str
    depth: int
    capacity: int  # 0 = unlimited
    items_enqueued: int  # Total items ever added
    items_dequeued: int  # Total items ever removed
    avg_latency_ms: float  # Average time items spend in queue

    @property
    def utilization(self) -> float:
        """Queue utilization percentage"""
        if self.capacity <= 0:
            return 0.0
        return (self.depth / self.capacity) * 100

    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'timestamp_iso': datetime.fromtimestamp(self.timestamp).isoformat(),
            'name': self.name,
            'depth': self.depth,
            'capacity': self.capacity,
            'utilization_percent': round(self.utilization, 1),
            'items_enqueued': self.items_enqueued,
            'items_dequeued': self.items_dequeued,
            'avg_latency_ms': round(self.avg_latency_ms, 2),
        }


@dataclass
class QueueAlert:
    """Queue-related alert"""
    timestamp: float
    queue_name: str
    level: QueueAlertLevel
    alert_type: str
    message: str
    current_depth: int
    threshold: int
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'timestamp_iso': datetime.fromtimestamp(self.timestamp).isoformat(),
            'queue_name': self.queue_name,
            'level': self.level.value,
            'alert_type': self.alert_type,
            'message': self.message,
            'current_depth': self.current_depth,
            'threshold': self.threshold,
            'metadata': self.metadata,
        }


@dataclass
class QueueConfig:
    """Configuration for a monitored queue"""
    name: str
    warning_depth: int = 100        # Alert at this depth
    critical_depth: int = 500       # Critical alert at this depth
    warning_utilization: float = 70.0   # % utilization warning
    critical_utilization: float = 90.0  # % utilization critical
    growth_rate_warning: float = 10.0   # Items/second growth
    latency_warning_ms: float = 1000.0  # Queue latency warning

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'warning_depth': self.warning_depth,
            'critical_depth': self.critical_depth,
            'warning_utilization': self.warning_utilization,
            'critical_utilization': self.critical_utilization,
            'growth_rate_warning': self.growth_rate_warning,
            'latency_warning_ms': self.latency_warning_ms,
        }


@dataclass
class QueueMonitorConfig:
    """Global queue monitoring configuration"""
    sample_interval: float = 5.0      # Seconds between samples
    history_size: int = 120           # Keep 10 min at 5s intervals
    alert_cooldown: int = 12          # Samples between repeated alerts (1 min)
    default_warning_depth: int = 100
    default_critical_depth: int = 500

    def to_dict(self) -> Dict:
        return {
            'sample_interval': self.sample_interval,
            'history_size': self.history_size,
            'alert_cooldown': self.alert_cooldown,
            'default_warning_depth': self.default_warning_depth,
            'default_critical_depth': self.default_critical_depth,
        }


class MonitoredQueue:
    """
    Wrapper for queues that tracks depth, enqueue/dequeue counts, and latency.
    Can wrap standard queue.Queue or provide a standalone queue.
    """

    def __init__(
        self,
        name: str,
        queue: Optional[Queue] = None,
        maxsize: int = 0,
        config: Optional[QueueConfig] = None,
    ):
        """
        Initialize a monitored queue.

        Args:
            name: Queue name for identification
            queue: Existing Queue to wrap (or None to create new)
            maxsize: Max size for new queue (0 = unlimited)
            config: QueueConfig for thresholds
        """
        self.name = name
        self.config = config or QueueConfig(name=name)
        self._queue = queue or Queue(maxsize=maxsize)
        self._maxsize = maxsize if queue is None else getattr(queue, 'maxsize', 0)

        # Tracking counters
        self._enqueue_count = 0
        self._dequeue_count = 0
        self._lock = threading.Lock()

        # Latency tracking
        self._latency_samples: Deque[float] = deque(maxlen=100)
        self._item_timestamps: Dict[int, float] = {}  # item_id -> enqueue_time
        self._next_item_id = 0

    @property
    def depth(self) -> int:
        """Current queue depth"""
        return self._queue.qsize()

    @property
    def capacity(self) -> int:
        """Queue capacity (0 = unlimited)"""
        return self._maxsize

    @property
    def is_full(self) -> bool:
        """Check if queue is full"""
        return self._queue.full() if self._maxsize > 0 else False

    @property
    def is_empty(self) -> bool:
        """Check if queue is empty"""
        return self._queue.empty()

    def put(self, item: Any, block: bool = True, timeout: Optional[float] = None):
        """
        Add item to queue with tracking.
        """
        with self._lock:
            item_id = self._next_item_id
            self._next_item_id += 1
            self._item_timestamps[item_id] = time.time()
            self._enqueue_count += 1

        # Wrap item with tracking info
        wrapped = (item_id, item)
        self._queue.put(wrapped, block=block, timeout=timeout)

    def get(self, block: bool = True, timeout: Optional[float] = None) -> Any:
        """
        Get item from queue with latency tracking.
        """
        wrapped = self._queue.get(block=block, timeout=timeout)
        item_id, item = wrapped

        with self._lock:
            self._dequeue_count += 1
            if item_id in self._item_timestamps:
                latency = time.time() - self._item_timestamps[item_id]
                self._latency_samples.append(latency * 1000)  # Convert to ms
                del self._item_timestamps[item_id]

        return item

    def get_nowait(self) -> Any:
        """Get item without blocking"""
        return self.get(block=False)

    def put_nowait(self, item: Any):
        """Put item without blocking"""
        return self.put(item, block=False)

    def get_stats(self) -> Dict:
        """Get queue statistics"""
        with self._lock:
            latencies = list(self._latency_samples)
            enqueued = self._enqueue_count
            dequeued = self._dequeue_count

        avg_latency = sum(latencies) / len(latencies) if latencies else 0

        return {
            'name': self.name,
            'depth': self.depth,
            'capacity': self.capacity,
            'utilization': (self.depth / self.capacity * 100) if self.capacity > 0 else 0,
            'enqueued_total': enqueued,
            'dequeued_total': dequeued,
            'pending': enqueued - dequeued,
            'avg_latency_ms': avg_latency,
            'latency_samples': len(latencies),
        }

    def get_snapshot(self) -> QueueSnapshot:
        """Get a point-in-time snapshot"""
        stats = self.get_stats()
        return QueueSnapshot(
            timestamp=time.time(),
            name=self.name,
            depth=stats['depth'],
            capacity=stats['capacity'],
            items_enqueued=stats['enqueued_total'],
            items_dequeued=stats['dequeued_total'],
            avg_latency_ms=stats['avg_latency_ms'],
        )


class QueueDepthAdapter:
    """
    Adapter for monitoring queue depth without wrapping the queue.
    Used when you can't replace the queue but can observe it.
    """

    def __init__(
        self,
        name: str,
        depth_func: Callable[[], int],
        capacity_func: Optional[Callable[[], int]] = None,
        config: Optional[QueueConfig] = None,
    ):
        """
        Initialize a queue depth adapter.

        Args:
            name: Queue name for identification
            depth_func: Function that returns current queue depth
            capacity_func: Function that returns queue capacity (optional)
            config: QueueConfig for thresholds
        """
        self.name = name
        self.config = config or QueueConfig(name=name)
        self._depth_func = depth_func
        self._capacity_func = capacity_func

        # Track depth changes for rate calculation
        self._last_depth = 0
        self._last_sample_time = time.time()
        self._enqueue_estimate = 0
        self._dequeue_estimate = 0

    @property
    def depth(self) -> int:
        """Current queue depth"""
        return self._depth_func()

    @property
    def capacity(self) -> int:
        """Queue capacity (0 = unlimited)"""
        if self._capacity_func:
            return self._capacity_func()
        return 0

    def get_snapshot(self) -> QueueSnapshot:
        """Get a point-in-time snapshot"""
        now = time.time()
        current_depth = self.depth

        # Estimate enqueue/dequeue from depth changes
        depth_change = current_depth - self._last_depth
        if depth_change > 0:
            self._enqueue_estimate += depth_change
        else:
            self._dequeue_estimate += abs(depth_change)

        self._last_depth = current_depth
        self._last_sample_time = now

        return QueueSnapshot(
            timestamp=now,
            name=self.name,
            depth=current_depth,
            capacity=self.capacity,
            items_enqueued=self._enqueue_estimate,
            items_dequeued=self._dequeue_estimate,
            avg_latency_ms=0,  # Can't measure without queue wrapping
        )


class QueueMonitor:
    """
    Monitors multiple queues for depth, backpressure, and processing rates.

    Features:
    - Register multiple queues to monitor
    - Track queue depths over time
    - Detect backpressure conditions
    - Alert on queue threshold violations
    - Calculate processing rates
    """

    def __init__(
        self,
        daemon=None,
        config: Optional[QueueMonitorConfig] = None,
        on_alert: Optional[Callable[[QueueAlert], None]] = None,
    ):
        """
        Initialize QueueMonitor.

        Args:
            daemon: Reference to BoundaryDaemon instance
            config: QueueMonitorConfig instance
            on_alert: Callback for queue alerts
        """
        self.daemon = daemon
        self.config = config or QueueMonitorConfig()
        self._on_alert = on_alert

        # State
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Registered queues
        self._queues: Dict[str, Any] = {}  # name -> MonitoredQueue or QueueDepthAdapter
        self._queue_configs: Dict[str, QueueConfig] = {}

        # History per queue
        self._history: Dict[str, deque] = {}  # name -> deque of QueueSnapshot

        # Alerts
        self._alerts: List[QueueAlert] = []
        self._alert_history_size = 50
        self._last_alert: Dict[str, int] = {}  # "queue:alert_type" -> sample_count
        self._sample_count = 0

        # Backpressure state
        self._backpressure_state: Dict[str, BackpressureState] = {}

        # Telemetry
        self._telemetry_manager = None

    def register_queue(
        self,
        name: str,
        queue: Optional[Any] = None,
        depth_func: Optional[Callable[[], int]] = None,
        capacity_func: Optional[Callable[[], int]] = None,
        config: Optional[QueueConfig] = None,
    ) -> Optional[MonitoredQueue]:
        """
        Register a queue for monitoring.

        Args:
            name: Queue name for identification
            queue: Queue instance to wrap (creates MonitoredQueue)
            depth_func: Function to get depth (creates QueueDepthAdapter)
            capacity_func: Function to get capacity (for adapter)
            config: QueueConfig for thresholds

        Returns:
            MonitoredQueue if queue was wrapped, None if using adapter
        """
        queue_config = config or QueueConfig(
            name=name,
            warning_depth=self.config.default_warning_depth,
            critical_depth=self.config.default_critical_depth,
        )

        if depth_func:
            # Create adapter for existing queue
            adapter = QueueDepthAdapter(
                name=name,
                depth_func=depth_func,
                capacity_func=capacity_func,
                config=queue_config,
            )
            with self._lock:
                self._queues[name] = adapter
                self._queue_configs[name] = queue_config
                self._history[name] = deque(maxlen=self.config.history_size)
                self._backpressure_state[name] = BackpressureState.NONE
            logger.info(f"Registered queue adapter: {name}")
            return None
        elif queue:
            # Wrap existing queue
            monitored = MonitoredQueue(
                name=name,
                queue=queue,
                config=queue_config,
            )
            with self._lock:
                self._queues[name] = monitored
                self._queue_configs[name] = queue_config
                self._history[name] = deque(maxlen=self.config.history_size)
                self._backpressure_state[name] = BackpressureState.NONE
            logger.info(f"Registered monitored queue: {name}")
            return monitored
        else:
            # Create new monitored queue
            monitored = MonitoredQueue(
                name=name,
                config=queue_config,
            )
            with self._lock:
                self._queues[name] = monitored
                self._queue_configs[name] = queue_config
                self._history[name] = deque(maxlen=self.config.history_size)
                self._backpressure_state[name] = BackpressureState.NONE
            logger.info(f"Created new monitored queue: {name}")
            return monitored

    def unregister_queue(self, name: str):
        """Remove a queue from monitoring"""
        with self._lock:
            self._queues.pop(name, None)
            self._queue_configs.pop(name, None)
            self._history.pop(name, None)
            self._backpressure_state.pop(name, None)
        logger.info(f"Unregistered queue: {name}")

    def set_telemetry_manager(self, telemetry_manager):
        """Set telemetry manager for metrics export"""
        self._telemetry_manager = telemetry_manager

    def start(self):
        """Start queue monitoring"""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info(f"Queue monitor started (interval: {self.config.sample_interval}s)")

    def stop(self):
        """Stop queue monitoring"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("Queue monitor stopped")

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                self._sample_count += 1
                self._check_all_queues()
                time.sleep(self.config.sample_interval)
            except Exception as e:
                logger.error(f"Error in queue monitor loop: {e}")
                time.sleep(self.config.sample_interval)

    def _check_all_queues(self):
        """Check all registered queues"""
        with self._lock:
            queues = dict(self._queues)

        for name, queue_obj in queues.items():
            try:
                snapshot = queue_obj.get_snapshot()
                config = self._queue_configs.get(name, QueueConfig(name=name))

                with self._lock:
                    self._history[name].append(snapshot)

                # Check thresholds
                self._check_depth_thresholds(snapshot, config)
                self._check_backpressure(name, config)

                # Export metrics
                self._export_queue_metrics(snapshot)

            except Exception as e:
                logger.error(f"Error checking queue {name}: {e}")

    def _check_depth_thresholds(self, snapshot: QueueSnapshot, config: QueueConfig):
        """Check queue depth thresholds"""
        name = snapshot.name
        depth = snapshot.depth

        # Check absolute depth thresholds
        if depth >= config.critical_depth:
            self._raise_alert(
                name,
                QueueAlertLevel.CRITICAL,
                "depth_critical",
                f"Queue {name} depth critical: {depth} >= {config.critical_depth}",
                depth,
                config.critical_depth,
            )
        elif depth >= config.warning_depth:
            self._raise_alert(
                name,
                QueueAlertLevel.WARNING,
                "depth_warning",
                f"Queue {name} depth warning: {depth} >= {config.warning_depth}",
                depth,
                config.warning_depth,
            )

        # Check utilization thresholds
        if snapshot.capacity > 0:
            util = snapshot.utilization
            if util >= config.critical_utilization:
                self._raise_alert(
                    name,
                    QueueAlertLevel.CRITICAL,
                    "utilization_critical",
                    f"Queue {name} utilization critical: {util:.1f}% >= {config.critical_utilization}%",
                    depth,
                    int(snapshot.capacity * config.critical_utilization / 100),
                    metadata={'utilization': util, 'capacity': snapshot.capacity},
                )
            elif util >= config.warning_utilization:
                self._raise_alert(
                    name,
                    QueueAlertLevel.WARNING,
                    "utilization_warning",
                    f"Queue {name} utilization warning: {util:.1f}% >= {config.warning_utilization}%",
                    depth,
                    int(snapshot.capacity * config.warning_utilization / 100),
                    metadata={'utilization': util, 'capacity': snapshot.capacity},
                )

        # Check latency thresholds
        if snapshot.avg_latency_ms > config.latency_warning_ms:
            self._raise_alert(
                name,
                QueueAlertLevel.WARNING,
                "latency_warning",
                f"Queue {name} latency warning: {snapshot.avg_latency_ms:.1f}ms > {config.latency_warning_ms}ms",
                depth,
                config.warning_depth,
                metadata={'avg_latency_ms': snapshot.avg_latency_ms},
            )

    def _check_backpressure(self, name: str, config: QueueConfig):
        """Detect backpressure from queue growth trends"""
        with self._lock:
            history = list(self._history.get(name, []))

        if len(history) < 3:
            return

        # Calculate growth rate (depth change over last few samples)
        recent = history[-3:]
        first_depth = recent[0].depth
        last_depth = recent[-1].depth
        time_span = recent[-1].timestamp - recent[0].timestamp

        if time_span > 0:
            growth_rate = (last_depth - first_depth) / time_span
        else:
            growth_rate = 0

        # Determine backpressure state
        old_state = self._backpressure_state.get(name, BackpressureState.NONE)

        if growth_rate > config.growth_rate_warning * 2:
            new_state = BackpressureState.CRITICAL
        elif growth_rate > config.growth_rate_warning:
            new_state = BackpressureState.HIGH
        elif growth_rate > config.growth_rate_warning / 2:
            new_state = BackpressureState.MODERATE
        elif growth_rate > 0:
            new_state = BackpressureState.LOW
        else:
            new_state = BackpressureState.NONE

        self._backpressure_state[name] = new_state

        # Alert on significant backpressure
        if new_state in (BackpressureState.HIGH, BackpressureState.CRITICAL):
            if new_state != old_state:
                self._raise_alert(
                    name,
                    QueueAlertLevel.WARNING if new_state == BackpressureState.HIGH else QueueAlertLevel.CRITICAL,
                    f"backpressure_{new_state.value}",
                    f"Queue {name} backpressure {new_state.value}: "
                    f"growing at {growth_rate:.1f} items/sec",
                    last_depth,
                    int(config.growth_rate_warning),
                    metadata={
                        'growth_rate': growth_rate,
                        'previous_state': old_state.value,
                    },
                )
        elif old_state in (BackpressureState.HIGH, BackpressureState.CRITICAL):
            # Recovered from backpressure
            self._raise_alert(
                name,
                QueueAlertLevel.INFO,
                "backpressure_recovered",
                f"Queue {name} backpressure recovered (was {old_state.value})",
                last_depth,
                int(config.growth_rate_warning),
                metadata={'previous_state': old_state.value},
            )

    def _raise_alert(
        self,
        queue_name: str,
        level: QueueAlertLevel,
        alert_type: str,
        message: str,
        current_depth: int,
        threshold: int,
        metadata: Optional[Dict] = None,
    ):
        """Raise a queue alert with cooldown"""
        # Check cooldown
        alert_key = f"{queue_name}:{alert_type}"
        last_sample = self._last_alert.get(alert_key, 0)
        if (self._sample_count - last_sample) < self.config.alert_cooldown:
            return  # Still in cooldown

        self._last_alert[alert_key] = self._sample_count

        alert = QueueAlert(
            timestamp=time.time(),
            queue_name=queue_name,
            level=level,
            alert_type=alert_type,
            message=message,
            current_depth=current_depth,
            threshold=threshold,
            metadata=metadata or {},
        )

        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > self._alert_history_size:
                self._alerts = self._alerts[-self._alert_history_size:]

        log_level = {
            QueueAlertLevel.INFO: logging.INFO,
            QueueAlertLevel.WARNING: logging.WARNING,
            QueueAlertLevel.CRITICAL: logging.ERROR,
        }.get(level, logging.WARNING)

        logger.log(log_level, f"Queue alert [{level.value}]: {message}")

        if self._on_alert:
            try:
                self._on_alert(alert)
            except Exception as e:
                logger.error(f"Error in queue alert callback: {e}")

        # Log to daemon event logger if available
        if self.daemon and hasattr(self.daemon, 'event_logger'):
            try:
                from .event_logger import EventType
                self.daemon.event_logger.log_event(
                    EventType.ALERT if level == QueueAlertLevel.CRITICAL else EventType.INFO,
                    message,
                    metadata={
                        'queue_name': queue_name,
                        'alert_type': alert_type,
                        'level': level.value,
                        'current_depth': current_depth,
                        'threshold': threshold,
                        **(metadata or {}),
                    }
                )
            except Exception:
                pass

    def _export_queue_metrics(self, snapshot: QueueSnapshot):
        """Export queue metrics to telemetry"""
        if not self._telemetry_manager:
            return

        try:
            name = snapshot.name.replace('.', '_').replace('-', '_')

            self._telemetry_manager.set_gauge(f"queue.{name}.depth", snapshot.depth)
            if snapshot.capacity > 0:
                self._telemetry_manager.set_gauge(
                    f"queue.{name}.utilization",
                    int(snapshot.utilization)
                )
            self._telemetry_manager.set_gauge(
                f"queue.{name}.latency_ms",
                int(snapshot.avg_latency_ms)
            )

        except Exception as e:
            logger.debug(f"Failed to export queue metrics: {e}")

    # Public API

    def get_queue(self, name: str) -> Optional[Any]:
        """Get a registered queue by name"""
        with self._lock:
            return self._queues.get(name)

    def get_queue_stats(self, name: str) -> Optional[Dict]:
        """Get current stats for a queue"""
        queue_obj = self.get_queue(name)
        if queue_obj:
            snapshot = queue_obj.get_snapshot()
            return snapshot.to_dict()
        return None

    def get_all_queue_stats(self) -> Dict[str, Dict]:
        """Get stats for all queues"""
        with self._lock:
            queues = dict(self._queues)

        stats = {}
        for name, queue_obj in queues.items():
            try:
                snapshot = queue_obj.get_snapshot()
                stats[name] = snapshot.to_dict()
                stats[name]['backpressure'] = self._backpressure_state.get(
                    name, BackpressureState.NONE
                ).value
            except Exception as e:
                stats[name] = {'error': str(e)}

        return stats

    def get_queue_history(self, name: str, limit: Optional[int] = None) -> List[QueueSnapshot]:
        """Get history for a queue"""
        with self._lock:
            history = list(self._history.get(name, []))
            if limit:
                return history[-limit:]
            return history

    def get_alerts(self, limit: Optional[int] = None,
                   queue_name: Optional[str] = None) -> List[QueueAlert]:
        """Get recent alerts"""
        with self._lock:
            alerts = self._alerts
            if queue_name:
                alerts = [a for a in alerts if a.queue_name == queue_name]
            if limit:
                return alerts[-limit:]
            return list(alerts)

    def get_backpressure_state(self, name: str) -> BackpressureState:
        """Get backpressure state for a queue"""
        return self._backpressure_state.get(name, BackpressureState.NONE)

    def get_summary(self) -> Dict:
        """Get queue monitoring summary"""
        with self._lock:
            queue_names = list(self._queues.keys())
            alert_count = len(self._alerts)

        all_stats = self.get_all_queue_stats()

        total_depth = sum(s.get('depth', 0) for s in all_stats.values() if isinstance(s, dict))
        queues_with_backpressure = sum(
            1 for name in queue_names
            if self._backpressure_state.get(name, BackpressureState.NONE) != BackpressureState.NONE
        )

        return {
            'queue_count': len(queue_names),
            'queues': queue_names,
            'total_depth': total_depth,
            'queues_with_backpressure': queues_with_backpressure,
            'alerts_count': alert_count,
            'sample_count': self._sample_count,
            'config': self.config.to_dict(),
            'queue_stats': all_stats,
        }


# Convenience function
def create_queue_monitor(
    daemon=None,
    sample_interval: float = 5.0,
) -> QueueMonitor:
    """
    Create a configured queue monitor.

    Args:
        daemon: BoundaryDaemon instance
        sample_interval: Seconds between samples

    Returns:
        Configured QueueMonitor instance
    """
    config = QueueMonitorConfig(sample_interval=sample_interval)
    return QueueMonitor(daemon=daemon, config=config)


if __name__ == '__main__':
    # Test the queue monitor
    import random

    print("Testing Queue Monitor...")

    config = QueueMonitorConfig(
        sample_interval=2.0,
        default_warning_depth=5,
        default_critical_depth=10,
    )

    def on_alert(alert: QueueAlert):
        print(f"\n[ALERT] {alert.level.value} - {alert.message}")

    monitor = QueueMonitor(config=config, on_alert=on_alert)

    # Create a test queue
    test_queue = monitor.register_queue(
        name="test_queue",
        config=QueueConfig(
            name="test_queue",
            warning_depth=5,
            critical_depth=10,
            growth_rate_warning=2.0,
        ),
    )

    monitor.start()

    try:
        print("\nMonitoring queues. Press Ctrl+C to stop...")

        # Simulate queue activity
        for i in range(20):
            # Add items
            items_to_add = random.randint(0, 4)
            for _ in range(items_to_add):
                try:
                    test_queue.put(f"item_{i}", block=False)
                except Exception:
                    pass

            # Remove some items
            items_to_remove = random.randint(0, 2)
            for _ in range(items_to_remove):
                try:
                    test_queue.get_nowait()
                except Exception:
                    pass

            # Print stats
            stats = monitor.get_queue_stats("test_queue")
            if stats:
                bp = monitor.get_backpressure_state("test_queue")
                print(f"[{i:2d}] Depth: {stats['depth']}, "
                      f"Enqueued: {stats['items_enqueued']}, "
                      f"Dequeued: {stats['items_dequeued']}, "
                      f"Backpressure: {bp.value}")

            time.sleep(1)

        # Print summary
        print("\n=== Summary ===")
        summary = monitor.get_summary()
        print(f"Queues: {summary['queue_count']}")
        print(f"Total depth: {summary['total_depth']}")
        print(f"Alerts: {summary['alerts_count']}")

    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        monitor.stop()
        print("Queue monitor test complete.")
