"""
Memory Monitor - Process Memory and Leak Detection
Monitors daemon memory usage, detects potential leaks, and tracks Python GC stats.

Features:
- Process memory metrics (RSS, VMS, USS, PSS)
- Memory growth trend analysis for leak detection
- Python garbage collector statistics
- Configurable alert thresholds
- Integration with OpenTelemetry metrics
- Optional tracemalloc debug mode for pinpointing leak sources
"""

import gc
import os
import time
import threading
import logging
import tracemalloc
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Callable, Any, Tuple
from datetime import datetime
from enum import Enum
from collections import deque

logger = logging.getLogger(__name__)

# Try importing psutil (should always be available - used by state_monitor)
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None


class MemoryAlertLevel(Enum):
    """Memory alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class LeakIndicator(Enum):
    """Types of memory leak indicators"""
    NONE = "none"
    POSSIBLE = "possible"       # Memory growing but could be normal
    LIKELY = "likely"           # Consistent growth pattern detected
    CONFIRMED = "confirmed"     # Sustained growth over extended period


@dataclass
class AllocationSite:
    """Represents a memory allocation site from tracemalloc"""
    filename: str
    lineno: int
    size_bytes: int
    count: int

    def to_dict(self) -> Dict:
        return {
            'filename': self.filename,
            'lineno': self.lineno,
            'location': f"{self.filename}:{self.lineno}",
            'size_bytes': self.size_bytes,
            'size_mb': round(self.size_bytes / (1024 * 1024), 3),
            'count': self.count,
        }


@dataclass
class TraceMallocSnapshot:
    """Wrapper for tracemalloc snapshot with analysis"""
    timestamp: float
    total_size: int
    total_count: int
    top_allocations: List[AllocationSite]

    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'timestamp_iso': datetime.fromtimestamp(self.timestamp).isoformat(),
            'total_size_bytes': self.total_size,
            'total_size_mb': round(self.total_size / (1024 * 1024), 2),
            'total_count': self.total_count,
            'top_allocations': [a.to_dict() for a in self.top_allocations],
        }


@dataclass
class LeakReport:
    """Report of detected memory leak with allocation details"""
    timestamp: float
    growth_bytes: int
    growth_sites: List[Dict]  # Sites that grew the most
    new_sites: List[Dict]     # New allocation sites
    total_current: int
    total_baseline: int

    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'timestamp_iso': datetime.fromtimestamp(self.timestamp).isoformat(),
            'growth_bytes': self.growth_bytes,
            'growth_mb': round(self.growth_bytes / (1024 * 1024), 2),
            'growth_sites': self.growth_sites,
            'new_sites': self.new_sites,
            'total_current_mb': round(self.total_current / (1024 * 1024), 2),
            'total_baseline_mb': round(self.total_baseline / (1024 * 1024), 2),
        }


class TraceMallocDebugger:
    """
    Optional tracemalloc integration for debugging memory leaks.

    This is a heavier-weight debugging tool that should only be enabled
    when actively investigating memory issues. It provides:
    - Exact allocation sites (file:line)
    - Memory growth comparison between snapshots
    - Top allocation analysis

    Performance impact: 5-30% CPU overhead, 10-30% memory overhead
    """

    def __init__(self, top_count: int = 20, nframe: int = 5):
        """
        Initialize TraceMallocDebugger.

        Args:
            top_count: Number of top allocations to track
            nframe: Number of frames to capture in tracebacks
        """
        self.top_count = top_count
        self.nframe = nframe
        self._enabled = False
        self._baseline_snapshot = None
        self._snapshots: List[TraceMallocSnapshot] = []
        self._leak_reports: List[LeakReport] = []
        self._lock = threading.Lock()
        self._max_snapshots = 10
        self._max_reports = 20

    @property
    def is_enabled(self) -> bool:
        """Check if tracemalloc is currently enabled"""
        return self._enabled and tracemalloc.is_tracing()

    def start(self) -> bool:
        """
        Start tracemalloc tracing.

        Returns:
            True if started successfully
        """
        if self._enabled:
            return True

        try:
            tracemalloc.start(self.nframe)
            self._enabled = True
            logger.info(f"tracemalloc started (nframe={self.nframe})")

            # Take initial baseline snapshot
            self._baseline_snapshot = self._take_raw_snapshot()
            return True
        except Exception as e:
            logger.error(f"Failed to start tracemalloc: {e}")
            return False

    def stop(self):
        """Stop tracemalloc tracing"""
        if not self._enabled:
            return

        try:
            tracemalloc.stop()
            self._enabled = False
            logger.info("tracemalloc stopped")
        except Exception as e:
            logger.error(f"Failed to stop tracemalloc: {e}")

    def _take_raw_snapshot(self):
        """Take a raw tracemalloc snapshot"""
        if not tracemalloc.is_tracing():
            return None
        return tracemalloc.take_snapshot()

    def take_snapshot(self) -> Optional[TraceMallocSnapshot]:
        """
        Take a tracemalloc snapshot and analyze top allocations.

        Returns:
            TraceMallocSnapshot with analysis, or None if not enabled
        """
        if not self.is_enabled:
            return None

        try:
            raw_snapshot = self._take_raw_snapshot()
            if not raw_snapshot:
                return None

            # Filter to focus on our code (exclude stdlib, site-packages)
            snapshot = raw_snapshot.filter_traces((
                tracemalloc.Filter(False, "<frozen*"),
                tracemalloc.Filter(False, "<unknown>"),
                tracemalloc.Filter(False, tracemalloc.__file__),
            ))

            # Get top allocations by size
            top_stats = snapshot.statistics('lineno')[:self.top_count]

            total_size = sum(stat.size for stat in snapshot.statistics('filename'))
            total_count = sum(stat.count for stat in snapshot.statistics('filename'))

            top_allocations = [
                AllocationSite(
                    filename=stat.traceback[0].filename if stat.traceback else "<unknown>",
                    lineno=stat.traceback[0].lineno if stat.traceback else 0,
                    size_bytes=stat.size,
                    count=stat.count,
                )
                for stat in top_stats
            ]

            result = TraceMallocSnapshot(
                timestamp=time.time(),
                total_size=total_size,
                total_count=total_count,
                top_allocations=top_allocations,
            )

            # Store snapshot
            with self._lock:
                self._snapshots.append(result)
                if len(self._snapshots) > self._max_snapshots:
                    self._snapshots = self._snapshots[-self._max_snapshots:]

            return result

        except Exception as e:
            logger.error(f"Failed to take tracemalloc snapshot: {e}")
            return None

    def compare_to_baseline(self) -> Optional[LeakReport]:
        """
        Compare current memory state to baseline and identify leak sources.

        Returns:
            LeakReport with growth analysis, or None if not available
        """
        if not self.is_enabled or not self._baseline_snapshot:
            return None

        try:
            current_snapshot = self._take_raw_snapshot()
            if not current_snapshot:
                return None

            # Compare snapshots
            diff_stats = current_snapshot.compare_to(
                self._baseline_snapshot, 'lineno'
            )

            # Get sites that grew the most
            growth_sites = []
            for stat in sorted(diff_stats, key=lambda s: s.size_diff, reverse=True)[:self.top_count]:
                if stat.size_diff > 0:
                    growth_sites.append({
                        'location': f"{stat.traceback[0].filename}:{stat.traceback[0].lineno}" if stat.traceback else "<unknown>",
                        'size_diff_bytes': stat.size_diff,
                        'size_diff_mb': round(stat.size_diff / (1024 * 1024), 3),
                        'count_diff': stat.count_diff,
                        'current_size_bytes': stat.size,
                        'current_count': stat.count,
                    })

            # Get new allocation sites (didn't exist in baseline)
            new_sites = []
            for stat in diff_stats:
                if stat.count_diff == stat.count and stat.size > 10000:  # New site, >10KB
                    new_sites.append({
                        'location': f"{stat.traceback[0].filename}:{stat.traceback[0].lineno}" if stat.traceback else "<unknown>",
                        'size_bytes': stat.size,
                        'size_mb': round(stat.size / (1024 * 1024), 3),
                        'count': stat.count,
                    })
            new_sites = sorted(new_sites, key=lambda s: s['size_bytes'], reverse=True)[:10]

            # Calculate totals
            current_total = sum(stat.size for stat in current_snapshot.statistics('filename'))
            baseline_total = sum(stat.size for stat in self._baseline_snapshot.statistics('filename'))
            growth = current_total - baseline_total

            report = LeakReport(
                timestamp=time.time(),
                growth_bytes=growth,
                growth_sites=growth_sites,
                new_sites=new_sites,
                total_current=current_total,
                total_baseline=baseline_total,
            )

            # Store report
            with self._lock:
                self._leak_reports.append(report)
                if len(self._leak_reports) > self._max_reports:
                    self._leak_reports = self._leak_reports[-self._max_reports:]

            return report

        except Exception as e:
            logger.error(f"Failed to compare tracemalloc snapshots: {e}")
            return None

    def reset_baseline(self):
        """Reset the baseline snapshot to current state"""
        if not self.is_enabled:
            return

        self._baseline_snapshot = self._take_raw_snapshot()
        logger.info("tracemalloc baseline reset")

    def get_current_traced_memory(self) -> Tuple[int, int]:
        """
        Get current traced memory usage.

        Returns:
            (current_bytes, peak_bytes)
        """
        if not self.is_enabled:
            return (0, 0)

        try:
            return tracemalloc.get_traced_memory()
        except Exception:
            return (0, 0)

    def get_snapshots(self, limit: Optional[int] = None) -> List[TraceMallocSnapshot]:
        """Get stored snapshots"""
        with self._lock:
            if limit:
                return self._snapshots[-limit:]
            return list(self._snapshots)

    def get_leak_reports(self, limit: Optional[int] = None) -> List[LeakReport]:
        """Get stored leak reports"""
        with self._lock:
            if limit:
                return self._leak_reports[-limit:]
            return list(self._leak_reports)

    def get_status(self) -> Dict:
        """Get debugger status"""
        current, peak = self.get_current_traced_memory()
        return {
            'enabled': self._enabled,
            'is_tracing': tracemalloc.is_tracing() if self._enabled else False,
            'nframe': self.nframe,
            'top_count': self.top_count,
            'snapshots_stored': len(self._snapshots),
            'leak_reports_stored': len(self._leak_reports),
            'has_baseline': self._baseline_snapshot is not None,
            'current_traced_mb': round(current / (1024 * 1024), 2),
            'peak_traced_mb': round(peak / (1024 * 1024), 2),
        }


@dataclass
class MemorySnapshot:
    """Point-in-time memory measurement"""
    timestamp: float
    rss: int              # Resident Set Size (bytes)
    vms: int              # Virtual Memory Size (bytes)
    uss: Optional[int]    # Unique Set Size (bytes) - Linux only
    pss: Optional[int]    # Proportional Set Size (bytes) - Linux only
    shared: Optional[int] # Shared memory (bytes)

    # Python-specific metrics
    gc_objects: int       # Total tracked objects
    gc_garbage: int       # Uncollectable objects (cycles)
    gc_collections: Dict[int, int]  # Collections per generation

    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'timestamp_iso': datetime.fromtimestamp(self.timestamp).isoformat(),
            'rss_bytes': self.rss,
            'rss_mb': round(self.rss / (1024 * 1024), 2),
            'vms_bytes': self.vms,
            'vms_mb': round(self.vms / (1024 * 1024), 2),
            'uss_bytes': self.uss,
            'uss_mb': round(self.uss / (1024 * 1024), 2) if self.uss else None,
            'pss_bytes': self.pss,
            'pss_mb': round(self.pss / (1024 * 1024), 2) if self.pss else None,
            'shared_bytes': self.shared,
            'gc_objects': self.gc_objects,
            'gc_garbage': self.gc_garbage,
            'gc_collections': self.gc_collections,
        }


@dataclass
class MemoryAlert:
    """Memory-related alert"""
    timestamp: float
    level: MemoryAlertLevel
    alert_type: str
    message: str
    current_value: float
    threshold: float
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'timestamp_iso': datetime.fromtimestamp(self.timestamp).isoformat(),
            'level': self.level.value,
            'alert_type': self.alert_type,
            'message': self.message,
            'current_value': self.current_value,
            'threshold': self.threshold,
            'metadata': self.metadata,
        }


@dataclass
class MemoryMonitorConfig:
    """Configuration for memory monitoring"""
    # Sampling configuration
    sample_interval: float = 5.0      # Seconds between samples
    history_size: int = 720           # Keep 1 hour at 5s intervals

    # Absolute thresholds (bytes)
    rss_warning_mb: float = 500.0     # RSS warning threshold
    rss_critical_mb: float = 1000.0   # RSS critical threshold

    # Growth rate thresholds (leak detection)
    growth_window_samples: int = 60   # Samples to analyze (5 min at 5s)
    growth_rate_warning_mb_per_hour: float = 50.0   # MB/hour growth rate warning
    growth_rate_critical_mb_per_hour: float = 100.0 # MB/hour growth rate critical

    # GC thresholds
    gc_garbage_warning: int = 100     # Uncollectable objects warning
    gc_garbage_critical: int = 1000   # Uncollectable objects critical
    gc_objects_warning: int = 1000000 # Total objects warning (1M)

    # Leak detection tuning
    leak_detection_enabled: bool = True
    leak_confirmation_samples: int = 120  # 10 min at 5s intervals
    leak_growth_threshold_percent: float = 10.0  # 10% growth = possible leak

    # Debug mode (tracemalloc) - WARNING: significant performance overhead
    debug_enabled: bool = False           # Enable tracemalloc debugging
    debug_nframe: int = 5                 # Number of frames to capture
    debug_top_count: int = 20             # Top allocations to track
    debug_snapshot_on_alert: bool = True  # Auto-snapshot on leak alerts
    debug_auto_disable_after: int = 300   # Auto-disable after N seconds (0=never)

    def to_dict(self) -> Dict:
        return {
            'sample_interval': self.sample_interval,
            'history_size': self.history_size,
            'rss_warning_mb': self.rss_warning_mb,
            'rss_critical_mb': self.rss_critical_mb,
            'growth_rate_warning_mb_per_hour': self.growth_rate_warning_mb_per_hour,
            'growth_rate_critical_mb_per_hour': self.growth_rate_critical_mb_per_hour,
            'gc_garbage_warning': self.gc_garbage_warning,
            'gc_garbage_critical': self.gc_garbage_critical,
            'gc_objects_warning': self.gc_objects_warning,
            'leak_detection_enabled': self.leak_detection_enabled,
            'leak_confirmation_samples': self.leak_confirmation_samples,
            'leak_growth_threshold_percent': self.leak_growth_threshold_percent,
            'debug_enabled': self.debug_enabled,
            'debug_nframe': self.debug_nframe,
            'debug_top_count': self.debug_top_count,
            'debug_snapshot_on_alert': self.debug_snapshot_on_alert,
            'debug_auto_disable_after': self.debug_auto_disable_after,
        }


class MemoryMonitor:
    """
    Monitors process memory usage and detects potential memory leaks.

    Provides:
    - Real-time memory metrics (RSS, VMS, USS, PSS)
    - Python GC statistics
    - Memory growth trend analysis
    - Leak detection with configurable thresholds
    - Integration with telemetry system
    """

    def __init__(
        self,
        daemon=None,
        config: Optional[MemoryMonitorConfig] = None,
        on_alert: Optional[Callable[[MemoryAlert], None]] = None,
    ):
        """
        Initialize MemoryMonitor.

        Args:
            daemon: Reference to BoundaryDaemon instance
            config: MemoryMonitorConfig instance
            on_alert: Callback for memory alerts
        """
        self.daemon = daemon
        self.config = config or MemoryMonitorConfig()
        self._on_alert = on_alert

        # State
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # History storage (ring buffer)
        self._history: deque = deque(maxlen=self.config.history_size)
        self._alerts: List[MemoryAlert] = []
        self._alert_history_size = 100

        # Current state
        self._current_snapshot: Optional[MemorySnapshot] = None
        self._leak_indicator = LeakIndicator.NONE
        self._baseline_rss: Optional[int] = None

        # Process handle
        self._process: Optional[Any] = None
        if PSUTIL_AVAILABLE:
            self._process = psutil.Process(os.getpid())

        # Telemetry integration
        self._telemetry_manager = None
        self._metrics_registered = False

        # Debug mode (tracemalloc)
        self._debugger: Optional[TraceMallocDebugger] = None
        self._debug_start_time: Optional[float] = None
        if self.config.debug_enabled:
            self._debugger = TraceMallocDebugger(
                top_count=self.config.debug_top_count,
                nframe=self.config.debug_nframe,
            )

    @property
    def is_available(self) -> bool:
        """Check if memory monitoring is available"""
        return PSUTIL_AVAILABLE

    def set_telemetry_manager(self, telemetry_manager):
        """Set telemetry manager for metrics export"""
        self._telemetry_manager = telemetry_manager
        self._register_metrics()

    def _register_metrics(self):
        """Register memory metrics with telemetry system"""
        if not self._telemetry_manager or self._metrics_registered:
            return

        try:
            # The telemetry manager handles metric registration internally
            # We'll use the gauge/counter methods directly when recording
            self._metrics_registered = True
            logger.info("Memory metrics registered with telemetry")
        except Exception as e:
            logger.warning(f"Failed to register memory metrics: {e}")

    def start(self):
        """Start memory monitoring"""
        if self._running:
            return

        if not self.is_available:
            logger.warning("Memory monitoring not available (psutil not installed)")
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info(f"Memory monitor started (interval: {self.config.sample_interval}s)")

        # Start debugger if enabled
        if self._debugger and self.config.debug_enabled:
            if self._debugger.start():
                self._debug_start_time = time.time()
                logger.warning("tracemalloc DEBUG MODE enabled - expect performance overhead")

    def stop(self):
        """Stop memory monitoring"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)

        # Stop debugger
        if self._debugger and self._debugger.is_enabled:
            # Take final leak report before stopping
            report = self._debugger.compare_to_baseline()
            if report:
                logger.info(f"Final memory growth: {report.growth_bytes / (1024*1024):.2f} MB")
            self._debugger.stop()

        logger.info("Memory monitor stopped")

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                snapshot = self._take_snapshot()

                with self._lock:
                    self._current_snapshot = snapshot
                    self._history.append(snapshot)

                    # Set baseline on first sample
                    if self._baseline_rss is None:
                        self._baseline_rss = snapshot.rss

                # Check thresholds and detect leaks
                self._check_thresholds(snapshot)

                if self.config.leak_detection_enabled:
                    self._detect_leaks()

                # Export metrics to telemetry
                self._export_metrics(snapshot)

                # Check debug mode auto-disable timer
                self._check_debug_auto_disable()

                time.sleep(self.config.sample_interval)

            except Exception as e:
                logger.error(f"Error in memory monitor loop: {e}")
                time.sleep(self.config.sample_interval)

    def _check_debug_auto_disable(self):
        """Check if debug mode should be auto-disabled"""
        if not self._debugger or not self._debugger.is_enabled:
            return

        if self.config.debug_auto_disable_after <= 0:
            return  # Never auto-disable

        if self._debug_start_time:
            elapsed = time.time() - self._debug_start_time
            if elapsed >= self.config.debug_auto_disable_after:
                # Take final report before disabling
                report = self._debugger.compare_to_baseline()
                if report:
                    logger.info(f"Debug mode auto-disable: growth={report.growth_bytes/(1024*1024):.2f} MB")
                    self._log_leak_report(report)
                self._debugger.stop()
                logger.info(f"tracemalloc debug mode auto-disabled after {elapsed:.0f}s")

    def _log_leak_report(self, report: LeakReport):
        """Log a leak report to the daemon event logger"""
        if not self.daemon or not hasattr(self.daemon, 'event_logger'):
            return

        try:
            from .event_logger import EventType
            # Log top growth sites
            top_sites = report.growth_sites[:5] if report.growth_sites else []
            self.daemon.event_logger.log_event(
                EventType.INFO,
                f"Memory debug report: {report.growth_bytes/(1024*1024):.2f} MB growth",
                metadata={
                    'growth_mb': round(report.growth_bytes / (1024 * 1024), 2),
                    'top_growth_sites': top_sites,
                    'new_sites_count': len(report.new_sites),
                }
            )
        except Exception:
            pass

    def _take_snapshot(self) -> MemorySnapshot:
        """Take a memory snapshot"""
        mem_info = self._process.memory_info()

        # Get extended memory info (USS, PSS) on Linux
        uss = None
        pss = None
        shared = None
        try:
            mem_full = self._process.memory_full_info()
            uss = getattr(mem_full, 'uss', None)
            pss = getattr(mem_full, 'pss', None)
            shared = getattr(mem_full, 'shared', None)
        except (psutil.AccessDenied, AttributeError):
            # memory_full_info may not be available
            pass

        # Get GC stats
        gc_stats = gc.get_stats()
        gc_collections = {}
        for i, stat in enumerate(gc_stats):
            gc_collections[i] = stat.get('collections', 0)

        return MemorySnapshot(
            timestamp=time.time(),
            rss=mem_info.rss,
            vms=mem_info.vms,
            uss=uss,
            pss=pss,
            shared=shared,
            gc_objects=len(gc.get_objects()),
            gc_garbage=len(gc.garbage),
            gc_collections=gc_collections,
        )

    def _check_thresholds(self, snapshot: MemorySnapshot):
        """Check memory against configured thresholds"""
        rss_mb = snapshot.rss / (1024 * 1024)

        # RSS thresholds
        if rss_mb >= self.config.rss_critical_mb:
            self._raise_alert(
                MemoryAlertLevel.CRITICAL,
                "rss_critical",
                f"RSS memory critical: {rss_mb:.1f} MB >= {self.config.rss_critical_mb} MB",
                rss_mb,
                self.config.rss_critical_mb,
            )
        elif rss_mb >= self.config.rss_warning_mb:
            self._raise_alert(
                MemoryAlertLevel.WARNING,
                "rss_warning",
                f"RSS memory warning: {rss_mb:.1f} MB >= {self.config.rss_warning_mb} MB",
                rss_mb,
                self.config.rss_warning_mb,
            )

        # GC garbage (uncollectable objects)
        if snapshot.gc_garbage >= self.config.gc_garbage_critical:
            self._raise_alert(
                MemoryAlertLevel.CRITICAL,
                "gc_garbage_critical",
                f"GC garbage critical: {snapshot.gc_garbage} uncollectable objects",
                snapshot.gc_garbage,
                self.config.gc_garbage_critical,
                metadata={'gc_objects': snapshot.gc_objects},
            )
        elif snapshot.gc_garbage >= self.config.gc_garbage_warning:
            self._raise_alert(
                MemoryAlertLevel.WARNING,
                "gc_garbage_warning",
                f"GC garbage warning: {snapshot.gc_garbage} uncollectable objects",
                snapshot.gc_garbage,
                self.config.gc_garbage_warning,
                metadata={'gc_objects': snapshot.gc_objects},
            )

        # Object count threshold
        if snapshot.gc_objects >= self.config.gc_objects_warning:
            self._raise_alert(
                MemoryAlertLevel.WARNING,
                "gc_objects_warning",
                f"High object count: {snapshot.gc_objects:,} tracked objects",
                snapshot.gc_objects,
                self.config.gc_objects_warning,
            )

    def _detect_leaks(self):
        """Analyze memory history for leak patterns"""
        with self._lock:
            if len(self._history) < self.config.growth_window_samples:
                return

            # Get samples for analysis
            samples = list(self._history)[-self.config.growth_window_samples:]

        # Calculate growth rate
        growth_rate = self._calculate_growth_rate(samples)
        growth_rate_mb_per_hour = growth_rate * 3600 / (1024 * 1024)

        # Check growth rate thresholds
        if growth_rate_mb_per_hour >= self.config.growth_rate_critical_mb_per_hour:
            self._leak_indicator = LeakIndicator.LIKELY
            self._raise_alert(
                MemoryAlertLevel.CRITICAL,
                "memory_leak_likely",
                f"Likely memory leak: growing at {growth_rate_mb_per_hour:.1f} MB/hour",
                growth_rate_mb_per_hour,
                self.config.growth_rate_critical_mb_per_hour,
                metadata={'leak_indicator': self._leak_indicator.value},
            )
        elif growth_rate_mb_per_hour >= self.config.growth_rate_warning_mb_per_hour:
            self._leak_indicator = LeakIndicator.POSSIBLE
            self._raise_alert(
                MemoryAlertLevel.WARNING,
                "memory_leak_possible",
                f"Possible memory leak: growing at {growth_rate_mb_per_hour:.1f} MB/hour",
                growth_rate_mb_per_hour,
                self.config.growth_rate_warning_mb_per_hour,
                metadata={'leak_indicator': self._leak_indicator.value},
            )
        else:
            self._leak_indicator = LeakIndicator.NONE

        # Check for confirmed leak (extended analysis)
        if len(self._history) >= self.config.leak_confirmation_samples:
            self._check_confirmed_leak()

    def _calculate_growth_rate(self, samples: List[MemorySnapshot]) -> float:
        """
        Calculate memory growth rate using linear regression.

        Returns:
            Growth rate in bytes per second
        """
        if len(samples) < 2:
            return 0.0

        # Simple linear regression on RSS values
        n = len(samples)
        sum_x = sum(s.timestamp for s in samples)
        sum_y = sum(s.rss for s in samples)
        sum_xy = sum(s.timestamp * s.rss for s in samples)
        sum_xx = sum(s.timestamp ** 2 for s in samples)

        # Slope = (n * sum_xy - sum_x * sum_y) / (n * sum_xx - sum_x^2)
        denominator = n * sum_xx - sum_x ** 2
        if denominator == 0:
            return 0.0

        slope = (n * sum_xy - sum_x * sum_y) / denominator
        return max(0, slope)  # Only positive growth indicates leak

    def _check_confirmed_leak(self):
        """Check if a leak is confirmed over extended period"""
        with self._lock:
            samples = list(self._history)

        if len(samples) < self.config.leak_confirmation_samples:
            return

        # Compare current to baseline
        current_rss = samples[-1].rss
        baseline_rss = self._baseline_rss or samples[0].rss

        growth_percent = ((current_rss - baseline_rss) / baseline_rss) * 100

        if growth_percent >= self.config.leak_growth_threshold_percent:
            # Check if growth is sustained (not just a spike)
            mid_point = len(samples) // 2
            mid_rss = samples[mid_point].rss

            # If middle sample is between start and end, growth is sustained
            if baseline_rss < mid_rss < current_rss:
                self._leak_indicator = LeakIndicator.CONFIRMED
                self._raise_alert(
                    MemoryAlertLevel.CRITICAL,
                    "memory_leak_confirmed",
                    f"Confirmed memory leak: {growth_percent:.1f}% growth over monitoring period",
                    growth_percent,
                    self.config.leak_growth_threshold_percent,
                    metadata={
                        'baseline_rss_mb': baseline_rss / (1024 * 1024),
                        'current_rss_mb': current_rss / (1024 * 1024),
                        'leak_indicator': self._leak_indicator.value,
                    },
                )

    def _raise_alert(
        self,
        level: MemoryAlertLevel,
        alert_type: str,
        message: str,
        current_value: float,
        threshold: float,
        metadata: Optional[Dict] = None,
    ):
        """Raise a memory alert"""
        alert = MemoryAlert(
            timestamp=time.time(),
            level=level,
            alert_type=alert_type,
            message=message,
            current_value=current_value,
            threshold=threshold,
            metadata=metadata or {},
        )

        # Store in history
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > self._alert_history_size:
                self._alerts = self._alerts[-self._alert_history_size:]

        # Log the alert
        log_level = {
            MemoryAlertLevel.INFO: logging.INFO,
            MemoryAlertLevel.WARNING: logging.WARNING,
            MemoryAlertLevel.CRITICAL: logging.ERROR,
        }.get(level, logging.WARNING)

        logger.log(log_level, f"Memory alert [{level.value}]: {message}")

        # Notify callback
        if self._on_alert:
            try:
                self._on_alert(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")

        # Log to daemon event logger if available
        if self.daemon and hasattr(self.daemon, 'event_logger'):
            try:
                from .event_logger import EventType
                self.daemon.event_logger.log_event(
                    EventType.ALERT if level == MemoryAlertLevel.CRITICAL else EventType.INFO,
                    message,
                    metadata={
                        'alert_type': alert_type,
                        'level': level.value,
                        'current_value': current_value,
                        'threshold': threshold,
                        **(metadata or {}),
                    }
                )
            except Exception:
                pass

        # Capture tracemalloc snapshot on critical leak alerts
        if (level == MemoryAlertLevel.CRITICAL and
            'leak' in alert_type and
            self.config.debug_snapshot_on_alert and
            self._debugger and self._debugger.is_enabled):
            try:
                report = self._debugger.compare_to_baseline()
                if report:
                    logger.info(f"Leak debug snapshot captured: {len(report.growth_sites)} growth sites")
                    self._log_leak_report(report)
                    # Log top sites to console for immediate visibility
                    for i, site in enumerate(report.growth_sites[:3]):
                        logger.warning(f"  Top leak site #{i+1}: {site['location']} "
                                      f"(+{site['size_diff_mb']:.2f} MB)")
            except Exception as e:
                logger.debug(f"Failed to capture debug snapshot: {e}")

    def _export_metrics(self, snapshot: MemorySnapshot):
        """Export metrics to telemetry system"""
        if not self._telemetry_manager:
            return

        try:
            # Memory gauges
            rss_mb = snapshot.rss / (1024 * 1024)
            vms_mb = snapshot.vms / (1024 * 1024)

            self._telemetry_manager.set_gauge("memory.rss_mb", int(rss_mb))
            self._telemetry_manager.set_gauge("memory.vms_mb", int(vms_mb))

            if snapshot.uss:
                uss_mb = snapshot.uss / (1024 * 1024)
                self._telemetry_manager.set_gauge("memory.uss_mb", int(uss_mb))

            if snapshot.pss:
                pss_mb = snapshot.pss / (1024 * 1024)
                self._telemetry_manager.set_gauge("memory.pss_mb", int(pss_mb))

            # GC gauges
            self._telemetry_manager.set_gauge("memory.gc_objects", snapshot.gc_objects)
            self._telemetry_manager.set_gauge("memory.gc_garbage", snapshot.gc_garbage)

            # Leak indicator
            leak_value = {
                LeakIndicator.NONE: 0,
                LeakIndicator.POSSIBLE: 1,
                LeakIndicator.LIKELY: 2,
                LeakIndicator.CONFIRMED: 3,
            }.get(self._leak_indicator, 0)
            self._telemetry_manager.set_gauge("memory.leak_indicator", leak_value)

        except Exception as e:
            logger.debug(f"Failed to export memory metrics: {e}")

    def get_current_snapshot(self) -> Optional[MemorySnapshot]:
        """Get the most recent memory snapshot"""
        with self._lock:
            return self._current_snapshot

    def get_history(self, limit: Optional[int] = None) -> List[MemorySnapshot]:
        """Get memory history"""
        with self._lock:
            if limit:
                return list(self._history)[-limit:]
            return list(self._history)

    def get_alerts(self, limit: Optional[int] = None) -> List[MemoryAlert]:
        """Get recent alerts"""
        with self._lock:
            if limit:
                return self._alerts[-limit:]
            return list(self._alerts)

    def get_leak_indicator(self) -> LeakIndicator:
        """Get current leak indicator status"""
        return self._leak_indicator

    def get_summary_stats(self) -> Dict:
        """Get summary statistics"""
        with self._lock:
            current = self._current_snapshot
            history_len = len(self._history)
            alert_count = len(self._alerts)

        stats = {
            'available': self.is_available,
            'running': self._running,
            'samples_collected': history_len,
            'alerts_total': alert_count,
            'leak_indicator': self._leak_indicator.value,
            'config': self.config.to_dict(),
        }

        if current:
            stats['current'] = current.to_dict()

        if self._baseline_rss:
            stats['baseline_rss_mb'] = round(self._baseline_rss / (1024 * 1024), 2)

        # Calculate growth since baseline
        if current and self._baseline_rss:
            growth = current.rss - self._baseline_rss
            growth_percent = (growth / self._baseline_rss) * 100
            stats['growth_since_baseline_mb'] = round(growth / (1024 * 1024), 2)
            stats['growth_since_baseline_percent'] = round(growth_percent, 2)

        # Add debug mode info
        if self._debugger:
            stats['debug'] = self._debugger.get_status()
            if self._debug_start_time:
                stats['debug']['running_seconds'] = round(time.time() - self._debug_start_time, 1)

        return stats

    # Debug mode control methods

    def enable_debug_mode(self, auto_disable_after: int = 300) -> bool:
        """
        Enable tracemalloc debug mode at runtime.

        Args:
            auto_disable_after: Seconds until auto-disable (0=never)

        Returns:
            True if enabled successfully
        """
        if self._debugger and self._debugger.is_enabled:
            logger.info("Debug mode already enabled")
            return True

        # Create debugger if not exists
        if not self._debugger:
            self._debugger = TraceMallocDebugger(
                top_count=self.config.debug_top_count,
                nframe=self.config.debug_nframe,
            )

        if self._debugger.start():
            self._debug_start_time = time.time()
            self.config.debug_auto_disable_after = auto_disable_after
            logger.warning(f"tracemalloc DEBUG MODE enabled (auto-disable: {auto_disable_after}s)")
            return True
        return False

    def disable_debug_mode(self) -> Optional[LeakReport]:
        """
        Disable tracemalloc debug mode.

        Returns:
            Final LeakReport if available
        """
        if not self._debugger or not self._debugger.is_enabled:
            return None

        # Capture final report
        report = self._debugger.compare_to_baseline()
        if report:
            self._log_leak_report(report)

        self._debugger.stop()
        self._debug_start_time = None
        logger.info("tracemalloc debug mode disabled")
        return report

    def get_debug_snapshot(self) -> Optional[TraceMallocSnapshot]:
        """
        Take a tracemalloc snapshot (debug mode must be enabled).

        Returns:
            TraceMallocSnapshot or None
        """
        if not self._debugger or not self._debugger.is_enabled:
            return None
        return self._debugger.take_snapshot()

    def get_debug_leak_report(self) -> Optional[LeakReport]:
        """
        Compare current allocations to baseline (debug mode must be enabled).

        Returns:
            LeakReport with growth analysis or None
        """
        if not self._debugger or not self._debugger.is_enabled:
            return None
        return self._debugger.compare_to_baseline()

    def get_debug_reports(self, limit: int = 10) -> List[LeakReport]:
        """Get stored leak reports from debug mode"""
        if not self._debugger:
            return []
        return self._debugger.get_leak_reports(limit)

    def reset_debug_baseline(self):
        """Reset the tracemalloc baseline to current state"""
        if self._debugger and self._debugger.is_enabled:
            self._debugger.reset_baseline()

    def force_gc(self) -> Dict:
        """Force garbage collection and return stats"""
        before_objects = len(gc.get_objects())
        before_garbage = len(gc.garbage)

        # Run collection for all generations
        collected = [gc.collect(i) for i in range(3)]

        after_objects = len(gc.get_objects())
        after_garbage = len(gc.garbage)

        return {
            'before_objects': before_objects,
            'after_objects': after_objects,
            'freed_objects': before_objects - after_objects,
            'before_garbage': before_garbage,
            'after_garbage': after_garbage,
            'collected_per_generation': collected,
        }

    def reset_baseline(self):
        """Reset the memory baseline to current value"""
        snapshot = self._take_snapshot()
        with self._lock:
            self._baseline_rss = snapshot.rss
            self._leak_indicator = LeakIndicator.NONE
        logger.info(f"Memory baseline reset to {snapshot.rss / (1024*1024):.1f} MB")


# Convenience function to create configured monitor
def create_memory_monitor(
    daemon=None,
    sample_interval: float = 5.0,
    rss_warning_mb: float = 500.0,
    rss_critical_mb: float = 1000.0,
    leak_detection: bool = True,
) -> MemoryMonitor:
    """
    Create a configured memory monitor.

    Args:
        daemon: BoundaryDaemon instance
        sample_interval: Seconds between samples
        rss_warning_mb: RSS warning threshold in MB
        rss_critical_mb: RSS critical threshold in MB
        leak_detection: Enable leak detection

    Returns:
        Configured MemoryMonitor instance
    """
    config = MemoryMonitorConfig(
        sample_interval=sample_interval,
        rss_warning_mb=rss_warning_mb,
        rss_critical_mb=rss_critical_mb,
        leak_detection_enabled=leak_detection,
    )

    return MemoryMonitor(daemon=daemon, config=config)


if __name__ == '__main__':
    # Test the memory monitor
    import sys

    print("Testing Memory Monitor...")
    print(f"psutil available: {PSUTIL_AVAILABLE}")

    if not PSUTIL_AVAILABLE:
        print("Cannot run test without psutil")
        sys.exit(1)

    # Create monitor with short intervals for testing
    config = MemoryMonitorConfig(
        sample_interval=1.0,
        history_size=60,
        rss_warning_mb=100.0,  # Low thresholds for testing
        growth_window_samples=10,
    )

    def on_alert(alert: MemoryAlert):
        print(f"\n[ALERT] {alert.level.value}: {alert.message}")

    monitor = MemoryMonitor(config=config, on_alert=on_alert)
    monitor.start()

    try:
        print("\nMonitoring memory. Press Ctrl+C to stop...")
        print("Creating some objects to test monitoring...\n")

        # Simulate some memory activity
        data = []
        for i in range(30):
            # Take snapshot manually for display
            snapshot = monitor.get_current_snapshot()
            if snapshot:
                print(f"[{i:2d}] RSS: {snapshot.rss/(1024*1024):.1f} MB, "
                      f"Objects: {snapshot.gc_objects:,}, "
                      f"Leak: {monitor.get_leak_indicator().value}")

            # Allocate some memory
            data.append([0] * 10000)
            time.sleep(1)

        # Print summary
        print("\n=== Summary ===")
        stats = monitor.get_summary_stats()
        for key, value in stats.items():
            if key != 'config':
                print(f"{key}: {value}")

        # Force GC
        print("\n=== Force GC ===")
        gc_result = monitor.force_gc()
        for key, value in gc_result.items():
            print(f"{key}: {value}")

        # Get alerts
        print("\n=== Alerts ===")
        alerts = monitor.get_alerts()
        if alerts:
            for alert in alerts[-5:]:
                print(f"[{alert.level.value}] {alert.alert_type}: {alert.message}")
        else:
            print("No alerts recorded")

    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        monitor.stop()
        print("Memory monitor test complete.")
