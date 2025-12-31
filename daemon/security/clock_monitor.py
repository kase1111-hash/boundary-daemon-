"""
Clock Monitor - Time Integrity and Drift Protection

Protects against time-based attacks by:
- Detecting NTP synchronization status
- Using monotonic clocks for internal timing
- Detecting sudden time jumps (manipulation attempts)
- Tracking clock drift over time
- Validating secure time sources

Time-based attacks this protects against:
- Token expiration bypass (setting clock back)
- Rate limit bypass (setting clock forward)
- Log timestamp manipulation
- Certificate/signature time attacks
"""

import os
import re
import subprocess
import threading
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ClockStatus(Enum):
    """Status of system clock synchronization."""
    SYNCHRONIZED = auto()      # Clock is NTP-synced
    NOT_SYNCHRONIZED = auto()  # Clock is not synced
    UNKNOWN = auto()           # Cannot determine status
    MANIPULATED = auto()       # Time manipulation detected


class TimeJumpDirection(Enum):
    """Direction of detected time jump."""
    FORWARD = auto()   # Clock jumped forward
    BACKWARD = auto()  # Clock jumped backward


@dataclass
class TimeJumpEvent:
    """Records a detected time jump."""
    timestamp_monotonic: float       # When detected (monotonic)
    timestamp_before: datetime       # Wall time before jump
    timestamp_after: datetime        # Wall time after jump
    jump_seconds: float              # Size of jump in seconds
    direction: TimeJumpDirection     # Forward or backward
    severity: str                    # LOW, MEDIUM, HIGH, CRITICAL


@dataclass
class ClockState:
    """Current state of the clock monitor."""
    status: ClockStatus = ClockStatus.UNKNOWN
    is_ntp_synced: bool = False
    ntp_server: Optional[str] = None
    last_sync_time: Optional[datetime] = None
    drift_ppm: float = 0.0           # Parts per million drift
    jump_count: int = 0              # Number of jumps detected
    last_jump: Optional[TimeJumpEvent] = None
    monitoring_since: float = 0.0    # Monotonic time when started
    wall_time_at_start: datetime = field(default_factory=datetime.utcnow)


class ClockMonitor:
    """
    Monitors system clock for manipulation and drift.

    Uses multiple time sources:
    - time.monotonic() for elapsed time (cannot be manipulated)
    - time.time() / datetime for wall clock
    - NTP status for sync verification

    Detection methods:
    - Compare monotonic elapsed time vs wall clock elapsed time
    - Check NTP synchronization status
    - Detect sudden jumps (> threshold)
    - Track cumulative drift
    """

    # Thresholds for time jump detection
    JUMP_THRESHOLD_LOW = 60          # 1 minute - suspicious
    JUMP_THRESHOLD_MEDIUM = 300      # 5 minutes - likely attack
    JUMP_THRESHOLD_HIGH = 3600       # 1 hour - definite attack
    JUMP_THRESHOLD_CRITICAL = 86400  # 1 day - major manipulation

    # Maximum acceptable drift (parts per million)
    MAX_DRIFT_PPM = 500  # 500 ppm = ~43 seconds/day

    # Check interval
    DEFAULT_CHECK_INTERVAL = 10  # seconds

    def __init__(
        self,
        check_interval: float = DEFAULT_CHECK_INTERVAL,
        on_time_jump: Optional[Callable[[TimeJumpEvent], None]] = None,
        on_ntp_lost: Optional[Callable[[], None]] = None,
        on_manipulation: Optional[Callable[[str], None]] = None,
    ):
        """
        Initialize clock monitor.

        Args:
            check_interval: How often to check clock (seconds)
            on_time_jump: Callback when time jump detected
            on_ntp_lost: Callback when NTP sync lost
            on_manipulation: Callback when manipulation detected
        """
        self.check_interval = check_interval
        self._on_time_jump = on_time_jump
        self._on_ntp_lost = on_ntp_lost
        self._on_manipulation = on_manipulation

        self._state = ClockState()
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()

        # Baseline for drift detection
        self._baseline_monotonic: float = 0.0
        self._baseline_wall: float = 0.0

        # Previous check values
        self._prev_monotonic: float = 0.0
        self._prev_wall: float = 0.0

        # Jump history
        self._jump_history: List[TimeJumpEvent] = []
        self._max_jump_history = 100

    def start(self):
        """Start clock monitoring."""
        if self._running:
            return

        self._running = True

        # Set baselines
        self._baseline_monotonic = time.monotonic()
        self._baseline_wall = time.time()
        self._prev_monotonic = self._baseline_monotonic
        self._prev_wall = self._baseline_wall

        # Initialize state
        self._state.monitoring_since = self._baseline_monotonic
        self._state.wall_time_at_start = datetime.utcnow()

        # Check initial NTP status
        self._update_ntp_status()

        # Start monitor thread
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="ClockMonitor"
        )
        self._monitor_thread.start()

        logger.info("[CLOCK] Clock monitor started")

    def stop(self):
        """Stop clock monitoring."""
        if not self._running:
            return

        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)

        logger.info("[CLOCK] Clock monitor stopped")

    def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                self._check_clock()
            except Exception as e:
                print(f"[CLOCK] Error in monitor loop: {e}")

            # Use monotonic sleep to avoid manipulation
            time.sleep(self.check_interval)

    def _check_clock(self):
        """Perform clock integrity check."""
        with self._lock:
            now_monotonic = time.monotonic()
            now_wall = time.time()

            # Calculate elapsed times
            monotonic_elapsed = now_monotonic - self._prev_monotonic
            wall_elapsed = now_wall - self._prev_wall

            # Detect time jumps
            time_diff = wall_elapsed - monotonic_elapsed

            if abs(time_diff) > self.JUMP_THRESHOLD_LOW:
                self._handle_time_jump(
                    time_diff,
                    datetime.fromtimestamp(self._prev_wall),
                    datetime.fromtimestamp(now_wall),
                    now_monotonic,
                )

            # Calculate drift since start
            total_monotonic = now_monotonic - self._baseline_monotonic
            total_wall = now_wall - self._baseline_wall

            if total_monotonic > 0:
                drift_ratio = (total_wall - total_monotonic) / total_monotonic
                self._state.drift_ppm = drift_ratio * 1_000_000

                if abs(self._state.drift_ppm) > self.MAX_DRIFT_PPM:
                    print(f"[CLOCK] Warning: High drift detected: {self._state.drift_ppm:.1f} ppm")

            # Update previous values
            self._prev_monotonic = now_monotonic
            self._prev_wall = now_wall

            # Periodic NTP check (every 10 intervals)
            if int(now_monotonic) % (self.check_interval * 10) < self.check_interval:
                self._update_ntp_status()

    def _handle_time_jump(
        self,
        jump_seconds: float,
        time_before: datetime,
        time_after: datetime,
        monotonic_now: float,
    ):
        """Handle detected time jump."""
        direction = TimeJumpDirection.FORWARD if jump_seconds > 0 else TimeJumpDirection.BACKWARD
        abs_jump = abs(jump_seconds)

        # Determine severity
        if abs_jump >= self.JUMP_THRESHOLD_CRITICAL:
            severity = "CRITICAL"
        elif abs_jump >= self.JUMP_THRESHOLD_HIGH:
            severity = "HIGH"
        elif abs_jump >= self.JUMP_THRESHOLD_MEDIUM:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        event = TimeJumpEvent(
            timestamp_monotonic=monotonic_now,
            timestamp_before=time_before,
            timestamp_after=time_after,
            jump_seconds=jump_seconds,
            direction=direction,
            severity=severity,
        )

        # Update state
        self._state.jump_count += 1
        self._state.last_jump = event
        self._state.status = ClockStatus.MANIPULATED

        # Add to history
        self._jump_history.append(event)
        if len(self._jump_history) > self._max_jump_history:
            self._jump_history.pop(0)

        # Log
        direction_str = "FORWARD" if direction == TimeJumpDirection.FORWARD else "BACKWARD"
        print(f"[CLOCK] TIME JUMP DETECTED: {direction_str} {abs_jump:.1f}s (severity: {severity})")
        print(f"[CLOCK]   Before: {time_before.isoformat()}")
        print(f"[CLOCK]   After:  {time_after.isoformat()}")

        # Callbacks
        if self._on_time_jump:
            try:
                self._on_time_jump(event)
            except Exception as e:
                print(f"[CLOCK] Error in time_jump callback: {e}")

        if severity in ("HIGH", "CRITICAL") and self._on_manipulation:
            try:
                self._on_manipulation(f"Time jump {direction_str}: {abs_jump:.1f}s")
            except Exception as e:
                print(f"[CLOCK] Error in manipulation callback: {e}")

    def _update_ntp_status(self):
        """Check NTP synchronization status."""
        was_synced = self._state.is_ntp_synced

        # Try multiple methods to check NTP status
        synced, server = self._check_timedatectl()

        if synced is None:
            synced, server = self._check_ntpstat()

        if synced is None:
            synced, server = self._check_chronyc()

        if synced is not None:
            self._state.is_ntp_synced = synced
            self._state.ntp_server = server

            if synced:
                self._state.status = ClockStatus.SYNCHRONIZED
                self._state.last_sync_time = datetime.utcnow()
            else:
                if self._state.status != ClockStatus.MANIPULATED:
                    self._state.status = ClockStatus.NOT_SYNCHRONIZED

            # Callback if sync was lost
            if was_synced and not synced and self._on_ntp_lost:
                try:
                    self._on_ntp_lost()
                except Exception as e:
                    print(f"[CLOCK] Error in ntp_lost callback: {e}")
        else:
            self._state.status = ClockStatus.UNKNOWN

    def _check_timedatectl(self) -> Tuple[Optional[bool], Optional[str]]:
        """Check NTP status using timedatectl."""
        try:
            result = subprocess.run(
                ["timedatectl", "status"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                output = result.stdout

                # Check for sync status
                sync_match = re.search(
                    r"(NTP synchronized|System clock synchronized):\s*(yes|no)",
                    output,
                    re.IGNORECASE
                )

                if sync_match:
                    synced = sync_match.group(2).lower() == "yes"
                    return synced, None

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass

        return None, None

    def _check_ntpstat(self) -> Tuple[Optional[bool], Optional[str]]:
        """Check NTP status using ntpstat."""
        try:
            result = subprocess.run(
                ["ntpstat"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            # ntpstat returns 0 if synchronized
            if result.returncode == 0:
                # Try to extract server
                server_match = re.search(r"synchronised to (.+)", result.stdout)
                server = server_match.group(1) if server_match else None
                return True, server
            elif result.returncode == 1:
                return False, None

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass

        return None, None

    def _check_chronyc(self) -> Tuple[Optional[bool], Optional[str]]:
        """Check NTP status using chronyc."""
        try:
            result = subprocess.run(
                ["chronyc", "tracking"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                output = result.stdout

                # Check leap status
                if "Leap status     : Normal" in output:
                    # Extract reference
                    ref_match = re.search(r"Reference ID\s+:\s+[\d.]+\s+\(([^)]+)\)", output)
                    server = ref_match.group(1) if ref_match else None
                    return True, server

                if "Not synchronised" in output:
                    return False, None

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass

        return None, None

    def get_state(self) -> Dict:
        """Get current clock state as dictionary."""
        with self._lock:
            state = {
                "status": self._state.status.name,
                "is_ntp_synced": self._state.is_ntp_synced,
                "ntp_server": self._state.ntp_server,
                "last_sync_time": self._state.last_sync_time.isoformat() if self._state.last_sync_time else None,
                "drift_ppm": round(self._state.drift_ppm, 2),
                "jump_count": self._state.jump_count,
                "monitoring_since": self._state.wall_time_at_start.isoformat(),
                "uptime_seconds": time.monotonic() - self._state.monitoring_since,
            }

            if self._state.last_jump:
                state["last_jump"] = {
                    "direction": self._state.last_jump.direction.name,
                    "seconds": self._state.last_jump.jump_seconds,
                    "severity": self._state.last_jump.severity,
                    "before": self._state.last_jump.timestamp_before.isoformat(),
                    "after": self._state.last_jump.timestamp_after.isoformat(),
                }

            return state

    def get_jump_history(self, limit: int = 10) -> List[Dict]:
        """Get recent time jump events."""
        with self._lock:
            events = self._jump_history[-limit:]
            return [
                {
                    "direction": e.direction.name,
                    "seconds": e.jump_seconds,
                    "severity": e.severity,
                    "before": e.timestamp_before.isoformat(),
                    "after": e.timestamp_after.isoformat(),
                }
                for e in events
            ]

    def is_time_trustworthy(self) -> Tuple[bool, str]:
        """
        Check if system time can be trusted.

        Returns:
            (is_trustworthy, reason)
        """
        with self._lock:
            # Check for recent manipulation
            if self._state.status == ClockStatus.MANIPULATED:
                if self._state.last_jump:
                    return False, f"Time manipulation detected: {self._state.last_jump.severity} severity jump"
                return False, "Time manipulation detected"

            # Check NTP sync
            if not self._state.is_ntp_synced:
                if self._state.status == ClockStatus.UNKNOWN:
                    return True, "NTP status unknown, assuming trustworthy"
                return False, "System clock not NTP synchronized"

            # Check drift
            if abs(self._state.drift_ppm) > self.MAX_DRIFT_PPM:
                return False, f"Excessive clock drift: {self._state.drift_ppm:.1f} ppm"

            return True, "Clock is synchronized and stable"

    def get_monotonic_time(self) -> float:
        """Get monotonic time (cannot be manipulated)."""
        return time.monotonic()

    def get_secure_timestamp(self) -> Tuple[datetime, bool]:
        """
        Get current timestamp with trustworthiness indicator.

        Returns:
            (timestamp, is_trustworthy)
        """
        is_trustworthy, _ = self.is_time_trustworthy()
        return datetime.utcnow(), is_trustworthy

    def validate_timestamp(self, timestamp: datetime, max_age_seconds: float = 300) -> Tuple[bool, str]:
        """
        Validate that a timestamp is reasonable.

        Args:
            timestamp: Timestamp to validate
            max_age_seconds: Maximum acceptable age

        Returns:
            (is_valid, reason)
        """
        now = datetime.utcnow()
        age = (now - timestamp).total_seconds()

        # Future timestamp
        if age < -60:  # Allow 1 minute of clock skew
            return False, f"Timestamp is {-age:.0f}s in the future"

        # Too old
        if age > max_age_seconds:
            return False, f"Timestamp is {age:.0f}s old (max: {max_age_seconds}s)"

        return True, "Timestamp is valid"


class SecureTimer:
    """
    Timer that uses monotonic clock for manipulation resistance.

    Use this instead of time.time() for:
    - Rate limiting windows
    - Token expiration checks
    - Session timeouts
    - Any security-sensitive timing
    """

    def __init__(self):
        self._start_monotonic = time.monotonic()
        self._start_wall = time.time()

    def elapsed(self) -> float:
        """Get elapsed time since timer started (monotonic)."""
        return time.monotonic() - self._start_monotonic

    def elapsed_since(self, start_monotonic: float) -> float:
        """Get elapsed time since a monotonic timestamp."""
        return time.monotonic() - start_monotonic

    def is_expired(self, duration_seconds: float) -> bool:
        """Check if timer has expired."""
        return self.elapsed() >= duration_seconds

    @staticmethod
    def now() -> float:
        """Get current monotonic timestamp."""
        return time.monotonic()

    def wall_time_at_start(self) -> datetime:
        """Get wall clock time when timer started (for logging only)."""
        return datetime.fromtimestamp(self._start_wall)


# Global secure timer instance
_secure_timer = SecureTimer()


def monotonic_now() -> float:
    """Get current monotonic time."""
    return time.monotonic()


def secure_elapsed(start: float) -> float:
    """Get elapsed time since a monotonic start time."""
    return time.monotonic() - start


if __name__ == "__main__":
    print("Testing Clock Monitor...")

    def on_jump(event):
        print(f"  CALLBACK: Jump detected - {event.severity}")

    def on_manipulation(reason):
        print(f"  CALLBACK: Manipulation - {reason}")

    monitor = ClockMonitor(
        check_interval=2,
        on_time_jump=on_jump,
        on_manipulation=on_manipulation,
    )

    monitor.start()

    print("\nInitial state:")
    state = monitor.get_state()
    for k, v in state.items():
        print(f"  {k}: {v}")

    print("\nChecking time trustworthiness...")
    trustworthy, reason = monitor.is_time_trustworthy()
    print(f"  Trustworthy: {trustworthy}")
    print(f"  Reason: {reason}")

    print("\nTesting SecureTimer...")
    timer = SecureTimer()
    time.sleep(1)
    print(f"  Elapsed: {timer.elapsed():.2f}s")
    print(f"  Wall time at start: {timer.wall_time_at_start()}")

    print("\nMonitoring for 10 seconds...")
    time.sleep(10)

    print("\nFinal state:")
    state = monitor.get_state()
    for k, v in state.items():
        print(f"  {k}: {v}")

    monitor.stop()
    print("\nTest complete!")
