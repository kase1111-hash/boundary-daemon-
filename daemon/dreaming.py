"""
Dreaming Status Reporter - Periodic CLI status updates.

Provides a gentle, non-intrusive status line that shows what the daemon
is doing internally. Updates every 5 seconds with minimal overhead.

The "dreaming" metaphor represents the daemon's quiet internal processing -
like thoughts passing through a sleeping mind.
"""

import logging
import random
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class DreamPhase(Enum):
    """Phases of daemon activity to report on."""
    AWAKENING = "awakening"      # Startup
    WATCHING = "watching"        # Monitoring state
    THINKING = "thinking"        # Processing policy decisions
    GUARDING = "guarding"        # Active enforcement
    LISTENING = "listening"      # Waiting for events
    VERIFYING = "verifying"      # Running integrity checks
    REMEMBERING = "remembering"  # Logging/persisting
    RESTING = "resting"          # Idle/low activity


@dataclass
class DreamEvent:
    """A single event to potentially report."""
    phase: DreamPhase
    message: str
    timestamp: float = field(default_factory=time.time)
    details: Optional[Dict[str, Any]] = None


class DreamingReporter:
    """
    Periodic status reporter for the daemon CLI.

    Reports daemon activity every 5 seconds with minimal overhead.
    Only samples existing state - does not trigger any new operations.

    Thread-safe and designed to be completely non-blocking.
    """

    # ANSI color codes for terminal output
    COLORS = {
        'dim': '\033[2m',
        'cyan': '\033[36m',
        'blue': '\033[34m',
        'magenta': '\033[35m',
        'green': '\033[32m',
        'yellow': '\033[33m',
        'reset': '\033[0m',
    }

    # Dream phrases for each phase (adds personality)
    DREAM_PHRASES = {
        DreamPhase.AWAKENING: [
            "...opening eyes...",
            "...stretching awareness...",
            "...initializing consciousness...",
        ],
        DreamPhase.WATCHING: [
            "...scanning horizons...",
            "...observing patterns...",
            "...monitoring flows...",
            "...tracking signals...",
        ],
        DreamPhase.THINKING: [
            "...weighing decisions...",
            "...evaluating paths...",
            "...considering options...",
            "...analyzing context...",
        ],
        DreamPhase.GUARDING: [
            "...enforcing boundaries...",
            "...holding the line...",
            "...maintaining barriers...",
            "...protecting perimeter...",
        ],
        DreamPhase.LISTENING: [
            "...awaiting signals...",
            "...tuned to whispers...",
            "...listening carefully...",
            "...ears to the ground...",
        ],
        DreamPhase.VERIFYING: [
            "...checking integrity...",
            "...validating state...",
            "...confirming authenticity...",
            "...verifying signatures...",
        ],
        DreamPhase.REMEMBERING: [
            "...writing memories...",
            "...preserving records...",
            "...etching events...",
            "...storing experiences...",
        ],
        DreamPhase.RESTING: [
            "...breathing quietly...",
            "...in peaceful watch...",
            "...standing sentinel...",
            "...dreaming of order...",
        ],
    }

    def __init__(
        self,
        interval: float = 5.0,
        use_colors: bool = True,
        output_func: Optional[Callable[[str], None]] = None,
    ):
        """
        Initialize the dreaming reporter.

        Args:
            interval: Seconds between status updates (default 5.0)
            use_colors: Whether to use ANSI colors in output
            output_func: Custom output function (defaults to print)
        """
        self.interval = interval
        self.use_colors = use_colors and self._terminal_supports_colors()
        self._output = output_func or print

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Event buffer - stores recent events to report
        self._events: deque = deque(maxlen=50)

        # Current activity tracking
        self._current_phase = DreamPhase.AWAKENING
        self._active_operations: Dict[str, float] = {}  # operation -> start_time
        self._completed_operations: deque = deque(maxlen=20)

        # Statistics (lightweight counters)
        self._stats = {
            'policy_checks': 0,
            'state_updates': 0,
            'events_logged': 0,
            'integrity_checks': 0,
            'enforcement_actions': 0,
            'health_checks': 0,
        }

        # Callbacks for getting daemon state (set by daemon)
        self._state_callbacks: Dict[str, Callable] = {}

    def _terminal_supports_colors(self) -> bool:
        """Check if terminal supports ANSI colors."""
        import sys
        import os

        if not sys.stdout.isatty():
            return False
        if os.name == 'nt':
            # Windows 10+ supports ANSI
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                return True
            except Exception:
                return False
        return True

    def _color(self, text: str, color: str) -> str:
        """Apply color to text if colors are enabled."""
        if not self.use_colors:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"

    def register_state_callback(self, name: str, callback: Callable) -> None:
        """Register a callback to get daemon state for reporting."""
        with self._lock:
            self._state_callbacks[name] = callback

    def start_operation(self, operation: str) -> None:
        """Record the start of an operation."""
        with self._lock:
            self._active_operations[operation] = time.time()

    def complete_operation(self, operation: str, success: bool = True) -> None:
        """Record completion of an operation."""
        with self._lock:
            start_time = self._active_operations.pop(operation, None)
            if start_time:
                duration = time.time() - start_time
                self._completed_operations.append({
                    'operation': operation,
                    'duration': duration,
                    'success': success,
                    'time': time.time(),
                })

    def record_event(self, phase: DreamPhase, message: str, details: Optional[Dict] = None) -> None:
        """Record an event for potential reporting."""
        with self._lock:
            self._events.append(DreamEvent(
                phase=phase,
                message=message,
                timestamp=time.time(),
                details=details,
            ))
            self._current_phase = phase

    def increment_stat(self, stat: str, amount: int = 1) -> None:
        """Increment a statistics counter."""
        with self._lock:
            if stat in self._stats:
                self._stats[stat] += amount

    def set_phase(self, phase: DreamPhase) -> None:
        """Set the current activity phase."""
        with self._lock:
            self._current_phase = phase

    def start(self) -> None:
        """Start the dreaming reporter thread."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._dream_loop, daemon=True, name="DreamingReporter")
        self._thread.start()
        logger.debug("Dreaming reporter started")

    def stop(self) -> None:
        """Stop the dreaming reporter thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        logger.debug("Dreaming reporter stopped")

    def _dream_loop(self) -> None:
        """Main dreaming loop - outputs status every interval."""
        while self._running:
            try:
                # Sleep first (so first output comes after daemon is running)
                time.sleep(self.interval)

                if not self._running:
                    break

                # Generate and output status
                status = self._generate_status()
                if status:
                    self._output(status)

            except Exception as e:
                logger.debug(f"Dreaming error (non-fatal): {e}")

    def _generate_status(self) -> str:
        """Generate the status line to output."""
        with self._lock:
            now = time.time()
            timestamp = datetime.now().strftime("%H:%M:%S")

            # Get a dream phrase for current phase
            phrases = self.DREAM_PHRASES.get(self._current_phase, ["...processing..."])
            phrase = random.choice(phrases)

            # Build status components
            parts = []

            # Timestamp
            parts.append(self._color(f"[{timestamp}]", 'dim'))

            # Dream phase with phrase
            phase_color = {
                DreamPhase.AWAKENING: 'yellow',
                DreamPhase.WATCHING: 'cyan',
                DreamPhase.THINKING: 'magenta',
                DreamPhase.GUARDING: 'green',
                DreamPhase.LISTENING: 'blue',
                DreamPhase.VERIFYING: 'yellow',
                DreamPhase.REMEMBERING: 'magenta',
                DreamPhase.RESTING: 'dim',
            }.get(self._current_phase, 'dim')

            parts.append(self._color(phrase, phase_color))

            # Add recent completion if any
            recent_completions = [
                op for op in self._completed_operations
                if now - op['time'] < self.interval
            ]
            if recent_completions:
                latest = recent_completions[-1]
                status_icon = self._color("✓", 'green') if latest['success'] else self._color("✗", 'yellow')
                parts.append(f"{status_icon} {latest['operation']}")

            # Add active operations count if any
            active_count = len(self._active_operations)
            if active_count > 0:
                parts.append(self._color(f"({active_count} active)", 'dim'))

            # Get dynamic state from callbacks
            for name, callback in self._state_callbacks.items():
                try:
                    state_info = callback()
                    if state_info:
                        parts.append(self._color(f"[{state_info}]", 'dim'))
                except Exception:
                    pass  # Silent fail - don't interrupt dreaming

            return " ".join(parts)

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        with self._lock:
            return {
                **self._stats,
                'current_phase': self._current_phase.value,
                'active_operations': len(self._active_operations),
                'recent_events': len(self._events),
            }


# Singleton instance for easy access
_dreaming_reporter: Optional[DreamingReporter] = None


def get_dreaming_reporter() -> Optional[DreamingReporter]:
    """Get the global dreaming reporter instance."""
    return _dreaming_reporter


def set_dreaming_reporter(reporter: DreamingReporter) -> None:
    """Set the global dreaming reporter instance."""
    global _dreaming_reporter
    _dreaming_reporter = reporter


def create_dreaming_reporter(
    interval: float = 5.0,
    use_colors: bool = True,
    enabled: bool = True,
) -> Optional[DreamingReporter]:
    """
    Create and start a dreaming reporter.

    Args:
        interval: Seconds between updates (default 5)
        use_colors: Use ANSI colors
        enabled: Whether to actually create/start it

    Returns:
        DreamingReporter instance or None if disabled
    """
    if not enabled:
        return None

    reporter = DreamingReporter(interval=interval, use_colors=use_colors)
    set_dreaming_reporter(reporter)
    return reporter


# Convenience functions for recording events from anywhere
def dream_watching(message: str = "state change detected") -> None:
    """Record a watching event."""
    if _dreaming_reporter:
        _dreaming_reporter.record_event(DreamPhase.WATCHING, message)


def dream_thinking(message: str = "evaluating policy") -> None:
    """Record a thinking event."""
    if _dreaming_reporter:
        _dreaming_reporter.record_event(DreamPhase.THINKING, message)


def dream_guarding(message: str = "enforcing boundary") -> None:
    """Record a guarding event."""
    if _dreaming_reporter:
        _dreaming_reporter.record_event(DreamPhase.GUARDING, message)


def dream_verifying(message: str = "checking integrity") -> None:
    """Record a verifying event."""
    if _dreaming_reporter:
        _dreaming_reporter.record_event(DreamPhase.VERIFYING, message)


def dream_operation_start(operation: str) -> None:
    """Record start of an operation."""
    if _dreaming_reporter:
        _dreaming_reporter.start_operation(operation)


def dream_operation_complete(operation: str, success: bool = True) -> None:
    """Record completion of an operation."""
    if _dreaming_reporter:
        _dreaming_reporter.complete_operation(operation, success)


if __name__ == "__main__":
    # Demo mode
    print("Dreaming Reporter Demo")
    print("=" * 50)

    reporter = create_dreaming_reporter(interval=3.0)
    reporter.start()

    # Simulate daemon activities
    import random

    phases = [
        (DreamPhase.WATCHING, "monitoring network"),
        (DreamPhase.THINKING, "evaluating request"),
        (DreamPhase.GUARDING, "enforcing policy"),
        (DreamPhase.VERIFYING, "checking signatures"),
        (DreamPhase.LISTENING, "awaiting input"),
        (DreamPhase.RESTING, "all quiet"),
    ]

    try:
        for i in range(10):
            time.sleep(2)
            phase, msg = random.choice(phases)
            reporter.record_event(phase, msg)

            if random.random() > 0.5:
                op = random.choice(["health_check", "policy_eval", "state_sync", "log_write"])
                reporter.start_operation(op)
                time.sleep(0.1)
                reporter.complete_operation(op, success=random.random() > 0.1)

    except KeyboardInterrupt:
        pass

    reporter.stop()
    print("\nDemo complete. Stats:", reporter.get_stats())
