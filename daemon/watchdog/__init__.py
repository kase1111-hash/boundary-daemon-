"""
Watchdog Module for Boundary Daemon

Provides:
1. Log Watchdog (Plan 8): Real-time log monitoring with LLM-powered analysis
2. Hardened Watchdog: Resilient daemon monitoring with cryptographic verification

SECURITY: The hardened watchdog addresses Critical Finding #6:
"External Watchdog Can Be Killed" by implementing:
- Mutual monitoring (daemon <-> watchdog)
- Cryptographic heartbeats with challenge-response
- Process hardening (prctl protections)
- Systemd watchdog integration
- Hardware watchdog support
- Multi-watchdog redundancy
"""

from .log_watchdog import (
    LogWatchdog,
    WatchdogAlert,
    WatchdogConfig,
    AlertSeverity,
    AlertStatus
)

from .hardened_watchdog import (
    HardenedWatchdog,
    DaemonWatchdogEndpoint,
    WatchdogProtocol,
    WatchdogState,
    ProcessHardening,
    SystemdWatchdog,
    HardwareWatchdog,
    generate_shared_secret,
)

__all__ = [
    # Log Watchdog
    'LogWatchdog',
    'WatchdogAlert',
    'WatchdogConfig',
    'AlertSeverity',
    'AlertStatus',
    # Hardened Watchdog
    'HardenedWatchdog',
    'DaemonWatchdogEndpoint',
    'WatchdogProtocol',
    'WatchdogState',
    'ProcessHardening',
    'SystemdWatchdog',
    'HardwareWatchdog',
    'generate_shared_secret',
]
