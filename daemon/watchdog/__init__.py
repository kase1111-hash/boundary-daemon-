"""
Watchdog Module for Boundary Daemon
Provides real-time log monitoring with LLM-powered analysis.

Plan 8: Log Watchdog Agent
"""

from .log_watchdog import (
    LogWatchdog,
    WatchdogAlert,
    WatchdogConfig,
    AlertSeverity,
    AlertStatus
)

__all__ = [
    'LogWatchdog',
    'WatchdogAlert',
    'WatchdogConfig',
    'AlertSeverity',
    'AlertStatus',
]
