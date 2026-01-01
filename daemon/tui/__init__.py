"""
TUI (Terminal User Interface) for Boundary Daemon

Phase 2 Operational Excellence: Provides real-time visibility
into daemon status without log parsing.
"""

from .dashboard import Dashboard, run_dashboard

__all__ = ['Dashboard', 'run_dashboard']
