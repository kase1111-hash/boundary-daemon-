"""
TUI (Terminal User Interface) for Boundary Daemon

Phase 2 Operational Excellence: Provides real-time visibility
into daemon status without log parsing.
"""

# Lazy imports to avoid RuntimeWarning when running as python -m daemon.tui.dashboard
# The warning occurs because importing dashboard here before it executes as __main__
# creates a module ordering issue.


def __getattr__(name):
    """Lazy import handler for module attributes."""
    if name == 'Dashboard':
        from .dashboard import Dashboard
        return Dashboard
    elif name == 'run_dashboard':
        from .dashboard import run_dashboard
        return run_dashboard
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ['Dashboard', 'run_dashboard']
