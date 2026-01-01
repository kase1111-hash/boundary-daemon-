"""
CLI Module for Boundary Daemon

Provides command-line tools for managing the daemon:
- sandboxctl: Sandbox management CLI

Usage:
    python -m daemon.cli.sandboxctl run -- /bin/bash
    python -m daemon.cli.sandboxctl list
"""

from .sandboxctl import SandboxCLI, main as sandboxctl_main

__all__ = [
    'SandboxCLI',
    'sandboxctl_main',
]
