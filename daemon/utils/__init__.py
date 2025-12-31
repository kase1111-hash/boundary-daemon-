"""
Utility modules for Boundary Daemon.

Provides common utilities including:
- Error handling with verbose logging
- Cross-platform helpers
- Common patterns and decorators
"""

from .error_handling import (
    ErrorCategory,
    ErrorSeverity,
    ErrorContext,
    ErrorAggregator,
    ErrorRecoveryAction,
    get_error_aggregator,
    handle_error,
    safe_execute,
    with_error_handling,
    determine_severity,
    normalize_platform_error,
    suggest_recovery_action,
    log_security_error,
    log_auth_error,
    log_network_error,
    log_filesystem_error,
    log_platform_error,
)

__all__ = [
    # Error handling
    'ErrorCategory',
    'ErrorSeverity',
    'ErrorContext',
    'ErrorAggregator',
    'ErrorRecoveryAction',
    'get_error_aggregator',
    'handle_error',
    'safe_execute',
    'with_error_handling',
    'determine_severity',
    'normalize_platform_error',
    'suggest_recovery_action',
    'log_security_error',
    'log_auth_error',
    'log_network_error',
    'log_filesystem_error',
    'log_platform_error',
]
