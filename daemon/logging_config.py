"""
Enhanced Logging Configuration for Boundary Daemon.

Provides centralized logging configuration with verbose mode toggle,
per-feature logging, and structured log formatting.

Usage:
    from daemon.logging_config import setup_logging, get_logger, set_verbose

    # Setup at daemon startup
    setup_logging(verbose=True)

    # Get feature-specific logger
    logger = get_logger('security.antivirus')
    logger.info("Scan complete", extra={'files_scanned': 100})

    # Toggle verbose mode at runtime
    set_verbose(True)
"""

import os
import sys
import json
import logging
import threading
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Optional, Dict, Any, Set, Callable, List
from dataclasses import dataclass, field


# =============================================================================
# LOGGING LEVELS AND FEATURES
# =============================================================================

class LogLevel(Enum):
    """Extended logging levels for boundary daemon."""
    TRACE = 5       # Ultra-verbose tracing
    DEBUG = 10      # Debug information
    VERBOSE = 15    # Verbose operational info
    INFO = 20       # Standard information
    NOTICE = 25     # Notable events
    WARNING = 30    # Warning conditions
    ERROR = 40      # Error conditions
    CRITICAL = 50   # Critical conditions
    SECURITY = 55   # Security-critical events (always logged)


class FeatureArea(Enum):
    """Feature areas for targeted logging."""
    CORE = auto()           # Core daemon operations
    STATE_MONITOR = auto()  # State monitoring
    POLICY_ENGINE = auto()  # Policy decisions
    TRIPWIRES = auto()      # Tripwire system
    EVENT_LOGGER = auto()   # Event logging
    SECURITY = auto()       # Security modules
    ENFORCEMENT = auto()    # Enforcement modules
    SANDBOX = auto()        # Sandbox/containment
    AUTH = auto()           # Authentication/ceremony
    HEALTH = auto()         # Health monitoring
    NETWORK = auto()        # Network operations
    INTEGRATION = auto()    # External integrations
    API = auto()            # API operations
    CRYPTO = auto()         # Cryptographic operations
    PII = auto()            # PII detection/protection
    TPM = auto()            # TPM/hardware
    DISTRIBUTED = auto()    # Distributed/cluster
    WATCHDOG = auto()       # Watchdog systems


# Add custom log levels
logging.addLevelName(5, 'TRACE')
logging.addLevelName(15, 'VERBOSE')
logging.addLevelName(25, 'NOTICE')
logging.addLevelName(55, 'SECURITY')


# =============================================================================
# THREAD-SAFE CONFIGURATION STATE
# =============================================================================

@dataclass
class LoggingState:
    """Thread-safe logging configuration state."""
    verbose: bool = False
    trace: bool = False
    log_file: Optional[str] = None
    console_enabled: bool = True
    json_format: bool = False
    feature_levels: Dict[FeatureArea, int] = field(default_factory=dict)
    enabled_features: Set[FeatureArea] = field(default_factory=lambda: set(FeatureArea))
    callbacks: List[Callable[[str, int, str, Dict], None]] = field(default_factory=list)
    initialized: bool = False
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def __post_init__(self):
        # Enable all features by default
        if not self.feature_levels:
            for feature in FeatureArea:
                self.feature_levels[feature] = logging.INFO
        if not self.enabled_features:
            self.enabled_features = set(FeatureArea)


_state = LoggingState()


# =============================================================================
# CUSTOM FORMATTER
# =============================================================================

class BoundaryFormatter(logging.Formatter):
    """Custom formatter with color support and structured output."""

    COLORS = {
        'TRACE': '\033[90m',      # Gray
        'DEBUG': '\033[36m',      # Cyan
        'VERBOSE': '\033[94m',    # Light blue
        'INFO': '\033[32m',       # Green
        'NOTICE': '\033[33m',     # Yellow
        'WARNING': '\033[33;1m',  # Bold yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[31;1m', # Bold red
        'SECURITY': '\033[35;1m', # Bold magenta
        'RESET': '\033[0m',
    }

    def __init__(self, use_colors: bool = True, json_format: bool = False):
        self.use_colors = use_colors and sys.stdout.isatty()
        self.json_format = json_format
        super().__init__()

    def format(self, record: logging.LogRecord) -> str:
        if self.json_format:
            return self._format_json(record)
        return self._format_text(record)

    def _format_text(self, record: logging.LogRecord) -> str:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        level_name = record.levelname

        # Color support
        if self.use_colors:
            color = self.COLORS.get(level_name, '')
            reset = self.COLORS['RESET']
            level_str = f"{color}{level_name:8}{reset}"
        else:
            level_str = f"{level_name:8}"

        # Extract feature area from logger name
        feature = self._extract_feature(record.name)
        feature_str = f"[{feature}]" if feature else ""

        # Build message
        msg = record.getMessage()

        # Add extra fields if present
        extra_str = ""
        if hasattr(record, 'extra_data') and record.extra_data:
            extra_items = [f"{k}={v}" for k, v in record.extra_data.items()]
            extra_str = f" | {', '.join(extra_items)}"

        return f"{timestamp} {level_str} {feature_str:20} {msg}{extra_str}"

    def _format_json(self, record: logging.LogRecord) -> str:
        data = {
            'timestamp': datetime.now().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'feature': self._extract_feature(record.name),
        }

        # Add extra data
        if hasattr(record, 'extra_data') and record.extra_data:
            data['extra'] = record.extra_data

        # Add exception info if present
        if record.exc_info:
            data['exception'] = self.formatException(record.exc_info)

        return json.dumps(data)

    def _extract_feature(self, logger_name: str) -> str:
        """Extract feature area from logger name."""
        parts = logger_name.split('.')
        if len(parts) >= 2:
            # daemon.security.antivirus -> security
            return parts[1] if parts[0] == 'daemon' else parts[0]
        return parts[0] if parts else 'core'


# =============================================================================
# CUSTOM LOGGER CLASS
# =============================================================================

class BoundaryLogger(logging.Logger):
    """Extended logger with additional methods and feature tracking."""

    def __init__(self, name: str, level: int = logging.NOTSET):
        super().__init__(name, level)
        self._feature: Optional[FeatureArea] = self._detect_feature(name)

    def _detect_feature(self, name: str) -> Optional[FeatureArea]:
        """Detect feature area from logger name."""
        feature_map = {
            'state_monitor': FeatureArea.STATE_MONITOR,
            'policy_engine': FeatureArea.POLICY_ENGINE,
            'policy': FeatureArea.POLICY_ENGINE,
            'tripwires': FeatureArea.TRIPWIRES,
            'tripwire': FeatureArea.TRIPWIRES,
            'event_logger': FeatureArea.EVENT_LOGGER,
            'security': FeatureArea.SECURITY,
            'enforcement': FeatureArea.ENFORCEMENT,
            'sandbox': FeatureArea.SANDBOX,
            'auth': FeatureArea.AUTH,
            'ceremony': FeatureArea.AUTH,
            'health': FeatureArea.HEALTH,
            'network': FeatureArea.NETWORK,
            'integration': FeatureArea.INTEGRATION,
            'api': FeatureArea.API,
            'crypto': FeatureArea.CRYPTO,
            'pii': FeatureArea.PII,
            'tpm': FeatureArea.TPM,
            'hardware': FeatureArea.TPM,
            'distributed': FeatureArea.DISTRIBUTED,
            'cluster': FeatureArea.DISTRIBUTED,
            'watchdog': FeatureArea.WATCHDOG,
        }

        name_lower = name.lower()
        for key, feature in feature_map.items():
            if key in name_lower:
                return feature
        return FeatureArea.CORE

    def trace(self, msg: str, *args, **kwargs):
        """Log at TRACE level (ultra-verbose)."""
        if self.isEnabledFor(5):
            self._log(5, msg, args, **kwargs)

    def verbose(self, msg: str, *args, **kwargs):
        """Log at VERBOSE level."""
        if self.isEnabledFor(15):
            self._log(15, msg, args, **kwargs)

    def notice(self, msg: str, *args, **kwargs):
        """Log at NOTICE level."""
        if self.isEnabledFor(25):
            self._log(25, msg, args, **kwargs)

    def security(self, msg: str, *args, **kwargs):
        """Log security-critical events (always logged)."""
        self._log(55, msg, args, **kwargs)

    def log_with_data(self, level: int, msg: str, data: Dict[str, Any], **kwargs):
        """Log with structured extra data."""
        extra = kwargs.get('extra', {})
        extra['extra_data'] = data
        kwargs['extra'] = extra
        self._log(level, msg, (), **kwargs)

    def pipeline_start(self, pipeline_name: str, **data):
        """Log pipeline start."""
        self.info(f"Pipeline START: {pipeline_name}", extra={'extra_data': data})

    def pipeline_end(self, pipeline_name: str, success: bool, **data):
        """Log pipeline end."""
        status = "SUCCESS" if success else "FAILED"
        level = logging.INFO if success else logging.ERROR
        self._log(level, f"Pipeline END: {pipeline_name} - {status}",
                  (), extra={'extra_data': data})

    def pipeline_step(self, step_name: str, **data):
        """Log pipeline step."""
        self.verbose(f"  Step: {step_name}", extra={'extra_data': data})


# Set our custom logger class
logging.setLoggerClass(BoundaryLogger)


# =============================================================================
# SETUP AND CONFIGURATION
# =============================================================================

def setup_logging(
    verbose: bool = False,
    trace: bool = False,
    log_file: Optional[str] = None,
    console: bool = True,
    json_format: bool = False,
    features: Optional[Set[FeatureArea]] = None,
) -> None:
    """
    Initialize the logging system.

    Args:
        verbose: Enable verbose logging (VERBOSE level)
        trace: Enable trace logging (TRACE level, implies verbose)
        log_file: Optional file path for log output
        console: Enable console output
        json_format: Use JSON format for logs
        features: Set of features to enable (all by default)
    """
    with _state._lock:
        _state.verbose = verbose or trace
        _state.trace = trace
        _state.log_file = log_file
        _state.console_enabled = console
        _state.json_format = json_format

        if features is not None:
            _state.enabled_features = features
        else:
            _state.enabled_features = set(FeatureArea)

        # Determine base level
        if trace:
            base_level = 5  # TRACE
        elif verbose:
            base_level = 15  # VERBOSE
        else:
            base_level = logging.INFO

        # Configure root logger
        root = logging.getLogger()
        root.setLevel(base_level)

        # Remove existing handlers
        for handler in root.handlers[:]:
            root.removeHandler(handler)

        # Add console handler
        if console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(base_level)
            console_handler.setFormatter(BoundaryFormatter(
                use_colors=True,
                json_format=json_format
            ))
            root.addHandler(console_handler)

        # Add file handler
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(base_level)
            file_handler.setFormatter(BoundaryFormatter(
                use_colors=False,
                json_format=json_format
            ))
            root.addHandler(file_handler)

        # Configure feature-specific loggers
        for feature in FeatureArea:
            feature_level = base_level if feature in _state.enabled_features else logging.WARNING
            _state.feature_levels[feature] = feature_level

        _state.initialized = True


def get_logger(name: str) -> BoundaryLogger:
    """
    Get a feature-aware logger.

    Args:
        name: Logger name (e.g., 'daemon.security.antivirus')

    Returns:
        BoundaryLogger instance
    """
    logger = logging.getLogger(name)
    if not isinstance(logger, BoundaryLogger):
        # Upgrade to BoundaryLogger if needed
        logging.setLoggerClass(BoundaryLogger)
        logger = logging.getLogger(name)
    return logger


def set_verbose(enabled: bool) -> None:
    """Toggle verbose mode at runtime."""
    with _state._lock:
        _state.verbose = enabled
        level = 15 if enabled else logging.INFO  # VERBOSE or INFO

        root = logging.getLogger()
        root.setLevel(level)

        for handler in root.handlers:
            handler.setLevel(level)


def set_trace(enabled: bool) -> None:
    """Toggle trace mode at runtime."""
    with _state._lock:
        _state.trace = enabled
        _state.verbose = enabled  # Trace implies verbose

        level = 5 if enabled else (15 if _state.verbose else logging.INFO)

        root = logging.getLogger()
        root.setLevel(level)

        for handler in root.handlers:
            handler.setLevel(level)


def set_feature_level(feature: FeatureArea, level: int) -> None:
    """Set logging level for a specific feature."""
    with _state._lock:
        _state.feature_levels[feature] = level


def enable_feature(feature: FeatureArea) -> None:
    """Enable logging for a feature."""
    with _state._lock:
        _state.enabled_features.add(feature)


def disable_feature(feature: FeatureArea) -> None:
    """Disable verbose logging for a feature (warnings+ only)."""
    with _state._lock:
        _state.enabled_features.discard(feature)
        _state.feature_levels[feature] = logging.WARNING


def is_verbose() -> bool:
    """Check if verbose mode is enabled."""
    return _state.verbose


def is_trace() -> bool:
    """Check if trace mode is enabled."""
    return _state.trace


def get_logging_state() -> Dict[str, Any]:
    """Get current logging configuration state."""
    with _state._lock:
        return {
            'verbose': _state.verbose,
            'trace': _state.trace,
            'log_file': _state.log_file,
            'console_enabled': _state.console_enabled,
            'json_format': _state.json_format,
            'enabled_features': [f.name for f in _state.enabled_features],
            'initialized': _state.initialized,
        }


# =============================================================================
# LOG CALLBACK SYSTEM
# =============================================================================

def add_log_callback(callback: Callable[[str, int, str, Dict], None]) -> None:
    """
    Add a callback for log events.

    Callback signature: callback(logger_name, level, message, extra_data)
    """
    with _state._lock:
        _state.callbacks.append(callback)


def remove_log_callback(callback: Callable[[str, int, str, Dict], None]) -> None:
    """Remove a log callback."""
    with _state._lock:
        if callback in _state.callbacks:
            _state.callbacks.remove(callback)


# =============================================================================
# CONTEXT MANAGER FOR TEMPORARY VERBOSE
# =============================================================================

class VerboseContext:
    """Context manager for temporary verbose logging."""

    def __init__(self, feature: Optional[FeatureArea] = None):
        self.feature = feature
        self.previous_verbose = False
        self.previous_level = logging.INFO

    def __enter__(self):
        with _state._lock:
            self.previous_verbose = _state.verbose
            if self.feature:
                self.previous_level = _state.feature_levels.get(
                    self.feature, logging.INFO
                )
                _state.feature_levels[self.feature] = 5  # TRACE
            else:
                set_verbose(True)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        with _state._lock:
            if self.feature:
                _state.feature_levels[self.feature] = self.previous_level
            else:
                set_verbose(self.previous_verbose)
        return False


def verbose_for(feature: Optional[FeatureArea] = None) -> VerboseContext:
    """Get a context manager for temporary verbose logging."""
    return VerboseContext(feature)


# =============================================================================
# FEATURE-SPECIFIC LOGGER SHORTCUTS
# =============================================================================

def get_core_logger() -> BoundaryLogger:
    """Get logger for core daemon operations."""
    return get_logger('daemon.core')


def get_security_logger() -> BoundaryLogger:
    """Get logger for security operations."""
    return get_logger('daemon.security')


def get_enforcement_logger() -> BoundaryLogger:
    """Get logger for enforcement operations."""
    return get_logger('daemon.enforcement')


def get_policy_logger() -> BoundaryLogger:
    """Get logger for policy operations."""
    return get_logger('daemon.policy_engine')


def get_tripwire_logger() -> BoundaryLogger:
    """Get logger for tripwire operations."""
    return get_logger('daemon.tripwires')


def get_auth_logger() -> BoundaryLogger:
    """Get logger for authentication operations."""
    return get_logger('daemon.auth')


def get_network_logger() -> BoundaryLogger:
    """Get logger for network operations."""
    return get_logger('daemon.network')


def get_sandbox_logger() -> BoundaryLogger:
    """Get logger for sandbox operations."""
    return get_logger('daemon.sandbox')


def get_health_logger() -> BoundaryLogger:
    """Get logger for health monitoring."""
    return get_logger('daemon.health')


def get_integration_logger() -> BoundaryLogger:
    """Get logger for integrations."""
    return get_logger('daemon.integration')


# =============================================================================
# ENVIRONMENT VARIABLE CONFIGURATION
# =============================================================================

def configure_from_environment() -> None:
    """Configure logging from environment variables."""
    verbose = os.environ.get('BOUNDARY_VERBOSE', '').lower() in ('1', 'true', 'yes')
    trace = os.environ.get('BOUNDARY_TRACE', '').lower() in ('1', 'true', 'yes')
    log_file = os.environ.get('BOUNDARY_LOG_FILE')
    json_format = os.environ.get('BOUNDARY_LOG_JSON', '').lower() in ('1', 'true', 'yes')
    no_console = os.environ.get('BOUNDARY_LOG_NO_CONSOLE', '').lower() in ('1', 'true', 'yes')

    # Feature-specific toggles
    enabled_features = set(FeatureArea)
    disabled = os.environ.get('BOUNDARY_LOG_DISABLE_FEATURES', '')
    if disabled:
        for feature_name in disabled.split(','):
            try:
                feature = FeatureArea[feature_name.strip().upper()]
                enabled_features.discard(feature)
            except KeyError:
                pass

    setup_logging(
        verbose=verbose,
        trace=trace,
        log_file=log_file,
        console=not no_console,
        json_format=json_format,
        features=enabled_features,
    )


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Enums
    'LogLevel',
    'FeatureArea',
    # Setup functions
    'setup_logging',
    'configure_from_environment',
    'get_logger',
    # Toggle functions
    'set_verbose',
    'set_trace',
    'set_feature_level',
    'enable_feature',
    'disable_feature',
    # Query functions
    'is_verbose',
    'is_trace',
    'get_logging_state',
    # Callbacks
    'add_log_callback',
    'remove_log_callback',
    # Context managers
    'verbose_for',
    'VerboseContext',
    # Shortcuts
    'get_core_logger',
    'get_security_logger',
    'get_enforcement_logger',
    'get_policy_logger',
    'get_tripwire_logger',
    'get_auth_logger',
    'get_network_logger',
    'get_sandbox_logger',
    'get_health_logger',
    'get_integration_logger',
    # Classes
    'BoundaryLogger',
    'BoundaryFormatter',
]
