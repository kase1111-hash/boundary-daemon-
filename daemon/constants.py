"""
Centralized Constants Module for Boundary Daemon.

This module consolidates all magic values, thresholds, and configuration
constants used throughout the daemon to ensure consistency and ease of
auditing.

SECURITY: Addresses Critical Finding "Hardcoded Magic Values"
Centralizing constants:
- Prevents inconsistencies between modules
- Makes security-sensitive values easy to audit
- Enables environment-based configuration overrides
- Improves testability through centralized mocking

Usage:
    from daemon.constants import Timeouts, Permissions, Paths

    subprocess.run(cmd, timeout=Timeouts.SUBPROCESS_DEFAULT)
    os.chmod(path, Permissions.SECURE_FILE)
"""

import os
import sys
import logging
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, FrozenSet, Set, Tuple, Optional, TypeVar, Callable

logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = sys.platform == 'win32'


# =============================================================================
# ENVIRONMENT VARIABLE OVERRIDE UTILITIES
# =============================================================================

T = TypeVar('T')


def _env_override(
    env_var: str,
    default: T,
    converter: Callable[[str], T] = str,
    validator: Optional[Callable[[T], bool]] = None,
    min_value: Optional[T] = None,
    max_value: Optional[T] = None,
) -> T:
    """Get a configuration value with environment variable override.

    SECURITY: Allows runtime configuration of security-critical values while
    maintaining safe defaults. Validates values to prevent misconfiguration.

    Args:
        env_var: Environment variable name (will be prefixed with BOUNDARY_)
        default: Default value if env var not set
        converter: Function to convert string to target type
        validator: Optional validation function
        min_value: Optional minimum allowed value
        max_value: Optional maximum allowed value

    Returns:
        Configured value (from env var if valid, otherwise default)
    """
    full_env_var = f"BOUNDARY_{env_var}"
    env_value = os.environ.get(full_env_var)

    if env_value is None:
        return default

    try:
        converted = converter(env_value)

        # Apply bounds checking for numeric types
        if min_value is not None and converted < min_value:
            logger.warning(
                f"SECURITY: {full_env_var}={env_value} below minimum {min_value}, using default"
            )
            return default
        if max_value is not None and converted > max_value:
            logger.warning(
                f"SECURITY: {full_env_var}={env_value} above maximum {max_value}, using default"
            )
            return default

        # Apply custom validation
        if validator is not None and not validator(converted):
            logger.warning(
                f"SECURITY: {full_env_var}={env_value} failed validation, using default"
            )
            return default

        logger.info(f"Using {full_env_var}={converted} (override)")
        return converted

    except (ValueError, TypeError) as e:
        logger.warning(f"Invalid value for {full_env_var}: {e}, using default")
        return default


def _env_override_list(
    env_var: str,
    default: Tuple[str, ...],
    separator: str = ",",
    validator: Optional[Callable[[str], bool]] = None,
) -> Tuple[str, ...]:
    """Get a list configuration value with environment variable override.

    Args:
        env_var: Environment variable name (will be prefixed with BOUNDARY_)
        default: Default tuple of values
        separator: Separator for parsing list values
        validator: Optional validation function for each item

    Returns:
        Configured tuple (from env var if valid, otherwise default)
    """
    full_env_var = f"BOUNDARY_{env_var}"
    env_value = os.environ.get(full_env_var)

    if env_value is None:
        return default

    try:
        items = tuple(item.strip() for item in env_value.split(separator) if item.strip())

        if not items:
            logger.warning(f"Empty list for {full_env_var}, using default")
            return default

        # Validate each item if validator provided
        if validator is not None:
            invalid_items = [item for item in items if not validator(item)]
            if invalid_items:
                logger.warning(
                    f"SECURITY: Invalid items in {full_env_var}: {invalid_items}, using default"
                )
                return default

        logger.info(f"Using {full_env_var}={items} (override)")
        return items

    except Exception as e:
        logger.warning(f"Invalid value for {full_env_var}: {e}, using default")
        return default


def _is_valid_ip(ip: str) -> bool:
    """Validate an IP address string."""
    import re
    # Simple IPv4 validation
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    # Simple IPv6 check (contains colons)
    if ':' in ip:
        return True
    return False


# =============================================================================
# TIMEOUT CONSTANTS
# =============================================================================

@dataclass(frozen=True)
class Timeouts:
    """
    Centralized timeout values in seconds.

    SECURITY: Timeout values affect DoS resistance and responsiveness.
    Too short = false failures. Too long = DoS vulnerability.
    """
    # Subprocess execution timeouts
    SUBPROCESS_SHORT: float = 2.0       # Quick commands (arp, ip)
    SUBPROCESS_DEFAULT: float = 5.0     # Standard commands (iptables)
    SUBPROCESS_MEDIUM: float = 10.0     # Longer operations
    SUBPROCESS_LONG: float = 30.0       # Complex operations
    SUBPROCESS_EXTENDED: float = 60.0   # Very long operations

    # Network timeouts
    SOCKET_CONNECT: float = 5.0         # Socket connection timeout
    SOCKET_READ: float = 10.0           # Socket read timeout
    DNS_QUERY: float = 5.0              # DNS resolution timeout
    HTTP_REQUEST: float = 30.0          # HTTP request timeout

    # Thread/process join timeouts
    THREAD_JOIN_SHORT: float = 2.0      # Quick thread shutdown
    THREAD_JOIN_DEFAULT: float = 5.0    # Standard thread shutdown
    THREAD_JOIN_LONG: float = 10.0      # Graceful thread shutdown

    # Monitoring intervals
    HEALTH_CHECK_INTERVAL: float = 60.0     # Health check frequency
    STATE_POLL_INTERVAL: float = 1.0        # State monitoring frequency
    ENFORCEMENT_INTERVAL: float = 5.0       # Enforcement loop frequency
    INTEGRITY_CHECK_INTERVAL: float = 60.0  # File integrity check frequency

    # Challenge/ceremony timeouts
    CHALLENGE_MAX_AGE: float = 5.0      # Cryptographic challenge validity
    CEREMONY_COOLDOWN: float = 30.0     # Override ceremony cooldown

    # Advanced ceremony timeouts
    CEREMONY_COOLDOWN_EMERGENCY: float = 60.0   # Emergency access cooldown
    CEREMONY_COOLDOWN_DATA_EXPORT: float = 45.0 # Data export cooldown
    CEREMONY_COOLDOWN_LOCKDOWN: float = 90.0    # Lockdown release cooldown
    CEREMONY_COOLDOWN_KEY_ROTATION: float = 60.0 # Key rotation cooldown
    N_OF_M_EXPIRY_HOURS: float = 24.0           # N-of-M ceremony expiry
    DEAD_MAN_CHECK_INTERVAL: float = 60.0       # Dead-man check interval
    HARDWARE_TOKEN_TIMEOUT: float = 30.0        # Hardware token response timeout

    # Cleanup and persistence
    CLEANUP_TIMEOUT: float = 300.0      # 5 minutes for cleanup operations
    PROTECTION_TIMEOUT: float = 300.0   # 5 minutes for protection timeout

    # Sleep intervals
    SLEEP_SHORT: float = 0.1            # Brief pause
    SLEEP_DEFAULT: float = 1.0          # Standard pause
    SLEEP_LONG: float = 10.0            # Extended pause


# =============================================================================
# BUFFER SIZE CONSTANTS
# =============================================================================

@dataclass(frozen=True)
class BufferSizes:
    """
    Centralized buffer and chunk sizes in bytes.

    SECURITY: Buffer sizes affect memory usage and DoS resistance.
    """
    # Socket buffers
    SOCKET_RECV: int = 4096             # Socket receive buffer
    SOCKET_SEND: int = 4096             # Socket send buffer

    # File I/O
    FILE_CHUNK: int = 65536             # File read chunk (64KB)
    FILE_CHUNK_SMALL: int = 4096        # Small file operations (4KB)
    FILE_CHUNK_LARGE: int = 1048576     # Large file operations (1MB)

    # Message limits
    MESSAGE_MAX_LENGTH: int = 1024      # Maximum message length
    LOG_LINE_MAX: int = 8192            # Maximum log line length

    # Memory buffers
    EVENT_BUFFER_SMALL: int = 1000      # Small event buffer
    EVENT_BUFFER_DEFAULT: int = 10000   # Default event buffer
    EVENT_BUFFER_LARGE: int = 100000    # Large event buffer

    # File size limits
    MAX_FILE_SIZE_SMALL: int = 1048576          # 1 MB
    MAX_FILE_SIZE_MEDIUM: int = 10485760        # 10 MB
    MAX_FILE_SIZE_LARGE: int = 104857600        # 100 MB
    MAX_FILE_SIZE_CODE: int = 1048576           # 1 MB for code analysis


# =============================================================================
# FILE PERMISSION CONSTANTS
# =============================================================================

class Permissions(IntEnum):
    """
    Centralized file permission modes.

    SECURITY: File permissions are critical for access control.
    Always use the most restrictive permissions possible.
    """
    # Owner-only permissions (most secure)
    OWNER_READ_ONLY = 0o400             # r--------
    OWNER_READ_WRITE = 0o600            # rw-------
    OWNER_READ_WRITE_EXEC = 0o700       # rwx------

    # Secure file defaults
    SECURE_FILE = 0o600                 # rw------- (secrets, keys, tokens)
    SECURE_DIR = 0o700                  # rwx------ (secure directories)

    # Standard permissions
    STANDARD_FILE = 0o644               # rw-r--r--
    STANDARD_DIR = 0o755                # rwxr-xr-x

    # Special permissions
    NO_ACCESS = 0o000                   # ---------- (quarantine)
    READ_ONLY_ALL = 0o444               # r--r--r-- (immutable files)

    # SUID/SGID detection
    SUID_BIT = 0o4000                   # Set-user-ID
    SGID_BIT = 0o2000                   # Set-group-ID
    STICKY_BIT = 0o1000                 # Sticky bit


# =============================================================================
# PATH CONSTANTS
# =============================================================================

@dataclass(frozen=True)
class Paths:
    """
    Centralized filesystem paths.

    SECURITY: Consistent paths prevent path confusion attacks.
    These can be overridden via environment variables.
    """
    # Base directories
    VAR_LIB_BASE: str = "/var/lib/boundary-daemon"
    VAR_RUN_BASE: str = "/var/run/boundary-daemon"
    VAR_LOG_BASE: str = "/var/log/boundary-daemon"
    ETC_BASE: str = "/etc/boundary-daemon"

    # State directories
    STATE_DIR: str = f"{VAR_LIB_BASE}/state"
    SECRETS_DIR: str = f"{VAR_LIB_BASE}/secrets"
    TPM_DIR: str = f"{VAR_LIB_BASE}/tpm"
    SECCOMP_DIR: str = f"{VAR_LIB_BASE}/seccomp"

    # Runtime paths
    SOCKET_PATH: str = f"{VAR_RUN_BASE}/boundary.sock"
    PID_FILE: str = f"{VAR_RUN_BASE}/boundary.pid"
    WATCHDOG_SOCKET: str = f"{VAR_RUN_BASE}/watchdog.sock"

    # Configuration files
    CONFIG_FILE: str = f"{ETC_BASE}/boundary.conf"
    POLICY_DIR: str = f"{ETC_BASE}/policies.d"
    MANIFEST_FILE: str = f"{ETC_BASE}/manifest.json"
    SIGNING_KEY: str = f"{ETC_BASE}/signing.key"

    # Log files
    EVENT_LOG: str = f"{VAR_LOG_BASE}/boundary_chain.log"
    SIGNATURE_LOG: str = f"{VAR_LOG_BASE}/boundary_chain.log.sig"

    # System paths (Linux-specific - use helper methods for cross-platform)
    MACHINE_ID: str = "/etc/machine-id"
    BOOT_ID: str = "/proc/sys/kernel/random/boot_id"
    PROC_MODULES: str = "/proc/modules"
    PROC_NET_ARP: str = "/proc/net/arp"
    PROC_NET_ROUTE: str = "/proc/net/route"

    # Device paths (Linux-specific)
    TPM_DEVICE: str = "/dev/tpm0"
    WATCHDOG_DEVICE: str = "/dev/watchdog"
    USB_DEVICES: str = "/sys/bus/usb/devices"

    @classmethod
    def get_path(cls, name: str, default: str) -> str:
        """Get path with environment variable override."""
        env_var = f"BOUNDARY_{name.upper()}"
        return os.environ.get(env_var, default)

    @classmethod
    def get_machine_id(cls) -> str:
        """Get machine ID path (cross-platform)."""
        if IS_WINDOWS:
            # Windows uses registry, return empty - use get_machine_id_value() instead
            return ""
        return cls.MACHINE_ID

    @classmethod
    def get_machine_id_value(cls) -> str:
        """Get machine ID value (cross-platform)."""
        if IS_WINDOWS:
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Cryptography"
                )
                machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                winreg.CloseKey(key)
                return machine_guid
            except Exception:
                return os.environ.get('COMPUTERNAME', 'unknown')
        else:
            try:
                with open(cls.MACHINE_ID, 'r') as f:
                    return f.read().strip()
            except Exception:
                return 'unknown'

    @classmethod
    def is_proc_available(cls) -> bool:
        """Check if /proc filesystem is available (Linux only)."""
        if IS_WINDOWS:
            return False
        return os.path.exists('/proc')

    @classmethod
    def get_base_path(cls) -> str:
        """Get the base path for the application.

        Handles PyInstaller frozen executables by checking for sys._MEIPASS.
        For frozen executables, returns the PyInstaller extraction directory.
        For normal execution, returns the daemon package's parent directory.

        Returns:
            Base path for locating application resources.
        """
        if getattr(sys, 'frozen', False):
            # Running as PyInstaller frozen executable
            return sys._MEIPASS
        else:
            # Running as normal Python script
            # Return the parent of the daemon package directory
            return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    @classmethod
    def get_config_dir(cls) -> str:
        """Get the configuration directory path.

        For frozen executables, checks in order:
        1. PyInstaller _MEIPASS/config (bundled config)
        2. Executable directory/config (config next to exe)
        3. System paths (/etc/boundary-daemon or local config)

        For normal execution:
        1. Local development config (daemon/../config)
        2. System paths

        Returns:
            Path to the configuration directory.
        """
        if getattr(sys, 'frozen', False):
            # Running as PyInstaller frozen executable
            # Check bundled config first
            meipass_config = os.path.join(sys._MEIPASS, 'config')
            if os.path.isdir(meipass_config):
                return meipass_config

            # Check next to the executable
            exe_dir = os.path.dirname(sys.executable)
            exe_config = os.path.join(exe_dir, 'config')
            if os.path.isdir(exe_config):
                return exe_config

            # Fall through to system/local paths below

        # Local development config
        local_config = os.path.join(cls.get_base_path(), 'config')
        if os.path.isdir(local_config):
            return local_config

        # System path (Linux)
        if not IS_WINDOWS and os.path.isdir(cls.ETC_BASE):
            return cls.ETC_BASE

        # Default to local config path (may not exist yet)
        return local_config

    @classmethod
    def get_manifest_path(cls) -> str:
        """Get the manifest.json file path.

        Returns:
            Full path to manifest.json in the appropriate config directory.
        """
        return os.path.join(cls.get_config_dir(), 'manifest.json')

    @classmethod
    def get_signing_key_path(cls) -> str:
        """Get the signing.key file path.

        Returns:
            Full path to signing.key in the appropriate config directory.
        """
        return os.path.join(cls.get_config_dir(), 'signing.key')


# =============================================================================
# CRYPTOGRAPHIC CONSTANTS
# =============================================================================

@dataclass(frozen=True)
class Crypto:
    """
    Cryptographic parameters and algorithm identifiers.

    SECURITY: These values follow OWASP and NIST recommendations.
    Do not reduce iterations or key sizes without security review.
    """
    # Key Derivation (OWASP recommended minimums)
    PBKDF2_ITERATIONS: int = 480000     # OWASP recommended for SHA-256
    PBKDF2_ITERATIONS_MIN: int = 310000 # Absolute minimum (2023 OWASP)
    ARGON2_TIME_COST: int = 3           # Argon2 time parameter
    ARGON2_MEMORY_COST: int = 65536     # Argon2 memory (64MB)
    ARGON2_PARALLELISM: int = 4         # Argon2 parallelism

    # Key sizes
    KEY_SIZE_128: int = 16              # 128-bit key
    KEY_SIZE_256: int = 32              # 256-bit key
    KEY_SIZE_512: int = 64              # 512-bit key

    # Salt sizes
    SALT_SIZE: int = 32                 # 256-bit salt

    # Hash algorithms (prefer in order)
    HASH_ALGORITHM_DEFAULT: str = "sha256"
    HASH_ALGORITHM_STRONG: str = "sha512"
    HASH_ALGORITHM_FAST: str = "blake2b"

    # TPM PCR indices (16-23 are user-defined)
    # Override with: BOUNDARY_TPM_PCR_INDEX=17
    TPM_PCR_USER_START: int = 16
    TPM_PCR_USER_END: int = 23
    TPM_PCR_DEFAULT: int = _env_override(
        "TPM_PCR_INDEX", 16, int, min_value=16, max_value=23
    )

    # Token/nonce sizes
    TOKEN_SIZE: int = 32                # 256-bit tokens
    NONCE_SIZE: int = 16                # 128-bit nonces


# =============================================================================
# TIME THRESHOLD CONSTANTS
# =============================================================================

@dataclass(frozen=True)
class TimeThresholds:
    """
    Time-based thresholds in seconds.

    SECURITY: These thresholds detect anomalous time behavior.
    """
    # Clock jump detection
    CLOCK_JUMP_LOW: int = 60            # 1 minute - suspicious
    CLOCK_JUMP_MEDIUM: int = 300        # 5 minutes - likely attack
    CLOCK_JUMP_HIGH: int = 3600         # 1 hour - definite attack
    CLOCK_JUMP_CRITICAL: int = 86400    # 1 day - major manipulation

    # Clock drift limits (PPM = parts per million)
    CLOCK_DRIFT_MAX_PPM: int = 500      # Maximum acceptable drift
    CLOCK_DRIFT_WARNING_PPM: int = 250  # Warning threshold

    # Cache TTLs
    CACHE_TTL_SHORT: int = 60           # 1 minute
    CACHE_TTL_DEFAULT: int = 300        # 5 minutes
    CACHE_TTL_LONG: int = 3600          # 1 hour
    CACHE_TTL_DAY: int = 86400          # 1 day

    # Alert cooldowns
    ALERT_COOLDOWN_SHORT: int = 60      # 1 minute
    ALERT_COOLDOWN_DEFAULT: int = 300   # 5 minutes
    ALERT_COOLDOWN_LONG: int = 3600     # 1 hour


# =============================================================================
# RATE LIMITING CONSTANTS
# =============================================================================

@dataclass(frozen=True)
class RateLimits:
    """
    Rate limiting parameters.

    SECURITY: Rate limits prevent DoS and brute-force attacks.
    """
    # Default window sizes (seconds)
    WINDOW_SHORT: int = 10              # 10 seconds
    WINDOW_DEFAULT: int = 60            # 1 minute
    WINDOW_LONG: int = 300              # 5 minutes
    WINDOW_HOUR: int = 3600             # 1 hour

    # Default request limits
    REQUESTS_LOW: int = 10              # Low-frequency operations
    REQUESTS_MEDIUM: int = 100          # Standard operations
    REQUESTS_HIGH: int = 500            # High-frequency operations
    REQUESTS_UNLIMITED: int = 1000      # Near-unlimited

    # Block durations (seconds)
    BLOCK_SHORT: int = 60               # 1 minute
    BLOCK_DEFAULT: int = 300            # 5 minutes
    BLOCK_LONG: int = 3600              # 1 hour

    # Per-command rate limits: (max_requests, window_seconds)
    COMMAND_LIMITS: Dict[str, Tuple[int, int]] = None

    @classmethod
    def get_command_limits(cls) -> Dict[str, Tuple[int, int]]:
        """Get command-specific rate limits."""
        return {
            'status': (200, 60),
            'get_events': (100, 60),
            'check_recall': (500, 60),
            'check_tool': (300, 60),
            'check_message': (200, 60),
            'set_mode': (10, 60),
            'create_token': (5, 60),
            'revoke_token': (10, 60),
            'admin': (20, 60),
        }


# =============================================================================
# RETRY CONSTANTS
# =============================================================================

@dataclass(frozen=True)
class Retries:
    """
    Retry parameters for resilient operations.

    SECURITY: Retry limits prevent infinite loops and resource exhaustion.
    """
    # Retry counts
    COUNT_LOW: int = 2                  # Quick give-up
    COUNT_DEFAULT: int = 3              # Standard retry
    COUNT_HIGH: int = 5                 # Persistent retry
    COUNT_NETWORK: int = 4              # Network operations

    # Retry delays (seconds) - for exponential backoff
    DELAY_BASE: float = 1.0             # Base delay
    DELAY_SHORT: float = 0.5            # Short delay
    DELAY_LONG: float = 2.0             # Long delay

    # Exponential backoff multiplier
    BACKOFF_MULTIPLIER: float = 2.0     # Double each retry

    # Maximum delays
    MAX_DELAY: float = 60.0             # Maximum backoff delay
    MAX_TOTAL_TIME: float = 300.0       # Maximum total retry time


# =============================================================================
# NETWORK CONSTANTS
# =============================================================================

@dataclass(frozen=True)
class NetworkConstants:
    """
    Network-related constants and port lists.

    SECURITY: Port lists help identify suspicious network activity.
    """
    # Suspicious/backdoor ports
    SUSPICIOUS_PORTS: FrozenSet[int] = frozenset({
        1337, 31337,            # "Elite" ports
        4444, 5555, 6666, 7777, # Common backdoor ports
        6667, 6668, 6669,       # IRC (often C2)
        9001, 9050, 9150,       # TOR
        3128, 8123,             # Proxies
    })

    # Standard service ports
    STANDARD_PORTS: FrozenSet[int] = frozenset({
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135,
        137, 138, 139, 143, 161, 162, 389, 443, 445, 465, 514, 587,
        636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443,
    })

    # High-risk remote admin ports
    HIGH_RISK_PORTS: FrozenSet[int] = frozenset({
        22,     # SSH
        23,     # Telnet
        3389,   # RDP
        5900,   # VNC
        5985,   # WinRM HTTP
        5986,   # WinRM HTTPS
    })

    # DNS configuration (with environment overrides)
    DNS_PORT: int = 53
    DNS_TIMEOUT: float = _env_override(
        "DNS_TIMEOUT", 5.0, float, min_value=1.0, max_value=30.0
    )

    # Default trusted DNS servers
    # Override with: BOUNDARY_TRUSTED_DNS_SERVERS="1.1.1.1,8.8.8.8,custom.dns"
    TRUSTED_DNS_SERVERS: Tuple[str, ...] = _env_override_list(
        "TRUSTED_DNS_SERVERS",
        ("1.1.1.1", "8.8.8.8", "9.9.9.9"),  # Cloudflare, Google, Quad9
        separator=",",
        validator=_is_valid_ip,
    )


# =============================================================================
# DETECTION THRESHOLDS
# =============================================================================

@dataclass(frozen=True)
class DetectionThresholds:
    """
    Thresholds for anomaly and threat detection.

    SECURITY: These thresholds balance detection sensitivity vs. false positives.
    """
    # Traffic thresholds (bytes)
    OUTBOUND_BYTES_5MIN: int = 100 * 1024 * 1024    # 100 MB in 5 min
    LARGE_TRANSFER: int = 50 * 1024 * 1024          # 50 MB single transfer
    UPLOAD_RATIO_WARNING: float = 0.8               # 80% upload ratio

    # Scan detection
    PORT_SCAN_THRESHOLD: int = 10       # Ports per minute
    HOST_SCAN_THRESHOLD: int = 5        # Hosts per minute

    # Beaconing detection
    BEACONING_MIN_CONNECTIONS: int = 5  # Minimum for pattern
    BEACONING_INTERVAL_TOLERANCE: float = 0.1  # 10% variance

    # Entropy thresholds
    HIGH_ENTROPY_THRESHOLD: float = 4.0     # Suspicious entropy
    VERY_HIGH_ENTROPY: float = 6.0          # Likely encoded/encrypted

    # PII confidence scores
    PII_CONFIDENCE_HIGH: float = 0.9        # High confidence match
    PII_CONFIDENCE_MEDIUM: float = 0.8      # Medium confidence
    PII_CONFIDENCE_LOW: float = 0.6         # Low confidence


# =============================================================================
# LIMIT CONSTANTS
# =============================================================================

@dataclass(frozen=True)
class Limits:
    """
    Various limit constants.

    SECURITY: Limits prevent resource exhaustion and abuse.
    Many values support environment variable overrides for operational flexibility.
    """
    # Failure limits (with environment overrides for security tuning)
    # Override with: BOUNDARY_MAX_AUTH_ATTEMPTS=10
    MAX_FAILURES_BEFORE_LOCKOUT: int = _env_override(
        "MAX_FAILURES_BEFORE_LOCKOUT", 3, int, min_value=1, max_value=10
    )
    MAX_AUTH_ATTEMPTS: int = _env_override(
        "MAX_AUTH_ATTEMPTS", 5, int, min_value=1, max_value=20
    )
    MAX_DISABLE_ATTEMPTS: int = 3           # Tripwire disable attempts
    MAX_CEREMONY_ATTEMPTS: int = 3          # Ceremony attempts before lockout
    MAX_N_OF_M_APPROVERS: int = 10          # Maximum approvers for N-of-M
    MAX_DEAD_MAN_TRIGGERS: int = 20         # Maximum dead-man triggers
    MAX_HARDWARE_TOKENS: int = 10           # Maximum registered hardware tokens

    # Resource limits (with environment overrides)
    # Override with: BOUNDARY_MAX_LOG_FILES=20
    MAX_OPEN_FILES: int = 100               # Maximum files to scan
    MAX_PROCESSES: int = 1000               # Maximum processes to list
    MAX_LOG_FILES: int = _env_override(
        "MAX_LOG_FILES", 10, int, min_value=1, max_value=100
    )
    MAX_BACKUPS: int = _env_override(
        "MAX_BACKUPS", 3, int, min_value=1, max_value=20
    )

    # Size limits
    MAX_PATH_LENGTH: int = 4096             # Maximum path length
    MAX_HOSTNAME_LENGTH: int = 255          # Maximum hostname length
    MAX_USERNAME_LENGTH: int = 256          # Maximum username length

    # ARP/Network limits (with environment overrides)
    # Override with: BOUNDARY_ARP_BLOCK_DURATION_MINUTES=120
    ARP_BLOCK_DURATION_MINUTES: int = _env_override(
        "ARP_BLOCK_DURATION_MINUTES", 60, int, min_value=1, max_value=1440
    )
    MAX_BLOCKED_IPS: int = _env_override(
        "MAX_BLOCKED_IPS", 1000, int, min_value=100, max_value=100000
    )

    # Logging limits
    MIN_HEALTHY_BACKENDS: int = 1           # Minimum loggers required


# =============================================================================
# ESSENTIAL PROCESS LIST
# =============================================================================

class EssentialProcesses:
    """
    List of essential system processes that should never be terminated.

    SECURITY: Killing essential processes can destabilize or crash the system.
    """
    PROTECTED_NAMES: FrozenSet[str] = frozenset({
        'init', 'systemd', 'kthreadd', 'rcu_sched', 'rcu_bh',
        'migration', 'watchdog', 'cpuhp', 'kdevtmpfs', 'netns',
        'kauditd', 'kswapd', 'ecryptfs', 'crypto', 'kworker',
        'ksoftirqd', 'sshd', 'boundary-daemon', 'journald',
        'udevd', 'dbus-daemon', 'login', 'getty',
    })

    PROTECTED_PIDS: FrozenSet[int] = frozenset({
        1,      # init/systemd
        2,      # kthreadd
    })

    @classmethod
    def is_protected(cls, name: str, pid: int) -> bool:
        """Check if a process is protected."""
        if pid in cls.PROTECTED_PIDS:
            return True
        name_lower = name.lower()
        return any(pn in name_lower for pn in cls.PROTECTED_NAMES)


# =============================================================================
# VERSION AND METADATA
# =============================================================================

@dataclass(frozen=True)
class Version:
    """Version and metadata constants."""
    CONSTANTS_VERSION: str = "1.0.0"
    MANIFEST_VERSION: str = "1.0"
    PROTOCOL_VERSION: str = "1.0"


# =============================================================================
# ENVIRONMENT VARIABLE OVERRIDES
# =============================================================================

def _get_env_int(name: str, default: int) -> int:
    """Get integer from environment variable."""
    val = os.environ.get(f"BOUNDARY_{name}")
    if val is not None:
        try:
            return int(val)
        except ValueError:
            pass
    return default


def _get_env_float(name: str, default: float) -> float:
    """Get float from environment variable."""
    val = os.environ.get(f"BOUNDARY_{name}")
    if val is not None:
        try:
            return float(val)
        except ValueError:
            pass
    return default


# Allow environment-based customization of security-sensitive values
class RuntimeConfig:
    """
    Runtime configuration that can be overridden via environment variables.

    SECURITY: Environment overrides enable deployment-specific tuning
    without code changes.
    """
    @staticmethod
    def get_kdf_iterations() -> int:
        """Get KDF iterations (can be increased for high-security deployments)."""
        return _get_env_int("KDF_ITERATIONS", Crypto.PBKDF2_ITERATIONS)

    @staticmethod
    def get_subprocess_timeout() -> float:
        """Get default subprocess timeout."""
        return _get_env_float("SUBPROCESS_TIMEOUT", Timeouts.SUBPROCESS_DEFAULT)

    @staticmethod
    def get_health_check_interval() -> float:
        """Get health check interval."""
        return _get_env_float("HEALTH_CHECK_INTERVAL", Timeouts.HEALTH_CHECK_INTERVAL)


# =============================================================================
# CONVENIENCE EXPORTS
# =============================================================================

# Commonly used constants can be imported directly
DEFAULT_TIMEOUT = Timeouts.SUBPROCESS_DEFAULT
SECURE_FILE_MODE = Permissions.SECURE_FILE
SECURE_DIR_MODE = Permissions.SECURE_DIR
DEFAULT_BUFFER_SIZE = BufferSizes.FILE_CHUNK
KDF_ITERATIONS = Crypto.PBKDF2_ITERATIONS


__all__ = [
    # Dataclass constants
    'Timeouts',
    'BufferSizes',
    'Permissions',
    'Paths',
    'Crypto',
    'TimeThresholds',
    'RateLimits',
    'Retries',
    'NetworkConstants',
    'DetectionThresholds',
    'Limits',
    'EssentialProcesses',
    'Version',
    'RuntimeConfig',
    # Convenience exports
    'DEFAULT_TIMEOUT',
    'SECURE_FILE_MODE',
    'SECURE_DIR_MODE',
    'DEFAULT_BUFFER_SIZE',
    'KDF_ITERATIONS',
]
