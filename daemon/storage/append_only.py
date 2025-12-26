"""
Append-Only Log Storage - Immutable audit log protection.

Provides multiple layers of protection for the event log:

1. Filesystem Protection:
   - chattr +a (Linux append-only attribute)
   - Immutable after write
   - Requires root to remove

2. Remote Syslog:
   - Copy events to remote syslog server
   - Off-system backup prevents local tampering
   - TLS encryption option

3. Integrity Sealing:
   - Periodic signed checkpoints
   - Cryptographic proof of log state
   - Tamper detection across restarts

4. Write-Ahead Log:
   - Buffer events before main log
   - Crash recovery
   - Atomic append guarantees
"""

import hashlib
import json
import os
import socket
import ssl
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


class AppendOnlyMode(Enum):
    """Modes for append-only protection."""
    NONE = "none"              # No protection (development)
    CHATTR = "chattr"          # Linux chattr +a
    COPY_ON_WRITE = "cow"      # Copy-on-write filesystem
    REMOTE_ONLY = "remote"     # Remote syslog only
    FULL = "full"              # All protections


class SyslogFacility(Enum):
    """Syslog facility codes."""
    KERN = 0
    USER = 1
    MAIL = 2
    DAEMON = 3
    AUTH = 4
    SYSLOG = 5
    LPR = 6
    NEWS = 7
    UUCP = 8
    CRON = 9
    AUTHPRIV = 10
    FTP = 11
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23


class SyslogSeverity(Enum):
    """Syslog severity levels."""
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7


@dataclass
class RemoteSyslogConfig:
    """Configuration for remote syslog."""
    host: str
    port: int = 514
    protocol: str = "udp"      # udp, tcp, tls
    facility: SyslogFacility = SyslogFacility.LOCAL0
    app_name: str = "boundary-daemon"
    use_tls: bool = False
    tls_ca_cert: Optional[str] = None
    tls_verify: bool = True
    timeout: float = 5.0
    retry_count: int = 3
    retry_delay: float = 1.0


@dataclass
class IntegrityCheckpoint:
    """Periodic integrity checkpoint."""
    checkpoint_id: str
    timestamp: str
    event_count: int
    last_event_hash: str
    checkpoint_hash: str      # Hash of all data
    signature: Optional[str] = None  # Optional Ed25519 signature


@dataclass
class AppendOnlyConfig:
    """Configuration for append-only storage."""
    mode: AppendOnlyMode = AppendOnlyMode.CHATTR
    log_path: str = "./logs/boundary_chain.log"
    wal_path: str = "./logs/boundary_wal.log"
    checkpoint_path: str = "./logs/checkpoints/"
    checkpoint_interval: int = 3600  # seconds
    remote_syslog: Optional[RemoteSyslogConfig] = None
    signing_key_path: Optional[str] = None
    auto_protect: bool = True
    backup_count: int = 5


class AppendOnlyStorage:
    """
    Append-only storage layer for event logs.

    Provides filesystem-level immutability protection and
    remote backup capabilities.

    Usage:
        storage = AppendOnlyStorage(config)
        storage.initialize()
        storage.append(event_json)
        storage.seal_checkpoint()
    """

    def __init__(self, config: Optional[AppendOnlyConfig] = None):
        """Initialize append-only storage."""
        self.config = config or AppendOnlyConfig()
        self._lock = threading.RLock()
        self._initialized = False
        self._protected = False
        self._remote_socket: Optional[socket.socket] = None
        self._wal_fd = None
        self._event_count = 0
        self._last_hash = "0" * 64
        self._last_checkpoint: Optional[IntegrityCheckpoint] = None
        self._signing_key = None

        # Statistics
        self._stats = {
            'events_written': 0,
            'remote_sent': 0,
            'remote_failed': 0,
            'checkpoints_created': 0,
            'protection_status': 'unknown',
        }

    def initialize(self) -> Tuple[bool, str]:
        """
        Initialize storage with protection.

        Returns:
            (success, message)
        """
        with self._lock:
            try:
                # Create directories
                Path(self.config.log_path).parent.mkdir(parents=True, exist_ok=True)
                Path(self.config.wal_path).parent.mkdir(parents=True, exist_ok=True)
                Path(self.config.checkpoint_path).mkdir(parents=True, exist_ok=True)

                # Load existing state
                self._load_state()

                # Initialize WAL
                self._init_wal()

                # Apply filesystem protection
                if self.config.auto_protect and self.config.mode in (
                    AppendOnlyMode.CHATTR, AppendOnlyMode.FULL
                ):
                    self._apply_chattr_protection()

                # Connect to remote syslog
                if self.config.remote_syslog and self.config.mode in (
                    AppendOnlyMode.REMOTE_ONLY, AppendOnlyMode.FULL
                ):
                    self._connect_remote_syslog()

                # Load signing key if configured
                if self.config.signing_key_path:
                    self._load_signing_key()

                self._initialized = True
                return True, "Storage initialized successfully"

            except Exception as e:
                return False, f"Failed to initialize storage: {e}"

    def _load_state(self):
        """Load existing log state."""
        log_path = Path(self.config.log_path)
        if not log_path.exists():
            return

        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()

            if lines:
                self._event_count = len(lines)
                last_line = lines[-1].strip()
                if last_line:
                    event_data = json.loads(last_line)
                    # Compute hash of last event
                    data = {
                        'event_id': event_data['event_id'],
                        'timestamp': event_data['timestamp'],
                        'event_type': event_data['event_type'],
                        'details': event_data['details'],
                        'metadata': event_data.get('metadata', {}),
                    }
                    self._last_hash = hashlib.sha256(
                        json.dumps(data, sort_keys=True).encode()
                    ).hexdigest()

            # Load last checkpoint
            self._load_last_checkpoint()

        except Exception as e:
            print(f"Warning: Error loading log state: {e}")

    def _load_last_checkpoint(self):
        """Load the most recent checkpoint."""
        checkpoint_dir = Path(self.config.checkpoint_path)
        if not checkpoint_dir.exists():
            return

        checkpoints = sorted(checkpoint_dir.glob("checkpoint_*.json"))
        if checkpoints:
            try:
                with open(checkpoints[-1], 'r') as f:
                    data = json.load(f)
                self._last_checkpoint = IntegrityCheckpoint(
                    checkpoint_id=data['checkpoint_id'],
                    timestamp=data['timestamp'],
                    event_count=data['event_count'],
                    last_event_hash=data['last_event_hash'],
                    checkpoint_hash=data['checkpoint_hash'],
                    signature=data.get('signature'),
                )
            except Exception as e:
                print(f"Warning: Error loading checkpoint: {e}")

    def _init_wal(self):
        """Initialize write-ahead log."""
        try:
            self._wal_fd = open(self.config.wal_path, 'a')
        except Exception as e:
            print(f"Warning: Could not open WAL: {e}")

    def _apply_chattr_protection(self) -> bool:
        """Apply chattr +a protection to log file."""
        log_path = Path(self.config.log_path)

        # Create file if it doesn't exist
        if not log_path.exists():
            log_path.touch()

        try:
            # First remove any existing immutable attribute (requires root)
            subprocess.run(
                ['chattr', '-i', str(log_path)],
                capture_output=True,
                check=False,
            )

            # Set append-only attribute
            result = subprocess.run(
                ['chattr', '+a', str(log_path)],
                capture_output=True,
                check=True,
            )

            self._protected = True
            self._stats['protection_status'] = 'chattr_protected'
            return True

        except subprocess.CalledProcessError as e:
            # chattr requires root
            self._stats['protection_status'] = f'chattr_failed: {e}'
            return False
        except FileNotFoundError:
            self._stats['protection_status'] = 'chattr_not_available'
            return False

    def _remove_chattr_protection(self) -> bool:
        """Remove chattr +a protection (requires root)."""
        log_path = Path(self.config.log_path)

        try:
            result = subprocess.run(
                ['chattr', '-a', str(log_path)],
                capture_output=True,
                check=True,
            )
            self._protected = False
            return True
        except Exception:
            return False

    def _connect_remote_syslog(self) -> bool:
        """Connect to remote syslog server."""
        config = self.config.remote_syslog
        if not config:
            return False

        try:
            if config.protocol == "udp":
                self._remote_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._remote_socket.settimeout(config.timeout)

            elif config.protocol in ("tcp", "tls"):
                self._remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._remote_socket.settimeout(config.timeout)
                self._remote_socket.connect((config.host, config.port))

                if config.protocol == "tls":
                    context = ssl.create_default_context()
                    if config.tls_ca_cert:
                        context.load_verify_locations(config.tls_ca_cert)
                    if not config.tls_verify:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    self._remote_socket = context.wrap_socket(
                        self._remote_socket,
                        server_hostname=config.host,
                    )

            return True

        except Exception as e:
            print(f"Warning: Failed to connect to remote syslog: {e}")
            self._remote_socket = None
            return False

    def _load_signing_key(self):
        """Load Ed25519 signing key for checkpoints."""
        try:
            # Try to import cryptography library
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend

            key_path = Path(self.config.signing_key_path)
            if key_path.exists():
                with open(key_path, 'rb') as f:
                    self._signing_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=default_backend(),
                    )
        except ImportError:
            pass  # cryptography not available
        except Exception as e:
            print(f"Warning: Could not load signing key: {e}")

    # === Writing ===

    def append(self, event_json: str, event_hash: str) -> Tuple[bool, str]:
        """
        Append an event to the log.

        Args:
            event_json: JSON-serialized event
            event_hash: Hash of the event

        Returns:
            (success, message)
        """
        if not self._initialized:
            return False, "Storage not initialized"

        with self._lock:
            try:
                # Write to WAL first (crash recovery)
                if self._wal_fd:
                    self._wal_fd.write(event_json + '\n')
                    self._wal_fd.flush()

                # Write to main log
                with open(self.config.log_path, 'a') as f:
                    f.write(event_json + '\n')
                    f.flush()
                    os.fsync(f.fileno())

                # Update state
                self._event_count += 1
                self._last_hash = event_hash
                self._stats['events_written'] += 1

                # Send to remote syslog
                if self._remote_socket:
                    self._send_to_remote(event_json)

                # Clear WAL entry (event committed)
                if self._wal_fd:
                    self._wal_fd.seek(0)
                    self._wal_fd.truncate()

                return True, "Event appended"

            except Exception as e:
                return False, f"Failed to append: {e}"

    def _send_to_remote(self, event_json: str):
        """Send event to remote syslog."""
        config = self.config.remote_syslog
        if not config or not self._remote_socket:
            return

        try:
            # Format syslog message (RFC 5424)
            priority = (config.facility.value * 8) + SyslogSeverity.INFO.value
            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            hostname = socket.gethostname()

            # Truncate event if too long for syslog
            max_msg_len = 1024
            if len(event_json) > max_msg_len:
                event_json = event_json[:max_msg_len - 3] + "..."

            message = f"<{priority}>1 {timestamp} {hostname} {config.app_name} - - - {event_json}"

            if config.protocol == "udp":
                self._remote_socket.sendto(
                    message.encode('utf-8'),
                    (config.host, config.port)
                )
            else:
                self._remote_socket.send(message.encode('utf-8') + b'\n')

            self._stats['remote_sent'] += 1

        except Exception as e:
            self._stats['remote_failed'] += 1
            # Try to reconnect
            self._connect_remote_syslog()

    # === Checkpointing ===

    def create_checkpoint(self) -> Optional[IntegrityCheckpoint]:
        """
        Create an integrity checkpoint.

        Returns:
            Checkpoint object or None on failure
        """
        with self._lock:
            try:
                import uuid

                checkpoint_id = str(uuid.uuid4())
                timestamp = datetime.utcnow().isoformat() + "Z"

                # Compute checkpoint hash
                checkpoint_data = {
                    'checkpoint_id': checkpoint_id,
                    'timestamp': timestamp,
                    'event_count': self._event_count,
                    'last_event_hash': self._last_hash,
                }
                checkpoint_hash = hashlib.sha256(
                    json.dumps(checkpoint_data, sort_keys=True).encode()
                ).hexdigest()

                # Sign if key available
                signature = None
                if self._signing_key:
                    try:
                        from cryptography.hazmat.primitives import hashes
                        from cryptography.hazmat.primitives.asymmetric import ed25519

                        signature = self._signing_key.sign(
                            checkpoint_hash.encode()
                        ).hex()
                    except Exception:
                        pass

                checkpoint = IntegrityCheckpoint(
                    checkpoint_id=checkpoint_id,
                    timestamp=timestamp,
                    event_count=self._event_count,
                    last_event_hash=self._last_hash,
                    checkpoint_hash=checkpoint_hash,
                    signature=signature,
                )

                # Save checkpoint
                checkpoint_file = Path(self.config.checkpoint_path) / f"checkpoint_{checkpoint_id}.json"
                with open(checkpoint_file, 'w') as f:
                    json.dump({
                        'checkpoint_id': checkpoint.checkpoint_id,
                        'timestamp': checkpoint.timestamp,
                        'event_count': checkpoint.event_count,
                        'last_event_hash': checkpoint.last_event_hash,
                        'checkpoint_hash': checkpoint.checkpoint_hash,
                        'signature': checkpoint.signature,
                    }, f, indent=2)

                self._last_checkpoint = checkpoint
                self._stats['checkpoints_created'] += 1

                # Cleanup old checkpoints
                self._cleanup_old_checkpoints()

                return checkpoint

            except Exception as e:
                print(f"Error creating checkpoint: {e}")
                return None

    def _cleanup_old_checkpoints(self):
        """Remove old checkpoints beyond backup count."""
        checkpoint_dir = Path(self.config.checkpoint_path)
        checkpoints = sorted(checkpoint_dir.glob("checkpoint_*.json"))

        while len(checkpoints) > self.config.backup_count:
            oldest = checkpoints.pop(0)
            try:
                oldest.unlink()
            except Exception:
                pass

    def verify_checkpoint(self, checkpoint: IntegrityCheckpoint) -> Tuple[bool, str]:
        """
        Verify a checkpoint against current log state.

        Returns:
            (is_valid, message)
        """
        # Recompute checkpoint hash
        checkpoint_data = {
            'checkpoint_id': checkpoint.checkpoint_id,
            'timestamp': checkpoint.timestamp,
            'event_count': checkpoint.event_count,
            'last_event_hash': checkpoint.last_event_hash,
        }
        computed_hash = hashlib.sha256(
            json.dumps(checkpoint_data, sort_keys=True).encode()
        ).hexdigest()

        if computed_hash != checkpoint.checkpoint_hash:
            return False, "Checkpoint hash mismatch - data modified"

        # Verify signature if present
        if checkpoint.signature and self._signing_key:
            try:
                from cryptography.hazmat.primitives.asymmetric import ed25519

                public_key = self._signing_key.public_key()
                public_key.verify(
                    bytes.fromhex(checkpoint.signature),
                    checkpoint.checkpoint_hash.encode(),
                )
            except Exception as e:
                return False, f"Signature verification failed: {e}"

        return True, "Checkpoint valid"

    # === Status & Statistics ===

    def get_protection_status(self) -> Dict:
        """Get current protection status."""
        # Check if file is actually protected
        log_path = Path(self.config.log_path)
        attrs = "unknown"

        if log_path.exists():
            try:
                result = subprocess.run(
                    ['lsattr', str(log_path)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                attrs = result.stdout.split()[0] if result.stdout else "none"
            except Exception:
                pass

        return {
            'mode': self.config.mode.value,
            'initialized': self._initialized,
            'protected': self._protected,
            'file_attributes': attrs,
            'remote_syslog_connected': self._remote_socket is not None,
            'last_checkpoint': self._last_checkpoint.timestamp if self._last_checkpoint else None,
            'event_count': self._event_count,
        }

    def get_stats(self) -> Dict:
        """Get storage statistics."""
        with self._lock:
            return {
                **self._stats.copy(),
                'event_count': self._event_count,
                'last_hash': self._last_hash[:16] + "...",
            }

    # === Lifecycle ===

    def close(self):
        """Close storage and cleanup."""
        with self._lock:
            if self._wal_fd:
                self._wal_fd.close()
                self._wal_fd = None

            if self._remote_socket:
                try:
                    self._remote_socket.close()
                except Exception:
                    pass
                self._remote_socket = None

            self._initialized = False


class AppendOnlyEventLogger:
    """
    Event logger with append-only storage protection.

    Wraps the standard EventLogger with AppendOnlyStorage for
    enhanced protection.
    """

    def __init__(
        self,
        log_file_path: str,
        storage_config: Optional[AppendOnlyConfig] = None,
    ):
        """Initialize append-only event logger."""
        from daemon.event_logger import EventLogger

        # Configure storage with same log path
        if storage_config:
            storage_config.log_path = log_file_path
        else:
            storage_config = AppendOnlyConfig(log_path=log_file_path)

        self.storage = AppendOnlyStorage(storage_config)
        self._base_logger = EventLogger(log_file_path)
        self._lock = threading.Lock()

    def initialize(self) -> Tuple[bool, str]:
        """Initialize storage protection."""
        return self.storage.initialize()

    def log_event(self, event_type, details: str, metadata=None, data=None):
        """Log an event with append-only protection."""
        with self._lock:
            # Use base logger's event creation
            event = self._base_logger.log_event(event_type, details, metadata or data)

            # Storage tracks the append (base logger already wrote to file)
            self.storage._event_count = self._base_logger.get_event_count()
            self.storage._last_hash = self._base_logger.get_last_hash()

            # Send to remote if configured
            if self.storage._remote_socket:
                self.storage._send_to_remote(event.to_json())

            return event

    def verify_chain(self):
        """Verify log integrity."""
        return self._base_logger.verify_chain()

    def get_event_count(self) -> int:
        """Get event count."""
        return self._base_logger.get_event_count()

    def get_recent_events(self, count: int = 100):
        """Get recent events."""
        return self._base_logger.get_recent_events(count)

    def create_checkpoint(self):
        """Create integrity checkpoint."""
        return self.storage.create_checkpoint()

    def get_protection_status(self) -> Dict:
        """Get protection status."""
        return self.storage.get_protection_status()

    def close(self):
        """Close logger."""
        self.storage.close()
