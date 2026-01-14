"""
Event Logger - Immutable Boundary Event Log with Hash Chain
Maintains tamper-evident log of all boundary events.

SECURITY IMPROVEMENTS:
- Log files are created with 0o600 permissions (owner read/write only)
- Log directory is created with 0o700 permissions (owner access only)
- Optional integration with LogHardener for chattr +a protection
- fsync() called after each write for crash recovery
"""

import hashlib
import json
import os
import threading
import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Tuple

logger = logging.getLogger(__name__)

# Secure file permissions
LOG_FILE_PERMS = 0o600   # Owner read/write only
LOG_DIR_PERMS = 0o700    # Owner access only


class EventType(Enum):
    """Types of boundary events"""
    MODE_CHANGE = "mode_change"
    VIOLATION = "violation"
    TRIPWIRE = "tripwire"
    POLICY_DECISION = "policy_decision"
    RECALL_ATTEMPT = "recall_attempt"
    TOOL_REQUEST = "tool_request"
    OVERRIDE = "override"
    BIOMETRIC_ATTEMPT = "biometric_attempt"
    SECURITY_SCAN = "security_scan"
    DAEMON_START = "daemon_start"
    DAEMON_STOP = "daemon_stop"
    HEALTH_CHECK = "health_check"
    MESSAGE_CHECK = "message_check"  # NatLangChain/Agent-OS message validation
    API_REQUEST = "api_request"  # Authenticated API request
    CLOCK_JUMP = "clock_jump"  # Time manipulation detected
    CLOCK_DRIFT = "clock_drift"  # Excessive clock drift
    NTP_SYNC_LOST = "ntp_sync_lost"  # NTP synchronization lost
    RATE_LIMIT_TOKEN = "rate_limit_token"  # Per-token rate limit exceeded
    RATE_LIMIT_GLOBAL = "rate_limit_global"  # Global rate limit exceeded
    RATE_LIMIT_COMMAND = "rate_limit_command"  # Per-command rate limit exceeded
    RATE_LIMIT_UNBLOCK = "rate_limit_unblock"  # Rate limit block expired
    PII_DETECTED = "pii_detected"  # PII detected in content
    PII_BLOCKED = "pii_blocked"  # Content blocked due to PII
    PII_REDACTED = "pii_redacted"  # PII redacted from content
    ALERT = "alert"  # System alert (critical/warning)
    INFO = "info"  # Informational event


@dataclass
class BoundaryEvent:
    """A single boundary event in the log"""
    event_id: str
    timestamp: str
    event_type: EventType
    details: str
    metadata: Dict
    hash_chain: str  # Hash of previous event

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp,
            'event_type': self.event_type.value,
            'details': self.details,
            'metadata': self.metadata,
            'hash_chain': self.hash_chain
        }

    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), sort_keys=True)

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this event"""
        # Hash the event data (excluding hash_chain to allow verification)
        data = {
            'event_id': self.event_id,
            'timestamp': self.timestamp,
            'event_type': self.event_type.value,
            'details': self.details,
            'metadata': self.metadata
        }
        json_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()


class EventLogger:
    """
    Immutable, tamper-evident event logger using hash chains.

    Each event contains the hash of the previous event, creating a blockchain-like
    chain that makes tampering detectable.
    """

    def __init__(self, log_file_path: str, secure_permissions: bool = True):
        """
        Initialize event logger.

        Args:
            log_file_path: Path to the log file
            secure_permissions: Apply secure permissions (0o600/0o700)
        """
        self.log_file_path = log_file_path
        self._lock = threading.Lock()
        self._last_hash: str = "0" * 64  # Genesis hash (all zeros)
        self._event_count = 0
        self._secure_permissions = secure_permissions
        self._file_created = False

        # Ensure log directory exists with secure permissions
        log_dir = os.path.dirname(log_file_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
            if self._secure_permissions:
                try:
                    os.chmod(log_dir, LOG_DIR_PERMS)
                except Exception as e:
                    logger.warning(f"Could not set secure directory permissions: {e}")

        # Load existing log to get the last hash
        self._load_existing_log()

    def _load_existing_log(self):
        """Load existing log file to resume chain"""
        if not os.path.exists(self.log_file_path):
            return

        try:
            with open(self.log_file_path, 'r') as f:
                lines = f.readlines()
                if lines:
                    # Get the last event's hash
                    last_line = lines[-1].strip()
                    if last_line:
                        event_data = json.loads(last_line)
                        event = BoundaryEvent(
                            event_id=event_data['event_id'],
                            timestamp=event_data['timestamp'],
                            event_type=EventType(event_data['event_type']),
                            details=event_data['details'],
                            metadata=event_data.get('metadata', {}),
                            hash_chain=event_data['hash_chain']
                        )
                        self._last_hash = event.compute_hash()
                        self._event_count = len(lines)
        except Exception as e:
            logger.warning(f"Error loading existing log: {e}")
            # Continue with genesis hash

    def log_event(self, event_type: EventType, details: str, metadata: Optional[Dict] = None) -> BoundaryEvent:
        """
        Log a boundary event.

        Args:
            event_type: Type of event
            details: Human-readable details
            metadata: Additional structured data

        Returns:
            The logged event
        """
        with self._lock:
            event = BoundaryEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.utcnow().isoformat() + "Z",
                event_type=event_type,
                details=details,
                metadata=metadata or {},
                hash_chain=self._last_hash
            )

            # Write to log file (append-only)
            self._append_to_log(event)

            # Update last hash for next event
            self._last_hash = event.compute_hash()
            self._event_count += 1

            return event

    def _append_to_log(self, event: BoundaryEvent):
        """Append event to log file with secure permissions"""
        try:
            # Check if file exists before writing
            file_existed = os.path.exists(self.log_file_path)

            with open(self.log_file_path, 'a') as f:
                f.write(event.to_json() + '\n')
                f.flush()
                os.fsync(f.fileno())  # Ensure written to disk

            # Set secure permissions on new files
            if not file_existed and self._secure_permissions:
                try:
                    os.chmod(self.log_file_path, LOG_FILE_PERMS)
                    logger.debug(f"Set secure permissions on log file: {oct(LOG_FILE_PERMS)}")
                except Exception as e:
                    logger.warning(f"Could not set secure file permissions: {e}")

        except Exception as e:
            logger.critical(f"Failed to write to event log: {e}")
            raise

    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        import uuid
        return str(uuid.uuid4())

    def get_event_count(self) -> int:
        """Get total number of logged events"""
        with self._lock:
            return self._event_count

    def get_last_hash(self) -> str:
        """Get the hash of the last event"""
        with self._lock:
            return self._last_hash

    def verify_chain(self) -> tuple[bool, Optional[str]]:
        """
        Verify the integrity of the entire event chain.

        Returns:
            (is_valid, error_message)
        """
        if not os.path.exists(self.log_file_path):
            return (True, None)  # Empty log is valid

        try:
            with open(self.log_file_path, 'r') as f:
                lines = f.readlines()

            if not lines:
                return (True, None)

            expected_hash = "0" * 64  # Genesis hash

            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue

                event_data = json.loads(line)
                event = BoundaryEvent(
                    event_id=event_data['event_id'],
                    timestamp=event_data['timestamp'],
                    event_type=EventType(event_data['event_type']),
                    details=event_data['details'],
                    metadata=event_data.get('metadata', {}),
                    hash_chain=event_data['hash_chain']
                )

                # Verify hash chain
                if event.hash_chain != expected_hash:
                    return (False, f"Hash chain broken at event {i}: expected {expected_hash}, got {event.hash_chain}")

                # Update expected hash for next event
                expected_hash = event.compute_hash()

            return (True, None)

        except Exception as e:
            return (False, f"Error verifying chain: {e}")

    def get_recent_events(self, count: int = 100) -> List[BoundaryEvent]:
        """
        Get the most recent events.

        Args:
            count: Number of events to retrieve

        Returns:
            List of recent events (newest first)
        """
        if not os.path.exists(self.log_file_path):
            return []

        try:
            with open(self.log_file_path, 'r') as f:
                lines = f.readlines()

            # Get last N lines
            recent_lines = lines[-count:] if len(lines) > count else lines

            events = []
            for line in recent_lines:
                line = line.strip()
                if not line:
                    continue

                event_data = json.loads(line)
                event = BoundaryEvent(
                    event_id=event_data['event_id'],
                    timestamp=event_data['timestamp'],
                    event_type=EventType(event_data['event_type']),
                    details=event_data['details'],
                    metadata=event_data.get('metadata', {}),
                    hash_chain=event_data['hash_chain']
                )
                events.append(event)

            # Return newest first
            return list(reversed(events))

        except Exception as e:
            logger.error(f"Error reading recent events: {e}")
            return []

    def get_events_by_type(self, event_type: EventType, limit: int = 100) -> List[BoundaryEvent]:
        """
        Get events of a specific type.

        Args:
            event_type: Type of events to retrieve
            limit: Maximum number of events

        Returns:
            List of matching events (newest first)
        """
        if not os.path.exists(self.log_file_path):
            return []

        try:
            with open(self.log_file_path, 'r') as f:
                lines = f.readlines()

            events: List[BoundaryEvent] = []
            # Read in reverse to get newest first
            for line in reversed(lines):
                if len(events) >= limit:
                    break

                line = line.strip()
                if not line:
                    continue

                event_data = json.loads(line)
                if event_data['event_type'] == event_type.value:
                    event = BoundaryEvent(
                        event_id=event_data['event_id'],
                        timestamp=event_data['timestamp'],
                        event_type=EventType(event_data['event_type']),
                        details=event_data['details'],
                        metadata=event_data.get('metadata', {}),
                        hash_chain=event_data['hash_chain']
                    )
                    events.append(event)

            return events

        except Exception as e:
            logger.error(f"Error reading events by type: {e}")
            return []

    def export_log(self, output_path: str, seal: bool = False) -> bool:
        """
        Export the log to a new file (for archival).

        Args:
            output_path: Path for exported log
            seal: If True, seal the exported log (read-only, immutable if possible)

        Returns:
            True if successful
        """
        try:
            import shutil
            shutil.copy2(self.log_file_path, output_path)

            if seal:
                # Make read-only
                os.chmod(output_path, 0o400)

                # Try to apply immutable attribute
                try:
                    import subprocess
                    result = subprocess.run(
                        ['chattr', '+i', output_path],
                        capture_output=True,
                        timeout=5,
                    )
                    if result.returncode == 0:
                        logger.info(f"Sealed exported log with immutable attribute: {output_path}")
                except Exception:
                    logger.debug("Could not apply immutable attribute (requires root)")

            return True
        except Exception as e:
            logger.error(f"Error exporting log: {e}")
            return False

    def seal_log(self) -> Tuple[bool, str]:
        """
        Seal the current log file (make it immutable).

        After sealing:
        - Permissions set to 0o400 (read-only)
        - chattr +i applied if available and running as root

        WARNING: After sealing, a new log file must be created for future events.

        Returns:
            (success, message)
        """
        with self._lock:
            if not os.path.exists(self.log_file_path):
                return (False, "Log file does not exist")

            try:
                # Log final event
                final_event = BoundaryEvent(
                    event_id=self._generate_event_id(),
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    event_type=EventType.INFO,
                    details="Log sealed",
                    metadata={
                        'action': 'seal',
                        'final_hash': self._last_hash,
                        'event_count': self._event_count,
                    },
                    hash_chain=self._last_hash,
                )

                with open(self.log_file_path, 'a') as f:
                    f.write(final_event.to_json() + '\n')
                    f.flush()
                    os.fsync(f.fileno())

                # Set read-only permissions
                os.chmod(self.log_file_path, 0o400)

                # Try to apply immutable attribute
                is_immutable = False
                try:
                    import subprocess
                    result = subprocess.run(
                        ['chattr', '+i', self.log_file_path],
                        capture_output=True,
                        timeout=5,
                    )
                    if result.returncode == 0:
                        is_immutable = True
                        logger.info(f"Applied immutable attribute to sealed log")
                except Exception:
                    pass

                # Compute final file hash
                import hashlib
                sha256 = hashlib.sha256()
                with open(self.log_file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(8192), b''):
                        sha256.update(chunk)
                file_hash = sha256.hexdigest()

                # Create seal checkpoint
                checkpoint_path = self.log_file_path + '.sealed'
                checkpoint = {
                    'sealed_at': datetime.utcnow().isoformat() + "Z",
                    'log_path': self.log_file_path,
                    'event_count': self._event_count + 1,
                    'final_chain_hash': final_event.compute_hash(),
                    'file_hash': file_hash,
                    'is_immutable': is_immutable,
                }

                with open(checkpoint_path, 'w') as f:
                    json.dump(checkpoint, f, indent=2)
                os.chmod(checkpoint_path, 0o400)

                msg = f"Log sealed: {self._event_count + 1} events, hash {file_hash[:16]}..."
                if is_immutable:
                    msg += " (immutable)"

                logger.info(msg)
                return (True, msg)

            except Exception as e:
                logger.error(f"Failed to seal log: {e}")
                return (False, str(e))

    def get_protection_status(self) -> Dict:
        """
        Get the protection status of the log file.

        Returns:
            Dictionary with protection details
        """
        status = {
            'path': self.log_file_path,
            'exists': os.path.exists(self.log_file_path),
            'permissions': None,
            'is_append_only': False,
            'is_immutable': False,
            'is_sealed': False,
        }

        if not status['exists']:
            return status

        try:
            st = os.stat(self.log_file_path)
            status['permissions'] = oct(st.st_mode)[-3:]
            status['owner_uid'] = st.st_uid
            status['size'] = st.st_size

            # Check for seal checkpoint
            checkpoint_path = self.log_file_path + '.sealed'
            status['is_sealed'] = os.path.exists(checkpoint_path)

            # Check chattr attributes (if available)
            try:
                import subprocess
                result = subprocess.run(
                    ['lsattr', self.log_file_path],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    attrs = result.stdout.split()[0] if result.stdout else ""
                    status['is_append_only'] = 'a' in attrs
                    status['is_immutable'] = 'i' in attrs
            except Exception:
                pass

        except Exception as e:
            status['error'] = str(e)

        return status


if __name__ == '__main__':
    # Test event logger
    print("Testing Event Logger...")

    import tempfile
    import os

    # Create a temporary log file
    temp_dir = tempfile.mkdtemp()
    log_file = os.path.join(temp_dir, 'boundary_chain.log')

    logger = EventLogger(log_file)

    # Log some events
    print("\nLogging events...")
    logger.log_event(EventType.DAEMON_START, "Boundary daemon started")
    logger.log_event(EventType.MODE_CHANGE, "Transitioned from OPEN to RESTRICTED",
                    metadata={'old_mode': 'open', 'new_mode': 'restricted'})
    logger.log_event(EventType.RECALL_ATTEMPT, "Memory class 3 recall requested",
                    metadata={'memory_class': 3, 'decision': 'allow'})
    logger.log_event(EventType.VIOLATION, "Network came online in AIRGAP mode",
                    metadata={'violation_type': 'network_in_airgap'})

    print(f"Total events: {logger.get_event_count()}")

    # Verify chain
    print("\nVerifying chain integrity...")
    is_valid, error = logger.verify_chain()
    print(f"Chain valid: {is_valid}")
    if error:
        print(f"Error: {error}")

    # Get recent events
    print("\nRecent events:")
    for event in logger.get_recent_events(10):
        print(f"  [{event.timestamp}] {event.event_type.value}: {event.details}")

    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)

    print("\nEvent logger test complete.")
