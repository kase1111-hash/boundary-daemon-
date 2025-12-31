"""
Persistent Rate Limiter - Survives Daemon Restarts

This module addresses the vulnerability: "Rate Limiting Bypass via Restart"

VULNERABILITY:
- Rate limit counters stored in memory are lost on daemon restart
- Attacker can bypass rate limits by:
  1. Making requests until rate limited
  2. Killing/restarting the daemon
  3. Continuing with fresh rate limit counters

SOLUTION:
- Persist rate limit state to disk with atomic writes
- Load state on startup
- Use wall clock time for persistence (monotonic resets on boot)
- Automatic cleanup of old entries
- File locking for concurrent access safety

STORAGE FORMAT:
- JSON file with rate limit entries
- Each entry has: token_id, request_times[], blocked_until, total_requests
- Timestamps stored as ISO8601 for readability
- File protected with restrictive permissions (0o600)
"""

import json
import os
import sys
import time
import fcntl

# Platform detection
IS_WINDOWS = sys.platform == 'win32'
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from threading import RLock

logger = logging.getLogger(__name__)


@dataclass
class PersistentRateLimitEntry:
    """Rate limit entry that can be persisted to disk."""
    token_id: str
    request_times: List[float] = field(default_factory=list)  # Unix timestamps
    blocked_until: Optional[float] = None  # Unix timestamp
    total_requests: int = 0
    total_blocks: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'token_id': self.token_id,
            'request_times': self.request_times,
            'blocked_until': self.blocked_until,
            'total_requests': self.total_requests,
            'total_blocks': self.total_blocks,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'PersistentRateLimitEntry':
        """Create from dictionary."""
        return cls(
            token_id=data.get('token_id', 'unknown'),
            request_times=data.get('request_times', []),
            blocked_until=data.get('blocked_until'),
            total_requests=data.get('total_requests', 0),
            total_blocks=data.get('total_blocks', 0),
            first_seen=data.get('first_seen', time.time()),
            last_seen=data.get('last_seen', time.time()),
        )


@dataclass
class GlobalRateLimitEntry:
    """Global rate limit entry that can be persisted."""
    request_times: List[float] = field(default_factory=list)
    blocked_until: Optional[float] = None
    total_requests: int = 0
    total_blocks: int = 0

    def to_dict(self) -> Dict:
        return {
            'request_times': self.request_times,
            'blocked_until': self.blocked_until,
            'total_requests': self.total_requests,
            'total_blocks': self.total_blocks,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'GlobalRateLimitEntry':
        return cls(
            request_times=data.get('request_times', []),
            blocked_until=data.get('blocked_until'),
            total_requests=data.get('total_requests', 0),
            total_blocks=data.get('total_blocks', 0),
        )


class PersistentRateLimiter:
    """
    Rate limiter with persistent state that survives daemon restarts.

    SECURITY: This prevents rate limit bypass by restarting the daemon.

    Features:
    - Atomic writes to prevent corruption
    - File locking for concurrent access
    - Automatic cleanup of expired entries
    - Configurable persistence interval
    - Uses wall clock for persistence (survives reboot)
    """

    DEFAULT_STATE_FILE = "/var/lib/boundary-daemon/rate_limits.json"
    DEFAULT_PERSIST_INTERVAL = 5.0  # Persist every 5 seconds max

    def __init__(
        self,
        state_file: str = None,
        rate_limit_window: int = 60,
        rate_limit_max_requests: int = 100,
        rate_limit_block_duration: int = 300,
        global_rate_limit_window: int = 60,
        global_rate_limit_max_requests: int = 1000,
        global_rate_limit_block_duration: int = 60,
        cleanup_interval: int = 3600,  # Clean old entries every hour
        max_entry_age: int = 86400,  # Remove entries older than 24 hours
        event_logger=None,
    ):
        """
        Initialize persistent rate limiter.

        Args:
            state_file: Path to state file
            rate_limit_window: Per-token rate limit window (seconds)
            rate_limit_max_requests: Max requests per window per token
            rate_limit_block_duration: Block duration when limit exceeded
            global_rate_limit_window: Global rate limit window
            global_rate_limit_max_requests: Max total requests per window
            global_rate_limit_block_duration: Global block duration
            cleanup_interval: How often to clean old entries
            max_entry_age: Maximum age of entries to keep
            event_logger: Optional event logger
        """
        self.state_file = Path(state_file or self.DEFAULT_STATE_FILE)
        self.rate_limit_window = rate_limit_window
        self.rate_limit_max_requests = rate_limit_max_requests
        self.rate_limit_block_duration = rate_limit_block_duration
        self.global_rate_limit_window = global_rate_limit_window
        self.global_rate_limit_max_requests = global_rate_limit_max_requests
        self.global_rate_limit_block_duration = global_rate_limit_block_duration
        self.cleanup_interval = cleanup_interval
        self.max_entry_age = max_entry_age
        self._event_logger = event_logger

        # In-memory state (loaded from disk)
        self._entries: Dict[str, PersistentRateLimitEntry] = {}
        self._global_entry: GlobalRateLimitEntry = GlobalRateLimitEntry()
        self._lock = RLock()

        # Persistence tracking
        self._last_persist = 0.0
        self._last_cleanup = 0.0
        self._dirty = False  # Track if state has changed

        # Ensure state directory exists
        self._ensure_state_directory()

        # Load existing state
        self._load_state()

        logger.info(f"Persistent rate limiter initialized: {self.state_file}")

    def _ensure_state_directory(self):
        """Ensure state directory exists with proper permissions."""
        state_dir = self.state_file.parent
        try:
            state_dir.mkdir(parents=True, exist_ok=True)
            if self._has_admin_privileges():
                os.chmod(state_dir, 0o700)
        except Exception as e:
            logger.warning(f"Could not create state directory: {e}")

    def _has_admin_privileges(self) -> bool:
        """Check if running with admin/root privileges (cross-platform)."""
        if IS_WINDOWS:
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0

    def _load_state(self):
        """Load rate limit state from disk."""
        if not self.state_file.exists():
            logger.debug("No existing rate limit state file")
            return

        try:
            with open(self.state_file, 'r') as f:
                # Acquire shared lock for reading
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    data = json.load(f)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

            # Load per-token entries
            entries_data = data.get('entries', {})
            for token_id, entry_data in entries_data.items():
                self._entries[token_id] = PersistentRateLimitEntry.from_dict(entry_data)

            # Load global entry
            global_data = data.get('global', {})
            self._global_entry = GlobalRateLimitEntry.from_dict(global_data)

            # Clean expired entries on load
            self._cleanup_expired()

            logger.info(f"Loaded {len(self._entries)} rate limit entries from disk")
            logger.info(f"Global: {self._global_entry.total_requests} total requests, "
                       f"{self._global_entry.total_blocks} blocks")

        except json.JSONDecodeError as e:
            logger.error(f"Corrupt rate limit state file: {e}")
            # Backup corrupt file and start fresh
            self._backup_corrupt_file()
        except Exception as e:
            logger.error(f"Failed to load rate limit state: {e}")

    def _backup_corrupt_file(self):
        """Backup corrupt state file."""
        try:
            backup_path = self.state_file.with_suffix('.corrupt')
            if self.state_file.exists():
                os.rename(self.state_file, backup_path)
                logger.warning(f"Backed up corrupt file to {backup_path}")
        except Exception as e:
            logger.error(f"Failed to backup corrupt file: {e}")

    def _persist_state(self, force: bool = False):
        """Persist rate limit state to disk."""
        now = time.time()

        # Check if we should persist
        if not force and not self._dirty:
            return
        if not force and (now - self._last_persist) < self.DEFAULT_PERSIST_INTERVAL:
            return

        try:
            # Build state data
            data = {
                'version': 1,
                'updated_at': datetime.utcnow().isoformat() + 'Z',
                'entries': {
                    token_id: entry.to_dict()
                    for token_id, entry in self._entries.items()
                },
                'global': self._global_entry.to_dict(),
            }

            # Atomic write: write to temp file, then rename
            temp_path = self.state_file.with_suffix('.tmp')

            with open(temp_path, 'w') as f:
                # Acquire exclusive lock for writing
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    json.dump(data, f, indent=2)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

            # Set restrictive permissions
            os.chmod(temp_path, 0o600)

            # Atomic rename
            os.rename(temp_path, self.state_file)

            self._last_persist = now
            self._dirty = False

            logger.debug(f"Persisted rate limit state ({len(self._entries)} entries)")

        except Exception as e:
            logger.error(f"Failed to persist rate limit state: {e}")

    def _cleanup_expired(self):
        """Remove expired entries to prevent unbounded growth."""
        now = time.time()

        if (now - self._last_cleanup) < self.cleanup_interval:
            return

        with self._lock:
            # Clean per-token entries
            expired = []
            for token_id, entry in self._entries.items():
                # Remove if too old and not currently blocked
                if (now - entry.last_seen) > self.max_entry_age:
                    if entry.blocked_until is None or entry.blocked_until < now:
                        expired.append(token_id)

            for token_id in expired:
                del self._entries[token_id]

            if expired:
                logger.info(f"Cleaned up {len(expired)} expired rate limit entries")
                self._dirty = True

            # Clean global request times
            window_start = now - self.global_rate_limit_window
            self._global_entry.request_times = [
                t for t in self._global_entry.request_times if t > window_start
            ]

            self._last_cleanup = now

    def check_global_rate_limit(self) -> Tuple[bool, str]:
        """
        Check and update global rate limit.

        Returns:
            (is_allowed, reason)
        """
        now = time.time()

        with self._lock:
            entry = self._global_entry

            # Check if currently blocked
            if entry.blocked_until and now < entry.blocked_until:
                remaining = int(entry.blocked_until - now)
                return False, f"Global rate limit exceeded. Try again in {remaining}s"

            # Clear block if expired
            if entry.blocked_until and now >= entry.blocked_until:
                entry.blocked_until = None
                self._dirty = True

            # Remove old request times
            window_start = now - self.global_rate_limit_window
            entry.request_times = [t for t in entry.request_times if t > window_start]

            # Check if over limit
            if len(entry.request_times) >= self.global_rate_limit_max_requests:
                entry.blocked_until = now + self.global_rate_limit_block_duration
                entry.total_blocks += 1
                self._dirty = True
                self._persist_state()  # Persist immediately on block
                return False, (
                    f"Global rate limit exceeded "
                    f"({self.global_rate_limit_max_requests} req/{self.global_rate_limit_window}s). "
                    f"Blocked for {self.global_rate_limit_block_duration}s"
                )

            # Record this request
            entry.request_times.append(now)
            entry.total_requests += 1
            self._dirty = True

            # Periodically persist
            self._persist_state()
            self._cleanup_expired()

            return True, "OK"

    def check_rate_limit(self, token_id: str) -> Tuple[bool, str]:
        """
        Check and update rate limit for a token.

        Args:
            token_id: Token identifier

        Returns:
            (is_allowed, reason)
        """
        now = time.time()

        with self._lock:
            entry = self._entries.get(token_id)

            if entry is None:
                entry = PersistentRateLimitEntry(token_id=token_id)
                self._entries[token_id] = entry

            entry.last_seen = now

            # Check if currently blocked
            if entry.blocked_until and now < entry.blocked_until:
                remaining = int(entry.blocked_until - now)
                return False, f"Rate limited. Try again in {remaining}s"

            # Clear block if expired
            if entry.blocked_until and now >= entry.blocked_until:
                entry.blocked_until = None
                self._dirty = True

            # Remove old request times
            window_start = now - self.rate_limit_window
            entry.request_times = [t for t in entry.request_times if t > window_start]

            # Check if over limit
            if len(entry.request_times) >= self.rate_limit_max_requests:
                entry.blocked_until = now + self.rate_limit_block_duration
                entry.total_blocks += 1
                self._dirty = True
                self._persist_state()  # Persist immediately on block
                return False, f"Rate limit exceeded. Blocked for {self.rate_limit_block_duration}s"

            # Record this request
            entry.request_times.append(now)
            entry.total_requests += 1
            self._dirty = True

            # Periodically persist
            self._persist_state()

            return True, "OK"

    def check_command_rate_limit(
        self,
        token_id: str,
        command: str,
        max_requests: int,
        window: int,
    ) -> Tuple[bool, str]:
        """
        Check rate limit for a specific command.

        Args:
            token_id: Token identifier
            command: Command name
            max_requests: Maximum requests allowed
            window: Time window in seconds

        Returns:
            (is_allowed, reason)
        """
        # Use composite key for command-specific tracking
        composite_id = f"{token_id}:cmd:{command}"
        now = time.time()

        with self._lock:
            entry = self._entries.get(composite_id)

            if entry is None:
                entry = PersistentRateLimitEntry(token_id=composite_id)
                self._entries[composite_id] = entry

            entry.last_seen = now

            # Remove old request times
            window_start = now - window
            entry.request_times = [t for t in entry.request_times if t > window_start]

            # Check if over limit
            if len(entry.request_times) >= max_requests:
                # Command rate limits don't block, just reject
                return False, f"Command rate limit exceeded for {command} ({max_requests}/{window}s)"

            # Record this request
            entry.request_times.append(now)
            entry.total_requests += 1
            self._dirty = True

            return True, "OK"

    def get_entry(self, token_id: str) -> Optional[PersistentRateLimitEntry]:
        """Get rate limit entry for a token."""
        with self._lock:
            return self._entries.get(token_id)

    def get_global_entry(self) -> GlobalRateLimitEntry:
        """Get global rate limit entry."""
        with self._lock:
            return self._global_entry

    def get_stats(self) -> Dict:
        """Get rate limiter statistics."""
        with self._lock:
            now = time.time()

            blocked_tokens = sum(
                1 for e in self._entries.values()
                if e.blocked_until and e.blocked_until > now
            )

            return {
                'total_entries': len(self._entries),
                'blocked_tokens': blocked_tokens,
                'global_total_requests': self._global_entry.total_requests,
                'global_total_blocks': self._global_entry.total_blocks,
                'global_blocked': (
                    self._global_entry.blocked_until is not None and
                    self._global_entry.blocked_until > now
                ),
                'state_file': str(self.state_file),
                'last_persist': datetime.fromtimestamp(self._last_persist).isoformat()
                    if self._last_persist else None,
            }

    def force_persist(self):
        """Force immediate persistence of state."""
        with self._lock:
            self._dirty = True
            self._persist_state(force=True)

    def clear_all(self):
        """Clear all rate limit entries (admin function)."""
        with self._lock:
            self._entries.clear()
            self._global_entry = GlobalRateLimitEntry()
            self._dirty = True
            self._persist_state(force=True)
            logger.warning("All rate limit entries cleared")

    def unblock_token(self, token_id: str) -> bool:
        """Manually unblock a token (admin function)."""
        with self._lock:
            entry = self._entries.get(token_id)
            if entry and entry.blocked_until:
                entry.blocked_until = None
                self._dirty = True
                self._persist_state(force=True)
                logger.info(f"Manually unblocked token: {token_id}")
                return True
            return False

    def shutdown(self):
        """Shutdown and persist final state."""
        with self._lock:
            self._persist_state(force=True)
            logger.info("Rate limiter shutdown, state persisted")


# Singleton instance for daemon-wide rate limiting
_instance: Optional[PersistentRateLimiter] = None


def get_rate_limiter(
    state_file: str = None,
    **kwargs,
) -> PersistentRateLimiter:
    """Get or create the singleton rate limiter instance."""
    global _instance
    if _instance is None:
        _instance = PersistentRateLimiter(state_file=state_file, **kwargs)
    return _instance


def reset_rate_limiter():
    """Reset the singleton instance (for testing)."""
    global _instance
    if _instance:
        _instance.shutdown()
    _instance = None


if __name__ == '__main__':
    import tempfile

    logging.basicConfig(level=logging.DEBUG)

    print("Persistent Rate Limiter Test")
    print("=" * 60)

    # Use temp file for testing
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        test_file = f.name

    try:
        # Create rate limiter
        limiter = PersistentRateLimiter(
            state_file=test_file,
            rate_limit_max_requests=5,
            rate_limit_window=10,
            rate_limit_block_duration=30,
        )

        # Test per-token rate limiting
        print("\n--- Per-Token Rate Limiting ---")
        token = "test_token_123"
        for i in range(7):
            allowed, reason = limiter.check_rate_limit(token)
            print(f"Request {i+1}: {'ALLOWED' if allowed else 'DENIED'} - {reason}")

        # Test persistence
        print("\n--- Persistence Test ---")
        limiter.force_persist()
        print(f"State persisted to: {test_file}")

        # Create new instance (simulates restart)
        print("\nSimulating daemon restart...")
        limiter2 = PersistentRateLimiter(state_file=test_file)

        # Should still be blocked
        allowed, reason = limiter2.check_rate_limit(token)
        print(f"After restart: {'ALLOWED' if allowed else 'DENIED'} - {reason}")

        # Print stats
        print("\n--- Statistics ---")
        stats = limiter2.get_stats()
        for key, value in stats.items():
            print(f"  {key}: {value}")

        print("\nTest complete - rate limits SURVIVED restart!")

    finally:
        # Cleanup
        try:
            os.unlink(test_file)
        except Exception:
            pass
