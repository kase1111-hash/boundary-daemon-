"""
API Authentication - Token-based authentication for Boundary Daemon API.

Provides:
- Secure token generation and storage
- Capability-based access control
- Rate limiting (with optional persistence to survive restarts)
- Token lifecycle management (create, revoke, expire)

SECURITY: Rate limiting now supports persistence to disk, preventing
bypass via daemon restart. This addresses the vulnerability:
"Rate Limiting Bypass via Restart"
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Import persistent rate limiter (SECURITY: survives restarts)
try:
    from .persistent_rate_limiter import PersistentRateLimiter
    PERSISTENT_RATE_LIMIT_AVAILABLE = True
except ImportError:
    PERSISTENT_RATE_LIMIT_AVAILABLE = False
    PersistentRateLimiter = None


class APICapability(Enum):
    """Capabilities that can be granted to API tokens."""
    # Read-only capabilities
    STATUS = auto()          # Get daemon status
    READ_EVENTS = auto()     # Read event log
    VERIFY_LOG = auto()      # Verify log integrity
    CHECK_RECALL = auto()    # Check recall permissions
    CHECK_TOOL = auto()      # Check tool permissions
    CHECK_MESSAGE = auto()   # Check message content

    # Write capabilities
    SET_MODE = auto()        # Change boundary mode

    # Admin capabilities
    MANAGE_TOKENS = auto()   # Create/revoke tokens
    ADMIN = auto()           # Full access (includes all capabilities)


# Predefined capability sets
CAPABILITY_SETS = {
    'readonly': {
        APICapability.STATUS,
        APICapability.READ_EVENTS,
        APICapability.VERIFY_LOG,
        APICapability.CHECK_RECALL,
        APICapability.CHECK_TOOL,
        APICapability.CHECK_MESSAGE,
    },
    'operator': {
        APICapability.STATUS,
        APICapability.READ_EVENTS,
        APICapability.VERIFY_LOG,
        APICapability.CHECK_RECALL,
        APICapability.CHECK_TOOL,
        APICapability.CHECK_MESSAGE,
        APICapability.SET_MODE,
    },
    'admin': {
        APICapability.ADMIN,
    },
}

# Map API commands to required capabilities
COMMAND_CAPABILITIES = {
    'status': APICapability.STATUS,
    'get_events': APICapability.READ_EVENTS,
    'verify_log': APICapability.VERIFY_LOG,
    'check_recall': APICapability.CHECK_RECALL,
    'check_tool': APICapability.CHECK_TOOL,
    'check_message': APICapability.CHECK_MESSAGE,
    'check_natlangchain': APICapability.CHECK_MESSAGE,
    'check_agentos': APICapability.CHECK_MESSAGE,
    'set_mode': APICapability.SET_MODE,
    'create_token': APICapability.MANAGE_TOKENS,
    'revoke_token': APICapability.MANAGE_TOKENS,
    'list_tokens': APICapability.MANAGE_TOKENS,
    'rate_limit_status': APICapability.MANAGE_TOKENS,
}

# Per-command rate limits (requests per window)
# Commands not listed use the default per-token rate limit
# Format: command -> (max_requests, window_seconds)
COMMAND_RATE_LIMITS = {
    # Read-only commands - higher limits
    'status': (200, 60),              # 200 per minute
    'get_events': (100, 60),          # 100 per minute
    'verify_log': (50, 60),           # 50 per minute
    'rate_limit_status': (30, 60),    # 30 per minute

    # Check commands - moderate limits (called frequently during normal operation)
    'check_recall': (500, 60),        # 500 per minute (memory operations are frequent)
    'check_tool': (300, 60),          # 300 per minute (tool calls are frequent)
    'check_message': (200, 60),       # 200 per minute
    'check_natlangchain': (200, 60),  # 200 per minute
    'check_agentos': (200, 60),       # 200 per minute

    # Write/modify commands - stricter limits
    'set_mode': (10, 60),             # 10 per minute (mode changes should be rare)

    # Token management - very strict limits
    'create_token': (5, 60),          # 5 per minute
    'revoke_token': (10, 60),         # 10 per minute
    'list_tokens': (20, 60),          # 20 per minute
}


@dataclass
class CommandRateLimitEntry:
    """Tracks rate limiting for a specific command."""
    request_times: List[float] = field(default_factory=list)  # Monotonic timestamps
    blocked_until: Optional[float] = None  # Monotonic timestamp


@dataclass
class APIToken:
    """Represents an API authentication token."""
    token_id: str                          # Short identifier (first 8 chars of hash)
    token_hash: str                        # SHA-256 hash of the actual token
    name: str                              # Human-readable name
    capabilities: Set[APICapability]       # Granted capabilities
    created_at: datetime                   # When token was created
    expires_at: Optional[datetime] = None  # Expiration time (None = never)
    last_used: Optional[datetime] = None   # Last usage time
    created_by: str = "system"             # Who created this token
    revoked: bool = False                  # Whether token has been revoked
    use_count: int = 0                     # Number of times used
    metadata: Dict = field(default_factory=dict)  # Additional metadata

    def is_valid(self) -> Tuple[bool, str]:
        """Check if token is valid for use."""
        if self.revoked:
            return False, "Token has been revoked"

        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False, "Token has expired"

        return True, "Token is valid"

    def has_capability(self, capability: APICapability) -> bool:
        """Check if token has a specific capability."""
        # ADMIN capability grants all permissions
        if APICapability.ADMIN in self.capabilities:
            return True
        return capability in self.capabilities

    def to_dict(self) -> Dict:
        """Convert to dictionary for storage/display."""
        return {
            'token_id': self.token_id,
            'token_hash': self.token_hash,
            'name': self.name,
            'capabilities': [c.name for c in self.capabilities],
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'created_by': self.created_by,
            'revoked': self.revoked,
            'use_count': self.use_count,
            'metadata': self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'APIToken':
        """Create from dictionary."""
        return cls(
            token_id=data['token_id'],
            token_hash=data['token_hash'],
            name=data['name'],
            capabilities={APICapability[c] for c in data['capabilities']},
            created_at=datetime.fromisoformat(data['created_at']),
            expires_at=datetime.fromisoformat(data['expires_at']) if data.get('expires_at') else None,
            last_used=datetime.fromisoformat(data['last_used']) if data.get('last_used') else None,
            created_by=data.get('created_by', 'system'),
            revoked=data.get('revoked', False),
            use_count=data.get('use_count', 0),
            metadata=data.get('metadata', {}),
        )


@dataclass
class RateLimitEntry:
    """Tracks rate limiting for a client using monotonic time."""
    request_times: List[float] = field(default_factory=list)  # Monotonic timestamps
    blocked_until: Optional[float] = None  # Monotonic timestamp


@dataclass
class GlobalRateLimitState:
    """Tracks global rate limiting across all tokens."""
    request_times: List[float] = field(default_factory=list)  # Monotonic timestamps
    blocked_until: Optional[float] = None  # Monotonic timestamp
    total_requests: int = 0  # Total requests ever
    blocked_count: int = 0  # Number of times global limit was hit


class TokenManager:
    """
    Manages API tokens with secure storage and rate limiting.

    Token Storage:
    - Tokens are stored as SHA-256 hashes (never plaintext)
    - Token file is chmod 600 (owner read/write only)
    - Supports token expiration and revocation

    Rate Limiting:
    - Per-token request rate limiting (prevents single token abuse)
    - Global rate limiting (prevents DDoS with multiple tokens)
    - Configurable windows and max requests
    - Automatic blocking on limit exceeded
    - Uses monotonic time to prevent clock manipulation
    """

    TOKEN_PREFIX = "bd_"  # Boundary Daemon token prefix
    TOKEN_LENGTH = 32     # 32 bytes = 256 bits of entropy

    def __init__(
        self,
        token_file: str = "./config/api_tokens.json",
        rate_limit_window: int = 60,      # 60 seconds
        rate_limit_max_requests: int = 100,  # 100 requests per window per token
        rate_limit_block_duration: int = 300,  # 5 minute block on limit exceeded
        global_rate_limit_window: int = 60,  # 60 seconds for global limit
        global_rate_limit_max_requests: int = 1000,  # 1000 total requests per window
        global_rate_limit_block_duration: int = 60,  # 1 minute global block
        event_logger=None,  # Optional EventLogger for rate limit events
        use_persistent_rate_limit: bool = True,  # SECURITY: Use persistent rate limiting
        rate_limit_state_file: str = None,  # Path to rate limit state file
    ):
        """
        Initialize token manager.

        Args:
            token_file: Path to token storage file
            rate_limit_window: Rate limit window in seconds (per token)
            rate_limit_max_requests: Max requests per window (per token)
            rate_limit_block_duration: Block duration in seconds when per-token limit exceeded
            global_rate_limit_window: Rate limit window in seconds (global)
            global_rate_limit_max_requests: Max total requests per window (global)
            global_rate_limit_block_duration: Block duration when global limit exceeded
            event_logger: Optional EventLogger instance for logging rate limit events
            use_persistent_rate_limit: Whether to use persistent rate limiting (survives restarts)
            rate_limit_state_file: Path to rate limit state file (default: /var/lib/boundary-daemon/rate_limits.json)
        """
        self.token_file = Path(token_file)
        self._event_logger = event_logger

        # Per-token rate limiting
        self.rate_limit_window = rate_limit_window
        self.rate_limit_max_requests = rate_limit_max_requests
        self.rate_limit_block_duration = rate_limit_block_duration

        # Global rate limiting
        self.global_rate_limit_window = global_rate_limit_window
        self.global_rate_limit_max_requests = global_rate_limit_max_requests
        self.global_rate_limit_block_duration = global_rate_limit_block_duration

        self._tokens: Dict[str, APIToken] = {}  # token_hash -> APIToken
        self._rate_limits: Dict[str, RateLimitEntry] = {}  # token_id -> RateLimitEntry
        self._command_rate_limits: Dict[str, Dict[str, CommandRateLimitEntry]] = {}  # token_id -> command -> entry
        self._global_rate_limit = GlobalRateLimitState()  # Global rate limit tracking
        self._lock = threading.RLock()

        # SECURITY: Initialize persistent rate limiter (survives daemon restarts)
        # This addresses the vulnerability: "Rate Limiting Bypass via Restart"
        self._persistent_rate_limiter = None
        if use_persistent_rate_limit and PERSISTENT_RATE_LIMIT_AVAILABLE and PersistentRateLimiter:
            try:
                self._persistent_rate_limiter = PersistentRateLimiter(
                    state_file=rate_limit_state_file,
                    rate_limit_window=rate_limit_window,
                    rate_limit_max_requests=rate_limit_max_requests,
                    rate_limit_block_duration=rate_limit_block_duration,
                    global_rate_limit_window=global_rate_limit_window,
                    global_rate_limit_max_requests=global_rate_limit_max_requests,
                    global_rate_limit_block_duration=global_rate_limit_block_duration,
                    event_logger=event_logger,
                )
                print("SECURITY: Persistent rate limiting enabled (survives restarts)")
            except Exception as e:
                print(f"Warning: Persistent rate limiting failed to initialize: {e}")
                print("WARNING: Rate limits will be reset on daemon restart!")
        elif use_persistent_rate_limit:
            print("WARNING: Persistent rate limiting not available")
            print("WARNING: Rate limits will be reset on daemon restart!")

        # Ensure config directory exists
        self.token_file.parent.mkdir(parents=True, exist_ok=True)

        # Load existing tokens
        self._load_tokens()

        # Create bootstrap token if no tokens exist
        if not self._tokens:
            self._create_bootstrap_token()

    def _hash_token(self, token: str) -> str:
        """Hash a token using SHA-256."""
        return hashlib.sha256(token.encode('utf-8')).hexdigest()

    def set_event_logger(self, event_logger):
        """Set the event logger for rate limit events."""
        self._event_logger = event_logger

    def _log_rate_limit_event(
        self,
        event_type: str,
        token_id: Optional[str] = None,
        token_name: Optional[str] = None,
        command: Optional[str] = None,
        limit: Optional[int] = None,
        window: Optional[int] = None,
        block_duration: Optional[int] = None,
        requests_in_window: Optional[int] = None,
    ):
        """Log a rate limit event if event logger is configured."""
        if not self._event_logger:
            return

        try:
            from daemon.event_logger import EventType as ET

            # Map string to EventType
            event_type_map = {
                'token': ET.RATE_LIMIT_TOKEN,
                'global': ET.RATE_LIMIT_GLOBAL,
                'command': ET.RATE_LIMIT_COMMAND,
                'unblock': ET.RATE_LIMIT_UNBLOCK,
            }
            et = event_type_map.get(event_type)
            if not et:
                return

            data = {}
            if token_id:
                data['token_id'] = token_id
            if token_name:
                data['token_name'] = token_name
            if command:
                data['command'] = command
            if limit is not None:
                data['limit'] = limit
            if window is not None:
                data['window_seconds'] = window
            if block_duration is not None:
                data['block_duration'] = block_duration
            if requests_in_window is not None:
                data['requests_in_window'] = requests_in_window

            self._event_logger.log_event(event_type=et, data=data)
        except Exception:
            pass  # Don't fail on logging errors

    def _generate_token(self) -> str:
        """Generate a secure random token."""
        random_bytes = secrets.token_bytes(self.TOKEN_LENGTH)
        token_body = secrets.token_urlsafe(self.TOKEN_LENGTH)
        return f"{self.TOKEN_PREFIX}{token_body}"

    def _load_tokens(self):
        """Load tokens from storage file."""
        if not self.token_file.exists():
            return

        try:
            with open(self.token_file, 'r') as f:
                data = json.load(f)

            for token_data in data.get('tokens', []):
                token = APIToken.from_dict(token_data)
                self._tokens[token.token_hash] = token

        except Exception as e:
            print(f"Warning: Failed to load tokens: {e}")

    def _save_tokens(self):
        """Save tokens to storage file."""
        try:
            data = {
                'version': 1,
                'updated_at': datetime.utcnow().isoformat(),
                'tokens': [t.to_dict() for t in self._tokens.values()],
            }

            # Write atomically
            temp_file = self.token_file.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            # Set permissions before rename
            os.chmod(temp_file, 0o600)

            # Atomic rename
            temp_file.rename(self.token_file)

        except Exception as e:
            print(f"Warning: Failed to save tokens: {e}")

    def _create_bootstrap_token(self) -> str:
        """
        Create initial admin token on first run.

        SECURITY: Bootstrap token is now encrypted at rest to prevent
        plaintext credential exposure. Use 'authctl decrypt' to retrieve.

        Addresses Critical Finding: "Insecure Token Storage"
        """
        token, _ = self.create_token(
            name="bootstrap-admin",
            capabilities={'admin'},
            created_by="system",
            expires_in_days=None,  # Never expires
        )

        # Write bootstrap token to an ENCRYPTED file for initial setup
        bootstrap_file = self.token_file.parent / 'bootstrap_token.enc'

        try:
            from daemon.auth.secure_token_storage import SecureTokenStorage

            storage = SecureTokenStorage()
            success, msg = storage.encrypt_bootstrap_token(
                token=token,
                output_path=str(bootstrap_file),
            )

            if success:
                print(f"[AUTH] Bootstrap admin token created (ENCRYPTED): {bootstrap_file}")
                print(f"[AUTH] To retrieve: authctl decrypt {bootstrap_file}")
            else:
                # Fallback to secure-ish plaintext with strong warnings
                self._write_bootstrap_fallback(token, bootstrap_file.with_suffix('.txt'))

        except ImportError:
            # SecureTokenStorage not available, use fallback
            self._write_bootstrap_fallback(token, bootstrap_file.with_suffix('.txt'))

        return token

    def _write_bootstrap_fallback(self, token: str, bootstrap_file: Path):
        """
        Fallback for writing bootstrap token when encryption is unavailable.
        Writes with strong security warnings.
        """
        with open(bootstrap_file, 'w') as f:
            f.write("# SECURITY WARNING: PLAINTEXT TOKEN FILE\n")
            f.write("#\n")
            f.write("# Boundary Daemon Bootstrap Token\n")
            f.write(f"# Created: {datetime.utcnow().isoformat()}\n")
            f.write("#\n")
            f.write("# !!! DELETE THIS FILE AFTER RETRIEVING THE TOKEN !!!\n")
            f.write("# !!! DO NOT COMMIT THIS FILE TO VERSION CONTROL !!!\n")
            f.write("# !!! STORE THE TOKEN IN A SECRETS MANAGER !!!\n")
            f.write("#\n")
            f.write("# This token has full admin access. Use it to create other tokens.\n")
            f.write("#\n")
            f.write(f"{token}\n")
        os.chmod(bootstrap_file, 0o600)

        print(f"[AUTH] WARNING: Bootstrap token created as PLAINTEXT: {bootstrap_file}")
        print(f"[AUTH] Delete this file after retrieving the token!")

    def create_token(
        self,
        name: str,
        capabilities: Set[str],
        created_by: str = "system",
        expires_in_days: Optional[int] = 365,
        metadata: Optional[Dict] = None,
    ) -> Tuple[str, APIToken]:
        """
        Create a new API token.

        Args:
            name: Human-readable name for the token
            capabilities: Set of capability names or predefined set name
            created_by: Who is creating this token
            expires_in_days: Days until expiration (None = never)
            metadata: Additional metadata to store

        Returns:
            (raw_token, token_object) - raw_token is only returned once!
        """
        with self._lock:
            # Generate token
            raw_token = self._generate_token()
            token_hash = self._hash_token(raw_token)
            token_id = token_hash[:8]

            # Parse capabilities
            parsed_caps: Set[APICapability] = set()
            for cap in capabilities:
                if cap in CAPABILITY_SETS:
                    # It's a predefined set name
                    parsed_caps.update(CAPABILITY_SETS[cap])
                else:
                    # It's an individual capability
                    try:
                        parsed_caps.add(APICapability[cap.upper()])
                    except KeyError:
                        raise ValueError(f"Unknown capability: {cap}")

            # Calculate expiration
            expires_at = None
            if expires_in_days is not None:
                expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

            # Create token object
            token = APIToken(
                token_id=token_id,
                token_hash=token_hash,
                name=name,
                capabilities=parsed_caps,
                created_at=datetime.utcnow(),
                expires_at=expires_at,
                created_by=created_by,
                metadata=metadata or {},
            )

            # Store and save
            self._tokens[token_hash] = token
            self._save_tokens()

            return raw_token, token

    def validate_token(self, raw_token: str) -> Tuple[bool, Optional[APIToken], str]:
        """
        Validate a raw token string.

        Args:
            raw_token: The token to validate

        Returns:
            (is_valid, token_object, error_message)
        """
        if not raw_token:
            return False, None, "No token provided"

        # Check token format
        if not raw_token.startswith(self.TOKEN_PREFIX):
            return False, None, "Invalid token format"

        # Hash and lookup
        token_hash = self._hash_token(raw_token)

        with self._lock:
            # Check global rate limit first (before token lookup)
            is_global_allowed, global_reason = self._check_global_rate_limit()
            if not is_global_allowed:
                return False, None, global_reason

            token = self._tokens.get(token_hash)

            if not token:
                return False, None, "Token not found"

            # Check validity
            is_valid, reason = token.is_valid()
            if not is_valid:
                return False, token, reason

            # Check per-token rate limit
            is_allowed, rate_reason = self._check_rate_limit(token.token_id)
            if not is_allowed:
                return False, token, rate_reason

            # Update usage stats
            token.last_used = datetime.utcnow()
            token.use_count += 1
            self._save_tokens()

            return True, token, "Valid"

    def check_capability(
        self,
        raw_token: str,
        command: str,
    ) -> Tuple[bool, Optional[APIToken], str]:
        """
        Validate token and check if it has capability for a command.

        Args:
            raw_token: The token to validate
            command: The API command being executed

        Returns:
            (is_authorized, token_object, error_message)
        """
        # First validate the token
        is_valid, token, reason = self.validate_token(raw_token)
        if not is_valid:
            return False, token, reason

        # Get required capability for command
        required_cap = COMMAND_CAPABILITIES.get(command)
        if required_cap is None:
            # Unknown command - deny by default (fail-closed)
            return False, token, f"Unknown command: {command}"

        # Check capability
        if not token.has_capability(required_cap):
            return False, token, f"Token lacks capability: {required_cap.name}"

        # Check per-command rate limit
        is_cmd_allowed, cmd_reason = self._check_command_rate_limit(token.token_id, command)
        if not is_cmd_allowed:
            return False, token, cmd_reason

        return True, token, "Authorized"

    def _check_global_rate_limit(self) -> Tuple[bool, str]:
        """Check and update global rate limit across all tokens.

        SECURITY: Uses persistent rate limiter when available to survive restarts.
        Falls back to monotonic time-based rate limiting otherwise.
        Must be called within self._lock.
        """
        # SECURITY: Use persistent rate limiter if available (survives restarts)
        if self._persistent_rate_limiter:
            return self._persistent_rate_limiter.check_global_rate_limit()

        # Fallback: in-memory rate limiting (resets on restart)
        now = time.monotonic()
        state = self._global_rate_limit

        # Check if currently blocked
        if state.blocked_until and now < state.blocked_until:
            remaining = int(state.blocked_until - now)
            return False, f"Global rate limit exceeded. Try again in {remaining}s"

        # Clear block if expired (log unblock event)
        if state.blocked_until:
            state.blocked_until = None
            self._log_rate_limit_event(
                event_type='unblock',
                limit=self.global_rate_limit_max_requests,
                window=self.global_rate_limit_window,
            )

        # Remove old request times
        window_start = now - self.global_rate_limit_window
        state.request_times = [t for t in state.request_times if t > window_start]

        # Check if over limit
        if len(state.request_times) >= self.global_rate_limit_max_requests:
            state.blocked_until = now + self.global_rate_limit_block_duration
            state.blocked_count += 1
            # Log global rate limit exceeded event
            self._log_rate_limit_event(
                event_type='global',
                limit=self.global_rate_limit_max_requests,
                window=self.global_rate_limit_window,
                block_duration=self.global_rate_limit_block_duration,
                requests_in_window=len(state.request_times),
            )
            return False, f"Global rate limit exceeded ({self.global_rate_limit_max_requests} req/{self.global_rate_limit_window}s). Blocked for {self.global_rate_limit_block_duration}s"

        # Record this request
        state.request_times.append(now)
        state.total_requests += 1

        return True, "OK"

    def _check_rate_limit(self, token_id: str) -> Tuple[bool, str]:
        """Check and update rate limit for a token.

        SECURITY: Uses persistent rate limiter when available to survive restarts.
        Falls back to monotonic time-based rate limiting otherwise.
        """
        # SECURITY: Use persistent rate limiter if available (survives restarts)
        if self._persistent_rate_limiter:
            return self._persistent_rate_limiter.check_rate_limit(token_id)

        # Fallback: in-memory rate limiting (resets on restart)
        now = time.monotonic()  # Monotonic clock cannot be manipulated

        with self._lock:
            entry = self._rate_limits.get(token_id)

            if entry is None:
                entry = RateLimitEntry()
                self._rate_limits[token_id] = entry

            # Check if currently blocked
            if entry.blocked_until and now < entry.blocked_until:
                remaining = int(entry.blocked_until - now)
                return False, f"Rate limited. Try again in {remaining}s"

            # Clear block if expired (log unblock event)
            if entry.blocked_until:
                entry.blocked_until = None
                self._log_rate_limit_event(
                    event_type='unblock',
                    token_id=token_id,
                    limit=self.rate_limit_max_requests,
                    window=self.rate_limit_window,
                )

            # Remove old request times
            window_start = now - self.rate_limit_window
            entry.request_times = [t for t in entry.request_times if t > window_start]

            # Check if over limit
            if len(entry.request_times) >= self.rate_limit_max_requests:
                entry.blocked_until = now + self.rate_limit_block_duration
                # Log per-token rate limit exceeded event
                self._log_rate_limit_event(
                    event_type='token',
                    token_id=token_id,
                    limit=self.rate_limit_max_requests,
                    window=self.rate_limit_window,
                    block_duration=self.rate_limit_block_duration,
                    requests_in_window=len(entry.request_times),
                )
                return False, f"Rate limit exceeded. Blocked for {self.rate_limit_block_duration}s"

            # Record this request
            entry.request_times.append(now)

            return True, "OK"

    def _check_command_rate_limit(self, token_id: str, command: str) -> Tuple[bool, str]:
        """Check and update rate limit for a specific command.

        Per-command rate limits allow different limits for different operations.
        For example, read-only 'status' can have higher limits than 'set_mode'.

        SECURITY: Uses persistent rate limiter when available to survive restarts.
        Falls back to monotonic time-based rate limiting otherwise.
        """
        # Check if this command has a specific rate limit
        if command not in COMMAND_RATE_LIMITS:
            return True, "OK"  # No per-command limit, use global/per-token only

        max_requests, window_seconds = COMMAND_RATE_LIMITS[command]

        # SECURITY: Use persistent rate limiter if available (survives restarts)
        if self._persistent_rate_limiter:
            return self._persistent_rate_limiter.check_command_rate_limit(
                token_id=token_id,
                command=command,
                max_requests=max_requests,
                window=window_seconds,
            )

        # Fallback: in-memory rate limiting (resets on restart)
        now = time.monotonic()

        with self._lock:
            # Get or create per-token command rate limit dict
            if token_id not in self._command_rate_limits:
                self._command_rate_limits[token_id] = {}

            token_commands = self._command_rate_limits[token_id]

            # Get or create entry for this command
            if command not in token_commands:
                token_commands[command] = CommandRateLimitEntry()

            entry = token_commands[command]

            # Check if currently blocked (block duration = 1/2 of window for commands)
            block_duration = window_seconds // 2 or 30
            if entry.blocked_until and now < entry.blocked_until:
                remaining = int(entry.blocked_until - now)
                return False, f"Command '{command}' rate limited. Try again in {remaining}s"

            # Clear block if expired (log unblock event)
            if entry.blocked_until:
                entry.blocked_until = None
                self._log_rate_limit_event(
                    event_type='unblock',
                    token_id=token_id,
                    command=command,
                    limit=max_requests,
                    window=window_seconds,
                )

            # Remove old request times
            window_start = now - window_seconds
            entry.request_times = [t for t in entry.request_times if t > window_start]

            # Check if over limit
            if len(entry.request_times) >= max_requests:
                entry.blocked_until = now + block_duration
                # Log per-command rate limit exceeded event
                self._log_rate_limit_event(
                    event_type='command',
                    token_id=token_id,
                    command=command,
                    limit=max_requests,
                    window=window_seconds,
                    block_duration=block_duration,
                    requests_in_window=len(entry.request_times),
                )
                return False, f"Command '{command}' rate limit exceeded ({max_requests} req/{window_seconds}s). Blocked for {block_duration}s"

            # Record this request
            entry.request_times.append(now)

            return True, "OK"

    def revoke_token(self, token_id: str, revoked_by: str = "system") -> Tuple[bool, str]:
        """
        Revoke a token by its ID.

        Args:
            token_id: Token ID (first 8 chars of hash)
            revoked_by: Who is revoking

        Returns:
            (success, message)
        """
        with self._lock:
            # Find token by ID
            target = None
            for token in self._tokens.values():
                if token.token_id == token_id:
                    target = token
                    break

            if not target:
                return False, f"Token not found: {token_id}"

            if target.revoked:
                return False, f"Token already revoked: {token_id}"

            target.revoked = True
            target.metadata['revoked_by'] = revoked_by
            target.metadata['revoked_at'] = datetime.utcnow().isoformat()

            self._save_tokens()

            return True, f"Token revoked: {token_id}"

    def list_tokens(self, include_revoked: bool = False) -> List[Dict]:
        """
        List all tokens (without exposing hashes).

        Args:
            include_revoked: Whether to include revoked tokens

        Returns:
            List of token info dicts (without full hash)
        """
        with self._lock:
            result = []
            for token in self._tokens.values():
                if not include_revoked and token.revoked:
                    continue

                info = token.to_dict()
                # Remove full hash for security
                del info['token_hash']

                # Add validity status
                is_valid, reason = token.is_valid()
                info['is_valid'] = is_valid
                info['status'] = reason if not is_valid else 'active'

                result.append(info)

            return sorted(result, key=lambda x: x['created_at'], reverse=True)

    def get_token_by_id(self, token_id: str) -> Optional[APIToken]:
        """Get token by its ID."""
        with self._lock:
            for token in self._tokens.values():
                if token.token_id == token_id:
                    return token
            return None

    def cleanup_expired(self) -> int:
        """Remove expired tokens from storage. Returns count removed."""
        with self._lock:
            now = datetime.utcnow()
            to_remove = []

            for token_hash, token in self._tokens.items():
                if token.expires_at and now > token.expires_at:
                    # Keep for audit but mark expired
                    if not token.revoked:
                        token.revoked = True
                        token.metadata['auto_expired'] = True
                        token.metadata['expired_at'] = now.isoformat()

            if to_remove:
                self._save_tokens()

            return len(to_remove)

    def get_rate_limit_status(self, token_id: str) -> Dict:
        """Get rate limit status for a token.

        Uses monotonic time for accurate tracking regardless of clock changes.
        """
        with self._lock:
            entry = self._rate_limits.get(token_id)
            if not entry:
                return {
                    'requests_in_window': 0,
                    'max_requests': self.rate_limit_max_requests,
                    'window_seconds': self.rate_limit_window,
                    'blocked': False,
                    'blocked_remaining_seconds': 0,
                }

            now = time.monotonic()
            window_start = now - self.rate_limit_window
            current_requests = len([t for t in entry.request_times if t > window_start])

            is_blocked = entry.blocked_until is not None and now < entry.blocked_until
            blocked_remaining = max(0, int(entry.blocked_until - now)) if is_blocked else 0

            return {
                'requests_in_window': current_requests,
                'max_requests': self.rate_limit_max_requests,
                'window_seconds': self.rate_limit_window,
                'blocked': is_blocked,
                'blocked_remaining_seconds': blocked_remaining,
            }

    def get_global_rate_limit_status(self) -> Dict:
        """Get global rate limit status across all tokens.

        Returns:
            Dict with global rate limit information
        """
        with self._lock:
            state = self._global_rate_limit
            now = time.monotonic()

            window_start = now - self.global_rate_limit_window
            current_requests = len([t for t in state.request_times if t > window_start])

            is_blocked = state.blocked_until is not None and now < state.blocked_until
            blocked_remaining = max(0, int(state.blocked_until - now)) if is_blocked else 0

            return {
                'requests_in_window': current_requests,
                'max_requests': self.global_rate_limit_max_requests,
                'window_seconds': self.global_rate_limit_window,
                'blocked': is_blocked,
                'blocked_remaining_seconds': blocked_remaining,
                'total_requests_ever': state.total_requests,
                'times_blocked': state.blocked_count,
                'utilization_percent': round(current_requests / self.global_rate_limit_max_requests * 100, 1),
            }

    def get_all_rate_limit_status(self) -> Dict:
        """Get combined rate limit status (global + all tokens).

        Returns:
            Dict with global and per-token rate limit information
        """
        with self._lock:
            result = {
                'global': self.get_global_rate_limit_status(),
                'tokens': {},
            }

            for token in self._tokens.values():
                if token.token_id in self._rate_limits:
                    result['tokens'][token.token_id] = {
                        'name': token.name,
                        'status': self.get_rate_limit_status(token.token_id),
                        'commands': self.get_command_rate_limit_status(token.token_id),
                    }

            return result

    def get_command_rate_limit_status(self, token_id: str) -> Dict:
        """Get per-command rate limit status for a token.

        Returns:
            Dict mapping command names to their rate limit status
        """
        with self._lock:
            result = {}
            now = time.monotonic()

            token_commands = self._command_rate_limits.get(token_id, {})

            for command, entry in token_commands.items():
                if command not in COMMAND_RATE_LIMITS:
                    continue

                max_requests, window_seconds = COMMAND_RATE_LIMITS[command]
                window_start = now - window_seconds
                current_requests = len([t for t in entry.request_times if t > window_start])

                is_blocked = entry.blocked_until is not None and now < entry.blocked_until
                blocked_remaining = max(0, int(entry.blocked_until - now)) if is_blocked else 0

                result[command] = {
                    'requests_in_window': current_requests,
                    'max_requests': max_requests,
                    'window_seconds': window_seconds,
                    'blocked': is_blocked,
                    'blocked_remaining_seconds': blocked_remaining,
                    'utilization_percent': round(current_requests / max_requests * 100, 1) if max_requests > 0 else 0,
                }

            return result

    def get_command_rate_limits_config(self) -> Dict:
        """Get the configured per-command rate limits.

        Returns:
            Dict mapping command names to (max_requests, window_seconds)
        """
        return {cmd: {'max_requests': limit[0], 'window_seconds': limit[1]}
                for cmd, limit in COMMAND_RATE_LIMITS.items()}

    def get_rate_limit_headers(self, token_id: str, command: Optional[str] = None) -> Dict[str, Any]:
        """Get rate limit information for inclusion in API responses.

        Returns headers following common API rate limiting conventions:
        - X-RateLimit-Limit: Max requests allowed per window
        - X-RateLimit-Remaining: Requests remaining in current window
        - X-RateLimit-Reset: Seconds until window resets
        - X-RateLimit-Global-*: Same for global limits
        - X-RateLimit-Command-*: Same for per-command limits (if applicable)

        Args:
            token_id: The token ID to get rate limit info for
            command: Optional command name for per-command rate limit info

        Returns:
            Dict with rate limit header values
        """
        headers = {}
        now = time.monotonic()

        with self._lock:
            # Per-token rate limit info
            entry = self._rate_limits.get(token_id)
            if entry:
                window_start = now - self.rate_limit_window
                current_requests = len([t for t in entry.request_times if t > window_start])
                remaining = max(0, self.rate_limit_max_requests - current_requests)

                # Calculate reset time (seconds until oldest request falls out of window)
                if entry.request_times:
                    oldest_in_window = min([t for t in entry.request_times if t > window_start], default=now)
                    reset_seconds = max(0, int(self.rate_limit_window - (now - oldest_in_window)))
                else:
                    reset_seconds = self.rate_limit_window

                headers['X-RateLimit-Limit'] = self.rate_limit_max_requests
                headers['X-RateLimit-Remaining'] = remaining
                headers['X-RateLimit-Reset'] = reset_seconds
                headers['X-RateLimit-Window'] = self.rate_limit_window

                if entry.blocked_until and now < entry.blocked_until:
                    headers['X-RateLimit-Blocked'] = True
                    headers['X-RateLimit-Retry-After'] = int(entry.blocked_until - now)
            else:
                headers['X-RateLimit-Limit'] = self.rate_limit_max_requests
                headers['X-RateLimit-Remaining'] = self.rate_limit_max_requests
                headers['X-RateLimit-Reset'] = self.rate_limit_window
                headers['X-RateLimit-Window'] = self.rate_limit_window

            # Global rate limit info
            state = self._global_rate_limit
            window_start = now - self.global_rate_limit_window
            global_current = len([t for t in state.request_times if t > window_start])
            global_remaining = max(0, self.global_rate_limit_max_requests - global_current)

            headers['X-RateLimit-Global-Limit'] = self.global_rate_limit_max_requests
            headers['X-RateLimit-Global-Remaining'] = global_remaining

            if state.blocked_until and now < state.blocked_until:
                headers['X-RateLimit-Global-Blocked'] = True
                headers['X-RateLimit-Global-Retry-After'] = int(state.blocked_until - now)

            # Per-command rate limit info (if command specified and has limits)
            if command and command in COMMAND_RATE_LIMITS:
                max_requests, window_seconds = COMMAND_RATE_LIMITS[command]
                token_commands = self._command_rate_limits.get(token_id, {})
                cmd_entry = token_commands.get(command)

                if cmd_entry:
                    cmd_window_start = now - window_seconds
                    cmd_current = len([t for t in cmd_entry.request_times if t > cmd_window_start])
                    cmd_remaining = max(0, max_requests - cmd_current)

                    headers['X-RateLimit-Command'] = command
                    headers['X-RateLimit-Command-Limit'] = max_requests
                    headers['X-RateLimit-Command-Remaining'] = cmd_remaining
                    headers['X-RateLimit-Command-Window'] = window_seconds

                    if cmd_entry.blocked_until and now < cmd_entry.blocked_until:
                        headers['X-RateLimit-Command-Blocked'] = True
                        headers['X-RateLimit-Command-Retry-After'] = int(cmd_entry.blocked_until - now)
                else:
                    headers['X-RateLimit-Command'] = command
                    headers['X-RateLimit-Command-Limit'] = max_requests
                    headers['X-RateLimit-Command-Remaining'] = max_requests
                    headers['X-RateLimit-Command-Window'] = window_seconds

        return headers


class AuthenticationMiddleware:
    """
    Middleware for authenticating API requests.

    Integrates with BoundaryAPIServer to validate tokens and check capabilities.
    """

    def __init__(self, token_manager: TokenManager, require_auth: bool = True):
        """
        Initialize middleware.

        Args:
            token_manager: TokenManager instance
            require_auth: Whether authentication is required (False allows anonymous read-only)
        """
        self.token_manager = token_manager
        self.require_auth = require_auth

    def authenticate_request(
        self,
        request: Dict,
    ) -> Tuple[bool, Optional[APIToken], str]:
        """
        Authenticate an API request.

        Args:
            request: The API request dict (should contain 'token' field)

        Returns:
            (is_authorized, token, error_message)
        """
        command = request.get('command', '')
        token_str = request.get('token')

        # Check if auth is required
        if not self.require_auth and not token_str:
            # Anonymous access - only allow read-only commands
            if command in {'status', 'verify_log'}:
                return True, None, "Anonymous read-only access"
            return False, None, "Authentication required for this command"

        if not token_str:
            return False, None, "No authentication token provided"

        # Validate token and check capability
        return self.token_manager.check_capability(token_str, command)


# Convenience function for creating a new token manager
def create_token_manager(
    token_file: str = "./config/api_tokens.json",
    **kwargs
) -> TokenManager:
    """Create and return a TokenManager instance."""
    return TokenManager(token_file=token_file, **kwargs)


if __name__ == '__main__':
    # Test token management
    print("Testing API Authentication...")

    # Create manager with test file
    manager = TokenManager(token_file="./test_tokens.json")

    # Create a test token
    print("\n1. Creating readonly token...")
    token, token_obj = manager.create_token(
        name="test-readonly",
        capabilities={'readonly'},
        expires_in_days=30,
    )
    print(f"   Token: {token[:20]}...")
    print(f"   ID: {token_obj.token_id}")
    print(f"   Capabilities: {[c.name for c in token_obj.capabilities]}")

    # Validate token
    print("\n2. Validating token...")
    is_valid, validated_token, reason = manager.validate_token(token)
    print(f"   Valid: {is_valid}, Reason: {reason}")

    # Check capability
    print("\n3. Checking capabilities...")
    can_status, _, _ = manager.check_capability(token, 'status')
    can_set_mode, _, msg = manager.check_capability(token, 'set_mode')
    print(f"   Can get status: {can_status}")
    print(f"   Can set mode: {can_set_mode} ({msg})")

    # Create admin token
    print("\n4. Creating admin token...")
    admin_token, admin_obj = manager.create_token(
        name="test-admin",
        capabilities={'admin'},
    )
    print(f"   Token: {admin_token[:20]}...")

    # Admin can do everything
    print("\n5. Admin capability check...")
    can_manage, _, _ = manager.check_capability(admin_token, 'create_token')
    print(f"   Admin can manage tokens: {can_manage}")

    # List tokens
    print("\n6. Listing tokens...")
    tokens = manager.list_tokens()
    for t in tokens:
        print(f"   - {t['name']} ({t['token_id']}): {t['status']}")

    # Test rate limiting
    print("\n7. Testing rate limiting...")
    manager.rate_limit_max_requests = 5  # Low limit for testing
    for i in range(7):
        is_valid, _, reason = manager.validate_token(token)
        print(f"   Request {i+1}: {'OK' if is_valid else reason}")

    # Cleanup
    import os
    os.remove("./test_tokens.json")
    print("\nTest complete!")
