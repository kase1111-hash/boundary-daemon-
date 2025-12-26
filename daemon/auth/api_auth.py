"""
API Authentication - Token-based authentication for Boundary Daemon API.

Provides:
- Secure token generation and storage
- Capability-based access control
- Rate limiting
- Token lifecycle management (create, revoke, expire)
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
from typing import Dict, List, Optional, Set, Tuple


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
}


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


class TokenManager:
    """
    Manages API tokens with secure storage and rate limiting.

    Token Storage:
    - Tokens are stored as SHA-256 hashes (never plaintext)
    - Token file is chmod 600 (owner read/write only)
    - Supports token expiration and revocation

    Rate Limiting:
    - Per-token request rate limiting
    - Configurable window and max requests
    - Automatic blocking on limit exceeded
    """

    TOKEN_PREFIX = "bd_"  # Boundary Daemon token prefix
    TOKEN_LENGTH = 32     # 32 bytes = 256 bits of entropy

    def __init__(
        self,
        token_file: str = "./config/api_tokens.json",
        rate_limit_window: int = 60,      # 60 seconds
        rate_limit_max_requests: int = 100,  # 100 requests per window
        rate_limit_block_duration: int = 300,  # 5 minute block on limit exceeded
    ):
        """
        Initialize token manager.

        Args:
            token_file: Path to token storage file
            rate_limit_window: Rate limit window in seconds
            rate_limit_max_requests: Max requests per window
            rate_limit_block_duration: Block duration in seconds when limit exceeded
        """
        self.token_file = Path(token_file)
        self.rate_limit_window = rate_limit_window
        self.rate_limit_max_requests = rate_limit_max_requests
        self.rate_limit_block_duration = rate_limit_block_duration

        self._tokens: Dict[str, APIToken] = {}  # token_hash -> APIToken
        self._rate_limits: Dict[str, RateLimitEntry] = {}  # token_id -> RateLimitEntry
        self._lock = threading.RLock()

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
        """Create initial admin token on first run."""
        token, _ = self.create_token(
            name="bootstrap-admin",
            capabilities={'admin'},
            created_by="system",
            expires_in_days=None,  # Never expires
        )

        # Write bootstrap token to a separate file for initial setup
        bootstrap_file = self.token_file.parent / 'bootstrap_token.txt'
        with open(bootstrap_file, 'w') as f:
            f.write(f"# Boundary Daemon Bootstrap Token\n")
            f.write(f"# Created: {datetime.utcnow().isoformat()}\n")
            f.write(f"# WARNING: Store this securely and delete this file after setup!\n")
            f.write(f"#\n")
            f.write(f"# This token has full admin access. Use it to create other tokens.\n")
            f.write(f"#\n")
            f.write(f"{token}\n")
        os.chmod(bootstrap_file, 0o600)

        print(f"[AUTH] Bootstrap admin token created: {bootstrap_file}")
        return token

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
            token = self._tokens.get(token_hash)

            if not token:
                return False, None, "Token not found"

            # Check validity
            is_valid, reason = token.is_valid()
            if not is_valid:
                return False, token, reason

            # Check rate limit
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

        return True, token, "Authorized"

    def _check_rate_limit(self, token_id: str) -> Tuple[bool, str]:
        """Check and update rate limit for a token.

        Uses monotonic time to prevent clock manipulation attacks.
        """
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

            # Clear block if expired
            if entry.blocked_until:
                entry.blocked_until = None

            # Remove old request times
            window_start = now - self.rate_limit_window
            entry.request_times = [t for t in entry.request_times if t > window_start]

            # Check if over limit
            if len(entry.request_times) >= self.rate_limit_max_requests:
                entry.blocked_until = now + self.rate_limit_block_duration
                return False, f"Rate limit exceeded. Blocked for {self.rate_limit_block_duration}s"

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
