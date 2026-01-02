"""
NatLangChain Boundary Integration

Provides boundary daemon integration for the NatLangChain protocol,
validating blockchain entries before recording.

NatLangChain is a prose-first blockchain that records human intent.
The boundary daemon validates entries for:
- Content policy compliance
- Author verification
- Intent classification
- Chain integrity
"""

import json
import logging
import os
import socket
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar('T')


class BoundaryMode(Enum):
    """Boundary operational modes."""
    OPEN = "open"
    RESTRICTED = "restricted"
    TRUSTED = "trusted"
    AIRGAP = "airgap"
    COLDROOM = "coldroom"
    LOCKDOWN = "lockdown"


@dataclass
class EntryValidationResult:
    """Result of entry validation."""
    valid: bool
    reason: str
    warnings: List[str] = None
    required_mode: Optional[BoundaryMode] = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


@dataclass
class ChainEntry:
    """NatLangChain entry for validation."""
    author: str
    intent: str
    timestamp: str
    signature: Optional[str] = None
    previous_hash: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class BoundaryError(Exception):
    """Base exception for boundary errors."""
    pass


class ValidationDeniedError(BoundaryError):
    """Raised when validation is denied."""
    pass


def get_socket_path() -> str:
    """Get boundary daemon socket path."""
    paths = [
        os.environ.get('BOUNDARY_DAEMON_SOCKET'),
        '/var/run/boundary-daemon/boundary.sock',
        os.path.expanduser('~/.agent-os/api/boundary.sock'),
        './api/boundary.sock',
    ]
    for path in paths:
        if path and os.path.exists(path):
            return path
    return '/var/run/boundary-daemon/boundary.sock'


class BoundaryClient:
    """Boundary client for NatLangChain."""

    def __init__(
        self,
        socket_path: Optional[str] = None,
        token: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.socket_path = socket_path or get_socket_path()
        self._token = token or os.environ.get('BOUNDARY_API_TOKEN')
        self.timeout = timeout

    def _send_request(self, command: str, params: Dict = None) -> Dict:
        """Send request to daemon."""
        request = {'command': command, 'params': params or {}}
        if self._token:
            request['token'] = self._token

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
            sock.sendall(json.dumps(request).encode('utf-8'))
            data = sock.recv(65536)
            return json.loads(data.decode('utf-8'))
        except (ConnectionRefusedError, FileNotFoundError) as e:
            return {'success': False, 'error': f'Daemon unavailable: {e}'}
        finally:
            sock.close()

    def get_mode(self) -> BoundaryMode:
        """Get current boundary mode."""
        response = self._send_request('status')
        mode_str = response.get('status', {}).get('mode', 'lockdown').lower()
        return BoundaryMode(mode_str)

    def check_entry(self, entry: ChainEntry) -> EntryValidationResult:
        """
        Check if a NatLangChain entry is valid.

        Uses the boundary daemon's check_natlangchain command.
        """
        params = {
            'author': entry.author,
            'intent': entry.intent,
            'timestamp': entry.timestamp,
        }
        if entry.signature:
            params['signature'] = entry.signature
        if entry.previous_hash:
            params['previous_hash'] = entry.previous_hash
        if entry.metadata:
            params['metadata'] = entry.metadata

        response = self._send_request('check_natlangchain', params)

        if not response.get('success'):
            return EntryValidationResult(
                valid=False,
                reason=response.get('error', 'Unknown error'),
            )

        result = response.get('result', {})
        return EntryValidationResult(
            valid=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
            warnings=result.get('warnings', []),
            required_mode=BoundaryMode(result['required_mode']) if result.get('required_mode') else None,
        )

    def check_intent_content(self, intent: str) -> Tuple[bool, str]:
        """Check intent content for policy compliance."""
        response = self._send_request('check_message', {
            'content': intent,
            'source': 'natlangchain',
            'context': {'type': 'intent'},
        })

        return (
            response.get('permitted', False),
            response.get('reason', 'Unknown'),
        )


class EntryValidator:
    """
    Validates NatLangChain entries against boundary policy.

    Usage:
        validator = EntryValidator()

        # Validate before recording
        result = validator.validate(entry)
        if result.valid:
            chain.record(entry)
        else:
            logger.error(f"Entry rejected: {result.reason}")
    """

    def __init__(self, client: Optional[BoundaryClient] = None):
        self.client = client or BoundaryClient()

    def validate(self, entry: ChainEntry) -> EntryValidationResult:
        """
        Validate an entry for recording.

        Checks:
        1. Entry structure and required fields
        2. Content policy compliance
        3. Author verification
        4. Mode requirements
        """
        # Check basic structure
        if not entry.author:
            return EntryValidationResult(valid=False, reason="Author required")
        if not entry.intent:
            return EntryValidationResult(valid=False, reason="Intent required")
        if not entry.timestamp:
            return EntryValidationResult(valid=False, reason="Timestamp required")

        # Check with boundary daemon
        return self.client.check_entry(entry)

    def require_validation(self, entry: ChainEntry) -> None:
        """
        Require entry validation, raising exception if invalid.

        Raises:
            ValidationDeniedError: If entry is not valid
        """
        result = self.validate(entry)
        if not result.valid:
            raise ValidationDeniedError(result.reason)

    def can_record_in_mode(self, entry: ChainEntry, mode: BoundaryMode) -> bool:
        """Check if entry can be recorded in specified mode."""
        result = self.validate(entry)

        if not result.valid:
            return False

        if result.required_mode:
            mode_rank = {
                BoundaryMode.OPEN: 0,
                BoundaryMode.RESTRICTED: 1,
                BoundaryMode.TRUSTED: 2,
                BoundaryMode.AIRGAP: 3,
                BoundaryMode.COLDROOM: 4,
                BoundaryMode.LOCKDOWN: 5,
            }
            return mode_rank.get(mode, 0) >= mode_rank.get(result.required_mode, 0)

        return True


class ChainGate:
    """
    Gate for NatLangChain operations.

    Enforces boundary policy on all chain operations.
    """

    def __init__(self, client: Optional[BoundaryClient] = None):
        self.client = client or BoundaryClient()
        self.validator = EntryValidator(self.client)

    def can_record(self, entry: ChainEntry) -> Tuple[bool, str]:
        """Check if entry can be recorded."""
        result = self.validator.validate(entry)
        return result.valid, result.reason

    def can_query(self) -> Tuple[bool, str]:
        """Check if chain can be queried."""
        mode = self.client.get_mode()

        if mode == BoundaryMode.LOCKDOWN:
            return False, "Chain query denied in LOCKDOWN mode"

        return True, "Chain query permitted"

    def can_broadcast(self) -> Tuple[bool, str]:
        """Check if entries can be broadcast to network."""
        mode = self.client.get_mode()

        if mode in [BoundaryMode.AIRGAP, BoundaryMode.COLDROOM, BoundaryMode.LOCKDOWN]:
            return False, f"Broadcasting denied in {mode.value} mode"

        return True, "Broadcasting permitted"


# =============================================================================
# NatLangChain Hooks
# =============================================================================

def before_record_hook(entry: ChainEntry) -> None:
    """
    Hook to call before recording an entry.

    Install in NatLangChain:
        chain.add_hook('before_record', before_record_hook)
    """
    gate = ChainGate()
    can_record, reason = gate.can_record(entry)

    if not can_record:
        raise ValidationDeniedError(f"Entry recording denied: {reason}")


def before_broadcast_hook(entries: List[ChainEntry]) -> None:
    """
    Hook to call before broadcasting entries.

    Install in NatLangChain:
        chain.add_hook('before_broadcast', before_broadcast_hook)
    """
    gate = ChainGate()
    can_broadcast, reason = gate.can_broadcast()

    if not can_broadcast:
        raise ValidationDeniedError(f"Broadcasting denied: {reason}")


# =============================================================================
# Decorator
# =============================================================================

def require_chain_validation(func: Callable[..., T]) -> Callable[..., T]:
    """
    Decorator that requires chain validation before execution.

    The decorated function must take a ChainEntry as first argument.
    """
    from functools import wraps

    @wraps(func)
    def wrapper(entry: ChainEntry, *args, **kwargs) -> T:
        validator = EntryValidator()
        validator.require_validation(entry)
        return func(entry, *args, **kwargs)

    return wrapper


# =============================================================================
# Integration Class
# =============================================================================

class NatLangChainBoundaryIntegration:
    """
    Main integration class for NatLangChain.

    Provides comprehensive boundary enforcement for the protocol.
    """

    def __init__(self):
        self.client = BoundaryClient()
        self.gate = ChainGate(self.client)
        self.validator = EntryValidator(self.client)

    def is_available(self) -> bool:
        """Check if boundary daemon is available."""
        try:
            self.client.get_mode()
            return True
        except:
            return False

    def get_mode(self) -> BoundaryMode:
        """Get current boundary mode."""
        return self.client.get_mode()

    def validate_entry(self, entry: ChainEntry) -> EntryValidationResult:
        """Validate an entry."""
        return self.validator.validate(entry)

    def can_record(self, entry: ChainEntry) -> Tuple[bool, str]:
        """Check if entry can be recorded."""
        return self.gate.can_record(entry)

    def can_broadcast(self) -> Tuple[bool, str]:
        """Check if broadcasting is permitted."""
        return self.gate.can_broadcast()

    def install_hooks(self, chain) -> None:
        """
        Install boundary hooks on a NatLangChain instance.

        Args:
            chain: NatLangChain instance with add_hook method
        """
        if hasattr(chain, 'add_hook'):
            chain.add_hook('before_record', before_record_hook)
            chain.add_hook('before_broadcast', before_broadcast_hook)
            logger.info("Boundary hooks installed on NatLangChain")
        else:
            logger.warning("Chain does not support hooks")
