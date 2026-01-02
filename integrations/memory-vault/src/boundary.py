"""
Memory Vault Boundary Integration

This module provides the CORRECT boundary daemon integration for Memory Vault.
Replaces the existing `boundry.py` (note: fixes typo in filename).

INTEGRATION REQUIREMENT:
Per INTEGRATION.md, Memory Vault MUST call boundary daemon before:
- Any memory recall
- Any memory storage
- Connection establishment

Usage:
    from boundary import RecallGate, check_recall

    # Before retrieving memory
    gate = RecallGate()
    if gate.can_recall(memory_class=3):
        memory = vault.retrieve(memory_id)

    # Or direct function
    permitted, reason = check_recall(classification=3)
"""

import json
import logging
import os
import socket
import time
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Any, Callable, Dict, Optional, Tuple, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar('T')


class OperationalMode(Enum):
    """Boundary operational modes."""
    OPEN = "open"
    RESTRICTED = "restricted"
    TRUSTED = "trusted"
    AIRGAP = "airgap"
    COLDROOM = "coldroom"
    LOCKDOWN = "lockdown"


class MemoryClassification(IntEnum):
    """Memory classification levels matching boundary-daemon."""
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3
    TOP_SECRET = 4
    CROWN_JEWEL = 5


@dataclass
class RecallDecision:
    """Result of a recall permission check."""
    permitted: bool
    reason: str
    mode: Optional[OperationalMode] = None
    requires_human_approval: bool = False
    requires_cooldown: bool = False


@dataclass
class ConnectionGrant:
    """Result of a connection protection request."""
    granted: bool
    token: Optional[str] = None
    expires_at: Optional[str] = None
    reason: str = ""


class BoundaryError(Exception):
    """Base exception for boundary errors."""
    pass


class DaemonUnavailableError(BoundaryError):
    """Raised when daemon is not reachable."""
    pass


class RecallDeniedError(BoundaryError):
    """Raised when recall is denied."""
    pass


def get_socket_path() -> str:
    """
    Get the boundary daemon socket path.

    Checks in order:
    1. BOUNDARY_DAEMON_SOCKET environment variable
    2. /var/run/boundary-daemon/boundary.sock (production)
    3. ~/.agent-os/api/boundary.sock (user mode)
    4. ./api/boundary.sock (development)
    """
    paths = [
        os.environ.get('BOUNDARY_DAEMON_SOCKET'),
        '/var/run/boundary-daemon/boundary.sock',
        os.path.expanduser('~/.agent-os/api/boundary.sock'),
        './api/boundary.sock',
    ]

    for path in paths:
        if path and os.path.exists(path):
            return path

    # Default to production path
    return '/var/run/boundary-daemon/boundary.sock'


class BoundaryClient:
    """
    Boundary Daemon Client for Memory Vault.

    Provides recall gating, connection protection, and status checking.
    """

    def __init__(
        self,
        socket_path: Optional[str] = None,
        token: Optional[str] = None,
        max_retries: int = 3,
        timeout: float = 5.0,
    ):
        self.socket_path = socket_path or get_socket_path()
        self._token = token or os.environ.get('BOUNDARY_API_TOKEN')
        self.max_retries = max_retries
        self.timeout = timeout

    def _send_request(
        self,
        command: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send request with retry logic."""
        request = {'command': command, 'params': params or {}}
        if self._token:
            request['token'] = self._token

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall(json.dumps(request).encode('utf-8'))
                data = sock.recv(65536)
                sock.close()
                return json.loads(data.decode('utf-8'))
            except (ConnectionRefusedError, FileNotFoundError, socket.timeout) as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    time.sleep(0.5 * (2 ** attempt))
            finally:
                try:
                    sock.close()
                except:
                    pass

        raise DaemonUnavailableError(f"Daemon unavailable: {last_error}")

    def get_status(self) -> Dict[str, Any]:
        """Get daemon status."""
        try:
            response = self._send_request('status')
            return response.get('status', {})
        except DaemonUnavailableError:
            return {'mode': 'lockdown', 'online': False}

    def get_mode(self) -> OperationalMode:
        """Get current operational mode."""
        status = self.get_status()
        mode_str = status.get('mode', 'lockdown').lower()
        return OperationalMode(mode_str)

    def check_recall(
        self,
        classification: int,
        memory_id: Optional[str] = None,
    ) -> RecallDecision:
        """
        Check if memory recall is permitted.

        Args:
            classification: Memory classification level (0-5)
            memory_id: Optional memory identifier

        Returns:
            RecallDecision with permit/deny and reason
        """
        params = {'memory_class': classification}
        if memory_id:
            params['memory_id'] = memory_id

        try:
            response = self._send_request('check_recall', params)
        except DaemonUnavailableError:
            return RecallDecision(
                permitted=False,
                reason="Boundary daemon unavailable - fail closed",
            )

        return RecallDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def request_connection_protection(
        self,
        database_path: str,
        target_path: str,
        duration_seconds: int = 3600,
    ) -> ConnectionGrant:
        """
        Request connection protection for database access.

        Args:
            database_path: Path to the database
            target_path: Target path being accessed
            duration_seconds: Duration of protection grant

        Returns:
            ConnectionGrant with token if successful
        """
        # Use check_tool with special parameters
        params = {
            'tool_name': 'memory_vault_connection',
            'requires_filesystem': True,
            'context': {
                'database_path': database_path,
                'target_path': target_path,
                'duration': duration_seconds,
            },
        }

        try:
            response = self._send_request('check_tool', params)
        except DaemonUnavailableError:
            return ConnectionGrant(
                granted=False,
                reason="Boundary daemon unavailable",
            )

        if response.get('permitted'):
            return ConnectionGrant(
                granted=True,
                token=response.get('token'),
                expires_at=response.get('expires_at'),
                reason="Connection protection granted",
            )

        return ConnectionGrant(
            granted=False,
            reason=response.get('reason', 'Protection denied'),
        )


class RecallGate:
    """
    Gate for memory recall operations.

    MANDATORY: Must be called before any memory recall.

    Usage:
        gate = RecallGate()

        # Method 1: Explicit check
        if gate.can_recall(memory_class=3):
            memory = vault.retrieve(memory_id)

        # Method 2: Raise on denial
        gate.require_recall(memory_class=3)
        memory = vault.retrieve(memory_id)

        # Method 3: With fallback
        memory = gate.recall_or_default(
            memory_class=3,
            recall_fn=lambda: vault.retrieve(memory_id),
            default=None,
        )
    """

    def __init__(self, client: Optional[BoundaryClient] = None):
        self.client = client or BoundaryClient()
        self._last_decision: Optional[RecallDecision] = None

    @property
    def last_decision(self) -> Optional[RecallDecision]:
        """Get the last recall decision."""
        return self._last_decision

    def can_recall(
        self,
        memory_class: int,
        memory_id: Optional[str] = None,
    ) -> bool:
        """
        Check if recall is permitted.

        Args:
            memory_class: Memory classification (0-5)
            memory_id: Optional memory identifier

        Returns:
            True if recall is permitted
        """
        decision = self.client.check_recall(memory_class, memory_id)
        self._last_decision = decision

        if decision.permitted:
            logger.debug(f"Recall permitted: class={memory_class}, id={memory_id}")
        else:
            logger.warning(f"Recall denied: {decision.reason}")

        return decision.permitted

    def require_recall(
        self,
        memory_class: int,
        memory_id: Optional[str] = None,
    ) -> None:
        """
        Require recall permission, raising exception if denied.

        Args:
            memory_class: Memory classification
            memory_id: Optional memory identifier

        Raises:
            RecallDeniedError: If recall is not permitted
        """
        if not self.can_recall(memory_class, memory_id):
            raise RecallDeniedError(
                f"Recall denied for class {memory_class}: {self._last_decision.reason}"
            )

    def recall_or_default(
        self,
        memory_class: int,
        recall_fn: Callable[[], T],
        default: T = None,
        memory_id: Optional[str] = None,
    ) -> T:
        """
        Recall memory if permitted, otherwise return default.

        Args:
            memory_class: Memory classification
            recall_fn: Function to call if permitted
            default: Default value if denied
            memory_id: Optional memory identifier

        Returns:
            Result of recall_fn or default
        """
        if self.can_recall(memory_class, memory_id):
            return recall_fn()
        return default


# Convenience functions

def check_recall(classification: int, memory_id: Optional[str] = None) -> Tuple[bool, str]:
    """
    Check recall permission (convenience function).

    Args:
        classification: Memory classification (0-5)
        memory_id: Optional memory identifier

    Returns:
        (permitted, reason)
    """
    client = BoundaryClient()
    decision = client.check_recall(classification, memory_id)
    return decision.permitted, decision.reason


def get_current_mode() -> OperationalMode:
    """Get current boundary mode."""
    client = BoundaryClient()
    return client.get_mode()


def is_airgap_mode() -> bool:
    """Check if currently in AIRGAP mode or higher."""
    mode = get_current_mode()
    return mode in [OperationalMode.AIRGAP, OperationalMode.COLDROOM, OperationalMode.LOCKDOWN]


# Decorator for protected recall

def require_boundary_check(
    memory_class: int,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator that requires boundary check before memory access.

    Usage:
        @require_boundary_check(memory_class=2)
        def get_confidential_data(memory_id):
            return vault.retrieve(memory_id)
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args, **kwargs) -> T:
            gate = RecallGate()
            gate.require_recall(memory_class)
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Memory Vault Integration Example

class MemoryVaultBoundaryMixin:
    """
    Mixin class for Memory Vault to add boundary integration.

    Add this to your MemoryVault class:

        class MemoryVault(MemoryVaultBoundaryMixin, BaseVault):
            pass
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._boundary_client = BoundaryClient()
        self._recall_gate = RecallGate(self._boundary_client)

    def retrieve(self, memory_id: str, classification: int = 0):
        """
        Retrieve memory with boundary check.

        This method adds boundary enforcement to the base retrieve method.
        """
        # MANDATORY: Check with boundary daemon first
        self._recall_gate.require_recall(classification, memory_id)

        # Proceed with retrieval (call parent method)
        return super().retrieve(memory_id)

    def store(self, memory_id: str, data: Any, classification: int = 0):
        """
        Store memory with boundary check.

        Storage also requires boundary permission.
        """
        # Check tool permission for storage
        decision = self._boundary_client.check_tool(
            tool_name='memory_vault_store',
            requires_filesystem=True,
        )
        if not decision.permitted:
            raise RecallDeniedError(f"Storage denied: {decision.reason}")

        # Check classification permission
        recall_decision = self._boundary_client.check_recall(classification)
        if not recall_decision.permitted:
            raise RecallDeniedError(f"Storage denied for class {classification}: {recall_decision.reason}")

        return super().store(memory_id, data)

    def get_boundary_status(self) -> Dict[str, Any]:
        """Get current boundary daemon status."""
        return self._boundary_client.get_status()

    def is_boundary_available(self) -> bool:
        """Check if boundary daemon is available."""
        try:
            self._boundary_client.get_status()
            return True
        except DaemonUnavailableError:
            return False
