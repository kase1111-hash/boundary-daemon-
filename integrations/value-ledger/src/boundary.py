"""
Value Ledger Boundary Integration

FIXED VERSION: Corrects socket path and adds full integration.

This module provides boundary daemon integration for the Value Ledger,
the economic and evidentiary accounting layer.

SOCKET PATH FIX:
- OLD (wrong): /var/run/boundary-daemon/api.sock
- NEW (correct): /var/run/boundary-daemon/boundary.sock
"""

import json
import logging
import os
import socket
import time
from dataclasses import dataclass
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, Optional, Tuple, TypeVar

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
class PolicyDecision:
    """Result of a policy check."""
    permitted: bool
    reason: str
    mode: Optional[BoundaryMode] = None


class BoundaryError(Exception):
    """Base exception for boundary errors."""
    pass


class DaemonUnavailableError(BoundaryError):
    """Raised when daemon is not reachable."""
    pass


class OperationDeniedError(BoundaryError):
    """Raised when operation is denied."""
    pass


def get_socket_path() -> str:
    """
    Get the correct boundary daemon socket path.

    FIXED: Uses /var/run/boundary-daemon/boundary.sock
    (not /var/run/boundary-daemon/api.sock)
    """
    paths = [
        os.environ.get('BOUNDARY_DAEMON_SOCKET'),
        '/var/run/boundary-daemon/boundary.sock',  # FIXED: Correct path
        os.path.expanduser('~/.agent-os/api/boundary.sock'),
        './api/boundary.sock',
    ]

    for path in paths:
        if path and os.path.exists(path):
            return path

    # FIXED: Return correct default path
    return '/var/run/boundary-daemon/boundary.sock'


class BoundaryClient:
    """
    Boundary Daemon Client for Value Ledger.
    """

    def __init__(
        self,
        socket_path: Optional[str] = None,
        token: Optional[str] = None,
        max_retries: int = 3,
        timeout: float = 5.0,
    ):
        # FIXED: Use correct socket path
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

    def get_mode(self) -> BoundaryMode:
        """Get current boundary mode."""
        status = self.get_status()
        mode_str = status.get('mode', 'lockdown').lower()
        return BoundaryMode(mode_str)

    def check_operation(
        self,
        operation_name: str,
        requires_network: bool = False,
        requires_filesystem: bool = False,
    ) -> PolicyDecision:
        """
        Check if an operation is permitted.
        """
        try:
            response = self._send_request('check_tool', {
                'tool_name': f'value_ledger:{operation_name}',
                'requires_network': requires_network,
                'requires_filesystem': requires_filesystem,
            })
            return PolicyDecision(
                permitted=response.get('permitted', False),
                reason=response.get('reason', 'Unknown'),
            )
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Boundary daemon unavailable - fail closed",
            )

    def check_value_access(
        self,
        value_class: int,
        value_id: Optional[str] = None,
    ) -> PolicyDecision:
        """
        Check if value record access is permitted.
        """
        try:
            response = self._send_request('check_recall', {
                'memory_class': value_class,
                'memory_id': value_id,
            })
            return PolicyDecision(
                permitted=response.get('permitted', False),
                reason=response.get('reason', 'Unknown'),
            )
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Boundary daemon unavailable - fail closed",
            )


# =============================================================================
# Protected Operation Decorator (Fixed)
# =============================================================================

def protected_operation(
    requires_network: bool = False,
    requires_filesystem: bool = False,
    value_class: Optional[int] = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator that enforces boundary policy on ledger operations.

    Usage:
        @protected_operation(requires_network=True)
        def sync_to_remote():
            ...

        @protected_operation(value_class=2)
        def access_confidential_value():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            client = BoundaryClient()

            # Check operation permission
            decision = client.check_operation(
                operation_name=func.__name__,
                requires_network=requires_network,
                requires_filesystem=requires_filesystem,
            )

            if not decision.permitted:
                raise OperationDeniedError(
                    f"Operation '{func.__name__}' denied: {decision.reason}"
                )

            # Check value access if specified
            if value_class is not None:
                value_decision = client.check_value_access(value_class)
                if not value_decision.permitted:
                    raise OperationDeniedError(
                        f"Value access denied: {value_decision.reason}"
                    )

            return func(*args, **kwargs)
        return wrapper
    return decorator


# =============================================================================
# Interruption Tracking
# =============================================================================

class InterruptionTracker:
    """
    Tracks boundary violations and interruptions.

    Used by Value Ledger to record when operations were interrupted
    due to boundary policy.
    """

    def __init__(self, client: Optional[BoundaryClient] = None):
        self.client = client or BoundaryClient()
        self.interruptions: list = []

    def record_interruption(
        self,
        operation: str,
        reason: str,
        value_id: Optional[str] = None,
    ) -> None:
        """Record an interruption event."""
        interruption = {
            'timestamp': time.time(),
            'operation': operation,
            'reason': reason,
            'value_id': value_id,
            'mode': self.client.get_mode().value,
        }
        self.interruptions.append(interruption)
        logger.warning(f"Interruption recorded: {interruption}")

    def get_interruptions(
        self,
        since: Optional[float] = None,
    ) -> list:
        """Get recorded interruptions."""
        if since is None:
            return self.interruptions

        return [i for i in self.interruptions if i['timestamp'] >= since]

    def report_to_siem(self) -> bool:
        """Report interruptions to SIEM via daemon."""
        if not self.interruptions:
            return True

        try:
            for interruption in self.interruptions:
                self.client._send_request('check_message', {
                    'content': f"VALUE_LEDGER_INTERRUPTION:{json.dumps(interruption)}",
                    'source': 'value-ledger',
                    'context': {
                        'event_type': 'interruption',
                        **interruption,
                    },
                })
            return True
        except BoundaryError:
            return False


# =============================================================================
# Value Ledger Integration
# =============================================================================

class ValueLedgerBoundaryIntegration:
    """
    Main integration class for Value Ledger.

    Provides boundary-aware access to all ledger operations.
    """

    def __init__(self):
        self.client = BoundaryClient()
        self.interruption_tracker = InterruptionTracker(self.client)

    def is_available(self) -> bool:
        """Check if boundary daemon is available."""
        try:
            self.client.get_status()
            return True
        except DaemonUnavailableError:
            return False

    def get_mode(self) -> BoundaryMode:
        """Get current boundary mode."""
        return self.client.get_mode()

    def can_record_value(
        self,
        value_class: int = 0,
        requires_network: bool = False,
    ) -> Tuple[bool, str]:
        """
        Check if value recording is permitted.

        Args:
            value_class: Classification of the value being recorded
            requires_network: Whether network sync is needed

        Returns:
            (permitted, reason)
        """
        # Check operation permission
        op_decision = self.client.check_operation(
            operation_name='record_value',
            requires_network=requires_network,
            requires_filesystem=True,
        )

        if not op_decision.permitted:
            return False, op_decision.reason

        # Check value class permission
        value_decision = self.client.check_value_access(value_class)
        if not value_decision.permitted:
            return False, value_decision.reason

        return True, "Value recording permitted"

    def record_with_boundary(
        self,
        record_fn: Callable[[], T],
        value_class: int = 0,
        value_id: Optional[str] = None,
        requires_network: bool = False,
    ) -> Optional[T]:
        """
        Record value with boundary enforcement.

        Returns None and records interruption if denied.
        """
        permitted, reason = self.can_record_value(value_class, requires_network)

        if not permitted:
            self.interruption_tracker.record_interruption(
                operation='record_value',
                reason=reason,
                value_id=value_id,
            )
            return None

        return record_fn()

    def on_mode_change(
        self,
        callback: Callable[[BoundaryMode, BoundaryMode], None],
    ) -> None:
        """
        Register callback for mode changes.

        Polls for mode changes (no push notification available).
        """
        import threading

        def poll_loop():
            last_mode = self.client.get_mode()
            while True:
                time.sleep(1.0)
                try:
                    current_mode = self.client.get_mode()
                    if current_mode != last_mode:
                        callback(current_mode, last_mode)
                        last_mode = current_mode
                except BoundaryError:
                    pass

        thread = threading.Thread(target=poll_loop, daemon=True)
        thread.start()


# =============================================================================
# Convenience Functions
# =============================================================================

def check_boundary() -> Tuple[bool, str]:
    """
    Quick check if boundary daemon is available and mode is not LOCKDOWN.

    Returns:
        (available_and_not_locked, status_message)
    """
    client = BoundaryClient()
    try:
        status = client.get_status()
        mode = status.get('mode', 'lockdown').lower()

        if mode == 'lockdown':
            return False, "System in LOCKDOWN mode"

        return True, f"Boundary available in {mode} mode"
    except DaemonUnavailableError:
        return False, "Boundary daemon unavailable"


def require_boundary(func: Callable[..., T]) -> Callable[..., T]:
    """
    Simple decorator that requires boundary availability.

    Raises OperationDeniedError if daemon unavailable or in LOCKDOWN.
    """
    @wraps(func)
    def wrapper(*args, **kwargs) -> T:
        available, message = check_boundary()
        if not available:
            raise OperationDeniedError(message)
        return func(*args, **kwargs)
    return wrapper
