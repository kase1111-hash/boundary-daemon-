"""
Shared Boundary Daemon Client for Python Integrations

This is the base client that all Python integrations should use.
It provides fail-closed semantics, automatic retry, and token management.
"""

import json
import logging
import os
import socket
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar('T')


class BoundaryMode(Enum):
    """Boundary security modes."""
    OPEN = "open"
    RESTRICTED = "restricted"
    TRUSTED = "trusted"
    AIRGAP = "airgap"
    COLDROOM = "coldroom"
    LOCKDOWN = "lockdown"


class MemoryClass(Enum):
    """Memory classification levels."""
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3
    TOP_SECRET = 4
    CROWN_JEWEL = 5


@dataclass
class BoundaryStatus:
    """Current boundary daemon status."""
    mode: BoundaryMode
    online: bool
    network_state: str
    hardware_trust: str
    lockdown_active: bool
    tripwire_count: int
    uptime_seconds: float

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BoundaryStatus':
        return cls(
            mode=BoundaryMode(data.get('mode', 'lockdown').lower()),
            online=data.get('online', False),
            network_state=data.get('network_state', 'unknown'),
            hardware_trust=data.get('hardware_trust', 'low'),
            lockdown_active=data.get('lockdown_active', True),
            tripwire_count=data.get('tripwire_count', 0),
            uptime_seconds=data.get('uptime_seconds', 0),
        )


@dataclass
class PolicyDecision:
    """Result of a policy check."""
    permitted: bool
    reason: str
    mode: Optional[BoundaryMode] = None
    requires_ceremony: bool = False


class BoundaryDaemonError(Exception):
    """Base exception for boundary daemon errors."""
    pass


class DaemonUnavailableError(BoundaryDaemonError):
    """Raised when daemon is not reachable."""
    pass


class AuthenticationError(BoundaryDaemonError):
    """Raised when authentication fails."""
    pass


class PolicyDeniedError(BoundaryDaemonError):
    """Raised when policy denies an operation."""
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
    # Environment variable takes precedence
    env_path = os.environ.get('BOUNDARY_DAEMON_SOCKET')
    if env_path and os.path.exists(env_path):
        return env_path

    # Production path
    prod_path = '/var/run/boundary-daemon/boundary.sock'
    if os.path.exists(prod_path):
        return prod_path

    # User mode path
    user_path = os.path.expanduser('~/.agent-os/api/boundary.sock')
    if os.path.exists(user_path):
        return user_path

    # Development path
    dev_path = './api/boundary.sock'
    if os.path.exists(dev_path):
        return dev_path

    # Default to production path even if not exists (will fail with clear error)
    return prod_path


class BoundaryClient:
    """
    Universal Boundary Daemon Client.

    Provides fail-closed access to boundary daemon with automatic retry,
    token management, and comprehensive error handling.
    """

    def __init__(
        self,
        socket_path: Optional[str] = None,
        token: Optional[str] = None,
        token_file: Optional[str] = None,
        max_retries: int = 3,
        retry_delay: float = 0.5,
        timeout: float = 5.0,
        fail_closed: bool = True,
    ):
        """
        Initialize boundary client.

        Args:
            socket_path: Path to Unix socket (auto-detected if None)
            token: API token for authentication
            token_file: Path to file containing API token
            max_retries: Maximum retry attempts on connection failure
            retry_delay: Initial delay between retries (exponential backoff)
            timeout: Socket timeout in seconds
            fail_closed: If True, deny operations when daemon unavailable
        """
        self.socket_path = socket_path or get_socket_path()
        self._token = self._resolve_token(token, token_file)
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout = timeout
        self.fail_closed = fail_closed
        self._status_cache: Optional[Tuple[BoundaryStatus, float]] = None
        self._cache_ttl = 1.0  # Cache status for 1 second

    def _resolve_token(
        self,
        token: Optional[str],
        token_file: Optional[str],
    ) -> Optional[str]:
        """Resolve token from various sources."""
        if token:
            return token.strip()

        if token_file:
            try:
                with open(token_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            return line
            except (IOError, OSError) as e:
                logger.warning(f"Could not read token file: {e}")

        # Try environment variable
        env_token = os.environ.get('BOUNDARY_API_TOKEN')
        if env_token:
            return env_token.strip()

        return None

    def _send_request(
        self,
        command: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send request with retry logic."""
        request = {
            'command': command,
            'params': params or {},
        }
        if self._token:
            request['token'] = self._token

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                return self._send_once(request)
            except (ConnectionRefusedError, FileNotFoundError, socket.timeout) as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    delay = self.retry_delay * (2 ** attempt)
                    logger.debug(f"Retry {attempt + 1}/{self.max_retries} after {delay}s: {e}")
                    time.sleep(delay)

        # All retries failed
        if self.fail_closed:
            raise DaemonUnavailableError(
                f"Boundary daemon unavailable after {self.max_retries} attempts: {last_error}"
            )
        return {'success': False, 'error': str(last_error)}

    def _send_once(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send a single request."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
            sock.sendall(json.dumps(request).encode('utf-8'))
            data = sock.recv(65536)
            return json.loads(data.decode('utf-8'))
        finally:
            sock.close()

    def get_status(self, use_cache: bool = True) -> BoundaryStatus:
        """
        Get current daemon status.

        Args:
            use_cache: If True, return cached status if fresh

        Returns:
            Current boundary status
        """
        if use_cache and self._status_cache:
            status, timestamp = self._status_cache
            if time.time() - timestamp < self._cache_ttl:
                return status

        response = self._send_request('status')
        if not response.get('success'):
            if self.fail_closed:
                # Return locked down status
                return BoundaryStatus(
                    mode=BoundaryMode.LOCKDOWN,
                    online=False,
                    network_state='unknown',
                    hardware_trust='low',
                    lockdown_active=True,
                    tripwire_count=0,
                    uptime_seconds=0,
                )
            raise BoundaryDaemonError(response.get('error', 'Unknown error'))

        status = BoundaryStatus.from_dict(response.get('status', {}))
        self._status_cache = (status, time.time())
        return status

    def get_mode(self) -> BoundaryMode:
        """Get current boundary mode."""
        return self.get_status().mode

    def is_available(self) -> bool:
        """Check if daemon is available."""
        try:
            self.get_status(use_cache=False)
            return True
        except BoundaryDaemonError:
            return False

    def check_recall(
        self,
        memory_class: int,
        memory_id: Optional[str] = None,
    ) -> PolicyDecision:
        """
        Check if memory recall is permitted.

        Args:
            memory_class: Memory classification level (0-5)
            memory_id: Optional memory identifier for logging

        Returns:
            Policy decision with permit/deny and reason
        """
        params = {'memory_class': memory_class}
        if memory_id:
            params['memory_id'] = memory_id

        try:
            response = self._send_request('check_recall', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Boundary daemon unavailable - fail closed",
            )

        if response.get('auth_error'):
            raise AuthenticationError(response.get('error', 'Authentication failed'))

        return PolicyDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def check_tool(
        self,
        tool_name: str,
        requires_network: bool = False,
        requires_filesystem: bool = False,
        requires_usb: bool = False,
    ) -> PolicyDecision:
        """
        Check if tool execution is permitted.

        Args:
            tool_name: Name of the tool
            requires_network: Tool needs network access
            requires_filesystem: Tool needs filesystem access
            requires_usb: Tool needs USB access

        Returns:
            Policy decision with permit/deny and reason
        """
        params = {
            'tool_name': tool_name,
            'requires_network': requires_network,
            'requires_filesystem': requires_filesystem,
            'requires_usb': requires_usb,
        }

        try:
            response = self._send_request('check_tool', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Boundary daemon unavailable - fail closed",
            )

        return PolicyDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def check_message(
        self,
        content: str,
        source: str = 'unknown',
        context: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Check message content for policy compliance.

        Args:
            content: Message content to check
            source: Source system identifier
            context: Additional context

        Returns:
            Policy decision
        """
        params = {'content': content, 'source': source}
        if context:
            params['context'] = context

        try:
            response = self._send_request('check_message', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Boundary daemon unavailable - fail closed",
            )

        return PolicyDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def check_natlangchain(
        self,
        author: str,
        intent: str,
        timestamp: str,
        signature: Optional[str] = None,
        previous_hash: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Check a NatLangChain blockchain entry.

        Args:
            author: Entry author
            intent: Intent description (prose)
            timestamp: Entry timestamp (ISO format)
            signature: Cryptographic signature
            previous_hash: Hash of previous entry
            metadata: Additional metadata

        Returns:
            Policy decision
        """
        params = {
            'author': author,
            'intent': intent,
            'timestamp': timestamp,
        }
        if signature:
            params['signature'] = signature
        if previous_hash:
            params['previous_hash'] = previous_hash
        if metadata:
            params['metadata'] = metadata

        try:
            response = self._send_request('check_natlangchain', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Boundary daemon unavailable - fail closed",
            )

        return PolicyDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def check_agentos(
        self,
        sender_agent: str,
        recipient_agent: str,
        content: str,
        message_type: str = 'request',
        authority_level: int = 0,
        timestamp: Optional[str] = None,
        requires_consent: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Check an Agent-OS inter-agent message.

        Args:
            sender_agent: Sending agent identifier
            recipient_agent: Receiving agent identifier
            content: Message content
            message_type: Type of message
            authority_level: Authority level (0-5)
            timestamp: Message timestamp
            requires_consent: Whether consent is required
            metadata: Additional metadata

        Returns:
            Policy decision
        """
        params = {
            'sender_agent': sender_agent,
            'recipient_agent': recipient_agent,
            'content': content,
            'message_type': message_type,
            'authority_level': authority_level,
            'requires_consent': requires_consent,
        }
        if timestamp:
            params['timestamp'] = timestamp
        if metadata:
            params['metadata'] = metadata

        try:
            response = self._send_request('check_agentos', params)
        except DaemonUnavailableError:
            return PolicyDecision(
                permitted=False,
                reason="Boundary daemon unavailable - fail closed",
            )

        return PolicyDecision(
            permitted=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
        )

    def set_mode(
        self,
        mode: BoundaryMode,
        operator: str = 'human',
        reason: str = '',
    ) -> Tuple[bool, str]:
        """
        Request mode change.

        Args:
            mode: Target boundary mode
            operator: Who is requesting (human|system)
            reason: Reason for change

        Returns:
            (success, message)
        """
        params = {
            'mode': mode.value,
            'operator': operator,
            'reason': reason,
        }
        response = self._send_request('set_mode', params)
        return (
            response.get('success', False),
            response.get('message', response.get('error', '')),
        )

    def verify_log(self) -> Tuple[bool, Optional[str]]:
        """
        Verify event log integrity.

        Returns:
            (is_valid, error_message)
        """
        response = self._send_request('verify_log')
        return (
            response.get('valid', False),
            response.get('error'),
        )


# Decorators for easy integration

def require_boundary_check(
    operation_type: str = 'tool',
    **check_kwargs,
) -> Callable:
    """
    Decorator that requires boundary check before execution.

    Args:
        operation_type: 'tool', 'recall', or 'message'
        **check_kwargs: Arguments passed to the check function
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args, **kwargs) -> T:
            client = BoundaryClient()

            if operation_type == 'tool':
                decision = client.check_tool(
                    tool_name=func.__name__,
                    **check_kwargs,
                )
            elif operation_type == 'recall':
                decision = client.check_recall(**check_kwargs)
            elif operation_type == 'message':
                decision = client.check_message(**check_kwargs)
            else:
                raise ValueError(f"Unknown operation type: {operation_type}")

            if not decision.permitted:
                raise PolicyDeniedError(
                    f"Operation '{func.__name__}' denied: {decision.reason}"
                )

            return func(*args, **kwargs)
        return wrapper
    return decorator


def boundary_protected(
    requires_network: bool = False,
    requires_filesystem: bool = False,
    requires_usb: bool = False,
    memory_class: Optional[int] = None,
) -> Callable:
    """
    Decorator that enforces boundary policies on a function.

    Args:
        requires_network: Function needs network access
        requires_filesystem: Function needs filesystem access
        requires_usb: Function needs USB access
        memory_class: If set, check recall permission for this class
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args, **kwargs) -> T:
            client = BoundaryClient()

            # Check tool permissions
            tool_decision = client.check_tool(
                tool_name=func.__name__,
                requires_network=requires_network,
                requires_filesystem=requires_filesystem,
                requires_usb=requires_usb,
            )
            if not tool_decision.permitted:
                raise PolicyDeniedError(
                    f"Tool '{func.__name__}' denied: {tool_decision.reason}"
                )

            # Check memory permissions if specified
            if memory_class is not None:
                recall_decision = client.check_recall(memory_class=memory_class)
                if not recall_decision.permitted:
                    raise PolicyDeniedError(
                        f"Memory access denied: {recall_decision.reason}"
                    )

            return func(*args, **kwargs)
        return wrapper
    return decorator


# Context manager for boundary-aware operations

class BoundaryContext:
    """
    Context manager for boundary-aware operations.

    Usage:
        with BoundaryContext(requires_network=True) as ctx:
            if ctx.permitted:
                do_network_operation()
            else:
                handle_denial(ctx.reason)
    """

    def __init__(
        self,
        tool_name: str = 'context_operation',
        requires_network: bool = False,
        requires_filesystem: bool = False,
        requires_usb: bool = False,
        memory_class: Optional[int] = None,
        raise_on_deny: bool = False,
    ):
        self.tool_name = tool_name
        self.requires_network = requires_network
        self.requires_filesystem = requires_filesystem
        self.requires_usb = requires_usb
        self.memory_class = memory_class
        self.raise_on_deny = raise_on_deny
        self.client = BoundaryClient()
        self.permitted = False
        self.reason = ""
        self.mode: Optional[BoundaryMode] = None

    def __enter__(self) -> 'BoundaryContext':
        # Get current mode
        try:
            status = self.client.get_status()
            self.mode = status.mode
        except BoundaryDaemonError as e:
            self.permitted = False
            self.reason = str(e)
            if self.raise_on_deny:
                raise PolicyDeniedError(self.reason)
            return self

        # Check tool permission
        decision = self.client.check_tool(
            tool_name=self.tool_name,
            requires_network=self.requires_network,
            requires_filesystem=self.requires_filesystem,
            requires_usb=self.requires_usb,
        )

        if not decision.permitted:
            self.permitted = False
            self.reason = decision.reason
            if self.raise_on_deny:
                raise PolicyDeniedError(self.reason)
            return self

        # Check memory permission if specified
        if self.memory_class is not None:
            recall_decision = self.client.check_recall(memory_class=self.memory_class)
            if not recall_decision.permitted:
                self.permitted = False
                self.reason = recall_decision.reason
                if self.raise_on_deny:
                    raise PolicyDeniedError(self.reason)
                return self

        self.permitted = True
        self.reason = "Operation permitted"
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Log operation completion if needed
        pass
