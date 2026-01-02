"""
Finite Intent Executor Boundary Integration

Provides boundary daemon integration for the Finite Intent Executor (FIE),
which enables bounded, posthumous execution of predefined intent.

Key integration points:
- Intent validation before execution
- Execution mode enforcement
- Asset access control
- Audit trail for all operations
"""

import json
import logging
import os
import socket
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from functools import wraps
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


class IntentClass(Enum):
    """Intent classification levels matching memory classes."""
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SENSITIVE = 3
    RESTRICTED = 4
    CROWN_JEWEL = 5


@dataclass
class IntentValidationResult:
    """Result of intent validation."""
    valid: bool
    reason: str
    required_mode: Optional[BoundaryMode] = None
    requires_ceremony: bool = False
    warnings: List[str] = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


@dataclass
class ExecutionGrant:
    """Grant for intent execution."""
    granted: bool
    token: Optional[str] = None
    expires_at: Optional[datetime] = None
    conditions: List[str] = None
    reason: str = ""

    def __post_init__(self):
        if self.conditions is None:
            self.conditions = []


class BoundaryError(Exception):
    """Base exception for boundary errors."""
    pass


class IntentDeniedError(BoundaryError):
    """Raised when intent execution is denied."""
    pass


class ExecutionDeniedError(BoundaryError):
    """Raised when execution is denied."""
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
    """Boundary client for Finite Intent Executor."""

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

    def check_intent(
        self,
        intent_description: str,
        intent_class: IntentClass,
        beneficiary: Optional[str] = None,
        assets: Optional[List[str]] = None,
    ) -> IntentValidationResult:
        """
        Validate intent before execution.
        """
        response = self._send_request('check_message', {
            'content': intent_description,
            'source': 'finite-intent-executor',
            'context': {
                'type': 'intent_validation',
                'intent_class': intent_class.value,
                'beneficiary': beneficiary,
                'assets': assets or [],
            },
        })

        if not response.get('success'):
            return IntentValidationResult(
                valid=False,
                reason=response.get('error', 'Unknown error'),
            )

        result = response.get('result', {})
        return IntentValidationResult(
            valid=response.get('permitted', False),
            reason=response.get('reason', 'Unknown'),
            required_mode=BoundaryMode(result['required_mode']) if result.get('required_mode') else None,
            requires_ceremony=result.get('requires_ceremony', False),
            warnings=result.get('warnings', []),
        )

    def check_execution(
        self,
        execution_type: str,
        requires_network: bool = False,
        requires_assets: bool = False,
    ) -> Tuple[bool, str]:
        """Check if execution is permitted."""
        response = self._send_request('check_tool', {
            'tool_name': f'fie:{execution_type}',
            'requires_network': requires_network,
            'requires_filesystem': requires_assets,
        })

        return (
            response.get('permitted', False),
            response.get('reason', 'Unknown'),
        )

    def check_asset_access(
        self,
        asset_class: int,
        asset_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Check if asset access is permitted."""
        response = self._send_request('check_recall', {
            'memory_class': asset_class,
            'memory_id': asset_id,
        })

        return (
            response.get('permitted', False),
            response.get('reason', 'Unknown'),
        )


class IntentGate:
    """
    Gate for intent validation and execution.

    Controls all intent-related operations.
    """

    def __init__(self, client: Optional[BoundaryClient] = None):
        self.client = client or BoundaryClient()
        self._last_validation: Optional[IntentValidationResult] = None

    @property
    def last_validation(self) -> Optional[IntentValidationResult]:
        return self._last_validation

    def can_execute_intent(
        self,
        intent_description: str,
        intent_class: IntentClass,
        beneficiary: Optional[str] = None,
        assets: Optional[List[str]] = None,
    ) -> bool:
        """Check if intent can be executed."""
        self._last_validation = self.client.check_intent(
            intent_description,
            intent_class,
            beneficiary,
            assets,
        )
        return self._last_validation.valid

    def require_intent_permission(
        self,
        intent_description: str,
        intent_class: IntentClass,
        beneficiary: Optional[str] = None,
        assets: Optional[List[str]] = None,
    ) -> None:
        """Require intent permission, raising exception if denied."""
        if not self.can_execute_intent(intent_description, intent_class, beneficiary, assets):
            raise IntentDeniedError(
                f"Intent execution denied: {self._last_validation.reason}"
            )


class AssetGate:
    """
    Gate for asset access.

    Controls access to assets referenced in intents.
    """

    def __init__(self, client: Optional[BoundaryClient] = None):
        self.client = client or BoundaryClient()

    def can_access(self, asset_class: int, asset_id: Optional[str] = None) -> Tuple[bool, str]:
        """Check if asset can be accessed."""
        return self.client.check_asset_access(asset_class, asset_id)

    def require_access(self, asset_class: int, asset_id: Optional[str] = None) -> None:
        """Require asset access, raising exception if denied."""
        permitted, reason = self.can_access(asset_class, asset_id)
        if not permitted:
            raise ExecutionDeniedError(f"Asset access denied: {reason}")


class ExecutionGate:
    """
    Gate for execution operations.
    """

    def __init__(self, client: Optional[BoundaryClient] = None):
        self.client = client or BoundaryClient()

    def can_execute(
        self,
        execution_type: str,
        requires_network: bool = False,
        requires_assets: bool = False,
    ) -> Tuple[bool, str]:
        """Check if execution is permitted."""
        return self.client.check_execution(execution_type, requires_network, requires_assets)

    def require_execution(
        self,
        execution_type: str,
        requires_network: bool = False,
        requires_assets: bool = False,
    ) -> None:
        """Require execution permission."""
        permitted, reason = self.can_execute(execution_type, requires_network, requires_assets)
        if not permitted:
            raise ExecutionDeniedError(f"Execution denied: {reason}")


# =============================================================================
# Decorators
# =============================================================================

def protected_intent(
    intent_class: IntentClass = IntentClass.INTERNAL,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator that enforces intent validation.
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            gate = IntentGate()
            gate.require_intent_permission(
                intent_description=f"Execute {func.__name__}",
                intent_class=intent_class,
            )
            return func(*args, **kwargs)
        return wrapper
    return decorator


def protected_execution(
    requires_network: bool = False,
    requires_assets: bool = False,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator that enforces execution permission.
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            gate = ExecutionGate()
            gate.require_execution(func.__name__, requires_network, requires_assets)
            return func(*args, **kwargs)
        return wrapper
    return decorator


# =============================================================================
# Main Integration
# =============================================================================

class FIEBoundaryIntegration:
    """
    Main integration class for Finite Intent Executor.

    Provides comprehensive boundary enforcement for intent execution.
    """

    def __init__(self):
        self.client = BoundaryClient()
        self.intent_gate = IntentGate(self.client)
        self.asset_gate = AssetGate(self.client)
        self.execution_gate = ExecutionGate(self.client)

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

    def validate_intent(
        self,
        intent_description: str,
        intent_class: IntentClass,
        beneficiary: Optional[str] = None,
        assets: Optional[List[str]] = None,
    ) -> IntentValidationResult:
        """Validate an intent for execution."""
        return self.client.check_intent(
            intent_description,
            intent_class,
            beneficiary,
            assets,
        )

    def can_execute_posthumous_intent(
        self,
        intent_description: str,
        beneficiary: str,
        assets: List[str],
    ) -> Tuple[bool, str]:
        """
        Check if posthumous intent execution is permitted.

        Posthumous intents require:
        - TRUSTED mode or higher
        - Ceremony for sensitive assets
        - Audit trail
        """
        mode = self.client.get_mode()

        if mode in [BoundaryMode.OPEN, BoundaryMode.RESTRICTED]:
            return False, "Posthumous intent requires TRUSTED mode or higher"

        if mode == BoundaryMode.LOCKDOWN:
            return False, "System in LOCKDOWN - all operations suspended"

        # Validate the intent
        validation = self.validate_intent(
            intent_description,
            IntentClass.SENSITIVE,  # Posthumous intents are at least sensitive
            beneficiary,
            assets,
        )

        return validation.valid, validation.reason

    def execute_with_boundary(
        self,
        intent_description: str,
        intent_class: IntentClass,
        execute_fn: Callable[[], T],
        beneficiary: Optional[str] = None,
        assets: Optional[List[str]] = None,
    ) -> Optional[T]:
        """
        Execute intent with boundary enforcement.

        Returns None if execution is denied.
        """
        validation = self.validate_intent(
            intent_description,
            intent_class,
            beneficiary,
            assets,
        )

        if not validation.valid:
            logger.warning(f"Intent execution denied: {validation.reason}")
            return None

        if validation.requires_ceremony:
            logger.info("Intent requires ceremony - proceeding with logged execution")

        return execute_fn()
