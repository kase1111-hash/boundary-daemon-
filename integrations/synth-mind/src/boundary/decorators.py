"""
Synth-Mind Boundary Decorators

Decorators for easy integration of boundary checks into synth-mind functions.
"""

import functools
from typing import Callable, TypeVar, Optional, Any

from .client import BoundaryClient
from .gates import ReflectionGate, CognitiveGate, MemoryGate
from .exceptions import ReflectionDeniedError, CognitiveDeniedError, MemoryDeniedError

T = TypeVar('T')


def require_reflection_check(
    reflection_type: str = 'meta',
    depth: int = 1,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator that requires reflection check before execution.

    Usage:
        @require_reflection_check()
        def meta_reflection():
            ...

        @require_reflection_check(reflection_type='introspective', depth=2)
        def deep_introspection():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            gate = ReflectionGate()
            gate.require_reflection(reflection_type, depth)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_cognitive_check(
    process_name: Optional[str] = None,
    requires_memory: bool = False,
    memory_class: int = 0,
    requires_network: bool = False,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator that requires cognitive process check before execution.

    Usage:
        @require_cognitive_check()
        def reasoning_process():
            ...

        @require_cognitive_check(requires_memory=True, memory_class=2)
        def recall_based_reasoning():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            gate = CognitiveGate()
            name = process_name or func.__name__
            gate.require_process(name, requires_memory, memory_class, requires_network)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_memory_check(
    memory_class: int,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator that requires memory access check before execution.

    Usage:
        @require_memory_check(memory_class=2)
        def access_confidential_memory():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            gate = MemoryGate()
            gate.require_access(memory_class)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def boundary_protected(
    requires_network: bool = False,
    requires_filesystem: bool = False,
    requires_usb: bool = False,
    memory_class: Optional[int] = None,
    reflection_check: bool = False,
    reflection_type: str = 'meta',
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Comprehensive boundary protection decorator.

    Combines tool, memory, and reflection checks.

    Usage:
        @boundary_protected(requires_network=True)
        def network_operation():
            ...

        @boundary_protected(memory_class=3, reflection_check=True)
        def sensitive_reflection():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            client = BoundaryClient()

            # Check tool permission
            decision = client.check_tool(
                tool_name=func.__name__,
                requires_network=requires_network,
                requires_filesystem=requires_filesystem,
                requires_usb=requires_usb,
            )
            if not decision.permitted:
                raise CognitiveDeniedError(
                    f"Function '{func.__name__}' denied: {decision.reason}"
                )

            # Check memory permission if required
            if memory_class is not None:
                recall_decision = client.check_recall(memory_class=memory_class)
                if not recall_decision.permitted:
                    raise MemoryDeniedError(
                        f"Memory access for '{func.__name__}' denied: {recall_decision.reason}"
                    )

            # Check reflection permission if required
            if reflection_check:
                reflection_decision = client.check_reflection(
                    reflection_type=reflection_type
                )
                if not reflection_decision.permitted:
                    raise ReflectionDeniedError(
                        f"Reflection for '{func.__name__}' denied: {reflection_decision.reason}"
                    )

            return func(*args, **kwargs)
        return wrapper
    return decorator


def fail_safe(
    default: Any = None,
    log_error: bool = True,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator that returns default value instead of raising on boundary denial.

    Usage:
        @fail_safe(default=[])
        @require_memory_check(memory_class=3)
        def get_memories():
            return retrieve_memories()  # Returns [] if denied
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            try:
                return func(*args, **kwargs)
            except (ReflectionDeniedError, CognitiveDeniedError, MemoryDeniedError) as e:
                if log_error:
                    import logging
                    logging.getLogger(__name__).warning(
                        f"Boundary denial in {func.__name__}: {e}"
                    )
                return default
        return wrapper
    return decorator


class BoundaryScope:
    """
    Context manager for scoped boundary checks.

    Usage:
        with BoundaryScope(requires_network=True) as scope:
            if scope.permitted:
                do_network_operation()
            else:
                handle_denial(scope.reason)
    """

    def __init__(
        self,
        tool_name: str = 'scoped_operation',
        requires_network: bool = False,
        requires_filesystem: bool = False,
        requires_usb: bool = False,
        memory_class: Optional[int] = None,
        reflection_check: bool = False,
        raise_on_deny: bool = False,
    ):
        self.tool_name = tool_name
        self.requires_network = requires_network
        self.requires_filesystem = requires_filesystem
        self.requires_usb = requires_usb
        self.memory_class = memory_class
        self.reflection_check = reflection_check
        self.raise_on_deny = raise_on_deny

        self.permitted = False
        self.reason = ""
        self.client = BoundaryClient()

    def __enter__(self) -> 'BoundaryScope':
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
                raise CognitiveDeniedError(self.reason)
            return self

        # Check memory if required
        if self.memory_class is not None:
            recall_decision = self.client.check_recall(memory_class=self.memory_class)
            if not recall_decision.permitted:
                self.permitted = False
                self.reason = recall_decision.reason
                if self.raise_on_deny:
                    raise MemoryDeniedError(self.reason)
                return self

        # Check reflection if required
        if self.reflection_check:
            reflection_decision = self.client.check_reflection()
            if not reflection_decision.permitted:
                self.permitted = False
                self.reason = reflection_decision.reason
                if self.raise_on_deny:
                    raise ReflectionDeniedError(self.reason)
                return self

        self.permitted = True
        self.reason = "Operation permitted"
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False
