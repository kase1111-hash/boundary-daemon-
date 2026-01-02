"""
Synth-Mind Boundary Gates

Gates provide structured access control for different synth-mind operations.
Each gate corresponds to a major synth-mind component that must integrate
with the boundary daemon.
"""

import logging
from typing import Callable, Optional, Any
from functools import wraps

from .client import BoundaryClient, BoundaryMode, PolicyDecision
from .exceptions import (
    ReflectionDeniedError,
    CognitiveDeniedError,
    MemoryDeniedError,
    CommunicationDeniedError,
)

logger = logging.getLogger(__name__)


class BaseGate:
    """Base class for all boundary gates."""

    def __init__(self, client: Optional[BoundaryClient] = None):
        self.client = client or BoundaryClient()
        self._last_check: Optional[PolicyDecision] = None

    @property
    def last_decision(self) -> Optional[PolicyDecision]:
        """Get the last policy decision."""
        return self._last_check

    def _log_decision(self, operation: str, decision: PolicyDecision):
        """Log a policy decision."""
        if decision.permitted:
            logger.debug(f"[{self.__class__.__name__}] {operation}: PERMITTED - {decision.reason}")
        else:
            logger.warning(f"[{self.__class__.__name__}] {operation}: DENIED - {decision.reason}")


class ReflectionGate(BaseGate):
    """
    Gate for meta-reflection and introspection operations.

    MANDATORY: Must be called before any reflection loop.

    Usage:
        gate = ReflectionGate()

        # Method 1: Explicit check
        if gate.can_reflect():
            run_reflection_loop()

        # Method 2: With context manager
        with gate.reflection_context('meta') as permitted:
            if permitted:
                run_reflection_loop()

        # Method 3: Raise on denial
        gate.require_reflection()  # Raises ReflectionDeniedError if denied
        run_reflection_loop()
    """

    def can_reflect(
        self,
        reflection_type: str = 'meta',
        depth: int = 1,
    ) -> bool:
        """
        Check if reflection is permitted.

        Args:
            reflection_type: Type of reflection
            depth: Reflection depth

        Returns:
            True if reflection is permitted
        """
        decision = self.client.check_reflection(
            reflection_type=reflection_type,
            depth=depth,
        )
        self._last_check = decision
        self._log_decision(f"reflect({reflection_type}, depth={depth})", decision)
        return decision.permitted

    def require_reflection(
        self,
        reflection_type: str = 'meta',
        depth: int = 1,
    ) -> None:
        """
        Require reflection permission, raising exception if denied.

        Args:
            reflection_type: Type of reflection
            depth: Reflection depth

        Raises:
            ReflectionDeniedError: If reflection is not permitted
        """
        if not self.can_reflect(reflection_type, depth):
            raise ReflectionDeniedError(
                f"Reflection denied: {self._last_check.reason}"
            )

    def reflection_context(self, reflection_type: str = 'meta', depth: int = 1):
        """
        Context manager for reflection operations.

        Usage:
            with gate.reflection_context('meta') as permitted:
                if permitted:
                    do_reflection()
        """
        return _ReflectionContext(self, reflection_type, depth)


class _ReflectionContext:
    """Context manager for reflection operations."""

    def __init__(self, gate: ReflectionGate, reflection_type: str, depth: int):
        self.gate = gate
        self.reflection_type = reflection_type
        self.depth = depth
        self.permitted = False

    def __enter__(self) -> bool:
        self.permitted = self.gate.can_reflect(self.reflection_type, self.depth)
        return self.permitted

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Log completion if reflection was performed
        if self.permitted and exc_type is None:
            logger.debug(f"Reflection completed: {self.reflection_type}")
        return False


class CognitiveGate(BaseGate):
    """
    Gate for cognitive processes (reasoning, planning, evaluation).

    Controls access to CPU-intensive cognitive operations that may
    process sensitive information.
    """

    def can_process(
        self,
        process_name: str,
        requires_memory: bool = False,
        memory_class: int = 0,
        requires_network: bool = False,
    ) -> bool:
        """
        Check if a cognitive process is permitted.

        Args:
            process_name: Name of the process
            requires_memory: Whether memory access is needed
            memory_class: Memory classification level
            requires_network: Whether network access is needed

        Returns:
            True if process is permitted
        """
        decision = self.client.check_cognitive_process(
            process_name=process_name,
            requires_memory=requires_memory,
            memory_class=memory_class,
            requires_network=requires_network,
        )
        self._last_check = decision
        self._log_decision(f"cognitive:{process_name}", decision)
        return decision.permitted

    def require_process(
        self,
        process_name: str,
        requires_memory: bool = False,
        memory_class: int = 0,
        requires_network: bool = False,
    ) -> None:
        """Require process permission, raising exception if denied."""
        if not self.can_process(process_name, requires_memory, memory_class, requires_network):
            raise CognitiveDeniedError(
                f"Cognitive process '{process_name}' denied: {self._last_check.reason}"
            )


class EmotionGate(BaseGate):
    """
    Gate for emotion regulation operations.

    Controls emotional state changes and valence adjustments.
    """

    def can_regulate(
        self,
        emotion_type: str,
        intensity: float = 0.5,
    ) -> bool:
        """
        Check if emotion regulation is permitted.

        Args:
            emotion_type: Type of emotion
            intensity: Emotion intensity (0.0 - 1.0)

        Returns:
            True if regulation is permitted
        """
        decision = self.client.check_emotion_regulation(
            emotion_type=emotion_type,
            intensity=intensity,
        )
        self._last_check = decision
        self._log_decision(f"emotion:{emotion_type}@{intensity}", decision)
        return decision.permitted

    def regulate_with_check(
        self,
        emotion_type: str,
        intensity: float,
        regulation_fn: Callable[[], Any],
    ) -> Optional[Any]:
        """
        Regulate emotion if permitted.

        Args:
            emotion_type: Type of emotion
            intensity: Emotion intensity
            regulation_fn: Function to call if permitted

        Returns:
            Result of regulation_fn or None if denied
        """
        if self.can_regulate(emotion_type, intensity):
            return regulation_fn()
        return None


class MemoryGate(BaseGate):
    """
    Gate for memory access operations.

    Controls access to stored memories based on classification.
    """

    def can_access(
        self,
        memory_class: int,
        memory_id: Optional[str] = None,
    ) -> bool:
        """
        Check if memory access is permitted.

        Args:
            memory_class: Memory classification (0-5)
            memory_id: Optional memory identifier

        Returns:
            True if access is permitted
        """
        decision = self.client.check_recall(
            memory_class=memory_class,
            memory_id=memory_id,
        )
        self._last_check = decision
        self._log_decision(f"memory:class={memory_class}", decision)
        return decision.permitted

    def require_access(
        self,
        memory_class: int,
        memory_id: Optional[str] = None,
    ) -> None:
        """Require memory access, raising exception if denied."""
        if not self.can_access(memory_class, memory_id):
            raise MemoryDeniedError(
                f"Memory access denied: {self._last_check.reason}"
            )

    def access_if_permitted(
        self,
        memory_class: int,
        access_fn: Callable[[], Any],
        memory_id: Optional[str] = None,
        default: Any = None,
    ) -> Any:
        """
        Access memory if permitted.

        Args:
            memory_class: Memory classification
            access_fn: Function to call if permitted
            memory_id: Optional memory identifier
            default: Default value if access denied

        Returns:
            Result of access_fn or default
        """
        if self.can_access(memory_class, memory_id):
            return access_fn()
        return default


class CommunicationGate(BaseGate):
    """
    Gate for external communications.

    Controls messages to external systems, users, or agents.
    """

    def can_communicate(
        self,
        target: str,
        content: str,
        requires_network: bool = True,
    ) -> bool:
        """
        Check if communication is permitted.

        Args:
            target: Communication target
            content: Message content
            requires_network: Whether network is needed

        Returns:
            True if communication is permitted
        """
        # Check tool permission for communication
        decision = self.client.check_tool(
            tool_name=f"communicate:{target}",
            requires_network=requires_network,
        )

        if not decision.permitted:
            self._last_check = decision
            self._log_decision(f"communicate:{target}", decision)
            return False

        # Check message content
        content_decision = self.client.check_message(
            content=content,
            source='synth-mind',
            context={'target': target},
        )
        self._last_check = content_decision
        self._log_decision(f"communicate:{target}:content", content_decision)
        return content_decision.permitted

    def require_communication(
        self,
        target: str,
        content: str,
        requires_network: bool = True,
    ) -> None:
        """Require communication permission, raising exception if denied."""
        if not self.can_communicate(target, content, requires_network):
            raise CommunicationDeniedError(
                f"Communication to '{target}' denied: {self._last_check.reason}"
            )
