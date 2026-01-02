"""
Synth-Mind Boundary Daemon Integration

This module provides boundary enforcement for the Synthetic Mind Stack.
All reflection loops, cognitive processes, and memory access MUST pass
through these gates.

INTEGRATION REQUIREMENT:
Per INTEGRATION.md, synth-mind MUST call boundary daemon before:
- Reflection loops
- Memory access
- External communications
- Tool invocations

Usage:
    from boundary import ReflectionGate, CognitiveGate, require_reflection_check

    # Check before reflection loop
    gate = ReflectionGate()
    if gate.can_reflect():
        run_reflection_loop()

    # Or use decorator
    @require_reflection_check
    def meta_reflection():
        ...
"""

from .gates import (
    ReflectionGate,
    CognitiveGate,
    EmotionGate,
    MemoryGate,
    CommunicationGate,
)
from .decorators import (
    require_reflection_check,
    require_cognitive_check,
    require_memory_check,
    boundary_protected,
)
from .client import BoundaryClient, BoundaryMode, PolicyDecision
from .exceptions import (
    BoundaryError,
    ReflectionDeniedError,
    CognitiveDeniedError,
    MemoryDeniedError,
)

__all__ = [
    # Gates
    'ReflectionGate',
    'CognitiveGate',
    'EmotionGate',
    'MemoryGate',
    'CommunicationGate',
    # Decorators
    'require_reflection_check',
    'require_cognitive_check',
    'require_memory_check',
    'boundary_protected',
    # Client
    'BoundaryClient',
    'BoundaryMode',
    'PolicyDecision',
    # Exceptions
    'BoundaryError',
    'ReflectionDeniedError',
    'CognitiveDeniedError',
    'MemoryDeniedError',
]
