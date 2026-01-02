"""
Synth-Mind Boundary Exceptions

Custom exceptions for boundary-related errors in synth-mind.
"""


class BoundaryError(Exception):
    """Base exception for all boundary errors."""

    def __init__(self, message: str, reason: str = None):
        super().__init__(message)
        self.reason = reason or message


class ReflectionDeniedError(BoundaryError):
    """Raised when reflection is denied by boundary policy."""
    pass


class CognitiveDeniedError(BoundaryError):
    """Raised when a cognitive process is denied by boundary policy."""
    pass


class MemoryDeniedError(BoundaryError):
    """Raised when memory access is denied by boundary policy."""
    pass


class CommunicationDeniedError(BoundaryError):
    """Raised when external communication is denied by boundary policy."""
    pass


class EmotionRegulationDeniedError(BoundaryError):
    """Raised when emotion regulation is denied by boundary policy."""
    pass
