"""
Authentication Module for Boundary Daemon
Handles biometric authentication (fingerprint and facial recognition).
"""

from .biometric_verifier import BiometricVerifier, BiometricType, BiometricResult
from .enhanced_ceremony import EnhancedCeremonyManager, BiometricCeremonyConfig

__all__ = [
    'BiometricVerifier',
    'BiometricType',
    'BiometricResult',
    'EnhancedCeremonyManager',
    'BiometricCeremonyConfig',
]
