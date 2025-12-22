"""
Hardware Module - Hardware Security Integration

This module provides integration with hardware security features
for enhanced trust guarantees.

Components:
- TPMManager: TPM 2.0 integration for mode attestation and secret sealing
"""

from .tpm_manager import (
    TPMManager,
    TPMError,
    TPMNotAvailableError,
    TPMSealingError,
    TPMUnsealingError,
    TPMAttestationError,
    SealedSecret,
)

__all__ = [
    'TPMManager',
    'TPMError',
    'TPMNotAvailableError',
    'TPMSealingError',
    'TPMUnsealingError',
    'TPMAttestationError',
    'SealedSecret',
]
