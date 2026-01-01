"""
Integrity module for Boundary Daemon.

Phase 1 Critical Security: Code signing and integrity verification
to prevent daemon binary/module tampering.

Features:
- Build-time signing of all Python modules
- Startup verification before daemon runs
- Runtime integrity monitoring (periodic re-verification)
- Hot-patching detection and LOCKDOWN trigger
"""

from .code_signer import (
    CodeSigner,
    SigningManifest,
    ModuleHash,
    sign_daemon_release,
)

from .integrity_verifier import (
    IntegrityVerifier,
    VerificationResult,
    IntegrityStatus,
    IntegrityMonitor,
)

__all__ = [
    # Code signing
    'CodeSigner',
    'SigningManifest',
    'ModuleHash',
    'sign_daemon_release',

    # Verification
    'IntegrityVerifier',
    'VerificationResult',
    'IntegrityStatus',
    'IntegrityMonitor',
]
