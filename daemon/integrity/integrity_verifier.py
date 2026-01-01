"""
Integrity Verifier - Runtime verification of daemon modules.

Phase 1 Critical Security: Verify module integrity at startup and
continuously during runtime to detect tampering.

Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │                    RUNTIME VERIFICATION                         │
    ├─────────────────────────────────────────────────────────────────┤
    │                                                                 │
    │  STARTUP                                                       │
    │  ┌────────────────────────────────────────────────────────────┐│
    │  │ 1. Load manifest.json                                      ││
    │  │ 2. Verify manifest signature against trusted public key    ││
    │  │ 3. Hash each module and compare to manifest                ││
    │  │ 4. REFUSE TO START if any verification fails               ││
    │  └────────────────────────────────────────────────────────────┘│
    │                              │                                  │
    │                              ▼                                  │
    │  RUNTIME MONITORING                                            │
    │  ┌────────────────────────────────────────────────────────────┐│
    │  │ • Re-verify all modules every 60 seconds                   ││
    │  │ • Detect file modifications (hot-patching)                 ││
    │  │ • Detect new unauthorized files                            ││
    │  │ • Trigger LOCKDOWN on any tampering                        ││
    │  └────────────────────────────────────────────────────────────┘│
    │                              │                                  │
    │                              ▼                                  │
    │  LOCKDOWN TRIGGER                                              │
    │  ┌────────────────────────────────────────────────────────────┐│
    │  │ • Log tamper event with full details                       ││
    │  │ • Transition to LOCKDOWN mode immediately                  ││
    │  │ • Disable all agent operations                             ││
    │  │ • Require ceremony to recover                              ││
    │  └────────────────────────────────────────────────────────────┘│
    └─────────────────────────────────────────────────────────────────┘

Verification Modes:
- STARTUP: Full verification, refuse to start on failure
- RUNTIME: Periodic re-verification, LOCKDOWN on failure
- ON_DEMAND: Manual verification triggered by admin
"""

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Callable

try:
    from nacl.signing import VerifyKey
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False

from .code_signer import SigningManifest, ModuleHash, CodeSigner

logger = logging.getLogger(__name__)


class IntegrityStatus(Enum):
    """Status of integrity verification."""
    VERIFIED = "verified"           # All modules verified
    UNVERIFIED = "unverified"       # Not yet verified
    SIGNATURE_INVALID = "signature_invalid"  # Manifest signature failed
    HASH_MISMATCH = "hash_mismatch"  # Module hash doesn't match
    FILE_MISSING = "file_missing"   # Module file not found
    FILE_ADDED = "file_added"       # Unauthorized file detected
    VERIFICATION_ERROR = "error"    # Error during verification


@dataclass
class VerificationResult:
    """Result of an integrity verification."""
    status: IntegrityStatus
    verified_at: datetime
    modules_checked: int
    modules_passed: int
    modules_failed: int
    failures: List[Dict[str, Any]]
    duration_ms: float
    manifest_version: Optional[str] = None
    daemon_version: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        """Check if verification passed."""
        return self.status == IntegrityStatus.VERIFIED

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'status': self.status.value,
            'verified_at': self.verified_at.isoformat(),
            'modules_checked': self.modules_checked,
            'modules_passed': self.modules_passed,
            'modules_failed': self.modules_failed,
            'failures': self.failures,
            'duration_ms': self.duration_ms,
            'manifest_version': self.manifest_version,
            'daemon_version': self.daemon_version,
            'is_valid': self.is_valid,
        }


class IntegrityVerifier:
    """
    Integrity Verifier - verifies daemon module integrity.

    Usage:
        verifier = IntegrityVerifier(
            manifest_path='/path/to/manifest.json',
            public_key=b'...',
        )
        result = verifier.verify()
        if not result.is_valid:
            # Refuse to start or trigger LOCKDOWN
    """

    def __init__(
        self,
        manifest_path: str,
        daemon_dir: str,
        public_key: Optional[bytes] = None,
        public_key_hex: Optional[str] = None,
        strict_mode: bool = True,
    ):
        """
        Initialize the integrity verifier.

        Args:
            manifest_path: Path to manifest.json
            daemon_dir: Path to daemon directory
            public_key: Ed25519 public key bytes
            public_key_hex: Ed25519 public key hex string
            strict_mode: If True, fail on any unrecognized files
        """
        self.manifest_path = manifest_path
        self.daemon_dir = Path(daemon_dir)
        self.strict_mode = strict_mode

        # Load public key
        if public_key:
            self._public_key = public_key
        elif public_key_hex:
            self._public_key = bytes.fromhex(public_key_hex)
        else:
            self._public_key = None

        # Cached manifest
        self._manifest: Optional[SigningManifest] = None
        self._signature: Optional[bytes] = None
        self._last_verification: Optional[VerificationResult] = None

        logger.info(f"IntegrityVerifier initialized for {daemon_dir}")

    def load_manifest(self) -> Tuple[SigningManifest, bytes]:
        """
        Load manifest and signature from files.

        Returns:
            Tuple of (manifest, signature)

        Raises:
            FileNotFoundError: If manifest not found
            json.JSONDecodeError: If manifest invalid
        """
        # Load manifest
        with open(self.manifest_path, 'r') as f:
            self._manifest = SigningManifest.from_json(f.read())

        # Load signature
        sig_path = self.manifest_path + '.sig'
        with open(sig_path, 'rb') as f:
            self._signature = f.read()

        logger.info(
            f"Loaded manifest: version={self._manifest.daemon_version}, "
            f"modules={len(self._manifest.modules)}"
        )
        return (self._manifest, self._signature)

    def verify_signature(self) -> bool:
        """
        Verify the manifest signature.

        Returns:
            True if signature is valid
        """
        if not self._manifest or not self._signature:
            self.load_manifest()

        # Determine which public key to use
        public_key = self._public_key
        if not public_key and self._manifest:
            # Use key from manifest (less secure, for dev only)
            logger.warning("Using public key from manifest - not recommended for production")
            public_key = bytes.fromhex(self._manifest.public_key)

        if not public_key:
            logger.error("No public key available for verification")
            return False

        return CodeSigner.verify_signature(
            self._manifest,
            self._signature,
            public_key,
        )

    def verify_module(self, module_hash: ModuleHash) -> Tuple[bool, Optional[str]]:
        """
        Verify a single module against its expected hash.

        Args:
            module_hash: Expected module hash

        Returns:
            Tuple of (is_valid, error_message)
        """
        file_path = self.daemon_dir / module_hash.path

        # Check file exists
        if not file_path.exists():
            return (False, f"File missing: {module_hash.path}")

        # Compute current hash
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                current_hash = hashlib.sha256(content).hexdigest()
        except Exception as e:
            return (False, f"Failed to hash {module_hash.path}: {e}")

        # Compare hashes
        if current_hash != module_hash.sha256:
            return (
                False,
                f"Hash mismatch for {module_hash.path}: "
                f"expected {module_hash.sha256[:16]}..., "
                f"got {current_hash[:16]}..."
            )

        return (True, None)

    def check_unauthorized_files(self) -> List[str]:
        """
        Check for files not in the manifest.

        Returns:
            List of unauthorized file paths
        """
        if not self._manifest:
            self.load_manifest()

        # Get set of expected files
        expected_files = {m.path for m in self._manifest.modules}

        # Scan directory
        unauthorized = []
        for py_file in self.daemon_dir.rglob('*.py'):
            rel_path = str(py_file.relative_to(self.daemon_dir))

            # Check exclusions
            skip = False
            for pattern in self._manifest.excluded_patterns:
                if pattern in rel_path:
                    skip = True
                    break

            if not skip and rel_path not in expected_files:
                unauthorized.append(rel_path)

        return unauthorized

    def verify(self, check_unauthorized: bool = True) -> VerificationResult:
        """
        Perform full integrity verification.

        Args:
            check_unauthorized: Whether to check for unauthorized files

        Returns:
            VerificationResult with details
        """
        start_time = time.time()
        failures = []

        try:
            # Load manifest if needed
            if not self._manifest:
                self.load_manifest()

            # Verify signature first
            if not self.verify_signature():
                return VerificationResult(
                    status=IntegrityStatus.SIGNATURE_INVALID,
                    verified_at=datetime.now(),
                    modules_checked=0,
                    modules_passed=0,
                    modules_failed=0,
                    failures=[{'type': 'signature', 'message': 'Manifest signature invalid'}],
                    duration_ms=(time.time() - start_time) * 1000,
                    manifest_version=self._manifest.version if self._manifest else None,
                    daemon_version=self._manifest.daemon_version if self._manifest else None,
                )

            # Verify each module
            modules_passed = 0
            modules_failed = 0

            for module_hash in self._manifest.modules:
                is_valid, error = self.verify_module(module_hash)
                if is_valid:
                    modules_passed += 1
                else:
                    modules_failed += 1
                    failures.append({
                        'type': 'hash_mismatch' if 'Hash mismatch' in (error or '') else 'file_missing',
                        'path': module_hash.path,
                        'message': error,
                    })

            # Check for unauthorized files
            if check_unauthorized and self.strict_mode:
                unauthorized = self.check_unauthorized_files()
                for path in unauthorized:
                    failures.append({
                        'type': 'unauthorized_file',
                        'path': path,
                        'message': f'Unauthorized file detected: {path}',
                    })

            # Determine status
            if failures:
                if any(f['type'] == 'hash_mismatch' for f in failures):
                    status = IntegrityStatus.HASH_MISMATCH
                elif any(f['type'] == 'file_missing' for f in failures):
                    status = IntegrityStatus.FILE_MISSING
                else:
                    status = IntegrityStatus.FILE_ADDED
            else:
                status = IntegrityStatus.VERIFIED

            result = VerificationResult(
                status=status,
                verified_at=datetime.now(),
                modules_checked=len(self._manifest.modules),
                modules_passed=modules_passed,
                modules_failed=modules_failed,
                failures=failures,
                duration_ms=(time.time() - start_time) * 1000,
                manifest_version=self._manifest.version,
                daemon_version=self._manifest.daemon_version,
            )

            self._last_verification = result

            if result.is_valid:
                logger.info(
                    f"Integrity verified: {modules_passed} modules OK "
                    f"({result.duration_ms:.1f}ms)"
                )
            else:
                logger.error(
                    f"Integrity verification FAILED: {modules_failed} failures"
                )
                for failure in failures[:5]:
                    logger.error(f"  - {failure['message']}")

            return result

        except FileNotFoundError as e:
            return VerificationResult(
                status=IntegrityStatus.VERIFICATION_ERROR,
                verified_at=datetime.now(),
                modules_checked=0,
                modules_passed=0,
                modules_failed=0,
                failures=[{'type': 'error', 'message': str(e)}],
                duration_ms=(time.time() - start_time) * 1000,
            )
        except Exception as e:
            logger.exception("Integrity verification error")
            return VerificationResult(
                status=IntegrityStatus.VERIFICATION_ERROR,
                verified_at=datetime.now(),
                modules_checked=0,
                modules_passed=0,
                modules_failed=0,
                failures=[{'type': 'error', 'message': str(e)}],
                duration_ms=(time.time() - start_time) * 1000,
            )

    def get_last_verification(self) -> Optional[VerificationResult]:
        """Get the last verification result."""
        return self._last_verification


class IntegrityMonitor:
    """
    Runtime Integrity Monitor - continuously monitors for tampering.

    Runs background verification and triggers callbacks on failure.
    """

    def __init__(
        self,
        verifier: IntegrityVerifier,
        check_interval: float = 60.0,
        on_tampering: Optional[Callable[[VerificationResult], None]] = None,
        on_verified: Optional[Callable[[VerificationResult], None]] = None,
    ):
        """
        Initialize the integrity monitor.

        Args:
            verifier: IntegrityVerifier instance
            check_interval: Seconds between checks
            on_tampering: Callback when tampering detected
            on_verified: Callback when verification passes
        """
        self.verifier = verifier
        self.check_interval = check_interval
        self.on_tampering = on_tampering
        self.on_verified = on_verified

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0
        self._tampering_detected = False

        logger.info(f"IntegrityMonitor initialized (interval={check_interval}s)")

    def start(self) -> None:
        """Start the monitoring thread."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("IntegrityMonitor started")

    def stop(self) -> None:
        """Stop the monitoring thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("IntegrityMonitor stopped")

    def _monitor_loop(self) -> None:
        """Background monitoring loop."""
        while self._running:
            try:
                result = self.verifier.verify()
                self._check_count += 1

                if result.is_valid:
                    if self.on_verified:
                        self.on_verified(result)
                else:
                    self._tampering_detected = True
                    logger.critical(
                        f"TAMPERING DETECTED: {result.status.value} - "
                        f"{len(result.failures)} failures"
                    )
                    if self.on_tampering:
                        self.on_tampering(result)
                    # Stop monitoring after tampering - system should be in LOCKDOWN
                    self._running = False
                    break

            except Exception as e:
                logger.error(f"Monitoring error: {e}")

            # Wait for next check
            for _ in range(int(self.check_interval)):
                if not self._running:
                    break
                time.sleep(1)

    def get_status(self) -> Dict[str, Any]:
        """Get monitor status."""
        return {
            'running': self._running,
            'check_count': self._check_count,
            'check_interval': self.check_interval,
            'tampering_detected': self._tampering_detected,
            'last_verification': (
                self.verifier.get_last_verification().to_dict()
                if self.verifier.get_last_verification()
                else None
            ),
        }

    def force_check(self) -> VerificationResult:
        """Force an immediate verification check."""
        result = self.verifier.verify()
        self._check_count += 1

        if not result.is_valid:
            self._tampering_detected = True
            if self.on_tampering:
                self.on_tampering(result)

        return result


def verify_at_startup(
    manifest_path: str,
    daemon_dir: str,
    public_key_hex: str,
    fail_action: str = "exit",
) -> bool:
    """
    Verify integrity at daemon startup.

    Convenience function for daemon initialization.

    Args:
        manifest_path: Path to manifest.json
        daemon_dir: Path to daemon directory
        public_key_hex: Trusted public key (hex)
        fail_action: What to do on failure ("exit", "warn", "lockdown")

    Returns:
        True if verified, False otherwise
    """
    logger.info("Performing startup integrity verification...")

    try:
        verifier = IntegrityVerifier(
            manifest_path=manifest_path,
            daemon_dir=daemon_dir,
            public_key_hex=public_key_hex,
        )

        result = verifier.verify()

        if result.is_valid:
            logger.info(
                f"Startup integrity verified: {result.modules_checked} modules OK"
            )
            return True
        else:
            logger.critical(
                f"STARTUP INTEGRITY VERIFICATION FAILED: {result.status.value}"
            )
            for failure in result.failures:
                logger.critical(f"  - {failure['message']}")

            if fail_action == "exit":
                logger.critical("Refusing to start - integrity compromised")
                raise SystemExit(1)
            elif fail_action == "lockdown":
                logger.critical("Entering LOCKDOWN mode due to integrity failure")
                # Would trigger lockdown here
            else:
                logger.warning("Continuing despite integrity failure (warn mode)")

            return False

    except FileNotFoundError:
        logger.warning(
            f"Manifest not found at {manifest_path} - skipping integrity check"
        )
        return True  # Allow startup without manifest (development mode)
    except Exception as e:
        logger.error(f"Integrity verification error: {e}")
        if fail_action == "exit":
            raise SystemExit(1)
        return False
