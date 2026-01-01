"""
TPM Manager - TPM 2.0 Integration for Hardware-Backed Security

Provides hardware-backed mode attestation and secret sealing using TPM 2.0.
Secrets can be bound to specific boundary modes, ensuring they can only
be accessed when the system is in the correct security posture.

Plan 2: TPM Integration (Priority: HIGH)
"""

import hashlib
import json
import logging
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any, TYPE_CHECKING

logger = logging.getLogger(__name__)

# SECURITY: Import AES-GCM for proper encryption instead of weak XOR
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

if TYPE_CHECKING:
    from ..policy_engine import BoundaryMode
    from ..event_logger import EventLogger


class SecureTempFile:
    """Context manager for secure temporary file handling.

    SECURITY: Addresses CWE-377 (Insecure Temporary File) by:
    - Creating files with restrictive permissions (0o600) atomically
    - Using a private temp directory when possible
    - Securely wiping file contents before deletion
    - Ensuring cleanup happens even on exceptions
    """

    def __init__(self, suffix: str = '', prefix: str = 'tpm_'):
        self.suffix = suffix
        self.prefix = prefix
        self.path: Optional[str] = None
        self._fd: Optional[int] = None

    def __enter__(self) -> str:
        import stat

        # Try to use /dev/shm (RAM-backed) for sensitive data, fall back to tempdir
        secure_dirs = ['/dev/shm', tempfile.gettempdir()]
        temp_dir = None
        for d in secure_dirs:
            if os.path.isdir(d) and os.access(d, os.W_OK):
                temp_dir = d
                break

        if temp_dir is None:
            raise TPMError("No writable temporary directory available")

        # Create unique filename
        import secrets
        random_suffix = secrets.token_hex(8)
        filename = f"{self.prefix}{random_suffix}{self.suffix}"
        self.path = os.path.join(temp_dir, filename)

        # SECURITY: Create file atomically with restrictive permissions
        # O_EXCL ensures file doesn't exist (prevents symlink attacks)
        # Mode 0o600 = owner read/write only
        self._fd = os.open(
            self.path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL,
            stat.S_IRUSR | stat.S_IWUSR
        )

        return self.path

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._secure_cleanup()
        return False

    def _secure_cleanup(self):
        """Securely wipe and delete the temporary file."""
        if self.path and os.path.exists(self.path):
            try:
                # Overwrite with random data before deletion
                file_size = os.path.getsize(self.path)
                if file_size > 0:
                    with open(self.path, 'r+b') as f:
                        f.write(os.urandom(file_size))
                        f.flush()
                        os.fsync(f.fileno())
            except (OSError, IOError) as wipe_err:
                # Best effort secure wipe - log but continue cleanup
                logger.debug(f"Secure wipe failed for temp file: {wipe_err}")

            try:
                os.unlink(self.path)
            except (OSError, FileNotFoundError) as unlink_err:
                # File cleanup failed - will be cleaned up by OS eventually
                logger.debug(f"Temp file unlink failed: {unlink_err}")

        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError as close_err:
                # File descriptor close failed - may already be closed
                logger.debug(f"Failed to close temp file descriptor: {close_err}")
            self._fd = None

    def write(self, data: bytes) -> None:
        """Write data to the secure temp file."""
        if self._fd is None:
            raise TPMError("SecureTempFile not initialized")
        os.write(self._fd, data)
        os.lseek(self._fd, 0, os.SEEK_SET)  # Reset position for reading


class TPMError(Exception):
    """Base exception for TPM operations"""
    pass


class TPMNotAvailableError(TPMError):
    """TPM is not available on this system"""
    pass


class TPMSealingError(TPMError):
    """Error during secret sealing"""
    pass


class TPMUnsealingError(TPMError):
    """Error during secret unsealing (mode mismatch or tampering)"""
    pass


class TPMAttestationError(TPMError):
    """Error during mode attestation"""
    pass


class TPMBackend(Enum):
    """Available TPM backends"""
    TPM2_TOOLS = "tpm2-tools"      # Command-line tools
    TPM2_PYTSS = "tpm2-pytss"      # Python library
    SIMULATOR = "simulator"        # Software TPM simulator (for testing)
    NONE = "none"                  # No TPM available


@dataclass
class SealedSecret:
    """A secret sealed to a specific boundary mode"""
    secret_id: str
    sealed_blob: bytes
    sealed_at: str
    mode_hash: str
    mode_name: str
    pcr_index: int
    pcr_value_at_seal: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'secret_id': self.secret_id,
            'sealed_blob': self.sealed_blob.hex(),
            'sealed_at': self.sealed_at,
            'mode_hash': self.mode_hash,
            'mode_name': self.mode_name,
            'pcr_index': self.pcr_index,
            'pcr_value_at_seal': self.pcr_value_at_seal,
            'metadata': self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'SealedSecret':
        """Create from dictionary"""
        return cls(
            secret_id=data['secret_id'],
            sealed_blob=bytes.fromhex(data['sealed_blob']),
            sealed_at=data['sealed_at'],
            mode_hash=data['mode_hash'],
            mode_name=data['mode_name'],
            pcr_index=data['pcr_index'],
            pcr_value_at_seal=data['pcr_value_at_seal'],
            metadata=data.get('metadata', {})
        )


@dataclass
class ModeAttestation:
    """Attestation record for a boundary mode"""
    mode_name: str
    mode_hash: str
    pcr_index: int
    pcr_value: str
    timestamp: str
    quote: Optional[bytes] = None  # TPM quote if available
    signature: Optional[bytes] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'mode_name': self.mode_name,
            'mode_hash': self.mode_hash,
            'pcr_index': self.pcr_index,
            'pcr_value': self.pcr_value,
            'timestamp': self.timestamp,
            'quote': self.quote.hex() if self.quote else None,
            'signature': self.signature.hex() if self.signature else None
        }

    def get_signable_data(self) -> bytes:
        """Get the data that should be signed for integrity verification.

        SECURITY: Returns a canonical representation of attestation data
        for signature verification. Excludes the signature field itself.
        """
        canonical = (
            f"{self.mode_name}|{self.mode_hash}|{self.pcr_index}|"
            f"{self.pcr_value}|{self.timestamp}"
        )
        if self.quote:
            canonical += f"|{self.quote.hex()}"
        return canonical.encode('utf-8')

    def compute_signature(self, signing_key: bytes) -> bytes:
        """Compute HMAC signature for this attestation.

        Args:
            signing_key: 32-byte signing key

        Returns:
            HMAC-SHA256 signature bytes
        """
        import hmac
        return hmac.new(signing_key, self.get_signable_data(), 'sha256').digest()

    def verify_signature(self, signing_key: bytes) -> bool:
        """Verify the attestation signature.

        SECURITY: Addresses CWE-347 by verifying attestation integrity
        before trusting loaded attestation records.

        Args:
            signing_key: 32-byte signing key used for signing

        Returns:
            True if signature is valid, False otherwise
        """
        if self.signature is None:
            return False

        import hmac
        expected = self.compute_signature(signing_key)
        return hmac.compare_digest(self.signature, expected)


class TPMManager:
    """
    Manages TPM-backed security features for the Boundary Daemon.

    Provides:
    - Mode attestation: Cryptographic proof of current boundary mode
    - Secret sealing: Encrypt secrets bound to specific modes
    - Secret unsealing: Decrypt secrets only when in correct mode
    - Mode binding: Record mode transitions in TPM PCR
    - Tamper detection: Detect unauthorized mode changes

    Uses TPM 2.0 PCR (Platform Configuration Register) 16 by default
    (user-defined PCR, safe for application use).
    """

    # PCR 16-23 are user-defined, safe for application use
    DEFAULT_PCR_INDEX = 16

    # Storage paths
    SEALED_SECRETS_DIR = "/var/lib/boundary-daemon/tpm/secrets"
    ATTESTATION_DIR = "/var/lib/boundary-daemon/tpm/attestations"

    def __init__(self, daemon=None, event_logger: Optional['EventLogger'] = None,
                 pcr_index: int = DEFAULT_PCR_INDEX):
        """
        Initialize TPM Manager.

        Args:
            daemon: Reference to BoundaryDaemon (for mode access)
            event_logger: EventLogger for audit logging
            pcr_index: PCR index to use (16-23 are user-defined)
        """
        self.daemon = daemon
        self.event_logger = event_logger
        self.pcr_index = pcr_index

        # Detect available TPM backend
        self.backend = self._detect_backend()
        self.is_available = self.backend != TPMBackend.NONE

        # TPM context (for pytss)
        self._tpm_ctx = None

        # Cached PCR values
        self._pcr_cache: Dict[int, str] = {}
        self._cache_time: float = 0
        self._cache_ttl: float = 5.0  # seconds

        # Attestation signing key (for integrity verification)
        self._attestation_signing_key: Optional[bytes] = None

        # Initialize storage directories
        if self.is_available:
            self._init_storage()

        # Mode hash tracking
        self._mode_hashes: Dict[str, str] = {}
        self._init_mode_hashes()

    def _detect_backend(self) -> TPMBackend:
        """Detect available TPM backend"""
        # Check for TPM device
        if not os.path.exists('/dev/tpm0') and not os.path.exists('/dev/tpmrm0'):
            # Check for software TPM simulator
            if self._check_swtpm():
                return TPMBackend.SIMULATOR
            return TPMBackend.NONE

        # Try tpm2-pytss first (preferred)
        try:
            import tpm2_pytss
            return TPMBackend.TPM2_PYTSS
        except ImportError:
            pass

        # Try tpm2-tools (command-line)
        try:
            result = subprocess.run(
                ['tpm2_getcap', 'properties-fixed'],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                return TPMBackend.TPM2_TOOLS
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        return TPMBackend.NONE

    def _check_swtpm(self) -> bool:
        """Check if software TPM simulator is available"""
        try:
            result = subprocess.run(
                ['swtpm', '--version'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def _init_storage(self):
        """Initialize storage directories and attestation signing key"""
        try:
            os.makedirs(self.SEALED_SECRETS_DIR, mode=0o700, exist_ok=True)
            os.makedirs(self.ATTESTATION_DIR, mode=0o700, exist_ok=True)
        except PermissionError:
            # Fallback to user directory
            home = os.path.expanduser("~")
            self.SEALED_SECRETS_DIR = os.path.join(home, ".boundary-daemon/tpm/secrets")
            self.ATTESTATION_DIR = os.path.join(home, ".boundary-daemon/tpm/attestations")
            os.makedirs(self.SEALED_SECRETS_DIR, mode=0o700, exist_ok=True)
            os.makedirs(self.ATTESTATION_DIR, mode=0o700, exist_ok=True)

        # Initialize attestation signing key
        self._init_attestation_signing_key()

    def _init_attestation_signing_key(self):
        """Initialize or load the attestation signing key.

        SECURITY: The signing key is used to sign attestation records to prevent
        forgery. Without this, an attacker with write access to the attestation
        directory could forge attestation records.
        """
        import stat

        # Determine key path based on attestation directory
        key_path = os.path.join(os.path.dirname(self.ATTESTATION_DIR), 'attestation_signing.key')

        if os.path.exists(key_path):
            # Load existing key
            try:
                with open(key_path, 'rb') as f:
                    self._attestation_signing_key = f.read()
                if len(self._attestation_signing_key) >= 32:
                    logger.debug(f"Loaded attestation signing key from {key_path}")
                    return
                else:
                    logger.warning("Attestation signing key too short, regenerating")
            except Exception as e:
                logger.warning(f"Failed to load attestation signing key: {e}")

        # Generate new key securely
        try:
            self._attestation_signing_key = os.urandom(32)

            # Create key file with secure permissions atomically
            fd = os.open(
                key_path,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                stat.S_IRUSR | stat.S_IWUSR  # 0o600
            )
            try:
                os.write(fd, self._attestation_signing_key)
            finally:
                os.close(fd)

            logger.info(f"Generated new attestation signing key at {key_path}")

        except Exception as e:
            logger.error(f"Failed to create attestation signing key: {e}")
            # Generate ephemeral key as fallback (not persisted)
            self._attestation_signing_key = os.urandom(32)
            logger.warning("Using ephemeral attestation signing key (not persisted)")

    def _init_mode_hashes(self):
        """Pre-compute mode hashes for all boundary modes"""
        from ..policy_engine import BoundaryMode
        for mode in BoundaryMode:
            self._mode_hashes[mode.name] = self._compute_mode_hash(mode)

    def _compute_mode_hash(self, mode: 'BoundaryMode') -> str:
        """Compute SHA-256 hash for a boundary mode"""
        mode_data = f"BOUNDARY_MODE:{mode.name}:{mode.value}"
        return hashlib.sha256(mode_data.encode()).hexdigest()

    def _log_event(self, event_type: str, details: str, metadata: Dict = None):
        """Log TPM event if logger available"""
        if self.event_logger:
            from ..event_logger import EventType
            # Use HEALTH_CHECK as closest event type, or add TPM_OPERATION
            self.event_logger.log_event(
                EventType.HEALTH_CHECK,
                f"TPM: {details}",
                metadata=metadata or {}
            )

    # =========================================================================
    # PCR Operations
    # =========================================================================

    def read_pcr(self, pcr_index: int = None) -> str:
        """
        Read PCR value.

        Args:
            pcr_index: PCR index to read (defaults to self.pcr_index)

        Returns:
            Hex string of PCR value

        Raises:
            TPMNotAvailableError: If TPM not available
            TPMError: If read fails
        """
        if not self.is_available:
            raise TPMNotAvailableError("TPM not available")

        pcr_index = pcr_index or self.pcr_index

        # Check cache
        now = time.time()
        if now - self._cache_time < self._cache_ttl and pcr_index in self._pcr_cache:
            return self._pcr_cache[pcr_index]

        if self.backend == TPMBackend.TPM2_TOOLS:
            return self._read_pcr_tpm2tools(pcr_index)
        elif self.backend == TPMBackend.TPM2_PYTSS:
            return self._read_pcr_pytss(pcr_index)
        elif self.backend == TPMBackend.SIMULATOR:
            return self._read_pcr_simulator(pcr_index)
        else:
            raise TPMNotAvailableError("No TPM backend available")

    def _read_pcr_tpm2tools(self, pcr_index: int) -> str:
        """Read PCR using tpm2-tools"""
        try:
            result = subprocess.run(
                ['tpm2_pcrread', f'sha256:{pcr_index}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                raise TPMError(f"tpm2_pcrread failed: {result.stderr}")

            # Parse output (format: "sha256:\n  16: 0x...")
            for line in result.stdout.split('\n'):
                if f'{pcr_index}:' in line:
                    # Extract hex value after 0x
                    parts = line.split('0x')
                    if len(parts) > 1:
                        value = parts[1].strip()
                        self._pcr_cache[pcr_index] = value
                        self._cache_time = time.time()
                        return value

            raise TPMError("Could not parse PCR value from output")

        except subprocess.TimeoutExpired:
            raise TPMError("TPM operation timed out")
        except subprocess.SubprocessError as e:
            raise TPMError(f"TPM subprocess error: {e}")

    def _read_pcr_pytss(self, pcr_index: int) -> str:
        """Read PCR using tpm2-pytss"""
        try:
            from tpm2_pytss import ESAPI
            from tpm2_pytss.constants import ESYS_TR

            if self._tpm_ctx is None:
                self._tpm_ctx = ESAPI()

            # Read PCR
            pcr_selection = f"sha256:{pcr_index}"
            _, _, digests = self._tpm_ctx.pcr_read(pcr_selection)

            if digests and len(digests) > 0:
                value = digests[0].hex()
                self._pcr_cache[pcr_index] = value
                self._cache_time = time.time()
                return value

            raise TPMError("No digest returned from PCR read")

        except ImportError:
            raise TPMNotAvailableError("tpm2-pytss not installed")
        except Exception as e:
            raise TPMError(f"TPM pytss error: {e}")

    def _read_pcr_simulator(self, pcr_index: int) -> str:
        """Read PCR from simulator (returns cached/computed value)"""
        if pcr_index not in self._pcr_cache:
            # Initialize with zeros
            self._pcr_cache[pcr_index] = '0' * 64
        return self._pcr_cache[pcr_index]

    def extend_pcr(self, data: bytes, pcr_index: int = None) -> str:
        """
        Extend PCR with data.

        PCR extension: new_value = SHA256(old_value || data)

        Args:
            data: Data to extend into PCR
            pcr_index: PCR index (defaults to self.pcr_index)

        Returns:
            New PCR value

        Raises:
            TPMNotAvailableError: If TPM not available
            TPMError: If extend fails
        """
        if not self.is_available:
            raise TPMNotAvailableError("TPM not available")

        pcr_index = pcr_index or self.pcr_index

        if self.backend == TPMBackend.TPM2_TOOLS:
            return self._extend_pcr_tpm2tools(data, pcr_index)
        elif self.backend == TPMBackend.TPM2_PYTSS:
            return self._extend_pcr_pytss(data, pcr_index)
        elif self.backend == TPMBackend.SIMULATOR:
            return self._extend_pcr_simulator(data, pcr_index)
        else:
            raise TPMNotAvailableError("No TPM backend available")

    def _extend_pcr_tpm2tools(self, data: bytes, pcr_index: int) -> str:
        """Extend PCR using tpm2-tools"""
        try:
            # Compute SHA256 of data
            data_hash = hashlib.sha256(data).hexdigest()

            result = subprocess.run(
                ['tpm2_pcrextend', f'{pcr_index}:sha256={data_hash}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                raise TPMError(f"tpm2_pcrextend failed: {result.stderr}")

            # Clear cache and read new value
            self._pcr_cache.pop(pcr_index, None)
            return self.read_pcr(pcr_index)

        except subprocess.TimeoutExpired:
            raise TPMError("TPM operation timed out")
        except subprocess.SubprocessError as e:
            raise TPMError(f"TPM subprocess error: {e}")

    def _extend_pcr_pytss(self, data: bytes, pcr_index: int) -> str:
        """Extend PCR using tpm2-pytss"""
        try:
            from tpm2_pytss import ESAPI

            if self._tpm_ctx is None:
                self._tpm_ctx = ESAPI()

            # Hash the data
            data_hash = hashlib.sha256(data).digest()

            # Extend PCR
            self._tpm_ctx.pcr_extend(pcr_index, data_hash)

            # Clear cache and read new value
            self._pcr_cache.pop(pcr_index, None)
            return self.read_pcr(pcr_index)

        except ImportError:
            raise TPMNotAvailableError("tpm2-pytss not installed")
        except Exception as e:
            raise TPMError(f"TPM pytss error: {e}")

    def _extend_pcr_simulator(self, data: bytes, pcr_index: int) -> str:
        """Extend PCR in simulator"""
        # Get current value
        old_value = bytes.fromhex(self._pcr_cache.get(pcr_index, '0' * 64))

        # Compute new value: SHA256(old || SHA256(data))
        data_hash = hashlib.sha256(data).digest()
        new_value = hashlib.sha256(old_value + data_hash).hexdigest()

        self._pcr_cache[pcr_index] = new_value
        return new_value

    # =========================================================================
    # Mode Attestation
    # =========================================================================

    def bind_mode_to_tpm(self, mode: 'BoundaryMode', reason: str = "") -> ModeAttestation:
        """
        Bind a boundary mode transition to the TPM.

        Extends PCR with mode hash to create cryptographic record
        of mode transition.

        Args:
            mode: Boundary mode being entered
            reason: Reason for mode transition

        Returns:
            ModeAttestation record

        Raises:
            TPMNotAvailableError: If TPM not available
            TPMAttestationError: If attestation fails
        """
        if not self.is_available:
            raise TPMNotAvailableError("TPM not available for mode attestation")

        try:
            mode_hash = self._mode_hashes.get(mode.name) or self._compute_mode_hash(mode)

            # Extend PCR with mode hash
            mode_data = f"{mode.name}:{mode.value}:{reason}:{datetime.utcnow().isoformat()}"
            new_pcr_value = self.extend_pcr(mode_data.encode())

            attestation = ModeAttestation(
                mode_name=mode.name,
                mode_hash=mode_hash,
                pcr_index=self.pcr_index,
                pcr_value=new_pcr_value,
                timestamp=datetime.utcnow().isoformat() + "Z"
            )

            # Save attestation record
            self._save_attestation(attestation)

            # Log event
            self._log_event(
                "MODE_ATTESTATION",
                f"Mode {mode.name} bound to TPM PCR {self.pcr_index}",
                metadata={
                    'mode': mode.name,
                    'pcr_index': self.pcr_index,
                    'pcr_value': new_pcr_value[:16] + "..."  # Truncate for log
                }
            )

            return attestation

        except TPMError:
            raise
        except Exception as e:
            raise TPMAttestationError(f"Mode attestation failed: {e}")

    def verify_mode_integrity(self, mode: 'BoundaryMode') -> Tuple[bool, Optional[str]]:
        """
        Verify current mode matches TPM PCR state.

        Checks that the expected mode sequence matches what's
        recorded in the TPM.

        Args:
            mode: Expected current boundary mode

        Returns:
            (is_valid, error_message)
        """
        if not self.is_available:
            return (True, None)  # Can't verify without TPM

        try:
            # Read current PCR
            current_pcr = self.read_pcr()

            # Load attestation history
            attestations = self._load_attestations()

            if not attestations:
                # No attestations yet - this is the first mode
                return (True, None)

            # Verify last attestation matches current mode
            last_attestation = attestations[-1]
            if last_attestation.mode_name != mode.name:
                return (False, f"Mode mismatch: TPM shows {last_attestation.mode_name}, expected {mode.name}")

            # Verify PCR hasn't changed unexpectedly
            if last_attestation.pcr_value != current_pcr:
                return (False, f"PCR mismatch: possible tampering detected")

            return (True, None)

        except TPMError as e:
            return (False, f"TPM verification error: {e}")

    def get_mode_attestation_chain(self) -> List[ModeAttestation]:
        """
        Get the chain of mode attestations.

        Returns:
            List of ModeAttestation records in chronological order
        """
        return self._load_attestations()

    def _save_attestation(self, attestation: ModeAttestation):
        """Save attestation record to disk with signature.

        SECURITY: Signs attestation before saving to prevent forgery.
        """
        # Sign the attestation before saving
        if self._attestation_signing_key:
            attestation.signature = attestation.compute_signature(self._attestation_signing_key)

        filename = f"attestation_{attestation.timestamp.replace(':', '-')}.json"
        filepath = os.path.join(self.ATTESTATION_DIR, filename)

        with open(filepath, 'w') as f:
            json.dump(attestation.to_dict(), f, indent=2)

    def _load_attestations(self, verify_signatures: bool = True) -> List[ModeAttestation]:
        """Load all attestation records with signature verification.

        SECURITY: Verifies attestation signatures on load to detect tampering.
        Addresses CWE-347 (Improper Verification of Cryptographic Signature).

        Args:
            verify_signatures: If True, verify signatures and skip invalid records

        Returns:
            List of verified attestation records
        """
        attestations = []
        unsigned_count = 0
        invalid_count = 0

        if not os.path.exists(self.ATTESTATION_DIR):
            return attestations

        for filename in sorted(os.listdir(self.ATTESTATION_DIR)):
            if filename.endswith('.json'):
                filepath = os.path.join(self.ATTESTATION_DIR, filename)
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)

                    attestation = ModeAttestation(
                        mode_name=data['mode_name'],
                        mode_hash=data['mode_hash'],
                        pcr_index=data['pcr_index'],
                        pcr_value=data['pcr_value'],
                        timestamp=data['timestamp'],
                        quote=bytes.fromhex(data['quote']) if data.get('quote') else None,
                        signature=bytes.fromhex(data['signature']) if data.get('signature') else None
                    )

                    # Verify signature if enabled and key is available
                    if verify_signatures and self._attestation_signing_key:
                        if attestation.signature is None:
                            unsigned_count += 1
                            logger.warning(
                                f"SECURITY: Skipping unsigned attestation: {filename}"
                            )
                            continue

                        if not attestation.verify_signature(self._attestation_signing_key):
                            invalid_count += 1
                            logger.error(
                                f"SECURITY: Invalid signature on attestation {filename} - "
                                "possible tampering detected!"
                            )
                            continue

                    attestations.append(attestation)

                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    logger.warning(f"Failed to load attestation {filename}: {e}")
                    continue

        if unsigned_count > 0 or invalid_count > 0:
            logger.warning(
                f"Attestation loading: {len(attestations)} valid, "
                f"{unsigned_count} unsigned, {invalid_count} invalid signatures"
            )

        return attestations

    # =========================================================================
    # Secret Sealing
    # =========================================================================

    def seal_secret(self, secret: bytes, mode: 'BoundaryMode',
                    secret_id: str = None, metadata: Dict = None) -> SealedSecret:
        """
        Seal a secret to a specific boundary mode.

        The secret can only be unsealed when the system is in the
        specified mode (or higher security mode).

        Args:
            secret: Secret bytes to seal
            mode: Boundary mode to seal to
            secret_id: Optional identifier for the secret
            metadata: Optional metadata to store with secret

        Returns:
            SealedSecret object

        Raises:
            TPMNotAvailableError: If TPM not available
            TPMSealingError: If sealing fails
        """
        if not self.is_available:
            raise TPMNotAvailableError("TPM not available for sealing")

        try:
            secret_id = secret_id or hashlib.sha256(secret).hexdigest()[:16]
            mode_hash = self._mode_hashes.get(mode.name) or self._compute_mode_hash(mode)
            current_pcr = self.read_pcr()

            if self.backend == TPMBackend.TPM2_TOOLS:
                sealed_blob = self._seal_tpm2tools(secret, mode_hash)
            elif self.backend == TPMBackend.TPM2_PYTSS:
                sealed_blob = self._seal_pytss(secret, mode_hash)
            elif self.backend == TPMBackend.SIMULATOR:
                sealed_blob = self._seal_simulator(secret, mode_hash)
            else:
                raise TPMSealingError("No TPM backend available")

            sealed_secret = SealedSecret(
                secret_id=secret_id,
                sealed_blob=sealed_blob,
                sealed_at=datetime.utcnow().isoformat() + "Z",
                mode_hash=mode_hash,
                mode_name=mode.name,
                pcr_index=self.pcr_index,
                pcr_value_at_seal=current_pcr,
                metadata=metadata or {}
            )

            # Save sealed secret
            self._save_sealed_secret(sealed_secret)

            # Log event
            self._log_event(
                "SECRET_SEALED",
                f"Secret '{secret_id}' sealed to mode {mode.name}",
                metadata={
                    'secret_id': secret_id,
                    'mode': mode.name,
                    'pcr_index': self.pcr_index
                }
            )

            return sealed_secret

        except TPMError:
            raise
        except Exception as e:
            raise TPMSealingError(f"Sealing failed: {e}")

    def unseal_secret(self, sealed_secret: SealedSecret,
                      current_mode: 'BoundaryMode') -> bytes:
        """
        Unseal a secret if current mode matches.

        Args:
            sealed_secret: The sealed secret to unseal
            current_mode: Current boundary mode

        Returns:
            Original secret bytes

        Raises:
            TPMNotAvailableError: If TPM not available
            TPMUnsealingError: If mode doesn't match or unsealing fails
        """
        if not self.is_available:
            raise TPMNotAvailableError("TPM not available for unsealing")

        try:
            current_mode_hash = self._mode_hashes.get(current_mode.name) or \
                               self._compute_mode_hash(current_mode)

            # Verify mode matches (allow higher security modes)
            from ..policy_engine import BoundaryMode
            sealed_mode = BoundaryMode[sealed_secret.mode_name]

            if current_mode.value < sealed_mode.value:
                raise TPMUnsealingError(
                    f"Cannot unseal: current mode {current_mode.name} is less "
                    f"secure than sealed mode {sealed_secret.mode_name}"
                )

            if self.backend == TPMBackend.TPM2_TOOLS:
                secret = self._unseal_tpm2tools(sealed_secret.sealed_blob,
                                                sealed_secret.mode_hash)
            elif self.backend == TPMBackend.TPM2_PYTSS:
                secret = self._unseal_pytss(sealed_secret.sealed_blob,
                                           sealed_secret.mode_hash)
            elif self.backend == TPMBackend.SIMULATOR:
                secret = self._unseal_simulator(sealed_secret.sealed_blob,
                                               sealed_secret.mode_hash,
                                               current_mode_hash)
            else:
                raise TPMUnsealingError("No TPM backend available")

            # Log event
            self._log_event(
                "SECRET_UNSEALED",
                f"Secret '{sealed_secret.secret_id}' unsealed in mode {current_mode.name}",
                metadata={
                    'secret_id': sealed_secret.secret_id,
                    'sealed_mode': sealed_secret.mode_name,
                    'current_mode': current_mode.name
                }
            )

            return secret

        except TPMError:
            raise
        except Exception as e:
            raise TPMUnsealingError(f"Unsealing failed: {e}")

    def _seal_tpm2tools(self, secret: bytes, mode_hash: str) -> bytes:
        """Seal using tpm2-tools with secure temporary file handling.

        SECURITY: Uses SecureTempFile for all temp files to ensure:
        - Files created with 0600 permissions atomically
        - Preferentially uses /dev/shm (RAM-backed) for secrets
        - Files are securely wiped before deletion
        """
        # Track all temp files for cleanup
        temp_files: List[SecureTempFile] = []

        try:
            # Create secure temp files
            secret_tf = SecureTempFile(suffix='.secret')
            temp_files.append(secret_tf)
            secret_path = secret_tf.__enter__()
            secret_tf.write(secret)

            sealed_tf = SecureTempFile(suffix='.sealed')
            temp_files.append(sealed_tf)
            sealed_path = sealed_tf.__enter__()

            policy_tf = SecureTempFile(suffix='.policy')
            temp_files.append(policy_tf)
            policy_path = policy_tf.__enter__()

            ctx_tf = SecureTempFile(suffix='.ctx')
            temp_files.append(ctx_tf)
            ctx_path = ctx_tf.__enter__()

            pub_tf = SecureTempFile(suffix='.pub')
            temp_files.append(pub_tf)
            pub_path = pub_tf.__enter__()

            priv_tf = SecureTempFile(suffix='.priv')
            temp_files.append(priv_tf)
            priv_path = priv_tf.__enter__()

            # Create policy
            result = subprocess.run(
                ['tpm2_createpolicy', '--policy-pcr',
                 '-l', f'sha256:{self.pcr_index}',
                 '-L', policy_path],
                capture_output=True,
                timeout=10
            )
            if result.returncode != 0:
                raise TPMSealingError(f"Policy creation failed: {result.stderr.decode()}")

            # Create primary key for sealing
            result = subprocess.run(
                ['tpm2_createprimary', '-C', 'o', '-c', ctx_path],
                capture_output=True,
                timeout=10
            )
            if result.returncode != 0:
                raise TPMSealingError(f"Primary key creation failed: {result.stderr.decode()}")

            # Seal the secret
            result = subprocess.run(
                ['tpm2_create', '-C', ctx_path, '-L', policy_path,
                 '-i', secret_path, '-u', pub_path,
                 '-r', priv_path],
                capture_output=True,
                timeout=10
            )
            if result.returncode != 0:
                raise TPMSealingError(f"Sealing failed: {result.stderr.decode()}")

            # Read sealed blob (combine pub and priv)
            with open(pub_path, 'rb') as f:
                pub_data = f.read()
            with open(priv_path, 'rb') as f:
                priv_data = f.read()

            # Format: [4 bytes pub length][pub data][priv data]
            sealed_blob = len(pub_data).to_bytes(4, 'big') + pub_data + priv_data

            return sealed_blob

        except subprocess.TimeoutExpired as e:
            raise TPMSealingError(f"TPM sealing operation timed out: {e}")
        except subprocess.SubprocessError as e:
            raise TPMSealingError(f"TPM subprocess error during sealing: {e}")
        finally:
            # Secure cleanup of all temp files (in reverse order)
            for tf in reversed(temp_files):
                try:
                    tf.__exit__(None, None, None)
                except (OSError, IOError) as cleanup_err:
                    # Best effort cleanup - log but don't fail
                    logger.debug(f"Temp file cleanup error: {cleanup_err}")

    def _unseal_tpm2tools(self, sealed_blob: bytes, mode_hash: str) -> bytes:
        """Unseal using tpm2-tools with secure temporary file handling.

        SECURITY: Uses SecureTempFile for all temp files to ensure:
        - Files created with 0600 permissions atomically
        - Preferentially uses /dev/shm (RAM-backed) for secrets
        - Files are securely wiped before deletion
        """
        # Track all temp files for cleanup
        temp_files: List[SecureTempFile] = []

        try:
            # Parse sealed blob
            pub_len = int.from_bytes(sealed_blob[:4], 'big')
            pub_data = sealed_blob[4:4+pub_len]
            priv_data = sealed_blob[4+pub_len:]

            # Create secure temp files
            pub_tf = SecureTempFile(suffix='.pub')
            temp_files.append(pub_tf)
            pub_path = pub_tf.__enter__()
            pub_tf.write(pub_data)

            priv_tf = SecureTempFile(suffix='.priv')
            temp_files.append(priv_tf)
            priv_path = priv_tf.__enter__()
            priv_tf.write(priv_data)

            ctx_tf = SecureTempFile(suffix='.ctx')
            temp_files.append(ctx_tf)
            ctx_path = ctx_tf.__enter__()

            out_tf = SecureTempFile(suffix='.out')
            temp_files.append(out_tf)
            out_path = out_tf.__enter__()

            obj_tf = SecureTempFile(suffix='.obj')
            temp_files.append(obj_tf)
            obj_path = obj_tf.__enter__()

            # Create primary key
            result = subprocess.run(
                ['tpm2_createprimary', '-C', 'o', '-c', ctx_path],
                capture_output=True,
                timeout=10
            )
            if result.returncode != 0:
                raise TPMUnsealingError(f"Primary key creation failed: {result.stderr.decode()}")

            # Load sealed object
            result = subprocess.run(
                ['tpm2_load', '-C', ctx_path, '-u', pub_path, '-r', priv_path, '-c', obj_path],
                capture_output=True,
                timeout=10
            )
            if result.returncode != 0:
                raise TPMUnsealingError(f"Load failed: {result.stderr.decode()}")

            # Unseal with PCR policy
            result = subprocess.run(
                ['tpm2_unseal', '-c', obj_path, '-o', out_path,
                 '-p', f'pcr:sha256:{self.pcr_index}'],
                capture_output=True,
                timeout=10
            )
            if result.returncode != 0:
                raise TPMUnsealingError(f"Unseal failed: {result.stderr.decode()}")

            with open(out_path, 'rb') as f:
                secret = f.read()

            return secret

        except subprocess.TimeoutExpired as e:
            raise TPMUnsealingError(f"TPM unsealing operation timed out: {e}")
        except subprocess.SubprocessError as e:
            raise TPMUnsealingError(f"TPM subprocess error during unsealing: {e}")
        finally:
            # Secure cleanup of all temp files (in reverse order)
            for tf in reversed(temp_files):
                try:
                    tf.__exit__(None, None, None)
                except (OSError, IOError) as cleanup_err:
                    # Best effort cleanup - log but don't fail
                    logger.debug(f"Temp file cleanup error: {cleanup_err}")

    def _seal_pytss(self, secret: bytes, mode_hash: str) -> bytes:
        """Seal using tpm2-pytss with AES-GCM encryption"""
        try:
            from tpm2_pytss import ESAPI
            from tpm2_pytss.types import TPM2B_SENSITIVE_CREATE

            if self._tpm_ctx is None:
                self._tpm_ctx = ESAPI()

            import hmac

            # Derive sealing key from TPM random
            random_bytes = self._tpm_ctx.get_random(32)
            seal_key = hmac.new(random_bytes, mode_hash.encode(), hashlib.sha256).digest()

            # SECURITY: Use AES-GCM for authenticated encryption instead of weak XOR
            if HAS_CRYPTOGRAPHY:
                # Generate a 12-byte nonce for AES-GCM
                nonce = os.urandom(12)
                aesgcm = AESGCM(seal_key)
                encrypted = aesgcm.encrypt(nonce, secret, mode_hash.encode())
                # Format: [random_bytes 32][nonce 12][encrypted+tag]
                sealed_blob = random_bytes + nonce + encrypted
            else:
                raise TPMSealingError(
                    "cryptography library required for secure sealing. "
                    "Install with: pip install cryptography"
                )

            return sealed_blob

        except ImportError:
            raise TPMNotAvailableError("tpm2-pytss not installed")
        except Exception as e:
            raise TPMSealingError(f"pytss sealing error: {e}")

    def _unseal_pytss(self, sealed_blob: bytes, mode_hash: str) -> bytes:
        """Unseal using tpm2-pytss with AES-GCM decryption"""
        try:
            import hmac

            # SECURITY: Use AES-GCM for authenticated decryption
            if not HAS_CRYPTOGRAPHY:
                raise TPMUnsealingError(
                    "cryptography library required for secure unsealing. "
                    "Install with: pip install cryptography"
                )

            # Parse sealed blob: [random_bytes 32][nonce 12][encrypted+tag]
            random_bytes = sealed_blob[:32]
            nonce = sealed_blob[32:44]
            encrypted = sealed_blob[44:]

            # Derive sealing key
            seal_key = hmac.new(random_bytes, mode_hash.encode(), hashlib.sha256).digest()

            # Decrypt with AES-GCM (also verifies authenticity)
            aesgcm = AESGCM(seal_key)
            secret = aesgcm.decrypt(nonce, encrypted, mode_hash.encode())

            return secret

        except Exception as e:
            raise TPMUnsealingError(f"pytss unsealing error: {e}")

    def _seal_simulator(self, secret: bytes, mode_hash: str) -> bytes:
        """Seal using simulator (software-only) with AES-GCM encryption"""
        import hmac

        # SECURITY: Use AES-GCM for authenticated encryption instead of weak XOR
        if not HAS_CRYPTOGRAPHY:
            raise TPMSealingError(
                "cryptography library required for secure sealing. "
                "Install with: pip install cryptography"
            )

        # Generate random key material
        random_bytes = os.urandom(32)

        # Derive key from random bytes and mode hash
        key = hmac.new(random_bytes, mode_hash.encode(), hashlib.sha256).digest()

        # Include mode hash in sealed blob for verification
        mode_hash_bytes = bytes.fromhex(mode_hash)

        # Generate a 12-byte nonce for AES-GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        encrypted = aesgcm.encrypt(nonce, secret, mode_hash.encode())

        # Format: [random_bytes 32][mode_hash 32][nonce 12][encrypted+tag]
        sealed_blob = random_bytes + mode_hash_bytes + nonce + encrypted

        return sealed_blob

    def _unseal_simulator(self, sealed_blob: bytes, expected_mode_hash: str,
                          current_mode_hash: str) -> bytes:
        """Unseal using simulator with AES-GCM decryption"""
        import hmac

        # SECURITY: Use AES-GCM for authenticated decryption
        if not HAS_CRYPTOGRAPHY:
            raise TPMUnsealingError(
                "cryptography library required for secure unsealing. "
                "Install with: pip install cryptography"
            )

        # Parse sealed blob: [random_bytes 32][mode_hash 32][nonce 12][encrypted+tag]
        random_bytes = sealed_blob[:32]
        stored_mode_hash = sealed_blob[32:64].hex()
        nonce = sealed_blob[64:76]
        encrypted = sealed_blob[76:]

        # Verify mode hash
        if stored_mode_hash != expected_mode_hash:
            raise TPMUnsealingError("Mode hash mismatch in sealed blob")

        # Derive key
        key = hmac.new(random_bytes, stored_mode_hash.encode(), hashlib.sha256).digest()

        # Decrypt with AES-GCM (also verifies authenticity)
        aesgcm = AESGCM(key)
        secret = aesgcm.decrypt(nonce, encrypted, stored_mode_hash.encode())

        return secret

    def _save_sealed_secret(self, sealed_secret: SealedSecret):
        """Save sealed secret to disk"""
        filename = f"secret_{sealed_secret.secret_id}.json"
        filepath = os.path.join(self.SEALED_SECRETS_DIR, filename)

        with open(filepath, 'w') as f:
            json.dump(sealed_secret.to_dict(), f, indent=2)

    def load_sealed_secret(self, secret_id: str) -> Optional[SealedSecret]:
        """Load a sealed secret by ID"""
        filename = f"secret_{secret_id}.json"
        filepath = os.path.join(self.SEALED_SECRETS_DIR, filename)

        if not os.path.exists(filepath):
            return None

        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                return SealedSecret.from_dict(data)
        except (json.JSONDecodeError, KeyError):
            return None

    def list_sealed_secrets(self) -> List[str]:
        """List all sealed secret IDs"""
        secrets = []

        if not os.path.exists(self.SEALED_SECRETS_DIR):
            return secrets

        for filename in os.listdir(self.SEALED_SECRETS_DIR):
            if filename.startswith('secret_') and filename.endswith('.json'):
                secret_id = filename[7:-5]  # Remove 'secret_' and '.json'
                secrets.append(secret_id)

        return secrets

    def delete_sealed_secret(self, secret_id: str) -> bool:
        """Delete a sealed secret"""
        filename = f"secret_{secret_id}.json"
        filepath = os.path.join(self.SEALED_SECRETS_DIR, filename)

        if os.path.exists(filepath):
            os.unlink(filepath)
            self._log_event(
                "SECRET_DELETED",
                f"Sealed secret '{secret_id}' deleted",
                metadata={'secret_id': secret_id}
            )
            return True
        return False

    # =========================================================================
    # Status and Diagnostics
    # =========================================================================

    def get_status(self) -> Dict:
        """Get TPM status information"""
        status = {
            'available': self.is_available,
            'backend': self.backend.value,
            'pcr_index': self.pcr_index
        }

        if self.is_available:
            try:
                status['pcr_value'] = self.read_pcr()
            except TPMError as e:
                status['pcr_error'] = str(e)

            status['sealed_secrets_count'] = len(self.list_sealed_secrets())
            status['attestations_count'] = len(self._load_attestations())

        return status

    def cleanup(self):
        """Cleanup TPM resources"""
        if self._tpm_ctx is not None:
            try:
                self._tpm_ctx.close()
            except (OSError, AttributeError, RuntimeError) as e:
                # Log but don't propagate cleanup errors
                logger.debug(f"TPM context cleanup error (non-critical): {e}")
            except Exception as e:
                # Catch any other exceptions but log them for debugging
                logger.warning(f"Unexpected error during TPM cleanup: {type(e).__name__}: {e}")
            finally:
                self._tpm_ctx = None

        self._pcr_cache.clear()


# Convenience function for checking TPM availability
def check_tpm_available() -> bool:
    """Check if TPM is available on this system"""
    manager = TPMManager()
    return manager.is_available


if __name__ == '__main__':
    # Test TPM manager
    print("Testing TPM Manager...")

    manager = TPMManager()
    print(f"TPM Available: {manager.is_available}")
    print(f"Backend: {manager.backend.value}")

    if manager.is_available:
        try:
            pcr_value = manager.read_pcr()
            print(f"PCR {manager.pcr_index}: {pcr_value}")
        except TPMError as e:
            print(f"PCR read error: {e}")

        # Test mode attestation
        from policy_engine import BoundaryMode
        try:
            attestation = manager.bind_mode_to_tpm(BoundaryMode.AIRGAP, "test")
            print(f"Mode attestation: {attestation.mode_name} at {attestation.timestamp}")
        except TPMError as e:
            print(f"Attestation error: {e}")

        # Test secret sealing
        try:
            secret = b"my secret data"
            sealed = manager.seal_secret(secret, BoundaryMode.AIRGAP, "test-secret")
            print(f"Sealed secret: {sealed.secret_id}")

            # Unseal
            unsealed = manager.unseal_secret(sealed, BoundaryMode.AIRGAP)
            print(f"Unsealed: {unsealed == secret}")
        except TPMError as e:
            print(f"Sealing error: {e}")

    print("\nTPM Manager test complete.")
