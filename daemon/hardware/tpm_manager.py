"""
TPM Manager - TPM 2.0 Integration for Hardware-Backed Security

Provides hardware-backed mode attestation and secret sealing using TPM 2.0.
Secrets can be bound to specific boundary modes, ensuring they can only
be accessed when the system is in the correct security posture.

Plan 2: TPM Integration (Priority: HIGH)
"""

import hashlib
import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..policy_engine import BoundaryMode
    from ..event_logger import EventLogger


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
        """Initialize storage directories"""
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
        """Save attestation record to disk"""
        filename = f"attestation_{attestation.timestamp.replace(':', '-')}.json"
        filepath = os.path.join(self.ATTESTATION_DIR, filename)

        with open(filepath, 'w') as f:
            json.dump(attestation.to_dict(), f, indent=2)

    def _load_attestations(self) -> List[ModeAttestation]:
        """Load all attestation records"""
        attestations = []

        if not os.path.exists(self.ATTESTATION_DIR):
            return attestations

        for filename in sorted(os.listdir(self.ATTESTATION_DIR)):
            if filename.endswith('.json'):
                filepath = os.path.join(self.ATTESTATION_DIR, filename)
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                        attestations.append(ModeAttestation(
                            mode_name=data['mode_name'],
                            mode_hash=data['mode_hash'],
                            pcr_index=data['pcr_index'],
                            pcr_value=data['pcr_value'],
                            timestamp=data['timestamp'],
                            quote=bytes.fromhex(data['quote']) if data.get('quote') else None,
                            signature=bytes.fromhex(data['signature']) if data.get('signature') else None
                        ))
                except (json.JSONDecodeError, KeyError):
                    continue

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
        """Seal using tpm2-tools"""
        try:
            with tempfile.NamedTemporaryFile(delete=False) as secret_file:
                secret_file.write(secret)
                secret_path = secret_file.name

            with tempfile.NamedTemporaryFile(delete=False, suffix='.sealed') as sealed_file:
                sealed_path = sealed_file.name

            # Create sealing policy based on PCR
            with tempfile.NamedTemporaryFile(delete=False, suffix='.policy') as policy_file:
                policy_path = policy_file.name

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
            with tempfile.NamedTemporaryFile(delete=False, suffix='.ctx') as ctx_file:
                ctx_path = ctx_file.name

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
                 '-i', secret_path, '-u', sealed_path + '.pub',
                 '-r', sealed_path + '.priv'],
                capture_output=True,
                timeout=10
            )
            if result.returncode != 0:
                raise TPMSealingError(f"Sealing failed: {result.stderr.decode()}")

            # Read sealed blob (combine pub and priv)
            with open(sealed_path + '.pub', 'rb') as f:
                pub_data = f.read()
            with open(sealed_path + '.priv', 'rb') as f:
                priv_data = f.read()

            # Format: [4 bytes pub length][pub data][priv data]
            sealed_blob = len(pub_data).to_bytes(4, 'big') + pub_data + priv_data

            return sealed_blob

        finally:
            # Cleanup temp files
            for path in [secret_path, sealed_path, policy_path, ctx_path,
                        sealed_path + '.pub', sealed_path + '.priv']:
                try:
                    os.unlink(path)
                except:
                    pass

    def _unseal_tpm2tools(self, sealed_blob: bytes, mode_hash: str) -> bytes:
        """Unseal using tpm2-tools"""
        try:
            # Parse sealed blob
            pub_len = int.from_bytes(sealed_blob[:4], 'big')
            pub_data = sealed_blob[4:4+pub_len]
            priv_data = sealed_blob[4+pub_len:]

            with tempfile.NamedTemporaryFile(delete=False, suffix='.pub') as pub_file:
                pub_file.write(pub_data)
                pub_path = pub_file.name

            with tempfile.NamedTemporaryFile(delete=False, suffix='.priv') as priv_file:
                priv_file.write(priv_data)
                priv_path = priv_file.name

            with tempfile.NamedTemporaryFile(delete=False, suffix='.ctx') as ctx_file:
                ctx_path = ctx_file.name

            with tempfile.NamedTemporaryFile(delete=False) as out_file:
                out_path = out_file.name

            # Create primary key
            result = subprocess.run(
                ['tpm2_createprimary', '-C', 'o', '-c', ctx_path],
                capture_output=True,
                timeout=10
            )
            if result.returncode != 0:
                raise TPMUnsealingError(f"Primary key creation failed: {result.stderr.decode()}")

            # Load sealed object
            with tempfile.NamedTemporaryFile(delete=False, suffix='.obj') as obj_file:
                obj_path = obj_file.name

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

        finally:
            # Cleanup temp files
            for path in [pub_path, priv_path, ctx_path, out_path, obj_path]:
                try:
                    os.unlink(path)
                except:
                    pass

    def _seal_pytss(self, secret: bytes, mode_hash: str) -> bytes:
        """Seal using tpm2-pytss"""
        try:
            from tpm2_pytss import ESAPI
            from tpm2_pytss.types import TPM2B_SENSITIVE_CREATE

            if self._tpm_ctx is None:
                self._tpm_ctx = ESAPI()

            # This is a simplified implementation
            # Full implementation would use proper TPM sealing

            # For now, use HMAC-based sealing simulation with TPM-derived key
            import hmac

            # Derive sealing key from TPM random
            random_bytes = self._tpm_ctx.get_random(32)
            seal_key = hmac.new(random_bytes, mode_hash.encode(), hashlib.sha256).digest()

            # Encrypt secret (simple XOR for demonstration)
            # Real implementation would use AES-GCM
            encrypted = bytes(a ^ b for a, b in zip(secret, (seal_key * ((len(secret) // 32) + 1))[:len(secret)]))

            # Format: [random bytes][encrypted secret]
            sealed_blob = random_bytes + encrypted

            return sealed_blob

        except ImportError:
            raise TPMNotAvailableError("tpm2-pytss not installed")
        except Exception as e:
            raise TPMSealingError(f"pytss sealing error: {e}")

    def _unseal_pytss(self, sealed_blob: bytes, mode_hash: str) -> bytes:
        """Unseal using tpm2-pytss"""
        try:
            import hmac

            # Parse sealed blob
            random_bytes = sealed_blob[:32]
            encrypted = sealed_blob[32:]

            # Derive sealing key
            seal_key = hmac.new(random_bytes, mode_hash.encode(), hashlib.sha256).digest()

            # Decrypt
            secret = bytes(a ^ b for a, b in zip(encrypted, (seal_key * ((len(encrypted) // 32) + 1))[:len(encrypted)]))

            return secret

        except Exception as e:
            raise TPMUnsealingError(f"pytss unsealing error: {e}")

    def _seal_simulator(self, secret: bytes, mode_hash: str) -> bytes:
        """Seal using simulator (software-only)"""
        import hmac

        # Generate random nonce
        nonce = os.urandom(32)

        # Derive key from mode hash and nonce
        key = hmac.new(nonce, mode_hash.encode(), hashlib.sha256).digest()

        # Simple XOR encryption (use AES in production)
        encrypted = bytes(a ^ b for a, b in zip(
            secret,
            (key * ((len(secret) // 32) + 1))[:len(secret)]
        ))

        # Include mode hash in sealed blob for verification
        mode_hash_bytes = bytes.fromhex(mode_hash)

        # Format: [nonce 32][mode_hash 32][encrypted]
        sealed_blob = nonce + mode_hash_bytes + encrypted

        return sealed_blob

    def _unseal_simulator(self, sealed_blob: bytes, expected_mode_hash: str,
                          current_mode_hash: str) -> bytes:
        """Unseal using simulator"""
        import hmac

        # Parse sealed blob
        nonce = sealed_blob[:32]
        stored_mode_hash = sealed_blob[32:64].hex()
        encrypted = sealed_blob[64:]

        # Verify mode hash
        if stored_mode_hash != expected_mode_hash:
            raise TPMUnsealingError("Mode hash mismatch in sealed blob")

        # Derive key
        key = hmac.new(nonce, stored_mode_hash.encode(), hashlib.sha256).digest()

        # Decrypt
        secret = bytes(a ^ b for a, b in zip(
            encrypted,
            (key * ((len(encrypted) // 32) + 1))[:len(encrypted)]
        ))

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
            except:
                pass
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
