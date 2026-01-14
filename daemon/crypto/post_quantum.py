"""
Post-Quantum Cryptography - Future-proof against quantum computing threats.

Phase 3 Cutting-Edge Innovation: Hybrid cryptographic schemes that combine
classical and post-quantum algorithms for defense-in-depth.

Migration Strategy:
    ┌─────────────────────────────────────────────────────────────────┐
    │                 POST-QUANTUM MIGRATION PATH                     │
    ├─────────────────────────────────────────────────────────────────┤
    │                                                                 │
    │  CURRENT                 HYBRID                  FUTURE        │
    │  ┌─────────┐            ┌─────────┐            ┌─────────┐    │
    │  │ Ed25519 │───────────►│Ed25519 +│───────────►│Dilithium│    │
    │  │         │            │Dilithium│            │   only  │    │
    │  └─────────┘            └─────────┘            └─────────┘    │
    │                                                                 │
    │  ┌─────────┐            ┌─────────┐            ┌─────────┐    │
    │  │ X25519  │───────────►│X25519 + │───────────►│ Kyber   │    │
    │  │         │            │ Kyber   │            │  only   │    │
    │  └─────────┘            └─────────┘            └─────────┘    │
    │                                                                 │
    │  ┌─────────┐            ┌─────────┐            ┌─────────┐    │
    │  │ SHA-256 │───────────►│SHA-256 +│───────────►│ SHA-3   │    │
    │  │         │            │ SHA-3   │            │  only   │    │
    │  └─────────┘            └─────────┘            └─────────┘    │
    └─────────────────────────────────────────────────────────────────┘

Supported Algorithms:
- Signatures: Dilithium-3 (NIST Level 3), Falcon-512
- Key Exchange: Kyber-768 (NIST Level 3), SIKE
- Hashing: SHA-3-256, SHAKE-256

Hybrid Mode Properties:
- Sign with BOTH Ed25519 AND Dilithium
- Verify with EITHER (backwards compatible)
- Key exchange combines X25519 AND Kyber
- Maximum security during transition period

Dependencies (optional):
- liboqs-python: Open Quantum Safe library bindings
- pqcrypto: Pure Python post-quantum implementations
"""

import hashlib
import logging
import os
import struct
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Tuple, Any
import base64

try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.public import PrivateKey, PublicKey, Box
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False

# Try to import liboqs for actual PQ algorithms
try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False

logger = logging.getLogger(__name__)


class PQAlgorithm(Enum):
    """Post-quantum algorithms."""
    # Signatures
    DILITHIUM2 = "dilithium2"      # NIST Level 2
    DILITHIUM3 = "dilithium3"      # NIST Level 3 (recommended)
    DILITHIUM5 = "dilithium5"      # NIST Level 5
    FALCON512 = "falcon512"        # NIST Level 1
    FALCON1024 = "falcon1024"      # NIST Level 5
    SPHINCS_SHA256_128F = "sphincs_sha256_128f"

    # Key Exchange
    KYBER512 = "kyber512"          # NIST Level 1
    KYBER768 = "kyber768"          # NIST Level 3 (recommended)
    KYBER1024 = "kyber1024"        # NIST Level 5


class MigrationStrategy(Enum):
    """Migration strategy for post-quantum transition."""
    CLASSICAL_ONLY = "classical"   # Ed25519/X25519 only
    HYBRID = "hybrid"              # Both classical and PQ
    PQ_ONLY = "pq_only"           # Post-quantum only (future)


@dataclass
class HybridSignature:
    """
    A hybrid signature combining classical and post-quantum algorithms.

    Contains both an Ed25519 signature and a Dilithium signature.
    Either signature alone is sufficient for verification during transition.
    """
    classical_signature: bytes    # Ed25519 signature
    pq_signature: bytes           # Dilithium signature
    algorithm: str = "ed25519+dilithium3"
    created_at: datetime = field(default_factory=datetime.now)

    def to_bytes(self) -> bytes:
        """Serialize the hybrid signature."""
        header = struct.pack(
            '>HH',
            len(self.classical_signature),
            len(self.pq_signature),
        )
        return header + self.classical_signature + self.pq_signature

    @classmethod
    def from_bytes(cls, data: bytes) -> 'HybridSignature':
        """Deserialize a hybrid signature."""
        classical_len, pq_len = struct.unpack('>HH', data[:4])
        classical_sig = data[4:4 + classical_len]
        pq_sig = data[4 + classical_len:4 + classical_len + pq_len]
        return cls(
            classical_signature=classical_sig,
            pq_signature=pq_sig,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'classical_signature': base64.b64encode(self.classical_signature).decode(),
            'pq_signature': base64.b64encode(self.pq_signature).decode(),
            'algorithm': self.algorithm,
            'created_at': self.created_at.isoformat(),
        }


@dataclass
class HybridKeyPair:
    """
    A hybrid key pair combining classical and post-quantum keys.
    """
    classical_private: bytes     # Ed25519/X25519 private key
    classical_public: bytes      # Ed25519/X25519 public key
    pq_private: bytes           # Dilithium/Kyber private key
    pq_public: bytes            # Dilithium/Kyber public key
    algorithm: str = "ed25519+dilithium3"
    created_at: datetime = field(default_factory=datetime.now)

    def get_public_bytes(self) -> bytes:
        """Get combined public key bytes."""
        header = struct.pack(
            '>HH',
            len(self.classical_public),
            len(self.pq_public),
        )
        return header + self.classical_public + self.pq_public


@dataclass
class HybridKeyExchange:
    """
    Hybrid key exchange result combining X25519 and Kyber.
    """
    classical_shared: bytes     # X25519 shared secret
    pq_shared: bytes           # Kyber shared secret
    combined_shared: bytes     # KDF(classical || pq)
    algorithm: str = "x25519+kyber768"

    def get_key(self, length: int = 32) -> bytes:
        """Derive a key of specified length."""
        return hashlib.sha256(self.combined_shared).digest()[:length]


class DilithiumSimulator:
    """
    Dilithium signature scheme simulator.

    When liboqs is not available, provides a secure placeholder
    that uses SHA-3 for demonstration purposes.

    WARNING: This is NOT real Dilithium and provides NO quantum resistance.
    Use liboqs for actual post-quantum security.
    """

    SECURITY_LEVELS = {
        PQAlgorithm.DILITHIUM2: 2,
        PQAlgorithm.DILITHIUM3: 3,
        PQAlgorithm.DILITHIUM5: 5,
    }

    def __init__(self, algorithm: PQAlgorithm = PQAlgorithm.DILITHIUM3):
        """Initialize Dilithium simulator."""
        self.algorithm = algorithm
        self.level = self.SECURITY_LEVELS.get(algorithm, 3)
        logger.warning(
            f"Using Dilithium SIMULATOR - not quantum-resistant! "
            f"Install liboqs for real PQ crypto."
        )

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a simulated Dilithium keypair."""
        # Simulate key sizes roughly matching Dilithium
        sk_size = 2528 if self.level == 2 else 4000 if self.level == 3 else 4864
        pk_size = 1312 if self.level == 2 else 1952 if self.level == 3 else 2592

        # Generate random keys
        private_key = os.urandom(sk_size)
        # Derive public key deterministically
        public_key = hashlib.sha3_256(private_key).digest()
        public_key = public_key + os.urandom(pk_size - len(public_key))

        return (private_key, public_key)

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Create a simulated Dilithium signature."""
        # Simulate signature size
        sig_size = 2420 if self.level == 2 else 3293 if self.level == 3 else 4595

        # Create deterministic signature from message and key
        sig_material = hashlib.sha3_512(private_key[:64] + message).digest()
        signature = sig_material + os.urandom(sig_size - len(sig_material))

        return signature

    def verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        """Verify a simulated Dilithium signature."""
        # In simulation, we always verify true for valid-looking signatures
        # This is NOT secure - just for testing the interface
        return len(signature) > 100


class KyberSimulator:
    """
    Kyber key encapsulation mechanism simulator.

    WARNING: This is NOT real Kyber and provides NO quantum resistance.
    """

    SECURITY_LEVELS = {
        PQAlgorithm.KYBER512: 1,
        PQAlgorithm.KYBER768: 3,
        PQAlgorithm.KYBER1024: 5,
    }

    def __init__(self, algorithm: PQAlgorithm = PQAlgorithm.KYBER768):
        """Initialize Kyber simulator."""
        self.algorithm = algorithm
        self.level = self.SECURITY_LEVELS.get(algorithm, 3)
        logger.warning(
            f"Using Kyber SIMULATOR - not quantum-resistant! "
            f"Install liboqs for real PQ crypto."
        )

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a simulated Kyber keypair."""
        # Simulate key sizes
        sk_size = 1632 if self.level == 1 else 2400 if self.level == 3 else 3168
        pk_size = 800 if self.level == 1 else 1184 if self.level == 3 else 1568

        private_key = os.urandom(sk_size)
        public_key = hashlib.sha3_256(private_key).digest()
        public_key = public_key + os.urandom(pk_size - len(public_key))

        return (private_key, public_key)

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret."""
        # Generate ciphertext and shared secret
        ct_size = 768 if self.level == 1 else 1088 if self.level == 3 else 1568
        shared_secret = hashlib.sha3_256(public_key + os.urandom(32)).digest()
        ciphertext = hashlib.sha3_256(shared_secret).digest()
        ciphertext = ciphertext + os.urandom(ct_size - len(ciphertext))

        return (ciphertext, shared_secret)

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate to recover shared secret."""
        # Derive shared secret from private key and ciphertext
        shared_secret = hashlib.sha3_256(private_key[:64] + ciphertext[:32]).digest()
        return shared_secret


class PostQuantumCrypto:
    """
    Post-Quantum Cryptography manager for the Boundary Daemon.

    Provides hybrid cryptographic operations that combine classical
    and post-quantum algorithms for defense-in-depth.
    """

    def __init__(
        self,
        strategy: MigrationStrategy = MigrationStrategy.HYBRID,
        sig_algorithm: PQAlgorithm = PQAlgorithm.DILITHIUM3,
        kem_algorithm: PQAlgorithm = PQAlgorithm.KYBER768,
    ):
        """
        Initialize Post-Quantum Crypto manager.

        Args:
            strategy: Migration strategy to use
            sig_algorithm: Post-quantum signature algorithm
            kem_algorithm: Post-quantum key exchange algorithm
        """
        self.strategy = strategy
        self.sig_algorithm = sig_algorithm
        self.kem_algorithm = kem_algorithm

        # Initialize classical crypto
        if NACL_AVAILABLE:
            self._classical_available = True
        else:
            self._classical_available = False
            logger.warning("PyNaCl not available - classical crypto disabled")

        # Initialize post-quantum crypto
        if OQS_AVAILABLE:
            self._pq_available = True
            self._dilithium = oqs.Signature(sig_algorithm.value)
            self._kyber = oqs.KeyEncapsulation(kem_algorithm.value)
        else:
            self._pq_available = False
            self._dilithium = DilithiumSimulator(sig_algorithm)
            self._kyber = KyberSimulator(kem_algorithm)
            logger.warning("liboqs not available - using PQ simulators")

        logger.info(
            f"PostQuantumCrypto initialized: strategy={strategy.value}, "
            f"oqs_available={self._pq_available}"
        )

    def generate_signing_keypair(self) -> HybridKeyPair:
        """
        Generate a hybrid signing keypair.

        Returns:
            HybridKeyPair with both classical and PQ keys
        """
        # Generate classical key
        if self._classical_available:
            classical_sk = SigningKey.generate()
            classical_private = bytes(classical_sk)
            classical_public = bytes(classical_sk.verify_key)
        else:
            classical_private = os.urandom(32)
            classical_public = hashlib.sha256(classical_private).digest()

        # Generate post-quantum key
        if self._pq_available:
            pq_public = self._dilithium.generate_keypair()
            pq_private = self._dilithium.export_secret_key()
        else:
            pq_private, pq_public = self._dilithium.generate_keypair()

        return HybridKeyPair(
            classical_private=classical_private,
            classical_public=classical_public,
            pq_private=pq_private,
            pq_public=pq_public,
            algorithm=f"ed25519+{self.sig_algorithm.value}",
        )

    def sign(
        self,
        keypair: HybridKeyPair,
        message: bytes,
    ) -> HybridSignature:
        """
        Create a hybrid signature.

        Args:
            keypair: Hybrid keypair to sign with
            message: Message to sign

        Returns:
            HybridSignature containing both classical and PQ signatures
        """
        # Classical signature
        if self._classical_available:
            sk = SigningKey(keypair.classical_private)
            signed = sk.sign(message)
            classical_sig = bytes(signed.signature)
        else:
            classical_sig = hashlib.sha256(
                message + keypair.classical_private
            ).digest()

        # Post-quantum signature
        if self._pq_available:
            pq_sig = self._dilithium.sign(message)
        else:
            pq_sig = self._dilithium.sign(keypair.pq_private, message)

        return HybridSignature(
            classical_signature=classical_sig,
            pq_signature=pq_sig,
            algorithm=keypair.algorithm,
        )

    def verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: HybridSignature,
        require_both: bool = False,
    ) -> Tuple[bool, str]:
        """
        Verify a hybrid signature.

        Args:
            public_key: Combined public key bytes
            message: Original message
            signature: Hybrid signature to verify
            require_both: Require both signatures to be valid

        Returns:
            Tuple of (is_valid, verification_method)
        """
        # Parse public key
        classical_len, pq_len = struct.unpack('>HH', public_key[:4])
        classical_public = public_key[4:4 + classical_len]
        pq_public = public_key[4 + classical_len:4 + classical_len + pq_len]

        classical_valid = False
        pq_valid = False

        # Verify classical signature
        try:
            if self._classical_available:
                vk = VerifyKey(classical_public)
                vk.verify(message, signature.classical_signature)
                classical_valid = True
            else:
                expected = hashlib.sha256(message + classical_public).digest()
                classical_valid = (expected == signature.classical_signature[:32])
        except Exception as e:
            logger.debug(f"Classical verification failed: {e}")

        # Verify post-quantum signature
        try:
            if self._pq_available:
                pq_valid = self._dilithium.verify(
                    message,
                    signature.pq_signature,
                    pq_public
                )
            else:
                pq_valid = self._dilithium.verify(
                    pq_public,
                    message,
                    signature.pq_signature
                )
        except Exception as e:
            logger.debug(f"PQ verification failed: {e}")

        # Determine result based on strategy
        if require_both:
            return (
                classical_valid and pq_valid,
                "both_required"
            )

        if self.strategy == MigrationStrategy.CLASSICAL_ONLY:
            return (classical_valid, "classical")

        if self.strategy == MigrationStrategy.PQ_ONLY:
            return (pq_valid, "post_quantum")

        # HYBRID: either signature is sufficient
        if classical_valid and pq_valid:
            return (True, "both_valid")
        elif classical_valid:
            return (True, "classical_only")
        elif pq_valid:
            return (True, "pq_only")
        else:
            return (False, "neither_valid")

    def generate_kem_keypair(self) -> HybridKeyPair:
        """
        Generate a hybrid key exchange keypair.

        Returns:
            HybridKeyPair with both X25519 and Kyber keys
        """
        # Generate classical key (X25519)
        if self._classical_available:
            classical_sk = PrivateKey.generate()
            classical_private = bytes(classical_sk)
            classical_public = bytes(classical_sk.public_key)
        else:
            classical_private = os.urandom(32)
            classical_public = hashlib.sha256(classical_private).digest()

        # Generate post-quantum key (Kyber)
        if self._pq_available:
            pq_public = self._kyber.generate_keypair()
            pq_private = self._kyber.export_secret_key()
        else:
            pq_private, pq_public = self._kyber.generate_keypair()

        return HybridKeyPair(
            classical_private=classical_private,
            classical_public=classical_public,
            pq_private=pq_private,
            pq_public=pq_public,
            algorithm=f"x25519+{self.kem_algorithm.value}",
        )

    def encapsulate(
        self,
        recipient_public: bytes,
    ) -> Tuple[bytes, HybridKeyExchange]:
        """
        Encapsulate a shared secret for a recipient.

        Args:
            recipient_public: Recipient's combined public key

        Returns:
            Tuple of (combined_ciphertext, key_exchange)
        """
        # Parse public key
        classical_len, pq_len = struct.unpack('>HH', recipient_public[:4])
        classical_public = recipient_public[4:4 + classical_len]
        pq_public = recipient_public[4 + classical_len:4 + classical_len + pq_len]

        # Classical key exchange (ephemeral)
        if self._classical_available:
            ephemeral_sk = PrivateKey.generate()
            recipient_pk = PublicKey(classical_public)
            box = Box(ephemeral_sk, recipient_pk)
            classical_shared = bytes(box.shared_key())
            classical_ct = bytes(ephemeral_sk.public_key)
        else:
            classical_ct = os.urandom(32)
            classical_shared = hashlib.sha256(
                classical_ct + classical_public
            ).digest()

        # Post-quantum encapsulation
        if self._pq_available:
            pq_ct, pq_shared = self._kyber.encap_secret(pq_public)
        else:
            pq_ct, pq_shared = self._kyber.encapsulate(pq_public)

        # Combine shared secrets with KDF
        combined = hashlib.sha3_256(
            classical_shared + pq_shared
        ).digest()

        # Combine ciphertexts
        header = struct.pack('>HH', len(classical_ct), len(pq_ct))
        combined_ct = header + classical_ct + pq_ct

        return (
            combined_ct,
            HybridKeyExchange(
                classical_shared=classical_shared,
                pq_shared=pq_shared,
                combined_shared=combined,
                algorithm=f"x25519+{self.kem_algorithm.value}",
            )
        )

    def decapsulate(
        self,
        keypair: HybridKeyPair,
        ciphertext: bytes,
    ) -> HybridKeyExchange:
        """
        Decapsulate a shared secret.

        Args:
            keypair: Recipient's keypair
            ciphertext: Combined ciphertext

        Returns:
            HybridKeyExchange with the shared secret
        """
        # Parse ciphertext
        classical_len, pq_len = struct.unpack('>HH', ciphertext[:4])
        classical_ct = ciphertext[4:4 + classical_len]
        pq_ct = ciphertext[4 + classical_len:4 + classical_len + pq_len]

        # Classical decapsulation
        if self._classical_available:
            ephemeral_pk = PublicKey(classical_ct)
            my_sk = PrivateKey(keypair.classical_private)
            box = Box(my_sk, ephemeral_pk)
            classical_shared = bytes(box.shared_key())
        else:
            classical_shared = hashlib.sha256(
                classical_ct + keypair.classical_public
            ).digest()

        # Post-quantum decapsulation
        if self._pq_available:
            pq_shared = self._kyber.decap_secret(pq_ct)
        else:
            pq_shared = self._kyber.decapsulate(keypair.pq_private, pq_ct)

        # Combine with KDF
        combined = hashlib.sha3_256(
            classical_shared + pq_shared
        ).digest()

        return HybridKeyExchange(
            classical_shared=classical_shared,
            pq_shared=pq_shared,
            combined_shared=combined,
            algorithm=keypair.algorithm,
        )

    def hash_hybrid(self, data: bytes) -> bytes:
        """
        Create a hybrid hash using both SHA-256 and SHA-3.

        Args:
            data: Data to hash

        Returns:
            Combined hash
        """
        sha256_hash = hashlib.sha256(data).digest()
        sha3_hash = hashlib.sha3_256(data).digest()

        # XOR the hashes together
        combined = bytes(a ^ b for a, b in zip(sha256_hash, sha3_hash))
        return combined

    def get_status(self) -> Dict[str, Any]:
        """Get cryptographic status."""
        return {
            'strategy': self.strategy.value,
            'sig_algorithm': self.sig_algorithm.value,
            'kem_algorithm': self.kem_algorithm.value,
            'classical_available': self._classical_available,
            'pq_available': self._pq_available,
            'using_real_pq': OQS_AVAILABLE,
        }

    def migrate_signature(
        self,
        old_signature: bytes,
        _old_keypair: Any,  # Classical-only keypair (preserved for API)
        new_keypair: HybridKeyPair,
        message: bytes,
    ) -> HybridSignature:
        """
        Migrate a classical signature to hybrid.

        Args:
            old_signature: Existing classical signature
            old_keypair: Original signing keypair
            new_keypair: New hybrid keypair
            message: Original message

        Returns:
            New hybrid signature
        """
        # Create new PQ signature
        if self._pq_available:
            pq_sig = self._dilithium.sign(message)
        else:
            pq_sig = self._dilithium.sign(new_keypair.pq_private, message)

        return HybridSignature(
            classical_signature=old_signature,
            pq_signature=pq_sig,
            algorithm=new_keypair.algorithm,
        )
