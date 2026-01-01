"""
Code Signer - Build-time signing for daemon modules.

Phase 1 Critical Security: Cryptographically sign all daemon modules
at build time to enable tamper detection at runtime.

Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │                     BUILD-TIME SIGNING                          │
    ├─────────────────────────────────────────────────────────────────┤
    │                                                                 │
    │  Source Files                    Signing Process               │
    │  ┌────────────────┐             ┌────────────────┐             │
    │  │ daemon/*.py    │────────────►│  Hash (SHA256) │             │
    │  │ daemon/**/*.py │             └───────┬────────┘             │
    │  └────────────────┘                     │                       │
    │                                         ▼                       │
    │                              ┌────────────────────┐            │
    │                              │    manifest.json   │            │
    │                              │  ┌──────────────┐  │            │
    │                              │  │ file: hash   │  │            │
    │                              │  │ file: hash   │  │            │
    │                              │  │ ...          │  │            │
    │                              │  └──────────────┘  │            │
    │                              └─────────┬──────────┘            │
    │                                        │                        │
    │                                        ▼                        │
    │                              ┌────────────────────┐            │
    │  Signing Key                 │   Sign Manifest    │            │
    │  ┌────────────────┐         │   (Ed25519)        │            │
    │  │ Private Key    │────────►│                    │            │
    │  │ (offline)      │         └─────────┬──────────┘            │
    │  └────────────────┘                   │                        │
    │                                       ▼                        │
    │                              ┌────────────────────┐            │
    │                              │ manifest.json.sig  │            │
    │                              └────────────────────┘            │
    │                                                                 │
    │  Public Key (embedded in config) ──► Runtime Verification      │
    └─────────────────────────────────────────────────────────────────┘

Security Properties:
- SHA-256 hash of each module
- Ed25519 signature of manifest
- Public key embedded in verified config
- Any modification detected at startup
"""

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.encoding import HexEncoder
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class ModuleHash:
    """Hash information for a single module."""
    path: str                    # Relative path from daemon root
    sha256: str                  # SHA-256 hash (hex)
    size: int                    # File size in bytes
    modified: str                # Last modified timestamp (ISO format)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'path': self.path,
            'sha256': self.sha256,
            'size': self.size,
            'modified': self.modified,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ModuleHash':
        """Create from dictionary."""
        return cls(
            path=data['path'],
            sha256=data['sha256'],
            size=data['size'],
            modified=data['modified'],
        )


@dataclass
class SigningManifest:
    """Manifest of all signed modules."""
    version: str                           # Manifest format version
    daemon_version: str                    # Daemon version being signed
    created_at: str                        # Signing timestamp (ISO format)
    signer_id: str                         # Identifier of signer
    public_key: str                        # Ed25519 public key (hex)
    modules: List[ModuleHash]              # All module hashes
    excluded_patterns: List[str]           # Patterns excluded from signing
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'version': self.version,
            'daemon_version': self.daemon_version,
            'created_at': self.created_at,
            'signer_id': self.signer_id,
            'public_key': self.public_key,
            'modules': [m.to_dict() for m in self.modules],
            'excluded_patterns': self.excluded_patterns,
            'metadata': self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SigningManifest':
        """Create from dictionary."""
        return cls(
            version=data['version'],
            daemon_version=data['daemon_version'],
            created_at=data['created_at'],
            signer_id=data['signer_id'],
            public_key=data['public_key'],
            modules=[ModuleHash.from_dict(m) for m in data['modules']],
            excluded_patterns=data.get('excluded_patterns', []),
            metadata=data.get('metadata', {}),
        )

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_json(cls, json_str: str) -> 'SigningManifest':
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def get_canonical_bytes(self) -> bytes:
        """Get canonical byte representation for signing."""
        # Sort keys for reproducibility
        return json.dumps(self.to_dict(), sort_keys=True).encode('utf-8')


class CodeSigner:
    """
    Code Signer - signs daemon modules at build time.

    Usage:
        signer = CodeSigner(signing_key_path='/path/to/key')
        manifest = signer.sign_directory('/path/to/daemon')
        signer.save_manifest(manifest, '/path/to/manifest.json')
    """

    # Default patterns to exclude from signing
    DEFAULT_EXCLUSIONS = [
        '__pycache__',
        '*.pyc',
        '*.pyo',
        '.git',
        '.pytest_cache',
        'tests/',
        '*.egg-info',
        'build/',
        'dist/',
        '.tox/',
        '.venv/',
        'venv/',
    ]

    MANIFEST_VERSION = "1.0"

    def __init__(
        self,
        signing_key: Optional[bytes] = None,
        signing_key_path: Optional[str] = None,
        signer_id: str = "build-system",
        exclusions: Optional[List[str]] = None,
    ):
        """
        Initialize the code signer.

        Args:
            signing_key: Ed25519 signing key bytes
            signing_key_path: Path to signing key file
            signer_id: Identifier for the signer
            exclusions: Patterns to exclude from signing
        """
        self.signer_id = signer_id
        self.exclusions = exclusions or self.DEFAULT_EXCLUSIONS

        # Load signing key
        if signing_key:
            self._signing_key = SigningKey(signing_key) if NACL_AVAILABLE else None
        elif signing_key_path:
            self._signing_key = self._load_key(signing_key_path)
        else:
            self._signing_key = None

        if self._signing_key and NACL_AVAILABLE:
            self._verify_key = self._signing_key.verify_key
            self.public_key = bytes(self._verify_key).hex()
        else:
            self._verify_key = None
            self.public_key = ""

        logger.info(f"CodeSigner initialized (signer_id={signer_id})")

    def _load_key(self, key_path: str) -> Optional['SigningKey']:
        """Load signing key from file."""
        if not NACL_AVAILABLE:
            logger.warning("PyNaCl not available - cannot load signing key")
            return None

        try:
            with open(key_path, 'rb') as f:
                key_data = f.read()
                # Support both raw and hex-encoded keys
                if len(key_data) == 64:  # Hex encoded
                    key_data = bytes.fromhex(key_data.decode().strip())
                return SigningKey(key_data)
        except Exception as e:
            logger.error(f"Failed to load signing key: {e}")
            raise

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new Ed25519 keypair for signing.

        Returns:
            Tuple of (private_key_bytes, public_key_bytes)
        """
        if not NACL_AVAILABLE:
            raise RuntimeError("PyNaCl required for key generation")

        signing_key = SigningKey.generate()
        private_key = bytes(signing_key)
        public_key = bytes(signing_key.verify_key)

        logger.info("Generated new signing keypair")
        return (private_key, public_key)

    def hash_file(self, file_path: str) -> ModuleHash:
        """
        Compute hash of a single file.

        Args:
            file_path: Path to the file

        Returns:
            ModuleHash with file details
        """
        path = Path(file_path)

        with open(path, 'rb') as f:
            content = f.read()
            sha256 = hashlib.sha256(content).hexdigest()

        stat = path.stat()

        return ModuleHash(
            path=str(path),
            sha256=sha256,
            size=stat.st_size,
            modified=datetime.fromtimestamp(stat.st_mtime).isoformat(),
        )

    def _should_include(self, path: Path, base_path: Path) -> bool:
        """Check if a file should be included in signing."""
        rel_path = str(path.relative_to(base_path))

        for pattern in self.exclusions:
            if pattern.endswith('/'):
                # Directory pattern
                if rel_path.startswith(pattern) or f'/{pattern}' in rel_path:
                    return False
            elif pattern.startswith('*.'):
                # Extension pattern
                if path.suffix == pattern[1:]:
                    return False
            else:
                # Exact match or contains
                if pattern in rel_path:
                    return False

        return True

    def hash_directory(
        self,
        directory: str,
        extensions: Optional[List[str]] = None,
    ) -> List[ModuleHash]:
        """
        Hash all matching files in a directory.

        Args:
            directory: Path to directory
            extensions: File extensions to include (default: ['.py'])

        Returns:
            List of ModuleHash objects
        """
        extensions = extensions or ['.py']
        base_path = Path(directory)
        hashes = []

        for ext in extensions:
            for file_path in base_path.rglob(f'*{ext}'):
                if self._should_include(file_path, base_path):
                    try:
                        rel_path = file_path.relative_to(base_path)
                        module_hash = self.hash_file(str(file_path))
                        module_hash.path = str(rel_path)
                        hashes.append(module_hash)
                    except Exception as e:
                        logger.warning(f"Failed to hash {file_path}: {e}")

        # Sort for reproducibility
        hashes.sort(key=lambda h: h.path)

        logger.info(f"Hashed {len(hashes)} files in {directory}")
        return hashes

    def create_manifest(
        self,
        directory: str,
        daemon_version: str,
        extensions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SigningManifest:
        """
        Create a signing manifest for a directory.

        Args:
            directory: Path to daemon directory
            daemon_version: Version string
            extensions: File extensions to include
            metadata: Additional metadata

        Returns:
            SigningManifest (unsigned)
        """
        modules = self.hash_directory(directory, extensions)

        manifest = SigningManifest(
            version=self.MANIFEST_VERSION,
            daemon_version=daemon_version,
            created_at=datetime.now().isoformat(),
            signer_id=self.signer_id,
            public_key=self.public_key,
            modules=modules,
            excluded_patterns=self.exclusions,
            metadata=metadata or {},
        )

        logger.info(
            f"Created manifest for {daemon_version} with {len(modules)} modules"
        )
        return manifest

    def sign_manifest(self, manifest: SigningManifest) -> bytes:
        """
        Sign a manifest.

        Args:
            manifest: The manifest to sign

        Returns:
            Ed25519 signature bytes
        """
        if not NACL_AVAILABLE or not self._signing_key:
            raise RuntimeError("Signing key not available")

        canonical_bytes = manifest.get_canonical_bytes()
        signed = self._signing_key.sign(canonical_bytes)

        logger.info(f"Signed manifest for {manifest.daemon_version}")
        return bytes(signed.signature)

    def sign_directory(
        self,
        directory: str,
        daemon_version: str,
        extensions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[SigningManifest, bytes]:
        """
        Create and sign a manifest for a directory.

        Args:
            directory: Path to daemon directory
            daemon_version: Version string
            extensions: File extensions to include
            metadata: Additional metadata

        Returns:
            Tuple of (manifest, signature)
        """
        manifest = self.create_manifest(
            directory,
            daemon_version,
            extensions,
            metadata,
        )
        signature = self.sign_manifest(manifest)
        return (manifest, signature)

    def save_manifest(
        self,
        manifest: SigningManifest,
        signature: bytes,
        manifest_path: str,
    ) -> None:
        """
        Save manifest and signature to files.

        Args:
            manifest: The manifest
            signature: The signature
            manifest_path: Path for manifest file
        """
        # Save manifest
        with open(manifest_path, 'w') as f:
            f.write(manifest.to_json())

        # Save signature
        sig_path = manifest_path + '.sig'
        with open(sig_path, 'wb') as f:
            f.write(signature)

        logger.info(f"Saved manifest to {manifest_path}")
        logger.info(f"Saved signature to {sig_path}")

    @staticmethod
    def verify_signature(
        manifest: SigningManifest,
        signature: bytes,
        public_key: Optional[bytes] = None,
    ) -> bool:
        """
        Verify a manifest signature.

        Args:
            manifest: The manifest
            signature: The signature
            public_key: Public key bytes (uses manifest key if not provided)

        Returns:
            True if valid, False otherwise
        """
        if not NACL_AVAILABLE:
            logger.warning("PyNaCl not available - cannot verify signature")
            return False

        try:
            if public_key is None:
                public_key = bytes.fromhex(manifest.public_key)

            verify_key = VerifyKey(public_key)
            canonical_bytes = manifest.get_canonical_bytes()
            verify_key.verify(canonical_bytes, signature)
            return True
        except Exception as e:
            logger.warning(f"Signature verification failed: {e}")
            return False


def sign_daemon_release(
    daemon_dir: str,
    version: str,
    signing_key_path: str,
    output_dir: Optional[str] = None,
    signer_id: str = "release-build",
) -> Tuple[str, str]:
    """
    Sign a daemon release.

    Convenience function for build scripts.

    Args:
        daemon_dir: Path to daemon source directory
        version: Version string
        signing_key_path: Path to signing key
        output_dir: Output directory (default: daemon_dir)
        signer_id: Signer identifier

    Returns:
        Tuple of (manifest_path, signature_path)
    """
    signer = CodeSigner(
        signing_key_path=signing_key_path,
        signer_id=signer_id,
    )

    manifest, signature = signer.sign_directory(
        daemon_dir,
        version,
        metadata={
            'build_time': datetime.now().isoformat(),
            'build_host': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
        },
    )

    output_dir = output_dir or daemon_dir
    manifest_path = os.path.join(output_dir, 'manifest.json')

    signer.save_manifest(manifest, signature, manifest_path)

    return (manifest_path, manifest_path + '.sig')
