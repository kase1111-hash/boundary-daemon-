"""
Secure Token Storage - Encrypted storage for API tokens and secrets.

Provides:
- Encryption at rest using Fernet (AES-128-CBC with HMAC)
- Machine-derived encryption keys
- Secure token file creation and reading
- Environment variable security warnings

SECURITY: Addresses Critical Finding "Insecure Token Storage"
- Bootstrap tokens are now encrypted before writing to disk
- Token file exports support encryption
- Clear warnings about environment variable security risks
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import platform
import secrets
import stat
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
import logging

logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = sys.platform == 'win32'

# Import secure memory utilities for key cleanup
try:
    from daemon.security.secure_memory import (
        SecureBytes,
        secure_zero_memory,
        secure_key_context,
    )
    SECURE_MEMORY_AVAILABLE = True
except ImportError:
    SECURE_MEMORY_AVAILABLE = False
    SecureBytes = None
    secure_zero_memory = None
    secure_key_context = None

# Try to import cryptography library, fall back to a simpler approach if not available
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("cryptography library not available - using fallback encryption")


class SecureTokenStorage:
    """
    Handles secure storage of tokens with encryption at rest.

    Features:
    - Machine-derived key for encryption (tied to hardware/installation)
    - Fernet encryption (AES-128-CBC with HMAC-SHA256)
    - Secure file permissions (0o600)
    - Atomic writes with fsync
    - Clear security warnings for risky operations
    """

    # File format markers
    ENCRYPTED_HEADER = "# BOUNDARY-DAEMON-ENCRYPTED-TOKEN v1\n"
    PLAINTEXT_WARNING = "# WARNING: This file contains sensitive credentials\n"

    # Key derivation parameters
    KDF_ITERATIONS = 480000  # OWASP recommended minimum for PBKDF2-SHA256

    def __init__(self, key_file: Optional[str] = None):
        """
        Initialize secure token storage.

        Args:
            key_file: Path to store/load the master encryption key.
                     If None, uses machine-derived key only.
        """
        self._key_file = Path(key_file) if key_file else None
        self._encryption_key: Optional[bytes] = None

        # SECURITY: Track key material for secure cleanup
        self._key_material: Optional[bytearray] = None

        # Initialize encryption key
        self._initialize_key()

    def __del__(self):
        """Destructor - ensure encryption keys are zeroed."""
        self.cleanup()

    def cleanup(self) -> bool:
        """
        Securely zero encryption keys from memory.

        SECURITY: Call this method when the SecureTokenStorage instance
        is no longer needed to minimize the exposure window for
        encryption key material in memory.

        Returns:
            True if cleanup was successful
        """
        success = True

        # Zero the key material if secure memory is available
        if self._key_material is not None:
            if SECURE_MEMORY_AVAILABLE and secure_zero_memory:
                try:
                    if not secure_zero_memory(self._key_material):
                        logger.warning("Failed to zero token encryption key material")
                        success = False
                except Exception as e:
                    logger.warning(f"Error zeroing key material: {e}")
                    success = False
            else:
                # Fallback: manual zeroing
                for i in range(len(self._key_material)):
                    self._key_material[i] = 0
            self._key_material = None

        # Clear the encryption key
        self._encryption_key = None

        # Force garbage collection
        import gc
        gc.collect()

        if success:
            logger.debug("Token encryption keys zeroed from memory")

        return success

    def _initialize_key(self):
        """Initialize the encryption key from file or derive from machine ID."""
        if self._key_file and self._key_file.exists():
            try:
                # Load existing key
                with open(self._key_file, 'rb') as f:
                    key_data = f.read()
                self._encryption_key = key_data
                return
            except Exception as e:
                logger.warning(f"Failed to load key file: {e}")

        # Derive key from machine characteristics
        machine_key = self._derive_machine_key()

        if self._key_file:
            # Store the derived key for future use
            try:
                self._key_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self._key_file, 'wb') as f:
                    f.write(machine_key)
                os.chmod(self._key_file, 0o600)
            except Exception as e:
                logger.warning(f"Failed to save key file: {e}")

        self._encryption_key = machine_key

    def _derive_machine_key(self) -> bytes:
        """
        Derive an encryption key from machine-specific characteristics.

        This ties the encryption to this specific machine installation,
        making it harder for attackers to decrypt tokens if they steal
        the token file but not the machine access.
        """
        # Collect machine-specific data
        machine_data = []

        if IS_WINDOWS:
            # Windows: Use machine GUID from registry
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Cryptography"
                )
                machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                winreg.CloseKey(key)
                machine_data.append(machine_guid)
            except Exception:
                pass
        else:
            # Machine ID (Linux)
            machine_id_path = Path("/etc/machine-id")
            if machine_id_path.exists():
                try:
                    machine_data.append(machine_id_path.read_text().strip())
                except Exception:
                    pass

        # Hostname (cross-platform)
        try:
            machine_data.append(platform.node())
        except Exception:
            pass

        # Installation-specific salt (created once)
        salt_path = Path("./config/.token_salt")
        if salt_path.exists():
            try:
                salt = salt_path.read_bytes()
            except Exception:
                salt = secrets.token_bytes(32)
        else:
            salt = secrets.token_bytes(32)
            try:
                salt_path.parent.mkdir(parents=True, exist_ok=True)
                with open(salt_path, 'wb') as f:
                    f.write(salt)
                os.chmod(salt_path, 0o600)
            except Exception:
                pass

        # Combine and derive key
        # SECURITY: Use bytearray so we can zero it after derivation
        combined = bytearray("|".join(machine_data).encode() + salt)

        try:
            if CRYPTO_AVAILABLE:
                # Use proper KDF
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=self.KDF_ITERATIONS,
                )
                derived = kdf.derive(bytes(combined))
                key = base64.urlsafe_b64encode(derived)

                # SECURITY: Track derived key material for later cleanup
                self._key_material = bytearray(derived)
            else:
                # Fallback: simple PBKDF2 implementation
                derived = self._simple_pbkdf2(bytes(combined), salt, 32)
                key = base64.urlsafe_b64encode(derived)

                # SECURITY: Track derived key material for later cleanup
                self._key_material = bytearray(derived)

            return key
        finally:
            # SECURITY: Zero the combined input data after derivation
            if SECURE_MEMORY_AVAILABLE and secure_zero_memory:
                secure_zero_memory(combined)
            else:
                # Fallback: manual zeroing
                for i in range(len(combined)):
                    combined[i] = 0

    def _simple_pbkdf2(self, password: bytes, salt: bytes, key_length: int) -> bytes:
        """Simple PBKDF2 fallback when cryptography is not available."""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password,
            salt,
            self.KDF_ITERATIONS,
            dklen=key_length
        )

    def encrypt_token(self, token: str, metadata: Optional[Dict] = None) -> bytes:
        """
        Encrypt a token for secure storage.

        Args:
            token: The plaintext token to encrypt
            metadata: Optional metadata to include (name, created, etc.)

        Returns:
            Encrypted token data ready for storage
        """
        if not self._encryption_key:
            raise RuntimeError("Encryption key not initialized")

        # Create payload with metadata
        payload = {
            'token': token,
            'encrypted_at': datetime.utcnow().isoformat() + "Z",
            'version': 1,
        }
        if metadata:
            payload['metadata'] = metadata

        payload_json = json.dumps(payload).encode()

        if CRYPTO_AVAILABLE:
            # Use Fernet encryption
            f = Fernet(self._encryption_key)
            encrypted = f.encrypt(payload_json)
        else:
            # Fallback: XOR with key stream (less secure but better than plaintext)
            encrypted = self._fallback_encrypt(payload_json)

        return encrypted

    def decrypt_token(self, encrypted_data: bytes) -> Tuple[str, Dict]:
        """
        Decrypt a token from secure storage.

        Args:
            encrypted_data: The encrypted token data

        Returns:
            (token, metadata) tuple
        """
        if not self._encryption_key:
            raise RuntimeError("Encryption key not initialized")

        if CRYPTO_AVAILABLE:
            f = Fernet(self._encryption_key)
            decrypted = f.decrypt(encrypted_data)
        else:
            decrypted = self._fallback_decrypt(encrypted_data)

        payload = json.loads(decrypted.decode())
        return payload['token'], payload.get('metadata', {})

    def _fallback_encrypt(self, data: bytes) -> bytes:
        """Fallback encryption when cryptography is not available."""
        # Generate a random IV
        iv = secrets.token_bytes(16)

        # Derive a key stream using HMAC
        key_stream = b''
        counter = 0
        while len(key_stream) < len(data):
            key_stream += hmac.new(
                self._encryption_key,
                iv + counter.to_bytes(4, 'big'),
                hashlib.sha256
            ).digest()
            counter += 1

        # XOR with data
        encrypted = bytes(a ^ b for a, b in zip(data, key_stream[:len(data)]))

        # Add HMAC for integrity
        mac = hmac.new(self._encryption_key, iv + encrypted, hashlib.sha256).digest()

        return iv + encrypted + mac

    def _fallback_decrypt(self, data: bytes) -> bytes:
        """Fallback decryption when cryptography is not available."""
        if len(data) < 48:  # 16 (IV) + 32 (HMAC)
            raise ValueError("Invalid encrypted data")

        iv = data[:16]
        encrypted = data[16:-32]
        mac = data[-32:]

        # Verify HMAC
        expected_mac = hmac.new(self._encryption_key, iv + encrypted, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("Invalid MAC - data may be corrupted or tampered")

        # Derive key stream
        key_stream = b''
        counter = 0
        while len(key_stream) < len(encrypted):
            key_stream += hmac.new(
                self._encryption_key,
                iv + counter.to_bytes(4, 'big'),
                hashlib.sha256
            ).digest()
            counter += 1

        # XOR to decrypt
        return bytes(a ^ b for a, b in zip(encrypted, key_stream[:len(encrypted)]))

    def write_encrypted_token_file(
        self,
        file_path: str,
        token: str,
        name: str,
        capabilities: str = "",
        expires: str = "",
    ) -> Tuple[bool, str]:
        """
        Write a token to an encrypted file.

        Args:
            file_path: Path to write the encrypted token file
            token: The plaintext token
            name: Token name/description
            capabilities: Token capabilities string
            expires: Expiration date string

        Returns:
            (success, message)
        """
        try:
            metadata = {
                'name': name,
                'capabilities': capabilities,
                'expires': expires,
                'created': datetime.utcnow().isoformat() + "Z",
            }

            encrypted = self.encrypt_token(token, metadata)

            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)

            # Write atomically
            temp_path = path.with_suffix('.tmp')
            with open(temp_path, 'wb') as f:
                # Write header
                f.write(self.ENCRYPTED_HEADER.encode())
                f.write(f"# Name: {name}\n".encode())
                f.write(f"# Created: {metadata['created']}\n".encode())
                f.write(f"# To decrypt: authctl decrypt {file_path}\n".encode())
                f.write(b"#\n")
                # Write encrypted data (base64 encoded for safe storage)
                f.write(base64.b64encode(encrypted))
                f.write(b"\n")
                f.flush()
                os.fsync(f.fileno())

            os.chmod(temp_path, 0o600)
            temp_path.rename(path)

            logger.info(f"Encrypted token saved to: {file_path}")
            return (True, f"Encrypted token saved to: {file_path}")

        except Exception as e:
            logger.error(f"Failed to write encrypted token: {e}")
            return (False, str(e))

    def read_encrypted_token_file(self, file_path: str) -> Tuple[Optional[str], Dict, str]:
        """
        Read and decrypt a token from an encrypted file.

        Args:
            file_path: Path to the encrypted token file

        Returns:
            (token, metadata, message) - token is None on failure
        """
        try:
            path = Path(file_path)
            if not path.exists():
                return (None, {}, f"File not found: {file_path}")

            with open(path, 'rb') as f:
                content = f.read()

            # Check if encrypted
            if not content.startswith(self.ENCRYPTED_HEADER.encode()):
                # Might be a plaintext token file
                return self._read_plaintext_token_file(content)

            # Find the encrypted data (after header comments)
            lines = content.split(b"\n")
            encrypted_b64 = None
            for line in lines:
                line = line.strip()
                if line and not line.startswith(b"#"):
                    encrypted_b64 = line
                    break

            if not encrypted_b64:
                return (None, {}, "No encrypted data found in file")

            encrypted = base64.b64decode(encrypted_b64)
            token, metadata = self.decrypt_token(encrypted)

            return (token, metadata, "Decryption successful")

        except Exception as e:
            logger.error(f"Failed to read encrypted token: {e}")
            return (None, {}, str(e))

    def _read_plaintext_token_file(self, content: bytes) -> Tuple[Optional[str], Dict, str]:
        """Handle reading legacy plaintext token files with a warning."""
        logger.warning("SECURITY: Reading plaintext token file - consider re-encrypting")

        try:
            lines = content.decode().strip().split('\n')
            token = None
            metadata = {}

            for line in lines:
                line = line.strip()
                if line.startswith('#'):
                    # Parse metadata from comments
                    if ':' in line:
                        key, value = line[1:].split(':', 1)
                        metadata[key.strip().lower()] = value.strip()
                elif line and line.startswith('bd_'):
                    # Token line
                    token = line
                    break

            if not token:
                return (None, metadata, "No token found in file")

            return (token, metadata, "WARNING: Read from plaintext file - consider encrypting")

        except Exception as e:
            return (None, {}, f"Failed to parse plaintext token file: {e}")

    def encrypt_bootstrap_token(
        self,
        token: str,
        output_path: str,
    ) -> Tuple[bool, str]:
        """
        Securely store a bootstrap token.

        Args:
            token: The bootstrap token
            output_path: Path to store the encrypted token

        Returns:
            (success, message)
        """
        return self.write_encrypted_token_file(
            file_path=output_path,
            token=token,
            name="bootstrap-admin",
            capabilities="ADMIN (full access)",
            expires="Never",
        )

    @staticmethod
    def print_env_var_warning():
        """Print security warning about environment variable token storage."""
        warning = """
================================================================================
  SECURITY WARNING: Environment Variable Token Storage
================================================================================

  Storing tokens in environment variables (BOUNDARY_API_TOKEN) has risks:

  1. Process listing: Other users may see via 'ps auxe' or /proc
  2. Log leakage: May appear in shell history, debug logs, crash dumps
  3. Child process inheritance: Tokens passed to all child processes
  4. Memory persistence: Stays in process memory until exit

  SAFER ALTERNATIVES:

  1. Token file (encrypted):
     authctl create --name "my-token" --encrypt --output token.enc
     boundaryctl --token-file token.enc status

  2. Token file (restricted permissions):
     chmod 600 ~/.boundary_token
     boundaryctl --token-file ~/.boundary_token status

  3. For production:
     - Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, etc.)
     - Rotate tokens regularly
     - Use short-lived tokens where possible

================================================================================
"""
        print(warning)

    @staticmethod
    def check_file_permissions(file_path: str) -> Tuple[bool, str]:
        """
        Check if a token file has secure permissions.

        Args:
            file_path: Path to the token file

        Returns:
            (is_secure, message)
        """
        try:
            path = Path(file_path)
            if not path.exists():
                return (False, "File does not exist")

            st = path.stat()
            mode = st.st_mode

            # Check if world or group readable
            if mode & stat.S_IRWXO:  # Others have any access
                return (False, f"INSECURE: File is world-accessible (mode: {oct(mode)})")
            if mode & stat.S_IRWXG:  # Group has any access
                return (False, f"WARNING: File is group-accessible (mode: {oct(mode)})")

            # Check owner-only
            if (mode & stat.S_IRWXU) == (stat.S_IRUSR | stat.S_IWUSR):
                return (True, "Secure: Owner read/write only (0o600)")

            return (True, f"Acceptable permissions (mode: {oct(mode)})")

        except Exception as e:
            return (False, f"Failed to check permissions: {e}")


# Convenience functions

def encrypt_token_to_file(
    token: str,
    file_path: str,
    name: str = "api-token",
    key_file: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Encrypt and save a token to a file.

    Args:
        token: The plaintext token
        file_path: Where to save the encrypted token
        name: Token name/description
        key_file: Optional path to encryption key file

    Returns:
        (success, message)
    """
    storage = SecureTokenStorage(key_file=key_file)
    return storage.write_encrypted_token_file(file_path, token, name)


def decrypt_token_from_file(
    file_path: str,
    key_file: Optional[str] = None,
) -> Tuple[Optional[str], str]:
    """
    Read and decrypt a token from a file.

    Args:
        file_path: Path to encrypted token file
        key_file: Optional path to encryption key file

    Returns:
        (token, message) - token is None on failure
    """
    storage = SecureTokenStorage(key_file=key_file)
    token, metadata, message = storage.read_encrypted_token_file(file_path)
    return (token, message)


def create_secure_bootstrap_token(
    token: str,
    output_path: str,
    key_file: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Create an encrypted bootstrap token file.

    Args:
        token: The bootstrap token
        output_path: Where to save the encrypted token
        key_file: Optional path to encryption key file

    Returns:
        (success, message)
    """
    storage = SecureTokenStorage(key_file=key_file)
    return storage.encrypt_bootstrap_token(token, output_path)


if __name__ == '__main__':
    # Test secure token storage
    print("Testing Secure Token Storage...")
    print(f"Cryptography available: {CRYPTO_AVAILABLE}")

    storage = SecureTokenStorage()

    # Test encryption/decryption
    test_token = "bd_test_token_12345"
    print(f"\n1. Encrypting token: {test_token[:20]}...")

    encrypted = storage.encrypt_token(test_token, {'name': 'test'})
    print(f"   Encrypted length: {len(encrypted)} bytes")

    decrypted, metadata = storage.decrypt_token(encrypted)
    print(f"   Decrypted: {decrypted[:20]}...")
    print(f"   Metadata: {metadata}")

    assert decrypted == test_token, "Decryption failed!"
    print("   PASS: Encryption/decryption works")

    # Test file operations
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='.enc') as f:
        test_file = f.name

    print(f"\n2. Writing encrypted token to file...")
    success, msg = storage.write_encrypted_token_file(
        test_file, test_token, "test-token", "readonly"
    )
    print(f"   {msg}")

    print(f"\n3. Reading encrypted token from file...")
    token, meta, msg = storage.read_encrypted_token_file(test_file)
    print(f"   Token: {token[:20] if token else 'None'}...")
    print(f"   Message: {msg}")

    # Cleanup
    os.remove(test_file)

    print("\n4. Security recommendations:")
    storage.print_env_var_warning()

    print("\nTest complete!")
