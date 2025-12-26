"""
Secure Configuration Storage - Encrypted configuration file handling.

Provides:
- Encryption of entire configuration files
- Selective encryption of sensitive fields within configs
- Support for JSON, YAML, and INI formats
- Machine-derived encryption keys
- Transparent loading/saving with encryption
- Key rotation support

SECURITY: Addresses Critical Finding "Configuration Files Not Encrypted"
Without encryption, attackers with filesystem access can read sensitive
configuration including API keys, network settings, and security policies.
"""

import base64
import configparser
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import logging

logger = logging.getLogger(__name__)

# Try to import cryptography library
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    InvalidToken = Exception
    logger.warning("cryptography library not available - config encryption disabled")

# Try to import YAML support
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None


class ConfigFormat(Enum):
    """Supported configuration file formats."""
    JSON = "json"
    YAML = "yaml"
    INI = "ini"
    AUTO = "auto"  # Detect from file extension


class EncryptionMode(Enum):
    """Configuration encryption modes."""
    NONE = "none"                    # No encryption
    FULL = "full"                    # Encrypt entire file
    SENSITIVE_ONLY = "sensitive"     # Encrypt only marked fields


@dataclass
class SecureConfigOptions:
    """Options for secure configuration handling."""
    # Encryption settings
    encryption_mode: EncryptionMode = EncryptionMode.SENSITIVE_ONLY

    # Fields to always encrypt (regex patterns)
    sensitive_patterns: List[str] = field(default_factory=lambda: [
        r".*password.*",
        r".*secret.*",
        r".*token.*",
        r".*key.*",
        r".*api_key.*",
        r".*private.*",
        r".*credential.*",
        r".*auth.*",
    ])

    # Fields to never encrypt
    exclude_patterns: List[str] = field(default_factory=lambda: [
        r".*public.*",
        r".*_path$",
        r".*_dir$",
        r".*enabled$",
        r".*_count$",
    ])

    # Key derivation settings
    kdf_iterations: int = 480000  # OWASP recommended

    # File permissions
    file_mode: int = 0o600

    # Backup settings
    create_backup: bool = True
    max_backups: int = 3


class SecureConfigStorage:
    """
    Handles secure storage and retrieval of configuration files.

    Features:
    - Full file encryption or selective field encryption
    - Machine-derived encryption keys
    - Fernet encryption (AES-128-CBC with HMAC-SHA256)
    - Secure file permissions
    - Automatic format detection
    - Key rotation support

    SECURITY: Encrypts sensitive configuration data to protect against
    filesystem-level attacks and unauthorized access.
    """

    # File format markers
    ENCRYPTED_HEADER = "# BOUNDARY-DAEMON-ENCRYPTED-CONFIG v1\n"
    ENCRYPTED_FIELD_PREFIX = "ENC::"
    ENCRYPTED_FIELD_SUFFIX = "::CNE"

    def __init__(
        self,
        key_file: Optional[str] = None,
        options: Optional[SecureConfigOptions] = None,
    ):
        """
        Initialize secure config storage.

        Args:
            key_file: Path to store/load the master encryption key.
                     If None, uses machine-derived key only.
            options: Configuration options
        """
        self.options = options or SecureConfigOptions()
        self._key_file = Path(key_file) if key_file else None
        self._encryption_key: Optional[bytes] = None
        self._fernet: Optional[Any] = None

        # Compile regex patterns
        self._sensitive_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in self.options.sensitive_patterns
        ]
        self._exclude_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in self.options.exclude_patterns
        ]

        # Initialize encryption if available
        if CRYPTO_AVAILABLE:
            self._initialize_key()

    def _initialize_key(self):
        """Initialize the encryption key."""
        if self._key_file and self._key_file.exists():
            try:
                with open(self._key_file, 'rb') as f:
                    key_data = f.read()
                # Validate it's a valid Fernet key
                if len(key_data) == 44:  # Base64-encoded 32-byte key
                    self._encryption_key = key_data
                    self._fernet = Fernet(key_data)
                    return
            except Exception as e:
                logger.warning(f"Failed to load config key: {e}")

        # Derive key from machine characteristics
        machine_key = self._derive_machine_key()
        self._encryption_key = machine_key
        self._fernet = Fernet(machine_key)

        # Save derived key if key_file specified
        if self._key_file:
            try:
                self._key_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self._key_file, 'wb') as f:
                    f.write(machine_key)
                os.chmod(self._key_file, 0o600)
            except Exception as e:
                logger.warning(f"Failed to save config key: {e}")

    def _derive_machine_key(self) -> bytes:
        """Derive encryption key from machine-specific characteristics."""
        machine_data = []

        # Machine ID (Linux)
        machine_id_path = Path("/etc/machine-id")
        if machine_id_path.exists():
            try:
                machine_data.append(machine_id_path.read_text().strip())
            except Exception:
                pass

        # Boot ID (changes on reboot - provides some forward secrecy)
        boot_id_path = Path("/proc/sys/kernel/random/boot_id")
        if boot_id_path.exists():
            try:
                machine_data.append(boot_id_path.read_text().strip())
            except Exception:
                pass

        # Installation-specific salt
        salt_path = Path("/etc/boundary-daemon/.config_salt")
        if not salt_path.exists():
            # Try local path
            salt_path = Path("./config/.config_salt")

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
            except Exception as e:
                logger.warning(f"Could not save config salt: {e}")

        # Combine and derive key
        combined = "|".join(machine_data).encode() + salt

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.options.kdf_iterations,
        )
        key = base64.urlsafe_b64encode(kdf.derive(combined))
        return key

    def _detect_format(self, filepath: Path) -> ConfigFormat:
        """Detect configuration format from file extension."""
        ext = filepath.suffix.lower()
        if ext in {'.json'}:
            return ConfigFormat.JSON
        elif ext in {'.yaml', '.yml'}:
            return ConfigFormat.YAML
        elif ext in {'.ini', '.conf', '.cfg'}:
            return ConfigFormat.INI
        else:
            # Try to detect from content
            try:
                content = filepath.read_text()
                if content.strip().startswith('{'):
                    return ConfigFormat.JSON
                elif ':' in content and not '=' in content.split('\n')[0]:
                    return ConfigFormat.YAML
                else:
                    return ConfigFormat.INI
            except Exception:
                return ConfigFormat.JSON

    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if a field should be encrypted."""
        # Check exclusions first
        for pattern in self._exclude_patterns:
            if pattern.match(field_name):
                return False

        # Check sensitive patterns
        for pattern in self._sensitive_patterns:
            if pattern.match(field_name):
                return True

        return False

    def _encrypt_value(self, value: str) -> str:
        """Encrypt a single value."""
        if not self._fernet:
            return value

        encrypted = self._fernet.encrypt(value.encode())
        return f"{self.ENCRYPTED_FIELD_PREFIX}{encrypted.decode()}{self.ENCRYPTED_FIELD_SUFFIX}"

    def _decrypt_value(self, value: str) -> str:
        """Decrypt a single value."""
        if not self._fernet:
            return value

        if not (value.startswith(self.ENCRYPTED_FIELD_PREFIX) and
                value.endswith(self.ENCRYPTED_FIELD_SUFFIX)):
            return value

        # Extract encrypted portion
        encrypted = value[len(self.ENCRYPTED_FIELD_PREFIX):-len(self.ENCRYPTED_FIELD_SUFFIX)]

        try:
            decrypted = self._fernet.decrypt(encrypted.encode())
            return decrypted.decode()
        except InvalidToken:
            logger.error("Failed to decrypt config value - invalid key or corrupted data")
            raise ValueError("Config decryption failed - key mismatch or data corruption")

    def _encrypt_dict(self, data: Dict, path: str = "") -> Dict:
        """Recursively encrypt sensitive fields in a dictionary."""
        result = {}

        for key, value in data.items():
            field_path = f"{path}.{key}" if path else key

            if isinstance(value, dict):
                result[key] = self._encrypt_dict(value, field_path)
            elif isinstance(value, list):
                result[key] = self._encrypt_list(value, field_path)
            elif isinstance(value, str):
                if self._is_sensitive_field(key):
                    result[key] = self._encrypt_value(value)
                else:
                    result[key] = value
            else:
                result[key] = value

        return result

    def _encrypt_list(self, data: List, path: str) -> List:
        """Recursively encrypt sensitive fields in a list."""
        result = []

        for i, item in enumerate(data):
            item_path = f"{path}[{i}]"
            if isinstance(item, dict):
                result.append(self._encrypt_dict(item, item_path))
            elif isinstance(item, list):
                result.append(self._encrypt_list(item, item_path))
            else:
                result.append(item)

        return result

    def _decrypt_dict(self, data: Dict, path: str = "") -> Dict:
        """Recursively decrypt fields in a dictionary."""
        result = {}

        for key, value in data.items():
            field_path = f"{path}.{key}" if path else key

            if isinstance(value, dict):
                result[key] = self._decrypt_dict(value, field_path)
            elif isinstance(value, list):
                result[key] = self._decrypt_list(value, field_path)
            elif isinstance(value, str):
                if value.startswith(self.ENCRYPTED_FIELD_PREFIX):
                    result[key] = self._decrypt_value(value)
                else:
                    result[key] = value
            else:
                result[key] = value

        return result

    def _decrypt_list(self, data: List, path: str) -> List:
        """Recursively decrypt fields in a list."""
        result = []

        for i, item in enumerate(data):
            item_path = f"{path}[{i}]"
            if isinstance(item, dict):
                result.append(self._decrypt_dict(item, item_path))
            elif isinstance(item, list):
                result.append(self._decrypt_list(item, item_path))
            elif isinstance(item, str) and item.startswith(self.ENCRYPTED_FIELD_PREFIX):
                result.append(self._decrypt_value(item))
            else:
                result.append(item)

        return result

    def _encrypt_ini(self, config: configparser.ConfigParser) -> configparser.ConfigParser:
        """Encrypt sensitive fields in an INI config."""
        for section in config.sections():
            for key in config[section]:
                if self._is_sensitive_field(key):
                    value = config[section][key]
                    config[section][key] = self._encrypt_value(value)
        return config

    def _decrypt_ini(self, config: configparser.ConfigParser) -> configparser.ConfigParser:
        """Decrypt fields in an INI config."""
        for section in config.sections():
            for key in config[section]:
                value = config[section][key]
                if value.startswith(self.ENCRYPTED_FIELD_PREFIX):
                    config[section][key] = self._decrypt_value(value)
        return config

    def load(
        self,
        filepath: Union[str, Path],
        format: ConfigFormat = ConfigFormat.AUTO,
    ) -> Dict[str, Any]:
        """
        Load and decrypt a configuration file.

        Args:
            filepath: Path to configuration file
            format: File format (auto-detected if AUTO)

        Returns:
            Decrypted configuration dictionary
        """
        filepath = Path(filepath)

        if not filepath.exists():
            raise FileNotFoundError(f"Config file not found: {filepath}")

        # Detect format if needed
        if format == ConfigFormat.AUTO:
            format = self._detect_format(filepath)

        # Read file content
        content = filepath.read_text()

        # Check for full-file encryption
        if content.startswith(self.ENCRYPTED_HEADER):
            content = self._decrypt_full_file(content)

        # Parse based on format
        if format == ConfigFormat.JSON:
            data = json.loads(content)
            return self._decrypt_dict(data)

        elif format == ConfigFormat.YAML:
            if not YAML_AVAILABLE:
                raise RuntimeError("YAML support not available - install pyyaml")
            data = yaml.safe_load(content)
            return self._decrypt_dict(data) if data else {}

        elif format == ConfigFormat.INI:
            config = configparser.ConfigParser()
            config.read_string(content)
            config = self._decrypt_ini(config)
            # Convert to dict
            return {s: dict(config[s]) for s in config.sections()}

        else:
            raise ValueError(f"Unsupported format: {format}")

    def save(
        self,
        data: Dict[str, Any],
        filepath: Union[str, Path],
        format: ConfigFormat = ConfigFormat.AUTO,
        encrypt: bool = True,
    ) -> None:
        """
        Encrypt and save a configuration file.

        Args:
            data: Configuration dictionary
            filepath: Path to save to
            format: File format (auto-detected if AUTO)
            encrypt: Whether to encrypt (uses options.encryption_mode)
        """
        filepath = Path(filepath)

        # Detect format if needed
        if format == ConfigFormat.AUTO:
            if filepath.exists():
                format = self._detect_format(filepath)
            else:
                # Guess from extension
                ext = filepath.suffix.lower()
                if ext in {'.yaml', '.yml'}:
                    format = ConfigFormat.YAML
                elif ext in {'.ini', '.conf', '.cfg'}:
                    format = ConfigFormat.INI
                else:
                    format = ConfigFormat.JSON

        # Create backup if requested
        if self.options.create_backup and filepath.exists():
            self._create_backup(filepath)

        # Encrypt if requested
        if encrypt and CRYPTO_AVAILABLE and self._fernet:
            mode = self.options.encryption_mode

            if mode == EncryptionMode.SENSITIVE_ONLY:
                data = self._encrypt_dict(data)
            elif mode == EncryptionMode.FULL:
                # Will encrypt the entire file content below
                pass

        # Serialize based on format
        if format == ConfigFormat.JSON:
            content = json.dumps(data, indent=2)

        elif format == ConfigFormat.YAML:
            if not YAML_AVAILABLE:
                raise RuntimeError("YAML support not available - install pyyaml")
            content = yaml.dump(data, default_flow_style=False)

        elif format == ConfigFormat.INI:
            config = configparser.ConfigParser()
            for section, values in data.items():
                config[section] = values
            if encrypt and self.options.encryption_mode == EncryptionMode.SENSITIVE_ONLY:
                config = self._encrypt_ini(config)

            import io
            output = io.StringIO()
            config.write(output)
            content = output.getvalue()

        else:
            raise ValueError(f"Unsupported format: {format}")

        # Apply full-file encryption if requested
        if encrypt and self.options.encryption_mode == EncryptionMode.FULL:
            content = self._encrypt_full_file(content)

        # Atomic write with secure permissions
        self._atomic_write(filepath, content)

    def _encrypt_full_file(self, content: str) -> str:
        """Encrypt entire file content."""
        if not self._fernet:
            return content

        encrypted = self._fernet.encrypt(content.encode())
        return f"{self.ENCRYPTED_HEADER}{encrypted.decode()}"

    def _decrypt_full_file(self, content: str) -> str:
        """Decrypt entire file content."""
        if not self._fernet:
            raise RuntimeError("Cannot decrypt - encryption not available")

        # Remove header
        encrypted = content[len(self.ENCRYPTED_HEADER):].strip()

        try:
            decrypted = self._fernet.decrypt(encrypted.encode())
            return decrypted.decode()
        except InvalidToken:
            raise ValueError("Config decryption failed - key mismatch or data corruption")

    def _atomic_write(self, filepath: Path, content: str):
        """Write file atomically with secure permissions."""
        filepath.parent.mkdir(parents=True, exist_ok=True)

        # Write to temp file first
        fd, temp_path = tempfile.mkstemp(
            dir=filepath.parent,
            prefix=f".{filepath.name}.",
            suffix=".tmp"
        )

        try:
            with os.fdopen(fd, 'w') as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())

            # Set secure permissions
            os.chmod(temp_path, self.options.file_mode)

            # Atomic rename
            os.rename(temp_path, filepath)

        except Exception:
            # Clean up temp file on error
            try:
                os.unlink(temp_path)
            except Exception:
                pass
            raise

    def _create_backup(self, filepath: Path):
        """Create a backup of the config file."""
        backup_dir = filepath.parent / ".config_backups"
        backup_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"{filepath.name}.{timestamp}.bak"

        try:
            import shutil
            shutil.copy2(filepath, backup_path)
            os.chmod(backup_path, self.options.file_mode)

            # Clean up old backups
            self._cleanup_old_backups(backup_dir, filepath.name)

        except Exception as e:
            logger.warning(f"Failed to create config backup: {e}")

    def _cleanup_old_backups(self, backup_dir: Path, base_name: str):
        """Remove old backup files exceeding max_backups."""
        pattern = f"{base_name}.*.bak"
        backups = sorted(
            backup_dir.glob(pattern),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )

        for old_backup in backups[self.options.max_backups:]:
            try:
                old_backup.unlink()
            except Exception:
                pass

    def rotate_key(self, new_key_file: Optional[str] = None) -> bool:
        """
        Rotate the encryption key.

        This will:
        1. Generate a new encryption key
        2. Return True to indicate caller should re-encrypt configs

        Args:
            new_key_file: Path for new key file (uses existing path if None)

        Returns:
            True if key was rotated successfully
        """
        if not CRYPTO_AVAILABLE:
            logger.error("Cannot rotate key - encryption not available")
            return False

        # Generate new key
        new_key = Fernet.generate_key()

        # Store old key for re-encryption
        old_fernet = self._fernet

        # Set new key
        self._encryption_key = new_key
        self._fernet = Fernet(new_key)

        # Save new key
        key_path = Path(new_key_file) if new_key_file else self._key_file
        if key_path:
            try:
                key_path.parent.mkdir(parents=True, exist_ok=True)
                with open(key_path, 'wb') as f:
                    f.write(new_key)
                os.chmod(key_path, 0o600)
                self._key_file = key_path
            except Exception as e:
                # Rollback
                self._encryption_key = old_fernet._signing_key if old_fernet else None
                self._fernet = old_fernet
                logger.error(f"Failed to save new key: {e}")
                return False

        logger.info("Config encryption key rotated successfully")
        return True

    def encrypt_existing_config(
        self,
        filepath: Union[str, Path],
        format: ConfigFormat = ConfigFormat.AUTO,
    ) -> bool:
        """
        Encrypt an existing plaintext configuration file.

        Args:
            filepath: Path to config file
            format: File format

        Returns:
            True if encryption was successful
        """
        try:
            # Load without decryption (it's plaintext)
            filepath = Path(filepath)
            content = filepath.read_text()

            if content.startswith(self.ENCRYPTED_HEADER):
                logger.info(f"Config already encrypted: {filepath}")
                return True

            # Detect format
            if format == ConfigFormat.AUTO:
                format = self._detect_format(filepath)

            # Parse
            if format == ConfigFormat.JSON:
                data = json.loads(content)
            elif format == ConfigFormat.YAML:
                data = yaml.safe_load(content) if YAML_AVAILABLE else {}
            elif format == ConfigFormat.INI:
                config = configparser.ConfigParser()
                config.read_string(content)
                data = {s: dict(config[s]) for s in config.sections()}
            else:
                return False

            # Save with encryption
            self.save(data, filepath, format, encrypt=True)
            logger.info(f"Encrypted config: {filepath}")
            return True

        except Exception as e:
            logger.error(f"Failed to encrypt config {filepath}: {e}")
            return False

    def get_encryption_status(self, filepath: Union[str, Path]) -> Dict[str, Any]:
        """
        Check encryption status of a configuration file.

        Returns:
            Dictionary with encryption status details
        """
        filepath = Path(filepath)

        if not filepath.exists():
            return {'exists': False, 'encrypted': False}

        content = filepath.read_text()

        full_encrypted = content.startswith(self.ENCRYPTED_HEADER)
        field_encrypted = self.ENCRYPTED_FIELD_PREFIX in content

        return {
            'exists': True,
            'full_encrypted': full_encrypted,
            'field_encrypted': field_encrypted,
            'any_encryption': full_encrypted or field_encrypted,
            'encryption_available': CRYPTO_AVAILABLE,
        }


# Convenience functions
def load_secure_config(
    filepath: Union[str, Path],
    key_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Load and decrypt a configuration file."""
    storage = SecureConfigStorage(key_file=key_file)
    return storage.load(filepath)


def save_secure_config(
    data: Dict[str, Any],
    filepath: Union[str, Path],
    key_file: Optional[str] = None,
    encrypt: bool = True,
) -> None:
    """Encrypt and save a configuration file."""
    storage = SecureConfigStorage(key_file=key_file)
    storage.save(data, filepath, encrypt=encrypt)


# CLI interface
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Secure Configuration Management')
    parser.add_argument('command', choices=['encrypt', 'decrypt', 'status', 'rotate-key'])
    parser.add_argument('config_file', nargs='?', help='Configuration file path')
    parser.add_argument('--key', '-k', help='Encryption key file path')
    parser.add_argument('--output', '-o', help='Output file (for decrypt)')
    parser.add_argument('--mode', '-m', choices=['full', 'sensitive'],
                       default='sensitive', help='Encryption mode')

    args = parser.parse_args()

    options = SecureConfigOptions(
        encryption_mode=EncryptionMode.FULL if args.mode == 'full'
                       else EncryptionMode.SENSITIVE_ONLY
    )

    storage = SecureConfigStorage(key_file=args.key, options=options)

    if args.command == 'encrypt':
        if not args.config_file:
            print("Error: config_file required")
            exit(1)
        if storage.encrypt_existing_config(args.config_file):
            print(f"Encrypted: {args.config_file}")
        else:
            print(f"Failed to encrypt: {args.config_file}")
            exit(1)

    elif args.command == 'decrypt':
        if not args.config_file:
            print("Error: config_file required")
            exit(1)
        data = storage.load(args.config_file)
        output = args.output or args.config_file + '.decrypted'
        # Save without encryption
        storage.options.encryption_mode = EncryptionMode.NONE
        storage.save(data, output, encrypt=False)
        print(f"Decrypted to: {output}")

    elif args.command == 'status':
        if not args.config_file:
            print("Error: config_file required")
            exit(1)
        status = storage.get_encryption_status(args.config_file)
        print(f"File: {args.config_file}")
        print(f"  Exists: {status['exists']}")
        print(f"  Full encryption: {status.get('full_encrypted', False)}")
        print(f"  Field encryption: {status.get('field_encrypted', False)}")
        print(f"  Crypto available: {status.get('encryption_available', False)}")

    elif args.command == 'rotate-key':
        if storage.rotate_key(args.key):
            print("Key rotated successfully")
            print("IMPORTANT: Re-encrypt all configuration files with the new key")
        else:
            print("Key rotation failed")
            exit(1)
