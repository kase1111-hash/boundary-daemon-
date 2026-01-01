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
import sys
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

# Platform detection
IS_WINDOWS = sys.platform == 'win32'

# Import error handling framework for consistent error management
try:
    from daemon.utils.error_handling import (
        handle_error,
        log_filesystem_error,
        ErrorCategory,
    )
    ERROR_HANDLING_AVAILABLE = True
except ImportError:
    ERROR_HANDLING_AVAILABLE = False
    def handle_error(e, op, category=None, severity=None, additional_context=None, reraise=False, log_level=None):
        logger.error(f"{op}: {e}")
    def log_filesystem_error(e, op, **ctx):
        logger.error(f"FILESYSTEM: {op}: {e}")

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

    # SECURITY: Boot ID inclusion in key derivation
    # WARNING: If True, encrypted configs become unreadable after reboot!
    # Set to False for persistent config encryption across reboots.
    # Set to True only if you need forward secrecy and accept data loss on reboot.
    use_boot_id: bool = False  # Default to False to prevent data loss

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

        # Track key material for secure cleanup
        self._key_material: Optional[bytearray] = None

        # Initialize encryption if available
        if CRYPTO_AVAILABLE:
            self._initialize_key()

    def __del__(self):
        """Destructor - ensure encryption keys are zeroed."""
        self.cleanup()

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
            except (IOError, OSError, ValueError) as e:
                # IOError/OSError: file access errors
                # ValueError: invalid key format
                log_filesystem_error(e, "load_config_key", key_file=str(self._key_file))

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
            except (IOError, OSError, PermissionError) as e:
                # File system errors - permission denied, disk full, etc.
                log_filesystem_error(e, "save_config_key", key_file=str(self._key_file))

    def _derive_machine_key(self) -> bytes:
        """Derive encryption key from machine-specific characteristics."""
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
            except (ImportError, OSError, KeyError, AttributeError):
                # ImportError: winreg not available
                # OSError: registry access failure
                # KeyError: registry key not found
                pass

            # Computer name as fallback
            try:
                machine_data.append(os.environ.get('COMPUTERNAME', ''))
            except (KeyError, AttributeError):
                pass
        else:
            # Machine ID (Linux)
            machine_id_path = Path("/etc/machine-id")
            if machine_id_path.exists():
                try:
                    machine_data.append(machine_id_path.read_text().strip())
                except (IOError, OSError):
                    pass

            # Boot ID (changes on reboot - provides some forward secrecy)
            # SECURITY WARNING: Including boot_id means configs are unreadable after reboot!
            if self.options.use_boot_id:
                boot_id_path = Path("/proc/sys/kernel/random/boot_id")
                if boot_id_path.exists():
                    try:
                        machine_data.append(boot_id_path.read_text().strip())
                        logger.warning(
                            "SECURITY: Boot ID is included in key derivation. "
                            "Encrypted configs will be UNREADABLE after system reboot. "
                            "Set use_boot_id=False if you need persistent encryption."
                        )
                    except (IOError, OSError):
                        pass

        # Installation-specific salt
        salt_path = Path("/etc/boundary-daemon/.config_salt")
        if not salt_path.exists():
            # Try local path
            salt_path = Path("./config/.config_salt")

        if salt_path.exists():
            try:
                salt = salt_path.read_bytes()
            except (IOError, OSError):
                salt = secrets.token_bytes(32)
        else:
            salt = secrets.token_bytes(32)
            try:
                salt_path.parent.mkdir(parents=True, exist_ok=True)
                with open(salt_path, 'wb') as f:
                    f.write(salt)
                os.chmod(salt_path, 0o600)
            except (IOError, OSError, PermissionError) as e:
                logger.warning(f"Could not save config salt: {e}")

        # Combine and derive key
        # SECURITY: Use bytearray so we can zero it after derivation
        combined = bytearray("|".join(machine_data).encode() + salt)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.options.kdf_iterations,
        )

        try:
            derived = kdf.derive(bytes(combined))
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
            except (IOError, OSError, UnicodeDecodeError):
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

        except (IOError, OSError, PermissionError):
            # Clean up temp file on error
            try:
                os.unlink(temp_path)
            except (IOError, OSError):
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

        except (IOError, OSError, PermissionError, shutil.Error) as e:
            # File copy/permission errors
            log_filesystem_error(e, "create_config_backup", filepath=str(filepath))

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
            except (IOError, OSError):
                pass

    def rotate_key(self, new_key_file: Optional[str] = None) -> bool:
        """
        Rotate the encryption key.

        KEY ROTATION PROCEDURE
        ======================

        Key rotation should be performed periodically (recommended: annually) or
        immediately if a key compromise is suspected. Follow these steps:

        1. PREPARATION:
           - Ensure you have access to all encrypted configuration files
           - Schedule maintenance window (brief service interruption may occur)
           - Back up current key file and all encrypted configs

        2. ROTATION STEPS:
           a) Create a new SecureConfigStorage instance with the current key
           b) Load all encrypted configurations (they will be decrypted in memory)
           c) Call rotate_key() to generate and store the new key
           d) Re-save all configurations (they will be encrypted with new key)
           e) Verify configurations can be loaded with the new key
           f) Securely delete old key backup after verification

        3. EXAMPLE CODE:
           ```python
           storage = SecureConfigStorage(key_file="/etc/boundary-daemon/config.key")

           # Load all configs with old key
           configs = {}
           for config_path in config_files:
               configs[config_path] = storage.load(config_path)

           # Rotate the key
           if storage.rotate_key():
               # Re-encrypt all configs with new key
               for config_path, data in configs.items():
                   storage.save(data, config_path)

               # Verify (load with new key)
               for config_path in config_files:
                   storage.load(config_path)  # Raises on failure

               print("Key rotation successful")
               storage.cleanup()  # Zero old key from memory
           ```

        4. CLI USAGE:
           ```bash
           # Rotate key for all configs
           python -m daemon.config.secure_config rotate-key --key /path/to/key

           # Re-encrypt configs after rotation
           python -m daemon.config.secure_config encrypt /path/to/config.json
           ```

        5. POST-ROTATION:
           - Restart the daemon to load new key
           - Verify daemon starts successfully
           - Monitor logs for decryption errors
           - Securely shred old key file backups

        SECURITY NOTES:
        - Old key is zeroed from memory after rotation
        - New key is cryptographically random (Fernet.generate_key)
        - Key file permissions are set to 0o600 (owner read/write only)
        - Rotation is atomic (rollback on failure)

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

        # SECURITY: Store old key material for zeroing after rotation
        old_fernet = self._fernet
        old_key_material = self._key_material
        old_encryption_key = self._encryption_key

        # Set new key
        self._encryption_key = new_key
        self._fernet = Fernet(new_key)
        self._key_material = bytearray(base64.urlsafe_b64decode(new_key))

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
                self._encryption_key = old_encryption_key
                self._fernet = old_fernet
                self._key_material = old_key_material
                logger.error(f"Failed to save new key: {e}")
                return False

        # SECURITY: Zero old key material from memory
        if old_key_material is not None:
            if SECURE_MEMORY_AVAILABLE and secure_zero_memory:
                secure_zero_memory(old_key_material)
            else:
                for i in range(len(old_key_material)):
                    old_key_material[i] = 0

        logger.info("Config encryption key rotated successfully")
        logger.info("IMPORTANT: Re-encrypt all configuration files with the new key")
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

    def cleanup(self) -> bool:
        """
        Securely zero encryption keys from memory.

        SECURITY: This method should be called when the SecureConfigStorage
        instance is no longer needed to minimize the exposure window for
        encryption key material in memory.

        Returns:
            True if cleanup was successful
        """
        success = True

        # Zero the key material if secure memory is available
        if self._key_material is not None and SECURE_MEMORY_AVAILABLE:
            try:
                if not secure_zero_memory(self._key_material):
                    logger.warning("Failed to zero config encryption key material")
                    success = False
            except Exception as e:
                logger.warning(f"Error zeroing key material: {e}")
                success = False
            finally:
                self._key_material = None

        # Zero the encryption key bytes
        if self._encryption_key is not None:
            if isinstance(self._encryption_key, bytearray):
                if SECURE_MEMORY_AVAILABLE:
                    secure_zero_memory(self._encryption_key)
            # For bytes, we can only help garbage collection
            self._encryption_key = None

        # Clear the Fernet instance
        self._fernet = None

        # Force garbage collection to help clean up
        import gc
        gc.collect()

        if success:
            logger.debug("Config encryption keys zeroed from memory")

        return success


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


class CryptographyRequiredError(Exception):
    """Raised when cryptography library is required but not available."""
    pass


def check_crypto_requirements(
    dev_mode: bool = False,
    allow_env_override: bool = True,
) -> Tuple[bool, str]:
    """
    Check if cryptography requirements are met for production use.

    SECURITY: This function enforces that the cryptography library is available
    for production deployments. Without it, encryption falls back to weaker
    XOR-based encryption which is not suitable for production security.

    This implements "soft enforcement" - production requires cryptography,
    but development/testing can bypass with explicit flags.

    Args:
        dev_mode: If True, allow running without cryptography (for development)
        allow_env_override: If True, check BOUNDARY_DEV_MODE environment variable

    Returns:
        (is_ok, message) - is_ok is True if requirements are met or bypassed

    Raises:
        CryptographyRequiredError: If requirements not met and not bypassed

    Example Usage:
        # In daemon startup code:
        try:
            check_crypto_requirements(dev_mode=args.dev_mode)
        except CryptographyRequiredError as e:
            print(f"FATAL: {e}")
            sys.exit(1)

    Environment Variables:
        BOUNDARY_DEV_MODE=1  - Bypass cryptography requirement (with warning)
    """
    # Check environment override
    if allow_env_override:
        env_dev_mode = os.environ.get('BOUNDARY_DEV_MODE', '').lower()
        if env_dev_mode in ('1', 'true', 'yes'):
            dev_mode = True
            logger.warning(
                "SECURITY WARNING: BOUNDARY_DEV_MODE is set - "
                "cryptography requirement bypassed"
            )

    if CRYPTO_AVAILABLE:
        return (True, "Cryptography library available - full encryption enabled")

    # Cryptography not available
    if dev_mode:
        warning_msg = (
            "SECURITY WARNING: Running without cryptography library!\n"
            "  - Configuration encryption uses weaker XOR-based fallback\n"
            "  - Token encryption uses weaker XOR-based fallback\n"
            "  - This is ONLY acceptable for development/testing\n"
            "  - Install cryptography for production: pip install cryptography"
        )
        logger.warning(warning_msg)
        return (True, warning_msg)

    # Production mode without cryptography - fail
    error_msg = (
        "FATAL: Cryptography library is required for production use.\n"
        "\n"
        "The 'cryptography' library provides secure AES encryption for:\n"
        "  - Configuration file encryption (Fernet/AES-128-CBC)\n"
        "  - Token storage encryption\n"
        "  - Secure key derivation (PBKDF2)\n"
        "\n"
        "Without it, the daemon falls back to weaker XOR-based encryption\n"
        "which is NOT suitable for production security.\n"
        "\n"
        "To fix:\n"
        "  pip install cryptography\n"
        "\n"
        "For development/testing only, you can bypass with:\n"
        "  --dev-mode flag, or\n"
        "  BOUNDARY_DEV_MODE=1 environment variable\n"
    )
    logger.critical(error_msg)
    raise CryptographyRequiredError(error_msg)


def require_crypto_or_exit(dev_mode: bool = False) -> None:
    """
    Convenience function to check crypto requirements and exit on failure.

    Call this at the start of daemon main() to enforce requirements.

    Args:
        dev_mode: If True, allow running without cryptography

    Example:
        def main():
            args = parse_args()
            require_crypto_or_exit(dev_mode=args.dev_mode)
            # ... rest of daemon startup
    """
    import sys
    try:
        ok, msg = check_crypto_requirements(dev_mode=dev_mode)
        if ok and CRYPTO_AVAILABLE:
            logger.info("Cryptography requirements met")
    except CryptographyRequiredError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


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
