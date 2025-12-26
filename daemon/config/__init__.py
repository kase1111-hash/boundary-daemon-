"""
Configuration Module for Boundary Daemon.

Provides secure configuration handling:
- Encrypted configuration file storage
- Selective encryption of sensitive fields
- Support for JSON, YAML, and INI formats
- Key rotation and management

SECURITY: Addresses Critical Finding "Configuration Files Not Encrypted"
Sensitive configuration data (passwords, keys, tokens) is now encrypted
at rest to protect against filesystem-level attacks.
"""

# Import secure config storage
try:
    from .secure_config import (
        SecureConfigStorage,
        SecureConfigOptions,
        ConfigFormat,
        EncryptionMode,
        load_secure_config,
        save_secure_config,
    )
    SECURE_CONFIG_AVAILABLE = True
except ImportError as e:
    SECURE_CONFIG_AVAILABLE = False
    SecureConfigStorage = None
    SecureConfigOptions = None
    ConfigFormat = None
    EncryptionMode = None
    load_secure_config = None
    save_secure_config = None

__all__ = [
    'SecureConfigStorage',
    'SecureConfigOptions',
    'ConfigFormat',
    'EncryptionMode',
    'load_secure_config',
    'save_secure_config',
    'SECURE_CONFIG_AVAILABLE',
]
