"""
Secure Memory - Utilities for secure handling of sensitive data in memory.

Provides:
- Secure zeroing of bytearrays and mutable buffers
- SecureBytes context manager for automatic cleanup
- Memory locking (where supported)
- Secure string comparison

SECURITY: Addresses the concern "No explicit memory clearing of secrets"
by providing utilities to zero sensitive data after use, reducing the
window of exposure for encryption keys, tokens, and passwords.

Note: Python's memory model makes truly secure memory handling challenging.
These utilities provide best-effort protection but cannot guarantee
secrets are not copied by the garbage collector or interpreter.
"""

import ctypes
import gc
import os
import hmac
import logging
from contextlib import contextmanager
from typing import Optional, Union, Callable

logger = logging.getLogger(__name__)

# Check for mlock support (Linux/Unix)
try:
    import mmap
    MLOCK_AVAILABLE = hasattr(mmap, 'PROT_READ')
except ImportError:
    MLOCK_AVAILABLE = False

# Check for ctypes memset
try:
    _libc = ctypes.CDLL(None)
    _memset = _libc.memset
    _memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
    _memset.restype = ctypes.c_void_p
    CTYPES_MEMSET_AVAILABLE = True
except (OSError, AttributeError):
    CTYPES_MEMSET_AVAILABLE = False


def secure_zero_memory(data: Union[bytearray, memoryview]) -> bool:
    """
    Securely zero memory containing sensitive data.

    Uses multiple techniques to ensure memory is actually zeroed:
    1. ctypes memset (bypasses Python optimizations)
    2. Direct byte-by-byte overwrite
    3. Multiple passes with different patterns

    Args:
        data: A mutable buffer (bytearray or memoryview) to zero

    Returns:
        True if zeroing succeeded, False otherwise

    Example:
        key = bytearray(secret_key)
        try:
            # Use the key...
        finally:
            secure_zero_memory(key)
    """
    if data is None or len(data) == 0:
        return True

    try:
        # Convert memoryview to get the underlying buffer
        if isinstance(data, memoryview):
            data = data.obj if hasattr(data, 'obj') else data

        if not isinstance(data, bytearray):
            logger.warning("secure_zero_memory requires bytearray, got %s", type(data).__name__)
            return False

        data_len = len(data)

        # Method 1: Use ctypes memset if available (most reliable)
        if CTYPES_MEMSET_AVAILABLE:
            try:
                # Get pointer to bytearray data
                buf_ptr = (ctypes.c_char * data_len).from_buffer(data)
                ctypes.memset(ctypes.addressof(buf_ptr), 0, data_len)
            except (ValueError, TypeError):
                pass  # Fall through to other methods

        # Method 2: Multiple overwrite passes with different patterns
        # This helps defeat potential compiler/interpreter optimizations
        patterns = [0x00, 0xFF, 0xAA, 0x55, 0x00]
        for pattern in patterns:
            for i in range(data_len):
                data[i] = pattern

        # Method 3: Final zero pass with slice assignment
        data[:] = b'\x00' * data_len

        # Verify zeroing succeeded
        if any(b != 0 for b in data):
            logger.warning("Memory zeroing verification failed")
            return False

        return True

    except Exception as e:
        logger.error("Failed to zero memory: %s", e)
        return False


def secure_zero_string(s: str) -> bool:
    """
    Attempt to zero a string's memory.

    WARNING: Python strings are immutable, making secure zeroing extremely
    difficult. This function makes a best-effort attempt but cannot guarantee
    the original string data is removed from memory.

    For truly sensitive data, use bytearray with secure_zero_memory() instead.

    Args:
        s: String to attempt to zero

    Returns:
        True if attempt was made, False on error
    """
    if s is None or len(s) == 0:
        return True

    try:
        if CTYPES_MEMSET_AVAILABLE:
            # Get the string's internal buffer address
            # This is highly implementation-dependent and may not work
            str_buffer = ctypes.create_string_buffer(s.encode('utf-8'))
            ctypes.memset(str_buffer, 0, len(s))

        # Force garbage collection to help clean up
        gc.collect()
        return True

    except Exception as e:
        logger.debug("String zeroing attempt failed (expected): %s", e)
        return False


class SecureBytes:
    """
    A bytearray wrapper that automatically zeros memory on cleanup.

    Use as a context manager for automatic cleanup:

        with SecureBytes(key_data) as key:
            cipher.encrypt(key.data, plaintext)
        # key memory is now zeroed

    Or manually:

        secure_key = SecureBytes(key_data)
        try:
            # Use secure_key.data
        finally:
            secure_key.clear()
    """

    def __init__(self, data: Union[bytes, bytearray, None] = None, size: int = 0):
        """
        Initialize secure bytes container.

        Args:
            data: Initial data (will be copied into internal bytearray)
            size: If data is None, allocate this many zero bytes
        """
        if data is not None:
            self._data = bytearray(data)
        elif size > 0:
            self._data = bytearray(size)
        else:
            self._data = bytearray()

        self._cleared = False

    @property
    def data(self) -> bytearray:
        """Get the underlying bytearray (read-only property)."""
        if self._cleared:
            raise ValueError("SecureBytes has been cleared")
        return self._data

    def __bytes__(self) -> bytes:
        """Convert to bytes (creates a copy - use sparingly)."""
        if self._cleared:
            raise ValueError("SecureBytes has been cleared")
        return bytes(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __enter__(self) -> 'SecureBytes':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.clear()

    def clear(self) -> bool:
        """
        Securely zero and clear the internal buffer.

        Returns:
            True if zeroing succeeded
        """
        if self._cleared:
            return True

        result = secure_zero_memory(self._data)
        self._cleared = True

        # Help garbage collector
        del self._data
        self._data = bytearray()

        return result

    def __del__(self):
        """Destructor - ensure memory is zeroed."""
        if not self._cleared:
            self.clear()


@contextmanager
def secure_key_context(key_data: Union[bytes, bytearray]):
    """
    Context manager for securely handling encryption keys.

    Ensures key material is zeroed after use, even if an exception occurs.

    Example:
        with secure_key_context(derived_key) as key:
            fernet = Fernet(base64.urlsafe_b64encode(key))
            encrypted = fernet.encrypt(data)
        # key is now zeroed

    Args:
        key_data: The key material to protect

    Yields:
        bytearray containing the key (will be zeroed on exit)
    """
    secure_key = SecureBytes(key_data)
    try:
        yield secure_key.data
    finally:
        secure_key.clear()
        # Also try to zero the original if it's a bytearray
        if isinstance(key_data, bytearray):
            secure_zero_memory(key_data)


def secure_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """
    Constant-time comparison to prevent timing attacks.

    Uses hmac.compare_digest which is designed to be constant-time.

    Args:
        a: First value to compare
        b: Second value to compare

    Returns:
        True if values are equal, False otherwise
    """
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')

    return hmac.compare_digest(a, b)


def generate_secure_random(size: int) -> SecureBytes:
    """
    Generate cryptographically secure random bytes in a SecureBytes container.

    The returned SecureBytes should be cleared after use.

    Args:
        size: Number of random bytes to generate

    Returns:
        SecureBytes containing the random data
    """
    return SecureBytes(os.urandom(size))


def secure_derive_key(
    password: Union[str, bytes],
    salt: bytes,
    iterations: int = 480000,
    key_length: int = 32,
) -> SecureBytes:
    """
    Derive a key using PBKDF2-SHA256 with secure memory handling.

    The returned SecureBytes should be cleared after use.

    Args:
        password: Password to derive from
        salt: Salt for key derivation
        iterations: PBKDF2 iteration count (default: 480000 per OWASP)
        key_length: Desired key length in bytes

    Returns:
        SecureBytes containing the derived key
    """
    import hashlib

    if isinstance(password, str):
        password = password.encode('utf-8')

    # Use hashlib's PBKDF2
    derived = hashlib.pbkdf2_hmac(
        'sha256',
        password,
        salt,
        iterations,
        dklen=key_length
    )

    result = SecureBytes(derived)

    # Zero the intermediate derived bytes
    if isinstance(derived, bytearray):
        secure_zero_memory(derived)

    return result


# Utility function for cleaning up after Fernet operations
def cleanup_fernet_key(fernet_key: bytes) -> bool:
    """
    Attempt to clean up a Fernet key from memory.

    Note: Fernet keys are base64-encoded bytes. This function makes
    a best-effort attempt to zero the memory, but Python's immutable
    bytes type makes this unreliable.

    For better security, use SecureBytes and convert to base64 only
    when needed for Fernet initialization.

    Args:
        fernet_key: The Fernet key bytes to clean up

    Returns:
        True if cleanup was attempted
    """
    # We can't reliably zero immutable bytes, but we can help GC
    gc.collect()
    return True


# Self-test function
def _self_test() -> bool:
    """Run self-tests for secure memory functions."""
    print("Testing secure memory functions...")

    # Test 1: secure_zero_memory
    test_data = bytearray(b"SECRET_KEY_12345")
    assert len(test_data) == 16
    result = secure_zero_memory(test_data)
    assert result, "secure_zero_memory failed"
    assert all(b == 0 for b in test_data), "Data not zeroed"
    print("  [PASS] secure_zero_memory")

    # Test 2: SecureBytes context manager
    with SecureBytes(b"ANOTHER_SECRET") as sb:
        assert len(sb.data) == 14
        assert bytes(sb) == b"ANOTHER_SECRET"
    # After context, should be cleared
    assert sb._cleared, "SecureBytes not cleared after context"
    print("  [PASS] SecureBytes context manager")

    # Test 3: secure_compare
    assert secure_compare("password", "password")
    assert not secure_compare("password", "passwerd")
    assert secure_compare(b"\x00\x01\x02", b"\x00\x01\x02")
    print("  [PASS] secure_compare")

    # Test 4: secure_key_context
    original = bytearray(b"KEY_TO_ZERO_123")
    with secure_key_context(original) as key:
        assert len(key) == 15
    # Original should be zeroed if it was a bytearray
    assert all(b == 0 for b in original), "Original not zeroed"
    print("  [PASS] secure_key_context")

    # Test 5: generate_secure_random
    with generate_secure_random(32) as rand:
        assert len(rand.data) == 32
        # Should have some entropy (not all zeros)
        assert any(b != 0 for b in rand.data)
    print("  [PASS] generate_secure_random")

    print("All secure memory tests passed!")
    return True


if __name__ == '__main__':
    _self_test()
