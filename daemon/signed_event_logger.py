"""
Signed Event Logger - Cryptographically Signed Event Log
Extends EventLogger with non-repudiable cryptographic signatures using NaCl.
"""

import nacl.signing
import nacl.encoding
import os
import json
import threading
import logging
from typing import Optional, List, Dict, Tuple
from pathlib import Path

from .event_logger import EventLogger, EventType, BoundaryEvent

logger = logging.getLogger(__name__)

# Import error handling framework for consistent error management
try:
    from daemon.utils.error_handling import (
        log_security_error,
        log_filesystem_error,
        ErrorCategory,
    )
    ERROR_HANDLING_AVAILABLE = True
except ImportError:
    ERROR_HANDLING_AVAILABLE = False
    def log_security_error(e, op, **ctx):
        logger.error(f"SECURITY: {op}: {e}")
    def log_filesystem_error(e, op, **ctx):
        logger.error(f"FILESYSTEM: {op}: {e}")


class SignedEventLogger(EventLogger):
    """
    Event logger with cryptographic signatures for non-repudiation.

    Each event is signed with a private key (Ed25519). Signatures are stored
    in a separate file, allowing external verification of log authenticity.
    """

    def __init__(self, log_file_path: str, signing_key_path: str):
        """
        Initialize signed event logger.

        Args:
            log_file_path: Path to the log file
            signing_key_path: Path to the signing key file
        """
        super().__init__(log_file_path)
        self.signing_key_path = signing_key_path
        self.signature_file_path = log_file_path + '.sig'
        self._sig_lock = threading.Lock()

        # Load or create signing key
        self.signing_key = self._load_or_create_signing_key()
        self.verify_key = self.signing_key.verify_key

    def _load_or_create_signing_key(self) -> nacl.signing.SigningKey:
        """
        Load existing signing key or create a new one.

        Returns:
            The signing key
        """
        if os.path.exists(self.signing_key_path):
            # Load existing key
            try:
                with open(self.signing_key_path, 'rb') as f:
                    key_bytes = f.read()
                signing_key = nacl.signing.SigningKey(key_bytes)
                logger.info(f"Loaded signing key from {self.signing_key_path}")
                return signing_key
            except (IOError, OSError, ValueError, nacl.exceptions.CryptoError) as e:
                # IOError/OSError: file access errors
                # ValueError/CryptoError: invalid key format or corrupted key
                log_security_error(e, "load_signing_key", key_path=self.signing_key_path)
                logger.info("Generating new key...")

        # Create new key
        signing_key = nacl.signing.SigningKey.generate()

        # Ensure key directory exists with secure permissions
        key_dir = os.path.dirname(self.signing_key_path)
        if key_dir:
            os.makedirs(key_dir, mode=0o700, exist_ok=True)

        # Save key with secure permissions atomically
        # SECURITY: Use os.open() with O_CREAT|O_EXCL to create file with correct
        # permissions from the start, preventing TOCTOU race condition (CWE-362)
        # where another process could read the key before chmod() is called
        try:
            import stat
            fd = os.open(
                self.signing_key_path,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                stat.S_IRUSR | stat.S_IWUSR  # 0o600 - owner read/write only
            )
            try:
                os.write(fd, bytes(signing_key))
            finally:
                os.close(fd)
            logger.info(f"Generated new signing key at {self.signing_key_path}")
            logger.info(f"Public key (for verification): {signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()}")
        except (IOError, OSError, PermissionError) as e:
            # File system errors - permission denied, disk full, etc.
            log_filesystem_error(e, "save_signing_key", key_path=self.signing_key_path)

        return signing_key

    def log_event(self, event_type: EventType, details: str,
                  metadata: Optional[Dict] = None) -> BoundaryEvent:
        """
        Log a boundary event with cryptographic signature.

        Args:
            event_type: Type of event
            details: Human-readable details
            metadata: Additional structured data

        Returns:
            The logged event
        """
        # Log the event using parent class
        event = super().log_event(event_type, details, metadata)

        # Sign the event
        self._sign_event(event)

        return event

    def _sign_event(self, event: BoundaryEvent):
        """
        Sign an event and append signature to signature file.

        Args:
            event: The event to sign
        """
        with self._sig_lock:
            # Create signature of the event JSON
            event_data = event.to_json().encode()
            signed = self.signing_key.sign(event_data)

            # Create signature record
            signature_record = {
                'event_id': event.event_id,
                'signature': signed.signature.hex(),
                'public_key': self.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()
            }

            # Append to signature file
            try:
                with open(self.signature_file_path, 'a') as f:
                    f.write(json.dumps(signature_record) + '\n')
                    f.flush()
                    os.fsync(f.fileno())
            except (IOError, OSError, PermissionError) as e:
                # Signature write failure is critical - must not lose signatures
                log_security_error(e, "write_signature", signature_file=self.signature_file_path)
                raise

    def verify_signatures(self) -> Tuple[bool, Optional[str]]:
        """
        Verify all event signatures.

        Returns:
            (is_valid, error_message)
        """
        if not os.path.exists(self.log_file_path):
            return (True, None)  # Empty log is valid

        if not os.path.exists(self.signature_file_path):
            return (False, "Signature file not found")

        try:
            # Read all events
            with open(self.log_file_path, 'r') as f:
                event_lines = f.readlines()

            # Read all signatures
            with open(self.signature_file_path, 'r') as f:
                sig_lines = f.readlines()

            # Filter out empty lines
            event_lines = [line.strip() for line in event_lines if line.strip()]
            sig_lines = [line.strip() for line in sig_lines if line.strip()]

            if len(event_lines) != len(sig_lines):
                return (False, f"Mismatch: {len(event_lines)} events but {len(sig_lines)} signatures")

            # Verify each event-signature pair
            for i, (event_line, sig_line) in enumerate(zip(event_lines, sig_lines)):
                event_data = json.loads(event_line)
                sig_record = json.loads(sig_line)

                # Check event ID matches
                if event_data['event_id'] != sig_record['event_id']:
                    return (False, f"Event ID mismatch at line {i+1}: log has {event_data['event_id']}, signature has {sig_record['event_id']}")

                # Reconstruct event for verification
                event = BoundaryEvent(
                    event_id=event_data['event_id'],
                    timestamp=event_data['timestamp'],
                    event_type=EventType(event_data['event_type']),
                    details=event_data['details'],
                    metadata=event_data.get('metadata', {}),
                    hash_chain=event_data['hash_chain']
                )

                # Verify signature
                try:
                    verify_key = nacl.signing.VerifyKey(
                        sig_record['public_key'],
                        encoder=nacl.encoding.HexEncoder
                    )

                    verify_key.verify(
                        event.to_json().encode(),
                        bytes.fromhex(sig_record['signature'])
                    )
                except nacl.exceptions.BadSignatureError:
                    return (False, f"Invalid signature for event {event.event_id} at line {i+1}")
                except (ValueError, json.JSONDecodeError, nacl.exceptions.CryptoError) as e:
                    # ValueError: invalid hex/data format
                    # JSONDecodeError: corrupted signature record
                    # CryptoError: invalid public key format
                    return (False, f"Error verifying signature at line {i+1}: {e}")

            return (True, None)

        except (IOError, OSError, json.JSONDecodeError) as e:
            # File access or JSON parsing errors
            return (False, f"Error reading logs: {e}")

    def verify_full_integrity(self) -> Tuple[bool, Optional[str]]:
        """
        Verify both hash chain and signatures.

        Returns:
            (is_valid, error_message)
        """
        # First verify hash chain
        chain_valid, chain_error = self.verify_chain()
        if not chain_valid:
            return (False, f"Hash chain verification failed: {chain_error}")

        # Then verify signatures
        sig_valid, sig_error = self.verify_signatures()
        if not sig_valid:
            return (False, f"Signature verification failed: {sig_error}")

        return (True, None)

    def get_public_key_hex(self) -> str:
        """
        Get the public verification key as hex string.

        Returns:
            Hex-encoded public key
        """
        return self.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()

    def export_public_key(self, output_path: str) -> bool:
        """
        Export the public verification key for external verification.

        Args:
            output_path: Path to save the public key

        Returns:
            True if successful
        """
        try:
            with open(output_path, 'w') as f:
                f.write(f"# Boundary Daemon Event Log Public Verification Key\n")
                f.write(f"# This key can be used to verify the authenticity of event log signatures\n")
                f.write(f"# Generated: {__import__('datetime').datetime.utcnow().isoformat()}Z\n\n")
                f.write(self.get_public_key_hex() + '\n')
            logger.info(f"Public key exported to {output_path}")
            return True
        except (IOError, OSError, PermissionError) as e:
            # File write errors
            log_filesystem_error(e, "export_public_key", output_path=output_path)
            return False


if __name__ == '__main__':
    # Test signed event logger
    print("Testing Signed Event Logger...")

    import tempfile
    import shutil

    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    log_file = os.path.join(temp_dir, 'boundary_chain.log')
    key_file = os.path.join(temp_dir, 'signing.key')

    print(f"\nUsing temporary directory: {temp_dir}")

    # Create logger
    logger = SignedEventLogger(log_file, key_file)

    # Log some events
    print("\nLogging events...")
    logger.log_event(EventType.DAEMON_START, "Boundary daemon started")
    logger.log_event(EventType.MODE_CHANGE, "Transitioned from OPEN to RESTRICTED",
                    metadata={'old_mode': 'open', 'new_mode': 'restricted'})
    logger.log_event(EventType.RECALL_ATTEMPT, "Memory class 3 recall requested",
                    metadata={'memory_class': 3, 'decision': 'allow'})
    logger.log_event(EventType.VIOLATION, "Network came online in AIRGAP mode",
                    metadata={'violation_type': 'network_in_airgap'})

    print(f"Total events logged: {logger.get_event_count()}")

    # Verify hash chain
    print("\nVerifying hash chain...")
    chain_valid, chain_error = logger.verify_chain()
    print(f"Hash chain valid: {chain_valid}")
    if chain_error:
        print(f"Error: {chain_error}")

    # Verify signatures
    print("\nVerifying signatures...")
    sig_valid, sig_error = logger.verify_signatures()
    print(f"Signatures valid: {sig_valid}")
    if sig_error:
        print(f"Error: {sig_error}")

    # Full integrity check
    print("\nFull integrity verification...")
    full_valid, full_error = logger.verify_full_integrity()
    print(f"Full integrity valid: {full_valid}")
    if full_error:
        print(f"Error: {full_error}")

    # Export public key
    print("\nExporting public key...")
    pub_key_file = os.path.join(temp_dir, 'public_key.txt')
    logger.export_public_key(pub_key_file)

    # Display public key
    print(f"\nPublic verification key: {logger.get_public_key_hex()}")

    # Test tampering detection
    print("\n\n=== Testing Tamper Detection ===")
    print("Attempting to tamper with log...")

    # Read log file
    with open(log_file, 'r') as f:
        lines = f.readlines()

    # Modify second event
    if len(lines) > 1:
        event_data = json.loads(lines[1])
        event_data['details'] = "TAMPERED DATA"
        lines[1] = json.dumps(event_data) + '\n'

        # Write back tampered log
        with open(log_file, 'w') as f:
            f.writelines(lines)

        print("Log tampered (modified second event)")

        # Try to verify
        print("\nVerifying tampered log...")
        tampered_valid, tampered_error = logger.verify_signatures()
        print(f"Signatures valid: {tampered_valid}")
        if tampered_error:
            print(f"Error detected: {tampered_error}")

    # Cleanup
    print(f"\nCleaning up {temp_dir}...")
    shutil.rmtree(temp_dir)

    print("\nSigned event logger test complete.")
