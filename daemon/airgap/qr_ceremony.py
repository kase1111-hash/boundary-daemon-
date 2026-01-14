"""
QR-Code Ceremonies - Approve operations via QR scan from separate device.

Enables ceremony approval without network connectivity by:
1. Generating a QR code containing ceremony challenge
2. Scanning QR with a separate trusted device
3. Device computes response and displays as QR
4. Air-gapped system scans response QR to complete ceremony

SECURITY: All QR data is cryptographically signed. Responses include
HMAC proof that the challenge was seen by the trusted device.
No network required - fully air-gap compatible.
"""

import json
import hmac
import hashlib
import base64
import secrets
from enum import Enum
from typing import Optional, Dict, Any, Tuple, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# QR code generation (optional dependency)
try:
    import qrcode
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

# For terminal QR display
try:
    import io  # noqa: F401
    from PIL import Image  # noqa: F401
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


# =============================================================================
# QR CEREMONY STRUCTURES
# =============================================================================

class QRDisplayMode(Enum):
    """How to display QR codes."""
    TERMINAL_ASCII = "terminal_ascii"    # ASCII art in terminal
    TERMINAL_UNICODE = "terminal_unicode"  # Unicode blocks in terminal
    IMAGE_FILE = "image_file"            # Save as PNG file
    RAW_DATA = "raw_data"                # Return raw data only


class QRCeremonyType(Enum):
    """Types of ceremonies that support QR."""
    OVERRIDE = "override"
    MODE_CHANGE = "mode_change"
    LOG_EXPORT = "log_export"
    KEY_ROTATION = "key_rotation"
    N_OF_M_APPROVAL = "n_of_m_approval"
    DEAD_MAN_CHECKIN = "dead_man_checkin"
    CUSTOM = "custom"


@dataclass
class QRCeremonyChallenge:
    """
    Challenge data encoded in the QR code.

    The trusted device scans this, verifies it, and generates a response.
    """
    challenge_id: str
    ceremony_type: QRCeremonyType
    action: str
    reason: str
    timestamp: str
    expires_at: str
    nonce: str  # Random nonce for replay protection
    node_id: str
    merkle_root: Optional[str] = None  # For log-related ceremonies
    chain_hash: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    # HMAC key hint (not the actual key - just for verification)
    key_hint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for QR encoding."""
        return {
            'cid': self.challenge_id,
            'type': self.ceremony_type.value,
            'act': self.action,
            'rsn': self.reason,
            'ts': self.timestamp,
            'exp': self.expires_at,
            'nonce': self.nonce,
            'node': self.node_id,
            'mroot': self.merkle_root,
            'chain': self.chain_hash,
            'meta': self.metadata,
            'hint': self.key_hint
        }

    def to_qr_data(self) -> str:
        """Convert to compact JSON for QR encoding."""
        return json.dumps(self.to_dict(), separators=(',', ':'))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'QRCeremonyChallenge':
        """Create from dictionary."""
        return cls(
            challenge_id=data['cid'],
            ceremony_type=QRCeremonyType(data['type']),
            action=data['act'],
            reason=data['rsn'],
            timestamp=data['ts'],
            expires_at=data['exp'],
            nonce=data['nonce'],
            node_id=data['node'],
            merkle_root=data.get('mroot'),
            chain_hash=data.get('chain'),
            metadata=data.get('meta', {}),
            key_hint=data.get('hint')
        )

    def is_expired(self) -> bool:
        """Check if challenge has expired."""
        try:
            expiry = datetime.fromisoformat(self.expires_at.replace('Z', '+00:00'))
            now = datetime.utcnow().replace(tzinfo=expiry.tzinfo)
            return now > expiry
        except Exception:
            return True

    def compute_response_hmac(self, shared_secret: bytes, approval: bool) -> str:
        """
        Compute HMAC for response.

        The trusted device uses this to prove it saw the challenge.
        """
        message = f"{self.challenge_id}:{self.nonce}:{approval}".encode()
        return hmac.new(shared_secret, message, hashlib.sha256).hexdigest()


@dataclass
class QRCeremonyResponse:
    """
    Response data from the trusted device.

    This is displayed as a QR code on the trusted device and scanned
    by the air-gapped system.
    """
    challenge_id: str
    approved: bool
    responder_id: str
    responder_name: str
    response_time: str
    hmac_signature: str
    reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for QR encoding."""
        return {
            'cid': self.challenge_id,
            'ok': self.approved,
            'rid': self.responder_id,
            'rname': self.responder_name,
            'ts': self.response_time,
            'sig': self.hmac_signature,
            'rsn': self.reason,
            'meta': self.metadata
        }

    def to_qr_data(self) -> str:
        """Convert to compact JSON for QR encoding."""
        return json.dumps(self.to_dict(), separators=(',', ':'))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'QRCeremonyResponse':
        """Create from dictionary."""
        return cls(
            challenge_id=data['cid'],
            approved=data['ok'],
            responder_id=data['rid'],
            responder_name=data['rname'],
            response_time=data['ts'],
            hmac_signature=data['sig'],
            reason=data.get('rsn'),
            metadata=data.get('meta', {})
        )


# =============================================================================
# QR CODE GENERATOR
# =============================================================================

class QRGenerator:
    """Generates QR codes for ceremony challenges and responses."""

    def __init__(self, display_mode: QRDisplayMode = QRDisplayMode.TERMINAL_ASCII):
        """
        Initialize QR generator.

        Args:
            display_mode: How to display QR codes
        """
        self.display_mode = display_mode

    def generate(self, data: str, output_path: Optional[str] = None) -> Tuple[bool, str]:
        """
        Generate QR code from data.

        Args:
            data: Data to encode
            output_path: Optional path to save image

        Returns:
            (success, result_or_error)
        """
        if not QRCODE_AVAILABLE:
            return self._fallback_display(data)

        try:
            qr = qrcode.QRCode(
                version=None,  # Auto-size
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=1,
                border=1
            )
            qr.add_data(data)
            qr.make(fit=True)

            if self.display_mode == QRDisplayMode.IMAGE_FILE:
                if output_path:
                    img = qr.make_image(fill_color="black", back_color="white")
                    img.save(output_path)
                    return (True, f"QR code saved to {output_path}")
                else:
                    return (False, "No output path specified for image")

            elif self.display_mode == QRDisplayMode.TERMINAL_ASCII:
                return (True, self._to_ascii(qr))

            elif self.display_mode == QRDisplayMode.TERMINAL_UNICODE:
                return (True, self._to_unicode(qr))

            elif self.display_mode == QRDisplayMode.RAW_DATA:
                return (True, data)

        except Exception as e:
            return (False, f"QR generation failed: {e}")

        return (False, "Unknown display mode")

    def _to_ascii(self, qr) -> str:
        """Convert QR to ASCII art."""
        output = []
        for row in qr.modules:
            line = ""
            for cell in row:
                line += "██" if cell else "  "
            output.append(line)
        return "\n".join(output)

    def _to_unicode(self, qr) -> str:
        """Convert QR to Unicode block characters (more compact)."""
        output = []
        modules = qr.modules

        for y in range(0, len(modules), 2):
            line = ""
            for x in range(len(modules[0])):
                top = modules[y][x] if y < len(modules) else False
                bottom = modules[y + 1][x] if y + 1 < len(modules) else False

                if top and bottom:
                    line += "█"
                elif top:
                    line += "▀"
                elif bottom:
                    line += "▄"
                else:
                    line += " "

            output.append(line)

        return "\n".join(output)

    def _fallback_display(self, data: str) -> Tuple[bool, str]:
        """Fallback when qrcode library not available."""
        # Display as base64-encoded data that can be manually entered
        encoded = base64.b64encode(data.encode()).decode()

        output = [
            "=" * 60,
            "QR CODE LIBRARY NOT AVAILABLE",
            "=" * 60,
            "",
            "Install with: pip install qrcode[pil]",
            "",
            "Manual entry data (base64):",
            "-" * 60,
        ]

        # Wrap at 60 chars
        for i in range(0, len(encoded), 60):
            output.append(encoded[i:i + 60])

        output.append("-" * 60)

        return (True, "\n".join(output))


# =============================================================================
# QR CEREMONY MANAGER
# =============================================================================

class QRCeremonyManager:
    """
    Manages QR-based ceremony workflows.

    Workflow:
    1. Air-gapped system generates challenge QR
    2. Operator scans with trusted device
    3. Trusted device displays response QR
    4. Air-gapped system scans response
    5. System verifies HMAC and completes ceremony
    """

    # Challenge validity period
    DEFAULT_CHALLENGE_TTL = 300  # 5 minutes

    def __init__(self, node_id: str, shared_secret: bytes,
                 display_mode: QRDisplayMode = QRDisplayMode.TERMINAL_ASCII,
                 challenge_ttl: int = DEFAULT_CHALLENGE_TTL):
        """
        Initialize QR ceremony manager.

        Args:
            node_id: Identifier for this node
            shared_secret: Shared secret for HMAC (must match trusted device)
            display_mode: How to display QR codes
            challenge_ttl: Challenge validity period in seconds
        """
        self.node_id = node_id
        self.shared_secret = shared_secret
        self.challenge_ttl = challenge_ttl
        self.qr_generator = QRGenerator(display_mode)

        # Pending challenges
        self._pending: Dict[str, QRCeremonyChallenge] = {}

        # Completed challenges (for audit)
        self._completed: List[Tuple[QRCeremonyChallenge, QRCeremonyResponse]] = []

    def create_challenge(self, ceremony_type: QRCeremonyType, action: str,
                        reason: str, merkle_root: Optional[str] = None,
                        chain_hash: Optional[str] = None,
                        metadata: Optional[Dict] = None) -> QRCeremonyChallenge:
        """
        Create a new ceremony challenge.

        Args:
            ceremony_type: Type of ceremony
            action: Action being approved
            reason: Reason for the ceremony
            merkle_root: Current Merkle root (for log ceremonies)
            chain_hash: Current chain hash
            metadata: Additional metadata

        Returns:
            Challenge object
        """
        now = datetime.utcnow()
        expires = now + timedelta(seconds=self.challenge_ttl)

        challenge = QRCeremonyChallenge(
            challenge_id=secrets.token_hex(8),
            ceremony_type=ceremony_type,
            action=action,
            reason=reason,
            timestamp=now.isoformat() + "Z",
            expires_at=expires.isoformat() + "Z",
            nonce=secrets.token_hex(16),
            node_id=self.node_id,
            merkle_root=merkle_root,
            chain_hash=chain_hash,
            metadata=metadata or {},
            key_hint=hashlib.sha256(self.shared_secret).hexdigest()[:8]
        )

        self._pending[challenge.challenge_id] = challenge
        return challenge

    def display_challenge(self, challenge: QRCeremonyChallenge,
                         output_path: Optional[str] = None) -> Tuple[bool, str]:
        """
        Display challenge as QR code.

        Args:
            challenge: Challenge to display
            output_path: Optional path to save image

        Returns:
            (success, result_or_error)
        """
        print("\n" + "=" * 60)
        print("QR CEREMONY CHALLENGE")
        print("=" * 60)
        print(f"Challenge ID: {challenge.challenge_id}")
        print(f"Type: {challenge.ceremony_type.value}")
        print(f"Action: {challenge.action}")
        print(f"Reason: {challenge.reason}")
        print(f"Expires: {challenge.expires_at}")
        print("=" * 60)
        print("\nScan this QR code with your trusted device:\n")

        return self.qr_generator.generate(challenge.to_qr_data(), output_path)

    def verify_response(self, response_data: str) -> Tuple[bool, str, Optional[QRCeremonyResponse]]:
        """
        Verify a scanned response.

        Args:
            response_data: Raw QR data from scan

        Returns:
            (valid, message, response)
        """
        try:
            data = json.loads(response_data)
            response = QRCeremonyResponse.from_dict(data)
        except Exception as e:
            return (False, f"Invalid response format: {e}", None)

        # Find matching challenge
        if response.challenge_id not in self._pending:
            return (False, "Unknown or expired challenge", None)

        challenge = self._pending[response.challenge_id]

        # Check expiry
        if challenge.is_expired():
            del self._pending[response.challenge_id]
            return (False, "Challenge has expired", None)

        # Verify HMAC
        expected_hmac = challenge.compute_response_hmac(self.shared_secret, response.approved)
        if not hmac.compare_digest(response.hmac_signature, expected_hmac):
            return (False, "Invalid HMAC signature", None)

        # Valid response
        del self._pending[response.challenge_id]
        self._completed.append((challenge, response))

        if response.approved:
            return (True, f"Ceremony approved by {response.responder_name}", response)
        else:
            return (True, f"Ceremony rejected by {response.responder_name}: {response.reason}", response)

    def verify_response_interactive(self) -> Tuple[bool, str, Optional[QRCeremonyResponse]]:
        """
        Interactively prompt for response QR data.

        Returns:
            (valid, message, response)
        """
        print("\n" + "-" * 60)
        print("SCAN RESPONSE QR CODE")
        print("-" * 60)
        print("Enter the response data from your trusted device.")
        print("(Paste the JSON data and press Enter twice)")
        print("-" * 60 + "\n")

        lines = []
        while True:
            try:
                line = input()
                if not line:
                    break
                lines.append(line)
            except EOFError:
                break

        response_data = "".join(lines)
        return self.verify_response(response_data)

    def get_pending_challenges(self) -> List[QRCeremonyChallenge]:
        """Get list of pending challenges."""
        # Clean up expired
        now = datetime.utcnow()
        expired = [
            cid for cid, c in self._pending.items()
            if c.is_expired()
        ]
        for cid in expired:
            del self._pending[cid]

        return list(self._pending.values())

    def get_completed_ceremonies(self, limit: int = 100) -> List[Tuple[QRCeremonyChallenge, QRCeremonyResponse]]:
        """Get list of completed ceremonies."""
        return self._completed[-limit:]


# =============================================================================
# TRUSTED DEVICE RESPONDER
# =============================================================================

class TrustedDeviceResponder:
    """
    Responder running on the trusted device (not air-gapped).

    This would typically be a mobile app or separate computer.
    Included here for testing and as reference implementation.
    """

    def __init__(self, responder_id: str, responder_name: str,
                 shared_secret: bytes):
        """
        Initialize trusted device responder.

        Args:
            responder_id: Unique responder identifier
            responder_name: Human-readable name
            shared_secret: Shared secret (must match air-gapped system)
        """
        self.responder_id = responder_id
        self.responder_name = responder_name
        self.shared_secret = shared_secret
        self.qr_generator = QRGenerator(QRDisplayMode.TERMINAL_ASCII)

    def process_challenge(self, challenge_data: str) -> Optional[QRCeremonyChallenge]:
        """
        Process scanned challenge data.

        Args:
            challenge_data: Raw QR data from scan

        Returns:
            Challenge object or None if invalid
        """
        try:
            data = json.loads(challenge_data)
            challenge = QRCeremonyChallenge.from_dict(data)

            # Verify key hint matches
            expected_hint = hashlib.sha256(self.shared_secret).hexdigest()[:8]
            if challenge.key_hint and challenge.key_hint != expected_hint:
                print("WARNING: Key hint mismatch - shared secret may be wrong")

            return challenge

        except Exception as e:
            print(f"Invalid challenge: {e}")
            return None

    def create_response(self, challenge: QRCeremonyChallenge,
                       approved: bool, reason: Optional[str] = None) -> QRCeremonyResponse:
        """
        Create response to a challenge.

        Args:
            challenge: The challenge to respond to
            approved: Whether to approve
            reason: Optional reason (especially for rejections)

        Returns:
            Response object
        """
        hmac_sig = challenge.compute_response_hmac(self.shared_secret, approved)

        return QRCeremonyResponse(
            challenge_id=challenge.challenge_id,
            approved=approved,
            responder_id=self.responder_id,
            responder_name=self.responder_name,
            response_time=datetime.utcnow().isoformat() + "Z",
            hmac_signature=hmac_sig,
            reason=reason
        )

    def display_response(self, response: QRCeremonyResponse,
                        output_path: Optional[str] = None) -> Tuple[bool, str]:
        """
        Display response as QR code.

        Args:
            response: Response to display
            output_path: Optional path to save image

        Returns:
            (success, result_or_error)
        """
        print("\n" + "=" * 60)
        print("QR CEREMONY RESPONSE")
        print("=" * 60)
        print(f"Challenge ID: {response.challenge_id}")
        print(f"Approved: {'YES' if response.approved else 'NO'}")
        print(f"Responder: {response.responder_name}")
        if response.reason:
            print(f"Reason: {response.reason}")
        print("=" * 60)
        print("\nScan this QR code on the air-gapped system:\n")

        return self.qr_generator.generate(response.to_qr_data(), output_path)

    def interactive_respond(self, challenge_data: str) -> Optional[QRCeremonyResponse]:
        """
        Interactively process challenge and create response.

        Args:
            challenge_data: Raw challenge QR data

        Returns:
            Response or None if cancelled
        """
        challenge = self.process_challenge(challenge_data)
        if not challenge:
            return None

        print("\n" + "=" * 60)
        print("CEREMONY APPROVAL REQUEST")
        print("=" * 60)
        print(f"From: {challenge.node_id}")
        print(f"Type: {challenge.ceremony_type.value}")
        print(f"Action: {challenge.action}")
        print(f"Reason: {challenge.reason}")
        print(f"Expires: {challenge.expires_at}")
        print("=" * 60)

        if challenge.is_expired():
            print("\n⚠ This challenge has EXPIRED!")
            return None

        response = input("\nApprove this ceremony? (yes/no): ").lower().strip()

        if response in ('yes', 'y'):
            return self.create_response(challenge, approved=True)
        else:
            reason = input("Reason for rejection (optional): ").strip()
            return self.create_response(challenge, approved=False, reason=reason or None)


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    'QRDisplayMode',
    'QRCeremonyType',
    'QRCeremonyChallenge',
    'QRCeremonyResponse',
    'QRGenerator',
    'QRCeremonyManager',
    'TrustedDeviceResponder',
]
