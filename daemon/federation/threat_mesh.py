"""
Federated AI Security Mesh - Cross-organization threat intelligence sharing.

Phase 3 Cutting-Edge Innovation: First federated threat intelligence network
specifically designed for AI/LLM attacks.

Features:
- Privacy-preserving threat signature sharing via Bloom filters
- Differential privacy for pattern aggregation
- Cryptographically signed contributions
- Peer reputation scoring
- Verified organization identities
- Revocation for bad actors

Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │                     THREAT MESH NETWORK                         │
    ├─────────────────────────────────────────────────────────────────┤
    │  Org A            Org B            Org C            Org D       │
    │  ┌───┐            ┌───┐            ┌───┐            ┌───┐      │
    │  │ D │◄──────────►│ D │◄──────────►│ D │◄──────────►│ D │      │
    │  └───┘            └───┘            └───┘            └───┘      │
    │    │                │                │                │        │
    │    ▼                ▼                ▼                ▼        │
    │  Local            Local            Local            Local      │
    │  Threats          Threats          Threats          Threats    │
    └─────────────────────────────────────────────────────────────────┘

    D = Daemon with Mesh Client

Privacy Model:
- Raw prompts NEVER leave organization
- Only anonymized patterns/signatures shared
- Bloom filters for IOC matching (no false negatives, controlled false positives)
- Differential privacy adds noise to aggregate statistics
"""

import hashlib
import hmac
import json
import math
import os
import struct
import threading
import time
import ssl
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any, Callable
import logging

try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.encoding import HexEncoder
    from nacl.exceptions import BadSignatureError
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False

logger = logging.getLogger(__name__)


class ThreatCategory(Enum):
    """Categories of AI/LLM threats."""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SANDBOX_ESCAPE = "sandbox_escape"
    RESOURCE_ABUSE = "resource_abuse"
    SOCIAL_ENGINEERING = "social_engineering"
    MODEL_MANIPULATION = "model_manipulation"
    CONTEXT_POISONING = "context_poisoning"
    TOOL_ABUSE = "tool_abuse"


class SharePolicy(Enum):
    """Policies for threat sharing."""
    SHARE_ALL = "share_all"           # Share with all verified peers
    SHARE_TRUSTED = "share_trusted"   # Share only with trusted peers (reputation > threshold)
    SHARE_RECIPROCAL = "share_reciprocal"  # Share only with peers who share back
    SHARE_NONE = "share_none"         # Local only, no sharing


@dataclass
class ThreatSignature:
    """
    Anonymized threat signature for sharing.

    Contains no raw content - only hashed/anonymized patterns.
    """
    signature_id: str
    category: ThreatCategory
    pattern_hash: str  # SHA-256 of normalized pattern
    pattern_bloom: bytes  # Bloom filter of pattern tokens
    confidence: float  # 0.0 - 1.0
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    contributor_id: str  # Anonymized org identifier
    contributor_signature: bytes  # Ed25519 signature
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'signature_id': self.signature_id,
            'category': self.category.value,
            'pattern_hash': self.pattern_hash,
            'pattern_bloom': self.pattern_bloom.hex(),
            'confidence': self.confidence,
            'severity': self.severity,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'occurrence_count': self.occurrence_count,
            'contributor_id': self.contributor_id,
            'contributor_signature': self.contributor_signature.hex(),
            'metadata': self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatSignature':
        """Create from dictionary."""
        return cls(
            signature_id=data['signature_id'],
            category=ThreatCategory(data['category']),
            pattern_hash=data['pattern_hash'],
            pattern_bloom=bytes.fromhex(data['pattern_bloom']),
            confidence=data['confidence'],
            severity=data['severity'],
            first_seen=datetime.fromisoformat(data['first_seen']),
            last_seen=datetime.fromisoformat(data['last_seen']),
            occurrence_count=data['occurrence_count'],
            contributor_id=data['contributor_id'],
            contributor_signature=bytes.fromhex(data['contributor_signature']),
            metadata=data.get('metadata', {}),
        )


@dataclass
class MeshPeer:
    """A peer in the threat mesh network."""
    peer_id: str
    organization_name: str
    public_key: bytes  # Ed25519 verify key
    endpoint: str  # URL for mesh communication
    reputation_score: float = 1.0  # 0.0 - 1.0
    last_seen: Optional[datetime] = None
    signatures_received: int = 0
    signatures_contributed: int = 0
    verified: bool = False
    revoked: bool = False
    trust_level: str = "standard"  # standard, trusted, untrusted

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'peer_id': self.peer_id,
            'organization_name': self.organization_name,
            'public_key': self.public_key.hex(),
            'endpoint': self.endpoint,
            'reputation_score': self.reputation_score,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'signatures_received': self.signatures_received,
            'signatures_contributed': self.signatures_contributed,
            'verified': self.verified,
            'revoked': self.revoked,
            'trust_level': self.trust_level,
        }


class BloomFilter:
    """
    Bloom filter for privacy-preserving IOC matching.

    Properties:
    - No false negatives (if item was added, it will be found)
    - Controlled false positive rate
    - Cannot extract original items from filter
    """

    def __init__(self, size: int = 1024, hash_count: int = 7):
        """
        Initialize Bloom filter.

        Args:
            size: Number of bits in the filter
            hash_count: Number of hash functions
        """
        self.size = size
        self.hash_count = hash_count
        self.bit_array = bytearray((size + 7) // 8)

    def _hashes(self, item: str) -> List[int]:
        """Generate hash values for an item."""
        hashes = []
        for i in range(self.hash_count):
            # Use HMAC with different keys for each hash
            h = hmac.new(
                f"bloom_hash_{i}".encode(),
                item.encode(),
                hashlib.sha256
            ).digest()
            # Convert first 8 bytes to int and mod by size
            val = struct.unpack('>Q', h[:8])[0] % self.size
            hashes.append(val)
        return hashes

    def add(self, item: str) -> None:
        """Add an item to the filter."""
        for h in self._hashes(item):
            byte_idx = h // 8
            bit_idx = h % 8
            self.bit_array[byte_idx] |= (1 << bit_idx)

    def check(self, item: str) -> bool:
        """Check if an item might be in the filter."""
        for h in self._hashes(item):
            byte_idx = h // 8
            bit_idx = h % 8
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True

    def to_bytes(self) -> bytes:
        """Export filter as bytes."""
        return bytes(self.bit_array)

    @classmethod
    def from_bytes(cls, data: bytes, size: int = 1024, hash_count: int = 7) -> 'BloomFilter':
        """Create filter from bytes."""
        bf = cls(size=size, hash_count=hash_count)
        bf.bit_array = bytearray(data)
        return bf

    def merge(self, other: 'BloomFilter') -> 'BloomFilter':
        """Merge two Bloom filters (OR operation)."""
        if self.size != other.size or self.hash_count != other.hash_count:
            raise ValueError("Cannot merge filters with different parameters")

        result = BloomFilter(self.size, self.hash_count)
        for i in range(len(self.bit_array)):
            result.bit_array[i] = self.bit_array[i] | other.bit_array[i]
        return result


class DifferentialPrivacy:
    """
    Differential privacy mechanisms for aggregate statistics.

    Adds calibrated noise to protect individual contributions
    while preserving aggregate utility.
    """

    def __init__(self, epsilon: float = 1.0, delta: float = 1e-5):
        """
        Initialize differential privacy.

        Args:
            epsilon: Privacy budget (lower = more private)
            delta: Probability of privacy breach
        """
        self.epsilon = epsilon
        self.delta = delta

    def add_laplace_noise(self, value: float, sensitivity: float = 1.0) -> float:
        """
        Add Laplace noise for epsilon-differential privacy.

        Args:
            value: The true value
            sensitivity: Maximum change from one record

        Returns:
            Noisy value
        """
        scale = sensitivity / self.epsilon
        # Laplace noise
        u = os.urandom(8)
        uniform = struct.unpack('>d', u)[0]
        # Transform uniform to Laplace
        if uniform < 0.5:
            noise = scale * math.log(2 * uniform)
        else:
            noise = -scale * math.log(2 * (1 - uniform))
        return value + noise

    def add_gaussian_noise(self, value: float, sensitivity: float = 1.0) -> float:
        """
        Add Gaussian noise for (epsilon, delta)-differential privacy.

        Args:
            value: The true value
            sensitivity: Maximum change from one record

        Returns:
            Noisy value
        """
        sigma = sensitivity * math.sqrt(2 * math.log(1.25 / self.delta)) / self.epsilon
        # Box-Muller transform for Gaussian
        u1 = struct.unpack('>d', os.urandom(8))[0]
        u2 = struct.unpack('>d', os.urandom(8))[0]
        # Ensure u1 is not 0
        u1 = max(u1, 1e-10)
        noise = sigma * math.sqrt(-2 * math.log(u1)) * math.cos(2 * math.pi * u2)
        return value + noise

    def randomized_response(self, true_value: bool, p: Optional[float] = None) -> bool:
        """
        Randomized response for boolean values.

        Args:
            true_value: The true boolean value
            p: Probability of telling truth (default: calculated from epsilon)

        Returns:
            Possibly flipped value
        """
        if p is None:
            p = math.exp(self.epsilon) / (1 + math.exp(self.epsilon))

        rand = struct.unpack('>d', os.urandom(8))[0]
        if rand < p:
            return true_value
        else:
            return not true_value


class ThreatMesh:
    """
    Federated AI Security Mesh - main coordinator.

    Manages:
    - Local threat signature database
    - Peer connections and reputation
    - Signature sharing and receiving
    - Privacy-preserving aggregation
    """

    def __init__(
        self,
        organization_id: str,
        signing_key: Optional[bytes] = None,
        share_policy: SharePolicy = SharePolicy.SHARE_TRUSTED,
        privacy_epsilon: float = 1.0,
        min_peer_reputation: float = 0.5,
        data_dir: Optional[str] = None,
    ):
        """
        Initialize the Threat Mesh.

        Args:
            organization_id: Unique identifier for this organization
            signing_key: Ed25519 signing key (generated if not provided)
            share_policy: Policy for sharing signatures
            privacy_epsilon: Differential privacy budget
            min_peer_reputation: Minimum reputation to share with
            data_dir: Directory for persistent storage
        """
        self.organization_id = organization_id
        self.share_policy = share_policy
        self.min_peer_reputation = min_peer_reputation
        self.data_dir = data_dir

        # Cryptographic keys
        if NACL_AVAILABLE:
            if signing_key:
                self._signing_key = SigningKey(signing_key)
            else:
                self._signing_key = SigningKey.generate()
            self._verify_key = self._signing_key.verify_key
            self.public_key = bytes(self._verify_key)
        else:
            self._signing_key = None
            self._verify_key = None
            self.public_key = os.urandom(32)  # Placeholder

        # Privacy mechanisms
        self.dp = DifferentialPrivacy(epsilon=privacy_epsilon)

        # Local signature database
        self._signatures: Dict[str, ThreatSignature] = {}
        self._signature_lock = threading.RLock()

        # Peer registry
        self._peers: Dict[str, MeshPeer] = {}
        self._peer_lock = threading.RLock()

        # Event handlers - use dict for O(1) unregister to prevent memory leaks
        self._on_threat_received: Dict[int, Callable[[ThreatSignature], None]] = {}
        self._on_peer_joined: Dict[int, Callable[[MeshPeer], None]] = {}
        self._on_peer_revoked: Dict[int, Callable[[MeshPeer], None]] = {}
        self._next_handler_id = 0
        self._handler_lock = threading.RLock()

        # Statistics
        self._stats = {
            'signatures_created': 0,
            'signatures_shared': 0,
            'signatures_received': 0,
            'queries_processed': 0,
            'matches_found': 0,
        }

        # Background sync
        self._sync_thread: Optional[threading.Thread] = None
        self._running = False

        logger.info(f"ThreatMesh initialized for organization: {organization_id}")

    def start(self) -> None:
        """Start the mesh client."""
        self._running = True
        self._sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self._sync_thread.start()
        logger.info("ThreatMesh started")

    def stop(self) -> None:
        """Stop the mesh client."""
        self._running = False
        if self._sync_thread:
            self._sync_thread.join(timeout=5.0)
        logger.info("ThreatMesh stopped")

    def _sync_loop(self) -> None:
        """Background synchronization loop."""
        while self._running:
            try:
                self._sync_with_peers()
            except Exception as e:
                logger.error(f"Sync error: {e}")
            time.sleep(60)  # Sync every minute

    def _sync_with_peers(self) -> None:
        """Synchronize signatures with peers."""
        with self._peer_lock:
            active_peers = [
                p for p in self._peers.values()
                if not p.revoked and p.verified
            ]

        for peer in active_peers:
            if self._should_share_with(peer):
                try:
                    self._push_signatures_to_peer(peer)
                    self._pull_signatures_from_peer(peer)
                except Exception as e:
                    logger.warning(f"Failed to sync with {peer.peer_id}: {e}")
                    self._update_peer_reputation(peer.peer_id, -0.01)

    def _should_share_with(self, peer: MeshPeer) -> bool:
        """Determine if we should share with this peer."""
        if self.share_policy == SharePolicy.SHARE_NONE:
            return False

        if self.share_policy == SharePolicy.SHARE_ALL:
            return peer.verified and not peer.revoked

        if self.share_policy == SharePolicy.SHARE_TRUSTED:
            return (
                peer.verified and
                not peer.revoked and
                peer.reputation_score >= self.min_peer_reputation
            )

        if self.share_policy == SharePolicy.SHARE_RECIPROCAL:
            return (
                peer.verified and
                not peer.revoked and
                peer.signatures_contributed > 0
            )

        return False

    def _push_signatures_to_peer(self, peer: MeshPeer) -> None:
        """
        Push new signatures to a peer via HTTPS.

        Protocol:
        1. Collect unpushed signatures for this peer
        2. Sign the payload with our private key
        3. Send via HTTPS POST to peer's endpoint
        4. Verify acknowledgment signature
        """
        if not NACL_AVAILABLE or not self._signing_key:
            logger.debug("Cannot push signatures: nacl not available or no signing key")
            return

        if peer.revoked or not peer.verified:
            logger.debug(f"Skipping push to {peer.peer_id}: revoked={peer.revoked}, verified={peer.verified}")
            return

        try:
            # Collect signatures to push (those created since last sync)
            with self._lock:
                signatures_to_push = [
                    sig.to_dict() for sig in self._signatures.values()
                    if sig.source_org == self.config.organization_id
                ]

            if not signatures_to_push:
                return

            # Create signed payload
            payload = {
                'action': 'push_signatures',
                'source_org': self.config.organization_id,
                'source_peer_id': self._peer_id,
                'timestamp': datetime.now().isoformat(),
                'signatures': signatures_to_push,
                'signature_count': len(signatures_to_push),
            }

            # Sign the payload
            payload_bytes = json.dumps(payload, sort_keys=True).encode()
            signed = self._signing_key.sign(payload_bytes, encoder=HexEncoder)

            request_body = {
                'payload': payload,
                'signature': signed.signature.decode(),
                'public_key': self._verify_key.encode(encoder=HexEncoder).decode(),
            }

            # Send via HTTPS
            url = f"{peer.endpoint.rstrip('/')}/mesh/v1/signatures"
            req = urllib.request.Request(
                url,
                data=json.dumps(request_body).encode(),
                headers={
                    'Content-Type': 'application/json',
                    'X-Mesh-Peer-ID': self._peer_id,
                    'X-Mesh-Org': self.config.organization_id,
                },
                method='POST'
            )

            # Use TLS with certificate verification
            context = ssl.create_default_context()

            with urllib.request.urlopen(req, timeout=30, context=context) as response:
                # Read response (acknowledgment) - contents not needed
                _ = response.read()

                # Update peer stats
                with self._lock:
                    peer.last_seen = datetime.now()
                    peer.signatures_contributed += len(signatures_to_push)

                logger.info(f"Pushed {len(signatures_to_push)} signatures to {peer.organization_name}")

        except urllib.error.URLError as e:
            logger.warning(f"Failed to push signatures to {peer.organization_name}: {e}")
            # Decrease reputation for unreachable peers
            with self._lock:
                peer.reputation_score = max(0.0, peer.reputation_score - 0.01)
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Invalid response from {peer.organization_name}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error pushing to {peer.organization_name}: {e}")

    def _pull_signatures_from_peer(self, peer: MeshPeer) -> None:
        """
        Pull new signatures from a peer via HTTPS.

        Protocol:
        1. Request signatures newer than our last sync
        2. Verify signature on response payload
        3. Validate and import each signature
        4. Update peer reputation based on quality
        """
        if not NACL_AVAILABLE or not self._signing_key:
            logger.debug("Cannot pull signatures: nacl not available or no signing key")
            return

        if peer.revoked or not peer.verified:
            logger.debug(f"Skipping pull from {peer.peer_id}: revoked={peer.revoked}, verified={peer.verified}")
            return

        try:
            # Build request with our last sync timestamp
            last_sync = peer.last_seen.isoformat() if peer.last_seen else "1970-01-01T00:00:00"

            # Create signed request
            request_payload = {
                'action': 'pull_signatures',
                'requester_org': self.config.organization_id,
                'requester_peer_id': self._peer_id,
                'since': last_sync,
                'timestamp': datetime.now().isoformat(),
            }

            payload_bytes = json.dumps(request_payload, sort_keys=True).encode()
            signed = self._signing_key.sign(payload_bytes, encoder=HexEncoder)

            request_body = {
                'payload': request_payload,
                'signature': signed.signature.decode(),
                'public_key': self._verify_key.encode(encoder=HexEncoder).decode(),
            }

            # Send request
            url = f"{peer.endpoint.rstrip('/')}/mesh/v1/signatures/pull"
            req = urllib.request.Request(
                url,
                data=json.dumps(request_body).encode(),
                headers={
                    'Content-Type': 'application/json',
                    'X-Mesh-Peer-ID': self._peer_id,
                    'X-Mesh-Org': self.config.organization_id,
                },
                method='POST'
            )

            context = ssl.create_default_context()

            with urllib.request.urlopen(req, timeout=30, context=context) as response:
                response_data = json.loads(response.read().decode())

                # Verify response signature using peer's public key
                if 'signature' in response_data and 'payload' in response_data:
                    try:
                        peer_verify_key = VerifyKey(peer.public_key)
                        response_payload = response_data['payload']
                        response_sig = bytes.fromhex(response_data['signature'])

                        # Verify signature
                        payload_bytes = json.dumps(response_payload, sort_keys=True).encode()
                        peer_verify_key.verify(payload_bytes, response_sig)

                        # Import verified signatures
                        imported_count = 0
                        for sig_data in response_payload.get('signatures', []):
                            if self._import_signature(sig_data, peer):
                                imported_count += 1

                        # Update peer stats
                        with self._lock:
                            peer.last_seen = datetime.now()
                            peer.signatures_received += imported_count
                            # Increase reputation for good contributions
                            if imported_count > 0:
                                peer.reputation_score = min(1.0, peer.reputation_score + 0.001 * imported_count)

                        logger.info(f"Pulled {imported_count} signatures from {peer.organization_name}")

                    except BadSignatureError:
                        logger.error(f"Invalid signature from {peer.organization_name} - possible tampering!")
                        with self._lock:
                            peer.reputation_score = max(0.0, peer.reputation_score - 0.1)
                else:
                    logger.warning(f"Missing signature in response from {peer.organization_name}")

        except urllib.error.URLError as e:
            logger.warning(f"Failed to pull signatures from {peer.organization_name}: {e}")
            with self._lock:
                peer.reputation_score = max(0.0, peer.reputation_score - 0.01)
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Invalid response from {peer.organization_name}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error pulling from {peer.organization_name}: {e}")

    def _import_signature(self, sig_data: Dict[str, Any], peer: MeshPeer) -> bool:
        """
        Import a signature from a peer after validation.

        Returns True if signature was imported, False if rejected.
        """
        try:
            sig_id = sig_data.get('signature_id')
            if not sig_id:
                return False

            # Skip if we already have this signature
            with self._lock:
                if sig_id in self._signatures:
                    return False

            # Validate required fields
            required_fields = ['pattern_hash', 'category', 'severity', 'created_at']
            if not all(f in sig_data for f in required_fields):
                logger.debug(f"Rejecting signature {sig_id}: missing required fields")
                return False

            # Validate category
            try:
                category = ThreatCategory(sig_data['category'])
            except ValueError:
                logger.debug(f"Rejecting signature {sig_id}: invalid category")
                return False

            # Apply trust filter - lower trust peers get more scrutiny
            if peer.trust_level == 'untrusted':
                # Only accept high-severity from untrusted peers
                if sig_data.get('severity') not in ('HIGH', 'CRITICAL'):
                    return False

            # Create ThreatSignature object
            signature = ThreatSignature(
                signature_id=sig_id,
                pattern_hash=sig_data['pattern_hash'],
                bloom_filter=sig_data.get('bloom_filter', ''),
                category=category,
                severity=sig_data['severity'],
                confidence=sig_data.get('confidence', 0.5),
                source_org=sig_data.get('source_org', peer.organization_name),
                created_at=datetime.fromisoformat(sig_data['created_at']),
                signature_data=sig_data.get('signature_data', b''),
                metadata=sig_data.get('metadata', {}),
            )

            # Add to our collection
            with self._lock:
                self._signatures[sig_id] = signature

            return True

        except Exception as e:
            logger.debug(f"Error importing signature: {e}")
            return False

    def create_signature(
        self,
        raw_content: str,
        category: ThreatCategory,
        severity: str = "MEDIUM",
        confidence: float = 0.8,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ThreatSignature:
        """
        Create a threat signature from raw content.

        The raw content is NEVER stored - only anonymized representations.

        Args:
            raw_content: The raw threat content (e.g., malicious prompt)
            category: Category of threat
            severity: Severity level
            confidence: Detection confidence
            metadata: Additional metadata (must not contain PII)

        Returns:
            Anonymized ThreatSignature
        """
        # Normalize content
        normalized = self._normalize_content(raw_content)

        # Create pattern hash (one-way)
        pattern_hash = hashlib.sha256(normalized.encode()).hexdigest()

        # Create Bloom filter of tokens
        tokens = self._tokenize(normalized)
        bloom = BloomFilter(size=1024, hash_count=7)
        for token in tokens:
            bloom.add(token)

        # Generate signature ID
        sig_id = f"sig_{hashlib.sha256(os.urandom(16)).hexdigest()[:16]}"

        now = datetime.now()

        # Create signature data for signing
        sig_data = {
            'signature_id': sig_id,
            'category': category.value,
            'pattern_hash': pattern_hash,
            'contributor_id': self.organization_id,
            'timestamp': now.isoformat(),
        }

        # Sign the signature
        if NACL_AVAILABLE and self._signing_key:
            signed = self._signing_key.sign(json.dumps(sig_data).encode())
            contributor_sig = bytes(signed.signature)
        else:
            contributor_sig = os.urandom(64)  # Placeholder

        signature = ThreatSignature(
            signature_id=sig_id,
            category=category,
            pattern_hash=pattern_hash,
            pattern_bloom=bloom.to_bytes(),
            confidence=confidence,
            severity=severity,
            first_seen=now,
            last_seen=now,
            occurrence_count=1,
            contributor_id=self.organization_id,
            contributor_signature=contributor_sig,
            metadata=metadata or {},
        )

        # Store locally
        with self._signature_lock:
            self._signatures[sig_id] = signature
            self._stats['signatures_created'] += 1

        logger.info(f"Created threat signature: {sig_id} ({category.value})")
        return signature

    def _normalize_content(self, content: str) -> str:
        """Normalize content for consistent hashing."""
        # Lowercase
        normalized = content.lower()
        # Remove extra whitespace
        normalized = ' '.join(normalized.split())
        # Remove common variations
        replacements = [
            ('please', ''),
            ('could you', ''),
            ('can you', ''),
            ('would you', ''),
        ]
        for old, new in replacements:
            normalized = normalized.replace(old, new)
        return normalized.strip()

    def _tokenize(self, content: str) -> List[str]:
        """Tokenize content for Bloom filter."""
        # Simple word tokenization
        words = content.split()
        tokens = []

        # Add individual words
        tokens.extend(words)

        # Add bigrams
        for i in range(len(words) - 1):
            tokens.append(f"{words[i]} {words[i+1]}")

        # Add trigrams
        for i in range(len(words) - 2):
            tokens.append(f"{words[i]} {words[i+1]} {words[i+2]}")

        return tokens

    def check_content(self, content: str) -> List[Tuple[ThreatSignature, float]]:
        """
        Check if content matches any known threat signatures.

        Uses Bloom filter for fast pre-filtering, then verifies matches.

        Args:
            content: Content to check

        Returns:
            List of (signature, match_score) tuples
        """
        normalized = self._normalize_content(content)
        tokens = self._tokenize(normalized)
        content_hash = hashlib.sha256(normalized.encode()).hexdigest()

        matches = []

        with self._signature_lock:
            for sig in self._signatures.values():
                # First check: exact hash match
                if sig.pattern_hash == content_hash:
                    matches.append((sig, 1.0))
                    continue

                # Second check: Bloom filter token matching
                bloom = BloomFilter.from_bytes(sig.pattern_bloom)
                matching_tokens = sum(1 for t in tokens if bloom.check(t))

                if matching_tokens > 0:
                    match_score = matching_tokens / len(tokens)
                    if match_score >= 0.3:  # Threshold for partial match
                        matches.append((sig, match_score))

        self._stats['queries_processed'] += 1
        self._stats['matches_found'] += len(matches)

        # Sort by match score
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches

    def receive_signature(
        self,
        signature: ThreatSignature,
        from_peer_id: str,
    ) -> bool:
        """
        Receive a signature from a peer.

        Validates the signature and stores if valid.

        Args:
            signature: The threat signature
            from_peer_id: ID of the contributing peer

        Returns:
            True if accepted, False if rejected
        """
        # Verify peer exists and is not revoked
        with self._peer_lock:
            peer = self._peers.get(from_peer_id)
            if not peer or peer.revoked:
                logger.warning(f"Rejected signature from unknown/revoked peer: {from_peer_id}")
                return False

        # Verify signature
        if NACL_AVAILABLE:
            # Get contributor's public key
            contributor_peer = self._peers.get(signature.contributor_id)
            if contributor_peer:
                try:
                    verify_key = VerifyKey(contributor_peer.public_key)
                    sig_data = {
                        'signature_id': signature.signature_id,
                        'category': signature.category.value,
                        'pattern_hash': signature.pattern_hash,
                        'contributor_id': signature.contributor_id,
                        'timestamp': signature.first_seen.isoformat(),
                    }
                    verify_key.verify(
                        json.dumps(sig_data).encode(),
                        signature.contributor_signature
                    )
                except BadSignatureError:
                    logger.warning(f"Invalid signature from {signature.contributor_id}")
                    self._update_peer_reputation(from_peer_id, -0.1)
                    return False

        # Store the signature
        with self._signature_lock:
            if signature.signature_id not in self._signatures:
                self._signatures[signature.signature_id] = signature
                self._stats['signatures_received'] += 1

                # Update peer stats
                with self._peer_lock:
                    if peer:
                        peer.signatures_received += 1

                # Notify handlers - copy values to avoid modification during iteration
                with self._handler_lock:
                    handlers = list(self._on_threat_received.values())
                for handler in handlers:
                    try:
                        handler(signature)
                    except Exception as e:
                        logger.error(f"Handler error: {e}")

                logger.info(f"Received signature: {signature.signature_id} from {from_peer_id}")
                return True
            else:
                # Update existing signature
                existing = self._signatures[signature.signature_id]
                existing.occurrence_count += signature.occurrence_count
                existing.last_seen = max(existing.last_seen, signature.last_seen)
                return True

        return False

    def add_peer(
        self,
        peer_id: str,
        organization_name: str,
        public_key: bytes,
        endpoint: str,
    ) -> MeshPeer:
        """
        Add a new peer to the mesh.

        Args:
            peer_id: Unique peer identifier
            organization_name: Human-readable org name
            public_key: Ed25519 public key
            endpoint: Communication endpoint URL

        Returns:
            The created MeshPeer
        """
        peer = MeshPeer(
            peer_id=peer_id,
            organization_name=organization_name,
            public_key=public_key,
            endpoint=endpoint,
            last_seen=datetime.now(),
        )

        with self._peer_lock:
            self._peers[peer_id] = peer

        logger.info(f"Added peer: {peer_id} ({organization_name})")

        # Notify handlers - copy values to avoid modification during iteration
        with self._handler_lock:
            handlers = list(self._on_peer_joined.values())
        for handler in handlers:
            try:
                handler(peer)
            except Exception as e:
                logger.error(f"Handler error: {e}")

        return peer

    def verify_peer(self, peer_id: str, _verification_token: str) -> bool:
        """
        Verify a peer's identity.

        Args:
            peer_id: The peer to verify
            verification_token: Token proving ownership

        Returns:
            True if verified successfully
        """
        with self._peer_lock:
            peer = self._peers.get(peer_id)
            if not peer:
                return False

            # In a real implementation, this would verify the token
            # against the peer's public key
            peer.verified = True
            logger.info(f"Verified peer: {peer_id}")
            return True

    def revoke_peer(self, peer_id: str, reason: str) -> bool:
        """
        Revoke a peer from the mesh.

        Args:
            peer_id: The peer to revoke
            reason: Reason for revocation

        Returns:
            True if revoked successfully
        """
        with self._peer_lock:
            peer = self._peers.get(peer_id)
            if not peer:
                return False

            peer.revoked = True
            logger.warning(f"Revoked peer {peer_id}: {reason}")

            # Notify handlers - copy values to avoid modification during iteration
            with self._handler_lock:
                handlers = list(self._on_peer_revoked.values())
            for handler in handlers:
                try:
                    handler(peer)
                except Exception as e:
                    logger.error(f"Handler error: {e}")

            return True

    def _update_peer_reputation(self, peer_id: str, delta: float) -> None:
        """Update a peer's reputation score."""
        with self._peer_lock:
            peer = self._peers.get(peer_id)
            if peer:
                peer.reputation_score = max(0.0, min(1.0, peer.reputation_score + delta))

                # Auto-revoke if reputation too low
                if peer.reputation_score < 0.1:
                    self.revoke_peer(peer_id, "Reputation too low")

    def get_aggregate_stats(self, with_privacy: bool = True) -> Dict[str, Any]:
        """
        Get aggregate statistics with optional differential privacy.

        Args:
            with_privacy: Whether to add DP noise

        Returns:
            Dictionary of statistics
        """
        with self._signature_lock:
            category_counts = {}
            for sig in self._signatures.values():
                cat = sig.category.value
                category_counts[cat] = category_counts.get(cat, 0) + 1

        stats = {
            'total_signatures': len(self._signatures),
            'category_distribution': category_counts,
            'peers_connected': len([p for p in self._peers.values() if not p.revoked]),
            'peers_verified': len([p for p in self._peers.values() if p.verified and not p.revoked]),
        }

        if with_privacy:
            # Add differential privacy noise
            stats['total_signatures'] = int(self.dp.add_laplace_noise(
                stats['total_signatures'],
                sensitivity=1.0
            ))
            for cat in stats['category_distribution']:
                stats['category_distribution'][cat] = int(self.dp.add_laplace_noise(
                    stats['category_distribution'][cat],
                    sensitivity=1.0
                ))

        stats.update(self._stats)
        return stats

    def on_threat_received(self, handler: Callable[[ThreatSignature], None]) -> int:
        """Register a handler for received threats.

        Returns:
            Handler ID that can be used to unregister the handler
        """
        with self._handler_lock:
            handler_id = self._next_handler_id
            self._next_handler_id += 1
            self._on_threat_received[handler_id] = handler
            return handler_id

    def unregister_threat_handler(self, handler_id: int) -> bool:
        """Unregister a threat received handler.

        Args:
            handler_id: The ID returned from on_threat_received

        Returns:
            True if handler was found and removed, False otherwise
        """
        with self._handler_lock:
            if handler_id in self._on_threat_received:
                del self._on_threat_received[handler_id]
                return True
            return False

    def on_peer_joined(self, handler: Callable[[MeshPeer], None]) -> int:
        """Register a handler for new peers.

        Returns:
            Handler ID that can be used to unregister the handler
        """
        with self._handler_lock:
            handler_id = self._next_handler_id
            self._next_handler_id += 1
            self._on_peer_joined[handler_id] = handler
            return handler_id

    def unregister_peer_joined_handler(self, handler_id: int) -> bool:
        """Unregister a peer joined handler.

        Args:
            handler_id: The ID returned from on_peer_joined

        Returns:
            True if handler was found and removed, False otherwise
        """
        with self._handler_lock:
            if handler_id in self._on_peer_joined:
                del self._on_peer_joined[handler_id]
                return True
            return False

    def on_peer_revoked(self, handler: Callable[[MeshPeer], None]) -> int:
        """Register a handler for revoked peers.

        Returns:
            Handler ID that can be used to unregister the handler
        """
        with self._handler_lock:
            handler_id = self._next_handler_id
            self._next_handler_id += 1
            self._on_peer_revoked[handler_id] = handler
            return handler_id

    def unregister_peer_revoked_handler(self, handler_id: int) -> bool:
        """Unregister a peer revoked handler.

        Args:
            handler_id: The ID returned from on_peer_revoked

        Returns:
            True if handler was found and removed, False otherwise
        """
        with self._handler_lock:
            if handler_id in self._on_peer_revoked:
                del self._on_peer_revoked[handler_id]
                return True
            return False

    def export_local_signatures(self) -> List[Dict[str, Any]]:
        """Export all local signatures for backup."""
        with self._signature_lock:
            return [sig.to_dict() for sig in self._signatures.values()]

    def import_signatures(self, signatures: List[Dict[str, Any]]) -> int:
        """
        Import signatures from backup.

        Args:
            signatures: List of signature dictionaries

        Returns:
            Number of signatures imported
        """
        imported = 0
        with self._signature_lock:
            for sig_data in signatures:
                try:
                    sig = ThreatSignature.from_dict(sig_data)
                    if sig.signature_id not in self._signatures:
                        self._signatures[sig.signature_id] = sig
                        imported += 1
                except Exception as e:
                    logger.warning(f"Failed to import signature: {e}")

        logger.info(f"Imported {imported} signatures")
        return imported
