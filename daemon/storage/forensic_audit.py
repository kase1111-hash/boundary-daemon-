"""
Forensic Audit Enhancements - Cryptographic proofs for tamper-evident logging.

Features:
- Merkle Tree Proofs: Compact proofs for any event range with O(log n) verification
- Cross-Node Log Anchoring: Cluster nodes periodically anchor hashes to each other
- Log Witness Protocol: External parties countersign log hashes for non-repudiation
- Selective Disclosure Proofs: Prove specific events without revealing others

SECURITY: All proofs are cryptographically verifiable without the private key.
Proofs can be exported and verified offline or by external auditors.
"""

import os
import json
import time
import hashlib
import threading
from typing import Optional, Dict, List, Any, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime

# Cryptographic imports
try:
    import nacl.signing
    import nacl.encoding
    import nacl.hash
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False

from ..event_logger import EventLogger, BoundaryEvent, EventType


# =============================================================================
# MERKLE TREE IMPLEMENTATION
# =============================================================================

def sha256_hash(data: bytes) -> bytes:
    """Compute SHA-256 hash of data."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash and return as hex string."""
    return hashlib.sha256(data).hexdigest()


@dataclass
class MerkleNode:
    """A node in the Merkle tree."""
    hash: bytes
    left: Optional['MerkleNode'] = None
    right: Optional['MerkleNode'] = None
    index: Optional[int] = None  # Leaf index (only for leaf nodes)

    def hex_hash(self) -> str:
        """Get hash as hex string."""
        return self.hash.hex()


@dataclass
class MerkleProof:
    """
    Proof of inclusion for a specific leaf in the Merkle tree.

    The proof consists of sibling hashes along the path from leaf to root.
    Verification is O(log n) - only need to recompute hashes along the path.
    """
    leaf_index: int
    leaf_hash: str  # Hash of the leaf data
    proof_hashes: List[Tuple[str, str]]  # [(hash, 'L'|'R'), ...] - siblings with position
    root_hash: str
    tree_size: int
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'leaf_index': self.leaf_index,
            'leaf_hash': self.leaf_hash,
            'proof_hashes': self.proof_hashes,
            'root_hash': self.root_hash,
            'tree_size': self.tree_size,
            'timestamp': self.timestamp
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MerkleProof':
        """Create from dictionary."""
        return cls(
            leaf_index=data['leaf_index'],
            leaf_hash=data['leaf_hash'],
            proof_hashes=data['proof_hashes'],
            root_hash=data['root_hash'],
            tree_size=data['tree_size'],
            timestamp=data.get('timestamp', '')
        )


@dataclass
class RangeProof:
    """
    Proof of inclusion for a range of events.

    Proves events [start_index, end_index] are included in the tree.
    """
    start_index: int
    end_index: int
    event_hashes: List[str]  # Hashes of events in range
    proof_hashes: List[Tuple[str, int]]  # Sibling hashes needed for verification
    root_hash: str
    tree_size: int
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'start_index': self.start_index,
            'end_index': self.end_index,
            'event_hashes': self.event_hashes,
            'proof_hashes': self.proof_hashes,
            'root_hash': self.root_hash,
            'tree_size': self.tree_size,
            'timestamp': self.timestamp
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class MerkleTree:
    """
    Merkle tree for efficient proof generation and verification.

    Properties:
    - Leaf nodes are hashes of individual events
    - Internal nodes are hash(left_child || right_child)
    - Root hash commits to entire event sequence
    - Inclusion proofs are O(log n) in size and verification time
    """

    def __init__(self, leaves: Optional[List[bytes]] = None):
        """
        Initialize Merkle tree.

        Args:
            leaves: Optional list of leaf data (will be hashed)
        """
        self._leaves: List[bytes] = []
        self._leaf_hashes: List[bytes] = []
        self._root: Optional[MerkleNode] = None
        self._levels: List[List[MerkleNode]] = []

        if leaves:
            for leaf in leaves:
                self.add_leaf(leaf)
            self.build()

    def add_leaf(self, data: bytes):
        """Add a leaf to the tree (must call build() after adding all leaves)."""
        self._leaves.append(data)
        self._leaf_hashes.append(sha256_hash(data))

    def add_event(self, event: BoundaryEvent):
        """Add an event as a leaf."""
        self.add_leaf(event.to_json().encode())

    def build(self):
        """Build the Merkle tree from added leaves."""
        if not self._leaf_hashes:
            self._root = None
            self._levels = []
            return

        # Create leaf nodes
        leaf_nodes = [
            MerkleNode(hash=h, index=i)
            for i, h in enumerate(self._leaf_hashes)
        ]

        self._levels = [leaf_nodes]

        # Build tree bottom-up
        current_level = leaf_nodes
        while len(current_level) > 1:
            next_level = []

            # Process pairs
            for i in range(0, len(current_level), 2):
                left = current_level[i]

                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                    combined = left.hash + right.hash
                else:
                    # Odd number of nodes - duplicate the last one
                    right = left
                    combined = left.hash + left.hash

                parent_hash = sha256_hash(combined)
                parent = MerkleNode(hash=parent_hash, left=left, right=right)
                next_level.append(parent)

            self._levels.append(next_level)
            current_level = next_level

        self._root = current_level[0] if current_level else None

    def get_root_hash(self) -> Optional[str]:
        """Get the root hash as hex string."""
        if self._root is None:
            return None
        return self._root.hex_hash()

    def get_leaf_count(self) -> int:
        """Get number of leaves in the tree."""
        return len(self._leaf_hashes)

    def get_proof(self, leaf_index: int) -> Optional[MerkleProof]:
        """
        Generate inclusion proof for a specific leaf.

        Args:
            leaf_index: Index of the leaf (0-based)

        Returns:
            MerkleProof or None if index is invalid
        """
        if not self._root or leaf_index < 0 or leaf_index >= len(self._leaf_hashes):
            return None

        proof_hashes = []
        index = leaf_index

        # Traverse from leaf to root, collecting siblings
        for level in self._levels[:-1]:  # Exclude root level
            sibling_index = index ^ 1  # XOR to get sibling index

            if sibling_index < len(level):
                sibling = level[sibling_index]
                # 'L' if sibling is on left, 'R' if on right
                position = 'L' if sibling_index < index else 'R'
                proof_hashes.append((sibling.hex_hash(), position))

            index //= 2

        return MerkleProof(
            leaf_index=leaf_index,
            leaf_hash=self._leaf_hashes[leaf_index].hex(),
            proof_hashes=proof_hashes,
            root_hash=self._root.hex_hash(),
            tree_size=len(self._leaf_hashes)
        )

    def get_range_proof(self, start: int, end: int) -> Optional[RangeProof]:
        """
        Generate proof for a range of leaves.

        Args:
            start: Start index (inclusive)
            end: End index (inclusive)

        Returns:
            RangeProof or None if range is invalid
        """
        if not self._root or start < 0 or end >= len(self._leaf_hashes) or start > end:
            return None

        event_hashes = [h.hex() for h in self._leaf_hashes[start:end + 1]]

        # Collect all sibling hashes needed for the range
        # This is more complex - we need siblings outside the range
        proof_hashes = []
        indices_to_prove = set(range(start, end + 1))

        for level_idx, level in enumerate(self._levels[:-1]):
            new_indices = set()
            for idx in indices_to_prove:
                sibling_idx = idx ^ 1
                parent_idx = idx // 2
                new_indices.add(parent_idx)

                if sibling_idx < len(level) and sibling_idx not in indices_to_prove:
                    proof_hashes.append((level[sibling_idx].hex_hash(), sibling_idx))

            indices_to_prove = new_indices

        return RangeProof(
            start_index=start,
            end_index=end,
            event_hashes=event_hashes,
            proof_hashes=proof_hashes,
            root_hash=self._root.hex_hash(),
            tree_size=len(self._leaf_hashes)
        )

    @staticmethod
    def verify_proof(proof: MerkleProof, leaf_data: Optional[bytes] = None) -> bool:
        """
        Verify an inclusion proof.

        Args:
            proof: The proof to verify
            leaf_data: Optional raw leaf data (if not provided, uses proof.leaf_hash)

        Returns:
            True if proof is valid
        """
        if leaf_data:
            current_hash = sha256_hash(leaf_data)
            if current_hash.hex() != proof.leaf_hash:
                return False
        else:
            current_hash = bytes.fromhex(proof.leaf_hash)

        # Recompute path to root
        for sibling_hash, position in proof.proof_hashes:
            sibling = bytes.fromhex(sibling_hash)

            if position == 'L':
                combined = sibling + current_hash
            else:
                combined = current_hash + sibling

            current_hash = sha256_hash(combined)

        return current_hash.hex() == proof.root_hash


# =============================================================================
# CROSS-NODE LOG ANCHORING
# =============================================================================

@dataclass
class LogAnchor:
    """
    An anchor point that commits to log state at a specific time.

    Anchors are exchanged between cluster nodes to create a distributed
    commitment that makes tampering detectable across nodes.
    """
    anchor_id: str
    node_id: str
    timestamp: str
    event_count: int
    merkle_root: str
    chain_hash: str  # Last hash chain value
    previous_anchor_id: Optional[str] = None
    signature: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'anchor_id': self.anchor_id,
            'node_id': self.node_id,
            'timestamp': self.timestamp,
            'event_count': self.event_count,
            'merkle_root': self.merkle_root,
            'chain_hash': self.chain_hash,
            'previous_anchor_id': self.previous_anchor_id,
            'signature': self.signature
        }

    def compute_hash(self) -> str:
        """Compute hash of anchor data (excluding signature)."""
        data = {
            'anchor_id': self.anchor_id,
            'node_id': self.node_id,
            'timestamp': self.timestamp,
            'event_count': self.event_count,
            'merkle_root': self.merkle_root,
            'chain_hash': self.chain_hash,
            'previous_anchor_id': self.previous_anchor_id
        }
        return sha256_hex(json.dumps(data, sort_keys=True).encode())


@dataclass
class CrossNodeAnchorRecord:
    """Record of an anchor received from another node."""
    anchor: LogAnchor
    received_at: str
    verified: bool = False
    verification_error: Optional[str] = None


class CrossNodeAnchoringManager:
    """
    Manages cross-node log anchoring for distributed tamper detection.

    Each node periodically:
    1. Generates an anchor (Merkle root + chain hash)
    2. Signs the anchor
    3. Broadcasts to other nodes
    4. Stores received anchors from other nodes

    If any node's log is tampered with, cross-node verification will detect it.
    """

    def __init__(self, node_id: str, signing_key: Optional[bytes] = None,
                 anchor_interval_seconds: int = 3600):
        """
        Initialize cross-node anchoring manager.

        Args:
            node_id: Unique identifier for this node
            signing_key: Ed25519 signing key (optional)
            anchor_interval_seconds: How often to create anchors
        """
        self.node_id = node_id
        self.anchor_interval = anchor_interval_seconds
        self._local_anchors: List[LogAnchor] = []
        self._remote_anchors: Dict[str, List[CrossNodeAnchorRecord]] = {}  # node_id -> anchors
        self._lock = threading.Lock()

        # Signing key
        if signing_key and NACL_AVAILABLE:
            self._signing_key = nacl.signing.SigningKey(signing_key)
            self._verify_key = self._signing_key.verify_key
        else:
            self._signing_key = None
            self._verify_key = None

        # Public keys of other nodes for verification
        self._node_public_keys: Dict[str, bytes] = {}

    def register_node_public_key(self, node_id: str, public_key: bytes):
        """Register a node's public key for signature verification."""
        self._node_public_keys[node_id] = public_key

    def create_anchor(self, merkle_tree: MerkleTree, chain_hash: str) -> LogAnchor:
        """
        Create a new anchor from current log state.

        Args:
            merkle_tree: Current Merkle tree of events
            chain_hash: Current hash chain value

        Returns:
            Signed anchor
        """
        with self._lock:
            anchor_id = sha256_hex(
                f"{self.node_id}:{time.time()}:{chain_hash}".encode()
            )[:16]

            previous_id = self._local_anchors[-1].anchor_id if self._local_anchors else None

            anchor = LogAnchor(
                anchor_id=anchor_id,
                node_id=self.node_id,
                timestamp=datetime.utcnow().isoformat() + "Z",
                event_count=merkle_tree.get_leaf_count(),
                merkle_root=merkle_tree.get_root_hash() or "",
                chain_hash=chain_hash,
                previous_anchor_id=previous_id
            )

            # Sign the anchor
            if self._signing_key:
                anchor_hash = anchor.compute_hash()
                signed = self._signing_key.sign(anchor_hash.encode())
                anchor.signature = signed.signature.hex()

            self._local_anchors.append(anchor)
            return anchor

    def receive_anchor(self, anchor: LogAnchor) -> Tuple[bool, str]:
        """
        Receive and verify an anchor from another node.

        Args:
            anchor: The anchor to receive

        Returns:
            (accepted, message)
        """
        with self._lock:
            # Verify signature if we have the node's public key
            verified = False
            verification_error = None

            if anchor.node_id in self._node_public_keys and anchor.signature:
                try:
                    if NACL_AVAILABLE:
                        verify_key = nacl.signing.VerifyKey(
                            self._node_public_keys[anchor.node_id]
                        )
                        anchor_hash = anchor.compute_hash()
                        verify_key.verify(
                            anchor_hash.encode(),
                            bytes.fromhex(anchor.signature)
                        )
                        verified = True
                except Exception as e:
                    verification_error = str(e)
            elif not anchor.signature:
                verification_error = "Anchor not signed"
            else:
                verification_error = "Unknown node public key"

            # Store the anchor
            record = CrossNodeAnchorRecord(
                anchor=anchor,
                received_at=datetime.utcnow().isoformat() + "Z",
                verified=verified,
                verification_error=verification_error
            )

            if anchor.node_id not in self._remote_anchors:
                self._remote_anchors[anchor.node_id] = []

            self._remote_anchors[anchor.node_id].append(record)

            if verified:
                return (True, f"Anchor accepted and verified from node {anchor.node_id}")
            else:
                return (True, f"Anchor accepted but not verified: {verification_error}")

    def verify_against_anchor(self, anchor: LogAnchor, merkle_tree: MerkleTree,
                             chain_hash: str) -> Tuple[bool, str]:
        """
        Verify current log state against a previously created anchor.

        Args:
            anchor: The anchor to verify against
            merkle_tree: Current Merkle tree
            chain_hash: Current chain hash

        Returns:
            (matches, message)
        """
        current_root = merkle_tree.get_root_hash() or ""

        # For verification, we need to verify up to the anchor's event count
        if merkle_tree.get_leaf_count() < anchor.event_count:
            return (False, f"Log has fewer events ({merkle_tree.get_leaf_count()}) than anchor ({anchor.event_count})")

        if anchor.merkle_root != current_root and merkle_tree.get_leaf_count() == anchor.event_count:
            return (False, f"Merkle root mismatch: anchor={anchor.merkle_root[:16]}..., current={current_root[:16]}...")

        return (True, "Log state matches anchor")

    def get_local_anchors(self, limit: int = 100) -> List[LogAnchor]:
        """Get recent local anchors."""
        with self._lock:
            return self._local_anchors[-limit:]

    def get_remote_anchors(self, node_id: Optional[str] = None) -> Dict[str, List[CrossNodeAnchorRecord]]:
        """Get anchors received from other nodes."""
        with self._lock:
            if node_id:
                return {node_id: self._remote_anchors.get(node_id, [])}
            return dict(self._remote_anchors)

    def export_anchors(self, output_path: str) -> bool:
        """Export all anchors to a file."""
        try:
            data = {
                'node_id': self.node_id,
                'exported_at': datetime.utcnow().isoformat() + "Z",
                'local_anchors': [a.to_dict() for a in self._local_anchors],
                'remote_anchors': {
                    nid: [{'anchor': r.anchor.to_dict(), 'received_at': r.received_at,
                           'verified': r.verified, 'error': r.verification_error}
                          for r in records]
                    for nid, records in self._remote_anchors.items()
                }
            }

            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)

            return True
        except Exception:
            return False


# =============================================================================
# LOG WITNESS PROTOCOL
# =============================================================================

@dataclass
class WitnessCommitment:
    """
    A commitment from a witness to the log state.

    Witnesses are external parties who periodically sign log hashes,
    providing independent verification of log integrity.
    """
    commitment_id: str
    witness_id: str
    witness_name: str
    timestamp: str
    merkle_root: str
    event_count: int
    chain_hash: str
    public_key: str
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'commitment_id': self.commitment_id,
            'witness_id': self.witness_id,
            'witness_name': self.witness_name,
            'timestamp': self.timestamp,
            'merkle_root': self.merkle_root,
            'event_count': self.event_count,
            'chain_hash': self.chain_hash,
            'public_key': self.public_key,
            'signature': self.signature
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class LogWitness:
    """
    A witness that can sign log commitments.

    Witnesses are external parties (auditors, security teams, automated services)
    who periodically receive log state and countersign it.
    """

    def __init__(self, witness_id: str, witness_name: str,
                 signing_key: Optional[bytes] = None):
        """
        Initialize a log witness.

        Args:
            witness_id: Unique identifier for this witness
            witness_name: Human-readable name
            signing_key: Ed25519 signing key (generates new if not provided)
        """
        self.witness_id = witness_id
        self.witness_name = witness_name

        if NACL_AVAILABLE:
            if signing_key:
                self._signing_key = nacl.signing.SigningKey(signing_key)
            else:
                self._signing_key = nacl.signing.SigningKey.generate()
            self._verify_key = self._signing_key.verify_key
            self.public_key = self._verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        else:
            self._signing_key = None
            self._verify_key = None
            self.public_key = ""

    def create_commitment(self, merkle_root: str, event_count: int,
                         chain_hash: str) -> Optional[WitnessCommitment]:
        """
        Create a signed commitment to log state.

        Args:
            merkle_root: Current Merkle root
            event_count: Number of events
            chain_hash: Current chain hash

        Returns:
            Signed commitment or None if signing unavailable
        """
        if not self._signing_key:
            return None

        commitment_id = sha256_hex(
            f"{self.witness_id}:{merkle_root}:{time.time()}".encode()
        )[:16]

        # Data to sign
        data = {
            'commitment_id': commitment_id,
            'witness_id': self.witness_id,
            'merkle_root': merkle_root,
            'event_count': event_count,
            'chain_hash': chain_hash,
            'timestamp': datetime.utcnow().isoformat() + "Z"
        }
        data_json = json.dumps(data, sort_keys=True)

        # Sign
        signed = self._signing_key.sign(data_json.encode())

        return WitnessCommitment(
            commitment_id=commitment_id,
            witness_id=self.witness_id,
            witness_name=self.witness_name,
            timestamp=data['timestamp'],
            merkle_root=merkle_root,
            event_count=event_count,
            chain_hash=chain_hash,
            public_key=self.public_key,
            signature=signed.signature.hex()
        )

    def get_public_key(self) -> str:
        """Get the public key for verification."""
        return self.public_key


class LogWitnessManager:
    """
    Manages witness commitments for a log.

    Collects commitments from multiple witnesses and provides verification.
    """

    def __init__(self, log_id: str):
        """
        Initialize witness manager.

        Args:
            log_id: Identifier for the log being witnessed
        """
        self.log_id = log_id
        self._commitments: List[WitnessCommitment] = []
        self._witness_public_keys: Dict[str, str] = {}  # witness_id -> public_key
        self._lock = threading.Lock()

    def register_witness(self, witness_id: str, public_key: str):
        """Register a witness's public key."""
        self._witness_public_keys[witness_id] = public_key

    def add_commitment(self, commitment: WitnessCommitment) -> Tuple[bool, str]:
        """
        Add and verify a witness commitment.

        Args:
            commitment: The commitment to add

        Returns:
            (valid, message)
        """
        with self._lock:
            # Verify signature
            if commitment.witness_id in self._witness_public_keys:
                expected_key = self._witness_public_keys[commitment.witness_id]
                if commitment.public_key != expected_key:
                    return (False, "Public key mismatch")

            if NACL_AVAILABLE:
                try:
                    verify_key = nacl.signing.VerifyKey(
                        commitment.public_key,
                        encoder=nacl.encoding.HexEncoder
                    )

                    # Reconstruct signed data
                    data = {
                        'commitment_id': commitment.commitment_id,
                        'witness_id': commitment.witness_id,
                        'merkle_root': commitment.merkle_root,
                        'event_count': commitment.event_count,
                        'chain_hash': commitment.chain_hash,
                        'timestamp': commitment.timestamp
                    }
                    data_json = json.dumps(data, sort_keys=True)

                    verify_key.verify(
                        data_json.encode(),
                        bytes.fromhex(commitment.signature)
                    )
                except Exception as e:
                    return (False, f"Signature verification failed: {e}")

            self._commitments.append(commitment)
            return (True, f"Commitment accepted from witness {commitment.witness_name}")

    def get_commitments(self, witness_id: Optional[str] = None,
                       limit: int = 100) -> List[WitnessCommitment]:
        """Get witness commitments."""
        with self._lock:
            if witness_id:
                return [c for c in self._commitments if c.witness_id == witness_id][-limit:]
            return self._commitments[-limit:]

    def verify_log_at_commitment(self, commitment: WitnessCommitment,
                                merkle_tree: MerkleTree) -> Tuple[bool, str]:
        """
        Verify that log matches a witness commitment.

        Args:
            commitment: The commitment to verify against
            merkle_tree: Current Merkle tree

        Returns:
            (matches, message)
        """
        current_root = merkle_tree.get_root_hash() or ""

        if merkle_tree.get_leaf_count() < commitment.event_count:
            return (False, f"Log has fewer events than commitment")

        # If same event count, roots must match
        if merkle_tree.get_leaf_count() == commitment.event_count:
            if current_root != commitment.merkle_root:
                return (False, "Merkle root mismatch - log may have been tampered")

        return (True, f"Log verified against commitment from {commitment.witness_name}")

    def export_commitments(self, output_path: str) -> bool:
        """Export all commitments to a file."""
        try:
            data = {
                'log_id': self.log_id,
                'exported_at': datetime.utcnow().isoformat() + "Z",
                'commitment_count': len(self._commitments),
                'witnesses': list(self._witness_public_keys.keys()),
                'commitments': [c.to_dict() for c in self._commitments]
            }

            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)

            return True
        except Exception:
            return False


# =============================================================================
# SELECTIVE DISCLOSURE PROOFS
# =============================================================================

@dataclass
class SelectiveDisclosureProof:
    """
    Proof that specific events exist without revealing other events.

    Uses Merkle proofs to prove inclusion of selected events while
    keeping other events private.
    """
    proof_id: str
    timestamp: str
    disclosed_events: List[Dict[str, Any]]  # The actual events being disclosed
    merkle_proofs: List[MerkleProof]  # Inclusion proofs for each event
    root_hash: str
    total_events: int
    redacted_count: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'proof_id': self.proof_id,
            'timestamp': self.timestamp,
            'disclosed_events': self.disclosed_events,
            'merkle_proofs': [p.to_dict() for p in self.merkle_proofs],
            'root_hash': self.root_hash,
            'total_events': self.total_events,
            'redacted_count': self.redacted_count,
            'metadata': self.metadata
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class SelectiveDisclosureManager:
    """
    Manages selective disclosure of log events.

    Allows proving specific events exist without revealing the full log.
    Useful for audits, legal discovery, and privacy-preserving verification.
    """

    def __init__(self, event_logger: EventLogger):
        """
        Initialize selective disclosure manager.

        Args:
            event_logger: The event logger to work with
        """
        self.event_logger = event_logger
        self._merkle_tree: Optional[MerkleTree] = None
        self._events: List[BoundaryEvent] = []
        self._lock = threading.Lock()

    def build_tree(self) -> bool:
        """
        Build Merkle tree from current log.

        Returns:
            True if successful
        """
        with self._lock:
            try:
                self._events = []
                self._merkle_tree = MerkleTree()

                # Read all events
                if not os.path.exists(self.event_logger.log_file_path):
                    return True

                with open(self.event_logger.log_file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue

                        event_data = json.loads(line)
                        event = BoundaryEvent(
                            event_id=event_data['event_id'],
                            timestamp=event_data['timestamp'],
                            event_type=EventType(event_data['event_type']),
                            details=event_data['details'],
                            metadata=event_data.get('metadata', {}),
                            hash_chain=event_data['hash_chain']
                        )
                        self._events.append(event)
                        self._merkle_tree.add_event(event)

                self._merkle_tree.build()
                return True

            except Exception:
                return False

    def create_disclosure_proof(
        self,
        event_indices: Optional[List[int]] = None,
        event_filter: Optional[Callable[[BoundaryEvent], bool]] = None,
        event_type: Optional[EventType] = None,
        time_range: Optional[Tuple[str, str]] = None
    ) -> Optional[SelectiveDisclosureProof]:
        """
        Create a selective disclosure proof for specific events.

        Args:
            event_indices: Specific event indices to disclose
            event_filter: Custom filter function
            event_type: Filter by event type
            time_range: Filter by time range (start, end) in ISO format

        Returns:
            SelectiveDisclosureProof or None
        """
        with self._lock:
            if not self._merkle_tree or not self._events:
                return None

            # Determine which events to disclose
            indices_to_disclose = []

            if event_indices is not None:
                indices_to_disclose = [i for i in event_indices if 0 <= i < len(self._events)]

            else:
                for i, event in enumerate(self._events):
                    include = True

                    if event_filter and not event_filter(event):
                        include = False

                    if event_type and event.event_type != event_type:
                        include = False

                    if time_range:
                        start, end = time_range
                        if event.timestamp < start or event.timestamp > end:
                            include = False

                    if include:
                        indices_to_disclose.append(i)

            if not indices_to_disclose:
                return None

            # Generate proofs
            disclosed_events = []
            merkle_proofs = []

            for idx in indices_to_disclose:
                event = self._events[idx]
                proof = self._merkle_tree.get_proof(idx)

                if proof:
                    disclosed_events.append(event.to_dict())
                    merkle_proofs.append(proof)

            proof_id = sha256_hex(
                f"{indices_to_disclose}:{time.time()}".encode()
            )[:16]

            return SelectiveDisclosureProof(
                proof_id=proof_id,
                timestamp=datetime.utcnow().isoformat() + "Z",
                disclosed_events=disclosed_events,
                merkle_proofs=merkle_proofs,
                root_hash=self._merkle_tree.get_root_hash() or "",
                total_events=len(self._events),
                redacted_count=len(self._events) - len(indices_to_disclose),
                metadata={
                    'filter_type': 'indices' if event_indices else 'criteria',
                    'event_type': event_type.value if event_type else None,
                    'time_range': time_range
                }
            )

    def verify_disclosure_proof(self, proof: SelectiveDisclosureProof) -> Tuple[bool, str]:
        """
        Verify a selective disclosure proof.

        Args:
            proof: The proof to verify

        Returns:
            (valid, message)
        """
        if len(proof.disclosed_events) != len(proof.merkle_proofs):
            return (False, "Event count doesn't match proof count")

        for i, (event_dict, merkle_proof) in enumerate(zip(proof.disclosed_events, proof.merkle_proofs)):
            # Reconstruct event
            event = BoundaryEvent(
                event_id=event_dict['event_id'],
                timestamp=event_dict['timestamp'],
                event_type=EventType(event_dict['event_type']),
                details=event_dict['details'],
                metadata=event_dict.get('metadata', {}),
                hash_chain=event_dict['hash_chain']
            )

            # Verify Merkle proof
            event_data = event.to_json().encode()
            if not MerkleTree.verify_proof(merkle_proof, event_data):
                return (False, f"Merkle proof verification failed for event {i}")

            # Verify root hash matches
            if merkle_proof.root_hash != proof.root_hash:
                return (False, f"Root hash mismatch for event {i}")

        return (True, f"All {len(proof.disclosed_events)} disclosed events verified")

    def get_merkle_root(self) -> Optional[str]:
        """Get current Merkle root."""
        if self._merkle_tree:
            return self._merkle_tree.get_root_hash()
        return None

    def export_proof(self, proof: SelectiveDisclosureProof, output_path: str) -> bool:
        """Export a proof to a file."""
        try:
            with open(output_path, 'w') as f:
                f.write(proof.to_json())
            return True
        except Exception:
            return False


# =============================================================================
# FORENSIC AUDIT MANAGER (UNIFIED)
# =============================================================================

class ForensicAuditManager:
    """
    Unified manager for all forensic audit capabilities.

    Combines:
    - Merkle tree proofs
    - Cross-node log anchoring
    - Log witness protocol
    - Selective disclosure proofs
    """

    def __init__(self, event_logger: EventLogger, node_id: str,
                 signing_key: Optional[bytes] = None):
        """
        Initialize forensic audit manager.

        Args:
            event_logger: The event logger to audit
            node_id: Unique node identifier
            signing_key: Ed25519 signing key (optional)
        """
        self.event_logger = event_logger
        self.node_id = node_id

        # Initialize components
        self.merkle_tree = MerkleTree()
        self.anchoring = CrossNodeAnchoringManager(node_id, signing_key)
        self.witness_manager = LogWitnessManager(node_id)
        self.selective_disclosure = SelectiveDisclosureManager(event_logger)

        self._lock = threading.Lock()
        self._last_rebuild = None

    def rebuild_merkle_tree(self) -> bool:
        """Rebuild Merkle tree from current log."""
        with self._lock:
            self.merkle_tree = MerkleTree()

            if not os.path.exists(self.event_logger.log_file_path):
                return True

            try:
                with open(self.event_logger.log_file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue

                        event_data = json.loads(line)
                        event = BoundaryEvent(
                            event_id=event_data['event_id'],
                            timestamp=event_data['timestamp'],
                            event_type=EventType(event_data['event_type']),
                            details=event_data['details'],
                            metadata=event_data.get('metadata', {}),
                            hash_chain=event_data['hash_chain']
                        )
                        self.merkle_tree.add_event(event)

                self.merkle_tree.build()
                self._last_rebuild = datetime.utcnow()

                # Also rebuild selective disclosure tree
                self.selective_disclosure.build_tree()

                return True

            except Exception:
                return False

    def get_event_proof(self, event_index: int) -> Optional[MerkleProof]:
        """Get Merkle proof for a specific event."""
        return self.merkle_tree.get_proof(event_index)

    def get_range_proof(self, start: int, end: int) -> Optional[RangeProof]:
        """Get proof for a range of events."""
        return self.merkle_tree.get_range_proof(start, end)

    def create_anchor(self) -> LogAnchor:
        """Create an anchor from current state."""
        chain_hash = self.event_logger.get_last_hash()
        return self.anchoring.create_anchor(self.merkle_tree, chain_hash)

    def request_witness_commitment(self, witness: LogWitness) -> Optional[WitnessCommitment]:
        """Request a commitment from a witness."""
        merkle_root = self.merkle_tree.get_root_hash() or ""
        event_count = self.merkle_tree.get_leaf_count()
        chain_hash = self.event_logger.get_last_hash()

        commitment = witness.create_commitment(merkle_root, event_count, chain_hash)
        if commitment:
            self.witness_manager.add_commitment(commitment)
        return commitment

    def create_selective_proof(self, **kwargs) -> Optional[SelectiveDisclosureProof]:
        """Create a selective disclosure proof."""
        return self.selective_disclosure.create_disclosure_proof(**kwargs)

    def verify_selective_proof(self, proof: SelectiveDisclosureProof) -> Tuple[bool, str]:
        """Verify a selective disclosure proof."""
        return self.selective_disclosure.verify_disclosure_proof(proof)

    def get_audit_summary(self) -> Dict[str, Any]:
        """Get a summary of audit state."""
        return {
            'node_id': self.node_id,
            'merkle_root': self.merkle_tree.get_root_hash(),
            'event_count': self.merkle_tree.get_leaf_count(),
            'chain_hash': self.event_logger.get_last_hash(),
            'last_rebuild': self._last_rebuild.isoformat() if self._last_rebuild else None,
            'local_anchors': len(self.anchoring.get_local_anchors()),
            'remote_anchors': sum(len(v) for v in self.anchoring.get_remote_anchors().values()),
            'witness_commitments': len(self.witness_manager.get_commitments())
        }

    def export_full_audit(self, output_dir: str) -> Tuple[bool, str]:
        """
        Export complete audit package.

        Creates:
        - merkle_tree.json: Current tree state
        - anchors.json: All anchors
        - commitments.json: Witness commitments
        - audit_summary.json: Summary
        """
        try:
            os.makedirs(output_dir, exist_ok=True)

            # Summary
            with open(os.path.join(output_dir, 'audit_summary.json'), 'w') as f:
                json.dump(self.get_audit_summary(), f, indent=2)

            # Anchors
            self.anchoring.export_anchors(os.path.join(output_dir, 'anchors.json'))

            # Commitments
            self.witness_manager.export_commitments(os.path.join(output_dir, 'commitments.json'))

            return (True, f"Audit package exported to {output_dir}")

        except Exception as e:
            return (False, str(e))


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Merkle tree
    'MerkleTree',
    'MerkleNode',
    'MerkleProof',
    'RangeProof',

    # Cross-node anchoring
    'LogAnchor',
    'CrossNodeAnchorRecord',
    'CrossNodeAnchoringManager',

    # Log witness protocol
    'WitnessCommitment',
    'LogWitness',
    'LogWitnessManager',

    # Selective disclosure
    'SelectiveDisclosureProof',
    'SelectiveDisclosureManager',

    # Unified manager
    'ForensicAuditManager',
]
