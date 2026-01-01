"""
Agent Attestation System for BoundaryDaemon

Provides cryptographic identity verification and capability attestation for AI agents.
This module ensures agents can prove their identity and authorized capabilities
through cryptographic attestation chains.

SECURITY: This addresses "No Agent Identity Verification" by providing:
- Cryptographic agent identity certificates
- Attestation tokens with capability claims
- Chain of trust verification
- Action binding with cryptographic signatures
- Capability-based access control

Integration with BoundaryDaemon:
- Works with policy engine for capability enforcement
- Integrates with audit logging for attestation events
- Supports all boundary modes
"""

import hashlib
import hmac
import json
import os
import secrets
import time
import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class AttestationStatus(Enum):
    """Status of an attestation verification."""
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INVALID_SIGNATURE = "invalid_signature"
    INVALID_CHAIN = "invalid_chain"
    CAPABILITY_MISMATCH = "capability_mismatch"
    UNKNOWN_ISSUER = "unknown_issuer"
    NOT_YET_VALID = "not_yet_valid"


class AgentCapability(Enum):
    """Capabilities that can be attested for an agent."""
    # File operations
    FILE_READ = "file:read"
    FILE_WRITE = "file:write"
    FILE_EXECUTE = "file:execute"
    FILE_DELETE = "file:delete"

    # Network operations
    NETWORK_OUTBOUND = "network:outbound"
    NETWORK_INBOUND = "network:inbound"
    NETWORK_LOCAL = "network:local"

    # Process operations
    PROCESS_SPAWN = "process:spawn"
    PROCESS_KILL = "process:kill"
    PROCESS_INSPECT = "process:inspect"

    # System operations
    SYSTEM_CONFIG = "system:config"
    SYSTEM_AUDIT = "system:audit"
    SYSTEM_ADMIN = "system:admin"

    # AI/Agent operations
    AGENT_DELEGATE = "agent:delegate"
    AGENT_SPAWN = "agent:spawn"
    AGENT_SUPERVISE = "agent:supervise"

    # Tool operations
    TOOL_INVOKE = "tool:invoke"
    TOOL_CHAIN = "tool:chain"
    TOOL_UNSAFE = "tool:unsafe"

    # Data operations
    DATA_READ_PII = "data:read_pii"
    DATA_WRITE_PII = "data:write_pii"
    DATA_EXPORT = "data:export"


class TrustLevel(Enum):
    """Trust levels for agents."""
    UNTRUSTED = 0
    SANDBOXED = 1
    LIMITED = 2
    STANDARD = 3
    ELEVATED = 4
    PRIVILEGED = 5
    SYSTEM = 6


@dataclass
class AgentIdentity:
    """Cryptographic identity for an agent."""
    agent_id: str
    agent_name: str
    agent_type: str  # e.g., "llm", "tool", "orchestrator"
    public_key_hash: str
    issuer_id: str
    created_at: datetime
    expires_at: datetime
    trust_level: TrustLevel
    capabilities: Set[AgentCapability]
    constraints: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize identity to dictionary."""
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "public_key_hash": self.public_key_hash,
            "issuer_id": self.issuer_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "trust_level": self.trust_level.value,
            "capabilities": [c.value for c in self.capabilities],
            "constraints": self.constraints,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentIdentity":
        """Deserialize identity from dictionary."""
        return cls(
            agent_id=data["agent_id"],
            agent_name=data["agent_name"],
            agent_type=data["agent_type"],
            public_key_hash=data["public_key_hash"],
            issuer_id=data["issuer_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            trust_level=TrustLevel(data["trust_level"]),
            capabilities={AgentCapability(c) for c in data["capabilities"]},
            constraints=data.get("constraints", {}),
            metadata=data.get("metadata", {}),
        )


@dataclass
class AttestationToken:
    """Cryptographic attestation token."""
    token_id: str
    agent_id: str
    issuer_id: str
    issued_at: datetime
    expires_at: datetime
    capabilities: Set[AgentCapability]
    constraints: Dict[str, Any]
    nonce: str
    signature: str
    parent_token_id: Optional[str] = None  # For delegation chains

    def to_dict(self) -> Dict[str, Any]:
        """Serialize token to dictionary."""
        return {
            "token_id": self.token_id,
            "agent_id": self.agent_id,
            "issuer_id": self.issuer_id,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "capabilities": [c.value for c in self.capabilities],
            "constraints": self.constraints,
            "nonce": self.nonce,
            "signature": self.signature,
            "parent_token_id": self.parent_token_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttestationToken":
        """Deserialize token from dictionary."""
        return cls(
            token_id=data["token_id"],
            agent_id=data["agent_id"],
            issuer_id=data["issuer_id"],
            issued_at=datetime.fromisoformat(data["issued_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            capabilities={AgentCapability(c) for c in data["capabilities"]},
            constraints=data.get("constraints", {}),
            nonce=data["nonce"],
            signature=data["signature"],
            parent_token_id=data.get("parent_token_id"),
        )


@dataclass
class AttestationResult:
    """Result of attestation verification."""
    status: AttestationStatus
    agent_identity: Optional[AgentIdentity]
    token: Optional[AttestationToken]
    verified_capabilities: Set[AgentCapability]
    trust_level: TrustLevel
    chain_depth: int
    verification_time: datetime
    details: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """Check if attestation is valid."""
        return self.status == AttestationStatus.VALID


@dataclass
class ActionBinding:
    """Cryptographic binding of an action to an agent."""
    binding_id: str
    agent_id: str
    token_id: str
    action_type: str
    action_hash: str
    timestamp: datetime
    signature: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class AgentAttestationSystem:
    """
    Agent Attestation System for cryptographic identity and capability verification.

    Provides:
    - Agent identity registration and management
    - Attestation token issuance and verification
    - Capability-based access control
    - Delegation chain verification
    - Action binding with signatures
    """

    # Root attestation authority
    ROOT_ISSUER_ID = "boundary-daemon-root"

    # Default token validity
    DEFAULT_TOKEN_VALIDITY = timedelta(hours=1)
    MAX_TOKEN_VALIDITY = timedelta(days=7)

    # Maximum delegation chain depth
    MAX_CHAIN_DEPTH = 5

    # Capability inheritance rules (what capabilities can delegate what)
    DELEGATION_RULES: Dict[AgentCapability, Set[AgentCapability]] = {
        AgentCapability.AGENT_DELEGATE: {
            AgentCapability.FILE_READ,
            AgentCapability.NETWORK_LOCAL,
            AgentCapability.TOOL_INVOKE,
        },
        AgentCapability.AGENT_SUPERVISE: {
            AgentCapability.FILE_READ,
            AgentCapability.FILE_WRITE,
            AgentCapability.NETWORK_OUTBOUND,
            AgentCapability.NETWORK_LOCAL,
            AgentCapability.TOOL_INVOKE,
            AgentCapability.TOOL_CHAIN,
            AgentCapability.AGENT_DELEGATE,
        },
        AgentCapability.SYSTEM_ADMIN: {
            cap for cap in AgentCapability  # All capabilities
        },
    }

    def __init__(
        self,
        signing_key: Optional[bytes] = None,
        storage_path: Optional[Path] = None,
        mode: str = "RESTRICTED",
    ):
        """
        Initialize the attestation system.

        Args:
            signing_key: HMAC signing key (generated if not provided)
            storage_path: Path for persistent storage
            mode: BoundaryDaemon mode
        """
        self._signing_key = signing_key or secrets.token_bytes(32)
        self._storage_path = storage_path
        self._mode = mode

        # In-memory registries
        self._identities: Dict[str, AgentIdentity] = {}
        self._tokens: Dict[str, AttestationToken] = {}
        self._revoked_tokens: Set[str] = set()
        self._action_bindings: Dict[str, ActionBinding] = {}

        # Trust anchors (issuers we trust)
        self._trust_anchors: Set[str] = {self.ROOT_ISSUER_ID}

        # Mode-based capability restrictions
        self._mode_restrictions = self._get_mode_restrictions()

        # Load persisted state
        if storage_path:
            self._load_state()

    def _get_mode_restrictions(self) -> Dict[str, Set[AgentCapability]]:
        """Get capability restrictions based on mode."""
        return {
            "OPEN": set(),  # No restrictions
            "RESTRICTED": {
                AgentCapability.SYSTEM_ADMIN,
                AgentCapability.TOOL_UNSAFE,
                AgentCapability.DATA_EXPORT,
            },
            "TRUSTED": {
                AgentCapability.SYSTEM_ADMIN,
                AgentCapability.TOOL_UNSAFE,
                AgentCapability.DATA_EXPORT,
                AgentCapability.NETWORK_INBOUND,
            },
            "AIRGAP": {
                AgentCapability.NETWORK_OUTBOUND,
                AgentCapability.NETWORK_INBOUND,
                AgentCapability.DATA_EXPORT,
                AgentCapability.SYSTEM_ADMIN,
                AgentCapability.TOOL_UNSAFE,
            },
            "COLDROOM": {
                AgentCapability.NETWORK_OUTBOUND,
                AgentCapability.NETWORK_INBOUND,
                AgentCapability.DATA_EXPORT,
                AgentCapability.SYSTEM_ADMIN,
                AgentCapability.TOOL_UNSAFE,
                AgentCapability.AGENT_SPAWN,
                AgentCapability.PROCESS_SPAWN,
            },
            "LOCKDOWN": {
                cap for cap in AgentCapability  # All capabilities restricted
            },
        }

    def register_agent(
        self,
        agent_name: str,
        agent_type: str,
        capabilities: Set[AgentCapability],
        trust_level: TrustLevel = TrustLevel.STANDARD,
        validity: timedelta = timedelta(days=30),
        constraints: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentIdentity:
        """
        Register a new agent and issue identity.

        Args:
            agent_name: Human-readable agent name
            agent_type: Type of agent (llm, tool, orchestrator)
            capabilities: Set of capabilities to grant
            trust_level: Trust level for the agent
            validity: How long the identity is valid
            constraints: Additional constraints
            metadata: Additional metadata

        Returns:
            AgentIdentity for the registered agent
        """
        # Generate unique agent ID
        agent_id = f"agent_{secrets.token_hex(16)}"

        # Generate public key hash (simulated - would use actual PKI)
        public_key_hash = hashlib.sha256(
            f"{agent_id}:{agent_name}:{secrets.token_hex(32)}".encode()
        ).hexdigest()

        # Filter capabilities based on mode restrictions
        restricted = self._mode_restrictions.get(self._mode, set())
        allowed_capabilities = capabilities - restricted

        if capabilities != allowed_capabilities:
            logger.warning(
                f"Some capabilities restricted by mode {self._mode}: "
                f"{capabilities - allowed_capabilities}"
            )

        now = datetime.utcnow()
        identity = AgentIdentity(
            agent_id=agent_id,
            agent_name=agent_name,
            agent_type=agent_type,
            public_key_hash=public_key_hash,
            issuer_id=self.ROOT_ISSUER_ID,
            created_at=now,
            expires_at=now + validity,
            trust_level=trust_level,
            capabilities=allowed_capabilities,
            constraints=constraints or {},
            metadata=metadata or {},
        )

        self._identities[agent_id] = identity
        self._persist_state()

        logger.info(f"Registered agent: {agent_name} ({agent_id}) with {len(allowed_capabilities)} capabilities")

        return identity

    def issue_token(
        self,
        agent_id: str,
        capabilities: Optional[Set[AgentCapability]] = None,
        validity: Optional[timedelta] = None,
        constraints: Optional[Dict[str, Any]] = None,
        parent_token_id: Optional[str] = None,
    ) -> Optional[AttestationToken]:
        """
        Issue an attestation token for an agent.

        Args:
            agent_id: Agent to issue token for
            capabilities: Subset of agent's capabilities (defaults to all)
            validity: Token validity period
            constraints: Additional runtime constraints
            parent_token_id: Parent token for delegation chains

        Returns:
            AttestationToken or None if agent not found
        """
        identity = self._identities.get(agent_id)
        if not identity:
            logger.error(f"Agent not found: {agent_id}")
            return None

        # Check identity validity
        now = datetime.utcnow()
        if now > identity.expires_at:
            logger.error(f"Agent identity expired: {agent_id}")
            return None

        # Determine capabilities
        if capabilities:
            # Can only issue subset of agent's capabilities
            token_capabilities = capabilities & identity.capabilities
        else:
            token_capabilities = identity.capabilities

        # Validate delegation chain
        if parent_token_id:
            parent_token = self._tokens.get(parent_token_id)
            if not parent_token:
                logger.error(f"Parent token not found: {parent_token_id}")
                return None

            # Check chain depth
            chain_depth = self._get_chain_depth(parent_token_id)
            if chain_depth >= self.MAX_CHAIN_DEPTH:
                logger.error(f"Maximum delegation chain depth exceeded: {chain_depth}")
                return None

            # Delegated capabilities must be subset of parent's delegatable capabilities
            parent_identity = self._identities.get(parent_token.agent_id)
            if parent_identity:
                delegatable = self._get_delegatable_capabilities(parent_identity)
                token_capabilities = token_capabilities & delegatable

        # Apply mode restrictions
        restricted = self._mode_restrictions.get(self._mode, set())
        token_capabilities = token_capabilities - restricted

        # Determine validity
        if validity:
            token_validity = min(validity, self.MAX_TOKEN_VALIDITY)
        else:
            token_validity = self.DEFAULT_TOKEN_VALIDITY

        # Generate token
        token_id = f"token_{secrets.token_hex(16)}"
        nonce = secrets.token_hex(16)

        token_data = {
            "token_id": token_id,
            "agent_id": agent_id,
            "issuer_id": self.ROOT_ISSUER_ID,
            "issued_at": now.isoformat(),
            "expires_at": (now + token_validity).isoformat(),
            "capabilities": sorted([c.value for c in token_capabilities]),
            "constraints": constraints or {},
            "nonce": nonce,
            "parent_token_id": parent_token_id,
        }

        # Sign token
        signature = self._sign_data(token_data)

        token = AttestationToken(
            token_id=token_id,
            agent_id=agent_id,
            issuer_id=self.ROOT_ISSUER_ID,
            issued_at=now,
            expires_at=now + token_validity,
            capabilities=token_capabilities,
            constraints=constraints or {},
            nonce=nonce,
            signature=signature,
            parent_token_id=parent_token_id,
        )

        self._tokens[token_id] = token
        self._persist_state()

        logger.info(f"Issued token {token_id} for agent {agent_id} with {len(token_capabilities)} capabilities")

        return token

    def verify_token(
        self,
        token: Union[AttestationToken, Dict[str, Any], str],
        required_capabilities: Optional[Set[AgentCapability]] = None,
    ) -> AttestationResult:
        """
        Verify an attestation token.

        Args:
            token: Token to verify (object, dict, or token_id)
            required_capabilities: Capabilities that must be present

        Returns:
            AttestationResult with verification details
        """
        now = datetime.utcnow()

        # Resolve token
        if isinstance(token, str):
            token_obj = self._tokens.get(token)
            if not token_obj:
                return AttestationResult(
                    status=AttestationStatus.INVALID_SIGNATURE,
                    agent_identity=None,
                    token=None,
                    verified_capabilities=set(),
                    trust_level=TrustLevel.UNTRUSTED,
                    chain_depth=0,
                    verification_time=now,
                    details={"error": "Token not found"},
                )
        elif isinstance(token, dict):
            token_obj = AttestationToken.from_dict(token)
        else:
            token_obj = token

        # Check revocation
        if token_obj.token_id in self._revoked_tokens:
            return AttestationResult(
                status=AttestationStatus.REVOKED,
                agent_identity=None,
                token=token_obj,
                verified_capabilities=set(),
                trust_level=TrustLevel.UNTRUSTED,
                chain_depth=0,
                verification_time=now,
                details={"error": "Token has been revoked"},
            )

        # Check expiration
        if now > token_obj.expires_at:
            return AttestationResult(
                status=AttestationStatus.EXPIRED,
                agent_identity=None,
                token=token_obj,
                verified_capabilities=set(),
                trust_level=TrustLevel.UNTRUSTED,
                chain_depth=0,
                verification_time=now,
                details={"error": "Token has expired"},
            )

        # Check not-before
        if now < token_obj.issued_at:
            return AttestationResult(
                status=AttestationStatus.NOT_YET_VALID,
                agent_identity=None,
                token=token_obj,
                verified_capabilities=set(),
                trust_level=TrustLevel.UNTRUSTED,
                chain_depth=0,
                verification_time=now,
                details={"error": "Token not yet valid"},
            )

        # Verify signature
        token_data = {
            "token_id": token_obj.token_id,
            "agent_id": token_obj.agent_id,
            "issuer_id": token_obj.issuer_id,
            "issued_at": token_obj.issued_at.isoformat(),
            "expires_at": token_obj.expires_at.isoformat(),
            "capabilities": sorted([c.value for c in token_obj.capabilities]),
            "constraints": token_obj.constraints,
            "nonce": token_obj.nonce,
            "parent_token_id": token_obj.parent_token_id,
        }

        if not self._verify_signature(token_data, token_obj.signature):
            return AttestationResult(
                status=AttestationStatus.INVALID_SIGNATURE,
                agent_identity=None,
                token=token_obj,
                verified_capabilities=set(),
                trust_level=TrustLevel.UNTRUSTED,
                chain_depth=0,
                verification_time=now,
                details={"error": "Invalid token signature"},
            )

        # Verify issuer
        if token_obj.issuer_id not in self._trust_anchors:
            return AttestationResult(
                status=AttestationStatus.UNKNOWN_ISSUER,
                agent_identity=None,
                token=token_obj,
                verified_capabilities=set(),
                trust_level=TrustLevel.UNTRUSTED,
                chain_depth=0,
                verification_time=now,
                details={"error": f"Unknown issuer: {token_obj.issuer_id}"},
            )

        # Get agent identity
        identity = self._identities.get(token_obj.agent_id)
        if not identity:
            return AttestationResult(
                status=AttestationStatus.INVALID_CHAIN,
                agent_identity=None,
                token=token_obj,
                verified_capabilities=set(),
                trust_level=TrustLevel.UNTRUSTED,
                chain_depth=0,
                verification_time=now,
                details={"error": "Agent identity not found"},
            )

        # Verify delegation chain
        chain_depth = 0
        warnings = []

        if token_obj.parent_token_id:
            chain_result = self._verify_chain(token_obj)
            if not chain_result[0]:
                return AttestationResult(
                    status=AttestationStatus.INVALID_CHAIN,
                    agent_identity=identity,
                    token=token_obj,
                    verified_capabilities=set(),
                    trust_level=TrustLevel.UNTRUSTED,
                    chain_depth=0,
                    verification_time=now,
                    details={"error": chain_result[1]},
                )
            chain_depth = chain_result[2]

        # Check required capabilities
        verified_capabilities = token_obj.capabilities
        if required_capabilities:
            missing = required_capabilities - verified_capabilities
            if missing:
                return AttestationResult(
                    status=AttestationStatus.CAPABILITY_MISMATCH,
                    agent_identity=identity,
                    token=token_obj,
                    verified_capabilities=verified_capabilities,
                    trust_level=identity.trust_level,
                    chain_depth=chain_depth,
                    verification_time=now,
                    details={"missing_capabilities": [c.value for c in missing]},
                )

        # Check mode restrictions on capabilities
        restricted = self._mode_restrictions.get(self._mode, set())
        restricted_in_token = verified_capabilities & restricted
        if restricted_in_token:
            warnings.append(
                f"Token contains mode-restricted capabilities: {[c.value for c in restricted_in_token]}"
            )
            verified_capabilities = verified_capabilities - restricted

        return AttestationResult(
            status=AttestationStatus.VALID,
            agent_identity=identity,
            token=token_obj,
            verified_capabilities=verified_capabilities,
            trust_level=identity.trust_level,
            chain_depth=chain_depth,
            verification_time=now,
            details={
                "token_id": token_obj.token_id,
                "agent_name": identity.agent_name,
                "chain_depth": chain_depth,
            },
            warnings=warnings,
        )

    def revoke_token(self, token_id: str, reason: str = "") -> bool:
        """Revoke an attestation token."""
        if token_id in self._tokens:
            self._revoked_tokens.add(token_id)
            self._persist_state()
            logger.info(f"Revoked token {token_id}: {reason}")
            return True
        return False

    def revoke_agent(self, agent_id: str, reason: str = "") -> int:
        """Revoke all tokens for an agent."""
        count = 0
        for token_id, token in self._tokens.items():
            if token.agent_id == agent_id and token_id not in self._revoked_tokens:
                self._revoked_tokens.add(token_id)
                count += 1

        if count > 0:
            self._persist_state()
            logger.info(f"Revoked {count} tokens for agent {agent_id}: {reason}")

        return count

    def bind_action(
        self,
        token: AttestationToken,
        action_type: str,
        action_data: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[ActionBinding]:
        """
        Bind an action to an agent with cryptographic signature.

        Args:
            token: Attestation token for the agent
            action_type: Type of action being performed
            action_data: Data describing the action
            metadata: Additional metadata

        Returns:
            ActionBinding or None if token invalid
        """
        # Verify token first
        result = self.verify_token(token)
        if not result.is_valid:
            logger.error(f"Cannot bind action: token invalid ({result.status.value})")
            return None

        # Create action hash
        action_json = json.dumps(action_data, sort_keys=True, default=str)
        action_hash = hashlib.sha256(action_json.encode()).hexdigest()

        now = datetime.utcnow()
        binding_id = f"binding_{secrets.token_hex(16)}"

        binding_data = {
            "binding_id": binding_id,
            "agent_id": token.agent_id,
            "token_id": token.token_id,
            "action_type": action_type,
            "action_hash": action_hash,
            "timestamp": now.isoformat(),
            "metadata": metadata or {},
        }

        signature = self._sign_data(binding_data)

        binding = ActionBinding(
            binding_id=binding_id,
            agent_id=token.agent_id,
            token_id=token.token_id,
            action_type=action_type,
            action_hash=action_hash,
            timestamp=now,
            signature=signature,
            metadata=metadata or {},
        )

        self._action_bindings[binding_id] = binding

        logger.debug(f"Bound action {action_type} to agent {token.agent_id}")

        return binding

    def verify_action_binding(
        self,
        binding: ActionBinding,
        action_data: Any,
    ) -> bool:
        """Verify an action binding is valid and matches the action data."""
        # Verify action hash
        action_json = json.dumps(action_data, sort_keys=True, default=str)
        action_hash = hashlib.sha256(action_json.encode()).hexdigest()

        if action_hash != binding.action_hash:
            logger.error("Action data does not match binding hash")
            return False

        # Verify signature
        binding_data = {
            "binding_id": binding.binding_id,
            "agent_id": binding.agent_id,
            "token_id": binding.token_id,
            "action_type": binding.action_type,
            "action_hash": binding.action_hash,
            "timestamp": binding.timestamp.isoformat(),
            "metadata": binding.metadata,
        }

        if not self._verify_signature(binding_data, binding.signature):
            logger.error("Invalid binding signature")
            return False

        # Verify token is still valid
        token = self._tokens.get(binding.token_id)
        if not token:
            logger.error("Binding references unknown token")
            return False

        result = self.verify_token(token)
        if not result.is_valid:
            logger.error(f"Binding token is no longer valid: {result.status.value}")
            return False

        return True

    def check_capability(
        self,
        token: Union[AttestationToken, str],
        capability: AgentCapability,
    ) -> bool:
        """Check if a token grants a specific capability."""
        result = self.verify_token(token, required_capabilities={capability})
        return result.is_valid

    def get_agent_identity(self, agent_id: str) -> Optional[AgentIdentity]:
        """Get an agent's identity."""
        return self._identities.get(agent_id)

    def list_agents(self, agent_type: Optional[str] = None) -> List[AgentIdentity]:
        """List all registered agents, optionally filtered by type."""
        agents = list(self._identities.values())
        if agent_type:
            agents = [a for a in agents if a.agent_type == agent_type]
        return agents

    def add_trust_anchor(self, issuer_id: str) -> None:
        """Add a trusted issuer."""
        self._trust_anchors.add(issuer_id)
        self._persist_state()

    def remove_trust_anchor(self, issuer_id: str) -> bool:
        """Remove a trusted issuer (cannot remove root)."""
        if issuer_id == self.ROOT_ISSUER_ID:
            logger.error("Cannot remove root trust anchor")
            return False

        if issuer_id in self._trust_anchors:
            self._trust_anchors.remove(issuer_id)
            self._persist_state()
            return True
        return False

    def set_mode(self, mode: str) -> None:
        """Update the operational mode."""
        self._mode = mode
        self._mode_restrictions = self._get_mode_restrictions()
        logger.info(f"Attestation system mode set to: {mode}")

    def _sign_data(self, data: Dict[str, Any]) -> str:
        """Sign data using HMAC-SHA256."""
        data_json = json.dumps(data, sort_keys=True, default=str)
        signature = hmac.new(
            self._signing_key,
            data_json.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature

    def _verify_signature(self, data: Dict[str, Any], signature: str) -> bool:
        """Verify HMAC-SHA256 signature."""
        expected = self._sign_data(data)
        return hmac.compare_digest(expected, signature)

    def _get_chain_depth(self, token_id: str) -> int:
        """Get the depth of a token's delegation chain."""
        depth = 0
        current_id = token_id

        while current_id:
            token = self._tokens.get(current_id)
            if not token:
                break
            current_id = token.parent_token_id
            depth += 1

            if depth > self.MAX_CHAIN_DEPTH + 1:
                # Prevent infinite loops
                break

        return depth

    def _verify_chain(self, token: AttestationToken) -> Tuple[bool, str, int]:
        """Verify the delegation chain of a token."""
        chain = []
        current = token

        while current.parent_token_id:
            parent = self._tokens.get(current.parent_token_id)
            if not parent:
                return (False, f"Parent token not found: {current.parent_token_id}", 0)

            if parent.token_id in self._revoked_tokens:
                return (False, f"Parent token revoked: {parent.token_id}", 0)

            if datetime.utcnow() > parent.expires_at:
                return (False, f"Parent token expired: {parent.token_id}", 0)

            # Verify capabilities are subset of parent
            if not current.capabilities.issubset(parent.capabilities):
                return (False, "Child capabilities exceed parent capabilities", 0)

            chain.append(parent)
            current = parent

            if len(chain) > self.MAX_CHAIN_DEPTH:
                return (False, "Maximum chain depth exceeded", 0)

        return (True, "", len(chain))

    def _get_delegatable_capabilities(
        self,
        identity: AgentIdentity,
    ) -> Set[AgentCapability]:
        """Get capabilities that can be delegated by an agent."""
        delegatable = set()

        for cap in identity.capabilities:
            if cap in self.DELEGATION_RULES:
                delegatable.update(self.DELEGATION_RULES[cap])

        # Can always delegate own capabilities if has AGENT_DELEGATE
        if AgentCapability.AGENT_DELEGATE in identity.capabilities:
            delegatable.update(identity.capabilities)

        return delegatable

    def _persist_state(self) -> None:
        """Persist state to storage."""
        if not self._storage_path:
            return

        try:
            state = {
                "identities": {
                    k: v.to_dict() for k, v in self._identities.items()
                },
                "tokens": {
                    k: v.to_dict() for k, v in self._tokens.items()
                },
                "revoked_tokens": list(self._revoked_tokens),
                "trust_anchors": list(self._trust_anchors),
            }

            state_path = self._storage_path / "attestation_state.json"
            state_path.parent.mkdir(parents=True, exist_ok=True)

            with open(state_path, 'w') as f:
                json.dump(state, f, indent=2, default=str)

        except Exception as e:
            logger.error(f"Failed to persist attestation state: {e}")

    def _load_state(self) -> None:
        """Load state from storage."""
        if not self._storage_path:
            return

        state_path = self._storage_path / "attestation_state.json"
        if not state_path.exists():
            return

        try:
            with open(state_path, 'r') as f:
                state = json.load(f)

            self._identities = {
                k: AgentIdentity.from_dict(v)
                for k, v in state.get("identities", {}).items()
            }
            self._tokens = {
                k: AttestationToken.from_dict(v)
                for k, v in state.get("tokens", {}).items()
            }
            self._revoked_tokens = set(state.get("revoked_tokens", []))
            self._trust_anchors = set(state.get("trust_anchors", [self.ROOT_ISSUER_ID]))

            logger.info(
                f"Loaded attestation state: {len(self._identities)} identities, "
                f"{len(self._tokens)} tokens"
            )

        except Exception as e:
            logger.error(f"Failed to load attestation state: {e}")


# Singleton instance
_attestation_system: Optional[AgentAttestationSystem] = None


def get_attestation_system() -> AgentAttestationSystem:
    """Get the global attestation system instance."""
    global _attestation_system
    if _attestation_system is None:
        _attestation_system = AgentAttestationSystem()
    return _attestation_system


def configure_attestation_system(
    signing_key: Optional[bytes] = None,
    storage_path: Optional[Path] = None,
    mode: str = "RESTRICTED",
) -> AgentAttestationSystem:
    """Configure and return the global attestation system."""
    global _attestation_system
    _attestation_system = AgentAttestationSystem(
        signing_key=signing_key,
        storage_path=storage_path,
        mode=mode,
    )
    return _attestation_system
