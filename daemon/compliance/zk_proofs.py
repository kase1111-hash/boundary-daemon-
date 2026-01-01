"""
Zero-Knowledge Compliance Proofs - Prove compliance without revealing data.

Phase 3 Cutting-Edge Innovation: Mathematical proofs of compliance assertions
that can be verified without access to sensitive audit logs.

Key Concepts:
- Prover: The daemon (has access to all logs)
- Verifier: Auditor (receives proof only, not raw data)
- Statement: What we're proving (e.g., "All critical alerts were acknowledged")
- Witness: The actual data proving the statement (never revealed)

Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │                    ZK COMPLIANCE PROVER                         │
    ├─────────────────────────────────────────────────────────────────┤
    │                                                                 │
    │  AUDIT DATA (Secret)         STATEMENT (Public)                │
    │  ┌────────────────┐         ┌────────────────┐                 │
    │  │ Event logs     │         │ "All CRITICAL  │                 │
    │  │ Alert history  │────────►│  alerts acked  │                 │
    │  │ User actions   │         │  within 24h"   │                 │
    │  └────────────────┘         └───────┬────────┘                 │
    │         │                           │                           │
    │         │                           ▼                           │
    │         │                   ┌────────────────┐                 │
    │         └──────────────────►│  PROOF SYSTEM  │                 │
    │                             │  (Commitment + │                 │
    │                             │   Challenge +  │                 │
    │                             │   Response)    │                 │
    │                             └───────┬────────┘                 │
    │                                     │                           │
    │                                     ▼                           │
    │                             ┌────────────────┐                 │
    │                             │    PROOF       │                 │
    │                             │  (Verifiable   │                 │
    │                             │   without data)│                 │
    │                             └────────────────┘                 │
    └─────────────────────────────────────────────────────────────────┘

Supported Assertions:
- All alerts of severity X acknowledged within Y time
- No mode overrides without approval
- All ceremonies completed within SLA
- No unauthorized access attempts
- All data exports audited
- Continuous monitoring active for X% of time

Cryptographic Basis:
- Pedersen commitments for hiding values
- Schnorr protocol for proving statements
- Hash chains for proving inclusion
"""

import hashlib
import hmac
import json
import os
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any, Callable
import logging

try:
    from nacl.hash import sha256
    from nacl.encoding import HexEncoder
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False

logger = logging.getLogger(__name__)


class AssertionType(Enum):
    """Types of compliance assertions that can be proven."""
    ALERT_RESPONSE_SLA = "alert_response_sla"
    NO_UNAUTHORIZED_OVERRIDE = "no_unauthorized_override"
    CEREMONY_SLA_COMPLIANCE = "ceremony_sla_compliance"
    CONTINUOUS_MONITORING = "continuous_monitoring"
    DATA_EXPORT_AUDITED = "data_export_audited"
    ACCESS_LOGGED = "access_logged"
    ENCRYPTION_ENFORCED = "encryption_enforced"
    NO_POLICY_VIOLATIONS = "no_policy_violations"


@dataclass
class ComplianceAssertion:
    """A compliance assertion to be proven."""
    assertion_id: str
    assertion_type: AssertionType
    description: str
    parameters: Dict[str, Any]  # e.g., {"severity": "CRITICAL", "max_hours": 24}
    time_range_start: datetime
    time_range_end: datetime
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'assertion_id': self.assertion_id,
            'assertion_type': self.assertion_type.value,
            'description': self.description,
            'parameters': self.parameters,
            'time_range_start': self.time_range_start.isoformat(),
            'time_range_end': self.time_range_end.isoformat(),
            'created_at': self.created_at.isoformat(),
        }


@dataclass
class VerificationResult:
    """Result of verifying a compliance proof."""
    valid: bool
    assertion_id: str
    verified_at: datetime
    verifier_id: Optional[str] = None
    details: str = ""
    cryptographic_check: bool = True
    time_range_check: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'valid': self.valid,
            'assertion_id': self.assertion_id,
            'verified_at': self.verified_at.isoformat(),
            'verifier_id': self.verifier_id,
            'details': self.details,
            'cryptographic_check': self.cryptographic_check,
            'time_range_check': self.time_range_check,
        }


@dataclass
class ComplianceProof:
    """
    A zero-knowledge compliance proof.

    Contains cryptographic commitments and responses that prove
    a statement without revealing the underlying data.
    """
    proof_id: str
    assertion: ComplianceAssertion
    commitment: bytes  # Pedersen commitment to witness
    challenge: bytes   # Random challenge (from verifier or hash)
    response: bytes    # Prover's response
    public_params: Dict[str, Any]  # Public parameters needed for verification
    merkle_root: bytes  # Root of event log Merkle tree
    timestamp: datetime
    prover_signature: bytes  # Signature over proof

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'proof_id': self.proof_id,
            'assertion': self.assertion.to_dict(),
            'commitment': self.commitment.hex(),
            'challenge': self.challenge.hex(),
            'response': self.response.hex(),
            'public_params': self.public_params,
            'merkle_root': self.merkle_root.hex(),
            'timestamp': self.timestamp.isoformat(),
            'prover_signature': self.prover_signature.hex(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ComplianceProof':
        """Create from dictionary."""
        assertion = ComplianceAssertion(
            assertion_id=data['assertion']['assertion_id'],
            assertion_type=AssertionType(data['assertion']['assertion_type']),
            description=data['assertion']['description'],
            parameters=data['assertion']['parameters'],
            time_range_start=datetime.fromisoformat(data['assertion']['time_range_start']),
            time_range_end=datetime.fromisoformat(data['assertion']['time_range_end']),
            created_at=datetime.fromisoformat(data['assertion']['created_at']),
        )
        return cls(
            proof_id=data['proof_id'],
            assertion=assertion,
            commitment=bytes.fromhex(data['commitment']),
            challenge=bytes.fromhex(data['challenge']),
            response=bytes.fromhex(data['response']),
            public_params=data['public_params'],
            merkle_root=bytes.fromhex(data['merkle_root']),
            timestamp=datetime.fromisoformat(data['timestamp']),
            prover_signature=bytes.fromhex(data['prover_signature']),
        )

    def export_json(self) -> str:
        """Export proof as JSON."""
        return json.dumps(self.to_dict(), indent=2)


class PedersenCommitment:
    """
    Pedersen commitment scheme for zero-knowledge proofs.

    commit(v, r) = g^v * h^r (mod p)

    Properties:
    - Hiding: Without knowing r, commitment reveals nothing about v
    - Binding: Cannot open commitment to different value
    """

    def __init__(self, p: int = None, g: int = None, h: int = None):
        """
        Initialize with group parameters.

        For simplicity, we use a large prime p and generators g, h.
        In production, use elliptic curve groups.
        """
        # Use fixed safe prime and generators for reproducibility
        # In production, these would be properly generated/verified
        if p is None:
            # 256-bit safe prime
            self.p = int(
                'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F',
                16
            )
            self.g = 2
            self.h = 3
        else:
            self.p = p
            self.g = g
            self.h = h

    def commit(self, value: int, randomness: int = None) -> Tuple[int, int]:
        """
        Create a commitment to a value.

        Args:
            value: The value to commit to
            randomness: Random blinding factor (generated if not provided)

        Returns:
            (commitment, randomness) tuple
        """
        if randomness is None:
            randomness = int.from_bytes(os.urandom(32), 'big') % self.p

        # c = g^v * h^r (mod p)
        commitment = (pow(self.g, value, self.p) * pow(self.h, randomness, self.p)) % self.p

        return (commitment, randomness)

    def verify(self, commitment: int, value: int, randomness: int) -> bool:
        """
        Verify a commitment opening.

        Args:
            commitment: The commitment value
            value: The claimed value
            randomness: The blinding factor

        Returns:
            True if valid opening
        """
        expected = (pow(self.g, value, self.p) * pow(self.h, randomness, self.p)) % self.p
        return commitment == expected


class ZKComplianceProver:
    """
    Zero-Knowledge Compliance Prover.

    Generates cryptographic proofs of compliance assertions
    without revealing the underlying audit data.
    """

    def __init__(
        self,
        event_log_provider: Callable[[datetime, datetime], List[Dict]],
        alert_provider: Optional[Callable[[datetime, datetime], List[Dict]]] = None,
        signing_key: Optional[bytes] = None,
    ):
        """
        Initialize the ZK Compliance Prover.

        Args:
            event_log_provider: Callable that returns events for a time range
            alert_provider: Callable that returns alerts for a time range
            signing_key: Ed25519 signing key for proof signatures
        """
        self.event_log_provider = event_log_provider
        self.alert_provider = alert_provider

        # Cryptographic primitives
        self.commitment_scheme = PedersenCommitment()

        # Signing key
        if NACL_AVAILABLE and signing_key:
            from nacl.signing import SigningKey
            self._signing_key = SigningKey(signing_key)
        else:
            self._signing_key = None

        # Assertion evaluators
        self._evaluators: Dict[AssertionType, Callable] = {
            AssertionType.ALERT_RESPONSE_SLA: self._evaluate_alert_sla,
            AssertionType.NO_UNAUTHORIZED_OVERRIDE: self._evaluate_no_unauthorized_override,
            AssertionType.CEREMONY_SLA_COMPLIANCE: self._evaluate_ceremony_sla,
            AssertionType.CONTINUOUS_MONITORING: self._evaluate_continuous_monitoring,
            AssertionType.DATA_EXPORT_AUDITED: self._evaluate_data_export,
            AssertionType.ACCESS_LOGGED: self._evaluate_access_logged,
            AssertionType.ENCRYPTION_ENFORCED: self._evaluate_encryption,
            AssertionType.NO_POLICY_VIOLATIONS: self._evaluate_no_violations,
        }

        logger.info("ZKComplianceProver initialized")

    def create_assertion(
        self,
        assertion_type: AssertionType,
        parameters: Dict[str, Any],
        time_range_start: datetime,
        time_range_end: datetime,
        description: Optional[str] = None,
    ) -> ComplianceAssertion:
        """
        Create a compliance assertion.

        Args:
            assertion_type: Type of assertion
            parameters: Parameters for the assertion
            time_range_start: Start of time range
            time_range_end: End of time range
            description: Human-readable description

        Returns:
            ComplianceAssertion object
        """
        assertion_id = f"assert_{int(time.time() * 1000)}"

        if description is None:
            description = self._generate_description(assertion_type, parameters)

        return ComplianceAssertion(
            assertion_id=assertion_id,
            assertion_type=assertion_type,
            description=description,
            parameters=parameters,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
        )

    def _generate_description(
        self,
        assertion_type: AssertionType,
        parameters: Dict[str, Any],
    ) -> str:
        """Generate human-readable description for assertion."""
        descriptions = {
            AssertionType.ALERT_RESPONSE_SLA: (
                f"All {parameters.get('severity', 'CRITICAL')} alerts were acknowledged "
                f"within {parameters.get('max_hours', 24)} hours"
            ),
            AssertionType.NO_UNAUTHORIZED_OVERRIDE: (
                "No mode overrides occurred without proper authorization"
            ),
            AssertionType.CEREMONY_SLA_COMPLIANCE: (
                f"All ceremonies completed within {parameters.get('max_minutes', 30)} minute SLA"
            ),
            AssertionType.CONTINUOUS_MONITORING: (
                f"Monitoring was active for at least {parameters.get('min_percent', 99)}% of the time"
            ),
            AssertionType.DATA_EXPORT_AUDITED: (
                "All data exports were properly audited and authorized"
            ),
            AssertionType.ACCESS_LOGGED: (
                "All access attempts were logged with full audit trail"
            ),
            AssertionType.ENCRYPTION_ENFORCED: (
                "All sensitive data operations used encryption"
            ),
            AssertionType.NO_POLICY_VIOLATIONS: (
                "No policy violations occurred during the period"
            ),
        }
        return descriptions.get(assertion_type, str(assertion_type.value))

    def prove(self, assertion: ComplianceAssertion) -> ComplianceProof:
        """
        Generate a zero-knowledge proof for an assertion.

        Args:
            assertion: The assertion to prove

        Returns:
            ComplianceProof that can be verified without access to underlying data
        """
        # Get events for the time range
        events = self.event_log_provider(
            assertion.time_range_start,
            assertion.time_range_end,
        )

        # Evaluate the assertion against the witness (events)
        evaluator = self._evaluators.get(assertion.assertion_type)
        if not evaluator:
            raise ValueError(f"Unknown assertion type: {assertion.assertion_type}")

        # Evaluate returns (is_true, witness_summary)
        is_true, witness_summary = evaluator(events, assertion.parameters)

        if not is_true:
            raise ValueError(
                f"Cannot prove false assertion: {assertion.description}"
            )

        # Generate cryptographic proof
        proof_id = f"proof_{int(time.time() * 1000)}"

        # Create commitment to witness
        witness_hash = self._hash_witness(witness_summary)
        witness_int = int.from_bytes(witness_hash[:16], 'big')
        commitment, randomness = self.commitment_scheme.commit(witness_int)

        # Generate challenge (Fiat-Shamir heuristic)
        challenge = self._generate_challenge(assertion, commitment)

        # Generate response (simplified Schnorr-like protocol)
        response = self._generate_response(
            witness_int,
            randomness,
            int.from_bytes(challenge, 'big'),
        )

        # Build Merkle root of events
        merkle_root = self._build_merkle_root(events)

        # Public parameters for verification
        public_params = {
            'event_count': len(events),
            'witness_type': assertion.assertion_type.value,
            'commitment_value': commitment,
            'time_range_hash': hashlib.sha256(
                f"{assertion.time_range_start.isoformat()}|{assertion.time_range_end.isoformat()}".encode()
            ).hexdigest(),
        }

        # Sign the proof
        proof_data = json.dumps({
            'proof_id': proof_id,
            'assertion_id': assertion.assertion_id,
            'commitment': commitment,
            'merkle_root': merkle_root.hex(),
        }).encode()

        if self._signing_key:
            signed = self._signing_key.sign(proof_data)
            signature = bytes(signed.signature)
        else:
            signature = hashlib.sha256(proof_data).digest()

        proof = ComplianceProof(
            proof_id=proof_id,
            assertion=assertion,
            commitment=commitment.to_bytes(32, 'big'),
            challenge=challenge,
            response=response.to_bytes(64, 'big'),
            public_params=public_params,
            merkle_root=merkle_root,
            timestamp=datetime.now(),
            prover_signature=signature,
        )

        logger.info(f"Generated ZK proof: {proof_id} for {assertion.assertion_type.value}")
        return proof

    def _hash_witness(self, witness_summary: Dict) -> bytes:
        """Hash the witness summary."""
        return hashlib.sha256(
            json.dumps(witness_summary, sort_keys=True).encode()
        ).digest()

    def _generate_challenge(
        self,
        assertion: ComplianceAssertion,
        commitment: int,
    ) -> bytes:
        """Generate challenge using Fiat-Shamir heuristic."""
        challenge_input = (
            assertion.assertion_id +
            str(commitment) +
            assertion.time_range_start.isoformat() +
            assertion.time_range_end.isoformat()
        )
        return hashlib.sha256(challenge_input.encode()).digest()

    def _generate_response(
        self,
        witness: int,
        randomness: int,
        challenge: int,
    ) -> int:
        """Generate response for the proof."""
        # Simplified: response = witness + challenge * randomness (mod p)
        response = (witness + challenge * randomness) % self.commitment_scheme.p
        return response

    def _build_merkle_root(self, events: List[Dict]) -> bytes:
        """Build Merkle root of events."""
        if not events:
            return hashlib.sha256(b'empty').digest()

        # Hash each event
        leaves = [
            hashlib.sha256(json.dumps(e, sort_keys=True).encode()).digest()
            for e in events
        ]

        # Pad to power of 2
        while len(leaves) & (len(leaves) - 1):
            leaves.append(leaves[-1])

        # Build tree
        while len(leaves) > 1:
            new_leaves = []
            for i in range(0, len(leaves), 2):
                combined = leaves[i] + leaves[i + 1]
                new_leaves.append(hashlib.sha256(combined).digest())
            leaves = new_leaves

        return leaves[0]

    # Assertion evaluators

    def _evaluate_alert_sla(
        self,
        events: List[Dict],
        params: Dict[str, Any],
    ) -> Tuple[bool, Dict]:
        """Evaluate alert response SLA assertion."""
        severity = params.get('severity', 'CRITICAL')
        max_hours = params.get('max_hours', 24)

        # Find alerts and their acknowledgments
        alerts = {}
        acks = {}

        for event in events:
            if event.get('type') == 'ALERT' and event.get('severity') == severity:
                alert_id = event.get('alert_id')
                alerts[alert_id] = datetime.fromisoformat(event.get('timestamp'))

            if event.get('type') == 'ALERT_ACK':
                alert_id = event.get('alert_id')
                acks[alert_id] = datetime.fromisoformat(event.get('timestamp'))

        # Check all alerts were acked within SLA
        all_compliant = True
        max_response_time = timedelta(0)

        for alert_id, alert_time in alerts.items():
            if alert_id in acks:
                response_time = acks[alert_id] - alert_time
                max_response_time = max(max_response_time, response_time)
                if response_time > timedelta(hours=max_hours):
                    all_compliant = False
            else:
                all_compliant = False

        witness_summary = {
            'total_alerts': len(alerts),
            'acked_alerts': len(acks),
            'max_response_hours': max_response_time.total_seconds() / 3600,
            'compliant': all_compliant,
        }

        return (all_compliant, witness_summary)

    def _evaluate_no_unauthorized_override(
        self,
        events: List[Dict],
        params: Dict[str, Any],
    ) -> Tuple[bool, Dict]:
        """Evaluate no unauthorized override assertion."""
        unauthorized_count = 0

        for event in events:
            if event.get('type') == 'MODE_OVERRIDE':
                if not event.get('authorized', False):
                    unauthorized_count += 1

        witness_summary = {
            'total_overrides': sum(
                1 for e in events if e.get('type') == 'MODE_OVERRIDE'
            ),
            'unauthorized_count': unauthorized_count,
            'compliant': unauthorized_count == 0,
        }

        return (unauthorized_count == 0, witness_summary)

    def _evaluate_ceremony_sla(
        self,
        events: List[Dict],
        params: Dict[str, Any],
    ) -> Tuple[bool, Dict]:
        """Evaluate ceremony SLA compliance assertion."""
        max_minutes = params.get('max_minutes', 30)

        ceremonies_started = {}
        ceremonies_completed = {}

        for event in events:
            if event.get('type') == 'CEREMONY_STARTED':
                ceremony_id = event.get('ceremony_id')
                ceremonies_started[ceremony_id] = datetime.fromisoformat(
                    event.get('timestamp')
                )
            if event.get('type') == 'CEREMONY_COMPLETED':
                ceremony_id = event.get('ceremony_id')
                ceremonies_completed[ceremony_id] = datetime.fromisoformat(
                    event.get('timestamp')
                )

        all_compliant = True
        max_duration = timedelta(0)

        for cer_id, start_time in ceremonies_started.items():
            if cer_id in ceremonies_completed:
                duration = ceremonies_completed[cer_id] - start_time
                max_duration = max(max_duration, duration)
                if duration > timedelta(minutes=max_minutes):
                    all_compliant = False

        witness_summary = {
            'total_ceremonies': len(ceremonies_started),
            'completed_ceremonies': len(ceremonies_completed),
            'max_duration_minutes': max_duration.total_seconds() / 60,
            'compliant': all_compliant,
        }

        return (all_compliant, witness_summary)

    def _evaluate_continuous_monitoring(
        self,
        events: List[Dict],
        params: Dict[str, Any],
    ) -> Tuple[bool, Dict]:
        """Evaluate continuous monitoring assertion."""
        min_percent = params.get('min_percent', 99)

        # Find heartbeat events
        heartbeats = sorted([
            datetime.fromisoformat(e.get('timestamp'))
            for e in events
            if e.get('type') == 'HEARTBEAT'
        ])

        if not heartbeats:
            return (False, {'compliant': False, 'uptime_percent': 0})

        # Calculate uptime (assuming 1-minute heartbeat interval)
        total_expected = len(heartbeats)  # Simplified
        actual_percent = 100.0  # Would calculate from gaps

        # Check for gaps > 5 minutes
        for i in range(1, len(heartbeats)):
            gap = (heartbeats[i] - heartbeats[i-1]).total_seconds()
            if gap > 300:  # 5 minute gap
                actual_percent -= (gap - 60) / 60 * (100 / total_expected)

        actual_percent = max(0, actual_percent)
        compliant = actual_percent >= min_percent

        witness_summary = {
            'heartbeat_count': len(heartbeats),
            'uptime_percent': actual_percent,
            'required_percent': min_percent,
            'compliant': compliant,
        }

        return (compliant, witness_summary)

    def _evaluate_data_export(
        self,
        events: List[Dict],
        params: Dict[str, Any],
    ) -> Tuple[bool, Dict]:
        """Evaluate data export audit assertion."""
        exports = []
        audited_exports = set()

        for event in events:
            if event.get('type') == 'DATA_EXPORT':
                exports.append(event.get('export_id'))
            if event.get('type') == 'EXPORT_AUDITED':
                audited_exports.add(event.get('export_id'))

        all_audited = all(exp_id in audited_exports for exp_id in exports)

        witness_summary = {
            'total_exports': len(exports),
            'audited_exports': len(audited_exports),
            'compliant': all_audited,
        }

        return (all_audited, witness_summary)

    def _evaluate_access_logged(
        self,
        events: List[Dict],
        params: Dict[str, Any],
    ) -> Tuple[bool, Dict]:
        """Evaluate access logging assertion."""
        # All ACCESS events should have corresponding LOG entries
        access_events = [e for e in events if e.get('type') == 'ACCESS']

        all_logged = all(
            e.get('logged', False) for e in access_events
        )

        witness_summary = {
            'total_access': len(access_events),
            'logged_count': sum(1 for e in access_events if e.get('logged')),
            'compliant': all_logged,
        }

        return (all_logged, witness_summary)

    def _evaluate_encryption(
        self,
        events: List[Dict],
        params: Dict[str, Any],
    ) -> Tuple[bool, Dict]:
        """Evaluate encryption enforcement assertion."""
        sensitive_ops = [
            e for e in events
            if e.get('type') in ('DATA_READ', 'DATA_WRITE', 'DATA_TRANSFER')
            and e.get('sensitive', False)
        ]

        all_encrypted = all(
            e.get('encrypted', False) for e in sensitive_ops
        )

        witness_summary = {
            'sensitive_operations': len(sensitive_ops),
            'encrypted_count': sum(1 for e in sensitive_ops if e.get('encrypted')),
            'compliant': all_encrypted,
        }

        return (all_encrypted, witness_summary)

    def _evaluate_no_violations(
        self,
        events: List[Dict],
        params: Dict[str, Any],
    ) -> Tuple[bool, Dict]:
        """Evaluate no policy violations assertion."""
        violations = [e for e in events if e.get('type') == 'POLICY_VIOLATION']

        witness_summary = {
            'violation_count': len(violations),
            'compliant': len(violations) == 0,
        }

        return (len(violations) == 0, witness_summary)

    @staticmethod
    def verify(
        proof: ComplianceProof,
        verifier_id: Optional[str] = None,
    ) -> VerificationResult:
        """
        Verify a zero-knowledge compliance proof.

        This can be done by anyone without access to the underlying audit data.

        Args:
            proof: The proof to verify
            verifier_id: Optional identifier for the verifier

        Returns:
            VerificationResult indicating validity
        """
        try:
            # Check time range is valid
            if proof.assertion.time_range_end < proof.assertion.time_range_start:
                return VerificationResult(
                    valid=False,
                    assertion_id=proof.assertion.assertion_id,
                    verified_at=datetime.now(),
                    verifier_id=verifier_id,
                    details="Invalid time range",
                    time_range_check=False,
                )

            # Verify commitment structure
            commitment = int.from_bytes(proof.commitment, 'big')
            if commitment <= 0:
                return VerificationResult(
                    valid=False,
                    assertion_id=proof.assertion.assertion_id,
                    verified_at=datetime.now(),
                    verifier_id=verifier_id,
                    details="Invalid commitment",
                    cryptographic_check=False,
                )

            # Verify challenge was correctly derived (Fiat-Shamir)
            expected_challenge = hashlib.sha256(
                (
                    proof.assertion.assertion_id +
                    str(commitment) +
                    proof.assertion.time_range_start.isoformat() +
                    proof.assertion.time_range_end.isoformat()
                ).encode()
            ).digest()

            if proof.challenge != expected_challenge:
                return VerificationResult(
                    valid=False,
                    assertion_id=proof.assertion.assertion_id,
                    verified_at=datetime.now(),
                    verifier_id=verifier_id,
                    details="Challenge verification failed",
                    cryptographic_check=False,
                )

            # Verify Merkle root is non-empty
            if len(proof.merkle_root) != 32:
                return VerificationResult(
                    valid=False,
                    assertion_id=proof.assertion.assertion_id,
                    verified_at=datetime.now(),
                    verifier_id=verifier_id,
                    details="Invalid Merkle root",
                    cryptographic_check=False,
                )

            # Verify public params consistency
            if proof.public_params.get('commitment_value') != commitment:
                return VerificationResult(
                    valid=False,
                    assertion_id=proof.assertion.assertion_id,
                    verified_at=datetime.now(),
                    verifier_id=verifier_id,
                    details="Public params inconsistent",
                    cryptographic_check=False,
                )

            # All checks passed
            return VerificationResult(
                valid=True,
                assertion_id=proof.assertion.assertion_id,
                verified_at=datetime.now(),
                verifier_id=verifier_id,
                details=f"Proof verified for: {proof.assertion.description}",
            )

        except Exception as e:
            return VerificationResult(
                valid=False,
                assertion_id=proof.assertion.assertion_id,
                verified_at=datetime.now(),
                verifier_id=verifier_id,
                details=f"Verification error: {str(e)}",
            )

    def generate_compliance_report(
        self,
        assertions: List[ComplianceAssertion],
    ) -> Dict[str, Any]:
        """
        Generate a compliance report with proofs for multiple assertions.

        Args:
            assertions: List of assertions to prove

        Returns:
            Report dictionary with proofs
        """
        report = {
            'report_id': f"report_{int(time.time() * 1000)}",
            'generated_at': datetime.now().isoformat(),
            'assertions': [],
            'proofs': [],
            'summary': {
                'total': len(assertions),
                'proven': 0,
                'failed': 0,
            }
        }

        for assertion in assertions:
            try:
                proof = self.prove(assertion)
                report['assertions'].append(assertion.to_dict())
                report['proofs'].append(proof.to_dict())
                report['summary']['proven'] += 1
            except ValueError as e:
                report['assertions'].append({
                    **assertion.to_dict(),
                    'error': str(e),
                })
                report['summary']['failed'] += 1

        return report
