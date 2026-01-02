# Advanced Boundary Rules Specification

This document specifies additional policy gates and integration rules identified through ecosystem analysis.

## Overview

The base boundary-daemon provides 6 modes and core gates (check_recall, check_tool, check_message). This specification extends coverage with **47 new policy gates** addressing gaps in:

- Cryptographic verification
- Semantic content analysis
- Economic transaction authorization
- Cognitive state monitoring
- Cross-repo coordination

## New API Commands

### 1. Cryptographic Verification Gates

#### `verify_key_derivation`
Validates that key derivation meets minimum security requirements.

```python
# Request
{
    "command": "verify_key_derivation",
    "params": {
        "kdf_type": "argon2id",      # Required: argon2id, scrypt, pbkdf2
        "memory_cost": 1073741824,    # bytes (1GB minimum for argon2id)
        "time_cost": 4,               # iterations
        "parallelism": 4
    }
}

# Response
{
    "success": true,
    "permitted": true,
    "reason": "KDF parameters meet OWASP 2024 requirements"
}
```

**Mode restrictions:**
- OPEN/RESTRICTED: memory_cost >= 64MB
- TRUSTED+: memory_cost >= 1GB, time_cost >= 4

#### `verify_merkle_proof`
Validates Merkle tree integrity before granting access.

```python
{
    "command": "verify_merkle_proof",
    "params": {
        "root_hash": "abc123...",
        "leaf_hash": "def456...",
        "proof_path": ["hash1", "hash2", ...],
        "leaf_index": 42
    }
}
```

#### `verify_cryptographic_signature`
Generic signature verification using daemon's HSM/TPM.

```python
{
    "command": "verify_cryptographic_signature",
    "params": {
        "algorithm": "ed25519",       # ed25519, ecdsa-p256, rsa-pss, bls12-381
        "message_hash": "...",
        "signature": "...",
        "public_key": "...",
        "require_hardware": false     # If true, requires TPM-bound key
    }
}
```

#### `verify_zkp_proof`
Validates zero-knowledge proofs (Groth16, PLONK).

```python
{
    "command": "verify_zkp_proof",
    "params": {
        "proof_system": "groth16",
        "proof": "...",
        "public_inputs": [...],
        "verification_key": "..."
    }
}
```

### 2. Semantic Content Gates

#### `classify_intent_semantics`
Classifies text intent for policy decisions.

```python
{
    "command": "classify_intent_semantics",
    "params": {
        "text": "I want to share my research with the team",
        "context": "workplace",
        "author_id": "user@example.com"
    }
}

# Response
{
    "success": true,
    "classification": {
        "threat_level": 0,           # 0-5 (maps to memory class)
        "category": "collaboration",
        "manipulation_score": 0.02,
        "coercion_score": 0.0,
        "ambiguity_score": 0.15,
        "political_content": false,
        "pii_detected": false
    },
    "permitted": true,
    "ceremony_required": false
}
```

#### `detect_semantic_drift`
Detects gradual meaning shifts across a sequence.

```python
{
    "command": "detect_semantic_drift",
    "params": {
        "entry_sequence": ["entry1_hash", "entry2_hash", ...],
        "drift_threshold": 0.3,
        "window_size": 100
    }
}
```

#### `detect_cross_language_injection`
Detects translation-based prompt injection attacks.

```python
{
    "command": "detect_cross_language_injection",
    "params": {
        "original_text": "...",
        "source_language": "en",
        "check_languages": ["ja", "zh", "ar", "ru"]
    }
}
```

#### `verify_llm_consensus`
Validates multi-model agreement on intent interpretation.

```python
{
    "command": "verify_llm_consensus",
    "params": {
        "entry_hash": "...",
        "model_signatures": [
            {"model": "gpt-4", "interpretation_hash": "...", "signature": "..."},
            {"model": "claude", "interpretation_hash": "...", "signature": "..."},
            {"model": "llama", "interpretation_hash": "...", "signature": "..."}
        ],
        "agreement_threshold": 0.67  # 2/3 Byzantine tolerance
    }
}
```

### 3. Economic Transaction Gates

#### `verify_stake_escrow`
Confirms stake is in escrow before settlement.

```python
{
    "command": "verify_stake_escrow",
    "params": {
        "escrow_id": "...",
        "expected_amount": 1000,
        "currency": "ETH",
        "parties": ["party_a", "party_b"]
    }
}
```

#### `verify_stake_burned`
Cryptographic proof that stake was burned on-chain.

```python
{
    "command": "verify_stake_burned",
    "params": {
        "burn_tx_hash": "0x...",
        "chain": "ethereum",
        "amount": 500,
        "burn_address": "0x000...dead"
    }
}
```

#### `verify_effort_proof`
Validates Merkle proof of cognitive effort (value-ledger).

```python
{
    "command": "verify_effort_proof",
    "params": {
        "value_record_id": "...",
        "merkle_proof": [...],
        "effort_vector": {
            "time_minutes": 120,
            "novelty_score": 0.7,
            "failure_recovery": 3,
            "reflection_depth": 2
        }
    }
}
```

#### `verify_w3c_credential`
Validates W3C Verifiable Credential signatures.

```python
{
    "command": "verify_w3c_credential",
    "params": {
        "credential": {...},        # Full VC JSON
        "issuer_did": "did:key:...",
        "expected_type": "EffortReceipt"
    }
}
```

### 4. Cognitive State Gates

#### `check_reflection_intensity`
Mode-aware limits on reflection depth/frequency.

```python
{
    "command": "check_reflection_intensity",
    "params": {
        "intensity_level": 3,        # 0-5
        "reflection_type": "meta",   # meta, self, world
        "depth": 2,                  # recursion depth
        "duration_seconds": 300
    }
}

# Mode restrictions:
# OPEN: intensity <= 5, depth <= 10
# RESTRICTED: intensity <= 4, depth <= 5
# TRUSTED: intensity <= 3, depth <= 3
# AIRGAP: intensity <= 2, depth <= 2
# COLDROOM: intensity <= 1, depth <= 1, no predictive
# LOCKDOWN: all reflection denied
```

#### `check_identity_mutation`
Prevents identity changes that violate learning contracts.

```python
{
    "command": "check_identity_mutation",
    "params": {
        "current_identity_hash": "...",
        "proposed_identity_hash": "...",
        "mutation_type": "personality_shift",
        "learning_contract_ids": ["contract1", "contract2"]
    }
}
```

#### `check_agent_attestation`
Verifies agent capability tokens for multi-agent operations.

```python
{
    "command": "check_agent_attestation",
    "params": {
        "agent_id": "synth-mind-001",
        "capability": "reflect",
        "attestation_token": "...",
        "peer_agent_id": "memory-vault-001"  # Optional: for federation
    }
}
```

### 5. Contract Integrity Gates

#### `verify_contract_signature`
Ensures learning contract hasn't been tampered.

```python
{
    "command": "verify_contract_signature",
    "params": {
        "contract_id": "...",
        "contract_hash": "...",
        "issuer_signature": "...",
        "issuer_public_key": "..."
    }
}
```

#### `verify_memory_not_revoked`
Checks against revocation list before allowing recall.

```python
{
    "command": "verify_memory_not_revoked",
    "params": {
        "memory_id": "...",
        "revocation_list_hash": "..."  # Optional: specific list version
    }
}
```

#### `check_contract_delegation_depth`
Prevents unlimited contract chains.

```python
{
    "command": "check_contract_delegation_depth",
    "params": {
        "contract_id": "...",
        "parent_chain": ["parent1", "parent2", ...]
    }
}

# Response includes max_depth (default: 3)
```

#### `verify_constitution_integrity`
Validates Agent-OS constitution hash.

```python
{
    "command": "verify_constitution_integrity",
    "params": {
        "constitution_hash": "...",
        "agent_id": "guardian",
        "expected_version": "1.2.0"
    }
}
```

### 6. Execution Safeguard Gates

#### `verify_execution_confidence`
Enforces 95% confidence threshold (Finite-Intent-Executor).

```python
{
    "command": "verify_execution_confidence",
    "params": {
        "intent_id": "...",
        "model_confidence": 0.97,
        "threshold": 0.95,
        "model_id": "executor-model-v2"
    }
}
```

#### `detect_political_activity`
Hard-coded political activity detection.

```python
{
    "command": "detect_political_activity",
    "params": {
        "intended_action": "Fund community garden project",
        "beneficiaries": ["local_org"],
        "check_depth": "comprehensive"  # basic, comprehensive
    }
}

# Response
{
    "success": true,
    "is_political": false,
    "political_indicators": [],
    "confidence": 0.98
}
```

#### `verify_sunset_deadline`
Enforces 20-year auto-termination.

```python
{
    "command": "verify_sunset_deadline",
    "params": {
        "intent_created_timestamp": "2025-01-01T00:00:00Z",
        "current_timestamp": "2045-01-02T00:00:00Z",
        "max_years": 20
    }
}
```

#### `prevent_posthumous_revocation`
Blocks revocation attempts after death trigger.

```python
{
    "command": "prevent_posthumous_revocation",
    "params": {
        "intent_id": "...",
        "death_trigger_timestamp": "2030-01-01T00:00:00Z",
        "revocation_attempt_timestamp": "2030-06-01T00:00:00Z"
    }
}
```

### 7. Dispute Resolution Gates

#### `check_counter_proposal_limit`
Enforces maximum 3 counter-proposals.

```python
{
    "command": "check_counter_proposal_limit",
    "params": {
        "negotiation_id": "...",
        "current_count": 2
    }
}
```

#### `verify_settlement_honors_constraints`
Validates settlement satisfies both parties' original intents.

```python
{
    "command": "verify_settlement_honors_constraints",
    "params": {
        "settlement": {...},
        "party_a_original_intent": {...},
        "party_b_original_intent": {...},
        "constraint_satisfaction_threshold": 0.8
    }
}
```

#### `check_dispute_class_mode_requirement`
Mode-aware dispute classification.

```python
{
    "command": "check_dispute_class_mode_requirement",
    "params": {
        "dispute_class": 4,  # 0-5
        "current_mode": "TRUSTED"
    }
}

# Mapping:
# Class 0-1: Any mode
# Class 2: RESTRICTED+
# Class 3: TRUSTED+
# Class 4: AIRGAP+
# Class 5: COLDROOM only
```

### 8. SIEM Integration Gates

#### `verify_detection_rule_signature`
Ensures SIEM rules haven't been tampered.

```python
{
    "command": "verify_detection_rule_signature",
    "params": {
        "rule_id": "rule_103",
        "rule_hash": "...",
        "rule_signature": "...",
        "signer_public_key": "..."
    }
}
```

#### `audit_rule_state_change`
Requires ceremony for rule enable/disable in TRUSTED+ modes.

```python
{
    "command": "audit_rule_state_change",
    "params": {
        "rule_id": "rule_42",
        "old_state": "enabled",
        "new_state": "disabled",
        "operator_id": "admin@siem",
        "justification": "False positive rate too high"
    }
}

# In TRUSTED+ modes, returns ceremony_required: true
```

#### `correlate_siem_event`
Links SIEM events to policy decisions for audit.

```python
{
    "command": "correlate_siem_event",
    "params": {
        "siem_event_id": "...",
        "policy_decision_id": "...",
        "correlation_type": "caused_by"  # caused_by, triggered, related
    }
}
```

### 9. Rate Limiting Gates

#### `check_entity_rate_limit`
Per-entity operation rate limiting.

```python
{
    "command": "check_entity_rate_limit",
    "params": {
        "entity_id": "mediator-001",
        "entity_type": "mediator",
        "operation": "post_intent",
        "window_seconds": 86400,
        "max_operations": 100
    }
}

# Mode-aware limits:
# OPEN: 100/day
# RESTRICTED: 50/day
# AIRGAP: 0/day (no posting)
```

### 10. Consent & Authorization Gates

#### `verify_memory_consent`
Proves human consent was obtained for memory access.

```python
{
    "command": "verify_memory_consent",
    "params": {
        "memory_id": "...",
        "consent_token": "...",
        "consent_signature": "...",
        "consenter_public_key": "..."
    }
}
```

#### `verify_physical_token_presented`
Confirms FIDO2/YubiKey for Level 5 access.

```python
{
    "command": "verify_physical_token_presented",
    "params": {
        "token_type": "fido2",
        "assertion": {...},
        "memory_class": 5,
        "credential_id": "..."
    }
}
```

## Cross-Cutting Middleware

### Ceremony Integration

All gates that return `ceremony_required: true` should trigger:

```python
{
    "command": "initiate_ceremony",
    "params": {
        "ceremony_type": "human_override",
        "required_for": "verify_key_derivation",
        "context": {...},
        "timeout_seconds": 300
    }
}
```

### Anomaly Score Integration

Before sensitive operations, check entity anomaly score:

```python
{
    "command": "check_anomaly_score",
    "params": {
        "entity_id": "agent-001",
        "operation": "recall",
        "threshold": 0.7
    }
}

# If anomaly_score > threshold, operation denied or ceremony required
```

### Mode-Aware Policy Gradation

Replace binary allow/deny with graduated permissions:

```python
{
    "command": "get_graduated_permission",
    "params": {
        "operation": "reflect",
        "params": {...}
    }
}

# Response
{
    "permissions": {
        "OPEN": {"permitted": true, "ceremony": false, "limits": {"depth": 10}},
        "RESTRICTED": {"permitted": true, "ceremony": false, "limits": {"depth": 5}},
        "TRUSTED": {"permitted": true, "ceremony": true, "limits": {"depth": 3}},
        "AIRGAP": {"permitted": true, "ceremony": true, "limits": {"depth": 2}},
        "COLDROOM": {"permitted": false},
        "LOCKDOWN": {"permitted": false}
    },
    "current_mode": "TRUSTED",
    "current_permission": {"permitted": true, "ceremony": true, "limits": {"depth": 3}}
}
```

## Implementation Priority

### Tier 1: Critical (Security Impact)
| Gate | Repo | Effort |
|------|------|--------|
| `verify_merkle_proof` | memory-vault | 2h |
| `verify_execution_confidence` | finite-intent-executor | 2h |
| `verify_llm_consensus` | natlangchain | 4h |
| `verify_stake_burned` | ilr-module | 3h |
| `verify_contract_signature` | learning-contracts | 3h |

### Tier 2: High (Policy Enforcement)
| Gate | Repo | Effort |
|------|------|--------|
| `verify_constitution_integrity` | agent-os | 4h |
| `verify_detection_rule_signature` | boundary-siem | 3h |
| `verify_settlement_honors_constraints` | mediator-node | 4h |
| `check_reflection_intensity` | synth-mind | 3h |
| `verify_memory_consent` | agent-os, memory-vault | 4h |

### Tier 3: Medium (Operational)
| Gate | Repo | Effort |
|------|------|--------|
| `check_agent_attestation` | synth-mind, agent-os | 5h |
| `verify_effort_proof` | value-ledger | 3h |
| `classify_intent_semantics` | all | 8h |
| `detect_semantic_drift` | natlangchain | 4h |
| `check_entity_rate_limit` | all | 3h |

## Backward Compatibility

All new gates are **additive**. Existing integrations continue to work. New gates return `permitted: true` by default if the feature is not configured, ensuring gradual adoption.

## Testing Requirements

Each new gate requires:
1. Unit tests for all mode combinations
2. Integration test with target repo
3. Ceremony flow test (where applicable)
4. Fail-closed behavior verification
5. Rate limit edge case testing

---

*Specification version: 2.0*
*Generated: 2026-01-02*
