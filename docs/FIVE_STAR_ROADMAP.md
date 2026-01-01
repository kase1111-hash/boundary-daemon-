# Five-Star Security Roadmap

**Goal:** Achieve 5-star operational readiness and establish cutting-edge security leadership.

**Current State:** 4-star security architecture with gaps in operational tooling and some critical hardening features.

**Target State:** Production-ready, enterprise-grade AI security platform with industry-leading capabilities.

---

## Executive Summary

This roadmap is organized into three phases:

| Phase | Focus | Timeline | Outcome |
|-------|-------|----------|---------|
| **Phase 1** | Critical Security Gaps | Immediate | Close all HIGH/CRITICAL security vulnerabilities |
| **Phase 2** | Operational Excellence | Short-term | 5-star operational readiness |
| **Phase 3** | Cutting-Edge Innovation | Medium-term | Industry leadership position |

---

## Phase 1: Critical Security Gaps (Priority: CRITICAL)

These items represent security vulnerabilities that must be addressed immediately.

### 1.1 Clock Drift Protection

**Current State:** NOT IMPLEMENTED
**Risk Level:** HIGH
**Attack Vector:** Time manipulation attacks (`date -s "2020-01-01"`)

**Implementation Steps:**

```
1. Add monotonic clock usage for all time-sensitive operations
   └── File: daemon/time_guard.py (new)
   └── Use time.monotonic() instead of time.time() for intervals

2. Implement NTP sync verification
   └── Query multiple NTP servers
   └── Detect discrepancies > configurable threshold
   └── Trigger LOCKDOWN on major time jumps

3. Add time manipulation detection
   └── Monitor for backwards time jumps
   └── Detect sudden large forward jumps (> 60 seconds)
   └── Log all clock adjustments to event log

4. Mode transition freezing on clock skew
   └── If clock skew detected, freeze in current mode
   └── Require ceremony to unlock after time stabilizes
```

**Files to Create/Modify:**
- `daemon/time_guard.py` (new) - Time protection module
- `daemon/boundary_daemon.py` - Integrate time guard
- `daemon/tripwires.py` - Add clock manipulation tripwire

**Verification:**
```bash
# Test: Attempt time manipulation while daemon running
sudo date -s "2020-01-01"  # Should trigger LOCKDOWN
```

---

### 1.2 Code Signing & Integrity Verification

**Current State:** NOT IMPLEMENTED
**Risk Level:** HIGH
**Attack Vector:** Daemon binary/module tampering

**Implementation Steps:**

```
1. Generate signing keypair for daemon distribution
   └── Ed25519 keypair (reuse existing pynacl dependency)
   └── Public key embedded in config
   └── Private key secured offline

2. Sign all Python modules at build time
   └── Hash each .py file
   └── Create manifest.json with all hashes
   └── Sign manifest with Ed25519

3. Verify signatures at daemon startup
   └── Load public key from config
   └── Verify manifest signature
   └── Check each module hash
   └── REFUSE TO START if verification fails

4. Runtime integrity monitoring
   └── Periodic re-verification (every 60s)
   └── Detect hot-patching attempts
   └── Trigger LOCKDOWN on tampering
```

**Files to Create/Modify:**
- `daemon/integrity/code_signer.py` (new) - Signing utilities
- `daemon/integrity/integrity_verifier.py` (new) - Runtime verification
- `scripts/sign_release.py` (new) - Build-time signing
- `daemon/boundary_daemon.py` - Add startup verification

---

### 1.3 TPM Integration (Full Implementation)

**Current State:** Framework exists, functionality incomplete
**Risk Level:** MEDIUM
**Purpose:** Hardware-backed mode attestation

**Implementation Steps:**

```
1. Complete TPM manager implementation
   └── File: daemon/hardware/tpm_manager.py
   └── Implement seal_secret() - Bind secrets to PCR state
   └── Implement unseal_secret() - Retrieve if PCR matches
   └── Implement extend_pcr() - Record mode changes

2. Bind boundary modes to TPM state
   └── Each mode transition extends PCR
   └── High-security modes require TPM unsealing
   └── Tampering with mode history breaks unseal

3. Hardware attestation for ceremonies
   └── Ceremonies in COLDROOM require TPM quote
   └── Quote proves unmodified boot chain
   └── External verifier can validate quote
```

**Dependencies:**
- `tpm2-pytss` or `python-tpm2-pytss`

---

### 1.4 Biometric Verification (Full Implementation)

**Current State:** Returns "disabled" stub
**Risk Level:** MEDIUM
**Purpose:** Stronger human presence verification

**Implementation Steps:**

```
1. Implement fingerprint reader support
   └── File: daemon/auth/biometric_verifier.py
   └── Use fprintd D-Bus interface (Linux)
   └── Configurable: required vs optional

2. Add facial recognition option
   └── Local-only processing (no cloud)
   └── OpenCV + dlib for detection
   └── Template stored locally, encrypted

3. Multi-factor ceremony support
   └── Biometric + keyboard input + time delay
   └── Configurable combinations per ceremony type
   └── Fallback to keyboard-only in AIRGAP (no sensors)
```

**Dependencies:**
- `fprintd` (system service, not Python package)
- Optional: `opencv-python`, `dlib` for facial recognition

---

### 1.5 Network Attestation

**Current State:** NOT IMPLEMENTED
**Risk Level:** MEDIUM
**Purpose:** Cryptographically verify network trust levels

**Implementation Steps:**

```
1. VPN certificate verification
   └── Extract VPN connection certificate
   └── Verify against trusted CA list
   └── Map VPN identity to trust level

2. Network fingerprinting
   └── Record expected network characteristics
   └── Detect network spoofing attempts
   └── Alert on unexpected network changes

3. Mode-network binding
   └── TRUSTED mode requires verified VPN
   └── Automatic downgrade if VPN drops
   └── Log all network state transitions
```

---

## Phase 2: Operational Excellence (Priority: HIGH)

These items address the "missing 1 star" in operational readiness.

### 2.1 Terminal Dashboard (TUI)

**Current State:** Not implemented
**Gap:** No real-time visibility without log parsing

**Implementation Steps:**

```
1. Create TUI framework
   └── File: daemon/tui/dashboard.py
   └── Use 'textual' or 'rich' library
   └── Real-time updates via daemon socket

2. Dashboard panels:
   ┌─────────────────────────────────────────────────────────────┐
   │  BOUNDARY DAEMON v2.0          Mode: TRUSTED    ▲ 99.9%    │
   ├─────────────────────────────────────────────────────────────┤
   │  EVENTS (last 10)              │  ALERTS                   │
   │  ├─ 14:32:01 MODE_CHANGE       │  ⚠ 2 unacknowledged      │
   │  ├─ 14:31:45 TOOL_REQUEST      │  └─ Prompt injection      │
   │  ├─ 14:31:12 POLICY_DECISION   │  └─ Clock drift warning   │
   │  └─ 14:30:58 SANDBOX_START     │                           │
   ├─────────────────────────────────────────────────────────────┤
   │  SANDBOX STATUS                │  SIEM SHIPPING            │
   │  Active: 3  |  Queued: 0       │  Kafka: ✓ Connected       │
   │  Memory: 2.1GB / 8GB           │  Last batch: 14:32:00     │
   │  CPU: 45% (limit: 80%)         │  Queue depth: 12 events   │
   └─────────────────────────────────────────────────────────────┘

3. Keyboard shortcuts:
   └── [m] Mode change ceremony
   └── [a] Acknowledge alert
   └── [e] Export event range
   └── [q] Quit dashboard
   └── [/] Search events
```

**File:** `daemon/tui/dashboard.py`
**Dependency:** `textual>=0.40.0`

---

### 2.2 Query CLI (`boundaryctl query`)

**Current State:** Not implemented
**Gap:** Cannot query events without external SIEM

**Implementation Steps:**

```
1. Create SQLite index for events
   └── File: daemon/query/event_index.py
   └── Index: timestamp, event_type, severity, actor
   └── Derived from hash-chained log (read-only)
   └── Auto-rebuild on daemon start

2. Implement query language
   └── boundaryctl query "type:VIOLATION after:2024-01-01"
   └── boundaryctl query "severity:>=HIGH source:sandbox"
   └── boundaryctl query "actor:agent-* action:TOOL_REQUEST"

3. Query output formats:
   └── Table (default)
   └── JSON (--format json)
   └── CSV (--format csv)
   └── Compact (--format oneline)

4. Query examples:
   $ boundaryctl query "type:VIOLATION" --last 24h
   $ boundaryctl query "severity:CRITICAL" --export report.json
   $ boundaryctl query "sandbox:*" --correlate 60s
```

**Files:**
- `daemon/query/event_index.py` (new)
- `daemon/query/query_parser.py` (new)
- `daemon/cli/query_cmd.py` (new)

---

### 2.3 Configuration Linter

**Current State:** Not implemented
**Gap:** Misconfigurations silently weaken security

**Implementation Steps:**

```
1. Create config validator
   └── File: daemon/config/linter.py
   └── Validate before daemon start
   └── Block startup on CRITICAL issues
   └── Warn on MEDIUM issues

2. Validation rules:
   ├── CRITICAL: Conflicting mode definitions
   ├── CRITICAL: Invalid cryptographic key paths
   ├── CRITICAL: Permissions too open on key files
   ├── HIGH: Network whitelist too broad
   ├── HIGH: Ceremony timeout < 10 seconds
   ├── MEDIUM: SIEM endpoint not reachable
   ├── MEDIUM: USB whitelist not empty in COLDROOM
   └── LOW: Deprecated config options used

3. CLI integration:
   $ boundaryctl config lint
   $ boundaryctl config lint --fix  # Auto-fix where possible
   $ boundaryctl config diff old.conf new.conf
```

---

### 2.4 Case Management Integration

**Current State:** Not implemented
**Gap:** Alerts have no workflow

**Implementation Steps:**

```
1. Alert lifecycle management
   └── File: daemon/alerts/case_manager.py
   └── States: NEW → ASSIGNED → INVESTIGATING → RESOLVED/DISMISSED
   └── Assignment to analysts via webhook
   └── SLA tracking (time to acknowledge, time to resolve)

2. Integration webhooks:
   └── ServiceNow: Create incident on CRITICAL
   └── Jira: Create issue with labels
   └── PagerDuty: Page on-call for CRITICAL
   └── Slack: Thread updates for case progress

3. Case correlation:
   └── Group related alerts into single case
   └── Link sandbox events to prompt injection alerts
   └── Timeline view of case events
```

---

### 2.5 Ceremony Templates

**Current State:** Planned, not implemented
**Gap:** Ceremonies are ad-hoc

**Implementation Steps:**

```
1. Create template system
   └── File: daemon/ceremony/templates.py
   └── YAML-defined ceremony types
   └── Reusable steps and validations

2. Built-in templates:
   ├── emergency_access.yaml
   │   └── 3-step: Request → Manager approval → Execute
   ├── mode_override.yaml
   │   └── 4-step: Request → Justification → Cooldown → Confirm
   ├── data_export.yaml
   │   └── 5-step: Request → Review → Approve → Export → Verify
   └── break_glass.yaml
       └── 2-step: Biometric → Execute (audit emphasized)

3. Custom template support:
   └── User-defined templates in /etc/boundary/ceremonies/
   └── Validation against schema
   └── Import/export for sharing
```

---

### 2.6 Merkle Tree Audit Proofs

**Current State:** Planned, not implemented
**Gap:** Cannot prove individual events without full log

**Implementation Steps:**

```
1. Build Merkle tree from event log
   └── File: daemon/audit/merkle_tree.py
   └── Leaf = SHA256(event)
   └── Internal = SHA256(left || right)
   └── Root published periodically

2. Generate inclusion proofs
   └── Prove event X is in tree with root R
   └── Proof size: O(log n) hashes
   └── Verifiable without full log access

3. External anchoring
   └── Publish root hash to:
       ├── RFC 3161 timestamp server
       ├── Blockchain (optional, configurable)
       └── Cross-organization witness network

4. Proof verification API
   └── POST /verify/merkle with event + proof
   └── Returns: valid/invalid + anchor references
```

---

## Phase 3: Cutting-Edge Innovation (Priority: MEDIUM)

These items establish industry leadership and differentiation.

### 3.1 Federated AI Security Mesh

**Concept:** Cross-organization threat intelligence sharing for AI attacks

**Implementation Steps:**

```
1. Threat signature sharing
   └── File: daemon/federation/threat_mesh.py
   └── Share anonymized prompt injection patterns
   └── Receive patterns from mesh peers
   └── Cryptographically signed contributions

2. Privacy-preserving sharing
   └── Bloom filters for IOC matching
   └── Differential privacy for pattern aggregation
   └── No raw prompts leave organization

3. Trust hierarchy
   └── Peer reputation scoring
   └── Verified organization identities
   └── Revocation for bad actors
```

**Innovation:** First federated threat intelligence network specifically for AI/LLM attacks.

---

### 3.2 Predictive Boundary Mode Recommendation

**Concept:** Suggest optimal boundary mode based on context

**Implementation Steps:**

```
1. Context analysis engine
   └── File: daemon/intelligence/mode_advisor.py
   └── Analyze: time of day, active users, network location
   └── Analyze: recent alert patterns, sandbox activity
   └── Deterministic rules (not ML black box)

2. Mode recommendations
   └── "Recommend: TRUSTED → RESTRICTED"
   └── "Reason: 3 prompt injection attempts in last hour"
   └── "Confidence: HIGH (based on policy rule #47)"

3. Auto-escalation with ceremony
   └── If threat indicators exceed threshold
   └── Initiate ceremony for mode escalation
   └── Human approves or dismisses
```

---

### 3.3 Zero-Knowledge Compliance Proofs

**Concept:** Prove compliance without revealing sensitive audit data

**Implementation Steps:**

```
1. ZK proof generation
   └── File: daemon/compliance/zk_proofs.py
   └── Prove: "No CRITICAL alerts unacknowledged > 24h"
   └── Without revealing: specific alert contents

2. Compliance assertions
   └── "All ceremonies completed within SLA"
   └── "No mode overrides without manager approval"
   └── "All data exports audited"

3. Auditor verification
   └── Auditor receives proof, not raw logs
   └── Mathematically verifiable
   └── Privacy preserved
```

**Dependency:** `py_ecc` or `arkworks` bindings

---

### 3.4 Autonomous Agent Containment Protocol

**Concept:** Industry-first protocol for containing runaway AI agents

**Implementation Steps:**

```
1. Agent behavior profiling
   └── File: daemon/containment/agent_profiler.py
   └── Baseline: normal tool usage patterns
   └── Baseline: normal resource consumption
   └── Baseline: normal output characteristics

2. Anomaly triggers
   └── Sudden increase in tool call frequency
   └── Attempts to access outside capability set
   └── Output patterns matching known attacks
   └── Resource consumption spike

3. Containment actions
   ├── WARN: Log and alert, continue execution
   ├── THROTTLE: Rate-limit tool calls
   ├── ISOLATE: Move to more restrictive sandbox
   ├── SUSPEND: Pause agent, await human review
   └── TERMINATE: Kill agent process immediately

4. Recovery protocol
   └── Human reviews containment decision
   └── Ceremony required to release from containment
   └── Agent state preserved for forensic analysis
```

**Innovation:** First standardized protocol for AI agent containment.

---

### 3.5 Hardware Security Module (HSM) Native Support

**Concept:** Enterprise-grade key management for signing operations

**Implementation Steps:**

```
1. HSM abstraction layer
   └── File: daemon/crypto/hsm_provider.py
   └── Support: PKCS#11 interface
   └── Support: AWS CloudHSM
   └── Support: Azure Dedicated HSM
   └── Support: YubiHSM

2. Key operations via HSM
   └── Event signing keys stored in HSM
   └── Signing operations never expose key
   └── Audit log of all HSM operations

3. HSM ceremony integration
   └── Certain ceremonies require HSM-backed signatures
   └── Multi-party HSM access for critical operations
   └── HSM failure triggers LOCKDOWN
```

---

### 3.6 Quantum-Resistant Cryptography Migration Path

**Concept:** Future-proof against quantum computing threats

**Implementation Steps:**

```
1. Hybrid signature scheme
   └── File: daemon/crypto/post_quantum.py
   └── Sign with Ed25519 AND Dilithium-3
   └── Verify with either (backwards compatible)
   └── Migrate to PQ-only when ecosystem ready

2. Hash function agility
   └── Support SHA-256 and SHA-3
   └── Configurable hash chain algorithm
   └── Migration tools for existing logs

3. Key exchange upgrade
   └── Current: X25519
   └── Hybrid: X25519 + Kyber-768
   └── Future: Kyber-768 only
```

**Dependency:** `pqcrypto` or `liboqs-python`

---

## Implementation Priority Matrix

| Phase | Item | Effort | Impact | Dependencies |
|-------|------|--------|--------|--------------|
| **1.1** | Clock Drift Protection | Medium | Critical | None |
| **1.2** | Code Signing | Medium | Critical | None (use existing pynacl) |
| **1.3** | TPM Integration | High | High | tpm2-pytss |
| **1.4** | Biometric Verification | Medium | Medium | fprintd |
| **1.5** | Network Attestation | Medium | Medium | None |
| **2.1** | Terminal Dashboard | Medium | High | textual |
| **2.2** | Query CLI | Medium | High | None |
| **2.3** | Config Linter | Low | High | None |
| **2.4** | Case Management | Medium | Medium | None |
| **2.5** | Ceremony Templates | Low | Medium | None |
| **2.6** | Merkle Tree Proofs | Medium | High | None |
| **3.1** | Federated AI Mesh | High | Differentiating | None |
| **3.2** | Mode Advisor | Medium | Differentiating | None |
| **3.3** | ZK Compliance | High | Differentiating | py_ecc |
| **3.4** | Agent Containment | High | Differentiating | None |
| **3.5** | HSM Support | High | Enterprise | pkcs11 |
| **3.6** | Post-Quantum | Medium | Future-proof | liboqs |

---

## Success Metrics

| Metric | Current | Phase 1 | Phase 2 | Phase 3 |
|--------|---------|---------|---------|---------|
| **Security Gaps** | 5 critical | 0 critical | 0 high | 0 medium |
| **Operational Rating** | 4 stars | 4 stars | 5 stars | 5 stars |
| **Industry Position** | Competitive | Competitive | Leading | Defining |
| **Enterprise Readiness** | 80% | 90% | 95% | 100% |
| **Unique Capabilities** | 3 | 3 | 5 | 10+ |

---

## Boundary-SIEM Integration Enhancements

To maximize the ecosystem value:

### SIEM Correlation Rules for Boundary Events

```yaml
# Example: Prompt injection followed by mode override
- name: suspicious_override_after_injection
  condition:
    sequence:
      - event_type: PROMPT_INJECTION within 5m
      - event_type: CEREMONY_STARTED where ceremony_type: mode_override
  action: ALERT_CRITICAL
  description: "Potential social engineering - override attempt after injection"
```

### Boundary-SIEM Bidirectional API

```
Daemon → SIEM: Events, alerts, sandbox telemetry
SIEM → Daemon: Threat intel updates, containment requests
```

### Unified Dashboard

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    BOUNDARY SECURITY ECOSYSTEM                          │
├─────────────────────────────────────────────────────────────────────────┤
│  DAEMON STATUS          │  SIEM STATUS            │  WATCHDOG STATUS   │
│  Mode: TRUSTED          │  Events/sec: 1,247      │  Logs monitored: 3 │
│  Sandboxes: 5 active    │  Correlation rules: 89  │  Anomalies: 0      │
│  Events today: 12,847   │  Alerts (24h): 7        │  Last scan: 2m ago │
├─────────────────────────────────────────────────────────────────────────┤
│  CORRELATED ALERTS                                                      │
│  ┌─ CRITICAL: Agent escape attempt correlated with prompt injection    │
│  │  Source: daemon + siem correlation                                  │
│  │  Status: INVESTIGATING (assigned: analyst@org.com)                  │
│  └─ Action: [Acknowledge] [Escalate] [Contain Agent]                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start: First Steps

### Immediate Actions (This Week)

1. **Clock Drift Protection**
   ```bash
   # Create time_guard.py
   # Integrate into boundary_daemon.py
   # Add tests for time manipulation
   ```

2. **Config Linter**
   ```bash
   # Create linter.py with basic rules
   # Add to daemon startup sequence
   # Create boundaryctl config lint command
   ```

3. **Terminal Dashboard MVP**
   ```bash
   pip install textual
   # Create basic dashboard.py
   # Show mode, events, alerts
   ```

### Next Sprint

4. **Code Signing**
5. **Query CLI**
6. **Merkle Tree Proofs**

---

## Conclusion

This roadmap transforms the Boundary ecosystem from a **strong security architecture** into an **industry-defining platform**:

- **Phase 1** closes all security gaps → Production-safe
- **Phase 2** achieves operational excellence → 5-star readiness
- **Phase 3** establishes thought leadership → Industry-first capabilities

The combination of Boundary Daemon + Boundary SIEM + Watchdog, enhanced with this roadmap, will represent the most comprehensive AI security platform available.

---

*Document Version: 1.0*
*Created: 2026-01-01*
*Classification: Internal Roadmap*
