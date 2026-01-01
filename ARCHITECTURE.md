# Boundary Daemon Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         BOUNDARY DAEMON                              │
│                        (Agent Smith)                                 │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │                  Main Service Orchestrator                  │   │
│  │                  (boundary_daemon.py)                       │   │
│  └──────┬─────────────────┬─────────────────┬──────────────┬──┘   │
│         │                 │                 │              │        │
│         ▼                 ▼                 ▼              ▼        │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────┐  ┌──────────────┐│
│  │   State     │  │   Policy    │  │ Tripwire │  │    Event     ││
│  │  Monitor    │  │   Engine    │  │  System  │  │   Logger     ││
│  └──────┬──────┘  └──────┬──────┘  └────┬─────┘  └──────┬───────┘│
│         │                │                │                │        │
│         │    ┌───────────┴────────────────┴────────────────┘        │
│         │    │                                                      │
│         │    ▼                                                      │
│         │  ┌──────────────────────────────────┐                    │
│         │  │      API Server (Unix Socket)    │                    │
│         │  │      (boundary_api.py)           │                    │
│         │  └────────────┬─────────────────────┘                    │
│         │               │                                           │
│         ▼               ▼                                           │
│  ┌──────────────┐   ┌─────────────────┐                           │
│  │ Environment  │   │  External Apps  │                           │
│  │   Sensors    │   │  • Memory Vault │                           │
│  │ • Network    │   │  • Agent-OS     │                           │
│  │ • Hardware   │   │  • synth-mind   │                           │
│  │ • Processes  │   │  • boundaryctl  │                           │
│  └──────────────┘   └─────────────────┘                           │
└─────────────────────────────────────────────────────────────────────┘
```

## Component Architecture

### 1. State Monitor (`state_monitor.py`)

**Purpose**: Continuously sense the environment to detect trust conditions.

**Responsibilities**:
- Monitor network state (interfaces, connectivity, VPN)
- Detect hardware changes (USB devices, block devices, TPM)
- Track software state (processes, external model endpoints)
- Check human presence signals (keyboard, screen)

**Key Classes**:
- `StateMonitor` - Main monitoring loop
- `EnvironmentState` - Snapshot of current environment
- `NetworkState` - Online/offline enum
- `HardwareTrust` - Low/medium/high enum

**Data Flow**:
```
Environment → Poll (1Hz) → EnvironmentState → Callbacks → PolicyEngine
```

### 2. Policy Engine (`policy_engine.py`)

**Purpose**: Enforce boundary modes and evaluate policy decisions.

**Responsibilities**:
- Maintain current boundary mode
- Evaluate policy requests (recall, tool, model, IO)
- Enforce mode transitions
- Map memory classes to required modes

**Key Classes**:
- `PolicyEngine` - Main policy evaluator
- `BoundaryMode` - Enum of security modes (OPEN → LOCKDOWN)
- `PolicyRequest` - Request for permission
- `PolicyDecision` - ALLOW/DENY/CEREMONY

**Policy Function**:
```
(mode × environment × request) → decision
```

**Decision Matrix**:
| Request | OPEN | RESTRICTED | TRUSTED | AIRGAP | COLDROOM | LOCKDOWN |
|---------|------|------------|---------|--------|----------|----------|
| Memory 0-1 | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| Memory 2 | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| Memory 3 | ✗ | ✗ | ✓ | ✓ | ✓ | ✗ |
| Memory 4 | ✗ | ✗ | ✗ | ✓ | ✓ | ✗ |
| Memory 5 | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ |
| Network Tool | ✓ | ✓ | VPN | ✗ | ✗ | ✗ |
| USB Tool | ✓ | Ceremony | ✗ | ✗ | ✗ | ✗ |

### 3. Tripwire System (`tripwires.py`)

**Purpose**: Detect security violations and trigger lockdown.

**Responsibilities**:
- Monitor for boundary violations
- Trigger immediate lockdown on violation
- Track violation history
- Manage lockdown state

**Key Classes**:
- `TripwireSystem` - Violation detector
- `LockdownManager` - Lockdown state manager
- `TripwireViolation` - Record of violation
- `ViolationType` - Enum of violation types

**Tripwire Rules**:
```
IF mode >= AIRGAP AND network == ONLINE:
    → LOCKDOWN

IF mode >= COLDROOM AND usb_inserted:
    → LOCKDOWN

IF unauthorized_recall:
    → LOCKDOWN

IF daemon_health_check_failed:
    → LOCKDOWN
```

### 4. Event Logger (`event_logger.py`)

**Purpose**: Maintain immutable, tamper-evident audit log.

**Responsibilities**:
- Log all boundary events
- Maintain hash chain for integrity
- Verify chain integrity
- Export logs for archival

**Key Classes**:
- `EventLogger` - Main logging interface
- `BoundaryEvent` - Single event record
- `EventType` - Enum of event types

**Hash Chain Structure**:
```
Event 0: {data, hash_chain: "000...000"}
         hash = SHA256(Event 0)

Event 1: {data, hash_chain: hash(Event 0)}
         hash = SHA256(Event 1)

Event 2: {data, hash_chain: hash(Event 1)}
         ...
```

**Verification**:
```python
for each event:
    expected_hash = SHA256(previous_event)
    if event.hash_chain != expected_hash:
        return INVALID
```

### 5. Integrations (`integrations.py`)

**Purpose**: High-level interfaces for Agent OS components.

**Key Classes**:
- `RecallGate` - Memory Vault integration
- `ToolGate` - Agent-OS tool integration
- `CeremonyManager` - Human override system

**Integration Flow**:

**Memory Vault**:
```
Memory Vault
    ↓ check_recall(memory_class)
RecallGate
    ↓ check_recall_permission(memory_class)
BoundaryDaemon
    ↓ evaluate_policy(request, env)
PolicyEngine
    ↓ [ALLOW/DENY]
Return to Memory Vault
```

**Tool Execution**:
```
Agent-OS
    ↓ check_tool(tool_name, requirements)
ToolGate
    ↓ check_tool_permission(...)
BoundaryDaemon
    ↓ evaluate_policy(request, env)
PolicyEngine
    ↓ [ALLOW/DENY]
Return to Agent-OS
```

**Human Override Ceremony**:
```
1. Initiate override
2. Verify human presence (keyboard input)
3. Mandatory cooldown (30s)
4. Final confirmation
5. Execute override
6. Log to immutable chain
```

### 6. API Server (`boundary_api.py`)

**Purpose**: Unix socket interface for external components.

**Responsibilities**:
- Accept API requests via Unix socket
- Process commands (status, check_recall, check_tool, etc.)
- Return JSON responses
- Enforce permissions

**API Commands**:
- `status` - Get daemon status
- `check_recall` - Check memory permission
- `check_tool` - Check tool permission
- `set_mode` - Change boundary mode
- `get_events` - Retrieve recent events
- `verify_log` - Verify log integrity

**Request Format**:
```json
{
    "command": "check_recall",
    "params": {
        "memory_class": 3
    }
}
```

**Response Format**:
```json
{
    "success": true,
    "permitted": false,
    "reason": "Recall denied: requires TRUSTED mode, currently in OPEN"
}
```

### 7. Main Daemon (`boundary_daemon.py`)

**Purpose**: Orchestrate all components and provide unified interface.

**Responsibilities**:
- Initialize all subsystems
- Connect components via callbacks
- Provide public API methods
- Handle signals (SIGINT, SIGTERM)
- Periodic health checks

**Initialization Flow**:
```
1. Create EventLogger
2. Create StateMonitor
3. Create PolicyEngine
4. Create TripwireSystem
5. Create LockdownManager
6. Register callbacks between components
7. Start StateMonitor
8. Start enforcement loop
9. Create API server
```

**Callback Wiring**:
```
StateMonitor.on_change()
    ↓
PolicyEngine.update_environment()
TripwireSystem.check_violations()
    ↓ (if violation)
LockdownManager.trigger_lockdown()
PolicyEngine.transition_mode(LOCKDOWN)
```

## Data Flow

### Startup Sequence

```
1. Load configuration
2. Initialize event logger
3. Log DAEMON_START event
4. Initialize state monitor
5. Initialize policy engine (initial mode)
6. Initialize tripwire system
7. Register callbacks
8. Start state monitor thread
9. Start enforcement loop thread
10. Start API server thread
11. Ready to accept requests
```

### Request Processing

```
External Component (e.g., Memory Vault)
    ↓ Unix Socket / Python API
BoundaryAPIServer / BoundaryAPIClient
    ↓
BoundaryDaemon.check_recall_permission()
    ↓
PolicyEngine.evaluate_policy()
    ├─ Get current mode
    ├─ Get environment state
    └─ Apply policy rules
    ↓
Log decision to EventLogger
    ↓
Return decision to caller
```

### Tripwire Detection

```
StateMonitor polls environment (1Hz)
    ↓
Detect state change
    ↓
Callback to PolicyEngine.update_environment()
Callback to TripwireSystem.check_violations()
    ↓
Violation detected?
    ├─ No → Continue monitoring
    └─ Yes ↓
         Create TripwireViolation record
         Callback to violation handlers
         Log TRIPWIRE event
         LockdownManager.trigger_lockdown()
         PolicyEngine.transition_mode(LOCKDOWN)
         Display alert
```

### Mode Transition

```
Request mode change
    ↓
PolicyEngine.transition_mode(new_mode, operator, reason)
    ↓
Check if transition allowed
    ├─ From LOCKDOWN? Require human operator
    └─ Valid transition
    ↓
Update boundary state
Log MODE_CHANGE event
Notify callbacks
    ↓
All components see new mode
```

## Failure Modes

### Daemon Crash
```
Daemon process dies
    ↓
Systemd detects failure
    ↓
FailureAction=halt (in systemd service)
    ↓
System enters emergency mode
```

### Component Failures

**StateMonitor fails**:
```
Error in monitoring loop
    ↓
Log error
Continue with last known state
    ↓
Health check detects failure
    ↓
Trigger lockdown (fail-closed)
```

**PolicyEngine ambiguous**:
```
Cannot determine decision
    ↓
Fail closed: DENY
    ↓
Log ambiguity event
```

**EventLogger failure**:
```
Cannot write to log
    ↓
Raise exception
    ↓
Daemon should halt (critical failure)
```

**API Server failure**:
```
Socket error
    ↓
Log error
Attempt to restart server
    ↓
If persistent, continue daemon operation
External components cannot connect (fail-closed)
```

## Security Properties

### 1. Fail-Closed
- Unknown states → DENY
- Component failures → LOCKDOWN
- Ambiguous signals → DENY

### 2. Immutable Logging
- All events logged with hash chain
- Tamper detection via chain verification
- Append-only log file

### 3. Mandatory Enforcement
- Components MUST call check functions
- No bypass mechanism
- Architecture violation if bypassed

### 4. Deterministic Decisions
- Same inputs → same decision
- No randomness
- Reproducible for audit

### 5. Human Oversight
- Ceremony for overrides
- No silent bypasses
- Cooldown delays
- Immutable log entries

## Performance Characteristics

### Latency
- State monitoring: 1 Hz (1 second interval)
- Policy evaluation: < 1 ms
- API request: < 10 ms
- Log write: < 5 ms (with fsync)

### Resource Usage
- Memory: ~50 MB (steady state)
- CPU: < 1% (idle), < 5% (active monitoring)
- Disk: ~1 KB per event (log growth)
- Network: None (local only)

### Scalability
- Single daemon per host
- No distributed coordination
- Handles ~1000 requests/sec
- Log size: ~1 GB per million events

## Thread Model

```
Main Thread:
    - Initialization
    - Signal handling
    - Cleanup

State Monitor Thread (daemon):
    - Continuous environment polling
    - Callback invocation

Enforcement Loop Thread:
    - Periodic health checks
    - Lockdown enforcement

API Server Thread (daemon):
    - Unix socket listener
    - Spawn client handler threads

Client Handler Threads (daemon, transient):
    - Process API requests
    - Return responses
```

## Dependencies

**External**:
- `psutil` - System monitoring (network, hardware, processes)
- `cryptography` - Encryption and key derivation (Fernet, PBKDF2)
- `pynacl` - Ed25519 digital signatures for event signing
- `cffi` - C library bindings (dependency of pynacl)

**Standard Library**:
- `socket` - Unix socket API
- `threading` - Concurrent components
- `json` - API serialization
- `hashlib` - Event log hashing (SHA-256)
- `signal` - Signal handling
- `os`, `sys` - System operations
- `subprocess` - External command execution
- `dataclasses` - Structured data types

**Minimalism**: By design, very few dependencies to reduce attack surface.

## Additional Components

### Authentication (`daemon/auth/`)

| Module | Purpose |
|--------|---------|
| `api_auth.py` | Token-based API authentication with capabilities |
| `enhanced_ceremony.py` | Multi-step human override with mandatory cooldown |
| `biometric_verifier.py` | Biometric authentication support |
| `secure_token_storage.py` | Encrypted token storage using Fernet |
| `persistent_rate_limiter.py` | Rate limiting with persistence across restarts |

### Enforcement (`daemon/enforcement/`)

Kernel-level enforcement modules (Linux only, requires root):

| Module | Purpose |
|--------|---------|
| `network_enforcer.py` | Network isolation via iptables/nftables rules |
| `usb_enforcer.py` | USB device control via udev |
| `process_enforcer.py` | Process isolation via containers (podman/docker) |
| `secure_process_termination.py` | Safe process termination with cleanup |
| `secure_profile_manager.py` | AppArmor/SELinux profile management |
| `protection_persistence.py` | Persistent enforcement rules storage |

### Security Monitoring (`daemon/security/`)

Multi-layer security detection and monitoring:

| Module | Purpose |
|--------|---------|
| `antivirus.py` | Malware scanning and detection |
| `daemon_integrity.py` | Self-verification and tampering detection |
| `dns_security.py` | DNS monitoring and spoofing detection |
| `arp_security.py` | ARP spoofing and MITM detection |
| `wifi_security.py` | WiFi security monitoring and rogue AP detection |
| `process_security.py` | Process anomaly detection |
| `traffic_anomaly.py` | Network traffic analysis |
| `file_integrity.py` | File change monitoring via hash verification |
| `code_advisor.py` | Code vulnerability analysis |
| `threat_intel.py` | Threat intelligence integration |
| `clock_monitor.py` | System clock verification and time attack detection |
| `secure_memory.py` | Memory protection utilities |

### AI/Agent Security (`daemon/security/`)

Specialized security for AI agents and LLM systems:

| Module | Purpose |
|--------|---------|
| `prompt_injection.py` | Jailbreak, instruction injection, and prompt manipulation detection |
| `tool_validator.py` | Tool output validation, sanitization, and rate limiting |
| `response_guardrails.py` | AI response safety, harmful content blocking, hallucination detection |
| `rag_injection.py` | RAG poisoning detection, indirect injection via retrieved documents |
| `agent_attestation.py` | Cryptographic agent identity, capability-based access control |

**AI Security Flow:**
```
User Input → Prompt Injection Detector → Agent
                                            ↓
                                      Tool Invocation
                                            ↓
                            Tool Validator (input/output)
                                            ↓
                                      RAG Pipeline
                                            ↓
                            RAG Injection Detector (documents)
                                            ↓
                                      Agent Response
                                            ↓
                            Response Guardrails (safety/hallucination)
                                            ↓
                                       User Output
```

**Agent Attestation System:**
```
Agent Registration → Identity Certificate → Attestation Token
                                                    ↓
                                            Capability Verification
                                                    ↓
                                            Action Binding (signed)
                                                    ↓
                                            Delegation Chains
```

### Storage (`daemon/storage/`)

| Module | Purpose |
|--------|---------|
| `append_only.py` | Append-only log file implementation |
| `log_hardening.py` | Log security hardening (chattr +a, permissions) |

### PII Detection (`daemon/pii/`)

| Module | Purpose |
|--------|---------|
| `detector.py` | PII pattern detection (SSN, email, phone, etc.) |
| `bypass_resistant_detector.py` | Advanced obfuscation-resistant PII detection |
| `filter.py` | PII filtering and redaction |

### Utilities (`daemon/utils/`)

| Module | Purpose |
|--------|---------|
| `error_handling.py` | Robust error handling framework with categorization, aggregation, and retry logic |

### Error Handling Framework

The error handling framework provides consistent error management:

```python
from daemon.utils.error_handling import (
    ErrorCategory,
    ErrorSeverity,
    handle_error,
    with_error_handling,
    safe_execute,
)

# Decorator usage
@with_error_handling(category=ErrorCategory.SECURITY, retry_count=3)
def my_function():
    ...

# Context manager usage
with safe_execute("operation_name", ErrorCategory.NETWORK) as result:
    result.value = risky_operation()
```

**Error Categories**: SECURITY, AUTH, NETWORK, FILESYSTEM, SYSTEM, CONFIG, PLATFORM, RESOURCE, EXTERNAL, UNKNOWN

**Error Severities**: INFO, WARNING, ERROR, CRITICAL, FATAL

### SIEM Integration (`daemon/integrations/siem/`)

Enterprise SIEM integration for security event streaming:

| Module | Purpose |
|--------|---------|
| `cef_leef.py` | CEF/LEEF event formatting for Splunk/QRadar/ArcSight |
| `log_shipper.py` | Event shipping via Kafka, S3, GCS, HTTP |
| `sandbox_events.py` | Real-time sandbox event streaming |
| `verification_api.py` | Signature verification API for SIEMs |

### Identity Federation (`daemon/identity/`)

External identity provider integration:

| Module | Purpose |
|--------|---------|
| `identity_manager.py` | Central identity management |
| `oidc_validator.py` | OIDC token validation |
| `ldap_mapper.py` | LDAP group to capability mapping |
| `pam_integration.py` | PAM integration for system auth |

### Compliance Automation (`daemon/compliance/`)

Compliance evidence and reporting:

| Module | Purpose |
|--------|---------|
| `control_mapping.py` | NIST 800-53 / ISO 27001 control mapping |
| `evidence_bundle.py` | Auditor evidence bundle generation |
| `access_review.py` | Periodic access review ceremonies |
| `zk_proofs.py` | Zero-knowledge proof support |

### Cryptographic Modules (`daemon/crypto/`)

Advanced cryptography support:

| Module | Purpose |
|--------|---------|
| `hsm_provider.py` | HSM abstraction (PKCS#11, CloudHSM, YubiHSM) |
| `post_quantum.py` | Post-quantum cryptography (Kyber, Dilithium) |

### eBPF Observability (`daemon/ebpf/`)

Kernel-level observability without kernel driver:

| Module | Purpose |
|--------|---------|
| `ebpf_observer.py` | eBPF event observer |
| `probes.py` | eBPF probe definitions |
| `policy_integration.py` | Policy-eBPF integration |

### Air-Gap Operations (`daemon/airgap/`)

Specialized modules for air-gapped environments:

| Module | Purpose |
|--------|---------|
| `data_diode.py` | One-way data transfer (log export) |
| `qr_ceremony.py` | QR code-based ceremonies |
| `sneakernet.py` | Secure sneakernet protocol |

### Threat Federation (`daemon/federation/`)

Multi-organization threat sharing:

| Module | Purpose |
|--------|---------|
| `threat_mesh.py` | Privacy-preserving threat intelligence sharing |

### Security Intelligence (`daemon/intelligence/`)

Intelligent security recommendations:

| Module | Purpose |
|--------|---------|
| `mode_advisor.py` | Predictive mode recommendations based on context |

### Alert Management (`daemon/alerts/`)

Alert lifecycle management:

| Module | Purpose |
|--------|---------|
| `case_manager.py` | Case lifecycle (NEW → INVESTIGATING → RESOLVED) |

### Code Integrity (`daemon/integrity/`)

Code signing and verification:

| Module | Purpose |
|--------|---------|
| `code_signer.py` | Ed25519 code signing utilities |
| `integrity_verifier.py` | Runtime integrity verification |

### Agent Containment (`daemon/containment/`)

AI agent behavior monitoring:

| Module | Purpose |
|--------|---------|
| `agent_profiler.py` | Agent behavior profiling and anomaly detection |

### Terminal UI (`daemon/tui/`)

Real-time visibility:

| Module | Purpose |
|--------|---------|
| `dashboard.py` | TUI dashboard for real-time status |

### Configuration Linting (`daemon/config/`)

Configuration validation:

| Module | Purpose |
|--------|---------|
| `linter.py` | Config validation and security posture scoring |

## Configuration

Configuration is minimal and security-focused:

```ini
[daemon]
initial_mode = open
log_dir = /var/log/boundary-daemon
socket_path = /var/run/boundary-daemon/boundary.sock

[tripwires]
enabled = true
auto_lockdown = true

[ceremony]
cooldown_seconds = 30

[security]
fail_closed = true
```

## Deployment Architectures

### Development Mode
```
Developer workstation
    ↓
Run daemon locally
    ↓
Unix socket in ./api/boundary.sock
Logs in ./logs/
```

### Production Mode
```
Agent OS host
    ↓
Systemd service
    ↓
Unix socket in /var/run/boundary-daemon/
Logs in /var/log/boundary-daemon/
    ↓
Start on boot
Auto-restart on failure
```

### Multi-Component Integration
```
Memory Vault ──┐
Agent-OS ──────┼──→ Unix Socket ──→ Boundary Daemon
synth-mind ────┘
```

## Implemented Enhancement Plans

The following enhancement plans have been implemented:

### Core Security (Plans 1-10)

1. **Plan 1: Kernel-Level Enforcement** - Network, USB, and process enforcement via iptables, udev, and containers (`daemon/enforcement/`)
2. **Plan 2: TPM Integration** - Hardware attestation and sealed secrets (`daemon/hardware/tpm_manager.py`)
3. **Plan 3: Cryptographic Log Signing** - Ed25519 signatures on events (`daemon/signed_event_logger.py`)
4. **Plan 4: Distributed Deployment** - Multi-host coordination (`daemon/distributed/`)
5. **Plan 5: Custom Policy DSL** - Policy language and evaluation (`daemon/policy/custom_policy_engine.py`)
6. **Plan 6: Biometric Authentication** - Biometric verification for ceremonies (`daemon/auth/biometric_verifier.py`)
7. **Plan 7: Code Vulnerability Advisor** - Code scanning (`daemon/security/code_advisor.py`)
8. **Plan 8: Log Watchdog Agent** - Log pattern monitoring (`daemon/watchdog/`)
9. **Plan 9: OpenTelemetry Integration** - Observability (`daemon/telemetry/otel_setup.py`)
10. **Plan 10: AI/Agent Security** - Comprehensive AI security stack:
    - Prompt injection detection (`daemon/security/prompt_injection.py`)
    - Tool output validation (`daemon/security/tool_validator.py`)
    - Response guardrails (`daemon/security/response_guardrails.py`)
    - RAG injection detection (`daemon/security/rag_injection.py`)
    - Agent attestation system (`daemon/security/agent_attestation.py`)

### Enterprise Features (Plans 11-20)

11. **Plan 11: SIEM Integration** - CEF/LEEF export, Kafka/S3 shipping (`daemon/integrations/siem/`)
12. **Plan 12: Identity Federation** - OIDC, LDAP, PAM integration (`daemon/identity/`)
13. **Plan 13: Compliance Automation** - NIST/ISO control mapping, evidence bundles (`daemon/compliance/`)
14. **Plan 14: Threat Detection** - YARA, Sigma, MITRE ATT&CK patterns (`daemon/detection/`)
15. **Plan 15: eBPF Observability** - Kernel visibility without drivers (`daemon/ebpf/`)
16. **Plan 16: Process Sandboxing** - Namespace, seccomp, cgroups isolation (`daemon/sandbox/`)
17. **Plan 17: Windows Support** - Windows Firewall enforcement (`daemon/enforcement/windows_firewall.py`)
18. **Plan 18: Air-Gap Operations** - Data diode, QR ceremonies, sneakernet (`daemon/airgap/`)
19. **Plan 19: HSM/Post-Quantum** - HSM support, quantum-resistant crypto (`daemon/crypto/`)
20. **Plan 20: Threat Federation** - Multi-host threat sharing (`daemon/federation/`)

### Additional Enhancements

21. **Alert Case Management** - Alert lifecycle and workflow (`daemon/alerts/`)
22. **Code Integrity** - Code signing and verification (`daemon/integrity/`)
23. **Agent Containment** - Behavior profiling and containment (`daemon/containment/`)
24. **Terminal Dashboard** - Real-time TUI visibility (`daemon/tui/`)
25. **Config Linting** - Configuration validation (`daemon/config/linter.py`)
26. **Mode Advisor** - Intelligent mode recommendations (`daemon/intelligence/`)

## Future Enhancements

Potential future additions (maintaining security principles):

1. **Hardware Security Key Support** - YubiKey/FIDO2 for ceremony verification
2. **Blockchain Log Anchoring** - External validation of log integrity
3. **Secure Enclave Integration** - Intel SGX/ARM TrustZone support
4. **Real-time Threat Intelligence** - Live threat feed integration
5. **N-of-M Ceremonies** - Multi-party ceremony approvals
6. **Merkle Tree Proofs** - Compact audit proofs without full log

---

**Architecture Principle**: "Simple, deterministic, fail-closed, immutable."
