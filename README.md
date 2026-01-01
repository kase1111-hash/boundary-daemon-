# Boundary Daemon - Agent Smith

**The Trust Policy & Audit Layer for Agent OS**

> *"If the Memory Vault is the safe, the Boundary Daemon is the armed guard + walls + air-gap switches."*

---

> ## ⚠️ Important: Understanding the Enforcement Model
>
> **This daemon provides policy decisions and audit logging, NOT runtime enforcement.**
>
> The Boundary Daemon is a **detection and audit system** that:
> - ✅ Monitors environment state (network, USB, processes, hardware)
> - ✅ Evaluates policies and returns allow/deny decisions
> - ✅ Logs all security events with tamper-evident hash chains
> - ✅ Detects violations and triggers alerts
>
> It does **NOT** (by default):
> - ❌ Block network connections at the OS level
> - ❌ Prevent memory access or file operations
> - ❌ Terminate processes or enforce lockdowns
>
> **NEW: Sandbox Module** - The daemon now includes an optional sandbox module that CAN:
> - ✅ Isolate processes via Linux namespaces (PID, network, mount)
> - ✅ Filter syscalls via seccomp-bpf
> - ✅ Enforce resource limits via cgroups v2
> - ✅ Integrate sandbox restrictions with boundary modes
>
> **External systems must voluntarily respect daemon decisions.** For additional enforcement, integrate with:
> - Kernel-level controls (SELinux, AppArmor)
> - Network firewalls (iptables/nftables)
> - Hardware controls
>
> See [ENFORCEMENT_MODEL.md](ENFORCEMENT_MODEL.md) for the complete security architecture.

---

## Overview

The Boundary Daemon, codenamed **Agent Smith**, is the policy decision and audit layer that defines and maintains trust boundaries for learning co-worker systems. It determines where cognition is allowed to flow and where it must stop, **but relies on cooperating systems to respect those decisions**.

### Role in Agent OS

Agent Smith serves as the **policy authority and audit system** - the decision-maker that determines what operations should be permitted within trust boundaries. It is:

- **Authoritative**: Provides canonical policy decisions that cooperating subsystems should respect
- **Omnipresent**: Monitors all environment changes continuously
- **Uncompromising**: Fails closed, never open
- **Persistent**: Maintains immutable audit trail

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Agent OS Ecosystem                      │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │Memory Vault  │  │  Agent-OS    │  │ synth-mind   │      │
│  │              │  │              │  │              │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                  │                  │              │
│         └──────────────────┼──────────────────┘              │
│                            │                                 │
│                            ▼                                 │
│         ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓            │
│         ┃   Boundary Daemon (Agent Smith)      ┃            │
│         ┃   ════════════════════════════       ┃            │
│         ┃   • State Monitor                    ┃            │
│         ┃   • Policy Engine                    ┃            │
│         ┃   • Tripwire System                  ┃            │
│         ┃   • Event Logger                     ┃            │
│         ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛            │
│                            │                                 │
│                            ▼                                 │
│              ┌──────────────────────────┐                    │
│              │   Environment Sensors    │                    │
│              │  Network│Hardware│Procs  │                    │
│              └──────────────────────────┘                    │
└─────────────────────────────────────────────────────────────┘
```

## Core Responsibilities

1. **Environment Sensing** - Detect current trust conditions
2. **Mode Enforcement** - Enforce boundary modes
3. **Recall Gating** - Permit or deny memory recall
4. **Execution Gating** - Restrict tools, IO, models
5. **Tripwire Response** - Lock down on violation
6. **Audit Signaling** - Emit immutable boundary events

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Start daemon in OPEN mode
python daemon/boundary_daemon.py

# Or start in AIRGAP mode
python daemon/boundary_daemon.py --mode=airgap

# Check status
./boundaryctl status

# Change mode
./boundaryctl set-mode restricted --reason "Starting work session"
```

## Boundary Modes

| Mode | Network | Memory Classes | Tools | Use Case |
|------|---------|----------------|-------|----------|
| **OPEN** | ✓ Online | 0-1 | All | Casual use |
| **RESTRICTED** | ✓ Online | 0-2 | Most | Research |
| **TRUSTED** | VPN only | 0-3 | No USB | Serious work |
| **AIRGAP** | ✗ Offline | 0-4 | No network | High-value IP |
| **COLDROOM** | ✗ Offline | 0-5 | Display only | Crown jewels |
| **LOCKDOWN** | ✗ Blocked | None | None | Emergency |

## Key Features

### Fail-Closed Security
- Ambiguous signals → DENY
- Daemon crash → LOCKDOWN
- Clock drift → Freeze transitions
- Unknown states → Block operation

### Immutable Audit Log
- Blockchain-style hash chain (SHA-256)
- Ed25519 cryptographic signatures
- Append-only log storage with chattr +a
- Tamper-evident and verifiable
- Complete audit trail

### Tripwire System
- Network in AIRGAP → LOCKDOWN
- USB in COLDROOM → LOCKDOWN
- Unauthorized recall → LOCKDOWN
- Daemon tampering → LOCKDOWN

### Human Override Ceremony
- Multi-step confirmation
- Mandatory cooldown delay
- Physical presence required
- Biometric verification support
- Immutably logged
- **No silent overrides. Ever.**

### Optional Enforcement (Linux)
- Network isolation via iptables/nftables
- USB device control via udev
- Process isolation via containers (podman/docker)
- AppArmor/SELinux profile management

### Process Sandboxing (New!)
- Linux namespace isolation (PID, network, mount, user, IPC)
- Seccomp-bpf syscall filtering with boundary mode profiles
- Cgroups v2 resource limits (CPU, memory, I/O, PIDs)
- **Per-sandbox iptables/nftables firewall rules** (cgroup-matched)
- Fine-grained network policy (allowed hosts, ports, CIDRs)
- Automatic sandbox profile selection based on boundary mode
- Ceremony integration for break-glass scenarios
- Defense in depth: namespace + firewall + seccomp combined

### Advanced Security Features
- Malware scanning (antivirus module)
- DNS/ARP/WiFi security monitoring
- Traffic anomaly detection
- File integrity monitoring
- Threat intelligence integration
- PII detection and filtering
- TPM integration for hardware security

### Robust Error Handling
- Categorized error types (security, network, auth, etc.)
- Automatic error aggregation and deduplication
- Retry logic with exponential backoff
- Cross-platform error normalization
- Recovery action suggestions

## Directory Structure

```
boundary-daemon/
├─ daemon/                    # Core daemon components
│  ├─ boundary_daemon.py          # Main service orchestrator
│  ├─ state_monitor.py            # Environment sensing
│  ├─ policy_engine.py            # Mode enforcement
│  ├─ tripwires.py                # Security violations
│  ├─ event_logger.py             # Immutable logging
│  ├─ integrations.py             # RecallGate, ToolGate, Ceremony
│  ├─ constants.py                # Centralized constants & config
│  ├─ health_monitor.py           # Daemon health checks
│  ├─ memory_monitor.py           # Memory usage tracking
│  ├─ resource_monitor.py         # Resource monitoring
│  ├─ queue_monitor.py            # Queue monitoring
│  ├─ privilege_manager.py        # Privilege management
│  ├─ signed_event_logger.py      # Cryptographic log signing
│  ├─ redundant_event_logger.py   # Redundant logging
│  │
│  ├─ auth/                       # Authentication & ceremony
│  │  ├─ api_auth.py                  # API authentication & rate limiting
│  │  ├─ enhanced_ceremony.py         # Human override ceremony
│  │  ├─ biometric_verifier.py        # Biometric authentication
│  │  ├─ secure_token_storage.py      # Token management
│  │  └─ persistent_rate_limiter.py   # Rate limiting
│  │
│  ├─ enforcement/                # Kernel-level enforcement
│  │  ├─ network_enforcer.py          # Network isolation via iptables
│  │  ├─ usb_enforcer.py              # USB device control
│  │  ├─ process_enforcer.py          # Process isolation & containers
│  │  ├─ secure_process_termination.py
│  │  ├─ secure_profile_manager.py    # AppArmor/SELinux profiles
│  │  └─ protection_persistence.py
│  │
│  ├─ security/                   # Multi-layer security
│  │  ├─ antivirus.py                 # Malware scanning
│  │  ├─ daemon_integrity.py          # Self-verification
│  │  ├─ dns_security.py              # DNS monitoring
│  │  ├─ arp_security.py              # ARP spoofing detection
│  │  ├─ wifi_security.py             # WiFi security monitoring
│  │  ├─ process_security.py          # Process anomaly detection
│  │  ├─ traffic_anomaly.py           # Network traffic analysis
│  │  ├─ file_integrity.py            # File change monitoring
│  │  ├─ code_advisor.py              # Code vulnerability scanning
│  │  ├─ threat_intel.py              # Threat intelligence
│  │  ├─ clock_monitor.py             # System clock verification
│  │  └─ secure_memory.py             # Memory protection
│  │
│  ├─ storage/                    # Data persistence
│  │  ├─ append_only.py               # Append-only log storage
│  │  └─ log_hardening.py             # Log security hardening
│  │
│  ├─ pii/                        # PII detection & filtering
│  │  ├─ detector.py                  # PII pattern detection
│  │  ├─ bypass_resistant_detector.py # Advanced PII detection
│  │  └─ filter.py                    # PII filtering/redaction
│  │
│  ├─ sandbox/                    # Process sandboxing
│  │  ├─ __init__.py                  # Module exports
│  │  ├─ namespace.py                 # Linux namespace isolation
│  │  ├─ seccomp_filter.py            # Seccomp-bpf syscall filtering
│  │  ├─ cgroups.py                   # Cgroups v2 resource limits
│  │  ├─ network_policy.py            # Per-sandbox iptables/nftables firewall
│  │  └─ sandbox_manager.py           # Policy-integrated sandbox orchestration
│  │
│  ├─ hardware/                   # Hardware integration
│  │  └─ tpm_manager.py               # TPM sealing & attestation
│  │
│  ├─ distributed/                # Multi-host deployment
│  │  ├─ cluster_manager.py           # Cluster coordination
│  │  └─ coordinators.py              # Distributed consensus
│  │
│  ├─ policy/                     # Custom policy engine
│  │  └─ custom_policy_engine.py      # Policy DSL & evaluation
│  │
│  ├─ watchdog/                   # Log monitoring
│  │  ├─ log_watchdog.py              # Log pattern detection
│  │  └─ hardened_watchdog.py         # Hardened watchdog
│  │
│  ├─ telemetry/                  # OpenTelemetry
│  │  └─ otel_setup.py                # OTEL instrumentation
│  │
│  ├─ utils/                      # Utilities
│  │  └─ error_handling.py            # Error handling framework
│  │
│  └─ config/                     # Configuration management
│     └─ secure_config.py             # Encrypted config handling
│
├─ api/                           # External interface
│  └─ boundary_api.py                 # Unix socket API + client
│
├─ tests/                         # Comprehensive test suite
│  ├─ test_*.py                       # Test modules
│  └─ conftest.py                     # Test fixtures
│
├─ logs/                          # Event logs
│  └─ boundary_chain.log              # Immutable hash-chained log
│
├─ config/                        # Configuration
│  ├─ boundary.conf                   # Daemon configuration
│  └─ boundary-daemon.service         # Systemd service
│
├─ systemd/                       # Systemd service files
│  ├─ boundary-daemon.service
│  └─ boundary-watchdog.service
│
├─ scripts/                       # Setup scripts
│  └─ setup-watchdog.sh
│
├─ CLI Tools
│  ├─ boundaryctl                     # Main control CLI
│  ├─ authctl                         # Authentication management
│  ├─ policy_ctl                      # Policy management
│  ├─ cluster_ctl                     # Cluster management
│  ├─ biometric_ctl                   # Biometric management
│  ├─ security_scan                   # Security scanning
│  └─ verify_signatures               # Signature verification
│
├─ requirements.txt               # Python dependencies
├─ setup.py                       # Installation script
│
└─ Documentation
   ├─ README.md                       # This file
   ├─ ARCHITECTURE.md                 # System architecture
   ├─ SPEC.md                         # Full specification
   ├─ INTEGRATION.md                  # Integration guide
   ├─ USAGE.md                        # Usage guide
   ├─ USER_GUIDE.md                   # User manual
   ├─ SECURITY.md                     # Security policies
   ├─ SECURITY_AUDIT.md               # Security audit
   ├─ ENFORCEMENT_MODEL.md            # Enforcement explanation
   └─ CHANGELOG.md                    # Change history
```

## Integration

### Memory Vault Integration

```python
from daemon.integrations import RecallGate
from daemon.policy_engine import MemoryClass

# Initialize recall gate
recall_gate = RecallGate(daemon)

# Check before retrieving memory
permitted, reason = recall_gate.check_recall(
    memory_class=MemoryClass.SECRET,
    memory_id="mem_12345"
)

if not permitted:
    raise PermissionError(f"Recall denied: {reason}")
```

### Agent-OS Tool Integration

```python
from daemon.integrations import ToolGate

# Initialize tool gate
tool_gate = ToolGate(daemon)

# Check before executing tool
permitted, reason = tool_gate.check_tool(
    tool_name='wget',
    requires_network=True
)

if not permitted:
    raise PermissionError(f"Tool execution denied: {reason}")
```

### Sandbox Integration

```python
from daemon.sandbox import SandboxManager, SandboxProfile, NetworkPolicy
from daemon.policy_engine import PolicyEngine, BoundaryMode

# Initialize with policy engine
policy_engine = PolicyEngine(initial_mode=BoundaryMode.RESTRICTED)
sandbox_manager = SandboxManager(policy_engine)

# Run untrusted code in policy-appropriate sandbox
result = sandbox_manager.run_sandboxed(
    command=["python3", "untrusted_script.py"],
    timeout=30,
)

print(f"Exit code: {result.exit_code}")
print(f"Output: {result.stdout}")

# Create sandbox with fine-grained network policy
profile = SandboxProfile(
    name="api-worker",
    network_policy=NetworkPolicy(
        allowed_hosts=["api.internal:443", "db.internal:5432"],
        allowed_cidrs=["10.0.0.0/8"],
        allow_dns=True,
        log_blocked=True,
    ),
)
sandbox = sandbox_manager.create_sandbox(name="worker-1", profile=profile)
sandbox.run(["./process_data.sh"])
sandbox.terminate()
```

### Unix Socket API

```bash
# Check recall permission
echo '{"command": "check_recall", "params": {"memory_class": 3}}' | \
    nc -U ./api/boundary.sock

# Change mode
echo '{"command": "set_mode", "params": {"mode": "airgap", "operator": "human"}}' | \
    nc -U ./api/boundary.sock
```

## CLI Usage

```bash
# Status and monitoring
boundaryctl status              # Show current status
boundaryctl watch               # Live status updates
boundaryctl events              # Show recent events
boundaryctl verify              # Verify log integrity

# Permission checks
boundaryctl check-recall 3      # Check memory class 3
boundaryctl check-tool wget --network  # Check network tool

# Mode management
boundaryctl set-mode airgap     # Change to AIRGAP mode
boundaryctl set-mode restricted --reason "Code review"
```

## Design Principles

1. **Authoritative** - Daemon decisions cannot be overridden programmatically
2. **Fail-Closed** - Uncertainty defaults to DENY
3. **Deterministic** - Same inputs always produce same decision
4. **Immutable Logging** - All events logged with tamper-evident chain
5. **Human Oversight** - Overrides require ceremony, never silent
6. **Minimal Dependencies** - Small attack surface by design

## Threat Model

### What This System Provides

| Capability | Description |
|------------|-------------|
| **Policy Decisions** | Canonical allow/deny verdicts for operations |
| **Audit Trail** | Immutable hash-chained log of all security events |
| **Violation Detection** | Identifies policy violations as they occur |
| **Environment Monitoring** | Continuous sensing of network, USB, processes |
| **Coordination Point** | Central authority for distributed policy queries |

### What This System Does NOT Provide

| Not Provided | Why |
|--------------|-----|
| **Runtime Enforcement** | Returns decisions but cannot block operations |
| **Process Isolation** | No sandboxing - requires external container/VM |
| **Network Blocking** | Detects but doesn't control network access |
| **Memory Protection** | Cannot prevent unauthorized memory reads |

### Security Architecture (Defense in Depth)

For actual security, deploy this daemon as **one layer** in a defense-in-depth strategy:

```
Layer 1: Kernel enforcement (SELinux, seccomp-bpf)     ← BLOCKS operations
Layer 2: Container isolation (namespaces, cgroups)     ← ISOLATES processes
Layer 3: This daemon (policy + logging)                ← DECIDES + LOGS
Layer 4: Application cooperation (Memory Vault, etc.)  ← RESPECTS decisions
Layer 5: Hardware controls (disabled USB, air-gap)     ← PHYSICAL security
```

**This daemon operates at Layer 3.** Without Layers 1-2, decisions are advisory only.

### Mitigations

| Risk | Mitigation | Enforcement Level |
|------|------------|-------------------|
| Boundary bypass | Mandatory hooks in cooperating systems | Application (voluntary) |
| Gradual erosion | Immutable audit logs | Detection only |
| Owner impatience | Ceremony + cooldown | Application (voluntary) |
| Supply-chain attack | Offline verification | Detection only |

## Non-Goals

- Performance optimization
- User convenience
- Stealth operation

**Security is allowed to be annoying.**

## System Requirements

- Python 3.9+ (supports 3.9, 3.10, 3.11, 3.12, 3.13)
- Linux (recommended for full enforcement) or Windows (monitoring mode)
- psutil, pynacl, cryptography libraries
- Root/sudo access (for system service and enforcement features)

### Platform Support

| Feature | Linux | Windows |
|---------|-------|---------|
| Core Daemon | Yes | Yes |
| Monitoring | Yes | Yes |
| Config Encryption | Yes | Yes |
| Cryptographic Logging | Yes | Yes |
| Network Enforcement | Yes | No |
| USB Enforcement | Yes | No |
| Process Enforcement | Yes | No |
| Watchdog Service | Yes | No |

## Installation

### Development Mode

```bash
git clone <repository>
cd boundary-daemon
pip install -r requirements.txt
pip install -e .
```

### System Service

```bash
# Install
sudo python setup.py install

# Copy service file
sudo cp config/boundary-daemon.service /etc/systemd/system/

# Create directories
sudo mkdir -p /var/log/boundary-daemon
sudo mkdir -p /var/run/boundary-daemon

# Enable and start
sudo systemctl enable boundary-daemon
sudo systemctl start boundary-daemon
```

## Testing

```bash
# Test state monitor
python daemon/state_monitor.py

# Test policy engine
python daemon/policy_engine.py

# Test tripwires
python daemon/tripwires.py

# Test event logger
python daemon/event_logger.py

# Test API client
python api/boundary_api.py
```

## Documentation

- **[SPEC.md](SPEC.md)** - Complete technical specification
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture and design
- **[INTEGRATION.md](INTEGRATION.md)** - Integration guide for Agent OS components
- **[USAGE.md](USAGE.md)** - Usage guide and common workflows
- **[USER_GUIDE.md](USER_GUIDE.md)** - Comprehensive user manual
- **[SECURITY.md](SECURITY.md)** - Security policies and practices
- **[SECURITY_AUDIT.md](SECURITY_AUDIT.md)** - Security audit findings
- **[ENFORCEMENT_MODEL.md](ENFORCEMENT_MODEL.md)** - Understanding the enforcement model
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and changes

## Planned Features (TODO)

### Tier 2: Cover Gaps (Without Losing Edge)

#### SIEM Integration
*Feed SIEMs, don't replace them*

- [x] CEF/LEEF export (Splunk/QRadar/ArcSight)
- [x] Kafka producer, S3/GCS log shipping
- [x] Signature verification API for SIEMs

#### Identity Federation
*External identity is advisory*

- [x] OIDC token validation → local capabilities
- [x] LDAP group mapping
- [x] PAM integration
- [x] Ceremonies still required for sensitive ops

#### Compliance Automation

- [x] NIST 800-53 / ISO 27001 control mapping export
- [x] Self-contained evidence bundles for auditors
- [x] Access review ceremonies

### Tier 3: Selective Enhancement

#### Deterministic Threat Detection (No ML)

- [x] YARA rule engine
- [x] Sigma rule support
- [x] Signed IOC feeds
- [x] MITRE ATT&CK patterns as deterministic rules

#### eBPF Observability (Optional Module)

- [x] Kernel visibility without kernel driver
- [x] Read-only observation for policy decisions
- [x] Graceful degradation on older kernels

#### Process Sandboxing (New!)

- [x] Linux namespace isolation (PID, network, mount, user, IPC, UTS)
- [x] Seccomp-bpf syscall filtering with pre-built profiles
- [x] Cgroups v2 resource limits (CPU, memory, I/O, PIDs)
- [x] Boundary mode integration (profile auto-selection)
- [x] Ceremony integration for break-glass scenarios
- [x] Policy engine integration for sandbox decisions
- [x] Per-sandbox iptables/nftables firewall (cgroup-matched)
- [x] Fine-grained network policy (hosts, ports, CIDRs)

---

## Contributing

This is a security-critical component. Contributions must:

1. Maintain fail-closed semantics
2. Preserve immutable logging
3. Not introduce convenience features that weaken security
4. Include comprehensive tests
5. Be reviewed by security team

## License

MIT License (see LICENSE file)

## Design Constraint

> *"If the system cannot clearly answer 'where am I allowed to think right now?' it is not safe to think at all."*

The Boundary Daemon exists to answer that question.

---

## Agent Smith's Motto

**"Never compromise. Not even in the face of Armageddon."**

The Boundary Daemon is the guard. It determines where cognition flows and where it stops. Respect the boundaries.
