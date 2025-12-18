# Boundary Daemon - Agent Smith

**The Trust Enforcement Layer for Agent OS**

> *"If the Memory Vault is the safe, the Boundary Daemon is the armed guard + walls + air-gap switches."*

## Overview

The Boundary Daemon, codenamed **Agent Smith**, is the mandatory hard enforcement layer that defines and maintains trust boundaries for learning co-worker systems. It determines where cognition is allowed to flow and where it must stop.

### Role in Agent OS

Agent Smith serves as the **security enforcer** - the guardian that ensures the system operates within its trust boundaries. Like its namesake from The Matrix, it is:

- **Authoritative**: Other subsystems must not override it
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

### 🛡️ Fail-Closed Security
- Ambiguous signals → DENY
- Daemon crash → LOCKDOWN
- Clock drift → Freeze transitions
- Unknown states → Block operation

### 🔗 Immutable Audit Log
- Blockchain-style hash chain
- Tamper-evident event log
- Verifiable integrity
- Complete audit trail

### 🚨 Tripwire System
- Network in AIRGAP → LOCKDOWN
- USB in COLDROOM → LOCKDOWN
- Unauthorized recall → LOCKDOWN
- Daemon tampering → LOCKDOWN

### 🎭 Human Override Ceremony
- Multi-step confirmation
- Mandatory cooldown delay
- Physical presence required
- Immutably logged
- **No silent overrides. Ever.**

## Directory Structure

```
boundary-daemon/
├─ daemon/              # Core daemon components
│  ├─ boundary_daemon.py    # Main service orchestrator
│  ├─ state_monitor.py      # Environment sensing
│  ├─ policy_engine.py      # Mode enforcement
│  ├─ tripwires.py          # Security violations
│  ├─ event_logger.py       # Immutable logging
│  └─ integrations.py       # RecallGate, ToolGate, Ceremony
│
├─ api/                 # External interface
│  └─ boundary_api.py       # Unix socket API + client
│
├─ logs/                # Event logs
│  └─ boundary_chain.log    # Immutable hash-chained log
│
├─ config/              # Configuration
│  ├─ boundary.conf         # Daemon configuration
│  └─ boundary-daemon.service  # Systemd service
│
├─ boundaryctl          # CLI control tool
├─ requirements.txt     # Python dependencies
├─ setup.py            # Installation script
│
└─ docs/
   ├─ specs.md         # Full specification
   ├─ INTEGRATION.md   # Integration guide
   └─ USAGE.md         # Usage guide
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

### Protected Against

- Remote attackers (network-based)
- Local malware (process monitoring)
- Rogue agents (mandatory gating)
- Accidental misuse (fail-closed design)
- Gradual erosion (immutable logs)
- Supply chain attacks (offline verification)

### Adversaries

- Remote attackers
- Local malware
- Rogue agents
- Accidental owner misuse

### Mitigations

| Risk | Mitigation |
|------|------------|
| Boundary bypass | Mandatory hooks |
| Gradual erosion | Immutable logs |
| Owner impatience | Ceremony + cooldown |
| Supply-chain attack | Offline verification |

## Non-Goals

- Performance optimization
- User convenience
- Stealth operation

**Security is allowed to be annoying.**

## System Requirements

- Python 3.8+
- Linux (systemd for service mode)
- psutil library
- Root/sudo access (for system service)

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

- **[specs.md](specs.md)** - Complete technical specification
- **[INTEGRATION.md](INTEGRATION.md)** - Integration guide for Agent OS components
- **[USAGE.md](USAGE.md)** - User guide and common workflows

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
