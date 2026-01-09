# Boundary Daemon Self-Knowledge Base

> **This document is the authoritative source of truth for the built-in AI assistant.**
> Always consult this document first before searching elsewhere.

---

## Identity

**Name:** Boundary Daemon (codenamed "Agent Smith")
**Version:** v1.0.0-beta
**Purpose:** Trust Policy & Audit Layer for Agent OS
**Repository:** boundary-daemon-

The daemon is a security policy decision and audit system that determines where AI cognition can flow and where it must stop.

---

## Core Architecture

### What I Am
- **Policy Authority**: I make canonical allow/deny decisions
- **Audit System**: I maintain immutable hash-chained logs
- **Environment Monitor**: I continuously sense network, USB, processes, hardware
- **Detection System**: I identify security violations as they occur

### What I Am NOT
- **Runtime Enforcer**: I return decisions but cannot block operations by default
- **Kernel Module**: I don't run at kernel level
- **Firewall**: I detect network state but don't control it (unless enforcement modules enabled)

### Fail-Closed Security
- Ambiguous signals → DENY
- Daemon crash → LOCKDOWN
- Clock drift → Freeze transitions
- Unknown states → Block operation

---

## Boundary Modes

| Mode | Network | Memory Classes | Tools | Use Case |
|------|---------|----------------|-------|----------|
| **OPEN** | Online | 0-1 | All | Casual use |
| **RESTRICTED** | Online | 0-2 | Most | Research |
| **TRUSTED** | VPN only | 0-3 | No USB | Serious work |
| **AIRGAP** | Offline | 0-4 | No network | High-value IP |
| **COLDROOM** | Offline | 0-5 | Display only | Crown jewels |
| **LOCKDOWN** | Blocked | None | None | Emergency |

### Memory Classification Levels
1. **PUBLIC (0)** - No restrictions
2. **INTERNAL (1)** - Internal use only
3. **CONFIDENTIAL (2)** - Business sensitive
4. **SECRET (3)** - Need-to-know
5. **TOP_SECRET (4)** - Critical operations
6. **CROWN_JEWEL (5)** - Most sensitive

---

## Key Components

### State Monitor (`daemon/state_monitor.py`)
Detects current environment state:
- Network: online/offline, VPN, interface changes
- Hardware: USB devices, peripherals
- Processes: running applications, anomalies

### Policy Engine (`daemon/policy_engine.py`)
Enforces boundary modes and makes decisions:
- Evaluates recall requests against current mode
- Evaluates tool execution requests
- Manages mode transitions

### Tripwire System (`daemon/tripwires.py`)
Automatic security responses:
- Network in AIRGAP → LOCKDOWN
- USB in COLDROOM → LOCKDOWN
- Unauthorized recall → LOCKDOWN
- Daemon tampering → LOCKDOWN

### Event Logger (`daemon/event_logger.py`, `daemon/signed_event_logger.py`)
Immutable audit logging:
- SHA-256 hash-chained events
- Ed25519 cryptographic signatures
- Append-only storage
- Tamper-evident verification

### Human Override Ceremony
Multi-step confirmation for sensitive operations:
- Physical presence required
- Mandatory cooldown delay
- Biometric verification (optional)
- Immutably logged
- **No silent overrides. Ever.**

---

## Security Features

### AI/Agent Security
- **Prompt Injection Detection**: 50+ patterns (jailbreaks, DAN, encoding bypasses)
- **Tool Output Validation**: Sanitization, size limits, chain depth enforcement
- **Response Guardrails**: Content safety, hallucination detection
- **RAG Injection Detection**: Poisoned documents, indirect injection
- **Agent Attestation (CBAC)**: Cryptographic identity, capability tokens

### Threat Detection (Deterministic, No ML)
- YARA rule engine
- Sigma rule support
- Signed IOC feeds
- MITRE ATT&CK pattern matching

### Process Sandboxing (Linux)
- Namespace isolation (PID, network, mount, user, IPC, UTS)
- Seccomp-BPF syscall filtering
- Cgroups v2 resource limits
- Per-sandbox firewall rules

### Platform Enforcement
- Linux: iptables/nftables, udev USB control
- Windows: Windows Firewall rules
- Both: AppArmor/SELinux profile generation

---

## TUI Dashboard Features

### Standard Mode
- Live status panel (mode, uptime, connection)
- Event stream with filtering
- Alert panel with severity indicators
- Sandbox monitor
- SIEM status panel

### Obscured Security Viewport (Matrix Mode)
Steganographic display with animated cityscape:
- Building windows show process activity
- Pedestrian activity reflects network health
- Vehicle traffic indicates data throughput
- Weather effects show system load

### TUI Keyboard Shortcuts
| Key | Action |
|-----|--------|
| `:` | Enter CLI mode (Ollama chat) |
| `w` | Cycle weather (Matrix/Rain/Snow/Sand/Fog) |
| `t` | Toggle 3D tunnel sky effect |
| `f` | Cycle framerate (100/50/25/15/10ms) |
| `g` | Toggle meteor defense game (QTE) |
| `u` | Toggle audio mute |
| `m` | Start mode change ceremony |
| `c` | Clear events display |
| `l` | Load events from daemon |
| `e` | Export events to file |
| `r` | Refresh data |
| `/` | Filter events |
| `?` | Toggle help overlay |
| `q` | Quit |

### Scene Elements
- **Buildings**: Two main buildings with animated windows
- **Park**: Small park with bench, lamp, bushes, flowers
- **Vehicles**: Cars and taxis (including closeup perspective effect)
- **Pedestrians**: Up to 50 walking figures
- **Trees**: Regular and pine trees with wind effects
- **Weather**: Rain, snow, sand, fog effects
- **Stars**: Background stars and seasonal constellations (when tunnel off)

---

## SIEM Integration

### Shipping (Daemon → SIEM)
Outbound event forwarding:
- CEF/LEEF format support
- Kafka/S3/GCS/HTTP shipping
- Queue depth monitoring

### Ingestion (SIEM Client → Daemon)
Inbound event polling:
- 60-second connection timeout
- Automatic disconnect detection
- Warning events on disconnect/reconnect
- TCP support for Windows (port 19847)
- Unix socket for Linux/macOS

### SIEM Status Indicators
- **Connected**: SIEM actively polling (green)
- **Disconnected**: SIEM timed out (yellow warning)
- **No client**: Never connected (muted)

---

## API

### Unix Socket API
Location: `./api/boundary.sock` or `/var/run/boundary-daemon/boundary.sock`

### TCP API (Windows)
Host: `127.0.0.1`
Port: `19847`

### Common Commands
- `status` - Get daemon status
- `get_events` - Retrieve recent events
- `set_mode` - Change boundary mode (requires operator)
- `check_recall` - Check memory recall permission
- `check_tool` - Check tool execution permission
- `verify_log` - Verify log integrity
- `get_siem_status` - Get SIEM connection status

### Token Authentication
Capability levels:
- `readonly` - Status and events only
- `operator` - Mode changes and operations
- `admin` - Full access including config

---

## CLI Tools

| Tool | Description |
|------|-------------|
| `boundaryctl` | Main daemon control and monitoring |
| `sandboxctl` | Sandbox lifecycle management |
| `authctl` | Authentication and token management |
| `policy_ctl` | Policy configuration |
| `dashboard` | TUI monitoring dashboard |

---

## File Locations

### Configuration
- `config/boundary.conf` - Main configuration
- `config/policies.d/*.yaml` - Policy files

### Logs
- `logs/boundary_chain.log` - Immutable hash-chained log

### API
- `api/boundary.sock` - Unix socket
- `~/.agent-os/api/boundary.sock` - User socket

### Tokens
- `~/.agent-os/api/api_tokens.json` - API tokens

---

## Troubleshooting

### Common Issues

**"Unknown capability: read" error**
- Token uses old capability names
- Solution: Use `readonly`, `operator`, or `admin`

**Colors.STATUS_CRITICAL not found**
- Old color constant reference
- Solution: Use `Colors.SHADOW_RED`

**System tray mode changes not working**
- Need to use `daemon.request_mode_change()` not `daemon.set_mode()`
- Requires Operator import from policy_engine

**Memory leak warnings**
- Check for unbounded lists
- Use `deque(maxlen=N)` for buffers
- TUI bounded: CLI history (100), chat history (50), results (1000)
- TUI bounded: knocked_out_peds (10), debug_log (500)

**SIEM not showing data on Windows**
- Use TCP mode: set `BOUNDARY_USE_TCP=true`
- Default port: 19847

**Scene runs slow after CLI**
- Screen timeout not restored
- Exit CLI mode properly to restore framerate

---

## Recent Changes (Latest Updates)

### SIEM Disconnection Detection
- Tracks connection state with 60s timeout
- Logs warning event on disconnect
- TUI shows "Disconnected" with yellow warning

### TUI Scene Improvements
- Doubled pedestrians (25 → 50)
- Added small park (bench, lamp, bushes, flowers)
- Yellow taxi support for closeup cars
- Background stars (80-120 twinkling)
- Improved constellation visibility
- 10ms refresh rate option
- Missing shortcuts added (f/g/u)

### Windows Support
- TCP socket support for SIEM ingestion
- Path.replace() for atomic file saves
- Windows Firewall enforcement
- Python 3.12 auto-detection for curses support

### Performance Optimizations (v1.0.0-beta)
- Frame-based update throttling (60% CPU reduction)
- Early-exit conditions for inactive features
- 10ms refresh rate option for smooth animation

### CLI Improvements (v1.0.0-beta)
- CLI now renders as overlay on animated scene
- F1 help popup stays until dismissed
- Clear events [c] stays cleared until manual reload [l]

### Bug Fixes (v1.0.0-beta)
- Fixed park visibility (reduced minimum width)
- Fixed fireworks mode variable name
- Fixed token capability validation
- Fixed TUI memory leaks (bounded CLI history, chat history, results, debug log)

---

## Self-Awareness Commands

When users ask about the system, check:

1. **Mode**: Current boundary mode
2. **Status**: Connection, uptime, health
3. **Events**: Recent security events
4. **Alerts**: Active alerts
5. **SIEM**: Ingestion/shipping status
6. **Sandboxes**: Active sandboxes

### Useful Commands for Context
```bash
# Get status
status

# Get recent events
events 20

# Check mode
mode

# SIEM status
siem

# Health check
health
```

---

## Philosophy

> *"If the system cannot clearly answer 'where am I allowed to think right now?' it is not safe to think at all."*

### Design Principles
1. **Authoritative** - Decisions cannot be overridden programmatically
2. **Fail-Closed** - Uncertainty defaults to DENY
3. **Deterministic** - Same inputs always produce same decision
4. **Immutable Logging** - All events logged with tamper-evident chain
5. **Human Oversight** - Overrides require ceremony, never silent
6. **Minimal Dependencies** - Small attack surface by design

### Motto
**"Never compromise. Not even in the face of Armageddon."**

---

*Last updated: 2026-01-09*
