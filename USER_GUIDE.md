# Boundary Daemon User Guide

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Security Modes](#security-modes)
5. [Monitoring Features](#monitoring-features)
6. [Ollama Integration](#ollama-integration)
7. [Configuration](#configuration)
8. [Command Line Tools](#command-line-tools)
9. [API Reference](#api-reference)
10. [Troubleshooting](#troubleshooting)

---

## Overview

The Boundary Daemon (Agent Smith) is a trust boundary enforcement system that monitors and controls security boundaries for AI agent systems. It provides:

- **Security Mode Enforcement**: Four security levels from permissive to complete lockdown
- **Real-time Monitoring**: Memory, CPU, disk, network, and health monitoring
- **Cryptographic Logging**: Signed, tamper-evident event logs
- **AI-Powered Analysis**: Natural language queries via Ollama integration
- **Config Encryption**: Sensitive configuration encrypted at rest

### Platform Support

| Feature | Linux | Windows |
|---------|-------|---------|
| Core Daemon | ✅ | ✅ |
| Monitoring | ✅ | ✅ |
| Config Encryption | ✅ | ✅ |
| Ollama Integration | ✅ | ✅ |
| Network Enforcement | ✅ | ❌ (Linux-only) |
| USB Enforcement | ✅ | ❌ (Linux-only) |
| Process Enforcement | ✅ | ❌ (Linux-only) |

---

## Installation

### Prerequisites

- Python 3.9 or higher (supports 3.9, 3.10, 3.11, 3.12, 3.13)
- Ollama (optional, for AI features)

### Windows Installation

1. **Install Python** from https://python.org

2. **Clone or download** the repository

3. **Build the executable**:
   ```batch
   build.bat
   ```
   This will:
   - Install dependencies (psutil, cryptography, pynacl)
   - Build `dist\boundary-daemon.exe`
   - Copy configuration files

4. **Run the daemon**:
   ```batch
   cd dist
   boundary-daemon.exe
   ```

### Linux Installation

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the daemon**:
   ```bash
   # Development mode
   python run_daemon.py

   # With full enforcement (requires root)
   sudo python run_daemon.py
   ```

### Installing Ollama (Optional)

For AI-powered reports and natural language queries:

1. **Install Ollama**:
   - Windows: Download from https://ollama.ai
   - Linux: `curl https://ollama.ai/install.sh | sh`

2. **Pull a model**:
   ```bash
   ollama pull llama3.2
   ```

3. **Start Ollama** (runs as a service on Windows, or run `ollama serve` on Linux)

---

## Quick Start

### Starting the Daemon

```batch
# Windows
boundary-daemon.exe

# Linux
python run_daemon.py
```

### First Run Output

On first run, you'll see:
```
======================================================================
Boundary Daemon - Trust Boundary Enforcement System
======================================================================
Verifying daemon integrity...
Initializing Boundary Daemon (Agent Smith)...
Generated new signing key at .\logs\signing.key
Signed event logging enabled
[AUTH] Bootstrap admin token created (ENCRYPTED): config\bootstrap_token.enc
Boundary Daemon initialized in OPEN mode
Boundary Daemon running. Close this window or press Ctrl+Break to stop.
======================================================================
```

### Stopping the Daemon

- **Windows**: Close the window or press `Ctrl+Break`
- **Linux**: Press `Ctrl+C`

---

## Security Modes

The daemon operates in four security modes, from most permissive to most restrictive:

### OPEN Mode (Default)
```
Mode: OPEN
Description: Permissive monitoring mode
Behavior: All operations allowed, events logged
Use Case: Development, testing, initial setup
```

### GUARDED Mode
```
Mode: GUARDED
Description: Active monitoring with warnings
Behavior: Operations allowed but flagged if suspicious
Use Case: Normal operation with oversight
```

### AIRGAP Mode
```
Mode: AIRGAP
Description: Network isolation enforced
Behavior: External network access blocked
Use Case: Sensitive operations, data processing
Requires: Linux with root privileges
```

### LOCKDOWN Mode
```
Mode: LOCKDOWN
Description: Maximum security
Behavior: All external access blocked
Use Case: Emergency response, incident containment
Requires: Linux with root privileges
```

### Changing Modes

Modes can be changed via the API:
```python
from api.boundary_api import BoundaryAPIClient

client = BoundaryAPIClient()
client.set_mode("GUARDED")
```

---

## Monitoring Features

### Memory Monitor

Tracks daemon memory usage to detect leaks and excessive consumption.

**Metrics:**
- `current_mb`: Current RAM usage in megabytes
- `peak_mb`: Highest RAM usage since startup
- `warning_threshold_mb`: Warning level (default: 500 MB)
- `critical_threshold_mb`: Critical level (default: 1000 MB)
- `leak_detected`: Boolean indicating potential memory leak

**Configuration:**
```
Displayed as:
  Memory monitor available (interval: 5.0s)
    RSS warning: 500.0 MB, critical: 1000.0 MB
    Leak detection: enabled
```

### Resource Monitor

Tracks system resources including CPU, disk, file descriptors, and network connections.

**Metrics:**
- `cpu_percent`: Current CPU usage percentage
- `fd_count`: Open file descriptors
- `thread_count`: Active threads
- `disk_used_percent`: Disk usage percentage
- `connection_count`: Active network connections

**Thresholds:**
- File descriptor warning: 70% of system limit
- Disk warning: 90% (configurable)
- Disk critical: 95%

**Configuration:**
```
Displayed as:
  Resource monitor available (interval: 10.0s)
    FD warning: 70.0%, Disk warning: 90.0%
```

### Health Monitor

Performs periodic health checks on the daemon.

**Metrics:**
- `status`: healthy, degraded, or unhealthy
- `last_heartbeat`: Time of last successful check
- `uptime_seconds`: How long the daemon has been running
- `issues`: List of active problems

**Configuration:**
```
Displayed as:
  Health monitor available (check interval: 30.0s)
    Heartbeat timeout: 60.0s
```

### Queue Monitor

Monitors event processing queues for backlogs.

**Metrics:**
- `current_depth`: Events waiting to be processed
- `peak_depth`: Highest queue size seen
- `total_processed`: Total events handled
- `is_backed_up`: Whether queue is backing up

**Thresholds:**
- Warning depth: 100 events
- Critical depth: 500 events

**Configuration:**
```
Displayed as:
  Queue monitor available (sample interval: 5.0s)
    Warning depth: 100, Critical depth: 500
```

### Clock Monitor

Monitors system time and NTP synchronization.

**Purpose:**
- Ensures accurate timestamps in logs
- Detects time drift that could affect security

---

## Ollama Integration

The daemon integrates with Ollama for AI-powered features:

### Checking Ollama Status

```batch
python query_daemon.py --check
```

Output:
```
Ollama Status:
  Endpoint: http://localhost:11434
  Available: Yes
  Model: llama3.2
  Model Available: Yes
```

### Generating AI Reports

Generate a monitoring report with AI analysis:

```batch
python generate_report.py
```

Output includes:
- Current daemon state
- Resource metrics
- AI-generated analysis and recommendations

**Options:**
```batch
# Full report with AI analysis
python generate_report.py

# Health-focused report
python generate_report.py --type health

# Raw report without AI
python generate_report.py --no-interpret

# Show raw JSON data
python generate_report.py --raw

# Use different model
python generate_report.py --model llama3.1
```

### Natural Language Queries

Query the daemon using natural language:

```batch
# Single query
python query_daemon.py "What is the memory usage?"

# Interactive mode
python query_daemon.py --interactive
```

**Example Queries:**
- "What is the current memory usage?"
- "Are there any critical issues?"
- "What security mode is the daemon in?"
- "Is the system healthy?"
- "How much disk space is being used?"
- "What is the CPU usage?"
- "Are there any memory leaks?"
- "How long has the daemon been running?"
- "What alerts have occurred recently?"

**Interactive Mode:**
```
You: What is the memory usage?
Daemon: The daemon is currently using 45.2 MB of RAM, which is well
        below the warning threshold of 500 MB...

You: Any issues?
Daemon: The system is healthy with no critical issues detected...

You: quit
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OLLAMA_ENDPOINT` | Ollama API URL | `http://localhost:11434` |
| `OLLAMA_MODEL` | Ollama model to use | `llama3.2` |
| `BOUNDARY_DISK_WARNING_PERCENT` | Disk warning threshold | `90` |
| `BOUNDARY_POLICY_DIR` | Custom policy directory | (disabled) |
| `BOUNDARY_SECURITY_DIR` | Security advisor directory | (disabled) |
| `BOUNDARY_WATCHDOG_DIR` | Log watchdog directory | (disabled) |
| `BOUNDARY_TELEMETRY_DIR` | Telemetry directory | (disabled) |

### Configuration Files

**Location:** `config/` directory

| File | Purpose |
|------|---------|
| `bootstrap_token.enc` | Encrypted admin API token |
| `manifest.json` | Integrity verification manifest (auto-generated) |
| `signing.key` | Manifest signing key |

### Logs

**Location:** `logs/` directory

| File | Purpose |
|------|---------|
| `boundary_chain.log` | Signed event log chain |
| `signing.key` | Event log signing key |

---

## Command Line Tools

### boundary-daemon.exe / run_daemon.py

The main daemon executable.

```batch
# Windows
boundary-daemon.exe

# Linux
python run_daemon.py
```

### generate_report.py

Generate monitoring reports with optional AI analysis.

```batch
python generate_report.py [options]

Options:
  --type TYPE       Report type: full, summary, alerts, health (default: full)
  --no-interpret    Skip AI analysis
  --raw             Show raw JSON data
  --check           Check Ollama status
  --endpoint URL    Ollama endpoint (default: http://localhost:11434)
  --model MODEL     Ollama model (default: llama3.2)
```

**Examples:**
```batch
# Full report with AI
python generate_report.py

# Health report only
python generate_report.py --type health

# Check Ollama connection
python generate_report.py --check
```

### query_daemon.py

Query the daemon using natural language.

```batch
python query_daemon.py [question] [options]

Options:
  --interactive, -i    Run in interactive mode
  --check, -c          Check system status
  --json, -j           Output as JSON
  --endpoint URL       Ollama endpoint
  --model MODEL        Ollama model
```

**Examples:**
```batch
# Single query
python query_daemon.py "What is the memory usage?"

# Interactive mode
python query_daemon.py -i

# JSON output
python query_daemon.py -j "System status?"

# Check status
python query_daemon.py --check
```

### build.bat (Windows)

Build the Windows executable.

```batch
build.bat
```

This script:
1. Checks Python installation
2. Installs PyInstaller if needed
3. Installs dependencies from requirements.txt
4. Builds boundary-daemon.exe
5. Copies configuration files to dist/

---

## API Reference

### Python Client

```python
from api.boundary_api import BoundaryAPIClient

client = BoundaryAPIClient()
```

### Available Methods

#### Status and Mode

```python
# Get current status
status = client.get_status()

# Get current mode
mode = client.get_mode()

# Set mode (OPEN, GUARDED, AIRGAP, LOCKDOWN)
client.set_mode("GUARDED")
```

#### Monitoring

```python
# Generate report with AI analysis
report = client.generate_report(
    report_type="full",      # full, summary, alerts, health
    interpret=True,          # Enable AI analysis
    custom_prompt=None,      # Custom prompt for AI
    ollama_model=None,       # Override model
)

# Get raw report (no AI)
raw_report = client.get_raw_report(report_type="full")

# Get report history
history = client.get_report_history(limit=10)
```

#### Ollama Integration

```python
# Check Ollama status
status = client.check_ollama_status()
# Returns: {'available': True, 'model': 'llama3.2', ...}

# Natural language query
result = client.query("What is the memory usage?")
print(result['answer'])
```

#### Event Logging

```python
# Get recent events
events = client.get_events(limit=100)

# Get events by type
alerts = client.get_events_by_type("ALERT", limit=50)
```

---

## Troubleshooting

### Common Issues

#### "cryptography library not available"

**Solution:** Install the cryptography package:
```batch
pip install cryptography>=41.0.0
```

#### "Ollama is not available"

**Solution:**
1. Install Ollama from https://ollama.ai
2. Start Ollama: `ollama serve`
3. Pull a model: `ollama pull llama3.2`

#### "Module not loaded" for network/USB/process

**Explanation:** These modules require Linux-specific features (iptables, udev, seccomp) and are not available on Windows. This is expected behavior.

On Windows, you'll see:
```
Network enforcement: Windows mode (iptables/nftables not available)
USB enforcement: Windows mode (udev not available)
Process enforcement: Windows mode (seccomp not available)
```

#### Manifest signature invalid

**Explanation:** This occurs when the signing key changes between restarts. In development mode, the manifest is automatically regenerated.

**For production:** Use a persistent signing key stored securely.

#### Disk space warnings

**Solution:** Either free up disk space or adjust the threshold:
```batch
set BOUNDARY_DISK_WARNING_PERCENT=95
boundary-daemon.exe
```

### Log Files

Check these files for debugging:

| File | Contains |
|------|----------|
| `logs/boundary_chain.log` | All daemon events |
| Console output | Real-time status and errors |

### Getting Help

1. Check this user guide
2. Review console output for error messages
3. Use `python query_daemon.py --check` to verify Ollama status
4. Report issues at the project repository

---

## Security Considerations

### Config Encryption

Sensitive configuration (tokens, credentials) is encrypted using:
- **Algorithm:** Fernet (AES-128-CBC with HMAC-SHA256)
- **Key Derivation:** PBKDF2-HMAC-SHA256 with 480,000 iterations
- **Key Source:** Machine-specific (tied to machine ID)

### Event Log Signing

All events are cryptographically signed using:
- **Algorithm:** Ed25519 digital signatures
- **Chain Integrity:** Each event includes hash of previous event
- **Verification:** Use `verify_chain()` to check integrity

### Running as Administrator

For full security enforcement on Linux, run as root:
```bash
sudo python run_daemon.py
```

On Windows, some features work without Administrator, but enforcement modules require Linux.

### Best Practices

1. **Production:** Use a persistent signing key
2. **Production:** Set `allow_missing_manifest=False`
3. **Production:** Run in GUARDED or higher mode
4. **Development:** OPEN mode is acceptable
5. **Always:** Keep Ollama running locally (not exposed to network)

---

## Version Information

- **Current Version:** See startup banner
- **Python Required:** 3.9+ (supports 3.9, 3.10, 3.11, 3.12, 3.13)
- **Supported Platforms:** Windows 10+, Linux (kernel 4.4+)

---

## Appendix: Security Modes Quick Reference

| Mode | Network | USB | Processes | Logging | Use Case |
|------|---------|-----|-----------|---------|----------|
| OPEN | Allowed | Allowed | Allowed | Yes | Development |
| GUARDED | Monitored | Monitored | Monitored | Yes | Normal ops |
| AIRGAP | Blocked | Controlled | Controlled | Yes | Sensitive work |
| LOCKDOWN | Blocked | Blocked | Blocked | Yes | Emergency |

---

## Appendix: Monitoring Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Memory | 500 MB | 1000 MB |
| Disk | 90% | 95% |
| File Descriptors | 70% of limit | N/A |
| Queue Depth | 100 events | 500 events |
| Heartbeat | N/A | 60s timeout |
