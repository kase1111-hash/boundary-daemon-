# Boundary Daemon Usage Guide

## Quick Start

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Install boundary daemon
python setup.py install

# Or install in development mode
pip install -e .
```

### Starting the Daemon

```bash
# Start in OPEN mode (default)
python daemon/boundary_daemon.py

# Start in specific mode
python daemon/boundary_daemon.py --mode=restricted

# Start with custom log directory
python daemon/boundary_daemon.py --mode=trusted --log-dir=/var/log/boundary
```

### Using as a System Service

```bash
# Copy service file
sudo cp config/boundary-daemon.service /etc/systemd/system/

# Create required directories
sudo mkdir -p /var/log/boundary-daemon
sudo mkdir -p /var/run/boundary-daemon

# Enable and start service
sudo systemctl enable boundary-daemon
sudo systemctl start boundary-daemon

# Check status
sudo systemctl status boundary-daemon
```

## CLI Tool (boundaryctl)

### Status Commands

```bash
# Show daemon status
boundaryctl status

# Watch status (live updates)
boundaryctl watch

# Watch with custom interval
boundaryctl watch --interval=5
```

### Permission Checks

```bash
# Check if memory class is accessible
boundaryctl check-recall 0  # Public
boundaryctl check-recall 3  # Secret
boundaryctl check-recall 5  # Crown jewel

# Check if tool is allowed
boundaryctl check-tool curl --network
boundaryctl check-tool cat --filesystem
boundaryctl check-tool usb-mount --usb
```

### Mode Management

```bash
# Change to RESTRICTED mode
boundaryctl set-mode restricted

# Change with reason
boundaryctl set-mode airgap --reason "Working on sensitive project"

# Available modes:
# - open       (networked, low trust)
# - restricted (network allowed, memory limited)
# - trusted    (offline or VPN only)
# - airgap     (physically isolated)
# - coldroom   (no IO except keyboard/display)
```

### Event Log

```bash
# Show recent events
boundaryctl events

# Show more events
boundaryctl events --count=50

# Filter by type
boundaryctl events --type=mode_change
boundaryctl events --type=violation

# Verify log integrity
boundaryctl verify
```

## Boundary Modes Explained

### OPEN Mode
- **Network**: Full access
- **Memory**: Classes 0-1 (Public, Internal)
- **Tools**: All allowed
- **Use Case**: Casual browsing, research

```bash
boundaryctl set-mode open
```

### RESTRICTED Mode
- **Network**: Full access
- **Memory**: Classes 0-2 (+ Confidential)
- **Tools**: Most allowed, some require ceremony
- **Use Case**: Development work, code review

```bash
boundaryctl set-mode restricted
```

### TRUSTED Mode
- **Network**: Offline or VPN only
- **Memory**: Classes 0-3 (+ Secret)
- **Tools**: No USB, filesystem OK
- **Use Case**: Working with proprietary code

```bash
boundaryctl set-mode trusted
```

### AIRGAP Mode
- **Network**: Completely offline
- **Memory**: Classes 0-4 (+ Top Secret)
- **Tools**: No network, no USB
- **Use Case**: High-value intellectual property

```bash
boundaryctl set-mode airgap
```

### COLDROOM Mode
- **Network**: Offline
- **Memory**: Classes 0-5 (+ Crown Jewel)
- **Tools**: Display + keyboard only
- **Use Case**: Maximum security, crown jewel thinking

```bash
boundaryctl set-mode coldroom
```

### LOCKDOWN Mode
- **Trigger**: Automatic (tripwire violation)
- **Network**: Blocked
- **Memory**: No recall
- **Tools**: None
- **Recovery**: Requires human override ceremony

## Tripwires

Tripwires trigger automatic LOCKDOWN on security violations:

### Network in AIRGAP
```bash
# Set AIRGAP mode
boundaryctl set-mode airgap

# If network comes online → LOCKDOWN
# System will automatically enter lockdown mode
```

### USB in COLDROOM
```bash
# Set COLDROOM mode
boundaryctl set-mode coldroom

# If USB device inserted → LOCKDOWN
```

### Checking for Violations
```bash
# View status (shows violation count)
boundaryctl status

# View violation events
boundaryctl events --type=violation
boundaryctl events --type=tripwire
```

## Human Override Ceremony

When system enters LOCKDOWN, recovery requires ceremony:

```python
from daemon.integrations import CeremonyManager

# Initialize ceremony
ceremony = CeremonyManager(daemon)

# Attempt override
success, message = ceremony.override_lockdown(
    reason="Authorized recovery after false positive"
)

# Ceremony steps:
# 1. Verify human presence (keyboard input)
# 2. Mandatory cooldown (30 seconds)
# 3. Final confirmation
# 4. Immutable log entry
```

The ceremony is designed to prevent:
- Impulse decisions
- Silent overrides
- Automated bypasses
- Gradual erosion of boundaries

## Event Logging

All boundary decisions are logged immutably with hash chain:

### View Recent Events
```bash
boundaryctl events
```

Example output:
```
[2024-01-15T10:30:00Z] MODE_CHANGE
  Transitioned from OPEN to RESTRICTED: Starting work session

[2024-01-15T10:35:00Z] RECALL_ATTEMPT
  Memory class 3 recall: allow

[2024-01-15T11:00:00Z] TOOL_REQUEST
  Tool 'wget' request: allow
```

### Verify Log Integrity
```bash
boundaryctl verify
```

If log is tampered:
```
✗ Event log chain is INVALID: Hash chain broken at event 42
```

### Export Log
```python
from daemon.event_logger import EventLogger

logger = EventLogger('./logs/boundary_chain.log')
logger.export_log('/backup/boundary_log_2024-01-15.log')
```

## Monitoring

### Real-Time Status
```bash
# Watch daemon status
boundaryctl watch
```

### System Logs
```bash
# View daemon logs
journalctl -u boundary-daemon -f

# View errors only
journalctl -u boundary-daemon -p err
```

### Health Checks
The daemon performs periodic health checks:
- Daemon integrity
- Log chain integrity
- Environment state
- Tripwire status

## Common Workflows

### Workflow 1: Daily Work Session
```bash
# Morning: Start in RESTRICTED mode
boundaryctl set-mode restricted --reason "Daily work session"

# Check what's accessible
boundaryctl check-recall 2  # Can access confidential

# Work...
# Check tool permissions as needed
boundaryctl check-tool git --network

# Evening: Return to OPEN
boundaryctl set-mode open
```

### Workflow 2: Sensitive Project
```bash
# Disconnect network
nmcli networking off

# Enter AIRGAP mode
boundaryctl set-mode airgap --reason "Sensitive project work"

# Verify mode
boundaryctl status

# Work offline with high-security memory
# ...

# When done, reconnect
boundaryctl set-mode trusted --reason "Completed session"
nmcli networking on
```

### Workflow 3: Maximum Security
```bash
# Physically disconnect network cable

# Remove all USB devices

# Enter COLDROOM mode
boundaryctl set-mode coldroom --reason "Crown jewel architecture"

# Only keyboard and display work
# Maximum security memory accessible

# Work...

# Exit COLDROOM
boundaryctl set-mode restricted --reason "Session complete"
```

## Troubleshooting

### Daemon Won't Start
```bash
# Check if already running
ps aux | grep boundary_daemon

# Check socket file
ls -la ./api/boundary.sock

# Remove stale socket
rm ./api/boundary.sock

# Start daemon
python daemon/boundary_daemon.py
```

### Permission Denied Errors
```bash
# Check current mode
boundaryctl status

# Check what mode is required
boundaryctl check-recall 4  # Shows required mode

# Change mode if authorized
boundaryctl set-mode airgap
```

### Log Chain Integrity Error
```bash
# Verify log
boundaryctl verify

# If invalid, this indicates:
# - Log tampering (security incident)
# - File corruption
# - System compromise

# DO NOT delete the log
# Investigate the cause
```

### Recovering from LOCKDOWN
```python
# Use ceremony manager
from daemon.integrations import CeremonyManager
from daemon.boundary_daemon import BoundaryDaemon

daemon = BoundaryDaemon()
ceremony = CeremonyManager(daemon)

# Initiate override (requires physical presence)
success, msg = ceremony.override_lockdown(
    reason="Authorized recovery"
)

# Follow ceremony steps:
# 1. Type 'PRESENT' to confirm presence
# 2. Wait 30 seconds (cooldown)
# 3. Type 'CONFIRM' to complete

# System transitions to RESTRICTED mode
```

## Best Practices

### 1. Default to Higher Security
Start with higher security mode and relax if needed:
```bash
# Start restrictive
boundaryctl set-mode airgap

# Relax only if necessary
boundaryctl set-mode trusted --reason "Need VPN access"
```

### 2. Log Reasons for Mode Changes
Always provide reasons:
```bash
boundaryctl set-mode restricted --reason "Code review for Project X"
```

### 3. Regular Log Verification
Periodically verify log integrity:
```bash
# Daily verification
boundaryctl verify

# Automated check
0 9 * * * /usr/local/bin/boundaryctl verify || notify-admin
```

### 4. Monitor Events
Watch for suspicious patterns:
```bash
# Check violations
boundaryctl events --type=violation

# Check unauthorized attempts
boundaryctl events --type=recall_attempt | grep denied
```

### 5. Test Tripwires
Periodically test that tripwires work:
```bash
# Set AIRGAP mode
boundaryctl set-mode airgap

# Try to enable network (should trigger lockdown)
# Verify lockdown occurred
boundaryctl status  # Should show LOCKDOWN

# Use ceremony to recover
```

## Security Notes

### Security is Allowed to be Annoying
The Boundary Daemon prioritizes security over convenience:
- Cooldown delays are intentional
- Ceremonies are mandatory
- No silent overrides
- Fail-closed by design

### Trust but Verify
- Verify log integrity regularly
- Monitor event stream
- Review mode transitions
- Audit override ceremonies

### Defense in Depth
Boundary Daemon is one layer:
- Use with Memory Vault encryption
- Combine with OS-level security
- Implement application-level checks
- Maintain physical security

---

**Remember**: Agent Smith (Boundary Daemon) is the guard. It determines where cognition is allowed to flow and where it must stop. Respect the boundaries.
