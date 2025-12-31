# Enforcement Model

**Understanding What the Boundary Daemon Does and Does Not Do**

---

## Executive Summary

The Boundary Daemon is a **policy decision and audit system**, not a security enforcement mechanism. It:

- **Monitors** environment state (network, USB, processes, hardware)
- **Evaluates** policies and returns allow/deny decisions
- **Logs** all security events with tamper-evident hash chains
- **Detects** violations and signals alerts

It does **NOT** prevent operations at the OS level. External systems must voluntarily respect daemon decisions.

---

## The Cooperation Model

### How the Daemon Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Calling Application                          │
│                     (Memory Vault, Agent-OS, etc.)                 │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  │ 1. "Can I access TOP_SECRET memory?"
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Boundary Daemon                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
│  │   Policy    │  │    State    │  │    Event    │                 │
│  │   Engine    │  │   Monitor   │  │   Logger    │                 │
│  └─────────────┘  └─────────────┘  └─────────────┘                 │
│         │                                   │                       │
│         │ 2. Evaluate policy                │ 3. Log the request   │
│         ▼                                   ▼                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │         Return: (False, "Denied: mode OPEN < AIRGAP")       │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  │ 4. Decision returned
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Calling Application                          │
│                                                                     │
│  COOPERATIVE:                      NON-COOPERATIVE:                 │
│  ┌─────────────────────────┐      ┌─────────────────────────┐      │
│  │ if not permitted:       │      │ # Ignore the daemon     │      │
│  │     raise AccessDenied  │      │ return secret_data      │      │
│  └─────────────────────────┘      └─────────────────────────┘      │
│         ✅ Respects decision              ⚠️ Bypasses daemon       │
└─────────────────────────────────────────────────────────────────────┘
```

### The Critical Insight

**The daemon cannot prevent a non-cooperative application from ignoring its decisions.**

This is by design - the daemon is a Python user-space process. It cannot:
- Intercept system calls
- Block network traffic
- Prevent memory access
- Terminate processes

These capabilities require kernel-level or hardware-level enforcement.

---

## Defense in Depth Architecture

For actual security, deploy this daemon as **one layer** in a multi-layer architecture:

```
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 5: Hardware Controls                                          │
│ ─────────────────────────                                           │
│ • Physically disable USB ports                                      │
│ • Air-gap network (disconnect cable)                                │
│ • Hardware security modules (HSM)                                   │
│ • Trusted Platform Module (TPM)                                     │
│                                                                     │
│ Enforcement: PHYSICAL - Cannot be bypassed by software              │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 4: Kernel Enforcement                                         │
│ ──────────────────────────                                          │
│ • SELinux / AppArmor mandatory access control                       │
│ • seccomp-bpf syscall filtering                                     │
│ • eBPF network filtering                                            │
│ • iptables / nftables firewall rules                               │
│                                                                     │
│ Enforcement: HARD - Kernel blocks operations before they occur     │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 3: Container/Process Isolation                                │
│ ───────────────────────────────────                                 │
│ • Linux namespaces (network, PID, mount)                           │
│ • cgroups resource limits                                           │
│ • Container runtimes (podman, docker)                              │
│ • Virtual machines                                                  │
│                                                                     │
│ Enforcement: HARD - Isolated processes cannot access host resources│
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 2: BOUNDARY DAEMON (This System)                              │
│ ─────────────────────────────────────                               │
│ • Policy decision point                                             │
│ • Environment monitoring                                            │
│ • Audit logging with hash chains                                   │
│ • Violation detection                                               │
│ • Coordination between components                                   │
│                                                                     │
│ Enforcement: ADVISORY - Returns decisions, cannot block operations │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 1: Application Cooperation                                    │
│ ───────────────────────────────                                     │
│ • Memory Vault respects recall decisions                           │
│ • Agent-OS respects tool permissions                               │
│ • Applications check permissions before operations                 │
│                                                                     │
│ Enforcement: VOLUNTARY - Applications must choose to cooperate     │
└─────────────────────────────────────────────────────────────────────┘
```

### Layer Responsibilities

| Layer | Type | Can Prevent? | Examples |
|-------|------|--------------|----------|
| 5. Hardware | Physical | Yes | Disabled USB, air-gap, HSM |
| 4. Kernel | Hard | Yes | SELinux, seccomp, iptables |
| 3. Container | Hard | Yes | Namespaces, cgroups, VMs |
| **2. Daemon** | **Advisory** | **No** | **Policy decisions, logging** |
| 1. Application | Voluntary | Depends | Cooperative code |

### What Happens Without Each Layer

| Missing Layer | Consequence |
|---------------|-------------|
| No Layer 4-5 | Daemon decisions are suggestions only |
| No Layer 3 | Malicious code in same container can bypass |
| No Layer 2 | No central policy authority or audit trail |
| No Layer 1 | Even correct decisions are ignored |

---

## What the Daemon Actually Provides

### Detection & Monitoring

```python
# The daemon continuously monitors:
state = {
    "network": {
        "interfaces": ["eth0", "wlan0"],
        "internet_available": True,
        "vpn_active": False
    },
    "hardware": {
        "usb_devices": ["/dev/sda1"],
        "tpm_present": True
    },
    "processes": {
        "suspicious": ["curl api.openai.com"],
        "shell_escapes": []
    }
}
```

### Policy Decisions

```python
# Applications query the daemon for decisions:
permitted, reason = daemon.check_recall_permission(MemoryClass.TOP_SECRET)
# Returns: (False, "Denied: current mode OPEN requires AIRGAP for TOP_SECRET")

permitted, reason = daemon.check_tool_permission("wget", requires_network=True)
# Returns: (False, "Denied: network tools blocked in AIRGAP mode")
```

### Audit Logging

```json
{
    "timestamp": "2025-12-22T10:30:00Z",
    "event_type": "RECALL_ATTEMPT",
    "memory_class": "TOP_SECRET",
    "decision": "DENY",
    "reason": "Mode OPEN < required AIRGAP",
    "hash": "a1b2c3...",
    "prev_hash": "x9y8z7..."
}
```

### Violation Detection

```python
# Tripwires detect policy violations:
if network_detected and mode == AIRGAP:
    trigger_violation("NETWORK_IN_AIRGAP")
    transition_to_lockdown()
```

---

## Enabling Hard Enforcement

The daemon includes optional enforcement modules that CAN provide hard enforcement when properly configured:

### Network Enforcer

```bash
# Enable network enforcement (requires root)
export BOUNDARY_NETWORK_ENFORCE=1
sudo python daemon/boundary_daemon.py

# This will:
# - Install iptables/nftables rules on mode transitions
# - Block network traffic in AIRGAP/LOCKDOWN modes
# - Allow only VPN in TRUSTED mode
```

### USB Enforcer

```bash
# Enable USB enforcement (requires root)
export BOUNDARY_USB_ENFORCE=1
sudo python daemon/boundary_daemon.py

# This will:
# - Install udev rules to block USB devices
# - De-authorize USB storage in restricted modes
# - Block all USB in LOCKDOWN mode
```

### Process Enforcer

```bash
# Enable process enforcement (requires root + container runtime)
export BOUNDARY_PROCESS_ENFORCE=1
sudo python daemon/boundary_daemon.py

# This will:
# - Apply seccomp-bpf filters to managed processes
# - Run workloads in isolated containers
# - Block dangerous syscalls based on mode
```

### Requirements for Enforcement

| Enforcer | Requirements |
|----------|--------------|
| Network | Root, iptables/nftables |
| USB | Root, udev |
| Process | Root, seccomp, podman/docker |

**Without these prerequisites, enforcers log warnings but cannot block operations.**

---

## External Watchdog System

The daemon includes a hardened external watchdog that monitors the daemon and triggers emergency lockdown if it fails. This addresses the critical vulnerability: "Daemon Can Be Killed."

### Architecture

```
                    ┌─────────────────────────────────────┐
                    │              systemd                 │
                    │  (restarts services, WatchdogSec)   │
                    └─────────────────────────────────────┘
                                     │
                                     ▼
                    ┌─────────────────────────────────────┐
                    │        boundary-daemon.service       │
                    │  (policy decisions, enforcement)     │
                    └─────────────────────────────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    ▼                                 ▼
          ┌─────────────────┐             ┌─────────────────────┐
          │ Primary Watchdog │◄───────────►│ Secondary Watchdog  │
          │  (monitors daemon)│             │  (monitors primary) │
          └─────────────────┘             └─────────────────────┘
                    │                                 │
                    └────────────────┬────────────────┘
                                     ▼
                            ┌─────────────────┐
                            │    LOCKDOWN     │
                            │  (iptables)     │
                            └─────────────────┘
```

### Features

| Feature | Description |
|---------|-------------|
| **Cryptographic Heartbeats** | HMAC-SHA256 challenge-response authentication |
| **Process Hardening** | prctl protections, signal handlers |
| **Systemd Integration** | Uses sd_notify for kernel-level monitoring |
| **Hardware Watchdog** | Optional /dev/watchdog integration |
| **Multi-Watchdog** | Primary + secondary for redundancy |
| **Fail-Closed** | Triggers iptables lockdown on failure |

### Quick Setup

```bash
# Install with setup script
sudo ./scripts/setup-watchdog.sh --install

# Or with redundant secondary watchdog
sudo ./scripts/setup-watchdog.sh --install --secondary

# Check status
sudo ./scripts/setup-watchdog.sh --status
```

### Manual Setup

```bash
# 1. Copy service files
sudo cp systemd/boundary-daemon.service /etc/systemd/system/
sudo cp systemd/boundary-watchdog.service /etc/systemd/system/

# 2. Create directories
sudo mkdir -p /var/log/boundary-daemon /var/run/boundary-daemon
sudo chmod 700 /var/log/boundary-daemon /var/run/boundary-daemon

# 3. Install and enable
sudo systemctl daemon-reload
sudo systemctl enable boundary-daemon boundary-watchdog
sudo systemctl start boundary-daemon boundary-watchdog

# 4. Verify
sudo systemctl status boundary-daemon boundary-watchdog
```

### What Happens on Daemon Failure

When the watchdog detects the daemon is unresponsive:

1. **Challenge-Response Fails**: Daemon doesn't respond to cryptographic heartbeat
2. **Failure Counter Increments**: 3 consecutive failures trigger lockdown
3. **Emergency Lockdown**:
   - All iptables policies set to DROP
   - Syslog alert sent
   - Wall message broadcast
   - Lockdown indicator file created
4. **Manual Intervention Required**: System stays locked until admin recovers

### Monitoring Watchdog Status

```bash
# Check service status
sudo systemctl status boundary-watchdog

# View watchdog logs
sudo journalctl -u boundary-watchdog -f

# Check for lockdown state
cat /var/run/boundary-daemon/LOCKDOWN
```

### Redundancy with Secondary Watchdog

For maximum protection, run a secondary watchdog that monitors both the daemon AND the primary watchdog:

```bash
# Enable secondary watchdog
sudo cp systemd/boundary-watchdog-secondary.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable boundary-watchdog-secondary
sudo systemctl start boundary-watchdog-secondary
```

The secondary watchdog:
- Monitors the primary watchdog's heartbeat socket
- Triggers lockdown if both daemon AND primary watchdog fail
- Makes it much harder to silently disable monitoring

---

## Security Considerations

### What IS Protected

When properly integrated with cooperating systems:

| Asset | Protection Mechanism |
|-------|---------------------|
| Audit trail | Hash-chained immutable log |
| Policy consistency | Centralized decision authority |
| Violation detection | Continuous monitoring + tripwires |
| Mode transitions | Logged with operator attribution |

### What IS NOT Protected

Without kernel/hardware enforcement:

| Risk | Why Not Protected |
|------|-------------------|
| Malicious code | Can ignore daemon decisions |
| Root user | Can kill daemon, modify logs |
| Network exfiltration | Detection is after-the-fact |
| USB data theft | Detection after mounting |

### Attack Scenarios

**Scenario 1: Non-cooperative Application**
```python
# Malicious code simply ignores the daemon
secret = memory_vault.read_raw(memory_id)  # Never calls check_recall
send_to_external_server(secret)  # Daemon never knew
```

**Scenario 2: Race Condition**
```
T=0.0: Daemon polls - network offline ✓
T=0.1: Attacker enables WiFi
T=0.5: Attacker exfiltrates data
T=1.0: Daemon polls - detects network, triggers lockdown
       (Too late - data already exfiltrated)
```

**Scenario 3: Daemon Termination**
```bash
sudo kill -9 $(pgrep boundary_daemon)
# System continues operating with no policy checks
```

---

## Recommendations

### For Development/Testing

The daemon works well as-is for:
- Developing security-aware applications
- Testing policy logic
- Creating audit trails
- Coordinating between components

### For Production Security

Add enforcement layers:

1. **Run in containers** with network=none for sensitive workloads
2. **Use SELinux/AppArmor** policies to restrict processes
3. **Deploy iptables rules** independent of daemon
4. **Enable daemon enforcers** with root privileges
5. **Use hardware controls** for highest-sensitivity data

### Integration Checklist

- [ ] All components call daemon before sensitive operations
- [ ] Components raise exceptions on DENY (don't ignore)
- [ ] Kernel-level enforcement matches daemon modes
- [ ] Container isolation for workload separation
- [ ] Hardware controls for physical security
- [ ] Log forwarding to external SIEM
- [x] Watchdog to detect daemon failure (see [External Watchdog System](#external-watchdog-system))

---

## Conclusion

The Boundary Daemon is a valuable component for:
- **Policy coordination** across distributed systems
- **Audit logging** with cryptographic integrity
- **Environment monitoring** and violation detection
- **Decision authority** that other systems respect

It is NOT a standalone security solution. For actual data protection, combine with kernel-level and hardware-level enforcement mechanisms.

**Think of it as:** A security guard who checks IDs and logs visitors, but cannot physically stop someone who runs past them. The guard is useful, but you also need locked doors (kernel enforcement) and walls (hardware controls).

---

## See Also

- [SECURITY_AUDIT.md](SECURITY_AUDIT.md) - Detailed security audit findings
- [SPEC.md](SPEC.md) - Complete technical specification
- [test_bypass_vulnerability.py](test_bypass_vulnerability.py) - Proof-of-concept bypass demonstrations
