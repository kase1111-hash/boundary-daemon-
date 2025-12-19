# Boundary Daemon - Complete Technical Specification

**Version:** 1.0
**Status:** Active Development
**Last Updated:** 2025-12-19

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Current Implementation Status](#current-implementation-status)
4. [Unimplemented Features](#unimplemented-features)
5. [Implementation Plans](#implementation-plans)
6. [API Specification](#api-specification)
7. [Security Model](#security-model)
8. [Deployment](#deployment)

---

## System Overview

### Purpose

The Boundary Daemon (codenamed "Agent Smith") is the mandatory trust enforcement layer for Agent OS. It defines and maintains trust boundaries for learning co-worker systems, determining where cognition is allowed to flow and where it must stop.

### Core Responsibilities

1. **Environment Sensing** - Detect current trust conditions
2. **Mode Enforcement** - Enforce boundary modes based on environment
3. **Recall Gating** - Permit or deny memory recall operations
4. **Execution Gating** - Restrict tools, IO, and model access
5. **Tripwire Response** - Detect violations and trigger lockdown
6. **Audit Signaling** - Emit immutable boundary events

### Design Principles

- **Authoritative**: Daemon decisions cannot be overridden programmatically
- **Fail-Closed**: Uncertainty defaults to DENY
- **Deterministic**: Same inputs always produce same decision
- **Immutable Logging**: All events logged with tamper-evident chain
- **Human Oversight**: Overrides require ceremony, never silent
- **Minimal Dependencies**: Small attack surface by design

---

## Architecture

### Component Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                    Boundary Daemon (Main)                    │
│                   boundary_daemon.py                         │
└────┬──────────────┬──────────────┬──────────────┬───────────┘
     │              │              │              │
     ▼              ▼              ▼              ▼
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│  State   │  │  Policy  │  │Tripwire  │  │  Event   │
│ Monitor  │  │  Engine  │  │  System  │  │  Logger  │
└──────────┘  └──────────┘  └──────────┘  └──────────┘
     │              │              │              │
     └──────────────┴──────────────┴──────────────┘
                         │
                         ▼
              ┌──────────────────┐
              │   API Server     │
              │   (Unix Socket)  │
              └──────────────────┘
                         │
                         ▼
              ┌──────────────────┐
              │  Integration     │
              │  Interfaces      │
              └──────────────────┘
```

### Boundary Modes

| Mode | Network | Memory Classes | Tools | Use Case |
|------|---------|----------------|-------|----------|
| **OPEN** | ✓ Online | 0-1 | All | Casual use |
| **RESTRICTED** | ✓ Online | 0-2 | Most | Research |
| **TRUSTED** | VPN only | 0-3 | No USB | Serious work |
| **AIRGAP** | ✗ Offline | 0-4 | No network | High-value IP |
| **COLDROOM** | ✗ Offline | 0-5 | Display only | Crown jewels |
| **LOCKDOWN** | ✗ Blocked | None | None | Emergency |

### Memory Classification

| Level | Name | Minimum Mode | Description |
|-------|------|--------------|-------------|
| 0 | PUBLIC | OPEN | Public information |
| 1 | INTERNAL | OPEN | Internal use only |
| 2 | CONFIDENTIAL | RESTRICTED | Confidential data |
| 3 | SECRET | TRUSTED | Secret information |
| 4 | TOP_SECRET | AIRGAP | Top secret data |
| 5 | CROWN_JEWEL | COLDROOM | Crown jewel IP |

---

## Current Implementation Status

### ✅ Fully Implemented

#### 1. State Monitor (`state_monitor.py`)
- **Network Detection**: Active interfaces, internet connectivity, VPN detection, DNS availability
- **Hardware Monitoring**: USB devices, block devices, camera/mic detection, TPM presence
- **Software Detection**: External model endpoints (heuristic), suspicious processes, shell escapes
- **Human Presence**: Login detection, activity tracking
- **Polling**: 1 Hz continuous monitoring with change callbacks
- **Trust Calculation**: Hardware trust levels (LOW/MEDIUM/HIGH)

#### 2. Policy Engine (`policy_engine.py`)
- **Boundary Modes**: All 6 modes implemented (OPEN → LOCKDOWN)
- **Memory Policy**: Memory class to mode mapping fully implemented
- **Tool Policy**: Network/filesystem/USB requirement evaluation
- **Model Policy**: External model access restrictions
- **IO Policy**: Input/output restriction evaluation
- **Mode Transitions**: With operator tracking and callbacks
- **Environment Updates**: Integration with state monitor

#### 3. Tripwire System (`tripwires.py`)
- **Violation Detection**: Network in AIRGAP, USB in COLDROOM, external models, suspicious processes
- **Lockdown Manager**: Lockdown triggering and state management
- **Violation Tracking**: Complete violation history with metadata
- **Callback System**: Notification of security violations
- **Baseline Tracking**: USB and network state baselines
- **Health Checks**: Basic daemon integrity checks

#### 4. Event Logger (`event_logger.py`)
- **Hash Chain**: SHA-256 blockchain-style event chaining
- **Event Types**: MODE_CHANGE, VIOLATION, TRIPWIRE, RECALL_ATTEMPT, TOOL_REQUEST, OVERRIDE, etc.
- **Immutable Log**: Append-only with fsync guarantees
- **Chain Verification**: Complete integrity verification
- **Event Retrieval**: Recent events, filtered by type
- **Log Export**: Archival capabilities

#### 5. Integration Interfaces (`integrations.py`)
- **RecallGate**: Memory Vault integration for recall gating
- **ToolGate**: Agent-OS integration for tool execution
- **CeremonyManager**: Human override ceremony (3-step process with cooldown)
- **Capability Queries**: Mode-based capability discovery

#### 6. API Server (`boundary_api.py`)
- **Unix Socket**: Local-only communication
- **Commands**: status, check_recall, check_tool, set_mode, get_events, verify_log
- **Client Library**: Full Python client implementation
- **JSON Protocol**: Request/response serialization
- **Thread Safety**: Concurrent request handling

#### 7. CLI Tool (`boundaryctl`)
- **Commands**: status, check-recall, check-tool, set-mode, events, verify, watch
- **Live Monitoring**: Real-time status updates
- **Formatted Output**: Human-readable status and event display

#### 8. Main Daemon (`boundary_daemon.py`)
- **Component Orchestration**: All subsystems integrated
- **Callback Wiring**: Inter-component communication
- **Health Checks**: Periodic integrity verification
- **Signal Handling**: Graceful shutdown (SIGINT/SIGTERM)
- **Public API**: check_recall_permission, check_tool_permission, get_status

### ⚠️ Partially Implemented / Limited

#### 1. Enforcement Mechanism
- **Status**: Detection-only, no actual prevention
- **What Works**: Logging, policy decisions, denial responses
- **What's Missing**: Cannot physically block operations (network, USB, filesystem)
- **Impact**: System is voluntary - components can ignore denials

#### 2. Human Presence Verification
- **Status**: Basic keyboard input only
- **What Works**: Input prompts, cooldown delays
- **What's Missing**: True biometric verification, hardware tokens
- **Impact**: Ceremony can be automated/scripted

#### 3. Log Tamper-Proofing
- **Status**: Hash chain works, but file can be deleted/replaced
- **What Works**: Chain verification detects tampering
- **What's Missing**: Append-only filesystem, remote logging, HSM integration
- **Impact**: Entire log file can be deleted

#### 4. External Model Detection
- **Status**: Heuristic-based process scanning
- **What Works**: Detects common API endpoints in command lines
- **What's Missing**: Deep packet inspection, encrypted traffic analysis
- **Impact**: Easy to bypass with encoding/proxying

### ❌ Not Implemented (Documented Only)

See [Unimplemented Features](#unimplemented-features) section below.

---

## Unimplemented Features

### Critical Security Gaps (from SECURITY_AUDIT.md findings)

#### 1. **Kernel-Level Enforcement**
- **Current State**: User-space Python daemon, no actual blocking
- **What's Needed**:
  - SELinux/AppArmor policies
  - seccomp-bpf syscall filtering
  - eBPF network filtering
  - Mandatory Access Control (MAC)
- **Impact**: Without this, system provides audit trail only, not enforcement

#### 2. **Network Blocking**
- **Current State**: Detects network state, logs violations
- **What's Needed**:
  - iptables/nftables rule management
  - Network namespace isolation
  - Physical interface disabling
  - Socket syscall interception
- **Impact**: Data can be exfiltrated in AIRGAP mode

#### 3. **USB Prevention**
- **Current State**: Detects USB insertion after it's already mounted
- **What's Needed**:
  - udev rules to prevent mounting
  - Kernel module blacklisting
  - Hardware-level USB port control
  - BIOS USB disabling automation
- **Impact**: USB devices accessible before lockdown triggers

#### 4. **Process Isolation**
- **Current State**: No isolation, daemon is killable
- **What's Needed**:
  - Container/VM isolation for protected workloads
  - Daemon as PID 1 in namespace
  - Watchdog process (external to daemon)
  - Hardware watchdog timer integration
- **Impact**: Daemon can be killed, disabling all "protection"

#### 5. **Clock Drift Protection**
- **Current State**: Mentioned in specs, not implemented
- **What's Needed**:
  - NTP sync verification
  - Monotonic clock usage
  - Time manipulation detection
  - Mode transition freezing on clock skew
- **Impact**: Time-based attacks possible

### Enhancement Features (from ARCHITECTURE.md)

#### 6. **TPM Integration**
- **Status**: Not implemented
- **Purpose**: Bind boundary modes to TPM sealed secrets
- **Use Case**: Hardware-backed mode attestation, tamper detection

#### 7. **Biometric Confirmation**
- **Status**: Not implemented
- **Purpose**: Replace keyboard input with fingerprint/face recognition
- **Use Case**: Stronger human presence verification in ceremonies

#### 8. **Network Attestation**
- **Status**: Not implemented
- **Purpose**: Cryptographically verify VPN/network trust levels
- **Use Case**: Ensure TRUSTED mode actually has trusted network

#### 9. **Log Signing**
- **Status**: Not implemented
- **Purpose**: Cryptographically sign each event with private key
- **Use Case**: Non-repudiation, external verification

#### 10. **Distributed Deployment**
- **Status**: Not implemented
- **Purpose**: Multi-host boundary coordination
- **Use Case**: Cluster-wide security policies

#### 11. **Custom Policy Language**
- **Status**: Not implemented
- **Purpose**: User-defined policy rules beyond hardcoded logic
- **Use Case**: Organization-specific security policies

### Quality & Hardening Features

#### 12. **API Authentication**
- **Status**: Not implemented
- **Current**: Anyone with socket access can query daemon
- **What's Needed**: Token-based auth, capability-based access

#### 13. **Rate Limiting**
- **Status**: Not implemented
- **Current**: API can be spammed with requests
- **What's Needed**: Request throttling, backoff mechanisms

#### 14. **Code Signing & Integrity**
- **Status**: Not implemented
- **Current**: Daemon doesn't verify itself
- **What's Needed**: Startup integrity checks, module verification

#### 15. **Append-Only Log Storage**
- **Status**: Not implemented
- **Current**: Regular file with fsync
- **What's Needed**: chattr +a, immutable filesystem, remote syslog

#### 16. **Hardware Security Module (HSM)**
- **Status**: Not implemented
- **Purpose**: Secure key storage for log signing, mode sealing
- **Use Case**: Cryptographic operations in secure enclave

#### 17. **Secure Boot Integration**
- **Status**: Not implemented
- **Purpose**: Verify daemon is authentic during system boot
- **Use Case**: Prevent unauthorized daemon replacement

---

## Implementation Plans

### Plan 1: Kernel-Level Enforcement (Priority: CRITICAL)

**Goal**: Transform from detection-only to actual enforcement system.

**Components**:
1. **SELinux/AppArmor Policy Generator**
2. **iptables/nftables Rule Manager**
3. **udev USB Rule Manager**
4. **seccomp-bpf Filter Installer**

**Implementation Steps**:

#### Phase 1: Network Enforcement (4-6 weeks)
```python
# New module: daemon/enforcement/network_enforcer.py

class NetworkEnforcer:
    """Enforces network restrictions using iptables/nftables"""

    def __init__(self, daemon):
        self.daemon = daemon
        self.firewall_backend = self._detect_firewall()  # iptables or nftables

    def enforce_airgap_mode(self):
        """Block all network traffic except loopback"""
        if self.firewall_backend == 'iptables':
            subprocess.run(['iptables', '-P', 'INPUT', 'DROP'])
            subprocess.run(['iptables', '-P', 'OUTPUT', 'DROP'])
            subprocess.run(['iptables', '-P', 'FORWARD', 'DROP'])
            # Allow loopback
            subprocess.run(['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'])
            subprocess.run(['iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'])
        # ... nftables implementation

    def enforce_trusted_mode(self, vpn_interface: str):
        """Allow only VPN traffic"""
        # Block all except loopback and VPN interface
        self._block_all_except([vpn_interface, 'lo'])

    def restore_open_mode(self):
        """Restore full network access"""
        self._flush_rules()
        subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'])
        subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'])
```

**Integration**:
- Add to `PolicyEngine.transition_mode()` - apply network rules on mode change
- Add to `TripwireSystem` - immediate enforcement on violation
- Requires root privileges
- Add rollback mechanism if rules fail to apply

**Testing**:
- Unit tests: Verify correct iptables commands generated
- Integration tests: Actual network blocking in VM
- Failure tests: Network still accessible if daemon crashes

**Risks**:
- Locked out of system if misconfigured
- Requires root access
- Platform-dependent (Linux-only)

**Deliverables**:
- `daemon/enforcement/network_enforcer.py`
- Updated `PolicyEngine` integration
- Systemd service updates (requires CAP_NET_ADMIN)
- Documentation in `ENFORCEMENT.md`

---

#### Phase 2: USB Prevention (3-4 weeks)
```python
# New module: daemon/enforcement/usb_enforcer.py

class USBEnforcer:
    """Prevents USB device mounting using udev rules"""

    UDEV_RULE_PATH = '/etc/udev/rules.d/99-boundary-usb-block.rules'

    def __init__(self, daemon):
        self.daemon = daemon

    def block_all_usb(self):
        """Install udev rule to block USB storage"""
        rule = '''
# Boundary Daemon: Block USB storage in COLDROOM mode
ACTION=="add", SUBSYSTEMS=="usb", ATTRS{bDeviceClass}=="08", RUN+="/bin/sh -c 'echo 0 > /sys$env{DEVPATH}/authorized'"
'''
        with open(self.UDEV_RULE_PATH, 'w') as f:
            f.write(rule)
        subprocess.run(['udevadm', 'control', '--reload-rules'])

    def allow_usb(self):
        """Remove USB blocking rule"""
        if os.path.exists(self.UDEV_RULE_PATH):
            os.unlink(self.UDEV_RULE_PATH)
        subprocess.run(['udevadm', 'control', '--reload-rules'])

    def eject_all_usb(self):
        """Forcibly unmount and eject all USB devices"""
        # Find all USB storage devices
        for device in self._find_usb_storage():
            subprocess.run(['umount', device])
            # De-authorize USB port
            auth_path = f'/sys/bus/usb/devices/{device}/authorized'
            if os.path.exists(auth_path):
                with open(auth_path, 'w') as f:
                    f.write('0')
```

**Integration**:
- Apply on COLDROOM mode entry
- Remove on mode downgrade
- Log all USB events before blocking

**Testing**:
- Verify USB devices cannot mount
- Verify existing USB is ejected
- Test recovery on mode change

---

#### Phase 3: Process Isolation (5-7 weeks)
```python
# New module: daemon/enforcement/container_enforcer.py

class ContainerEnforcer:
    """Runs protected workloads in isolated containers"""

    def __init__(self, daemon):
        self.daemon = daemon
        self.container_runtime = 'podman'  # or 'docker'

    def create_secure_container(self, mode: BoundaryMode):
        """Create container with mode-appropriate restrictions"""
        config = {
            BoundaryMode.AIRGAP: {
                'network': 'none',
                'capabilities': ['drop', 'ALL'],
                'read_only': True,
                'no_new_privileges': True
            },
            BoundaryMode.COLDROOM: {
                'network': 'none',
                'devices': [],  # No devices
                'volumes': [],  # No volumes
                'security_opt': ['no-new-privileges', 'seccomp=unconfined']
            }
        }

        # Create container with restrictions
        return self._launch_container(config[mode])
```

**External Watchdog**:
```python
# New tool: watchdog/boundary_watchdog.py

class BoundaryWatchdog:
    """External process that monitors daemon health"""

    def __init__(self):
        self.daemon_pid = self._find_daemon_pid()
        self.last_heartbeat = time.time()

    def monitor_loop(self):
        """Check daemon health every second"""
        while True:
            if not self._daemon_is_healthy():
                self._trigger_emergency_lockdown()
            time.sleep(1)

    def _trigger_emergency_lockdown(self):
        """System-level lockdown if daemon fails"""
        # Block all network
        subprocess.run(['iptables', '-P', 'INPUT', 'DROP'])
        subprocess.run(['iptables', '-P', 'OUTPUT', 'DROP'])
        # Alert
        subprocess.run(['wall', 'BOUNDARY DAEMON FAILURE - EMERGENCY LOCKDOWN'])
        # Optionally: halt system
        # subprocess.run(['systemctl', 'emergency'])
```

---

### Plan 2: TPM Integration (Priority: HIGH)

**Goal**: Hardware-backed mode attestation and secret sealing.

**Duration**: 4-6 weeks

**Dependencies**:
- tpm2-tools installed
- TPM 2.0 chip present
- tpm2-pytss Python library

**Implementation**:

```python
# New module: daemon/hardware/tpm_manager.py

import tpm2_pytss

class TPMManager:
    """Manages TPM-backed security features"""

    def __init__(self):
        self.tpm = tpm2_pytss.ESAPI()
        self.pcr_index = 16  # User PCR for boundary mode

    def seal_mode_secret(self, mode: BoundaryMode, secret: bytes):
        """Seal a secret to current boundary mode"""
        # Extend PCR with mode value
        mode_hash = hashlib.sha256(mode.name.encode()).digest()
        self.tpm.PCR_Extend(self.pcr_index, mode_hash)

        # Seal secret to PCR value
        policy = self.tpm.PolicyPCR(self.pcr_index)
        sealed_blob = self.tpm.Create(secret, policy=policy)
        return sealed_blob

    def unseal_mode_secret(self, sealed_blob: bytes) -> bytes:
        """Unseal secret (only works if mode matches)"""
        # Will fail if PCR has changed (mode changed)
        return self.tpm.Unseal(sealed_blob)

    def verify_mode_integrity(self, mode: BoundaryMode) -> bool:
        """Verify current mode matches TPM PCR"""
        current_pcr = self.tpm.PCR_Read(self.pcr_index)
        expected = self._compute_mode_pcr(mode)
        return current_pcr == expected

    def bind_mode_to_tpm(self, mode: BoundaryMode):
        """Record mode transition in TPM"""
        mode_hash = hashlib.sha256(mode.name.encode()).digest()
        self.tpm.PCR_Extend(self.pcr_index, mode_hash)
        self.daemon.event_logger.log_event(
            EventType.MODE_CHANGE,
            f"Mode {mode.name} bound to TPM PCR {self.pcr_index}",
            metadata={'pcr_value': current_pcr.hex()}
        )
```

**Integration Points**:
- `PolicyEngine.transition_mode()` - extend TPM PCR on mode change
- `RecallGate` - unseal encryption keys only if mode is correct
- Health checks - verify PCR matches expected mode

**Use Cases**:
1. **Mode Attestation**: Cryptographic proof of current mode
2. **Key Sealing**: Encrypt memory vault keys, only accessible in correct mode
3. **Tamper Detection**: PCR mismatch indicates unauthorized mode change

**Testing**:
- VM with virtual TPM (swtpm)
- Verify secret unsealing fails when mode changes
- Test PCR reset on reboot

---

### Plan 3: Cryptographic Log Signing (Priority: MEDIUM)

**Goal**: Non-repudiable event logs with external verification.

**Duration**: 2-3 weeks

**Implementation**:

```python
# Enhanced: daemon/event_logger.py

import nacl.signing
import nacl.encoding

class SignedEventLogger(EventLogger):
    """Event logger with cryptographic signatures"""

    def __init__(self, log_file_path: str, signing_key_path: str):
        super().__init__(log_file_path)
        self.signing_key = self._load_or_create_signing_key(signing_key_path)

    def log_event(self, event_type: EventType, details: str,
                  metadata: Optional[Dict] = None) -> BoundaryEvent:
        """Log event with cryptographic signature"""
        event = super().log_event(event_type, details, metadata)

        # Sign the event
        event_data = event.to_json().encode()
        signature = self.signing_key.sign(event_data)

        # Append signature to log
        signature_record = {
            'event_id': event.event_id,
            'signature': signature.signature.hex(),
            'public_key': self.signing_key.verify_key.encode(
                encoder=nacl.encoding.HexEncoder
            ).decode()
        }

        with open(self.log_file_path + '.sig', 'a') as f:
            f.write(json.dumps(signature_record) + '\n')

        return event

    def verify_signatures(self) -> tuple[bool, Optional[str]]:
        """Verify all event signatures"""
        # Read events and signatures
        events = self._read_all_events()
        signatures = self._read_all_signatures()

        for event, sig_record in zip(events, signatures):
            if event.event_id != sig_record['event_id']:
                return (False, f"Signature mismatch for event {event.event_id}")

            # Verify signature
            verify_key = nacl.signing.VerifyKey(
                sig_record['public_key'],
                encoder=nacl.encoding.HexEncoder
            )

            try:
                verify_key.verify(
                    event.to_json().encode(),
                    bytes.fromhex(sig_record['signature'])
                )
            except nacl.exceptions.BadSignatureError:
                return (False, f"Invalid signature for event {event.event_id}")

        return (True, None)
```

**Benefits**:
- External parties can verify log authenticity
- Non-repudiation of events
- Detect if logs were regenerated

**Key Management**:
- Private key stored in TPM or HSM
- Public key published externally
- Key rotation policy

---

### Plan 4: Distributed Deployment (Priority: LOW)

**Goal**: Coordinate boundary policies across multiple hosts.

**Duration**: 8-12 weeks

**Architecture**:
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Host 1     │     │  Host 2     │     │  Host 3     │
│  Boundary   │────▶│  Boundary   │────▶│  Boundary   │
│  Daemon     │     │  Daemon     │     │  Daemon     │
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │
       └───────────────────┴───────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  Coordinator    │
                  │  (etcd/consul)  │
                  └─────────────────┘
```

**Features**:
- Cluster-wide mode enforcement
- Distributed tripwire detection
- Synchronized mode transitions
- Federated event logging

**Implementation Sketch**:
```python
# New module: daemon/distributed/cluster_manager.py

class ClusterManager:
    """Manages distributed boundary daemon cluster"""

    def __init__(self, coordinator_url: str):
        self.coordinator = etcd3.client(host=coordinator_url)
        self.node_id = self._register_node()

    def broadcast_mode_change(self, mode: BoundaryMode):
        """Notify all cluster nodes of mode change"""
        self.coordinator.put(
            f'/boundary/cluster/mode',
            mode.name,
            lease=self._get_lease()
        )

    def sync_mode_with_cluster(self) -> BoundaryMode:
        """Get cluster-wide mode (most restrictive wins)"""
        nodes = self.coordinator.get_prefix('/boundary/nodes/')
        modes = [BoundaryMode[node.value.decode()] for node in nodes]
        return max(modes)  # Most restrictive

    def report_violation(self, violation: TripwireViolation):
        """Report violation to cluster"""
        self.coordinator.put(
            f'/boundary/violations/{violation.violation_id}',
            json.dumps(violation.to_dict())
        )
```

---

### Plan 5: Custom Policy Language (Priority: LOW)

**Goal**: User-defined policy rules beyond hardcoded logic.

**Duration**: 6-8 weeks

**Example Policy Syntax**:
```yaml
# /etc/boundary-daemon/policies.d/custom.yaml

policies:
  - name: "Block API keys in AIRGAP"
    condition:
      mode: [AIRGAP, COLDROOM]
      environment:
        processes:
          contains: "OPENAI_API_KEY"
    action: DENY

  - name: "Require VPN for confidential memories"
    condition:
      memory_class: [CONFIDENTIAL, SECRET]
      environment:
        vpn_active: false
    action: DENY

  - name: "Allow filesystem tools in development mode"
    condition:
      mode: [OPEN, RESTRICTED]
      tool:
        requires_filesystem: true
        name_pattern: "^(cat|ls|grep)$"
    action: ALLOW
```

**Implementation**:
```python
# New module: daemon/policy/custom_policy_engine.py

class CustomPolicyEngine:
    """Evaluates user-defined policy rules"""

    def __init__(self, policy_dir: str):
        self.policies = self._load_policies(policy_dir)

    def evaluate(self, request: PolicyRequest,
                 env: EnvironmentState) -> Optional[PolicyDecision]:
        """Evaluate custom policies"""
        for policy in self.policies:
            if self._matches_condition(policy['condition'], request, env):
                return PolicyDecision[policy['action']]
        return None  # Fall through to default policy

    def _matches_condition(self, condition: dict,
                          request: PolicyRequest,
                          env: EnvironmentState) -> bool:
        """Check if condition matches current state"""
        # Mode check
        if 'mode' in condition:
            if env.mode.name not in condition['mode']:
                return False

        # Environment checks
        if 'environment' in condition:
            if not self._check_environment(condition['environment'], env):
                return False

        # Request checks
        if 'memory_class' in condition:
            if request.memory_class.name not in condition['memory_class']:
                return False

        return True
```

---

### Plan 6: Biometric Authentication (Priority: MEDIUM)

**Goal**: Replace keyboard ceremony with fingerprint/face recognition.

**Duration**: 3-4 weeks

**Dependencies**:
- libfprint (fingerprint)
- OpenCV + face_recognition (face)
- Hardware: fingerprint reader or webcam

**Implementation**:
```python
# New module: daemon/auth/biometric_verifier.py

import fprint
import face_recognition

class BiometricVerifier:
    """Biometric authentication for ceremonies"""

    def __init__(self, enrolled_fingerprints: list = None):
        self.fp_device = fprint.Device()
        self.enrolled_prints = enrolled_fingerprints or []

    def verify_fingerprint(self) -> bool:
        """Verify user fingerprint"""
        print("Place finger on reader...")
        sample = self.fp_device.enroll_finger()

        for enrolled in self.enrolled_prints:
            if fprint.compare(sample, enrolled) > 0.7:
                return True
        return False

    def verify_face(self) -> bool:
        """Verify user face with webcam"""
        import cv2

        # Capture frame
        camera = cv2.VideoCapture(0)
        ret, frame = camera.read()
        camera.release()

        # Detect face
        face_locations = face_recognition.face_locations(frame)
        if not face_locations:
            return False

        # Compare with enrolled faces
        face_encoding = face_recognition.face_encodings(frame, face_locations)[0]
        matches = face_recognition.compare_faces(
            self.enrolled_faces,
            face_encoding
        )
        return any(matches)

# Integration into CeremonyManager
class EnhancedCeremonyManager(CeremonyManager):
    def __init__(self, daemon, biometric_verifier: BiometricVerifier):
        super().__init__(daemon)
        self.biometric = biometric_verifier

    def _verify_human_presence(self, confirmation_callback=None) -> bool:
        """Use biometric instead of keyboard"""
        print("Biometric verification required...")
        return self.biometric.verify_fingerprint()
```

**Enrollment Process**:
```bash
# New CLI command
boundaryctl enroll-fingerprint
boundaryctl enroll-face
boundaryctl list-enrolled
```

---

## API Specification

### Unix Socket API

**Socket Path**: `/var/run/boundary-daemon/boundary.sock` (production) or `./api/boundary.sock` (dev)

**Protocol**: JSON over Unix domain socket

**Request Format**:
```json
{
  "command": "status|check_recall|check_tool|set_mode|get_events|verify_log",
  "params": {
    // Command-specific parameters
  }
}
```

**Response Format**:
```json
{
  "success": true,
  "// ... command-specific fields"
}
```

### Commands

#### 1. `status`
Get current daemon status.

**Request**:
```json
{"command": "status"}
```

**Response**:
```json
{
  "success": true,
  "status": {
    "running": true,
    "boundary_state": {
      "mode": "airgap",
      "network": "offline",
      "hardware_trust": "high",
      "external_models": false,
      "last_transition": "2025-12-19T10:30:00Z",
      "operator": "human"
    },
    "environment": {
      "network": "offline",
      "active_interfaces": [],
      "has_internet": false,
      "vpn_active": false,
      "usb_devices": ["1-1", "1-2"],
      // ... more environment data
    },
    "lockdown": null,
    "event_count": 1234,
    "tripwire_violations": 2
  }
}
```

#### 2. `check_recall`
Check if memory recall is permitted.

**Request**:
```json
{
  "command": "check_recall",
  "params": {
    "memory_class": 3
  }
}
```

**Response**:
```json
{
  "success": true,
  "permitted": false,
  "reason": "Recall denied: requires TRUSTED mode, currently in OPEN",
  "memory_class": 3
}
```

#### 3. `check_tool`
Check if tool execution is permitted.

**Request**:
```json
{
  "command": "check_tool",
  "params": {
    "tool_name": "wget",
    "requires_network": true,
    "requires_filesystem": false,
    "requires_usb": false
  }
}
```

**Response**:
```json
{
  "success": true,
  "permitted": false,
  "reason": "Tool execution denied by policy",
  "tool_name": "wget"
}
```

#### 4. `set_mode`
Request boundary mode change.

**Request**:
```json
{
  "command": "set_mode",
  "params": {
    "mode": "airgap",
    "operator": "human",
    "reason": "Working on sensitive project"
  }
}
```

**Response**:
```json
{
  "success": true,
  "message": "Transitioned from OPEN to AIRGAP",
  "new_mode": "airgap"
}
```

#### 5. `get_events`
Retrieve recent events.

**Request**:
```json
{
  "command": "get_events",
  "params": {
    "count": 100,
    "event_type": "violation"  // optional
  }
}
```

**Response**:
```json
{
  "success": true,
  "events": [
    {
      "event_id": "uuid",
      "timestamp": "2025-12-19T10:30:00Z",
      "event_type": "tripwire",
      "details": "Network came online in AIRGAP mode",
      "metadata": {...},
      "hash_chain": "abc123..."
    }
  ],
  "count": 1
}
```

#### 6. `verify_log`
Verify event log integrity.

**Request**:
```json
{"command": "verify_log"}
```

**Response**:
```json
{
  "success": true,
  "valid": true,
  "error": null
}
```

---

## Security Model

### Threat Model

#### Protected Against
- Remote attackers (network-based)
- Local malware (process monitoring, tripwires)
- Rogue agents (mandatory gating)
- Accidental misuse (fail-closed design)
- Gradual erosion (immutable logs)
- Supply chain attacks (offline verification)

#### Not Protected Against (Current Implementation)
- Root user bypassing daemon
- Kernel-level attacks
- Hardware attacks (DMA, physical access)
- Sophisticated malware that can kill daemon
- Time-based attacks (clock manipulation)

### Security Properties

#### 1. Fail-Closed
- Unknown states → DENY
- Component failures → LOCKDOWN
- Ambiguous signals → DENY
- Daemon crash → **No protection** (see Plan 1, Phase 3 for watchdog)

#### 2. Immutable Logging
- SHA-256 hash chain (blockchain-style)
- Append-only file writes with fsync
- Chain verification detects tampering
- **Gap**: File can be deleted (see Plan 3)

#### 3. Deterministic Decisions
- Same inputs → same output
- No randomness in policy evaluation
- Reproducible for audit

#### 4. Mandatory Enforcement
- **Current**: Voluntary - components must choose to call daemon
- **Planned**: Kernel-level mandatory access control (see Plan 1)

#### 5. Human Oversight
- Three-step ceremony: presence → cooldown → confirmation
- 30-second mandatory delay (configurable)
- All overrides logged immutably
- **Gap**: Keyboard input can be automated (see Plan 6)

### Attack Scenarios & Mitigations

#### Scenario 1: Kill Daemon
**Attack**: `kill -9 <daemon_pid>`
**Current Defense**: None - daemon dies, no protection
**Planned**: External watchdog triggers emergency lockdown (Plan 1, Phase 3)

#### Scenario 2: Delete Event Log
**Attack**: `rm /var/log/boundary-daemon/boundary_chain.log`
**Current Defense**: None - file is deleted
**Planned**: Append-only filesystem (chattr +a), remote syslog (Plan 3)

#### Scenario 3: Bypass Network Detection
**Attack**: Enable network after state poll, before next poll (1-second window)
**Current Defense**: Tripwire triggers on next poll
**Planned**: eBPF network filtering, real-time enforcement (Plan 1, Phase 1)

#### Scenario 4: Fake Ceremony
**Attack**: `echo "PRESENT\nCONFIRM" | boundaryctl`
**Current Defense**: None - keyboard input accepted
**Planned**: Biometric verification (Plan 6)

#### Scenario 5: Time Travel
**Attack**: `date -s "2020-01-01"`
**Current Defense**: None - not implemented
**Planned**: Clock drift detection (mentioned in specs, needs implementation)

---

## Deployment

### Development Mode

```bash
# Clone repository
git clone <repository>
cd boundary-daemon

# Install dependencies
pip install -r requirements.txt

# Start daemon
python daemon/boundary_daemon.py --mode=open

# In another terminal, use CLI
./boundaryctl status
./boundaryctl check-recall 2
```

### Production Mode (Systemd Service)

```bash
# Install daemon
sudo python setup.py install

# Copy service file
sudo cp config/boundary-daemon.service /etc/systemd/system/

# Create directories
sudo mkdir -p /var/log/boundary-daemon
sudo mkdir -p /var/run/boundary-daemon

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable boundary-daemon
sudo systemctl start boundary-daemon

# Check status
sudo systemctl status boundary-daemon
boundaryctl status
```

### Configuration

**File**: `/etc/boundary-daemon/boundary.conf` (or `config/boundary.conf`)

```ini
[daemon]
initial_mode = open
log_dir = /var/log/boundary-daemon
socket_path = /var/run/boundary-daemon/boundary.sock
poll_interval = 1.0

[tripwires]
enabled = true
auto_lockdown = true

[ceremony]
cooldown_seconds = 30

[security]
fail_closed = true
require_root = true

[enforcement]
# Future: enforcement backends
network_enforcer = iptables
usb_enforcer = udev
```

### Hardware Requirements

**Minimum**:
- Linux kernel 4.4+
- Python 3.8+
- 50 MB RAM
- Minimal CPU (<1% idle)

**Recommended**:
- Linux kernel 5.10+ (for eBPF support)
- Python 3.10+
- TPM 2.0 chip
- 512 MB RAM allocated
- Root/sudo access

**Optional**:
- Fingerprint reader (for biometric auth)
- Webcam (for face recognition)
- HSM (for key storage)
- Hardware watchdog timer

### Platform Support

**Supported**:
- Linux (Debian, Ubuntu, RHEL, Arch)
- systemd-based distributions

**Not Supported**:
- Windows (fundamentally incompatible)
- macOS (would require significant rework)
- BSD (possible but not tested)

### Dependencies

**Core** (required):
```
psutil==5.9.0        # System monitoring
```

**Optional** (for enhancements):
```
tpm2-pytss           # TPM integration
PyNaCl               # Cryptographic signing
python-fprint        # Fingerprint reader
face-recognition     # Face recognition
opencv-python        # Camera access
python-etcd3         # Distributed deployment
```

---

## Appendices

### A. Event Types Reference

| Event Type | Description | Metadata Fields |
|------------|-------------|-----------------|
| MODE_CHANGE | Boundary mode transition | old_mode, new_mode, operator, reason |
| VIOLATION | Security violation detected | violation_type, details |
| TRIPWIRE | Tripwire triggered | violation_type, current_mode |
| RECALL_ATTEMPT | Memory recall attempted | memory_class, decision, memory_id |
| TOOL_REQUEST | Tool execution requested | tool_name, decision, requirements |
| OVERRIDE | Human override ceremony | action, status, reason |
| DAEMON_START | Daemon started | initial_mode |
| DAEMON_STOP | Daemon stopped | - |
| HEALTH_CHECK | Health check result | healthy, error |

### B. Memory Class to Mode Mapping

```python
MEMORY_CLASS_REQUIREMENTS = {
    MemoryClass.PUBLIC:       BoundaryMode.OPEN,
    MemoryClass.INTERNAL:     BoundaryMode.OPEN,
    MemoryClass.CONFIDENTIAL: BoundaryMode.RESTRICTED,
    MemoryClass.SECRET:       BoundaryMode.TRUSTED,
    MemoryClass.TOP_SECRET:   BoundaryMode.AIRGAP,
    MemoryClass.CROWN_JEWEL:  BoundaryMode.COLDROOM,
}
```

### C. Tripwire Violation Types

```python
class ViolationType(Enum):
    NETWORK_IN_AIRGAP = "network_in_airgap"
    USB_IN_COLDROOM = "usb_in_coldroom"
    UNAUTHORIZED_RECALL = "unauthorized_recall"
    DAEMON_TAMPERING = "daemon_tampering"
    MODE_INCOMPATIBLE = "mode_incompatible"
    EXTERNAL_MODEL_VIOLATION = "external_model_violation"
    SUSPICIOUS_PROCESS = "suspicious_process"
    HARDWARE_TRUST_DEGRADED = "hardware_trust_degraded"
```

### D. File Locations

| File | Development | Production |
|------|-------------|------------|
| Daemon | `./daemon/boundary_daemon.py` | `/opt/boundary-daemon/daemon/` |
| Socket | `./api/boundary.sock` | `/var/run/boundary-daemon/boundary.sock` |
| Logs | `./logs/boundary_chain.log` | `/var/log/boundary-daemon/boundary_chain.log` |
| Config | `./config/boundary.conf` | `/etc/boundary-daemon/boundary.conf` |
| Service | N/A | `/etc/systemd/system/boundary-daemon.service` |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-19 | Initial comprehensive specification |

---

**Document Status**: ACTIVE
**Security Classification**: CONFIDENTIAL
**Maintained By**: Boundary Daemon Development Team
