# Security TODO

## External Enforcement (Required for Complete Security)

The Boundary Daemon provides **detection and audit** but not enforcement.
These external controls are required for complete security:

### Network Enforcement
- [x] **Firewall Integration Module** - `daemon/enforcement/firewall_integration.py`
  - Generates iptables/nftables rules based on boundary mode
  - Can apply rules (requires root)
  - Supports Windows Firewall via netsh
- [ ] **Deploy firewall rules in production**
  - Review generated rules for your environment
  - Apply via: `fw.apply_rules(fw.generate_mode_rules("RESTRICTED"))`

### Process Enforcement
- [x] **MAC Profile Generator** - `daemon/enforcement/mac_profiles.py`
  - Generates SELinux policy modules
  - Generates AppArmor profiles
  - Supports per-process profiles by mode
- [ ] **Deploy MAC profiles in production**
  - SELinux: `semodule -i boundary_daemon.pp`
  - AppArmor: `apparmor_parser -r /etc/apparmor.d/boundary-daemon`

### Data Protection
- [x] **Disk Encryption Checker** - `daemon/enforcement/disk_encryption.py`
  - Detects LUKS, BitLocker, FileVault
  - Verifies log directory encryption
  - Generates security reports
- [ ] **Enable encryption if not present**
  - Linux: `cryptsetup luksFormat /dev/sdX`
  - Windows: `manage-bde -on C:`
  - macOS: `fdesetup enable`

## Usage Examples

### Firewall Integration
```python
from daemon.enforcement import get_firewall_manager

fw = get_firewall_manager()
print(fw.get_status())

# Generate rules for AIRGAP mode
rules = fw.generate_mode_rules("AIRGAP")

# Generate iptables script
script = fw.generate_iptables_script("RESTRICTED")

# Apply rules (requires root)
success, msg = fw.apply_rules(rules)
```

### MAC Profiles
```python
from daemon.enforcement import get_mac_generator

mac = get_mac_generator()
print(mac.get_mac_status())

# Generate daemon profile
profile = mac.generate_daemon_profile()

# Generate profile for monitored process
app_profile = mac.generate_process_profile(
    "/usr/bin/myapp",
    mode="RESTRICTED"
)

# Install profile (requires root)
success, msg = mac.install_profile(profile, "boundary-daemon")
```

### Disk Encryption
```python
from daemon.enforcement import get_encryption_checker

enc = get_encryption_checker()

# Check all volumes
volumes = enc.check_all_volumes()

# Verify log directory is encrypted
is_enc, msg = enc.verify_log_encryption("/var/log/boundary-daemon")

# Get security report
report = enc.get_security_report()
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Complete Security                     │
├─────────────────────────────────────────────────────────┤
│  Detection Layer (daemon)                               │
│  ├── Policy decisions (ALLOW/DENY)                      │
│  ├── Audit logging (hash-chained)                       │
│  ├── SIEM integration (CEF/LEEF/JSON)                   │
│  └── Tripwire alerts                                    │
├─────────────────────────────────────────────────────────┤
│  Enforcement Layer (new modules)                        │
│  ├── firewall_integration.py ─── iptables/nftables     │
│  ├── mac_profiles.py ─────────── SELinux/AppArmor      │
│  └── disk_encryption.py ──────── LUKS/BitLocker check  │
├─────────────────────────────────────────────────────────┤
│  Visibility Layer                                       │
│  └── SIEM ────────────────────── Correlation & alerting │
└─────────────────────────────────────────────────────────┘
```

## What You Have Now

| Component | Status | Location |
|-----------|--------|----------|
| SIEM Integration | ✅ Done | `daemon/security/siem_integration.py` |
| Error Handling + SIEM | ✅ Done | `daemon/utils/error_handling.py` |
| Firewall Rules | ✅ Done | `daemon/enforcement/firewall_integration.py` |
| SELinux/AppArmor | ✅ Done | `daemon/enforcement/mac_profiles.py` |
| Encryption Check | ✅ Done | `daemon/enforcement/disk_encryption.py` |

**Daemon + SIEM + enforcement modules = comprehensive security**
