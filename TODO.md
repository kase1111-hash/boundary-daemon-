# Security TODO

## External Enforcement (Required for Complete Security)

The Boundary Daemon provides **detection and audit** but not enforcement.
These external controls are required for complete security:

### Network Enforcement
- [ ] **Firewall/WAF** - iptables, nftables, or cloud WAF
  - Block unauthorized outbound connections
  - Rate limit inbound requests
  - Geo-blocking if applicable
  - Integration: Daemon can trigger firewall rules via enforcement module

### Process Enforcement
- [ ] **SELinux/AppArmor** - Mandatory Access Control
  - Confine daemon and agent processes
  - Restrict file system access
  - Limit network capabilities per process
  - Prevent privilege escalation

### Data Protection
- [ ] **Disk encryption** - LUKS, BitLocker, or FileVault
  - Encrypt data-at-rest
  - Protect logs and audit trails
  - Secure key management (TPM integration available)

## Architecture Note

```
┌─────────────────────────────────────────────────────────┐
│                    Complete Security                     │
├─────────────────────────────────────────────────────────┤
│  Detection Layer (this daemon)                          │
│  ├── Policy decisions (ALLOW/DENY)                      │
│  ├── Audit logging (hash-chained)                       │
│  ├── SIEM integration (CEF/LEEF/JSON)                   │
│  └── Tripwire alerts                                    │
├─────────────────────────────────────────────────────────┤
│  Enforcement Layer (external - TODO)                    │
│  ├── Firewall/WAF ────────────── Network enforcement    │
│  ├── SELinux/AppArmor ────────── Process enforcement    │
│  └── Disk encryption ─────────── Data-at-rest           │
├─────────────────────────────────────────────────────────┤
│  Visibility Layer                                       │
│  └── SIEM ────────────────────── Correlation & alerting │
└─────────────────────────────────────────────────────────┘
```

Daemon + SIEM = visibility
Daemon + SIEM + enforcement = security
