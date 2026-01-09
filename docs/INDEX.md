# Boundary Daemon Documentation Index

**Version:** v1.0.0-beta
**Last Updated:** 2026-01-09

This document provides a comprehensive index of all documentation for the Boundary Daemon project.

---

## Quick Start

| Document | Description |
|----------|-------------|
| [README.md](../README.md) | Project overview, features, and quick start guide |
| [USER_GUIDE.md](../USER_GUIDE.md) | Comprehensive user manual |
| [CHANGELOG.md](../CHANGELOG.md) | Version history and changes |

---

## Core Documentation

### Architecture & Design

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](../ARCHITECTURE.md) | Complete system architecture with component diagrams |
| [SPEC.md](../SPEC.md) | Full technical specification (v2.5) |
| [ENFORCEMENT_MODEL.md](../ENFORCEMENT_MODEL.md) | Understanding what the daemon does and doesn't do |

### Security

| Document | Description |
|----------|-------------|
| [SECURITY.md](../SECURITY.md) | Security policies, practices, and vulnerability reporting |
| [SECURITY_AUDIT.md](../SECURITY_AUDIT.md) | Detailed security audit findings and remediations |
| [SECURITY_COMPARISON.md](SECURITY_COMPARISON.md) | Comparison with enterprise security tools |

### Monitoring & Metrics

| Document | Description |
|----------|-------------|
| [MONITORING_METRICS.md](../MONITORING_METRICS.md) | Security rules, test cases, and monitoring points |

---

## Integration Documentation

### Integration Guides

| Document | Description |
|----------|-------------|
| [INTEGRATION.md](../INTEGRATION.md) | Quick reference for integrating with the daemon |
| [integrations/README.md](../integrations/README.md) | Integration package overview |
| [integrations/INTEGRATION_GUIDE.md](../integrations/INTEGRATION_GUIDE.md) | Complete ecosystem integration guide |
| [integrations/SECURITY_INTEGRATION.md](../integrations/SECURITY_INTEGRATION.md) | Attack vectors prevented by integration |
| [integrations/ADVANCED_RULES.md](../integrations/ADVANCED_RULES.md) | Advanced boundary rules (47 policy gates) |

### Integration Packages

Located in `integrations/`:

| Package | Description |
|---------|-------------|
| `agent-os/` | Agent-OS tool integration |
| `memory-vault/` | Memory Vault recall gating |
| `synth-mind/` | Reflection loop integration |
| `boundary-siem/` | SIEM event shipping |
| `finite-intent-executor/` | Intent execution gating |
| `intentlog/` | Intent logging integration |
| `learning-contracts/` | Learning boundary contracts |
| `mediator-node/` | Multi-agent mediation |
| `natlangchain/` | Natural language chain security |
| `ilr-module/` | ILR module integration |
| `rra-module/` | RRA module integration |
| `value-ledger/` | Value ledger integration |
| `shared/` | Shared client libraries (Python, TypeScript) |

---

## Planning & Roadmap

| Document | Description |
|----------|-------------|
| [FEATURE_ROADMAP.md](FEATURE_ROADMAP.md) | Strategic feature priorities and design principles |

---

## AI Assistant Knowledge

| Document | Description |
|----------|-------------|
| [SELF_KNOWLEDGE.md](SELF_KNOWLEDGE.md) | Built-in AI assistant (Agent Smith) knowledge base |

---

## Configuration Files

| File | Description |
|------|-------------|
| `config/boundary.conf` | Main daemon configuration |
| `config/policies.d/` | Policy definition files |
| `systemd/boundary-daemon.service` | Systemd service definition |
| `systemd/boundary-watchdog.service` | Watchdog service definition |

---

## CLI Tools Reference

| Tool | Description |
|------|-------------|
| `boundaryctl` | Main daemon control and monitoring |
| `sandboxctl` | Sandbox lifecycle management |
| `authctl` | Authentication and token management |
| `policy_ctl` | Policy configuration |
| `cluster_ctl` | Distributed deployment management |
| `biometric_ctl` | Biometric verification |
| `security_scan` | Security scanning utilities |
| `verify_signatures` | Signature verification |
| `dashboard` | Real-time TUI monitoring |
| `art_editor` | ASCII sprite editor for TUI |

---

## Document Relationships

```
README.md (Entry Point)
    │
    ├── USER_GUIDE.md (User Manual)
    │
    ├── Architecture
    │   ├── ARCHITECTURE.md (Technical Details)
    │   ├── SPEC.md (Full Specification)
    │   └── ENFORCEMENT_MODEL.md (Enforcement Explanation)
    │
    ├── Security
    │   ├── SECURITY.md (Policies & Practices)
    │   ├── SECURITY_AUDIT.md (Audit Report)
    │   └── docs/SECURITY_COMPARISON.md (Comparison)
    │
    ├── Integration
    │   ├── INTEGRATION.md (Quick Start)
    │   └── integrations/
    │       ├── README.md (Package List)
    │       ├── INTEGRATION_GUIDE.md (Complete Guide)
    │       ├── SECURITY_INTEGRATION.md (Attack Vectors)
    │       └── ADVANCED_RULES.md (Policy Gates)
    │
    └── docs/
        ├── INDEX.md (This File)
        ├── FEATURE_ROADMAP.md (Future Plans)
        ├── SECURITY_COMPARISON.md (Tool Comparison)
        └── SELF_KNOWLEDGE.md (AI Knowledge Base)
```

---

## Document Updates

This index is maintained alongside the documentation. When adding new documents:

1. Add entry to the appropriate section above
2. Update the document relationships diagram
3. Ensure cross-references in other documents

---

**Maintained by:** Boundary Daemon Team
