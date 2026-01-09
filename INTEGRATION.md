# Boundary Daemon Integration Guide

> **Note:** This document has been consolidated. For comprehensive integration documentation, see:
> - **[integrations/INTEGRATION_GUIDE.md](integrations/INTEGRATION_GUIDE.md)** - Complete ecosystem integration guide
> - **[integrations/README.md](integrations/README.md)** - Quick reference and package list
> - **[integrations/SECURITY_INTEGRATION.md](integrations/SECURITY_INTEGRATION.md)** - Attack vectors prevented
> - **[integrations/ADVANCED_RULES.md](integrations/ADVANCED_RULES.md)** - Advanced policy gates (47 rules)

---

## Quick Start

### Mandatory Callers

The following components MUST call the Boundary Daemon:

1. **Memory Vault** - Before any memory recall
2. **Agent-OS** - Before any tool execution
3. **synth-mind** - Before reflection loops
4. **External Model Adapters** - Before API calls

### Python Integration

```python
from api.boundary_api import BoundaryAPIClient

client = BoundaryAPIClient(socket_path='./api/boundary.sock')

# Check memory recall permission
permitted, reason = client.check_recall(memory_class=3)
if not permitted:
    raise PermissionError(f"Recall denied: {reason}")

# Check tool execution permission
permitted, reason = client.check_tool(
    tool_name='wget',
    requires_network=True
)
```

### Unix Socket API

```bash
echo '{"command": "check_recall", "params": {"memory_class": 3}}' | \
    nc -U ./api/boundary.sock
```

---

## Boundary Modes Reference

| Mode | Network | Memory Classes | Tools | Use Case |
|------|---------|----------------|-------|----------|
| OPEN | Full | 0-1 | All | Casual use |
| RESTRICTED | Monitored | 0-2 | Most | Research |
| TRUSTED | VPN only | 0-3 | No USB | Serious work |
| AIRGAP | None | 0-4 | No network | High-value IP |
| COLDROOM | None | 0-5 | Display only | Crown jewels |
| LOCKDOWN | Blocked | None | None | Emergency |

---

## Architecture Principles

1. **Mandatory Enforcement**: Components MUST NOT bypass the daemon
2. **Fail-Closed**: Ambiguity defaults to DENY
3. **Immutable Logging**: All decisions logged with hash chain and Ed25519 signatures
4. **Human Override**: Requires ceremony, never silent
5. **Deterministic**: Same inputs → same decision

---

For detailed integration instructions, code examples, and repository-specific guides, see **[integrations/INTEGRATION_GUIDE.md](integrations/INTEGRATION_GUIDE.md)**.
