# Boundary Daemon Integration Packages

Ready-to-use integration modules for all Agent OS ecosystem components.

> For detailed integration instructions and code examples, see [INTEGRATION_GUIDE.md](./INTEGRATION_GUIDE.md).

## Security Integration Check

Run the security integration checker to validate attack prevention across all repositories:

```bash
python integrations/security_integration_check.py

# JSON output
python integrations/security_integration_check.py --format json
```

See [SECURITY_INTEGRATION.md](./SECURITY_INTEGRATION.md) for attack vectors prevented.

## Integration Packages (Alphabetical)

| Package | Language | Key Components | Attack Vectors Prevented |
|---------|----------|----------------|-------------------------|
| [agent-os](./agent-os/) | TypeScript | `ToolGate`, `AgentMessageGate`, `SmithBoundaryIntegration` | Tool exec, Impersonation, Privilege escalation |
| [boundary-siem](./boundary-siem/) | Python | `EventIngestionPipeline`, `SIEMForwarder` | Crypto bypass, Clock manipulation |
| [finite-intent-executor](./finite-intent-executor/) | Python | `IntentGate`, `AssetGate`, `ExecutionGate` | Tool exec, Privilege escalation |
| [ilr-module](./ilr-module/) | TypeScript | `DisputeGate`, `LicenseGate`, `ResolutionGate` | Crypto bypass, Contract tampering |
| [intentlog](./intentlog/) | Python | `IntentLogGate`, `AuditTrailValidator` | Contract tampering, Clock manipulation, Crypto bypass |
| [learning-contracts](./learning-contracts/) | TypeScript | `DaemonConnector`, `ContractEnforcer` | Contract tampering, Privilege escalation |
| [mediator-node](./mediator-node/) | TypeScript | `MediationGate`, `MiningGate` | Prompt injection, Rate limit bypass |
| [memory-vault](./memory-vault/) | Python | `RecallGate`, `MemoryVaultBoundaryMixin` | Memory exfiltration, Crypto bypass |
| [natlangchain](./natlangchain/) | Python | `EntryValidator`, `ChainGate` | Semantic drift, Prompt injection, Crypto bypass |
| [rra-module](./rra-module/) | Python | `RiskGate`, `RewardGate`, `AnalysisAuditGate` | Privilege escalation, Semantic drift, Crypto bypass |
| [synth-mind](./synth-mind/) | Python | `ReflectionGate`, `CognitiveGate`, `MemoryGate` | Memory exfiltration, Privilege escalation |
| [value-ledger](./value-ledger/) | Python | `ValueLedgerBoundaryIntegration`, `InterruptionTracker` | Crypto bypass, Rate limit bypass |

## Shared Libraries

| Library | Path | Description |
|---------|------|-------------|
| Python Client | [`shared/python/boundary_client.py`](./shared/python/boundary_client.py) | Base client for Python integrations |
| TypeScript Client | [`shared/typescript/boundary-client.ts`](./shared/typescript/boundary-client.ts) | Base client for TypeScript integrations |

## Quick Start

### Python

```bash
# 1. Copy shared client
cp integrations/shared/python/boundary_client.py /path/to/repo/

# 2. Copy repo-specific integration
cp -r integrations/<repo-name>/src/* /path/to/repo/
```

### TypeScript

```bash
# 1. Copy shared client
cp integrations/shared/typescript/boundary-client.ts /path/to/repo/src/boundary/

# 2. Copy repo-specific integration
cp -r integrations/<repo-name>/src/* /path/to/repo/src/
```

## Socket Path Discovery

All integrations use this precedence order:

1. `BOUNDARY_DAEMON_SOCKET` environment variable
2. `/var/run/boundary-daemon/boundary.sock` (production)
3. `~/.agent-os/api/boundary.sock` (user mode)
4. `./api/boundary.sock` (development)

## Core Features

All integrations implement:

- **Fail-closed semantics** - Daemon unavailable = operation denied
- **Automatic retry** - Exponential backoff on connection failures
- **Token management** - Automatic token refresh and caching
- **Event logging** - All operations logged to daemon audit trail
- **Mode-aware behavior** - Operations adapt to current boundary mode

## Related Documentation

- [INTEGRATION_GUIDE.md](./INTEGRATION_GUIDE.md) - Detailed integration guide with examples
- [ADVANCED_RULES.md](./ADVANCED_RULES.md) - Advanced policy gates specification (v2.0)
- [../INTEGRATION.md](../INTEGRATION.md) - Core integration concepts
- [../ARCHITECTURE.md](../ARCHITECTURE.md) - System architecture
- [../SPEC.md](../SPEC.md) - Full specification
