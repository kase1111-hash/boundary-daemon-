# Boundary Daemon Integration Packages

Ready-to-use integration modules for all Agent OS ecosystem components.

> For detailed integration instructions and code examples, see [INTEGRATION_GUIDE.md](./INTEGRATION_GUIDE.md).

## Integration Packages (Alphabetical)

| Package | Language | Key Components |
|---------|----------|----------------|
| [agent-os](./agent-os/) | TypeScript | `ToolGate`, `AgentMessageGate`, `SmithBoundaryIntegration` |
| [boundary-siem](./boundary-siem/) | Python | `EventIngestionPipeline`, `SIEMForwarder` |
| [finite-intent-executor](./finite-intent-executor/) | Python | `IntentGate`, `AssetGate`, `ExecutionGate` |
| [ilr-module](./ilr-module/) | TypeScript | `DisputeGate`, `LicenseGate`, `ResolutionGate` |
| [learning-contracts](./learning-contracts/) | TypeScript | `DaemonConnector`, `ContractEnforcer` |
| [mediator-node](./mediator-node/) | TypeScript | `MediationGate`, `MiningGate` |
| [memory-vault](./memory-vault/) | Python | `RecallGate`, `MemoryVaultBoundaryMixin` |
| [natlangchain](./natlangchain/) | Python | `EntryValidator`, `ChainGate` |
| [synth-mind](./synth-mind/) | Python | `ReflectionGate`, `CognitiveGate`, `MemoryGate` |
| [value-ledger](./value-ledger/) | Python | `ValueLedgerBoundaryIntegration`, `InterruptionTracker` |

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
