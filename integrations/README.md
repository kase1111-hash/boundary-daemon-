# Boundary Daemon Integration Packages

This directory contains ready-to-use integration modules for all Agent OS ecosystem components.

## Quick Start

Each subdirectory contains a complete integration package that can be copied into the target repository.

```bash
# Example: Add synth-mind integration
cp -r integrations/synth-mind/src/* /path/to/synth-mind/

# Example: Add learning-contracts integration (TypeScript)
cp -r integrations/learning-contracts/src/* /path/to/learning-contracts/src/boundary/
```

## Integration Packages

| Package | Language | Target Repo | Status |
|---------|----------|-------------|--------|
| synth-mind | Python | synth-mind | Full integration |
| memory-vault | Python | memory-vault | Enhanced integration |
| agent-os | TypeScript | Agent-OS | Full integration |
| learning-contracts | TypeScript | learning-contracts | Fixed + enhanced |
| value-ledger | Python | value-ledger | Fixed + enhanced |
| boundary-siem | Python/Go | Boundary-SIEM | Enhanced |
| natlangchain | Python/TS | NatLangChain | Full integration |
| mediator-node | TypeScript | mediator-node | Full integration |
| finite-intent-executor | Python | Finite-Intent-Executor | Full integration |
| ilr-module | TypeScript | ILR-module | Full integration |

## Socket Path Configuration

All integrations use the following socket paths (in order of precedence):

1. `BOUNDARY_DAEMON_SOCKET` environment variable
2. `/var/run/boundary-daemon/boundary.sock` (production)
3. `~/.agent-os/api/boundary.sock` (user mode)
4. `./api/boundary.sock` (development)

## Common Features

All integrations include:

- **Fail-closed semantics**: If daemon unavailable, operations are denied
- **Automatic retry**: Exponential backoff on connection failures
- **Token management**: Automatic token refresh and caching
- **Event logging**: All operations logged to daemon audit trail
- **Mode-aware behavior**: Operations adapt to current boundary mode
