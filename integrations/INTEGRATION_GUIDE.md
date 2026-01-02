# Boundary Daemon Ecosystem Integration Guide

This guide provides comprehensive instructions for integrating all Agent OS ecosystem components with the Boundary Daemon.

## Quick Reference

| Repository | Language | Integration File | Key Classes |
|------------|----------|-----------------|-------------|
| synth-mind | Python | `boundary/` | `ReflectionGate`, `CognitiveGate`, `MemoryGate` |
| memory-vault | Python | `boundary.py` | `RecallGate`, `BoundaryClient` |
| Agent-OS | TypeScript | `boundary/` | `ToolGate`, `AgentMessageGate`, `SmithBoundaryIntegration` |
| learning-contracts | TypeScript | `daemon-connector.ts` | `DaemonConnector`, `ContractEnforcer` |
| value-ledger | Python | `boundary.py` | `ValueLedgerBoundaryIntegration`, `InterruptionTracker` |
| Boundary-SIEM | Python | `boundary_ingestion.py` | `EventIngestionPipeline`, `SIEMForwarder` |
| NatLangChain | Python | `boundary.py` | `EntryValidator`, `ChainGate` |
| mediator-node | TypeScript | `boundary.ts` | `MediationGate`, `MiningGate` |
| Finite-Intent-Executor | Python | `boundary.py` | `IntentGate`, `ExecutionGate` |
| ILR-module | TypeScript | `boundary.ts` | `DisputeGate`, `LicenseGate`, `ResolutionGate` |

## Socket Path Configuration

All integrations use a consistent socket path discovery:

```
1. BOUNDARY_DAEMON_SOCKET environment variable
2. /var/run/boundary-daemon/boundary.sock (production)
3. ~/.agent-os/api/boundary.sock (user mode)
4. ./api/boundary.sock (development)
```

**IMPORTANT:** Previous versions had incorrect socket paths. This integration package fixes:
- learning-contracts: `/var/run/boundary-daemon.sock` → `/var/run/boundary-daemon/boundary.sock`
- value-ledger: `/var/run/boundary-daemon/api.sock` → `/var/run/boundary-daemon/boundary.sock`

## Installation

### Python Repositories

```bash
# Copy shared client
cp integrations/shared/python/boundary_client.py /path/to/repo/

# Copy repo-specific integration
cp -r integrations/<repo-name>/src/* /path/to/repo/
```

### TypeScript Repositories

```bash
# Copy shared client
cp integrations/shared/typescript/boundary-client.ts /path/to/repo/src/boundary/

# Copy repo-specific integration
cp -r integrations/<repo-name>/src/* /path/to/repo/src/
```

## Integration Patterns

### Pattern 1: Gate Pattern (Recommended)

Gates provide structured access control for specific operation types.

```python
# Python
from boundary import RecallGate

gate = RecallGate()
if gate.can_recall(memory_class=3):
    memory = vault.retrieve(memory_id)
else:
    logger.warning(f"Recall denied: {gate.last_decision.reason}")
```

```typescript
// TypeScript
import { ToolGate } from './boundary';

const gate = new ToolGate();
if (await gate.canExecute('wget', { network: true })) {
    await executeTool('wget', args);
}
```

### Pattern 2: Decorator Pattern

Decorators provide simple enforcement on functions.

```python
# Python
from boundary import require_reflection_check, boundary_protected

@require_reflection_check()
def meta_reflection():
    # Only runs if reflection is permitted
    pass

@boundary_protected(requires_network=True, memory_class=2)
def fetch_and_store():
    # Requires both network and memory class 2 access
    pass
```

```typescript
// TypeScript
import { boundaryProtected, requiresNetwork } from './boundary';

class MyTool {
    @boundaryProtected({ requiresNetwork: true })
    async run() { ... }

    @requiresNetwork()
    async fetchData() { ... }
}
```

### Pattern 3: Context Manager Pattern

Context managers provide scoped boundary checks.

```python
# Python
from boundary import BoundaryScope

with BoundaryScope(requires_network=True) as scope:
    if scope.permitted:
        do_network_operation()
    else:
        handle_denial(scope.reason)
```

### Pattern 4: Higher-Order Function Pattern

Wrap functions with boundary protection.

```typescript
// TypeScript
import { withBoundaryCheck } from './boundary';

const protectedFetch = withBoundaryCheck(
    fetchData,
    { toolName: 'fetch', requiresNetwork: true }
);
```

## Repository-Specific Integration

### 1. synth-mind (CRITICAL)

Synth-mind was previously missing boundary integration entirely.

**Required Changes:**

```python
# Before each reflection loop
from boundary import ReflectionGate

gate = ReflectionGate()
gate.require_reflection()  # Raises if denied

# For meta-reflection module
from boundary import require_reflection_check

@require_reflection_check(reflection_type='meta', depth=1)
def run_reflection_loop():
    ...

# Full integration
from boundary import SynthMindBoundaryIntegration

boundary = SynthMindBoundaryIntegration()
if boundary.can_run_reflection():
    run_reflection_loop()
```

### 2. memory-vault

**Required Changes:**

```python
# Replace boundry.py (typo) with boundary.py
from boundary import RecallGate, require_boundary_check

# Before any memory recall
gate = RecallGate()
gate.require_recall(memory_class=classification)

# Or use mixin
from boundary import MemoryVaultBoundaryMixin

class SecureVault(MemoryVaultBoundaryMixin, BaseVault):
    pass
```

### 3. Agent-OS

```typescript
import { ToolGate, AgentMessageGate, SmithBoundaryIntegration } from './boundary';

// Before tool execution
const toolGate = new ToolGate();
await toolGate.requireExecution('wget', { network: true });

// For inter-agent messages
const msgGate = new AgentMessageGate();
await msgGate.requireSend({
    sender: 'orchestrator',
    recipient: 'executor',
    content: message,
});

// Smith Guardian integration
const smith = new SmithBoundaryIntegration();
const validation = await smith.validateOperation({
    operation: 'execute_tool',
    agent: 'executor',
    requiresNetwork: true,
});
```

### 4. learning-contracts

```typescript
import { DaemonConnector, ContractEnforcer } from './daemon-connector';

const daemon = new DaemonConnector();  // Uses correct socket path now

// Check before memory creation
const decision = await daemon.checkMemoryCreation({
    classification: Classification.CONFIDENTIAL,
    domain: 'learning',
});

// Use contract enforcer for lifecycle management
const enforcer = new ContractEnforcer(daemon);
enforcer.registerContract({
    contractId: 'contract-1',
    requiredMode: BoundaryMode.TRUSTED,
    maxClassification: Classification.SECRET,
});
```

### 5. value-ledger

```python
from boundary import (
    ValueLedgerBoundaryIntegration,
    protected_operation,
    require_boundary,
)

# Check before recording
integration = ValueLedgerBoundaryIntegration()
permitted, reason = integration.can_record_value(value_class=2)

# Use decorator
@protected_operation(requires_network=True)
def sync_to_remote():
    ...

# Track interruptions
integration.interruption_tracker.record_interruption(
    operation='sync',
    reason='Network denied in AIRGAP mode',
)
```

### 6. Boundary-SIEM

```python
from boundary_ingestion import (
    EventIngestionPipeline,
    SIEMForwarder,
    start_siem_forwarding,
)

# Start ingestion pipeline
pipeline, forwarder = start_siem_forwarding(
    syslog_host='siem.example.com',
    output_format='cef',
)

# Or manual setup
pipeline = EventIngestionPipeline(output_format=EventFormat.CEF)
pipeline.add_handler(lambda event: print(event.to_cef()))
pipeline.start()

# Verify log integrity
valid, error = pipeline.verify_integrity()
```

### 7. NatLangChain

```python
from boundary import (
    NatLangChainBoundaryIntegration,
    ChainEntry,
    before_record_hook,
)

integration = NatLangChainBoundaryIntegration()

# Validate entry before recording
entry = ChainEntry(
    author="user@example.com",
    intent="I want to share my research",
    timestamp=datetime.now().isoformat(),
)
result = integration.validate_entry(entry)

# Install hooks
integration.install_hooks(chain)  # Adds before_record and before_broadcast hooks
```

### 8. mediator-node

```typescript
import { MediatorBoundaryIntegration, createProtectedLLMClient } from './boundary';

const boundary = new MediatorBoundaryIntegration();

// Check LLM call permission
if (await boundary.mediationGate.canCallLLM('gpt-4')) {
    await callLLM('gpt-4', prompt);
}

// Or use wrapper
const result = await boundary.withLLMBoundary(
    'gpt-4',
    () => callLLM('gpt-4', prompt),
    () => callLocalLLM(prompt),  // fallback
);

// Create protected client
const protectedClient = createProtectedLLMClient(llmClient, 'gpt-4');
```

### 9. Finite-Intent-Executor

```python
from boundary import (
    FIEBoundaryIntegration,
    IntentClass,
    protected_intent,
)

integration = FIEBoundaryIntegration()

# Validate posthumous intent
can_execute, reason = integration.can_execute_posthumous_intent(
    intent_description="Transfer assets to beneficiary",
    beneficiary="john@example.com",
    assets=["asset-1", "asset-2"],
)

# Use decorator
@protected_intent(intent_class=IntentClass.SENSITIVE)
def execute_asset_transfer():
    ...
```

### 10. ILR-module

```typescript
import { ILRBoundaryIntegration, DisputeClass } from './boundary';

const ilr = new ILRBoundaryIntegration();

// Check dispute filing permission
await ilr.disputeGate.requireDisputePermission(
    disputeContent,
    DisputeClass.CONFIDENTIAL,
    ['party-a', 'party-b'],
);

// Check resolution workflow
const { canProceed, reason } = await ilr.canResolveDispute({
    disputeContent,
    disputeClass: DisputeClass.CONFIDENTIAL,
    parties: ['party-a', 'party-b'],
    requiresPayment: true,
});
```

## Testing Integration

### Start Daemon in Test Mode

```bash
# Start daemon with no authentication for testing
python daemon/boundary_daemon.py --mode=open --no-auth
```

### Test Commands

```bash
# Python
python -c "from boundary import BoundaryClient; print(BoundaryClient().get_mode())"

# TypeScript
npx ts-node -e "import BoundaryClient from './boundary/client'; console.log(await new BoundaryClient().getMode())"
```

### Integration Test Example

```python
import pytest
from boundary import BoundaryClient, RecallGate

def test_recall_in_open_mode():
    client = BoundaryClient()
    gate = RecallGate(client)

    # Public memory should be accessible in OPEN mode
    assert gate.can_recall(memory_class=0)

    # Crown jewel should be denied in OPEN mode
    assert not gate.can_recall(memory_class=5)
```

## Fail-Closed Behavior

All integrations implement fail-closed semantics:

- **Daemon unavailable** → Operation denied
- **Socket connection refused** → Operation denied
- **Timeout** → Operation denied
- **Invalid response** → Operation denied

This ensures security is maintained even when the daemon is down.

## Mode Reference

| Mode | Network | Memory Classes | Tools | Use Case |
|------|---------|----------------|-------|----------|
| OPEN | Full | 0-1 | All | Casual use |
| RESTRICTED | Monitored | 0-2 | Most | Research |
| TRUSTED | VPN only | 0-3 | No USB | Serious work |
| AIRGAP | None | 0-4 | No network | High-value IP |
| COLDROOM | None | 0-5 | Display only | Crown jewels |
| LOCKDOWN | Blocked | None | None | Emergency |

## Troubleshooting

### Socket Not Found

```bash
# Check if daemon is running
ps aux | grep boundary_daemon

# Check socket path
ls -la /var/run/boundary-daemon/boundary.sock

# Start daemon
python daemon/boundary_daemon.py
```

### Permission Denied

```bash
# Check socket permissions
ls -la /var/run/boundary-daemon/

# Socket should be owned by daemon user
# Client user should be in same group
```

### Authentication Failed

```bash
# Set API token
export BOUNDARY_API_TOKEN=bd_your_token_here

# Or use token file
echo "bd_your_token_here" > ~/.boundary_token
```

## Security Best Practices

1. **Always use fail-closed semantics** - Never default to allowing operations
2. **Log all boundary decisions** - Audit trail is critical
3. **Use appropriate modes** - Don't stay in OPEN mode for sensitive operations
4. **Check before every operation** - Don't cache decisions for too long
5. **Handle mode changes** - Subscribe to mode change notifications
6. **Verify log integrity** - Periodically check hash chain

---

For more information, see:
- [INTEGRATION.md](../INTEGRATION.md) - Main integration documentation
- [SPEC.md](../SPEC.md) - Full specification
- [ARCHITECTURE.md](../ARCHITECTURE.md) - System architecture
