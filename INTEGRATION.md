# Boundary Daemon Integration Guide

## Overview

The Boundary Daemon (Agent Smith) is the **mandatory** security enforcement layer for Agent OS. All cognitive components **MUST** integrate with it. Bypassing the Boundary Daemon is a fatal architecture violation.

## Mandatory Callers

The following components MUST call the Boundary Daemon:

1. **Memory Vault** - Before any memory recall
2. **Agent-OS** - Before any tool execution
3. **synth-mind** - Before reflection loops
4. **External Model Adapters** - Before API calls

## Integration Methods

### Method 1: Python API (Recommended)

For Python components, use the native Python API:

```python
from api.boundary_api import BoundaryAPIClient

# Initialize client
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
if not permitted:
    raise PermissionError(f"Tool execution denied: {reason}")
```

### Method 2: Unix Socket API

For non-Python components, use the Unix socket API directly:

```bash
# Example: Check recall permission
echo '{"command": "check_recall", "params": {"memory_class": 3}}' | \
    nc -U ./api/boundary.sock

# Response:
# {"success": true, "permitted": true, "reason": "Recall permitted"}
```

### Method 3: Integration Interfaces

For advanced integration, use the high-level interfaces:

```python
from daemon.integrations import RecallGate, ToolGate, CeremonyManager
from daemon.policy_engine import MemoryClass

# Memory Vault integration
recall_gate = RecallGate(daemon)

# Check if memory is accessible
if recall_gate.is_accessible(MemoryClass.SECRET):
    memory = vault.retrieve(memory_id)
else:
    raise PermissionError("Memory not accessible in current mode")

# Agent-OS tool integration
tool_gate = ToolGate(daemon)

# Check before executing tool
permitted, reason = tool_gate.check_tool(
    tool_name='curl',
    requires_network=True
)
```

## Memory Vault Integration

### Architecture

```
Memory Vault
    ↓
RecallGate.check_recall()
    ↓
BoundaryDaemon.check_recall_permission()
    ↓
PolicyEngine.evaluate_policy()
    ↓
[ALLOW / DENY / CEREMONY]
```

### Implementation Example

```python
class MemoryVault:
    def __init__(self, boundary_daemon):
        self.recall_gate = RecallGate(boundary_daemon)

    def retrieve(self, memory_id: str, memory_class: MemoryClass):
        """Retrieve memory with boundary enforcement"""

        # MANDATORY: Check with boundary daemon
        permitted, reason = self.recall_gate.check_recall(
            memory_class=memory_class,
            memory_id=memory_id
        )

        if not permitted:
            # Log denial
            logging.warning(f"Memory recall denied: {reason}")
            raise PermissionError(reason)

        # Permitted: proceed with retrieval
        return self._internal_retrieve(memory_id)
```

### Direct Unix Socket Integration

For production deployments, the Memory Vault can integrate directly via Unix socket:

```python
# memory_vault/boundary.py
import socket
import json
import os

SOCKET_PATH = os.path.expanduser("~/.agent-os/api/boundary.sock")

def check_recall(classification: int) -> tuple[bool, str]:
    """
    Query the boundary-daemon for recall permission.
    Returns (permitted: bool, reason: str)
    """
    request = {
        "command": "check_recall",
        "params": {"memory_class": classification}
    }

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(SOCKET_PATH)
            s.sendall(json.dumps(request).encode('utf-8') + b'\n')
            response_data = s.recv(4096).decode('utf-8')
            response = json.loads(response_data)
            permitted = response.get("permitted", False)
            reason = response.get("reason", "No reason provided")
            return permitted, reason
    except FileNotFoundError:
        return False, "Boundary daemon socket not found (offline/airgap mode?)"
    except ConnectionRefusedError:
        return False, "Boundary daemon not running"
    except socket.timeout:
        return False, "Boundary daemon timeout"
    except Exception as e:
        return False, f"Boundary daemon error: {str(e)}"
```

### Integration in Recall Flow

The boundary check must occur **before** any human approval or cooldown:

```python
# In recall_memory()
# 1. BOUNDARY CHECK FIRST - before any human approval or cooldown
permitted, reason = check_recall(classification)
if not permitted:
    self._log_recall(c, memory_id, requester, False,
                     justification + f" | boundary: {reason}")
    raise PermissionError(f"Boundary check failed: {reason}")

# 2. If permitted, proceed to human approval (level ≥3)
if classification >= 3:
    # ... human approval ceremony ...
    pass

# 3. Apply cooldown
# ... cooldown logic ...

# 4. Retrieve memory
return secret_data
```

### Memory Class Mapping

| Memory Class | Minimum Mode | Description |
|--------------|--------------|-------------|
| 0-1 (PUBLIC/INTERNAL) | OPEN | Unrestricted |
| 2 (CONFIDENTIAL) | RESTRICTED | Limited access |
| 3 (SECRET) | TRUSTED | Offline/VPN only |
| 4 (TOP_SECRET) | AIRGAP | Air-gapped only |
| 5 (CROWN_JEWEL) | COLDROOM | Maximum security |

### Boundary Policy Examples

The daemon enforces policies based on current mode:

| Vault Level | Boundary Requirement | Example Daemon Response |
|-------------|---------------------|------------------------|
| 0-2 | Usually permitted | `{"permitted": true}` |
| 3 | Offline preferred | Deny if network detected |
| 4 | AIRGAP or COLDROOM | Deny if any network/USB |
| 5 | COLDROOM + physical presence | Strictest checks |

### Testing the Integration

```bash
# 1. Start boundary-daemon in permissive mode
boundaryctl set-mode open

# 2. Recall low-level memory → succeeds
memory-vault recall <id>

# 3. Switch daemon to AIRGAP mode
boundaryctl set-mode airgap

# 4. Recall level 4 memory → denied with reason
memory-vault recall <id>
# → Error: Boundary check failed: Network interface active in AIRGAP mode
```

### Fail-Closed Behavior

If the daemon is unavailable:
- All recalls are safely **denied**
- Reason is clearly logged
- Enforces "fail-closed" security

**This is intentional** - no daemon = assume unsafe environment.

## Agent-OS Tool Integration

### Architecture

```
Agent-OS
    ↓
ToolGate.check_tool()
    ↓
BoundaryDaemon.check_tool_permission()
    ↓
PolicyEngine.evaluate_policy()
    ↓
[ALLOW / DENY]
```

### Implementation Example

```python
class ToolExecutor:
    def __init__(self, boundary_daemon):
        self.tool_gate = ToolGate(boundary_daemon)

    def execute_tool(self, tool_name: str, args: list):
        """Execute tool with boundary enforcement"""

        # Analyze tool requirements
        requires_network = self._requires_network(tool_name)
        requires_filesystem = self._requires_filesystem(tool_name)

        # MANDATORY: Check with boundary daemon
        permitted, reason = self.tool_gate.check_tool(
            tool_name=tool_name,
            requires_network=requires_network,
            requires_filesystem=requires_filesystem
        )

        if not permitted:
            raise PermissionError(f"Tool execution denied: {reason}")

        # Permitted: execute tool
        return self._execute(tool_name, args)
```

### Tool Classification

Tools must declare their requirements:

```python
TOOL_REQUIREMENTS = {
    'wget': {'network': True, 'filesystem': True},
    'curl': {'network': True, 'filesystem': False},
    'cat': {'network': False, 'filesystem': True},
    'echo': {'network': False, 'filesystem': False},
}
```

## External Model Adapter Integration

### Implementation

```python
class ModelAdapter:
    def __init__(self, boundary_daemon):
        self.tool_gate = ToolGate(boundary_daemon)

    def call_model(self, prompt: str):
        """Call external model with boundary enforcement"""

        # Check if external models allowed
        permitted, reason = self.tool_gate.check_tool(
            tool_name='external_model_api',
            requires_network=True
        )

        if not permitted:
            # Fall back to local model or deny
            return self._fallback_local_model(prompt)

        # Call external API
        return self._call_external_api(prompt)
```

## Boundary Modes Reference

| Mode | Network | Memory | Tools | Use Case |
|------|---------|--------|-------|----------|
| OPEN | ✓ | 0-1 | All | Casual use |
| RESTRICTED | ✓ | 0-2 | Most | Research |
| TRUSTED | VPN only | 0-3 | No USB | Serious work |
| AIRGAP | ✗ | 0-4 | No network | High-value IP |
| COLDROOM | ✗ | 0-5 | Display only | Crown jewels |
| LOCKDOWN | ✗ | NONE | NONE | Emergency |

## Human Override Ceremony

For operations requiring override:

```python
from daemon.integrations import CeremonyManager

ceremony = CeremonyManager(daemon)

# Override lockdown
success, message = ceremony.override_lockdown(
    reason="Emergency access to debug critical issue"
)

if success:
    # Lockdown released, system in RESTRICTED mode
    proceed_with_operation()
```

## Event Logging

All boundary decisions are logged immutably:

```python
# Get recent events
events = client.get_events(count=100)

for event in events:
    print(f"[{event['timestamp']}] {event['event_type']}")
    print(f"  {event['details']}")

# Verify log integrity
is_valid, error = client.verify_log()
if not is_valid:
    print(f"LOG INTEGRITY VIOLATION: {error}")
```

## Error Handling

### Fail-Closed Behavior

The Boundary Daemon implements fail-closed semantics:

- If daemon is unreachable → **DENY**
- If environment is ambiguous → **DENY**
- If policy is unclear → **DENY**
- If clock drift detected → **DENY**

### Integration Pattern

```python
def safe_operation():
    try:
        permitted, reason = client.check_permission(...)

        if not permitted:
            # Denied by policy
            handle_denial(reason)
            return

        # Proceed with operation
        execute_operation()

    except ConnectionError:
        # Daemon unreachable: fail closed
        logging.error("Boundary daemon unreachable - denying operation")
        raise PermissionError("Cannot verify boundary permission")

    except Exception as e:
        # Unknown error: fail closed
        logging.error(f"Boundary check failed: {e}")
        raise PermissionError("Boundary check failed")
```

## Testing Integration

### Unit Tests

```python
import unittest
from api.boundary_api import BoundaryAPIClient
from daemon.boundary_daemon import BoundaryDaemon
from daemon.policy_engine import BoundaryMode

class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.daemon = BoundaryDaemon(initial_mode=BoundaryMode.OPEN)
        self.daemon.start()
        self.client = BoundaryAPIClient()

    def test_recall_permission(self):
        # Test recall in OPEN mode
        permitted, _ = self.client.check_recall(memory_class=1)
        self.assertTrue(permitted)

        # Test recall denied in OPEN mode
        permitted, _ = self.client.check_recall(memory_class=4)
        self.assertFalse(permitted)

    def tearDown(self):
        self.daemon.stop()
```

## Deployment Checklist

- [ ] Boundary Daemon installed and running
- [ ] Unix socket accessible to all components
- [ ] Memory Vault integrated with RecallGate
- [ ] Agent-OS integrated with ToolGate
- [ ] External model adapters integrated
- [ ] Event logging verified
- [ ] Systemd service enabled
- [ ] Initial mode configured
- [ ] Tripwires enabled
- [ ] Human override ceremony tested

## Common Pitfalls

### ❌ Don't Do This

```python
# WRONG: Bypassing boundary daemon
def retrieve_memory(memory_id):
    # NO CHECK WITH BOUNDARY DAEMON
    return database.get(memory_id)  # FATAL VIOLATION
```

### ✅ Do This

```python
# CORRECT: Always check with boundary daemon
def retrieve_memory(memory_id, memory_class):
    permitted, reason = recall_gate.check_recall(memory_class)
    if not permitted:
        raise PermissionError(reason)
    return database.get(memory_id)
```

## Support

For integration issues:

1. Check daemon status: `boundaryctl status`
2. Review recent events: `boundaryctl events`
3. Verify log integrity: `boundaryctl verify`
4. Check daemon logs: `journalctl -u boundary-daemon`

## Architecture Principles

1. **Mandatory Enforcement**: Components MUST NOT bypass the daemon
2. **Fail-Closed**: Ambiguity defaults to DENY
3. **Immutable Logging**: All decisions are logged with hash chain and Ed25519 signatures
4. **Human Override**: Requires ceremony, never silent
5. **Deterministic**: Same inputs → same decision

## Error Handling Integration

All integrating components should use the daemon's error handling framework for consistent error management:

```python
from daemon.utils.error_handling import (
    ErrorCategory,
    handle_error,
    with_error_handling,
    safe_execute,
)

# Decorator for automatic error handling with retries
@with_error_handling(
    category=ErrorCategory.NETWORK,
    retry_count=3,
    retry_delay=1.0,
    retry_backoff=2.0,
)
def call_boundary_daemon():
    client = BoundaryAPIClient()
    return client.check_recall(memory_class=3)

# Context manager for scoped error handling
with safe_execute("boundary_check", ErrorCategory.SECURITY) as result:
    client = BoundaryAPIClient()
    result.value = client.check_recall(memory_class=3)

if not result.success:
    # Handle error (already logged)
    fallback_behavior()
```

### Error Categories

- **SECURITY**: Security-related errors (highest priority)
- **AUTH**: Authentication/authorization errors
- **NETWORK**: Network connectivity errors
- **FILESYSTEM**: File system errors
- **SYSTEM**: Process/system errors
- **CONFIG**: Configuration errors

---

**Remember**: The Boundary Daemon exists to answer "where am I allowed to think?" If the system cannot clearly answer this question, it is not safe to think at all.
