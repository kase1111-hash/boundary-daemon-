# Memory Vault Boundary Integration

Proper boundary daemon integration for Memory Vault.

**Note:** This replaces the existing `boundry.py` (fixes typo in filename).

## Installation

```bash
# Replace existing boundary module
cp src/boundary.py /path/to/memory-vault/memory_vault/boundary.py

# Update imports in memory_vault/__init__.py
# from .boundry import ...  # OLD (typo)
# from .boundary import ...  # NEW (correct)
```

## Quick Start

```python
from memory_vault.boundary import RecallGate, check_recall

# Before retrieving memory
gate = RecallGate()
if gate.can_recall(memory_class=3):
    memory = vault.retrieve(memory_id)
else:
    print(f"Recall denied: {gate.last_decision.reason}")

# Or use convenience function
permitted, reason = check_recall(classification=3)
```

## Integration Pattern

```python
from memory_vault.boundary import MemoryVaultBoundaryMixin

class SecureMemoryVault(MemoryVaultBoundaryMixin, BaseMemoryVault):
    """Memory Vault with automatic boundary enforcement."""
    pass

vault = SecureMemoryVault()
# All retrieve/store operations now have boundary checks
memory = vault.retrieve(memory_id, classification=2)
```

## Socket Path

The integration uses the correct socket path:
`/var/run/boundary-daemon/boundary.sock`

This fixes the path mismatch from the original integration.
