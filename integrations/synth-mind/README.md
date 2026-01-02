# Synth-Mind Boundary Integration

Complete boundary daemon integration for the Synthetic Mind Stack.

## Installation

Copy the `src/boundary` directory to your synth-mind installation:

```bash
cp -r src/boundary /path/to/synth-mind/
```

## Quick Start

```python
from boundary import SynthMindBoundaryIntegration, ReflectionGate

# Initialize integration
boundary = SynthMindBoundaryIntegration()

# Check before reflection loop (MANDATORY)
if boundary.can_run_reflection():
    run_reflection_loop()

# Or use decorator
from boundary import require_reflection_check

@require_reflection_check()
def meta_reflection():
    # This will only run if reflection is permitted
    pass
```

## Required Changes to Synth-Mind

### 1. Meta-Reflection Module

```python
# Before (NO BOUNDARY CHECK - VIOLATION)
def run_reflection_loop():
    while True:
        reflect()
        time.sleep(interval)

# After (WITH BOUNDARY CHECK)
from boundary import ReflectionGate

def run_reflection_loop():
    gate = ReflectionGate()
    while True:
        if gate.can_reflect():
            reflect()
        else:
            logger.warning(f"Reflection skipped: {gate.last_decision.reason}")
        time.sleep(interval)
```

### 2. Memory Access

```python
from boundary import MemoryGate

gate = MemoryGate()
if gate.can_access(memory_class=2):  # CONFIDENTIAL
    memory = vault.retrieve(memory_id)
```

### 3. External Communications

```python
from boundary import CommunicationGate

gate = CommunicationGate()
if gate.can_communicate(target="user", content=message):
    send_message(target, message)
```

## Module-Specific Integration

See `src/boundary/integration.py` for complete examples of integrating
each of the six psychological modules.
