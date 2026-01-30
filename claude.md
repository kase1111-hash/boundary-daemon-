# Claude.md - Boundary Daemon

## Project Overview

Boundary Daemon (Agent Smith) is a security daemon and cognition boundary control layer for multi-agent AI systems. It's the core trust enforcement system for Agent OS—a natural language operating system for AI agents.

**Core Mission:** Define, enforce, and audit AI boundary policies between cognitive modules. It determines where AI can think, what it can access, and ensures secure agent orchestration.

**Key Question It Answers:** "Where am I allowed to think right now?"

## Architecture

### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| Main Daemon | `daemon/boundary_daemon.py` | Service orchestration, lifecycle management |
| State Monitor | `daemon/state_monitor.py` | Environment sensing at 1Hz (network, hardware, processes) |
| Policy Engine | `daemon/policy_engine.py` | Permission evaluation against boundary modes |
| Tripwires | `daemon/tripwires.py` | Security violation detection, auto-lockdown triggers |
| Event Logger | `daemon/event_logger.py` | Immutable SHA-256 hash-chained audit trail |

### Directory Structure

```
daemon/
├── auth/           # Authentication & ceremony workflows
├── enforcement/    # Kernel enforcement (iptables, USB, processes)
├── security/       # AI security (prompt injection, RAG, attestation)
├── sandbox/        # Process sandboxing (namespaces, seccomp, cgroups)
├── detection/      # Threat detection (YARA, Sigma, IOC feeds)
├── integrations/   # SIEM integration (CEF/LEEF, Kafka)
├── identity/       # Identity federation (OIDC, LDAP, PAM)
├── compliance/     # Compliance automation (NIST, ISO 27001)
└── ...             # See full structure in codebase
api/                # Unix socket API
tests/              # pytest test suite
config/             # Configuration files
```

### Boundary Modes (Central Concept)

```python
class BoundaryMode(IntEnum):
    OPEN = 0        # Networked, low trust
    RESTRICTED = 1  # Network allowed, memory limited
    TRUSTED = 2     # Offline or verified LAN
    AIRGAP = 3      # Physically isolated
    COLDROOM = 4    # Display-only I/O
    LOCKDOWN = 5    # Emergency freeze
```

Policy decisions are based on: `(mode × environment × request) → decision`

## Technology Stack

- **Language:** Python 3.9+ (supports 3.9-3.13)
- **Testing:** pytest with pytest-cov
- **Type Checking:** mypy
- **Linting:** ruff
- **Security Scanning:** bandit, safety
- **Core Dependencies:** psutil, cryptography, pynacl, yara-python, PyYAML

## Development Commands

```bash
# Install for development
pip install -e .
pip install -r requirements-dev.txt

# Run tests
pytest                           # All tests
pytest tests/test_policy.py      # Specific module
pytest -m unit                   # Only unit tests
pytest -m "not slow"             # Skip slow tests

# Code quality
mypy daemon/                     # Type checking
ruff check .                     # Linting
bandit -r daemon/                # Security scan

# CLI tools
boundaryctl status               # Check daemon status
sandboxctl list                  # List sandboxes
```

## Security-First Design Philosophy

### Core Principles

1. **Fail-Closed** - Ambiguous signals default to DENY
2. **Authoritative** - Daemon decisions cannot be overridden programmatically
3. **Deterministic** - Same inputs always produce same decision (no ML for policy)
4. **Human-Centric** - Overrides require multi-step ceremony, never silent
5. **Immutable** - Audit trail is tamper-evident and permanent

### Critical Code Patterns

```python
# Always fail-closed on ambiguity
if ambiguous_state:
    return PolicyDecision.DENY

# Immutable logging with hash chain
event.prev_hash = self._last_hash
event.hash = hashlib.sha256(event_data).hexdigest()
```

### What NOT to Do

- Never allow silent failures in security paths
- Never skip hash chaining in event logging
- Never add convenience features that bypass ceremony
- Never use ML/probabilistic methods for policy decisions

## Coding Conventions

### Style

- **Line Length:** 100 characters
- **Type Hints:** Required on all function signatures
- **Docstrings:** Module, class, and public function docstrings required
- **Naming:** PascalCase for classes, snake_case for functions, UPPER_SNAKE_CASE for constants

### Patterns Used

- **Dataclasses** for data structures (`EnvironmentState`, `BoundaryState`)
- **Enums** for constants (`BoundaryMode`, `EventType`, `MemoryClass`)
- **Threading locks** for shared mutable state
- **Callbacks/Observers** for event notification
- **Optional imports** with graceful fallbacks for platform-specific features

### Cross-Platform Support

```python
IS_WINDOWS = sys.platform == 'win32'

# Pattern for optional features
try:
    from .enforcement import NetworkEnforcer
    ENFORCEMENT_AVAILABLE = True
except ImportError:
    ENFORCEMENT_AVAILABLE = False
```

## Testing Requirements

- All security-critical code requires comprehensive tests
- Use pytest markers: `unit`, `integration`, `security`, `slow`, `enforcement`
- Mock external dependencies (network, hardware, system calls)
- Test both success and failure paths
- Verify fail-closed behavior in error conditions

## Key Integration Points

- **Memory Vault** - Recall permission gating
- **Agent-OS** - Tool execution gating
- **SIEM Systems** - CEF/LEEF event streaming
- **Kubernetes** - Health check endpoints
- **SystemD** - Service management

## Important Files to Know

| Purpose | File |
|---------|------|
| Main entry point | `daemon/boundary_daemon.py` |
| Policy logic | `daemon/policy_engine.py` |
| Constants/Config | `daemon/constants.py` |
| Test fixtures | `tests/conftest.py` |
| CI/CD | `.github/workflows/ci.yml` |
| Full spec | `SPEC.md` |

## Common Tasks

### Adding a New Security Check

1. Add detection logic in appropriate `daemon/security/` module
2. Integrate with tripwire system if it can trigger lockdown
3. Add event type if new audit category needed
4. Write comprehensive tests including edge cases
5. Update documentation

### Modifying Policy Engine

1. Understand the decision matrix in `policy_engine.py`
2. Ensure changes maintain fail-closed semantics
3. Test all boundary mode combinations
4. Verify thread safety with locks
5. Update hash chain if event format changes

### Adding New Boundary Mode

1. Add to `BoundaryMode` enum in `constants.py`
2. Update decision matrix in `policy_engine.py`
3. Add tripwire rules in `tripwires.py`
4. Update enforcement modules if needed
5. Add comprehensive tests for new mode

## Warnings

- **This is security-critical software.** Every change must be carefully reviewed.
- **No exceptions allowed** in the fail-closed principle.
- **Hash chain integrity** must be maintained in event logger.
- **Test coverage** on security modules is mandatory.
- **Breaking changes** to policy engine require extensive testing.
