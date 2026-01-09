# Security Policy

**Version:** 1.0.0-beta
**Effective Date:** 2026-01-01
**Last Review:** 2026-01-09

---

## Purpose

This document codifies security practices, policies, and best practices for the Boundary Daemon (Agent Smith) project to ensure consistent security hygiene across development, testing, and deployment.

---

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

---

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub issue** for security vulnerabilities
2. Email your findings to the maintainers (see repository contacts)
3. Include the following in your report:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours of your report
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release cycle

### Disclosure Policy

- We follow coordinated disclosure practices
- Security fixes will be released as soon as possible
- Credit will be given to reporters (unless anonymity is requested)
- Public disclosure after patch is available

---

## Security Best Practices

### Run with Appropriate Privileges

```bash
# For full enforcement, run as root
sudo boundary-daemon

# For monitoring-only mode, non-root is acceptable
boundary-daemon --mode=open
```

### Protect Configuration Files

```bash
# Secure token storage
chmod 600 /etc/boundary-daemon/api_tokens.json
chmod 700 /etc/boundary-daemon/

# Protect log files
chmod 600 /var/log/boundary-daemon/*.log
```

### Network Security

- Use Unix sockets (default) instead of TCP for local API
- If using TCP, bind only to localhost
- Enable TLS for remote syslog if configured

### Log Integrity

- Enable append-only mode for audit logs
- Configure remote syslog backup
- Regularly verify log chain integrity

```bash
boundaryctl verify-log
```

---

## Security Features

### Defense in Depth

The daemon implements multiple security layers:

1. **Policy Engine**: Enforces boundary modes (OPEN → LOCKDOWN)
2. **Tripwires**: Detects violations and triggers automatic lockdown
3. **Immutable Logging**: SHA-256 hash chains, Ed25519 signatures
4. **Rate Limiting**: Prevents abuse, persists across restarts
5. **Token Authentication**: Capability-based access control

### Fail-Closed Design

- Unknown states → DENY
- Ambiguous signals → DENY
- Daemon crash → LOCKDOWN
- Clock drift → Freeze transitions

### Known Limitations

1. **Not a Runtime Enforcer**: The daemon provides policy decisions, not enforcement. Actual enforcement requires kernel-level controls (SELinux, seccomp, etc.)

2. **Root Required for Enforcement**: Full enforcement features (iptables, chattr, USB blocking) require root privileges. Without root, the daemon operates in detection/logging mode only.

3. **Cooperative Model**: External systems must voluntarily respect the daemon's decisions.

See [ENFORCEMENT_MODEL.md](ENFORCEMENT_MODEL.md) for detailed explanation.

---

## SSL/TLS Certificate Verification

### Policy
All production deployments MUST use full certificate verification (`CERT_REQUIRED`).

### CERT_NONE Usage Guidelines

| Context | Allowed | Requirements |
|---------|---------|--------------|
| Production | No | Never disable verification |
| Development | Conditional | Explicit warning logged |
| Testing | Yes | Test environment only |
| Federation modules | Conditional | Must be explicitly configured |

### Monitoring Requirements

The following files use configurable SSL verification and require quarterly review:

```
daemon/federation/threat_sharing.py
daemon/federation/privacy_sharing.py
```

---

## CI/CD Security Scanner Integration

### Required Scans

| Scanner | Location | Trigger |
|---------|----------|---------|
| Static Analyzer | `daemon/security/static_analyzer.py` | Pre-commit, PR |
| Backdoor Scanner | `daemon/security/static_analyzer.py` | PR, Nightly |
| Credential Scanner | Pre-commit hook | Every commit |
| Dependency Audit | `pip-audit` / `safety` | Weekly, PR |

### Scan Failure Response

| Severity | Action |
|----------|--------|
| Critical | Block merge, notify security team |
| High | Block merge, require security review |
| Medium | Warning, require acknowledgment |
| Low | Warning only |

---

## Test Credential Hygiene

### Allowed Test Credentials

| Pattern | Location | Purpose |
|---------|----------|---------|
| `test_token_*` | `tests/` only | Unit test authentication |
| `example_password` | `tests/` only | Password validation tests |
| `AKIA[EXAMPLE]*` | Documentation only | AWS key format examples |

### Prohibited Patterns

The following patterns are **NEVER** allowed anywhere in the codebase:

- Real API keys (AWS, GCP, Azure, etc.)
- Production database credentials
- Private keys (RSA, Ed25519, etc.)
- OAuth client secrets
- JWT signing keys

### Pre-commit Hook

A comprehensive credential detection hook is provided in `.githooks/pre-commit`.

**Installation:**
```bash
./scripts/install-hooks.sh
# Or manually:
git config core.hooksPath .githooks
```

---

## Code Review Security Checklist

All PRs modifying security-sensitive code require this checklist:

### Authentication & Authorization
- [ ] No hardcoded credentials
- [ ] Tokens use `secrets` module (not `random`)
- [ ] Constant-time comparison for secrets (`hmac.compare_digest`)
- [ ] Capability checks before privileged operations

### Input Validation
- [ ] All external input sanitized
- [ ] No `eval()` or `exec()` on user input
- [ ] No `shell=True` with user-controlled data
- [ ] Path traversal prevention for file operations

### Cryptography
- [ ] Uses `os.urandom()` or `secrets` for randomness
- [ ] No deprecated algorithms (MD5, SHA1 for security, DES)
- [ ] Key material not logged or exposed

### Network Security
- [ ] SSL verification enabled by default
- [ ] Timeouts on all network operations
- [ ] No SSRF vulnerabilities

---

## Incident Response

### Security Issue Discovery

1. **Do NOT** commit fixes without security team review
2. **Do NOT** disclose publicly until patched
3. **DO** report via security@example.com or private issue

### Severity Classification

| Level | Examples | Response Time |
|-------|----------|---------------|
| Critical | RCE, credential leak, backdoor | Immediate (< 4 hours) |
| High | Privilege escalation, auth bypass | 24 hours |
| Medium | Information disclosure, DoS | 72 hours |
| Low | Best practice violation | Next release |

---

## Dependency Security

### Policy
All dependencies MUST be audited before addition and monitored continuously.

### Approval Requirements

| Dependency Type | Approval |
|-----------------|----------|
| Core (required) | Security team + 2 maintainers |
| Optional module | 1 maintainer |
| Dev/test only | Any maintainer |

### Monitoring

```bash
# Weekly dependency audit
pip-audit --strict --vulnerability-service osv

# Check for outdated packages with known vulnerabilities
safety check
```

### Core Dependencies

We minimize dependencies to reduce attack surface:

- `psutil`: System monitoring
- `pynacl`: Ed25519 cryptography (libsodium bindings)
- `cryptography`: Additional cryptographic primitives (Fernet, PBKDF2)
- `cffi`: C library bindings (dependency of pynacl)

All dependencies are regularly scanned for vulnerabilities using `safety` and GitHub Dependabot.

---

## Enforcement Module Security

### Environment Variables

Enforcement modules require explicit enablement:

| Variable | Purpose | Default |
|----------|---------|---------|
| `BOUNDARY_NETWORK_ENFORCE` | iptables/nftables rules | Disabled |
| `BOUNDARY_USB_ENFORCE` | udev device blocking | Disabled |
| `BOUNDARY_PROCESS_ENFORCE` | seccomp/container isolation | Disabled |

### Privilege Requirements

| Module | Minimum Privilege | Fallback |
|--------|-------------------|----------|
| Network enforcer | root / CAP_NET_ADMIN | Log-only mode |
| USB enforcer | root | Log-only mode |
| Process enforcer | root / CAP_SYS_ADMIN | Log-only mode |

---

## Audit Log Protection

### Requirements

- Logs MUST use append-only mode (`chattr +a` on Linux)
- Hash chain integrity verification enabled
- Remote log shipping for critical deployments
- 90-day minimum retention

### Verification

```bash
# Verify log integrity
boundaryctl verify --all

# Check append-only attribute
lsattr /var/log/boundary/*.log
```

---

## Error Handling

The daemon uses a robust error handling framework that:

- **Categorizes errors** by type (security, auth, network, filesystem, etc.)
- **Assigns severity levels** (info, warning, error, critical, fatal)
- **Aggregates and deduplicates** errors to prevent log flooding
- **Provides retry logic** with exponential backoff for transient failures
- **Normalizes platform-specific errors** for consistent handling across Windows/Linux

### Security-Critical Error Handling

For security-critical operations, the daemon:

1. Uses narrow exception handling to avoid catching security exceptions
2. Logs all errors with full context for forensic analysis
3. Applies fail-closed semantics for ambiguous errors
4. Suggests appropriate recovery actions based on error type

---

## Static Analysis

The codebase is regularly analyzed with [Bandit](https://bandit.readthedocs.io/) for security issues.

### Current Status (77,576 lines)

| Severity | Count | Status |
|----------|-------|--------|
| High | 0 | Clean |
| Medium | ~50 | Reviewed (see below) |
| Low | ~600 | Expected (subprocess usage) |

### Intentional Security Choices

The following patterns are intentionally used and marked with `# nosec`:

1. **B104 (0.0.0.0 binding)**: Health check endpoint needs network access for Kubernetes/orchestrator probes
2. **B108 (/tmp usage)**: Monitoring paths, detecting malicious processes, development defaults
3. **B311 (random module)**: Used for non-security purposes (UI phrase variety, mock simulations)
4. **B110 (try/except/pass)**: Optional feature imports that should not crash the daemon
5. **B603/B607 (subprocess)**: Required for system enforcement (iptables, SELinux, etc.)

### Running Security Scans

```bash
# Full scan
python -m bandit -r daemon/ -f txt

# High severity only
python -m bandit -r daemon/ -f txt -lll

# Generate HTML report
python -m bandit -r daemon/ -f html -o security_report.html
```

---

## Recent Security Fixes

The following security issues have been addressed:

- **Critical**: Fixed four critical security vulnerabilities in core modules
- **High**: Fixed three high severity security vulnerabilities
- **Medium**: Fixed four medium severity security issues in TPM manager
- **Low**: Fixed three low severity security issues
- Narrowed broad Exception catches in security-critical paths
- Integrated centralized error framework for consistent security logging

---

## Security Contacts

| Role | Contact | Responsibility |
|------|---------|----------------|
| Security Lead | security@example.com | Policy, incidents |
| On-call | pager@example.com | Critical issues |
| Maintainers | GitHub issues (private) | Code review |

---

## Policy Review

This policy is reviewed quarterly. Changes require:

1. Security team approval
2. Maintainer review
3. Changelog entry
4. Version increment

---

## Related Documentation

- [SECURITY_AUDIT.md](SECURITY_AUDIT.md) - Full security audit report
- [ENFORCEMENT_MODEL.md](ENFORCEMENT_MODEL.md) - What the daemon does and doesn't do
- [docs/SECURITY_COMPARISON.md](docs/SECURITY_COMPARISON.md) - Comparison with enterprise tools

---

**Document Control:**
- **Author:** Security Team
- **Classification:** PUBLIC
- **Repository:** boundary-daemon-/SECURITY.md
