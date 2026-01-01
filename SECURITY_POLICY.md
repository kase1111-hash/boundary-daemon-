# Security Policy

**Version:** 1.0.0
**Effective Date:** 2026-01-01
**Last Review:** 2026-01-01
**Next Review:** 2026-04-01 (Quarterly)

---

## Purpose

This document codifies security practices for the Boundary Daemon project to ensure consistent security hygiene across development, testing, and deployment.

---

## 1. SSL/TLS Certificate Verification

### Policy
All production deployments MUST use full certificate verification (`CERT_REQUIRED`).

### CERT_NONE Usage Guidelines

| Context | Allowed | Requirements |
|---------|---------|--------------|
| Production | ❌ No | Never disable verification |
| Development | ⚠️ Conditional | Explicit warning logged |
| Testing | ✅ Yes | Test environment only |
| Federation modules | ⚠️ Conditional | Must be explicitly configured |

### Monitoring Requirements

The following files use configurable SSL verification and require quarterly review:

```
daemon/federation/threat_sharing.py
daemon/federation/privacy_sharing.py
```

**Review Checklist:**
- [ ] Verify `CERT_NONE` is not hardcoded
- [ ] Confirm warning messages are logged when verification is disabled
- [ ] Ensure environment variable or config flag controls the behavior
- [ ] Document any legitimate use cases requiring disabled verification

---

## 2. CI/CD Security Scanner Integration

### Policy
All code changes MUST pass automated security scanning before merge.

### Required Scans

| Scanner | Location | Trigger |
|---------|----------|---------|
| Static Analyzer | `daemon/security/static_analyzer.py` | Pre-commit, PR |
| Backdoor Scanner | `daemon/security/static_analyzer.py` | PR, Nightly |
| Credential Scanner | Pre-commit hook | Every commit |
| Dependency Audit | `pip-audit` / `safety` | Weekly, PR |

### Integration Points

```yaml
# Example CI configuration
security-scan:
  stage: test
  script:
    - python -m daemon.security.static_analyzer --path . --strict
    - pip-audit
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_PIPELINE_SOURCE == "schedule"
```

### Scan Failure Response

| Severity | Action |
|----------|--------|
| Critical | Block merge, notify security team |
| High | Block merge, require security review |
| Medium | Warning, require acknowledgment |
| Low | Warning only |

---

## 3. Test Credential Hygiene

### Policy
Test credentials MUST be clearly marked and MUST NOT leak into production.

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

### Review Schedule

| Review Type | Frequency | Scope |
|-------------|-----------|-------|
| Automated scan | Every commit | Full codebase |
| Manual audit | Quarterly | Test files, fixtures |
| Secret rotation | Immediate | Any suspected leak |

### Pre-commit Hook

A comprehensive credential detection hook is provided in `.githooks/pre-commit`.

**Installation:**
```bash
# Run the install script
./scripts/install-hooks.sh

# Or configure manually
git config core.hooksPath .githooks
```

**What it detects:**

| Category | Examples |
|----------|----------|
| Cloud Provider Keys | AWS (AKIA...), GCP service accounts, Azure keys |
| Private Keys | RSA, DSA, EC, OpenSSH, PGP private keys |
| API Tokens | GitHub, GitLab, Slack, Stripe, SendGrid, Twilio |
| Database URLs | PostgreSQL, MySQL, MongoDB, Redis with passwords |
| Generic Secrets | JWT secrets, hardcoded passwords, API keys |
| Credential Files | .env, credentials.json, .pem, .key files |

**Bypass (not recommended):**
```bash
git commit --no-verify  # Skips all hooks
```

---

## 4. Code Review Security Checklist

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

## 5. Incident Response

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

## 6. Dependency Security

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

---

## 7. Enforcement Module Security

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

## 8. Audit Log Protection

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

## 9. Security Contacts

| Role | Contact | Responsibility |
|------|---------|----------------|
| Security Lead | security@example.com | Policy, incidents |
| On-call | pager@example.com | Critical issues |
| Maintainers | GitHub issues (private) | Code review |

---

## 10. Policy Review

This policy is reviewed quarterly. Changes require:

1. Security team approval
2. Maintainer review
3. Changelog entry
4. Version increment

---

**Document Control:**
- **Author:** Security Team
- **Classification:** PUBLIC
- **Repository:** boundary-daemon-/SECURITY_POLICY.md
