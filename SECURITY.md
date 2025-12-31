# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

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

## Security Best Practices

When deploying Boundary Daemon:

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

## Security Audit

See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the full security audit report.

## Dependencies

We minimize dependencies to reduce attack surface:

- `psutil`: System monitoring
- `pynacl`: Ed25519 cryptography (libsodium bindings)
- `cryptography`: Additional cryptographic primitives

All dependencies are regularly scanned for vulnerabilities using `safety` and GitHub Dependabot.
