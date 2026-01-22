## Description

Provide a clear and concise description of your changes.

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Security improvement
- [ ] Code refactoring (no functional changes)

## Related Issues

Fixes #(issue number)

## Security Checklist

**All contributions must maintain our security-first approach.**

- [ ] I have read [CONTRIBUTING.md](CONTRIBUTING.md)
- [ ] This change maintains fail-closed semantics
- [ ] This change does not weaken audit logging or event integrity
- [ ] This change does not introduce convenience at the cost of security
- [ ] I have not added any dependencies with known vulnerabilities
- [ ] Sensitive data (passwords, keys, PII) is never logged
- [ ] All inputs at trust boundaries are validated

## Testing

- [ ] I have added tests that prove my fix/feature works
- [ ] All new and existing tests pass locally
- [ ] I have run `pytest` with no failures
- [ ] I have run `mypy daemon/` with no type errors
- [ ] I have run `ruff check daemon/` with no issues
- [ ] I have run `bandit -r daemon/` for security scanning

## Documentation

- [ ] I have updated relevant documentation
- [ ] I have added docstrings to new public functions/classes
- [ ] My code is self-documenting with clear variable/function names

## Changes Made

List the specific changes:

-
-
-

## Screenshots (if applicable)

Add screenshots for UI changes.

## Additional Notes

Add any additional context or notes for reviewers.

---

**Reviewer Notes:**

For security-sensitive changes (auth, crypto, logging, policy engine, tripwires), this PR requires security team review.
