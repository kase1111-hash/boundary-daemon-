# Contributing to Boundary Daemon

Thank you for your interest in contributing to Boundary Daemon (Agent Smith). This is a security-critical component, and we take contributions seriously.

## Security First

Before contributing, please understand that this project prioritizes security over convenience. All contributions must:

1. **Maintain fail-closed semantics** - Uncertainty must default to DENY
2. **Preserve immutable logging** - Never bypass or weaken audit trails
3. **Not introduce convenience features that weaken security**
4. **Include comprehensive tests**
5. **Pass security review**

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Git
- Understanding of security principles and threat modeling

### Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR-USERNAME/boundary-daemon-.git
   cd boundary-daemon
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```
4. Install in development mode:
   ```bash
   pip install -e .
   ```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=daemon --cov-report=html

# Run specific test file
pytest tests/test_policy_engine.py

# Run security-specific tests
pytest tests/test_security_stack_e2e.py
```

### Code Quality Checks

```bash
# Type checking
mypy daemon/

# Linting
ruff check daemon/

# Security scanning
bandit -r daemon/
```

## How to Contribute

### Reporting Bugs

- Check existing issues first to avoid duplicates
- Use the bug report template
- Include detailed reproduction steps
- Specify your environment (OS, Python version)
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

### Suggesting Features

- Use the feature request template
- Explain the security implications
- Consider if the feature aligns with the project's fail-closed philosophy
- Features that introduce convenience at the cost of security will not be accepted

### Submitting Pull Requests

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed

3. **Test thoroughly**:
   ```bash
   pytest
   mypy daemon/
   ruff check daemon/
   ```

4. **Commit with clear messages**:
   ```bash
   git commit -m "Add feature: brief description

   Detailed explanation of what this change does and why.
   Include any security considerations."
   ```

5. **Push and create PR**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Fill out the PR template** completely

## Code Guidelines

### Style

- Follow PEP 8 with a line length of 100 characters
- Use type hints for all function signatures
- Use descriptive variable and function names
- Keep functions focused and small

### Security Requirements

- Never log sensitive data (passwords, keys, PII)
- Validate all inputs at trust boundaries
- Use cryptographic functions from `pynacl` or `cryptography` libraries
- Avoid shell injection vulnerabilities
- Handle errors without exposing internal details

### Documentation

- Add docstrings to all public functions and classes
- Update relevant markdown documentation
- Include usage examples for new features
- Document security implications

### Testing

- Write unit tests for all new code
- Include edge cases and error conditions
- Test security-sensitive code paths thoroughly
- Aim for high coverage on security-critical modules

## Review Process

1. **Automated checks** must pass (CI/CD pipeline)
2. **Code review** by at least one maintainer
3. **Security review** for changes affecting:
   - Authentication/authorization
   - Cryptography
   - Logging/audit
   - Policy engine
   - Tripwire system

## What We Accept

- Bug fixes with tests
- Security improvements
- Documentation improvements
- Performance improvements that don't compromise security
- New detection capabilities (YARA rules, Sigma rules, etc.)
- Platform support improvements

## What We Don't Accept

- Features that weaken security for convenience
- Changes that bypass fail-closed semantics
- Modifications to audit logging that reduce integrity
- Dependencies with known security vulnerabilities
- Machine learning-based detection (we use deterministic rules only)

## Communication

- Use GitHub Issues for bug reports and feature requests
- Use GitHub Discussions for questions and general discussion
- For security vulnerabilities, follow the process in [SECURITY.md](SECURITY.md)

## License

By contributing to Boundary Daemon, you agree that your contributions will be licensed under the GNU General Public License v3 (GPL-3.0).

## Recognition

Contributors will be recognized in release notes. Significant contributions may be acknowledged in the README.

---

Thank you for helping make AI systems more secure and trustworthy.
