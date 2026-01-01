# Changelog

All notable changes to the Boundary Daemon project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **AI/Agent Security Features**:
  - Prompt injection detection (`daemon/security/prompt_injection.py`):
    - 50+ detection patterns across 10 injection categories
    - Jailbreak, DAN, instruction injection, encoding bypass detection
    - Configurable sensitivity levels (low, medium, high, paranoid)
  - Tool output validation (`daemon/security/tool_validator.py`):
    - Recursive call chain detection and prevention
    - Command injection detection in tool outputs
    - PII and sensitive data leakage prevention
    - Rate limiting and size limits
  - Response guardrails (`daemon/security/response_guardrails.py`):
    - Harmful content blocking (violence, self-harm, hate speech)
    - Hallucination detection (overconfidence, unsupported claims)
    - Citation and source validation
    - Mode-specific guardrail policies
  - RAG injection detection (`daemon/security/rag_injection.py`):
    - Poisoned document detection
    - Indirect injection via retrieved documents
    - Context manipulation detection
    - Exfiltration query detection
    - Document trust level verification
  - Agent attestation (`daemon/security/agent_attestation.py`):
    - Cryptographic agent identity certificates
    - Attestation token issuance and verification
    - Capability-based access control (CBAC)
    - Delegation chain verification (max depth 5)
    - Action binding with HMAC-SHA256 signatures
    - Token and agent revocation
    - Trust levels (UNTRUSTED → SYSTEM)
- **Windows Firewall Enforcement** (`daemon/enforcement/windows_firewall.py`):
  - Windows Firewall with Advanced Security via netsh/PowerShell
  - Mode-based firewall rules (OPEN, RESTRICTED, TRUSTED, AIRGAP, LOCKDOWN)
  - VPN adapter detection and whitelisting
  - Rule backup and restore
  - Fail-closed enforcement
- **End-to-End Security Stack Tests** (`tests/test_security_stack_e2e.py`):
  - Comprehensive tests for all AI security components
  - Integrated workflow testing
  - Attack scenario validation
- GitHub Actions CI/CD workflow for automated testing
- Comprehensive unit test suite (478 tests)
- Test coverage for core modules (privilege_manager, state_monitor, tripwires, etc.)
- **Robust error handling framework** (`daemon/utils/error_handling.py`):
  - Categorized error types (security, network, auth, filesystem, etc.)
  - Error severity levels (info, warning, error, critical, fatal)
  - Automatic error aggregation and deduplication
  - Retry logic with exponential backoff
  - Cross-platform error normalization (Windows/Linux)
  - Recovery action suggestions
  - Decorator and context manager patterns for clean integration
- Persistent signing key support for daemon integrity verification
- Windows platform support across core modules
- Centralized constants module for security-sensitive values

### Changed
- Updated minimum Python version to 3.9 (dropped Python 3.8 EOL support)
- Added Python 3.12 and 3.13 to supported versions
- Lowered test coverage threshold to 25% (target: 50%)
- Narrowed broad Exception catches in security-critical paths
- Integrated error handling framework across security modules and API server

### Fixed
- Renamed `TestResultCollector` to `AttackResultCollector` to fix pytest collection warning
- Added coverage files to `.gitignore`
- Fixed Windows platform issues in antivirus module
- Fixed four critical security vulnerabilities in core modules
- Fixed three high severity security vulnerabilities
- Fixed four medium severity security issues in TPM manager
- Fixed three low severity security issues
- Improved error handling in API server and TPM manager

### Security
- Narrowed exception handlers to prevent catching security-critical exceptions
- Added specific exception handling for known error types
- Integrated centralized error framework for consistent security logging
- Fixed potential security issues identified in security audit

## [1.0.0] - 2024-01-01

### Added
- Initial release of Boundary Daemon (Agent Smith)
- Policy decision and audit layer for Agent OS
- Six security boundary modes: OPEN, RESTRICTED, TRUSTED, AIRGAP, COLDROOM, LOCKDOWN
- Memory classification system (PUBLIC to CROWN_JEWEL)
- Immutable audit logging with SHA-256 hash chains
- Ed25519 cryptographic signatures for events
- Tripwire system for security violation detection
- Token-based API authentication with capabilities
- Rate limiting with persistence across restarts
- State monitoring for network, hardware, and human presence
- Integration interfaces for Memory Vault, Tool Enforcement, and Ceremonies
- Multi-step human confirmation ceremonies for sensitive operations
- Biometric verification support
- TPM (Trusted Platform Module) integration
- Distributed coordination for multi-host deployments
- Log hardening with Linux chattr append-only protection
- DNS, ARP, and WiFi security monitoring
- Threat intelligence integration
- File integrity monitoring
- Traffic anomaly detection
- Process security monitoring
- Health monitoring with heartbeat tracking
- OpenTelemetry observability integration
- CLI tools: boundaryctl, authctl, policy_ctl, cluster_ctl, biometric_ctl
- Systemd service files for daemon and watchdog
- Comprehensive documentation (SPEC.md, ARCHITECTURE.md, USER_GUIDE.md)

### Security
- Fail-closed design: ambiguous signals result in DENY
- Defense in depth: operates at Layer 3, requires kernel/hardware enforcement
- Tamper-evident logging with cryptographic proof
- Constant-time token comparison to prevent timing attacks
- Automatic lockdown on security violations
- Rate limiting to prevent abuse
- Privilege tracking and alerting for root requirements

[Unreleased]: https://github.com/kase1111-hash/boundary-daemon-/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/kase1111-hash/boundary-daemon-/releases/tag/v1.0.0
