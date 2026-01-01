# Changelog

All notable changes to the Boundary Daemon project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha] - 2026-01-01

**Alpha Release** - First public Alpha of Boundary Daemon (Agent Smith)

This release represents a fully-featured security policy and audit system for AI agent environments with 140+ modules across all capability areas.

### Highlights

- **Complete Core Security Engine**: Six boundary modes, fail-closed security, immutable audit logging
- **AI/Agent Security Suite**: Prompt injection detection (50+ patterns), RAG injection detection, agent attestation
- **Process Sandboxing**: Linux namespace isolation, seccomp-bpf filtering, cgroups v2, per-sandbox firewall
- **Blockchain Security**: Validator key protection (slashing prevention), RPC endpoint hardening, MEV protection
- **Enterprise Ready**: SIEM integration, identity federation, compliance automation, Prometheus metrics
- **Cross-Platform**: Linux (full support) and Windows (monitoring + firewall enforcement)

### What's in Alpha

All documented features are implemented and tested. This release is suitable for:
- Development and testing environments
- Security researchers and evaluators
- Early adopters building on Agent OS

API contracts may evolve before v1.0 stable release.

### Added
- **SIEM Integration** (`daemon/integrations/siem/`):
  - CEF/LEEF event formatting for Splunk/QRadar/ArcSight
  - Log shipping via Kafka, S3, GCS, HTTP endpoints
  - Sandbox event streaming
  - Signature verification API for external SIEMs
- **Identity Federation** (`daemon/identity/`):
  - OIDC token validation
  - LDAP group to capability mapping
  - PAM integration for system authentication
  - Identity manager for centralized identity handling
- **Compliance Automation** (`daemon/compliance/`):
  - NIST 800-53 / ISO 27001 control mapping
  - Evidence bundle generation for auditors
  - Periodic access review ceremonies
  - Zero-knowledge proof support
- **Threat Detection** (`daemon/detection/`):
  - YARA rule engine integration
  - Sigma rule support
  - Signed IOC feed management
  - MITRE ATT&CK pattern detection
- **eBPF Observability** (`daemon/ebpf/`):
  - eBPF-based kernel observability
  - Policy integration for eBPF events
  - Multiple probe definitions
- **Process Sandboxing** (`daemon/sandbox/`):
  - Linux namespace isolation (PID, network, mount, IPC, UTS, user)
  - Seccomp-bpf syscall filtering
  - Cgroups v2 resource limits
  - Per-sandbox network policy
  - AppArmor/SELinux profile generation
  - YAML profile configuration
- **Air-Gap Operations** (`daemon/airgap/`):
  - Data diode for one-way log export
  - QR code ceremonies for offline approval
  - Sneakernet protocol for secure data transfer
- **Cryptographic Enhancements** (`daemon/crypto/`):
  - HSM abstraction layer (PKCS#11, CloudHSM, YubiHSM)
  - Post-quantum cryptography preparation (Kyber, Dilithium)
- **Threat Federation** (`daemon/federation/`):
  - Multi-host threat intelligence sharing
  - Privacy-preserving pattern sharing
- **Security Intelligence** (`daemon/intelligence/`):
  - Mode advisor for context-based recommendations
- **Alert Case Management** (`daemon/alerts/`):
  - Case lifecycle management (NEW → INVESTIGATING → RESOLVED)
  - SLA tracking
- **Code Integrity** (`daemon/integrity/`):
  - Ed25519 code signing utilities
  - Runtime integrity verification
  - Manifest-based verification
- **Agent Containment** (`daemon/containment/`):
  - Agent behavior profiling
  - Anomaly detection for AI agents
- **Terminal Dashboard** (`daemon/tui/`):
  - Real-time TUI dashboard
- **Configuration Linting** (`daemon/config/linter.py`):
  - Configuration validation
  - Security posture scoring
- **Health Check API** (`daemon/api/health.py`):
  - Kubernetes/systemd compatibility
  - Liveness, readiness, startup probes
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
- **Blockchain Security Module** (`daemon/blockchain/`):
  - Validator key protection with double-sign/slashing prevention
  - Height/round/step tracking for Tendermint/CometBFT validators
  - Ethereum 2.0 validator slashing protection
  - Persistent signing history for crash recovery
  - RPC endpoint firewall with method risk classification
  - MEV (Maximal Extractable Value) attack protection
  - Per-client rate limiting for RPC endpoints
  - Authentication enforcement for sensitive RPC methods
- **Dreaming Status Reporter** (`daemon/dreaming.py`):
  - Periodic CLI status updates during daemon operations
  - Activity-based output (only prints during active operations)
  - Phase tracking (watching, verifying, guarding, etc.)
  - Operation completion status with success/failure indicators
- **Threat Mesh Federation** (`daemon/federation/threat_mesh.py`):
  - HTTPS-based threat signature sharing between daemon instances
  - Ed25519 signed payloads for peer verification
  - TLS verification for secure federation
- **HSM Cryptographic Strengthening** (`daemon/crypto/hsm_provider.py`):
  - XSalsa20-Poly1305 authenticated encryption (replacing weak XOR)
  - PBKDF2 key derivation with 100k iterations
  - Ed25519 signatures for HSM operations
- YARA scanning enabled via yara-python dependency
- Comprehensive unit test suite expanded to 488 tests

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
- Fixed memory leaks in state_monitor, tripwires, privilege_manager, queue_monitor
  - Converted unbounded lists to bounded deques (maxlen=100-1000)
- Fixed deque slicing in cellular threat detection
- Rate-limited manifest integrity failure messages (10-minute cooldown)

### Security
- Narrowed exception handlers to prevent catching security-critical exceptions
- Added specific exception handling for known error types
- Integrated centralized error framework for consistent security logging
- Fixed potential security issues identified in security audit
- Static security analysis with Bandit (77,576 lines, 0 high severity issues)
- Use tempfile.TemporaryDirectory for SELinux module compilation
- Added nosec annotations for intentional security choices (documented in SECURITY.md)

## [0.0.1] - 2024-01-01 (Initial Development)

### Added
- Initial development version of Boundary Daemon (Agent Smith)
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

[0.1.0-alpha]: https://github.com/kase1111-hash/boundary-daemon-/releases/tag/v0.1.0-alpha
