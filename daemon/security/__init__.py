"""
Security Module for Boundary Daemon

Provides:
- Advisory-only code vulnerability scanning using local LLMs
- Antivirus scanning focused on keylogger and malware detection
- Native DNS resolution without external tool dependencies
- Daemon binary integrity protection

SECURITY: The native DNS resolver addresses the vulnerability:
"DNS Response Verification Uses External Tools" by providing
pure Python DNS packet construction and parsing.

SECURITY: The daemon integrity module addresses the vulnerability:
"No Integrity Protection on Daemon Binary" by providing cryptographic
verification of all daemon code files.
"""

from .code_advisor import (
    CodeVulnerabilityAdvisor,
    SecurityAdvisory,
    AdvisorySeverity,
    AdvisoryStatus,
    ScanResult
)

from .antivirus import (
    AntivirusScanner,
    RealTimeMonitor,
    StartupMonitor,
    ThreatIndicator,
    ThreatLevel,
    ThreatCategory,
    KeyloggerSignatures,
    ScreenSharingSignatures,
    NetworkMonitoringSignatures,
    ScanResult as AntivirusScanResult,
)

from .native_dns_resolver import (
    NativeDNSResolver,
    SecureDNSVerifier,
    DNSType,
    DNSResponse,
    DNSRecord,
)

# Secure memory utilities (SECURITY: Secret zeroing after use)
try:
    from .secure_memory import (
        SecureBytes,
        secure_zero_memory,
        secure_key_context,
        secure_compare,
        generate_secure_random,
    )
    SECURE_MEMORY_AVAILABLE = True
except ImportError:
    SECURE_MEMORY_AVAILABLE = False
    SecureBytes = None
    secure_zero_memory = None
    secure_key_context = None
    secure_compare = None
    generate_secure_random = None

# Daemon integrity protection (SECURITY: Binary tampering prevention)
try:
    from .daemon_integrity import (
        DaemonIntegrityProtector,
        IntegrityConfig,
        IntegrityStatus,
        IntegrityAction,
        IntegrityManifest,
        IntegrityCheckResult,
        verify_daemon_integrity,
    )
    DAEMON_INTEGRITY_AVAILABLE = True
except ImportError:
    DAEMON_INTEGRITY_AVAILABLE = False
    DaemonIntegrityProtector = None
    IntegrityConfig = None
    IntegrityStatus = None
    IntegrityAction = None
    IntegrityManifest = None
    IntegrityCheckResult = None
    verify_daemon_integrity = None

__all__ = [
    # Code advisor
    'CodeVulnerabilityAdvisor',
    'SecurityAdvisory',
    'AdvisorySeverity',
    'AdvisoryStatus',
    'ScanResult',
    # Antivirus
    'AntivirusScanner',
    'RealTimeMonitor',
    'StartupMonitor',
    'ThreatIndicator',
    'ThreatLevel',
    'ThreatCategory',
    'KeyloggerSignatures',
    'ScreenSharingSignatures',
    'NetworkMonitoringSignatures',
    'AntivirusScanResult',
    # Native DNS Resolver (SECURITY: No external tools)
    'NativeDNSResolver',
    'SecureDNSVerifier',
    'DNSType',
    'DNSResponse',
    'DNSRecord',
    # Daemon integrity (SECURITY: Binary tampering prevention)
    'DaemonIntegrityProtector',
    'IntegrityConfig',
    'IntegrityStatus',
    'IntegrityAction',
    'IntegrityManifest',
    'IntegrityCheckResult',
    'verify_daemon_integrity',
    'DAEMON_INTEGRITY_AVAILABLE',
    # Secure memory (SECURITY: Secret zeroing)
    'SecureBytes',
    'secure_zero_memory',
    'secure_key_context',
    'secure_compare',
    'generate_secure_random',
    'SECURE_MEMORY_AVAILABLE',
]
