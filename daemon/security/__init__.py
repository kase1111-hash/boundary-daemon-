"""
Security Module for Boundary Daemon

Provides:
- Advisory-only code vulnerability scanning using local LLMs
- Antivirus scanning focused on keylogger and malware detection
- Native DNS resolution without external tool dependencies

SECURITY: The native DNS resolver addresses the vulnerability:
"DNS Response Verification Uses External Tools" by providing
pure Python DNS packet construction and parsing.
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
]
