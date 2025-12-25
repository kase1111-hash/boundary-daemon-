"""
Security Module for Boundary Daemon

Provides:
- Advisory-only code vulnerability scanning using local LLMs
- Antivirus scanning focused on keylogger and malware detection
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
    ThreatIndicator,
    ThreatLevel,
    ThreatCategory,
    KeyloggerSignatures,
    ScanResult as AntivirusScanResult,
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
    'ThreatIndicator',
    'ThreatLevel',
    'ThreatCategory',
    'KeyloggerSignatures',
    'AntivirusScanResult',
]
