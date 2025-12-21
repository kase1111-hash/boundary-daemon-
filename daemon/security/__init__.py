"""
Security Module for Boundary Daemon
Provides advisory-only code vulnerability scanning using local LLMs.
"""

from .code_advisor import (
    CodeVulnerabilityAdvisor,
    SecurityAdvisory,
    AdvisorySeverity,
    AdvisoryStatus,
    ScanResult
)

__all__ = [
    'CodeVulnerabilityAdvisor',
    'SecurityAdvisory',
    'AdvisorySeverity',
    'AdvisoryStatus',
    'ScanResult',
]
