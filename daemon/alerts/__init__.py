"""
Alerts module for Boundary Daemon.

Phase 2: Case Management and Alert Lifecycle.
"""

from .case_manager import (
    CaseManager,
    Case,
    CaseStatus,
    CaseSeverity,
    Alert,
    IntegrationConfig,
    SLAConfig,
)

__all__ = [
    'CaseManager',
    'Case',
    'CaseStatus',
    'CaseSeverity',
    'Alert',
    'IntegrationConfig',
    'SLAConfig',
]
