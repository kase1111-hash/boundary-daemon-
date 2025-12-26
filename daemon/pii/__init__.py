"""
PII Detection & Redaction Module for Boundary Daemon.

Provides detection and redaction of Personally Identifiable Information (PII)
to prevent sensitive data leakage through memory recalls, logs, and API responses.

SECURITY: BypassResistantPIIDetector addresses the vulnerability:
"Regex-Based PII Detection Bypasses" by providing multi-layer normalization
and detection of common bypass techniques (encoding, homoglyphs, zero-width chars).
"""

from daemon.pii.detector import (
    PIIDetector,
    PIIEntity,
    PIIEntityType,
    PIISeverity,
    RedactionMethod,
)
from daemon.pii.filter import PIIFilter, PIIFilterConfig

# Import bypass-resistant detector (SECURITY: defeats regex bypasses)
try:
    from daemon.pii.bypass_resistant_detector import (
        BypassResistantPIIDetector,
        BypassDetector,
        TextNormalizer,
        BypassTechnique,
        BypassAttempt,
        EntropyAnalyzer,
    )
    BYPASS_RESISTANT_AVAILABLE = True
except ImportError:
    BYPASS_RESISTANT_AVAILABLE = False
    BypassResistantPIIDetector = None
    BypassDetector = None
    TextNormalizer = None
    BypassTechnique = None
    BypassAttempt = None
    EntropyAnalyzer = None

__all__ = [
    # Standard PII detection
    'PIIDetector',
    'PIIEntity',
    'PIIEntityType',
    'PIISeverity',
    'RedactionMethod',
    'PIIFilter',
    'PIIFilterConfig',
    # Bypass-resistant detection (SECURITY)
    'BypassResistantPIIDetector',
    'BypassDetector',
    'TextNormalizer',
    'BypassTechnique',
    'BypassAttempt',
    'EntropyAnalyzer',
    'BYPASS_RESISTANT_AVAILABLE',
]
