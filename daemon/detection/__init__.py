"""
Deterministic Threat Detection Module for Boundary Daemon

Provides threat detection WITHOUT machine learning:
- YARA rule engine for pattern matching
- Sigma rule support for log-based detection
- Signed IOC (Indicators of Compromise) feeds
- MITRE ATT&CK patterns as deterministic rules

All detection is deterministic and auditable - same input
always produces same output, with full rule traceability.
"""

from .yara_engine import (
    YARAEngine,
    YARARule,
    YARARuleSet,
    YARAMatch,
    YARAScanResult,
)

from .sigma_engine import (
    SigmaEngine,
    SigmaRule,
    SigmaRuleSet,
    SigmaMatch,
    SigmaDetection,
    LogSource,
)

from .ioc_feeds import (
    IOCFeed,
    IOCEntry,
    IOCType,
    IOCFeedManager,
    SignedIOCFeed,
    IOCMatch,
)

from .mitre_attack import (
    MITREPattern,
    MITRETactic,
    MITRETechnique,
    MITREDetector,
    AttackMatch,
    TechniqueMapping,
)

from .event_publisher import (
    EventPublisher,
    SecurityEvent,
    SecurityAlert,
    DetectionResult,
    EventType as DetectionEventType,
    AlertSeverity,
    get_event_publisher,
    configure_event_publisher,
)

__all__ = [
    # YARA
    'YARAEngine',
    'YARARule',
    'YARARuleSet',
    'YARAMatch',
    'YARAScanResult',

    # Sigma
    'SigmaEngine',
    'SigmaRule',
    'SigmaRuleSet',
    'SigmaMatch',
    'SigmaDetection',
    'LogSource',

    # IOC Feeds
    'IOCFeed',
    'IOCEntry',
    'IOCType',
    'IOCFeedManager',
    'SignedIOCFeed',
    'IOCMatch',

    # MITRE ATT&CK
    'MITREPattern',
    'MITRETactic',
    'MITRETechnique',
    'MITREDetector',
    'AttackMatch',
    'TechniqueMapping',

    # Event Publisher
    'EventPublisher',
    'SecurityEvent',
    'SecurityAlert',
    'DetectionResult',
    'DetectionEventType',
    'AlertSeverity',
    'get_event_publisher',
    'configure_event_publisher',
]
