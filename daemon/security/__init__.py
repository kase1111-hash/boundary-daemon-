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

# Prompt injection detection (SECURITY: AI/Agent jailbreak prevention)
try:
    from .prompt_injection import (
        PromptInjectionDetector,
        InjectionType,
        InjectionPattern,
        InjectionDetection,
        DetectionSeverity,
        DetectionAction,
        DetectionResult,
        get_prompt_injection_detector,
        configure_prompt_injection_detector,
    )
    PROMPT_INJECTION_AVAILABLE = True
except ImportError:
    PROMPT_INJECTION_AVAILABLE = False
    PromptInjectionDetector = None
    InjectionType = None
    InjectionPattern = None
    InjectionDetection = None
    DetectionSeverity = None
    DetectionAction = None
    DetectionResult = None
    get_prompt_injection_detector = None
    configure_prompt_injection_detector = None

# Tool output validation (SECURITY: AI tool response validation)
try:
    from .tool_validator import (
        ToolOutputValidator,
        ToolPolicy,
        ToolCall,
        ToolValidationResult,
        ValidationResult,
        ViolationType,
        ValidationViolation,
        SanitizationAction,
        get_tool_validator,
        configure_tool_validator,
    )
    TOOL_VALIDATOR_AVAILABLE = True
except ImportError:
    TOOL_VALIDATOR_AVAILABLE = False
    ToolOutputValidator = None
    ToolPolicy = None
    ToolCall = None
    ToolValidationResult = None
    ValidationResult = None
    ViolationType = None
    ValidationViolation = None
    SanitizationAction = None
    get_tool_validator = None
    configure_tool_validator = None

# Response guardrails (SECURITY: AI response safety validation)
try:
    from .response_guardrails import (
        ResponseGuardrails,
        GuardrailPolicy,
        GuardrailResult,
        GuardrailViolation,
        GuardrailSeverity,
        GuardrailAction,
        ContentCategory,
        HallucinationIndicator,
        HallucinationDetection,
        get_response_guardrails,
        configure_response_guardrails,
    )
    RESPONSE_GUARDRAILS_AVAILABLE = True
except ImportError:
    RESPONSE_GUARDRAILS_AVAILABLE = False
    ResponseGuardrails = None
    GuardrailPolicy = None
    GuardrailResult = None
    GuardrailViolation = None
    GuardrailSeverity = None
    GuardrailAction = None
    ContentCategory = None
    HallucinationIndicator = None
    HallucinationDetection = None
    get_response_guardrails = None
    configure_response_guardrails = None

# RAG injection detection (SECURITY: RAG poisoning prevention)
try:
    from .rag_injection import (
        RAGInjectionDetector,
        RAGThreatType,
        RAGAnalysisResult,
        RAGThreat,
        RetrievedDocument,
        DocumentTrustLevel,
        ThreatSeverity,
        get_rag_detector,
        configure_rag_detector,
    )
    # Aliases for consistency
    RAGDetectionResult = RAGAnalysisResult
    get_rag_injection_detector = get_rag_detector
    configure_rag_injection_detector = configure_rag_detector
    RAG_INJECTION_AVAILABLE = True
except ImportError:
    RAG_INJECTION_AVAILABLE = False
    RAGInjectionDetector = None
    RAGThreatType = None
    RAGAnalysisResult = None
    RAGDetectionResult = None
    RAGThreat = None
    RetrievedDocument = None
    DocumentTrustLevel = None
    ThreatSeverity = None
    get_rag_detector = None
    get_rag_injection_detector = None
    configure_rag_detector = None
    configure_rag_injection_detector = None

# Agent attestation (SECURITY: Cryptographic agent identity)
try:
    from .agent_attestation import (
        AgentAttestationSystem,
        AgentIdentity,
        AttestationToken,
        AttestationResult,
        AttestationStatus,
        AgentCapability,
        TrustLevel,
        ActionBinding,
        get_attestation_system,
        configure_attestation_system,
    )
    AGENT_ATTESTATION_AVAILABLE = True
except ImportError:
    AGENT_ATTESTATION_AVAILABLE = False
    AgentAttestationSystem = None
    AgentIdentity = None
    AttestationToken = None
    AttestationResult = None
    AttestationStatus = None
    AgentCapability = None
    TrustLevel = None
    ActionBinding = None
    get_attestation_system = None
    configure_attestation_system = None

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
    # Prompt injection detection (SECURITY: AI/Agent jailbreak prevention)
    'PromptInjectionDetector',
    'InjectionType',
    'InjectionPattern',
    'InjectionDetection',
    'DetectionSeverity',
    'DetectionAction',
    'DetectionResult',
    'get_prompt_injection_detector',
    'configure_prompt_injection_detector',
    'PROMPT_INJECTION_AVAILABLE',
    # Tool output validation (SECURITY: AI tool response validation)
    'ToolOutputValidator',
    'ToolPolicy',
    'ToolCall',
    'ToolValidationResult',
    'ValidationResult',
    'ViolationType',
    'ValidationViolation',
    'SanitizationAction',
    'get_tool_validator',
    'configure_tool_validator',
    'TOOL_VALIDATOR_AVAILABLE',
    # Response guardrails (SECURITY: AI response safety validation)
    'ResponseGuardrails',
    'GuardrailPolicy',
    'GuardrailResult',
    'GuardrailViolation',
    'GuardrailSeverity',
    'GuardrailAction',
    'ContentCategory',
    'HallucinationIndicator',
    'HallucinationDetection',
    'get_response_guardrails',
    'configure_response_guardrails',
    'RESPONSE_GUARDRAILS_AVAILABLE',
    # RAG injection detection (SECURITY: RAG poisoning prevention)
    'RAGInjectionDetector',
    'RAGThreatType',
    'RAGAnalysisResult',
    'RAGDetectionResult',  # Alias
    'RAGThreat',
    'RetrievedDocument',
    'DocumentTrustLevel',
    'ThreatSeverity',
    'get_rag_detector',
    'get_rag_injection_detector',  # Alias
    'configure_rag_detector',
    'configure_rag_injection_detector',  # Alias
    'RAG_INJECTION_AVAILABLE',
    # Agent attestation (SECURITY: Cryptographic agent identity)
    'AgentAttestationSystem',
    'AgentIdentity',
    'AttestationToken',
    'AttestationResult',
    'AttestationStatus',
    'AgentCapability',
    'TrustLevel',
    'ActionBinding',
    'get_attestation_system',
    'configure_attestation_system',
    'AGENT_ATTESTATION_AVAILABLE',
]
