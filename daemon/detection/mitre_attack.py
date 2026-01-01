"""
MITRE ATT&CK Pattern Detection

Provides deterministic detection of MITRE ATT&CK techniques:
- Tactic and technique mappings
- Pattern-based detection rules
- Event correlation for technique identification

All detection is rule-based and deterministic - no ML.
"""

import hashlib
import json
import logging
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Any, Pattern, Callable

logger = logging.getLogger(__name__)


class MITRETactic(Enum):
    """MITRE ATT&CK Tactics (Enterprise)."""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


# Tactic display names
TACTIC_NAMES = {
    MITRETactic.RECONNAISSANCE: "Reconnaissance",
    MITRETactic.RESOURCE_DEVELOPMENT: "Resource Development",
    MITRETactic.INITIAL_ACCESS: "Initial Access",
    MITRETactic.EXECUTION: "Execution",
    MITRETactic.PERSISTENCE: "Persistence",
    MITRETactic.PRIVILEGE_ESCALATION: "Privilege Escalation",
    MITRETactic.DEFENSE_EVASION: "Defense Evasion",
    MITRETactic.CREDENTIAL_ACCESS: "Credential Access",
    MITRETactic.DISCOVERY: "Discovery",
    MITRETactic.LATERAL_MOVEMENT: "Lateral Movement",
    MITRETactic.COLLECTION: "Collection",
    MITRETactic.COMMAND_AND_CONTROL: "Command and Control",
    MITRETactic.EXFILTRATION: "Exfiltration",
    MITRETactic.IMPACT: "Impact",
}


@dataclass
class MITRETechnique:
    """A MITRE ATT&CK technique."""
    technique_id: str  # e.g., "T1059"
    name: str
    tactics: List[MITRETactic]
    description: str = ""

    # Sub-technique info
    parent_id: Optional[str] = None
    sub_technique_id: Optional[str] = None  # e.g., "001" for T1059.001

    # Detection info
    data_sources: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)

    # Reference
    url: str = ""

    @property
    def full_id(self) -> str:
        """Get full technique ID including sub-technique."""
        if self.sub_technique_id:
            return f"{self.technique_id}.{self.sub_technique_id}"
        return self.technique_id


@dataclass
class MITREPattern:
    """A detection pattern for a MITRE technique."""
    pattern_id: str
    technique_id: str
    name: str
    description: str = ""

    # Detection logic
    event_type: Optional[str] = None
    field_matches: Dict[str, Any] = field(default_factory=dict)
    regex_patterns: Dict[str, str] = field(default_factory=dict)

    # Severity
    severity: str = "medium"

    # Confidence
    confidence: str = "medium"

    # Compiled patterns
    _compiled_patterns: Dict[str, Pattern] = field(default_factory=dict)

    def compile_patterns(self) -> None:
        """Compile regex patterns for matching."""
        for field_name, pattern in self.regex_patterns.items():
            try:
                self._compiled_patterns[field_name] = re.compile(
                    pattern, re.IGNORECASE
                )
            except re.error as e:
                logger.error(f"Failed to compile pattern for {field_name}: {e}")


@dataclass
class TechniqueMapping:
    """Mapping of daemon events to MITRE techniques."""
    event_type: str
    technique_ids: List[str]
    conditions: Dict[str, Any] = field(default_factory=dict)
    description: str = ""


@dataclass
class AttackMatch:
    """A match indicating potential MITRE technique."""
    technique_id: str
    technique_name: str
    tactics: List[str]
    pattern_id: str
    pattern_name: str

    # Match details
    event: Dict[str, Any]
    matched_fields: Dict[str, Any] = field(default_factory=dict)
    matched_at: datetime = field(default_factory=datetime.utcnow)

    # Severity and confidence
    severity: str = "medium"
    confidence: str = "medium"


class MITREDetector:
    """
    MITRE ATT&CK technique detector.

    Uses deterministic rules to identify potential ATT&CK techniques
    in events and system activity.

    Usage:
        detector = MITREDetector()

        # Add patterns
        detector.add_pattern(my_pattern)

        # Check events
        event = {"event_type": "PROCESS_START", "command_line": "powershell -enc ..."}
        matches = detector.detect(event)

        for match in matches:
            print(f"Detected: {match.technique_id} - {match.technique_name}")
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Technique database
        self._techniques: Dict[str, MITRETechnique] = {}

        # Detection patterns
        self._patterns: Dict[str, MITREPattern] = {}

        # Event type to patterns mapping
        self._event_patterns: Dict[str, List[str]] = {}

        # Technique mappings for daemon events
        self._mappings: List[TechniqueMapping] = []

        # Stats
        self._events_analyzed = 0
        self._techniques_detected = 0

        # Load built-in techniques and patterns
        self._load_builtin_techniques()
        self._load_builtin_patterns()

    def _load_builtin_techniques(self) -> None:
        """Load common MITRE techniques."""
        techniques = [
            MITRETechnique(
                technique_id="T1059",
                name="Command and Scripting Interpreter",
                tactics=[MITRETactic.EXECUTION],
                description="Adversaries may abuse command and script interpreters",
                data_sources=["Command", "Process", "Script"],
            ),
            MITRETechnique(
                technique_id="T1059",
                sub_technique_id="001",
                name="PowerShell",
                tactics=[MITRETactic.EXECUTION],
                description="Adversaries may abuse PowerShell",
                data_sources=["Command", "Process", "Script"],
                parent_id="T1059",
            ),
            MITRETechnique(
                technique_id="T1059",
                sub_technique_id="004",
                name="Unix Shell",
                tactics=[MITRETactic.EXECUTION],
                description="Adversaries may abuse Unix shell",
                data_sources=["Command", "Process"],
                parent_id="T1059",
            ),
            MITRETechnique(
                technique_id="T1562",
                name="Impair Defenses",
                tactics=[MITRETactic.DEFENSE_EVASION],
                description="Adversaries may maliciously modify security tools",
                data_sources=["Process", "Service", "Windows Registry"],
            ),
            MITRETechnique(
                technique_id="T1562",
                sub_technique_id="001",
                name="Disable or Modify Tools",
                tactics=[MITRETactic.DEFENSE_EVASION],
                description="Adversaries may disable security tools",
                parent_id="T1562",
            ),
            MITRETechnique(
                technique_id="T1110",
                name="Brute Force",
                tactics=[MITRETactic.CREDENTIAL_ACCESS],
                description="Adversaries may use brute force techniques",
                data_sources=["Application Log", "User Account"],
            ),
            MITRETechnique(
                technique_id="T1548",
                name="Abuse Elevation Control Mechanism",
                tactics=[MITRETactic.PRIVILEGE_ESCALATION, MITRETactic.DEFENSE_EVASION],
                description="Adversaries may circumvent elevation controls",
                data_sources=["Command", "Process"],
            ),
            MITRETechnique(
                technique_id="T1071",
                name="Application Layer Protocol",
                tactics=[MITRETactic.COMMAND_AND_CONTROL],
                description="Adversaries may communicate using application layer protocols",
                data_sources=["Network Traffic"],
            ),
            MITRETechnique(
                technique_id="T1486",
                name="Data Encrypted for Impact",
                tactics=[MITRETactic.IMPACT],
                description="Adversaries may encrypt data on target systems",
                data_sources=["File", "Process"],
            ),
            MITRETechnique(
                technique_id="T1003",
                name="OS Credential Dumping",
                tactics=[MITRETactic.CREDENTIAL_ACCESS],
                description="Adversaries may attempt to dump credentials",
                data_sources=["Command", "Process"],
            ),
            MITRETechnique(
                technique_id="T1027",
                name="Obfuscated Files or Information",
                tactics=[MITRETactic.DEFENSE_EVASION],
                description="Adversaries may obfuscate content",
                data_sources=["File", "Process", "Script"],
            ),
            MITRETechnique(
                technique_id="T1105",
                name="Ingress Tool Transfer",
                tactics=[MITRETactic.COMMAND_AND_CONTROL],
                description="Adversaries may transfer tools from external systems",
                data_sources=["File", "Network Traffic"],
            ),
        ]

        for tech in techniques:
            self._techniques[tech.full_id] = tech

    def _load_builtin_patterns(self) -> None:
        """Load built-in detection patterns for Boundary Daemon."""
        patterns = [
            # Defense Evasion - Boundary violations
            MITREPattern(
                pattern_id="bd-t1562-001",
                technique_id="T1562.001",
                name="Boundary Daemon Lockdown Triggered",
                description="Security lockdown indicates potential defense evasion",
                event_type="LOCKDOWN",
                severity="critical",
                confidence="high",
            ),
            MITREPattern(
                pattern_id="bd-t1562-002",
                technique_id="T1562.001",
                name="Tripwire Violation",
                description="Tripwire indicates security boundary violation",
                event_type="TRIPWIRE",
                severity="critical",
                confidence="high",
            ),
            # Credential Access - Auth failures
            MITREPattern(
                pattern_id="bd-t1110-001",
                technique_id="T1110",
                name="Authentication Failure",
                description="Multiple auth failures may indicate brute force",
                event_type="AUTH_FAILURE",
                severity="high",
                confidence="medium",
            ),
            # Privilege Escalation - Ceremony abuse
            MITREPattern(
                pattern_id="bd-t1548-001",
                technique_id="T1548",
                name="Ceremony Abort",
                description="Ceremony abort may indicate privilege abuse attempt",
                event_type="CEREMONY_ABORT",
                severity="high",
                confidence="medium",
            ),
            # Defense Evasion - Mode changes
            MITREPattern(
                pattern_id="bd-t1562-003",
                technique_id="T1562",
                name="Security Mode Downgrade",
                description="Mode change to less restrictive may indicate evasion",
                event_type="MODE_CHANGE",
                field_matches={
                    "new_mode": ["OPEN", "RESTRICTED"],
                    "old_mode": ["AIRGAP", "COLDROOM", "TRUSTED"],
                },
                severity="high",
                confidence="medium",
            ),
            # Execution - Tool execution
            MITREPattern(
                pattern_id="bd-t1059-001",
                technique_id="T1059",
                name="Suspicious Tool Execution",
                description="Potentially malicious tool execution",
                event_type="TOOL_EXECUTION",
                regex_patterns={
                    "tool_name": r"(powershell|cmd|bash|sh|python|perl|ruby|wget|curl|nc|netcat)",
                },
                severity="medium",
                confidence="low",
            ),
            # Exfiltration - Recall attempts
            MITREPattern(
                pattern_id="bd-t1041-001",
                technique_id="T1041",
                name="High-Class Memory Recall",
                description="Recall of high-class memory may indicate exfiltration",
                event_type="RECALL_ATTEMPT",
                field_matches={
                    "memory_class": [4, 5],
                },
                severity="high",
                confidence="medium",
            ),
        ]

        for pattern in patterns:
            pattern.compile_patterns()
            self.add_pattern(pattern)

    def add_technique(self, technique: MITRETechnique) -> None:
        """Add a technique to the database."""
        self._techniques[technique.full_id] = technique

    def add_pattern(self, pattern: MITREPattern) -> None:
        """Add a detection pattern."""
        with self._lock:
            self._patterns[pattern.pattern_id] = pattern

            # Index by event type
            if pattern.event_type:
                event_patterns = self._event_patterns.setdefault(
                    pattern.event_type, []
                )
                if pattern.pattern_id not in event_patterns:
                    event_patterns.append(pattern.pattern_id)

    def add_mapping(self, mapping: TechniqueMapping) -> None:
        """Add an event-to-technique mapping."""
        self._mappings.append(mapping)

    def detect(self, event: Dict[str, Any]) -> List[AttackMatch]:
        """
        Detect MITRE techniques in an event.

        Args:
            event: Event dictionary with event_type and other fields

        Returns:
            List of technique matches
        """
        matches: List[AttackMatch] = []
        event_type = event.get('event_type', '')

        with self._lock:
            self._events_analyzed += 1

            # Get patterns for this event type
            pattern_ids = self._event_patterns.get(event_type, [])

            # Also check patterns without specific event type
            pattern_ids.extend(
                pid for pid, p in self._patterns.items()
                if p.event_type is None and pid not in pattern_ids
            )

            for pattern_id in pattern_ids:
                pattern = self._patterns.get(pattern_id)
                if not pattern:
                    continue

                match = self._check_pattern(pattern, event)
                if match:
                    matches.append(match)
                    self._techniques_detected += 1

        return matches

    def _check_pattern(
        self,
        pattern: MITREPattern,
        event: Dict[str, Any],
    ) -> Optional[AttackMatch]:
        """Check if an event matches a pattern."""
        # Check event type if specified
        if pattern.event_type:
            if event.get('event_type') != pattern.event_type:
                return None

        matched_fields = {}

        # Check field matches
        for field_name, expected_values in pattern.field_matches.items():
            event_value = self._get_nested_value(event, field_name)
            if event_value is None:
                return None

            if isinstance(expected_values, list):
                if event_value not in expected_values:
                    return None
            else:
                if event_value != expected_values:
                    return None

            matched_fields[field_name] = event_value

        # Check regex patterns
        for field_name, regex_pattern in pattern.regex_patterns.items():
            event_value = self._get_nested_value(event, field_name)
            if event_value is None:
                continue  # Optional regex match

            compiled = pattern._compiled_patterns.get(field_name)
            if compiled:
                if not compiled.search(str(event_value)):
                    return None
                matched_fields[field_name] = event_value

        # Get technique info
        technique = self._techniques.get(pattern.technique_id)
        if not technique:
            technique_name = pattern.technique_id
            tactics = []
        else:
            technique_name = technique.name
            tactics = [TACTIC_NAMES.get(t, t.value) for t in technique.tactics]

        return AttackMatch(
            technique_id=pattern.technique_id,
            technique_name=technique_name,
            tactics=tactics,
            pattern_id=pattern.pattern_id,
            pattern_name=pattern.name,
            event=event.copy(),
            matched_fields=matched_fields,
            severity=pattern.severity,
            confidence=pattern.confidence,
        )

    def _get_nested_value(self, data: Dict, key: str) -> Any:
        """Get a value from nested dict using dot notation."""
        parts = key.split('.')
        value = data

        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None

        return value

    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Get technique by ID."""
        return self._techniques.get(technique_id)

    def get_techniques_by_tactic(
        self,
        tactic: MITRETactic,
    ) -> List[MITRETechnique]:
        """Get all techniques for a tactic."""
        return [
            t for t in self._techniques.values()
            if tactic in t.tactics
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return {
            'techniques_loaded': len(self._techniques),
            'patterns_loaded': len(self._patterns),
            'events_analyzed': self._events_analyzed,
            'techniques_detected': self._techniques_detected,
        }

    def export_technique_coverage(self) -> Dict[str, Any]:
        """Export technique coverage report."""
        covered = set()
        for pattern in self._patterns.values():
            covered.add(pattern.technique_id)

        return {
            'total_techniques': len(self._techniques),
            'covered_techniques': len(covered),
            'coverage_percentage': (len(covered) / len(self._techniques) * 100)
            if self._techniques else 0,
            'covered_ids': list(covered),
            'by_tactic': {
                TACTIC_NAMES[t]: len(self.get_techniques_by_tactic(t))
                for t in MITRETactic
            },
        }


if __name__ == '__main__':
    print("Testing MITRE ATT&CK Detector...")

    detector = MITREDetector()

    print(f"\nLoaded:")
    print(f"  Techniques: {len(detector._techniques)}")
    print(f"  Patterns: {len(detector._patterns)}")

    # Test detection
    test_events = [
        {"event_type": "LOCKDOWN", "details": "Network in AIRGAP"},
        {"event_type": "AUTH_FAILURE", "user": "attacker", "attempts": 5},
        {"event_type": "CEREMONY_ABORT", "reason": "timeout"},
        {"event_type": "MODE_CHANGE", "old_mode": "AIRGAP", "new_mode": "OPEN"},
        {"event_type": "TOOL_EXECUTION", "tool_name": "curl", "args": ["http://evil.com"]},
        {"event_type": "RECALL_ATTEMPT", "memory_class": 5, "result": "denied"},
        {"event_type": "DAEMON_START", "version": "1.0"},  # Should not match
    ]

    print("\nDetection Results:")
    for event in test_events:
        matches = detector.detect(event)
        if matches:
            for match in matches:
                print(f"  {event['event_type']}:")
                print(f"    Technique: {match.technique_id} - {match.technique_name}")
                print(f"    Tactics: {', '.join(match.tactics)}")
                print(f"    Severity: {match.severity}, Confidence: {match.confidence}")
        else:
            print(f"  {event['event_type']}: No matches")

    print(f"\nStats: {detector.get_stats()}")

    print("\nTechnique Coverage:")
    coverage = detector.export_technique_coverage()
    print(f"  Coverage: {coverage['coverage_percentage']:.1f}%")

    print("\nMITRE ATT&CK detector test complete.")
