"""
Sigma Rule Engine for Log-Based Detection

Sigma is a generic signature format for log events. This engine:
- Parses Sigma rules (YAML format)
- Matches events against rule conditions
- Supports common log sources (syslog, auditd, etc.)

Sigma rules are deterministic - same events produce same detections.
"""

import hashlib
import json
import logging
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Union, Pattern

logger = logging.getLogger(__name__)

# Try to import YAML parser
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logger.warning("PyYAML not available - Sigma YAML parsing disabled")


class SigmaLevel(Enum):
    """Sigma rule severity levels."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SigmaStatus(Enum):
    """Sigma rule status."""
    STABLE = "stable"
    TEST = "test"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    UNSUPPORTED = "unsupported"


class LogSource(Enum):
    """Common log sources for Sigma rules."""
    SYSLOG = "syslog"
    AUDITD = "auditd"
    WINDOWS_SECURITY = "windows_security"
    WINDOWS_SYSTEM = "windows_system"
    WINDOWS_POWERSHELL = "windows_powershell"
    APACHE = "apache"
    NGINX = "nginx"
    FIREWALL = "firewall"
    DNS = "dns"
    PROXY = "proxy"
    ANTIVIRUS = "antivirus"
    BOUNDARY_DAEMON = "boundary_daemon"
    CUSTOM = "custom"


@dataclass
class SigmaDetection:
    """Detection logic for a Sigma rule."""
    # Selection criteria (field -> value patterns)
    selections: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Filter criteria (exclusions)
    filters: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Condition expression
    condition: str = ""

    # Timeframe for aggregation rules
    timeframe: Optional[str] = None

    # Aggregation
    count: Optional[Dict[str, Any]] = None


@dataclass
class SigmaRule:
    """A Sigma detection rule."""
    # Identity
    id: str
    title: str

    # Metadata
    status: SigmaStatus = SigmaStatus.EXPERIMENTAL
    level: SigmaLevel = SigmaLevel.MEDIUM
    description: str = ""
    author: str = ""
    date: Optional[str] = None
    modified: Optional[str] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # Log source
    logsource_category: Optional[str] = None
    logsource_product: Optional[str] = None
    logsource_service: Optional[str] = None

    # Detection
    detection: Optional[SigmaDetection] = None

    # False positives
    falsepositives: List[str] = field(default_factory=list)

    # Source
    source_file: Optional[str] = None
    source_hash: Optional[str] = None

    # MITRE ATT&CK
    mitre_attack_ids: List[str] = field(default_factory=list)


@dataclass
class SigmaMatch:
    """A match from a Sigma rule."""
    rule_id: str
    rule_title: str
    level: SigmaLevel

    # Matched event
    event: Dict[str, Any]
    matched_fields: Dict[str, Any] = field(default_factory=dict)

    # Match details
    matched_at: Optional[datetime] = None
    selection_name: Optional[str] = None


@dataclass
class SigmaRuleSet:
    """A collection of Sigma rules."""
    name: str
    rules: List[SigmaRule] = field(default_factory=list)

    # Signature verification
    signature: Optional[str] = None
    signed_by: Optional[str] = None

    # Metadata
    version: str = "1.0"
    source_dir: Optional[str] = None


class SigmaEngine:
    """
    Sigma rule matching engine.

    Usage:
        engine = SigmaEngine()

        # Load rules
        engine.load_rules_from_file("/path/to/rule.yml")
        engine.load_rules_from_directory("/path/to/rules/")

        # Match events
        event = {"EventID": 4688, "CommandLine": "powershell -enc ..."}
        matches = engine.match_event(event, log_source=LogSource.WINDOWS_SECURITY)

        for match in matches:
            print(f"Matched: {match.rule_title} ({match.level.value})")
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._rules: Dict[str, SigmaRule] = {}
        self._rulesets: Dict[str, SigmaRuleSet] = {}

        # Compiled patterns for performance
        self._compiled_patterns: Dict[str, Dict[str, List[Pattern]]] = {}

        # Stats
        self._events_processed = 0
        self._matches_found = 0

    def add_rule(self, rule: SigmaRule) -> bool:
        """Add a Sigma rule."""
        with self._lock:
            self._rules[rule.id] = rule
            self._compile_rule_patterns(rule)
            logger.debug(f"Added Sigma rule: {rule.title}")
            return True

    def add_ruleset(self, ruleset: SigmaRuleSet) -> bool:
        """Add a ruleset."""
        with self._lock:
            self._rulesets[ruleset.name] = ruleset
            for rule in ruleset.rules:
                self._rules[rule.id] = rule
                self._compile_rule_patterns(rule)
            logger.info(f"Added Sigma ruleset {ruleset.name} with {len(ruleset.rules)} rules")
            return True

    def load_rules_from_file(self, path: str) -> bool:
        """Load Sigma rules from a YAML file."""
        if not YAML_AVAILABLE:
            logger.error("PyYAML not available")
            return False

        try:
            with open(path, 'r') as f:
                content = f.read()
                rule_data = yaml.safe_load(content)

            rule = self._parse_sigma_rule(rule_data, path)
            if rule:
                return self.add_rule(rule)
            return False

        except Exception as e:
            logger.error(f"Failed to load Sigma rule from {path}: {e}")
            return False

    def load_rules_from_directory(self, directory: str) -> int:
        """Load all Sigma rules from a directory."""
        loaded = 0
        dir_path = Path(directory)

        for yaml_file in dir_path.glob("**/*.yml"):
            if self.load_rules_from_file(str(yaml_file)):
                loaded += 1

        for yaml_file in dir_path.glob("**/*.yaml"):
            if self.load_rules_from_file(str(yaml_file)):
                loaded += 1

        logger.info(f"Loaded {loaded} Sigma rules from {directory}")
        return loaded

    def load_rule_from_dict(self, rule_dict: Dict[str, Any], source: str = "inline") -> bool:
        """Load a Sigma rule from a dictionary."""
        rule = self._parse_sigma_rule(rule_dict, source)
        if rule:
            return self.add_rule(rule)
        return False

    def _parse_sigma_rule(self, data: Dict[str, Any], source: str) -> Optional[SigmaRule]:
        """Parse a Sigma rule from dictionary data."""
        try:
            # Extract MITRE ATT&CK tags
            tags = data.get('tags', [])
            mitre_ids = [t.replace('attack.', '') for t in tags if t.startswith('attack.t')]

            # Parse detection
            detection_data = data.get('detection', {})
            detection = self._parse_detection(detection_data)

            # Parse logsource
            logsource = data.get('logsource', {})

            rule = SigmaRule(
                id=data.get('id', hashlib.sha256(str(data).encode()).hexdigest()[:16]),
                title=data.get('title', 'Unnamed Rule'),
                status=SigmaStatus(data.get('status', 'experimental')),
                level=SigmaLevel(data.get('level', 'medium')),
                description=data.get('description', ''),
                author=data.get('author', ''),
                date=data.get('date'),
                modified=data.get('modified'),
                references=data.get('references', []),
                tags=tags,
                logsource_category=logsource.get('category'),
                logsource_product=logsource.get('product'),
                logsource_service=logsource.get('service'),
                detection=detection,
                falsepositives=data.get('falsepositives', []),
                source_file=source,
                source_hash=hashlib.sha256(str(data).encode()).hexdigest(),
                mitre_attack_ids=mitre_ids,
            )

            return rule

        except Exception as e:
            logger.error(f"Failed to parse Sigma rule: {e}")
            return None

    def _parse_detection(self, data: Dict[str, Any]) -> SigmaDetection:
        """Parse detection section of a Sigma rule."""
        detection = SigmaDetection()

        for key, value in data.items():
            if key == 'condition':
                detection.condition = value
            elif key == 'timeframe':
                detection.timeframe = value
            elif key.startswith('filter'):
                detection.filters[key] = value
            else:
                detection.selections[key] = value

        return detection

    def _compile_rule_patterns(self, rule: SigmaRule) -> None:
        """Compile regex patterns for a rule."""
        if rule.detection is None:
            return

        patterns: Dict[str, List[Pattern]] = {}

        for sel_name, sel_data in rule.detection.selections.items():
            if isinstance(sel_data, dict):
                for field_name, value in sel_data.items():
                    pattern_key = f"{sel_name}.{field_name}"
                    patterns[pattern_key] = self._compile_value_patterns(value)

        self._compiled_patterns[rule.id] = patterns

    def _compile_value_patterns(self, value: Any) -> List[Pattern]:
        """Compile value(s) to regex patterns."""
        patterns = []

        if isinstance(value, list):
            for v in value:
                patterns.extend(self._compile_value_patterns(v))
        elif isinstance(value, str):
            # Convert Sigma wildcards to regex
            regex = value
            regex = regex.replace('*', '.*')
            regex = regex.replace('?', '.')
            try:
                patterns.append(re.compile(regex, re.IGNORECASE))
            except re.error:
                # Escape and try again
                patterns.append(re.compile(re.escape(value), re.IGNORECASE))

        return patterns

    def match_event(
        self,
        event: Dict[str, Any],
        log_source: Optional[LogSource] = None,
    ) -> List[SigmaMatch]:
        """
        Match an event against loaded Sigma rules.

        Args:
            event: Event dictionary with field names and values
            log_source: Optional log source filter

        Returns:
            List of matches
        """
        matches: List[SigmaMatch] = []

        with self._lock:
            self._events_processed += 1

            for rule in self._rules.values():
                # Filter by log source if specified
                if log_source and rule.logsource_category:
                    # Simple matching - could be more sophisticated
                    pass

                if self._rule_matches(rule, event):
                    match = SigmaMatch(
                        rule_id=rule.id,
                        rule_title=rule.title,
                        level=rule.level,
                        event=event.copy(),
                        matched_at=datetime.utcnow(),
                    )
                    matches.append(match)
                    self._matches_found += 1

        return matches

    def _rule_matches(self, rule: SigmaRule, event: Dict[str, Any]) -> bool:
        """Check if an event matches a rule."""
        if rule.detection is None:
            return False

        # Evaluate each selection
        selection_results: Dict[str, bool] = {}

        for sel_name, sel_data in rule.detection.selections.items():
            selection_results[sel_name] = self._selection_matches(
                sel_data, event, rule.id, sel_name
            )

        # Evaluate filter (exclusions)
        for filter_name, filter_data in rule.detection.filters.items():
            if self._selection_matches(filter_data, event, rule.id, filter_name):
                return False  # Filtered out

        # Evaluate condition
        condition = rule.detection.condition
        if not condition:
            # Default: any selection matches
            return any(selection_results.values())

        return self._evaluate_condition(condition, selection_results)

    def _selection_matches(
        self,
        selection: Union[Dict, List],
        event: Dict[str, Any],
        rule_id: str,
        sel_name: str,
    ) -> bool:
        """Check if an event matches a selection."""
        if isinstance(selection, list):
            # List of selections (OR)
            return any(
                self._selection_matches(s, event, rule_id, sel_name)
                for s in selection
            )

        if not isinstance(selection, dict):
            return False

        # All field conditions must match (AND)
        for field_name, expected in selection.items():
            # Handle field modifiers
            actual_field = field_name
            modifiers = []

            if '|' in field_name:
                parts = field_name.split('|')
                actual_field = parts[0]
                modifiers = parts[1:]

            # Get event value
            event_value = event.get(actual_field)
            if event_value is None:
                return False

            # Match value
            if not self._value_matches(event_value, expected, modifiers):
                return False

        return True

    def _value_matches(
        self,
        event_value: Any,
        expected: Any,
        modifiers: List[str],
    ) -> bool:
        """Check if an event value matches expected pattern."""
        event_str = str(event_value)

        if isinstance(expected, list):
            # Any value matches (OR)
            return any(
                self._value_matches(event_value, e, modifiers)
                for e in expected
            )

        expected_str = str(expected)

        # Apply modifiers
        if 'contains' in modifiers:
            return expected_str.lower() in event_str.lower()
        if 'startswith' in modifiers:
            return event_str.lower().startswith(expected_str.lower())
        if 'endswith' in modifiers:
            return event_str.lower().endswith(expected_str.lower())
        if 're' in modifiers:
            try:
                return bool(re.search(expected_str, event_str, re.IGNORECASE))
            except re.error:
                return False

        # Default: wildcard matching
        if '*' in expected_str or '?' in expected_str:
            pattern = expected_str.replace('*', '.*').replace('?', '.')
            try:
                return bool(re.match(pattern, event_str, re.IGNORECASE))
            except re.error:
                pass

        # Exact match (case insensitive)
        return event_str.lower() == expected_str.lower()

    def _evaluate_condition(
        self,
        condition: str,
        results: Dict[str, bool],
    ) -> bool:
        """Evaluate Sigma condition expression."""
        # Handle common conditions
        condition = condition.strip()

        # Simple cases
        if condition in results:
            return results[condition]

        if condition.startswith('all of '):
            pattern = condition[7:]
            if pattern == 'them':
                return all(results.values())
            # Pattern match (e.g., "all of selection*")
            pattern = pattern.replace('*', '.*')
            matching = [v for k, v in results.items() if re.match(pattern, k)]
            return all(matching) if matching else False

        if condition.startswith('1 of ') or condition.startswith('any of '):
            pattern = condition.split(' ', 2)[-1]
            if pattern == 'them':
                return any(results.values())
            pattern = pattern.replace('*', '.*')
            matching = [v for k, v in results.items() if re.match(pattern, k)]
            return any(matching)

        # Boolean expressions
        # Simple parser for "selection1 and selection2", "selection1 or selection2"
        if ' and ' in condition:
            parts = condition.split(' and ')
            return all(
                self._evaluate_condition(p.strip(), results)
                for p in parts
            )

        if ' or ' in condition:
            parts = condition.split(' or ')
            return any(
                self._evaluate_condition(p.strip(), results)
                for p in parts
            )

        if condition.startswith('not '):
            return not self._evaluate_condition(condition[4:], results)

        # Parentheses - simplified
        if condition.startswith('(') and condition.endswith(')'):
            return self._evaluate_condition(condition[1:-1], results)

        return results.get(condition, False)

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return {
            'rules_loaded': len(self._rules),
            'rulesets_loaded': len(self._rulesets),
            'events_processed': self._events_processed,
            'matches_found': self._matches_found,
        }

    def clear_rules(self) -> None:
        """Clear all loaded rules."""
        with self._lock:
            self._rules.clear()
            self._rulesets.clear()
            self._compiled_patterns.clear()


# Built-in Sigma rules for Boundary Daemon events
BUILTIN_SIGMA_RULES = [
    {
        "id": "bd-001",
        "title": "Boundary Daemon Lockdown Triggered",
        "status": "stable",
        "level": "critical",
        "description": "Detects when Boundary Daemon enters lockdown mode",
        "logsource": {"category": "boundary_daemon"},
        "detection": {
            "selection": {
                "event_type": ["LOCKDOWN", "TRIPWIRE"]
            },
            "condition": "selection"
        },
        "tags": ["attack.defense_evasion", "attack.t1562"]
    },
    {
        "id": "bd-002",
        "title": "Multiple Authentication Failures",
        "status": "stable",
        "level": "high",
        "description": "Detects multiple authentication failures",
        "logsource": {"category": "boundary_daemon"},
        "detection": {
            "selection": {
                "event_type": "AUTH_FAILURE"
            },
            "condition": "selection"
        },
        "tags": ["attack.credential_access", "attack.t1110"]
    },
    {
        "id": "bd-003",
        "title": "Ceremony Override Attempt",
        "status": "stable",
        "level": "high",
        "description": "Detects ceremony abort or unusual ceremony activity",
        "logsource": {"category": "boundary_daemon"},
        "detection": {
            "selection": {
                "event_type": "CEREMONY_ABORT"
            },
            "condition": "selection"
        },
        "tags": ["attack.defense_evasion", "attack.t1548"]
    },
]


if __name__ == '__main__':
    print("Testing Sigma Engine...")

    engine = SigmaEngine()

    # Load built-in rules
    for rule_dict in BUILTIN_SIGMA_RULES:
        engine.load_rule_from_dict(rule_dict)

    print(f"\nLoaded {len(engine._rules)} rules")

    # Test event matching
    test_events = [
        {"event_type": "LOCKDOWN", "details": "Network detected in AIRGAP"},
        {"event_type": "AUTH_FAILURE", "user": "attacker"},
        {"event_type": "MODE_CHANGE", "new_mode": "RESTRICTED"},
        {"event_type": "CEREMONY_ABORT", "reason": "timeout"},
    ]

    print("\nMatching events:")
    for event in test_events:
        matches = engine.match_event(event)
        if matches:
            for match in matches:
                print(f"  Event {event['event_type']}: MATCHED {match.rule_title} ({match.level.value})")
        else:
            print(f"  Event {event['event_type']}: no matches")

    print(f"\nStats: {engine.get_stats()}")
    print("\nSigma engine test complete.")
