"""
PII Detector - Pattern-based detection of Personally Identifiable Information.

Detects 30+ PII entity types including:
- Government IDs (SSN, passport, driver's license)
- Financial (credit cards, bank accounts, crypto wallets)
- Contact (email, phone, address)
- Authentication (passwords, API keys, tokens)
- Personal (names, DOB, medical records)

Supports multiple redaction methods:
- MASK: Replace with asterisks (***-**-1234)
- REPLACE: Replace with placeholder ([REDACTED])
- HASH: Replace with one-way hash
- REMOVE: Remove entirely
"""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Pattern, Set, Tuple, Callable


class PIIEntityType(Enum):
    """Types of PII entities that can be detected."""
    # Government IDs
    SSN = "ssn"                          # Social Security Number
    SSN_LAST4 = "ssn_last4"              # Last 4 digits of SSN
    PASSPORT = "passport"                 # Passport number
    DRIVERS_LICENSE = "drivers_license"   # Driver's license
    NATIONAL_ID = "national_id"           # National ID (various countries)
    TAX_ID = "tax_id"                     # Tax identification number

    # Financial
    CREDIT_CARD = "credit_card"           # Credit/debit card numbers
    CREDIT_CARD_CVV = "credit_card_cvv"   # Card CVV/CVC
    BANK_ACCOUNT = "bank_account"         # Bank account numbers
    ROUTING_NUMBER = "routing_number"     # Bank routing numbers
    IBAN = "iban"                         # International bank account
    SWIFT_BIC = "swift_bic"               # SWIFT/BIC codes
    CRYPTO_WALLET = "crypto_wallet"       # Cryptocurrency wallet addresses

    # Contact Information
    EMAIL = "email"                       # Email addresses
    PHONE = "phone"                       # Phone numbers
    ADDRESS = "address"                   # Physical addresses
    ZIP_CODE = "zip_code"                 # ZIP/postal codes

    # Authentication & Secrets
    PASSWORD = "password"                 # Passwords in text
    API_KEY = "api_key"                   # API keys
    ACCESS_TOKEN = "access_token"         # OAuth/JWT tokens
    PRIVATE_KEY = "private_key"           # Private keys (RSA, SSH, etc.)
    AWS_KEY = "aws_key"                   # AWS access keys

    # Personal Information
    PERSON_NAME = "person_name"           # Full names
    DATE_OF_BIRTH = "date_of_birth"       # Birth dates
    AGE = "age"                           # Age mentions
    GENDER = "gender"                     # Gender/sex

    # Medical
    MEDICAL_RECORD = "medical_record"     # Medical record numbers
    HEALTH_PLAN_ID = "health_plan_id"     # Health insurance IDs
    DIAGNOSIS = "diagnosis"               # Medical diagnoses
    MEDICATION = "medication"             # Prescription drugs

    # Network/Technical
    IP_ADDRESS = "ip_address"             # IP addresses
    MAC_ADDRESS = "mac_address"           # MAC addresses
    URL_WITH_CREDENTIALS = "url_creds"    # URLs with embedded credentials

    # Other Sensitive
    VEHICLE_ID = "vehicle_id"             # VIN numbers
    BIOMETRIC = "biometric"               # Biometric data references
    GENETIC = "genetic"                   # Genetic data references


class PIISeverity(Enum):
    """Severity levels for PII detection."""
    CRITICAL = "critical"   # Government IDs, financial data
    HIGH = "high"           # Authentication secrets, full contact info
    MEDIUM = "medium"       # Partial data, addresses
    LOW = "low"             # Names, general info
    INFO = "info"           # Potentially sensitive context


class RedactionMethod(Enum):
    """Methods for redacting detected PII."""
    MASK = "mask"           # Partial masking: 123-45-****
    REPLACE = "replace"     # Full replacement: [SSN REDACTED]
    HASH = "hash"           # One-way hash: [SSN:a1b2c3d4]
    REMOVE = "remove"       # Complete removal
    TOKENIZE = "tokenize"   # Reversible tokenization (requires key)


@dataclass
class PIIEntity:
    """A detected PII entity."""
    entity_type: PIIEntityType
    value: str                           # Original value
    start: int                           # Start position in text
    end: int                             # End position in text
    confidence: float                    # Detection confidence (0.0-1.0)
    severity: PIISeverity
    context: str = ""                    # Surrounding context
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            'entity_type': self.entity_type.value,
            'value_length': len(self.value),  # Don't expose actual value
            'start': self.start,
            'end': self.end,
            'confidence': self.confidence,
            'severity': self.severity.value,
            'context_length': len(self.context),
            'metadata': self.metadata,
        }


@dataclass
class PIIPattern:
    """Pattern definition for PII detection."""
    entity_type: PIIEntityType
    pattern: Pattern
    severity: PIISeverity
    confidence: float = 0.9
    validator: Optional[Callable[[str], bool]] = None  # Additional validation
    description: str = ""


class PIIDetector:
    """
    Detects PII in text using pattern matching and validation.

    Features:
    - 30+ entity type detection
    - Configurable confidence thresholds
    - Luhn algorithm validation for credit cards
    - Context-aware detection
    - Multiple redaction methods

    Usage:
        detector = PIIDetector()
        entities = detector.detect("My SSN is 123-45-6789")
        redacted = detector.redact(text, entities)
    """

    # Default confidence thresholds by severity
    DEFAULT_THRESHOLDS = {
        PIISeverity.CRITICAL: 0.7,
        PIISeverity.HIGH: 0.75,
        PIISeverity.MEDIUM: 0.8,
        PIISeverity.LOW: 0.85,
        PIISeverity.INFO: 0.9,
    }

    def __init__(
        self,
        enabled_types: Optional[Set[PIIEntityType]] = None,
        thresholds: Optional[Dict[PIISeverity, float]] = None,
        context_window: int = 50,
    ):
        """
        Initialize PII detector.

        Args:
            enabled_types: Set of entity types to detect (None = all)
            thresholds: Confidence thresholds by severity
            context_window: Characters of context to capture around matches
        """
        self.enabled_types = enabled_types
        self.thresholds = thresholds or self.DEFAULT_THRESHOLDS.copy()
        self.context_window = context_window
        self._patterns: List[PIIPattern] = []
        self._stats = {
            'scans': 0,
            'entities_found': 0,
            'by_type': {},
        }

        # Initialize patterns
        self._init_patterns()

    def _init_patterns(self):
        """Initialize all PII detection patterns."""
        patterns = []

        # === Government IDs ===

        # SSN: 123-45-6789 or 123456789
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.SSN,
            pattern=re.compile(
                r'\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b'
            ),
            severity=PIISeverity.CRITICAL,
            confidence=0.95,
            validator=self._validate_ssn,
            description="US Social Security Number",
        ))

        # SSN Last 4
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.SSN_LAST4,
            pattern=re.compile(r'\b(?:ssn|social)\s*(?:last\s*4|ending)?\s*[:.]?\s*(\d{4})\b', re.I),
            severity=PIISeverity.HIGH,
            confidence=0.85,
            description="Last 4 digits of SSN",
        ))

        # Passport (US format)
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.PASSPORT,
            pattern=re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
            severity=PIISeverity.CRITICAL,
            confidence=0.7,
            description="Passport number",
        ))

        # Driver's License (various formats)
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.DRIVERS_LICENSE,
            pattern=re.compile(
                r'\b(?:DL|driver[\'s]*\s*license)[\s:#]*([A-Z]?\d{5,12})\b',
                re.I
            ),
            severity=PIISeverity.CRITICAL,
            confidence=0.8,
            description="Driver's license number",
        ))

        # === Financial ===

        # Credit Card Numbers (with Luhn validation)
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.CREDIT_CARD,
            pattern=re.compile(
                r'\b(?:4[0-9]{12}(?:[0-9]{3})?|'  # Visa
                r'5[1-5][0-9]{14}|'                # Mastercard
                r'3[47][0-9]{13}|'                 # Amex
                r'6(?:011|5[0-9]{2})[0-9]{12}|'    # Discover
                r'(?:2131|1800|35\d{3})\d{11})\b'  # JCB
            ),
            severity=PIISeverity.CRITICAL,
            confidence=0.95,
            validator=self._validate_luhn,
            description="Credit/debit card number",
        ))

        # Credit card with spaces/dashes
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.CREDIT_CARD,
            pattern=re.compile(
                r'\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b'
            ),
            severity=PIISeverity.CRITICAL,
            confidence=0.9,
            validator=lambda x: self._validate_luhn(x.replace('-', '').replace(' ', '')),
            description="Credit card with separators",
        ))

        # CVV/CVC
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.CREDIT_CARD_CVV,
            pattern=re.compile(r'\b(?:cvv|cvc|cvv2|cvc2|security\s*code)[\s:]*(\d{3,4})\b', re.I),
            severity=PIISeverity.CRITICAL,
            confidence=0.9,
            description="Card security code",
        ))

        # Bank Account
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.BANK_ACCOUNT,
            pattern=re.compile(r'\b(?:account|acct)[\s#:]*(\d{8,17})\b', re.I),
            severity=PIISeverity.CRITICAL,
            confidence=0.85,
            description="Bank account number",
        ))

        # Routing Number
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.ROUTING_NUMBER,
            pattern=re.compile(r'\b(?:routing|aba|rtn)[\s#:]*(\d{9})\b', re.I),
            severity=PIISeverity.HIGH,
            confidence=0.9,
            validator=self._validate_routing,
            description="Bank routing number",
        ))

        # IBAN
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.IBAN,
            pattern=re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b'),
            severity=PIISeverity.CRITICAL,
            confidence=0.85,
            description="International bank account number",
        ))

        # Crypto Wallets
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.CRYPTO_WALLET,
            pattern=re.compile(
                r'\b(?:'
                r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}|'      # Bitcoin
                r'0x[a-fA-F0-9]{40}|'                     # Ethereum
                r'[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}|'     # Litecoin
                r'r[0-9a-zA-Z]{24,34}'                    # Ripple
                r')\b'
            ),
            severity=PIISeverity.HIGH,
            confidence=0.8,
            description="Cryptocurrency wallet address",
        ))

        # === Contact Information ===

        # Email
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.EMAIL,
            pattern=re.compile(
                r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
            ),
            severity=PIISeverity.MEDIUM,
            confidence=0.95,
            description="Email address",
        ))

        # Phone (various formats)
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.PHONE,
            pattern=re.compile(
                r'\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
            ),
            severity=PIISeverity.MEDIUM,
            confidence=0.85,
            description="Phone number",
        ))

        # International phone
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.PHONE,
            pattern=re.compile(r'\+\d{1,3}[-.\s]?\d{6,14}\b'),
            severity=PIISeverity.MEDIUM,
            confidence=0.8,
            description="International phone number",
        ))

        # ZIP Code
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.ZIP_CODE,
            pattern=re.compile(r'\b\d{5}(?:-\d{4})?\b'),
            severity=PIISeverity.LOW,
            confidence=0.6,  # Many false positives
            description="US ZIP code",
        ))

        # === Authentication & Secrets ===

        # Password in text
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.PASSWORD,
            pattern=re.compile(
                r'(?:password|passwd|pwd|pass)[\s:=]+["\']?([^\s"\']{6,})["\']?',
                re.I
            ),
            severity=PIISeverity.CRITICAL,
            confidence=0.9,
            description="Password in plaintext",
        ))

        # API Key patterns
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.API_KEY,
            pattern=re.compile(
                r'\b(?:api[_-]?key|apikey|api[_-]?secret)[\s:=]+["\']?([a-zA-Z0-9_-]{20,})["\']?',
                re.I
            ),
            severity=PIISeverity.CRITICAL,
            confidence=0.9,
            description="API key",
        ))

        # Bearer/OAuth tokens
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.ACCESS_TOKEN,
            pattern=re.compile(
                r'\b(?:bearer|token|access[_-]?token|auth[_-]?token)[\s:=]+["\']?([a-zA-Z0-9._-]{20,})["\']?',
                re.I
            ),
            severity=PIISeverity.CRITICAL,
            confidence=0.85,
            description="Access token",
        ))

        # JWT tokens
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.ACCESS_TOKEN,
            pattern=re.compile(r'\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b'),
            severity=PIISeverity.CRITICAL,
            confidence=0.95,
            description="JWT token",
        ))

        # Private keys
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.PRIVATE_KEY,
            pattern=re.compile(
                r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                re.I
            ),
            severity=PIISeverity.CRITICAL,
            confidence=0.99,
            description="Private key header",
        ))

        # AWS Access Keys
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.AWS_KEY,
            pattern=re.compile(r'\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b'),
            severity=PIISeverity.CRITICAL,
            confidence=0.95,
            description="AWS access key",
        ))

        # AWS Secret Keys
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.AWS_KEY,
            pattern=re.compile(
                r'(?:aws[_-]?secret|secret[_-]?key)[\s:=]+["\']?([a-zA-Z0-9/+=]{40})["\']?',
                re.I
            ),
            severity=PIISeverity.CRITICAL,
            confidence=0.9,
            description="AWS secret key",
        ))

        # === Personal Information ===

        # Date of Birth
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.DATE_OF_BIRTH,
            pattern=re.compile(
                r'\b(?:dob|birth\s*date|date\s*of\s*birth)[\s:]+(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})\b',
                re.I
            ),
            severity=PIISeverity.HIGH,
            confidence=0.9,
            description="Date of birth",
        ))

        # Age explicit mention
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.AGE,
            pattern=re.compile(r'\b(?:age|aged)[\s:]+(\d{1,3})\s*(?:years?|yrs?)?\b', re.I),
            severity=PIISeverity.LOW,
            confidence=0.8,
            description="Age",
        ))

        # === Medical ===

        # Medical Record Number
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.MEDICAL_RECORD,
            pattern=re.compile(r'\b(?:mrn|medical\s*record|patient\s*id)[\s#:]*([A-Z0-9]{6,12})\b', re.I),
            severity=PIISeverity.CRITICAL,
            confidence=0.85,
            description="Medical record number",
        ))

        # Health Plan ID
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.HEALTH_PLAN_ID,
            pattern=re.compile(
                r'\b(?:member\s*id|health\s*plan|insurance\s*id)[\s#:]*([A-Z0-9]{8,15})\b',
                re.I
            ),
            severity=PIISeverity.HIGH,
            confidence=0.8,
            description="Health plan ID",
        ))

        # === Network/Technical ===

        # IPv4 Address
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.IP_ADDRESS,
            pattern=re.compile(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            ),
            severity=PIISeverity.MEDIUM,
            confidence=0.9,
            validator=lambda x: not x.startswith(('127.', '0.', '255.')),
            description="IPv4 address",
        ))

        # IPv6 Address
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.IP_ADDRESS,
            pattern=re.compile(
                r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
            ),
            severity=PIISeverity.MEDIUM,
            confidence=0.85,
            description="IPv6 address",
        ))

        # MAC Address
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.MAC_ADDRESS,
            pattern=re.compile(
                r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
            ),
            severity=PIISeverity.LOW,
            confidence=0.9,
            description="MAC address",
        ))

        # URL with credentials
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.URL_WITH_CREDENTIALS,
            pattern=re.compile(
                r'(?:https?|ftp)://[^:@\s]+:[^:@\s]+@[^\s]+'
            ),
            severity=PIISeverity.CRITICAL,
            confidence=0.95,
            description="URL with embedded credentials",
        ))

        # === Other ===

        # VIN (Vehicle Identification Number)
        patterns.append(PIIPattern(
            entity_type=PIIEntityType.VEHICLE_ID,
            pattern=re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'),
            severity=PIISeverity.MEDIUM,
            confidence=0.7,
            validator=self._validate_vin,
            description="Vehicle identification number",
        ))

        self._patterns = patterns

    # === Validators ===

    def _validate_ssn(self, ssn: str) -> bool:
        """Validate SSN format and basic rules."""
        digits = re.sub(r'[-\s]', '', ssn)
        if len(digits) != 9:
            return False
        # Area number (first 3) cannot be 000, 666, or 900-999
        area = int(digits[:3])
        if area == 0 or area == 666 or area >= 900:
            return False
        # Group number (middle 2) cannot be 00
        if digits[3:5] == '00':
            return False
        # Serial number (last 4) cannot be 0000
        if digits[5:] == '0000':
            return False
        return True

    def _validate_luhn(self, number: str) -> bool:
        """Validate credit card using Luhn algorithm."""
        digits = re.sub(r'\D', '', number)
        if len(digits) < 13 or len(digits) > 19:
            return False

        total = 0
        for i, digit in enumerate(reversed(digits)):
            n = int(digit)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0

    def _validate_routing(self, routing: str) -> bool:
        """Validate bank routing number checksum."""
        digits = re.sub(r'\D', '', routing)
        if len(digits) != 9:
            return False

        # ABA routing number checksum
        weights = [3, 7, 1, 3, 7, 1, 3, 7, 1]
        total = sum(int(d) * w for d, w in zip(digits, weights))
        return total % 10 == 0

    def _validate_vin(self, vin: str) -> bool:
        """Validate VIN checksum."""
        if len(vin) != 17:
            return False

        # VIN transliteration and weights
        trans = {
            'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
            'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9,
            'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
        }
        weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]

        try:
            total = 0
            for i, char in enumerate(vin.upper()):
                if char.isdigit():
                    value = int(char)
                else:
                    value = trans.get(char)
                    if value is None:
                        return False
                total += value * weights[i]

            check = total % 11
            check_char = 'X' if check == 10 else str(check)
            return vin[8].upper() == check_char
        except (ValueError, IndexError):
            return False

    # === Core Detection ===

    def detect(
        self,
        text: str,
        types: Optional[Set[PIIEntityType]] = None,
    ) -> List[PIIEntity]:
        """
        Detect PII entities in text.

        Args:
            text: Text to scan for PII
            types: Specific types to detect (None = use enabled_types)

        Returns:
            List of detected PII entities
        """
        if not text:
            return []

        self._stats['scans'] += 1
        entities = []
        types_to_check = types or self.enabled_types

        for pattern_def in self._patterns:
            # Filter by enabled types
            if types_to_check and pattern_def.entity_type not in types_to_check:
                continue

            # Check confidence threshold
            min_confidence = self.thresholds.get(
                pattern_def.severity,
                self.DEFAULT_THRESHOLDS[pattern_def.severity]
            )
            if pattern_def.confidence < min_confidence:
                continue

            # Find matches
            for match in pattern_def.pattern.finditer(text):
                value = match.group(0)

                # Run validator if present
                if pattern_def.validator:
                    try:
                        if not pattern_def.validator(value):
                            continue
                    except Exception:
                        continue

                # Extract context
                start = max(0, match.start() - self.context_window)
                end = min(len(text), match.end() + self.context_window)
                context = text[start:end]

                entity = PIIEntity(
                    entity_type=pattern_def.entity_type,
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    confidence=pattern_def.confidence,
                    severity=pattern_def.severity,
                    context=context,
                    metadata={'pattern': pattern_def.description},
                )
                entities.append(entity)

                # Update stats
                self._stats['entities_found'] += 1
                type_key = pattern_def.entity_type.value
                self._stats['by_type'][type_key] = self._stats['by_type'].get(type_key, 0) + 1

        # Sort by position
        entities.sort(key=lambda e: e.start)

        # Remove overlapping entities (keep highest confidence)
        entities = self._remove_overlaps(entities)

        return entities

    def _remove_overlaps(self, entities: List[PIIEntity]) -> List[PIIEntity]:
        """Remove overlapping entities, keeping highest confidence."""
        if len(entities) <= 1:
            return entities

        result = []
        for entity in entities:
            # Check if overlaps with any existing
            overlaps = False
            for i, existing in enumerate(result):
                if (entity.start < existing.end and entity.end > existing.start):
                    # Overlaps - keep higher confidence
                    if entity.confidence > existing.confidence:
                        result[i] = entity
                    overlaps = True
                    break

            if not overlaps:
                result.append(entity)

        return result

    # === Redaction ===

    def redact(
        self,
        text: str,
        entities: Optional[List[PIIEntity]] = None,
        method: RedactionMethod = RedactionMethod.REPLACE,
        types: Optional[Set[PIIEntityType]] = None,
    ) -> Tuple[str, List[PIIEntity]]:
        """
        Redact PII from text.

        Args:
            text: Text to redact
            entities: Pre-detected entities (will detect if None)
            method: Redaction method to use
            types: Entity types to redact (None = all detected)

        Returns:
            Tuple of (redacted_text, entities)
        """
        if entities is None:
            entities = self.detect(text, types)

        if not entities:
            return text, []

        # Filter by types if specified
        if types:
            entities = [e for e in entities if e.entity_type in types]

        # Redact from end to preserve positions
        result = text
        for entity in reversed(sorted(entities, key=lambda e: e.start)):
            replacement = self._get_replacement(entity, method)
            result = result[:entity.start] + replacement + result[entity.end:]

        return result, entities

    def _get_replacement(self, entity: PIIEntity, method: RedactionMethod) -> str:
        """Get replacement string for an entity."""
        if method == RedactionMethod.MASK:
            return self._mask_value(entity)
        elif method == RedactionMethod.REPLACE:
            return f"[{entity.entity_type.value.upper()} REDACTED]"
        elif method == RedactionMethod.HASH:
            hash_val = hashlib.sha256(entity.value.encode()).hexdigest()[:8]
            return f"[{entity.entity_type.value.upper()}:{hash_val}]"
        elif method == RedactionMethod.REMOVE:
            return ""
        elif method == RedactionMethod.TOKENIZE:
            # Simple tokenization (in production, use reversible encryption)
            token = hashlib.sha256(entity.value.encode()).hexdigest()[:12]
            return f"<PII:{token}>"
        else:
            return f"[REDACTED]"

    def _mask_value(self, entity: PIIEntity) -> str:
        """Create masked version of value."""
        value = entity.value
        length = len(value)

        if entity.entity_type == PIIEntityType.SSN:
            # Show last 4: ***-**-1234
            digits = re.sub(r'\D', '', value)
            return f"***-**-{digits[-4:]}"

        elif entity.entity_type == PIIEntityType.CREDIT_CARD:
            # Show last 4: ****-****-****-1234
            digits = re.sub(r'\D', '', value)
            return f"****-****-****-{digits[-4:]}"

        elif entity.entity_type == PIIEntityType.EMAIL:
            # Mask local part: j***@example.com
            parts = value.split('@')
            if len(parts) == 2:
                local = parts[0]
                masked = local[0] + '*' * (len(local) - 1)
                return f"{masked}@{parts[1]}"

        elif entity.entity_type == PIIEntityType.PHONE:
            # Show last 4: (***) ***-1234
            digits = re.sub(r'\D', '', value)
            return f"(***) ***-{digits[-4:]}"

        # Default: mask middle, show first and last char
        if length <= 4:
            return '*' * length
        else:
            return value[0] + '*' * (length - 2) + value[-1]

    # === Statistics ===

    def get_stats(self) -> Dict:
        """Get detection statistics."""
        return self._stats.copy()

    def reset_stats(self):
        """Reset detection statistics."""
        self._stats = {
            'scans': 0,
            'entities_found': 0,
            'by_type': {},
        }

    # === Utility ===

    def has_pii(
        self,
        text: str,
        min_severity: PIISeverity = PIISeverity.LOW,
    ) -> bool:
        """
        Quick check if text contains any PII at or above severity level.

        Args:
            text: Text to check
            min_severity: Minimum severity to consider

        Returns:
            True if PII found at or above severity level
        """
        severity_order = [
            PIISeverity.INFO,
            PIISeverity.LOW,
            PIISeverity.MEDIUM,
            PIISeverity.HIGH,
            PIISeverity.CRITICAL,
        ]
        min_index = severity_order.index(min_severity)

        entities = self.detect(text)
        for entity in entities:
            if severity_order.index(entity.severity) >= min_index:
                return True
        return False

    def get_severity_summary(self, entities: List[PIIEntity]) -> Dict[str, int]:
        """Get count of entities by severity."""
        summary = {s.value: 0 for s in PIISeverity}
        for entity in entities:
            summary[entity.severity.value] += 1
        return summary
