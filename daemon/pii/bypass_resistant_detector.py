"""
Bypass-Resistant PII Detection - Defense against regex bypass techniques.

SECURITY: This module addresses the vulnerability:
"Regex-Based PII Detection Bypasses"

Problems with regex-only PII detection:
1. Encoding bypasses: Base64, hex, URL encoding, Unicode escapes
2. Character substitution: Homoglyphs (O→0, l→1, a→@)
3. Unicode variations: Fullwidth characters, combining marks
4. Invisible characters: Zero-width chars, RTL override
5. Formatting tricks: Extra whitespace, delimiter changes
6. Obfuscation: Reversed strings, split across fields

Solution:
1. Multi-layer normalization before detection
2. Automatic decoding of common encodings
3. Homoglyph normalization
4. Suspicious pattern detection
5. Entropy-based anomaly detection
6. Contextual analysis
"""

import base64
import binascii
import hashlib
import html
import logging
import math
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Callable
from urllib.parse import unquote

logger = logging.getLogger(__name__)


class BypassTechnique(Enum):
    """Detected bypass techniques."""
    NONE = "none"
    BASE64_ENCODING = "base64_encoding"
    HEX_ENCODING = "hex_encoding"
    URL_ENCODING = "url_encoding"
    UNICODE_ESCAPE = "unicode_escape"
    HTML_ENTITY = "html_entity"
    HOMOGLYPH = "homoglyph"
    ZERO_WIDTH = "zero_width"
    FULLWIDTH = "fullwidth"
    REVERSED = "reversed"
    SPLIT_DATA = "split_data"
    WHITESPACE = "whitespace"
    CASE_MIXING = "case_mixing"
    ROT13 = "rot13"


class DetectionConfidence(Enum):
    """Confidence levels for detection."""
    CERTAIN = "certain"       # Direct pattern match
    HIGH = "high"             # Decoded/normalized match
    MEDIUM = "medium"         # Heuristic detection
    LOW = "low"               # Suspicious but uncertain
    SUSPICIOUS = "suspicious" # Anomaly detected


@dataclass
class NormalizationResult:
    """Result of text normalization."""
    original: str
    normalized: str
    transformations: List[str] = field(default_factory=list)
    decoded_from: Optional[BypassTechnique] = None
    confidence_reduction: float = 0.0  # How much to reduce detection confidence


@dataclass
class BypassAttempt:
    """A detected bypass attempt."""
    technique: BypassTechnique
    original_text: str
    decoded_text: str
    position: int
    length: int
    confidence: float
    severity: str = "medium"


# Homoglyph mappings - characters that look similar
HOMOGLYPHS = {
    # Latin look-alikes
    '0': ['O', 'o', 'Ο', 'ο', '০', '᱐', '𝟢', '𝟬', '𝟶', '𝟎', '⓪'],
    'O': ['0', 'Ο', 'О', 'Օ', '〇', '○', '◯', '𝐎', '𝑂', '𝖮'],
    'o': ['0', 'ο', 'о', 'օ', 'ᴏ', 'ₒ', '𝐨', '𝑜', '𝖔'],
    '1': ['l', 'I', 'i', '|', 'ǀ', 'Ɩ', 'ı', '١', '۱', '𝟙', '𝟣'],
    'l': ['1', 'I', 'i', '|', 'ǀ', 'Ɩ', 'ı', 'ℓ', '𝐥', '𝑙'],
    'I': ['1', 'l', 'i', '|', 'Ɩ', 'Ι', 'І', 'ǀ', '𝐈', '𝐼'],
    'i': ['1', 'l', 'I', 'í', 'ì', 'ι', 'і', 'ı', '𝐢', '𝑖'],
    '2': ['Z', 'z', '𝟐', '𝟚', '𝟤', '②'],
    '5': ['S', 's', '𝟓', '𝟝', '𝟧', '⑤'],
    'S': ['5', '$', 'Ѕ', 'Ꮪ', '𝐒', '𝑆', '𝖲'],
    's': ['5', '$', 'ѕ', 'ꮪ', '𝐬', '𝑠', '𝖘'],
    '6': ['G', 'b', '𝟔', '𝟞', '𝟨', '⑥'],
    '8': ['B', '𝟖', '𝟠', '𝟪', '⑧'],
    'B': ['8', '𝐁', '𝐵', '𝖡', 'Β', 'В'],
    '9': ['g', 'q', '𝟗', '𝟡', '𝟫', '⑨'],
    'a': ['@', 'α', 'а', 'ɑ', '𝐚', '𝑎', '𝖆'],
    '@': ['a', 'α'],
    'e': ['3', 'є', 'е', 'ē', '𝐞', '𝑒', '𝖊'],
    '3': ['E', 'e', 'З', 'з', '𝟑', '𝟛', '𝟥'],
    't': ['+', '𝐭', '𝑡', '𝖙', 'τ', 'т'],
    '+': ['t'],
    'x': ['×', '✕', '✖', '𝐱', '𝑥', '𝖝'],
    '×': ['x'],
    'n': ['ո', 'ñ', 'ń', '𝐧', '𝑛', '𝖓'],
    'm': ['rn', 'ⅿ', '𝐦', '𝑚', '𝖒'],
    'c': ['(', '[', 'ϲ', 'с', '𝐜', '𝑐', '𝖈'],
    'd': ['ɗ', 'ԁ', '𝐝', '𝑑', '𝖉'],
    'p': ['ρ', 'р', '𝐩', '𝑝', '𝖕'],
    'r': ['г', 'ⲅ', '𝐫', '𝑟', '𝖗'],
    'v': ['ν', 'ѵ', '𝐯', '𝑣', '𝖛'],
    'w': ['ω', 'ѡ', '𝐰', '𝑤', '𝖜'],
    'y': ['γ', 'у', '𝐲', '𝑦', '𝖞'],
    '-': ['–', '—', '−', '‒', '‐', '⁃'],
    '.': ['·', '٠', '۰', '᠐'],
}

# Build reverse mapping
REVERSE_HOMOGLYPHS: Dict[str, str] = {}
for canonical, variants in HOMOGLYPHS.items():
    for variant in variants:
        if variant not in REVERSE_HOMOGLYPHS:
            REVERSE_HOMOGLYPHS[variant] = canonical

# Zero-width characters to remove
ZERO_WIDTH_CHARS = {
    '\u200b',  # Zero-width space
    '\u200c',  # Zero-width non-joiner
    '\u200d',  # Zero-width joiner
    '\u2060',  # Word joiner
    '\ufeff',  # Zero-width no-break space (BOM)
    '\u00ad',  # Soft hyphen
    '\u180e',  # Mongolian vowel separator
    '\u2061',  # Function application
    '\u2062',  # Invisible times
    '\u2063',  # Invisible separator
    '\u2064',  # Invisible plus
}

# Suspicious high-entropy patterns (might indicate encoded data)
HIGH_ENTROPY_THRESHOLD = 4.0


class TextNormalizer:
    """
    Normalizes text to defeat bypass techniques.

    Performs multi-layer normalization:
    1. Remove zero-width characters
    2. Normalize Unicode (NFC/NFKC)
    3. Convert fullwidth to ASCII
    4. Normalize homoglyphs
    5. Decode common encodings
    """

    def __init__(
        self,
        normalize_homoglyphs: bool = True,
        decode_encodings: bool = True,
        strip_zero_width: bool = True,
        normalize_unicode: bool = True,
    ):
        self.normalize_homoglyphs = normalize_homoglyphs
        self.decode_encodings = decode_encodings
        self.strip_zero_width = strip_zero_width
        self.normalize_unicode = normalize_unicode

    def normalize(self, text: str) -> NormalizationResult:
        """
        Apply all normalizations to text.

        Args:
            text: Text to normalize

        Returns:
            NormalizationResult with normalized text and transformations applied
        """
        result = NormalizationResult(original=text, normalized=text)

        # 1. Strip zero-width characters
        if self.strip_zero_width:
            new_text = self._strip_zero_width(result.normalized)
            if new_text != result.normalized:
                result.transformations.append("strip_zero_width")
                result.normalized = new_text

        # 2. Unicode normalization (NFKC decomposes and recomposes)
        if self.normalize_unicode:
            new_text = unicodedata.normalize('NFKC', result.normalized)
            if new_text != result.normalized:
                result.transformations.append("unicode_nfkc")
                result.normalized = new_text

        # 3. Convert fullwidth to ASCII
        new_text = self._convert_fullwidth(result.normalized)
        if new_text != result.normalized:
            result.transformations.append("fullwidth_to_ascii")
            result.normalized = new_text

        # 4. Normalize homoglyphs
        if self.normalize_homoglyphs:
            new_text = self._normalize_homoglyphs(result.normalized)
            if new_text != result.normalized:
                result.transformations.append("homoglyph_normalize")
                result.normalized = new_text
                result.confidence_reduction += 0.1

        # 5. Decode encodings
        if self.decode_encodings:
            decoded, technique = self._try_decode(result.normalized)
            if decoded != result.normalized:
                result.transformations.append(f"decode_{technique.value}")
                result.normalized = decoded
                result.decoded_from = technique
                result.confidence_reduction += 0.2

        return result

    def _strip_zero_width(self, text: str) -> str:
        """Remove zero-width characters."""
        return ''.join(c for c in text if c not in ZERO_WIDTH_CHARS)

    def _convert_fullwidth(self, text: str) -> str:
        """Convert fullwidth ASCII to regular ASCII."""
        result = []
        for char in text:
            code = ord(char)
            # Fullwidth ASCII variants (FF01-FF5E) -> regular ASCII (21-7E)
            if 0xFF01 <= code <= 0xFF5E:
                result.append(chr(code - 0xFF01 + 0x21))
            # Fullwidth space
            elif code == 0x3000:
                result.append(' ')
            else:
                result.append(char)
        return ''.join(result)

    def _normalize_homoglyphs(self, text: str) -> str:
        """Replace homoglyphs with canonical characters."""
        result = []
        for char in text:
            result.append(REVERSE_HOMOGLYPHS.get(char, char))
        return ''.join(result)

    def _try_decode(self, text: str) -> Tuple[str, BypassTechnique]:
        """Try to decode encoded text."""
        # Try URL decoding
        try:
            decoded = unquote(text)
            if decoded != text and '%' in text:
                return decoded, BypassTechnique.URL_ENCODING
        except Exception:
            pass

        # Try HTML entity decoding
        try:
            decoded = html.unescape(text)
            if decoded != text and ('&' in text or '&#' in text):
                return decoded, BypassTechnique.HTML_ENTITY
        except Exception:
            pass

        # Try base64 decoding (only for likely base64 strings)
        try:
            # Check if it looks like base64
            if re.match(r'^[A-Za-z0-9+/=]{16,}$', text.strip()):
                # Must be multiple of 4 (with padding)
                padded = text.strip()
                while len(padded) % 4:
                    padded += '='
                decoded = base64.b64decode(padded).decode('utf-8', errors='strict')
                if decoded.isprintable():
                    return decoded, BypassTechnique.BASE64_ENCODING
        except Exception:
            pass

        # Try hex decoding
        try:
            if re.match(r'^[0-9a-fA-F]{8,}$', text.strip()) and len(text) % 2 == 0:
                decoded = binascii.unhexlify(text.strip()).decode('utf-8', errors='strict')
                if decoded.isprintable():
                    return decoded, BypassTechnique.HEX_ENCODING
        except Exception:
            pass

        # Try Unicode escape sequences
        try:
            if '\\u' in text or '\\x' in text:
                decoded = text.encode().decode('unicode_escape')
                if decoded != text:
                    return decoded, BypassTechnique.UNICODE_ESCAPE
        except Exception:
            pass

        return text, BypassTechnique.NONE


class EntropyAnalyzer:
    """Analyzes text entropy to detect potential encoded/obfuscated data."""

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """
        Calculate Shannon entropy of text.

        High entropy suggests encoded/random data.
        """
        if not text:
            return 0.0

        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        entropy = 0.0
        length = len(text)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    @staticmethod
    def is_suspicious_entropy(text: str, threshold: float = HIGH_ENTROPY_THRESHOLD) -> bool:
        """Check if text has suspiciously high entropy."""
        if len(text) < 10:
            return False
        return EntropyAnalyzer.calculate_entropy(text) > threshold


class BypassDetector:
    """Detects attempts to bypass PII detection."""

    def __init__(self):
        self.normalizer = TextNormalizer()
        self.entropy_analyzer = EntropyAnalyzer()

    def detect_bypass_attempts(self, text: str) -> List[BypassAttempt]:
        """
        Detect potential bypass attempts in text.

        Args:
            text: Text to analyze

        Returns:
            List of detected bypass attempts
        """
        attempts = []

        # Check for zero-width characters
        zwc_positions = self._find_zero_width(text)
        if zwc_positions:
            attempts.append(BypassAttempt(
                technique=BypassTechnique.ZERO_WIDTH,
                original_text=text,
                decoded_text=self.normalizer._strip_zero_width(text),
                position=zwc_positions[0],
                length=len(zwc_positions),
                confidence=0.9,
                severity="high",
            ))

        # Check for homoglyphs
        homoglyph_positions = self._find_homoglyphs(text)
        if homoglyph_positions:
            attempts.append(BypassAttempt(
                technique=BypassTechnique.HOMOGLYPH,
                original_text=text,
                decoded_text=self.normalizer._normalize_homoglyphs(text),
                position=homoglyph_positions[0][0],
                length=len(homoglyph_positions),
                confidence=0.8,
                severity="medium",
            ))

        # Check for fullwidth characters
        fullwidth_positions = self._find_fullwidth(text)
        if fullwidth_positions:
            attempts.append(BypassAttempt(
                technique=BypassTechnique.FULLWIDTH,
                original_text=text,
                decoded_text=self.normalizer._convert_fullwidth(text),
                position=fullwidth_positions[0],
                length=len(fullwidth_positions),
                confidence=0.85,
                severity="medium",
            ))

        # Check for encoded segments
        encoded_segments = self._find_encoded_segments(text)
        for segment in encoded_segments:
            attempts.append(segment)

        # Check for suspicious high-entropy regions
        high_entropy_regions = self._find_high_entropy_regions(text)
        for region in high_entropy_regions:
            attempts.append(BypassAttempt(
                technique=BypassTechnique.BASE64_ENCODING,  # Most common
                original_text=region['text'],
                decoded_text="[HIGH ENTROPY DETECTED]",
                position=region['start'],
                length=region['end'] - region['start'],
                confidence=0.6,
                severity="low",
            ))

        return attempts

    def _find_zero_width(self, text: str) -> List[int]:
        """Find positions of zero-width characters."""
        positions = []
        for i, char in enumerate(text):
            if char in ZERO_WIDTH_CHARS:
                positions.append(i)
        return positions

    def _find_homoglyphs(self, text: str) -> List[Tuple[int, str, str]]:
        """Find homoglyph positions and their canonical forms."""
        positions = []
        for i, char in enumerate(text):
            if char in REVERSE_HOMOGLYPHS:
                positions.append((i, char, REVERSE_HOMOGLYPHS[char]))
        return positions

    def _find_fullwidth(self, text: str) -> List[int]:
        """Find positions of fullwidth characters."""
        positions = []
        for i, char in enumerate(text):
            code = ord(char)
            if 0xFF01 <= code <= 0xFF5E or code == 0x3000:
                positions.append(i)
        return positions

    def _find_encoded_segments(self, text: str) -> List[BypassAttempt]:
        """Find and decode encoded segments."""
        attempts = []

        # Base64 patterns
        b64_pattern = re.compile(r'[A-Za-z0-9+/=]{20,}')
        for match in b64_pattern.finditer(text):
            segment = match.group()
            try:
                # Try to decode
                padded = segment
                while len(padded) % 4:
                    padded += '='
                decoded = base64.b64decode(padded).decode('utf-8', errors='strict')
                if decoded.isprintable() and len(decoded) >= 5:
                    attempts.append(BypassAttempt(
                        technique=BypassTechnique.BASE64_ENCODING,
                        original_text=segment,
                        decoded_text=decoded,
                        position=match.start(),
                        length=len(segment),
                        confidence=0.8,
                        severity="high",
                    ))
            except Exception:
                pass

        # Hex patterns
        hex_pattern = re.compile(r'(?:0x)?[0-9a-fA-F]{16,}')
        for match in hex_pattern.finditer(text):
            segment = match.group()
            hex_part = segment[2:] if segment.startswith('0x') else segment
            if len(hex_part) % 2 == 0:
                try:
                    decoded = binascii.unhexlify(hex_part).decode('utf-8', errors='strict')
                    if decoded.isprintable() and len(decoded) >= 5:
                        attempts.append(BypassAttempt(
                            technique=BypassTechnique.HEX_ENCODING,
                            original_text=segment,
                            decoded_text=decoded,
                            position=match.start(),
                            length=len(segment),
                            confidence=0.75,
                            severity="high",
                        ))
                except Exception:
                    pass

        # URL encoded patterns
        url_pattern = re.compile(r'(?:%[0-9a-fA-F]{2}){3,}')
        for match in url_pattern.finditer(text):
            segment = match.group()
            try:
                decoded = unquote(segment)
                if decoded != segment and len(decoded) >= 3:
                    attempts.append(BypassAttempt(
                        technique=BypassTechnique.URL_ENCODING,
                        original_text=segment,
                        decoded_text=decoded,
                        position=match.start(),
                        length=len(segment),
                        confidence=0.85,
                        severity="medium",
                    ))
            except Exception:
                pass

        return attempts

    def _find_high_entropy_regions(self, text: str, min_length: int = 20) -> List[Dict]:
        """Find regions with suspiciously high entropy."""
        regions = []

        # Slide window over text
        window_size = min_length
        for i in range(0, len(text) - window_size + 1, window_size // 2):
            window = text[i:i + window_size]
            if self.entropy_analyzer.is_suspicious_entropy(window):
                regions.append({
                    'start': i,
                    'end': i + window_size,
                    'text': window,
                    'entropy': self.entropy_analyzer.calculate_entropy(window),
                })

        # Merge overlapping regions
        merged = []
        for region in sorted(regions, key=lambda x: x['start']):
            if merged and region['start'] < merged[-1]['end']:
                merged[-1]['end'] = max(merged[-1]['end'], region['end'])
            else:
                merged.append(region)

        return merged


class BypassResistantPIIDetector:
    """
    PII detector with bypass resistance.

    Wraps the standard PIIDetector and adds:
    1. Text normalization before detection
    2. Bypass attempt detection
    3. Multi-pass detection (original + normalized)
    4. Confidence adjustment based on bypass detection
    """

    def __init__(
        self,
        base_detector=None,
        normalize_before_scan: bool = True,
        detect_bypass_attempts: bool = True,
        scan_decoded_content: bool = True,
        flag_suspicious_entropy: bool = True,
    ):
        """
        Initialize bypass-resistant detector.

        Args:
            base_detector: Underlying PIIDetector (will create if None)
            normalize_before_scan: Normalize text before scanning
            detect_bypass_attempts: Detect and log bypass attempts
            scan_decoded_content: Scan decoded content for PII
            flag_suspicious_entropy: Flag high-entropy regions
        """
        # Import here to avoid circular imports
        from .detector import PIIDetector

        self.base_detector = base_detector or PIIDetector()
        self.normalizer = TextNormalizer()
        self.bypass_detector = BypassDetector()

        self.normalize_before_scan = normalize_before_scan
        self.detect_bypass_attempts = detect_bypass_attempts
        self.scan_decoded_content = scan_decoded_content
        self.flag_suspicious_entropy = flag_suspicious_entropy

        self._stats = {
            'scans': 0,
            'bypass_attempts_detected': 0,
            'by_technique': {},
            'normalized_detections': 0,
        }

    def detect(self, text: str, types=None) -> Dict:
        """
        Detect PII with bypass resistance.

        Args:
            text: Text to scan
            types: Specific PII types to detect

        Returns:
            Dict with:
            - entities: Detected PII entities
            - bypass_attempts: Detected bypass attempts
            - normalized: Whether normalization was applied
            - warnings: Any warnings about potential evasion
        """
        self._stats['scans'] += 1

        result = {
            'entities': [],
            'bypass_attempts': [],
            'normalized': False,
            'warnings': [],
            'transformations': [],
        }

        # 1. Detect bypass attempts first
        if self.detect_bypass_attempts:
            bypass_attempts = self.bypass_detector.detect_bypass_attempts(text)
            result['bypass_attempts'] = [
                {
                    'technique': ba.technique.value,
                    'position': ba.position,
                    'length': ba.length,
                    'confidence': ba.confidence,
                    'severity': ba.severity,
                }
                for ba in bypass_attempts
            ]

            if bypass_attempts:
                self._stats['bypass_attempts_detected'] += 1
                for ba in bypass_attempts:
                    technique = ba.technique.value
                    self._stats['by_technique'][technique] = \
                        self._stats['by_technique'].get(technique, 0) + 1
                result['warnings'].append(
                    f"Detected {len(bypass_attempts)} potential bypass attempt(s)"
                )

        # 2. Scan original text
        original_entities = self.base_detector.detect(text, types)
        result['entities'].extend(original_entities)

        # 3. Normalize and scan again
        if self.normalize_before_scan:
            norm_result = self.normalizer.normalize(text)

            if norm_result.normalized != text:
                result['normalized'] = True
                result['transformations'] = norm_result.transformations

                # Scan normalized text
                normalized_entities = self.base_detector.detect(
                    norm_result.normalized, types
                )

                # Add entities not found in original scan
                # (adjust positions back to original text if possible)
                for entity in normalized_entities:
                    if not self._entity_overlaps(entity, original_entities):
                        # Mark as found via normalization
                        entity.metadata['found_via'] = 'normalization'
                        entity.metadata['transformations'] = norm_result.transformations
                        # Reduce confidence since we had to normalize
                        entity.confidence *= (1 - norm_result.confidence_reduction)
                        result['entities'].append(entity)
                        self._stats['normalized_detections'] += 1

        # 4. Scan decoded content from bypass attempts
        if self.scan_decoded_content:
            for ba in self.bypass_detector.detect_bypass_attempts(text):
                if ba.decoded_text and ba.decoded_text != ba.original_text:
                    decoded_entities = self.base_detector.detect(
                        ba.decoded_text, types
                    )
                    for entity in decoded_entities:
                        entity.metadata['found_via'] = f'decoded_{ba.technique.value}'
                        entity.metadata['original_position'] = ba.position
                        entity.confidence *= 0.8  # Reduce confidence
                        result['entities'].append(entity)

        # 5. Flag suspicious high-entropy regions
        if self.flag_suspicious_entropy:
            high_entropy = self.bypass_detector._find_high_entropy_regions(text)
            for region in high_entropy:
                result['warnings'].append(
                    f"High entropy region at position {region['start']}-{region['end']} "
                    f"(entropy: {region['entropy']:.2f}) - may contain encoded PII"
                )

        # Deduplicate entities
        result['entities'] = self._deduplicate_entities(result['entities'])

        return result

    def _entity_overlaps(self, entity, entities) -> bool:
        """Check if entity overlaps with any in list."""
        for e in entities:
            if (entity.start < e.end and entity.end > e.start and
                entity.entity_type == e.entity_type):
                return True
        return False

    def _deduplicate_entities(self, entities) -> List:
        """Remove duplicate entities, keeping highest confidence."""
        if len(entities) <= 1:
            return entities

        # Sort by position and confidence
        sorted_entities = sorted(
            entities,
            key=lambda e: (e.start, -e.confidence)
        )

        result = []
        for entity in sorted_entities:
            # Check if overlaps with existing
            overlaps = False
            for i, existing in enumerate(result):
                if (entity.start < existing.end and entity.end > existing.start and
                    entity.entity_type == existing.entity_type):
                    # Keep higher confidence
                    if entity.confidence > existing.confidence:
                        result[i] = entity
                    overlaps = True
                    break

            if not overlaps:
                result.append(entity)

        return result

    def get_stats(self) -> Dict:
        """Get detection statistics."""
        base_stats = self.base_detector.get_stats()
        return {
            **base_stats,
            'bypass_resistant': self._stats.copy(),
        }

    def has_pii(self, text: str, min_severity=None) -> bool:
        """Quick check if text contains PII."""
        result = self.detect(text)
        if not result['entities']:
            return False

        if min_severity:
            from .detector import PIISeverity
            severity_order = list(PIISeverity)
            min_index = severity_order.index(min_severity)
            for entity in result['entities']:
                if severity_order.index(entity.severity) >= min_index:
                    return True
            return False

        return True

    def redact(self, text: str, method=None, types=None) -> Tuple[str, Dict]:
        """
        Redact PII with bypass resistance.

        First normalizes, then detects, then redacts.
        """
        # Normalize first
        norm_result = self.normalizer.normalize(text)

        # Detect on normalized
        detection = self.detect(text, types)

        # Redact using base detector
        from .detector import RedactionMethod
        method = method or RedactionMethod.REPLACE

        redacted, entities = self.base_detector.redact(
            text,
            detection['entities'],
            method,
            types
        )

        return redacted, detection


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    print("Testing Bypass-Resistant PII Detection")
    print("=" * 60)

    # Test cases demonstrating bypass techniques
    test_cases = [
        # Normal SSN
        ("My SSN is 123-45-6789", "Normal SSN"),

        # Zero-width character bypass
        ("My SSN is 123\u200b-\u200b45\u200b-\u200b6789", "Zero-width bypass"),

        # Homoglyph bypass (O -> 0, l -> 1)
        ("My SSN is l23-45-6789", "Homoglyph bypass"),

        # Fullwidth bypass
        ("My SSN is 123-45-6789", "Fullwidth bypass"),

        # Base64 encoded SSN
        ("My SSN is " + base64.b64encode(b"123-45-6789").decode(), "Base64 bypass"),

        # Hex encoded
        ("SSN: " + binascii.hexlify(b"123-45-6789").decode(), "Hex bypass"),

        # URL encoded
        ("SSN: %31%32%33%2D%34%35%2D%36%37%38%39", "URL encoded bypass"),
    ]

    detector = BypassResistantPIIDetector()

    for text, description in test_cases:
        print(f"\n{description}:")
        print(f"  Input: {repr(text)}")

        result = detector.detect(text)
        print(f"  Entities found: {len(result['entities'])}")
        print(f"  Bypass attempts: {len(result['bypass_attempts'])}")
        print(f"  Normalized: {result['normalized']}")

        if result['warnings']:
            print(f"  Warnings: {result['warnings']}")

        for entity in result['entities']:
            print(f"    - {entity.entity_type.value}: confidence={entity.confidence:.2f}")

    print("\n" + "=" * 60)
    print("Stats:", detector.get_stats())
