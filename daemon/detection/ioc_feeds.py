"""
Signed IOC (Indicators of Compromise) Feeds

Provides management of threat intelligence feeds:
- IP addresses, domains, URLs, file hashes
- Cryptographically signed feeds for authenticity
- Feed versioning and update tracking
- Deterministic matching

All feeds must be signed to prevent tampering.
"""

import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Pattern

logger = logging.getLogger(__name__)

# Try to import NaCl for signature verification
try:
    import nacl.signing
    import nacl.encoding
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False


class IOCType(Enum):
    """Types of IOCs."""
    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "md5"
    FILE_HASH_SHA1 = "sha1"
    FILE_HASH_SHA256 = "sha256"
    EMAIL = "email"
    MUTEX = "mutex"
    REGISTRY_KEY = "registry"
    FILE_PATH = "filepath"
    PROCESS_NAME = "process"
    USER_AGENT = "user_agent"
    JA3_HASH = "ja3"
    CIDR = "cidr"
    ASN = "asn"


class ThreatCategory(Enum):
    """Threat categories for IOCs."""
    MALWARE = "malware"
    PHISHING = "phishing"
    C2 = "c2"  # Command and Control
    BOTNET = "botnet"
    RANSOMWARE = "ransomware"
    APT = "apt"  # Advanced Persistent Threat
    EXPLOIT = "exploit"
    SPAM = "spam"
    SCANNER = "scanner"
    TOR_EXIT = "tor_exit"
    VPN = "vpn"
    PROXY = "proxy"
    SUSPICIOUS = "suspicious"


class Confidence(Enum):
    """Confidence levels for IOCs."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


@dataclass
class IOCEntry:
    """A single IOC entry."""
    value: str
    ioc_type: IOCType
    category: ThreatCategory = ThreatCategory.SUSPICIOUS
    confidence: Confidence = Confidence.MEDIUM

    # Metadata
    description: str = ""
    source: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    expiration: Optional[datetime] = None

    # References
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # MITRE ATT&CK
    mitre_techniques: List[str] = field(default_factory=list)

    @property
    def is_expired(self) -> bool:
        if self.expiration is None:
            return False
        return datetime.utcnow() > self.expiration

    @property
    def value_hash(self) -> str:
        """Get hash of the IOC value for deduplication."""
        return hashlib.sha256(
            f"{self.ioc_type.value}:{self.value}".encode()
        ).hexdigest()[:16]


@dataclass
class IOCMatch:
    """Result of an IOC match."""
    ioc: IOCEntry
    matched_value: str
    matched_at: datetime = field(default_factory=datetime.utcnow)
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IOCFeed:
    """A collection of IOCs from a single source."""
    name: str
    source_url: Optional[str] = None
    entries: List[IOCEntry] = field(default_factory=list)

    # Versioning
    version: str = "1.0"
    published_at: Optional[datetime] = None
    fetched_at: Optional[datetime] = None

    # Update tracking
    update_interval_hours: int = 24
    last_update: Optional[datetime] = None

    # Provider info
    provider: str = ""
    license: str = ""

    @property
    def entry_count(self) -> int:
        return len(self.entries)

    @property
    def needs_update(self) -> bool:
        if self.last_update is None:
            return True
        elapsed = datetime.utcnow() - self.last_update
        return elapsed > timedelta(hours=self.update_interval_hours)


@dataclass
class SignedIOCFeed(IOCFeed):
    """A cryptographically signed IOC feed."""
    # Signature
    signature: Optional[str] = None
    signed_by: Optional[str] = None
    public_key: Optional[str] = None

    # Verification
    signature_valid: bool = False
    verified_at: Optional[datetime] = None

    def verify_signature(self) -> bool:
        """Verify feed signature."""
        if not NACL_AVAILABLE:
            logger.warning("NaCl not available - cannot verify signature")
            return False

        if not self.signature or not self.public_key:
            return False

        try:
            # Reconstruct signed content
            content = json.dumps({
                'name': self.name,
                'version': self.version,
                'entries': [
                    {
                        'value': e.value,
                        'type': e.ioc_type.value,
                        'category': e.category.value,
                    }
                    for e in self.entries
                ],
            }, sort_keys=True)

            verify_key = nacl.signing.VerifyKey(
                bytes.fromhex(self.public_key)
            )
            verify_key.verify(
                content.encode(),
                bytes.fromhex(self.signature)
            )

            self.signature_valid = True
            self.verified_at = datetime.utcnow()
            return True

        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            self.signature_valid = False
            return False


class IOCFeedManager:
    """
    Manages IOC feeds and provides matching.

    Usage:
        manager = IOCFeedManager()

        # Add feeds
        manager.add_feed(my_feed)
        manager.load_feed_from_file("/path/to/feed.json")

        # Check IOCs
        matches = manager.check_ip("192.168.1.1")
        matches = manager.check_domain("evil.com")
        matches = manager.check_hash("abc123...")

        # Or generic check
        matches = manager.check_value("evil.com", IOCType.DOMAIN)
    """

    def __init__(self, require_signatures: bool = True):
        self.require_signatures = require_signatures
        self._lock = threading.Lock()

        # Feeds
        self._feeds: Dict[str, IOCFeed] = {}

        # Index for fast lookups
        self._ip_index: Dict[str, List[IOCEntry]] = {}
        self._domain_index: Dict[str, List[IOCEntry]] = {}
        self._hash_index: Dict[str, List[IOCEntry]] = {}
        self._url_index: Dict[str, List[IOCEntry]] = {}
        self._generic_index: Dict[str, Dict[str, List[IOCEntry]]] = {}

        # Stats
        self._checks_performed = 0
        self._matches_found = 0

        # Compiled patterns for wildcards
        self._domain_patterns: List[tuple[Pattern, IOCEntry]] = []

    def add_feed(self, feed: IOCFeed) -> bool:
        """Add an IOC feed."""
        # Verify signature if required
        if self.require_signatures:
            if isinstance(feed, SignedIOCFeed):
                if not feed.verify_signature():
                    logger.error(f"Feed {feed.name} has invalid signature")
                    return False
            else:
                logger.error(f"Feed {feed.name} is not signed (signatures required)")
                return False

        with self._lock:
            self._feeds[feed.name] = feed
            self._index_feed(feed)

        logger.info(f"Added feed {feed.name} with {feed.entry_count} entries")
        return True

    def _index_feed(self, feed: IOCFeed) -> None:
        """Index feed entries for fast lookup."""
        for entry in feed.entries:
            if entry.is_expired:
                continue

            value_lower = entry.value.lower()

            if entry.ioc_type == IOCType.IP_ADDRESS:
                self._ip_index.setdefault(value_lower, []).append(entry)
            elif entry.ioc_type == IOCType.DOMAIN:
                if '*' in entry.value:
                    # Wildcard domain - compile pattern
                    pattern = entry.value.replace('.', r'\.').replace('*', '.*')
                    try:
                        compiled = re.compile(f"^{pattern}$", re.IGNORECASE)
                        self._domain_patterns.append((compiled, entry))
                    except re.error:
                        pass
                else:
                    self._domain_index.setdefault(value_lower, []).append(entry)
            elif entry.ioc_type in (IOCType.FILE_HASH_MD5, IOCType.FILE_HASH_SHA1, IOCType.FILE_HASH_SHA256):
                self._hash_index.setdefault(value_lower, []).append(entry)
            elif entry.ioc_type == IOCType.URL:
                self._url_index.setdefault(value_lower, []).append(entry)
            else:
                # Generic index
                type_index = self._generic_index.setdefault(entry.ioc_type.value, {})
                type_index.setdefault(value_lower, []).append(entry)

    def load_feed_from_file(self, path: str) -> bool:
        """Load an IOC feed from a JSON file."""
        try:
            with open(path, 'r') as f:
                data = json.load(f)

            feed = self._parse_feed(data, path)
            if feed:
                return self.add_feed(feed)
            return False

        except Exception as e:
            logger.error(f"Failed to load feed from {path}: {e}")
            return False

    def _parse_feed(self, data: Dict[str, Any], source: str) -> Optional[IOCFeed]:
        """Parse feed from dictionary data."""
        try:
            entries = []
            for entry_data in data.get('entries', []):
                entry = IOCEntry(
                    value=entry_data['value'],
                    ioc_type=IOCType(entry_data.get('type', 'domain')),
                    category=ThreatCategory(entry_data.get('category', 'suspicious')),
                    confidence=Confidence(entry_data.get('confidence', 'medium')),
                    description=entry_data.get('description', ''),
                    source=data.get('provider', source),
                    tags=entry_data.get('tags', []),
                    mitre_techniques=entry_data.get('mitre', []),
                )

                if 'first_seen' in entry_data:
                    entry.first_seen = datetime.fromisoformat(entry_data['first_seen'])
                if 'expiration' in entry_data:
                    entry.expiration = datetime.fromisoformat(entry_data['expiration'])

                entries.append(entry)

            # Check if signed
            if 'signature' in data and 'public_key' in data:
                feed = SignedIOCFeed(
                    name=data.get('name', Path(source).stem),
                    entries=entries,
                    version=data.get('version', '1.0'),
                    provider=data.get('provider', ''),
                    signature=data.get('signature'),
                    public_key=data.get('public_key'),
                    signed_by=data.get('signed_by'),
                )
            else:
                feed = IOCFeed(
                    name=data.get('name', Path(source).stem),
                    entries=entries,
                    version=data.get('version', '1.0'),
                    provider=data.get('provider', ''),
                )

            feed.fetched_at = datetime.utcnow()
            return feed

        except Exception as e:
            logger.error(f"Failed to parse feed: {e}")
            return None

    def check_ip(self, ip: str) -> List[IOCMatch]:
        """Check an IP address against feeds."""
        return self.check_value(ip, IOCType.IP_ADDRESS)

    def check_domain(self, domain: str) -> List[IOCMatch]:
        """Check a domain against feeds."""
        matches = self.check_value(domain, IOCType.DOMAIN)

        # Also check wildcard patterns
        domain_lower = domain.lower()
        for pattern, entry in self._domain_patterns:
            if pattern.match(domain_lower):
                matches.append(IOCMatch(
                    ioc=entry,
                    matched_value=domain,
                ))

        return matches

    def check_hash(self, hash_value: str) -> List[IOCMatch]:
        """Check a file hash against feeds."""
        hash_lower = hash_value.lower()
        matches = []

        # Try all hash types
        entries = self._hash_index.get(hash_lower, [])
        for entry in entries:
            if not entry.is_expired:
                matches.append(IOCMatch(ioc=entry, matched_value=hash_value))

        self._update_stats(1, len(matches))
        return matches

    def check_url(self, url: str) -> List[IOCMatch]:
        """Check a URL against feeds."""
        return self.check_value(url, IOCType.URL)

    def check_value(self, value: str, ioc_type: IOCType) -> List[IOCMatch]:
        """Check a value against feeds."""
        matches: List[IOCMatch] = []
        value_lower = value.lower()

        with self._lock:
            # Get appropriate index
            if ioc_type == IOCType.IP_ADDRESS:
                index = self._ip_index
            elif ioc_type == IOCType.DOMAIN:
                index = self._domain_index
            elif ioc_type in (IOCType.FILE_HASH_MD5, IOCType.FILE_HASH_SHA1, IOCType.FILE_HASH_SHA256):
                index = self._hash_index
            elif ioc_type == IOCType.URL:
                index = self._url_index
            else:
                index = self._generic_index.get(ioc_type.value, {})

            entries = index.get(value_lower, [])
            for entry in entries:
                if not entry.is_expired:
                    matches.append(IOCMatch(
                        ioc=entry,
                        matched_value=value,
                    ))

        self._update_stats(1, len(matches))
        return matches

    def check_multiple(
        self,
        values: List[tuple[str, IOCType]],
    ) -> Dict[str, List[IOCMatch]]:
        """Check multiple values at once."""
        results = {}
        for value, ioc_type in values:
            matches = self.check_value(value, ioc_type)
            if matches:
                results[value] = matches
        return results

    def _update_stats(self, checks: int, matches: int) -> None:
        """Update statistics."""
        self._checks_performed += checks
        self._matches_found += matches

    def get_stats(self) -> Dict[str, Any]:
        """Get manager statistics."""
        total_entries = sum(f.entry_count for f in self._feeds.values())
        return {
            'feeds_loaded': len(self._feeds),
            'total_entries': total_entries,
            'indexed_ips': len(self._ip_index),
            'indexed_domains': len(self._domain_index),
            'indexed_hashes': len(self._hash_index),
            'checks_performed': self._checks_performed,
            'matches_found': self._matches_found,
        }

    def export_feed(
        self,
        feed_name: str,
        output_path: str,
        sign_with: Optional[bytes] = None,
    ) -> bool:
        """Export a feed to JSON, optionally signed."""
        feed = self._feeds.get(feed_name)
        if not feed:
            return False

        try:
            data = {
                'name': feed.name,
                'version': feed.version,
                'provider': feed.provider,
                'entries': [
                    {
                        'value': e.value,
                        'type': e.ioc_type.value,
                        'category': e.category.value,
                        'confidence': e.confidence.value,
                        'description': e.description,
                        'tags': e.tags,
                    }
                    for e in feed.entries
                ],
            }

            # Sign if key provided
            if sign_with and NACL_AVAILABLE:
                signing_key = nacl.signing.SigningKey(sign_with)
                content = json.dumps({
                    'name': feed.name,
                    'version': feed.version,
                    'entries': [
                        {'value': e.value, 'type': e.ioc_type.value, 'category': e.category.value}
                        for e in feed.entries
                    ],
                }, sort_keys=True)

                signed = signing_key.sign(content.encode())
                data['signature'] = signed.signature.hex()
                data['public_key'] = signing_key.verify_key.encode(
                    encoder=nacl.encoding.HexEncoder
                ).decode()

            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)

            return True

        except Exception as e:
            logger.error(f"Failed to export feed: {e}")
            return False


# Sample IOC feed for testing
SAMPLE_IOC_FEED = {
    "name": "sample_threats",
    "version": "1.0",
    "provider": "BoundaryDaemon",
    "entries": [
        {
            "value": "192.168.1.100",
            "type": "ip",
            "category": "suspicious",
            "confidence": "low",
            "description": "Test suspicious IP",
        },
        {
            "value": "evil-domain.com",
            "type": "domain",
            "category": "c2",
            "confidence": "high",
            "description": "Known C2 domain",
        },
        {
            "value": "*.malware-cdn.net",
            "type": "domain",
            "category": "malware",
            "confidence": "high",
            "description": "Malware CDN wildcard",
        },
        {
            "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "type": "sha256",
            "category": "malware",
            "confidence": "confirmed",
            "description": "Known malware hash",
        },
    ]
}


if __name__ == '__main__':
    print("Testing IOC Feed Manager...")

    # Create manager (allow unsigned for testing)
    manager = IOCFeedManager(require_signatures=False)

    # Parse and add sample feed
    feed = manager._parse_feed(SAMPLE_IOC_FEED, "sample")
    if feed:
        manager.add_feed(feed)

    print(f"\nStats: {manager.get_stats()}")

    # Test lookups
    test_cases = [
        ("192.168.1.100", IOCType.IP_ADDRESS),
        ("evil-domain.com", IOCType.DOMAIN),
        ("test.malware-cdn.net", IOCType.DOMAIN),
        ("safe-domain.com", IOCType.DOMAIN),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IOCType.FILE_HASH_SHA256),
    ]

    print("\nIOC Lookups:")
    for value, ioc_type in test_cases:
        if ioc_type == IOCType.DOMAIN:
            matches = manager.check_domain(value)
        else:
            matches = manager.check_value(value, ioc_type)

        if matches:
            for match in matches:
                print(f"  {value}: MATCH - {match.ioc.category.value} ({match.ioc.confidence.value})")
        else:
            print(f"  {value}: clean")

    print(f"\nFinal stats: {manager.get_stats()}")
    print("\nIOC feed manager test complete.")
