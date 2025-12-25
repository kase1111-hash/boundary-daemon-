"""
Threat Intelligence Integration Module

Provides threat intelligence capabilities including:
- IP reputation checking (AbuseIPDB, VirusTotal)
- Known C2 server/botnet IP detection
- TOR exit node detection
- Threat feed integration
- Local threat caching
"""

import threading
import time
import socket
import re
import os
import json
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict
import urllib.request
import urllib.error


class ThreatCategory(Enum):
    """Categories of threats"""
    MALWARE = "malware"
    BOTNET = "botnet"
    C2_SERVER = "c2_server"
    PHISHING = "phishing"
    SPAM = "spam"
    TOR_EXIT = "tor_exit"
    VPN_PROXY = "vpn_proxy"
    SCANNER = "scanner"
    BRUTEFORCE = "bruteforce"
    EXPLOIT = "exploit"
    CRYPTOMINER = "cryptominer"
    RANSOMWARE = "ransomware"
    APT = "apt"
    UNKNOWN = "unknown"


class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"  # 90-100 confidence
    HIGH = "high"          # 70-89 confidence
    MEDIUM = "medium"      # 40-69 confidence
    LOW = "low"            # 10-39 confidence
    INFO = "info"          # 0-9 confidence or informational


class ThreatIntelAlert(Enum):
    """Types of threat intelligence alerts"""
    MALICIOUS_IP = "malicious_ip"
    C2_COMMUNICATION = "c2_communication"
    BOTNET_IP = "botnet_ip"
    TOR_EXIT_NODE = "tor_exit_node"
    KNOWN_ATTACKER = "known_attacker"
    BLACKLISTED_IP = "blacklisted_ip"
    SUSPICIOUS_CONNECTION = "suspicious_connection"


@dataclass
class ThreatIntelConfig:
    """Configuration for threat intelligence"""
    # API Keys (optional - works without them using local lists)
    abuseipdb_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None

    # Detection settings
    enable_ip_reputation: bool = True
    enable_c2_detection: bool = True
    enable_tor_detection: bool = True
    enable_local_blacklist: bool = True

    # Caching
    cache_ttl_seconds: int = 3600  # 1 hour cache
    max_cache_size: int = 10000

    # Thresholds
    min_abuse_confidence: int = 50  # Minimum AbuseIPDB confidence score
    alert_on_tor: bool = True  # Alert when TOR exit nodes are detected

    # Rate limiting
    max_api_calls_per_minute: int = 60

    # Local threat feeds (URLs to fetch)
    threat_feed_urls: List[str] = field(default_factory=list)

    # Whitelist
    whitelisted_ips: Set[str] = field(default_factory=set)
    whitelisted_domains: Set[str] = field(default_factory=set)


@dataclass
class ThreatInfo:
    """Information about a detected threat"""
    ip: str
    categories: List[ThreatCategory]
    severity: ThreatSeverity
    confidence_score: int  # 0-100
    source: str  # Where the threat info came from
    first_seen: datetime
    last_seen: datetime
    details: Dict = field(default_factory=dict)
    is_tor_exit: bool = False
    is_c2: bool = False
    is_botnet: bool = False


@dataclass
class ThreatIntelStatus:
    """Current threat intelligence status"""
    is_active: bool = False
    last_update: Optional[datetime] = None
    cached_threats: int = 0
    known_tor_exits: int = 0
    known_c2_servers: int = 0
    alerts: List[str] = field(default_factory=list)
    api_calls_remaining: int = 0
    threats_detected: int = 0


class ThreatIntelMonitor:
    """Monitors network connections for known threats"""

    # Well-known malicious IP ranges (for demonstration - real systems use feeds)
    KNOWN_MALICIOUS_RANGES = [
        # Reserved for documentation/testing - used as examples
        "192.0.2.",      # TEST-NET-1
        "198.51.100.",   # TEST-NET-2
        "203.0.113.",    # TEST-NET-3
    ]

    # Known C2 server patterns (simplified for demonstration)
    KNOWN_C2_PATTERNS = [
        # Domain patterns commonly used by malware
        r"^[a-z0-9]{16,}\.(com|net|org|info|biz)$",  # DGA-like domains
        r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.bc\.googleusercontent\.com$",
    ]

    def __init__(self, config: Optional[ThreatIntelConfig] = None):
        self.config = config or ThreatIntelConfig()
        self.status = ThreatIntelStatus()
        self._lock = threading.RLock()

        # Threat cache: IP -> ThreatInfo
        self._threat_cache: Dict[str, ThreatInfo] = {}
        self._cache_timestamps: Dict[str, datetime] = {}

        # Known threat lists
        self._tor_exit_nodes: Set[str] = set()
        self._known_c2_servers: Set[str] = set()
        self._known_botnets: Set[str] = set()
        self._local_blacklist: Set[str] = set()

        # API rate limiting
        self._api_calls: List[datetime] = []

        # Connection tracking
        self._connection_history: Dict[str, List[datetime]] = defaultdict(list)

        # Initialize with built-in threat data
        self._initialize_threat_data()

    def _initialize_threat_data(self):
        """Initialize with built-in threat intelligence data"""
        # Sample TOR exit nodes (in real systems, fetch from https://check.torproject.org/exit-addresses)
        self._sample_tor_exits = {
            "185.220.101.1", "185.220.101.2", "185.220.101.3",
            "185.220.102.1", "185.220.102.2", "185.220.102.3",
            "104.244.72.1", "104.244.73.1", "104.244.74.1",
            "199.249.230.1", "199.249.230.2",
            "45.66.35.1", "45.66.35.2",
            "91.132.147.1", "91.132.147.2",
        }

        # Sample known C2 servers (for testing)
        self._sample_c2_servers = {
            "45.33.32.156",    # Example malware C2
            "198.51.100.50",   # Test net - simulated C2
            "203.0.113.100",   # Test net - simulated C2
        }

        # Sample botnet IPs
        self._sample_botnets = {
            "192.0.2.100",     # Test net - simulated botnet
            "198.51.100.200",  # Test net - simulated botnet
        }

        # Initialize with sample data (real systems would fetch from feeds)
        self._tor_exit_nodes.update(self._sample_tor_exits)
        self._known_c2_servers.update(self._sample_c2_servers)
        self._known_botnets.update(self._sample_botnets)

        self.status.known_tor_exits = len(self._tor_exit_nodes)
        self.status.known_c2_servers = len(self._known_c2_servers)

    def check_ip(self, ip: str) -> Optional[ThreatInfo]:
        """
        Check an IP address against threat intelligence sources

        Args:
            ip: IP address to check

        Returns:
            ThreatInfo if threat detected, None otherwise
        """
        if not ip or not self._is_valid_ip(ip):
            return None

        # Check whitelist first
        if ip in self.config.whitelisted_ips:
            return None

        # Skip private/local IPs
        if self._is_private_ip(ip):
            return None

        with self._lock:
            # Check cache first
            cached = self._get_from_cache(ip)
            if cached is not None:
                return cached

            threat_info = self._analyze_ip(ip)

            if threat_info:
                self._add_to_cache(ip, threat_info)
                self.status.threats_detected += 1

            return threat_info

    def _analyze_ip(self, ip: str) -> Optional[ThreatInfo]:
        """Analyze an IP against all threat sources"""
        categories = []
        max_confidence = 0
        details = {}
        is_tor = False
        is_c2 = False
        is_botnet = False
        source = "local"

        # Check TOR exit nodes
        if self.config.enable_tor_detection:
            if ip in self._tor_exit_nodes or self._check_tor_exit(ip):
                categories.append(ThreatCategory.TOR_EXIT)
                is_tor = True
                max_confidence = max(max_confidence, 95)
                details['tor_exit'] = True
                source = "tor_project"

        # Check known C2 servers
        if self.config.enable_c2_detection:
            if ip in self._known_c2_servers:
                categories.append(ThreatCategory.C2_SERVER)
                is_c2 = True
                max_confidence = max(max_confidence, 90)
                details['c2_server'] = True
                source = "c2_database"

        # Check known botnets
        if ip in self._known_botnets:
            categories.append(ThreatCategory.BOTNET)
            is_botnet = True
            max_confidence = max(max_confidence, 85)
            details['botnet'] = True
            source = "botnet_database"

        # Check local blacklist
        if self.config.enable_local_blacklist:
            if ip in self._local_blacklist:
                categories.append(ThreatCategory.MALWARE)
                max_confidence = max(max_confidence, 80)
                details['blacklisted'] = True
                source = "local_blacklist"

        # Check against known malicious ranges
        for range_prefix in self.KNOWN_MALICIOUS_RANGES:
            if ip.startswith(range_prefix):
                categories.append(ThreatCategory.MALWARE)
                max_confidence = max(max_confidence, 60)
                details['malicious_range'] = range_prefix
                source = "range_check"
                break

        # Check AbuseIPDB if API key is available
        if self.config.enable_ip_reputation and self.config.abuseipdb_api_key:
            abuse_result = self._check_abuseipdb(ip)
            if abuse_result:
                if abuse_result['confidence'] >= self.config.min_abuse_confidence:
                    categories.extend(abuse_result['categories'])
                    max_confidence = max(max_confidence, abuse_result['confidence'])
                    details['abuseipdb'] = abuse_result
                    source = "abuseipdb"

        # Check VirusTotal if API key is available
        if self.config.enable_ip_reputation and self.config.virustotal_api_key:
            vt_result = self._check_virustotal(ip)
            if vt_result and vt_result['malicious_count'] > 0:
                categories.append(ThreatCategory.MALWARE)
                vt_confidence = min(vt_result['malicious_count'] * 10, 100)
                max_confidence = max(max_confidence, vt_confidence)
                details['virustotal'] = vt_result
                source = "virustotal"

        if not categories:
            return None

        # Determine severity based on confidence
        severity = self._confidence_to_severity(max_confidence)

        now = datetime.now()
        return ThreatInfo(
            ip=ip,
            categories=list(set(categories)),
            severity=severity,
            confidence_score=max_confidence,
            source=source,
            first_seen=now,
            last_seen=now,
            details=details,
            is_tor_exit=is_tor,
            is_c2=is_c2,
            is_botnet=is_botnet
        )

    def _check_tor_exit(self, ip: str) -> bool:
        """Check if IP is a TOR exit node"""
        # Check against loaded list
        if ip in self._tor_exit_nodes:
            return True

        # Additional heuristic: check common TOR exit node ranges
        tor_ranges = [
            "185.220.100.", "185.220.101.", "185.220.102.", "185.220.103.",
            "104.244.72.", "104.244.73.", "104.244.74.", "104.244.75.",
            "199.249.230.", "199.249.231.",
            "45.66.35.",
            "91.132.147.",
            "178.17.170.", "178.17.171.",
            "82.221.128.", "82.221.129.", "82.221.130.", "82.221.131.",
        ]

        for tor_range in tor_ranges:
            if ip.startswith(tor_range):
                return True

        return False

    def _check_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Check IP against AbuseIPDB"""
        if not self._can_make_api_call():
            return None

        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
            req = urllib.request.Request(url)
            req.add_header('Key', self.config.abuseipdb_api_key)
            req.add_header('Accept', 'application/json')

            with urllib.request.urlopen(req, timeout=5) as response:
                self._record_api_call()
                data = json.loads(response.read().decode())

                if 'data' in data:
                    result = data['data']
                    categories = self._map_abuseipdb_categories(
                        result.get('usageType', ''),
                        result.get('totalReports', 0)
                    )
                    return {
                        'confidence': result.get('abuseConfidenceScore', 0),
                        'categories': categories,
                        'total_reports': result.get('totalReports', 0),
                        'country': result.get('countryCode', ''),
                        'isp': result.get('isp', ''),
                        'domain': result.get('domain', ''),
                    }

        except (urllib.error.URLError, urllib.error.HTTPError, Exception):
            pass

        return None

    def _check_virustotal(self, ip: str) -> Optional[Dict]:
        """Check IP against VirusTotal"""
        if not self._can_make_api_call():
            return None

        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            req = urllib.request.Request(url)
            req.add_header('x-apikey', self.config.virustotal_api_key)

            with urllib.request.urlopen(req, timeout=5) as response:
                self._record_api_call()
                data = json.loads(response.read().decode())

                if 'data' in data and 'attributes' in data['data']:
                    attrs = data['data']['attributes']
                    stats = attrs.get('last_analysis_stats', {})
                    return {
                        'malicious_count': stats.get('malicious', 0),
                        'suspicious_count': stats.get('suspicious', 0),
                        'harmless_count': stats.get('harmless', 0),
                        'undetected_count': stats.get('undetected', 0),
                        'country': attrs.get('country', ''),
                        'asn': attrs.get('asn', ''),
                        'as_owner': attrs.get('as_owner', ''),
                    }

        except (urllib.error.URLError, urllib.error.HTTPError, Exception):
            pass

        return None

    def _map_abuseipdb_categories(self, usage_type: str, report_count: int) -> List[ThreatCategory]:
        """Map AbuseIPDB usage type to threat categories"""
        categories = []

        usage_lower = usage_type.lower()

        if 'malware' in usage_lower or 'virus' in usage_lower:
            categories.append(ThreatCategory.MALWARE)
        if 'botnet' in usage_lower:
            categories.append(ThreatCategory.BOTNET)
        if 'spam' in usage_lower:
            categories.append(ThreatCategory.SPAM)
        if 'phish' in usage_lower:
            categories.append(ThreatCategory.PHISHING)
        if 'scan' in usage_lower:
            categories.append(ThreatCategory.SCANNER)
        if 'brute' in usage_lower:
            categories.append(ThreatCategory.BRUTEFORCE)
        if 'exploit' in usage_lower:
            categories.append(ThreatCategory.EXPLOIT)
        if 'vpn' in usage_lower or 'proxy' in usage_lower:
            categories.append(ThreatCategory.VPN_PROXY)

        # If no specific category but high reports, mark as unknown threat
        if not categories and report_count > 10:
            categories.append(ThreatCategory.UNKNOWN)

        return categories

    def _confidence_to_severity(self, confidence: int) -> ThreatSeverity:
        """Convert confidence score to severity level"""
        if confidence >= 90:
            return ThreatSeverity.CRITICAL
        elif confidence >= 70:
            return ThreatSeverity.HIGH
        elif confidence >= 40:
            return ThreatSeverity.MEDIUM
        elif confidence >= 10:
            return ThreatSeverity.LOW
        else:
            return ThreatSeverity.INFO

    def analyze_connection(self, src_ip: str, dst_ip: str,
                          port: int = 0, protocol: str = "tcp") -> List[Dict]:
        """
        Analyze a network connection for threats

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            port: Destination port
            protocol: Protocol (tcp, udp, etc.)

        Returns:
            List of threat alerts
        """
        alerts = []

        with self._lock:
            # Track connection
            self._record_connection(dst_ip)

            # Check destination IP
            dst_threat = self.check_ip(dst_ip)
            if dst_threat:
                alert = self._create_alert(dst_threat, dst_ip, port, "outbound")
                alerts.append(alert)
                self.status.alerts.append(alert['message'])

            # Check source IP (for inbound connections)
            if not self._is_private_ip(src_ip):
                src_threat = self.check_ip(src_ip)
                if src_threat:
                    alert = self._create_alert(src_threat, src_ip, port, "inbound")
                    alerts.append(alert)
                    self.status.alerts.append(alert['message'])

            # Check for suspicious connection patterns
            pattern_alerts = self._check_connection_patterns(dst_ip, port)
            alerts.extend(pattern_alerts)

        return alerts

    def _create_alert(self, threat: ThreatInfo, ip: str,
                     port: int, direction: str) -> Dict:
        """Create a threat alert"""
        alert_type = ThreatIntelAlert.MALICIOUS_IP

        if threat.is_tor_exit:
            alert_type = ThreatIntelAlert.TOR_EXIT_NODE
        elif threat.is_c2:
            alert_type = ThreatIntelAlert.C2_COMMUNICATION
        elif threat.is_botnet:
            alert_type = ThreatIntelAlert.BOTNET_IP

        categories_str = ", ".join(c.value for c in threat.categories)
        message = f"{alert_type.value}: {direction} connection to {ip}"
        if port:
            message += f":{port}"
        message += f" ({categories_str}, confidence: {threat.confidence_score}%)"

        return {
            "type": alert_type.value,
            "message": message,
            "severity": threat.severity.value,
            "timestamp": datetime.now().isoformat(),
            "details": {
                "ip": ip,
                "port": port,
                "direction": direction,
                "categories": [c.value for c in threat.categories],
                "confidence": threat.confidence_score,
                "source": threat.source,
                "is_tor": threat.is_tor_exit,
                "is_c2": threat.is_c2,
                "is_botnet": threat.is_botnet,
            }
        }

    def _check_connection_patterns(self, ip: str, port: int) -> List[Dict]:
        """Check for suspicious connection patterns"""
        alerts = []

        # Check for rapid connections to same IP (beaconing)
        if ip in self._connection_history:
            recent = [t for t in self._connection_history[ip]
                     if (datetime.now() - t).seconds < 60]

            if len(recent) >= 10:
                alert = {
                    "type": ThreatIntelAlert.SUSPICIOUS_CONNECTION.value,
                    "message": f"Rapid connections to {ip} ({len(recent)} in last minute) - possible beaconing",
                    "severity": ThreatSeverity.MEDIUM.value,
                    "timestamp": datetime.now().isoformat(),
                    "details": {
                        "ip": ip,
                        "connection_count": len(recent),
                        "timeframe": "60 seconds"
                    }
                }
                alerts.append(alert)
                self.status.alerts.append(alert['message'])

        # Check for connections to suspicious ports
        suspicious_ports = {
            4444: "Metasploit default",
            5555: "Android ADB",
            6666: "IRC botnet",
            6667: "IRC",
            8080: "Proxy/C2",
            31337: "Elite/Back Orifice",
            12345: "NetBus",
            65535: "RC1 Trojan",
        }

        if port in suspicious_ports:
            alert = {
                "type": ThreatIntelAlert.SUSPICIOUS_CONNECTION.value,
                "message": f"Connection to suspicious port {ip}:{port} ({suspicious_ports[port]})",
                "severity": ThreatSeverity.MEDIUM.value,
                "timestamp": datetime.now().isoformat(),
                "details": {
                    "ip": ip,
                    "port": port,
                    "port_info": suspicious_ports[port]
                }
            }
            alerts.append(alert)
            self.status.alerts.append(alert['message'])

        return alerts

    def _record_connection(self, ip: str):
        """Record a connection for pattern analysis"""
        self._connection_history[ip].append(datetime.now())

        # Clean old entries
        cutoff = datetime.now() - timedelta(minutes=5)
        self._connection_history[ip] = [
            t for t in self._connection_history[ip] if t > cutoff
        ]

    def add_to_blacklist(self, ip: str):
        """Add an IP to the local blacklist"""
        with self._lock:
            self._local_blacklist.add(ip)

    def add_to_whitelist(self, ip: str):
        """Add an IP to the whitelist"""
        with self._lock:
            self.config.whitelisted_ips.add(ip)

    def add_tor_exit(self, ip: str):
        """Add a known TOR exit node"""
        with self._lock:
            self._tor_exit_nodes.add(ip)
            self.status.known_tor_exits = len(self._tor_exit_nodes)

    def add_c2_server(self, ip: str):
        """Add a known C2 server"""
        with self._lock:
            self._known_c2_servers.add(ip)
            self.status.known_c2_servers = len(self._known_c2_servers)

    def add_botnet_ip(self, ip: str):
        """Add a known botnet IP"""
        with self._lock:
            self._known_botnets.add(ip)

    def _get_from_cache(self, ip: str) -> Optional[ThreatInfo]:
        """Get threat info from cache if not expired"""
        if ip in self._threat_cache and ip in self._cache_timestamps:
            cache_time = self._cache_timestamps[ip]
            if (datetime.now() - cache_time).seconds < self.config.cache_ttl_seconds:
                return self._threat_cache[ip]
            else:
                # Expired - remove from cache
                del self._threat_cache[ip]
                del self._cache_timestamps[ip]
        return None

    def _add_to_cache(self, ip: str, threat: ThreatInfo):
        """Add threat info to cache"""
        # Enforce cache size limit
        if len(self._threat_cache) >= self.config.max_cache_size:
            # Remove oldest entries
            oldest = sorted(self._cache_timestamps.items(), key=lambda x: x[1])[:100]
            for old_ip, _ in oldest:
                self._threat_cache.pop(old_ip, None)
                self._cache_timestamps.pop(old_ip, None)

        self._threat_cache[ip] = threat
        self._cache_timestamps[ip] = datetime.now()
        self.status.cached_threats = len(self._threat_cache)

    def _can_make_api_call(self) -> bool:
        """Check if we can make an API call (rate limiting)"""
        now = datetime.now()
        cutoff = now - timedelta(minutes=1)

        # Clean old API calls
        self._api_calls = [t for t in self._api_calls if t > cutoff]

        # Check rate limit
        return len(self._api_calls) < self.config.max_api_calls_per_minute

    def _record_api_call(self):
        """Record an API call for rate limiting"""
        self._api_calls.append(datetime.now())
        self.status.api_calls_remaining = (
            self.config.max_api_calls_per_minute - len(self._api_calls)
        )

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/reserved"""
        private_ranges = [
            "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168.", "127.", "0.",
            "169.254.",  # Link-local
            "224.",  # Multicast
        ]

        for prefix in private_ranges:
            if ip.startswith(prefix):
                return True

        return False

    def get_status(self) -> ThreatIntelStatus:
        """Get current threat intelligence status"""
        with self._lock:
            self.status.last_update = datetime.now()
            return self.status

    def get_threat_summary(self) -> Dict:
        """Get a summary of threat intelligence status"""
        with self._lock:
            return {
                "is_active": self.status.is_active,
                "cached_threats": self.status.cached_threats,
                "known_tor_exits": self.status.known_tor_exits,
                "known_c2_servers": self.status.known_c2_servers,
                "known_botnets": len(self._known_botnets),
                "local_blacklist_size": len(self._local_blacklist),
                "threats_detected": self.status.threats_detected,
                "active_alerts": len(self.status.alerts),
                "api_calls_remaining": self.status.api_calls_remaining,
                "last_update": self.status.last_update.isoformat() if self.status.last_update else None
            }

    def clear_alerts(self):
        """Clear all active alerts"""
        with self._lock:
            self.status.alerts = []

    def clear_cache(self):
        """Clear the threat cache"""
        with self._lock:
            self._threat_cache.clear()
            self._cache_timestamps.clear()
            self.status.cached_threats = 0
