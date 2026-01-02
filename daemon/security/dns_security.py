"""
DNS Security Monitor - Detects AND BLOCKS DNS-based attacks and anomalies.

Features:
- DNS spoofing/cache poisoning detection AND BLOCKING
- DNS tunneling/exfiltration detection AND BLOCKING
- DoH/DoT (secure DNS) enforcement verification
- DNS query anomaly detection
- ENFORCEMENT via iptables/nftables domain blocking
- Hosts file poisoning for immediate blocking
- Response Policy Zone (RPZ) integration

SECURITY: This module now provides ACTUAL ENFORCEMENT, not just detection.
Addresses Critical Finding: "Detection Without Enforcement"

SECURITY: External DNS queries and domain resolution are blocked in AIRGAP,
COLDROOM, and LOCKDOWN modes to prevent data leakage.
Addresses Critical Finding: "AIRGAP Mode Leaks Network Traffic"

SECURITY: DNS response verification now uses pure Python sockets instead of
external tools (dig, nslookup). This addresses the vulnerability:
"DNS Response Verification Uses External Tools"
"""

import os
import re
import socket
import subprocess
import threading
import time
import shutil
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Callable
from enum import Enum
from collections import defaultdict, deque
import hashlib
import sys

logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = sys.platform == 'win32'

# Cross-platform privilege detection
def _is_elevated() -> bool:
    """Check if running with elevated privileges (cross-platform)."""
    if sys.platform == 'win32':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0

# Import native DNS resolver (SECURITY: replaces external tool usage)
try:
    from .native_dns_resolver import (
        NativeDNSResolver,
        SecureDNSVerifier,
        DNSType,
    )
    NATIVE_DNS_AVAILABLE = True
except ImportError:
    NATIVE_DNS_AVAILABLE = False
    NativeDNSResolver = None
    SecureDNSVerifier = None
    DNSType = None


class DNSSecurityAlert(Enum):
    """Types of DNS security alerts"""
    NONE = "none"
    SPOOFING_DETECTED = "spoofing_detected"
    CACHE_POISONING = "cache_poisoning"
    TUNNELING_DETECTED = "tunneling_detected"
    EXFILTRATION_SUSPECTED = "exfiltration_suspected"
    INSECURE_DNS = "insecure_dns"
    HIGH_QUERY_RATE = "high_query_rate"
    SUSPICIOUS_TLD = "suspicious_tld"
    DNS_REBINDING = "dns_rebinding"


@dataclass
class DNSQueryRecord:
    """Record of a DNS query for analysis"""
    domain: str
    query_type: str  # A, AAAA, TXT, MX, etc.
    timestamp: datetime
    response_ips: List[str]
    response_time_ms: float
    resolver: str


class DNSEnforcementAction(Enum):
    """Actions to take when DNS threat is detected"""
    LOG_ONLY = "log_only"           # Just log (detection mode)
    BLOCK_HOSTS = "block_hosts"     # Add to /etc/hosts pointing to 0.0.0.0
    BLOCK_FIREWALL = "block_firewall"  # Block via iptables/nftables
    BLOCK_BOTH = "block_both"       # Both hosts and firewall
    SINKHOLE = "sinkhole"           # Redirect to sinkhole IP


@dataclass
class DNSSecurityConfig:
    """Configuration for DNS security monitoring AND ENFORCEMENT"""
    # Detection toggles
    detect_spoofing: bool = True
    detect_tunneling: bool = True
    detect_exfiltration: bool = True
    enforce_secure_dns: bool = False  # Warn if not using DoH/DoT

    # ENFORCEMENT toggles (NEW)
    enforcement_enabled: bool = True  # Master switch for enforcement
    enforcement_action: DNSEnforcementAction = DNSEnforcementAction.BLOCK_BOTH
    auto_block_tunneling: bool = True  # Auto-block detected tunneling domains
    auto_block_suspicious_tld: bool = False  # Auto-block suspicious TLDs (can cause false positives)
    auto_block_spoofing: bool = True  # Block domains with detected spoofing
    auto_block_rebinding: bool = True  # Block domains attempting DNS rebinding

    # Sinkhole configuration
    sinkhole_ipv4: str = "0.0.0.0"  # Where to redirect blocked domains
    sinkhole_ipv6: str = "::"

    # Hosts file management
    hosts_file_path: str = "/etc/hosts"
    hosts_backup_path: str = "/etc/hosts.boundary-backup"
    hosts_marker_start: str = "# >>> BOUNDARY-DAEMON DNS BLOCKING START <<<"
    hosts_marker_end: str = "# >>> BOUNDARY-DAEMON DNS BLOCKING END <<<"

    # Thresholds
    max_subdomain_length: int = 50  # Longer subdomains may indicate tunneling
    max_label_count: int = 10  # Too many labels may indicate tunneling
    max_queries_per_minute: int = 100  # High query rate threshold
    max_txt_record_size: int = 255  # Large TXT records may indicate exfiltration

    # Known safe resolvers (DoH/DoT)
    secure_resolvers: List[str] = field(default_factory=lambda: [
        "1.1.1.1",        # Cloudflare
        "1.0.0.1",        # Cloudflare
        "8.8.8.8",        # Google
        "8.8.4.4",        # Google
        "9.9.9.9",        # Quad9
        "149.112.112.112", # Quad9
        "208.67.222.222",  # OpenDNS
        "208.67.220.220",  # OpenDNS
    ])

    # Suspicious TLDs often used in attacks
    suspicious_tlds: List[str] = field(default_factory=lambda: [
        ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs often abused
        ".top", ".xyz", ".club", ".work",   # Commonly abused TLDs
        ".zip", ".mov",  # Confusing TLDs
    ])

    # Whitelist - never block these domains
    whitelisted_domains: Set[str] = field(default_factory=lambda: {
        "localhost",
        "localhost.localdomain",
    })

    def to_dict(self) -> Dict:
        return {
            'detect_spoofing': self.detect_spoofing,
            'detect_tunneling': self.detect_tunneling,
            'detect_exfiltration': self.detect_exfiltration,
            'enforce_secure_dns': self.enforce_secure_dns,
            'enforcement_enabled': self.enforcement_enabled,
            'enforcement_action': self.enforcement_action.value,
            'auto_block_tunneling': self.auto_block_tunneling,
            'auto_block_spoofing': self.auto_block_spoofing,
            'max_subdomain_length': self.max_subdomain_length,
            'max_queries_per_minute': self.max_queries_per_minute,
        }


@dataclass
class DNSSecurityStatus:
    """Current DNS security status"""
    alerts: List[str]
    is_secure_dns: bool
    current_resolver: str
    query_rate_per_minute: float
    suspicious_domains: List[str]
    potential_tunneling_domains: List[str]
    last_check: str
    # Enforcement status (NEW)
    enforcement_enabled: bool = False
    blocked_domains_count: int = 0
    blocked_domains: List[str] = field(default_factory=list)
    enforcement_action: str = "log_only"

    def to_dict(self) -> Dict:
        return {
            'alerts': self.alerts,
            'is_secure_dns': self.is_secure_dns,
            'current_resolver': self.current_resolver,
            'query_rate_per_minute': self.query_rate_per_minute,
            'suspicious_domains': self.suspicious_domains,
            'potential_tunneling_domains': self.potential_tunneling_domains,
            'last_check': self.last_check,
            'enforcement_enabled': self.enforcement_enabled,
            'blocked_domains_count': self.blocked_domains_count,
            'blocked_domains': self.blocked_domains[:20],  # Limit for display
            'enforcement_action': self.enforcement_action,
        }


class DNSSecurityMonitor:
    """
    Monitors DNS traffic for security threats AND ENFORCES BLOCKING.

    Detection AND Enforcement capabilities:
    1. DNS Spoofing: Detects when DNS responses don't match expected values -> BLOCKS
    2. Cache Poisoning: Monitors for suspicious DNS cache changes -> BLOCKS
    3. DNS Tunneling: Detects encoded data in DNS queries (exfiltration) -> BLOCKS
    4. Secure DNS: Verifies DoH/DoT usage
    5. NEW: Hosts file blocking for immediate effect
    6. NEW: Firewall-level blocking via iptables/nftables

    SECURITY: This class now provides ACTUAL ENFORCEMENT, not just detection.

    SECURITY: External DNS queries are blocked in AIRGAP/COLDROOM/LOCKDOWN modes
    to prevent data leakage through DNS channels.
    """

    # iptables chain name for DNS blocking
    IPTABLES_CHAIN = "BOUNDARY_DNS_BLOCK"

    # Modes that block all external network access
    NETWORK_BLOCKED_MODES = {'AIRGAP', 'COLDROOM', 'LOCKDOWN'}

    def __init__(self, config: Optional[DNSSecurityConfig] = None,
                 event_logger=None,
                 on_block_callback: Optional[Callable[[str, str], None]] = None,
                 mode_getter: Optional[Callable[[], str]] = None):
        self.config = config or DNSSecurityConfig()
        self._event_logger = event_logger
        self._on_block_callback = on_block_callback  # Called when domain is blocked

        # SECURITY: Mode getter for network isolation enforcement
        self._get_mode = mode_getter

        # Track blocked operations for security auditing (bounded to prevent memory leak)
        self._blocked_dns_ops: deque = deque(maxlen=500)

        # Query tracking
        self._query_history: List[DNSQueryRecord] = []
        self._query_counts: Dict[str, int] = defaultdict(int)  # domain -> count
        self._last_minute_queries: List[datetime] = []

        # Baseline DNS responses for spoofing detection
        self._dns_baseline: Dict[str, Set[str]] = {}  # domain -> known good IPs

        # Known legitimate high-entropy domains (CDNs, cloud services)
        self._legitimate_high_entropy: Set[str] = {
            "cloudfront.net", "amazonaws.com", "akamaiedge.net",
            "cloudflare.com", "fastly.net", "azureedge.net",
            "googleusercontent.com", "gstatic.com",
        }

        # Tracking for rebinding detection
        self._domain_ip_history: Dict[str, List[Tuple[str, datetime]]] = defaultdict(list)

        # ENFORCEMENT: Blocked domains tracking (NEW)
        self._blocked_domains: Set[str] = set()  # Currently blocked domains
        self._block_reasons: Dict[str, str] = {}  # domain -> reason
        self._block_timestamps: Dict[str, datetime] = {}  # domain -> when blocked

        # Thread safety - use RLock for reentrant locking (get_status calls helpers that also lock)
        self._lock = threading.RLock()

        # Monitoring state
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None

        # Check enforcement capabilities (cross-platform)
        self._has_root = _is_elevated()
        self._has_iptables = shutil.which('iptables') is not None
        self._has_nftables = shutil.which('nft') is not None

        if self.config.enforcement_enabled and not self._has_root:
            if sys.platform == 'win32':
                logger.warning("DNS enforcement enabled but not running as Administrator. "
                              "Hosts file and firewall blocking may fail.")
            else:
                logger.warning("DNS enforcement enabled but not running as root. "
                              "Hosts file and firewall blocking may fail.")

        # SECURITY: Initialize native DNS resolver (no external tool dependencies)
        # This addresses: "DNS Response Verification Uses External Tools"
        self._native_resolver = None
        self._secure_verifier = None
        if NATIVE_DNS_AVAILABLE and NativeDNSResolver:
            try:
                self._native_resolver = NativeDNSResolver()
                self._secure_verifier = SecureDNSVerifier(event_logger=event_logger)
                logger.info("Native DNS resolver initialized (no external tools)")
            except Exception as e:
                logger.warning(f"Native DNS resolver failed to initialize: {e}")
        else:
            logger.warning("Native DNS resolver not available, falling back to external tools")

    def set_mode_getter(self, getter: Callable[[], str]):
        """Set the mode getter callback."""
        self._get_mode = getter

    def _is_network_blocked(self) -> bool:
        """
        Check if external network access is blocked in current mode.

        Returns:
            True if network access should be blocked (AIRGAP, COLDROOM, LOCKDOWN)
        """
        if not self._get_mode:
            return False  # No mode getter, assume network allowed

        try:
            current_mode = self._get_mode()
            if current_mode and current_mode.upper() in self.NETWORK_BLOCKED_MODES:
                return True
        except Exception:
            pass

        return False

    def _log_blocked_dns_op(self, operation: str, target: str, reason: str):
        """Log a blocked DNS operation for security auditing."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'operation': operation,
            'target': target,
            'reason': reason,
            'mode': self._get_mode() if self._get_mode else 'unknown',
        }
        self._blocked_dns_ops.append(entry)
        logger.warning(f"SECURITY: Blocked DNS {operation} for {target}: {reason}")

    def get_blocked_dns_operations(self) -> List[Dict]:
        """Get list of DNS operations blocked due to network isolation."""
        with self._lock:
            return list(self._blocked_dns_ops)

    def start(self):
        """Start continuous DNS monitoring"""
        if self._running:
            return

        self._running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def stop(self):
        """Stop DNS monitoring"""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                # Periodic checks
                self._check_resolver_security()
                self._cleanup_old_records()
                time.sleep(10)  # Check every 10 seconds
            except Exception as e:
                print(f"Error in DNS monitor loop: {e}")
                time.sleep(10)

    def get_status(self) -> DNSSecurityStatus:
        """Get current DNS security status"""
        with self._lock:
            alerts = self._get_current_alerts()
            is_secure, resolver = self._check_resolver_security()
            query_rate = self._calculate_query_rate()
            suspicious = self._get_suspicious_domains()
            tunneling = self._get_potential_tunneling_domains()

            return DNSSecurityStatus(
                alerts=alerts,
                is_secure_dns=is_secure,
                current_resolver=resolver,
                query_rate_per_minute=query_rate,
                suspicious_domains=suspicious[:10],  # Top 10
                potential_tunneling_domains=tunneling[:10],
                last_check=datetime.utcnow().isoformat() + "Z",
                # Enforcement status
                enforcement_enabled=self.config.enforcement_enabled,
                blocked_domains_count=len(self._blocked_domains),
                blocked_domains=list(self._blocked_domains)[:20],
                enforcement_action=self.config.enforcement_action.value,
            )

    # ==================== ENFORCEMENT METHODS (NEW) ====================

    def block_domain(self, domain: str, reason: str) -> Tuple[bool, str]:
        """
        Block a domain using configured enforcement method.

        Args:
            domain: Domain to block (e.g., "malicious.example.com")
            reason: Reason for blocking (for logging)

        Returns:
            (success, message)
        """
        if not self.config.enforcement_enabled:
            return (False, "Enforcement is disabled")

        # Check whitelist
        domain_lower = domain.lower().strip()
        if self._is_whitelisted(domain_lower):
            return (False, f"Domain {domain} is whitelisted")

        # Already blocked?
        if domain_lower in self._blocked_domains:
            return (True, f"Domain {domain} already blocked")

        success = False
        messages = []

        action = self.config.enforcement_action

        # Block via hosts file
        if action in (DNSEnforcementAction.BLOCK_HOSTS,
                      DNSEnforcementAction.BLOCK_BOTH,
                      DNSEnforcementAction.SINKHOLE):
            host_success, host_msg = self._block_via_hosts(domain_lower)
            messages.append(f"Hosts: {host_msg}")
            success = success or host_success

        # Block via firewall
        if action in (DNSEnforcementAction.BLOCK_FIREWALL,
                      DNSEnforcementAction.BLOCK_BOTH):
            fw_success, fw_msg = self._block_via_firewall(domain_lower)
            messages.append(f"Firewall: {fw_msg}")
            success = success or fw_success

        if success:
            with self._lock:
                self._blocked_domains.add(domain_lower)
                self._block_reasons[domain_lower] = reason
                self._block_timestamps[domain_lower] = datetime.utcnow()

            # Log the blocking event
            self._log_block_event(domain_lower, reason, action.value)

            # Invoke callback if set
            if self._on_block_callback:
                try:
                    self._on_block_callback(domain_lower, reason)
                except Exception as e:
                    logger.error(f"Block callback error: {e}")

        return (success, "; ".join(messages))

    def unblock_domain(self, domain: str) -> Tuple[bool, str]:
        """
        Unblock a previously blocked domain.

        Args:
            domain: Domain to unblock

        Returns:
            (success, message)
        """
        domain_lower = domain.lower().strip()

        if domain_lower not in self._blocked_domains:
            return (False, f"Domain {domain} is not blocked")

        success = False
        messages = []

        # Remove from hosts file
        host_success, host_msg = self._unblock_from_hosts(domain_lower)
        messages.append(f"Hosts: {host_msg}")
        success = success or host_success

        # Remove from firewall
        fw_success, fw_msg = self._unblock_from_firewall(domain_lower)
        messages.append(f"Firewall: {fw_msg}")
        success = success or fw_success

        if success:
            with self._lock:
                self._blocked_domains.discard(domain_lower)
                self._block_reasons.pop(domain_lower, None)
                self._block_timestamps.pop(domain_lower, None)

            self._log_unblock_event(domain_lower)

        return (success, "; ".join(messages))

    def get_blocked_domains(self) -> List[Dict]:
        """Get list of currently blocked domains with details."""
        with self._lock:
            result = []
            for domain in self._blocked_domains:
                result.append({
                    'domain': domain,
                    'reason': self._block_reasons.get(domain, 'unknown'),
                    'blocked_at': self._block_timestamps.get(
                        domain, datetime.utcnow()
                    ).isoformat() + "Z"
                })
            return sorted(result, key=lambda x: x['blocked_at'], reverse=True)

    def _is_whitelisted(self, domain: str) -> bool:
        """Check if domain is whitelisted."""
        # Exact match
        if domain in self.config.whitelisted_domains:
            return True
        # Check if it's a subdomain of a whitelisted domain
        for whitelisted in self.config.whitelisted_domains:
            if domain.endswith('.' + whitelisted):
                return True
        return False

    def _block_via_hosts(self, domain: str) -> Tuple[bool, str]:
        """
        Block domain by adding to /etc/hosts.

        This provides immediate blocking without firewall changes.
        """
        if not self._has_root:
            return (False, "Need root to modify hosts file")

        try:
            hosts_path = self.config.hosts_file_path
            backup_path = self.config.hosts_backup_path

            # Read current hosts file
            with open(hosts_path, 'r') as f:
                content = f.read()

            # Create backup if it doesn't exist
            if not os.path.exists(backup_path):
                with open(backup_path, 'w') as f:
                    f.write(content)
                os.chmod(backup_path, 0o644)

            # Find or create our blocking section
            marker_start = self.config.hosts_marker_start
            marker_end = self.config.hosts_marker_end

            if marker_start in content:
                # Extract existing blocked domains
                start_idx = content.index(marker_start)
                end_idx = content.index(marker_end) + len(marker_end)
                before = content[:start_idx]
                after = content[end_idx:]
                existing_section = content[start_idx:end_idx]

                # Parse existing blocked domains
                blocked_lines = []
                for line in existing_section.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        blocked_lines.append(line)

                # Add new domain
                sinkhole_v4 = self.config.sinkhole_ipv4
                sinkhole_v6 = self.config.sinkhole_ipv6
                new_entry_v4 = f"{sinkhole_v4} {domain}"
                new_entry_v6 = f"{sinkhole_v6} {domain}"

                if new_entry_v4 not in blocked_lines:
                    blocked_lines.append(new_entry_v4)
                if new_entry_v6 not in blocked_lines:
                    blocked_lines.append(new_entry_v6)

                # Rebuild section
                new_section = f"{marker_start}\n"
                new_section += '\n'.join(blocked_lines)
                new_section += f"\n{marker_end}"

                new_content = before + new_section + after
            else:
                # Create new section
                sinkhole_v4 = self.config.sinkhole_ipv4
                sinkhole_v6 = self.config.sinkhole_ipv6
                new_section = f"\n{marker_start}\n"
                new_section += f"{sinkhole_v4} {domain}\n"
                new_section += f"{sinkhole_v6} {domain}\n"
                new_section += f"{marker_end}\n"

                new_content = content + new_section

            # Write atomically
            temp_path = hosts_path + '.boundary-tmp'
            with open(temp_path, 'w') as f:
                f.write(new_content)
            os.chmod(temp_path, 0o644)
            os.rename(temp_path, hosts_path)

            logger.info(f"Blocked domain via hosts: {domain}")
            return (True, f"Added {domain} to hosts file")

        except Exception as e:
            logger.error(f"Failed to block via hosts: {e}")
            return (False, str(e))

    def _unblock_from_hosts(self, domain: str) -> Tuple[bool, str]:
        """Remove domain from hosts file blocking."""
        if not self._has_root:
            return (False, "Need root to modify hosts file")

        try:
            hosts_path = self.config.hosts_file_path
            marker_start = self.config.hosts_marker_start
            marker_end = self.config.hosts_marker_end

            with open(hosts_path, 'r') as f:
                content = f.read()

            if marker_start not in content:
                return (True, "No blocking section found")

            start_idx = content.index(marker_start)
            end_idx = content.index(marker_end) + len(marker_end)
            before = content[:start_idx]
            after = content[end_idx:]
            existing_section = content[start_idx:end_idx]

            # Remove lines containing this domain
            new_lines = []
            for line in existing_section.split('\n'):
                if domain not in line:
                    new_lines.append(line)

            new_section = '\n'.join(new_lines)

            # If section is now empty (just markers), remove it entirely
            if new_section.strip() == f"{marker_start}\n{marker_end}".strip():
                new_content = before.rstrip() + after
            else:
                new_content = before + new_section + after

            # Write atomically
            temp_path = hosts_path + '.boundary-tmp'
            with open(temp_path, 'w') as f:
                f.write(new_content)
            os.chmod(temp_path, 0o644)
            os.rename(temp_path, hosts_path)

            logger.info(f"Unblocked domain from hosts: {domain}")
            return (True, f"Removed {domain} from hosts file")

        except Exception as e:
            logger.error(f"Failed to unblock from hosts: {e}")
            return (False, str(e))

    def _block_via_firewall(self, domain: str) -> Tuple[bool, str]:
        """
        Block domain via iptables by resolving and blocking IPs.

        Note: This blocks by IP, so dynamic DNS may evade this.
        For comprehensive blocking, use hosts file method too.

        SECURITY: DNS resolution is blocked in AIRGAP/COLDROOM/LOCKDOWN modes
        to prevent data leakage through DNS queries.
        """
        if not self._has_root:
            return (False, "Need root for firewall rules")

        if not self._has_iptables:
            return (False, "iptables not available")

        # SECURITY: Block DNS resolution in network-isolated modes
        if self._is_network_blocked():
            self._log_blocked_dns_op(
                'firewall_block_resolve',
                domain,
                'DNS resolution blocked in current security mode'
            )
            return (False, "DNS resolution blocked: Network isolated mode active")

        try:
            # Resolve domain to IPs
            ips = set()
            try:
                # Get IPv4 addresses
                for info in socket.getaddrinfo(domain, None, socket.AF_INET):
                    ips.add(info[4][0])
            except socket.gaierror:
                pass

            try:
                # Get IPv6 addresses
                for info in socket.getaddrinfo(domain, None, socket.AF_INET6):
                    ips.add(info[4][0])
            except socket.gaierror:
                pass

            if not ips:
                return (False, f"Could not resolve {domain}")

            # Ensure our chain exists
            self._setup_iptables_chain()

            # Add block rules for each IP
            blocked_ips = []
            for ip in ips:
                if ':' in ip:
                    # IPv6
                    cmd = ['ip6tables', '-A', self.IPTABLES_CHAIN,
                           '-d', ip, '-j', 'DROP',
                           '-m', 'comment', '--comment', f'boundary-block-{domain}']
                else:
                    # IPv4
                    cmd = ['iptables', '-A', self.IPTABLES_CHAIN,
                           '-d', ip, '-j', 'DROP',
                           '-m', 'comment', '--comment', f'boundary-block-{domain}']

                result = subprocess.run(cmd, capture_output=True, timeout=5)
                if result.returncode == 0:
                    blocked_ips.append(ip)

            if blocked_ips:
                logger.info(f"Blocked domain via firewall: {domain} -> {blocked_ips}")
                return (True, f"Blocked IPs: {blocked_ips}")
            else:
                return (False, "Failed to add firewall rules")

        except Exception as e:
            logger.error(f"Failed to block via firewall: {e}")
            return (False, str(e))

    def _unblock_from_firewall(self, domain: str) -> Tuple[bool, str]:
        """Remove firewall rules for a domain."""
        if not self._has_root or not self._has_iptables:
            return (False, "Need root and iptables")

        try:
            # Remove rules matching the domain comment
            comment = f'boundary-block-{domain}'

            for iptables_cmd in ['iptables', 'ip6tables']:
                # List rules with line numbers
                result = subprocess.run(
                    [iptables_cmd, '-L', self.IPTABLES_CHAIN, '-n', '--line-numbers'],
                    capture_output=True, timeout=5
                )
                if result.returncode != 0:
                    continue

                # Find and delete rules (in reverse order to preserve line numbers)
                lines_to_delete = []
                for line in result.stdout.decode().split('\n'):
                    if comment in line:
                        parts = line.split()
                        if parts and parts[0].isdigit():
                            lines_to_delete.append(int(parts[0]))

                for line_num in reversed(sorted(lines_to_delete)):
                    subprocess.run(
                        [iptables_cmd, '-D', self.IPTABLES_CHAIN, str(line_num)],
                        capture_output=True, timeout=5
                    )

            logger.info(f"Unblocked domain from firewall: {domain}")
            return (True, f"Removed firewall rules for {domain}")

        except Exception as e:
            logger.error(f"Failed to unblock from firewall: {e}")
            return (False, str(e))

    def _setup_iptables_chain(self):
        """Ensure our iptables chain exists."""
        for iptables_cmd in ['iptables', 'ip6tables']:
            # Create chain if it doesn't exist
            subprocess.run(
                [iptables_cmd, '-N', self.IPTABLES_CHAIN],
                capture_output=True, timeout=5
            )

            # Check if jump rule exists in OUTPUT
            result = subprocess.run(
                [iptables_cmd, '-C', 'OUTPUT', '-j', self.IPTABLES_CHAIN],
                capture_output=True, timeout=5
            )
            if result.returncode != 0:
                # Add jump rule
                subprocess.run(
                    [iptables_cmd, '-I', 'OUTPUT', '1', '-j', self.IPTABLES_CHAIN],
                    capture_output=True, timeout=5
                )

    def _log_block_event(self, domain: str, reason: str, action: str):
        """Log a domain blocking event."""
        if self._event_logger:
            try:
                from ..event_logger import EventType
                self._event_logger.log_event(
                    event_type=EventType.VIOLATION,
                    data={
                        'event': 'dns_domain_blocked',
                        'domain': domain,
                        'reason': reason,
                        'action': action,
                        'timestamp': datetime.utcnow().isoformat() + "Z"
                    }
                )
            except Exception:
                pass

        logger.warning(f"DNS BLOCKED: {domain} - Reason: {reason} - Action: {action}")

    def _log_unblock_event(self, domain: str):
        """Log a domain unblocking event."""
        if self._event_logger:
            try:
                from ..event_logger import EventType
                self._event_logger.log_event(
                    event_type=EventType.POLICY_DECISION,
                    data={
                        'event': 'dns_domain_unblocked',
                        'domain': domain,
                        'timestamp': datetime.utcnow().isoformat() + "Z"
                    }
                )
            except Exception:
                pass

        logger.info(f"DNS UNBLOCKED: {domain}")

    def cleanup_enforcement(self):
        """Clean up all enforcement rules (call on shutdown)."""
        logger.info("Cleaning up DNS enforcement rules...")

        # Remove from hosts file
        try:
            hosts_path = self.config.hosts_file_path
            marker_start = self.config.hosts_marker_start
            marker_end = self.config.hosts_marker_end

            with open(hosts_path, 'r') as f:
                content = f.read()

            if marker_start in content and marker_end in content:
                start_idx = content.index(marker_start)
                end_idx = content.index(marker_end) + len(marker_end)
                new_content = content[:start_idx].rstrip() + content[end_idx:]

                temp_path = hosts_path + '.boundary-tmp'
                with open(temp_path, 'w') as f:
                    f.write(new_content)
                os.chmod(temp_path, 0o644)
                os.rename(temp_path, hosts_path)
                logger.info("Cleaned up hosts file")
        except Exception as e:
            logger.error(f"Failed to cleanup hosts file: {e}")

        # Remove iptables chain
        if self._has_iptables and self._has_root:
            for iptables_cmd in ['iptables', 'ip6tables']:
                try:
                    # Remove jump rule
                    subprocess.run(
                        [iptables_cmd, '-D', 'OUTPUT', '-j', self.IPTABLES_CHAIN],
                        capture_output=True, timeout=5
                    )
                    # Flush chain
                    subprocess.run(
                        [iptables_cmd, '-F', self.IPTABLES_CHAIN],
                        capture_output=True, timeout=5
                    )
                    # Delete chain
                    subprocess.run(
                        [iptables_cmd, '-X', self.IPTABLES_CHAIN],
                        capture_output=True, timeout=5
                    )
                except Exception:
                    pass
            logger.info("Cleaned up iptables rules")

        with self._lock:
            self._blocked_domains.clear()
            self._block_reasons.clear()
            self._block_timestamps.clear()

    # ==================== END ENFORCEMENT METHODS ====================

    def analyze_query(self, domain: str, query_type: str = "A",
                      auto_block: bool = True) -> List[str]:
        """
        Analyze a DNS query for security issues AND AUTO-BLOCK if threats detected.

        Args:
            domain: The domain being queried
            query_type: DNS record type (A, AAAA, TXT, etc.)
            auto_block: Whether to automatically block detected threats

        Returns:
            List of alert messages
        """
        alerts = []
        should_block = False
        block_reason = ""

        # Check for tunneling indicators
        if self.config.detect_tunneling:
            tunneling_alerts = self._detect_tunneling(domain)
            alerts.extend(tunneling_alerts)
            if tunneling_alerts and self.config.auto_block_tunneling:
                should_block = True
                block_reason = "DNS tunneling/exfiltration detected"

        # Check for suspicious TLDs
        tld_alerts = self._check_suspicious_tld(domain)
        alerts.extend(tld_alerts)
        if tld_alerts and self.config.auto_block_suspicious_tld:
            should_block = True
            block_reason = block_reason or "Suspicious TLD"

        # Track query rate
        self._record_query(domain, query_type)

        # Check for high query rate
        if self._calculate_query_rate() > self.config.max_queries_per_minute:
            alerts.append(f"{DNSSecurityAlert.HIGH_QUERY_RATE.value}: "
                         f"Query rate exceeds {self.config.max_queries_per_minute}/min")

        # AUTO-BLOCK if threats detected (NEW ENFORCEMENT)
        if should_block and auto_block and self.config.enforcement_enabled:
            success, msg = self.block_domain(domain, block_reason)
            if success:
                alerts.append(f"BLOCKED: {domain} - {block_reason}")
            else:
                alerts.append(f"BLOCK FAILED for {domain}: {msg}")

        return alerts

    def analyze_response(self, domain: str, response_ips: List[str],
                        response_time_ms: float,
                        auto_block: bool = True) -> List[str]:
        """
        Analyze a DNS response for spoofing/poisoning AND AUTO-BLOCK if detected.

        Args:
            domain: The queried domain
            response_ips: IP addresses in the response
            response_time_ms: Response time in milliseconds
            auto_block: Whether to automatically block detected threats

        Returns:
            List of alert messages
        """
        alerts = []
        should_block = False
        block_reason = ""

        if not self.config.detect_spoofing:
            return alerts

        # Check for DNS rebinding (rapid IP changes)
        rebinding_alert = self._detect_rebinding(domain, response_ips)
        if rebinding_alert:
            alerts.append(rebinding_alert)
            if self.config.auto_block_rebinding:
                should_block = True
                block_reason = "DNS rebinding attack detected"

        # Check against baseline
        spoofing_alert = self._detect_spoofing(domain, response_ips)
        if spoofing_alert:
            alerts.append(spoofing_alert)
            if self.config.auto_block_spoofing:
                should_block = True
                block_reason = block_reason or "DNS spoofing detected"

        # Unusually fast response might indicate local spoofing
        if response_time_ms < 1.0 and not self._is_cached_response(domain):
            alerts.append(f"{DNSSecurityAlert.SPOOFING_DETECTED.value}: "
                         f"Suspiciously fast DNS response ({response_time_ms}ms) for {domain}")
            if self.config.auto_block_spoofing:
                should_block = True
                block_reason = block_reason or "Suspicious fast DNS response (possible local spoofing)"

        # Update baseline
        self._update_baseline(domain, response_ips)

        # AUTO-BLOCK if threats detected (NEW ENFORCEMENT)
        if should_block and auto_block and self.config.enforcement_enabled:
            success, msg = self.block_domain(domain, block_reason)
            if success:
                alerts.append(f"BLOCKED: {domain} - {block_reason}")
            else:
                alerts.append(f"BLOCK FAILED for {domain}: {msg}")

        return alerts

    def check_dns_over_https(self) -> Tuple[bool, str]:
        """
        Check if the system is using DNS-over-HTTPS.

        Returns:
            (is_using_doh, resolver_info)
        """
        # Windows: DoH/DoT detection is limited
        if IS_WINDOWS:
            # Check for running DoH clients via tasklist
            doh_clients = ['cloudflared', 'dnscrypt-proxy', 'stubby', 'doh-client']
            try:
                result = subprocess.run(
                    ['tasklist'],
                    capture_output=True, timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                if result.returncode == 0:
                    output = result.stdout.decode().lower()
                    for client in doh_clients:
                        if client in output:
                            return True, f"DoH client running: {client}"
            except Exception:
                pass
            return False, "DoH detection limited on Windows"

        # Linux: Check for common DoH configurations
        doh_indicators = []

        # Check systemd-resolved for DoH
        try:
            result = subprocess.run(
                ['resolvectl', 'status'],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                output = result.stdout.decode()
                if 'DNSOverTLS' in output and 'yes' in output.lower():
                    return True, "systemd-resolved with DoT enabled"
                if 'DNS Servers' in output:
                    for line in output.split('\n'):
                        if 'DNS Servers' in line:
                            doh_indicators.append(line.strip())
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check /etc/resolv.conf
        try:
            with open('/etc/resolv.conf', 'r') as f:
                resolv_content = f.read()
                for resolver in self.config.secure_resolvers:
                    if resolver in resolv_content:
                        return True, f"Using known secure resolver: {resolver}"
        except Exception:
            pass

        # Check for running DoH clients
        doh_clients = ['cloudflared', 'dnscrypt-proxy', 'stubby', 'doh-client']
        for client in doh_clients:
            try:
                result = subprocess.run(['pgrep', '-f', client], capture_output=True, timeout=2)
                if result.returncode == 0:
                    return True, f"DoH client running: {client}"
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return False, "No secure DNS detected"

    def check_dns_over_tls(self) -> Tuple[bool, str]:
        """
        Check if the system is using DNS-over-TLS.

        Returns:
            (is_using_dot, resolver_info)
        """
        # Windows: DoT detection is limited
        if IS_WINDOWS:
            # Check for stubby via tasklist
            try:
                result = subprocess.run(
                    ['tasklist'],
                    capture_output=True, timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                if result.returncode == 0:
                    output = result.stdout.decode().lower()
                    if 'stubby' in output:
                        return True, "Stubby DoT client running"
            except Exception:
                pass
            return False, "DoT detection limited on Windows"

        # Linux: Check systemd-resolved for DoT
        try:
            result = subprocess.run(
                ['resolvectl', 'status'],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                output = result.stdout.decode()
                if 'DNSOverTLS' in output:
                    if 'yes' in output.lower() or 'opportunistic' in output.lower():
                        return True, "systemd-resolved with DoT"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check for stubby (DoT client)
        try:
            result = subprocess.run(['pgrep', '-f', 'stubby'], capture_output=True, timeout=2)
            if result.returncode == 0:
                return True, "Stubby DoT client running"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return False, "No DNS-over-TLS detected"

    def _detect_tunneling(self, domain: str) -> List[str]:
        """
        Detect potential DNS tunneling/exfiltration.

        Tunneling indicators:
        - Very long subdomain names
        - High entropy in subdomain (encoded data)
        - Many subdomain labels
        - Unusual characters patterns
        """
        alerts = []

        # Skip known legitimate high-entropy domains
        for legit in self._legitimate_high_entropy:
            if domain.endswith(legit):
                return alerts

        parts = domain.split('.')

        # Check total subdomain length
        if len(parts) > 2:
            subdomain = '.'.join(parts[:-2])
            if len(subdomain) > self.config.max_subdomain_length:
                alerts.append(f"{DNSSecurityAlert.TUNNELING_DETECTED.value}: "
                             f"Unusually long subdomain ({len(subdomain)} chars): {domain[:50]}...")

        # Check number of labels
        if len(parts) > self.config.max_label_count:
            alerts.append(f"{DNSSecurityAlert.TUNNELING_DETECTED.value}: "
                         f"Too many subdomain labels ({len(parts)}): {domain[:50]}...")

        # Check for high entropy (base64/hex encoded data)
        for part in parts[:-2]:  # Exclude TLD and SLD
            if len(part) > 10:
                entropy = self._calculate_entropy(part)
                if entropy > 4.0:  # High entropy threshold
                    alerts.append(f"{DNSSecurityAlert.EXFILTRATION_SUSPECTED.value}: "
                                 f"High entropy subdomain detected: {part[:30]}...")
                    break

        # Check for hex-like patterns
        hex_pattern = re.compile(r'^[0-9a-f]{16,}$', re.IGNORECASE)
        for part in parts[:-2]:
            if hex_pattern.match(part):
                alerts.append(f"{DNSSecurityAlert.TUNNELING_DETECTED.value}: "
                             f"Hex-encoded subdomain detected: {part[:30]}...")
                break

        # Check for base64-like patterns
        b64_pattern = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
        for part in parts[:-2]:
            if b64_pattern.match(part):
                alerts.append(f"{DNSSecurityAlert.TUNNELING_DETECTED.value}: "
                             f"Base64-encoded subdomain detected: {part[:30]}...")
                break

        return alerts

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0

        freq = defaultdict(int)
        for char in text.lower():
            freq[char] += 1

        length = len(text)
        entropy = 0.0

        import math
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _detect_spoofing(self, domain: str, response_ips: List[str]) -> Optional[str]:
        """Detect DNS spoofing by comparing against baseline"""
        if domain not in self._dns_baseline:
            return None

        known_ips = self._dns_baseline[domain]
        new_ips = set(response_ips)

        # If completely different IPs, might be spoofing
        if known_ips and new_ips and not known_ips.intersection(new_ips):
            # Could be legitimate CDN rotation, so just warn
            return (f"{DNSSecurityAlert.SPOOFING_DETECTED.value}: "
                   f"DNS response for {domain} differs from baseline. "
                   f"Expected: {list(known_ips)[:3]}, Got: {list(new_ips)[:3]}")

        return None

    def _detect_rebinding(self, domain: str, response_ips: List[str]) -> Optional[str]:
        """
        Detect DNS rebinding attacks.

        DNS rebinding: Attacker's domain initially resolves to their server,
        then quickly switches to internal IP (127.0.0.1, 192.168.x.x, etc.)
        """
        now = datetime.utcnow()

        with self._lock:
            history = self._domain_ip_history[domain]

            # Add current IPs to history
            for ip in response_ips:
                history.append((ip, now))

            # Keep only last 10 minutes of history
            cutoff = now - timedelta(minutes=10)
            history[:] = [(ip, ts) for ip, ts in history if ts > cutoff]

            # Check for rebinding pattern: external IP -> internal IP
            internal_prefixes = ('127.', '10.', '192.168.', '172.16.', '172.17.',
                                '172.18.', '172.19.', '172.20.', '172.21.',
                                '172.22.', '172.23.', '172.24.', '172.25.',
                                '172.26.', '172.27.', '172.28.', '172.29.',
                                '172.30.', '172.31.', '169.254.', '::1', 'fe80:')

            has_external = False
            has_internal = False

            for ip, _ in history:
                if any(ip.startswith(prefix) for prefix in internal_prefixes):
                    has_internal = True
                else:
                    has_external = True

            if has_external and has_internal:
                return (f"{DNSSecurityAlert.DNS_REBINDING.value}: "
                       f"Domain {domain} resolved to both external and internal IPs")

        return None

    def _check_suspicious_tld(self, domain: str) -> List[str]:
        """Check if domain uses a suspicious TLD"""
        alerts = []

        for tld in self.config.suspicious_tlds:
            if domain.endswith(tld):
                alerts.append(f"{DNSSecurityAlert.SUSPICIOUS_TLD.value}: "
                             f"Domain uses suspicious TLD: {domain}")
                break

        return alerts

    def _check_resolver_security(self) -> Tuple[bool, str]:
        """Check if current DNS resolver is secure"""
        # Try to determine current resolver
        resolver = "unknown"
        is_secure = False

        if IS_WINDOWS:
            # Windows: Get DNS server via ipconfig
            try:
                result = subprocess.run(
                    ['ipconfig', '/all'],
                    capture_output=True, timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                if result.returncode == 0:
                    output = result.stdout.decode()
                    # Look for DNS Servers line
                    for line in output.split('\n'):
                        if 'DNS Servers' in line or 'DNS-Server' in line:
                            parts = line.split(':')
                            if len(parts) >= 2:
                                resolver = parts[1].strip().split()[0]
                                break
            except Exception:
                pass
        else:
            # Linux: Read /etc/resolv.conf
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            resolver = line.split()[1]
                            break
            except Exception:
                pass

        # Check DoH/DoT
        doh_ok, doh_info = self.check_dns_over_https()
        if doh_ok:
            return True, doh_info

        dot_ok, dot_info = self.check_dns_over_tls()
        if dot_ok:
            return True, dot_info

        # Check if using known secure resolver
        if resolver in self.config.secure_resolvers:
            is_secure = True

        return is_secure, resolver

    def _record_query(self, domain: str, query_type: str):
        """Record a DNS query for rate tracking"""
        now = datetime.utcnow()

        with self._lock:
            self._last_minute_queries.append(now)
            self._query_counts[domain] += 1

            # Cleanup old entries
            cutoff = now - timedelta(minutes=1)
            self._last_minute_queries = [
                ts for ts in self._last_minute_queries if ts > cutoff
            ]

    def _calculate_query_rate(self) -> float:
        """Calculate queries per minute"""
        with self._lock:
            now = datetime.utcnow()
            cutoff = now - timedelta(minutes=1)
            recent = [ts for ts in self._last_minute_queries if ts > cutoff]
            return float(len(recent))

    def _update_baseline(self, domain: str, ips: List[str]):
        """Update baseline DNS responses"""
        with self._lock:
            if domain not in self._dns_baseline:
                self._dns_baseline[domain] = set()
            self._dns_baseline[domain].update(ips)

            # Keep baseline reasonable size
            if len(self._dns_baseline[domain]) > 20:
                # Keep most recent IPs
                self._dns_baseline[domain] = set(list(self._dns_baseline[domain])[-20:])

    def _is_cached_response(self, domain: str) -> bool:
        """Check if domain is likely cached"""
        with self._lock:
            return self._query_counts.get(domain, 0) > 1

    def _get_current_alerts(self) -> List[str]:
        """Get current active alerts"""
        alerts = []

        # Check secure DNS
        if self.config.enforce_secure_dns:
            is_secure, resolver = self._check_resolver_security()
            if not is_secure:
                alerts.append(f"{DNSSecurityAlert.INSECURE_DNS.value}: "
                             f"Not using secure DNS (DoH/DoT). Resolver: {resolver}")

        # Check query rate
        rate = self._calculate_query_rate()
        if rate > self.config.max_queries_per_minute:
            alerts.append(f"{DNSSecurityAlert.HIGH_QUERY_RATE.value}: "
                         f"High DNS query rate: {rate:.0f}/min")

        return alerts

    def _get_suspicious_domains(self) -> List[str]:
        """Get list of recently queried suspicious domains"""
        suspicious = []

        with self._lock:
            for domain in self._query_counts.keys():
                for tld in self.config.suspicious_tlds:
                    if domain.endswith(tld):
                        suspicious.append(domain)
                        break

        return suspicious

    def _get_potential_tunneling_domains(self) -> List[str]:
        """Get domains that show tunneling indicators"""
        tunneling = []

        with self._lock:
            for domain in self._query_counts.keys():
                alerts = self._detect_tunneling(domain)
                if alerts:
                    tunneling.append(domain)

        return tunneling

    def _cleanup_old_records(self):
        """Clean up old tracking data"""
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=1)

        with self._lock:
            # Clean query history
            self._query_history = [
                q for q in self._query_history if q.timestamp > cutoff
            ]

            # Reset query counts periodically
            if len(self._query_counts) > 10000:
                self._query_counts.clear()

    def verify_dns_response(self, domain: str, expected_ips: Optional[List[str]] = None) -> Dict:
        """
        Verify a DNS response by querying multiple resolvers.

        SECURITY: External DNS queries are blocked in AIRGAP/COLDROOM/LOCKDOWN
        modes to prevent domain name leakage to public resolvers.

        SECURITY: This method now uses pure Python DNS resolution instead of
        external tools (dig, nslookup). This addresses the vulnerability:
        "DNS Response Verification Uses External Tools"

        Args:
            domain: Domain to verify
            expected_ips: Optional list of expected IP addresses

        Returns:
            Dict with verification results
        """
        results = {
            'domain': domain,
            'consistent': True,
            'responses': {},
            'alerts': [],
            'method': 'native' if self._native_resolver else 'legacy',
        }

        # SECURITY: Block external DNS queries in network-isolated modes
        if self._is_network_blocked():
            self._log_blocked_dns_op(
                'verify_dns_response',
                domain,
                'External DNS queries blocked in current security mode'
            )
            results['alerts'].append(
                "DNS verification skipped: Network isolated mode active"
            )
            results['responses']['blocked'] = ['network_isolated']
            return results

        # SECURITY: Use native Python DNS resolver if available (no external tools)
        if self._secure_verifier:
            try:
                native_result = self._secure_verifier.verify_dns_response(domain, expected_ips)
                results['consistent'] = native_result['consistent']
                results['alerts'].extend(native_result['alerts'])

                # Format responses for compatibility
                for resolver_name, data in native_result['responses'].items():
                    if isinstance(data, dict):
                        if 'error' in data:
                            results['responses'][resolver_name] = ['error']
                        else:
                            results['responses'][resolver_name] = data.get('ips', [])
                    else:
                        results['responses'][resolver_name] = data

                # Add consistency alert
                if not native_result['consistent']:
                    results['alerts'].append(
                        f"{DNSSecurityAlert.CACHE_POISONING.value}: "
                        f"Inconsistent DNS responses across resolvers for {domain}"
                    )

                return results

            except Exception as e:
                logger.warning(f"Native DNS verification failed, using fallback: {e}")
                # Fall through to legacy method

        # LEGACY FALLBACK: Use external dig command (less secure)
        # This code path is only used if native resolver is unavailable
        logger.warning(f"Using legacy DNS verification with external tools for {domain}")
        results['method'] = 'legacy_external_tools'
        results['alerts'].append("WARNING: Using external tool (dig) for DNS verification")

        resolvers = [
            ('1.1.1.1', 'Cloudflare'),
            ('8.8.8.8', 'Google'),
            ('9.9.9.9', 'Quad9'),
        ]

        all_ips = []

        for resolver_ip, resolver_name in resolvers:
            try:
                # Query using specific resolver
                result = subprocess.run(
                    ['dig', f'@{resolver_ip}', domain, '+short', '+timeout=3'],
                    capture_output=True, timeout=5
                )
                if result.returncode == 0:
                    ips = [ip.strip() for ip in result.stdout.decode().split('\n') if ip.strip()]
                    results['responses'][resolver_name] = ips
                    all_ips.extend(ips)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                results['responses'][resolver_name] = ['error']

        # Check consistency
        unique_responses = set()
        for resolver_name, ips in results['responses'].items():
            if ips != ['error']:
                unique_responses.add(tuple(sorted(ips)))

        if len(unique_responses) > 1:
            results['consistent'] = False
            results['alerts'].append(
                f"{DNSSecurityAlert.CACHE_POISONING.value}: "
                f"Inconsistent DNS responses across resolvers for {domain}"
            )

        # Check against expected
        if expected_ips:
            expected_set = set(expected_ips)
            actual_set = set(all_ips)
            if not expected_set.intersection(actual_set):
                results['alerts'].append(
                    f"{DNSSecurityAlert.SPOOFING_DETECTED.value}: "
                    f"DNS response doesn't match expected IPs for {domain}"
                )

        return results


# Convenience function for quick DNS security check
def quick_dns_security_check() -> DNSSecurityStatus:
    """Perform a quick DNS security check and return status"""
    monitor = DNSSecurityMonitor()
    return monitor.get_status()


if __name__ == '__main__':
    # Test the DNS security monitor
    print("DNS Security Monitor Test")
    print("=" * 50)

    monitor = DNSSecurityMonitor()

    # Check secure DNS status
    print("\n--- Secure DNS Check ---")
    doh_ok, doh_info = monitor.check_dns_over_https()
    print(f"DNS-over-HTTPS: {doh_ok} - {doh_info}")

    dot_ok, dot_info = monitor.check_dns_over_tls()
    print(f"DNS-over-TLS: {dot_ok} - {dot_info}")

    # Test tunneling detection
    print("\n--- Tunneling Detection Test ---")
    test_domains = [
        "normal.example.com",
        "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.evil.com",  # Base64-like
        "4e6f772069732074686520746.ioc.io",  # Hex-like
        "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.evil.com",  # Many labels
        "thisisaverylongsubdomainthatmightindicatetunnelingactivity.bad.com",
    ]

    for domain in test_domains:
        alerts = monitor.analyze_query(domain)
        if alerts:
            print(f"[ALERT] {domain[:40]}...")
            for alert in alerts:
                print(f"        {alert}")
        else:
            print(f"[OK] {domain[:40]}...")

    # Test rebinding detection
    print("\n--- DNS Rebinding Test ---")
    alerts = monitor.analyze_response("test.evil.com", ["1.2.3.4"], 50)
    alerts = monitor.analyze_response("test.evil.com", ["192.168.1.1"], 50)
    if alerts:
        for alert in alerts:
            print(f"[ALERT] {alert}")
    else:
        print("[OK] No rebinding detected")

    # Get overall status
    print("\n--- Overall Status ---")
    status = monitor.get_status()
    print(f"Secure DNS: {status.is_secure_dns}")
    print(f"Resolver: {status.current_resolver}")
    print(f"Query Rate: {status.query_rate_per_minute}/min")
    print(f"Alerts: {status.alerts}")

    # Verify DNS response
    print("\n--- DNS Verification ---")
    result = monitor.verify_dns_response("google.com")
    print(f"Domain: {result['domain']}")
    print(f"Consistent: {result['consistent']}")
    for resolver, ips in result['responses'].items():
        print(f"  {resolver}: {ips[:3]}...")
