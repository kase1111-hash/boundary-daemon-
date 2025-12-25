"""
ARP Security Monitor - Detects ARP-based attacks and anomalies.

Features:
- ARP spoofing detection (IP-MAC binding changes)
- Duplicate MAC address detection
- Gratuitous ARP flood detection
- Gateway impersonation detection
- ARP cache poisoning detection
"""

import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum
from collections import defaultdict


class ARPSecurityAlert(Enum):
    """Types of ARP security alerts"""
    NONE = "none"
    SPOOFING_DETECTED = "arp_spoofing"
    DUPLICATE_MAC = "duplicate_mac"
    GATEWAY_IMPERSONATION = "gateway_impersonation"
    ARP_FLOOD = "arp_flood"
    MAC_CHANGE = "mac_change"
    NEW_HOST = "new_host"
    CACHE_POISONING = "cache_poisoning"


@dataclass
class ARPEntry:
    """Represents an ARP table entry"""
    ip_address: str
    mac_address: str
    interface: str
    flags: str
    first_seen: datetime
    last_seen: datetime
    change_count: int = 0


@dataclass
class ARPSecurityConfig:
    """Configuration for ARP security monitoring"""
    # Detection toggles
    detect_spoofing: bool = True
    detect_duplicate_mac: bool = True
    detect_gateway_impersonation: bool = True
    detect_arp_flood: bool = True
    alert_on_new_hosts: bool = False  # Can be noisy on dynamic networks

    # Thresholds
    max_mac_changes_per_minute: int = 3  # Rapid MAC changes indicate spoofing
    max_arp_requests_per_minute: int = 100  # ARP flood threshold
    mac_change_alert_threshold: int = 2  # Alert after N MAC changes for same IP

    # Known trusted bindings (IP -> MAC)
    trusted_bindings: Dict[str, str] = field(default_factory=dict)

    # Gateway IP (auto-detected if not set)
    gateway_ip: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            'detect_spoofing': self.detect_spoofing,
            'detect_duplicate_mac': self.detect_duplicate_mac,
            'detect_gateway_impersonation': self.detect_gateway_impersonation,
            'detect_arp_flood': self.detect_arp_flood,
            'alert_on_new_hosts': self.alert_on_new_hosts,
            'max_mac_changes_per_minute': self.max_mac_changes_per_minute,
            'max_arp_requests_per_minute': self.max_arp_requests_per_minute,
        }


@dataclass
class ARPSecurityStatus:
    """Current ARP security status"""
    alerts: List[str]
    arp_table_size: int
    gateway_ip: str
    gateway_mac: str
    suspicious_ips: List[str]
    duplicate_macs: List[str]
    recent_changes: int
    last_check: str

    def to_dict(self) -> Dict:
        return {
            'alerts': self.alerts,
            'arp_table_size': self.arp_table_size,
            'gateway_ip': self.gateway_ip,
            'gateway_mac': self.gateway_mac,
            'suspicious_ips': self.suspicious_ips,
            'duplicate_macs': self.duplicate_macs,
            'recent_changes': self.recent_changes,
            'last_check': self.last_check,
        }


class ARPSecurityMonitor:
    """
    Monitors ARP traffic and table for security threats.

    Detection capabilities:
    1. ARP Spoofing: Detects when IP-MAC bindings change unexpectedly
    2. Duplicate MAC: Multiple IPs using the same MAC address
    3. Gateway Impersonation: Someone claiming to be the gateway
    4. ARP Flood: Excessive ARP traffic indicating attack
    """

    def __init__(self, config: Optional[ARPSecurityConfig] = None):
        self.config = config or ARPSecurityConfig()

        # ARP table tracking
        self._arp_cache: Dict[str, ARPEntry] = {}  # IP -> ARPEntry
        self._mac_to_ips: Dict[str, Set[str]] = defaultdict(set)  # MAC -> set of IPs
        self._ip_mac_history: Dict[str, List[Tuple[str, datetime]]] = defaultdict(list)

        # Gateway tracking
        self._gateway_ip: Optional[str] = None
        self._gateway_mac: Optional[str] = None
        self._original_gateway_mac: Optional[str] = None

        # Rate tracking
        self._arp_events: List[datetime] = []
        self._mac_changes: List[Tuple[str, datetime]] = []  # (IP, timestamp)

        # Thread safety - use RLock to allow reentrant locking
        self._lock = threading.RLock()

        # Monitoring state
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None

        # Initialize gateway
        self._detect_gateway()

    def start(self):
        """Start continuous ARP monitoring"""
        if self._running:
            return

        self._running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def stop(self):
        """Stop ARP monitoring"""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                self._update_arp_table()
                self._cleanup_old_records()
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                print(f"Error in ARP monitor loop: {e}")
                time.sleep(5)

    def get_status(self) -> ARPSecurityStatus:
        """Get current ARP security status"""
        with self._lock:
            alerts = self._get_current_alerts()
            suspicious = self._get_suspicious_ips()
            duplicates = self._get_duplicate_macs()
            recent = self._count_recent_changes()

            return ARPSecurityStatus(
                alerts=alerts,
                arp_table_size=len(self._arp_cache),
                gateway_ip=self._gateway_ip or "unknown",
                gateway_mac=self._gateway_mac or "unknown",
                suspicious_ips=suspicious[:10],
                duplicate_macs=duplicates[:10],
                recent_changes=recent,
                last_check=datetime.utcnow().isoformat() + "Z"
            )

    def add_trusted_binding(self, ip: str, mac: str):
        """Add a trusted IP-MAC binding"""
        self.config.trusted_bindings[ip] = mac.lower()

    def set_gateway(self, ip: str, mac: str):
        """Manually set the gateway IP and MAC"""
        self._gateway_ip = ip
        self._gateway_mac = mac.lower()
        self._original_gateway_mac = mac.lower()

    def analyze_arp_entry(self, ip: str, mac: str, interface: str = "") -> List[str]:
        """
        Analyze a single ARP entry for security issues.

        Args:
            ip: IP address
            mac: MAC address
            interface: Network interface (optional)

        Returns:
            List of alert messages
        """
        alerts = []
        mac = mac.lower()
        now = datetime.utcnow()

        with self._lock:
            # Record ARP event for rate limiting
            self._arp_events.append(now)

            # Check for gateway impersonation
            if self.config.detect_gateway_impersonation:
                if ip == self._gateway_ip and mac != self._original_gateway_mac:
                    if self._original_gateway_mac:
                        alerts.append(
                            f"{ARPSecurityAlert.GATEWAY_IMPERSONATION.value}: "
                            f"Gateway {ip} MAC changed from {self._original_gateway_mac} to {mac}"
                        )

            # Check for MAC change (potential spoofing)
            if self.config.detect_spoofing:
                if ip in self._arp_cache:
                    old_mac = self._arp_cache[ip].mac_address
                    if old_mac != mac:
                        # Record the change
                        self._mac_changes.append((ip, now))
                        self._ip_mac_history[ip].append((mac, now))

                        # Check if this is a trusted binding violation
                        if ip in self.config.trusted_bindings:
                            expected_mac = self.config.trusted_bindings[ip]
                            if mac != expected_mac:
                                alerts.append(
                                    f"{ARPSecurityAlert.SPOOFING_DETECTED.value}: "
                                    f"Trusted IP {ip} MAC changed from {expected_mac} to {mac}"
                                )
                        else:
                            # Count recent changes for this IP
                            change_count = self._arp_cache[ip].change_count + 1
                            if change_count >= self.config.mac_change_alert_threshold:
                                alerts.append(
                                    f"{ARPSecurityAlert.MAC_CHANGE.value}: "
                                    f"IP {ip} MAC changed {change_count} times "
                                    f"(was {old_mac}, now {mac})"
                                )

            # Check for duplicate MACs
            if self.config.detect_duplicate_mac:
                self._mac_to_ips[mac].add(ip)
                if len(self._mac_to_ips[mac]) > 1:
                    # Multiple IPs using same MAC
                    ips_with_mac = list(self._mac_to_ips[mac])
                    # Filter out legitimate cases (same host, multiple IPs)
                    if not self._is_legitimate_multi_ip(mac, ips_with_mac):
                        alerts.append(
                            f"{ARPSecurityAlert.DUPLICATE_MAC.value}: "
                            f"MAC {mac} used by multiple IPs: {ips_with_mac}"
                        )

            # Update or create entry
            if ip in self._arp_cache:
                entry = self._arp_cache[ip]
                if entry.mac_address != mac:
                    entry.change_count += 1
                entry.mac_address = mac
                entry.last_seen = now
                entry.interface = interface or entry.interface
            else:
                # New host
                self._arp_cache[ip] = ARPEntry(
                    ip_address=ip,
                    mac_address=mac,
                    interface=interface,
                    flags="",
                    first_seen=now,
                    last_seen=now,
                    change_count=0
                )
                if self.config.alert_on_new_hosts:
                    alerts.append(
                        f"{ARPSecurityAlert.NEW_HOST.value}: "
                        f"New host detected: {ip} ({mac})"
                    )

            # Check for ARP flood
            if self.config.detect_arp_flood:
                flood_alert = self._check_arp_flood()
                if flood_alert:
                    alerts.append(flood_alert)

        return alerts

    def verify_gateway(self) -> Tuple[bool, str]:
        """
        Verify that the gateway MAC hasn't been spoofed.

        Returns:
            (is_valid, message)
        """
        if not self._gateway_ip or not self._original_gateway_mac:
            return True, "Gateway not configured for verification"

        current_mac = self._get_mac_for_ip(self._gateway_ip)
        if current_mac and current_mac != self._original_gateway_mac:
            return False, (
                f"Gateway MAC mismatch! Expected {self._original_gateway_mac}, "
                f"got {current_mac}. Possible ARP spoofing attack!"
            )

        return True, "Gateway MAC verified"

    def _detect_gateway(self):
        """Auto-detect the default gateway"""
        try:
            # Try to get default gateway from /proc/net/route
            with open('/proc/net/route', 'r') as f:
                for line in f.readlines()[1:]:  # Skip header
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        # Default route has destination 00000000
                        if parts[1] == '00000000':
                            # Gateway is in hex, little-endian
                            gateway_hex = parts[2]
                            # Convert hex to IP
                            gateway_ip = '.'.join([
                                str(int(gateway_hex[i:i+2], 16))
                                for i in range(6, -1, -2)
                            ])
                            self._gateway_ip = gateway_ip
                            self.config.gateway_ip = gateway_ip

                            # Get gateway MAC from ARP cache
                            self._gateway_mac = self._get_mac_for_ip(gateway_ip)
                            self._original_gateway_mac = self._gateway_mac
                            break
        except Exception as e:
            print(f"Error detecting gateway: {e}")

        # Fallback: try ip route command
        if not self._gateway_ip:
            try:
                result = subprocess.run(
                    ['ip', 'route', 'show', 'default'],
                    capture_output=True, timeout=2
                )
                if result.returncode == 0:
                    output = result.stdout.decode()
                    match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', output)
                    if match:
                        self._gateway_ip = match.group(1)
                        self.config.gateway_ip = self._gateway_ip
                        self._gateway_mac = self._get_mac_for_ip(self._gateway_ip)
                        self._original_gateway_mac = self._gateway_mac
            except Exception:
                pass

    def _get_mac_for_ip(self, ip: str) -> Optional[str]:
        """Get MAC address for an IP from the ARP cache"""
        # First check our cache
        if ip in self._arp_cache:
            return self._arp_cache[ip].mac_address

        # Try reading from /proc/net/arp
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f.readlines()[1:]:  # Skip header
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3].lower()
                        if mac != '00:00:00:00:00:00':
                            return mac
        except Exception:
            pass

        # Try arp command
        try:
            result = subprocess.run(
                ['arp', '-n', ip],
                capture_output=True, timeout=2
            )
            if result.returncode == 0:
                output = result.stdout.decode()
                # Parse arp output for MAC
                mac_pattern = re.compile(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', re.I)
                match = mac_pattern.search(output)
                if match:
                    return match.group(1).lower()
        except Exception:
            pass

        return None

    def _update_arp_table(self):
        """Update internal ARP table from system"""
        try:
            with open('/proc/net/arp', 'r') as f:
                lines = f.readlines()[1:]  # Skip header

            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 6:
                    ip = parts[0]
                    mac = parts[3].lower()
                    interface = parts[5]

                    # Skip incomplete entries
                    if mac == '00:00:00:00:00:00':
                        continue

                    # Analyze each entry
                    self.analyze_arp_entry(ip, mac, interface)

        except Exception as e:
            print(f"Error updating ARP table: {e}")

    def _check_arp_flood(self) -> Optional[str]:
        """Check for ARP flood attack"""
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=1)

        # Count recent events
        with self._lock:
            recent_events = [e for e in self._arp_events if e > cutoff]
            self._arp_events = recent_events  # Cleanup old events

            if len(recent_events) > self.config.max_arp_requests_per_minute:
                return (
                    f"{ARPSecurityAlert.ARP_FLOOD.value}: "
                    f"High ARP activity detected: {len(recent_events)} events/min "
                    f"(threshold: {self.config.max_arp_requests_per_minute})"
                )

        return None

    def _is_legitimate_multi_ip(self, mac: str, ips: List[str]) -> bool:
        """
        Check if multiple IPs on same MAC is legitimate.

        Legitimate cases:
        - Router with multiple IPs
        - Host with multiple network interfaces
        - Virtual IPs for HA
        """
        # Check if all IPs are in same subnet (likely same host)
        try:
            # Simple check: same /24 network
            networks = set()
            for ip in ips:
                parts = ip.split('.')
                if len(parts) == 4:
                    networks.add('.'.join(parts[:3]))

            # If all in same /24, likely legitimate
            if len(networks) == 1:
                return True

            # Check if this is the gateway (often has multiple IPs)
            if self._gateway_mac and mac == self._gateway_mac:
                return True

        except Exception:
            pass

        return False

    def _get_current_alerts(self) -> List[str]:
        """Get current active alerts"""
        alerts = []

        # Verify gateway
        is_valid, msg = self.verify_gateway()
        if not is_valid:
            alerts.append(f"{ARPSecurityAlert.GATEWAY_IMPERSONATION.value}: {msg}")

        # Check for flood
        flood_alert = self._check_arp_flood()
        if flood_alert:
            alerts.append(flood_alert)

        # Check for rapid MAC changes
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=1)
        recent_changes = [c for c in self._mac_changes if c[1] > cutoff]
        if len(recent_changes) > self.config.max_mac_changes_per_minute:
            alerts.append(
                f"{ARPSecurityAlert.CACHE_POISONING.value}: "
                f"Rapid MAC changes detected: {len(recent_changes)}/min"
            )

        return alerts

    def _get_suspicious_ips(self) -> List[str]:
        """Get list of IPs with suspicious activity"""
        suspicious = []

        for ip, entry in self._arp_cache.items():
            if entry.change_count >= self.config.mac_change_alert_threshold:
                suspicious.append(ip)

        return suspicious

    def _get_duplicate_macs(self) -> List[str]:
        """Get list of MACs used by multiple IPs"""
        duplicates = []

        for mac, ips in self._mac_to_ips.items():
            if len(ips) > 1:
                if not self._is_legitimate_multi_ip(mac, list(ips)):
                    duplicates.append(mac)

        return duplicates

    def _count_recent_changes(self) -> int:
        """Count MAC changes in the last minute"""
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=1)
        return len([c for c in self._mac_changes if c[1] > cutoff])

    def _cleanup_old_records(self):
        """Clean up old tracking data"""
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=1)

        with self._lock:
            # Clean up old ARP events
            self._arp_events = [e for e in self._arp_events if e > cutoff]

            # Clean up old MAC changes
            self._mac_changes = [c for c in self._mac_changes if c[1] > cutoff]

            # Clean up IP-MAC history (keep last 10 per IP)
            for ip in self._ip_mac_history:
                self._ip_mac_history[ip] = self._ip_mac_history[ip][-10:]

    def get_arp_table(self) -> List[Dict]:
        """Get the current ARP table as a list of dicts"""
        with self._lock:
            return [
                {
                    'ip': entry.ip_address,
                    'mac': entry.mac_address,
                    'interface': entry.interface,
                    'first_seen': entry.first_seen.isoformat(),
                    'last_seen': entry.last_seen.isoformat(),
                    'change_count': entry.change_count,
                }
                for entry in self._arp_cache.values()
            ]

    def simulate_spoofing_attack(self, target_ip: str, fake_mac: str) -> List[str]:
        """
        Simulate an ARP spoofing attack for testing.

        Args:
            target_ip: IP address to spoof
            fake_mac: Fake MAC address to use

        Returns:
            List of alerts generated
        """
        # First, ensure the IP has a baseline entry
        original_mac = self._get_mac_for_ip(target_ip) or "aa:bb:cc:dd:ee:ff"
        self.analyze_arp_entry(target_ip, original_mac)

        # Now simulate the attack
        return self.analyze_arp_entry(target_ip, fake_mac)


# Convenience function for quick ARP security check
def quick_arp_security_check() -> ARPSecurityStatus:
    """Perform a quick ARP security check and return status"""
    monitor = ARPSecurityMonitor()
    monitor._update_arp_table()
    return monitor.get_status()


if __name__ == '__main__':
    # Test the ARP security monitor
    print("ARP Security Monitor Test")
    print("=" * 50)

    monitor = ARPSecurityMonitor()

    # Display gateway info
    print(f"\n--- Gateway Detection ---")
    print(f"Gateway IP: {monitor._gateway_ip}")
    print(f"Gateway MAC: {monitor._gateway_mac}")

    # Update ARP table
    monitor._update_arp_table()

    # Get status
    print(f"\n--- ARP Table Status ---")
    status = monitor.get_status()
    print(f"Table size: {status.arp_table_size}")
    print(f"Recent changes: {status.recent_changes}")
    print(f"Alerts: {status.alerts}")

    # Display ARP table
    print(f"\n--- Current ARP Table ---")
    for entry in monitor.get_arp_table()[:10]:  # First 10 entries
        print(f"  {entry['ip']:15} -> {entry['mac']} ({entry['interface']})")

    # Simulate attacks
    print(f"\n--- Attack Simulation ---")

    # Simulate MAC change (spoofing)
    print("\nSimulating ARP spoofing attack...")
    alerts = monitor.analyze_arp_entry("192.168.1.100", "aa:bb:cc:dd:ee:01")
    alerts = monitor.analyze_arp_entry("192.168.1.100", "aa:bb:cc:dd:ee:02")
    alerts = monitor.analyze_arp_entry("192.168.1.100", "aa:bb:cc:dd:ee:03")
    print(f"Alerts after spoofing: {alerts}")

    # Simulate duplicate MAC
    print("\nSimulating duplicate MAC attack...")
    alerts = monitor.analyze_arp_entry("192.168.1.200", "ff:ff:ff:00:00:01")
    alerts = monitor.analyze_arp_entry("192.168.1.201", "ff:ff:ff:00:00:01")
    print(f"Alerts after duplicate MAC: {alerts}")

    # Simulate gateway impersonation
    if monitor._gateway_ip:
        print(f"\nSimulating gateway impersonation...")
        alerts = monitor.analyze_arp_entry(monitor._gateway_ip, "de:ad:be:ef:ca:fe")
        print(f"Alerts after gateway impersonation: {alerts}")

    # Final status
    print(f"\n--- Final Status ---")
    status = monitor.get_status()
    print(f"Suspicious IPs: {status.suspicious_ips}")
    print(f"Duplicate MACs: {status.duplicate_macs}")
    print(f"All alerts: {status.alerts}")
