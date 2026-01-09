"""
WiFi Security Monitoring Module

Detects WiFi-based attacks including:
- Evil Twin AP detection (duplicate SSIDs with different BSSIDs)
- Deauthentication flood detection
- WPA handshake capture attempts
- Rogue access point detection
- Karma attack detection
"""

import threading
import subprocess
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict

# Platform detection
IS_WINDOWS = sys.platform == 'win32'


class WiFiSecurityAlert(Enum):
    """Types of WiFi security alerts"""
    EVIL_TWIN_DETECTED = "evil_twin_detected"
    DEAUTH_FLOOD = "deauth_flood"
    HANDSHAKE_CAPTURE = "handshake_capture_attempt"
    ROGUE_AP = "rogue_ap"
    KARMA_ATTACK = "karma_attack"
    SUSPICIOUS_PROBE = "suspicious_probe"
    CHANNEL_HOPPING = "channel_hopping"
    BEACON_FLOOD = "beacon_flood"


@dataclass
class WiFiSecurityConfig:
    """Configuration for WiFi security monitoring"""
    # Evil Twin detection
    enable_evil_twin_detection: bool = True
    ssid_similarity_threshold: float = 0.8  # For typosquatting detection

    # Deauth detection
    enable_deauth_detection: bool = True
    deauth_threshold: int = 10  # Deauths per minute to trigger alert
    deauth_window_seconds: int = 60

    # Handshake capture detection
    enable_handshake_detection: bool = True
    handshake_suspicious_tools: List[str] = field(default_factory=lambda: [
        'aircrack-ng', 'airmon-ng', 'airodump-ng', 'aireplay-ng',
        'hashcat', 'cowpatty', 'pyrit', 'wifite', 'fern-wifi-cracker',
        'bettercap', 'wifiphisher', 'fluxion', 'linset'
    ])

    # Rogue AP detection
    enable_rogue_ap_detection: bool = True
    known_aps: Dict[str, str] = field(default_factory=dict)  # SSID -> expected BSSID

    # Monitoring intervals
    scan_interval_seconds: int = 30
    alert_cooldown_seconds: int = 300  # 5 minutes between same alerts


@dataclass
class AccessPoint:
    """Represents a detected access point"""
    ssid: str
    bssid: str
    channel: int
    signal_strength: int
    encryption: str
    first_seen: datetime
    last_seen: datetime
    beacon_count: int = 0


@dataclass
class DeauthEvent:
    """Represents a deauthentication event"""
    timestamp: datetime
    source_mac: str
    target_mac: str
    bssid: str
    reason_code: int


@dataclass
class WiFiSecurityStatus:
    """Current WiFi security status"""
    is_monitoring: bool = False
    interface: Optional[str] = None
    monitor_mode: bool = False
    detected_aps: Dict[str, List[AccessPoint]] = field(default_factory=dict)  # SSID -> [APs]
    active_alerts: List[Dict] = field(default_factory=list)
    deauth_events: List[DeauthEvent] = field(default_factory=list)
    suspicious_processes: List[str] = field(default_factory=list)
    last_scan: Optional[datetime] = None
    total_alerts: int = 0


class WiFiSecurityMonitor:
    """Monitors WiFi security and detects various attacks"""

    def __init__(self, config: Optional[WiFiSecurityConfig] = None):
        self.config = config or WiFiSecurityConfig()
        self.status = WiFiSecurityStatus()
        self._lock = threading.RLock()  # Reentrant lock for thread safety

        # Track detected APs by SSID for Evil Twin detection
        self._aps_by_ssid: Dict[str, List[AccessPoint]] = defaultdict(list)

        # Track deauth events for flood detection
        self._deauth_events: List[DeauthEvent] = []

        # Track recent alerts to prevent duplicates
        self._recent_alerts: Dict[str, datetime] = {}

        # Known legitimate APs (learned over time)
        self._trusted_aps: Dict[str, Set[str]] = defaultdict(set)  # SSID -> set of BSSIDs

        # Baseline for normal operation
        self._baseline_established = False
        self._baseline_aps: Dict[str, str] = {}  # SSID -> primary BSSID

    def analyze_access_point(self, ssid: str, bssid: str, channel: int = 0,
                            signal_strength: int = -50, encryption: str = "WPA2") -> List[Dict]:
        """
        Analyze an access point for potential security issues

        Args:
            ssid: The SSID of the access point
            bssid: The BSSID (MAC address) of the access point
            channel: The WiFi channel
            signal_strength: Signal strength in dBm
            encryption: Encryption type (WPA2, WPA3, WEP, Open)

        Returns:
            List of security alerts
        """
        alerts = []
        now = datetime.now()

        with self._lock:
            # Create or update AP record
            ap = AccessPoint(
                ssid=ssid,
                bssid=bssid.upper(),
                channel=channel,
                signal_strength=signal_strength,
                encryption=encryption,
                first_seen=now,
                last_seen=now
            )

            # Check for existing AP with same BSSID
            existing_ap = None
            for existing in self._aps_by_ssid.get(ssid, []):
                if existing.bssid == bssid.upper():
                    existing_ap = existing
                    existing.last_seen = now
                    existing.beacon_count += 1
                    existing.signal_strength = signal_strength
                    break

            if existing_ap is None:
                self._aps_by_ssid[ssid].append(ap)

            # Evil Twin Detection
            if self.config.enable_evil_twin_detection:
                evil_twin_alert = self._check_evil_twin(ssid, bssid.upper(), channel, signal_strength)
                if evil_twin_alert:
                    alerts.append(evil_twin_alert)

            # Rogue AP Detection
            if self.config.enable_rogue_ap_detection:
                rogue_alert = self._check_rogue_ap(ssid, bssid.upper())
                if rogue_alert:
                    alerts.append(rogue_alert)

            # Weak encryption warning
            if encryption in ["WEP", "Open", "NONE"]:
                alerts.append(self._create_alert(
                    WiFiSecurityAlert.ROGUE_AP,
                    f"Weak or no encryption on AP {ssid}",
                    severity="medium",
                    details={"ssid": ssid, "bssid": bssid, "encryption": encryption}
                ))

            # Update status
            self.status.detected_aps = dict(self._aps_by_ssid)
            self.status.last_scan = now

            for alert in alerts:
                if alert not in self.status.active_alerts:
                    self.status.active_alerts.append(alert)
                    self.status.total_alerts += 1
                    # Limit active_alerts to prevent memory leak
                    if len(self.status.active_alerts) > 100:
                        self.status.active_alerts = self.status.active_alerts[-100:]

        return alerts

    def _check_evil_twin(self, ssid: str, bssid: str, channel: int,
                         signal_strength: int) -> Optional[Dict]:
        """Check for Evil Twin AP (same SSID, different BSSID)"""
        if not ssid or ssid == "":
            return None

        existing_aps = self._aps_by_ssid.get(ssid, [])

        # If we have multiple APs with the same SSID but different BSSIDs
        unique_bssids = set(ap.bssid for ap in existing_aps)

        if len(unique_bssids) > 1 and bssid in unique_bssids:
            # Check if this is a known enterprise setup (multiple legitimate APs)
            if ssid in self._trusted_aps and len(self._trusted_aps[ssid]) > 1:
                # Already established as multi-AP network
                if bssid in self._trusted_aps[ssid]:
                    return None

            # This could be an Evil Twin
            other_bssids = [b for b in unique_bssids if b != bssid]

            alert_key = f"evil_twin_{ssid}"
            if self._should_alert(alert_key):
                return self._create_alert(
                    WiFiSecurityAlert.EVIL_TWIN_DETECTED,
                    f"Potential Evil Twin detected for SSID '{ssid}'",
                    severity="critical",
                    details={
                        "ssid": ssid,
                        "suspicious_bssid": bssid,
                        "legitimate_bssids": other_bssids,
                        "channel": channel,
                        "signal_strength": signal_strength
                    }
                )

        return None

    def _check_rogue_ap(self, ssid: str, bssid: str) -> Optional[Dict]:
        """Check if AP is not in the known/trusted list"""
        if not self.config.known_aps:
            return None

        if ssid in self.config.known_aps:
            expected_bssid = self.config.known_aps[ssid].upper()
            if bssid != expected_bssid:
                alert_key = f"rogue_ap_{ssid}_{bssid}"
                if self._should_alert(alert_key):
                    return self._create_alert(
                        WiFiSecurityAlert.ROGUE_AP,
                        f"Rogue AP detected: SSID '{ssid}' with unexpected BSSID",
                        severity="high",
                        details={
                            "ssid": ssid,
                            "detected_bssid": bssid,
                            "expected_bssid": expected_bssid
                        }
                    )

        return None

    def analyze_deauth_frame(self, source_mac: str, target_mac: str,
                             bssid: str, reason_code: int = 0) -> List[Dict]:
        """
        Analyze a deauthentication frame for potential attacks

        Args:
            source_mac: Source MAC address
            target_mac: Target MAC address
            bssid: BSSID of the network
            reason_code: Deauth reason code

        Returns:
            List of security alerts
        """
        alerts = []
        now = datetime.now()

        with self._lock:
            # Record the deauth event
            event = DeauthEvent(
                timestamp=now,
                source_mac=source_mac.upper(),
                target_mac=target_mac.upper(),
                bssid=bssid.upper(),
                reason_code=reason_code
            )
            self._deauth_events.append(event)
            self.status.deauth_events.append(event)

            # Clean old events from both lists to prevent memory leaks
            cutoff = now - timedelta(seconds=self.config.deauth_window_seconds)
            self._deauth_events = [e for e in self._deauth_events if e.timestamp > cutoff]
            # Also prune status.deauth_events - keep only last 1000 events
            if len(self.status.deauth_events) > 1000:
                self.status.deauth_events = self.status.deauth_events[-1000:]

            # Check for deauth flood
            if self.config.enable_deauth_detection:
                flood_alert = self._check_deauth_flood()
                if flood_alert:
                    alerts.append(flood_alert)

            # Check for targeted deauth (potential handshake capture attempt)
            if self.config.enable_handshake_detection:
                handshake_alert = self._check_handshake_capture_attempt()
                if handshake_alert:
                    alerts.append(handshake_alert)

            for alert in alerts:
                if alert not in self.status.active_alerts:
                    self.status.active_alerts.append(alert)
                    self.status.total_alerts += 1
                    # Limit active_alerts to prevent memory leak
                    if len(self.status.active_alerts) > 100:
                        self.status.active_alerts = self.status.active_alerts[-100:]

        return alerts

    def _check_deauth_flood(self) -> Optional[Dict]:
        """Check for deauthentication flood attack"""
        if len(self._deauth_events) >= self.config.deauth_threshold:
            # Count unique targets
            targets = set(e.target_mac for e in self._deauth_events)
            sources = set(e.source_mac for e in self._deauth_events)

            alert_key = "deauth_flood"
            if self._should_alert(alert_key):
                # Determine attack type
                if len(targets) == 1 and targets != {"FF:FF:FF:FF:FF:FF"}:
                    attack_type = "targeted"
                elif "FF:FF:FF:FF:FF:FF" in targets:
                    attack_type = "broadcast"
                else:
                    attack_type = "distributed"

                return self._create_alert(
                    WiFiSecurityAlert.DEAUTH_FLOOD,
                    f"Deauthentication flood detected ({len(self._deauth_events)} frames in {self.config.deauth_window_seconds}s)",
                    severity="critical",
                    details={
                        "deauth_count": len(self._deauth_events),
                        "unique_targets": len(targets),
                        "unique_sources": len(sources),
                        "attack_type": attack_type,
                        "window_seconds": self.config.deauth_window_seconds
                    }
                )

        return None

    def _check_handshake_capture_attempt(self) -> Optional[Dict]:
        """Check for potential WPA handshake capture attempt"""
        # Pattern: Multiple deauths followed by authentication attempts
        if len(self._deauth_events) < 3:
            return None

        # Group by target
        target_counts = defaultdict(int)
        for event in self._deauth_events:
            target_counts[event.target_mac] += 1

        # If a single client is being repeatedly deauthed, it's suspicious
        for target, count in target_counts.items():
            if count >= 3 and target != "FF:FF:FF:FF:FF:FF":
                alert_key = f"handshake_capture_{target}"
                if self._should_alert(alert_key):
                    return self._create_alert(
                        WiFiSecurityAlert.HANDSHAKE_CAPTURE,
                        f"Potential WPA handshake capture attempt targeting {target}",
                        severity="critical",
                        details={
                            "target_mac": target,
                            "deauth_count": count,
                            "timeframe_seconds": self.config.deauth_window_seconds
                        }
                    )

        return None

    def check_suspicious_processes(self) -> List[Dict]:
        """Check for running processes associated with WiFi attacks"""
        alerts = []
        suspicious_found = []

        with self._lock:
            for tool in self.config.handshake_suspicious_tools:
                if self._is_process_running(tool):
                    suspicious_found.append(tool)

            if suspicious_found:
                self.status.suspicious_processes = suspicious_found
                alert_key = f"suspicious_tools_{'_'.join(sorted(suspicious_found))}"

                if self._should_alert(alert_key):
                    alert = self._create_alert(
                        WiFiSecurityAlert.HANDSHAKE_CAPTURE,
                        f"Suspicious WiFi attack tools detected: {', '.join(suspicious_found)}",
                        severity="high",
                        details={
                            "tools_detected": suspicious_found,
                            "recommendation": "Verify if these tools are authorized for security testing"
                        }
                    )
                    alerts.append(alert)
                    self.status.active_alerts.append(alert)
                    self.status.total_alerts += 1
                    # Limit active_alerts to prevent memory leak
                    if len(self.status.active_alerts) > 100:
                        self.status.active_alerts = self.status.active_alerts[-100:]

        return alerts

    def _is_process_running(self, process_name: str) -> bool:
        """Check if a process is running"""
        if IS_WINDOWS:
            # Windows: Use psutil for cross-platform process detection
            try:
                import psutil
                process_name_lower = process_name.lower()
                for proc in psutil.process_iter(['name', 'cmdline']):
                    try:
                        # Check process name
                        if proc.info['name'] and process_name_lower in proc.info['name'].lower():
                            return True
                        # Check command line for scripts
                        cmdline = proc.info.get('cmdline')
                        if cmdline:
                            cmdline_str = ' '.join(cmdline).lower()
                            if process_name_lower in cmdline_str:
                                return True
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                return False
            except ImportError:
                # Fallback: use tasklist command on Windows
                try:
                    result = subprocess.run(
                        ['tasklist', '/FI', f'IMAGENAME eq {process_name}*'],
                        capture_output=True,
                        timeout=5
                    )
                    return process_name.lower() in result.stdout.decode().lower()
                except Exception:
                    return False
        else:
            # Linux: Use pgrep
            try:
                # Check using pgrep
                result = subprocess.run(
                    ['pgrep', '-x', process_name],
                    capture_output=True,
                    timeout=2
                )
                if result.returncode == 0:
                    return True

                # Also check with partial match for scripts
                result = subprocess.run(
                    ['pgrep', '-f', process_name],
                    capture_output=True,
                    timeout=2
                )
                return result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
                return False

    def scan_wireless_networks(self, interface: str = "wlan0") -> List[Dict]:
        """
        Scan for wireless networks and analyze them

        Args:
            interface: Wireless interface to use

        Returns:
            List of security alerts from the scan
        """
        alerts = []

        with self._lock:
            self.status.interface = interface

            try:
                # Try using iwlist scan
                result = subprocess.run(
                    ['sudo', 'iwlist', interface, 'scan'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0:
                    # Parse scan results
                    networks = self._parse_iwlist_scan(result.stdout)

                    for network in networks:
                        network_alerts = self.analyze_access_point(
                            ssid=network.get('ssid', ''),
                            bssid=network.get('bssid', ''),
                            channel=network.get('channel', 0),
                            signal_strength=network.get('signal', -50),
                            encryption=network.get('encryption', 'Unknown')
                        )
                        alerts.extend(network_alerts)

                    self.status.is_monitoring = True
                    self.status.last_scan = datetime.now()

            except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
                # Scanning not available - continue with manual analysis
                pass

        return alerts

    def _parse_iwlist_scan(self, output: str) -> List[Dict]:
        """Parse iwlist scan output"""
        networks = []
        current_network = {}

        for line in output.split('\n'):
            line = line.strip()

            # New cell (network)
            if 'Cell' in line and 'Address:' in line:
                if current_network:
                    networks.append(current_network)
                bssid_match = re.search(r'Address:\s*([0-9A-Fa-f:]+)', line)
                current_network = {
                    'bssid': bssid_match.group(1) if bssid_match else ''
                }

            # SSID
            elif 'ESSID:' in line:
                ssid_match = re.search(r'ESSID:"([^"]*)"', line)
                if ssid_match:
                    current_network['ssid'] = ssid_match.group(1)

            # Channel
            elif 'Channel:' in line:
                channel_match = re.search(r'Channel:(\d+)', line)
                if channel_match:
                    current_network['channel'] = int(channel_match.group(1))

            # Signal
            elif 'Signal level' in line:
                signal_match = re.search(r'Signal level[=:](-?\d+)', line)
                if signal_match:
                    current_network['signal'] = int(signal_match.group(1))

            # Encryption
            elif 'Encryption key:' in line:
                if 'off' in line.lower():
                    current_network['encryption'] = 'Open'
                else:
                    current_network['encryption'] = 'WPA2'  # Default assumption

            elif 'WPA2' in line:
                current_network['encryption'] = 'WPA2'
            elif 'WPA' in line:
                current_network['encryption'] = 'WPA'
            elif 'WEP' in line:
                current_network['encryption'] = 'WEP'

        if current_network:
            networks.append(current_network)

        return networks

    def add_trusted_ap(self, ssid: str, bssid: str):
        """Add an AP to the trusted list"""
        with self._lock:
            self._trusted_aps[ssid].add(bssid.upper())

    def set_known_aps(self, known_aps: Dict[str, str]):
        """Set the list of known/expected APs"""
        with self._lock:
            self.config.known_aps = {k: v.upper() for k, v in known_aps.items()}

    def _should_alert(self, alert_key: str) -> bool:
        """Check if we should generate an alert (respects cooldown)"""
        now = datetime.now()

        if alert_key in self._recent_alerts:
            last_alert = self._recent_alerts[alert_key]
            if (now - last_alert).total_seconds() < self.config.alert_cooldown_seconds:
                return False

        self._recent_alerts[alert_key] = now
        return True

    def _create_alert(self, alert_type: WiFiSecurityAlert, message: str,
                      severity: str = "medium", details: Optional[Dict] = None) -> Dict:
        """Create a standardized alert dictionary"""
        return {
            "type": alert_type.value,
            "message": message,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "details": details or {}
        }

    def get_status(self) -> WiFiSecurityStatus:
        """Get current WiFi security status"""
        with self._lock:
            return self.status

    def get_security_summary(self) -> Dict:
        """Get a summary of WiFi security status"""
        with self._lock:
            # Count APs with potential issues
            evil_twin_candidates = 0
            for ssid, aps in self._aps_by_ssid.items():
                if len(set(ap.bssid for ap in aps)) > 1:
                    evil_twin_candidates += 1

            return {
                "monitoring_active": self.status.is_monitoring,
                "interface": self.status.interface,
                "total_aps_detected": sum(len(aps) for aps in self._aps_by_ssid.values()),
                "unique_ssids": len(self._aps_by_ssid),
                "evil_twin_candidates": evil_twin_candidates,
                "recent_deauth_events": len(self._deauth_events),
                "active_alerts": len(self.status.active_alerts),
                "total_alerts": self.status.total_alerts,
                "suspicious_processes": self.status.suspicious_processes,
                "last_scan": self.status.last_scan.isoformat() if self.status.last_scan else None
            }

    def clear_alerts(self):
        """Clear all active alerts"""
        with self._lock:
            self.status.active_alerts = []

    def reset(self):
        """Reset all monitoring data"""
        with self._lock:
            self._aps_by_ssid.clear()
            self._deauth_events.clear()
            self._recent_alerts.clear()
            self.status = WiFiSecurityStatus()
