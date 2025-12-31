"""
Network Traffic Anomaly Detection Module

Detects suspicious network traffic patterns including:
- Unusual outbound data volumes (data exfiltration)
- Port scanning activity (vertical and horizontal)
- Connections to unusual ports/protocols
- Beaconing patterns
- Covert channel detection
"""

import logging
import os
import sys
import re
import time
import threading
import subprocess
from enum import Enum
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = sys.platform == 'win32'


class TrafficAnomalyAlert(Enum):
    """Types of traffic anomaly alerts"""
    # Exfiltration detection
    HIGH_OUTBOUND_VOLUME = "high_outbound_volume"
    UNUSUAL_UPLOAD_RATIO = "unusual_upload_ratio"
    LARGE_TRANSFER = "large_transfer"
    SUSTAINED_OUTBOUND = "sustained_outbound"

    # Port scan detection
    VERTICAL_PORT_SCAN = "vertical_port_scan"
    HORIZONTAL_PORT_SCAN = "horizontal_port_scan"
    SYN_SCAN_DETECTED = "syn_scan_detected"
    STEALTH_SCAN = "stealth_scan"

    # Unusual connections
    UNUSUAL_PORT = "unusual_port"
    RARE_PROTOCOL = "rare_protocol"
    NON_STANDARD_PORT = "non_standard_port"
    HIGH_PORT_EPHEMERAL = "high_port_ephemeral"

    # Behavioral anomalies
    BEACONING_PATTERN = "beaconing_pattern"
    COVERT_CHANNEL = "covert_channel"
    DNS_OVER_TCP = "dns_over_tcp"
    ICMP_TUNNEL = "icmp_tunnel"


class TrafficSeverity(Enum):
    """Severity levels for traffic anomalies"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TrafficCategory(Enum):
    """Categories of traffic anomalies"""
    EXFILTRATION = "exfiltration"
    RECONNAISSANCE = "reconnaissance"
    EVASION = "evasion"
    BEHAVIORAL = "behavioral"


@dataclass
class TrafficAnomalyConfig:
    """Configuration for traffic anomaly detection"""
    # Exfiltration thresholds
    outbound_bytes_threshold: int = 100 * 1024 * 1024  # 100 MB in 5 minutes
    upload_ratio_threshold: float = 0.8  # Upload > 80% of total = suspicious
    large_transfer_threshold: int = 50 * 1024 * 1024  # 50 MB single transfer
    sustained_outbound_minutes: int = 5  # Minutes of sustained high upload

    # Port scan thresholds
    port_scan_threshold: int = 10  # Ports per minute to single host
    horizontal_scan_threshold: int = 5  # Hosts on same port per minute
    syn_only_threshold: int = 20  # SYN packets without completion

    # Connection thresholds
    unusual_port_list: List[int] = field(default_factory=lambda: [
        1337, 31337, 4444, 5555, 6666, 7777,  # Common backdoor ports
        6667, 6668, 6669,  # IRC (C2)
        8080, 8443, 8888,  # Alt HTTP/HTTPS
        9001, 9050, 9150,  # TOR
        3128, 8123,  # Proxies
    ])

    # Standard service ports (connections outside these may be flagged)
    standard_ports: Set[int] = field(default_factory=lambda: {
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137,
        138, 139, 143, 161, 162, 389, 443, 445, 465, 514, 587, 636, 993,
        995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443
    })

    # Beaconing detection
    beaconing_interval_tolerance: float = 0.1  # 10% tolerance for regularity
    beaconing_min_connections: int = 5  # Minimum connections to detect pattern

    # Monitoring intervals
    check_interval_seconds: int = 60
    history_window_minutes: int = 30


@dataclass
class ConnectionEvent:
    """Represents a network connection event"""
    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    bytes_sent: int = 0
    bytes_recv: int = 0
    state: str = "unknown"
    flags: str = ""


@dataclass
class TrafficAnomaly:
    """Represents a detected traffic anomaly"""
    alert_type: TrafficAnomalyAlert
    severity: TrafficSeverity
    category: TrafficCategory
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str]
    port: Optional[int]
    details: Dict = field(default_factory=dict)

    def to_alert_string(self) -> str:
        """Convert to alert message string"""
        msg = f"[{self.severity.value.upper()}] {self.alert_type.value}"
        if self.destination_ip:
            msg += f" - {self.source_ip} -> {self.destination_ip}"
        if self.port:
            msg += f":{self.port}"
        if self.details:
            detail_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            msg += f" ({detail_str})"
        return msg


@dataclass
class TrafficAnomalyStatus:
    """Current traffic anomaly monitoring status"""
    is_monitoring: bool = False
    total_connections: int = 0
    total_bytes_in: int = 0
    total_bytes_out: int = 0
    active_anomalies: List[TrafficAnomaly] = field(default_factory=list)
    alerts: List[str] = field(default_factory=list)
    last_check: Optional[datetime] = None


class TrafficAnomalyMonitor:
    """
    Monitors network traffic for anomalies including exfiltration,
    port scanning, and unusual connection patterns.
    """

    def __init__(self, config: Optional[TrafficAnomalyConfig] = None):
        self.config = config or TrafficAnomalyConfig()

        # Connection tracking
        self._connections: List[ConnectionEvent] = []
        self._connection_history: Dict[str, List[ConnectionEvent]] = defaultdict(list)

        # Traffic counters (per interface)
        self._bytes_sent: Dict[str, int] = defaultdict(int)
        self._bytes_recv: Dict[str, int] = defaultdict(int)
        self._last_bytes_sent: Dict[str, int] = {}
        self._last_bytes_recv: Dict[str, int] = {}

        # Port scan tracking
        self._port_access: Dict[str, Dict[str, Set[int]]] = defaultdict(lambda: defaultdict(set))
        self._host_access: Dict[str, Dict[int, Set[str]]] = defaultdict(lambda: defaultdict(set))
        self._syn_only: Dict[str, int] = defaultdict(int)

        # Beaconing detection
        self._connection_intervals: Dict[str, List[float]] = defaultdict(list)

        # Active anomalies
        self._anomalies: List[TrafficAnomaly] = []
        self._alerts: List[str] = []

        # Thread safety
        self._lock = threading.RLock()

        # Monitoring state
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._last_check = None

    def start(self):
        """Start background traffic monitoring"""
        with self._lock:
            if self._running:
                return

            self._running = True
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop,
                daemon=True
            )
            self._monitor_thread.start()

    def stop(self):
        """Stop background monitoring"""
        with self._lock:
            self._running = False
            if self._monitor_thread:
                self._monitor_thread.join(timeout=5)
                self._monitor_thread = None

    def _monitor_loop(self):
        """Background monitoring loop"""
        while self._running:
            try:
                self._check_traffic_stats()
                self._cleanup_old_data()
                self._last_check = datetime.utcnow()
            except Exception as e:
                logger.error(f"Error in traffic monitoring: {e}")

            time.sleep(self.config.check_interval_seconds)

    def analyze_connection(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str = "tcp",
        bytes_sent: int = 0,
        bytes_recv: int = 0,
        state: str = "established",
        flags: str = ""
    ) -> List[TrafficAnomaly]:
        """
        Analyze a network connection for anomalies.

        Args:
            src_ip: Source IP address
            src_port: Source port
            dst_ip: Destination IP address
            dst_port: Destination port
            protocol: Protocol (tcp, udp, icmp)
            bytes_sent: Bytes sent in this connection
            bytes_recv: Bytes received in this connection
            state: Connection state
            flags: TCP flags if applicable

        Returns:
            List of detected anomalies
        """
        anomalies = []
        now = datetime.utcnow()

        with self._lock:
            # Create connection event
            event = ConnectionEvent(
                timestamp=now,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                bytes_sent=bytes_sent,
                bytes_recv=bytes_recv,
                state=state,
                flags=flags
            )

            self._connections.append(event)
            self._connection_history[dst_ip].append(event)

            # Check for unusual ports
            port_anomaly = self._check_unusual_port(event)
            if port_anomaly:
                anomalies.append(port_anomaly)

            # Check for port scanning
            scan_anomalies = self._check_port_scanning(event)
            anomalies.extend(scan_anomalies)

            # Check for large transfers (potential exfiltration)
            if bytes_sent > self.config.large_transfer_threshold:
                anomaly = TrafficAnomaly(
                    alert_type=TrafficAnomalyAlert.LARGE_TRANSFER,
                    severity=TrafficSeverity.HIGH,
                    category=TrafficCategory.EXFILTRATION,
                    timestamp=now,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    port=dst_port,
                    details={
                        'bytes_sent': bytes_sent,
                        'threshold': self.config.large_transfer_threshold
                    }
                )
                anomalies.append(anomaly)

            # Check for beaconing patterns
            beaconing = self._check_beaconing(dst_ip, now)
            if beaconing:
                anomalies.append(beaconing)

            # Check for covert channels
            covert = self._check_covert_channel(event)
            if covert:
                anomalies.append(covert)

            # Store anomalies
            for anomaly in anomalies:
                self._anomalies.append(anomaly)
                self._alerts.append(anomaly.to_alert_string())

        return anomalies

    def analyze_traffic_volume(
        self,
        interface: str,
        bytes_sent: int,
        bytes_recv: int
    ) -> List[TrafficAnomaly]:
        """
        Analyze traffic volume for potential exfiltration.

        Args:
            interface: Network interface name
            bytes_sent: Total bytes sent on interface
            bytes_recv: Total bytes received on interface

        Returns:
            List of detected anomalies
        """
        anomalies = []
        now = datetime.utcnow()

        with self._lock:
            # Calculate delta since last check
            last_sent = self._last_bytes_sent.get(interface, 0)
            last_recv = self._last_bytes_recv.get(interface, 0)

            if last_sent > 0:
                delta_sent = bytes_sent - last_sent
                delta_recv = bytes_recv - last_recv

                # Check for high outbound volume
                if delta_sent > self.config.outbound_bytes_threshold:
                    anomaly = TrafficAnomaly(
                        alert_type=TrafficAnomalyAlert.HIGH_OUTBOUND_VOLUME,
                        severity=TrafficSeverity.HIGH,
                        category=TrafficCategory.EXFILTRATION,
                        timestamp=now,
                        source_ip="local",
                        destination_ip=None,
                        port=None,
                        details={
                            'interface': interface,
                            'bytes_sent': delta_sent,
                            'threshold': self.config.outbound_bytes_threshold
                        }
                    )
                    anomalies.append(anomaly)
                    self._anomalies.append(anomaly)
                    self._alerts.append(anomaly.to_alert_string())

                # Check upload ratio
                total = delta_sent + delta_recv
                if total > 0:
                    upload_ratio = delta_sent / total
                    if upload_ratio > self.config.upload_ratio_threshold:
                        anomaly = TrafficAnomaly(
                            alert_type=TrafficAnomalyAlert.UNUSUAL_UPLOAD_RATIO,
                            severity=TrafficSeverity.MEDIUM,
                            category=TrafficCategory.EXFILTRATION,
                            timestamp=now,
                            source_ip="local",
                            destination_ip=None,
                            port=None,
                            details={
                                'interface': interface,
                                'upload_ratio': round(upload_ratio, 2),
                                'threshold': self.config.upload_ratio_threshold
                            }
                        )
                        anomalies.append(anomaly)
                        self._anomalies.append(anomaly)
                        self._alerts.append(anomaly.to_alert_string())

            # Update last values
            self._last_bytes_sent[interface] = bytes_sent
            self._last_bytes_recv[interface] = bytes_recv
            self._bytes_sent[interface] = bytes_sent
            self._bytes_recv[interface] = bytes_recv

        return anomalies

    def detect_port_scan(
        self,
        src_ip: str,
        dst_ip: str,
        ports: List[int],
        scan_type: str = "connect"
    ) -> List[TrafficAnomaly]:
        """
        Detect port scanning activity.

        Args:
            src_ip: Source IP performing the scan
            dst_ip: Target IP being scanned
            ports: List of ports being probed
            scan_type: Type of scan (connect, syn, fin, xmas, null)

        Returns:
            List of detected scan anomalies
        """
        anomalies = []
        now = datetime.utcnow()

        with self._lock:
            # Track ports accessed
            key = f"{src_ip}->{dst_ip}"
            for port in ports:
                self._port_access[key][dst_ip].add(port)

            num_ports = len(self._port_access[key][dst_ip])

            # Detect vertical port scan (many ports on one host)
            if num_ports >= self.config.port_scan_threshold:
                severity = TrafficSeverity.HIGH if num_ports > 50 else TrafficSeverity.MEDIUM

                # Determine alert type based on scan type
                if scan_type == "syn":
                    alert_type = TrafficAnomalyAlert.SYN_SCAN_DETECTED
                elif scan_type in ["fin", "xmas", "null"]:
                    alert_type = TrafficAnomalyAlert.STEALTH_SCAN
                else:
                    alert_type = TrafficAnomalyAlert.VERTICAL_PORT_SCAN

                anomaly = TrafficAnomaly(
                    alert_type=alert_type,
                    severity=severity,
                    category=TrafficCategory.RECONNAISSANCE,
                    timestamp=now,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    port=None,
                    details={
                        'ports_scanned': num_ports,
                        'scan_type': scan_type,
                        'sample_ports': sorted(list(self._port_access[key][dst_ip]))[:10]
                    }
                )
                anomalies.append(anomaly)
                self._anomalies.append(anomaly)
                self._alerts.append(anomaly.to_alert_string())

        return anomalies

    def detect_horizontal_scan(
        self,
        src_ip: str,
        port: int,
        targets: List[str]
    ) -> List[TrafficAnomaly]:
        """
        Detect horizontal port scanning (same port across many hosts).

        Args:
            src_ip: Source IP performing the scan
            port: Port being probed
            targets: List of target IPs

        Returns:
            List of detected scan anomalies
        """
        anomalies = []
        now = datetime.utcnow()

        with self._lock:
            for target in targets:
                self._host_access[src_ip][port].add(target)

            num_hosts = len(self._host_access[src_ip][port])

            if num_hosts >= self.config.horizontal_scan_threshold:
                anomaly = TrafficAnomaly(
                    alert_type=TrafficAnomalyAlert.HORIZONTAL_PORT_SCAN,
                    severity=TrafficSeverity.HIGH,
                    category=TrafficCategory.RECONNAISSANCE,
                    timestamp=now,
                    source_ip=src_ip,
                    destination_ip=None,
                    port=port,
                    details={
                        'hosts_scanned': num_hosts,
                        'target_port': port,
                        'sample_targets': list(self._host_access[src_ip][port])[:10]
                    }
                )
                anomalies.append(anomaly)
                self._anomalies.append(anomaly)
                self._alerts.append(anomaly.to_alert_string())

        return anomalies

    def _check_unusual_port(self, event: ConnectionEvent) -> Optional[TrafficAnomaly]:
        """Check if connection uses an unusual port"""
        dst_port = event.dst_port

        # Check known suspicious ports
        if dst_port in self.config.unusual_port_list:
            return TrafficAnomaly(
                alert_type=TrafficAnomalyAlert.UNUSUAL_PORT,
                severity=TrafficSeverity.MEDIUM,
                category=TrafficCategory.EVASION,
                timestamp=event.timestamp,
                source_ip=event.src_ip,
                destination_ip=event.dst_ip,
                port=dst_port,
                details={'reason': 'known suspicious port'}
            )

        # Check for non-standard ports (outside common services)
        if dst_port not in self.config.standard_ports and dst_port < 1024:
            return TrafficAnomaly(
                alert_type=TrafficAnomalyAlert.NON_STANDARD_PORT,
                severity=TrafficSeverity.LOW,
                category=TrafficCategory.EVASION,
                timestamp=event.timestamp,
                source_ip=event.src_ip,
                destination_ip=event.dst_ip,
                port=dst_port,
                details={'reason': 'non-standard low port'}
            )

        return None

    def _check_port_scanning(self, event: ConnectionEvent) -> List[TrafficAnomaly]:
        """Check for port scanning patterns"""
        anomalies = []
        src_ip = event.src_ip
        dst_ip = event.dst_ip
        dst_port = event.dst_port

        key = f"{src_ip}->{dst_ip}"
        self._port_access[key][dst_ip].add(dst_port)

        # Check for SYN-only connections (SYN scan indicator)
        if 'S' in event.flags and 'A' not in event.flags:
            self._syn_only[key] += 1

            if self._syn_only[key] >= self.config.syn_only_threshold:
                anomaly = TrafficAnomaly(
                    alert_type=TrafficAnomalyAlert.SYN_SCAN_DETECTED,
                    severity=TrafficSeverity.HIGH,
                    category=TrafficCategory.RECONNAISSANCE,
                    timestamp=event.timestamp,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    port=None,
                    details={
                        'syn_only_count': self._syn_only[key],
                        'threshold': self.config.syn_only_threshold
                    }
                )
                anomalies.append(anomaly)

        # Check for rapid port enumeration
        num_ports = len(self._port_access[key][dst_ip])
        if num_ports >= self.config.port_scan_threshold:
            # Only alert once per threshold crossing
            if num_ports == self.config.port_scan_threshold:
                anomaly = TrafficAnomaly(
                    alert_type=TrafficAnomalyAlert.VERTICAL_PORT_SCAN,
                    severity=TrafficSeverity.MEDIUM,
                    category=TrafficCategory.RECONNAISSANCE,
                    timestamp=event.timestamp,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    port=None,
                    details={
                        'ports_probed': num_ports,
                        'sample_ports': sorted(list(self._port_access[key][dst_ip]))[:5]
                    }
                )
                anomalies.append(anomaly)

        return anomalies

    def _check_beaconing(self, dst_ip: str, now: datetime) -> Optional[TrafficAnomaly]:
        """Check for beaconing patterns to a destination"""
        history = self._connection_history.get(dst_ip, [])

        if len(history) < self.config.beaconing_min_connections:
            return None

        # Calculate intervals between connections
        timestamps = [e.timestamp for e in history[-20:]]  # Last 20 connections
        if len(timestamps) < 3:
            return None

        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            if interval > 0:
                intervals.append(interval)

        if len(intervals) < 3:
            return None

        # Check for regularity (beaconing has consistent intervals)
        avg_interval = sum(intervals) / len(intervals)
        if avg_interval <= 0:
            return None

        # Calculate coefficient of variation
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        std_dev = variance ** 0.5
        cv = std_dev / avg_interval

        # Low CV indicates regular beaconing
        if cv < self.config.beaconing_interval_tolerance:
            return TrafficAnomaly(
                alert_type=TrafficAnomalyAlert.BEACONING_PATTERN,
                severity=TrafficSeverity.HIGH,
                category=TrafficCategory.BEHAVIORAL,
                timestamp=now,
                source_ip="local",
                destination_ip=dst_ip,
                port=None,
                details={
                    'avg_interval_seconds': round(avg_interval, 2),
                    'coefficient_of_variation': round(cv, 4),
                    'connection_count': len(history)
                }
            )

        return None

    def _check_covert_channel(self, event: ConnectionEvent) -> Optional[TrafficAnomaly]:
        """Check for potential covert channel usage"""
        # DNS over TCP (unusual, may be tunneling)
        if event.dst_port == 53 and event.protocol == "tcp":
            return TrafficAnomaly(
                alert_type=TrafficAnomalyAlert.DNS_OVER_TCP,
                severity=TrafficSeverity.MEDIUM,
                category=TrafficCategory.EVASION,
                timestamp=event.timestamp,
                source_ip=event.src_ip,
                destination_ip=event.dst_ip,
                port=53,
                details={'reason': 'DNS over TCP may indicate tunneling'}
            )

        # ICMP with significant data (potential tunnel)
        if event.protocol == "icmp" and event.bytes_sent > 1000:
            return TrafficAnomaly(
                alert_type=TrafficAnomalyAlert.ICMP_TUNNEL,
                severity=TrafficSeverity.HIGH,
                category=TrafficCategory.EVASION,
                timestamp=event.timestamp,
                source_ip=event.src_ip,
                destination_ip=event.dst_ip,
                port=None,
                details={
                    'bytes_in_icmp': event.bytes_sent,
                    'reason': 'large ICMP payload suggests tunneling'
                }
            )

        return None

    def _check_traffic_stats(self):
        """Check system traffic statistics"""
        try:
            if IS_WINDOWS:
                # Windows: Use psutil for network I/O stats (cross-platform)
                try:
                    import psutil
                    net_io = psutil.net_io_counters(pernic=True)
                    for iface, stats in net_io.items():
                        if 'loopback' not in iface.lower():
                            self.analyze_traffic_volume(iface, stats.bytes_sent, stats.bytes_recv)
                except ImportError:
                    logger.debug("psutil not available for network stats")
            else:
                # Linux: Read /proc/net/dev for interface statistics
                if os.path.exists('/proc/net/dev'):
                    with open('/proc/net/dev', 'r') as f:
                        lines = f.readlines()[2:]  # Skip headers

                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 10:
                            iface = parts[0].rstrip(':')
                            if iface not in ['lo']:  # Skip loopback
                                bytes_recv = int(parts[1])
                                bytes_sent = int(parts[9])
                                self.analyze_traffic_volume(iface, bytes_sent, bytes_recv)
        except Exception as e:
            logger.error(f"Error reading traffic stats: {e}")

    def _cleanup_old_data(self):
        """Remove old data outside the history window"""
        cutoff = datetime.utcnow() - timedelta(minutes=self.config.history_window_minutes)

        with self._lock:
            # Clean connections
            self._connections = [c for c in self._connections if c.timestamp > cutoff]

            # Clean connection history
            for ip in list(self._connection_history.keys()):
                self._connection_history[ip] = [
                    c for c in self._connection_history[ip] if c.timestamp > cutoff
                ]
                if not self._connection_history[ip]:
                    del self._connection_history[ip]

            # Clean anomalies
            self._anomalies = [a for a in self._anomalies if a.timestamp > cutoff]

            # Limit alerts history
            if len(self._alerts) > 100:
                self._alerts = self._alerts[-100:]

            # Reset scan tracking periodically
            self._port_access.clear()
            self._host_access.clear()
            self._syn_only.clear()

    def get_status(self) -> TrafficAnomalyStatus:
        """Get current monitoring status"""
        with self._lock:
            return TrafficAnomalyStatus(
                is_monitoring=self._running,
                total_connections=len(self._connections),
                total_bytes_in=sum(self._bytes_recv.values()),
                total_bytes_out=sum(self._bytes_sent.values()),
                active_anomalies=list(self._anomalies),
                alerts=list(self._alerts),
                last_check=self._last_check
            )

    def get_recent_anomalies(self, limit: int = 10) -> List[TrafficAnomaly]:
        """Get most recent anomalies"""
        with self._lock:
            return sorted(
                self._anomalies,
                key=lambda a: a.timestamp,
                reverse=True
            )[:limit]

    def clear_alerts(self):
        """Clear all alerts and anomalies"""
        with self._lock:
            self._anomalies.clear()
            self._alerts.clear()
