"""
State Monitor - Environment Sensing Component
Continuously monitors network, hardware, software, and human presence signals.
"""

import os
import sys
import psutil
import socket
import subprocess
import threading
import time
import logging
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Set
from enum import Enum
from datetime import datetime
from collections import deque

logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = sys.platform == 'win32'


class NetworkState(Enum):
    """Network connectivity state"""
    OFFLINE = "offline"
    ONLINE = "online"


class NetworkType(Enum):
    """Network interface type classification"""
    ETHERNET = "ethernet"      # eth*, en*, eno*, enp* interfaces
    WIFI = "wifi"              # wlan*, wlp*, wifi*, ath* interfaces
    CELLULAR_4G = "cellular_4g"  # wwan*, wwp*, ppp* with LTE/4G
    CELLULAR_5G = "cellular_5g"  # wwan* with 5G capability
    VPN = "vpn"                # tun*, vpn*, wg*, tap* interfaces
    BLUETOOTH = "bluetooth"    # bt*, bnep* interfaces
    BRIDGE = "bridge"          # br*, virbr*, docker* interfaces
    # IoT and specialty network types
    LORA = "lora"              # LoRa/LoRaWAN - Long-range IoT
    THREAD = "thread"          # Thread/Matter - Smart home mesh
    WIMAX = "wimax"            # WiMAX - Mostly obsolete
    IRDA = "irda"              # Infrared (IrDA) - Legacy
    ANT_PLUS = "ant_plus"      # ANT+ - Fitness devices
    UNKNOWN = "unknown"        # Unclassified interfaces


class CellularSecurityAlert(Enum):
    """Cellular security alert types (IMSI catcher/Stingray detection)"""
    NONE = "none"
    TOWER_CHANGE = "tower_change"           # Unexpected cell tower change
    WEAK_ENCRYPTION = "weak_encryption"     # 2G/no encryption forced
    SIGNAL_ANOMALY = "signal_anomaly"       # Unusual signal strength pattern
    IMSI_CATCHER = "imsi_catcher"           # Suspected IMSI catcher
    DOWNGRADE_ATTACK = "downgrade_attack"   # Forced protocol downgrade


@dataclass
class SpecialtyNetworkStatus:
    """Status of specialty/IoT network interfaces"""
    lora_devices: List[str]          # Detected LoRa/LoRaWAN devices
    thread_devices: List[str]        # Thread/Matter mesh devices
    wimax_interfaces: List[str]      # WiMAX interfaces (legacy)
    irda_devices: List[str]          # IrDA infrared devices
    ant_plus_devices: List[str]      # ANT+ fitness devices
    cellular_alerts: List[str]       # Security alerts for cellular

    def to_dict(self) -> Dict:
        return {
            'lora_devices': self.lora_devices,
            'thread_devices': self.thread_devices,
            'wimax_interfaces': self.wimax_interfaces,
            'irda_devices': self.irda_devices,
            'ant_plus_devices': self.ant_plus_devices,
            'cellular_alerts': self.cellular_alerts
        }


@dataclass
class MonitoringConfig:
    """Configuration for which network types to monitor"""
    monitor_lora: bool = True
    monitor_thread: bool = True
    monitor_cellular_security: bool = True
    monitor_wimax: bool = False      # Disabled by default (obsolete)
    monitor_irda: bool = False       # Disabled by default (legacy)
    monitor_ant_plus: bool = True
    monitor_dns_security: bool = True  # DNS security monitoring
    monitor_arp_security: bool = True  # ARP security monitoring
    monitor_wifi_security: bool = True  # WiFi security monitoring
    monitor_threat_intel: bool = True  # Threat intelligence monitoring
    monitor_file_integrity: bool = True  # File integrity monitoring
    monitor_traffic_anomaly: bool = True  # Traffic anomaly monitoring
    monitor_process_security: bool = True  # Process security monitoring

    def to_dict(self) -> Dict:
        return {
            'monitor_lora': self.monitor_lora,
            'monitor_thread': self.monitor_thread,
            'monitor_cellular_security': self.monitor_cellular_security,
            'monitor_wimax': self.monitor_wimax,
            'monitor_irda': self.monitor_irda,
            'monitor_ant_plus': self.monitor_ant_plus,
            'monitor_dns_security': self.monitor_dns_security,
            'monitor_arp_security': self.monitor_arp_security,
            'monitor_wifi_security': self.monitor_wifi_security,
            'monitor_threat_intel': self.monitor_threat_intel,
            'monitor_file_integrity': self.monitor_file_integrity,
            'monitor_traffic_anomaly': self.monitor_traffic_anomaly,
            'monitor_process_security': self.monitor_process_security
        }


class HardwareTrust(Enum):
    """Hardware trust level based on detected conditions"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class EnvironmentState:
    """Complete environment state snapshot"""
    timestamp: str
    network: NetworkState
    hardware_trust: HardwareTrust

    # Network details
    active_interfaces: List[str]
    interface_types: Dict[str, NetworkType]  # Map of interface name to type
    has_internet: bool
    vpn_active: bool
    dns_available: bool

    # Specialty/IoT network details
    specialty_networks: SpecialtyNetworkStatus

    # DNS security details
    dns_security_alerts: List[str]

    # ARP security details
    arp_security_alerts: List[str]

    # WiFi security details
    wifi_security_alerts: List[str]

    # Threat intelligence details
    threat_intel_alerts: List[str]

    # File integrity details
    file_integrity_alerts: List[str]

    # Traffic anomaly details
    traffic_anomaly_alerts: List[str]

    # Process security details
    process_security_alerts: List[str]

    # Hardware details
    usb_devices: Set[str]
    block_devices: Set[str]
    camera_available: bool
    mic_available: bool
    tpm_present: bool

    # Software details
    external_model_endpoints: List[str]
    suspicious_processes: List[str]
    shell_escapes_detected: int

    # Human presence
    keyboard_active: bool
    screen_unlocked: bool
    last_activity: Optional[str]

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        result = asdict(self)
        result['network'] = self.network.value
        result['hardware_trust'] = self.hardware_trust.value
        result['interface_types'] = {k: v.value for k, v in self.interface_types.items()}
        result['specialty_networks'] = self.specialty_networks.to_dict()
        result['dns_security_alerts'] = self.dns_security_alerts
        result['arp_security_alerts'] = self.arp_security_alerts
        result['wifi_security_alerts'] = self.wifi_security_alerts
        result['threat_intel_alerts'] = self.threat_intel_alerts
        result['file_integrity_alerts'] = self.file_integrity_alerts
        result['traffic_anomaly_alerts'] = self.traffic_anomaly_alerts
        result['process_security_alerts'] = self.process_security_alerts
        result['usb_devices'] = list(self.usb_devices)
        result['block_devices'] = list(self.block_devices)
        return result


class StateMonitor:
    """
    Continuous environment monitoring service.
    Detects network state, hardware changes, software anomalies, and human presence.
    """

    def __init__(self, poll_interval: float = 1.0, monitoring_config: Optional[MonitoringConfig] = None):
        """
        Initialize state monitor.

        Args:
            poll_interval: How frequently to poll environment (seconds)
            monitoring_config: Configuration for which network types to monitor
        """
        self.poll_interval = poll_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._current_state: Optional[EnvironmentState] = None
        self._state_lock = threading.Lock()
        self._callbacks: List[callable] = []

        # Monitoring configuration
        self.monitoring_config = monitoring_config or MonitoringConfig()

        # Baseline state for detecting changes
        self._baseline_usb: Optional[Set[str]] = None
        self._baseline_block_devices: Optional[Set[str]] = None
        self._last_network_state: Optional[NetworkState] = None

        # Cellular security tracking (for IMSI catcher detection)
        self._last_cell_tower: Optional[str] = None
        self._cell_tower_history: deque = deque(maxlen=100)  # Bounded history
        self._signal_strength_history: deque = deque(maxlen=20)  # Bounded history

        # DNS security monitor (lazy initialization)
        self._dns_security_monitor = None

        # ARP security monitor (lazy initialization)
        self._arp_security_monitor = None

        # WiFi security monitor (lazy initialization)
        self._wifi_security_monitor = None

        # Threat intelligence monitor (lazy initialization)
        self._threat_intel_monitor = None

        # File integrity monitor (lazy initialization)
        self._file_integrity_monitor = None

        # Traffic anomaly monitor (lazy initialization)
        self._traffic_anomaly_monitor = None

        # Process security monitor (lazy initialization)
        self._process_security_monitor = None

    def get_monitoring_config(self) -> MonitoringConfig:
        """Get the current monitoring configuration"""
        return self.monitoring_config

    def set_monitoring_config(self, config: MonitoringConfig):
        """Set the monitoring configuration"""
        self.monitoring_config = config

    def set_monitor_lora(self, enabled: bool):
        """Enable or disable LoRa/LoRaWAN monitoring"""
        self.monitoring_config.monitor_lora = enabled

    def set_monitor_thread(self, enabled: bool):
        """Enable or disable Thread/Matter monitoring"""
        self.monitoring_config.monitor_thread = enabled

    def set_monitor_cellular_security(self, enabled: bool):
        """Enable or disable cellular security (IMSI catcher) monitoring"""
        self.monitoring_config.monitor_cellular_security = enabled

    def set_monitor_wimax(self, enabled: bool):
        """Enable or disable WiMAX monitoring"""
        self.monitoring_config.monitor_wimax = enabled

    def set_monitor_irda(self, enabled: bool):
        """Enable or disable IrDA monitoring"""
        self.monitoring_config.monitor_irda = enabled

    def set_monitor_ant_plus(self, enabled: bool):
        """Enable or disable ANT+ monitoring"""
        self.monitoring_config.monitor_ant_plus = enabled

    def set_monitor_dns_security(self, enabled: bool):
        """Enable or disable DNS security monitoring"""
        self.monitoring_config.monitor_dns_security = enabled

    def _get_dns_security_monitor(self):
        """Get or create DNS security monitor (lazy initialization)"""
        if self._dns_security_monitor is None:
            try:
                from daemon.security.dns_security import DNSSecurityMonitor
                self._dns_security_monitor = DNSSecurityMonitor()
            except ImportError:
                return None
        return self._dns_security_monitor

    def set_monitor_arp_security(self, enabled: bool):
        """Enable or disable ARP security monitoring"""
        self.monitoring_config.monitor_arp_security = enabled

    def _get_arp_security_monitor(self):
        """Get or create ARP security monitor (lazy initialization)"""
        if self._arp_security_monitor is None:
            try:
                from daemon.security.arp_security import ARPSecurityMonitor
                self._arp_security_monitor = ARPSecurityMonitor()
            except ImportError:
                return None
        return self._arp_security_monitor

    def set_monitor_wifi_security(self, enabled: bool):
        """Enable or disable WiFi security monitoring"""
        self.monitoring_config.monitor_wifi_security = enabled

    def _get_wifi_security_monitor(self):
        """Get or create WiFi security monitor (lazy initialization)"""
        if self._wifi_security_monitor is None:
            try:
                from daemon.security.wifi_security import WiFiSecurityMonitor
                self._wifi_security_monitor = WiFiSecurityMonitor()
            except ImportError:
                return None
        return self._wifi_security_monitor

    def set_monitor_threat_intel(self, enabled: bool):
        """Enable or disable threat intelligence monitoring"""
        self.monitoring_config.monitor_threat_intel = enabled

    def _get_threat_intel_monitor(self):
        """Get or create threat intelligence monitor (lazy initialization)"""
        if self._threat_intel_monitor is None:
            try:
                from daemon.security.threat_intel import ThreatIntelMonitor
                self._threat_intel_monitor = ThreatIntelMonitor()
            except ImportError:
                return None
        return self._threat_intel_monitor

    def set_monitor_file_integrity(self, enabled: bool):
        """Enable or disable file integrity monitoring"""
        self.monitoring_config.monitor_file_integrity = enabled

    def _get_file_integrity_monitor(self):
        """Get or create file integrity monitor (lazy initialization)"""
        if self._file_integrity_monitor is None:
            try:
                from daemon.security.file_integrity import FileIntegrityMonitor
                self._file_integrity_monitor = FileIntegrityMonitor()
            except ImportError:
                return None
        return self._file_integrity_monitor

    def set_monitor_traffic_anomaly(self, enabled: bool):
        """Enable or disable traffic anomaly monitoring"""
        self.monitoring_config.monitor_traffic_anomaly = enabled

    def _get_traffic_anomaly_monitor(self):
        """Get or create traffic anomaly monitor (lazy initialization)"""
        if self._traffic_anomaly_monitor is None:
            try:
                from daemon.security.traffic_anomaly import TrafficAnomalyMonitor
                self._traffic_anomaly_monitor = TrafficAnomalyMonitor()
            except ImportError:
                return None
        return self._traffic_anomaly_monitor

    def set_monitor_process_security(self, enabled: bool):
        """Enable or disable process security monitoring"""
        self.monitoring_config.monitor_process_security = enabled

    def _get_process_security_monitor(self):
        """Get or create process security monitor (lazy initialization)"""
        if self._process_security_monitor is None:
            try:
                from daemon.security.process_security import ProcessSecurityMonitor
                self._process_security_monitor = ProcessSecurityMonitor()
            except ImportError:
                return None
        return self._process_security_monitor

    def register_callback(self, callback: callable):
        """
        Register a callback to be notified of state changes.

        Args:
            callback: Function accepting (old_state, new_state)
        """
        self._callbacks.append(callback)

    def start(self):
        """Start continuous monitoring"""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop monitoring"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)

    def get_current_state(self) -> Optional[EnvironmentState]:
        """Get the most recent environment state"""
        with self._state_lock:
            return self._current_state

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                new_state = self._sample_environment()

                with self._state_lock:
                    old_state = self._current_state
                    self._current_state = new_state

                # Notify callbacks of state change
                if old_state != new_state:
                    for callback in self._callbacks:
                        try:
                            callback(old_state, new_state)
                        except Exception as e:
                            logger.error(f"Error in state change callback: {e}")

                time.sleep(self.poll_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.poll_interval)

    def _sample_environment(self) -> EnvironmentState:
        """Sample all environment sensors"""
        timestamp = datetime.utcnow().isoformat() + "Z"

        # Network sensing
        network_info = self._check_network()

        # Specialty/IoT network sensing
        specialty_info = self._check_specialty_networks()

        # DNS security sensing
        dns_security_alerts = self._check_dns_security()

        # ARP security sensing
        arp_security_alerts = self._check_arp_security()

        # WiFi security sensing
        wifi_security_alerts = self._check_wifi_security()

        # Threat intelligence sensing
        threat_intel_alerts = self._check_threat_intel()

        # File integrity sensing
        file_integrity_alerts = self._check_file_integrity()

        # Traffic anomaly sensing
        traffic_anomaly_alerts = self._check_traffic_anomaly()

        # Process security sensing
        process_security_alerts = self._check_process_security()

        # Hardware sensing
        hardware_info = self._check_hardware()

        # Software sensing
        software_info = self._check_software()

        # Human presence sensing
        presence_info = self._check_human_presence()

        # Determine overall hardware trust level
        hardware_trust = self._calculate_hardware_trust(hardware_info)

        # Detect network state changes for tripwire detection
        current_network = network_info['state']
        if self._last_network_state != current_network:
            self._last_network_state = current_network

        return EnvironmentState(
            timestamp=timestamp,
            network=network_info['state'],
            hardware_trust=hardware_trust,
            active_interfaces=network_info['interfaces'],
            interface_types=network_info['interface_types'],
            has_internet=network_info['has_internet'],
            vpn_active=network_info['vpn_active'],
            dns_available=network_info['dns_available'],
            specialty_networks=specialty_info,
            dns_security_alerts=dns_security_alerts,
            arp_security_alerts=arp_security_alerts,
            wifi_security_alerts=wifi_security_alerts,
            threat_intel_alerts=threat_intel_alerts,
            file_integrity_alerts=file_integrity_alerts,
            traffic_anomaly_alerts=traffic_anomaly_alerts,
            process_security_alerts=process_security_alerts,
            usb_devices=hardware_info['usb_devices'],
            block_devices=hardware_info['block_devices'],
            camera_available=hardware_info['camera'],
            mic_available=hardware_info['mic'],
            tpm_present=hardware_info['tpm'],
            external_model_endpoints=software_info['external_endpoints'],
            suspicious_processes=software_info['suspicious_processes'],
            shell_escapes_detected=software_info['shell_escapes'],
            keyboard_active=presence_info['keyboard_active'],
            screen_unlocked=presence_info['screen_unlocked'],
            last_activity=presence_info['last_activity']
        )

    def _detect_interface_type(self, iface: str) -> NetworkType:
        """
        Detect the type of a network interface based on its name and system info.

        Args:
            iface: Interface name (e.g., 'eth0', 'wlan0', 'wg0')

        Returns:
            NetworkType enum value
        """
        iface_lower = iface.lower()

        # VPN interfaces (check first as they may overlay other types)
        if any(pattern in iface_lower for pattern in ['tun', 'tap', 'vpn', 'wg']):
            return NetworkType.VPN

        # WiFi/WLAN interfaces
        if any(pattern in iface_lower for pattern in ['wlan', 'wlp', 'wifi', 'ath', 'wlx']):
            return NetworkType.WIFI

        # Cellular interfaces - try to detect 5G vs 4G
        if any(pattern in iface_lower for pattern in ['wwan', 'wwp', 'rmnet', 'usb']):
            # Check for 5G capability via sysfs if available
            if self._is_5g_capable(iface):
                return NetworkType.CELLULAR_5G
            return NetworkType.CELLULAR_4G

        # PPP interfaces (often used for cellular/dial-up)
        if iface_lower.startswith('ppp'):
            return NetworkType.CELLULAR_4G

        # Bluetooth interfaces
        if any(pattern in iface_lower for pattern in ['bt', 'bnep', 'pan']):
            return NetworkType.BLUETOOTH

        # Bridge interfaces
        if any(pattern in iface_lower for pattern in ['br', 'virbr', 'docker', 'veth', 'cni']):
            return NetworkType.BRIDGE

        # Ethernet interfaces (most common patterns)
        if any(pattern in iface_lower for pattern in ['eth', 'enp', 'eno', 'ens', 'em']):
            return NetworkType.ETHERNET

        # Try to detect type from sysfs as a fallback
        sys_type = self._get_interface_type_from_sysfs(iface)
        if sys_type:
            return sys_type

        return NetworkType.UNKNOWN

    def _is_5g_capable(self, iface: str) -> bool:
        """
        Check if a cellular interface supports 5G.

        Args:
            iface: Interface name

        Returns:
            True if 5G capable, False otherwise
        """
        # Skip sysfs checks on Windows - no equivalent
        if IS_WINDOWS:
            return False

        # Check modem capabilities via sysfs/dbus if available (Linux only)
        try:
            # Check for 5G modem indicators in sysfs
            modem_paths = [
                f'/sys/class/net/{iface}/device/capabilities',
                f'/sys/class/net/{iface}/device/uevent'
            ]
            for path in modem_paths:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        content = f.read().lower()
                        if '5g' in content or 'nr' in content:
                            return True

            # Check ModemManager info if available
            mm_path = f'/sys/class/net/{iface}/device/driver'
            if os.path.exists(mm_path):
                driver = os.readlink(mm_path)
                # Common 5G modem drivers
                if any(d in driver.lower() for d in ['qmi', 'mbim', 'option']):
                    # Additional check would need ModemManager D-Bus API
                    pass
        except Exception:
            pass

        return False

    def _get_interface_type_from_sysfs(self, iface: str) -> Optional[NetworkType]:
        """
        Get interface type from sysfs as a fallback.

        Args:
            iface: Interface name

        Returns:
            NetworkType if detected, None otherwise
        """
        # Skip sysfs checks on Windows - use interface name heuristics instead
        if IS_WINDOWS:
            iface_lower = iface.lower()
            if 'wi-fi' in iface_lower or 'wireless' in iface_lower or 'wlan' in iface_lower:
                return NetworkType.WIFI
            if 'ethernet' in iface_lower or 'local area' in iface_lower:
                return NetworkType.ETHERNET
            if 'vpn' in iface_lower or 'tunnel' in iface_lower:
                return NetworkType.VPN
            if 'bluetooth' in iface_lower:
                return NetworkType.BLUETOOTH
            return None

        try:
            # Check the interface type from sysfs (Linux only)
            type_path = f'/sys/class/net/{iface}/type'
            if os.path.exists(type_path):
                with open(type_path, 'r') as f:
                    iface_type = int(f.read().strip())
                    # Linux ARPHRD types
                    if iface_type == 1:  # ARPHRD_ETHER - could be ethernet or wifi
                        # Check for wireless directory
                        if os.path.exists(f'/sys/class/net/{iface}/wireless'):
                            return NetworkType.WIFI
                        return NetworkType.ETHERNET
                    elif iface_type == 772:  # ARPHRD_LOOPBACK
                        return None  # Skip loopback
                    elif iface_type == 65534:  # ARPHRD_NONE (tunnel)
                        return NetworkType.VPN

            # Check for wireless interface
            if os.path.exists(f'/sys/class/net/{iface}/wireless'):
                return NetworkType.WIFI

            # Check device driver for clues
            driver_path = f'/sys/class/net/{iface}/device/driver'
            if os.path.exists(driver_path):
                driver = os.path.basename(os.readlink(driver_path))
                if driver in ['iwlwifi', 'ath9k', 'ath10k', 'rtlwifi', 'brcmfmac']:
                    return NetworkType.WIFI
                if driver in ['e1000', 'e1000e', 'igb', 'ixgbe', 'r8169']:
                    return NetworkType.ETHERNET
        except Exception:
            pass

        return None

    def _check_network(self) -> Dict:
        """Check network state"""
        interfaces = []
        interface_types: Dict[str, NetworkType] = {}
        has_internet = False
        vpn_active = False
        dns_available = False

        # Get active network interfaces
        try:
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()

            for iface, addrs in net_if_addrs.items():
                if iface in net_if_stats and net_if_stats[iface].isup:
                    # Skip loopback
                    if iface != 'lo' and not iface.startswith('lo'):
                        interfaces.append(iface)

                        # Detect interface type
                        iface_type = self._detect_interface_type(iface)
                        interface_types[iface] = iface_type

                        # Check for VPN interfaces using the detected type
                        if iface_type == NetworkType.VPN:
                            vpn_active = True
        except Exception as e:
            logger.error(f"Error checking network interfaces: {e}")

        # Test for internet connectivity
        try:
            # Try to resolve a common domain
            # Note: socket.getaddrinfo doesn't accept timeout parameter
            # Use setdefaulttimeout temporarily for DNS lookup timeout
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(2.0)
            try:
                socket.getaddrinfo('google.com', 80)
                dns_available = True
                has_internet = True
            finally:
                socket.setdefaulttimeout(old_timeout)
        except (socket.gaierror, socket.timeout, OSError):
            pass

        # Determine overall network state
        state = NetworkState.ONLINE if (interfaces or has_internet) else NetworkState.OFFLINE

        return {
            'state': state,
            'interfaces': interfaces,
            'interface_types': interface_types,
            'has_internet': has_internet,
            'vpn_active': vpn_active,
            'dns_available': dns_available
        }

    def _check_specialty_networks(self) -> SpecialtyNetworkStatus:
        """Check for specialty/IoT network devices based on monitoring config"""
        lora_devices = []
        thread_devices = []
        wimax_interfaces = []
        irda_devices = []
        ant_plus_devices = []
        cellular_alerts = []

        # LoRa/LoRaWAN detection
        if self.monitoring_config.monitor_lora:
            lora_devices = self._detect_lora_devices()

        # Thread/Matter mesh detection
        if self.monitoring_config.monitor_thread:
            thread_devices = self._detect_thread_devices()

        # WiMAX detection (legacy)
        if self.monitoring_config.monitor_wimax:
            wimax_interfaces = self._detect_wimax_interfaces()

        # IrDA infrared detection (legacy)
        if self.monitoring_config.monitor_irda:
            irda_devices = self._detect_irda_devices()

        # ANT+ fitness device detection
        if self.monitoring_config.monitor_ant_plus:
            ant_plus_devices = self._detect_ant_plus_devices()

        # Cellular security (IMSI catcher/Stingray detection)
        if self.monitoring_config.monitor_cellular_security:
            cellular_alerts = self._detect_cellular_security_threats()

        return SpecialtyNetworkStatus(
            lora_devices=lora_devices,
            thread_devices=thread_devices,
            wimax_interfaces=wimax_interfaces,
            irda_devices=irda_devices,
            ant_plus_devices=ant_plus_devices,
            cellular_alerts=cellular_alerts
        )

    def _check_dns_security(self) -> List[str]:
        """Check for DNS security threats if monitoring is enabled"""
        if not self.monitoring_config.monitor_dns_security:
            return []

        try:
            dns_monitor = self._get_dns_security_monitor()
            if dns_monitor is None:
                return []

            # Get current DNS security status
            status = dns_monitor.get_status()
            return status.alerts
        except Exception as e:
            logger.error(f"Error checking DNS security: {e}")
            return []

    def _check_arp_security(self) -> List[str]:
        """Check for ARP security threats if monitoring is enabled"""
        if not self.monitoring_config.monitor_arp_security:
            return []

        try:
            arp_monitor = self._get_arp_security_monitor()
            if arp_monitor is None:
                return []

            # Update ARP table and get current status
            arp_monitor._update_arp_table()
            status = arp_monitor.get_status()
            return status.alerts
        except Exception as e:
            logger.error(f"Error checking ARP security: {e}")
            return []

    def _check_wifi_security(self) -> List[str]:
        """Check for WiFi security threats if monitoring is enabled"""
        if not self.monitoring_config.monitor_wifi_security:
            return []

        try:
            wifi_monitor = self._get_wifi_security_monitor()
            if wifi_monitor is None:
                return []

            # Check for suspicious processes (attack tools)
            alerts = wifi_monitor.check_suspicious_processes()

            # Get current status alerts
            status = wifi_monitor.get_status()
            alert_messages = [
                alert.get('message', str(alert)) for alert in status.active_alerts
            ]
            return alert_messages
        except Exception as e:
            logger.error(f"Error checking WiFi security: {e}")
            return []

    def _check_threat_intel(self) -> List[str]:
        """Check for threat intelligence alerts if monitoring is enabled"""
        if not self.monitoring_config.monitor_threat_intel:
            return []

        try:
            threat_monitor = self._get_threat_intel_monitor()
            if threat_monitor is None:
                return []

            # Get current status alerts
            status = threat_monitor.get_status()
            return status.alerts
        except Exception as e:
            logger.error(f"Error checking threat intelligence: {e}")
            return []

    def _check_file_integrity(self) -> List[str]:
        """Check for file integrity alerts if monitoring is enabled"""
        if not self.monitoring_config.monitor_file_integrity:
            return []

        try:
            fim_monitor = self._get_file_integrity_monitor()
            if fim_monitor is None:
                return []

            # Get current status alerts
            status = fim_monitor.get_status()
            return status.alerts
        except Exception as e:
            logger.error(f"Error checking file integrity: {e}")
            return []

    def _check_traffic_anomaly(self) -> List[str]:
        """Check for traffic anomaly alerts if monitoring is enabled"""
        if not self.monitoring_config.monitor_traffic_anomaly:
            return []

        try:
            traffic_monitor = self._get_traffic_anomaly_monitor()
            if traffic_monitor is None:
                return []

            # Get current status alerts
            status = traffic_monitor.get_status()
            return status.alerts
        except Exception as e:
            logger.error(f"Error checking traffic anomaly: {e}")
            return []

    def _check_process_security(self) -> List[str]:
        """Check for process security alerts if monitoring is enabled"""
        if not self.monitoring_config.monitor_process_security:
            return []

        try:
            process_monitor = self._get_process_security_monitor()
            if process_monitor is None:
                return []

            # Get current status alerts
            status = process_monitor.get_status()
            return status.alerts
        except Exception as e:
            logger.error(f"Error checking process security: {e}")
            return []

    def _detect_lora_devices(self) -> List[str]:
        """
        Detect LoRa/LoRaWAN devices.

        LoRa devices typically appear as:
        - USB serial devices (SX127x, RFM9x chipsets)
        - SPI devices (/dev/spidev*)
        - Network interfaces for LoRaWAN gateways
        """
        # LoRa device detection requires Linux sysfs
        if IS_WINDOWS:
            return []

        devices = []

        try:
            # Check for LoRa USB devices via sysfs
            if os.path.exists('/sys/bus/usb/devices'):
                for device in os.listdir('/sys/bus/usb/devices'):
                    device_path = f'/sys/bus/usb/devices/{device}'
                    # Check for LoRa vendor/product IDs
                    try:
                        product_path = os.path.join(device_path, 'product')
                        if os.path.exists(product_path):
                            with open(product_path, 'r') as f:
                                product = f.read().strip().lower()
                                if any(x in product for x in ['lora', 'sx127', 'rfm9', 'semtech']):
                                    devices.append(f"USB: {product}")
                    except Exception:
                        pass

            # Check for SPI-connected LoRa modules
            spi_devices = [f'/dev/spidev{i}.{j}' for i in range(3) for j in range(3)]
            for spi in spi_devices:
                if os.path.exists(spi):
                    # Check if it's a LoRa device via driver binding
                    try:
                        driver_path = f'/sys/class/spidev/{os.path.basename(spi)}/device/driver'
                        if os.path.exists(driver_path):
                            driver = os.path.basename(os.readlink(driver_path))
                            if 'lora' in driver.lower() or 'sx127' in driver.lower():
                                devices.append(f"SPI: {spi}")
                    except Exception:
                        pass

            # Check for LoRaWAN gateway interfaces
            if os.path.exists('/sys/class/net'):
                for iface in os.listdir('/sys/class/net'):
                    if 'lora' in iface.lower() or 'lorawan' in iface.lower():
                        devices.append(f"Interface: {iface}")

        except Exception as e:
            logger.error(f"Error detecting LoRa devices: {e}")

        return devices

    def _detect_thread_devices(self) -> List[str]:
        """
        Detect Thread/Matter mesh networking devices.

        Thread devices typically appear as:
        - IEEE 802.15.4 radio interfaces (wpan*)
        - USB Thread border routers
        - OpenThread daemon connections
        """
        # Thread device detection requires Linux sysfs
        if IS_WINDOWS:
            return []

        devices = []

        try:
            # Check for IEEE 802.15.4 / Thread interfaces
            if os.path.exists('/sys/class/net'):
                for iface in os.listdir('/sys/class/net'):
                    iface_lower = iface.lower()
                    # wpan interfaces are 802.15.4 (used by Thread)
                    if iface.startswith('wpan') or 'thread' in iface_lower:
                        devices.append(f"Interface: {iface}")

            # Check for Thread USB devices
            if os.path.exists('/sys/bus/usb/devices'):
                for device in os.listdir('/sys/bus/usb/devices'):
                    device_path = f'/sys/bus/usb/devices/{device}'
                    try:
                        product_path = os.path.join(device_path, 'product')
                        if os.path.exists(product_path):
                            with open(product_path, 'r') as f:
                                product = f.read().strip().lower()
                                if any(x in product for x in ['thread', 'matter', '802.15.4', 'zigbee']):
                                    devices.append(f"USB: {product}")
                    except Exception:
                        pass

            # Check for OpenThread daemon socket
            otbr_sockets = ['/var/run/openthread.sock', '/tmp/openthread.sock']
            for sock in otbr_sockets:
                if os.path.exists(sock):
                    devices.append(f"OpenThread: {sock}")

            # Check for Matter controller processes (Linux only - uses pgrep)
            try:
                result = subprocess.run(
                    ['pgrep', '-l', '-f', 'matter|chip-tool|otbr'],
                    capture_output=True, timeout=2
                )
                if result.returncode == 0:
                    for line in result.stdout.decode().strip().split('\n'):
                        if line:
                            devices.append(f"Process: {line}")
            except Exception:
                pass

        except Exception as e:
            logger.error(f"Error detecting Thread devices: {e}")

        return devices

    def _detect_wimax_interfaces(self) -> List[str]:
        """
        Detect WiMAX interfaces (mostly obsolete technology).

        WiMAX interfaces typically appear as:
        - wmx* or wimax* interfaces
        - USB WiMAX modems
        """
        # WiMAX detection requires Linux sysfs
        if IS_WINDOWS:
            return []

        interfaces = []

        try:
            if os.path.exists('/sys/class/net'):
                for iface in os.listdir('/sys/class/net'):
                    iface_lower = iface.lower()
                    if 'wmx' in iface_lower or 'wimax' in iface_lower:
                        interfaces.append(iface)

            # Check for WiMAX USB devices
            if os.path.exists('/sys/bus/usb/devices'):
                for device in os.listdir('/sys/bus/usb/devices'):
                    device_path = f'/sys/bus/usb/devices/{device}'
                    try:
                        product_path = os.path.join(device_path, 'product')
                        if os.path.exists(product_path):
                            with open(product_path, 'r') as f:
                                product = f.read().strip().lower()
                                if 'wimax' in product:
                                    interfaces.append(f"USB: {product}")
                    except Exception:
                        pass

        except Exception as e:
            logger.error(f"Error detecting WiMAX interfaces: {e}")

        return interfaces

    def _detect_irda_devices(self) -> List[str]:
        """
        Detect IrDA (Infrared Data Association) devices.

        IrDA devices typically appear as:
        - irda* interfaces
        - /dev/ircomm* devices
        - USB IrDA dongles
        """
        # IrDA detection requires Linux sysfs/proc
        if IS_WINDOWS:
            return []

        devices = []

        try:
            # Check for IrDA network interfaces
            if os.path.exists('/sys/class/net'):
                for iface in os.listdir('/sys/class/net'):
                    if 'irda' in iface.lower() or iface.startswith('irlan'):
                        devices.append(f"Interface: {iface}")

            # Check for IrDA serial devices
            irda_devs = ['/dev/ircomm0', '/dev/ircomm1', '/dev/irlpt0', '/dev/irlpt1']
            for dev in irda_devs:
                if os.path.exists(dev):
                    devices.append(f"Device: {dev}")

            # Check for IrDA USB dongles
            if os.path.exists('/sys/bus/usb/devices'):
                for device in os.listdir('/sys/bus/usb/devices'):
                    device_path = f'/sys/bus/usb/devices/{device}'
                    try:
                        product_path = os.path.join(device_path, 'product')
                        if os.path.exists(product_path):
                            with open(product_path, 'r') as f:
                                product = f.read().strip().lower()
                                if 'irda' in product or 'infrared' in product:
                                    devices.append(f"USB: {product}")
                    except Exception:
                        pass

            # Check for IrDA kernel module
            try:
                with open('/proc/modules', 'r') as f:
                    modules = f.read().lower()
                    if 'irda' in modules or 'ircomm' in modules:
                        devices.append("Kernel: IrDA modules loaded")
            except Exception:
                pass

        except Exception as e:
            logger.error(f"Error detecting IrDA devices: {e}")

        return devices

    def _detect_ant_plus_devices(self) -> List[str]:
        """
        Detect ANT+ fitness and sports devices.

        ANT+ devices typically appear as:
        - USB ANT+ sticks (Garmin, Dynastream)
        - ANT+ network adapters
        """
        # ANT+ detection requires Linux sysfs
        if IS_WINDOWS:
            return []

        devices = []

        try:
            # ANT+ USB vendor/product IDs
            # Dynastream (ANT+): 0fcf
            # Common product IDs: 1004 (ANT+ stick), 1008 (ANT+ stick mini)
            ant_vendor_ids = ['0fcf']
            ant_product_ids = ['1004', '1008', '1009']

            if os.path.exists('/sys/bus/usb/devices'):
                for device in os.listdir('/sys/bus/usb/devices'):
                    device_path = f'/sys/bus/usb/devices/{device}'
                    try:
                        # Check vendor ID
                        vendor_path = os.path.join(device_path, 'idVendor')
                        product_id_path = os.path.join(device_path, 'idProduct')

                        if os.path.exists(vendor_path) and os.path.exists(product_id_path):
                            with open(vendor_path, 'r') as f:
                                vendor = f.read().strip().lower()
                            with open(product_id_path, 'r') as f:
                                prod_id = f.read().strip().lower()

                            if vendor in ant_vendor_ids or prod_id in ant_product_ids:
                                # Get product name
                                product_name = "ANT+ Device"
                                product_path = os.path.join(device_path, 'product')
                                if os.path.exists(product_path):
                                    with open(product_path, 'r') as f:
                                        product_name = f.read().strip()
                                devices.append(f"USB: {product_name} ({vendor}:{prod_id})")

                        # Also check product string
                        product_path = os.path.join(device_path, 'product')
                        if os.path.exists(product_path):
                            with open(product_path, 'r') as f:
                                product = f.read().strip().lower()
                                if 'ant+' in product or 'ant stick' in product or 'dynastream' in product:
                                    if f"USB: {product}" not in [d.lower() for d in devices]:
                                        devices.append(f"USB: {product}")
                    except Exception:
                        pass

            # Check for ANT-related processes (Linux only - uses pgrep)
            try:
                result = subprocess.run(
                    ['pgrep', '-l', '-f', 'antfs|garmin-ant|openant|python-ant'],
                    capture_output=True, timeout=2
                )
                if result.returncode == 0:
                    for line in result.stdout.decode().strip().split('\n'):
                        if line:
                            devices.append(f"Process: {line}")
            except Exception:
                pass

        except Exception as e:
            logger.error(f"Error detecting ANT+ devices: {e}")

        return devices

    def _detect_cellular_security_threats(self) -> List[str]:
        """
        Detect potential IMSI catcher (Stingray) threats on cellular connections.

        Detection heuristics:
        1. Unexpected cell tower changes
        2. Downgrade to 2G (weaker/no encryption)
        3. Unusual signal strength patterns
        4. Unknown or suspicious cell tower IDs
        """
        alerts = []

        try:
            # Try to read cellular modem info via ModemManager or sysfs
            cell_info = self._get_cellular_info()

            if cell_info:
                # Check for forced 2G downgrade (weak encryption risk)
                if cell_info.get('technology') == '2G':
                    if cell_info.get('has_4g_capability', False):
                        alerts.append(f"{CellularSecurityAlert.DOWNGRADE_ATTACK.value}: Forced to 2G despite 4G capability")

                # Check for weak/no encryption
                cipher = cell_info.get('cipher_algorithm', '')
                if cipher in ['A5/0', 'none', ''] or 'no cipher' in cipher.lower():
                    alerts.append(f"{CellularSecurityAlert.WEAK_ENCRYPTION.value}: No encryption or weak cipher ({cipher})")

                # Check for suspicious cell tower changes
                current_tower = cell_info.get('cell_id', '')
                if current_tower and self._last_cell_tower:
                    if current_tower != self._last_cell_tower:
                        # Record tower change
                        self._cell_tower_history.append({
                            'from': self._last_cell_tower,
                            'to': current_tower,
                            'time': datetime.utcnow().isoformat()
                        })

                        # Too many tower changes in short time is suspicious
                        # Get last 10 items from deque (deques don't support slicing)
                        history_list = list(self._cell_tower_history)
                        last_10 = history_list[-10:] if len(history_list) >= 10 else history_list
                        recent_changes = [
                            c for c in last_10
                            if (datetime.utcnow() - datetime.fromisoformat(c['time'])).seconds < 300
                        ]
                        if len(recent_changes) > 5:
                            alerts.append(f"{CellularSecurityAlert.IMSI_CATCHER.value}: Rapid cell tower switching detected")

                self._last_cell_tower = current_tower

                # Check signal strength anomalies
                signal = cell_info.get('signal_strength')
                if signal is not None:
                    self._signal_strength_history.append(signal)
                    # deque with maxlen handles trimming automatically

                    # Sudden massive signal increase can indicate fake tower
                    if len(self._signal_strength_history) >= 2:
                        prev_signal = self._signal_strength_history[-2]
                        if signal - prev_signal > 30:  # 30dB sudden increase
                            alerts.append(f"{CellularSecurityAlert.SIGNAL_ANOMALY.value}: Sudden signal strength spike (+{signal - prev_signal}dB)")

                # Check for LAC (Location Area Code) anomalies
                lac = cell_info.get('lac', '')
                expected_lacs = cell_info.get('expected_lacs', [])
                if lac and expected_lacs and lac not in expected_lacs:
                    alerts.append(f"{CellularSecurityAlert.TOWER_CHANGE.value}: Unexpected LAC: {lac}")

        except Exception as e:
            logger.error(f"Error detecting cellular security threats: {e}")

        return alerts

    def _get_cellular_info(self) -> Optional[Dict]:
        """
        Get cellular modem information from system.

        Attempts to read from:
        1. ModemManager via D-Bus (if available)
        2. sysfs entries for WWAN devices
        3. QMI/MBIM interfaces
        """
        # Cellular info detection requires Linux sysfs/ModemManager
        if IS_WINDOWS:
            return None

        info = {}

        try:
            # Try sysfs for WWAN devices (Linux only)
            if os.path.exists('/sys/class/net'):
                for iface in os.listdir('/sys/class/net'):
                    if any(p in iface.lower() for p in ['wwan', 'wwp', 'rmnet']):
                        device_path = f'/sys/class/net/{iface}/device'

                        # Try to get modem info
                        if os.path.exists(device_path):
                            # Check for QMI device
                            qmi_path = os.path.join(device_path, 'qmi')
                            if os.path.exists(qmi_path):
                                info['type'] = 'QMI'
                                info['interface'] = iface

                            # Check for MBIM device
                            mbim_path = os.path.join(device_path, 'mbim')
                            if os.path.exists(mbim_path):
                                info['type'] = 'MBIM'
                                info['interface'] = iface

            # Try to get signal strength from /proc or sysfs
            # This is hardware-specific; common paths for various modems
            signal_paths = [
                '/sys/class/net/wwan0/device/signal_quality',
                '/proc/net/wwan/signal',
            ]
            for path in signal_paths:
                if os.path.exists(path):
                    try:
                        with open(path, 'r') as f:
                            content = f.read().strip()
                            # Parse signal value (format varies by driver)
                            if content.isdigit():
                                info['signal_strength'] = int(content)
                    except Exception:
                        pass

            # Try mmcli (ModemManager CLI) if available
            import subprocess
            try:
                result = subprocess.run(
                    ['mmcli', '-m', '0', '--output-keyvalue'],
                    capture_output=True, timeout=5
                )
                if result.returncode == 0:
                    output = result.stdout.decode()
                    for line in output.split('\n'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip().lower().replace(' ', '_').replace('.', '_')
                            value = value.strip()

                            if 'access_technology' in key:
                                if '5g' in value.lower() or 'nr' in value.lower():
                                    info['technology'] = '5G'
                                    info['has_4g_capability'] = True
                                elif '4g' in value.lower() or 'lte' in value.lower():
                                    info['technology'] = '4G'
                                    info['has_4g_capability'] = True
                                elif '3g' in value.lower():
                                    info['technology'] = '3G'
                                    info['has_4g_capability'] = True
                                elif '2g' in value.lower() or 'gsm' in value.lower():
                                    info['technology'] = '2G'

                            if 'signal_quality' in key and value.isdigit():
                                info['signal_strength'] = int(value)

                            if 'cell_id' in key or 'cid' in key:
                                info['cell_id'] = value

                            if 'location_area_code' in key or 'lac' in key:
                                info['lac'] = value

            except FileNotFoundError:
                # mmcli not installed
                pass
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass

            return info if info else None

        except Exception as e:
            logger.error(f"Error getting cellular info: {e}")
            return None

    def _check_hardware(self) -> Dict:
        """Check hardware state"""
        usb_devices = set()
        block_devices = set()
        camera = False
        mic = False
        tpm = False

        if IS_WINDOWS:
            # Windows: Use cross-platform methods only
            # Block devices via psutil (cross-platform)
            try:
                for partition in psutil.disk_partitions(all=True):
                    block_devices.add(partition.device)
            except Exception as e:
                logger.error(f"Error checking block devices: {e}")

            # Store baseline on first check
            if self._baseline_usb is None:
                self._baseline_usb = usb_devices.copy()
            if self._baseline_block_devices is None:
                self._baseline_block_devices = block_devices.copy()

            return {
                'usb_devices': usb_devices,
                'block_devices': block_devices,
                'camera': camera,
                'mic': mic,
                'tpm': tpm
            }

        # Linux: Check USB devices via /sys/bus/usb/devices
        try:
            if os.path.exists('/sys/bus/usb/devices'):
                for device in os.listdir('/sys/bus/usb/devices'):
                    if device.startswith('usb'):
                        continue
                    usb_devices.add(device)
        except Exception as e:
            logger.error(f"Error checking USB devices: {e}")

        # Check block devices (cross-platform via psutil)
        try:
            for partition in psutil.disk_partitions(all=True):
                block_devices.add(partition.device)
        except Exception as e:
            logger.error(f"Error checking block devices: {e}")

        # Check for camera devices (Linux)
        try:
            if os.path.exists('/dev'):
                video_devs = [d for d in os.listdir('/dev') if d.startswith('video')]
                camera = len(video_devs) > 0
        except Exception:
            pass

        # Check for audio input devices (Linux)
        try:
            if os.path.exists('/proc/asound'):
                cards = os.listdir('/proc/asound')
                mic = any(c.startswith('card') for c in cards)
        except Exception:
            pass

        # Check for TPM (Linux)
        try:
            tpm = os.path.exists('/dev/tpm0') or os.path.exists('/sys/class/tpm')
        except Exception:
            pass

        # Store baseline on first check
        if self._baseline_usb is None:
            self._baseline_usb = usb_devices.copy()
        if self._baseline_block_devices is None:
            self._baseline_block_devices = block_devices.copy()

        return {
            'usb_devices': usb_devices,
            'block_devices': block_devices,
            'camera': camera,
            'mic': mic,
            'tpm': tpm
        }

    def _check_software(self) -> Dict:
        """Check software state for anomalies"""
        external_endpoints = []
        suspicious_processes = []
        shell_escapes = 0

        # Check for processes that might indicate external model usage
        try:
            for proc in psutil.process_iter(['name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info['cmdline'] or [])

                    # Look for OpenAI, Anthropic, or other API endpoints
                    if any(endpoint in cmdline.lower() for endpoint in
                           ['openai', 'anthropic', 'api.claude', 'api.openai']):
                        external_endpoints.append(proc.info['name'])

                    # Look for suspicious shell activity
                    if any(cmd in cmdline.lower() for cmd in
                           ['bash -c', 'sh -c', 'eval', 'exec']):
                        shell_escapes += 1

                    # Look for privilege escalation attempts
                    if proc.info['name'] in ['sudo', 'su', 'pkexec']:
                        suspicious_processes.append(f"{proc.info['name']} (PID: {proc.pid})")

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.error(f"Error checking processes: {e}")

        return {
            'external_endpoints': external_endpoints,
            'suspicious_processes': suspicious_processes,
            'shell_escapes': shell_escapes
        }

    def _check_human_presence(self) -> Dict:
        """Check for human presence signals"""
        keyboard_active = False
        screen_unlocked = True  # Assume unlocked if we can't detect
        last_activity = None

        # Check for recent keyboard/mouse activity via idle time
        try:
            # Try to get idle time from X11 (if available)
            if os.environ.get('DISPLAY'):
                # This would require xprintidle or similar, skip for now
                pass

            # Check last user login
            users = psutil.users()
            if users:
                last_activity = datetime.fromtimestamp(users[0].started).isoformat()
                keyboard_active = True
        except Exception as e:
            logger.error(f"Error checking human presence: {e}")

        return {
            'keyboard_active': keyboard_active,
            'screen_unlocked': screen_unlocked,
            'last_activity': last_activity
        }

    def _calculate_hardware_trust(self, hardware_info: Dict) -> HardwareTrust:
        """
        Calculate hardware trust level based on detected conditions.

        LOW: Untrusted hardware detected, unknown USB devices
        MEDIUM: Some trusted hardware, controlled environment
        HIGH: Fully trusted hardware, TPM present, no unknown devices
        """
        # Check for new USB devices since baseline
        if self._baseline_usb is not None:
            new_usb = hardware_info['usb_devices'] - self._baseline_usb
            if new_usb:
                return HardwareTrust.LOW

        # Check for new block devices
        if self._baseline_block_devices is not None:
            new_blocks = hardware_info['block_devices'] - self._baseline_block_devices
            if new_blocks:
                return HardwareTrust.LOW

        # HIGH trust: TPM present and no new devices
        if hardware_info['tpm']:
            return HardwareTrust.HIGH

        # MEDIUM: Stable hardware but no TPM
        return HardwareTrust.MEDIUM

    def get_usb_changes(self) -> tuple[Set[str], Set[str]]:
        """
        Get USB device changes since baseline.

        Returns:
            (added_devices, removed_devices)
        """
        current_state = self.get_current_state()
        if not current_state or self._baseline_usb is None:
            return (set(), set())

        added = current_state.usb_devices - self._baseline_usb
        removed = self._baseline_usb - current_state.usb_devices
        return (added, removed)

    def get_network_change_detected(self) -> bool:
        """Check if network state has changed since last check"""
        current = self.get_current_state()
        if not current:
            return False
        return current.network != self._last_network_state


if __name__ == '__main__':
    # Test the state monitor
    print("Starting State Monitor test...")

    # Create monitoring config with all options enabled for testing
    config = MonitoringConfig(
        monitor_lora=True,
        monitor_thread=True,
        monitor_cellular_security=True,
        monitor_wimax=True,    # Enable for testing
        monitor_irda=True,     # Enable for testing
        monitor_ant_plus=True
    )
    monitor = StateMonitor(poll_interval=2.0, monitoring_config=config)

    def on_state_change(old_state, new_state):
        print(f"\n=== State Change Detected ===")
        if old_state:
            print(f"Old network: {old_state.network.value}")
        print(f"New network: {new_state.network.value}")
        print(f"Hardware trust: {new_state.hardware_trust.value}")
        print(f"Active interfaces: {new_state.active_interfaces}")
        print(f"Interface types: {{{', '.join(f'{k}: {v.value}' for k, v in new_state.interface_types.items())}}}")
        print(f"USB devices: {len(new_state.usb_devices)}")
        print(f"Internet: {new_state.has_internet}")

        # Display specialty network status
        specialty = new_state.specialty_networks
        print(f"\n--- Specialty Networks ---")
        print(f"LoRa devices: {specialty.lora_devices}")
        print(f"Thread/Matter devices: {specialty.thread_devices}")
        print(f"WiMAX interfaces: {specialty.wimax_interfaces}")
        print(f"IrDA devices: {specialty.irda_devices}")
        print(f"ANT+ devices: {specialty.ant_plus_devices}")
        if specialty.cellular_alerts:
            print(f"Cellular security alerts: {specialty.cellular_alerts}")

    monitor.register_callback(on_state_change)

    # Show monitoring config
    print(f"\nMonitoring Configuration:")
    print(f"  LoRa: {config.monitor_lora}")
    print(f"  Thread/Matter: {config.monitor_thread}")
    print(f"  Cellular Security: {config.monitor_cellular_security}")
    print(f"  WiMAX: {config.monitor_wimax}")
    print(f"  IrDA: {config.monitor_irda}")
    print(f"  ANT+: {config.monitor_ant_plus}")

    monitor.start()

    try:
        print("\nMonitoring environment. Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        monitor.stop()
        print("Monitor stopped.")
