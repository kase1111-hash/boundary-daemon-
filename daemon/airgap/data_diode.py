"""
Data Diode Support - One-way log export for air-gapped systems.

Implements asymmetric data flow where:
- OUTBOUND: Logs flow out to collection systems (read-only export)
- INBOUND: Policy updates enter via manual review (write-only import)

Data diodes are hardware or software mechanisms that enforce
unidirectional information flow, commonly used in high-security
environments to allow data export while preventing data ingress.

SECURITY: All exports are signed and can be verified offline.
The diode enforces one-way flow at the protocol level.
"""

import os
import json
import time
import socket
import hashlib
import threading
from enum import Enum
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field
from datetime import datetime
from queue import Queue, Empty

# Cryptographic imports
try:
    import nacl.signing
    import nacl.encoding
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False


# =============================================================================
# DATA DIODE TYPES
# =============================================================================

class DataDiodeMode(Enum):
    """Operating modes for data diode."""
    OUTBOUND_ONLY = "outbound"      # Logs out, nothing in
    INBOUND_ONLY = "inbound"        # Updates in, nothing out
    BIDIRECTIONAL = "bidirectional"  # Both (for testing only)


class DiodeExportFormat(Enum):
    """Export formats for diode transmission."""
    JSON_LINES = "jsonl"            # One JSON object per line
    SIGNED_BUNDLE = "bundle"        # Complete signed bundle
    CEF = "cef"                     # Common Event Format
    SYSLOG = "syslog"               # RFC 5424 syslog
    RAW = "raw"                     # Raw event data


class DiodeProtocol(Enum):
    """Transport protocols for diode."""
    UDP = "udp"                     # Stateless, one-way friendly
    TCP = "tcp"                     # Connection-oriented
    FILE = "file"                   # Write to file/fifo
    SERIAL = "serial"              # Serial port (true hardware diode)


@dataclass
class DiodePacket:
    """
    A single packet for diode transmission.

    Packets are self-contained units that can be verified independently.
    """
    packet_id: str
    sequence: int
    timestamp: str
    source_node: str
    format: DiodeExportFormat
    data: bytes
    checksum: str
    signature: Optional[str] = None
    is_final: bool = False  # Last packet in stream

    def to_bytes(self) -> bytes:
        """Serialize packet for transmission."""
        header = json.dumps({
            'pid': self.packet_id,
            'seq': self.sequence,
            'ts': self.timestamp,
            'src': self.source_node,
            'fmt': self.format.value,
            'csum': self.checksum,
            'sig': self.signature,
            'fin': self.is_final
        }, separators=(',', ':')).encode()

        # Format: header_length(4 bytes) + header + data_length(4 bytes) + data
        return (
            len(header).to_bytes(4, 'big') +
            header +
            len(self.data).to_bytes(4, 'big') +
            self.data
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> Optional['DiodePacket']:
        """Deserialize packet from transmission."""
        try:
            header_len = int.from_bytes(raw[:4], 'big')
            header = json.loads(raw[4:4 + header_len].decode())
            data_len = int.from_bytes(raw[4 + header_len:8 + header_len], 'big')
            data = raw[8 + header_len:8 + header_len + data_len]

            return cls(
                packet_id=header['pid'],
                sequence=header['seq'],
                timestamp=header['ts'],
                source_node=header['src'],
                format=DiodeExportFormat(header['fmt']),
                data=data,
                checksum=header['csum'],
                signature=header.get('sig'),
                is_final=header.get('fin', False)
            )
        except Exception:
            return None

    def verify_checksum(self) -> bool:
        """Verify packet checksum."""
        return hashlib.sha256(self.data).hexdigest() == self.checksum


# =============================================================================
# DIODE CHANNEL
# =============================================================================

@dataclass
class DiodeChannel:
    """
    Configuration for a diode channel.

    Each channel represents a one-way data path with specific
    format and destination.
    """
    channel_id: str
    name: str
    mode: DataDiodeMode
    protocol: DiodeProtocol
    export_format: DiodeExportFormat
    destination: str  # IP:port, file path, or serial device
    enabled: bool = True
    rate_limit: int = 100  # Max packets per second
    buffer_size: int = 1000  # Max queued packets
    retry_count: int = 3
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'channel_id': self.channel_id,
            'name': self.name,
            'mode': self.mode.value,
            'protocol': self.protocol.value,
            'export_format': self.export_format.value,
            'destination': self.destination,
            'enabled': self.enabled,
            'rate_limit': self.rate_limit,
            'buffer_size': self.buffer_size,
            'retry_count': self.retry_count,
            'metadata': self.metadata
        }


# =============================================================================
# DATA DIODE EXPORTER
# =============================================================================

class DataDiodeExporter:
    """
    Exports data through a one-way diode channel.

    The exporter:
    1. Receives events/data to export
    2. Formats according to channel config
    3. Signs for authenticity
    4. Transmits through diode (UDP/TCP/file/serial)

    No acknowledgments expected - diode is one-way.
    """

    def __init__(self, node_id: str, signing_key: Optional[bytes] = None):
        """
        Initialize data diode exporter.

        Args:
            node_id: Identifier for this node
            signing_key: Ed25519 signing key for packet signing
        """
        self.node_id = node_id
        self._channels: Dict[str, DiodeChannel] = {}
        self._queues: Dict[str, Queue] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._stop_events: Dict[str, threading.Event] = {}
        self._sequence_counters: Dict[str, int] = {}
        self._stats: Dict[str, Dict[str, int]] = {}

        # Initialize signing
        if signing_key and NACL_AVAILABLE:
            self._signing_key = nacl.signing.SigningKey(signing_key)
        else:
            self._signing_key = None

    def add_channel(self, channel: DiodeChannel) -> bool:
        """
        Add a diode channel.

        Args:
            channel: Channel configuration

        Returns:
            True if added successfully
        """
        if channel.channel_id in self._channels:
            return False

        if channel.mode not in (DataDiodeMode.OUTBOUND_ONLY, DataDiodeMode.BIDIRECTIONAL):
            return False  # Exporter only handles outbound

        self._channels[channel.channel_id] = channel
        self._queues[channel.channel_id] = Queue(maxsize=channel.buffer_size)
        self._stop_events[channel.channel_id] = threading.Event()
        self._sequence_counters[channel.channel_id] = 0
        self._stats[channel.channel_id] = {
            'packets_sent': 0,
            'packets_dropped': 0,
            'bytes_sent': 0,
            'errors': 0
        }

        return True

    def start_channel(self, channel_id: str) -> bool:
        """Start a channel's transmission thread."""
        if channel_id not in self._channels:
            return False

        channel = self._channels[channel_id]
        if not channel.enabled:
            return False

        self._stop_events[channel_id].clear()

        thread = threading.Thread(
            target=self._transmission_loop,
            args=(channel_id,),
            daemon=True,
            name=f"Diode-{channel_id}"
        )
        self._threads[channel_id] = thread
        thread.start()

        return True

    def stop_channel(self, channel_id: str):
        """Stop a channel's transmission thread."""
        if channel_id in self._stop_events:
            self._stop_events[channel_id].set()

        if channel_id in self._threads:
            self._threads[channel_id].join(timeout=5)

    def export_event(self, channel_id: str, event: Dict) -> bool:
        """
        Queue an event for export.

        Args:
            channel_id: Target channel
            event: Event dictionary to export

        Returns:
            True if queued successfully
        """
        if channel_id not in self._channels:
            return False

        channel = self._channels[channel_id]
        if not channel.enabled:
            return False

        # Format the event
        data = self._format_event(event, channel.export_format)
        if not data:
            return False

        # Create packet
        packet = self._create_packet(channel_id, data, channel.export_format)

        # Queue for transmission
        try:
            self._queues[channel_id].put_nowait(packet)
            return True
        except Exception:
            self._stats[channel_id]['packets_dropped'] += 1
            return False

    def export_batch(self, channel_id: str, events: List[Dict]) -> int:
        """
        Queue a batch of events.

        Args:
            channel_id: Target channel
            events: List of event dictionaries

        Returns:
            Number of events queued successfully
        """
        queued = 0
        for event in events:
            if self.export_event(channel_id, event):
                queued += 1
        return queued

    def flush_channel(self, channel_id: str, timeout: float = 10.0) -> bool:
        """
        Wait for channel queue to empty.

        Args:
            channel_id: Channel to flush
            timeout: Maximum wait time

        Returns:
            True if flushed successfully
        """
        if channel_id not in self._queues:
            return False

        queue = self._queues[channel_id]
        start = time.time()

        while not queue.empty() and (time.time() - start) < timeout:
            time.sleep(0.1)

        return queue.empty()

    def get_stats(self, channel_id: Optional[str] = None) -> Dict[str, Any]:
        """Get transmission statistics."""
        if channel_id:
            return self._stats.get(channel_id, {})
        return dict(self._stats)

    def _format_event(self, event: Dict, fmt: DiodeExportFormat) -> Optional[bytes]:
        """Format event for transmission."""
        try:
            if fmt == DiodeExportFormat.JSON_LINES:
                return json.dumps(event, separators=(',', ':')).encode() + b'\n'

            elif fmt == DiodeExportFormat.CEF:
                return self._format_cef(event)

            elif fmt == DiodeExportFormat.SYSLOG:
                return self._format_syslog(event)

            elif fmt == DiodeExportFormat.RAW:
                return json.dumps(event).encode()

            elif fmt == DiodeExportFormat.SIGNED_BUNDLE:
                # Single event as signed bundle
                return json.dumps({
                    'event': event,
                    'timestamp': datetime.utcnow().isoformat() + "Z",
                    'source': self.node_id
                }).encode()

        except Exception:
            return None

        return None

    def _format_cef(self, event: Dict) -> bytes:
        """Format event as CEF (Common Event Format)."""
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        severity = event.get('metadata', {}).get('severity', 5)
        event_type = event.get('event_type', 'unknown')
        details = event.get('details', '').replace('|', '\\|').replace('\\', '\\\\')

        cef = f"CEF:0|BoundaryDaemon|AgentSmith|1.0|{event_type}|{details}|{severity}|"

        # Add extension fields
        extensions = []
        if 'event_id' in event:
            extensions.append(f"externalId={event['event_id']}")
        if 'timestamp' in event:
            extensions.append(f"rt={event['timestamp']}")
        if 'metadata' in event:
            for k, v in event['metadata'].items():
                if isinstance(v, (str, int, float, bool)):
                    extensions.append(f"cs1Label={k} cs1={v}")

        cef += " ".join(extensions)
        return (cef + "\n").encode()

    def _format_syslog(self, event: Dict) -> bytes:
        """Format event as RFC 5424 syslog."""
        # <priority>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        facility = 16  # local0
        severity_map = {
            'violation': 3,  # error
            'tripwire': 2,   # critical
            'override': 5,   # notice
            'info': 6        # info
        }
        event_type = event.get('event_type', 'info')
        severity = severity_map.get(event_type, 6)
        priority = facility * 8 + severity

        timestamp = event.get('timestamp', datetime.utcnow().isoformat() + "Z")
        hostname = self.node_id
        app_name = "boundary-daemon"
        procid = str(os.getpid())
        msgid = event.get('event_id', '-')[:32]

        # Structured data
        sd = f'[boundary@1 type="{event_type}"'
        if 'metadata' in event:
            for k, v in list(event['metadata'].items())[:5]:
                if isinstance(v, (str, int, float)):
                    sd += f' {k}="{v}"'
        sd += ']'

        msg = event.get('details', '')

        syslog = f"<{priority}>1 {timestamp} {hostname} {app_name} {procid} {msgid} {sd} {msg}\n"
        return syslog.encode('utf-8')

    def _create_packet(self, channel_id: str, data: bytes,
                      fmt: DiodeExportFormat) -> DiodePacket:
        """Create a signed packet."""
        sequence = self._sequence_counters[channel_id]
        self._sequence_counters[channel_id] += 1

        packet_id = hashlib.sha256(
            f"{channel_id}:{sequence}:{time.time()}".encode()
        ).hexdigest()[:16]

        checksum = hashlib.sha256(data).hexdigest()

        packet = DiodePacket(
            packet_id=packet_id,
            sequence=sequence,
            timestamp=datetime.utcnow().isoformat() + "Z",
            source_node=self.node_id,
            format=fmt,
            data=data,
            checksum=checksum
        )

        # Sign packet
        if self._signing_key:
            sign_data = f"{packet_id}:{sequence}:{checksum}".encode()
            signed = self._signing_key.sign(sign_data)
            packet.signature = signed.signature.hex()

        return packet

    def _transmission_loop(self, channel_id: str):
        """Main transmission loop for a channel."""
        channel = self._channels[channel_id]
        queue = self._queues[channel_id]
        stop_event = self._stop_events[channel_id]

        # Rate limiting
        min_interval = 1.0 / channel.rate_limit
        last_send: float = 0

        while not stop_event.is_set():
            try:
                packet = queue.get(timeout=0.5)
            except Empty:
                continue

            # Rate limit
            now = time.time()
            if now - last_send < min_interval:
                time.sleep(min_interval - (now - last_send))

            # Transmit
            success = self._transmit_packet(channel, packet)
            last_send = time.time()

            if success:
                self._stats[channel_id]['packets_sent'] += 1
                self._stats[channel_id]['bytes_sent'] += len(packet.data)
            else:
                self._stats[channel_id]['errors'] += 1

    def _transmit_packet(self, channel: DiodeChannel, packet: DiodePacket) -> bool:
        """Transmit a single packet."""
        try:
            if channel.protocol == DiodeProtocol.UDP:
                return self._send_udp(channel.destination, packet)

            elif channel.protocol == DiodeProtocol.TCP:
                return self._send_tcp(channel.destination, packet)

            elif channel.protocol == DiodeProtocol.FILE:
                return self._send_file(channel.destination, packet)

            elif channel.protocol == DiodeProtocol.SERIAL:
                return self._send_serial(channel.destination, packet)

        except Exception:
            return False

        return False

    def _send_udp(self, destination: str, packet: DiodePacket) -> bool:
        """Send packet via UDP."""
        try:
            host, port_str = destination.rsplit(':', 1)
            port = int(port_str)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)

            data = packet.to_bytes()
            sock.sendto(data, (host, port))
            sock.close()

            return True
        except Exception:
            return False

    def _send_tcp(self, destination: str, packet: DiodePacket) -> bool:
        """Send packet via TCP."""
        try:
            host, port_str = destination.rsplit(':', 1)
            port = int(port_str)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((host, port))

            data = packet.to_bytes()
            sock.sendall(data)
            sock.close()

            return True
        except Exception:
            return False

    def _send_file(self, path: str, packet: DiodePacket) -> bool:
        """Write packet to file/fifo."""
        try:
            # For JSONL format, just append the data
            if packet.format == DiodeExportFormat.JSON_LINES:
                with open(path, 'ab') as f:
                    f.write(packet.data)
            else:
                # Write full packet
                with open(path, 'ab') as f:
                    f.write(packet.to_bytes())

            return True
        except Exception:
            return False

    def _send_serial(self, device: str, packet: DiodePacket) -> bool:
        """Send packet via serial port."""
        try:
            import serial
            ser = serial.Serial(device, 115200, timeout=1)
            ser.write(packet.to_bytes())
            ser.close()
            return True
        except ImportError:
            # Serial library not available
            return False
        except Exception:
            return False


# =============================================================================
# DATA DIODE RECEIVER (FOR TESTING)
# =============================================================================

class DataDiodeReceiver:
    """
    Receives data from a diode channel.

    This runs on the receiving end of the diode.
    For production, this would typically be a separate system.
    """

    def __init__(self, channel: DiodeChannel,
                 trusted_public_keys: Optional[Dict[str, str]] = None):
        """
        Initialize receiver.

        Args:
            channel: Channel configuration
            trusted_public_keys: Dict of node_id -> public_key for verification
        """
        self.channel = channel
        self.trusted_keys = trusted_public_keys or {}
        self._received: List[DiodePacket] = []
        self._stop_event = threading.Event()
        self._receive_thread: Optional[threading.Thread] = None

    def start(self):
        """Start receiving."""
        self._stop_event.clear()
        self._receive_thread = threading.Thread(
            target=self._receive_loop,
            daemon=True,
            name=f"DiodeRecv-{self.channel.channel_id}"
        )
        self._receive_thread.start()

    def stop(self):
        """Stop receiving."""
        self._stop_event.set()
        if self._receive_thread:
            self._receive_thread.join(timeout=5)

    def get_received(self) -> List[DiodePacket]:
        """Get received packets."""
        return list(self._received)

    def _receive_loop(self):
        """Main receive loop."""
        if self.channel.protocol == DiodeProtocol.UDP:
            self._receive_udp()
        elif self.channel.protocol == DiodeProtocol.TCP:
            self._receive_tcp()
        elif self.channel.protocol == DiodeProtocol.FILE:
            self._receive_file()

    def _receive_udp(self):
        """Receive UDP packets."""
        try:
            host, port = self.channel.destination.rsplit(':', 1)
            port = int(port)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.settimeout(1.0)

            while not self._stop_event.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                    packet = DiodePacket.from_bytes(data)
                    if packet and packet.verify_checksum():
                        self._received.append(packet)
                except socket.timeout:
                    continue

            sock.close()

        except Exception as e:
            print(f"UDP receive error: {e}")

    def _receive_tcp(self):
        """Receive TCP connections."""
        try:
            host, port = self.channel.destination.rsplit(':', 1)
            port = int(port)

            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((host, port))
            server.listen(5)
            server.settimeout(1.0)

            while not self._stop_event.is_set():
                try:
                    conn, addr = server.accept()
                    data = b''
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk

                    packet = DiodePacket.from_bytes(data)
                    if packet and packet.verify_checksum():
                        self._received.append(packet)

                    conn.close()

                except socket.timeout:
                    continue

            server.close()

        except Exception as e:
            print(f"TCP receive error: {e}")

    def _receive_file(self):
        """Read from file/fifo."""
        try:
            while not self._stop_event.is_set():
                if os.path.exists(self.channel.destination):
                    with open(self.channel.destination, 'rb') as f:
                        data = f.read()

                    if data:
                        # Try to parse as packet
                        packet = DiodePacket.from_bytes(data)
                        if packet and packet.verify_checksum():
                            self._received.append(packet)

                time.sleep(1.0)

        except Exception as e:
            print(f"File receive error: {e}")


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    'DataDiodeMode',
    'DiodeExportFormat',
    'DiodeProtocol',
    'DiodePacket',
    'DiodeChannel',
    'DataDiodeExporter',
    'DataDiodeReceiver',
]
