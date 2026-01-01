"""
CEF/LEEF Format Exporters for SIEM Integration

Supports:
- CEF (Common Event Format) for ArcSight, Splunk, and others
- LEEF (Log Event Extended Format) for IBM QRadar

CEF Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
LEEF Format: LEEF:Version|Vendor|Product|Version|EventID|Key1=Value1\tKey2=Value2
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum, Enum
from typing import Dict, Optional, List, Any, Callable
from urllib.parse import quote

logger = logging.getLogger(__name__)


class CEFSeverity(IntEnum):
    """CEF severity levels (0-10 scale)."""
    UNKNOWN = 0
    LOW = 1
    LOW_MEDIUM = 2
    MEDIUM = 3
    MEDIUM_HIGH = 4
    HIGH = 5
    HIGH_CRITICAL = 6
    CRITICAL = 7
    CRITICAL_SEVERE = 8
    SEVERE = 9
    EMERGENCY = 10


class SIEMFormat(Enum):
    """Supported SIEM format types."""
    CEF = "cef"
    LEEF = "leef"
    JSON = "json"


# Mapping from Boundary Daemon event types to CEF signature IDs
EVENT_TYPE_TO_SIGNATURE_ID = {
    'DAEMON_START': 1001,
    'DAEMON_STOP': 1002,
    'MODE_CHANGE': 2001,
    'RECALL_ATTEMPT': 3001,
    'RECALL_DENIED': 3002,
    'TOOL_EXECUTION': 4001,
    'TOOL_DENIED': 4002,
    'VIOLATION': 5001,
    'TRIPWIRE': 5002,
    'LOCKDOWN': 5003,
    'CEREMONY_START': 6001,
    'CEREMONY_COMPLETE': 6002,
    'CEREMONY_ABORT': 6003,
    'AUTH_SUCCESS': 7001,
    'AUTH_FAILURE': 7002,
    'CONFIG_CHANGE': 8001,
    'INTEGRITY_CHECK': 9001,
    'INTEGRITY_VIOLATION': 9002,
    # Sandbox events (10xxx range)
    'SANDBOX_CREATED': 10001,
    'SANDBOX_STARTED': 10002,
    'SANDBOX_STOPPED': 10003,
    'SANDBOX_TERMINATED': 10004,
    'SANDBOX_ERROR': 10005,
    'SANDBOX_TIMEOUT': 10006,
    'SANDBOX_OOM_KILLED': 10007,
    'SANDBOX_SECCOMP_VIOLATION': 10008,
    'SANDBOX_NAMESPACE_SETUP': 10009,
    'SANDBOX_CGROUP_LIMIT': 10010,
    'SANDBOX_FIREWALL_BLOCKED': 10011,
    'SANDBOX_FIREWALL_ALLOWED': 10012,
    'SANDBOX_SYSCALL_DENIED': 10013,
    'SANDBOX_ESCAPE_ATTEMPT': 10014,
    'SANDBOX_RESOURCE_EXCEEDED': 10015,
}

# Mapping from event types to CEF severity
EVENT_TYPE_TO_SEVERITY = {
    'DAEMON_START': CEFSeverity.LOW,
    'DAEMON_STOP': CEFSeverity.LOW,
    'MODE_CHANGE': CEFSeverity.MEDIUM,
    'RECALL_ATTEMPT': CEFSeverity.MEDIUM,
    'RECALL_DENIED': CEFSeverity.HIGH,
    'TOOL_EXECUTION': CEFSeverity.LOW,
    'TOOL_DENIED': CEFSeverity.MEDIUM,
    'VIOLATION': CEFSeverity.CRITICAL,
    'TRIPWIRE': CEFSeverity.SEVERE,
    'LOCKDOWN': CEFSeverity.EMERGENCY,
    'CEREMONY_START': CEFSeverity.MEDIUM,
    'CEREMONY_COMPLETE': CEFSeverity.MEDIUM,
    'CEREMONY_ABORT': CEFSeverity.HIGH,
    'AUTH_SUCCESS': CEFSeverity.LOW,
    'AUTH_FAILURE': CEFSeverity.HIGH,
    'CONFIG_CHANGE': CEFSeverity.MEDIUM,
    'INTEGRITY_CHECK': CEFSeverity.LOW,
    'INTEGRITY_VIOLATION': CEFSeverity.EMERGENCY,
    # Sandbox event severities
    'SANDBOX_CREATED': CEFSeverity.LOW,
    'SANDBOX_STARTED': CEFSeverity.LOW,
    'SANDBOX_STOPPED': CEFSeverity.LOW,
    'SANDBOX_TERMINATED': CEFSeverity.MEDIUM,
    'SANDBOX_ERROR': CEFSeverity.HIGH,
    'SANDBOX_TIMEOUT': CEFSeverity.MEDIUM,
    'SANDBOX_OOM_KILLED': CEFSeverity.HIGH,
    'SANDBOX_SECCOMP_VIOLATION': CEFSeverity.CRITICAL,
    'SANDBOX_NAMESPACE_SETUP': CEFSeverity.LOW,
    'SANDBOX_CGROUP_LIMIT': CEFSeverity.MEDIUM,
    'SANDBOX_FIREWALL_BLOCKED': CEFSeverity.MEDIUM,
    'SANDBOX_FIREWALL_ALLOWED': CEFSeverity.LOW,
    'SANDBOX_SYSCALL_DENIED': CEFSeverity.HIGH,
    'SANDBOX_ESCAPE_ATTEMPT': CEFSeverity.EMERGENCY,
    'SANDBOX_RESOURCE_EXCEEDED': CEFSeverity.HIGH,
}

# CEF extension key mappings
CEF_EXTENSION_KEYS = {
    'event_id': 'externalId',
    'timestamp': 'rt',
    'source_ip': 'src',
    'destination_ip': 'dst',
    'source_host': 'shost',
    'destination_host': 'dhost',
    'user': 'suser',
    'target_user': 'duser',
    'process_name': 'sproc',
    'process_id': 'spid',
    'file_path': 'filePath',
    'file_hash': 'fileHash',
    'outcome': 'outcome',
    'reason': 'reason',
    'message': 'msg',
    'category': 'cat',
    'action': 'act',
    'memory_class': 'cs1',
    'boundary_mode': 'cs2',
    'ceremony_id': 'cs3',
    'hash_chain': 'cs4',
    'signature': 'cs5',
    'public_key': 'cs6',
    # Sandbox-specific fields
    'sandbox_id': 'cn1',
    'sandbox_profile': 'cs7',
    'cgroup_path': 'cs8',
    'syscall_name': 'cs9',
    'resource_type': 'cs10',
    'cpu_usage_percent': 'cn2',
    'memory_usage_bytes': 'cn3',
}

# CEF custom string labels
CEF_CUSTOM_LABELS = {
    'cs1Label': 'MemoryClass',
    'cs2Label': 'BoundaryMode',
    'cs3Label': 'CeremonyID',
    'cs4Label': 'HashChain',
    'cs5Label': 'Signature',
    'cs6Label': 'PublicKey',
    # Sandbox labels
    'cn1Label': 'SandboxID',
    'cs7Label': 'SandboxProfile',
    'cs8Label': 'CgroupPath',
    'cs9Label': 'SyscallName',
    'cs10Label': 'ResourceType',
    'cn2Label': 'CPUUsagePercent',
    'cn3Label': 'MemoryUsageBytes',
}


def _escape_cef_value(value: str) -> str:
    """Escape special characters for CEF format."""
    if not isinstance(value, str):
        value = str(value)
    # CEF requires escaping: backslash, equals, pipe, newline
    value = value.replace('\\', '\\\\')
    value = value.replace('=', '\\=')
    value = value.replace('|', '\\|')
    value = value.replace('\n', '\\n')
    value = value.replace('\r', '\\r')
    return value


def _escape_cef_header(value: str) -> str:
    """Escape special characters for CEF header fields."""
    if not isinstance(value, str):
        value = str(value)
    # Header fields only need pipe and backslash escaped
    value = value.replace('\\', '\\\\')
    value = value.replace('|', '\\|')
    return value


def _escape_leef_value(value: str) -> str:
    """Escape special characters for LEEF format."""
    if not isinstance(value, str):
        value = str(value)
    # LEEF uses tab as delimiter, escape tabs and newlines
    value = value.replace('\t', ' ')
    value = value.replace('\n', '\\n')
    value = value.replace('\r', '\\r')
    return value


def _format_timestamp_cef(ts: str) -> str:
    """Format timestamp for CEF (milliseconds since epoch)."""
    try:
        if isinstance(ts, str):
            dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        elif isinstance(ts, datetime):
            dt = ts
        else:
            return str(ts)
        return str(int(dt.timestamp() * 1000))
    except (ValueError, AttributeError):
        return str(ts)


def _format_timestamp_leef(ts: str) -> str:
    """Format timestamp for LEEF (ISO 8601 or MMM dd yyyy HH:mm:ss)."""
    try:
        if isinstance(ts, str):
            dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        elif isinstance(ts, datetime):
            dt = ts
        else:
            return str(ts)
        return dt.strftime('%b %d %Y %H:%M:%S')
    except (ValueError, AttributeError):
        return str(ts)


@dataclass
class CEFExporter:
    """
    Export events in CEF (Common Event Format).

    CEF is widely supported by:
    - ArcSight
    - Splunk
    - LogRhythm
    - AlienVault
    - McAfee ESM
    """

    vendor: str = "BoundaryDaemon"
    product: str = "AgentSmith"
    version: str = "1.0"
    cef_version: int = 0

    # Custom field mappings
    custom_mappings: Dict[str, str] = field(default_factory=dict)

    # Include signature in extension
    include_signature: bool = True

    # Include hash chain in extension
    include_hash_chain: bool = True

    def format_event(self, event: Dict[str, Any]) -> str:
        """
        Format a boundary event as CEF.

        Args:
            event: Event dictionary with at minimum:
                   - event_id
                   - event_type
                   - timestamp
                   - details

        Returns:
            CEF formatted string
        """
        event_type = event.get('event_type', 'UNKNOWN')

        # Build header
        signature_id = EVENT_TYPE_TO_SIGNATURE_ID.get(event_type, 9999)
        severity = EVENT_TYPE_TO_SEVERITY.get(event_type, CEFSeverity.UNKNOWN)
        name = _escape_cef_header(event.get('details', event_type))

        header = (
            f"CEF:{self.cef_version}|"
            f"{_escape_cef_header(self.vendor)}|"
            f"{_escape_cef_header(self.product)}|"
            f"{_escape_cef_header(self.version)}|"
            f"{signature_id}|"
            f"{name}|"
            f"{severity}"
        )

        # Build extension
        extensions = []

        # Add standard CEF fields
        if 'event_id' in event:
            extensions.append(f"externalId={_escape_cef_value(event['event_id'])}")

        if 'timestamp' in event:
            rt = _format_timestamp_cef(event['timestamp'])
            extensions.append(f"rt={rt}")

        # Add custom string labels
        for label_key, label_value in CEF_CUSTOM_LABELS.items():
            extensions.append(f"{label_key}={label_value}")

        # Map metadata fields
        metadata = event.get('metadata', {})

        for src_key, cef_key in CEF_EXTENSION_KEYS.items():
            # Check in event directly
            if src_key in event and src_key not in ('event_id', 'timestamp'):
                value = event[src_key]
                if value is not None:
                    extensions.append(f"{cef_key}={_escape_cef_value(value)}")
            # Check in metadata
            elif src_key in metadata:
                value = metadata[src_key]
                if value is not None:
                    extensions.append(f"{cef_key}={_escape_cef_value(value)}")

        # Add custom mappings
        for src_key, cef_key in self.custom_mappings.items():
            if src_key in event:
                extensions.append(f"{cef_key}={_escape_cef_value(event[src_key])}")
            elif src_key in metadata:
                extensions.append(f"{cef_key}={_escape_cef_value(metadata[src_key])}")

        # Add hash chain if enabled
        if self.include_hash_chain and 'hash_chain' in event:
            extensions.append(f"cs4={_escape_cef_value(event['hash_chain'])}")

        # Add signature if present and enabled
        if self.include_signature and 'signature' in event:
            extensions.append(f"cs5={_escape_cef_value(event['signature'])}")

        # Add event type as category
        extensions.append(f"cat={_escape_cef_value(event_type)}")

        # Add outcome based on event type
        if 'DENIED' in event_type or 'FAILURE' in event_type or 'VIOLATION' in event_type:
            extensions.append("outcome=Failure")
        elif 'SUCCESS' in event_type or 'COMPLETE' in event_type:
            extensions.append("outcome=Success")

        extension_str = ' '.join(extensions)
        return f"{header}|{extension_str}"

    def format_events(self, events: List[Dict[str, Any]]) -> List[str]:
        """Format multiple events as CEF."""
        return [self.format_event(event) for event in events]


@dataclass
class LEEFExporter:
    """
    Export events in LEEF (Log Event Extended Format) for IBM QRadar.

    LEEF 2.0 format:
    LEEF:2.0|Vendor|Product|Version|EventID|delimiter|Key=Value
    """

    vendor: str = "BoundaryDaemon"
    product: str = "AgentSmith"
    version: str = "1.0"
    leef_version: str = "2.0"
    delimiter: str = "\t"

    # Custom field mappings
    custom_mappings: Dict[str, str] = field(default_factory=dict)

    # Include cryptographic fields
    include_crypto: bool = True

    def format_event(self, event: Dict[str, Any]) -> str:
        """
        Format a boundary event as LEEF.

        Args:
            event: Event dictionary

        Returns:
            LEEF formatted string
        """
        event_type = event.get('event_type', 'UNKNOWN')
        event_id = EVENT_TYPE_TO_SIGNATURE_ID.get(event_type, 9999)

        # LEEF header
        # Use 0x09 for tab delimiter indication in header
        header = (
            f"LEEF:{self.leef_version}|"
            f"{self.vendor}|"
            f"{self.product}|"
            f"{self.version}|"
            f"{event_id}|"
        )

        # Build attributes
        attrs = []

        # Standard LEEF fields
        if 'timestamp' in event:
            devTime = _format_timestamp_leef(event['timestamp'])
            attrs.append(f"devTime={_escape_leef_value(devTime)}")

        if 'event_id' in event:
            attrs.append(f"devTimeFormat=MMM dd yyyy HH:mm:ss")
            attrs.append(f"externalId={_escape_leef_value(event['event_id'])}")

        # Category and severity
        attrs.append(f"cat={_escape_leef_value(event_type)}")
        severity = EVENT_TYPE_TO_SEVERITY.get(event_type, CEFSeverity.UNKNOWN)
        attrs.append(f"sev={severity}")

        # Event details
        if 'details' in event:
            attrs.append(f"msg={_escape_leef_value(event['details'])}")

        # Metadata fields
        metadata = event.get('metadata', {})

        # Map common fields
        leef_mappings = {
            'user': 'usrName',
            'source_ip': 'src',
            'destination_ip': 'dst',
            'source_host': 'srcHostName',
            'destination_host': 'dstHostName',
            'process_name': 'process',
            'process_id': 'pid',
            'file_path': 'resource',
            'action': 'action',
            'outcome': 'outcome',
            'memory_class': 'memoryClass',
            'boundary_mode': 'boundaryMode',
            'ceremony_id': 'ceremonyId',
        }

        for src_key, leef_key in leef_mappings.items():
            if src_key in event:
                attrs.append(f"{leef_key}={_escape_leef_value(event[src_key])}")
            elif src_key in metadata:
                attrs.append(f"{leef_key}={_escape_leef_value(metadata[src_key])}")

        # Add custom mappings
        for src_key, leef_key in self.custom_mappings.items():
            if src_key in event:
                attrs.append(f"{leef_key}={_escape_leef_value(event[src_key])}")
            elif src_key in metadata:
                attrs.append(f"{leef_key}={_escape_leef_value(metadata[src_key])}")

        # Cryptographic fields
        if self.include_crypto:
            if 'hash_chain' in event:
                attrs.append(f"hashChain={_escape_leef_value(event['hash_chain'])}")
            if 'signature' in event:
                attrs.append(f"signature={_escape_leef_value(event['signature'])}")
            if 'public_key' in event:
                attrs.append(f"publicKey={_escape_leef_value(event['public_key'])}")

        # Outcome based on event type
        if 'DENIED' in event_type or 'FAILURE' in event_type or 'VIOLATION' in event_type:
            attrs.append("outcome=Failure")
        elif 'SUCCESS' in event_type or 'COMPLETE' in event_type:
            attrs.append("outcome=Success")

        # Join with delimiter
        attrs_str = self.delimiter.join(attrs)
        return f"{header}{attrs_str}"

    def format_events(self, events: List[Dict[str, Any]]) -> List[str]:
        """Format multiple events as LEEF."""
        return [self.format_event(event) for event in events]


def format_event_cef(
    event: Dict[str, Any],
    vendor: str = "BoundaryDaemon",
    product: str = "AgentSmith",
    version: str = "1.0",
) -> str:
    """
    Convenience function to format a single event as CEF.

    Args:
        event: Event dictionary
        vendor: Vendor name for CEF header
        product: Product name for CEF header
        version: Version for CEF header

    Returns:
        CEF formatted string
    """
    exporter = CEFExporter(vendor=vendor, product=product, version=version)
    return exporter.format_event(event)


def format_event_leef(
    event: Dict[str, Any],
    vendor: str = "BoundaryDaemon",
    product: str = "AgentSmith",
    version: str = "1.0",
) -> str:
    """
    Convenience function to format a single event as LEEF.

    Args:
        event: Event dictionary
        vendor: Vendor name for LEEF header
        product: Product name for LEEF header
        version: Version for LEEF header

    Returns:
        LEEF formatted string
    """
    exporter = LEEFExporter(vendor=vendor, product=product, version=version)
    return exporter.format_event(event)


class SIEMEventTransformer:
    """
    Transform boundary events for various SIEM formats with
    configurable field mappings and filters.
    """

    def __init__(
        self,
        format_type: SIEMFormat = SIEMFormat.CEF,
        vendor: str = "BoundaryDaemon",
        product: str = "AgentSmith",
        version: str = "1.0",
    ):
        self.format_type = format_type
        self.vendor = vendor
        self.product = product
        self.version = version

        # Field filters
        self._include_fields: Optional[List[str]] = None
        self._exclude_fields: List[str] = []

        # Event type filters
        self._include_event_types: Optional[List[str]] = None
        self._exclude_event_types: List[str] = []

        # Severity threshold
        self._min_severity: CEFSeverity = CEFSeverity.UNKNOWN

        # Pre/post processors
        self._preprocessors: List[Callable[[Dict], Dict]] = []
        self._postprocessors: List[Callable[[str], str]] = []

        # Initialize exporters
        self._cef_exporter = CEFExporter(
            vendor=vendor, product=product, version=version
        )
        self._leef_exporter = LEEFExporter(
            vendor=vendor, product=product, version=version
        )

    def set_field_filter(
        self,
        include: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> 'SIEMEventTransformer':
        """Set field inclusion/exclusion filters."""
        self._include_fields = include
        if exclude:
            self._exclude_fields = exclude
        return self

    def set_event_type_filter(
        self,
        include: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> 'SIEMEventTransformer':
        """Set event type inclusion/exclusion filters."""
        self._include_event_types = include
        if exclude:
            self._exclude_event_types = exclude
        return self

    def set_min_severity(self, severity: CEFSeverity) -> 'SIEMEventTransformer':
        """Only include events at or above this severity."""
        self._min_severity = severity
        return self

    def add_preprocessor(
        self, func: Callable[[Dict], Dict]
    ) -> 'SIEMEventTransformer':
        """Add a function to transform events before formatting."""
        self._preprocessors.append(func)
        return self

    def add_postprocessor(
        self, func: Callable[[str], str]
    ) -> 'SIEMEventTransformer':
        """Add a function to transform formatted output."""
        self._postprocessors.append(func)
        return self

    def _should_include_event(self, event: Dict[str, Any]) -> bool:
        """Check if event passes filters."""
        event_type = event.get('event_type', 'UNKNOWN')

        # Check event type filters
        if self._include_event_types:
            if event_type not in self._include_event_types:
                return False

        if event_type in self._exclude_event_types:
            return False

        # Check severity threshold
        severity = EVENT_TYPE_TO_SEVERITY.get(event_type, CEFSeverity.UNKNOWN)
        if severity < self._min_severity:
            return False

        return True

    def _filter_fields(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Apply field filters to event."""
        if not self._include_fields and not self._exclude_fields:
            return event

        filtered = {}
        for key, value in event.items():
            # Check inclusion
            if self._include_fields and key not in self._include_fields:
                continue
            # Check exclusion
            if key in self._exclude_fields:
                continue
            filtered[key] = value

        return filtered

    def transform(self, event: Dict[str, Any]) -> Optional[str]:
        """
        Transform a single event to the configured SIEM format.

        Args:
            event: Event dictionary

        Returns:
            Formatted string or None if filtered out
        """
        # Check filters
        if not self._should_include_event(event):
            return None

        # Apply field filters
        event = self._filter_fields(event)

        # Apply preprocessors
        for preprocessor in self._preprocessors:
            event = preprocessor(event)

        # Format based on type
        if self.format_type == SIEMFormat.CEF:
            result = self._cef_exporter.format_event(event)
        elif self.format_type == SIEMFormat.LEEF:
            result = self._leef_exporter.format_event(event)
        else:  # JSON
            result = json.dumps(event)

        # Apply postprocessors
        for postprocessor in self._postprocessors:
            result = postprocessor(result)

        return result

    def transform_batch(
        self, events: List[Dict[str, Any]]
    ) -> List[str]:
        """Transform multiple events, filtering out None results."""
        results = []
        for event in events:
            result = self.transform(event)
            if result is not None:
                results.append(result)
        return results


if __name__ == '__main__':
    # Test CEF/LEEF formatters
    print("Testing CEF/LEEF Exporters...")

    test_event = {
        'event_id': 'evt_12345',
        'event_type': 'VIOLATION',
        'timestamp': '2024-01-15T10:30:00Z',
        'details': 'Network detected in AIRGAP mode',
        'hash_chain': 'abc123def456',
        'metadata': {
            'boundary_mode': 'AIRGAP',
            'source_ip': '192.168.1.100',
            'user': 'operator1',
            'violation_type': 'network_in_airgap',
        }
    }

    print("\n=== CEF Format ===")
    cef = format_event_cef(test_event)
    print(cef)

    print("\n=== LEEF Format ===")
    leef = format_event_leef(test_event)
    print(leef)

    print("\n=== Transformer with filters ===")
    transformer = SIEMEventTransformer(format_type=SIEMFormat.CEF)
    transformer.set_min_severity(CEFSeverity.HIGH)

    events = [
        {'event_id': '1', 'event_type': 'DAEMON_START', 'timestamp': '2024-01-15T10:00:00Z', 'details': 'Started'},
        {'event_id': '2', 'event_type': 'VIOLATION', 'timestamp': '2024-01-15T10:30:00Z', 'details': 'Violation!'},
        {'event_id': '3', 'event_type': 'MODE_CHANGE', 'timestamp': '2024-01-15T11:00:00Z', 'details': 'Mode changed'},
    ]

    filtered = transformer.transform_batch(events)
    print(f"Filtered {len(events)} events to {len(filtered)} (severity >= HIGH)")
    for f in filtered:
        print(f"  {f[:80]}...")

    print("\nCEF/LEEF exporter test complete.")
