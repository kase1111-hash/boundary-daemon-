#!/usr/bin/env python3
"""
queryctl - Event Query CLI for Boundary Daemon

Phase 2 Operational Excellence: Query events from the hash-chain log
without needing external SIEM access.

Usage:
    boundaryctl query "type:VIOLATION after:2024-01-01"
    boundaryctl query "severity:>=HIGH source:sandbox"
    boundaryctl query "actor:agent-* action:TOOL_REQUEST"
    boundaryctl query --last 24h
    boundaryctl query --export report.json

Query Language:
    type:<event_type>       - Filter by event type
    severity:<level>        - Filter by severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)
    severity:>=<level>      - Minimum severity
    after:<date>            - Events after date (YYYY-MM-DD or ISO8601)
    before:<date>           - Events before date
    source:<component>      - Filter by source component
    contains:<text>         - Full-text search in details
    actor:<pattern>         - Actor/agent pattern (supports *)
    action:<pattern>        - Action pattern

Options:
    --last <duration>       - Last N hours/days (e.g., "24h", "7d")
    --limit <n>             - Maximum results (default: 100)
    --format <fmt>          - Output format: table, json, csv, oneline
    --export <file>         - Export results to file
    --correlate <window>    - Correlate events within time window (seconds)
    --stats                 - Show statistics instead of events
"""

import argparse
import csv
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Iterator

# ANSI colors
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'
    MAGENTA = '\033[95m'

    @classmethod
    def disable(cls):
        for attr in ['RESET', 'BOLD', 'RED', 'GREEN', 'YELLOW', 'BLUE', 'CYAN', 'GRAY', 'MAGENTA']:
            setattr(cls, attr, '')


class Severity(Enum):
    """Event severity levels."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, s: str) -> 'Severity':
        try:
            return cls[s.upper()]
        except KeyError:
            return cls.INFO


@dataclass
class QueryEvent:
    """Event from the log file."""
    event_id: str
    timestamp: datetime
    event_type: str
    details: str
    metadata: Dict = field(default_factory=dict)
    hash_chain: str = ""
    severity: Severity = Severity.INFO

    @classmethod
    def from_dict(cls, data: Dict) -> 'QueryEvent':
        """Parse event from dict."""
        timestamp = data.get('timestamp', '')
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                timestamp = datetime.utcnow()

        # Determine severity from event type or metadata
        event_type = data.get('event_type', 'INFO')
        severity = Severity.INFO
        if 'VIOLATION' in event_type or 'TRIPWIRE' in event_type:
            severity = Severity.CRITICAL
        elif 'ERROR' in event_type or 'FAILED' in event_type:
            severity = Severity.HIGH
        elif 'WARNING' in event_type or 'WARN' in event_type:
            severity = Severity.MEDIUM
        elif 'ALERT' in event_type:
            severity = Severity.HIGH

        # Override from metadata if present
        if 'severity' in data.get('metadata', {}):
            severity = Severity.from_string(data['metadata']['severity'])

        return cls(
            event_id=data.get('event_id', ''),
            timestamp=timestamp,
            event_type=event_type,
            details=data.get('details', ''),
            metadata=data.get('metadata', {}),
            hash_chain=data.get('hash_chain', ''),
            severity=severity,
        )

    def to_dict(self) -> Dict:
        """Convert to dict for export."""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'details': self.details,
            'metadata': self.metadata,
            'severity': self.severity.name,
        }

    @property
    def timestamp_short(self) -> str:
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class QueryFilter:
    """Filter for querying events."""
    event_type: Optional[str] = None
    min_severity: Optional[Severity] = None
    after: Optional[datetime] = None
    before: Optional[datetime] = None
    source: Optional[str] = None
    contains: Optional[str] = None
    actor: Optional[str] = None
    action: Optional[str] = None

    def matches(self, event: QueryEvent) -> bool:
        """Check if event matches filter."""
        # Type filter
        if self.event_type:
            if not self._pattern_match(self.event_type, event.event_type):
                return False

        # Severity filter
        if self.min_severity:
            if event.severity.value < self.min_severity.value:
                return False

        # Time filters
        if self.after and event.timestamp < self.after:
            return False
        if self.before and event.timestamp > self.before:
            return False

        # Source filter
        if self.source:
            source = event.metadata.get('source', event.metadata.get('component', ''))
            if not self._pattern_match(self.source, source):
                return False

        # Contains filter (full-text)
        if self.contains:
            text = f"{event.event_type} {event.details} {json.dumps(event.metadata)}"
            if self.contains.lower() not in text.lower():
                return False

        # Actor filter
        if self.actor:
            actor = event.metadata.get('actor', event.metadata.get('agent_id', ''))
            if not self._pattern_match(self.actor, actor):
                return False

        # Action filter
        if self.action:
            action = event.metadata.get('action', event.event_type)
            if not self._pattern_match(self.action, action):
                return False

        return True

    @staticmethod
    def _pattern_match(pattern: str, value: str) -> bool:
        """Match pattern with wildcard support."""
        if '*' in pattern:
            # Convert to regex
            regex = pattern.replace('*', '.*')
            return bool(re.match(f'^{regex}$', value, re.IGNORECASE))
        return pattern.lower() == value.lower()


class QueryParser:
    """Parse query strings into filters."""

    @staticmethod
    def parse(query: str) -> QueryFilter:
        """Parse query string into filter."""
        flt = QueryFilter()

        if not query:
            return flt

        # Split into tokens
        tokens = query.split()

        for token in tokens:
            if ':' in token:
                key, value = token.split(':', 1)
                key = key.lower()

                if key == 'type':
                    flt.event_type = value
                elif key == 'severity':
                    if value.startswith('>='):
                        flt.min_severity = Severity.from_string(value[2:])
                    else:
                        flt.min_severity = Severity.from_string(value)
                elif key == 'after':
                    flt.after = QueryParser._parse_date(value)
                elif key == 'before':
                    flt.before = QueryParser._parse_date(value)
                elif key == 'source':
                    flt.source = value
                elif key == 'contains':
                    flt.contains = value
                elif key == 'actor':
                    flt.actor = value
                elif key == 'action':
                    flt.action = value
            else:
                # Treat as contains search
                if flt.contains:
                    flt.contains += ' ' + token
                else:
                    flt.contains = token

        return flt

    @staticmethod
    def _parse_date(value: str) -> Optional[datetime]:
        """Parse date string."""
        try:
            # Try ISO format first
            if 'T' in value:
                return datetime.fromisoformat(value.replace('Z', '+00:00'))
            # Try date only
            return datetime.strptime(value, '%Y-%m-%d')
        except:
            return None


class EventReader:
    """Read events from log file."""

    def __init__(self, log_path: str):
        self.log_path = log_path

    def read_events(self, reverse: bool = True) -> Iterator[QueryEvent]:
        """
        Read events from log file.

        Args:
            reverse: Read newest first (default True)
        """
        if not os.path.exists(self.log_path):
            return

        with open(self.log_path, 'r') as f:
            lines = f.readlines()

        if reverse:
            lines = list(reversed(lines))

        for line in lines:
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                yield QueryEvent.from_dict(data)
            except json.JSONDecodeError:
                continue

    def count_events(self) -> int:
        """Count total events."""
        if not os.path.exists(self.log_path):
            return 0

        count = 0
        with open(self.log_path, 'r') as f:
            for line in f:
                if line.strip():
                    count += 1
        return count


class QueryCLI:
    """Command-line interface for querying events."""

    DEFAULT_LOG_PATH = '/var/log/boundary-daemon/boundary_chain.log'

    def __init__(self, log_path: Optional[str] = None):
        self.log_path = log_path or os.environ.get('BOUNDARY_LOG', self.DEFAULT_LOG_PATH)
        self.reader = EventReader(self.log_path)

    def query(self, query: str, limit: int = 100, last: Optional[str] = None) -> List[QueryEvent]:
        """
        Execute query and return matching events.

        Args:
            query: Query string
            limit: Maximum results
            last: Duration like "24h" or "7d"
        """
        flt = QueryParser.parse(query)

        # Apply --last filter
        if last:
            duration = self._parse_duration(last)
            if duration:
                flt.after = datetime.utcnow() - duration

        results = []
        for event in self.reader.read_events():
            if flt.matches(event):
                results.append(event)
                if len(results) >= limit:
                    break

        return results

    def stats(self, query: str = "", last: Optional[str] = None) -> Dict:
        """
        Get statistics for matching events.

        Returns counts by type, severity, source, etc.
        """
        events = self.query(query, limit=10000, last=last)

        stats = {
            'total': len(events),
            'by_type': {},
            'by_severity': {},
            'by_hour': {},
            'first_event': None,
            'last_event': None,
        }

        for event in events:
            # By type
            stats['by_type'][event.event_type] = stats['by_type'].get(event.event_type, 0) + 1

            # By severity
            sev = event.severity.name
            stats['by_severity'][sev] = stats['by_severity'].get(sev, 0) + 1

            # By hour
            hour = event.timestamp.strftime('%Y-%m-%d %H:00')
            stats['by_hour'][hour] = stats['by_hour'].get(hour, 0) + 1

            # Time range
            if stats['first_event'] is None or event.timestamp < stats['first_event']:
                stats['first_event'] = event.timestamp
            if stats['last_event'] is None or event.timestamp > stats['last_event']:
                stats['last_event'] = event.timestamp

        return stats

    def correlate(self, query: str, window: int = 60, last: Optional[str] = None) -> List[List[QueryEvent]]:
        """
        Correlate events within time windows.

        Groups events that occur within `window` seconds of each other.
        """
        events = self.query(query, limit=10000, last=last)

        if not events:
            return []

        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp)

        groups = []
        current_group = [events[0]]

        for event in events[1:]:
            time_diff = (event.timestamp - current_group[-1].timestamp).total_seconds()
            if time_diff <= window:
                current_group.append(event)
            else:
                if len(current_group) > 1:  # Only keep groups with multiple events
                    groups.append(current_group)
                current_group = [event]

        if len(current_group) > 1:
            groups.append(current_group)

        return groups

    def format_table(self, events: List[QueryEvent]) -> str:
        """Format events as table."""
        if not events:
            return "No events found."

        lines = []

        # Header
        header = f"{Colors.BOLD}{'TIME':<20} {'TYPE':<18} {'SEV':<8} {'DETAILS':<50}{Colors.RESET}"
        lines.append(header)
        lines.append("-" * 100)

        for event in events:
            sev_colors = {
                Severity.CRITICAL: Colors.RED,
                Severity.HIGH: Colors.YELLOW,
                Severity.MEDIUM: Colors.BLUE,
                Severity.LOW: Colors.GRAY,
                Severity.INFO: '',
            }
            sev_color = sev_colors.get(event.severity, '')

            time_str = event.timestamp_short
            type_str = event.event_type[:18]
            sev_str = event.severity.name[:8]
            details = event.details[:50] if len(event.details) > 50 else event.details

            line = f"{time_str:<20} {type_str:<18} {sev_color}{sev_str:<8}{Colors.RESET} {details:<50}"
            lines.append(line)

        return '\n'.join(lines)

    def format_json(self, events: List[QueryEvent]) -> str:
        """Format events as JSON."""
        return json.dumps([e.to_dict() for e in events], indent=2)

    def format_csv(self, events: List[QueryEvent]) -> str:
        """Format events as CSV."""
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['timestamp', 'event_type', 'severity', 'details', 'event_id'])
        for event in events:
            writer.writerow([
                event.timestamp.isoformat(),
                event.event_type,
                event.severity.name,
                event.details,
                event.event_id,
            ])
        return output.getvalue()

    def format_oneline(self, events: List[QueryEvent]) -> str:
        """Format events as one line per event."""
        lines = []
        for event in events:
            line = f"{event.timestamp_short} [{event.event_type}] {event.details}"
            lines.append(line)
        return '\n'.join(lines)

    def format_stats(self, stats: Dict) -> str:
        """Format statistics."""
        lines = []
        lines.append(f"{Colors.BOLD}Event Statistics{Colors.RESET}")
        lines.append(f"  Total events: {stats['total']}")

        if stats['first_event'] and stats['last_event']:
            lines.append(f"  Time range: {stats['first_event']} to {stats['last_event']}")

        lines.append(f"\n{Colors.BOLD}By Type:{Colors.RESET}")
        for etype, count in sorted(stats['by_type'].items(), key=lambda x: -x[1]):
            lines.append(f"  {etype:<25} {count:>6}")

        lines.append(f"\n{Colors.BOLD}By Severity:{Colors.RESET}")
        for sev, count in sorted(stats['by_severity'].items()):
            color = ''
            if sev == 'CRITICAL':
                color = Colors.RED
            elif sev == 'HIGH':
                color = Colors.YELLOW
            lines.append(f"  {color}{sev:<12}{Colors.RESET} {count:>6}")

        return '\n'.join(lines)

    def format_correlations(self, groups: List[List[QueryEvent]]) -> str:
        """Format correlated event groups."""
        lines = []
        lines.append(f"{Colors.BOLD}Correlated Event Groups ({len(groups)} groups){Colors.RESET}\n")

        for i, group in enumerate(groups, 1):
            time_range = f"{group[0].timestamp_short} - {group[-1].timestamp_short}"
            lines.append(f"{Colors.CYAN}Group {i} ({len(group)} events) [{time_range}]{Colors.RESET}")

            for event in group:
                lines.append(f"  {event.timestamp_short} [{event.event_type}] {event.details[:60]}")

            lines.append("")

        return '\n'.join(lines)

    @staticmethod
    def _parse_duration(duration: str) -> Optional[timedelta]:
        """Parse duration string like "24h" or "7d"."""
        match = re.match(r'^(\d+)([hdwm])$', duration.lower())
        if not match:
            return None

        value = int(match.group(1))
        unit = match.group(2)

        if unit == 'h':
            return timedelta(hours=value)
        elif unit == 'd':
            return timedelta(days=value)
        elif unit == 'w':
            return timedelta(weeks=value)
        elif unit == 'm':
            return timedelta(days=value * 30)

        return None


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Query Boundary Daemon events",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Query Examples:
  boundaryctl query "type:VIOLATION"
  boundaryctl query "severity:>=HIGH" --last 24h
  boundaryctl query "contains:sandbox" --format json
  boundaryctl query "actor:agent-*" --correlate 60
  boundaryctl query --stats --last 7d
        """
    )

    parser.add_argument("query", nargs="?", default="",
                       help="Query string (see examples)")
    parser.add_argument("--last", "-l", type=str,
                       help="Last N hours/days (e.g., 24h, 7d)")
    parser.add_argument("--limit", "-n", type=int, default=100,
                       help="Maximum results (default: 100)")
    parser.add_argument("--format", "-f", choices=['table', 'json', 'csv', 'oneline'],
                       default='table', help="Output format")
    parser.add_argument("--export", "-e", type=str,
                       help="Export results to file")
    parser.add_argument("--correlate", "-c", type=int,
                       help="Correlate events within time window (seconds)")
    parser.add_argument("--stats", "-s", action="store_true",
                       help="Show statistics instead of events")
    parser.add_argument("--log", type=str,
                       help="Path to log file")
    parser.add_argument("--no-color", action="store_true",
                       help="Disable color output")

    args = parser.parse_args()

    # Disable colors if requested or not a TTY
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    cli = QueryCLI(log_path=args.log)

    # Execute query
    if args.stats:
        stats = cli.stats(args.query, last=args.last)
        output = cli.format_stats(stats)
    elif args.correlate:
        groups = cli.correlate(args.query, window=args.correlate, last=args.last)
        output = cli.format_correlations(groups)
    else:
        events = cli.query(args.query, limit=args.limit, last=args.last)

        if args.format == 'table':
            output = cli.format_table(events)
        elif args.format == 'json':
            output = cli.format_json(events)
        elif args.format == 'csv':
            output = cli.format_csv(events)
        elif args.format == 'oneline':
            output = cli.format_oneline(events)
        else:
            output = cli.format_table(events)

    # Output or export
    if args.export:
        with open(args.export, 'w') as f:
            f.write(output)
        print(f"Exported to {args.export}")
    else:
        print(output)


if __name__ == "__main__":
    main()
