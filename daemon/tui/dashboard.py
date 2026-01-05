"""
Terminal Dashboard - Real-time Boundary Daemon Status

Phase 2 Operational Excellence: Provides at-a-glance visibility
into daemon status, events, alerts, and resource usage.

Features:
- Real-time mode and status display
- Event stream with filtering
- Alert management (acknowledge, resolve)
- Sandbox monitoring
- SIEM shipping status
- Keyboard shortcuts for common operations

Usage:
    boundaryctl dashboard
    boundaryctl dashboard --refresh 1

Keyboard Shortcuts:
    [m] Mode change ceremony
    [a] Acknowledge alert
    [e] Export event range
    [r] Refresh
    [q] Quit
    [/] Search events
    [?] Help
"""

import json
import logging
import os
import random
import signal
import socket
import sys
import threading
import time

# Handle curses import for Windows compatibility
# Defer error to runtime to allow PyInstaller to analyze the module
try:
    import curses
    CURSES_AVAILABLE = True
except ImportError:
    curses = None
    CURSES_AVAILABLE = False
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable

logger = logging.getLogger(__name__)


class PanelType(Enum):
    """Types of dashboard panels."""
    STATUS = "status"
    EVENTS = "events"
    ALERTS = "alerts"
    SANDBOXES = "sandboxes"
    SIEM = "siem"
    RESOURCES = "resources"


@dataclass
class DashboardEvent:
    """Event for display in dashboard."""
    timestamp: str
    event_type: str
    details: str
    severity: str = "INFO"
    metadata: Dict = field(default_factory=dict)

    @property
    def time_short(self) -> str:
        """Get short time format (HH:MM:SS)."""
        try:
            dt = datetime.fromisoformat(self.timestamp.replace('Z', '+00:00'))
            return dt.strftime("%H:%M:%S")
        except:
            return self.timestamp[:8]


@dataclass
class DashboardAlert:
    """Alert for display in dashboard."""
    alert_id: str
    timestamp: str
    severity: str
    message: str
    status: str = "NEW"  # NEW, ACKNOWLEDGED, RESOLVED
    source: str = ""


@dataclass
class SandboxStatus:
    """Sandbox status for display."""
    sandbox_id: str
    profile: str
    status: str
    memory_used: int = 0
    memory_limit: int = 0
    cpu_percent: float = 0.0
    uptime: float = 0.0


class Colors:
    """Color pairs for curses."""
    NORMAL = 0
    STATUS_OK = 1
    STATUS_WARN = 2
    STATUS_ERROR = 3
    HEADER = 4
    SELECTED = 5
    MUTED = 6
    ACCENT = 7
    MATRIX_BRIGHT = 8
    MATRIX_DIM = 9

    @staticmethod
    def init_colors(matrix_mode: bool = False):
        """Initialize curses color pairs."""
        curses.start_color()
        curses.use_default_colors()
        if matrix_mode:
            Colors._init_matrix_colors()
        else:
            curses.init_pair(Colors.STATUS_OK, curses.COLOR_GREEN, -1)
            curses.init_pair(Colors.STATUS_WARN, curses.COLOR_YELLOW, -1)
            curses.init_pair(Colors.STATUS_ERROR, curses.COLOR_RED, -1)
            curses.init_pair(Colors.HEADER, curses.COLOR_CYAN, -1)
            curses.init_pair(Colors.SELECTED, curses.COLOR_BLACK, curses.COLOR_WHITE)
            curses.init_pair(Colors.MUTED, curses.COLOR_WHITE, -1)
            curses.init_pair(Colors.ACCENT, curses.COLOR_MAGENTA, -1)

    @staticmethod
    def _init_matrix_colors():
        """Initialize Matrix-style green-on-black color scheme."""
        # All green, all the time
        curses.init_pair(Colors.STATUS_OK, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.STATUS_WARN, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.STATUS_ERROR, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.HEADER, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.SELECTED, curses.COLOR_BLACK, curses.COLOR_GREEN)
        curses.init_pair(Colors.MUTED, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.ACCENT, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.MATRIX_BRIGHT, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.MATRIX_DIM, curses.COLOR_GREEN, curses.COLOR_BLACK)


class MatrixRain:
    """Digital rain effect from The Matrix."""

    # Characters used in the Matrix digital rain (mix of half-width katakana and symbols)
    MATRIX_CHARS = (
        "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ"
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "+-*/<>=$#@&"
    )

    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height
        self.drops: List[Dict] = []
        self._init_drops()

    def _init_drops(self):
        """Initialize rain drops at random positions."""
        self.drops = []
        # Start with a few drops
        for _ in range(max(3, self.width // 20)):
            self._add_drop()

    def _add_drop(self):
        """Add a new rain drop."""
        self.drops.append({
            'x': random.randint(0, self.width - 1),
            'y': random.randint(-self.height, 0),
            'speed': random.uniform(0.3, 1.0),
            'length': random.randint(4, min(12, self.height // 2)),
            'chars': [random.choice(self.MATRIX_CHARS) for _ in range(15)],
            'phase': 0.0,
        })

    def update(self):
        """Update rain drop positions."""
        new_drops = []
        for drop in self.drops:
            drop['phase'] += drop['speed']
            drop['y'] = int(drop['phase'])

            # Randomly change characters for that flickering effect
            if random.random() < 0.3:
                idx = random.randint(0, len(drop['chars']) - 1)
                drop['chars'][idx] = random.choice(self.MATRIX_CHARS)

            # Keep drop if still on screen
            if drop['y'] - drop['length'] < self.height:
                new_drops.append(drop)

        self.drops = new_drops

        # Occasionally add new drops
        if random.random() < 0.15 and len(self.drops) < self.width // 8:
            self._add_drop()

    def resize(self, width: int, height: int):
        """Handle terminal resize."""
        self.width = width
        self.height = height
        # Remove drops that are now out of bounds
        self.drops = [d for d in self.drops if d['x'] < width]

    def render(self, screen):
        """Render rain drops to screen."""
        for drop in self.drops:
            for i in range(drop['length']):
                y = drop['y'] - i
                if 0 <= y < self.height and 0 <= drop['x'] < self.width:
                    char = drop['chars'][i % len(drop['chars'])]
                    try:
                        if i == 0:
                            # Bright white head of the drop
                            screen.attron(curses.color_pair(Colors.MATRIX_BRIGHT) | curses.A_BOLD)
                            screen.addstr(y, drop['x'], char)
                            screen.attroff(curses.color_pair(Colors.MATRIX_BRIGHT) | curses.A_BOLD)
                        elif i < 3:
                            # Bright green near the head
                            screen.attron(curses.color_pair(Colors.MATRIX_DIM) | curses.A_BOLD)
                            screen.addstr(y, drop['x'], char)
                            screen.attroff(curses.color_pair(Colors.MATRIX_DIM) | curses.A_BOLD)
                        else:
                            # Dimmer green for the tail
                            screen.attron(curses.color_pair(Colors.MATRIX_DIM))
                            screen.addstr(y, drop['x'], char)
                            screen.attroff(curses.color_pair(Colors.MATRIX_DIM))
                    except curses.error:
                        pass


class DashboardClient:
    """Client for communicating with daemon."""

    def __init__(self, socket_path: str = "/var/run/boundary-daemon/boundary.sock"):
        self.socket_path = socket_path
        self._connected = False

    def connect(self) -> bool:
        """Test connection to daemon."""
        try:
            if os.path.exists(self.socket_path):
                self._connected = True
                return True
        except:
            pass
        self._connected = False
        return False

    def get_status(self) -> Dict:
        """Get daemon status."""
        # In production, this would use Unix socket
        # For now, return mock data
        return {
            'mode': 'TRUSTED',
            'mode_since': datetime.utcnow().isoformat(),
            'uptime': 3600,
            'events_today': 1247,
            'violations': 0,
            'tripwire_enabled': True,
            'clock_monitor_enabled': True,
            'network_attestation_enabled': True,
            'is_frozen': False,
        }

    def get_events(self, limit: int = 20) -> List[DashboardEvent]:
        """Get recent events."""
        # Mock data for demonstration
        events = []
        base_time = datetime.utcnow()
        event_types = [
            ("MODE_CHANGE", "INFO", "Mode transitioned to TRUSTED"),
            ("POLICY_DECISION", "INFO", "Tool request approved: file_read"),
            ("SANDBOX_START", "INFO", "Sandbox sandbox-001 started"),
            ("TOOL_REQUEST", "INFO", "Agent requested network access"),
            ("HEALTH_CHECK", "INFO", "Health check passed"),
        ]

        for i in range(min(limit, 10)):
            etype, sev, details = event_types[i % len(event_types)]
            events.append(DashboardEvent(
                timestamp=(base_time - timedelta(seconds=i*30)).isoformat(),
                event_type=etype,
                details=details,
                severity=sev,
            ))

        return events

    def get_alerts(self) -> List[DashboardAlert]:
        """Get active alerts."""
        # Mock data
        return [
            DashboardAlert(
                alert_id="alert-001",
                timestamp=datetime.utcnow().isoformat(),
                severity="HIGH",
                message="Prompt injection attempt detected",
                status="NEW",
                source="prompt_injection",
            ),
            DashboardAlert(
                alert_id="alert-002",
                timestamp=(datetime.utcnow() - timedelta(hours=1)).isoformat(),
                severity="MEDIUM",
                message="Clock drift warning (150s)",
                status="ACKNOWLEDGED",
                source="clock_monitor",
            ),
        ]

    def get_sandboxes(self) -> List[SandboxStatus]:
        """Get active sandboxes."""
        return [
            SandboxStatus(
                sandbox_id="sandbox-001",
                profile="standard",
                status="running",
                memory_used=256*1024*1024,
                memory_limit=1024*1024*1024,
                cpu_percent=25.5,
                uptime=1800,
            ),
        ]

    def get_siem_status(self) -> Dict:
        """Get SIEM shipping status."""
        return {
            'connected': True,
            'backend': 'kafka',
            'last_shipped': datetime.utcnow().isoformat(),
            'queue_depth': 12,
            'events_shipped_today': 5432,
        }


class Dashboard:
    """
    Terminal-based dashboard for Boundary Daemon.

    Displays:
    - Current mode and status
    - Recent events
    - Active alerts
    - Sandbox status
    - SIEM shipping status
    """

    def __init__(self, refresh_interval: float = 2.0, socket_path: Optional[str] = None,
                 matrix_mode: bool = False):
        self.refresh_interval = refresh_interval
        self.client = DashboardClient(socket_path or "/var/run/boundary-daemon/boundary.sock")
        self.running = False
        self.screen = None
        self.selected_panel = PanelType.STATUS
        self.event_filter = ""
        self.scroll_offset = 0
        self.show_help = False
        self.matrix_mode = matrix_mode
        self.matrix_rain: Optional[MatrixRain] = None

        # Data caches
        self.status: Dict = {}
        self.events: List[DashboardEvent] = []
        self.alerts: List[DashboardAlert] = []
        self.sandboxes: List[SandboxStatus] = []
        self.siem_status: Dict = {}

        # Layout
        self.height = 0
        self.width = 0

    def run(self):
        """Run the dashboard."""
        if not CURSES_AVAILABLE:
            if sys.platform == 'win32':
                # Try to auto-launch with Python 3.12 if available
                if self._try_relaunch_with_py312():
                    return  # Successfully relaunched
                print("Error: curses library not available on Windows.")
                print("")
                print("Try: pip install windows-curses")
                print("")
                print("If that fails (e.g., Python 3.14+), install Python 3.12:")
                print("  1. Download from https://www.python.org/downloads/release/python-3120/")
                print("  2. Run: py -3.12 -m pip install windows-curses")
                print("  3. Re-run this command (it will auto-detect Python 3.12)")
            else:
                print("Error: curses library not available.")
            sys.exit(1)
        curses.wrapper(self._main_loop)

    def _try_relaunch_with_py312(self) -> bool:
        """Try to relaunch the dashboard with Python 3.12 on Windows."""
        import subprocess

        # Check if we're already being relaunched (prevent infinite loop)
        if os.environ.get('_BOUNDARY_PY312_RELAUNCH'):
            return False

        # Try to find Python 3.12
        try:
            result = subprocess.run(
                ['py', '-3.12', '--version'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return False
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

        # Check if windows-curses is installed for Python 3.12
        try:
            result = subprocess.run(
                ['py', '-3.12', '-c', 'import curses'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                # Try to install windows-curses automatically
                print("Found Python 3.12, installing windows-curses...")
                install_result = subprocess.run(
                    ['py', '-3.12', '-m', 'pip', 'install', '-q', 'windows-curses'],
                    capture_output=True, text=True, timeout=60
                )
                if install_result.returncode != 0:
                    print("Failed to install windows-curses for Python 3.12")
                    return False
                print("Successfully installed windows-curses!")
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

        # Relaunch with Python 3.12
        print("Relaunching with Python 3.12...")
        env = os.environ.copy()
        env['_BOUNDARY_PY312_RELAUNCH'] = '1'

        # Rebuild the command line arguments
        args = ['py', '-3.12', '-m', 'daemon.tui.dashboard']
        if self.matrix_mode:
            args.append('--matrix')
        if self.refresh_interval != 2.0:
            args.extend(['--refresh', str(self.refresh_interval)])

        try:
            result = subprocess.run(args, env=env)
            sys.exit(result.returncode)
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

        return True

    def _main_loop(self, screen):
        """Main curses loop."""
        self.screen = screen
        self.running = True

        # Setup curses
        curses.curs_set(0)  # Hide cursor
        Colors.init_colors(self.matrix_mode)

        # Matrix mode: faster refresh for smooth animation, black background
        if self.matrix_mode:
            screen.timeout(100)  # 100ms for smooth rain animation
            screen.bkgd(' ', curses.color_pair(Colors.MATRIX_DIM))
            self._update_dimensions()
            self.matrix_rain = MatrixRain(self.width, self.height)
        else:
            screen.timeout(int(self.refresh_interval * 1000))

        # Handle terminal resize
        signal.signal(signal.SIGWINCH, lambda *_: self._handle_resize())

        # Initial data fetch
        self._refresh_data()

        while self.running:
            try:
                self._update_dimensions()

                # Update matrix rain animation
                if self.matrix_mode and self.matrix_rain:
                    self.matrix_rain.update()

                self._draw()

                # Wait for input with timeout
                key = screen.getch()
                self._handle_input(key)

                # Refresh data on timeout (less frequently in matrix mode)
                if key == -1:  # Timeout
                    if not self.matrix_mode or random.random() < 0.1:
                        self._refresh_data()

            except KeyboardInterrupt:
                self.running = False
            except curses.error:
                pass

    def _handle_resize(self):
        """Handle terminal resize."""
        self._update_dimensions()
        if self.matrix_mode and self.matrix_rain:
            self.matrix_rain.resize(self.width, self.height)
        self.screen.clear()

    def _update_dimensions(self):
        """Update terminal dimensions."""
        self.height, self.width = self.screen.getmaxyx()

    def _refresh_data(self):
        """Refresh all data from daemon."""
        try:
            self.status = self.client.get_status()
            self.events = self.client.get_events(20)
            self.alerts = self.client.get_alerts()
            self.sandboxes = self.client.get_sandboxes()
            self.siem_status = self.client.get_siem_status()
        except Exception as e:
            logger.error(f"Failed to refresh data: {e}")

    def _handle_input(self, key: int):
        """Handle keyboard input."""
        if key == ord('q') or key == ord('Q'):
            self.running = False
        elif key == ord('r') or key == ord('R'):
            self._refresh_data()
        elif key == ord('?'):
            self.show_help = not self.show_help
        elif key == ord('m') or key == ord('M'):
            self._show_mode_ceremony()
        elif key == ord('a') or key == ord('A'):
            self._acknowledge_alert()
        elif key == ord('/'):
            self._start_search()
        elif key == curses.KEY_UP:
            self.scroll_offset = max(0, self.scroll_offset - 1)
        elif key == curses.KEY_DOWN:
            self.scroll_offset += 1
        elif key == ord('1'):
            self.selected_panel = PanelType.STATUS
        elif key == ord('2'):
            self.selected_panel = PanelType.EVENTS
        elif key == ord('3'):
            self.selected_panel = PanelType.ALERTS
        elif key == ord('4'):
            self.selected_panel = PanelType.SANDBOXES

    def _draw(self):
        """Draw the dashboard."""
        self.screen.clear()

        # Render matrix rain in background first
        if self.matrix_mode and self.matrix_rain:
            self.matrix_rain.render(self.screen)

        if self.show_help:
            self._draw_help()
        else:
            self._draw_header()
            self._draw_panels()
            self._draw_footer()

        self.screen.refresh()

    def _draw_header(self):
        """Draw the header bar."""
        header = f" BOUNDARY DAEMON  │  Mode: {self.status.get('mode', 'UNKNOWN')}  │  "
        if self.status.get('is_frozen'):
            header += "⚠ MODE FROZEN  │  "
        header += f"Uptime: {self._format_duration(self.status.get('uptime', 0))}"

        # Pad to full width
        header = header.ljust(self.width - 1)

        self.screen.attron(curses.color_pair(Colors.HEADER) | curses.A_BOLD)
        self.screen.addstr(0, 0, header[:self.width-1])
        self.screen.attroff(curses.color_pair(Colors.HEADER) | curses.A_BOLD)

    def _draw_panels(self):
        """Draw the main panels."""
        # Calculate panel dimensions
        panel_height = self.height - 4  # Header + Footer + Borders
        left_width = self.width // 2
        right_width = self.width - left_width

        # Left column: Status + Events
        status_height = 8
        events_height = panel_height - status_height

        self._draw_status_panel(2, 0, left_width, status_height)
        self._draw_events_panel(2 + status_height, 0, left_width, events_height)

        # Right column: Alerts + Sandboxes + SIEM
        alerts_height = panel_height // 3
        sandbox_height = panel_height // 3
        siem_height = panel_height - alerts_height - sandbox_height

        self._draw_alerts_panel(2, left_width, right_width, alerts_height)
        self._draw_sandbox_panel(2 + alerts_height, left_width, right_width, sandbox_height)
        self._draw_siem_panel(2 + alerts_height + sandbox_height, left_width, right_width, siem_height)

    def _draw_status_panel(self, y: int, x: int, width: int, height: int):
        """Draw the status panel."""
        self._draw_box(y, x, width, height, "STATUS")

        row = y + 1
        col = x + 2

        # Mode
        mode = self.status.get('mode', 'UNKNOWN')
        mode_color = Colors.STATUS_OK if mode in ('TRUSTED', 'AIRGAP', 'COLDROOM') else Colors.STATUS_WARN
        self._addstr(row, col, f"Mode: ", Colors.MUTED)
        self._addstr(row, col + 6, mode, mode_color, bold=True)
        row += 1

        # Tripwires
        tw_enabled = self.status.get('tripwire_enabled', False)
        tw_text = "✓ Enabled" if tw_enabled else "✗ Disabled"
        tw_color = Colors.STATUS_OK if tw_enabled else Colors.STATUS_ERROR
        self._addstr(row, col, "Tripwires: ", Colors.MUTED)
        self._addstr(row, col + 11, tw_text, tw_color)
        row += 1

        # Clock Monitor
        cm_enabled = self.status.get('clock_monitor_enabled', False)
        cm_text = "✓ Active" if cm_enabled else "✗ Inactive"
        cm_color = Colors.STATUS_OK if cm_enabled else Colors.STATUS_WARN
        self._addstr(row, col, "Clock: ", Colors.MUTED)
        self._addstr(row, col + 7, cm_text, cm_color)
        row += 1

        # Network Attestation
        na_enabled = self.status.get('network_attestation_enabled', False)
        na_text = "✓ Active" if na_enabled else "○ Inactive"
        na_color = Colors.STATUS_OK if na_enabled else Colors.MUTED
        self._addstr(row, col, "Network: ", Colors.MUTED)
        self._addstr(row, col + 9, na_text, na_color)
        row += 1

        # Events today
        events_count = self.status.get('events_today', 0)
        self._addstr(row, col, f"Events: {events_count:,}", Colors.MUTED)
        row += 1

        # Violations
        violations = self.status.get('violations', 0)
        v_color = Colors.STATUS_ERROR if violations > 0 else Colors.STATUS_OK
        self._addstr(row, col, f"Violations: {violations}", v_color)

    def _draw_events_panel(self, y: int, x: int, width: int, height: int):
        """Draw the events panel."""
        self._draw_box(y, x, width, height, f"EVENTS (last {len(self.events)})")

        row = y + 1
        col = x + 2
        max_rows = height - 2
        display_width = width - 4

        for i, event in enumerate(self.events[:max_rows]):
            if row >= y + height - 1:
                break

            # Time
            time_str = event.time_short
            self._addstr(row, col, time_str, Colors.MUTED)

            # Type
            type_col = col + 10
            type_color = Colors.ACCENT if event.event_type in ('VIOLATION', 'TRIPWIRE') else Colors.NORMAL
            event_type = event.event_type[:15]
            self._addstr(row, type_col, event_type, type_color)

            # Details (truncated)
            detail_col = type_col + 16
            max_detail = display_width - (detail_col - col)
            details = event.details[:max_detail] if len(event.details) > max_detail else event.details
            self._addstr(row, detail_col, details, Colors.NORMAL)

            row += 1

    def _draw_alerts_panel(self, y: int, x: int, width: int, height: int):
        """Draw the alerts panel."""
        unack_count = sum(1 for a in self.alerts if a.status == "NEW")
        title = f"ALERTS ({unack_count} unacknowledged)" if unack_count else "ALERTS"
        title_color = Colors.STATUS_ERROR if unack_count else Colors.HEADER
        self._draw_box(y, x, width, height, title, title_color)

        row = y + 1
        col = x + 2
        display_width = width - 4

        if not self.alerts:
            self._addstr(row, col, "No active alerts", Colors.STATUS_OK)
        else:
            for alert in self.alerts[:height-2]:
                if row >= y + height - 1:
                    break

                # Status icon
                if alert.status == "NEW":
                    icon = "⚠"
                    icon_color = Colors.STATUS_WARN if alert.severity == "MEDIUM" else Colors.STATUS_ERROR
                elif alert.status == "ACKNOWLEDGED":
                    icon = "○"
                    icon_color = Colors.MUTED
                else:
                    icon = "✓"
                    icon_color = Colors.STATUS_OK

                self._addstr(row, col, icon, icon_color)
                self._addstr(row, col + 2, alert.severity[:4], icon_color)

                # Message (truncated)
                msg_col = col + 8
                max_msg = display_width - 10
                message = alert.message[:max_msg] if len(alert.message) > max_msg else alert.message
                self._addstr(row, msg_col, message, Colors.NORMAL)

                row += 1

    def _draw_sandbox_panel(self, y: int, x: int, width: int, height: int):
        """Draw the sandbox panel."""
        active_count = len([s for s in self.sandboxes if s.status == "running"])
        self._draw_box(y, x, width, height, f"SANDBOXES ({active_count} active)")

        row = y + 1
        col = x + 2
        display_width = width - 4

        if not self.sandboxes:
            self._addstr(row, col, "No active sandboxes", Colors.MUTED)
        else:
            for sb in self.sandboxes[:height-2]:
                if row >= y + height - 1:
                    break

                # ID and profile
                id_str = f"{sb.sandbox_id[:12]} ({sb.profile})"
                status_color = Colors.STATUS_OK if sb.status == "running" else Colors.MUTED
                self._addstr(row, col, id_str, status_color)

                # Memory
                mem_pct = (sb.memory_used / sb.memory_limit * 100) if sb.memory_limit else 0
                mem_color = Colors.STATUS_OK if mem_pct < 80 else Colors.STATUS_WARN
                mem_str = f"{self._format_bytes(sb.memory_used)}/{self._format_bytes(sb.memory_limit)}"
                self._addstr(row, col + 28, mem_str, mem_color)

                # CPU
                cpu_color = Colors.STATUS_OK if sb.cpu_percent < 80 else Colors.STATUS_WARN
                cpu_str = f"{sb.cpu_percent:.0f}%"
                self._addstr(row, col + 45, cpu_str, cpu_color)

                row += 1

    def _draw_siem_panel(self, y: int, x: int, width: int, height: int):
        """Draw the SIEM status panel."""
        connected = self.siem_status.get('connected', False)
        title_color = Colors.STATUS_OK if connected else Colors.STATUS_ERROR
        self._draw_box(y, x, width, height, "SIEM SHIPPING", title_color)

        row = y + 1
        col = x + 2

        # Connection status
        status_text = "✓ Connected" if connected else "✗ Disconnected"
        status_color = Colors.STATUS_OK if connected else Colors.STATUS_ERROR
        self._addstr(row, col, f"Status: {status_text}", status_color)
        row += 1

        # Backend
        backend = self.siem_status.get('backend', 'unknown')
        self._addstr(row, col, f"Backend: {backend}", Colors.MUTED)
        row += 1

        # Queue depth
        queue = self.siem_status.get('queue_depth', 0)
        queue_color = Colors.STATUS_OK if queue < 100 else Colors.STATUS_WARN
        self._addstr(row, col, f"Queue: {queue} events", queue_color)
        row += 1

        # Events shipped
        shipped = self.siem_status.get('events_shipped_today', 0)
        self._addstr(row, col, f"Shipped today: {shipped:,}", Colors.MUTED)

    def _draw_footer(self):
        """Draw the footer bar."""
        shortcuts = "[m]Mode [a]Ack [r]Refresh [/]Search [?]Help [q]Quit"
        footer = f" {shortcuts} ".ljust(self.width - 1)

        row = self.height - 1
        self.screen.attron(curses.color_pair(Colors.MUTED))
        try:
            self.screen.addstr(row, 0, footer[:self.width-1])
        except curses.error:
            pass
        self.screen.attroff(curses.color_pair(Colors.MUTED))

    def _draw_help(self):
        """Draw help overlay."""
        help_text = [
            "KEYBOARD SHORTCUTS",
            "",
            "  m    Start mode change ceremony",
            "  a    Acknowledge selected alert",
            "  e    Export events to file",
            "  r    Refresh data",
            "  /    Filter events",
            "",
            "  1    Focus status panel",
            "  2    Focus events panel",
            "  3    Focus alerts panel",
            "  4    Focus sandboxes panel",
            "",
            "  ↑↓   Scroll current panel",
            "  q    Quit dashboard",
            "  ?    Toggle this help",
            "",
            "Press any key to close",
        ]

        # Calculate centered position
        box_width = max(len(line) for line in help_text) + 4
        box_height = len(help_text) + 2
        start_y = (self.height - box_height) // 2
        start_x = (self.width - box_width) // 2

        # Draw box
        self._draw_box(start_y, start_x, box_width, box_height, "HELP")

        # Draw help text
        for i, line in enumerate(help_text):
            self._addstr(start_y + 1 + i, start_x + 2, line, Colors.NORMAL)

    def _draw_box(self, y: int, x: int, width: int, height: int, title: str, title_color: int = None):
        """Draw a box with title."""
        if title_color is None:
            title_color = Colors.HEADER

        try:
            # Top border
            self.screen.addch(y, x, curses.ACS_ULCORNER)
            self.screen.addch(y, x + width - 1, curses.ACS_URCORNER)
            for i in range(1, width - 1):
                self.screen.addch(y, x + i, curses.ACS_HLINE)

            # Title
            if title:
                title_str = f" {title} "
                self.screen.attron(curses.color_pair(title_color) | curses.A_BOLD)
                self.screen.addstr(y, x + 2, title_str[:width-4])
                self.screen.attroff(curses.color_pair(title_color) | curses.A_BOLD)

            # Side borders
            for i in range(1, height - 1):
                self.screen.addch(y + i, x, curses.ACS_VLINE)
                self.screen.addch(y + i, x + width - 1, curses.ACS_VLINE)

            # Bottom border
            self.screen.addch(y + height - 1, x, curses.ACS_LLCORNER)
            self.screen.addch(y + height - 1, x + width - 1, curses.ACS_LRCORNER)
            for i in range(1, width - 1):
                self.screen.addch(y + height - 1, x + i, curses.ACS_HLINE)
        except curses.error:
            pass

    def _addstr(self, y: int, x: int, text: str, color: int = Colors.NORMAL, bold: bool = False):
        """Add string with color and bounds checking."""
        if y >= self.height or x >= self.width:
            return

        max_len = self.width - x - 1
        if max_len <= 0:
            return

        text = text[:max_len]

        try:
            attr = curses.color_pair(color)
            if bold:
                attr |= curses.A_BOLD
            self.screen.attron(attr)
            self.screen.addstr(y, x, text)
            self.screen.attroff(attr)
        except curses.error:
            pass

    def _show_mode_ceremony(self):
        """Show mode change ceremony dialog."""
        # In production, this would integrate with ceremony manager
        self.screen.clear()
        self._addstr(self.height // 2, self.width // 2 - 10, "Mode ceremony not implemented", Colors.STATUS_WARN)
        self.screen.refresh()
        time.sleep(1)

    def _acknowledge_alert(self):
        """Acknowledge selected alert."""
        # In production, this would integrate with alert manager
        if self.alerts:
            for alert in self.alerts:
                if alert.status == "NEW":
                    alert.status = "ACKNOWLEDGED"
                    break

    def _start_search(self):
        """Start event search/filter."""
        # In production, this would show a search input
        pass

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format duration as human-readable string."""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds // 60)}m {int(seconds % 60)}s"
        else:
            hours = int(seconds // 3600)
            mins = int((seconds % 3600) // 60)
            return f"{hours}h {mins}m"

    @staticmethod
    def _format_bytes(n: int) -> str:
        """Format bytes as human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if abs(n) < 1024.0:
                return f"{n:.0f}{unit}"
            n /= 1024.0
        return f"{n:.0f}TB"


def run_dashboard(refresh_interval: float = 2.0, socket_path: Optional[str] = None,
                  matrix_mode: bool = False):
    """
    Run the dashboard.

    Args:
        refresh_interval: How often to refresh data (seconds)
        socket_path: Path to daemon socket
        matrix_mode: Enable Matrix-style theme with digital rain
    """
    dashboard = Dashboard(refresh_interval=refresh_interval, socket_path=socket_path,
                         matrix_mode=matrix_mode)
    dashboard.run()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Boundary Daemon Dashboard")
    parser.add_argument("--refresh", "-r", type=float, default=2.0,
                       help="Refresh interval in seconds")
    parser.add_argument("--socket", "-s", type=str,
                       help="Path to daemon socket")
    # Secret Matrix mode - not shown in help
    parser.add_argument("--matrix", action="store_true",
                       help=argparse.SUPPRESS)

    args = parser.parse_args()
    run_dashboard(refresh_interval=args.refresh, socket_path=args.socket,
                  matrix_mode=args.matrix)
