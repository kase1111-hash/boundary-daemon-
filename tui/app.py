"""
Boundary Daemon TUI Main Application.

This is the main entry point for the terminal user interface.
"""

import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
import asyncio

# Add parent to path for daemon imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header, Footer, Static, Button, Label,
    DataTable, Log, TabbedContent, TabPane,
    ProgressBar, Rule, Switch, Input, Select
)
from textual.screen import Screen
from textual.reactive import reactive
from textual.message import Message
from textual import work

# Import daemon components
try:
    from daemon.boundary_daemon import BoundaryDaemon
    from daemon.policy_engine import BoundaryMode, PolicyEngine, Operator
    from daemon.state_monitor import StateMonitor, NetworkState, HardwareTrust
    from daemon.tripwires import TripwireSystem, ViolationType
    from daemon.event_logger import EventLogger, EventType
    from daemon.health_monitor import HealthMonitor, HealthStatus
    DAEMON_AVAILABLE = True
except ImportError as e:
    DAEMON_AVAILABLE = False
    IMPORT_ERROR = str(e)


# =============================================================================
# CUSTOM WIDGETS
# =============================================================================

class ModeIndicator(Static):
    """Visual indicator for current boundary mode."""

    MODE_STYLES = {
        "OPEN": ("green", "Low security - all operations allowed"),
        "RESTRICTED": ("yellow", "Limited external access"),
        "TRUSTED": ("cyan", "Verified environment only"),
        "AIRGAP": ("orange", "No network access"),
        "COLDROOM": ("magenta", "No USB, limited I/O"),
        "LOCKDOWN": ("red", "Emergency lockdown - all operations blocked"),
    }

    mode = reactive("UNKNOWN")

    def render(self) -> str:
        style, desc = self.MODE_STYLES.get(self.mode, ("white", "Unknown mode"))
        return f"[bold {style}]{self.mode}[/]"

    def watch_mode(self, mode: str) -> None:
        self.refresh()


class HealthIndicator(Static):
    """Health status indicator with color coding."""

    status = reactive("UNKNOWN")

    STATUS_COLORS = {
        "HEALTHY": "green",
        "DEGRADED": "yellow",
        "UNHEALTHY": "red",
        "UNKNOWN": "dim white",
    }

    def render(self) -> str:
        color = self.STATUS_COLORS.get(self.status, "white")
        icon = "●" if self.status == "HEALTHY" else "◐" if self.status == "DEGRADED" else "○"
        return f"[{color}]{icon} {self.status}[/]"


class ComponentStatus(Static):
    """Individual component status display."""

    def __init__(self, name: str, status: str = "OK", **kwargs):
        super().__init__(**kwargs)
        self.component_name = name
        self.component_status = status

    def render(self) -> str:
        icon = "●" if self.component_status == "OK" else "○"
        color = "green" if self.component_status == "OK" else "red"
        return f"[{color}]{icon}[/] {self.component_name}"


class StatBox(Static):
    """A styled statistics box."""

    def __init__(self, label: str, value: str = "0", **kwargs):
        super().__init__(**kwargs)
        self.stat_label = label
        self.stat_value = value

    def render(self) -> str:
        return f"[dim]{self.stat_label}[/]\n[bold]{self.stat_value}[/]"

    def update_value(self, value: str) -> None:
        self.stat_value = value
        self.refresh()


# =============================================================================
# SCREENS
# =============================================================================

class DashboardScreen(Screen):
    """Main dashboard with real-time status overview."""

    BINDINGS = [
        Binding("r", "refresh", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Container(id="dashboard"):
            # Top row: Mode and Health
            with Horizontal(id="top-row"):
                with Vertical(id="mode-box", classes="panel"):
                    yield Label("CURRENT MODE", classes="panel-title")
                    yield ModeIndicator(id="mode-indicator")
                    yield Label("", id="mode-description", classes="dim")

                with Vertical(id="health-box", classes="panel"):
                    yield Label("SYSTEM HEALTH", classes="panel-title")
                    yield HealthIndicator(id="health-indicator")
                    yield Label("", id="uptime-label", classes="dim")

            # Stats row
            with Horizontal(id="stats-row"):
                yield StatBox("Events (24h)", "0", id="stat-events", classes="stat-box")
                yield StatBox("Violations", "0", id="stat-violations", classes="stat-box")
                yield StatBox("Blocked Ops", "0", id="stat-blocked", classes="stat-box")
                yield StatBox("Active Rules", "0", id="stat-rules", classes="stat-box")

            # Components status
            with Vertical(id="components-panel", classes="panel"):
                yield Label("COMPONENTS", classes="panel-title")
                with Horizontal(id="components-grid"):
                    yield ComponentStatus("State Monitor", id="comp-state")
                    yield ComponentStatus("Policy Engine", id="comp-policy")
                    yield ComponentStatus("Tripwires", id="comp-tripwires")
                    yield ComponentStatus("Event Logger", id="comp-logger")

            # Recent events
            with Vertical(id="events-panel", classes="panel"):
                yield Label("RECENT EVENTS", classes="panel-title")
                yield DataTable(id="recent-events")

        yield Footer()

    def on_mount(self) -> None:
        # Setup events table
        table = self.query_one("#recent-events", DataTable)
        table.add_columns("Time", "Type", "Message")
        table.cursor_type = "row"

        # Start refresh loop
        self.refresh_data()
        self.set_interval(2.0, self.refresh_data)

    @work(exclusive=True)
    async def refresh_data(self) -> None:
        """Refresh dashboard data from daemon."""
        app = self.app
        if not isinstance(app, BoundaryDaemonTUI):
            return

        daemon = app.daemon
        if not daemon:
            return

        try:
            # Update mode
            mode = daemon.policy_engine.get_current_mode()
            mode_indicator = self.query_one("#mode-indicator", ModeIndicator)
            mode_indicator.mode = mode.name

            # Update mode description
            desc_label = self.query_one("#mode-description", Label)
            desc = ModeIndicator.MODE_STYLES.get(mode.name, ("", ""))[1]
            desc_label.update(desc)

            # Update health
            if daemon.health_monitor:
                health = daemon.health_monitor.get_health()
                health_indicator = self.query_one("#health-indicator", HealthIndicator)
                health_indicator.status = health.status.name if hasattr(health, 'status') else "UNKNOWN"

                uptime_label = self.query_one("#uptime-label", Label)
                uptime = daemon.health_monitor.get_uptime()
                hours = int(uptime // 3600)
                minutes = int((uptime % 3600) // 60)
                uptime_label.update(f"Uptime: {hours}h {minutes}m")

            # Update stats
            if daemon.event_logger:
                events = daemon.event_logger.get_recent_events(count=100)
                self.query_one("#stat-events", StatBox).update_value(str(len(events)))

            if daemon.tripwire_system:
                violations = daemon.tripwire_system.get_violation_count()
                self.query_one("#stat-violations", StatBox).update_value(str(violations))

            # Update recent events table
            if daemon.event_logger:
                table = self.query_one("#recent-events", DataTable)
                table.clear()
                events = daemon.event_logger.get_recent_events(count=10)
                for event in reversed(events):
                    time_str = event.timestamp.strftime("%H:%M:%S") if hasattr(event, 'timestamp') else "??:??:??"
                    event_type = event.event_type.name if hasattr(event, 'event_type') else "INFO"
                    message = getattr(event, 'message', str(event))[:60]
                    table.add_row(time_str, event_type, message)

        except Exception as e:
            self.notify(f"Refresh error: {e}", severity="error")

    def action_refresh(self) -> None:
        self.refresh_data()
        self.notify("Dashboard refreshed")


class ModeControlScreen(Screen):
    """Mode transition and control screen."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Container(id="mode-control"):
            yield Label("MODE CONTROL", classes="screen-title")
            yield Rule()

            # Current mode display
            with Horizontal(id="current-mode-row"):
                yield Label("Current Mode: ", classes="label")
                yield ModeIndicator(id="current-mode")

            yield Rule()
            yield Label("TRANSITION TO:", classes="section-title")

            # Mode buttons
            with Vertical(id="mode-buttons"):
                for mode in ["OPEN", "RESTRICTED", "TRUSTED", "AIRGAP", "COLDROOM", "LOCKDOWN"]:
                    style, desc = ModeIndicator.MODE_STYLES.get(mode, ("white", ""))
                    yield Button(
                        f"{mode}\n[dim]{desc}[/]",
                        id=f"btn-{mode.lower()}",
                        classes="mode-button",
                        variant="warning" if mode == "LOCKDOWN" else "default"
                    )

            yield Rule()

            # Transition log
            with Vertical(id="transition-log-panel", classes="panel"):
                yield Label("TRANSITION HISTORY", classes="panel-title")
                yield Log(id="transition-log", max_lines=50)

        yield Footer()

    def on_mount(self) -> None:
        self.refresh_mode()

    def refresh_mode(self) -> None:
        app = self.app
        if isinstance(app, BoundaryDaemonTUI) and app.daemon:
            mode = app.daemon.policy_engine.get_current_mode()
            self.query_one("#current-mode", ModeIndicator).mode = mode.name

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id and button_id.startswith("btn-"):
            target_mode = button_id[4:].upper()
            await self.transition_to_mode(target_mode)

    async def transition_to_mode(self, target_mode: str) -> None:
        app = self.app
        if not isinstance(app, BoundaryDaemonTUI) or not app.daemon:
            self.notify("Daemon not available", severity="error")
            return

        log = self.query_one("#transition-log", Log)

        try:
            mode_enum = BoundaryMode[target_mode]
            current = app.daemon.policy_engine.get_current_mode()

            if current == mode_enum:
                self.notify(f"Already in {target_mode} mode")
                return

            log.write_line(f"[{datetime.now().strftime('%H:%M:%S')}] Requesting transition: {current.name} -> {target_mode}")

            # Attempt transition
            success, message = app.daemon.policy_engine.transition_mode(
                mode_enum,
                Operator.HUMAN
            )

            if success:
                log.write_line(f"[{datetime.now().strftime('%H:%M:%S')}] SUCCESS: {message}")
                self.notify(f"Transitioned to {target_mode}", severity="information")
                self.refresh_mode()
            else:
                log.write_line(f"[{datetime.now().strftime('%H:%M:%S')}] FAILED: {message}")
                self.notify(f"Transition failed: {message}", severity="error")

        except KeyError:
            self.notify(f"Invalid mode: {target_mode}", severity="error")
        except Exception as e:
            log.write_line(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR: {e}")
            self.notify(f"Error: {e}", severity="error")


class EventLogScreen(Screen):
    """Event log viewer with filtering."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("r", "refresh", "Refresh"),
        Binding("c", "clear_filter", "Clear Filter"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Container(id="event-log"):
            yield Label("EVENT LOG", classes="screen-title")

            # Filter controls
            with Horizontal(id="filter-row"):
                yield Label("Filter: ", classes="label")
                yield Select(
                    [(t.name, t.name) for t in EventType] if DAEMON_AVAILABLE else [("ALL", "ALL")],
                    id="type-filter",
                    value="ALL",
                    allow_blank=True,
                    prompt="All Types"
                )
                yield Input(placeholder="Search...", id="search-input")
                yield Button("Refresh", id="btn-refresh", variant="primary")

            yield Rule()

            # Events table
            yield DataTable(id="events-table", zebra_stripes=True)

            # Stats footer
            with Horizontal(id="log-stats"):
                yield Label("", id="event-count")
                yield Label("", id="chain-status")

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#events-table", DataTable)
        table.add_columns("ID", "Time", "Type", "Severity", "Message")
        table.cursor_type = "row"

        self.load_events()

    @work(exclusive=True)
    async def load_events(self, filter_type: Optional[str] = None, search: str = "") -> None:
        app = self.app
        if not isinstance(app, BoundaryDaemonTUI) or not app.daemon:
            return

        table = self.query_one("#events-table", DataTable)
        table.clear()

        try:
            if app.daemon.event_logger:
                events = app.daemon.event_logger.get_recent_events(count=500)

                # Apply filters
                if filter_type and filter_type != "ALL":
                    events = [e for e in events if hasattr(e, 'event_type') and e.event_type.name == filter_type]

                if search:
                    search_lower = search.lower()
                    events = [e for e in events if search_lower in str(getattr(e, 'message', '')).lower()]

                for event in reversed(events[-100:]):  # Show last 100
                    event_id = getattr(event, 'id', '?')[:8] if hasattr(event, 'id') else '?'
                    time_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if hasattr(event, 'timestamp') else "?"
                    event_type = event.event_type.name if hasattr(event, 'event_type') else "INFO"
                    severity = getattr(event, 'severity', 'INFO')
                    message = str(getattr(event, 'message', event))[:80]
                    table.add_row(event_id, time_str, event_type, str(severity), message)

                count_label = self.query_one("#event-count", Label)
                count_label.update(f"Showing {min(100, len(events))} of {len(events)} events")

                # Check chain integrity
                result = app.daemon.event_logger.verify_chain()
                valid = result[0] if isinstance(result, tuple) else result
                chain_label = self.query_one("#chain-status", Label)
                chain_label.update(
                    "[green]Chain Valid[/]" if valid else "[red]Chain Invalid![/]"
                )

        except Exception as e:
            self.notify(f"Error loading events: {e}", severity="error")

    def action_refresh(self) -> None:
        filter_select = self.query_one("#type-filter", Select)
        search_input = self.query_one("#search-input", Input)
        self.load_events(filter_type=str(filter_select.value), search=search_input.value)

    def action_clear_filter(self) -> None:
        self.query_one("#type-filter", Select).value = Select.BLANK
        self.query_one("#search-input", Input).value = ""
        self.load_events()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-refresh":
            self.action_refresh()


class TripwireScreen(Screen):
    """Tripwire monitoring and lockdown controls."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("r", "refresh", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Container(id="tripwire-screen"):
            yield Label("TRIPWIRE MONITOR", classes="screen-title")
            yield Rule()

            # Status row
            with Horizontal(id="tripwire-status"):
                with Vertical(classes="panel"):
                    yield Label("STATUS", classes="panel-title")
                    yield Label("", id="tripwire-enabled")
                    yield Label("", id="violation-count")

                with Vertical(classes="panel"):
                    yield Label("LOCKDOWN CONTROL", classes="panel-title")
                    yield Button("TRIGGER LOCKDOWN", id="btn-lockdown", variant="error")
                    yield Button("Reset Tripwires", id="btn-reset", variant="warning")

            yield Rule()
            yield Label("ACTIVE VIOLATIONS", classes="section-title")

            # Violations table
            yield DataTable(id="violations-table", zebra_stripes=True)

            yield Rule()
            yield Label("TRIPWIRE TYPES", classes="section-title")

            # Type status grid
            with Horizontal(id="tripwire-types"):
                pass  # Will be populated dynamically

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#violations-table", DataTable)
        table.add_columns("Time", "Type", "Severity", "Details", "Status")
        table.cursor_type = "row"

        self.refresh_data()

    @work(exclusive=True)
    async def refresh_data(self) -> None:
        app = self.app
        if not isinstance(app, BoundaryDaemonTUI) or not app.daemon:
            return

        try:
            tripwires = app.daemon.tripwire_system
            if tripwires:
                # Update status
                enabled = tripwires.is_enabled()
                enabled_label = self.query_one("#tripwire-enabled", Label)
                enabled_label.update(
                    "[green]ENABLED[/]" if enabled else "[red]DISABLED[/]"
                )

                count = tripwires.get_violation_count()
                count_label = self.query_one("#violation-count", Label)
                count_label.update(f"Violations: {count}")

                # Update violations table
                table = self.query_one("#violations-table", DataTable)
                table.clear()

                violations = tripwires.get_violations()
                for v in violations:
                    time_str = v.timestamp.strftime("%H:%M:%S") if hasattr(v, 'timestamp') else "?"
                    vtype = v.violation_type.name if hasattr(v, 'violation_type') else "?"
                    severity = getattr(v, 'severity', 'HIGH')
                    details = str(getattr(v, 'details', ''))[:50]
                    status = getattr(v, 'status', 'ACTIVE')
                    table.add_row(time_str, vtype, str(severity), details, str(status))

        except Exception as e:
            self.notify(f"Error refreshing: {e}", severity="error")

    def action_refresh(self) -> None:
        self.refresh_data()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        app = self.app
        if not isinstance(app, BoundaryDaemonTUI) or not app.daemon:
            return

        if event.button.id == "btn-lockdown":
            # Confirm lockdown
            self.notify("LOCKDOWN requires confirmation!", severity="warning")
            # In real app, would show confirmation dialog
            try:
                success, msg = app.daemon.policy_engine.transition_mode(
                    BoundaryMode.LOCKDOWN,
                    Operator.HUMAN
                )
                if success:
                    self.notify("LOCKDOWN ACTIVATED", severity="error")
                else:
                    self.notify(f"Lockdown failed: {msg}", severity="error")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

        elif event.button.id == "btn-reset":
            self.notify("Tripwire reset requested", severity="information")


class SettingsScreen(Screen):
    """Configuration and settings screen."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Container(id="settings-screen"):
            yield Label("SETTINGS", classes="screen-title")
            yield Rule()

            with TabbedContent():
                with TabPane("General", id="tab-general"):
                    with Vertical(classes="settings-section"):
                        yield Label("Logging", classes="section-title")
                        with Horizontal():
                            yield Label("Verbose Mode:")
                            yield Switch(id="verbose-switch")
                        with Horizontal():
                            yield Label("Trace Mode:")
                            yield Switch(id="trace-switch")
                        with Horizontal():
                            yield Label("JSON Logging:")
                            yield Switch(id="json-switch")

                with TabPane("Security", id="tab-security"):
                    with Vertical(classes="settings-section"):
                        yield Label("Tripwires", classes="section-title")
                        with Horizontal():
                            yield Label("Auto-Lockdown:")
                            yield Switch(id="auto-lockdown-switch", value=True)
                        with Horizontal():
                            yield Label("Integrity Checks:")
                            yield Switch(id="integrity-switch", value=True)

                with TabPane("Network", id="tab-network"):
                    with Vertical(classes="settings-section"):
                        yield Label("Network Settings", classes="section-title")
                        with Horizontal():
                            yield Label("API Socket:")
                            yield Input(value="/var/run/boundary.sock", id="socket-input")
                        with Horizontal():
                            yield Label("API Port:")
                            yield Input(value="8080", id="port-input")

                with TabPane("About", id="tab-about"):
                    yield Label("Boundary Daemon TUI", classes="section-title")
                    yield Label("Version 1.0.0")
                    yield Label("")
                    yield Label("The mandatory trust enforcement layer for Agent OS.")
                    yield Label("")
                    yield Label("[dim]Press ESC to return to main menu[/]")

        yield Footer()


# =============================================================================
# MAIN APPLICATION
# =============================================================================

class BoundaryDaemonTUI(App):
    """Boundary Daemon Terminal User Interface."""

    CSS = """
    Screen {
        background: $surface;
    }

    #dashboard, #mode-control, #event-log, #tripwire-screen, #settings-screen {
        padding: 1;
    }

    .screen-title {
        text-style: bold;
        text-align: center;
        width: 100%;
        padding: 1;
    }

    .panel {
        border: solid $primary;
        padding: 1;
        margin: 1;
    }

    .panel-title {
        text-style: bold;
        color: $text;
        margin-bottom: 1;
    }

    .section-title {
        text-style: bold;
        margin: 1 0;
    }

    #top-row {
        height: auto;
        max-height: 12;
    }

    #mode-box, #health-box {
        width: 1fr;
        min-width: 30;
    }

    #mode-indicator, #health-indicator {
        text-align: center;
        text-style: bold;
        height: 3;
        content-align: center middle;
    }

    #stats-row {
        height: auto;
        margin: 1 0;
    }

    .stat-box {
        width: 1fr;
        height: 5;
        border: solid $secondary;
        padding: 1;
        text-align: center;
        margin: 0 1;
    }

    #components-grid {
        height: auto;
    }

    #components-grid ComponentStatus {
        margin-right: 3;
    }

    #events-panel {
        height: 1fr;
        min-height: 10;
    }

    #recent-events {
        height: 1fr;
    }

    .mode-button {
        width: 100%;
        margin: 1 0;
        min-height: 3;
    }

    #transition-log-panel {
        height: 1fr;
        min-height: 15;
    }

    #transition-log {
        height: 1fr;
        background: $surface-darken-1;
    }

    #filter-row {
        height: auto;
        padding: 1;
    }

    #filter-row > * {
        margin-right: 1;
    }

    #type-filter {
        width: 20;
    }

    #search-input {
        width: 30;
    }

    #events-table {
        height: 1fr;
    }

    #log-stats {
        height: 3;
        padding: 1;
    }

    #log-stats Label {
        margin-right: 3;
    }

    #tripwire-status {
        height: auto;
    }

    #tripwire-status .panel {
        width: 1fr;
    }

    #violations-table {
        height: 1fr;
        min-height: 10;
    }

    .settings-section {
        padding: 2;
    }

    .settings-section Horizontal {
        height: 3;
        margin: 1 0;
    }

    .settings-section Label {
        width: 20;
    }

    .dim {
        color: $text-muted;
    }
    """

    BINDINGS = [
        Binding("d", "show_dashboard", "Dashboard", show=True),
        Binding("m", "show_mode", "Mode Control", show=True),
        Binding("e", "show_events", "Events", show=True),
        Binding("t", "show_tripwires", "Tripwires", show=True),
        Binding("s", "show_settings", "Settings", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    TITLE = "Boundary Daemon Control Center"

    daemon: Optional[BoundaryDaemon] = None

    def __init__(self, daemon: Optional[BoundaryDaemon] = None, **kwargs):
        super().__init__(**kwargs)
        self.daemon = daemon

    def compose(self) -> ComposeResult:
        yield DashboardScreen()

    def on_mount(self) -> None:
        if not self.daemon:
            self.notify("Running in demo mode - no daemon connected", severity="warning")

    def action_show_dashboard(self) -> None:
        self.switch_screen(DashboardScreen())

    def action_show_mode(self) -> None:
        self.push_screen(ModeControlScreen())

    def action_show_events(self) -> None:
        self.push_screen(EventLogScreen())

    def action_show_tripwires(self) -> None:
        self.push_screen(TripwireScreen())

    def action_show_settings(self) -> None:
        self.push_screen(SettingsScreen())


# =============================================================================
# ENTRY POINT
# =============================================================================

def run_tui(daemon: Optional[BoundaryDaemon] = None) -> None:
    """Run the TUI application."""
    app = BoundaryDaemonTUI(daemon=daemon)
    app.run()


if __name__ == "__main__":
    run_tui()
