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
import math
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

# Import Ollama client for CLI chat
try:
    from daemon.monitoring_report import OllamaClient, OllamaConfig
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    OllamaClient = None
    OllamaConfig = None

logger = logging.getLogger(__name__)

# Import audio engine for TTS car sounds
try:
    from daemon.audio import get_audio_engine, AudioEngine
    AUDIO_ENGINE_AVAILABLE = True
except ImportError:
    AUDIO_ENGINE_AVAILABLE = False
    get_audio_engine = None
    AudioEngine = None


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
    MATRIX_FADE1 = 10
    MATRIX_FADE2 = 11
    MATRIX_FADE3 = 12
    LIGHTNING = 13  # Inverted flash for lightning bolt
    # Alley scene colors
    ALLEY_DARK = 14      # Darkest shadows
    ALLEY_MID = 15       # Mid-tone buildings
    ALLEY_LIGHT = 16     # Lighter details
    ALLEY_BLUE = 17      # Muted blue accents
    # Creature colors
    RAT_YELLOW = 18      # Yellow rat for warnings
    SHADOW_RED = 19      # Red glowing eyes for threats
    # Weather mode colors
    RAIN_BRIGHT = 20     # Bright blue rain
    RAIN_DIM = 21        # Dim blue rain
    RAIN_FADE1 = 22      # Fading blue
    RAIN_FADE2 = 23      # Very faded blue
    SNOW_BRIGHT = 24     # Bright white snow
    SNOW_DIM = 25        # Dim gray snow
    SNOW_FADE = 26       # Faded gray snow
    SAND_BRIGHT = 27     # Bright sand/brown
    SAND_DIM = 28        # Dim sand
    SAND_FADE = 29       # Faded sand
    MATRIX_DARK = 30     # Dark green for rain tails
    BRICK_RED = 31       # Red brick color for upper building
    GREY_BLOCK = 32      # Grey block color for lower building
    DOOR_KNOB_GOLD = 33  # Gold door knob color
    CAFE_WARM = 34       # Warm yellow/orange for cafe interior
    # Weather-based box border colors
    BOX_BROWN = 35       # Brown for snow mode top/sides
    BOX_DARK_BROWN = 36  # Dark brown for rain mode
    BOX_GREY = 37        # Grey for sand mode
    BOX_WHITE = 38       # White for snow mode bottom
    # Weather-blended text colors
    TEXT_RAIN = 39       # Blue-tinted text for rain mode
    TEXT_SNOW = 40       # White text for snow mode
    TEXT_SAND = 41       # Yellow/tan text for sand mode
    # Christmas light colors (secret event Dec 20-31)
    XMAS_RED = 42        # Red Christmas light
    XMAS_GREEN = 43      # Green Christmas light
    CAFE_GREEN = 47      # Green for Shell Cafe turtle shell
    XMAS_BLUE = 44       # Blue Christmas light
    XMAS_YELLOW = 45     # Yellow Christmas light
    # Halloween colors (secret event Oct 24-31)
    HALLOWEEN_ORANGE = 46  # Orange pumpkin glow
    HALLOWEEN_PURPLE = 53  # Spooky purple (was 47, conflicted with CAFE_GREEN)
    # Firework colors (4th of July Jul 1-7)
    FIREWORK_WHITE = 48   # White burst
    FIREWORK_MAGENTA = 49 # Magenta burst
    # Easter colors
    EASTER_PINK = 50      # Pink easter egg
    EASTER_CYAN = 51      # Cyan easter egg
    EASTER_LAVENDER = 52  # Lavender easter egg
    # 3D Tunnel backdrop colors
    TUNNEL_FAR = 54       # Furthest depth - very dim
    TUNNEL_MID = 55       # Mid depth
    TUNNEL_NEAR = 56      # Near depth - brighter
    TUNNEL_BRIGHT = 57    # Brightest tunnel highlights

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
        # Matrix rain colors - bright to dim gradient
        curses.init_pair(Colors.MATRIX_BRIGHT, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.MATRIX_DIM, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.MATRIX_FADE1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.MATRIX_FADE2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.MATRIX_FADE3, curses.COLOR_BLACK, curses.COLOR_BLACK)
        # Dark green for rain tails - try to use custom dark green if terminal supports it
        try:
            if curses.can_change_color() and curses.COLORS >= 256:
                # Define a custom dark green color (RGB values scaled 0-1000)
                curses.init_color(100, 0, 300, 0)  # Dark green
                curses.init_pair(Colors.MATRIX_DARK, 100, curses.COLOR_BLACK)
            else:
                # Fallback: use normal green, will apply A_DIM when rendering
                curses.init_pair(Colors.MATRIX_DARK, curses.COLOR_GREEN, curses.COLOR_BLACK)
        except:
            curses.init_pair(Colors.MATRIX_DARK, curses.COLOR_GREEN, curses.COLOR_BLACK)
        # Lightning flash - inverted bright white on green
        curses.init_pair(Colors.LIGHTNING, curses.COLOR_BLACK, curses.COLOR_WHITE)
        # Alley scene colors - muted blue and grey
        curses.init_pair(Colors.ALLEY_DARK, curses.COLOR_BLACK, curses.COLOR_BLACK)
        curses.init_pair(Colors.ALLEY_MID, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.ALLEY_LIGHT, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.ALLEY_BLUE, curses.COLOR_CYAN, curses.COLOR_BLACK)
        # Creature colors
        curses.init_pair(Colors.RAT_YELLOW, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(Colors.SHADOW_RED, curses.COLOR_RED, curses.COLOR_BLACK)
        # Weather mode colors
        # Rain (blue)
        curses.init_pair(Colors.RAIN_BRIGHT, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.RAIN_DIM, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(Colors.RAIN_FADE1, curses.COLOR_BLUE, curses.COLOR_BLACK)
        curses.init_pair(Colors.RAIN_FADE2, curses.COLOR_BLUE, curses.COLOR_BLACK)
        # Snow (white/gray)
        curses.init_pair(Colors.SNOW_BRIGHT, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.SNOW_DIM, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.SNOW_FADE, curses.COLOR_WHITE, curses.COLOR_BLACK)
        # Sand (yellow/brown - using yellow as closest to brown)
        curses.init_pair(Colors.SAND_BRIGHT, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(Colors.SAND_DIM, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(Colors.SAND_FADE, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        # Building colors
        curses.init_pair(Colors.BRICK_RED, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(Colors.GREY_BLOCK, curses.COLOR_WHITE, curses.COLOR_BLACK)
        # Door knob - gold/yellow
        curses.init_pair(Colors.DOOR_KNOB_GOLD, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        # Cafe warm interior color
        curses.init_pair(Colors.CAFE_WARM, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        # Weather-based box border colors
        curses.init_pair(Colors.BOX_BROWN, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Brown approximation
        curses.init_pair(Colors.BOX_DARK_BROWN, curses.COLOR_RED, curses.COLOR_BLACK)  # Dark brown via dim red
        curses.init_pair(Colors.BOX_GREY, curses.COLOR_WHITE, curses.COLOR_BLACK)  # Grey via dim white
        curses.init_pair(Colors.BOX_WHITE, curses.COLOR_WHITE, curses.COLOR_BLACK)  # White
        # Weather-blended text colors
        curses.init_pair(Colors.TEXT_RAIN, curses.COLOR_CYAN, curses.COLOR_BLACK)  # Blue/cyan for rain
        curses.init_pair(Colors.TEXT_SNOW, curses.COLOR_WHITE, curses.COLOR_BLACK)  # White for snow
        curses.init_pair(Colors.TEXT_SAND, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Yellow/tan for sand
        # Christmas light colors
        curses.init_pair(Colors.XMAS_RED, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(Colors.XMAS_GREEN, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.CAFE_GREEN, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.XMAS_BLUE, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(Colors.XMAS_YELLOW, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        # Halloween colors
        curses.init_pair(Colors.HALLOWEEN_ORANGE, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Orange via yellow
        curses.init_pair(Colors.HALLOWEEN_PURPLE, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        # Firework colors
        curses.init_pair(Colors.FIREWORK_WHITE, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.FIREWORK_MAGENTA, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        # Easter colors
        curses.init_pair(Colors.EASTER_PINK, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        curses.init_pair(Colors.EASTER_CYAN, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(Colors.EASTER_LAVENDER, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        # 3D Tunnel backdrop colors - deep blues and cyans for cosmic depth
        curses.init_pair(Colors.TUNNEL_FAR, curses.COLOR_BLUE, curses.COLOR_BLACK)
        curses.init_pair(Colors.TUNNEL_MID, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(Colors.TUNNEL_NEAR, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(Colors.TUNNEL_BRIGHT, curses.COLOR_WHITE, curses.COLOR_BLACK)


class WeatherMode(Enum):
    """Weather modes for Matrix-style effects."""
    MATRIX = "matrix"      # Classic green Matrix rain
    RAIN = "rain"          # Blue rain
    SNOW = "snow"          # White/gray snow
    SAND = "sand"          # Brown/yellow sandstorm
    CALM = "calm"          # No particles, just wind (leaves/debris)

    @property
    def display_name(self) -> str:
        """Get display name for the weather mode."""
        return {
            WeatherMode.MATRIX: "Matrix",
            WeatherMode.RAIN: "Rain",
            WeatherMode.SNOW: "Snow",
            WeatherMode.SAND: "Sandstorm",
            WeatherMode.CALM: "Calm",
        }.get(self, self.value.title())


class MatrixRain:
    """Digital rain effect from The Matrix with depth simulation and weather modes."""

    # Weather-specific character sets
    WEATHER_CHARS = {
        WeatherMode.MATRIX: [
            ".-·:;'`",  # Layer 0: Tiny rain - minimal dots
            ".|!:;+-=",  # Layer 1: Simple ASCII
            "0123456789+-*/<>=$#",  # Layer 2: Numbers and symbols
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",  # Layer 3: Alphanumeric
            "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789$#@&",  # Layer 4: Nearest
        ],
        WeatherMode.RAIN: [
            ".|'`",  # Layer 0: Light drizzle
            ".|!:",  # Layer 1: Light rain
            ".|!:;",  # Layer 2: Rain
            "||!:;/\\",  # Layer 3: Heavy rain
            "|||///\\\\\\",  # Layer 4: Downpour
        ],
        WeatherMode.SNOW: [
            "··",  # Layer 0: Distant snowflakes
            ".·*",  # Layer 1: Small flakes
            ".*+",  # Layer 2: Medium flakes
            "*+❄",  # Layer 3: Large flakes (using simple chars for compatibility)
            "*❄❅❆",  # Layer 4: Big fluffy snowflakes
        ],
        WeatherMode.SAND: [
            ".,",  # Layer 0: Fine dust
            ".,;:",  # Layer 1: Fine sand
            ".,:;'",  # Layer 2: Sand particles
            ",:;~^",  # Layer 3: Coarse sand
            "~^°º",  # Layer 4: Larger particles
        ],
        WeatherMode.CALM: [
            "",  # Layer 0: No particles
            "",  # Layer 1: No particles
            "",  # Layer 2: No particles
            "",  # Layer 3: No particles
            "",  # Layer 4: No particles (wind effects only)
        ],
    }

    # Weather-specific speed multipliers (relative to base speeds)
    WEATHER_SPEED_MULT = {
        WeatherMode.MATRIX: 1.0,
        WeatherMode.RAIN: 1.2,   # Rain falls fast
        WeatherMode.SNOW: 0.4,   # Base snow speed (modified per-depth below)
        WeatherMode.SAND: 0.15,  # Sand falls very slowly (blows horizontally instead)
        WeatherMode.CALM: 0.0,   # No particles falling
    }

    # Snow-specific speeds: big flakes fall FASTER than small ones (opposite of rain)
    # Slowed down for more gentle snowfall
    SNOW_DEPTH_SPEEDS = [
        0.15,  # Layer 0: Small flakes - slowest
        0.2,   # Layer 1: Small-medium
        0.3,   # Layer 2: Medium
        0.45,  # Layer 3: Big - faster
        0.6,   # Layer 4: Biggest - fastest
    ]

    # Weather-specific length multipliers (sand/snow = short particles)
    WEATHER_LENGTHS = {
        WeatherMode.MATRIX: None,  # Use default DEPTH_LENGTHS
        WeatherMode.RAIN: None,    # Use default DEPTH_LENGTHS
        WeatherMode.SNOW: [(1, 1), (1, 1), (1, 2), (1, 2), (1, 2)],  # Single flakes
        WeatherMode.SAND: [(1, 1), (1, 1), (1, 1), (1, 2), (1, 2)],  # Tiny grains
        WeatherMode.CALM: [(0, 0), (0, 0), (0, 0), (0, 0), (0, 0)],  # No particles
    }

    # Weather-specific horizontal movement
    WEATHER_HORIZONTAL = {
        WeatherMode.MATRIX: (0, 0),       # No horizontal movement
        WeatherMode.RAIN: (-0.1, 0.1),    # Slight wind variation
        WeatherMode.SNOW: (-0.4, 0.4),    # Gentle drift both ways
        WeatherMode.SAND: (1.5, 3.0),     # Strong wind blowing right
        WeatherMode.CALM: (0, 0),         # No particles to move
    }

    # Weather-specific color mappings (bright, dim, fade1, fade2)
    WEATHER_COLORS = {
        WeatherMode.MATRIX: (Colors.MATRIX_BRIGHT, Colors.MATRIX_DIM, Colors.MATRIX_FADE1, Colors.MATRIX_FADE2),
        WeatherMode.RAIN: (Colors.RAIN_BRIGHT, Colors.RAIN_DIM, Colors.RAIN_FADE1, Colors.RAIN_FADE2),
        WeatherMode.SNOW: (Colors.SNOW_BRIGHT, Colors.SNOW_DIM, Colors.SNOW_FADE, Colors.SNOW_FADE),
        WeatherMode.SAND: (Colors.SAND_BRIGHT, Colors.SAND_DIM, Colors.SAND_FADE, Colors.SAND_FADE),
        WeatherMode.CALM: (Colors.MATRIX_DIM, Colors.MATRIX_FADE1, Colors.MATRIX_FADE2, Colors.MATRIX_FADE3),
    }

    # 5 depth layers - each with different character sets (simple=far, complex=near)
    # Layer 0: Farthest - tiny fast raindrops falling from sky
    # Layer 4: Nearest - big slow drops sliding down window
    DEPTH_CHARS = WEATHER_CHARS[WeatherMode.MATRIX]  # Default to Matrix

    # Speed ranges - REVERSED: tiny rain (layer 0) is FASTEST like falling from sky
    # Big drops (layer 4) are SLOWEST like sliding down a window
    DEPTH_SPEEDS = [
        (3.5, 5.0),   # Layer 0: FASTEST - tiny rain falling from sky
        (2.0, 3.0),   # Layer 1: Fast
        (1.0, 1.5),   # Layer 2: Medium
        (0.5, 0.8),   # Layer 3: Slow
        (0.2, 0.4),   # Layer 4: SLOWEST - sliding down window
    ]

    # Tail lengths for each depth (tiny rain = very short, big drops = long trails)
    DEPTH_LENGTHS = [
        (1, 3),    # Layer 0: Very short drops - single chars and short streaks
        (2, 6),    # Layer 1: Short
        (6, 12),   # Layer 2: Medium
        (12, 20),  # Layer 3: Long
        (18, 30),  # Layer 4: Very long trails
    ]

    # Distribution - massive tiny rain!
    # Layer 0: 3x more, Layer 1: 2x more, Layers 2-4: unchanged
    # Calculated: [0.60*3, 0.15*2, 0.12, 0.08, 0.05] = [1.80, 0.30, 0.12, 0.08, 0.05]
    # Normalized to sum to 1.0
    DEPTH_WEIGHTS = [0.766, 0.128, 0.051, 0.034, 0.021]

    # Splat characters for when tiny rain hits
    SPLAT_CHARS = ['+', '*', '×', '·']

    def __init__(self, width: int, height: int, weather_mode: WeatherMode = WeatherMode.MATRIX):
        self.width = width
        self.height = height
        self.weather_mode = weather_mode
        self.drops: List[Dict] = []
        self.splats: List[Dict] = []  # Splat effects when tiny rain hits
        # Increased by 2.35x to maintain absolute counts for layers 2-4
        self._target_drops = max(28, width * 7 // 10)
        self._init_drops()

        # Flicker state
        self._frame_count = 0
        self._global_flicker = 0.0  # 0-1 intensity of global flicker
        self._intermittent_flicker = False  # Major flicker event active

        # Snow-specific state: stuck snowflakes that fade over time
        self._stuck_snow: List[Dict] = []
        # Roof/sill snow - lasts 10x longer and doesn't count towards max
        self._roof_sill_snow: List[Dict] = []
        # Snow filter callback - returns True if position is valid for snow collection
        self._snow_filter: Optional[callable] = None
        # Roof/sill checker callback - returns True if position is on roof or window sill
        self._roof_sill_checker: Optional[callable] = None

        # Snow wind gusts - temporary bursts of sideways movement
        self._snow_gusts: List[Dict] = []
        if weather_mode == WeatherMode.SNOW:
            self._init_snow_gusts()

        # Sand-specific state: vertical gust columns
        self._sand_gusts: List[Dict] = []
        if weather_mode == WeatherMode.SAND:
            self._init_sand_gusts()

    def set_weather_mode(self, mode: WeatherMode):
        """Change the weather mode and reinitialize particles."""
        if mode != self.weather_mode:
            self.weather_mode = mode
            self.drops = []
            self.splats = []
            self._stuck_snow = []
            self._roof_sill_snow = []
            self._snow_gusts = []
            self._sand_gusts = []
            self._init_drops()
            if mode == WeatherMode.SNOW:
                self._init_snow_gusts()
            if mode == WeatherMode.SAND:
                self._init_sand_gusts()

    def set_snow_filter(self, filter_func: callable):
        """Set a callback function that checks if a position is valid for snow collection.

        The function should accept (x, y) and return True if snow can collect there.
        """
        self._snow_filter = filter_func

    def set_roof_sill_checker(self, checker_func: callable):
        """Set a callback function that checks if a position is on roof or window sill.

        Snow on these positions lasts 10x longer and doesn't count towards max.
        """
        self._roof_sill_checker = checker_func

    def set_glow_positions(self, positions: List[Tuple[int, int]]):
        """Set street light glow center positions for snow melting.

        Snow near these positions will melt faster.
        """
        self._glow_positions = positions

    def set_quick_melt_zones(self, sidewalk_y: int, mailbox_bounds: Tuple[int, int, int, int], street_y: int,
                              traffic_light_bounds: Tuple[int, int, int, int] = None,
                              cafe_bounds: Tuple[int, int, int, int, int] = None):
        """Set zones where snow melts very quickly (sidewalk, mailbox, traffic lines, traffic light, cafe).

        Args:
            sidewalk_y: Y coordinate of the sidewalk/curb
            mailbox_bounds: (x, y, width, height) of the mailbox
            street_y: Y coordinate of the street (for traffic lines)
            traffic_light_bounds: (x, y, width, height) of the traffic light
            cafe_bounds: (x, y, width, height, shell_roof_height) of the cafe - snow melts on building but not shell roof
        """
        self._quick_melt_sidewalk_y = sidewalk_y
        self._quick_melt_mailbox = mailbox_bounds
        self._quick_melt_street_y = street_y
        self._quick_melt_traffic_light = traffic_light_bounds
        self._quick_melt_cafe = cafe_bounds

    def _is_in_quick_melt_zone(self, x: int, y: int) -> bool:
        """Check if a position is in a quick-melt zone (sidewalk, mailbox, traffic light, traffic line)."""
        # Sidewalk
        if hasattr(self, '_quick_melt_sidewalk_y') and y == self._quick_melt_sidewalk_y:
            return True
        # Street/traffic lines
        if hasattr(self, '_quick_melt_street_y') and y == self._quick_melt_street_y:
            return True
        # Mailbox
        if hasattr(self, '_quick_melt_mailbox') and self._quick_melt_mailbox:
            mx, my, mw, mh = self._quick_melt_mailbox
            if mx <= x < mx + mw and my <= y < my + mh:
                return True
        # Traffic light
        if hasattr(self, '_quick_melt_traffic_light') and self._quick_melt_traffic_light:
            tx, ty, tw, th = self._quick_melt_traffic_light
            if tx <= x < tx + tw and ty <= y < ty + th:
                return True
        # Cafe (excluding shell roof which can accumulate snow)
        if hasattr(self, '_quick_melt_cafe') and self._quick_melt_cafe:
            cx, cy, cw, ch, shell_h = self._quick_melt_cafe
            # Only melt snow below the shell roof (shell_h rows from top)
            cafe_body_y = cy + shell_h
            if cx <= x < cx + cw and cafe_body_y <= y < cy + ch:
                return True
        return False

    def _is_in_glow_zone(self, x: int, y: int) -> bool:
        """Check if a position is within a street light glow cone."""
        if not hasattr(self, '_glow_positions') or not self._glow_positions:
            return False
        for light_x, light_y in self._glow_positions:
            # Glow cone: 4 rows below light, widening
            for row in range(5):
                spread = row + 1
                glow_y = light_y + 1 + row
                if y == glow_y and abs(x - light_x) <= spread:
                    return True
        return False

    def cycle_weather(self) -> WeatherMode:
        """Cycle to the next weather mode and return the new mode."""
        modes = list(WeatherMode)
        current_idx = modes.index(self.weather_mode)
        next_idx = (current_idx + 1) % len(modes)
        new_mode = modes[next_idx]
        self.set_weather_mode(new_mode)
        return new_mode

    def _init_sand_gusts(self):
        """Initialize vertical columns of faster-moving sand gusts."""
        self._sand_gusts = []
        # Create 3-6 gust columns across the screen
        num_gusts = random.randint(3, 6)
        for _ in range(num_gusts):
            self._sand_gusts.append({
                'x': random.randint(0, self.width - 1),
                'width': random.randint(2, 5),  # Gust column width
                'speed_mult': random.uniform(2.0, 4.0),  # How much faster than normal
                'life': random.randint(30, 80),  # Frames until gust moves/fades
                'opacity': random.uniform(0.7, 1.0),
            })

    def _init_snow_gusts(self):
        """Initialize wind gusts that push snow sideways."""
        self._snow_gusts = []
        # Start with 2-4 active gusts
        num_gusts = random.randint(2, 4)
        for _ in range(num_gusts):
            self._snow_gusts.append({
                'direction': random.choice([-1, 1]),  # -1 = left, 1 = right
                'strength': random.uniform(0.5, 2.0),  # How strong the push
                'y_start': random.randint(0, self.height - 1),
                'y_height': random.randint(5, 15),  # Vertical band height
                'life': random.randint(20, 60),  # Frames until gust fades
            })

    def _get_weather_chars(self) -> List[str]:
        """Get character sets for current weather mode."""
        return self.WEATHER_CHARS.get(self.weather_mode, self.WEATHER_CHARS[WeatherMode.MATRIX])

    def _get_speed_multiplier(self) -> float:
        """Get speed multiplier for current weather mode."""
        return self.WEATHER_SPEED_MULT.get(self.weather_mode, 1.0)

    def _get_weather_colors(self) -> tuple:
        """Get color tuple (bright, dim, fade1, fade2) for current weather mode."""
        return self.WEATHER_COLORS.get(self.weather_mode, self.WEATHER_COLORS[WeatherMode.MATRIX])

    def _init_drops(self):
        """Initialize rain drops at random positions across all depth layers."""
        self.drops = []
        for _ in range(self._target_drops):
            self._add_drop()

    def _add_drop(self, depth: Optional[int] = None):
        """Add a new rain drop at a random or specified depth layer."""
        if self.width <= 0:
            return

        # Choose depth layer based on weights if not specified
        if depth is None:
            depth = random.choices(range(5), weights=self.DEPTH_WEIGHTS)[0]

        speed_min, speed_max = self.DEPTH_SPEEDS[depth]

        # Get weather-specific lengths or use defaults
        weather_lengths = self.WEATHER_LENGTHS.get(self.weather_mode)
        if weather_lengths:
            len_min, len_max = weather_lengths[depth]
        else:
            len_min, len_max = self.DEPTH_LENGTHS[depth]

        # Apply weather-specific speed multiplier
        speed_mult = self._get_speed_multiplier()

        # Snow uses inverted depth speeds (big flakes = faster)
        if self.weather_mode == WeatherMode.SNOW:
            speed_mult = self.SNOW_DEPTH_SPEEDS[depth]

        weather_chars = self._get_weather_chars()

        # Get weather-specific horizontal movement
        h_min, h_max = self.WEATHER_HORIZONTAL.get(self.weather_mode, (0, 0))
        dx = random.uniform(h_min, h_max) if h_min != h_max else 0.0

        # Determine spawn position
        if self.weather_mode == WeatherMode.SAND:
            # Sand spawns from left edge and blows across
            start_x = random.randint(-10, 0)
            start_y = random.randint(0, self.height - 1)
        else:
            # Normal: spawn across width, start below cloud layer (row 3+)
            start_x = random.randint(0, self.width - 1)
            start_y = random.randint(3, 5)  # Start below solid cloud cover (rows 1-2)

        # Ensure length range is valid (max >= min)
        effective_max_len = max(len_min, min(len_max, max(1, self.height // 2)))

        # Skip adding drops if no characters for this weather mode (e.g., CALM mode)
        chars = weather_chars[depth]
        if not chars:
            return

        self.drops.append({
            'x': start_x,
            'y': start_y,
            'speed': random.uniform(speed_min, speed_max) * speed_mult,
            'length': random.randint(len_min, effective_max_len),
            'char_offset': random.randint(0, len(chars) - 1),
            'depth': depth,
            'phase': float(start_y),
            'dx': dx,  # Horizontal movement
            'fx': float(start_x),  # Fractional x position for smooth movement
        })

    def _add_splat(self, x: int, y: int):
        """Add a splat effect at the given position."""
        if 0 <= x < self.width and self.height // 2 <= y < self.height:
            self.splats.append({
                'x': x,
                'y': y,
                'life': random.randint(3, 8),  # Frames to live
                'char': random.choice(self.SPLAT_CHARS),
            })

    def update(self):
        """Update rain drop positions and flicker state."""
        self._frame_count += 1

        # Update flicker states (less flicker for non-Matrix modes)
        if self.weather_mode == WeatherMode.MATRIX:
            # Rapid low-level flicker - subtle constant shimmer (sine wave oscillation)
            self._global_flicker = 0.15 + 0.1 * math.sin(self._frame_count * 0.3)
            # Intermittent major flicker - brief stutter every few seconds
            if random.random() < 0.003:
                self._intermittent_flicker = True
            elif self._intermittent_flicker and random.random() < 0.3:
                self._intermittent_flicker = False
        else:
            self._global_flicker = 0.0
            self._intermittent_flicker = False

        # Update sand gusts if in sand mode
        if self.weather_mode == WeatherMode.SAND:
            self._update_sand_gusts()

        # Update snow gusts and stuck snow
        if self.weather_mode == WeatherMode.SNOW:
            self._update_snow_gusts()
            self._update_stuck_snow()

        weather_chars = self._get_weather_chars()

        new_drops = []
        for drop in self.drops:
            # Check if sand particle is in a gust column (moves faster)
            speed_boost = 1.0
            if self.weather_mode == WeatherMode.SAND:
                for gust in self._sand_gusts:
                    if gust['x'] <= drop['x'] < gust['x'] + gust['width']:
                        speed_boost = gust['speed_mult']
                        break

            drop['phase'] += drop['speed'] * speed_boost
            drop['y'] = int(drop['phase'])

            # Apply snow wind gusts - push flakes sideways
            gust_dx = 0.0
            if self.weather_mode == WeatherMode.SNOW:
                for gust in self._snow_gusts:
                    if gust['y_start'] <= drop['y'] < gust['y_start'] + gust['y_height']:
                        # Bigger flakes get pushed more by wind
                        size_factor = 0.5 + (drop['depth'] * 0.3)
                        gust_dx = gust['direction'] * gust['strength'] * size_factor
                        break

            # Update horizontal position for snow/sand
            base_dx = drop.get('dx', 0)
            total_dx = base_dx + gust_dx
            if total_dx != 0:
                dx_boost = speed_boost if self.weather_mode == WeatherMode.SAND else 1.0
                drop['fx'] = drop.get('fx', float(drop['x'])) + total_dx * dx_boost
                new_x = int(drop['fx'])

                # Sand blows off right edge and is removed
                if self.weather_mode == WeatherMode.SAND:
                    if new_x >= self.width:
                        continue  # Remove sand that went off right edge
                    drop['x'] = new_x
                else:
                    # Other modes wrap around
                    drop['x'] = new_x % self.width

            # Roll through characters as the drop falls
            # Tiny rain (layer 0) rolls fastest for that streaking effect
            roll_speed = 5 - drop['depth']  # Layer 0 = 5, Layer 4 = 1
            chars = weather_chars[drop['depth']]
            # Skip char_offset update if no characters (e.g., CALM mode with existing drops)
            if chars:
                drop['char_offset'] = (drop['char_offset'] + roll_speed) % len(chars)

            # Snow sticking behavior
            if self.weather_mode == WeatherMode.SNOW:
                # Big flakes (depth 3-4) can stick anywhere
                if drop['depth'] >= 3 and drop['y'] >= 0:
                    # Random chance to stick based on how far down the screen
                    stick_chance = 0.002 + (drop['y'] / self.height) * 0.01
                    if random.random() < stick_chance:
                        self._add_stuck_snow(drop['x'], drop['y'], drop['depth'], chars[drop['char_offset'] % len(chars)])
                        continue  # Remove this drop, it's now stuck

                # Small flakes (depth 0-2) fall to bottom 1/5th then stick
                elif drop['depth'] <= 2:
                    bottom_zone = self.height - (self.height // 5)
                    if drop['y'] >= bottom_zone:
                        # High chance to stick in bottom zone
                        if random.random() < 0.05:
                            self._add_stuck_snow(drop['x'], drop['y'], drop['depth'], chars[drop['char_offset'] % len(chars)])
                            continue

            # Check if tiny rain (layer 0) hit the ground (mid-screen to bottom)
            # Only create splats for Matrix and Rain modes
            if drop['depth'] == 0 and drop['y'] >= self.height:
                if self.weather_mode in (WeatherMode.MATRIX, WeatherMode.RAIN):
                    if random.random() < 0.7:  # 70% chance of splat
                        self._add_splat(drop['x'], self.height - 1)
                continue  # Don't keep this drop

            # Keep drop if still on screen (vertically)
            if drop['y'] - drop['length'] < self.height:
                new_drops.append(drop)

        self.drops = new_drops

        # Update splats - decrease life and remove dead ones
        new_splats = []
        for splat in self.splats:
            splat['life'] -= 1
            if splat['life'] > 0:
                new_splats.append(splat)
        self.splats = new_splats

        # Add new drops to maintain density (skip for CALM mode which has no particles)
        if self.weather_mode != WeatherMode.CALM:
            while len(self.drops) < self._target_drops:
                self._add_drop()

    def _add_stuck_snow(self, x: int, y: int, depth: int, char: str):
        """Add a snowflake that has stuck to the screen."""
        # Check if position is valid for snow collection
        if self._snow_filter and not self._snow_filter(x, y):
            return  # Position is not valid for snow collection

        # Check if this is roof/sill snow (lasts 10x longer, no max count)
        is_roof_sill = self._roof_sill_checker and self._roof_sill_checker(x, y)

        if is_roof_sill:
            # Roof/sill snow: lasts 10x longer (1600-4800), no limit
            self._roof_sill_snow.append({
                'x': x,
                'y': y,
                'depth': depth,
                'char': char,
                'life': random.randint(1600, 4800),  # 10x longer melt time
                'max_life': 4800,
            })
        else:
            # Regular stuck snow: limit to 800
            if len(self._stuck_snow) < 800:
                self._stuck_snow.append({
                    'x': x,
                    'y': y,
                    'depth': depth,
                    'char': char,
                    'life': random.randint(160, 480),
                    'max_life': 480,
                })

    def _update_stuck_snow(self):
        """Update stuck snow - slowly fade/melt away."""
        # Update regular stuck snow
        new_stuck = []
        for snow in self._stuck_snow:
            # Snow in quick-melt zones (sidewalk, mailbox, traffic lines) melts very fast
            if self._is_in_quick_melt_zone(snow['x'], snow['y']):
                snow['life'] -= 25  # Very fast melt
            # Snow in glow zones melts 10x faster (warmth from lights)
            elif self._is_in_glow_zone(snow['x'], snow['y']):
                snow['life'] -= 10
            else:
                snow['life'] -= 1
            if snow['life'] > 0:
                new_stuck.append(snow)
        self._stuck_snow = new_stuck

        # Update roof/sill snow (separate list)
        new_roof_sill = []
        for snow in self._roof_sill_snow:
            # Quick-melt zones
            if self._is_in_quick_melt_zone(snow['x'], snow['y']):
                snow['life'] -= 25
            # Roof/sill snow also melts faster in glow zones
            elif self._is_in_glow_zone(snow['x'], snow['y']):
                snow['life'] -= 10
            else:
                snow['life'] -= 1
            if snow['life'] > 0:
                new_roof_sill.append(snow)
        self._roof_sill_snow = new_roof_sill

    def _update_sand_gusts(self):
        """Update sand gust columns - they shift position over time."""
        for gust in self._sand_gusts:
            gust['life'] -= 1
            if gust['life'] <= 0:
                # Reset gust to new position
                gust['x'] = random.randint(0, self.width - 1)
                gust['width'] = random.randint(2, 5)
                gust['speed_mult'] = random.uniform(2.0, 4.0)
                gust['life'] = random.randint(30, 80)
                gust['opacity'] = random.uniform(0.7, 1.0)

    def _update_snow_gusts(self):
        """Update snow wind gusts - they fade and new ones appear."""
        new_gusts = []
        for gust in self._snow_gusts:
            gust['life'] -= 1
            if gust['life'] > 0:
                new_gusts.append(gust)

        self._snow_gusts = new_gusts

        # Randomly spawn new gusts
        if random.random() < 0.05 and len(self._snow_gusts) < 5:
            self._snow_gusts.append({
                'direction': random.choice([-1, 1]),
                'strength': random.uniform(0.5, 2.0),
                'y_start': random.randint(0, self.height - 1),
                'y_height': random.randint(5, 15),
                'life': random.randint(20, 60),
            })

    def resize(self, width: int, height: int):
        """Handle terminal resize."""
        old_width = self.width
        old_height = self.height
        self.width = width
        self.height = height
        self._target_drops = max(28, width * 7 // 10)  # Massive rain density

        # Remove drops and splats that are now out of bounds
        self.drops = [d for d in self.drops if d['x'] < width]
        self.splats = [s for s in self.splats if s['x'] < width and s['y'] < height]

        # Remove stuck snow that is now out of bounds
        self._stuck_snow = [s for s in self._stuck_snow if s['x'] < width and s['y'] < height]

        # Reinitialize sand gusts for new width
        if self.weather_mode == WeatherMode.SAND:
            if abs(width - old_width) > 10:
                self._init_sand_gusts()
            else:
                for gust in self._sand_gusts:
                    if gust['x'] >= width:
                        gust['x'] = random.randint(0, width - 1)

        # Add more drops if window got bigger
        if width > old_width:
            for _ in range(max(1, (width - old_width) * 7 // 10)):
                self._add_drop()

    def render(self, screen):
        """Render rain drops with depth-based visual effects and flicker."""
        weather_chars = self._get_weather_chars()
        colors = self._get_weather_colors()

        # Sort drops by depth so farther ones render first (get overwritten by nearer)
        sorted_drops = sorted(self.drops, key=lambda d: d['depth'])

        for drop in sorted_drops:
            depth = drop['depth']
            chars = weather_chars[depth]

            # Skip rendering if no characters for this weather mode (e.g., CALM mode)
            if not chars:
                continue

            # During intermittent flicker, skip rendering some drops randomly
            if self._intermittent_flicker and random.random() < 0.4:
                continue

            for i in range(drop['length']):
                y = drop['y'] - i
                if 0 <= y < self.height and 0 <= drop['x'] < self.width:
                    # Rapid low-level flicker - randomly skip some chars
                    if random.random() < self._global_flicker * 0.3:
                        continue

                    # Character rolls through the charset as it falls
                    char_idx = (drop['char_offset'] + i * 2) % len(chars)
                    char = chars[char_idx]

                    # More character mutation flicker for nearer drops (Matrix mode only)
                    if self.weather_mode == WeatherMode.MATRIX:
                        if random.random() < 0.02 * (depth + 1):
                            char = random.choice(chars)
                        # Rapid flicker can also swap characters briefly
                        if random.random() < self._global_flicker * 0.15:
                            char = random.choice(chars)

                    try:
                        self._render_char(screen, y, drop['x'], char, i, depth)
                    except curses.error:
                        pass

        # Render splats (tiny rain impact effects) - only for Matrix and Rain modes
        if self.weather_mode in (WeatherMode.MATRIX, WeatherMode.RAIN):
            bright, dim, fade1, fade2 = colors
            for splat in self.splats:
                try:
                    # Splats fade based on remaining life
                    if splat['life'] > 5:
                        attr = curses.color_pair(bright) | curses.A_BOLD
                    elif splat['life'] > 2:
                        attr = curses.color_pair(dim)
                    else:
                        attr = curses.color_pair(fade1) | curses.A_DIM

                    screen.attron(attr)
                    screen.addstr(splat['y'], splat['x'], splat['char'])
                    screen.attroff(attr)
                except curses.error:
                    pass

        # Render stuck snow (melting snowflakes)
        if self.weather_mode == WeatherMode.SNOW:
            # Render regular stuck snow
            for snow in self._stuck_snow:
                try:
                    if 0 <= snow['x'] < self.width - 1 and 0 <= snow['y'] < self.height:
                        # Fade based on remaining life (melting effect)
                        life_ratio = snow['life'] / snow['max_life']
                        if life_ratio > 0.6:
                            attr = curses.color_pair(Colors.SNOW_BRIGHT) | curses.A_BOLD
                        elif life_ratio > 0.3:
                            attr = curses.color_pair(Colors.SNOW_DIM)
                        else:
                            attr = curses.color_pair(Colors.SNOW_FADE) | curses.A_DIM

                        screen.attron(attr)
                        screen.addstr(snow['y'], snow['x'], snow['char'])
                        screen.attroff(attr)
                except curses.error:
                    pass

            # Render roof/sill snow (lasts longer)
            for snow in self._roof_sill_snow:
                try:
                    if 0 <= snow['x'] < self.width - 1 and 0 <= snow['y'] < self.height:
                        # Fade based on remaining life (melting effect)
                        life_ratio = snow['life'] / snow['max_life']
                        if life_ratio > 0.6:
                            attr = curses.color_pair(Colors.SNOW_BRIGHT) | curses.A_BOLD
                        elif life_ratio > 0.3:
                            attr = curses.color_pair(Colors.SNOW_DIM)
                        else:
                            attr = curses.color_pair(Colors.SNOW_FADE) | curses.A_DIM

                        screen.attron(attr)
                        screen.addstr(snow['y'], snow['x'], snow['char'])
                        screen.attroff(attr)
                except curses.error:
                    pass

    def _render_char(self, screen, y: int, x: int, char: str, pos: int, depth: int):
        """Render a single character with depth-appropriate styling."""
        # Depth 0 = farthest/dimmest, Depth 4 = nearest/brightest
        # Get weather-appropriate colors
        bright, dim, fade1, fade2 = self._get_weather_colors()

        # Use dark green for Matrix rain tails
        is_matrix = self.weather_mode == WeatherMode.MATRIX
        dark_tail = Colors.MATRIX_DARK if is_matrix else fade2

        if depth == 0:
            # Farthest layer - very dim, no head highlight
            if pos < 2:
                attr = curses.color_pair(dark_tail) | curses.A_DIM
            else:
                # Use dark green for Matrix tails, fade2 for others
                if is_matrix:
                    attr = curses.color_pair(Colors.MATRIX_DARK) | curses.A_DIM
                else:
                    attr = curses.color_pair(fade2) | curses.A_DIM
        elif depth == 1:
            # Far layer - dim
            if pos == 0:
                attr = curses.color_pair(fade1)
            elif pos < 3:
                attr = curses.color_pair(fade1) | curses.A_DIM
            else:
                attr = curses.color_pair(dark_tail) | curses.A_DIM
        elif depth == 2:
            # Middle layer - normal
            if pos == 0:
                attr = curses.color_pair(dim) | curses.A_BOLD
            elif pos < 3:
                attr = curses.color_pair(dim)
            elif pos < 6:
                attr = curses.color_pair(fade1) | curses.A_DIM
            else:
                attr = curses.color_pair(dark_tail) | curses.A_DIM
        elif depth == 3:
            # Near layer - bright
            if pos == 0:
                attr = curses.color_pair(bright) | curses.A_BOLD
            elif pos == 1:
                attr = curses.color_pair(dim) | curses.A_BOLD
            elif pos < 5:
                attr = curses.color_pair(dim)
            elif pos < 9:
                attr = curses.color_pair(fade1)
            else:
                attr = curses.color_pair(dark_tail) | curses.A_DIM
        else:  # depth == 4
            # Nearest layer - brightest, boldest
            if pos == 0:
                attr = curses.color_pair(bright) | curses.A_BOLD
            elif pos == 1:
                attr = curses.color_pair(bright)
            elif pos < 4:
                attr = curses.color_pair(dim) | curses.A_BOLD
            elif pos < 8:
                attr = curses.color_pair(dim)
            elif pos < 12:
                attr = curses.color_pair(fade1)
            else:
                attr = curses.color_pair(dark_tail)

        screen.attron(attr)
        screen.addstr(y, x, char)
        screen.attroff(attr)


class TunnelBackdrop:
    """
    Organic 3D tunnel effect for the sky backdrop - creates flowing, turbulent depth illusion.

    Uses layered noise functions to create organic, swirling patterns that flow toward
    a vanishing point, creating the illusion of flying through a cosmic tunnel/vortex.
    Characters range from sparse (.) to dense (@) based on computed depth values.

    Implements frame caching for performance - precomputes animation frames and cycles
    through them instead of computing every pixel every frame.
    """

    # Density character gradient from sparse to dense (organic ASCII tunnel style)
    DENSITY_CHARS = ' .,:;i1tfLCG0@#'

    # Weather-specific character sets (sparse to dense)
    WEATHER_CHARS = {
        WeatherMode.MATRIX: ' .,:;i1tfLCG0@#',
        WeatherMode.RAIN: ' .,~:;|/\\1tfL░▒▓',
        WeatherMode.SNOW: ' ·.,:*+o0O@#█',
        WeatherMode.SAND: ' .,:;~°^"oO0@',
        WeatherMode.CALM: ' .,:;=+*#@',
    }

    # Weather-specific color palettes (4 levels: far, mid, near, bright)
    WEATHER_COLORS = {
        WeatherMode.MATRIX: [Colors.TUNNEL_FAR, Colors.TUNNEL_MID, Colors.TUNNEL_NEAR, Colors.MATRIX_DIM],
        WeatherMode.RAIN: [Colors.RAIN_FADE2, Colors.RAIN_FADE1, Colors.RAIN_DIM, Colors.RAIN_BRIGHT],
        WeatherMode.SNOW: [Colors.SNOW_FADE, Colors.SNOW_DIM, Colors.SNOW_BRIGHT, Colors.SNOW_BRIGHT],
        WeatherMode.SAND: [Colors.SAND_FADE, Colors.SAND_DIM, Colors.SAND_BRIGHT, Colors.SAND_BRIGHT],
        WeatherMode.CALM: [Colors.TUNNEL_FAR, Colors.TUNNEL_MID, Colors.ALLEY_MID, Colors.ALLEY_LIGHT],
    }

    # Number of cached frames for animation loop (more = smoother)
    CACHE_FRAMES = 180

    def __init__(self, width: int, height: int, weather_mode: WeatherMode = WeatherMode.MATRIX):
        self.width = width
        self.height = height
        self.weather_mode = weather_mode
        self._enabled = True

        # Animation state
        self._frame_idx = 0
        self._speed = 1  # Single frame steps for smooth animation

        # Tunnel center (vanishing point)
        self._center_x = width // 2
        self._center_y = height // 3  # Higher up for taller effect

        # Precompute sine table for fast lookup
        self._sin_table = []
        import math
        for i in range(360):
            self._sin_table.append(math.sin(i * math.pi / 180))

        # Frame cache - list of frames, each frame is list of (y, x, char, color, bold) tuples
        self._frame_cache = []
        self._cache_valid = False
        self._cached_weather = weather_mode
        self._cached_width = width
        self._cached_height = height

    def _fast_sin(self, angle: float) -> float:
        """Fast sine lookup using precomputed table."""
        idx = int(angle * 57.2958) % 360
        return self._sin_table[idx]

    def _fast_cos(self, angle: float) -> float:
        """Fast cosine lookup using precomputed table."""
        idx = int((angle * 57.2958) + 90) % 360
        return self._sin_table[idx]

    def _noise(self, x: float, y: float, seed: float = 0) -> float:
        """Simple coherent noise function for organic patterns."""
        n = 0.0
        n += self._fast_sin(x * 0.1 + seed) * self._fast_cos(y * 0.15 + seed * 0.7)
        n += self._fast_sin(x * 0.23 + y * 0.17 + seed * 1.3) * 0.5
        n += self._fast_cos(x * 0.31 - y * 0.29 + seed * 0.9) * 0.25
        n += self._fast_sin((x + y) * 0.19 + seed * 2.1) * 0.125
        return n

    def _turbulence(self, x: float, y: float, t: float) -> float:
        """Create turbulent, organic flow patterns."""
        turb = 0.0
        turb += self._noise(x * 0.05 + t * 0.3, y * 0.08 + t * 0.2, t) * 0.5
        turb += self._noise(x * 0.12 + t * 0.5, y * 0.15 - t * 0.3, t * 1.7) * 0.3
        turb += self._noise(x * 0.25 - t * 0.4, y * 0.3 + t * 0.6, t * 2.3) * 0.2
        return turb

    def _build_cache(self):
        """Precompute all animation frames for the current size and weather."""
        import math

        self._frame_cache = []
        sky_height = self.height * 2 // 3  # Twice as tall

        chars = self.WEATHER_CHARS.get(self.weather_mode, self.DENSITY_CHARS)
        colors = self.WEATHER_COLORS.get(self.weather_mode,
                                         [Colors.TUNNEL_FAR, Colors.TUNNEL_MID,
                                          Colors.TUNNEL_NEAR, Colors.TUNNEL_BRIGHT])
        char_count = len(chars) - 1

        # Generate each frame
        for frame in range(self.CACHE_FRAMES):
            t = frame * 0.05  # Smaller time steps = smoother transitions
            frame_data = []

            for y in range(1, sky_height):
                for x in range(0, self.width - 1):
                    dx = x - self._center_x
                    dy = (y - self._center_y) * 2.0

                    dist = math.sqrt(dx * dx + dy * dy)
                    if dist < 1:
                        dist = 1

                    angle = math.atan2(dy, dx)
                    tunnel_depth = 50.0 / (dist + 5)
                    swirl = angle + t * 0.5 + tunnel_depth * 0.3

                    turb = self._turbulence(x + swirl * 3, y + t * 2, t)
                    density = tunnel_depth * 0.4 + turb * 0.4

                    wave = self._fast_sin(dist * 0.15 - t * 2) * 0.3
                    density += wave

                    spiral = self._fast_sin(angle * 3 + dist * 0.1 - t * 1.5) * 0.2
                    density += spiral

                    density = (density + 1) * 0.5
                    density = max(0, min(1, density))

                    char_idx = int(density * char_count)
                    char = chars[char_idx]

                    if char == ' ':
                        continue

                    color_idx = min(3, int(tunnel_depth * 0.8))
                    color = colors[color_idx]

                    # Store brightness level: 0=dim, 1=normal, 2=bold
                    if density > 0.7:
                        brightness = 2
                    elif density < 0.3:
                        brightness = 0
                    else:
                        brightness = 1

                    frame_data.append((y, x, char, color, brightness))

            self._frame_cache.append(frame_data)

        self._cache_valid = True
        self._cached_weather = self.weather_mode
        self._cached_width = self.width
        self._cached_height = self.height

    def set_weather_mode(self, mode: WeatherMode):
        """Change the weather mode."""
        if mode != self.weather_mode:
            self.weather_mode = mode
            self._cache_valid = False  # Invalidate cache

    def set_enabled(self, enabled: bool):
        """Enable or disable the tunnel effect."""
        self._enabled = enabled

    def resize(self, width: int, height: int):
        """Handle terminal resize."""
        if width != self.width or height != self.height:
            self.width = width
            self.height = height
            self._center_x = width // 2
            self._center_y = height // 3
            self._cache_valid = False  # Invalidate cache

    def update(self):
        """Update animation state."""
        if not self._enabled:
            return
        self._frame_idx = (self._frame_idx + self._speed) % self.CACHE_FRAMES

    def render(self, screen, sky_height: int = None):
        """
        Render the organic tunnel backdrop effect using cached frames.

        Args:
            screen: Curses screen object
            sky_height: Ignored - uses cached height (2/3 of screen)
        """
        if not self._enabled:
            return

        # Rebuild cache if needed
        if not self._cache_valid or self._cached_weather != self.weather_mode:
            self._build_cache()

        # Get current frame
        if not self._frame_cache:
            return

        frame_data = self._frame_cache[int(self._frame_idx)]

        # Render all pixels from cached frame
        for y, x, char, color, brightness in frame_data:
            if y >= self.height or x >= self.width - 1:
                continue

            try:
                attr = curses.color_pair(color)
                if brightness == 2:
                    attr |= curses.A_BOLD
                elif brightness == 0:
                    attr |= curses.A_DIM

                screen.attron(attr)
                screen.addstr(y, x, char)
                screen.attroff(attr)
            except curses.error:
                pass


class AlleyScene:
    """
    Simple alley scene with dumpster, box, traffic light, buildings, cars, and pedestrians.
    """

    # Dumpster ASCII art (7 wide x 5 tall)
    DUMPSTER = [
        " _____ ",
        "|#####|",
        "|#####|",
        "|#####|",
        "|=====|",
    ]

    # Cardboard box ASCII art (5 wide x 4 tall) - solid blocks, no outline
    BOX = [
        "▓▓▓▓▓",
        "▓▓▓▓▓",
        "▓▒X▒▓",
        "▓▓▓▓▓",
    ]

    # Blue street mailbox (6 wide x 5 tall)
    MAILBOX = [
        " ____ ",
        "|====|",
        "|MAIL|",
        "|____|",
        "  ||  ",
    ]

    # Mailbox with slot open (when person is mailing letter)
    MAILBOX_OPEN = [
        " ____ ",
        "|=██=|",
        "|MAIL|",
        "|____|",
        "  ||  ",
    ]

    # Person mailing letter (facing right, arm extended)
    PERSON_MAILING = [
        "  O_",
        " /|─",
        " /\\",
    ]

    # Cafe storefront (well-lit, between buildings) - taller size
    # Turtle shell logo for Shell Cafe (hexagonal pattern)
    BIG_SHELL_LOGO = [
        "                    ",
        "     ____________    ",
        "   / \\ __|__ /   \    ",
        "  |   \\/   \\/ /  \   ",
        "  |   /\\___/\\ \   |  ",
        "   \\ /  | |  \\ \/   ",
        "    \\___|_|___/ /     ",
    ]

    # Turtle head animation frames (peeks out from shell) - each frame is [head, neck]
    TURTLE_HEAD_FRAMES = [
        ["  @__@  ", "   ||   "],   # Normal eyes with neck
        ["  @~~@  ", "   ||   "],   # Blink with neck
        ["  @_~@  ", "   ||   "],   # Right wink with neck
        ["  ^__^  ", "   ||   "],   # Happy with neck
    ]

    CAFE = [
        "      ___________      ",
        "    /`    |    `\\     ",
        "   / \\ __|__ / \\ \\    ",
        "  |   \\/   \\/   \\|    ",
        "  |   /\\___/\\   /|    ",
        "   \\ /  | |  \\ / /    ",
        "    \\___|_|___\\/      ",
        "   ___________________________   ",
        "  |     S H E L L  C A F E   |  ",
        "  |                          |  ",
        "  |  [====]    O     [====]  |  ",
        "  |  [    ]   /|\\    [    ]  |  ",
        "  |  [    ]  [===]   [    ]  |  ",
        "  |  [====]          [====]  |  ",
        "  |                          |  ",
        "  |  [====]          [====]  |  ",
        "  |  [    ]          [    ]  |  ",
        "  |  [    ]          [    ]  |  ",
        "  |  [====]          [====]  |  ",
        "  |                          |  ",
        "  |[=======================]|  ",
        "  |[                  OPEN ]|  ",
        "  |[__________________     ]|  ",
        "  |__________[  ]__________|  ",
    ]

    # Traffic light showing two sides (corner view) - compact head, tall pole
    # Left column is N/S direction (flat), right column is E/W direction (brackets)
    # All 6 lights shown as circles, off lights are gray
    TRAFFIC_LIGHT_TEMPLATE = [
        " .===. ",
        " (L(R) ",  # Red lights - right side has brackets
        " (L(R) ",  # Yellow lights
        " (L(R) ",  # Green lights
        " '===' ",
        "   ||  ",
        "   ||  ",
        "   ||  ",
        "   ||  ",
        "   ||  ",
        "   ||  ",
        "   ||  ",
    ]

    # Car sprites - classic ASCII art style (4 rows tall) with filled body panels
    # Body panels use █ (solid block) to be colored, structure uses regular chars
    # Design inspired by classic ASCII art archives
    CAR_RIGHT = [
        "      ______          ",
        "   __/__||__\\`._      ",
        " (           \\     ",
        "  =`-(_)--(_)-'      ",
    ]
    CAR_LEFT = [
        "       ______         ",
        "     _.'__||__\\__    ",
        "    /              )   ",
        "     `-'(_)--(_)-=   ",
    ]

    # Taxi car sprites (yellow with TAXI sign on roof)
    TAXI_RIGHT = [
        "      _TAXI_          ",
        "   __/__||__\\`._      ",
        "  (  ███  ███  \\     ",
        "  =`-(_)--(_)-'      ",
    ]
    TAXI_LEFT = [
        "       _TAXI_         ",
        "     _.'__||__\\__    ",
        "    /  ███  ███   )   ",
        "     `-'(_)--(_)-=   ",
    ]

    # 4 car body colors
    CAR_BODY_COLORS = [
        Colors.SHADOW_RED,      # Red car
        Colors.ALLEY_BLUE,      # Blue car
        Colors.MATRIX_DIM,      # Green car
        Colors.GREY_BLOCK,      # Grey car
    ]

    # Truck sprites - delivery truck/van style (4 rows)
    TRUCK_RIGHT = [
        "    .----------.__    ",
        "    |██████████|[_|__ ",
        "    |██_.--.__██.-~;| ",
        "    `(_)------(_)-'   ",
    ]
    TRUCK_LEFT = [
        "    __.----------.    ",
        " __|_]|██████████|    ",
        " |;~-.██__.--._██|    ",
        "   `-(_)------(_)'    ",
    ]

    # Work truck with company logo area (template - text gets filled in)
    WORK_TRUCK_RIGHT = [
        "    .----------.__    ",
        "    |{logo:^10}|[_|__ ",
        "    |{line2:^10}.-~;| ",
        "    `(_)------(_)-'   ",
    ]
    WORK_TRUCK_LEFT = [
        "    __.----------.    ",
        " __|_]|{logo:^10}|    ",
        " |;~-.{line2:^10}|    ",
        "   `-(_)------(_)'    ",
    ]

    # 4 truck body colors
    TRUCK_BODY_COLORS = [
        Colors.SHADOW_RED,      # Red truck
        Colors.ALLEY_BLUE,      # Blue truck
        Colors.RAT_YELLOW,      # Yellow truck
        Colors.MATRIX_DIM,      # Green truck
    ]

    # Noire York City department trucks (white with city logo)
    CITY_TRUCK_DEPARTMENTS = [
        ("NOIRE YORK", "WATER DEPT"),
        ("NOIRE YORK", "SANITATION"),
        ("NOIRE YORK", "PARKS DEPT"),
        ("NOIRE YORK", "ELECTRIC"),
        ("NOIRE YORK", "GAS & UTIL"),
        ("NOIRE YORK", "TRANSIT"),
        ("NOIRE YORK", "FIRE DEPT"),
        ("NOIRE YORK", "POLICE"),
    ]

    # Prop plane sprites (small single-engine plane)
    PROP_PLANE_RIGHT = [
        "     __",
        " ---(_)=====>",
        "     ~~",
    ]
    PROP_PLANE_LEFT = [
        "        __     ",
        " <=====(_)--- ",
        "        ~~     ",
    ]

    # Banner attachment characters
    BANNER_ATTACH = "~~o"
    BANNER_END = "o~~"

    # Semi-truck base sprites - big 18-wheeler (5 rows tall, much wider)
    # Text area is 27 chars wide (rows 1-2 inside the trailer)
    SEMI_RIGHT_BASE = [
        "                 _____________________________  ",
        "        _______ |        {line1:^27}          | ",
        "   ____/   \\   |        {line2:^27}          | ",
        "  | °  |__|__|  |_____________________________|",
        "   (O)-----(O)------------------------(O)(O)--  ",
    ]
    SEMI_LEFT_BASE = [
        "  _____________________________                 ",
        " |         {line1:^27}         | _______        ",
        " |         {line2:^27}         |    /   \\____   ",
        " |_____________________________|  |__|__|  ° | ",
        "  --(O)(O)------------------------(O)-----(O)  ",
    ]

    # 50 unique trucking/advertising companies
    SEMI_COMPANIES = [
        # Logistics & Freight (10)
        "NEXUS FREIGHT", "TITAN LOGISTICS", "SWIFT HAUL", "IRONCLAD TRANSPORT",
        "VELOCITY CARGO", "APEX TRUCKING", "SUMMIT LOGISTICS", "TRAILBLAZER FREIGHT",
        "HORIZON CARRIERS", "REDLINE EXPRESS",
        # Tech & Computing (10)
        "CYBERLINK SYSTEMS", "QUANTUM DYNAMICS", "NEON CIRCUIT", "DATASTREAM INC",
        "PIXEL FORGE", "NEURAL NET CO", "BITWAVE TECH", "CLOUDPEAK SYSTEMS",
        "HEXCORE INDUSTRIES", "SYNTHWAVE LABS",
        # Food & Beverage (10)
        "MOUNTAIN BREW CO", "SUNRISE FARMS", "GOLDEN HARVEST", "ARCTIC FREEZE",
        "CRIMSON GRILL", "BLUE OCEAN FISH", "PRIME MEATS", "ORCHARD FRESH",
        "SUGAR RUSH CANDY", "MOONLIGHT DAIRY",
        # Industrial & Manufacturing (10)
        "STEEL DYNAMICS", "FORGE MASTERS", "CONCRETE KINGS", "LUMBER GIANT",
        "COPPER CREEK", "BOLT & IRON", "HEAVY METAL IND", "GRANITE WORKS",
        "ALLOY SOLUTIONS", "TURBINE POWER",
        # Retail & Consumer (10)
        "MEGA MART", "VALUE ZONE", "QUICK STOP", "BARGAIN BARN",
        "PRIME DELIVERY", "HOME ESSENTIALS", "EVERYDAY GOODS", "DISCOUNT DEPOT",
        "FAMILY FIRST", "SUPER SAVER",
    ]

    # 5 text layout styles for trailer (each returns line1, line2)
    SEMI_LAYOUTS = [
        # Style 0: Company name centered, tagline below
        lambda c: (c, "~ NATIONWIDE ~"),
        # Style 1: Company name with decorative borders
        lambda c: (f"★ {c} ★", "═══════════════════════════"),
        # Style 2: Company name with phone number style
        lambda c: (c, "1-800-DELIVER"),
        # Style 3: Company name with website
        lambda c: (c, "www.{}.com".format(c.lower().replace(' ', '')[:15])),
        # Style 4: Company name split if long, simple
        lambda c: (c[:14] if len(c) > 14 else c, c[14:] if len(c) > 14 else "TRUSTED SINCE 1987"),
    ]

    # 4 semi-truck trailer colors
    SEMI_COLORS = [
        Colors.ALLEY_LIGHT,     # White trailer
        Colors.SHADOW_RED,      # Red trailer
        Colors.ALLEY_BLUE,      # Blue trailer
        Colors.RAT_YELLOW,      # Yellow trailer
    ]

    # Warning/alert messages that scroll on truck when daemon events occur
    SEMI_WARNING_PREFIXES = [
        "⚠ ALERT: ", "⚡ WARNING: ", "🔔 NOTICE: ", "⛔ CRITICAL: ", "📢 BROADCAST: "
    ]

    # Car body colors for variety
    CAR_COLORS = [
        Colors.SHADOW_RED,      # Red
        Colors.ALLEY_BLUE,      # Blue
        Colors.RAT_YELLOW,      # Yellow
        Colors.MATRIX_DIM,      # Green
        Colors.ALLEY_LIGHT,     # White
    ]

    # Manhole cover (on street)
    MANHOLE = [
        "(====)",
    ]

    # Street drain (curb side)
    DRAIN = [
        "[|||]",
    ]

    # Steam animation frames
    STEAM_FRAMES = [
        ["  ~  ", " ~~~ ", "~~~~~"],
        [" ~~  ", "~~~~ ", " ~~~~"],
        ["~~   ", " ~~~ ", "~~~~ "],
    ]

    # Tree sprites for windy city effect (trunk centered under foliage)
    TREE = [
        "   (@@)   ",
        "  (@@@@@) ",
        " (@@@@@@@)",
        "  (@@@@@) ",
        "    ||    ",
        "    ||    ",
        "   _||_   ",
    ]

    # Tree blowing right (wind from left) - trunk stays centered
    TREE_WINDY_RIGHT = [
        "    (@@)  ",
        "   (@@@@@)",
        "  (@@@@@@@)",
        "   (@@@@) ",
        "    ||    ",
        "    ||    ",
        "   _||_   ",
    ]

    # Tree blowing left (wind from right) - trunk stays centered
    TREE_WINDY_LEFT = [
        "  (@@)    ",
        " (@@@@@)  ",
        "(@@@@@@@) ",
        " (@@@@)   ",
        "    ||    ",
        "    ||    ",
        "   _||_   ",
    ]

    # Pine tree sprite (taller, triangular)
    PINE_TREE = [
        "    *     ",
        "   /|\\   ",
        "  /|||\\  ",
        " /|||||\\",
        "  /|||\\  ",
        " /|||||\\",
        "/|||||||\\",
        "   |||    ",
        "   |||    ",
        "  _|||_   ",
    ]

    # Pine tree blowing right
    PINE_TREE_WINDY_RIGHT = [
        "     *    ",
        "    /|\\  ",
        "   /|||\\  ",
        "  /|||||\\",
        "   /|||\\  ",
        "  /|||||\\",
        " /|||||||\\",
        "    |||   ",
        "    |||   ",
        "   _|||_  ",
    ]

    # Pine tree blowing left
    PINE_TREE_WINDY_LEFT = [
        "    *     ",
        "   /|\\   ",
        "  /|||\\  ",
        " /|||||\\",
        "  /|||\\  ",
        " /|||||\\",
        "/|||||||\\",
        "   |||    ",
        "   |||    ",
        "  _|||_   ",
    ]

    # Debris sprites for windy weather
    DEBRIS_NEWSPAPER = ['▪', '▫', '□', '▢']
    DEBRIS_TRASH = ['~', '°', '·', '∘']
    DEBRIS_LEAVES = ['*', '✦', '✧', '⁕']

    # Wind wisp characters
    WIND_WISPS = ['~', '≈', '≋', '～', '-', '=']

    # ==========================================
    # HOLIDAY EVENT SPRITES
    # ==========================================

    # Pumpkin sprite (Halloween Oct 24-31)
    PUMPKIN = [
        " ,---, ",
        "(o ^ o)",
        " \\___/ ",
    ]

    # Spooky bare tree (Halloween - replaces regular trees)
    SPOOKY_TREE = [
        "    \\|/    ",
        "   --+--   ",
        "  / | \\  ",
        " /  |  \\ ",
        "    |     ",
        "   _|_    ",
    ]

    # Easter egg patterns (simple colored eggs)
    EASTER_EGG = [
        " /\\ ",
        "(  )",
        " \\/ ",
    ]

    # Firework burst patterns
    FIREWORK_BURST = [
        "  \\ | /  ",
        " -- * -- ",
        "  / | \\  ",
    ]

    FIREWORK_STAR = [
        "   *   ",
        " * + * ",
        "   *   ",
    ]

    FIREWORK_SHOWER = [
        " ' ' ' ",
        "  ' '  ",
        " ' ' ' ",
    ]

    # ==========================================
    # SEASONAL CONSTELLATIONS - Security Canary
    # Stars tied to memory monitor health
    # ==========================================

    # Spring constellation: Leo (the lion) - Mar-May
    # Recognizable by the "sickle" (backwards question mark) and triangle
    # Stars scaled 5x for visibility
    CONSTELLATION_LEO = {
        'name': 'Leo',
        'stars': [
            # Sickle (head) - backwards question mark shape
            (0, 0, 2),     # Regulus (brightest, alpha)
            (10, -10, 1),  # Eta Leonis
            (20, -15, 1),  # Gamma (Algieba)
            (30, -10, 2),  # Zeta
            (35, 0, 1),    # Mu
            (25, 5, 1),    # Epsilon
            # Body/hindquarters triangle
            (50, 0, 2),    # Denebola (beta, tail)
            (40, -5, 1),   # Delta
            (30, 5, 1),    # Theta
        ],
    }

    # Summer constellation: Scorpius (the scorpion) - Jun-Aug
    # Recognizable by the curved tail and red Antares
    # Stars scaled 5x for visibility
    CONSTELLATION_SCORPIUS = {
        'name': 'Scorpius',
        'stars': [
            # Head/claws
            (0, 0, 1),     # Graffias (beta)
            (10, -5, 1),   # Dschubba (delta)
            (20, 0, 1),    # Pi Scorpii
            # Body with Antares (heart)
            (25, 10, 2),   # Antares (alpha, red supergiant)
            (30, 15, 1),   # Tau
            # Curved tail
            (35, 25, 1),   # Epsilon
            (40, 30, 2),   # Mu
            (50, 35, 1),   # Zeta
            (60, 30, 1),   # Eta
            (70, 25, 2),   # Shaula (lambda, stinger)
            (75, 20, 1),   # Lesath (upsilon)
        ],
    }

    # Fall constellation: Pegasus (the winged horse) - Sep-Nov
    # Recognizable by the Great Square
    # Stars scaled 5x for visibility
    CONSTELLATION_PEGASUS = {
        'name': 'Pegasus',
        'stars': [
            # The Great Square
            (0, 0, 2),     # Markab (alpha)
            (40, 0, 2),    # Scheat (beta)
            (40, -30, 2),  # Algenib (gamma)
            (0, -30, 2),   # Alpheratz (actually Andromeda alpha)
            # Neck and head
            (-15, 10, 1),  # Homam (zeta)
            (-30, 15, 1),  # Biham (theta)
            (-45, 10, 2),  # Enif (epsilon, nose)
        ],
    }

    # Winter constellation: Orion (the hunter) - Dec-Feb
    # Most recognizable - belt of 3 stars, Betelgeuse and Rigel
    # Stars scaled 5x for visibility
    CONSTELLATION_ORION = {
        'name': 'Orion',
        'stars': [
            # Shoulders
            (0, 0, 2),    # Betelgeuse (alpha, red)
            (40, 0, 1),   # Bellatrix (gamma)
            # Belt (3 stars in a row)
            (10, 15, 2),  # Alnitak (zeta)
            (20, 15, 2),  # Alnilam (epsilon)
            (30, 15, 2),  # Mintaka (delta)
            # Feet
            (0, 30, 2),   # Saiph (kappa)
            (40, 30, 2),  # Rigel (beta, blue-white)
            # Sword (below belt)
            (20, 25, 1),  # Orion Nebula area
        ],
    }

    # ==========================================
    # METEOR QTE EVENT - Quick Time Event
    # ==========================================

    # Meteor sprites (falling chunks)
    METEOR_LARGE = [
        " @@@ ",
        "@@@@@",
        "@@@@@",
        " @@@ ",
    ]

    METEOR_MEDIUM = [
        " @@ ",
        "@@@@",
        " @@ ",
    ]

    METEOR_SMALL = [
        " @ ",
        "@@@",
    ]

    # Missile sprite (rising from bottom)
    MISSILE = [
        " ^ ",
        "/|\\",
        " | ",
    ]

    # Explosion animation frames
    EXPLOSION_FRAMES = [
        [" * "],
        ["***", " * "],
        ["*.*", "***", "*.*"],
        [" . ", ".*.", " . "],
        ["   "],
    ]

    # NPC caller (person waving for help)
    NPC_CALLER = [
        " O/ ",
        "/|  ",
        "/ \\ ",
    ]

    # QTE key mappings: key -> (column_index, row_index)
    # Columns spread across screen, rows are vertical layers
    # Keys: 6, 7, 8, 9, 0 for columns
    # Rows: top (0), middle (1), bottom (2)
    QTE_KEYS = ['6', '7', '8', '9', '0']

    # Person walking animation frames (arm swinging) - basic person
    # Pedestrian sprites with leg animation (4 frames for walking cycle)
    PERSON_RIGHT_FRAMES = [
        [" O ", "/| ", " | ", "/| "],   # Right arm back, right leg forward
        [" O ", " |\\", " | ", "|| "],   # Left arm back, legs together
        [" O ", "/| ", " | ", "|\\ "],   # Right arm back, left leg back
        [" O ", " |\\", " | ", "|| "],   # Left arm back, legs together
    ]
    PERSON_LEFT_FRAMES = [
        [" O ", " |\\", " | ", " |\\"],  # Left arm back, left leg forward
        [" O ", "/| ", " | ", " ||"],   # Right arm back, legs together
        [" O ", " |\\", " | ", " /|"],  # Left arm back, right leg back
        [" O ", "/| ", " | ", " ||"],   # Right arm back, legs together
    ]

    # Person with hat (~, on head) - with leg animation
    PERSON_HAT_RIGHT_FRAMES = [
        [" ~ ", " O ", "/| ", "/| "],   # Hat, right leg forward
        [" , ", " O ", " |\\", "|| "],   # Hat, legs together
        [" ~ ", " O ", "/| ", "|\\ "],   # Hat, left leg back
        [" , ", " O ", " |\\", "|| "],   # Hat, legs together
    ]
    PERSON_HAT_LEFT_FRAMES = [
        [" ~ ", " O ", " |\\", " |\\"],  # Hat, left leg forward
        [" , ", " O ", "/| ", " ||"],   # Hat, legs together
        [" ~ ", " O ", " |\\", " /|"],  # Hat, right leg back
        [" , ", " O ", "/| ", " ||"],   # Hat, legs together
    ]

    # Person with briefcase (# carried) - with leg animation
    PERSON_BRIEFCASE_RIGHT_FRAMES = [
        [" O ", "/|#", " | ", "/| "],   # Briefcase, right leg forward
        [" O ", " |#", " | ", "|| "],   # Briefcase, legs together
        [" O ", "/|#", " | ", "|\\ "],   # Briefcase, left leg back
        [" O ", " |#", " | ", "|| "],   # Briefcase, legs together
    ]
    PERSON_BRIEFCASE_LEFT_FRAMES = [
        [" O ", "#|\\", " | ", " |\\"],  # Briefcase, left leg forward
        [" O ", "#| ", " | ", " ||"],   # Briefcase, legs together
        [" O ", "#|\\", " | ", " /|"],  # Briefcase, right leg back
        [" O ", "#| ", " | ", " ||"],   # Briefcase, legs together
    ]

    # Person with skirt (A-line shape) - with leg animation
    PERSON_SKIRT_RIGHT_FRAMES = [
        [" O ", "/| ", "/A\\", "> |"],   # Skirt, right knee forward
        [" O ", " |\\", "/A\\", "| |"],   # Skirt, legs together
        [" O ", "/| ", "/A\\", "| >"],   # Skirt, left knee forward (still facing right)
        [" O ", " |\\", "/A\\", "| |"],   # Skirt, legs together
    ]
    PERSON_SKIRT_LEFT_FRAMES = [
        [" O ", " |\\", "/A\\", "| <"],  # Skirt, left knee forward
        [" O ", "/| ", "/A\\", "| |"],  # Skirt, legs together
        [" O ", " |\\", "/A\\", "< |"],  # Skirt, right knee forward (still facing left)
        [" O ", "/| ", "/A\\", "| |"],  # Skirt, legs together
    ]

    # All person types for random selection
    PERSON_TYPES_RIGHT = [
        PERSON_RIGHT_FRAMES,
        PERSON_HAT_RIGHT_FRAMES,
        PERSON_BRIEFCASE_RIGHT_FRAMES,
        PERSON_SKIRT_RIGHT_FRAMES,
    ]
    PERSON_TYPES_LEFT = [
        PERSON_LEFT_FRAMES,
        PERSON_HAT_LEFT_FRAMES,
        PERSON_BRIEFCASE_LEFT_FRAMES,
        PERSON_SKIRT_LEFT_FRAMES,
    ]

    # Skin tone colors for diversity
    SKIN_TONES = [
        Colors.ALLEY_LIGHT,     # Light skin
        Colors.RAT_YELLOW,      # Tan/olive
        Colors.BOX_BROWN,       # Brown
        Colors.ALLEY_MID,       # Medium brown
        Colors.GREY_BLOCK,      # Dark
    ]

    # Clothing colors for variety
    CLOTHING_COLORS = [
        Colors.SHADOW_RED,      # Red
        Colors.ALLEY_BLUE,      # Blue
        Colors.MATRIX_DIM,      # Green
        Colors.RAT_YELLOW,      # Yellow
        Colors.GREY_BLOCK,      # Grey
        Colors.ALLEY_MID,       # Brown
        Colors.STATUS_OK,       # Bright green
        Colors.ALLEY_LIGHT,     # White
    ]

    # Knocked out person sprite (lying on ground)
    KNOCKED_OUT_SPRITE = ["___o___"]

    # Ambulance sprite (4 rows, wider)
    AMBULANCE_RIGHT = [
        "  ___+___________  ",
        " |  ░░░ AMBULANCE| ",
        " |_░░░___________|_",
        " (O)-----------(O) ",
    ]
    AMBULANCE_LEFT = [
        "  ___________+___  ",
        " |AMBULANCE ░░░  | ",
        "_|___________░░░_| ",
        " (O)-----------(O) ",
    ]

    # Paramedic sprite (small, kneeling)
    PARAMEDIC_SPRITE = [" o ", "/|>", " A "]

    # ==========================================
    # WOMAN IN RED EVENT - Matrix iconic scene
    # ==========================================

    # Woman in red - blonde hair, red dress (walking right)
    WOMAN_RED_RIGHT_FRAMES = [
        ["~o~", "/|\\", "/A\\", "> |"],   # Walking frame 1
        ["~o~", "\\|/", "/A\\", "| |"],   # Walking frame 2
        ["~o~", "/|\\", "/A\\", "| <"],   # Walking frame 3
        ["~o~", "\\|/", "/A\\", "| |"],   # Walking frame 4
    ]

    # Woman in red - walking left
    WOMAN_RED_LEFT_FRAMES = [
        ["~o~", "\\|/", "/A\\", "| <"],   # Walking frame 1
        ["~o~", "/|\\", "/A\\", "| |"],   # Walking frame 2
        ["~o~", "\\|/", "/A\\", "> |"],   # Walking frame 3
        ["~o~", "/|\\", "/A\\", "| |"],   # Walking frame 4
    ]

    # Woman in red - waving (stationary, arm raised)
    WOMAN_RED_WAVE_FRAMES = [
        ["~o~", "\\|/", "/A\\", "| |"],   # Wave down
        ["~o~", "\\|_", "/A\\", "| |"],   # Wave mid
        ["~o~", "\\|^", "/A\\", "| |"],   # Wave up
        ["~o~", "\\|_", "/A\\", "| |"],   # Wave mid
    ]

    # Agent Smith - suit and sunglasses (walking/running right)
    AGENT_SMITH_RIGHT_FRAMES = [
        ["[=]", "/|\\", "[H]", "/ \\"],   # Running frame 1
        ["[=]", "\\|/", "[H]", " | "],    # Running frame 2
        ["[=]", "/|\\", "[H]", "\\ /"],   # Running frame 3
        ["[=]", "\\|/", "[H]", " | "],    # Running frame 4
    ]

    # Agent Smith - suit and sunglasses (walking/running left)
    AGENT_SMITH_LEFT_FRAMES = [
        ["[=]", "\\|/", "[H]", "/ \\"],   # Running frame 1
        ["[=]", "/|\\", "[H]", " | "],    # Running frame 2
        ["[=]", "\\|/", "[H]", "\\ /"],   # Running frame 3
        ["[=]", "/|\\", "[H]", " | "],    # Running frame 4
    ]

    # Neo - long coat, sunglasses (walking right)
    NEO_RIGHT_FRAMES = [
        ["(O)", "/|\\", "###", "/ \\"],   # Walking frame 1
        ["(O)", "\\|/", "###", " | "],    # Walking frame 2
        ["(O)", "/|\\", "###", "\\ /"],   # Walking frame 3
        ["(O)", "\\|/", "###", " | "],    # Walking frame 4
    ]

    # Neo - long coat, sunglasses (walking left / running away)
    NEO_LEFT_FRAMES = [
        ["(O)", "\\|/", "###", "/ \\"],   # Running frame 1
        ["(O)", "/|\\", "###", " | "],    # Running frame 2
        ["(O)", "\\|/", "###", "\\ /"],   # Running frame 3
        ["(O)", "/|\\", "###", " | "],    # Running frame 4
    ]

    # Morpheus - bald, long coat (walking right)
    MORPHEUS_RIGHT_FRAMES = [
        ["(0)", "/|\\", "%%%", "/ \\"],   # Walking frame 1
        ["(0)", "\\|/", "%%%", " | "],    # Walking frame 2
        ["(0)", "/|\\", "%%%", "\\ /"],   # Walking frame 3
        ["(0)", "\\|/", "%%%", " | "],    # Walking frame 4
    ]

    # Morpheus - bald, long coat (walking left / running away)
    MORPHEUS_LEFT_FRAMES = [
        ["(0)", "\\|/", "%%%", "/ \\"],   # Running frame 1
        ["(0)", "/|\\", "%%%", " | "],    # Running frame 2
        ["(0)", "\\|/", "%%%", "\\ /"],   # Running frame 3
        ["(0)", "/|\\", "%%%", " | "],    # Running frame 4
    ]

    # Transform effect frames (woman to agent glitch)
    TRANSFORM_FRAMES = [
        ["~o~", "/|\\", "/A\\", "| |"],   # Woman
        ["###", "###", "###", "###"],     # Glitch 1
        ["[=]", "???", "[H]", "???"],     # Partial transform
        ["###", "###", "###", "###"],     # Glitch 2
        ["[=]", "\\|/", "[H]", " | "],    # Agent Smith
    ]

    # UFO for abduction event
    UFO_SPRITE = [
        "    ___    ",
        " __/   \\__ ",
        "/  o   o  \\",
        "\\____*____/",
    ]

    # Tractor beam (extends below UFO)
    TRACTOR_BEAM = [
        "    |||    ",
        "   |||||   ",
        "  |||||||  ",
        " ||||||||| ",
    ]

    # Cow being abducted
    COW_SPRITE = [
        " ^__^",
        " (oo)",
        "/----\\",
        "||  ||",
    ]

    # Street light - taller pole
    STREET_LIGHT = [
        " ___ ",
        "[___]",
        "  |  ",
        "  |  ",
        "  |  ",
        "  |  ",
        "  |  ",
        "  |  ",
    ]

    # Street sign - Claude Av
    STREET_SIGN = [
        ".----------.",
        "| Claude Av|",
        "'----------'",
        "     ||     ",
        "     ||     ",
        "     ||     ",
    ]

    # Static cityscape backdrop (drawn behind main buildings in the gap)
    # 140 chars wide, dense city skyline with various building heights and solid walls
    CITYSCAPE = [
        "         T                    |~|                 T              T                    |~|              T           ",  # Row 0
        "   ___  /|\\        ___       |█|    ___         /|\\   ___      /|\\        ___       |█|    ___      /|\\   ___    ",  # Row 1
        "  |███| |█|  ___  |███|  ___ |█|   |███|  ___  |█|█| |███| ___ |█|  ___  |███|  ___ |█|   |███| ___ |█|█| |███|   ",  # Row 2
        "  |[ ]| |█| |███| |[ ]| |███||█|   |[ ]| |███| |█|█| |[ ]||███||█| |███| |[ ]| |███||█|   |[ ]||███||█|█| |[ ]|   ",  # Row 3
        "  |[ ]| |█| |[ ]| |[ ]| |[ ]||█|   |[ ]| |[ ]| |█|█| |[ ]||[ ]||█| |[ ]| |[ ]| |[ ]||█|   |[ ]||[ ]||█|█| |[ ]|   ",  # Row 4
        "  |[ ]| |█| |[ ]| |[ ]| |[ ]||█|   |[ ]| |[ ]| |█|█| |[ ]||[ ]||█| |[ ]| |[ ]| |[ ]||█|   |[ ]||[ ]||█|█| |[ ]|   ",  # Row 5
        "  |[ ]| |█| |[ ]| |[ ]| |[ ]||█|   |[ ]| |[ ]| |█|█| |[ ]||[ ]||█| |[ ]| |[ ]| |[ ]||█|   |[ ]||[ ]||█|█| |[ ]|   ",  # Row 6
        "  |[ ]| |█| |[ ]| |[ ]| |[ ]||█|   |[ ]| |[ ]| |█|█| |[ ]||[ ]||█| |[ ]| |[ ]| |[ ]||█|   |[ ]||[ ]||█|█| |[ ]|   ",  # Row 7
        "  |███| |█| |███| |███| |███||█|   |███| |███| |█|█| |███||███||█| |███| |███| |███||█|   |███||███||█|█| |███|   ",  # Row 8
        "        |█|              |███||█|              |█|█|      |███||█|              |███||█|        |███||█|█|         ",  # Row 9
        "        |█|              |[ ]||█|              |█|█|      |[ ]||█|              |[ ]||█|        |[ ]||█|█|         ",  # Row 10
        "        |█|              |[ ]||█|              |█|█|      |[ ]||█|              |[ ]||█|        |[ ]||█|█|         ",  # Row 11
        "        |█|              |███||█|              |█|█|      |███||█|              |███||█|        |███||█|█|         ",  # Row 12
        "        |_|                  |_|              |_||_|          |_|                  |_|             |_||_|         ",  # Row 13
    ]

    # Building wireframe - 2X TALL, 2X WIDE with mixed window sizes, two doors with stoops
    BUILDING = [
        "                         _____                                  ",
        "       __O__            |     |                  __O__          ",
        "      / === \\          |     |  [===]          / === \\         ",
        "     (==//\\==)         |_____|  [===]         (==//\\==)        ",
        ".--------------------------------------------------------------.",
        "                                                                ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "                                                                ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "                                                                ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "                                                                ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "                                                                ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "            .------.                    .------.                ",
        "            |      |                    |      |                ",
        "            |      |                    |      |                ",
        "            |      |                    |      |                ",
        "            | [==] |                    | [==] |                ",
        "____________|______|____________________|______|________________",
        "      ______.------.____          ______.------.____            ",
    ]

    # Second building (right side) - 2X TALL, 2X WIDE with two doors with stoops
    BUILDING2 = [
        "              _____                                      ",
        "             |     |     __O__               __O__         ",
        "      [===]  |     |    / === \\            / === \\        ",
        "      [===]  |_____|   (==//\\==)          (==//\\==)       ",
        ".----------------------------------------------------------.",
        "                                                            ",
        "     [========]    [====]    [========]    [====]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [========]    [====]    [========]    [====]           ",
        "                                                            ",
        "     [========]    [====]    [========]    [====]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [========]    [====]    [========]    [====]           ",
        "                                                            ",
        "     [========]    [====]    [========]    [====]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [========]    [====]    [========]    [====]           ",
        "                                                            ",
        "     [========]    [====]    [========]    [====]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [========]    [====]    [========]    [====]           ",
        "                                                            ",
        "     [========]    [====]    [========]    [====]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [========]    [====]    [========]    [====]           ",
        "            .------.                    .------.            ",
        "            |      |                    |      |            ",
        "            |      |                    |      |            ",
        "            |      |                    |      |            ",
        "            | [==] |                    | [==] |            ",
        "____________|______|____________________|______|____________",
        "      ______.------.____          ______.------.____        ",
    ]

    # Window positions for people animation (relative to building sprite)
    # Each entry is (row_offset, col_offset) for the middle of a window interior
    BUILDING_WINDOW_POSITIONS = [
        (8, 7), (8, 19), (8, 27), (8, 39),      # First row (inside window interiors)
        (14, 7), (14, 19), (14, 27), (14, 39),  # Second row
        (20, 7), (20, 19), (20, 27), (20, 39),  # Third row
        (26, 7), (26, 19), (26, 27), (26, 39),  # Fourth row
        (32, 7), (32, 19), (32, 27), (32, 39),  # Fifth row
    ]
    BUILDING2_WINDOW_POSITIONS = [
        (8, 9), (8, 21), (8, 33), (8, 45),      # First row (inside window interiors)
        (14, 9), (14, 21), (14, 33), (14, 45),  # Second row
        (20, 9), (20, 21), (20, 33), (20, 45),  # Third row
        (26, 9), (26, 21), (26, 33), (26, 45),  # Fourth row
        (32, 9), (32, 21), (32, 33), (32, 45),  # Fifth row
    ]

    # Door positions relative to building sprite (col_offset from building_x)
    # These are the two doors on each building
    BUILDING_DOOR_OFFSETS = [12, 40]   # Two doors on BUILDING
    BUILDING2_DOOR_OFFSETS = [12, 40]  # Two doors on BUILDING2

    # Person hailing taxi (arm raised)
    PERSON_HAILING_RIGHT = [
        " O/",
        "/| ",
        "/\\",
    ]
    PERSON_HAILING_LEFT = [
        "\\O ",
        " |\\",
        "/\\",
    ]

    # Open door overlay (replaces closed door section)
    DOOR_OPEN = [
        ".──────.",
        "|░░░░░░|",
        "|░░░░░░|",
        "|░░░░░░|",
        "|░[==]░|",
    ]

    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height
        self.scene: List[List[Tuple[str, int]]] = []
        # Store object positions for rat hiding
        self.dumpster_x = 0
        self.dumpster_y = 0
        self.box_x = 0
        self.box_y = 0
        # Store building positions for window people
        self._building_x = 0
        self._building_y = 0
        self._building2_x = 0
        self._building2_y = 0
        # Store building bottom for rat constraints
        self._building_bottom_y = height - 3
        # Traffic light state
        self._traffic_frame = 0
        self._traffic_state = 'NS_GREEN'  # NS_GREEN, NS_YELLOW, EW_GREEN, EW_YELLOW
        self._state_duration = 0
        # Horizontal cars on the street
        self._cars: List[Dict] = []
        self._car_spawn_timer = 0
        # Audio state for car sounds
        self._audio_muted = False
        self._car_sound_cooldown = 0
        # Close-up car (perspective effect - shrinks as it passes)
        self._closeup_car: Dict = None
        self._closeup_car_timer = 0
        # Pedestrians on the street
        self._pedestrians: List[Dict] = []
        self._pedestrian_spawn_timer = 0
        # Knocked out pedestrians from lightning
        self._knocked_out_peds: List[Dict] = []  # {x, y, timer, skin_color, clothing_color}
        # Ambulance for revival
        self._ambulance: Dict = None  # {x, direction, state, target_ped, paramedic_x}
        self._ambulance_cooldown = 0
        # Lightning strike position for knockout detection
        self._last_lightning_x = -1
        # Interaction states for pedestrians
        self._mailbox_interaction: Dict = None  # {ped, state, timer} - person mailing letter
        self._open_doors: List[Dict] = []  # [{building, door_idx, timer}] - currently open doors
        self._door_positions: List[Dict] = []  # Calculated door x positions
        self._waiting_taxi_peds: List[Dict] = []  # Peds waiting for taxi {ped, timer}
        self._taxi_pickup: Dict = None  # {taxi, ped, state, timer} - taxi picking up person
        # Street light flicker effect
        self._street_light_positions: List[Tuple[int, int]] = []
        self._street_light_flicker = [1.0, 1.0]  # Brightness per light (0-1)
        self._flicker_timer = 0
        # Building window lights (same flicker pattern as street lights, no pole)
        self._building_window_lights: List[Tuple[int, int]] = []  # (x, y) positions
        self._building_window_flicker = []  # Brightness per window light (0-1)
        # All window data with scenes and light states
        # Each window: {x, y, width, height, building, scene_type, light_on, brightness, scene_chars}
        self._all_windows: List[Dict] = []
        self._window_light_timer = 0  # Timer for random light on/off
        # Window scene types - each creates unique interior content
        self._window_scene_types = [
            'empty', 'plant', 'lamp', 'tv', 'cat', 'bookshelf', 'desk',
            'curtains', 'blinds', 'person_standing', 'couple', 'kitchen'
        ]
        # Window people - list of active silhouettes {window_idx, building, direction, progress}
        # Pre-spawn some people so windows aren't empty at start
        self._window_people: List[Dict] = [
            {'building': 1, 'window_idx': 2, 'direction': 1, 'progress': 0.5, 'state': 'staring', 'state_timer': 0, 'stare_duration': 200, 'wave_count': 0, 'wave_frame': 0},
            {'building': 1, 'window_idx': 8, 'direction': -1, 'progress': 0.3, 'state': 'walking', 'state_timer': 0, 'stare_duration': 150, 'wave_count': 0, 'wave_frame': 0},
            {'building': 2, 'window_idx': 5, 'direction': 1, 'progress': 0.6, 'state': 'staring', 'state_timer': 0, 'stare_duration': 180, 'wave_count': 0, 'wave_frame': 0},
            {'building': 2, 'window_idx': 12, 'direction': -1, 'progress': 0.4, 'state': 'walking', 'state_timer': 0, 'stare_duration': 160, 'wave_count': 0, 'wave_frame': 0},
        ]
        self._window_spawn_timer = 0
        # Window positions for layering (filled during _draw_building)
        self._window_interior_positions: List[Tuple[int, int]] = []
        self._window_frame_positions: List[Tuple[int, int, str]] = []  # (x, y, char)
        self._sidewalk_positions: List[Tuple[int, int, str, int]] = []  # (x, y, char, color)
        # Cafe people in the lower window (Shell Cafe)
        self._cafe_people: List[Dict] = [
            {'x_offset': 0.0, 'direction': 1, 'arm_frame': 0, 'move_timer': 0, 'arm_timer': 0},
            {'x_offset': 6.0, 'direction': -1, 'arm_frame': 1, 'move_timer': 30, 'arm_timer': 15},
            {'x_offset': 12.0, 'direction': 1, 'arm_frame': 0, 'move_timer': 60, 'arm_timer': 45},
        ]
        self._cafe_people_timer = 0
        # Turtle head animation (peeks out of shell and winks)
        self._turtle_active = False
        self._turtle_frame = 0  # 0=normal, 1=left wink, 2=right wink, 3=happy
        self._turtle_timer = 0
        self._turtle_cooldown = random.randint(300, 600)  # 5-10 seconds at 60fps
        self._turtle_visible_duration = 0
        self._turtle_side = 1  # 1=right side, -1=left side
        self._turtle_state = 'hidden'  # hidden, peeking, winking, retreating
        # Semi-truck advertising system - seeded randomness for screenshot validation
        self._semi_seed_base = int(time.time())  # Base seed from startup time
        self._semi_spawn_counter = 0  # Increments each semi spawn for unique seeds
        self._semi_active_warnings: List[Dict] = []  # Active warning trucks {car_ref, message, scroll_pos}
        self._last_event_check = 0  # Timer for checking real daemon events
        self._known_event_ids: set = set()  # Track seen events to avoid duplicates
        # Prop plane with scrolling banner for announcements
        self._prop_plane: Dict = None  # {x, y, direction, speed, message, scroll_offset}
        self._prop_plane_queue: List[str] = []  # Queue of messages to display
        self._prop_plane_cooldown = 0  # Cooldown between planes
        # Manholes and drains with occasional steam
        self._manhole_positions: List[Tuple[int, int]] = []  # (x, y)
        self._drain_positions: List[Tuple[int, int]] = []  # (x, y)
        self._steam_effects: List[Dict] = []  # {x, y, frame, timer, duration}
        self._steam_spawn_timer = 0
        # Windy city weather - debris, leaves, wind wisps
        self._debris: List[Dict] = []  # {x, y, char, color, speed, state, timer, stop_x}
        self._leaves: List[Dict] = []  # {x, y, char, speed, wobble}
        self._wind_wisps: List[Dict] = []  # {x, y, chars, speed}
        self._debris_spawn_timer = 0
        self._wind_wisp_timer = 0
        self._tree_positions: List[Tuple[int, int]] = []  # (x, y) for trees
        self._pine_tree_positions: List[Tuple[int, int]] = []  # (x, y) for pine trees

        # Christmas lights (secret event Dec 20-31)
        self._christmas_mode = self._check_christmas_week()
        self._christmas_light_frame = 0
        self._christmas_light_timer = 0
        # Halloween (secret event Oct 24-31)
        self._halloween_mode = self._check_halloween_week()
        self._pumpkin_positions: List[Tuple[int, int]] = []  # (x, y) for pumpkins
        self._pumpkin_glow_frame = 0
        self._pumpkin_glow_timer = 0
        # 4th of July (secret event Jul 1-7)
        self._july4th_mode = self._check_july4th_week()
        self._fireworks: List[Dict] = []  # {x, y, frame, color, type}
        self._firework_timer = 0
        # Easter (secret event - Sunday in spring)
        self._easter_mode = self._check_easter_week()
        self._easter_egg_positions: List[Tuple[int, int, int]] = []  # (x, y, color_idx)
        self._tree_sway_frame = 0

        # ==========================================
        # SECURITY CANARY SYSTEM
        # Visual elements tied to daemon monitor health
        # If monitors fail, scene elements disappear
        # ==========================================
        self._security_canary = {
            'stars': True,          # Tied to memory_monitor
            'clouds': True,         # Tied to resource_monitor
            'traffic_lights': True, # Tied to health_monitor
            'street_lights': True,  # Tied to state_monitor
            'trees': True,          # Tied to file_integrity
            'pedestrians': True,    # Tied to process_security
            'cafe_lights': True,    # Tied to wifi_security
            'vehicles': True,       # Tied to log_watchdog
        }
        self._canary_check_timer = 0
        self._canary_check_interval = 300  # Check every 5 seconds at 60fps

        # Seasonal constellation (position in sky, based on date)
        self._constellation = self._get_seasonal_constellation()
        self._constellation_x = 0  # Set during scene generation
        self._constellation_y = 0
        self._star_twinkle_timer = 0
        self._star_twinkle_frame = 0

        # Scene seeding - deterministic random based on date for consistency
        # Same date = same scene layout (for screenshot validation)
        today = datetime.now()
        self._scene_seed = today.year * 10000 + today.month * 100 + today.day
        random.seed(self._scene_seed)

        # Wind direction: 1 = blowing right (from left), -1 = blowing left (from right)
        self._wind_direction = 1
        self._wind_direction_timer = 0
        self._wind_direction_change_interval = random.randint(10800, 54000)  # 3-15 minutes at ~60fps
        # Meteor damage overlays - {x, y, char, timer, fade_time}
        self._damage_overlays: List[Dict] = []
        self._damage_fade_time = 18000  # ~5 minutes at 60fps (300 seconds * 60)
        # Woman in Red event - rare Matrix scene
        self._woman_red_active = False
        self._woman_red_state = 'idle'  # idle, neo_morpheus_enter, woman_enters, woman_passes, woman_waves, woman_pauses, transform, chase, cooldown
        self._woman_red_timer = 0
        self._woman_red_cooldown = 0
        self._woman_red_x = 0.0  # Woman's x position
        self._neo_x = 0.0  # Neo's x position
        self._morpheus_x = 0.0  # Morpheus's x position
        self._agent_x = 0.0  # Agent Smith's x position (after transform)
        self._woman_red_frame = 0
        self._neo_frame = 0
        self._morpheus_frame = 0
        self._agent_frame = 0
        self._transform_frame = 0
        self._frame_timer = 0
        # Meteor QTE event - quick time event
        self._qte_enabled = False  # Toggle for QTE events (off by default)
        self._qte_pending_activation = False  # Waiting for delayed activation
        self._qte_activation_time = 0.0  # When to activate QTE
        self._qte_active = False
        self._qte_state = 'idle'  # idle, warning, active, success, failure, cooldown
        self._qte_timer = 0
        self._qte_cooldown = 0
        self._qte_meteors: List[Dict] = []  # {x, y, col, row, speed, size, called}
        self._qte_missiles: List[Dict] = []  # {x, y, target_col, target_row, speed}
        self._qte_explosions: List[Dict] = []  # {x, y, frame, timer}
        self._qte_current_callout = None  # (col, row, key) - current key NPC is calling
        self._qte_callout_timer = 0
        self._qte_score = 0
        self._qte_misses = 0
        self._qte_npc_x = 0
        self._qte_npc_message = ""
        self._qte_message_timer = 0  # Timer for auto-clearing messages
        self._qte_message_duration = 90  # Frames to show message (1.5 sec at 60fps)
        self._qte_wave = 0  # Current wave of meteors
        self._qte_total_waves = 5  # Total waves per event
        self._qte_pending_keys: List[str] = []  # Keys player needs to press
        self._qte_last_meteor_positions: List[Tuple[int, int, int, int]] = []  # (x, y, w, h) for cleanup
        # Skyline buildings with animated window lights
        self._skyline_windows: List[Dict] = []  # {x, y, on, timer, toggle_time}
        self._skyline_buildings: List[Dict] = []  # {x, y, width, height, windows}
        # OPEN sign animation state
        self._open_sign_phase = 0  # 0=off, 1=O, 2=OP, 3=OPE, 4=OPEN, 5-9=flash
        self._open_sign_timer = 0
        self._open_sign_speed = 2  # Frames per phase (10x faster)
        # Calm mode flag - more debris/leaves, no particles
        self._calm_mode = False
        # Full weather mode for road effects
        self._weather_mode = WeatherMode.MATRIX
        # Road/sidewalk weather effects - subtle rolling changes
        self._road_effects: List[Dict] = []  # {x, y, char, color, timer, duration, type}
        self._road_effect_timer = 0
        self._road_effect_interval = 30  # Spawn new effects every ~0.5 sec at 60fps
        # UFO abduction event - super rare
        self._ufo_active = False
        self._ufo_state = 'idle'  # idle, descend, abduct, ascend, cooldown
        self._ufo_timer = 0
        self._ufo_cooldown = 0
        self._ufo_x = 0.0
        self._ufo_y = 0.0
        self._ufo_target_y = 0.0
        self._cow_y = 0.0  # Cow being abducted
        # Cloud layer with wisps
        self._clouds: List[Dict] = []
        self._init_clouds()
        self._generate_scene()

    def resize(self, width: int, height: int):
        """Regenerate scene for new dimensions."""
        self.width = width
        self.height = height
        self._cars = []  # Clear cars on resize
        self._closeup_car = None  # Clear close-up car on resize
        self._pedestrians = []  # Clear pedestrians on resize
        self._woman_red_active = False  # Reset woman in red event
        self._woman_red_state = 'idle'
        self._qte_active = False  # Reset QTE event
        self._qte_state = 'idle'
        self._qte_meteors = []
        self._qte_missiles = []
        self._qte_explosions = []
        self._init_clouds()  # Reinit clouds for new size
        self._generate_scene()

    def _check_christmas_week(self) -> bool:
        """Check if it's Christmas week (Dec 20-31) for secret lights event."""
        today = datetime.now()
        return today.month == 12 and today.day >= 20

    def _check_halloween_week(self) -> bool:
        """Check if it's Halloween week (Oct 24-31) for spooky event."""
        today = datetime.now()
        return today.month == 10 and today.day >= 24

    def _check_july4th_week(self) -> bool:
        """Check if it's 4th of July week (Jul 1-7) for fireworks event."""
        today = datetime.now()
        return today.month == 7 and today.day <= 7

    def _check_easter_week(self) -> bool:
        """Check if it's Easter week (Easter Sunday +/- 3 days)."""
        today = datetime.now()
        # Calculate Easter Sunday using Anonymous Gregorian algorithm
        year = today.year
        a = year % 19
        b = year // 100
        c = year % 100
        d = b // 4
        e = b % 4
        f = (b + 8) // 25
        g = (b - f + 1) // 3
        h = (19 * a + b - d - g + 15) % 30
        i = c // 4
        k = c % 4
        l = (32 + 2 * e + 2 * i - h - k) % 7
        m = (a + 11 * h + 22 * l) // 451
        month = (h + l - 7 * m + 114) // 31
        day = ((h + l - 7 * m + 114) % 31) + 1
        easter = datetime(year, month, day)
        # Check if within 3 days of Easter
        diff = abs((today - easter).days)
        return diff <= 3

    def _get_seasonal_constellation(self) -> dict:
        """Get the constellation for the current season."""
        today = datetime.now()
        month = today.month
        # Spring: March-May -> Leo
        if 3 <= month <= 5:
            return self.CONSTELLATION_LEO
        # Summer: June-August -> Scorpius
        elif 6 <= month <= 8:
            return self.CONSTELLATION_SCORPIUS
        # Fall: September-November -> Pegasus
        elif 9 <= month <= 11:
            return self.CONSTELLATION_PEGASUS
        # Winter: December-February -> Orion
        else:
            return self.CONSTELLATION_ORION

    def _check_security_canaries(self, daemon_client=None):
        """
        Check daemon monitor health and update canary state.
        Visual elements disappear when their tied monitor fails.

        Monitor -> Visual Element mapping:
        - memory_monitor    -> stars (constellation)
        - resource_monitor  -> clouds
        - health_monitor    -> traffic lights
        - state_monitor     -> street lights
        - file_integrity    -> trees/foliage
        - process_security  -> pedestrians
        - wifi_security     -> cafe lights
        - log_watchdog      -> vehicles
        """
        if daemon_client is None:
            return  # Can't check without client

        # Default all to True (assume healthy)
        monitors_healthy = {
            'memory_monitor': True,
            'resource_monitor': True,
            'health_monitor': True,
            'state_monitor': True,
            'file_integrity': True,
            'process_security': True,
            'wifi_security': True,
            'log_watchdog': True,
        }

        # Try to get status from daemon
        try:
            if hasattr(daemon_client, '_send_request'):
                response = daemon_client._send_request('get_health_stats')
                if response.get('success'):
                    stats = response.get('health_stats', {})
                    # Check each monitor's health status
                    monitors = stats.get('monitors', {})
                    for monitor_name, status in monitors.items():
                        if monitor_name in monitors_healthy:
                            monitors_healthy[monitor_name] = status.get('healthy', True)

                # Also check monitoring summary
                response = daemon_client._send_request('get_monitoring_summary')
                if response.get('success'):
                    summary = response.get('summary', {})
                    # Check specific monitor availability
                    if not summary.get('memory_monitor_active', True):
                        monitors_healthy['memory_monitor'] = False
                    if not summary.get('resource_monitor_active', True):
                        monitors_healthy['resource_monitor'] = False
        except Exception:
            pass  # Fail silently, keep previous canary state

        # Update canary state based on monitor health
        self._security_canary['stars'] = monitors_healthy['memory_monitor']
        self._security_canary['clouds'] = monitors_healthy['resource_monitor']
        self._security_canary['traffic_lights'] = monitors_healthy['health_monitor']
        self._security_canary['street_lights'] = monitors_healthy['state_monitor']
        self._security_canary['trees'] = monitors_healthy['file_integrity']
        self._security_canary['pedestrians'] = monitors_healthy['process_security']
        self._security_canary['cafe_lights'] = monitors_healthy['wifi_security']
        self._security_canary['vehicles'] = monitors_healthy['log_watchdog']

    def _update_security_canaries(self, daemon_client=None):
        """Periodically check security canary status."""
        self._canary_check_timer += 1
        if self._canary_check_timer >= self._canary_check_interval:
            self._canary_check_timer = 0
            self._check_security_canaries(daemon_client)

        # Update star twinkle animation
        self._star_twinkle_timer += 1
        if self._star_twinkle_timer >= 30:  # Twinkle every half second
            self._star_twinkle_timer = 0
            self._star_twinkle_frame = (self._star_twinkle_frame + 1) % 4

    def _update_christmas_lights(self):
        """Update Christmas light animation frame."""
        if not self._christmas_mode:
            return
        self._christmas_light_timer += 1
        # Change light pattern every 15 frames (~4 times per second at 60fps)
        if self._christmas_light_timer >= 15:
            self._christmas_light_timer = 0
            self._christmas_light_frame = (self._christmas_light_frame + 1) % 4

    def _update_halloween(self):
        """Update Halloween pumpkin glow animation."""
        if not self._halloween_mode:
            return
        self._pumpkin_glow_timer += 1
        # Flicker glow every 10-20 frames
        if self._pumpkin_glow_timer >= random.randint(10, 20):
            self._pumpkin_glow_timer = 0
            self._pumpkin_glow_frame = (self._pumpkin_glow_frame + 1) % 3

    def _update_fireworks(self):
        """Update 4th of July firework animations."""
        if not self._july4th_mode:
            return
        self._firework_timer += 1
        # Spawn new firework every 30-90 frames
        if self._firework_timer >= random.randint(30, 90):
            self._firework_timer = 0
            # Launch firework at random x position in sky
            self._fireworks.append({
                'x': random.randint(10, self.width - 10),
                'y': random.randint(3, 12),
                'frame': 0,
                'color': random.choice([Colors.XMAS_RED, Colors.FIREWORK_WHITE,
                                       Colors.XMAS_BLUE, Colors.FIREWORK_MAGENTA,
                                       Colors.XMAS_YELLOW]),
                'type': random.choice(['burst', 'star', 'shower']),
            })
        # Update existing fireworks
        for fw in self._fireworks[:]:
            fw['frame'] += 1
            if fw['frame'] > 20:  # Firework fades after 20 frames
                self._fireworks.remove(fw)

    def _init_clouds(self):
        """Initialize cloud layer with cumulus clouds and wisps."""
        self._clouds = []

        # Create big, FAST-moving cumulus clouds (closer, more detailed)
        num_cumulus = max(2, self.width // 60)
        for i in range(num_cumulus):
            # Large cumulus cloud shapes - move fast
            self._clouds.append({
                'x': random.uniform(0, self.width),
                'y': random.randint(4, 8),  # Mid-sky area
                'speed': random.uniform(0.15, 0.30),  # Fast movement for big clouds
                'type': 'cumulus',
                'chars': random.choice([
                    # Big puffy cumulus
                    ['      .-~~~-.      ',
                     '    .~       ~.    ',
                     '   (    ~~~    )   ',
                     '  (  .~     ~.  )  ',
                     ' (  (         )  ) ',
                     '  ~~~~~~~~~~~~~~~  '],
                    # Wide cumulus
                    ['    .--~~~--.    ',
                     '  .~         ~.  ',
                     ' (    ~~~~~    ) ',
                     '(               )',
                     ' ~~~~~~~~~~~~~~~'],
                    # Tall cumulus
                    ['     .~~.     ',
                     '   .~    ~.   ',
                     '  (        )  ',
                     ' (    ~~    ) ',
                     '(            )',
                     ' ~~~~~~~~~~~~'],
                    # Smaller cumulus
                    ['   .~~~.   ',
                     ' .~     ~. ',
                     '(         )',
                     ' ~~~~~~~~~'],
                ]),
            })

        # Create smaller main clouds - move very slow
        num_clouds = max(3, self.width // 40)  # More clouds
        for i in range(num_clouds):
            # Main cloud body - very slow
            self._clouds.append({
                'x': random.uniform(0, self.width),
                'y': random.randint(3, 6),  # Upper area
                'speed': random.uniform(0.01, 0.03),  # Very slow movement for small clouds
                'type': 'main',
                'chars': random.choice([
                    ['  ___  ', ' (   ) ', '(_____)', '  ~~~  '],
                    [' ~~~ ', '(   )', ' ~~~ '],
                    ['_____', '(   )', '~~~~~'],
                ]),
            })
            # Wisps below main clouds - slowest
            for _ in range(2):
                self._clouds.append({
                    'x': random.uniform(0, self.width),
                    'y': random.randint(6, 12),
                    'speed': random.uniform(0.005, 0.02),  # Even slower wisps
                    'type': 'wisp',
                    'char': random.choice(['~', '≈', '-', '.']),
                    'length': random.randint(3, 8),
                })

        # Create additional lower clouds - slowest, drift near buildings
        num_low_clouds = max(2, self.width // 60)
        for i in range(num_low_clouds):
            self._clouds.append({
                'x': random.uniform(0, self.width),
                'y': random.randint(10, 18),  # Lower on screen, near building tops
                'speed': random.uniform(0.008, 0.02),  # Very slow drift
                'type': 'main',
                'chars': random.choice([
                    ['  ___  ', ' (   ) ', '(_____)', '  ~~~  '],
                    [' ~~~ ', '(   )', ' ~~~ '],
                    ['_____', '(   )', '~~~~~'],
                    ['   ~~~   ', ' (     ) ', '(       )', ' ~~~~~~~ '],
                ]),
            })

        # Create DISTANT background clouds - behind everything, very slow, dim
        num_distant = max(2, self.width // 50)
        for i in range(num_distant):
            self._clouds.append({
                'x': random.uniform(0, self.width),
                'y': random.randint(5, 15),  # Mid-sky area behind buildings
                'speed': random.uniform(0.003, 0.01),  # Extremely slow drift
                'type': 'distant',
                'chars': random.choice([
                    # Hazy distant cloud
                    ['  .---.  ', ' (     ) ', '(       )', ' ~~~~~~~ '],
                    # Stretched distant cloud
                    ['    ~~~~    ', '  (      )  ', ' (        ) ', '~~~~~~~~~~~~'],
                    # Small distant puff
                    ['  ~~~  ', ' (   ) ', '~~~~~~'],
                    # Wispy distant cloud
                    ['   .~~~.   ', ' ~~     ~~ ', '~~~~~~~~~~~'],
                ]),
            })

        # Create HUGE foreground clouds - biggest, fastest, rendered on top
        num_foreground = max(1, self.width // 100)
        for i in range(num_foreground):
            self._clouds.append({
                'x': random.uniform(0, self.width),
                'y': random.randint(2, 10),  # Can go higher on screen
                'speed': random.uniform(0.4, 0.7),  # Very fast movement
                'type': 'foreground',
                'chars': random.choice([
                    # Massive storm cloud
                    ['          .--~~~~~~~--.          ',
                     '       .~~             ~~.       ',
                     '     .~                   ~.     ',
                     '   .~    ~~~~~~~~~~~        ~.   ',
                     '  (    ~~           ~~        )  ',
                     ' (   ~                 ~       ) ',
                     '(  (      ~~~~~~~       )      ) ',
                     ' (   ~               ~        )  ',
                     '  ~~                        ~~   ',
                     '    ~~~~~~~~~~~~~~~~~~~~~~~~~    '],
                    # Wide fluffy cloud
                    ['       .--~~~~~~~---.       ',
                     '    .~~             ~~.    ',
                     '  .~                   ~.  ',
                     ' (      ~~~~~~~~~~       ) ',
                     '(                         )',
                     ' ~~~~~~~~~~~~~~~~~~~~~~~~~ '],
                    # Giant cumulus
                    ['        .~~~~.        ',
                     '     .~~      ~~.     ',
                     '   .~            ~.   ',
                     '  (    ~~~~~~~~    )  ',
                     ' (                  ) ',
                     '(      ~~~~~~        )',
                     ' ~~~~~~~~~~~~~~~~~~~~ '],
                ]),
            })

    def _update_clouds(self):
        """Update cloud positions - drift in wind direction."""
        for cloud in self._clouds:
            # Clouds move in wind direction
            cloud['x'] += cloud['speed'] * self._wind_direction

            # Wrap around based on wind direction
            if cloud['type'] in ['main', 'cumulus', 'foreground', 'distant']:
                cloud_width = len(cloud['chars'][0]) if cloud['chars'] else 5
                if self._wind_direction > 0:
                    # Wind blowing right - wrap from left
                    if cloud['x'] > self.width + cloud_width:
                        cloud['x'] = -cloud_width
                else:
                    # Wind blowing left - wrap from right
                    if cloud['x'] < -cloud_width:
                        cloud['x'] = self.width + cloud_width
            else:
                # Wisps
                wisp_len = cloud.get('length', 5)
                if self._wind_direction > 0:
                    if cloud['x'] > self.width + wisp_len:
                        cloud['x'] = -wisp_len
                else:
                    if cloud['x'] < -wisp_len:
                        cloud['x'] = self.width + wisp_len

    def _update_steam(self):
        """Update steam effects from manholes and drains - rare occurrence."""
        self._steam_spawn_timer += 1

        # Rarely spawn steam (about 1 in 800 frames)
        if self._steam_spawn_timer >= random.randint(600, 1000):
            self._steam_spawn_timer = 0
            # Choose a random manhole or drain
            all_positions = self._manhole_positions + self._drain_positions
            if all_positions and len(self._steam_effects) < 2:  # Max 2 steam at once
                pos = random.choice(all_positions)
                self._steam_effects.append({
                    'x': pos[0],
                    'y': pos[1],
                    'frame': 0,
                    'timer': 0,
                    'duration': random.randint(40, 80),  # Short duration
                })

        # Update existing steam effects
        new_steam = []
        for steam in self._steam_effects:
            steam['timer'] += 1
            # Animate frame
            if steam['timer'] % 5 == 0:
                steam['frame'] = (steam['frame'] + 1) % len(self.STEAM_FRAMES)
            # Keep if not expired
            if steam['timer'] < steam['duration']:
                new_steam.append(steam)
        self._steam_effects = new_steam

    def _update_woman_red(self):
        """Update the Woman in Red event - rare Matrix iconic scene."""
        # Handle cooldown
        if self._woman_red_cooldown > 0:
            self._woman_red_cooldown -= 1
            return

        # If idle, check for rare trigger
        if self._woman_red_state == 'idle':
            # Rare trigger - about 1 in 2000 frames when not in cooldown
            if random.randint(1, 2000) == 1:
                self._woman_red_active = True
                self._woman_red_state = 'neo_morpheus_enter'
                self._woman_red_timer = 0
                # Neo and Morpheus enter from left
                self._neo_x = -10.0
                self._morpheus_x = -16.0  # Morpheus slightly behind
                # Woman starts off screen right
                self._woman_red_x = float(self.width + 10)
            return

        # Update timer and frame animation
        self._woman_red_timer += 1
        self._frame_timer += 1
        if self._frame_timer >= 4:  # Animation speed
            self._frame_timer = 0
            self._woman_red_frame = (self._woman_red_frame + 1) % 4
            self._neo_frame = (self._neo_frame + 1) % 4
            self._morpheus_frame = (self._morpheus_frame + 1) % 4
            self._agent_frame = (self._agent_frame + 1) % 4

        screen_center = self.width // 2

        if self._woman_red_state == 'neo_morpheus_enter':
            # Neo and Morpheus walk in from left and stop near center-left
            self._neo_x += 0.5
            self._morpheus_x += 0.5
            # Stop when Neo reaches about 1/3 of screen
            if self._neo_x >= screen_center - 20:
                self._woman_red_state = 'woman_enters'
                self._woman_red_timer = 0

        elif self._woman_red_state == 'woman_enters':
            # Woman in red walks from right toward center
            self._woman_red_x -= 0.4
            # When she reaches center, transition to passing
            if self._woman_red_x <= screen_center + 10:
                self._woman_red_state = 'woman_passes'
                self._woman_red_timer = 0

        elif self._woman_red_state == 'woman_passes':
            # Woman walks past Neo and Morpheus
            self._woman_red_x -= 0.4
            # When past them, stop and wave
            if self._woman_red_x <= self._neo_x - 5:
                self._woman_red_state = 'woman_waves'
                self._woman_red_timer = 0

        elif self._woman_red_state == 'woman_waves':
            # Woman stops and waves at Neo and Morpheus
            if self._woman_red_timer >= 60:  # Wave for about 60 frames
                self._woman_red_state = 'woman_pauses'
                self._woman_red_timer = 0

        elif self._woman_red_state == 'woman_pauses':
            # Brief pause before transformation
            if self._woman_red_timer >= 30:
                self._woman_red_state = 'transform'
                self._woman_red_timer = 0
                self._transform_frame = 0

        elif self._woman_red_state == 'transform':
            # Woman transforms into Agent Smith (glitch effect)
            if self._woman_red_timer % 8 == 0:
                self._transform_frame += 1
            if self._transform_frame >= len(self.TRANSFORM_FRAMES):
                self._woman_red_state = 'chase'
                self._woman_red_timer = 0
                self._agent_x = self._woman_red_x

        elif self._woman_red_state == 'chase':
            # Agent Smith chases Neo and Morpheus off screen left
            self._agent_x -= 0.8  # Agent runs fast
            self._neo_x -= 1.0  # Neo runs faster (escaping)
            self._morpheus_x -= 1.0  # Morpheus runs too
            # End when everyone is off screen
            if self._agent_x < -15 and self._neo_x < -15:
                self._woman_red_state = 'idle'
                self._woman_red_active = False
                self._woman_red_cooldown = 3000  # Long cooldown before next event

    def set_calm_mode(self, calm: bool):
        """Set calm mode - more debris/leaves, less mid-screen clutter."""
        self._calm_mode = calm

    def set_weather_mode(self, mode: WeatherMode):
        """Set the weather mode for road effects."""
        self._weather_mode = mode
        # Clear existing effects when weather changes
        self._road_effects = []

    def toggle_qte(self) -> bool:
        """Toggle QTE (meteor game) on/off. Returns new state."""
        self._qte_enabled = not self._qte_enabled
        # If disabling while active, cancel the current event
        if not self._qte_enabled and self._qte_active:
            self._qte_active = False
            self._qte_state = 'idle'
            self._qte_meteors = []
            self._qte_missiles = []
            self._qte_explosions = []
        return self._qte_enabled

    def toggle_mute(self) -> bool:
        """Toggle audio mute on/off. Returns new mute state."""
        self._audio_muted = not self._audio_muted
        return self._audio_muted

    def is_muted(self) -> bool:
        """Check if audio is muted."""
        return self._audio_muted

    def _play_car_sound(self, vehicle_type: str):
        """Play TTS car sound effect based on vehicle type."""
        if self._audio_muted or not AUDIO_ENGINE_AVAILABLE:
            return

        # Cooldown to prevent sound spam
        if self._car_sound_cooldown > 0:
            self._car_sound_cooldown -= 1
            return

        try:
            audio_engine = get_audio_engine()
            # Generate scene event audio for car
            audio_intent = audio_engine.generate_scene_event_audio('car')
            # Log the intent (actual TTS synthesis would happen elsewhere)
            logger.debug(f"Car sound: {audio_intent.onomatopoeia}")
            # Set cooldown (60 frames = ~1 second at 60fps)
            self._car_sound_cooldown = 60
        except Exception as e:
            logger.debug(f"Car sound error: {e}")

    def _update_ufo(self):
        """Update UFO cow abduction event - super rare."""
        # Handle cooldown
        if self._ufo_cooldown > 0:
            self._ufo_cooldown -= 1
            return

        # Very rare chance to trigger UFO event (about 1 in 50000 frames ~ once per 15 min)
        if not self._ufo_active and random.random() < 0.00002:
            self._ufo_active = True
            self._ufo_state = 'descend'
            self._ufo_timer = 0
            # Position UFO above a building (behind building gap)
            building1_right = self._building_x + len(self.BUILDING[0])
            building2_left = self._building2_x if self._building2_x > 0 else self.width
            gap_center = (building1_right + building2_left) // 2
            self._ufo_x = float(gap_center)
            self._ufo_y = -10.0  # Start above screen
            self._ufo_target_y = float(self.height // 2 + 5)  # Descend to mid-low area
            self._cow_y = self._ufo_target_y + 8  # Cow starts below UFO target

        if not self._ufo_active:
            return

        self._ufo_timer += 1

        if self._ufo_state == 'descend':
            # UFO descends slowly behind buildings
            self._ufo_y += 0.3
            if self._ufo_y >= self._ufo_target_y:
                self._ufo_y = self._ufo_target_y
                self._ufo_state = 'abduct'
                self._ufo_timer = 0

        elif self._ufo_state == 'abduct':
            # Cow rises up in tractor beam
            self._cow_y -= 0.15
            if self._cow_y <= self._ufo_y + len(self.UFO_SPRITE):
                self._ufo_state = 'ascend'
                self._ufo_timer = 0

        elif self._ufo_state == 'ascend':
            # UFO ascends with cow
            self._ufo_y -= 0.4
            self._cow_y = self._ufo_y + len(self.UFO_SPRITE)  # Cow attached
            if self._ufo_y < -15:
                self._ufo_state = 'idle'
                self._ufo_active = False
                self._ufo_cooldown = 36000  # ~10 minute cooldown

    def _update_wind(self):
        """Update wind effects - debris, leaves, and wisps blowing across screen."""
        street_y = self.height - 3
        curb_y = self.height - 4

        # Update wind direction timer - change direction every 3-15 minutes
        self._wind_direction_timer += 1
        if self._wind_direction_timer >= self._wind_direction_change_interval:
            self._wind_direction_timer = 0
            self._wind_direction *= -1  # Flip direction
            self._wind_direction_change_interval = random.randint(10800, 54000)

        # Update tree sway animation
        self._tree_sway_frame = (self._tree_sway_frame + 1) % 20

        # === DEBRIS SYSTEM (simple state machine) ===
        self._debris_spawn_timer += 1
        if self._debris_spawn_timer > 30:
            self._debris_spawn_timer = 0
            max_items = 12 if self._calm_mode else 6
            if len(self._debris) < max_items:
                # Pick debris type
                debris_type = random.choice(['leaf', 'leaf', 'newspaper', 'trash'])
                if debris_type == 'leaf':
                    char = random.choice(['*', '✦', '✧', '⁕', '@'])
                    color_type = 'leaf'
                elif debris_type == 'newspaper':
                    char = random.choice(['▪', '▫', '□', '▢'])
                    color_type = 'paper'
                else:
                    char = random.choice(['~', '°', '·'])
                    color_type = 'trash'

                # Spawn from upwind side
                if self._wind_direction > 0:
                    spawn_x = -2.0
                else:
                    spawn_x = float(self.width + 2)

                self._debris.append({
                    'x': spawn_x,
                    'y': float(random.choice([curb_y, street_y, street_y - 1])),
                    'char': char,
                    'color': color_type,
                    'speed': random.uniform(0.3, 0.8),
                    'state': 'blowing',
                    'timer': 0,
                    'stop_x': random.uniform(0.2, 0.7) * self.width,
                })

        # Update debris with state machine
        new_debris = []
        for d in self._debris:
            if d['state'] == 'blowing':
                d['x'] += d['speed'] * self._wind_direction
                # Check if reached stop point
                if self._wind_direction > 0 and d['x'] >= d['stop_x']:
                    d['state'] = 'slowing'
                elif self._wind_direction < 0 and d['x'] <= d['stop_x']:
                    d['state'] = 'slowing'
            elif d['state'] == 'slowing':
                d['speed'] *= 0.85
                d['x'] += d['speed'] * self._wind_direction
                if d['speed'] < 0.05:
                    d['state'] = 'stopped'
                    d['timer'] = 0
            elif d['state'] == 'stopped':
                d['timer'] += 1
                if d['timer'] > 60:  # Fixed duration to avoid random in tight loop
                    d['state'] = 'resuming'
                    d['timer'] = 0
            elif d['state'] == 'resuming':
                d['speed'] = min(d['speed'] + 0.02, 0.6)
                d['x'] += d['speed'] * self._wind_direction

            # Keep if on screen
            if -5 < d['x'] < self.width + 5:
                new_debris.append(d)
        self._debris = new_debris

        # === WIND WISPS ===
        max_wisps = 2 if self._calm_mode else 5
        self._wind_wisp_timer += 1
        if self._wind_wisp_timer > 45:
            self._wind_wisp_timer = 0
            if len(self._wind_wisps) < max_wisps:
                wisp_chars = ''.join([random.choice(self.WIND_WISPS) for _ in range(random.randint(3, 8))])
                spawn_x = -5.0 if self._wind_direction > 0 else float(self.width + 5)
                wisp_y = random.randint(3, max(4, self.height // 3))
                self._wind_wisps.append({
                    'x': spawn_x,
                    'y': float(wisp_y),
                    'chars': wisp_chars,
                    'speed': random.uniform(1.0, 2.5),
                })

        new_wisps = []
        for w in self._wind_wisps:
            w['x'] += w['speed'] * self._wind_direction
            if -10 < w['x'] < self.width + 10:
                new_wisps.append(w)
        self._wind_wisps = new_wisps

        # === LEAVES FROM TREES ===
        leaf_chance = 0.08 if self._calm_mode else 0.03
        max_leaves = 30 if self._calm_mode else 15
        for tree_x, tree_y in self._tree_positions:
            if random.random() < leaf_chance and len(self._leaves) < max_leaves:
                self._leaves.append({
                    'x': float(tree_x + random.randint(2, 7)),
                    'y': float(tree_y + random.randint(0, 3)),
                    'char': random.choice(self.DEBRIS_LEAVES),
                    'speed': random.uniform(0.5, 1.5),
                    'fall_speed': random.uniform(0.1, 0.3),
                    'wobble': random.uniform(0, 6.28),
                })

        new_leaves = []
        for leaf in self._leaves:
            leaf['x'] += leaf['speed'] * self._wind_direction
            leaf['y'] += leaf['fall_speed']
            leaf['wobble'] += 0.2
            leaf['x'] += math.sin(leaf['wobble']) * 0.3
            if -5 < leaf['x'] < self.width + 5 and leaf['y'] < street_y + 2:
                new_leaves.append(leaf)
        self._leaves = new_leaves

    def _update_qte(self):
        """Update meteor QTE event - quick time event."""
        # Skip if QTE is disabled
        if not self._qte_enabled:
            return

        # Handle cooldown
        if self._qte_cooldown > 0:
            self._qte_cooldown -= 1
            return

        ground_y = self.height - 5  # Ground level for meteor impact

        # If idle, check for rare trigger
        if self._qte_state == 'idle':
            # Rare trigger - about 1 in 3000 frames
            if random.randint(1, 3000) == 1:
                self._qte_active = True
                self._qte_state = 'warning'
                self._qte_timer = 0
                self._qte_score = 0
                self._qte_misses = 0
                self._qte_wave = 0
                self._qte_meteors = []
                self._qte_missiles = []
                self._qte_explosions = []
                self._qte_pending_keys = []
                # NPC appears on the left side
                self._qte_npc_x = 5
                self._qte_npc_message = "HELP! METEORS!"
                self._qte_message_timer = 0
                self._qte_last_meteor_positions = []  # Clear cleanup tracking
            return

        self._qte_timer += 1

        # Update message timer - auto-clear messages after duration
        if self._qte_npc_message:
            self._qte_message_timer += 1
            if self._qte_message_timer >= self._qte_message_duration:
                # Don't clear during warning or end states
                if self._qte_state == 'active':
                    self._qte_npc_message = ""
                    self._qte_message_timer = 0

        if self._qte_state == 'warning':
            # Warning phase - NPC appears and warns
            if self._qte_timer >= 60:
                self._qte_state = 'active'
                self._qte_timer = 0
                self._qte_wave = 1
                self._spawn_qte_wave()

        elif self._qte_state == 'active':
            # Update callout timer
            self._qte_callout_timer += 1

            # Spawn new callout if needed
            if self._qte_current_callout is None and self._qte_callout_timer >= 30:
                self._spawn_qte_callout()
                self._qte_callout_timer = 0

            # Update meteors (falling)
            new_meteors = []
            for meteor in self._qte_meteors:
                if meteor['called']:
                    meteor['y'] += meteor['speed']
                    # Check if meteor hit ground
                    if meteor['y'] >= ground_y:
                        self._qte_misses += 1
                        self._spawn_explosion(meteor['x'], ground_y, ground_impact=True)
                        # Clear current callout so next meteor can be called
                        self._qte_current_callout = None
                        continue
                new_meteors.append(meteor)
            self._qte_meteors = new_meteors

            # Update missiles (rising)
            new_missiles = []
            for missile in self._qte_missiles:
                missile['y'] -= missile['speed']
                # Check collision with meteors
                hit = False
                for meteor in self._qte_meteors:
                    if meteor['called'] and abs(missile['x'] - meteor['x']) < 4 and abs(missile['y'] - meteor['y']) < 3:
                        self._spawn_explosion(meteor['x'], meteor['y'])
                        self._qte_meteors.remove(meteor)
                        self._qte_score += 1
                        # Clear current callout so next meteor can be called
                        self._qte_current_callout = None
                        hit = True
                        break
                if not hit and missile['y'] > 3:
                    new_missiles.append(missile)
            self._qte_missiles = new_missiles

            # Update explosions
            new_explosions = []
            for exp in self._qte_explosions:
                exp['timer'] += 1
                if exp['timer'] % 4 == 0:
                    exp['frame'] += 1
                if exp['frame'] < len(self.EXPLOSION_FRAMES):
                    new_explosions.append(exp)
            self._qte_explosions = new_explosions

            # Check wave completion - wait for explosions to finish too
            active_meteors = [m for m in self._qte_meteors if m['called']]
            uncalled_meteors = [m for m in self._qte_meteors if not m['called']]
            explosions_done = len(self._qte_explosions) == 0
            if len(active_meteors) == 0 and len(uncalled_meteors) == 0 and len(self._qte_missiles) == 0 and explosions_done:
                self._qte_wave += 1
                if self._qte_wave > self._qte_total_waves:
                    # All waves complete
                    if self._qte_misses <= 2:
                        self._qte_state = 'success'
                    else:
                        self._qte_state = 'failure'
                    self._qte_timer = 0
                else:
                    self._spawn_qte_wave()

        elif self._qte_state == 'success':
            self._qte_npc_message = f"WE DID IT! Score: {self._qte_score}"
            if self._qte_timer >= 120:
                self._qte_state = 'idle'
                self._qte_active = False
                self._qte_cooldown = 5000

        elif self._qte_state == 'failure':
            self._qte_npc_message = f"THE CITY... Hits: {self._qte_score}"
            if self._qte_timer >= 120:
                self._qte_state = 'idle'
                self._qte_active = False
                self._qte_cooldown = 5000

    def _spawn_qte_wave(self):
        """Spawn a wave of meteors for QTE."""
        # Calculate column positions spread across screen
        col_width = (self.width - 40) // 5
        col_starts = [20 + i * col_width + col_width // 2 for i in range(5)]

        # Row heights (3 layers)
        row_heights = [8, 15, 22]  # Top, middle, bottom starting y

        # Spawn 2-4 meteors per wave
        num_meteors = min(self._qte_wave + 1, 4)
        used_positions = set()

        for _ in range(num_meteors):
            col = random.randint(0, 4)
            row = random.randint(0, 2)
            pos_key = (col, row)

            # Avoid duplicate positions
            attempts = 0
            while pos_key in used_positions and attempts < 10:
                col = random.randint(0, 4)
                row = random.randint(0, 2)
                pos_key = (col, row)
                attempts += 1

            used_positions.add(pos_key)

            # Determine meteor size based on row
            if row == 0:
                size = 'large'
                speed = 0.15
            elif row == 1:
                size = 'medium'
                speed = 0.2
            else:
                size = 'small'
                speed = 0.25

            self._qte_meteors.append({
                'x': col_starts[col],
                'y': float(row_heights[row]),
                'col': col,
                'row': row,
                'speed': speed,
                'size': size,
                'called': False,  # Not falling yet until called
            })

        self._qte_current_callout = None
        self._qte_callout_timer = 0

    def _spawn_qte_callout(self):
        """Spawn a new callout for the NPC to say."""
        # Find uncalled meteors
        uncalled = [m for m in self._qte_meteors if not m['called']]
        if not uncalled:
            self._qte_current_callout = None
            return

        # Pick a random uncalled meteor
        meteor = random.choice(uncalled)
        key = self.QTE_KEYS[meteor['col']]
        row_name = ['TOP', 'MID', 'LOW'][meteor['row']]

        self._qte_current_callout = (meteor['col'], meteor['row'], key)
        self._qte_npc_message = f"PRESS [{key}] {row_name}!"
        self._qte_message_timer = 0  # Reset message timer for new callout

        # Start the meteor falling
        meteor['called'] = True

    def _spawn_explosion(self, x: float, y: float, ground_impact: bool = False):
        """Spawn an explosion at the given position."""
        self._qte_explosions.append({
            'x': int(x),
            'y': int(y),
            'frame': 0,
            'timer': 0,
        })

        # If this is a ground impact, create damage overlay
        if ground_impact:
            self._spawn_damage_overlay(int(x), int(y))

    def _spawn_damage_overlay(self, x: int, y: int):
        """Spawn a damage overlay at impact site (lasts 5 minutes)."""
        damage_chars = ['░', '▒', '▓', '█', '#', 'X', '*']
        # Create a crater/damage pattern around impact point
        for dx in range(-3, 4):
            for dy in range(-2, 2):
                px = x + dx
                py = y + dy
                if 0 <= px < self.width - 1 and 0 <= py < self.height:
                    # Damage intensity decreases with distance
                    dist = abs(dx) + abs(dy)
                    if dist <= 4 and random.random() < (1.0 - dist * 0.15):
                        char = random.choice(damage_chars[:3] if dist > 2 else damage_chars)
                        self._damage_overlays.append({
                            'x': px,
                            'y': py,
                            'char': char,
                            'timer': 0,
                            'fade_time': self._damage_fade_time + random.randint(-1000, 1000),
                        })

    def _update_damage_overlays(self):
        """Update damage overlays - fade after 5 minutes."""
        new_overlays = []
        for overlay in self._damage_overlays:
            overlay['timer'] += 1
            if overlay['timer'] < overlay['fade_time']:
                new_overlays.append(overlay)
        self._damage_overlays = new_overlays

    def handle_qte_key(self, key: str) -> bool:
        """Handle a key press for the QTE event. Returns True if key was consumed."""
        if not self._qte_active or self._qte_state != 'active':
            return False

        if key not in self.QTE_KEYS:
            return False

        col = self.QTE_KEYS.index(key)

        # Check if there's a called meteor in this column to hit with missile
        called_meteors = [m for m in self._qte_meteors if m['called'] and m['col'] == col]
        if called_meteors:
            # Launch missile at the meteor
            meteor = called_meteors[0]
            col_width = (self.width - 40) // 5
            col_x = 20 + col * col_width + col_width // 2
            self._qte_missiles.append({
                'x': col_x,
                'y': float(self.height - 6),
                'target_col': col,
                'target_row': meteor['row'],
                'speed': 1.5,
            })
            # Clear current callout so NPC calls next one
            if self._qte_current_callout and self._qte_current_callout[0] == col:
                self._qte_current_callout = None
                self._qte_callout_timer = 20  # Short delay before next callout
            return True

        # Check if there's an uncalled meteor to activate
        uncalled = [m for m in self._qte_meteors if not m['called'] and m['col'] == col]
        if uncalled:
            # Activate the meteor (start it falling)
            meteor = uncalled[0]
            meteor['called'] = True
            return True

        return False

    def _update_skyline_windows(self):
        """Update animated skyline windows - toggle lights on/off."""
        # Get visibility bounds (set during _draw_distant_buildings)
        vis_left = getattr(self, '_skyline_visible_left', 0)
        vis_right = getattr(self, '_skyline_visible_right', self.width)

        # Get cafe bounds to avoid drawing windows behind cafe
        cafe_bounds = getattr(self, '_cafe_bounds', (0, 0, 0, 0))
        cafe_left, cafe_right, cafe_top, cafe_bottom = cafe_bounds

        for window in self._skyline_windows:
            if not window['animated']:
                continue

            window['timer'] += 1
            if window['timer'] >= window['toggle_time']:
                window['timer'] = 0
                window['on'] = not window['on']
                # Update the scene with new window state (only if in visible region and not behind cafe)
                px, py = window['x'], window['y']
                # Skip if behind cafe
                if cafe_left <= px <= cafe_right and cafe_top <= py <= cafe_bottom:
                    continue
                if vis_left <= px <= vis_right and 0 <= py < self.height:
                    if window['on']:
                        self.scene[py][px] = ('▪', Colors.RAT_YELLOW)
                    else:
                        self.scene[py][px] = ('▫', Colors.ALLEY_DARK)

    def _update_open_sign(self):
        """Update OPEN sign animation - lights up O, P, E, N then flashes."""
        self._open_sign_timer += 1
        if self._open_sign_timer >= self._open_sign_speed:
            self._open_sign_timer = 0
            self._open_sign_phase += 1
            if self._open_sign_phase > 9:  # 0-4 = lighting up, 5-9 = flashing
                self._open_sign_phase = 0

    def _render_cafe_sign(self, screen):
        """Render cafe sign with green SHELL CAFE and animated OPEN sign."""
        if not hasattr(self, 'cafe_x') or not hasattr(self, 'cafe_y'):
            return

        cafe_x = self.cafe_x
        cafe_y = self.cafe_y

        # Render big shell on roof - all green
        for row_idx in range(8):  # First 8 rows are the shell roof
            if row_idx < len(self.CAFE):
                for col_idx, char in enumerate(self.CAFE[row_idx]):
                    if char not in ' ':
                        px = cafe_x + col_idx
                        py = cafe_y + row_idx
                        if 0 <= px < self.width - 1 and 0 <= py < self.height:
                            try:
                                # All green for the shell
                                attr = curses.color_pair(Colors.CAFE_GREEN) | curses.A_BOLD
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                            except curses.error:
                                pass

        # Find the SHELL CAFE text in the sprite (row 8 after turtle shell)
        if len(self.CAFE) > 8:
            sign_row = self.CAFE[8]  # "  |     S H E L L  C A F E   |  "
            for col_idx, char in enumerate(sign_row):
                if char in 'SHELLCAFE':
                    px = cafe_x + col_idx
                    py = cafe_y + 8
                    if 0 <= px < self.width - 1 and 0 <= py < self.height:
                        try:
                            # Green bold for SHELL CAFE
                            attr = curses.color_pair(Colors.CAFE_GREEN) | curses.A_BOLD
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

        # Find and animate the OPEN sign (row 21 in CAFE sprite, after turtle shell)
        if len(self.CAFE) > 21:
            open_row = self.CAFE[21]  # "  |[                  OPEN ]|  "
            open_start = open_row.find('OPEN')
            if open_start != -1:
                # Determine which letters are lit based on phase
                # Phase 0: all off, 1: O, 2: OP, 3: OPE, 4: OPEN, 5-9: flash on/off
                letters = ['O', 'P', 'E', 'N']
                for i, letter in enumerate(letters):
                    px = cafe_x + open_start + i
                    py = cafe_y + 21
                    if 0 <= px < self.width - 1 and 0 <= py < self.height:
                        try:
                            if self._open_sign_phase == 0:
                                # All off - white/unlit
                                attr = curses.color_pair(Colors.ALLEY_MID)
                            elif self._open_sign_phase <= 4:
                                # Lighting up one by one
                                if i < self._open_sign_phase:
                                    # This letter is lit - bright yellow
                                    attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                                else:
                                    # Not lit yet - white/unlit
                                    attr = curses.color_pair(Colors.ALLEY_MID)
                            else:
                                # Flashing phase (5-9) - alternate on/off
                                if self._open_sign_phase % 2 == 1:
                                    attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                                else:
                                    attr = curses.color_pair(Colors.ALLEY_MID)
                            screen.attron(attr)
                            screen.addstr(py, px, letter)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_trees(self, screen):
        """Render trees on top of buildings (foreground layer). Tied to file_integrity health."""
        # Security canary: no trees if file integrity monitor is down
        if not self._security_canary.get('trees', True):
            return
        for tree_x, tree_y in self._tree_positions:
            # During Halloween, use spooky bare trees
            if self._halloween_mode:
                tree_sprite = self.SPOOKY_TREE
                for row_idx, row in enumerate(tree_sprite):
                    for col_idx, char in enumerate(row):
                        px = tree_x + col_idx
                        py = tree_y + row_idx
                        if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                            try:
                                # Spooky purple/dark colors
                                if char in '\\|/-+':
                                    attr = curses.color_pair(Colors.HALLOWEEN_PURPLE) | curses.A_DIM
                                else:
                                    attr = curses.color_pair(Colors.ALLEY_MID)
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                            except curses.error:
                                pass
            else:
                # Normal tree rendering
                if self._wind_direction > 0:
                    tree_sprite = self.TREE_WINDY_RIGHT
                else:
                    tree_sprite = self.TREE_WINDY_LEFT

                for row_idx, row in enumerate(tree_sprite):
                    for col_idx, char in enumerate(row):
                        px = tree_x + col_idx
                        py = tree_y + row_idx
                        if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                            try:
                                if char == '@':
                                    # Leaves - green
                                    attr = curses.color_pair(Colors.MATRIX_DIM)
                                elif char in '()|':
                                    # Trunk - brown/dark
                                    attr = curses.color_pair(Colors.SAND_DIM)
                                else:
                                    attr = curses.color_pair(Colors.ALLEY_MID)
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                            except curses.error:
                                pass

    def _render_pine_trees(self, screen):
        """Render pine trees on top of buildings (foreground layer)."""
        if not hasattr(self, '_pine_tree_positions'):
            return

        # Christmas light colors cycle through 4 patterns
        xmas_colors = [Colors.XMAS_RED, Colors.XMAS_GREEN, Colors.XMAS_BLUE, Colors.XMAS_YELLOW]

        for tree_x, tree_y in self._pine_tree_positions:
            # Use windy pine sprite based on wind direction
            if self._wind_direction > 0:
                tree_sprite = self.PINE_TREE_WINDY_RIGHT
            else:
                tree_sprite = self.PINE_TREE_WINDY_LEFT

            for row_idx, row in enumerate(tree_sprite):
                for col_idx, char in enumerate(row):
                    px = tree_x + col_idx
                    py = tree_y + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        try:
                            # Check for Christmas lights on branch rows (rows 1-6 have branches)
                            is_light = False
                            if self._christmas_mode and row_idx >= 1 and row_idx <= 6:
                                # Place lights on alternating positions along branches
                                # Pattern shifts with frame to create "chasing" effect
                                light_pattern = (col_idx + self._christmas_light_frame) % 3 == 0
                                if char in '/\\' and light_pattern:
                                    is_light = True
                                    # Cycle color based on position and frame
                                    color_idx = (col_idx + row_idx + self._christmas_light_frame) % 4
                                    attr = curses.color_pair(xmas_colors[color_idx]) | curses.A_BOLD
                                    screen.attron(attr)
                                    screen.addstr(py, px, 'o')  # Light bulb
                                    screen.attroff(attr)

                            if not is_light:
                                if char == '*':
                                    # Star on top - yellow (extra bright during Christmas)
                                    attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                                    if self._christmas_mode:
                                        # Blink the star
                                        if self._christmas_light_frame % 2 == 0:
                                            attr |= curses.A_BLINK if hasattr(curses, 'A_BLINK') else 0
                                elif char in '/\\|':
                                    # Pine needles and trunk - green
                                    attr = curses.color_pair(Colors.MATRIX_DIM)
                                else:
                                    attr = curses.color_pair(Colors.ALLEY_MID)
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_fireworks(self, screen):
        """Render 4th of July fireworks in the sky."""
        if not self._july4th_mode:
            return
        for fw in self._fireworks:
            # Get sprite based on type
            if fw['type'] == 'burst':
                sprite = self.FIREWORK_BURST
            elif fw['type'] == 'star':
                sprite = self.FIREWORK_STAR
            else:
                sprite = self.FIREWORK_SHOWER
            # Calculate fade based on frame
            if fw['frame'] < 5:
                attr = curses.color_pair(fw['color']) | curses.A_BOLD
            elif fw['frame'] < 12:
                attr = curses.color_pair(fw['color'])
            else:
                attr = curses.color_pair(fw['color']) | curses.A_DIM
            # Render sprite centered on position
            for row_idx, row in enumerate(sprite):
                for col_idx, char in enumerate(row):
                    px = fw['x'] - len(row) // 2 + col_idx
                    py = fw['y'] + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char not in ' ':
                        try:
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_pumpkins(self, screen):
        """Render Halloween pumpkins with flickering glow."""
        if not self._halloween_mode:
            return
        for pumpkin_x, pumpkin_y in self._pumpkin_positions:
            # Flicker effect based on glow frame
            if self._pumpkin_glow_frame == 0:
                attr = curses.color_pair(Colors.HALLOWEEN_ORANGE) | curses.A_BOLD
            elif self._pumpkin_glow_frame == 1:
                attr = curses.color_pair(Colors.HALLOWEEN_ORANGE)
            else:
                attr = curses.color_pair(Colors.HALLOWEEN_ORANGE) | curses.A_DIM
            for row_idx, row in enumerate(self.PUMPKIN):
                for col_idx, char in enumerate(row):
                    px = pumpkin_x + col_idx
                    py = pumpkin_y + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char not in ' ':
                        try:
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_easter_eggs(self, screen):
        """Render Easter eggs hidden around the scene."""
        if not self._easter_mode:
            return
        egg_colors = [Colors.EASTER_PINK, Colors.EASTER_CYAN, Colors.EASTER_LAVENDER,
                      Colors.XMAS_YELLOW, Colors.XMAS_GREEN]
        for egg_x, egg_y, color_idx in self._easter_egg_positions:
            attr = curses.color_pair(egg_colors[color_idx % len(egg_colors)]) | curses.A_BOLD
            for row_idx, row in enumerate(self.EASTER_EGG):
                for col_idx, char in enumerate(row):
                    px = egg_x + col_idx
                    py = egg_y + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char not in ' ':
                        try:
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_constellation(self, screen):
        """Render seasonal constellation in the sky. Tied to memory_monitor health."""
        # Security canary: no stars if memory monitor is down
        if not self._security_canary.get('stars', True):
            return

        if not self._constellation:
            return

        # Position constellation in upper sky area
        base_x = self._constellation_x
        base_y = self._constellation_y

        stars = self._constellation.get('stars', [])
        for dx, dy, brightness in stars:
            px = base_x + dx
            py = base_y + dy

            # Expanded sky area for larger 5x constellations
            if 0 <= px < self.width - 1 and 1 <= py < self.height // 2:  # Keep in upper half
                try:
                    # Subtle star characters based on brightness
                    if brightness == 2:
                        # Bright star - alternates with twinkle
                        if self._star_twinkle_frame == 0:
                            char = '*'
                            attr = curses.color_pair(Colors.ALLEY_LIGHT)
                        elif self._star_twinkle_frame == 1:
                            char = '+'
                            attr = curses.color_pair(Colors.GREY_BLOCK)
                        elif self._star_twinkle_frame == 2:
                            char = '*'
                            attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_DIM
                        else:
                            char = '·'
                            attr = curses.color_pair(Colors.GREY_BLOCK) | curses.A_DIM
                    else:
                        # Dim star - more subtle, less twinkle
                        if self._star_twinkle_frame % 2 == 0:
                            char = '·'
                            attr = curses.color_pair(Colors.GREY_BLOCK) | curses.A_DIM
                        else:
                            char = '.'
                            attr = curses.color_pair(Colors.ALLEY_MID) | curses.A_DIM

                    screen.attron(attr)
                    screen.addstr(py, px, char)
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_dotted_fog(self, screen):
        """Render dotted fog layer (behind clouds).
        Uses persistent fog positions that slowly drift for smooth animation.
        """
        # Initialize persistent fog state if needed
        if not hasattr(self, '_fog_particles') or len(self._fog_particles) == 0:
            self._fog_particles = []
            fog_chars = ['░', '·', '.', '∙']
            # Create fog particles with positions and drift speeds
            for row in range(3, 9):
                density = max(0.03, 0.18 - (row - 3) * 0.03)
                for x in range(self.width - 1):
                    if random.random() < density:
                        self._fog_particles.append({
                            'x': float(x),
                            'y': row,
                            'char': random.choice(fog_chars),
                            'drift_x': random.uniform(-0.02, 0.02),  # Very slow drift
                        })
            self._fog_update_counter = 0

        # Only update fog positions every 10 frames for slow movement
        self._fog_update_counter = getattr(self, '_fog_update_counter', 0) + 1
        if self._fog_update_counter >= 10:
            self._fog_update_counter = 0
            for particle in self._fog_particles:
                particle['x'] += particle['drift_x']
                # Wrap around screen edges
                if particle['x'] < 0:
                    particle['x'] = self.width - 2
                elif particle['x'] >= self.width - 1:
                    particle['x'] = 0

        # Render fog particles
        for particle in self._fog_particles:
            px = int(particle['x'])
            py = particle['y']
            if 0 <= px < self.width - 1 and 0 <= py < self.height:
                try:
                    attr = curses.color_pair(Colors.GREY_BLOCK) | curses.A_DIM
                    screen.attron(attr)
                    screen.addstr(py, px, particle['char'])
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_clouds(self, screen):
        """Render cloud layer."""
        # Security canary: no clouds if resource monitor is down
        if not self._security_canary.get('clouds', True):
            return
        for cloud in self._clouds:
            if cloud['type'] in ['main', 'cumulus']:
                # Render multi-line cloud (main or cumulus)
                # Cumulus clouds are brighter (no A_DIM)
                for row_idx, row in enumerate(cloud['chars']):
                    for col_idx, char in enumerate(row):
                        px = int(cloud['x']) + col_idx
                        py = cloud['y'] + row_idx
                        if 0 <= px < self.width - 1 and 0 <= py < self.height and char not in ' ':
                            try:
                                if cloud['type'] == 'cumulus':
                                    # Cumulus clouds are brighter/closer
                                    attr = curses.color_pair(Colors.ALLEY_LIGHT)
                                else:
                                    attr = curses.color_pair(Colors.GREY_BLOCK) | curses.A_DIM
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                            except curses.error:
                                pass
            elif cloud['type'] == 'wisp':
                # Render wisp
                for i in range(cloud['length']):
                    px = int(cloud['x']) + i
                    py = cloud['y']
                    if 0 <= px < self.width - 1 and 0 <= py < self.height:
                        try:
                            attr = curses.color_pair(Colors.GREY_BLOCK) | curses.A_DIM
                            screen.attron(attr)
                            screen.addstr(py, px, cloud['char'])
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_foreground_clouds(self, screen):
        """Render large foreground clouds on top of the scene."""
        for cloud in self._clouds:
            if cloud['type'] == 'foreground':
                # Render huge foreground cloud - brightest, on top
                for row_idx, row in enumerate(cloud['chars']):
                    for col_idx, char in enumerate(row):
                        px = int(cloud['x']) + col_idx
                        py = cloud['y'] + row_idx
                        if 0 <= px < self.width - 1 and 0 <= py < self.height and char not in ' ':
                            try:
                                # Foreground clouds are brightest white
                                attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_BOLD
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                            except curses.error:
                                pass

    def _render_distant_clouds(self, screen):
        """Render distant background clouds - behind everything, very dim."""
        for cloud in self._clouds:
            if cloud['type'] == 'distant':
                # Render distant cloud - very dim, behind everything
                for row_idx, row in enumerate(cloud['chars']):
                    for col_idx, char in enumerate(row):
                        px = int(cloud['x']) + col_idx
                        py = cloud['y'] + row_idx
                        if 0 <= px < self.width - 1 and 0 <= py < self.height and char not in ' ':
                            try:
                                # Distant clouds are very dim grey
                                attr = curses.color_pair(Colors.MATRIX_FADE2) | curses.A_DIM
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                            except curses.error:
                                pass

    def _render_ufo(self, screen):
        """Render UFO cow abduction event."""
        if not self._ufo_active:
            return

        ufo_x = int(self._ufo_x) - len(self.UFO_SPRITE[0]) // 2
        ufo_y = int(self._ufo_y)

        # Render tractor beam first (behind cow)
        if self._ufo_state in ('abduct', 'ascend'):
            beam_x = ufo_x + (len(self.UFO_SPRITE[0]) - len(self.TRACTOR_BEAM[0])) // 2
            beam_y = ufo_y + len(self.UFO_SPRITE)
            for row_idx, row in enumerate(self.TRACTOR_BEAM):
                # Repeat beam to reach cow
                py = beam_y + row_idx
                while py < int(self._cow_y):
                    for col_idx, char in enumerate(row):
                        px = beam_x + col_idx
                        if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                            try:
                                # Green tractor beam
                                attr = curses.color_pair(Colors.MATRIX_DIM)
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                            except curses.error:
                                pass
                    py += len(self.TRACTOR_BEAM)

        # Render UFO
        for row_idx, row in enumerate(self.UFO_SPRITE):
            py = ufo_y + row_idx
            for col_idx, char in enumerate(row):
                px = ufo_x + col_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    try:
                        if char in 'o*':
                            # Lights - yellow
                            attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                        else:
                            # Body - silver/white
                            attr = curses.color_pair(Colors.ALLEY_LIGHT)
                        screen.attron(attr)
                        screen.addstr(py, px, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

        # Render cow (during abduct or ascend)
        if self._ufo_state in ('abduct', 'ascend'):
            cow_x = int(self._ufo_x) - len(self.COW_SPRITE[0]) // 2
            cow_y = int(self._cow_y)
            for row_idx, row in enumerate(self.COW_SPRITE):
                py = cow_y + row_idx
                for col_idx, char in enumerate(row):
                    px = cow_x + col_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        try:
                            attr = curses.color_pair(Colors.ALLEY_MID)
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _generate_scene(self):
        """Generate scene with buildings, dumpster, box, curb, street, and street lights."""
        if self.width <= 0 or self.height <= 0:
            self.scene = []
            return

        # Clear window position tracking for layering
        self._window_interior_positions = []
        self._window_frame_positions = []

        # Initialize with empty space
        self.scene = [[(' ', Colors.ALLEY_DARK) for _ in range(self.width)]
                      for _ in range(self.height)]

        # Street and curb moved up 2 rows from bottom
        street_y = self.height - 3
        curb_y = self.height - 4

        # Ground level is just above curb (moved up from previous position)
        ground_y = curb_y - 1

        # Draw solid cloud cover at top (double line)
        self._draw_cloud_cover()

        # Position seasonal constellation in the sky (between buildings, below clouds)
        # Use seeded random for consistent daily positioning
        random.seed(self._scene_seed)
        # Center constellations on screen (5x scaled, largest ~75 chars wide)
        # Center horizontally with some variance
        center_x = self.width // 2 - 20  # Offset for constellation width
        self._constellation_x = center_x + random.randint(-10, 10)
        self._constellation_y = random.randint(15, 22)  # Mid-sky position
        # Reset random to time-based for dynamic elements
        random.seed()

        # Calculate building positions first for overlap avoidance
        self._building_x = 9
        building1_right = self._building_x + len(self.BUILDING[0])
        self._building2_x = self.width - len(self.BUILDING2[0]) - 11 if self.width > 60 else self.width

        # Calculate cafe position early for overlap avoidance (must match line ~4001)
        gap_center = (building1_right + self._building2_x) // 2
        cafe_width = len(self.CAFE[0])
        cafe_height = len(self.CAFE)
        cafe_left = gap_center - cafe_width // 2 - 28  # Match actual cafe_x calculation
        cafe_right = cafe_left + cafe_width
        cafe_top = ground_y - cafe_height - 3  # Match actual cafe_y calculation
        cafe_bottom = cafe_top + cafe_height

        # Draw distant buildings FIRST (furthest back) - only in gap between buildings
        # Pass cafe bounds so cityscape windows don't show through cafe
        self._draw_distant_buildings(gap_center, ground_y, building1_right, self._building2_x,
                                     cafe_left, cafe_right, cafe_top, cafe_bottom)

        # Draw mid-range buildings (behind big buildings, avoid cafe area)
        self._draw_midrange_buildings(ground_y, cafe_left, cafe_right)

        # Draw first building wireframe in background (left side)
        # Position building so its bottom edge is at ground level
        # Shifted 6 chars toward center (right)
        # Uses grey blocks on bottom half story, red bricks on upper portions
        self._building_x = 9
        self._building_y = ground_y - len(self.BUILDING) + 1
        self._draw_building(self.BUILDING, self._building_x, max(1, self._building_y))
        self._building_bottom_y = ground_y  # Store for rat constraint
        # Add side walls to building 1 (left side lighter, right side darker/shadow)
        self._draw_building_side_walls(self._building_x, max(1, self._building_y),
                                       len(self.BUILDING[0]), len(self.BUILDING), 'left')
        self._draw_building_side_walls(self._building_x, max(1, self._building_y),
                                       len(self.BUILDING[0]), len(self.BUILDING), 'right')

        # Draw second building on the right side
        # Shifted 6 chars toward center (left)
        # Uses grey blocks on bottom half story, red bricks on upper portions
        if self.width > 60:
            self._building2_x = self.width - len(self.BUILDING2[0]) - 11
            self._building2_y = ground_y - len(self.BUILDING2) + 1
            self._draw_building(self.BUILDING2, self._building2_x, max(1, self._building2_y))
            # Add side walls to building 2
            self._draw_building_side_walls(self._building2_x, max(1, self._building2_y),
                                           len(self.BUILDING2[0]), len(self.BUILDING2), 'left')
            self._draw_building_side_walls(self._building2_x, max(1, self._building2_y),
                                           len(self.BUILDING2[0]), len(self.BUILDING2), 'right')

        # Setup ALL building windows with unique scenes and light states
        # Big windows are [========] (8 chars), small are [====] (4 chars)
        self._all_windows = []
        self._building_window_lights = []

        # Building 1 window definitions: (col, width, is_big)
        b1_windows = [
            (4, 8, True), (17, 4, False), (24, 4, False), (37, 8, True), (50, 4, False)
        ]
        b1_window_rows = [7, 13, 19, 25, 31]  # Rows with window tops

        # Building 2 window definitions
        b2_windows = [
            (6, 8, True), (19, 4, False), (30, 8, True), (43, 4, False)
        ]

        # Create all windows for building 1
        for row in b1_window_rows:
            for col, width, is_big in b1_windows:
                wx = self._building_x + col
                wy = max(1, self._building_y) + row
                if 0 < wx < self.width - 5 and 0 < wy < self.height - 5:
                    # Assign unique scene and random light state
                    scene_type = random.choice(self._window_scene_types)
                    # More varied brightness - use discrete levels
                    light_on = random.random() > 0.25  # 75% chance light is on
                    if light_on:
                        # Discrete brightness levels: dim (0.3), medium (0.6), bright (1.0)
                        brightness = random.choice([0.3, 0.5, 0.7, 0.9, 1.0])
                    else:
                        brightness = 0.0
                    window = {
                        'x': wx, 'y': wy, 'width': width, 'height': 3,
                        'building': 1, 'scene_type': scene_type,
                        'light_on': light_on, 'brightness': brightness,
                        'is_big': is_big, 'scene_chars': self._generate_window_scene(scene_type, width)
                    }
                    self._all_windows.append(window)
                    # Only big windows get light glow effect (moved up 2 rows from window top)
                    if is_big:
                        self._building_window_lights.append((wx + width // 2, wy - 1))

        # Create all windows for building 2
        if self.width > 60:
            for row in b1_window_rows:  # Same row pattern
                for col, width, is_big in b2_windows:
                    wx = self._building2_x + col
                    wy = max(1, self._building2_y) + row
                    if 0 < wx < self.width - 5 and 0 < wy < self.height - 5:
                        scene_type = random.choice(self._window_scene_types)
                        light_on = random.random() > 0.25
                        if light_on:
                            brightness = random.choice([0.3, 0.5, 0.7, 0.9, 1.0])
                        else:
                            brightness = 0.0
                        window = {
                            'x': wx, 'y': wy, 'width': width, 'height': 3,
                            'building': 2, 'scene_type': scene_type,
                            'light_on': light_on, 'brightness': brightness,
                            'is_big': is_big, 'scene_chars': self._generate_window_scene(scene_type, width)
                        }
                        self._all_windows.append(window)
                        # Only big windows get light glow
                        if is_big:
                            self._building_window_lights.append((wx + width // 2, wy - 1))

        # Initialize flicker brightness from window states (only for windows with lights)
        self._building_window_flicker = []
        for w in self._all_windows:
            if w['is_big']:
                self._building_window_flicker.append(w['brightness'])

        # Draw street lights between buildings (in the gap)
        self._draw_street_lights(ground_y)

        # Draw curb/sidewalk - store positions for front-layer rendering
        # Exclude area between traffic light pole and Claude St sign pole (fill with bars)
        self._sidewalk_positions = []
        # Traffic light is at box_x + len(BOX[0]) + 96, street sign will be calculated later
        # We'll update this after street sign position is known
        traffic_light_pole_x = self.box_x + len(self.BOX[0]) + 96 if hasattr(self, 'box_x') else self.width - 20
        for x in range(self.width - 1):
            # Store sidewalk position for rendering on top of scene (but behind sprites)
            self._sidewalk_positions.append((x, curb_y, '▄', Colors.ALLEY_MID))
        # Store traffic light x for later sidewalk exclusion update
        self._traffic_light_pole_x = traffic_light_pole_x

        # Draw street surface (two rows)
        for x in range(self.width - 1):
            self.scene[street_y][x] = ('▓', Colors.ALLEY_DARK)
            if street_y + 1 < self.height:
                self.scene[street_y + 1][x] = ('▓', Colors.ALLEY_DARK)

        # Add dashed lane markings on bottom street row (every 4 chars, 2 on 2 off)
        if self.width > 30:
            lane_y = street_y + 1 if street_y + 1 < self.height else street_y
            for x in range(0, self.width - 1, 4):
                if x + 1 < self.width - 1:
                    self.scene[lane_y][x] = ('=', Colors.RAT_YELLOW)
                    self.scene[lane_y][x + 1] = ('=', Colors.RAT_YELLOW)

        # Add manholes to the street (every ~30 chars)
        self._manhole_positions = []
        for x in range(15, self.width - 15, 30):
            manhole_x = x + random.randint(-3, 3)  # Slight random offset
            if 5 < manhole_x < self.width - 10:
                self._manhole_positions.append((manhole_x, street_y))
                # Draw manhole cover
                for i, char in enumerate(self.MANHOLE[0]):
                    if manhole_x + i < self.width - 1:
                        self.scene[street_y][manhole_x + i] = (char, Colors.ALLEY_MID)

        # Add drains along the curb (every ~25 chars)
        self._drain_positions = []
        for x in range(10, self.width - 10, 25):
            drain_x = x + random.randint(-2, 2)  # Slight random offset
            if 3 < drain_x < self.width - 8:
                self._drain_positions.append((drain_x, curb_y))
                # Draw drain
                for i, char in enumerate(self.DRAIN[0]):
                    if drain_x + i < self.width - 1:
                        self.scene[curb_y][drain_x + i] = (char, Colors.ALLEY_DARK)

        # Place trees - one on left, two in front of right building
        self._tree_positions = []
        self._pine_tree_positions = []  # Pine trees stored separately
        tree_height = len(self.TREE)
        tree_width = len(self.TREE[0])
        pine_height = len(self.PINE_TREE)
        building2_left = self._building2_x if self._building2_x > 0 else self.width
        building2_width = len(self.BUILDING2[0]) if self.BUILDING2 else 60

        # Tree 1: in front of left building
        tree1_x = self._building_x + 15
        # Tree 2: in front of right building (center-left of building2)
        tree2_x = building2_left + building2_width // 3
        # Tree 3: in front of right building (center-right of building2)
        tree3_x = building2_left + 2 * building2_width // 3

        for tree_x in [tree1_x, tree2_x, tree3_x]:
            # Check tree fits and doesn't overlap with cafe
            cafe_left = getattr(self, 'cafe_x', 0)
            cafe_right = cafe_left + len(self.CAFE[0]) if hasattr(self, 'cafe_x') else 0
            overlaps_cafe = cafe_left - 5 < tree_x < cafe_right + 5

            # Allow trees in front of building2 (not just in the gap)
            if tree_x > building1_right + 2 and tree_x + tree_width < self.width - 2 and not overlaps_cafe:
                tree_y = ground_y - tree_height + 1
                self._tree_positions.append((tree_x, tree_y))
                self._draw_tree(tree_x, tree_y)

        # Note: Pine tree is placed after cafe is drawn (below)

        # Place dumpster to the LEFT of building 1 (moved up 4 rows)
        self.dumpster_x = 2
        self.dumpster_y = ground_y - len(self.DUMPSTER) + 1 - 4  # Moved up 4 rows
        self._draw_sprite(self.DUMPSTER, self.dumpster_x, self.dumpster_y, Colors.ALLEY_MID)

        # Place box in front of left building (moved up 4 rows)
        building1_right = self._building_x + len(self.BUILDING[0])
        building2_left = self._building2_x if self._building2_x > 0 else self.width
        gap_center = (building1_right + building2_left) // 2
        self.box_x = self._building_x + 5  # In front of left building
        self.box_y = ground_y - len(self.BOX) + 1 - 4  # Moved up 4 rows
        self._draw_box_with_label(self.box_x, self.box_y)

        # Place blue mailbox near building 1 (shifted 2 chars left)
        self.mailbox_x = self._building_x + len(self.BUILDING[0]) + 1
        self.mailbox_y = ground_y - len(self.MAILBOX) + 1
        self._draw_sprite(self.MAILBOX, self.mailbox_x, self.mailbox_y, Colors.ALLEY_BLUE)

        # Calculate door positions for pedestrian interactions
        self._door_positions = []
        # Building 1 doors
        for door_offset in self.BUILDING_DOOR_OFFSETS:
            door_x = self._building_x + door_offset
            self._door_positions.append({'building': 1, 'x': door_x, 'y': ground_y})
        # Building 2 doors
        for door_offset in self.BUILDING2_DOOR_OFFSETS:
            door_x = self._building2_x + door_offset
            self._door_positions.append({'building': 2, 'x': door_x, 'y': ground_y})
        # Cafe door (center bottom of cafe)
        cafe_door_x = gap_center - 28 + 14  # Approximate door position
        self._door_positions.append({'building': 'cafe', 'x': cafe_door_x, 'y': ground_y})

        # Calculate cafe position first (shifted 11 chars left)
        self.cafe_x = gap_center - len(self.CAFE[0]) // 2 - 28  # 10 more left (was -18)
        self.cafe_y = ground_y - len(self.CAFE) - 3  # Moved up 4 rows total (2 more)

        # Place well-lit Cafe between buildings (center of gap)
        self._draw_cafe(self.cafe_x, self.cafe_y)

        # Pine tree: to the right of Shell Cafe, 4 rows higher than regular trees
        cafe_right = self.cafe_x + len(self.CAFE[0])
        pine_height = len(self.PINE_TREE)
        pine_x = cafe_right + 3  # 3 chars to the right of cafe
        pine_y = ground_y - pine_height + 1 - 4  # 4 rows higher than regular trees
        if pine_x + len(self.PINE_TREE[0]) < self.width - 2 and pine_y > 0:
            self._pine_tree_positions.append((pine_x, pine_y))
            self._draw_pine_tree(pine_x, pine_y)

        # Place pumpkins during Halloween (near trees and buildings)
        if self._halloween_mode:
            self._pumpkin_positions = []
            # Pumpkin near each tree
            for tree_x, tree_y in self._tree_positions:
                pumpkin_x = tree_x + random.randint(-3, 3)
                pumpkin_y = ground_y - 3  # On ground level
                if 0 < pumpkin_x < self.width - 10:
                    self._pumpkin_positions.append((pumpkin_x, pumpkin_y))
            # Extra pumpkin near cafe door
            self._pumpkin_positions.append((self.cafe_x + 2, ground_y - 3))

        # Place easter eggs during Easter (hidden around scene)
        if self._easter_mode:
            self._easter_egg_positions = []
            # Hide eggs near trees
            for i, (tree_x, tree_y) in enumerate(self._tree_positions):
                egg_x = tree_x + random.randint(-2, 5)
                egg_y = ground_y - 3
                if 0 < egg_x < self.width - 6:
                    self._easter_egg_positions.append((egg_x, egg_y, i))
            # Hide eggs near cafe
            self._easter_egg_positions.append((self.cafe_x + 5, ground_y - 3, 3))
            # Hide eggs near buildings
            if hasattr(self, '_building_x'):
                self._easter_egg_positions.append((self._building_x + 8, ground_y - 3, 4))

        # Draw crosswalk between cafe and right building (shifted right 12 chars total)
        # cafe_right already calculated above
        self._crosswalk_x = cafe_right + 13  # +12 to move vanishing street right
        self._crosswalk_width = 32  # Store for car occlusion
        self._draw_crosswalk(self._crosswalk_x, curb_y, street_y)

        # Draw street sign near crosswalk (shifted 12 chars right)
        sign_x = self._crosswalk_x + self._crosswalk_width // 2 - len(self.STREET_SIGN[0]) // 2 + 16
        sign_y = ground_y - len(self.STREET_SIGN) + 1
        self._street_sign_x = sign_x  # Store for sidewalk exclusion
        self._draw_street_sign(sign_x, sign_y)

        # Update sidewalk to exclude area between traffic light and Claude St poles
        # Fill with vertical bars instead
        if hasattr(self, '_traffic_light_pole_x') and hasattr(self, '_street_sign_x'):
            exclude_start = min(self._traffic_light_pole_x, self._street_sign_x) + 2
            exclude_end = max(self._traffic_light_pole_x, self._street_sign_x) - 1
            updated_sidewalk = []
            for (x, y, char, color) in self._sidewalk_positions:
                if exclude_start <= x <= exclude_end:
                    # Replace sidewalk with vertical bars in this area
                    updated_sidewalk.append((x, y, '|', Colors.ALLEY_DARK))
                else:
                    updated_sidewalk.append((x, y, char, color))
            self._sidewalk_positions = updated_sidewalk

        # Add building street numbers
        self._draw_building_numbers(ground_y)

    def _draw_street_sign(self, x: int, y: int):
        """Draw a street sign at the given position."""
        for row_idx, row in enumerate(self.STREET_SIGN):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    if char in '.-\'|':
                        self.scene[py][px] = (char, Colors.ALLEY_MID)
                    else:
                        # Text - green like street signs
                        self.scene[py][px] = (char, Colors.MATRIX_DIM)

    def _draw_building_numbers(self, ground_y: int):
        """Draw building street numbers beside doorways in gold."""
        # Building 1 numbers - to the side of doors
        # Find door positions in BUILDING sprite
        door_row = len(self.BUILDING) - 5  # Row beside doors (middle of door)
        # Draw numbers to the LEFT side of each door
        number1_x = self._building_x + 8  # Left side of first door
        number2_x = self._building_x + 36  # Left side of second door
        number_y = self._building_y + door_row - 2  # Raised 2 rows

        # Building 1 - odd side (741, 743) - 3 digit vertical numbers beside door
        numbers1 = "741"
        numbers2 = "743"
        for i, char in enumerate(numbers1):
            py = number_y + i
            if 0 <= number1_x < self.width - 1 and 0 <= py < self.height:
                self.scene[py][number1_x] = (char, Colors.DOOR_KNOB_GOLD)
        for i, char in enumerate(numbers2):
            py = number_y + i
            if 0 <= number2_x < self.width - 1 and 0 <= py < self.height:
                self.scene[py][number2_x] = (char, Colors.DOOR_KNOB_GOLD)

        # Building 2 numbers - even side (742, 744)
        if self._building2_x > 0:
            number3_x = self._building2_x + 8  # Left side of first door
            number4_x = self._building2_x + 36  # Left side of second door
            number_y2 = self._building2_y + door_row - 2  # Raised 2 rows
            numbers3 = "742"
            numbers4 = "744"
            for i, char in enumerate(numbers3):
                py = number_y2 + i
                if 0 <= number3_x < self.width - 1 and 0 <= py < self.height:
                    self.scene[py][number3_x] = (char, Colors.DOOR_KNOB_GOLD)
            for i, char in enumerate(numbers4):
                py = number_y2 + i
                if 0 <= number4_x < self.width - 1 and 0 <= py < self.height:
                    self.scene[py][number4_x] = (char, Colors.DOOR_KNOB_GOLD)

    def _generate_window_scene(self, scene_type: str, width: int) -> List[str]:
        """Generate unique mini scene content for a window based on type and width."""
        # Each scene type returns 3 rows of characters to fill the window interior
        # Width is 8 for big windows, 4 for small windows

        if width >= 8:  # Big windows
            if scene_type == 'empty':
                return ['        ', '        ', '        ']
            elif scene_type == 'plant':
                return ['  ,@,   ', '  |#|   ', '  ~~~   ']
            elif scene_type == 'lamp':
                return ['   /\\   ', '   ||   ', '  ____  ']
            elif scene_type == 'tv':
                return [' [====] ', ' [    ] ', '  ~~~~  ']
            elif scene_type == 'cat':
                return ['        ', ' /\\_/\\  ', ' (o.o)  ']
            elif scene_type == 'bookshelf':
                return ['||||||||', '|--||--|', '||||||||']
            elif scene_type == 'desk':
                return ['  ___   ', ' |   |  ', ' |___|  ']
            elif scene_type == 'curtains':
                return ['|\\    /|', '| \\  / |', '|  \\/  |']
            elif scene_type == 'blinds':
                return ['========', '========', '========']
            elif scene_type == 'person_standing':
                return ['   O    ', '  /|\\   ', '  / \\   ']
            elif scene_type == 'couple':
                return [' O   O  ', '/|\\ /|\\ ', '/ \\ / \\ ']
            elif scene_type == 'kitchen':
                return [' []  [] ', ' |    | ', ' ~~~~~~ ']
            else:
                return ['        ', '        ', '        ']
        else:  # Small windows (width 4)
            if scene_type == 'empty':
                return ['    ', '    ', '    ']
            elif scene_type == 'plant':
                return [' @  ', ' |  ', ' ~  ']
            elif scene_type == 'lamp':
                return [' /\\ ', ' || ', ' __ ']
            elif scene_type == 'tv':
                return ['[==]', '[  ]', ' ~~ ']
            elif scene_type == 'cat':
                return ['/\\_/', '(oo)', '    ']
            elif scene_type == 'bookshelf':
                return ['||||', '|--|', '||||']
            elif scene_type == 'desk':
                return [' __ ', '|  |', '|__|']
            elif scene_type == 'curtains':
                return ['|\\/|', '|  |', '|/\\|']
            elif scene_type == 'blinds':
                return ['====', '====', '====']
            elif scene_type == 'person_standing':
                return [' O  ', '/|\\ ', '/ \\ ']
            elif scene_type == 'couple':
                return ['O O ', '|| |', '    ']
            elif scene_type == 'kitchen':
                return ['[][]', '|  |', '~~~~']
            else:
                return ['    ', '    ', '    ']

    def _draw_street_lights(self, ground_y: int):
        """Draw street lights along the scene and store positions for flicker effect."""
        light_height = len(self.STREET_LIGHT)
        # Position lights so they stand on the ground
        light_y = ground_y - light_height + 1

        # Place street lights between the buildings (in the alley gap)
        self._street_light_positions = []
        # Calculate gap between buildings
        building1_right = self._building_x + len(self.BUILDING[0])
        building2_left = self._building2_x if self._building2_x > 0 else self.width
        gap_center = (building1_right + building2_left) // 2
        # Position lights in the gap between buildings (moved 4 chars outward)
        light_x_positions = [gap_center - 42, gap_center + 42]
        for light_x in light_x_positions:
            if 0 < light_x < self.width - len(self.STREET_LIGHT[0]) - 1:
                self._draw_sprite(self.STREET_LIGHT, light_x, max(1, light_y), Colors.ALLEY_LIGHT)
                # Store position for flicker effect (center of light head)
                self._street_light_positions.append((light_x + 2, max(1, light_y) + 1))

    def _draw_cloud_cover(self):
        """Draw solid double-line cloud cover at top of screen.
        Note: Dotted fog is now rendered separately in _render_dotted_fog (behind clouds).
        """
        # Draw two solid lines of clouds right below the status area (rows 1-2)
        # Mostly solid blocks with occasional texture variation
        for row in range(1, 3):  # Rows 1 and 2
            for x in range(self.width - 1):
                # 80% solid blocks, 20% texture variation
                r = random.random()
                if r < 0.80:
                    char = '█'  # Solid block
                elif r < 0.90:
                    char = '▓'  # Dense shade
                elif r < 0.97:
                    char = '▒'  # Medium shade
                else:
                    char = '░'  # Light shade (rare)
                self.scene[row][x] = (char, Colors.GREY_BLOCK)

    def _draw_distant_buildings(self, center_x: int, ground_y: int, left_boundary: int, right_boundary: int,
                                 cafe_left: int = 0, cafe_right: int = 0, cafe_top: int = 0, cafe_bottom: int = 0):
        """Draw static cityscape backdrop in the gap between main buildings."""
        # Initialize skyline windows list
        self._skyline_windows = []
        self._skyline_buildings = []

        # Store visibility bounds
        self._skyline_visible_left = left_boundary + 1
        self._skyline_visible_right = right_boundary - 1

        # Store cafe bounds for window filtering
        self._cafe_bounds = (cafe_left, cafe_right, cafe_top, cafe_bottom)

        # Position cityscape centered in the gap
        cityscape_width = len(self.CITYSCAPE[0]) if self.CITYSCAPE else 0
        cityscape_height = len(self.CITYSCAPE)
        gap_width = right_boundary - left_boundary

        # Center the cityscape in the gap
        cityscape_x = left_boundary + (gap_width - cityscape_width) // 2

        # Position at top of the visible gap area (above the cafe/street level)
        cityscape_y = ground_y - cityscape_height - 6

        # Draw the static cityscape
        for row_idx, row in enumerate(self.CITYSCAPE):
            py = cityscape_y + row_idx
            if py < 0 or py >= self.height:
                continue

            for col_idx, char in enumerate(row):
                px = cityscape_x + col_idx
                if px < 0 or px >= self.width - 1:
                    continue
                # Only draw in visible gap
                if px <= left_boundary or px >= right_boundary:
                    continue
                if char == ' ':
                    continue

                # Color based on character
                if char in '[]':
                    # Window brackets
                    color = Colors.ALLEY_MID
                    # Check if this is a window position (between brackets)
                    # and set up animation
                elif char == '█':
                    # Solid wall blocks - darker for filled appearance
                    color = Colors.ALLEY_DARK
                elif char in '|_/\\':
                    # Building structure/outlines
                    color = Colors.ALLEY_MID
                elif char in '~T':
                    # Antenna/tower tops
                    color = Colors.ALLEY_MID
                elif char in '.:\'"':
                    # Building details
                    color = Colors.ALLEY_DARK
                elif char == '=':
                    # Window/structure fill
                    color = Colors.ALLEY_MID
                else:
                    color = Colors.ALLEY_DARK

                self.scene[py][px] = (char, color)

        # Add animated windows at window bracket positions [ ]
        # Find all window positions in the cityscape
        for row_idx, row in enumerate(self.CITYSCAPE):
            py = cityscape_y + row_idx
            if py < 2 or py >= self.height:
                continue

            col_idx = 0
            while col_idx < len(row) - 2:
                # Look for [ ] pattern (window)
                if row[col_idx:col_idx+3] == '[ ]':
                    px = cityscape_x + col_idx + 1  # Center of window
                    if left_boundary < px < right_boundary and 0 <= px < self.width - 1:
                        # Skip windows that would be behind the cafe
                        if (cafe_left <= px <= cafe_right and cafe_top <= py <= cafe_bottom):
                            col_idx += 3
                            continue
                        # Add animated window
                        rand_val = random.random()
                        if rand_val < 0.3:
                            is_on = True
                            is_animated = random.random() < 0.3
                        else:
                            is_on = False
                            is_animated = random.random() < 0.15

                        toggle_time = random.randint(100, 400) if is_animated else 0
                        self._skyline_windows.append({
                            'x': px,
                            'y': py,
                            'on': is_on,
                            'animated': is_animated,
                            'timer': random.randint(0, toggle_time) if is_animated else 0,
                            'toggle_time': toggle_time,
                        })

                        # Draw initial window state
                        if is_on:
                            self.scene[py][px] = ('▪', Colors.RAT_YELLOW)
                    col_idx += 3
                else:
                    col_idx += 1

    def _draw_outline_building(self, building: List[str], x: int, base_y: int, color: int):
        """Draw a building outline at the given position."""
        building_height = len(building)
        by = base_y - building_height + 1
        for row_idx, row in enumerate(building):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = by + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    self.scene[py][px] = (char, color)

    def _draw_midrange_buildings(self, ground_y: int, cafe_left: int = 0, cafe_right: int = 0):
        """Draw mid-range buildings above 1/5 of screen, behind big buildings."""
        # Mid-range building sprites - larger than distant, outline style
        midrange_buildings = [
            [
                "  ____  ",
                " |    | ",
                " | [] | ",
                " |    | ",
                " | [] | ",
                " |____| ",
            ],
            [
                " _______ ",
                "|       |",
                "| [] [] |",
                "|       |",
                "| [] [] |",
                "|_______|",
            ],
            [
                "  ___  ",
                " |   | ",
                " | o | ",
                " |   | ",
                " |___| ",
            ],
            [
                " _________ ",
                "|         |",
                "| []   [] |",
                "|         |",
                "| []   [] |",
                "|         |",
                "|_________|",
            ],
        ]

        # Position at 1/5 from bottom of screen
        midrange_y = self.height - (self.height // 5)

        # Draw across the screen, but skip cafe area
        positions = list(range(0, self.width, 20))
        for i, pos_x in enumerate(positions):
            # Skip if overlapping with cafe area
            if cafe_left - 10 < pos_x < cafe_right + 5:
                continue
            building = midrange_buildings[i % len(midrange_buildings)]
            building_height = len(building)
            by = midrange_y - building_height
            for row_idx, row in enumerate(building):
                for col_idx, char in enumerate(row):
                    px = pos_x + col_idx
                    py = by + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        self.scene[py][px] = (char, Colors.ALLEY_MID)

    def _draw_tree(self, x: int, y: int):
        """Draw a tree at the given position, blowing in wind direction."""
        # Use windy tree sprite based on wind direction
        if self._wind_direction > 0:
            tree_sprite = self.TREE_WINDY_RIGHT
        else:
            tree_sprite = self.TREE_WINDY_LEFT
        for row_idx, row in enumerate(tree_sprite):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    # Use different colors for different parts
                    if char == '@':
                        # Leaves - green
                        self.scene[py][px] = (char, Colors.MATRIX_DIM)
                    elif char in '()|':
                        # Trunk and outline - brown/dark
                        self.scene[py][px] = (char, Colors.SAND_DIM)
                    elif char == '_':
                        # Base
                        self.scene[py][px] = (char, Colors.ALLEY_MID)
                    else:
                        self.scene[py][px] = (char, Colors.ALLEY_MID)

    def _draw_pine_tree(self, x: int, y: int):
        """Draw a pine tree at the given position, blowing in wind direction."""
        # Use windy pine sprite based on wind direction
        if self._wind_direction > 0:
            tree_sprite = self.PINE_TREE_WINDY_RIGHT
        else:
            tree_sprite = self.PINE_TREE_WINDY_LEFT
        for row_idx, row in enumerate(tree_sprite):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    if char == '*':
                        # Star on top - yellow
                        self.scene[py][px] = (char, Colors.RAT_YELLOW)
                    elif char in '/\\|':
                        # Pine needles and trunk - green
                        self.scene[py][px] = (char, Colors.MATRIX_DIM)
                    elif char == '_':
                        # Base
                        self.scene[py][px] = (char, Colors.ALLEY_MID)
                    else:
                        self.scene[py][px] = (char, Colors.MATRIX_DIM)

    def _draw_cafe(self, x: int, y: int):
        """Draw a well-lit cafe storefront filled with warm color."""
        # Store cafe position
        self.cafe_x = x
        self.cafe_y = y

        total_rows = len(self.CAFE)
        total_cols = len(self.CAFE[0]) if self.CAFE else 0

        # Draw the cafe with warm lighting colors and fill empty space
        for row_idx, row in enumerate(self.CAFE):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height:
                    # Check if we're inside the cafe walls (between the | characters)
                    inside_cafe = False
                    if row_idx >= 1 and row_idx < total_rows - 1:
                        # Find wall positions in this row
                        left_wall = row.find('|')
                        right_wall = row.rfind('|')
                        if left_wall != -1 and right_wall != -1 and left_wall < col_idx < right_wall:
                            inside_cafe = True

                    if char != ' ':
                        # Use green for shell and cafe text, neutral for structure
                        # Turtle shell is rows 0-6
                        is_shell_row = row_idx < 7
                        if is_shell_row and char in '/\\|_`':
                            color = Colors.CAFE_GREEN  # Green turtle shell outline
                        elif char in 'SHELLCAFE':
                            color = Colors.CAFE_GREEN  # Green cafe name
                        elif char in 'OPEN':
                            color = Colors.ALLEY_LIGHT  # OPEN sign stays white
                        elif char in '[]=' or char == '~':
                            color = Colors.ALLEY_MID  # Windows - gray, no glow
                        elif char == 'O' and inside_cafe:
                            color = Colors.ALLEY_DARK  # People silhouettes - dark
                        elif char in '/\\' and not is_shell_row:
                            color = Colors.ALLEY_DARK  # People arms - dark
                        elif char == '|' and not is_shell_row:
                            color = Colors.ALLEY_MID  # Walls - gray
                        elif char in '_.-' and not is_shell_row:
                            color = Colors.ALLEY_MID  # Structure - gray
                        else:
                            color = Colors.ALLEY_MID  # Structure - gray
                        self.scene[py][px] = (char, color)
                    elif inside_cafe:
                        # Fill empty interior space with dark blocks (no warm glow)
                        self.scene[py][px] = ('▓', Colors.ALLEY_DARK)

    def is_valid_snow_position(self, x: int, y: int) -> bool:
        """Check if a position is valid for snow to collect.

        Snow can collect on: roof, window sills, ground, dumpster, box, curb.
        Snow should NOT collect on: building face (walls, between windows).
        """
        # Always allow snow on the ground/curb area (bottom 5 rows)
        ground_y = self.height - 5
        if y >= ground_y:
            return True

        # Check if position is on roof (within 2 rows of building top)
        if y <= self._building_y + 1 or y <= self._building2_y + 1:
            return True

        # Check if position is in the gap between buildings (alley)
        building1_right = self._building_x + len(self.BUILDING[0])
        building2_left = self._building2_x if self._building2_x > 0 else self.width
        if building1_right < x < building2_left:
            return True  # In the alley gap, allow snow

        # Check if position is on a window sill (rows with [====] pattern - every 6-7 rows)
        # Window sill rows relative to building top are: row 7, 13, 19, 25, 31 (bottom of each window section)
        # These correspond to building_y + row_offset
        building_sill_offsets = [7, 13, 19, 25, 31]

        # Check building 1
        if self._building_x <= x < self._building_x + len(self.BUILDING[0]):
            for offset in building_sill_offsets:
                sill_y = self._building_y + offset
                if y == sill_y or y == sill_y + 1:
                    return True
            return False  # On building face but not on sill

        # Check building 2
        if self._building2_x > 0 and self._building2_x <= x < self._building2_x + len(self.BUILDING2[0]):
            for offset in building_sill_offsets:
                sill_y = self._building2_y + offset
                if y == sill_y or y == sill_y + 1:
                    return True
            return False  # On building face but not on sill

        # Outside buildings, allow snow
        return True

    def is_roof_or_sill(self, x: int, y: int) -> bool:
        """Check if a position is specifically on a roof or window sill.

        Used to determine if snow should last 10x longer.
        """
        # Check if position is on roof (within 2 rows of building top)
        if self._building_y > 0 and y <= self._building_y + 1:
            if self._building_x <= x < self._building_x + len(self.BUILDING[0]):
                return True
        if self._building2_y > 0 and y <= self._building2_y + 1:
            if self._building2_x <= x < self._building2_x + len(self.BUILDING2[0]):
                return True

        # Check if position is on a window sill
        building_sill_offsets = [7, 13, 19, 25, 31]

        # Check building 1
        if self._building_x <= x < self._building_x + len(self.BUILDING[0]):
            for offset in building_sill_offsets:
                sill_y = self._building_y + offset
                if y == sill_y or y == sill_y + 1:
                    return True

        # Check building 2
        if self._building2_x > 0 and self._building2_x <= x < self._building2_x + len(self.BUILDING2[0]):
            for offset in building_sill_offsets:
                sill_y = self._building2_y + offset
                if y == sill_y or y == sill_y + 1:
                    return True

        return False

    def _generate_semi_sprite(self, direction: int, warning_message: str = None) -> Tuple[List[str], int, int, int, str]:
        """Generate a unique semi-truck sprite with advertising.

        Uses seeded randomness based on system time for screenshot validation.
        Returns: (sprite, company_idx, layout_idx, color_idx, seed_hex)
        """
        # Create unique seed from base time + spawn counter
        self._semi_spawn_counter += 1
        seed = self._semi_seed_base + self._semi_spawn_counter
        rng = random.Random(seed)

        # Select company (50 options)
        company_idx = rng.randint(0, len(self.SEMI_COMPANIES) - 1)
        company = self.SEMI_COMPANIES[company_idx]

        # Select layout style (5 options)
        layout_idx = rng.randint(0, len(self.SEMI_LAYOUTS) - 1)

        # Select color (4 options)
        color_idx = rng.randint(0, len(self.SEMI_COLORS) - 1)

        # Generate seed hex for validation (last 8 chars of hex seed)
        seed_hex = format(seed & 0xFFFFFFFF, '08X')

        # Get text content from layout
        if warning_message:
            # Warning truck - show scrolling message
            line1 = warning_message[:27]
            line2 = warning_message[27:54] if len(warning_message) > 27 else ""
        else:
            # Normal advertising truck
            line1, line2 = self.SEMI_LAYOUTS[layout_idx](company)

        # Build sprite from base template
        # Note: Sprite shows which way truck FACES - cab must lead when moving
        if direction == 1:  # Going right - cab on right leads
            base = self.SEMI_LEFT_BASE
        else:  # Going left - cab on left leads
            base = self.SEMI_RIGHT_BASE

        sprite = []
        for row in base:
            formatted = row.format(line1=line1[:27], line2=line2[:27])
            sprite.append(formatted)

        return sprite, company_idx, layout_idx, color_idx, seed_hex

    def _get_semi_validation_string(self, car: Dict) -> str:
        """Get the validation string for a semi-truck (for screenshot verification)."""
        if car.get('type') != 'semi':
            return ""
        seed_hex = car.get('seed_hex', '????????')
        company_idx = car.get('company_idx', 0)
        layout_idx = car.get('layout_idx', 0)
        color_idx = car.get('color_idx', 0)
        return f"SEMI-{seed_hex}-C{company_idx:02d}L{layout_idx}K{color_idx}"

    def _generate_work_truck_sprite(self, direction: int, logo: str, line2: str) -> List[str]:
        """Generate a work truck sprite with logo text."""
        if direction == 1:
            base = self.WORK_TRUCK_RIGHT
        else:
            base = self.WORK_TRUCK_LEFT
        sprite = []
        for row in base:
            formatted = row.format(logo=logo[:10], line2=line2[:10])
            sprite.append(formatted)
        return sprite

    def _spawn_car(self, warning_message: str = None):
        """Spawn a new car, taxi, truck, work truck, city truck, or semi-truck on the street.

        Vehicle distribution:
        - 45% regular cars (4 colors)
        - 10% taxis (yellow)
        - 20% regular trucks (4 colors with company names)
        - 10% work trucks (white with company logos)
        - 5% city trucks (Noire York departments)
        - 10% semi-trucks (50 companies, 5 layouts, 4 colors)

        Args:
            warning_message: If provided, spawns a warning semi-truck with this message
        """
        # Force semi if warning_message is provided
        if warning_message:
            vehicle_roll = 1.0  # Force semi
        else:
            vehicle_roll = random.random()

        # Play car sound effect via TTS audio engine
        self._play_car_sound('vehicle')

        # Determine direction first
        direction = 1 if random.random() < 0.5 else -1
        extra_data = {}

        if vehicle_roll < 0.45:
            # Regular car with random color from 4 options
            vehicle_type = 'car'
            sprite_right = self.CAR_RIGHT
            sprite_left = self.CAR_LEFT
            body_color = random.choice(self.CAR_BODY_COLORS)
            speed_range = (0.8, 1.5)
            spawn_offset = 25

        elif vehicle_roll < 0.55:
            # Taxi (always yellow)
            vehicle_type = 'taxi'
            sprite_right = self.TAXI_RIGHT
            sprite_left = self.TAXI_LEFT
            body_color = Colors.RAT_YELLOW
            speed_range = (0.9, 1.6)  # Taxis drive a bit faster
            spawn_offset = 25
            extra_data = {'is_taxi': True}

        elif vehicle_roll < 0.75:
            # Regular truck with color and company name
            vehicle_type = 'truck'
            sprite_right = self.TRUCK_RIGHT
            sprite_left = self.TRUCK_LEFT
            body_color = random.choice(self.TRUCK_BODY_COLORS)
            speed_range = (0.6, 1.2)
            spawn_offset = 30
            # Pick a random company name from the semi companies
            company = random.choice(self.SEMI_COMPANIES)
            extra_data = {'company': company}

        elif vehicle_roll < 0.85:
            # Work truck (white with company logo)
            vehicle_type = 'work_truck'
            company = random.choice(self.SEMI_COMPANIES)
            # Generate sprite with company name
            sprite = self._generate_work_truck_sprite(direction, company[:10], "SERVICE")
            body_color = Colors.ALLEY_LIGHT  # White
            speed_range = (0.5, 1.0)
            spawn_offset = 30
            extra_data = {'company': company}

            # Work truck already has sprite, spawn and return
            if direction == 1:
                self._cars.append({
                    'x': float(-spawn_offset),
                    'direction': 1,
                    'speed': random.uniform(*speed_range),
                    'sprite': sprite,
                    'color': body_color,
                    'type': vehicle_type,
                    **extra_data,
                })
            else:
                self._cars.append({
                    'x': float(self.width + spawn_offset),
                    'direction': -1,
                    'speed': random.uniform(*speed_range),
                    'sprite': sprite,
                    'color': body_color,
                    'type': vehicle_type,
                    **extra_data,
                })
            return

        elif vehicle_roll < 0.90:
            # Noire York City truck (white with city department)
            vehicle_type = 'city_truck'
            dept = random.choice(self.CITY_TRUCK_DEPARTMENTS)
            sprite = self._generate_work_truck_sprite(direction, dept[0][:10], dept[1][:10])
            body_color = Colors.ALLEY_LIGHT  # White city trucks
            speed_range = (0.4, 0.9)  # City trucks drive slower
            spawn_offset = 30
            extra_data = {'department': dept[1]}

            # City truck already has sprite, spawn and return
            if direction == 1:
                self._cars.append({
                    'x': float(-spawn_offset),
                    'direction': 1,
                    'speed': random.uniform(*speed_range),
                    'sprite': sprite,
                    'color': body_color,
                    'type': vehicle_type,
                    **extra_data,
                })
            else:
                self._cars.append({
                    'x': float(self.width + spawn_offset),
                    'direction': -1,
                    'speed': random.uniform(*speed_range),
                    'sprite': sprite,
                    'color': body_color,
                    'type': vehicle_type,
                    **extra_data,
                })
            return

        else:
            # Semi-truck with advertising
            vehicle_type = 'semi'
            speed_range = (0.4, 0.8)
            spawn_offset = 55  # Semi is much wider
            # Generate unique semi with advertising
            sprite, company_idx, layout_idx, color_idx, seed_hex = self._generate_semi_sprite(
                direction, warning_message
            )
            # Use semi-specific color
            body_color = self.SEMI_COLORS[color_idx]
            extra_data = {
                'company_idx': company_idx,
                'layout_idx': layout_idx,
                'color_idx': color_idx,
                'seed_hex': seed_hex,
                'is_warning': warning_message is not None,
                'warning_message': warning_message,
            }

            # Semi already has sprite, spawn and return
            if direction == 1:
                self._cars.append({
                    'x': float(-spawn_offset),
                    'direction': 1,
                    'speed': random.uniform(*speed_range),
                    'sprite': sprite,
                    'color': body_color,
                    'type': vehicle_type,
                    **extra_data,
                })
            else:
                self._cars.append({
                    'x': float(self.width + spawn_offset),
                    'direction': -1,
                    'speed': random.uniform(*speed_range),
                    'sprite': sprite,
                    'color': body_color,
                    'type': vehicle_type,
                    **extra_data,
                })
            return

        # For regular car/taxi/truck, spawn with the selected sprite
        if direction == 1:
            self._cars.append({
                'x': float(-spawn_offset),
                'direction': 1,
                'speed': random.uniform(*speed_range),
                'sprite': sprite_right,
                'color': body_color,
                'type': vehicle_type,
                **extra_data,
            })
        else:
            self._cars.append({
                'x': float(self.width + spawn_offset),
                'direction': -1,
                'speed': random.uniform(*speed_range),
                'sprite': sprite_left,
                'color': body_color,
                'type': vehicle_type,
                **extra_data,
            })

    def update(self):
        """Update traffic light state, cars, pedestrians, street light flicker, and window people."""
        self._traffic_frame += 1

        # State machine for traffic lights (with all-red transition)
        self._state_duration += 1

        if self._traffic_state == 'NS_GREEN':
            if self._state_duration >= 80:
                self._traffic_state = 'NS_YELLOW'
                self._state_duration = 0
        elif self._traffic_state == 'NS_YELLOW':
            if self._state_duration >= 40:  # Increased yellow duration for visibility
                self._traffic_state = 'ALL_RED_TO_EW'
                self._state_duration = 0
        elif self._traffic_state == 'ALL_RED_TO_EW':
            if self._state_duration >= 15:  # Brief all-red pause
                self._traffic_state = 'EW_GREEN'
                self._state_duration = 0
        elif self._traffic_state == 'EW_GREEN':
            if self._state_duration >= 80:
                self._traffic_state = 'EW_YELLOW'
                self._state_duration = 0
        elif self._traffic_state == 'EW_YELLOW':
            if self._state_duration >= 40:  # Increased yellow duration for visibility
                self._traffic_state = 'ALL_RED_TO_NS'
                self._state_duration = 0
        elif self._traffic_state == 'ALL_RED_TO_NS':
            if self._state_duration >= 15:  # Brief all-red pause
                self._traffic_state = 'NS_GREEN'
                self._state_duration = 0

        # Update cars
        self._update_cars()

        # Update close-up car (perspective effect)
        self._update_closeup_car()

        # Update pedestrians
        self._update_pedestrians()

        # Update knocked out pedestrians and ambulance
        self._update_knocked_out_and_ambulance()

        # Update street light flicker
        self._update_street_light_flicker()

        # Update window people
        self._update_window_people()

        # Update cafe people in Shell Cafe
        self._update_cafe_people()

        # Update turtle head animation
        self._update_turtle()

        # Update prop plane with banner
        self._update_prop_plane()

        # Update clouds
        self._update_clouds()

        # Update steam effects from manholes/drains
        self._update_steam()

        # Update woman in red event
        self._update_woman_red()

        # Update windy weather effects
        self._update_wind()

        # Update meteor QTE event
        self._update_qte()

        # Update UFO abduction event
        self._update_ufo()

        # Update skyline window lights
        self._update_skyline_windows()

        # Update OPEN sign animation
        self._update_open_sign()

        # Update meteor damage overlays
        self._update_damage_overlays()

        # Update Christmas lights (secret event Dec 20-31)
        self._update_christmas_lights()

        # Update Halloween pumpkin glow (secret event Oct 24-31)
        self._update_halloween()

        # Update 4th of July fireworks (secret event Jul 1-7)
        self._update_fireworks()

        # Update security canaries (tie visual elements to monitor health)
        self._update_security_canaries()

        # Update road/sidewalk weather effects
        self._update_road_effects()

    def _update_road_effects(self):
        """Update subtle weather effects on road/sidewalk."""
        street_y = self.height - 3
        curb_y = self.height - 4

        # Update existing effects - decrement timers and remove expired
        self._road_effects = [e for e in self._road_effects if e['timer'] < e['duration']]
        for effect in self._road_effects:
            effect['timer'] += 1

        # Spawn new effects occasionally
        self._road_effect_timer += 1
        if self._road_effect_timer < self._road_effect_interval:
            return
        self._road_effect_timer = 0

        # Limit total effects to keep it subtle
        if len(self._road_effects) >= 8:
            return

        # Random chance to spawn based on weather
        if random.random() > 0.4:  # 40% chance per interval
            return

        # Pick random position on road or sidewalk
        x = random.randint(5, self.width - 10)
        y = random.choice([street_y, street_y + 1, curb_y]) if street_y + 1 < self.height else random.choice([street_y, curb_y])

        # Weather-specific effects
        if self._weather_mode == WeatherMode.MATRIX:
            # Code rifts - brief glimpses of matrix code through cracks
            chars = ['0', '1', '|', '/', '\\', 'ｱ', 'ｲ', 'ｳ']
            effect = {
                'x': x, 'y': y,
                'char': random.choice(chars),
                'color': Colors.MATRIX_BRIGHT,
                'timer': 0,
                'duration': random.randint(8, 20),  # Quick flash
                'type': 'code_rift'
            }
        elif self._weather_mode == WeatherMode.RAIN:
            # Water puddles and blue spots
            chars = ['~', '≈', '░', '▒', '.']
            effect = {
                'x': x, 'y': y,
                'char': random.choice(chars),
                'color': Colors.RAIN_DIM,
                'timer': 0,
                'duration': random.randint(60, 180),  # Longer lasting puddles
                'type': 'puddle'
            }
        elif self._weather_mode == WeatherMode.SNOW:
            # Blowing snow and frost patches
            chars = ['*', '·', '.', ':', '+']
            effect = {
                'x': x, 'y': y,
                'char': random.choice(chars),
                'color': Colors.SNOW_DIM,
                'timer': 0,
                'duration': random.randint(40, 120),
                'type': 'snow_patch'
            }
        elif self._weather_mode == WeatherMode.SAND:
            # Dust settling and sand drifts
            chars = ['.', ',', ':', '~', '°']
            effect = {
                'x': x, 'y': y,
                'char': random.choice(chars),
                'color': Colors.SAND_DIM,
                'timer': 0,
                'duration': random.randint(30, 90),
                'type': 'dust'
            }
        else:  # CALM
            # Subtle dust motes
            chars = ['.', ',', "'"]
            effect = {
                'x': x, 'y': y,
                'char': random.choice(chars),
                'color': Colors.ALLEY_MID,
                'timer': 0,
                'duration': random.randint(60, 150),
                'type': 'dust_mote'
            }

        self._road_effects.append(effect)

    def _update_cars(self):
        """Update car/truck/semi positions and spawn new vehicles."""
        # Spawn new vehicles occasionally
        self._car_spawn_timer += 1
        if self._car_spawn_timer >= random.randint(40, 100):
            if len(self._cars) < 3:  # Max 3 vehicles at once
                self._spawn_car()
            self._car_spawn_timer = 0

        # Update open doors (close them after pedestrian enters)
        new_open_doors = []
        for door in self._open_doors:
            door['timer'] += 1
            if door['timer'] < 50:  # Keep door open for 50 frames
                new_open_doors.append(door)
        self._open_doors = new_open_doors

        # Update taxi pickup state
        if self._taxi_pickup:
            self._taxi_pickup['timer'] += 1
            if self._taxi_pickup['state'] == 'stopping':
                # Taxi slowing down
                taxi = self._taxi_pickup['taxi']
                taxi['speed'] = max(0.1, taxi['speed'] - 0.1)
                if taxi['speed'] <= 0.1:
                    self._taxi_pickup['state'] = 'boarding'
                    self._taxi_pickup['timer'] = 0
            elif self._taxi_pickup['state'] == 'boarding':
                # Person getting in (handled in pedestrian update)
                if self._taxi_pickup['timer'] > 30:
                    self._taxi_pickup['state'] = 'leaving'
            elif self._taxi_pickup['state'] == 'leaving':
                # Taxi driving away
                taxi = self._taxi_pickup['taxi']
                taxi['speed'] = min(1.5, taxi['speed'] + 0.1)
                if self._taxi_pickup['timer'] > 60:
                    # Remove ped from waiting list
                    ped = self._taxi_pickup.get('ped')
                    if ped in self._waiting_taxi_peds:
                        self._waiting_taxi_peds.remove(ped)
                    self._taxi_pickup = None

        # Update vehicle positions
        new_cars = []
        for car in self._cars:
            # Check if this taxi should stop for a waiting pedestrian
            if car.get('is_taxi') and self._waiting_taxi_peds and not self._taxi_pickup:
                for ped in self._waiting_taxi_peds:
                    ped_x = ped.get('x', 0)
                    # Taxi is near the waiting pedestrian
                    if abs(car['x'] - ped_x) < 15:
                        # Start pickup sequence
                        self._taxi_pickup = {
                            'taxi': car,
                            'ped': ped,
                            'state': 'stopping',
                            'timer': 0
                        }
                        break

            car['x'] += car['direction'] * car['speed']

            # Calculate margin based on vehicle type (semis are much wider)
            vehicle_type = car.get('type', 'car')
            if vehicle_type == 'semi':
                margin = 60
            elif vehicle_type == 'truck':
                margin = 35
            else:
                margin = 30

            # Keep vehicle if it's still on screen (with margin)
            if -margin < car['x'] < self.width + margin:
                new_cars.append(car)

        self._cars = new_cars

    def _update_closeup_car(self):
        """Update close-up car perspective effect with two types: approaching and departing."""
        # Spawn new close-up car occasionally
        self._closeup_car_timer += 1
        if self._closeup_car is None and self._closeup_car_timer >= random.randint(200, 400):
            self._closeup_car_timer = 0
            # Calculate position between right street light and traffic light
            building1_right = self._building_x + len(self.BUILDING[0]) if hasattr(self, '_building_x') else 70
            building2_left = self._building2_x if hasattr(self, '_building2_x') else self.width - 60
            gap_center = (building1_right + building2_left) // 2
            street_light_x = gap_center + 38
            traffic_light_x = self.box_x + len(self.BOX[0]) + 100 if hasattr(self, 'box_x') else self.width - 20
            car_x = (street_light_x + traffic_light_x) // 2

            # Randomly choose car type: approaching (from distance) or departing (from behind camera)
            car_type = random.choice(['approaching', 'departing'])

            if car_type == 'approaching':
                # Approaching: starts small/far, grows big, then disappears behind camera
                self._closeup_car = {
                    'x': float(car_x),
                    'direction': random.choice([-1, 1]),  # Face left or right
                    'scale': 0.5,  # Start small (far away)
                    'type': 'approaching',
                    'phase': 0,    # 0=growing, 1=passing behind camera
                    'scale_speed': 0.12,
                }
            else:
                # Departing: starts big (just passed camera), shrinks as it drives away
                self._closeup_car = {
                    'x': float(car_x),
                    'direction': random.choice([-1, 1]),  # Face left or right
                    'scale': 3.0,  # Start big (just passed camera)
                    'type': 'departing',
                    'phase': 0,    # 0=shrinking away
                    'scale_speed': 0.10,
                }

        # Update close-up car
        if self._closeup_car:
            car = self._closeup_car

            if car['type'] == 'approaching':
                # Approaching car: grows then passes behind camera
                if car['phase'] == 0:
                    # Growing phase - car approaching from distance
                    car['scale'] += car['scale_speed']
                    if car['scale'] >= 3.0:
                        car['scale'] = 3.0
                        car['phase'] = 1  # Now passing behind camera
                else:
                    # Passing behind camera - shrinks slightly then disappears
                    car['scale'] += car['scale_speed'] * 0.5  # Grows a tiny bit more
                    if car['scale'] >= 3.5:
                        self._closeup_car = None  # Passed behind camera

            else:  # departing
                # Departing car: shrinks as it drives away into distance
                car['scale'] -= car['scale_speed']
                if car['scale'] <= 0.3:
                    self._closeup_car = None  # Too far away to see

    def _spawn_pedestrian(self):
        """Spawn a new pedestrian on the sidewalk with random accessories, colors, and spacing."""
        # Check spacing - don't spawn if too close to existing pedestrians
        min_spacing = 8  # Minimum 8 chars between pedestrians
        direction = 1 if random.random() < 0.5 else -1

        if direction == 1:
            spawn_x = -5.0
            # Check for pedestrians near spawn point
            for ped in self._pedestrians:
                if ped['direction'] == 1 and abs(ped['x'] - spawn_x) < min_spacing:
                    return  # Too close, skip spawn
        else:
            spawn_x = float(self.width + 2)
            for ped in self._pedestrians:
                if ped['direction'] == -1 and abs(ped['x'] - spawn_x) < min_spacing:
                    return  # Too close, skip spawn

        # Randomly choose person type (basic, hat, briefcase, skirt)
        person_type_idx = random.randint(0, len(self.PERSON_TYPES_RIGHT) - 1)

        # Randomly choose skin tone and clothing color for diversity
        skin_color = random.choice(self.SKIN_TONES)
        clothing_color = random.choice(self.CLOTHING_COLORS)

        # Determine interaction behavior (50% have a destination)
        interaction = None
        destination_x = None
        rand = random.random()
        if rand < 0.15 and self._door_positions:
            # 15% go to a door (pick a door in their direction of travel)
            valid_doors = [d for d in self._door_positions
                          if (direction == 1 and d['x'] > spawn_x + 20) or
                             (direction == -1 and d['x'] < spawn_x - 20)]
            if valid_doors:
                door = random.choice(valid_doors)
                interaction = 'door'
                destination_x = door['x']
        elif rand < 0.22 and hasattr(self, 'mailbox_x'):
            # 7% mail a letter
            if (direction == 1 and self.mailbox_x > spawn_x) or \
               (direction == -1 and self.mailbox_x < spawn_x):
                interaction = 'mailbox'
                destination_x = self.mailbox_x - 2  # Stop next to mailbox
        elif rand < 0.30:
            # 8% hail a taxi
            # Pick a spot to wait at
            interaction = 'hail_taxi'
            if direction == 1:
                destination_x = random.uniform(self.width * 0.3, self.width * 0.7)
            else:
                destination_x = random.uniform(self.width * 0.3, self.width * 0.7)

        if direction == 1:
            # Pedestrian going right (spawn on left)
            self._pedestrians.append({
                'x': spawn_x,
                'direction': 1,
                'speed': random.uniform(0.3, 0.6),  # Slower than cars
                'frames': self.PERSON_TYPES_RIGHT[person_type_idx],
                'frame_idx': 0,
                'frame_timer': 0,
                'skin_color': skin_color,
                'clothing_color': clothing_color,
                'y_offset': random.choice([-1, 0, 1]),  # Wander on 2-row sidewalk
                'target_y_offset': random.choice([-1, 0, 1]),
                'y_wander_timer': random.randint(30, 80),
                'interaction': interaction,
                'destination_x': destination_x,
                'interaction_state': None,
                'interaction_timer': 0,
            })
        else:
            # Pedestrian going left (spawn on right)
            self._pedestrians.append({
                'x': spawn_x,
                'direction': -1,
                'speed': random.uniform(0.3, 0.6),
                'frames': self.PERSON_TYPES_LEFT[person_type_idx],
                'frame_idx': 0,
                'frame_timer': 0,
                'skin_color': skin_color,
                'clothing_color': clothing_color,
                'y_offset': random.choice([-1, 0, 1]),  # Wander on 2-row sidewalk
                'target_y_offset': random.choice([-1, 0, 1]),
                'y_wander_timer': random.randint(30, 80),
                'interaction': interaction,
                'destination_x': destination_x,
                'interaction_state': None,
                'interaction_timer': 0,
            })

    def _update_pedestrians(self):
        """Update pedestrian positions and spawn new pedestrians."""
        # Check if meteor event is active - pedestrians should panic
        meteor_active = self._qte_active and self._qte_state == 'active'

        # Check if woman in red scene is active - don't spawn during it
        woman_red_active = self._woman_red_active and self._woman_red_state not in ['idle', 'cooldown']

        # Spawn new pedestrians frequently (more pedestrians now)
        self._pedestrian_spawn_timer += 1
        spawn_interval = random.randint(5, 15)  # Spawn faster for more people
        if self._pedestrian_spawn_timer >= spawn_interval:
            if woman_red_active:
                max_peds = 3  # Very few during Matrix scene
            elif meteor_active:
                max_peds = 6  # Fewer during meteor (they're running away)
            else:
                max_peds = 25  # Increased from 18 to 25 pedestrians
            if len(self._pedestrians) < max_peds:
                self._spawn_pedestrian()
            self._pedestrian_spawn_timer = 0

        # Update pedestrian positions and arm animation
        new_pedestrians = []
        for ped in self._pedestrians:
            # During meteor event, pedestrians panic!
            if meteor_active:
                if not ped.get('panicking'):
                    # Start panicking - run faster in a random direction
                    ped['panicking'] = True
                    ped['panic_timer'] = 0
                    # Most run off screen, some dart around first
                    if random.random() < 0.7:
                        # Run off screen fast
                        ped['direction'] = random.choice([-1, 1])
                        ped['speed'] = random.uniform(1.5, 2.5)  # Run fast!
                    else:
                        # Dart around briefly before running
                        ped['darting'] = True
                        ped['dart_changes'] = random.randint(2, 4)

                if ped.get('darting'):
                    ped['panic_timer'] += 1
                    # Change direction rapidly while darting
                    if ped['panic_timer'] % 15 == 0:
                        ped['direction'] *= -1
                        ped['dart_changes'] -= 1
                        if ped['dart_changes'] <= 0:
                            # Done darting, now run off
                            ped['darting'] = False
                            ped['direction'] = random.choice([-1, 1])
                            ped['speed'] = random.uniform(1.8, 2.5)

                # Faster arm animation when panicking
                ped['frame_timer'] += 1
                if ped['frame_timer'] >= 1:  # Super fast arm swing
                    ped['frame_timer'] = 0
                    ped['frame_idx'] = (ped['frame_idx'] + 1) % len(ped['frames'])
            else:
                # Normal walking
                ped.pop('panicking', None)
                ped.pop('darting', None)

                # Check for interaction states
                interaction = ped.get('interaction')
                interaction_state = ped.get('interaction_state')
                destination_x = ped.get('destination_x')

                # Handle active interactions (pedestrian is stopped doing something)
                if interaction_state == 'mailing':
                    # Mailing a letter - stand still, animate
                    ped['interaction_timer'] += 1
                    if ped['interaction_timer'] > 60:  # Done mailing
                        self._mailbox_interaction = None
                        ped['interaction'] = None
                        ped['interaction_state'] = None
                        # Continue walking off screen
                    else:
                        self._mailbox_interaction = {'ped': ped, 'timer': ped['interaction_timer']}
                        continue  # Skip movement, add to new list at end
                elif interaction_state == 'entering_door':
                    # Entering a door - fade out / disappear
                    ped['interaction_timer'] += 1
                    if ped['interaction_timer'] > 30:  # Gone
                        # Remove door from open list after delay
                        continue  # Don't add to new_pedestrians, ped disappears
                    else:
                        new_pedestrians.append(ped)
                        continue  # Skip normal movement
                elif interaction_state == 'hailing':
                    # Hailing a taxi - wait for one to stop
                    ped['interaction_timer'] += 1
                    if ped['interaction_timer'] > 300:  # Give up after 5 seconds
                        ped['interaction'] = None
                        ped['interaction_state'] = None
                    elif self._taxi_pickup and self._taxi_pickup.get('ped') == ped:
                        # Taxi stopped for us
                        if self._taxi_pickup['state'] == 'boarding':
                            ped['interaction_timer'] += 1
                            if ped['interaction_timer'] > 20:
                                # Get in taxi and leave
                                self._taxi_pickup['state'] = 'leaving'
                                continue  # Remove pedestrian
                    new_pedestrians.append(ped)
                    continue  # Skip normal movement

                # Check if approaching destination
                if interaction and destination_x is not None and interaction_state is None:
                    dist = abs(ped['x'] - destination_x)
                    if dist < 3:  # Close enough to destination
                        if interaction == 'mailbox':
                            ped['interaction_state'] = 'mailing'
                            ped['interaction_timer'] = 0
                            ped['x'] = destination_x  # Snap to position
                            new_pedestrians.append(ped)
                            continue
                        elif interaction == 'door':
                            ped['interaction_state'] = 'entering_door'
                            ped['interaction_timer'] = 0
                            # Open the door
                            for door in self._door_positions:
                                if abs(door['x'] - destination_x) < 3:
                                    self._open_doors.append({
                                        'building': door['building'],
                                        'x': door['x'],
                                        'timer': 0
                                    })
                                    break
                            new_pedestrians.append(ped)
                            continue
                        elif interaction == 'hail_taxi':
                            ped['interaction_state'] = 'hailing'
                            ped['interaction_timer'] = 0
                            self._waiting_taxi_peds.append(ped)
                            new_pedestrians.append(ped)
                            continue

                # Normal arm animation
                ped['frame_timer'] += 1
                if ped['frame_timer'] >= 3:  # Normal arm swing
                    ped['frame_timer'] = 0
                    ped['frame_idx'] = (ped['frame_idx'] + 1) % len(ped['frames'])

            # Movement (skip if in certain states)
            if ped.get('interaction_state') not in ['mailing', 'entering_door', 'hailing']:
                ped['x'] += ped['direction'] * ped['speed']

            # Y wandering - pedestrians drift up/down on sidewalk to pass each other
            # Allow walking 4 rows closer (more negative offset) when under a building
            if not meteor_active:
                ped['y_wander_timer'] = ped.get('y_wander_timer', 50) - 1
                if ped['y_wander_timer'] <= 0:
                    # Check if under a building - allows walking closer to cafe
                    under_building = False
                    ped_x = ped['x']
                    if hasattr(self, '_building_x') and hasattr(self, '_building2_x'):
                        b1_left = self._building_x
                        b1_right = self._building_x + len(self.BUILDING[0])
                        b2_left = self._building2_x
                        b2_right = self._building2_x + len(self.BUILDING2[0])
                        if b1_left < ped_x < b1_right or b2_left < ped_x < b2_right:
                            under_building = True
                    # Pick new target y position - allow up to -5 when under building
                    # Walk 2 rows lower in front of buildings (positive offset = lower on screen)
                    if under_building:
                        ped['target_y_offset'] = random.choice([-5, -4, -3, -2, -1, 0, 1])
                    else:
                        ped['target_y_offset'] = random.choice([1, 2, 3])
                    ped['y_wander_timer'] = random.randint(40, 100)

                # Gradually move toward target y
                current_y = ped.get('y_offset', 0)
                target_y = ped.get('target_y_offset', 0)
                if current_y < target_y:
                    ped['y_offset'] = current_y + 1
                elif current_y > target_y:
                    ped['y_offset'] = current_y - 1

            # Keep pedestrian if still on screen (with margin)
            if -10 < ped['x'] < self.width + 10:
                new_pedestrians.append(ped)

        self._pedestrians = new_pedestrians

    def check_lightning_knockout(self, lightning_x: int):
        """Check if lightning struck near any pedestrians and knock them out."""
        self._last_lightning_x = lightning_x
        curb_y = self.height - 4  # Where pedestrians walk

        # Check each pedestrian for proximity to lightning
        knocked_out = []
        remaining = []
        for ped in self._pedestrians:
            ped_x = int(ped['x'])
            # If lightning is within 5 chars of pedestrian, knock them out
            if abs(ped_x - lightning_x) < 6:
                # Knock out this pedestrian
                knocked_out.append({
                    'x': ped_x,
                    'y': curb_y,
                    'timer': 0,
                    'skin_color': ped.get('skin_color', Colors.ALLEY_LIGHT),
                    'clothing_color': ped.get('clothing_color', Colors.ALLEY_MID),
                    'reviving': False,
                })
            else:
                remaining.append(ped)

        self._pedestrians = remaining
        self._knocked_out_peds.extend(knocked_out)

    def _update_knocked_out_and_ambulance(self):
        """Update knocked out pedestrians and ambulance revival system."""
        # Handle knocked out pedestrians
        for ko_ped in self._knocked_out_peds:
            ko_ped['timer'] += 1

        # Spawn ambulance if there are knocked out peds and no active ambulance
        if self._knocked_out_peds and self._ambulance is None and self._ambulance_cooldown <= 0:
            # Find the first knocked out ped to help
            target = self._knocked_out_peds[0]
            # Ambulance comes from whichever side is closer
            if target['x'] < self.width // 2:
                spawn_x = self.width + 25
                direction = -1
            else:
                spawn_x = -25
                direction = 1

            self._ambulance = {
                'x': float(spawn_x),
                'direction': direction,
                'state': 'arriving',  # arriving, stopped, paramedic_out, reviving, paramedic_return, leaving
                'target_ped': target,
                'paramedic_x': 0.0,
                'timer': 0,
            }

        # Update ambulance cooldown
        if self._ambulance_cooldown > 0:
            self._ambulance_cooldown -= 1

        # Update ambulance state machine
        if self._ambulance:
            amb = self._ambulance
            amb['timer'] += 1

            if amb['state'] == 'arriving':
                # Drive towards the knocked out pedestrian
                amb['x'] += amb['direction'] * 0.8
                target_x = amb['target_ped']['x']
                # Stop when close to the target
                if abs(amb['x'] - target_x) < 12:
                    amb['state'] = 'stopped'
                    amb['timer'] = 0

            elif amb['state'] == 'stopped':
                # Wait briefly then send out paramedic
                if amb['timer'] > 30:
                    amb['state'] = 'paramedic_out'
                    amb['timer'] = 0
                    # Paramedic starts at ambulance position
                    if amb['direction'] == 1:
                        amb['paramedic_x'] = amb['x'] + 10  # Right side of ambulance
                    else:
                        amb['paramedic_x'] = amb['x'] - 2  # Left side of ambulance

            elif amb['state'] == 'paramedic_out':
                # Paramedic walks to victim
                target_x = amb['target_ped']['x']
                if abs(amb['paramedic_x'] - target_x) > 2:
                    # Walk towards victim
                    if amb['paramedic_x'] < target_x:
                        amb['paramedic_x'] += 0.5
                    else:
                        amb['paramedic_x'] -= 0.5
                else:
                    amb['state'] = 'reviving'
                    amb['timer'] = 0
                    amb['target_ped']['reviving'] = True

            elif amb['state'] == 'reviving':
                # Reviving takes time
                if amb['timer'] > 90:  # 1.5 seconds
                    # Remove the knocked out ped from list
                    if amb['target_ped'] in self._knocked_out_peds:
                        self._knocked_out_peds.remove(amb['target_ped'])
                    amb['state'] = 'paramedic_return'
                    amb['timer'] = 0

            elif amb['state'] == 'paramedic_return':
                # Paramedic walks back to ambulance
                if amb['direction'] == 1:
                    target_x = amb['x'] + 10
                else:
                    target_x = amb['x'] - 2

                if abs(amb['paramedic_x'] - target_x) > 1:
                    if amb['paramedic_x'] < target_x:
                        amb['paramedic_x'] += 0.5
                    else:
                        amb['paramedic_x'] -= 0.5
                else:
                    amb['state'] = 'leaving'
                    amb['timer'] = 0

            elif amb['state'] == 'leaving':
                # Ambulance drives away
                amb['x'] += amb['direction'] * 1.0
                # Remove when off screen
                if amb['x'] < -30 or amb['x'] > self.width + 30:
                    self._ambulance = None
                    self._ambulance_cooldown = 120  # 2 second cooldown before next ambulance

    def _update_street_light_flicker(self):
        """Update street light flicker effect."""
        self._flicker_timer += 1

        # Randomly adjust flicker brightness for each light
        for i in range(len(self._street_light_flicker)):
            # Slight random variation
            if random.random() < 0.1:  # 10% chance of flicker per frame
                # Flicker down briefly
                self._street_light_flicker[i] = random.uniform(0.3, 0.7)
            elif self._street_light_flicker[i] < 1.0:
                # Gradually return to full brightness
                self._street_light_flicker[i] = min(1.0, self._street_light_flicker[i] + 0.1)

        # Update building window lights with on/off and brightness variation
        self._window_light_timer += 1

        # Update all windows (scenes visible based on light state)
        # Flicker array only tracks big windows that have light glows
        flicker_idx = 0
        for window in self._all_windows:
            # Occasionally toggle lights on/off (~0.3% chance per frame = ~once per 5.5 sec)
            if random.random() < 0.003:
                window['light_on'] = not window['light_on']
                if window['light_on']:
                    # Use discrete brightness levels for visible variation
                    window['brightness'] = random.choice([0.3, 0.5, 0.7, 0.9, 1.0])
                else:
                    window['brightness'] = 0.0

            # Only update flicker for big windows (they have light glows)
            if window['is_big'] and flicker_idx < len(self._building_window_flicker):
                if window['light_on']:
                    if random.random() < 0.03:  # 3% chance - subtle flicker
                        self._building_window_flicker[flicker_idx] = window['brightness'] * random.uniform(0.6, 0.95)
                    else:
                        # Gradually return to window's brightness level
                        target = window['brightness']
                        if self._building_window_flicker[flicker_idx] < target:
                            self._building_window_flicker[flicker_idx] = min(target, self._building_window_flicker[flicker_idx] + 0.05)
                else:
                    self._building_window_flicker[flicker_idx] = 0.0
                flicker_idx += 1

    def _update_window_people(self):
        """Update people walking by windows with walk/stare/wave animations."""
        self._window_spawn_timer += 1

        # Spawn people frequently (about every 60-150 frames) for more activity
        if self._window_spawn_timer >= random.randint(60, 150):
            self._window_spawn_timer = 0
            if len(self._window_people) < 8:  # Allow up to 8 window people at once
                # Pick a random window from either building
                building = random.choice([1, 2])
                if building == 1:
                    positions = self.BUILDING_WINDOW_POSITIONS
                    window_idx = random.randint(0, len(positions) - 1)
                else:
                    positions = self.BUILDING2_WINDOW_POSITIONS
                    window_idx = random.randint(0, len(positions) - 1)

                # Start from edge, walking state
                start_left = random.random() < 0.5
                self._window_people.append({
                    'building': building,
                    'window_idx': window_idx,
                    'direction': 1 if start_left else -1,
                    'progress': 0.0 if start_left else 1.0,
                    'state': 'walking',  # walking, staring, waving, leaving
                    'state_timer': 0,
                    'stare_duration': random.randint(80, 200),  # Long stare
                    'wave_count': 0,
                    'wave_frame': 0,
                })

        # Update existing window people
        new_window_people = []
        for person in self._window_people:
            person['state_timer'] += 1

            if person['state'] == 'walking':
                # Move person across window
                speed = 0.03
                person['progress'] += person['direction'] * speed

                # Check if reached center of window - stop to stare
                if 0.35 < person['progress'] < 0.65 and random.random() < 0.02:
                    person['state'] = 'staring'
                    person['state_timer'] = 0
                    person['progress'] = 0.5  # Center in window

                # Keep walking if not done
                if person['progress'] < -0.3 or person['progress'] > 1.3:
                    continue  # Remove person - walked off

            elif person['state'] == 'staring':
                # Person stares out window for a long time
                if person['state_timer'] >= person['stare_duration']:
                    # Start waving before leaving
                    person['state'] = 'waving'
                    person['state_timer'] = 0
                    person['wave_count'] = 0

            elif person['state'] == 'waving':
                # Wave animation - 3 waves
                person['wave_frame'] = (person['state_timer'] // 5) % 2  # Alternate every 5 frames
                if person['state_timer'] >= 30:  # Wave for 30 frames (about 3 waves)
                    person['state'] = 'leaving'
                    person['state_timer'] = 0
                    # Pick direction to leave
                    person['direction'] = random.choice([-1, 1])

            elif person['state'] == 'leaving':
                # Walk away from window
                speed = 0.04
                person['progress'] += person['direction'] * speed

                # Remove when off screen
                if person['progress'] < -0.3 or person['progress'] > 1.3:
                    continue  # Remove person

            new_window_people.append(person)

        self._window_people = new_window_people

    def _update_cafe_people(self):
        """Update the 3 people in Shell Cafe's lower window - gentle movement and arm animation."""
        self._cafe_people_timer += 1

        for person in self._cafe_people:
            person['move_timer'] += 1
            person['arm_timer'] += 1

            # Move person slightly back and forth within their zone
            if person['move_timer'] >= random.randint(30, 60):
                person['move_timer'] = 0
                # Small movements within their section of the window
                person['x_offset'] += person['direction'] * 0.5
                # Bounds check - each person has a ~5 char zone
                base_x = self._cafe_people.index(person) * 6.0
                if person['x_offset'] > base_x + 2.0:
                    person['direction'] = -1
                elif person['x_offset'] < base_x - 2.0:
                    person['direction'] = 1
                # Occasionally reverse direction randomly
                if random.random() < 0.2:
                    person['direction'] *= -1

            # Animate arms - cycle through arm positions
            if person['arm_timer'] >= random.randint(20, 50):
                person['arm_timer'] = 0
                person['arm_frame'] = (person['arm_frame'] + 1) % 4

    def _update_turtle(self):
        """Update turtle head animation - peeks out of shell and winks."""
        self._turtle_timer += 1

        if self._turtle_state == 'hidden':
            # Wait for cooldown then peek out
            if self._turtle_timer >= self._turtle_cooldown:
                self._turtle_state = 'peeking'
                self._turtle_timer = 0
                self._turtle_frame = 0  # Normal eyes
                self._turtle_side = random.choice([1, -1])  # Random side
                self._turtle_visible_duration = random.randint(180, 360)  # 3-6 seconds

        elif self._turtle_state == 'peeking':
            # Stay visible, occasionally wink
            if self._turtle_timer >= 30:  # Every 0.5 seconds
                self._turtle_timer = 0
                # 30% chance to wink
                if random.random() < 0.3:
                    self._turtle_state = 'winking'
                    self._turtle_frame = random.choice([1, 2])  # Left or right wink
                else:
                    self._turtle_frame = random.choice([0, 0, 0, 3])  # Mostly normal, sometimes happy
            # Check if should retreat
            self._turtle_visible_duration -= 1
            if self._turtle_visible_duration <= 0:
                self._turtle_state = 'retreating'
                self._turtle_timer = 0

        elif self._turtle_state == 'winking':
            # Brief wink then back to peeking
            if self._turtle_timer >= 15:  # 0.25 second wink
                self._turtle_state = 'peeking'
                self._turtle_timer = 0
                self._turtle_frame = 0

        elif self._turtle_state == 'retreating':
            # Go back to hidden
            if self._turtle_timer >= 20:
                self._turtle_state = 'hidden'
                self._turtle_timer = 0
                self._turtle_cooldown = random.randint(300, 900)  # 5-15 seconds

    def queue_plane_announcement(self, message: str):
        """Queue a message to be displayed by a prop plane with banner.

        Used for mode changes, weather changes, and similar announcements.
        """
        self._prop_plane_queue.append(message)

    def _update_prop_plane(self):
        """Update prop plane position and spawn new planes for queued messages."""
        # Handle cooldown
        if self._prop_plane_cooldown > 0:
            self._prop_plane_cooldown -= 1

        # Spawn new plane if queue has messages and no active plane
        if self._prop_plane is None and self._prop_plane_queue and self._prop_plane_cooldown <= 0:
            message = self._prop_plane_queue.pop(0)
            direction = random.choice([1, -1])
            # Plane flies in upper portion of screen
            y = random.randint(3, max(4, self.height // 4))

            if direction == 1:
                x = -len(self.PROP_PLANE_RIGHT[1]) - len(message) - 10
            else:
                x = self.width + 10

            self._prop_plane = {
                'x': float(x),
                'y': y,
                'direction': direction,
                'speed': random.uniform(2.0, 3.5),  # 5x faster
                'message': message,
                'scroll_offset': 0,
            }
            self._prop_plane_cooldown = 300  # 5 seconds between planes

        # Update active plane
        if self._prop_plane:
            self._prop_plane['x'] += self._prop_plane['direction'] * self._prop_plane['speed']

            # Check if plane has exited screen
            plane_width = len(self.PROP_PLANE_RIGHT[1]) + len(self._prop_plane['message']) + 10
            if self._prop_plane['direction'] == 1:
                if self._prop_plane['x'] > self.width + 10:
                    self._prop_plane = None
            else:
                if self._prop_plane['x'] < -plane_width:
                    self._prop_plane = None

    def _get_traffic_light_colors(self) -> Tuple[Tuple[str, int], Tuple[str, int], Tuple[str, int],
                                                   Tuple[str, int], Tuple[str, int], Tuple[str, int]]:
        """Get the current light colors for both directions.

        Returns: (ns_red, ns_yellow, ns_green, ew_red, ew_yellow, ew_green)
        Each is a tuple of (char, color).
        """
        # Define light states - off lights are gray circles
        off = ('o', Colors.GREY_BLOCK)
        red_on = ('O', Colors.SHADOW_RED)
        yellow_on = ('O', Colors.RAT_YELLOW)
        green_on = ('O', Colors.STATUS_OK)

        if self._traffic_state == 'NS_GREEN':
            # NS has green, EW has red
            return (off, off, green_on, red_on, off, off)
        elif self._traffic_state == 'NS_YELLOW':
            # NS has yellow, EW has red
            return (off, yellow_on, off, red_on, off, off)
        elif self._traffic_state == 'ALL_RED_TO_EW':
            # Both red (transition from NS to EW)
            return (red_on, off, off, red_on, off, off)
        elif self._traffic_state == 'EW_GREEN':
            # NS has red, EW has green
            return (red_on, off, off, off, off, green_on)
        elif self._traffic_state == 'EW_YELLOW':
            # NS has red, EW has yellow
            return (red_on, off, off, off, yellow_on, off)
        elif self._traffic_state == 'ALL_RED_TO_NS':
            # Both red (transition from EW to NS)
            return (red_on, off, off, red_on, off, off)
        else:
            # Default to NS green
            return (off, off, green_on, red_on, off, off)

    def _draw_sprite(self, sprite: List[str], x: int, y: int, color: int):
        """Draw an ASCII sprite at the given position."""
        for row_idx, row in enumerate(sprite):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    self.scene[py][px] = (char, color)

    def _draw_box_with_label(self, x: int, y: int):
        """Draw box with hashtag fill and white label."""
        for row_idx, row in enumerate(self.BOX):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    if char == 'X':
                        # White label
                        self.scene[py][px] = ('#', Colors.ALLEY_LIGHT)
                    else:
                        self.scene[py][px] = (char, Colors.SAND_DIM)

    def _draw_crosswalk(self, x: int, curb_y: int, street_y: int):
        """Draw vanishing street with hashtag crosswalk at sidewalk level."""
        crosswalk_width = 32

        # Draw hashtag (#) crosswalk pattern at sidewalk/street level
        # Pattern: horizontal bars with vertical stripes forming a grid
        hashtag_height = 3  # Height of crosswalk pattern
        hashtag_start_y = street_y - hashtag_height + 1  # At street level

        for cy in range(hashtag_height):
            py = hashtag_start_y + cy
            if 0 <= py < self.height:
                for cx in range(crosswalk_width):
                    px = x + cx
                    if 0 <= px < self.width - 1:
                        # Horizontal bars at top and bottom of pattern
                        if cy == 0 or cy == hashtag_height - 1:
                            self.scene[py][px] = ('═', Colors.ALLEY_LIGHT)
                        # Vertical bars every 4 characters
                        elif cx % 4 == 0:
                            self.scene[py][px] = ('║', Colors.ALLEY_LIGHT)
                        else:
                            # Street surface between stripes
                            self.scene[py][px] = ('▒', Colors.ALLEY_MID)

        # Draw vanishing street effect above the curb
        # Starts at curb and ends at lower 1/5th of screen
        vanish_end_y = self.height - (self.height // 5)  # Lower 1/5th of screen
        vanish_start_y = curb_y - 1  # Just above curb

        # Calculate crosswalk center for vanishing point
        crosswalk_center = x + crosswalk_width // 2

        for row_y in range(vanish_start_y, vanish_end_y - 1, -1):
            # Calculate perspective narrowing as we go up
            progress = (vanish_start_y - row_y) / max(1, vanish_start_y - vanish_end_y)
            # Street narrows as it goes into distance
            half_width = int((crosswalk_width // 2) * (1.0 - progress * 0.7))

            for offset in range(-half_width, half_width + 1):
                px = crosswalk_center + offset
                if 0 <= px < self.width - 1 and vanish_end_y <= row_y < vanish_start_y:
                    # Draw street surface with lane markings
                    if offset == 0:
                        # Center line - vertical || pattern (yellow)
                        self.scene[row_y][px] = ('|', Colors.RAT_YELLOW)
                    elif offset == 1:
                        # Second | of the || center line
                        self.scene[row_y][px] = ('|', Colors.RAT_YELLOW)
                    elif offset == -half_width:
                        # Left edge line (use forward slash for perspective - narrows toward top)
                        self.scene[row_y][px] = ('/', Colors.ALLEY_MID)
                    elif offset == half_width:
                        # Right edge line (use backslash for perspective - narrows toward top)
                        self.scene[row_y][px] = ('\\', Colors.ALLEY_MID)
                    else:
                        # Street surface
                        self.scene[row_y][px] = ('▓', Colors.ALLEY_DARK)

    def _draw_building(self, sprite: List[str], x: int, y: int):
        """Draw a building with grey blocks on bottom half story and red bricks on upper.

        The bottom ~8 rows (near door/porch) get grey blocks, upper rows get red bricks.
        Windows remain in blue/cyan color. Satellite dishes are grey.
        Brick outline around windows. Grey blocks fully filled with transparent texture.
        Door knobs rendered in gold. Roof items have solid dark backgrounds.
        """
        total_rows = len(sprite)
        # Grey block section: bottom 11 rows (half story with door, one row lower)
        grey_start_row = total_rows - 7  # 4 less grey (was -11), 4 more brick
        # Brick character for even texture
        brick_char = '▓'
        # Roof items section (rows with satellite dishes, antennas, etc.)
        roof_items_end = 5  # First 5 rows are roof items

        # First pass: find window boundaries for each row
        def is_inside_window(row_str: str, col: int) -> bool:
            """Check if a column is inside a window (between [ and ])."""
            # Find all [ and ] positions in the row
            bracket_open = -1
            for i, c in enumerate(row_str):
                if c == '[':
                    bracket_open = i
                elif c == ']':
                    if bracket_open != -1 and bracket_open < col < i:
                        return True
                    bracket_open = -1
            return False

        def is_window_outline(row_str: str, col: int) -> bool:
            """Check if position is adjacent to a window (for brick outline)."""
            # Check if there's a [ or ] within 1 character
            for offset in [-1, 0, 1]:
                check_col = col + offset
                if 0 <= check_col < len(row_str):
                    if row_str[check_col] in '[]':
                        return True
            return False

        # Helper to check if position is adjacent to a roof item (for filling behind items)
        def is_near_roof_item(row_str: str, col: int, row_idx: int, sprite: List[str]) -> bool:
            """Check if a position is adjacent to a roof item character."""
            roof_chars = 'O_|/\\()=[]'
            # Check horizontally adjacent
            for offset in [-1, 0, 1]:
                check_col = col + offset
                if 0 <= check_col < len(row_str):
                    if row_str[check_col] in roof_chars:
                        return True
            # Check vertically adjacent
            for row_offset in [-1, 1]:
                check_row = row_idx + row_offset
                if 0 <= check_row < len(sprite):
                    if col < len(sprite[check_row]) and sprite[check_row][col] in roof_chars:
                        return True
            return False

        for row_idx, row in enumerate(sprite):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height:
                    # Roof items rows (0-4) - only fill behind actual roof items, not entire area
                    if row_idx < roof_items_end:
                        if char == ' ':
                            # Only fill with dark if adjacent to a roof item
                            if is_near_roof_item(row, col_idx, row_idx, sprite):
                                self.scene[py][px] = ('█', Colors.ALLEY_DARK)
                            # Otherwise leave empty (transparent to sky/tunnel)
                        elif char in 'O_|/\\()=':
                            # Roof item characters - grey
                            self.scene[py][px] = (char, Colors.GREY_BLOCK)
                        elif char == '-':
                            # Roof line
                            self.scene[py][px] = (char, Colors.ALLEY_BLUE)
                        elif char == '.':
                            # Roof edge
                            self.scene[py][px] = (char, Colors.ALLEY_MID)
                        else:
                            self.scene[py][px] = (char, Colors.GREY_BLOCK)
                        continue

                    # Check if inside a window
                    inside_window = is_inside_window(row, col_idx)

                    if char != ' ':
                        # Determine color based on character and position
                        if char in '[]=' or (char == '-' and row_idx == roof_items_end):
                            # Window frames and roof line - keep blue
                            color = Colors.ALLEY_BLUE
                            # Store window frame positions for layering (draw on top of window people)
                            if char in '[]=':
                                self._window_frame_positions.append((px, py, char))
                        elif char in '|_.':
                            # Structural elements
                            if row_idx >= grey_start_row:
                                color = Colors.GREY_BLOCK
                            else:
                                color = Colors.BRICK_RED
                        elif char == '#':
                            # Check if this is a door window (# inside brackets in door area)
                            # Door windows are in the grey zone and have pattern |[####]|
                            if row_idx >= grey_start_row and inside_window:
                                # Door window - render in blue
                                color = Colors.ALLEY_BLUE
                            elif row_idx >= grey_start_row:
                                color = Colors.GREY_BLOCK
                            else:
                                color = Colors.BRICK_RED
                        else:
                            # Default
                            if row_idx >= grey_start_row:
                                color = Colors.GREY_BLOCK
                            else:
                                color = Colors.BRICK_RED

                        self.scene[py][px] = (char, color)
                    else:
                        # Empty space - add texture based on zone
                        # Fill window interior with SOLID dark background (prevents seeing through)
                        if inside_window:
                            self.scene[py][px] = ('█', Colors.ALLEY_DARK)
                            # Store window interior position for layering
                            self._window_interior_positions.append((px, py))
                            continue

                        if row_idx >= roof_items_end and row_idx < grey_start_row:
                            # Red brick zone - fill completely
                            self.scene[py][px] = (brick_char, Colors.BRICK_RED)
                        elif row_idx >= grey_start_row and row_idx < total_rows - 2:
                            # Grey zone - fill with consistent blocks (no random smudges)
                            # Bottom row of grey zone gets smudged texture
                            if row_idx == total_rows - 3:
                                # Smudge row at bottom of building (just above porch)
                                self.scene[py][px] = ('▒', Colors.GREY_BLOCK)
                            else:
                                # Solid consistent grey blocks
                                self.scene[py][px] = ('▓', Colors.GREY_BLOCK)
                        # Bottom 2 rows (porch/stoop level) - leave empty, no blocks

        # Second pass: add door knobs
        # Find door positions (look for the door pattern .------.)
        for row_idx, row in enumerate(sprite):
            if '.------.' in row:
                door_col = row.index('.------.')
                # Door knob should be in middle of door, on the right side
                knob_row = row_idx + 3  # Middle of door
                knob_col = door_col + 6  # Right side of door
                if knob_row < total_rows:
                    knob_px = x + knob_col
                    knob_py = y + knob_row
                    if 0 <= knob_px < self.width - 1 and 0 <= knob_py < self.height:
                        self.scene[knob_py][knob_px] = ('o', Colors.DOOR_KNOB_GOLD)

    def _draw_building_side_walls(self, building_x: int, building_y: int, building_width: int, building_height: int, side: str):
        """Draw 3-character wide vanishing point side walls on buildings.

        Args:
            building_x: Left edge of building
            building_y: Top of building
            building_width: Width of building sprite
            building_height: Height of building sprite
            side: 'left' for lighter wall, 'right' for darker shadow wall
        """
        wall_width = 3
        wall_chars = ['▓', '▒', '░']  # Gradient from building edge outward

        # Skip top rows (rooftop items) - start lower to avoid being too tall
        start_row = 5

        for row in range(start_row, building_height - 2):  # Skip bottom porch rows
            py = building_y + row
            if py < 0 or py >= self.height:
                continue

            for w in range(wall_width):
                if side == 'left':
                    # Left side wall - lighter color (sun-lit), extends left
                    px = building_x - w - 1
                    # Lighter color
                    color = Colors.ALLEY_MID if w == 0 else Colors.ALLEY_LIGHT
                    char = wall_chars[w] if w < len(wall_chars) else '░'
                else:
                    # Right side wall - darker color (shadow), extends right
                    px = building_x + building_width + w
                    # Darker color for shadow
                    color = Colors.ALLEY_DARK
                    char = wall_chars[wall_width - w - 1] if w < len(wall_chars) else '░'

                if 0 <= px < self.width - 1:
                    self.scene[py][px] = (char, color)

    def render(self, screen):
        """Render the alley scene to the screen with proper layering."""
        # Render constellation first (furthest back, behind clouds and buildings)
        self._render_constellation(screen)

        # Render distant clouds first (furthest back, behind everything)
        self._render_distant_clouds(screen)

        # Render dotted fog layer (behind main clouds)
        self._render_dotted_fog(screen)

        # Render main clouds (behind buildings, on top of fog)
        self._render_clouds(screen)

        # Render UFO event (in sky, behind buildings)
        self._render_ufo(screen)

        # Render static scene elements (except window frames - those go on top)
        for y, row in enumerate(self.scene):
            if y >= self.height:
                break
            for x, (char, color) in enumerate(row):
                if x >= self.width - 1:  # Leave last column empty to avoid scroll
                    break
                if char != ' ':
                    try:
                        attr = curses.color_pair(color) | curses.A_DIM
                        screen.attron(attr)
                        screen.addstr(y, x, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

        # Render window scenes (unique mini scenes inside each window)
        self._render_window_scenes(screen)

        # Render window people silhouettes (behind window frames)
        self._render_window_people(screen)

        # Render cafe people in Shell Cafe lower window
        self._render_cafe_people(screen)

        # Render cafe sign (green SHELL CAFE and animated OPEN sign)
        self._render_cafe_sign(screen)

        # Render turtle head peeking from shell
        self._render_turtle(screen)

        # Render prop plane with banner (flies in sky)
        self._render_prop_plane(screen)

        # Render window frames on top of window people (so people appear inside)
        self._render_window_frames(screen)

        # Render trees as foreground layer (in front of buildings)
        self._render_trees(screen)
        self._render_pine_trees(screen)

        # Render holiday events
        self._render_fireworks(screen)  # 4th of July fireworks in sky
        self._render_pumpkins(screen)   # Halloween pumpkins near trees
        self._render_easter_eggs(screen)  # Easter eggs hidden in scene

        # Render sidewalk/curb on top of scene but behind all sprites
        self._render_sidewalk(screen)

        # Render subtle weather effects on road/sidewalk
        self._render_road_effects(screen)

        # Render street light flicker effects
        self._render_street_light_flicker(screen)

        # Render building window lights (glow without pole)
        self._render_building_window_lights(screen)

        # Render steam effects from manholes/drains
        self._render_steam(screen)

        # Render meteor damage overlays
        self._render_damage_overlays(screen)

        # Render wind effects (debris, leaves, wisps)
        self._render_wind(screen)

        # Render open mailbox if someone is mailing
        self._render_mailbox_interaction(screen)

        # Render open doors
        self._render_open_doors(screen)

        # Render pedestrians on the sidewalk
        self._render_pedestrians(screen)

        # Render knocked out pedestrians and ambulance
        self._render_knocked_out_peds(screen)
        self._render_ambulance(screen)

        # Render Woman in Red event (on top of regular pedestrians)
        self._render_woman_red(screen)

        # Render traffic light (dynamic - lights change)
        self._render_traffic_light(screen)

        # Render close-up car (perspective effect)
        self._render_closeup_car(screen)

        # Render horizontal cars on the street LAST (on top of everything)
        self._render_cars(screen)

        # Render foreground clouds (big, fast, on top of scene)
        self._render_foreground_clouds(screen)

        # Render QTE event (meteors, missiles, explosions, NPC) on top of everything
        self._render_qte(screen)

        # Render solid fog layer at top (on top of EVERYTHING)
        self._render_fog_layer(screen)

    def _render_fog_layer(self, screen):
        """Render solid fog layer at top of screen - on top of everything."""
        # Render solid cloud cover at rows 1-2, on top of all other rendering
        for row in range(1, 3):
            for x in range(self.width - 1):
                if 0 <= row < self.height:
                    try:
                        # Get the stored fog character from scene
                        char, color = self.scene[row][x] if x < len(self.scene[row]) else ('█', Colors.GREY_BLOCK)
                        if char in '█▓▒░':  # Only render fog characters
                            attr = curses.color_pair(color)
                            screen.attron(attr)
                            screen.addstr(row, x, char)
                            screen.attroff(attr)
                    except curses.error:
                        pass

    def _render_window_frames(self, screen):
        """Render window frames on top of window people for proper layering."""
        for px, py, char in self._window_frame_positions:
            if 0 <= px < self.width - 1 and 0 <= py < self.height:
                try:
                    attr = curses.color_pair(Colors.ALLEY_BLUE) | curses.A_DIM
                    screen.attron(attr)
                    screen.addstr(py, px, char)
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_sidewalk(self, screen):
        """Render sidewalk/curb on top of scene but behind sprites."""
        for px, py, char, color in self._sidewalk_positions:
            if 0 <= px < self.width - 1 and 0 <= py < self.height:
                try:
                    attr = curses.color_pair(color)
                    screen.attron(attr)
                    screen.addstr(py, px, char)
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_road_effects(self, screen):
        """Render subtle weather effects on road/sidewalk."""
        for effect in self._road_effects:
            x, y = effect['x'], effect['y']
            if 0 <= x < self.width - 1 and 0 <= y < self.height:
                # Calculate fade based on timer (fade in/out)
                progress = effect['timer'] / effect['duration']
                # Quick fade in, longer fade out
                if progress < 0.1:
                    # Fade in
                    alpha = progress / 0.1
                elif progress > 0.7:
                    # Fade out
                    alpha = (1.0 - progress) / 0.3
                else:
                    alpha = 1.0

                # Skip if too faded
                if alpha < 0.3:
                    continue

                try:
                    attr = curses.color_pair(effect['color'])
                    # Bright for code rifts and new effects
                    if effect['type'] == 'code_rift' or alpha > 0.8:
                        attr |= curses.A_BOLD
                    elif alpha < 0.5:
                        attr |= curses.A_DIM

                    screen.attron(attr)
                    screen.addstr(y, x, effect['char'])
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_steam(self, screen):
        """Render steam rising from manholes and drains."""
        for steam in self._steam_effects:
            frame = self.STEAM_FRAMES[steam['frame']]
            base_x = steam['x']
            base_y = steam['y']

            # Draw steam rising (3 rows above the source)
            for row_idx, row in enumerate(frame):
                py = base_y - row_idx - 1  # Above the manhole/drain
                for col_idx, char in enumerate(row):
                    px = base_x + col_idx - 2  # Center the steam
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        try:
                            # Steam is white/light gray
                            attr = curses.color_pair(Colors.ALLEY_LIGHT)
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_damage_overlays(self, screen):
        """Render meteor damage overlays on the scene - fades from red to gray."""
        for overlay in self._damage_overlays:
            px = overlay['x']
            py = overlay['y']
            if 0 <= px < self.width - 1 and 0 <= py < self.height:
                try:
                    # Damage fades gradually: red -> orange -> gray -> dim gray -> gone
                    fade_progress = overlay['timer'] / overlay['fade_time']
                    if fade_progress < 0.15:
                        # Fresh damage - bright red
                        attr = curses.color_pair(Colors.SHADOW_RED) | curses.A_BOLD
                    elif fade_progress < 0.3:
                        # Cooling - red, no bold
                        attr = curses.color_pair(Colors.BRICK_RED)
                    elif fade_progress < 0.5:
                        # Cooled - bright gray
                        attr = curses.color_pair(Colors.ALLEY_LIGHT)
                    elif fade_progress < 0.7:
                        # Fading - medium gray
                        attr = curses.color_pair(Colors.ALLEY_MID)
                    elif fade_progress < 0.85:
                        # Old - dim gray
                        attr = curses.color_pair(Colors.GREY_BLOCK) | curses.A_DIM
                    else:
                        # Almost gone - very dim
                        attr = curses.color_pair(Colors.ALLEY_DARK) | curses.A_DIM
                    screen.attron(attr)
                    screen.addstr(py, px, overlay['char'])
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_wind(self, screen):
        """Render wind effects - debris, leaves, and wisps."""
        # Render debris (newspapers, trash, leaves on ground)
        for d in self._debris:
            px = int(d['x'])
            py = int(d['y'])
            if 0 <= px < self.width - 1 and 0 <= py < self.height:
                try:
                    if d.get('color') == 'leaf':
                        attr = curses.color_pair(Colors.MATRIX_DIM)
                    elif d.get('color') == 'paper':
                        attr = curses.color_pair(Colors.ALLEY_LIGHT)
                    else:
                        attr = curses.color_pair(Colors.ALLEY_MID)
                    screen.attron(attr)
                    screen.addstr(py, px, d['char'])
                    screen.attroff(attr)
                except curses.error:
                    pass

        # Render wind wisps in sky
        for w in self._wind_wisps:
            px = int(w['x'])
            py = int(w['y'])
            for i, char in enumerate(w['chars']):
                cx = px + i
                if 0 <= cx < self.width - 1 and 0 <= py < self.height:
                    try:
                        attr = curses.color_pair(Colors.ALLEY_MID) | curses.A_DIM
                        screen.attron(attr)
                        screen.addstr(py, cx, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

        # Render leaves blowing from trees
        for leaf in self._leaves:
            px = int(leaf['x'])
            py = int(leaf['y'])
            if 0 <= px < self.width - 1 and 0 <= py < self.height:
                try:
                    attr = curses.color_pair(Colors.MATRIX_DIM)
                    screen.attron(attr)
                    screen.addstr(py, px, leaf['char'])
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_mailbox_interaction(self, screen):
        """Render open mailbox when someone is mailing a letter."""
        if not self._mailbox_interaction:
            return

        timer = self._mailbox_interaction.get('timer', 0)
        # Only show open mailbox during middle of interaction
        if 10 < timer < 50:
            # Draw open mailbox over the regular mailbox
            mailbox_x = getattr(self, 'mailbox_x', 0)
            mailbox_y = getattr(self, 'mailbox_y', 0)
            if mailbox_x > 0:
                for row_idx, row in enumerate(self.MAILBOX_OPEN):
                    for col_idx, char in enumerate(row):
                        px = mailbox_x + col_idx
                        py = mailbox_y + row_idx
                        if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                            try:
                                # Open slot is highlighted
                                if char == '█':
                                    attr = curses.color_pair(Colors.ALLEY_DARK)
                                else:
                                    attr = curses.color_pair(Colors.ALLEY_BLUE)
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                            except curses.error:
                                pass

    def _render_open_doors(self, screen):
        """Render open doors when people are entering buildings."""
        if not self._open_doors:
            return

        ground_y = self.height - 1
        for door in self._open_doors:
            door_x = door.get('x', 0)
            building = door.get('building')

            # Door is at ground level, 5 rows tall
            door_y = ground_y - 4

            # Render open door overlay
            for row_idx, row in enumerate(self.DOOR_OPEN):
                for col_idx, char in enumerate(row):
                    px = door_x + col_idx - 3  # Center the door
                    py = door_y + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        try:
                            # Dark interior with frame
                            if char == '░':
                                attr = curses.color_pair(Colors.ALLEY_DARK)
                            elif char in '.|─[]':
                                attr = curses.color_pair(Colors.ALLEY_MID)
                            else:
                                attr = curses.color_pair(Colors.GREY_BLOCK)
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_qte(self, screen):
        """Render the meteor QTE event - meteors, missiles, explosions, NPC."""
        if not self._qte_active:
            # Clear any leftover positions from previous frame when QTE ends
            for (px, py, w, h) in self._qte_last_meteor_positions:
                for dy in range(h):
                    for dx in range(w):
                        cx, cy = px + dx, py + dy
                        if 0 <= cx < self.width - 1 and 0 <= cy < self.height:
                            try:
                                screen.addstr(cy, cx, ' ')
                            except curses.error:
                                pass
            self._qte_last_meteor_positions = []
            return

        # Track current meteor positions for cleanup next frame
        current_positions = []

        # Render meteors
        for meteor in self._qte_meteors:
            px = int(meteor['x'])
            py = int(meteor['y'])

            # Select sprite based on size
            if meteor['size'] == 'large':
                sprite = self.METEOR_LARGE
            elif meteor['size'] == 'medium':
                sprite = self.METEOR_MEDIUM
            else:
                sprite = self.METEOR_SMALL

            # Draw meteor sprite
            for row_idx, row in enumerate(sprite):
                for col_idx, char in enumerate(row):
                    cx = px + col_idx - len(row) // 2
                    cy = py + row_idx
                    if 0 <= cx < self.width - 1 and 0 <= cy < self.height and char != ' ':
                        try:
                            # Meteors are orange/red when falling, gray when waiting
                            if meteor['called']:
                                attr = curses.color_pair(Colors.SHADOW_RED) | curses.A_BOLD
                            else:
                                attr = curses.color_pair(Colors.ALLEY_MID)
                            screen.attron(attr)
                            screen.addstr(cy, cx, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

            # Track meteor position for cleanup (include sprite bounds + label)
            sprite_w = len(sprite[0]) if sprite else 5
            sprite_h = len(sprite) + 2  # +2 for label above
            current_positions.append((px - sprite_w // 2, py - 2, sprite_w + 3, sprite_h + 2))

            # Draw key indicator above meteor
            if not meteor['called']:
                key = self.QTE_KEYS[meteor['col']]
                key_x = px
                key_y = py - 1
                if 0 <= key_x < self.width - 1 and 0 <= key_y < self.height:
                    try:
                        attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                        screen.attron(attr)
                        screen.addstr(key_y, key_x, f"[{key}]")
                        screen.attroff(attr)
                    except curses.error:
                        pass

        # Save positions for cleanup next frame
        self._qte_last_meteor_positions = current_positions

        # Render missiles
        for missile in self._qte_missiles:
            px = int(missile['x'])
            py = int(missile['y'])

            for row_idx, row in enumerate(self.MISSILE):
                for col_idx, char in enumerate(row):
                    cx = px + col_idx - len(row) // 2
                    cy = py + row_idx
                    if 0 <= cx < self.width - 1 and 0 <= cy < self.height and char != ' ':
                        try:
                            attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_BOLD
                            screen.attron(attr)
                            screen.addstr(cy, cx, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

        # Render explosions
        for exp in self._qte_explosions:
            frame_idx = min(exp['frame'], len(self.EXPLOSION_FRAMES) - 1)
            frame = self.EXPLOSION_FRAMES[frame_idx]
            px = exp['x']
            py = exp['y']

            for row_idx, row in enumerate(frame):
                for col_idx, char in enumerate(row):
                    cx = px + col_idx - len(row) // 2
                    cy = py + row_idx - len(frame) // 2
                    if 0 <= cx < self.width - 1 and 0 <= cy < self.height and char != ' ':
                        try:
                            attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                            screen.attron(attr)
                            screen.addstr(cy, cx, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

        # Render NPC caller
        npc_x = self._qte_npc_x
        npc_y = self.height - 8

        for row_idx, row in enumerate(self.NPC_CALLER):
            for col_idx, char in enumerate(row):
                cx = npc_x + col_idx
                cy = npc_y + row_idx
                if 0 <= cx < self.width - 1 and 0 <= cy < self.height and char != ' ':
                    try:
                        attr = curses.color_pair(Colors.MATRIX_BRIGHT) | curses.A_BOLD
                        screen.attron(attr)
                        screen.addstr(cy, cx, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

        # Render NPC message/callout
        if self._qte_npc_message:
            msg_x = npc_x + 5
            msg_y = npc_y
            msg = self._qte_npc_message
            if 0 <= msg_y < self.height and msg_x + len(msg) < self.width:
                try:
                    # Message box background
                    attr = curses.color_pair(Colors.ALLEY_DARK)
                    screen.attron(attr)
                    screen.addstr(msg_y, msg_x - 1, ' ' * (len(msg) + 2))
                    screen.attroff(attr)

                    # Message text
                    attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                    screen.attron(attr)
                    screen.addstr(msg_y, msg_x, msg)
                    screen.attroff(attr)
                except curses.error:
                    pass

        # Render wave/score info
        if self._qte_state == 'active':
            info = f"Wave {self._qte_wave}/{self._qte_total_waves} | Score: {self._qte_score} | Miss: {self._qte_misses}"
            info_x = self.width // 2 - len(info) // 2
            info_y = 5
            if 0 <= info_y < self.height and 0 <= info_x < self.width:
                try:
                    attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_BOLD
                    screen.attron(attr)
                    screen.addstr(info_y, info_x, info)
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_woman_red(self, screen):
        """Render the Woman in Red event characters."""
        if not self._woman_red_active:
            return

        curb_y = self.height - 4  # Same as pedestrians

        def draw_character(x, sprite, color, is_blonde=False, is_transform=False):
            """Helper to draw a character sprite at position."""
            px_start = int(x)
            sprite_height = len(sprite)

            for row_idx, row in enumerate(sprite):
                for col_idx, char in enumerate(row):
                    px = px_start + col_idx
                    py = curb_y - (sprite_height - 1 - row_idx)

                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        try:
                            # Special coloring for woman in red
                            if is_blonde and row_idx == 0 and char == '~':
                                # Blonde hair - yellow
                                attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                            elif is_transform and char == '#':
                                # Glitch effect - flashing
                                attr = curses.color_pair(Colors.MATRIX_BRIGHT) | curses.A_BOLD
                            elif is_transform and char == '?':
                                # Partial transform - dim
                                attr = curses.color_pair(Colors.ALLEY_MID)
                            else:
                                attr = curses.color_pair(color)
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

        # Render based on current state
        if self._woman_red_state in ['neo_morpheus_enter', 'woman_enters', 'woman_passes', 'woman_waves', 'woman_pauses']:
            # Draw Neo (dark coat)
            neo_sprite = self.NEO_RIGHT_FRAMES[self._neo_frame]
            draw_character(self._neo_x, neo_sprite, Colors.ALLEY_BLUE)

            # Draw Morpheus (slightly behind Neo)
            morpheus_sprite = self.MORPHEUS_RIGHT_FRAMES[self._morpheus_frame]
            draw_character(self._morpheus_x, morpheus_sprite, Colors.GREY_BLOCK)

        if self._woman_red_state in ['woman_enters', 'woman_passes']:
            # Draw Woman in Red walking left
            woman_sprite = self.WOMAN_RED_LEFT_FRAMES[self._woman_red_frame]
            draw_character(self._woman_red_x, woman_sprite, Colors.SHADOW_RED, is_blonde=True)

        elif self._woman_red_state == 'woman_waves':
            # Draw Woman waving (10x faster)
            wave_frame = (self._woman_red_timer // 1) % len(self.WOMAN_RED_WAVE_FRAMES)
            woman_sprite = self.WOMAN_RED_WAVE_FRAMES[wave_frame]
            draw_character(self._woman_red_x, woman_sprite, Colors.SHADOW_RED, is_blonde=True)

        elif self._woman_red_state == 'woman_pauses':
            # Draw Woman standing still (last wave frame)
            woman_sprite = self.WOMAN_RED_WAVE_FRAMES[0]
            draw_character(self._woman_red_x, woman_sprite, Colors.SHADOW_RED, is_blonde=True)

        elif self._woman_red_state == 'transform':
            # Draw transform effect
            frame_idx = min(self._transform_frame, len(self.TRANSFORM_FRAMES) - 1)
            transform_sprite = self.TRANSFORM_FRAMES[frame_idx]
            draw_character(self._woman_red_x, transform_sprite, Colors.MATRIX_BRIGHT, is_transform=True)

        elif self._woman_red_state == 'chase':
            # Draw Neo running away (left)
            neo_sprite = self.NEO_LEFT_FRAMES[self._neo_frame]
            draw_character(self._neo_x, neo_sprite, Colors.ALLEY_BLUE)

            # Draw Morpheus running away (left)
            morpheus_sprite = self.MORPHEUS_LEFT_FRAMES[self._morpheus_frame]
            draw_character(self._morpheus_x, morpheus_sprite, Colors.GREY_BLOCK)

            # Draw Agent Smith chasing (left)
            agent_sprite = self.AGENT_SMITH_LEFT_FRAMES[self._agent_frame]
            draw_character(self._agent_x, agent_sprite, Colors.ALLEY_MID)

    def _render_cars(self, screen):
        """Render vehicles (cars, trucks, semis) on the street. Tied to log_watchdog health."""
        # Security canary: no vehicles if log watchdog is down
        if not self._security_canary.get('vehicles', True):
            return
        # Vehicles are 4-5 rows tall, bottom row at street level
        street_y = self.height - 1
        # Vehicles can't render above the 1/5th line
        min_car_y = self.height // 5

        for car in self._cars:
            x = int(car['x'])
            sprite = car['sprite']
            sprite_height = len(sprite)
            body_color = car.get('color', Colors.ALLEY_LIGHT)

            for row_idx, row in enumerate(sprite):
                for col_idx, char in enumerate(row):
                    px = x + col_idx
                    # Position sprite so bottom row is at street level
                    py = street_y - (sprite_height - 1 - row_idx)

                    # Don't render cars above the 1/5th line
                    if 0 <= px < self.width - 1 and min_car_y <= py < self.height and char != ' ':
                        try:
                            # Realistic vehicle coloring:
                            # - Tires (_) and () are dark/black
                            # - Bumpers (= - `) are chrome/silver
                            # - Windows (|) are blue tinted
                            # - Body panels (█) get the car's color
                            # - Structure/frame uses light grey
                            if char in '(_)':
                                # Tires - dark black
                                attr = curses.color_pair(Colors.ALLEY_DARK)
                            elif char in '=-`\'':
                                # Bumpers and trim - chrome/silver (bright white)
                                attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_BOLD
                            elif char == '|':
                                # Windows - blue tinted glass
                                attr = curses.color_pair(Colors.ALLEY_BLUE)
                            elif char == '█':
                                # Body panels - car's color
                                attr = curses.color_pair(body_color) | curses.A_BOLD
                            elif char in '/\\':
                                # Windshield angles - lighter
                                attr = curses.color_pair(Colors.ALLEY_MID)
                            elif char == '_':
                                # Undercarriage/shadow - dark
                                attr = curses.color_pair(Colors.ALLEY_DARK)
                            else:
                                # Other structure - medium grey
                                attr = curses.color_pair(Colors.GREY_BLOCK)
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_pedestrians(self, screen):
        """Render pedestrians on the sidewalk. Tied to process_security health."""
        # Security canary: no pedestrians if process security is down
        if not self._security_canary.get('pedestrians', True):
            return
        # Pedestrians walk on the curb/sidewalk area (at street level)
        base_curb_y = self.height - 1

        for ped in self._pedestrians:
            x = int(ped['x'])
            # Get y offset for wandering (pedestrians can be on different rows)
            y_offset = ped.get('y_offset', 0)
            curb_y = base_curb_y + y_offset  # Apply wandering offset

            # Check for special interaction poses
            interaction_state = ped.get('interaction_state')
            if interaction_state == 'hailing':
                # Use hailing pose instead of walking
                if ped.get('direction', 1) == 1:
                    sprite = self.PERSON_HAILING_RIGHT
                else:
                    sprite = self.PERSON_HAILING_LEFT
            elif interaction_state == 'mailing':
                # Use mailing pose
                sprite = self.PERSON_MAILING
            elif interaction_state == 'entering_door':
                # Fade out effect - skip rendering after a few frames
                timer = ped.get('interaction_timer', 0)
                if timer > 15:
                    continue  # Don't render, they're inside
                # Get current animation frame for partial render
                frames = ped.get('frames', [])
                frame_idx = ped.get('frame_idx', 0)
                if frames and frame_idx < len(frames):
                    sprite = frames[frame_idx]
                else:
                    continue
            else:
                # Get current animation frame
                frames = ped.get('frames', [])
                frame_idx = ped.get('frame_idx', 0)
                if frames and frame_idx < len(frames):
                    sprite = frames[frame_idx]
                else:
                    continue

            sprite_height = len(sprite)
            # Get colors for this pedestrian
            skin_color = ped.get('skin_color', Colors.ALLEY_LIGHT)
            clothing_color = ped.get('clothing_color', Colors.ALLEY_MID)

            for row_idx, row in enumerate(sprite):
                for col_idx, char in enumerate(row):
                    px = x + col_idx
                    # Position sprite so bottom row is at curb level
                    py = curb_y - (sprite_height - 1 - row_idx)

                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        try:
                            # Row 0 = head (skin tone), row 1-2 = body (clothing), row 3 = legs
                            if row_idx == 0:  # Head row - use skin tone
                                color = skin_color
                            elif row_idx in [1, 2]:  # Body rows - use clothing color
                                color = clothing_color
                            else:  # Legs - darker
                                color = Colors.GREY_BLOCK
                            attr = curses.color_pair(color)
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_knocked_out_peds(self, screen):
        """Render knocked out pedestrians lying on the ground."""
        curb_y = self.height - 1

        for ko_ped in self._knocked_out_peds:
            x = int(ko_ped['x'])
            y = curb_y

            sprite = self.KNOCKED_OUT_SPRITE[0]
            skin_color = ko_ped.get('skin_color', Colors.ALLEY_LIGHT)

            for col_idx, char in enumerate(sprite):
                px = x + col_idx - 3  # Center the sprite
                if 0 <= px < self.width - 1 and 0 <= y < self.height and char != ' ':
                    try:
                        # Use flashing color if being revived
                        if ko_ped.get('reviving', False) and ko_ped['timer'] % 10 < 5:
                            color = Colors.STATUS_OK
                        else:
                            color = skin_color
                        attr = curses.color_pair(color)
                        screen.attron(attr)
                        screen.addstr(y, px, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

    def _render_ambulance(self, screen):
        """Render ambulance and paramedic."""
        if not self._ambulance:
            return

        amb = self._ambulance
        x = int(amb['x'])
        curb_y = self.height - 1
        y = curb_y - 3  # Ambulance is 4 rows tall

        # Choose sprite based on direction
        if amb['direction'] == 1:
            sprite = self.AMBULANCE_RIGHT
        else:
            sprite = self.AMBULANCE_LEFT

        # Render ambulance
        for row_idx, row in enumerate(sprite):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    try:
                        # Red cross, white body
                        if char == '+':
                            color = Colors.SHADOW_RED
                        elif char in ['░', 'O']:
                            color = Colors.ALLEY_LIGHT
                        else:
                            color = Colors.GREY_BLOCK
                        attr = curses.color_pair(color)
                        screen.attron(attr)
                        screen.addstr(py, px, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

        # Render paramedic if out of ambulance
        if amb['state'] in ['paramedic_out', 'reviving', 'paramedic_return']:
            para_x = int(amb['paramedic_x'])
            para_y = curb_y - 2  # Paramedic is 3 rows
            for row_idx, row in enumerate(self.PARAMEDIC_SPRITE):
                for col_idx, char in enumerate(row):
                    px = para_x + col_idx
                    py = para_y + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        try:
                            # Green uniform
                            color = Colors.STATUS_OK
                            attr = curses.color_pair(color)
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_closeup_car(self, screen):
        """Render close-up car with perspective shrinking effect."""
        if not self._closeup_car:
            return

        car = self._closeup_car
        x = int(car['x'])  # Position calculated in _update_closeup_car
        scale = car['scale']
        direction = car['direction']
        # Calculate vertical offset based on scale (moves up as car shrinks)
        # At scale 3.0 (largest) = 0 offset, at scale 0.8 (smallest) = moves up
        scale_progress = (3.0 - scale) / 2.2  # 0 to 1 as car shrinks
        y_offset = int(scale_progress * (self.height // 5))  # Move up 1/5 of screen

        # Different car sprites based on scale (biggest to smallest)
        if scale >= 2.5:
            # Huge car (just passed camera)
            if direction == 1:
                sprite = [
                    "  .============.",
                    " /              \\",
                    "|  [O]      [O]  |",
                    "|________________|",
                    "  (__)       (__)",
                ]
            else:
                sprite = [
                    ".============.  ",
                    "/              \\",
                    "|  [O]      [O]  |",
                    "|________________|",
                    "  (__)       (__) ",
                ]
        elif scale >= 1.8:
            # Large car
            if direction == 1:
                sprite = [
                    " .========.",
                    "|  [O]  [O] |",
                    "|__________|",
                    " (__)  (__)",
                ]
            else:
                sprite = [
                    ".========. ",
                    "| [O]  [O] |",
                    "|__________|",
                    "(__)  (__) ",
                ]
        elif scale >= 1.3:
            # Medium car (normal-ish)
            if direction == 1:
                sprite = [
                    " .=====.",
                    "| O  O |",
                    "|______|",
                    " ()  ()",
                ]
            else:
                sprite = [
                    ".=====. ",
                    "| O  O |",
                    "|______|",
                    "()  () ",
                ]
        else:
            # Small car (far away)
            if direction == 1:
                sprite = [
                    " .==.",
                    "|OO|",
                ]
            else:
                sprite = [
                    ".==. ",
                    "|OO|",
                ]

        # Position car at street level (shifted up 2 rows + y_offset for perspective)
        street_y = self.height - 3 - y_offset
        sprite_height = len(sprite)

        # Render car on top of vanishing street (street is background)
        for row_idx, row in enumerate(sprite):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = street_y - (sprite_height - 1 - row_idx)

                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    try:
                        # Close-up car in bright white
                        attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_BOLD
                        screen.attron(attr)
                        screen.addstr(py, px, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

    def _render_street_light_flicker(self, screen):
        """Render flickering light effects under street lights. Tied to state_monitor."""
        # Security canary: no street lights if state monitor is down
        if not self._security_canary.get('street_lights', True):
            return
        # Light glow characters - brightest to dimmest
        glow_chars = ['█', '▓', '▒', '░']

        for i, (light_x, light_y) in enumerate(self._street_light_positions):
            if i >= len(self._street_light_flicker):
                continue

            brightness = self._street_light_flicker[i]

            # Draw light glow underneath the lamp (cone of light)
            # Brighter at top, dimmer at bottom
            glow_y = light_y + 1  # Start just below the lamp head
            for row in range(4):  # 4 rows of glow
                spread = row + 1  # Wider as it goes down
                # Top rows are brighter, bottom rows are dimmer
                row_brightness = brightness * (1.0 - row * 0.2)

                for dx in range(-spread, spread + 1):
                    px = light_x + dx
                    py = glow_y + row

                    if 0 <= px < self.width - 1 and 0 <= py < self.height:
                        # Pick glow character - brighter chars for top rows
                        dist_factor = abs(dx) / (spread + 1)
                        # Top row uses brightest char, bottom uses dimmest
                        char_idx = min(3, row + int(dist_factor * 2))
                        glow_char = glow_chars[char_idx] if row_brightness > 0.2 else ' '

                        if glow_char != ' ':
                            try:
                                # Top rows get BOLD, bottom rows get DIM
                                if row == 0:
                                    attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                                elif row == 1:
                                    attr = curses.color_pair(Colors.RAT_YELLOW)
                                else:
                                    attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_DIM
                                screen.attron(attr)
                                screen.addstr(py, px, glow_char)
                                screen.attroff(attr)
                            except curses.error:
                                pass

    def _render_building_window_lights(self, screen):
        """Render flickering light glow from building windows (no pole, just glow).
        Single row cone with most transparent blocks at edges.
        """
        # Gradient from solid to transparent: █ ▓ ▒ ░
        glow_chars = ['▓', '▒', '░']  # No solid block, start with semi-transparent

        for i, (light_x, light_y) in enumerate(self._building_window_lights):
            if i >= len(self._building_window_flicker):
                continue

            brightness = self._building_window_flicker[i]

            # Single row cone, 3 chars wide on each side
            spread = 2  # Width on each side
            py = light_y

            for dx in range(-spread, spread + 1):
                px = light_x + dx

                if 0 <= px < self.width - 1 and 0 <= py < self.height:
                    # More transparent at edges
                    dist = abs(dx)
                    if dist == 0:
                        char_idx = 0  # Center: ▓ (most solid of our set)
                    elif dist == 1:
                        char_idx = 1  # Mid: ▒
                    else:
                        char_idx = 2  # Edge: ░ (most transparent)

                    glow_char = glow_chars[char_idx] if brightness > 0.3 else ' '

                    if glow_char != ' ':
                        try:
                            attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_DIM
                            screen.attron(attr)
                            screen.addstr(py, px, glow_char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_window_scenes(self, screen):
        """Render unique mini scenes inside each building window."""
        for window in self._all_windows:
            brightness = window['brightness']

            # Skip completely dark windows (no scene visible)
            if brightness < 0.1:
                continue

            scene_chars = window.get('scene_chars', [])
            if not scene_chars:
                continue

            wx = window['x']
            wy = window['y']
            width = window['width']

            # Choose color based on brightness level for visible variation
            # Bright (0.9-1.0) = bright yellow, Medium (0.6-0.8) = mid tone,
            # Dim (0.3-0.5) = dark, Very dim (<0.3) = barely visible
            if brightness >= 0.9:
                color = Colors.RAT_YELLOW  # Bright warm light
                attr_mod = curses.A_BOLD
            elif brightness >= 0.7:
                color = Colors.RAT_YELLOW
                attr_mod = 0  # Normal
            elif brightness >= 0.5:
                color = Colors.ALLEY_MID
                attr_mod = 0
            elif brightness >= 0.3:
                color = Colors.ALLEY_MID
                attr_mod = curses.A_DIM
            else:
                color = Colors.ALLEY_DARK
                attr_mod = curses.A_DIM

            # Render each row of the scene
            for row_idx, row_chars in enumerate(scene_chars):
                py = wy + row_idx
                if py >= self.height:
                    continue

                for col_idx, char in enumerate(row_chars):
                    if col_idx >= width:
                        break
                    px = wx + col_idx
                    if px >= self.width - 1:
                        continue

                    # Only render non-space characters
                    if char != ' ':
                        try:
                            attr = curses.color_pair(color) | attr_mod
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_window_people(self, screen):
        """Render silhouettes of people walking by windows with animations."""
        for person in self._window_people:
            building = person['building']
            window_idx = person['window_idx']
            progress = person['progress']
            state = person.get('state', 'walking')

            # Get window position
            if building == 1:
                positions = self.BUILDING_WINDOW_POSITIONS
                base_x = self._building_x
                base_y = self._building_y
            else:
                positions = self.BUILDING2_WINDOW_POSITIONS
                base_x = self._building2_x
                base_y = self._building2_y

            if window_idx >= len(positions):
                continue

            row_offset, col_offset = positions[window_idx]
            window_x = base_x + col_offset
            window_y = base_y + row_offset

            # Calculate silhouette position within window (4 chars wide)
            window_width = 4
            silhouette_x = window_x + int(progress * window_width)

            # Choose silhouette based on state
            if state == 'walking' or state == 'leaving':
                # Walking silhouette - person shape
                silhouette = ['O', '|']  # Head and body
            elif state == 'staring':
                # Staring out window - face visible
                silhouette = ['O', '█']  # Head and shoulders
            elif state == 'waving':
                # Waving animation
                wave_frame = person.get('wave_frame', 0)
                if wave_frame == 0:
                    silhouette = ['O/', '█']  # Hand up right
                else:
                    silhouette = ['\\O', '█']  # Hand up left

            # Draw silhouette (2 chars tall) - use light color so visible against dark windows
            try:
                attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_BOLD
                screen.attron(attr)
                for i, char in enumerate(silhouette):
                    y = window_y + i
                    if 0 <= silhouette_x < self.width - 2 and 0 <= y < self.height:
                        screen.addstr(y, silhouette_x, char)
                screen.attroff(attr)
            except curses.error:
                pass

    def _render_cafe_people(self, screen):
        """Render the 3 people in Shell Cafe. Tied to wifi_security health."""
        # Security canary: no cafe people/lights if wifi security is down
        if not self._security_canary.get('cafe_lights', True):
            return
        if not hasattr(self, 'cafe_x') or not hasattr(self, 'cafe_y'):
            return

        # First floor door area is at rows 21-22 of CAFE sprite (0-indexed, after turtle shell)
        # Row 21: "[                  OPEN ]" - visible through door glass
        # Row 22: "[__________________     ]" - lower door area
        window_row = 21  # Row with people heads (door glass area)
        body_row = 22    # Row with bodies/arms
        window_start_col = 4  # Start of door glass content area

        # Arm animation frames (both arms shown)
        # Frame 0: arms down, Frame 1: left up, Frame 2: both up, Frame 3: right up
        arm_frames = [
            ('/|\\', '/ \\'),   # Frame 0: arms down
            ('\\|\\', '\\ \\'),  # Frame 1: left arm up
            ('\\|/', '\\ /'),    # Frame 2: both arms up (wave)
            ('/|/', '/ /'),      # Frame 3: right arm up
        ]

        for person in self._cafe_people:
            x_offset = int(person['x_offset'])
            arm_frame = person['arm_frame'] % len(arm_frames)

            # Calculate screen position
            px = self.cafe_x + window_start_col + x_offset
            py_head = self.cafe_y + window_row
            py_body = self.cafe_y + body_row

            if not (0 <= px < self.width - 3 and 0 <= py_head < self.height and 0 <= py_body < self.height):
                continue

            try:
                # Draw head
                attr = curses.color_pair(Colors.CAFE_WARM)
                screen.attron(attr)
                screen.addstr(py_head, px + 1, 'O')  # Head centered above body
                screen.attroff(attr)

                # Draw body with animated arms
                upper_body, lower_body = arm_frames[arm_frame]
                screen.attron(attr)
                screen.addstr(py_body, px, upper_body)  # Arms and torso
                screen.attroff(attr)
            except curses.error:
                pass

    def _render_turtle(self, screen):
        """Render turtle head peeking out of shell and winking."""
        if self._turtle_state == 'hidden':
            return

        if not hasattr(self, 'cafe_x') or not hasattr(self, 'cafe_y'):
            return

        # Turtle peeks out at row 3-4 of CAFE (middle of turtle shell logo)
        # Shell spans roughly columns 2-22 of CAFE sprite
        shell_row = 4
        turtle_y = self.cafe_y + shell_row

        # Position based on which side turtle peeks from
        if self._turtle_side == 1:  # Right side
            turtle_x = self.cafe_x + 25  # Right edge of shell
        else:  # Left side
            turtle_x = self.cafe_x - 1  # Left edge of shell

        # Get the current turtle head frame (now a list: [head, neck])
        frame = self.TURTLE_HEAD_FRAMES[self._turtle_frame]
        head = frame[0]
        neck = frame[1] if len(frame) > 1 else ""

        if not (0 <= turtle_x < self.width - len(head) and 0 <= turtle_y < self.height):
            return

        try:
            # Draw turtle head in green (like shell logo)
            attr = curses.color_pair(Colors.STATUS_OK) | curses.A_BOLD
            screen.attron(attr)
            # Draw head
            screen.addstr(turtle_y, turtle_x, head)
            # Draw neck below head
            if neck and turtle_y + 1 < self.height:
                screen.addstr(turtle_y + 1, turtle_x, neck)
            screen.attroff(attr)
        except curses.error:
            pass

    def _render_prop_plane(self, screen):
        """Render prop plane with trailing banner message."""
        if self._prop_plane is None:
            return

        plane = self._prop_plane
        x = int(plane['x'])
        y = plane['y']
        direction = plane['direction']
        message = plane['message']

        # Select plane sprite based on direction
        # Banner must trail BEHIND the plane (opposite side of nose)
        if direction == 1:
            plane_sprite = self.PROP_PLANE_RIGHT
            banner_offset = -len(message) - 8  # Banner trails behind (left of plane)
        else:
            plane_sprite = self.PROP_PLANE_LEFT
            banner_offset = len(plane_sprite[1]) + 2  # Banner trails behind (right of plane)

        # Draw plane
        for row_idx, row in enumerate(plane_sprite):
            py = y + row_idx
            for col_idx, char in enumerate(row):
                px = x + col_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    try:
                        if char in '(_)':
                            # Engine/body - dark
                            attr = curses.color_pair(Colors.GREY_BLOCK) | curses.A_BOLD
                        elif char in '-=':
                            # Wings - light
                            attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_BOLD
                        elif char == '>':
                            # Nose pointing right
                            attr = curses.color_pair(Colors.SHADOW_RED) | curses.A_BOLD
                        elif char == '<':
                            # Nose pointing left
                            attr = curses.color_pair(Colors.SHADOW_RED) | curses.A_BOLD
                        elif char == '~':
                            # Tail/exhaust
                            attr = curses.color_pair(Colors.ALLEY_MID)
                        elif char == '_':
                            # Top
                            attr = curses.color_pair(Colors.ALLEY_LIGHT)
                        else:
                            attr = curses.color_pair(Colors.ALLEY_LIGHT)
                        screen.attron(attr)
                        screen.addstr(py, px, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

        # Draw banner connection and message
        banner_y = y + 1  # Middle row of plane
        banner_x = x + banner_offset

        # Draw connection rope (trails behind banner)
        if direction == 1:
            # Moving right - rope connects on right side of banner, extends to plane on right
            rope = "]o~~"
            rope_x = banner_x + len(message)
        else:
            # Moving left - rope connects on left side of banner, extends to plane on left
            rope = "~~o["
            rope_x = banner_x - 4

        for i, char in enumerate(rope):
            px = rope_x + i
            if 0 <= px < self.width - 1 and 0 <= banner_y < self.height:
                try:
                    attr = curses.color_pair(Colors.ALLEY_MID)
                    screen.attron(attr)
                    screen.addstr(banner_y, px, char)
                    screen.attroff(attr)
                except curses.error:
                    pass

        # Draw banner message
        if direction == 1:
            msg_x = rope_x + len(rope)
        else:
            msg_x = banner_x

        for i, char in enumerate(message):
            px = msg_x + i
            if 0 <= px < self.width - 1 and 0 <= banner_y < self.height:
                try:
                    # Alternating colors for visibility
                    if i % 2 == 0:
                        attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                    else:
                        attr = curses.color_pair(Colors.SHADOW_RED) | curses.A_BOLD
                    screen.attron(attr)
                    screen.addstr(banner_y, px, char)
                    screen.attroff(attr)
                except curses.error:
                    pass

        # Draw banner end
        if direction == 1:
            end = "]"
            end_x = msg_x + len(message)
        else:
            end = "["
            end_x = msg_x - 1

        if 0 <= end_x < self.width - 1 and 0 <= banner_y < self.height:
            try:
                attr = curses.color_pair(Colors.ALLEY_MID)
                screen.attron(attr)
                screen.addstr(banner_y, end_x, end)
                screen.attroff(attr)
            except curses.error:
                pass

    def _render_traffic_light(self, screen):
        """Render the traffic light with current light states. Tied to health_monitor."""
        # Security canary: no traffic lights if health monitor is down
        if not self._security_canary.get('traffic_lights', True):
            return
        # Position traffic light on right side of scene (shifted 4 chars left)
        light_x = min(self.width - 10, self.box_x + len(self.BOX[0]) + 96)
        light_y = self.height - len(self.TRAFFIC_LIGHT_TEMPLATE) - 1  # Above curb, moved down

        if light_x < 0 or light_y < 0:
            return

        # Get current light states
        ns_red, ns_yellow, ns_green, ew_red, ew_yellow, ew_green = self._get_traffic_light_colors()

        # Render each row of traffic light
        # Compact template has lights at rows 1 (red), 2 (yellow), 3 (green)
        for row_idx, row in enumerate(self.TRAFFIC_LIGHT_TEMPLATE):
            for col_idx, char in enumerate(row):
                px = light_x + col_idx
                py = light_y + row_idx

                if not (0 <= px < self.width - 1 and 0 <= py < self.height):
                    continue
                if char == ' ':
                    continue

                # Determine color based on character position
                color = Colors.ALLEY_MID
                render_char = char

                if char == 'L':  # Left side lights (N/S direction)
                    if row_idx == 1:  # Red position
                        render_char, color = ns_red
                    elif row_idx == 2:  # Yellow position
                        render_char, color = ns_yellow
                    elif row_idx == 3:  # Green position
                        render_char, color = ns_green
                elif char == 'R':  # Right side lights (E/W direction)
                    if row_idx == 1:  # Red position
                        render_char, color = ew_red
                    elif row_idx == 2:  # Yellow position
                        render_char, color = ew_yellow
                    elif row_idx == 3:  # Green position
                        render_char, color = ew_green
                else:
                    render_char = char

                try:
                    if char in 'LR':
                        # Lights get bold when on
                        if render_char == 'O':
                            attr = curses.color_pair(color) | curses.A_BOLD
                        else:
                            attr = curses.color_pair(color) | curses.A_DIM
                    else:
                        # Structure of light
                        attr = curses.color_pair(Colors.ALLEY_MID) | curses.A_DIM

                    screen.attron(attr)
                    screen.addstr(py, px, render_char)
                    screen.attroff(attr)
                except curses.error:
                    pass


class LightningBolt:
    """
    Generates and renders dramatic lightning bolt across the screen.

    Creates a jagged lightning bolt path from top to bottom with
    screen flash and rapid flicker effect.
    """

    # Lightning bolt segment characters
    BOLT_CHARS = ['/', '\\', '|', '⚡', '╲', '╱', '│', '┃']

    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height
        self.path: List[Tuple[int, int]] = []  # (y, x) coordinates
        self._generate_bolt()

    def _generate_bolt(self):
        """Generate a jagged lightning bolt path from top to bottom."""
        self.path = []
        if self.width <= 0 or self.height <= 0:
            return

        # Start from random position in top third
        x = random.randint(self.width // 4, 3 * self.width // 4)
        y = 0

        while y < self.height:
            self.path.append((y, x))

            # Move down 1-3 rows
            y += random.randint(1, 3)

            # Jag left or right randomly
            direction = random.choice([-2, -1, -1, 0, 1, 1, 2])
            x = max(1, min(self.width - 2, x + direction))

            # Occasionally add a branch
            if random.random() < 0.15 and len(self.path) > 3:
                branch_x = x + random.choice([-3, -2, 2, 3])
                branch_y = y
                for _ in range(random.randint(2, 5)):
                    if 0 <= branch_x < self.width and branch_y < self.height:
                        self.path.append((branch_y, branch_x))
                        branch_y += 1
                        branch_x += random.choice([-1, 0, 1])

    def render(self, screen, flash_intensity: float = 1.0):
        """
        Render the lightning bolt with optional flash intensity.

        Args:
            screen: curses screen object
            flash_intensity: 0.0-1.0, controls visibility (for flicker effect)
        """
        if flash_intensity < 0.3:
            return  # Don't render during dim phase

        for y, x in self.path:
            if 0 <= y < self.height and 0 <= x < self.width:
                try:
                    char = random.choice(self.BOLT_CHARS)
                    attr = curses.color_pair(Colors.LIGHTNING) | curses.A_BOLD
                    if flash_intensity < 0.7:
                        attr = curses.color_pair(Colors.MATRIX_BRIGHT) | curses.A_BOLD
                    screen.attron(attr)
                    screen.addstr(y, x, char)
                    screen.attroff(attr)
                except curses.error:
                    pass

    @staticmethod
    def flash_screen(screen, width: int, height: int):
        """Flash the entire screen white briefly."""
        attr = curses.color_pair(Colors.LIGHTNING)
        try:
            for y in range(height):
                screen.attron(attr)
                screen.addstr(y, 0, ' ' * (width - 1))
                screen.attroff(attr)
        except curses.error:
            pass


class AlleyRat:
    """
    Yellow ASCII rat that scurries around the alley when security warnings appear.

    The rat appears near the dumpster or edges of the scene and moves
    in quick, erratic patterns when there are active warnings.
    """

    # Rat animation frames - no visible eyes
    # Sitting: 2x2 chars, Moving: 1x3 chars (horizontal running)
    RAT_FRAMES = {
        'right': [
            # Running right - 1x3 horizontal (tail-body-head)
            ["~=>"],
            ["_->"],
        ],
        'left': [
            # Running left - 1x3 horizontal (head-body-tail)
            ["<=~"],
            ["<-_"],
        ],
        'idle': [
            # Sitting rat - 2x2, no eyes (just fur/shape)
            ["()", "vv"],  # Curled up
            ["{}", "^^"],  # Slightly different
        ],
        'look_left': [
            ["<)", "vv"],  # Head turned left, 2x2
        ],
        'look_right': [
            ["(>", "vv"],  # Head turned right, 2x2
        ],
    }

    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height
        self.active = False
        self.visible = False

        # Position and movement
        self.x = 0.0
        self.y = 0.0
        self.target_x = 0.0
        self.target_y = 0.0
        self.direction = 'idle'
        self.speed = 0.0

        # Animation state
        self.frame = 0
        self.frame_counter = 0
        self.pause_counter = 0

        # Behavior state
        self._hiding = True
        self._flee_timer = 0

        # Hopping state - discrete jumps instead of continuous movement
        self._hop_cooldown = 0
        self._look_timer = 0
        self._look_direction = 'idle'

        # Hiding spots (positions behind objects)
        self._hiding_spots: List[Tuple[float, float]] = []

        # Floor constraint (building bottom level) - rat can't go above this
        self._floor_y = height * 4 // 5  # Default, updated by set_hiding_spots

    def set_hiding_spots(self, alley_scene):
        """Set hiding spots based on alley scene objects."""
        self._hiding_spots = []
        if alley_scene:
            # Behind dumpster (to the right of it)
            dumpster_behind_x = alley_scene.dumpster_x + 2
            dumpster_y = alley_scene.dumpster_y + 2
            self._hiding_spots.append((float(dumpster_behind_x), float(dumpster_y)))

            # Behind box (to the right of it)
            box_behind_x = alley_scene.box_x + 2
            box_y = alley_scene.box_y + 1
            self._hiding_spots.append((float(box_behind_x), float(box_y)))

            # Set floor constraint from building bottom - rat can't climb above this
            self._floor_y = alley_scene._building_bottom_y

    def resize(self, width: int, height: int):
        """Handle terminal resize."""
        self.width = width
        self.height = height
        # Keep rat in bounds
        self.x = min(self.x, width - 3)
        self.y = min(self.y, height - 3)

    def activate(self):
        """Activate the rat when warnings appear."""
        if not self.active:
            self.active = True
            self.visible = True
            self._hiding = False
            # Spawn at building bottom level, near dumpster area (above curb)
            max_y = self.height - 5
            min_y = min(self._floor_y, max_y)  # Ensure valid range
            self.x = float(random.randint(8, max(10, self.width // 4)))
            self.y = float(random.randint(min_y, max_y))  # Stay above curb
            self._pick_new_target()

    def deactivate(self):
        """Deactivate the rat when warnings clear."""
        # Rat runs off screen to hide
        if self.active and not self._hiding:
            self._hiding = True
            self.target_x = -5.0  # Run off left edge
            self.target_y = self.y
            self.speed = 1.5  # Fast escape

    def _pick_new_target(self):
        """Pick a new target position for the rat to scurry to."""
        # Stay at building bottom level, above the curb (can hide behind building)
        max_y = self.height - 5  # Stay above curb and street
        min_y = min(self._floor_y, max_y)  # Ensure valid range

        if random.random() < 0.6:
            # Most of the time, stay still and look around
            self.target_x = self.x
            self.target_y = self.y
            self.pause_counter = random.randint(40, 100)  # Longer pauses
            self.speed = 0
            self.direction = 'idle'
            self._look_timer = random.randint(15, 35)  # Start looking around
        elif random.random() < 0.4 and self._hiding_spots:
            # Sometimes hide behind dumpster or box
            hide_spot = random.choice(self._hiding_spots)
            self.target_x = hide_spot[0]
            self.target_y = hide_spot[1]
            # Use hopping
            self.speed = 0
            self._hop_cooldown = 0

            # Set direction based on target
            if self.target_x > self.x:
                self.direction = 'right'
            else:
                self.direction = 'left'
        else:
            # Occasionally hop to a random spot at building bottom level (above curb)
            self.target_x = float(random.randint(6, max(7, self.width // 3)))
            self.target_y = float(random.randint(min_y, max_y))
            # Use hopping - will move in discrete jumps
            self.speed = 0  # Don't move continuously
            self._hop_cooldown = 0  # Ready to hop

            # Set direction based on target
            if self.target_x > self.x:
                self.direction = 'right'
            else:
                self.direction = 'left'

    def update(self):
        """Update rat position and animation."""
        if not self.active:
            return

        self.frame_counter += 1

        # Handle looking around while idle - slow animation
        if self.direction == 'idle' and self.pause_counter > 0:
            self._look_timer -= 1
            if self._look_timer <= 0:
                # Switch look direction
                look_choice = random.random()
                if look_choice < 0.3:
                    self._look_direction = 'look_left'
                elif look_choice < 0.6:
                    self._look_direction = 'look_right'
                else:
                    self._look_direction = 'idle'
                self._look_timer = random.randint(20, 50)

            # Slow blink animation for idle (every 20 frames)
            if self.frame_counter % 20 == 0:
                frames = self.RAT_FRAMES.get(self._look_direction, self.RAT_FRAMES['idle'])
                self.frame = (self.frame + 1) % len(frames)
        elif self.direction in ('left', 'right'):
            # Moving animation - cycle frames while hopping
            if self._hop_cooldown <= 3:  # Only animate during hop
                if self.frame_counter % 3 == 0:
                    frames = self.RAT_FRAMES.get(self.direction, self.RAT_FRAMES['idle'])
                    self.frame = (self.frame + 1) % len(frames)

        # Handle pause (idle state)
        if self.pause_counter > 0:
            self.pause_counter -= 1
            if self.pause_counter == 0:
                self._pick_new_target()
            return

        # Handle fleeing (continuous fast movement)
        if self._hiding and self.speed > 0:
            dx = self.target_x - self.x
            dy = self.target_y - self.y
            dist = math.sqrt(dx * dx + dy * dy)
            if dist < 0.5 or self.x < 0:
                self.active = False
                self.visible = False
            else:
                self.x += (dx / dist) * self.speed
                self.y += (dy / dist) * self.speed
            return

        # Hopping movement - discrete jumps with pauses between
        if self.direction in ('left', 'right'):
            self._hop_cooldown -= 1
            if self._hop_cooldown <= 0:
                # Make a hop towards target
                dx = self.target_x - self.x
                dy = self.target_y - self.y
                dist = math.sqrt(dx * dx + dy * dy)

                if dist < 1.5:
                    # Reached target, pause and pick new target
                    self._pick_new_target()
                else:
                    # Hop a fixed distance (1-2 units)
                    hop_dist = min(dist, random.uniform(1.0, 2.0))
                    self.x += (dx / dist) * hop_dist
                    self.y += (dy / dist) * hop_dist
                    # Pause between hops
                    self._hop_cooldown = random.randint(8, 20)

    def render(self, screen):
        """Render the rat."""
        if not self.visible or not self.active:
            return

        # Use look direction when idle
        render_direction = self.direction
        if self.direction == 'idle':
            render_direction = self._look_direction if self._look_direction else 'idle'

        frames = self.RAT_FRAMES.get(render_direction, self.RAT_FRAMES['idle'])
        frame = frames[self.frame % len(frames)]

        ix = int(self.x)
        iy = int(self.y)

        attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD

        try:
            for row_idx, row in enumerate(frame):
                for col_idx, char in enumerate(row):
                    px = ix + col_idx
                    py = iy + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height - 1 and char != ' ':
                        screen.attron(attr)
                        screen.addstr(py, px, char)
                        screen.attroff(attr)
        except curses.error:
            pass


class LurkingShadow:
    """
    Lurking shadow with glowing red eyes that appears when threats are detected.

    The shadow lurks in dark corners of the alley, with only its red eyes
    visible. Occasionally blinks and shifts position.
    """

    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height
        self.active = False

        # Position (eyes position)
        self.x = 0
        self.y = 0

        # Blinking state
        self.eyes_open = True
        self.blink_counter = 0
        self.blink_interval = random.randint(30, 80)

        # Movement state
        self.move_counter = 0
        self.move_interval = random.randint(100, 300)

        # Intensity (for flickering eyes)
        self.intensity = 1.0
        self.flicker_counter = 0

    def resize(self, width: int, height: int):
        """Handle terminal resize."""
        self.width = width
        self.height = height
        # Keep in bounds
        self.x = min(self.x, width - 3)
        self.y = min(self.y, height - 2)

    def activate(self):
        """Activate the shadow when threats appear."""
        if not self.active:
            self.active = True
            self._choose_lurk_position()

    def deactivate(self):
        """Deactivate the shadow."""
        self.active = False

    def _choose_lurk_position(self):
        """Choose a dark corner to lurk in."""
        # Lurk only at screen edges, in the lower half
        positions = []

        # Lower half starts at height // 2
        lower_half_start = self.height // 2
        lower_bound = self.height - 4  # Don't go too close to bottom

        # Left edge - lower half only
        positions.append((random.randint(0, 5), random.randint(lower_half_start, lower_bound)))
        positions.append((random.randint(0, 3), random.randint(lower_half_start, lower_bound)))

        # Right edge - lower half only
        positions.append((self.width - random.randint(3, 8), random.randint(lower_half_start, lower_bound)))
        positions.append((self.width - random.randint(2, 6), random.randint(lower_half_start, lower_bound)))

        # Pick one
        pos = random.choice(positions)
        self.x = max(0, min(pos[0], self.width - 3))
        self.y = max(lower_half_start, min(pos[1], self.height - 2))

        # Reset blink/move timers
        self.blink_interval = random.randint(30, 80)
        self.move_interval = random.randint(100, 300)

    def update(self):
        """Update shadow state."""
        if not self.active:
            return

        self.blink_counter += 1
        self.move_counter += 1
        self.flicker_counter += 1

        # Subtle intensity flicker
        self.intensity = 0.8 + 0.2 * math.sin(self.flicker_counter * 0.1)

        # Blink occasionally
        if self.blink_counter >= self.blink_interval:
            self.blink_counter = 0
            self.eyes_open = not self.eyes_open
            if self.eyes_open:
                # Eyes were closed, now open - new blink interval
                self.blink_interval = random.randint(30, 80)
            else:
                # Closing eyes briefly
                self.blink_interval = random.randint(2, 5)

        # Move to new position occasionally
        if self.move_counter >= self.move_interval:
            self.move_counter = 0
            self._choose_lurk_position()

    def render(self, screen):
        """Render the lurking shadow with glowing red eyes."""
        if not self.active or not self.eyes_open:
            return

        # The shadow itself is invisible (dark)
        # Only render the glowing red eyes

        # Eyes: two dots with a space between
        eyes = "o o"

        # Determine intensity (for flickering effect)
        if self.intensity > 0.9:
            attr = curses.color_pair(Colors.SHADOW_RED) | curses.A_BOLD
        else:
            attr = curses.color_pair(Colors.SHADOW_RED)

        try:
            if 0 <= self.y < self.height - 1 and 0 <= self.x < self.width - 3:
                screen.attron(attr)
                screen.addstr(self.y, self.x, eyes)
                screen.attroff(attr)
        except curses.error:
            pass


class DashboardClient:
    """Client for communicating with daemon via socket API."""

    # Windows TCP fallback
    WINDOWS_HOST = '127.0.0.1'
    WINDOWS_PORT = 19847

    def __init__(self, socket_path: Optional[str] = None):
        self.socket_path = socket_path
        self._connected = False
        self._use_tcp = False  # Flag for Windows TCP mode
        self._log_file_path = None  # Path to daemon log file for offline mode
        self._connection_debug_log = []  # Store debug messages

        # Set up debug log file
        self._debug_log_path = self._setup_debug_log()

        self._log_debug("=" * 60)
        self._log_debug(f"TUI Connection Debug - {datetime.now().isoformat()}")
        self._log_debug(f"Platform: {sys.platform}")
        self._log_debug(f"Python version: {sys.version}")
        self._log_debug("=" * 60)

        # Build dynamic socket paths based on where daemon might create them
        self._socket_paths = self._build_socket_paths()
        self._log_debug(f"Socket paths to try: {self._socket_paths}")

        # Find log file for reading real events when offline
        self._log_file_path = self._find_log_file()
        self._log_debug(f"Daemon log file: {self._log_file_path}")

        # Try to find working socket
        if not self.socket_path:
            self.socket_path = self._find_socket()
        self._log_debug(f"Selected socket path: {self.socket_path}")

        # Resolve token after finding socket (token might be near socket)
        self._token = self._resolve_token()
        self._log_debug(f"API token found: {'Yes' if self._token else 'No'}")

        # On Windows, try TCP first (more reliable than Unix sockets)
        if sys.platform == 'win32':
            self._log_debug("Windows detected - trying TCP connection first")
            self._log_debug(f"Attempting TCP connection to {self.WINDOWS_HOST}:{self.WINDOWS_PORT}")

            if self._try_tcp_connection():
                self._connected = True
                self._use_tcp = True
                self._log_debug("SUCCESS: Connected via TCP")
                logger.info(f"Connected to daemon via TCP on port {self.WINDOWS_PORT}")
            else:
                self._log_debug("TCP connection failed, trying Unix socket fallback")
                # Fallback to socket test (unlikely to work on Windows)
                self._connected = self._test_connection()
                self._log_debug(f"Unix socket fallback result: {self._connected}")
        else:
            self._log_debug("Unix platform - trying socket connection first")
            # On Unix, try socket first, then TCP as fallback
            self._connected = self._test_connection()
            self._log_debug(f"Unix socket connection result: {self._connected}")

            if not self._connected:
                self._log_debug(f"Socket failed, trying TCP fallback to {self.WINDOWS_HOST}:{self.WINDOWS_PORT}")
                if self._try_tcp_connection():
                    self._connected = True
                    self._use_tcp = True
                    self._log_debug("SUCCESS: Connected via TCP fallback")
                    logger.info(f"Connected to daemon via TCP on port {self.WINDOWS_PORT}")

        if not self._connected:
            self._log_debug("FAILED: Could not connect to daemon")
            self._log_debug("Checking for offline log file...")
            if self._log_file_path and os.path.exists(self._log_file_path):
                self._log_debug(f"Found log file for offline mode: {self._log_file_path}")
                logger.info(f"Daemon not connected, reading events from {self._log_file_path}")
            else:
                self._log_debug("No log file found - running in demo mode")
                logger.info("Daemon not available, no log file found")

            # Additional diagnostics
            self._run_connection_diagnostics()
        else:
            self._log_debug(f"SUCCESS: Connected (use_tcp={self._use_tcp})")

        # Write all debug info to log file
        self._flush_debug_log()

    def _setup_debug_log(self) -> str:
        """Set up debug log file path."""
        # Try several locations
        log_locations = [
            Path(__file__).parent.parent.parent / 'logs' / 'tui_connection_debug.log',
            Path.home() / '.boundary-daemon' / 'logs' / 'tui_connection_debug.log',
            Path('./tui_connection_debug.log'),
        ]

        for log_path in log_locations:
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                # Test we can write to it
                with open(log_path, 'a') as f:
                    f.write('')
                return str(log_path)
            except (OSError, PermissionError):
                continue

        # Fallback to current directory
        return './tui_connection_debug.log'

    def _log_debug(self, message: str):
        """Add a debug message to the log buffer."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        self._connection_debug_log.append(f"[{timestamp}] {message}")

    def _flush_debug_log(self):
        """Write all buffered debug messages to log file."""
        try:
            with open(self._debug_log_path, 'a') as f:
                f.write('\n'.join(self._connection_debug_log) + '\n\n')
            self._connection_debug_log = []
        except Exception as e:
            logger.warning(f"Could not write debug log to {self._debug_log_path}: {e}")

    def _run_connection_diagnostics(self):
        """Run detailed connection diagnostics."""
        self._log_debug("\n--- Connection Diagnostics ---")

        # Check if port 19847 is in use
        self._log_debug(f"Checking if port {self.WINDOWS_PORT} is listening...")
        try:
            import psutil
            listening = False
            for conn in psutil.net_connections(kind='tcp'):
                if conn.laddr.port == self.WINDOWS_PORT:
                    self._log_debug(f"  Port {self.WINDOWS_PORT}: status={conn.status}, pid={conn.pid}")
                    if conn.status == 'LISTEN':
                        listening = True
                        try:
                            proc = psutil.Process(conn.pid)
                            self._log_debug(f"  Listening process: {proc.name()} (PID {conn.pid})")
                            self._log_debug(f"  Process cmdline: {' '.join(proc.cmdline())}")
                        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                            self._log_debug(f"  Could not get process info: {e}")
            if not listening:
                self._log_debug(f"  Port {self.WINDOWS_PORT} is NOT listening - daemon may not be running")
        except ImportError:
            self._log_debug("  psutil not available - cannot check port status")
        except Exception as e:
            self._log_debug(f"  Error checking port: {e}")

        # Check socket file existence
        self._log_debug("\nChecking socket paths:")
        for path in self._socket_paths:
            exists = os.path.exists(path)
            self._log_debug(f"  {path}: {'EXISTS' if exists else 'not found'}")

        # Check for daemon process
        self._log_debug("\nSearching for daemon process:")
        try:
            import psutil
            found_daemon = False
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    name = (proc.info.get('name') or '').lower()
                    cmdline = ' '.join(proc.info.get('cmdline') or []).lower()
                    if 'boundary' in name or 'boundary' in cmdline:
                        found_daemon = True
                        self._log_debug(f"  Found: PID={proc.info['pid']} name={proc.info['name']}")
                        self._log_debug(f"    cmdline: {cmdline[:100]}...")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            if not found_daemon:
                self._log_debug("  No daemon process found - daemon is probably not running")
        except ImportError:
            self._log_debug("  psutil not available")
        except Exception as e:
            self._log_debug(f"  Error: {e}")

        # Try direct TCP connection with detailed error
        self._log_debug(f"\nTrying direct TCP connection to {self.WINDOWS_HOST}:{self.WINDOWS_PORT}:")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect((self.WINDOWS_HOST, self.WINDOWS_PORT))
            self._log_debug("  TCP connect succeeded!")
            sock.close()
        except ConnectionRefusedError:
            self._log_debug("  ConnectionRefusedError - daemon not listening on this port")
        except socket.timeout:
            self._log_debug("  Timeout - no response from daemon")
        except OSError as e:
            self._log_debug(f"  OSError: {e}")
        except Exception as e:
            self._log_debug(f"  Error: {type(e).__name__}: {e}")

        self._log_debug("\n--- End Diagnostics ---\n")

    def _find_log_file(self) -> Optional[str]:
        """Find the daemon log file for reading real events offline."""
        package_root = Path(__file__).parent.parent.parent

        # Check possible log file locations
        log_paths = [
            package_root / 'logs' / 'boundary_chain.log',
            package_root / 'boundary_chain.log',
            Path('/var/log/boundary-daemon/boundary_chain.log'),
            Path.home() / '.boundary-daemon' / 'logs' / 'boundary_chain.log',
        ]

        for log_path in log_paths:
            if log_path.exists():
                return str(log_path)

        return None

    def _read_events_from_log(self, limit: int = 20) -> List[DashboardEvent]:
        """Read real events from daemon log file."""
        events = []

        if not self._log_file_path or not os.path.exists(self._log_file_path):
            return events

        try:
            with open(self._log_file_path, 'r') as f:
                lines = f.readlines()

            # Read last N lines (most recent events)
            for line in reversed(lines[-limit*2:]):  # Read more to filter
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                    # Map log entry to DashboardEvent
                    event_type = entry.get('event_type', 'UNKNOWN').upper()
                    details = entry.get('details', '')
                    timestamp = entry.get('timestamp', datetime.utcnow().isoformat())

                    # Map severity from metadata
                    metadata = entry.get('metadata', {})
                    alert_level = metadata.get('alert_level', 'info')
                    severity_map = {
                        'critical': 'ERROR',
                        'error': 'ERROR',
                        'warning': 'WARN',
                        'warn': 'WARN',
                        'info': 'INFO',
                    }
                    severity = severity_map.get(alert_level.lower(), 'INFO')

                    events.append(DashboardEvent(
                        timestamp=timestamp,
                        event_type=event_type,
                        details=details,
                        severity=severity,
                        metadata=metadata,
                    ))

                    if len(events) >= limit:
                        break

                except (json.JSONDecodeError, KeyError):
                    continue

        except Exception as e:
            logger.warning(f"Error reading log file: {e}")

        return events

    def _read_status_from_log(self) -> Dict:
        """Read status from the most recent log entries."""
        status = {
            'mode': 'UNKNOWN',
            'mode_since': datetime.utcnow().isoformat(),
            'uptime': 0,
            'events_today': 0,
            'violations': 0,
            'tripwire_enabled': True,
            'clock_monitor_enabled': True,
            'network_attestation_enabled': True,
            'is_frozen': False,
        }

        if not self._log_file_path or not os.path.exists(self._log_file_path):
            return status

        try:
            with open(self._log_file_path, 'r') as f:
                lines = f.readlines()

            event_count = len(lines)
            violation_count = 0

            # Scan recent entries for mode and violations
            for line in reversed(lines[-100:]):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                    event_type = entry.get('event_type', '')

                    if event_type == 'mode_change':
                        metadata = entry.get('metadata', {})
                        if 'new_mode' in metadata:
                            # Map mode number to name
                            mode_map = {0: 'OPEN', 1: 'TRUSTED', 2: 'RESTRICTED', 3: 'AIRGAP'}
                            status['mode'] = mode_map.get(metadata['new_mode'], 'UNKNOWN')
                        status['mode_since'] = entry.get('timestamp', status['mode_since'])

                    elif event_type == 'daemon_start':
                        metadata = entry.get('metadata', {})
                        status['mode'] = metadata.get('initial_mode', status['mode'])

                    elif event_type == 'violation':
                        violation_count += 1

                except (json.JSONDecodeError, KeyError):
                    continue

            status['events_today'] = event_count
            status['violations'] = violation_count

        except Exception as e:
            logger.warning(f"Error reading status from log: {e}")

        return status

    def _build_socket_paths(self) -> List[str]:
        """Build list of possible socket paths based on daemon behavior."""
        paths = []

        # Get package root directory (where boundary-daemon- is installed)
        package_root = Path(__file__).parent.parent.parent

        # 1. Check for running daemon process and get its working directory
        daemon_cwd = self._find_daemon_working_dir()
        if daemon_cwd:
            paths.append(os.path.join(daemon_cwd, 'api', 'boundary.sock'))

        # 2. Relative to package root (most common for development)
        paths.append(str(package_root / 'api' / 'boundary.sock'))

        # 2b. Sibling to logs directory (daemon creates socket relative to log_dir parent)
        # If log file is at /path/logs/boundary_chain.log, socket is at /path/api/boundary.sock
        if self._log_file_path:
            log_parent = Path(self._log_file_path).parent.parent
            paths.append(str(log_parent / 'api' / 'boundary.sock'))

        # 3. Standard system locations
        paths.append('/var/run/boundary-daemon/boundary.sock')

        # 4. User home directory locations
        paths.append(os.path.expanduser('~/.boundary-daemon/api/boundary.sock'))
        paths.append(os.path.expanduser('~/.agent-os/api/boundary.sock'))

        # 5. Current working directory
        paths.append('./api/boundary.sock')

        # 6. Check PID file for daemon location hints
        pid_socket = self._find_socket_from_pid_file()
        if pid_socket:
            paths.insert(0, pid_socket)

        # Remove duplicates while preserving order
        seen = set()
        unique_paths = []
        for p in paths:
            normalized = os.path.normpath(os.path.abspath(p))
            if normalized not in seen:
                seen.add(normalized)
                unique_paths.append(p)

        return unique_paths

    def _find_daemon_working_dir(self) -> Optional[str]:
        """Find working directory of running daemon process."""
        try:
            import psutil

            # First try: Find by process name/cmdline matching
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cwd', 'exe']):
                try:
                    # Check process name (works for .exe files)
                    name = (proc.info.get('name') or '').lower()
                    exe = (proc.info.get('exe') or '').lower()
                    cmdline = proc.info.get('cmdline') or []
                    cmdline_str = ' '.join(cmdline).lower()

                    # Look for boundary daemon process by various methods
                    is_daemon = False

                    # Method 1: Process name contains 'boundary'
                    if 'boundary' in name:
                        is_daemon = True
                    # Method 2: Exe path contains 'boundary'
                    elif 'boundary' in exe:
                        is_daemon = True
                    # Method 3: Command line contains both 'boundary' and 'daemon'
                    elif 'boundary' in cmdline_str and 'daemon' in cmdline_str:
                        is_daemon = True
                    # Method 4: Running boundary_daemon module
                    elif 'boundary_daemon' in cmdline_str:
                        is_daemon = True
                    # Method 5: Command line contains boundary-daemon- (directory name)
                    elif 'boundary-daemon-' in cmdline_str:
                        is_daemon = True

                    if is_daemon:
                        cwd = proc.info.get('cwd')
                        if cwd:
                            logger.debug(f"Found daemon process {proc.info['pid']} ({name}) at {cwd}")
                            return cwd
                        # If no cwd, try exe directory
                        if exe:
                            exe_dir = os.path.dirname(exe)
                            if exe_dir:
                                logger.debug(f"Found daemon exe {proc.info['pid']} at {exe_dir}")
                                return exe_dir
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            # Second try: Find process listening on port 19847 (TCP mode)
            for conn in psutil.net_connections(kind='tcp'):
                if conn.laddr.port == self.WINDOWS_PORT and conn.status == 'LISTEN':
                    try:
                        proc = psutil.Process(conn.pid)
                        cwd = proc.cwd()
                        if cwd:
                            logger.debug(f"Found daemon on port {self.WINDOWS_PORT}, pid {conn.pid}, cwd: {cwd}")
                            return cwd
                        exe_path = proc.exe()
                        if exe_path:
                            exe_dir = os.path.dirname(exe_path)
                            logger.debug(f"Found daemon on port {self.WINDOWS_PORT}, pid {conn.pid}, exe: {exe_dir}")
                            return exe_dir
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue

        except ImportError:
            logger.debug("psutil not available for process detection")
        except Exception as e:
            logger.debug(f"Error finding daemon process: {e}")
        return None

    def _find_socket_from_pid_file(self) -> Optional[str]:
        """Find socket path from daemon PID file."""
        pid_file_locations = [
            '/var/run/boundary-daemon/boundary.pid',
            os.path.expanduser('~/.boundary-daemon/boundary.pid'),
            './boundary.pid',
        ]
        # Add Windows-specific locations
        if sys.platform == 'win32':
            appdata = os.environ.get('APPDATA', '')
            localappdata = os.environ.get('LOCALAPPDATA', '')
            if appdata:
                pid_file_locations.append(os.path.join(appdata, 'boundary-daemon', 'boundary.pid'))
            if localappdata:
                pid_file_locations.append(os.path.join(localappdata, 'boundary-daemon', 'boundary.pid'))

        for pid_file in pid_file_locations:
            if os.path.exists(pid_file):
                # Socket is usually in api/ subdirectory relative to PID file
                pid_dir = os.path.dirname(pid_file)
                socket_path = os.path.join(pid_dir, 'api', 'boundary.sock')
                if os.path.exists(socket_path):
                    return socket_path
                # Or in parent directory's api folder
                parent_api = os.path.join(os.path.dirname(pid_dir), 'api', 'boundary.sock')
                if os.path.exists(parent_api):
                    return parent_api
        return None

    def _resolve_token(self) -> Optional[str]:
        """Resolve API token from environment, file, or bootstrap token."""
        self._log_debug("Resolving API token...")

        # 1. Environment variable (highest priority)
        token = os.environ.get('BOUNDARY_API_TOKEN')
        if token:
            self._log_debug("Found token in BOUNDARY_API_TOKEN environment variable")
            return token.strip()

        # Build paths to check
        token_paths = []
        bootstrap_paths = []

        # If we found a socket, look for token near it
        if self.socket_path:
            socket_dir = os.path.dirname(self.socket_path)
            parent_dir = os.path.dirname(socket_dir)
            token_paths.append(os.path.join(parent_dir, 'config', 'api_tokens.json'))
            token_paths.append(os.path.join(socket_dir, 'api_tokens.json'))
            # Bootstrap token locations
            bootstrap_paths.append(os.path.join(parent_dir, 'config', 'bootstrap_token.txt'))
            bootstrap_paths.append(os.path.join(parent_dir, 'config', 'tui_token.txt'))

        # Package root config
        package_root = Path(__file__).parent.parent.parent
        token_paths.append(str(package_root / 'config' / 'api_tokens.json'))
        bootstrap_paths.append(str(package_root / 'config' / 'bootstrap_token.txt'))
        bootstrap_paths.append(str(package_root / 'config' / 'tui_token.txt'))

        # Standard locations
        token_paths.extend([
            './config/api_tokens.json',
            os.path.expanduser('~/.boundary-daemon/config/api_tokens.json'),
            os.path.expanduser('~/.agent-os/api_token'),
            '/etc/boundary-daemon/api_token',
        ])
        bootstrap_paths.extend([
            './config/bootstrap_token.txt',
            './config/tui_token.txt',
            os.path.expanduser('~/.boundary-daemon/config/bootstrap_token.txt'),
            os.path.expanduser('~/.boundary-daemon/config/tui_token.txt'),
        ])

        # 2. Check for bootstrap/TUI token files (plaintext token)
        for path in bootstrap_paths:
            if os.path.exists(path):
                self._log_debug(f"Checking bootstrap/TUI token file: {path}")
                try:
                    with open(path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            # Skip comments and empty lines
                            if line and not line.startswith('#'):
                                self._log_debug(f"Found token in {path}")
                                return line
                except IOError as e:
                    self._log_debug(f"Failed to read {path}: {e}")

        # 3. Check JSON token files
        for path in token_paths:
            if os.path.exists(path):
                self._log_debug(f"Checking JSON token file: {path}")
                try:
                    with open(path, 'r') as f:
                        content = f.read().strip()
                        if path.endswith('.json'):
                            data = json.loads(content)
                            # Token file format: {"tokens": [{"token": "...", ...}]}
                            if isinstance(data, dict):
                                if 'token' in data:
                                    self._log_debug(f"Found token in {path}")
                                    return data['token']
                                if 'tokens' in data and data['tokens']:
                                    # Get first non-expired token with raw token value
                                    for tok in data['tokens']:
                                        if isinstance(tok, dict) and 'token' in tok:
                                            self._log_debug(f"Found token in {path}")
                                            return tok['token']
                            elif isinstance(data, list) and data:
                                if 'token' in data[0]:
                                    self._log_debug(f"Found token in {path}")
                                    return data[0].get('token')
                        else:
                            self._log_debug(f"Found token in {path}")
                            return content
                except (IOError, json.JSONDecodeError) as e:
                    self._log_debug(f"Failed to read token from {path}: {e}")

        # 4. Try to create a TUI token via daemon API (if connected without auth)
        token = self._request_tui_token()
        if token:
            return token

        self._log_debug("No API token found")
        return None

    def _request_tui_token(self) -> Optional[str]:
        """Request a TUI-specific token from the daemon."""
        self._log_debug("Attempting to request TUI token from daemon...")
        try:
            # Try TCP connection to request token
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect((self.WINDOWS_HOST, self.WINDOWS_PORT))

            # Request a TUI token (this would need daemon support)
            request = {
                'command': 'create_tui_token',
                'params': {'name': 'tui-dashboard', 'client': 'dashboard'}
            }
            sock.sendall(json.dumps(request).encode('utf-8'))
            data = sock.recv(65536)
            sock.close()

            response = json.loads(data.decode('utf-8'))
            if response.get('success') and response.get('token'):
                token = response['token']
                self._log_debug("Received TUI token from daemon")
                # Save token for future use
                self._save_tui_token(token)
                return token
            else:
                self._log_debug(f"Token request failed: {response.get('error', 'unknown')}")

        except Exception as e:
            self._log_debug(f"Failed to request TUI token: {e}")

        return None

    def _save_tui_token(self, token: str):
        """Save TUI token to file for future use."""
        try:
            # Try to save in config directory
            save_paths = [
                Path(__file__).parent.parent.parent / 'config' / 'tui_token.txt',
                Path.home() / '.boundary-daemon' / 'config' / 'tui_token.txt',
            ]

            for path in save_paths:
                try:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with open(path, 'w') as f:
                        f.write(f"# TUI Dashboard Token - Auto-generated\n")
                        f.write(f"# Created: {datetime.now().isoformat()}\n")
                        f.write(f"{token}\n")
                    self._log_debug(f"Saved TUI token to {path}")
                    return
                except (OSError, PermissionError):
                    continue
        except Exception as e:
            self._log_debug(f"Failed to save TUI token: {e}")
        return None

    def _find_socket(self) -> str:
        """Find available socket path by testing each candidate."""
        for path in self._socket_paths:
            if os.path.exists(path):
                logger.debug(f"Found socket at {path}")
                return path

        # No socket found - return first path as default
        logger.debug(f"No socket found, using default: {self._socket_paths[0] if self._socket_paths else './api/boundary.sock'}")
        return self._socket_paths[0] if self._socket_paths else './api/boundary.sock'

    def _test_connection(self) -> bool:
        """Test if daemon is reachable."""
        try:
            response = self._send_request('status')
            if response.get('success'):
                logger.debug("Connection test successful")
                return True
            elif 'error' in response:
                logger.debug(f"Connection test failed: {response.get('error')}")
                # If auth error, we're connected but need token - that's still "connected"
                if 'auth' in response.get('error', '').lower() or 'token' in response.get('error', '').lower():
                    logger.debug("Connection works but auth failed - daemon is running")
                    return True
            return False
        except Exception as e:
            logger.debug(f"Connection test failed: {e}")
            return False

    def _try_tcp_connection(self) -> bool:
        """Try direct TCP connection to daemon (Windows primary, Unix fallback)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((self.WINDOWS_HOST, self.WINDOWS_PORT))

            # Send a status request
            request = {'command': 'status'}
            if self._token:
                request['token'] = self._token
            sock.sendall(json.dumps(request).encode('utf-8'))

            # Try to receive response
            data = sock.recv(65536)
            sock.close()

            if data:
                response = json.loads(data.decode('utf-8'))
                if response.get('success') or 'error' in response:
                    logger.debug(f"TCP connection successful on port {self.WINDOWS_PORT}")
                    return True
        except Exception as e:
            logger.debug(f"TCP connection failed: {e}")
        return False

    def _send_request(self, command: str, params: Optional[Dict] = None) -> Dict:
        """Send request to daemon API."""
        request = {
            'command': command,
            'params': params or {},
        }
        if self._token:
            request['token'] = self._token

        try:
            # Use TCP if we're in TCP mode or on Windows
            if self._use_tcp or sys.platform == 'win32':
                return self._send_tcp(request)
            else:
                return self._send_unix(request)
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return {'success': False, 'error': str(e)}

    def _send_unix(self, request: Dict) -> Dict:
        """Send request via Unix socket."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
            sock.connect(self.socket_path)
            sock.sendall(json.dumps(request).encode('utf-8'))
            data = sock.recv(65536)
            return json.loads(data.decode('utf-8'))
        finally:
            sock.close()

    def _send_tcp(self, request: Dict) -> Dict:
        """Send request via TCP (Windows)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
            sock.connect((self.WINDOWS_HOST, self.WINDOWS_PORT))
            sock.sendall(json.dumps(request).encode('utf-8'))
            data = sock.recv(65536)
            return json.loads(data.decode('utf-8'))
        finally:
            sock.close()

    def connect(self) -> bool:
        """Test connection to daemon."""
        self._connected = self._test_connection()
        return self._connected

    def reconnect(self) -> bool:
        """Try to reconnect to daemon by refreshing socket paths."""
        # Rebuild socket paths (daemon might have started since last check)
        self._socket_paths = self._build_socket_paths()

        # Refresh token
        self._token = self._resolve_token()

        # Try each socket path (Unix sockets)
        if sys.platform != 'win32':
            for path in self._socket_paths:
                if os.path.exists(path):
                    old_path = self.socket_path
                    self.socket_path = path
                    self._use_tcp = False
                    if self._test_connection():
                        self._connected = True
                        logger.info(f"Connected to daemon at {path}")
                        return True
                    self.socket_path = old_path

        # Try TCP connection (Windows primary, Unix fallback)
        if self._try_tcp_connection():
            self._connected = True
            self._use_tcp = True
            logger.info(f"Connected to daemon via TCP {self.WINDOWS_HOST}:{self.WINDOWS_PORT}")
            return True

        return False

    def is_demo_mode(self) -> bool:
        """Check if running in demo mode (not connected to live daemon)."""
        return not self._connected

    def get_status(self) -> Dict:
        """Get daemon status from connection or log file."""
        # Try live connection first
        if self._connected:
            response = self._send_request('status')
            if response.get('success'):
                status = response.get('status', {})
                # Extract nested boundary_state (daemon returns mode inside boundary_state)
                boundary_state = status.get('boundary_state', {})
                lockdown = status.get('lockdown', {})
                environment = status.get('environment', {})
                # Map API response to dashboard format
                # Uptime can come from health monitor, clock monitor, or environment
                health = status.get('health', {})
                clock = status.get('clock', {})
                uptime = health.get('uptime_seconds') or clock.get('uptime_seconds') or 0
                return {
                    'mode': boundary_state.get('mode', 'unknown').upper(),
                    'mode_since': boundary_state.get('last_transition', datetime.utcnow().isoformat()),
                    'uptime': uptime,
                    'events_today': status.get('event_count', 0),
                    'violations': status.get('tripwire_violations', 0),
                    'tripwire_enabled': True,
                    'clock_monitor_enabled': status.get('running', False),
                    'network_attestation_enabled': boundary_state.get('network', 'isolated') != 'isolated',
                    'is_frozen': lockdown.get('active', False) if lockdown else False,
                }

        # Fall back to reading from log file
        if self._log_file_path:
            return self._read_status_from_log()

        # No connection and no log file - return empty status
        return {
            'mode': 'OFFLINE',
            'mode_since': datetime.utcnow().isoformat(),
            'uptime': 0,
            'events_today': 0,
            'violations': 0,
            'tripwire_enabled': False,
            'clock_monitor_enabled': False,
            'network_attestation_enabled': False,
            'is_frozen': False,
        }

    def get_events(self, limit: int = 20) -> List[DashboardEvent]:
        """Get recent events from connection or log file."""
        # Try live connection first
        if self._connected:
            response = self._send_request('get_events', {'count': limit})
            if response.get('success'):
                events = []
                for e in response.get('events', []):
                    events.append(DashboardEvent(
                        timestamp=e.get('timestamp', datetime.utcnow().isoformat()),
                        event_type=e.get('event_type', 'UNKNOWN'),
                        details=e.get('details', ''),
                        severity=e.get('severity', 'INFO'),
                        metadata=e.get('metadata', {}),
                    ))
                return events

        # Fall back to reading from log file
        if self._log_file_path:
            return self._read_events_from_log(limit)

        # No connection and no log file - return empty list
        return []

    def get_alerts(self) -> List[DashboardAlert]:
        """Get active alerts from daemon."""
        # Try to get alerts from daemon
        response = self._send_request('get_alerts')
        if response.get('success'):
            alerts = []
            for a in response.get('alerts', []):
                alerts.append(DashboardAlert(
                    alert_id=a.get('alert_id', ''),
                    timestamp=a.get('timestamp', datetime.utcnow().isoformat()),
                    severity=a.get('severity', 'MEDIUM'),
                    message=a.get('message', ''),
                    status=a.get('status', 'NEW'),
                    source=a.get('source', ''),
                ))
            return alerts
        return []

    def get_sandboxes(self) -> List[SandboxStatus]:
        """Get active sandboxes."""
        response = self._send_request('get_sandboxes')
        if response.get('success'):
            sandboxes = []
            for s in response.get('sandboxes', []):
                sandboxes.append(SandboxStatus(
                    sandbox_id=s.get('sandbox_id', ''),
                    profile=s.get('profile', 'standard'),
                    status=s.get('status', 'unknown'),
                    memory_used=s.get('memory_used', 0),
                    memory_limit=s.get('memory_limit', 0),
                    cpu_percent=s.get('cpu_percent', 0),
                    uptime=s.get('uptime', 0),
                ))
            return sandboxes
        return []

    def get_siem_status(self) -> Dict:
        """Get SIEM shipping status."""
        response = self._send_request('get_siem_status')
        if response.get('success'):
            return response.get('siem_status', {})
        return {'events_shipped_today': 0, 'last_ship_time': None, 'queue_size': 0}

    def set_mode(self, mode: str, reason: str = '') -> Tuple[bool, str]:
        """Request mode change."""
        if not self._connected:
            return False, "Daemon not connected"

        response = self._send_request('set_mode', {
            'mode': mode.lower(),
            'operator': 'human',
            'reason': reason,
        })
        if response.get('success'):
            return True, response.get('message', 'Mode changed')
        return False, response.get('error', 'Mode change failed')

    def acknowledge_alert(self, alert_id: str) -> Tuple[bool, str]:
        """Acknowledge an alert."""
        if not self._connected:
            return False, "Daemon not connected"

        response = self._send_request('acknowledge_alert', {'alert_id': alert_id})
        if response.get('success'):
            return True, response.get('message', 'Alert acknowledged')
        return False, response.get('error', 'Failed to acknowledge alert')

    def export_events(self, start_time: Optional[str] = None,
                      end_time: Optional[str] = None) -> List[Dict]:
        """Export events for a time range."""
        if self._log_file_path:
            events = self._read_events_from_log(100)
            return [e.__dict__ for e in events]

        params = {}
        if start_time:
            params['start_time'] = start_time
        if end_time:
            params['end_time'] = end_time
        params['count'] = 1000

        response = self._send_request('get_events', params)
        if response.get('success'):
            return response.get('events', [])
        return []


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
                 matrix_mode: bool = False, client: Optional['DashboardClient'] = None):
        self.refresh_interval = refresh_interval
        # Use pre-created client if provided, otherwise create new one
        self.client = client or DashboardClient(socket_path)
        self.running = False
        self.screen = None
        self.selected_panel = PanelType.STATUS
        self.event_filter = ""
        self.scroll_offset = 0
        self.show_help = False
        self.matrix_mode = matrix_mode
        self.matrix_rain: Optional[MatrixRain] = None
        self.alley_scene: Optional[AlleyScene] = None

        # Data caches
        self.status: Dict = {}
        self.events: List[DashboardEvent] = []
        self.alerts: List[DashboardAlert] = []
        self.sandboxes: List[SandboxStatus] = []
        self.siem_status: Dict = {}

        # Layout
        self.height = 0
        self.width = 0

        # Lightning effect state (for matrix mode)
        self._lightning_next_time = 0.0  # When to trigger next lightning
        self._lightning_active = False
        self._lightning_bolt: Optional[LightningBolt] = None
        self._lightning_flickers_remaining = 0
        self._lightning_flash_phase = 0

        # Creature state (for matrix mode)
        self.alley_rat: Optional[AlleyRat] = None
        self.lurking_shadow: Optional[LurkingShadow] = None
        self._has_warnings = False
        self._has_threats = False

        # Weather mode (for matrix mode)
        self._current_weather: WeatherMode = WeatherMode.MATRIX

        # Framerate options (for matrix mode)
        self._framerate_options = [100, 50, 25, 15]  # ms
        self._framerate_index = 1  # Start at 50ms
        self._qte_enabled = False  # QTE (meteor game) toggle state - off by default
        self._qte_pending_activation = False  # Waiting for delayed QTE activation
        self._qte_activation_time = 0.0  # When to activate QTE
        self._audio_muted = False  # Audio mute toggle state
        self._tunnel_enabled = True  # 3D tunnel backdrop toggle state - on by default

        # CLI mode state
        self._cli_history: List[str] = []
        self._cli_history_index = 0
        self._cli_results: List[str] = []
        self._cli_results_scroll = 0
        self._cli_last_activity = 0.0  # Last activity timestamp
        self._cli_timeout = 300.0  # 5 minutes inactivity timeout
        self._cli_chat_history: List[Dict[str, str]] = []  # Ollama chat history

        # Ollama client for CLI chat
        self._ollama_client = None
        if OLLAMA_AVAILABLE and OllamaConfig is not None:
            try:
                config = OllamaConfig(model="llama3.2", timeout=60)
                self._ollama_client = OllamaClient(config)
            except Exception:
                pass  # Ollama not available

        # Moon state (arcs across sky every 15 minutes)
        self._moon_active = False
        self._moon_x = 0.0
        self._moon_start_time = 0.0
        self._moon_next_time = 0.0  # When to start next moon arc
        self._moon_duration = 900.0  # 15 minutes (900 seconds) to cross screen

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

        # Install project dependencies for Python 3.12
        # Find the project root (where requirements.txt should be)
        project_root = Path(__file__).parent.parent.parent
        requirements_file = project_root / 'requirements.txt'

        if requirements_file.exists():
            print("Installing project dependencies for Python 3.12...")
            try:
                install_result = subprocess.run(
                    ['py', '-3.12', '-m', 'pip', 'install', '-q', '-r', str(requirements_file)],
                    capture_output=True, text=True, timeout=300
                )
                if install_result.returncode != 0:
                    # Try installing just the essential packages
                    print("Full install failed, trying essential packages...")
                    subprocess.run(
                        ['py', '-3.12', '-m', 'pip', 'install', '-q', 'psutil'],
                        capture_output=True, text=True, timeout=60
                    )
            except subprocess.SubprocessError:
                pass  # Continue anyway, might still work
        else:
            # No requirements.txt, just install psutil
            try:
                subprocess.run(
                    ['py', '-3.12', '-m', 'pip', 'install', '-q', 'psutil'],
                    capture_output=True, text=True, timeout=60
                )
            except subprocess.SubprocessError:
                pass

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
            screen.timeout(self._framerate_options[self._framerate_index])  # Use selected framerate
            screen.bkgd(' ', curses.color_pair(Colors.MATRIX_DIM))
            self._update_dimensions()
            self.alley_scene = AlleyScene(self.width, self.height)
            self.matrix_rain = MatrixRain(self.width, self.height)
            self.tunnel_backdrop = TunnelBackdrop(self.width, self.height)
            # Connect snow filter so snow only collects on roofs/sills, not building faces
            self.matrix_rain.set_snow_filter(self.alley_scene.is_valid_snow_position)
            # Connect roof/sill checker so snow on roofs/sills lasts 10x longer
            self.matrix_rain.set_roof_sill_checker(self.alley_scene.is_roof_or_sill)
            # Connect street light glow positions so snow melts faster in warm light
            self.matrix_rain.set_glow_positions(self.alley_scene._street_light_positions)
            # Set quick-melt zones (sidewalk, mailbox, street, traffic light) so snow melts very fast there
            sidewalk_y = self.height - 4  # curb_y
            street_y = self.height - 3
            mailbox_bounds = (self.alley_scene.mailbox_x, self.alley_scene.mailbox_y,
                              len(self.alley_scene.MAILBOX[0]), len(self.alley_scene.MAILBOX))
            # Traffic light bounds
            traffic_light_x = min(self.width - 10, self.alley_scene.box_x + len(self.alley_scene.BOX[0]) + 100)
            traffic_light_y = self.height - len(self.alley_scene.TRAFFIC_LIGHT_TEMPLATE) - 1
            traffic_light_bounds = (traffic_light_x, traffic_light_y,
                                    len(self.alley_scene.TRAFFIC_LIGHT_TEMPLATE[0]),
                                    len(self.alley_scene.TRAFFIC_LIGHT_TEMPLATE))
            # Cafe bounds (snow melts on building but not on turtle shell roof)
            cafe_bounds = (self.alley_scene.cafe_x, self.alley_scene.cafe_y,
                          len(self.alley_scene.CAFE[0]), len(self.alley_scene.CAFE), 7)  # 7 rows for turtle shell
            self.matrix_rain.set_quick_melt_zones(sidewalk_y, mailbox_bounds, street_y, traffic_light_bounds, cafe_bounds)
            # Initialize creatures
            self.alley_rat = AlleyRat(self.width, self.height)
            self.alley_rat.set_hiding_spots(self.alley_scene)
            self.lurking_shadow = LurkingShadow(self.width, self.height)
            # Schedule first lightning strike (5-30 minutes from now)
            self._lightning_next_time = time.time() + random.uniform(300, 1800)
            # Schedule first moon arc (start immediately, then every 15 minutes)
            self._moon_next_time = time.time() + 5.0  # Start in 5 seconds
        else:
            screen.timeout(int(self.refresh_interval * 1000))

        # Handle terminal resize (Unix only - Windows doesn't have SIGWINCH)
        if hasattr(signal, 'SIGWINCH'):
            signal.signal(signal.SIGWINCH, lambda *_: self._handle_resize())

        # Initial data fetch
        self._refresh_data()

        while self.running:
            try:
                old_width, old_height = self.width, self.height
                self._update_dimensions()

                # Sync matrix rain dimensions if window resized
                if self.matrix_mode and self.matrix_rain:
                    if self.width != old_width or self.height != old_height:
                        if self.alley_scene:
                            self.alley_scene.resize(self.width, self.height)
                            # Update glow positions for snow melting
                            self.matrix_rain.set_glow_positions(self.alley_scene._street_light_positions)
                            # Update quick-melt zones
                            sidewalk_y = self.height - 4
                            street_y = self.height - 3
                            mailbox_bounds = (self.alley_scene.mailbox_x, self.alley_scene.mailbox_y,
                                              len(self.alley_scene.MAILBOX[0]), len(self.alley_scene.MAILBOX))
                            traffic_light_x = min(self.width - 10, self.alley_scene.box_x + len(self.alley_scene.BOX[0]) + 100)
                            traffic_light_y = self.height - len(self.alley_scene.TRAFFIC_LIGHT_TEMPLATE) - 1
                            traffic_light_bounds = (traffic_light_x, traffic_light_y,
                                                    len(self.alley_scene.TRAFFIC_LIGHT_TEMPLATE[0]),
                                                    len(self.alley_scene.TRAFFIC_LIGHT_TEMPLATE))
                            # Cafe bounds (snow melts on building but not on shell roof)
                            cafe_bounds = (self.alley_scene.cafe_x, self.alley_scene.cafe_y,
                                          len(self.alley_scene.CAFE[0]), len(self.alley_scene.CAFE), 8)
                            self.matrix_rain.set_quick_melt_zones(sidewalk_y, mailbox_bounds, street_y, traffic_light_bounds, cafe_bounds)
                        self.matrix_rain.resize(self.width, self.height)
                        if hasattr(self, 'tunnel_backdrop') and self.tunnel_backdrop:
                            self.tunnel_backdrop.resize(self.width, self.height)
                        if self.alley_rat:
                            self.alley_rat.resize(self.width, self.height)
                            self.alley_rat.set_hiding_spots(self.alley_scene)
                        if self.lurking_shadow:
                            self.lurking_shadow.resize(self.width, self.height)
                    self.matrix_rain.update()

                    # Update tunnel backdrop animation
                    if hasattr(self, 'tunnel_backdrop') and self.tunnel_backdrop:
                        self.tunnel_backdrop.update()

                    # Update alley scene (traffic light)
                    if self.alley_scene:
                        self.alley_scene.update()
                        # Check for new daemon events to spawn warning trucks
                        self._check_daemon_events_for_trucks()
                        # Check for pending QTE activation
                        if self._qte_pending_activation and time.time() >= self._qte_activation_time:
                            self._qte_pending_activation = False
                            self._qte_enabled = True
                            self.alley_scene._qte_enabled = True

                    # Update creatures based on alert state
                    self._update_creatures()

                    # Check for lightning strike
                    self._update_lightning()

                    # Update moon arc
                    self._update_moon()

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
        if self.matrix_mode:
            if self.alley_scene:
                self.alley_scene.resize(self.width, self.height)
            if self.matrix_rain:
                self.matrix_rain.resize(self.width, self.height)
                # Update glow positions for snow melting
                if self.alley_scene:
                    self.matrix_rain.set_glow_positions(self.alley_scene._street_light_positions)
            if hasattr(self, 'tunnel_backdrop') and self.tunnel_backdrop:
                self.tunnel_backdrop.resize(self.width, self.height)
            if self.alley_rat:
                self.alley_rat.resize(self.width, self.height)
                self.alley_rat.set_hiding_spots(self.alley_scene)
            if self.lurking_shadow:
                self.lurking_shadow.resize(self.width, self.height)
        self.screen.clear()

    def _update_dimensions(self):
        """Update terminal dimensions."""
        self.height, self.width = self.screen.getmaxyx()

    def _check_daemon_events_for_trucks(self):
        """Check for new daemon events and spawn warning trucks for critical/important ones.

        Only spawns warning trucks for REAL daemon events, not demo events.
        Tracks seen event IDs to avoid duplicate trucks.
        """
        if not self.alley_scene:
            return

        # Rate limit: only check every ~2 seconds (120 frames at 60fps)
        self.alley_scene._last_event_check += 1
        if self.alley_scene._last_event_check < 120:
            return
        self.alley_scene._last_event_check = 0

        # Skip if in demo mode (no real events)
        if self.client.is_demo_mode():
            return

        try:
            # Get recent alerts (high priority events)
            alerts = self.client.get_alerts()
            for alert in alerts:
                # Create unique ID from alert properties
                alert_id = f"alert_{alert.severity}_{alert.message[:20]}_{alert.timestamp}"
                if alert_id in self.alley_scene._known_event_ids:
                    continue

                # Mark as seen
                self.alley_scene._known_event_ids.add(alert_id)

                # Create warning message for truck
                prefix = random.choice(self.alley_scene.SEMI_WARNING_PREFIXES)
                message = f"{prefix}{alert.message[:40]}"

                # Spawn warning truck
                self.alley_scene._spawn_car(warning_message=message)

            # Get recent events (check for critical ones)
            events = self.client.get_events(10)
            for event in events:
                # Only spawn trucks for critical/warning events
                if event.severity not in ['critical', 'high', 'warning']:
                    continue

                # Create unique ID
                event_id = f"event_{event.type}_{event.timestamp}"
                if event_id in self.alley_scene._known_event_ids:
                    continue

                # Mark as seen
                self.alley_scene._known_event_ids.add(event_id)

                # Create warning message for truck
                prefix = random.choice(self.alley_scene.SEMI_WARNING_PREFIXES)
                message = f"{prefix}{event.type}: {event.details.get('message', '')[:30]}"

                # Spawn warning truck
                self.alley_scene._spawn_car(warning_message=message)

            # Limit the size of known events set (keep last 1000)
            if len(self.alley_scene._known_event_ids) > 1000:
                # Remove oldest half
                known_list = list(self.alley_scene._known_event_ids)
                self.alley_scene._known_event_ids = set(known_list[500:])

        except Exception as e:
            # Silently ignore errors (daemon might be unavailable)
            pass

    def _update_lightning(self):
        """Check and update lightning strike state."""
        current_time = time.time()

        # Check if it's time for a lightning strike
        if not self._lightning_active and current_time >= self._lightning_next_time:
            # Start lightning strike!
            self._lightning_active = True
            self._lightning_bolt = LightningBolt(self.width, self.height)
            self._lightning_flickers_remaining = random.randint(3, 5)
            self._lightning_flash_phase = 0
            # Check if lightning knocked out any pedestrians
            if self._lightning_bolt.path and self.alley_scene:
                lightning_x = self._lightning_bolt.path[0][1]  # Get x from first point
                self.alley_scene.check_lightning_knockout(lightning_x)

        # Update active lightning
        if self._lightning_active:
            self._lightning_flash_phase += 1

            # Each flicker cycle: bright(2) -> dim(1) -> off(1) = 4 frames per flicker
            # At 100ms per frame, 4 frames = 400ms, so 3-5 flickers = 1.2-2 seconds total
            # But we want 3-5 flickers in ~0.5 second, so faster: 2 frames per flicker
            cycle_length = 2
            cycles_done = self._lightning_flash_phase // cycle_length

            if cycles_done >= self._lightning_flickers_remaining:
                # Lightning is done
                self._lightning_active = False
                self._lightning_bolt = None
                # Schedule next lightning (5-30 minutes from now)
                self._lightning_next_time = current_time + random.uniform(300, 1800)

    def _update_moon(self):
        """Update moon arc across the sky (15 minute cycle)."""
        current_time = time.time()

        # Check if it's time to start a new moon arc
        if not self._moon_active and current_time >= self._moon_next_time:
            self._moon_active = True
            self._moon_start_time = current_time
            self._moon_x = 0.0

        # Update active moon
        if self._moon_active:
            elapsed = current_time - self._moon_start_time
            progress = elapsed / self._moon_duration  # 0.0 to 1.0

            if progress >= 1.0:
                # Moon has crossed the sky
                self._moon_active = False
                # Schedule next moon arc (15 minutes from now)
                self._moon_next_time = current_time + 900.0  # 15 minutes
            else:
                # Update moon x position
                self._moon_x = progress * self.width

    def _render_moon(self, screen):
        """Render the moon in a high arc across the sky."""
        if not self._moon_active:
            return

        # Calculate moon position in arc
        progress = (self._moon_x / self.width) if self.width > 0 else 0

        # High arc: y = height at edges, low (near top) in middle
        # Using parabola: y = a * (x - 0.5)^2 + min_y
        # At edges (x=0 or 1): y = a * 0.25 + min_y = max_y
        # At center (x=0.5): y = min_y
        min_y = 2  # Highest point (near top of screen)
        max_y = self.height // 3  # Lowest point of arc (at edges)
        arc_height = max_y - min_y

        # Parabola centered at 0.5
        x_centered = progress - 0.5
        moon_y = int(min_y + arc_height * 4 * (x_centered ** 2))
        moon_x = int(self._moon_x)

        # Moon ASCII art (filled moon)
        moon_chars = [
            " @@@ ",
            "@@@@@",
            "@@@@@",
            "@@@@@",
            " @@@ ",
        ]

        # Render moon
        for row_idx, row in enumerate(moon_chars):
            for col_idx, char in enumerate(row):
                px = moon_x + col_idx - 2  # Center the moon
                py = moon_y + row_idx - 2
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    try:
                        attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_BOLD
                        screen.attron(attr)
                        screen.addstr(py, px, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

    def _update_creatures(self):
        """Update creature state based on alerts."""
        # Check for warnings (MEDIUM severity or WARN events)
        has_warnings = False
        has_threats = False

        for alert in self.alerts:
            if alert.severity in ('MEDIUM', 'LOW'):
                has_warnings = True
            if alert.severity in ('HIGH', 'CRITICAL'):
                has_threats = True

        # Also check recent events for warnings
        for event in self.events[:5]:  # Check last 5 events
            if event.severity == 'WARN':
                has_warnings = True
            if event.severity == 'ERROR':
                has_threats = True

        # Update rat state (for warnings)
        if self.alley_rat:
            if has_warnings and not self._has_warnings:
                # New warning appeared - activate rat
                self.alley_rat.activate()
            elif not has_warnings and self._has_warnings:
                # Warnings cleared - deactivate rat
                self.alley_rat.deactivate()
            self.alley_rat.update()

        # Update shadow state (for threats)
        if self.lurking_shadow:
            if has_threats and not self._has_threats:
                # New threat detected - activate shadow
                self.lurking_shadow.activate()
            elif not has_threats and self._has_threats:
                # Threats cleared - deactivate shadow
                self.lurking_shadow.deactivate()
            self.lurking_shadow.update()

        self._has_warnings = has_warnings
        self._has_threats = has_threats

    def _render_lightning(self):
        """Render the lightning bolt with flicker effect."""
        if not self._lightning_bolt:
            return

        # Calculate flash intensity based on phase
        # Alternate between bright and dim for flicker effect
        cycle_pos = self._lightning_flash_phase % 2
        if cycle_pos == 0:
            # Bright flash
            LightningBolt.flash_screen(self.screen, self.width, self.height)
            self._lightning_bolt.render(self.screen, 1.0)
        else:
            # Dim phase - just show the bolt, no full screen flash
            self._lightning_bolt.render(self.screen, 0.5)

    def _refresh_data(self):
        """Refresh all data from daemon."""
        # If in demo mode, periodically try to reconnect to real daemon
        if self.client.is_demo_mode():
            if self.client.reconnect():
                logger.info("Reconnected to daemon!")

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
        elif key == ord('e') or key == ord('E'):
            self._export_events()
        elif key == ord('c') or key == ord('C'):
            # Clear events display
            self.events = []
            self.scroll_offset = 0
        elif key == ord('l') or key == ord('L'):
            # Recall/reload events from daemon
            try:
                self.events = self.client.get_events(50)  # Get more events
                self.scroll_offset = 0
            except Exception:
                pass
        elif key == ord('/'):
            self._start_search()
        elif key == 27:  # ESC - clear search filter
            self.event_filter = ""
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
        elif key == ord('w') or key == ord('W'):
            # Cycle weather mode (only in matrix mode)
            if self.matrix_mode and self.matrix_rain:
                new_mode = self.matrix_rain.cycle_weather()
                # Store for header display
                self._current_weather = new_mode
                # Sync calm mode and full weather mode to alley scene
                if self.alley_scene:
                    self.alley_scene.set_calm_mode(new_mode == WeatherMode.CALM)
                    self.alley_scene.set_weather_mode(new_mode)
                    # Announce weather change via prop plane
                    weather_names = {
                        WeatherMode.MATRIX: "MATRIX MODE",
                        WeatherMode.RAIN: "RAIN STORM",
                        WeatherMode.SNOW: "SNOW FALL",
                        WeatherMode.SAND: "SAND STORM",
                        WeatherMode.CALM: "CALM WEATHER",
                    }
                    self.alley_scene.queue_plane_announcement(
                        f"★ WEATHER: {weather_names.get(new_mode, 'UNKNOWN')} ★"
                    )
                # Sync weather mode to tunnel backdrop
                if hasattr(self, 'tunnel_backdrop') and self.tunnel_backdrop:
                    self.tunnel_backdrop.set_weather_mode(new_mode)
        elif key == ord('t') or key == ord('T'):
            # Toggle tunnel backdrop effect (only in matrix mode)
            if self.matrix_mode and hasattr(self, 'tunnel_backdrop') and self.tunnel_backdrop:
                self._tunnel_enabled = not getattr(self, '_tunnel_enabled', True)
                self.tunnel_backdrop.set_enabled(self._tunnel_enabled)
        elif key == ord('f') or key == ord('F'):
            # Cycle framerate (only in matrix mode)
            if self.matrix_mode:
                self._framerate_index = (self._framerate_index + 1) % len(self._framerate_options)
                # Apply new framerate immediately
                if self.screen:
                    self.screen.timeout(self._framerate_options[self._framerate_index])
        elif key == ord('g') or key == ord('G'):
            # Toggle QTE (meteor game) on/off
            if self.matrix_mode and self.alley_scene:
                enabled = self.alley_scene.toggle_qte()
                self._qte_enabled = enabled  # Store for header display
        elif key == ord('u') or key == ord('U'):
            # Toggle audio mute on/off
            if self.matrix_mode and self.alley_scene:
                muted = self.alley_scene.toggle_mute()
                self._audio_muted = muted  # Store for header display
        # QTE keys (6, 7, 8, 9, 0) for meteor game
        elif key in [ord('6'), ord('7'), ord('8'), ord('9'), ord('0')]:
            if self.matrix_mode and self.alley_scene:
                if self._qte_enabled:
                    # QTE is on - pass key to game
                    self.alley_scene.handle_qte_key(chr(key))
                elif not self._qte_pending_activation:
                    # QTE is off - start delayed activation (30-90 seconds)
                    self._qte_pending_activation = True
                    self._qte_activation_time = time.time() + random.uniform(30, 90)
        # CLI mode (: or ;)
        elif key == ord(':') or key == ord(';'):
            self._start_cli()

    def _draw(self):
        """Draw the dashboard."""
        self.screen.clear()

        # Render 3D tunnel backdrop first (absolute furthest back - cosmic sky effect)
        if self.matrix_mode and hasattr(self, 'tunnel_backdrop') and self.tunnel_backdrop:
            self.tunnel_backdrop.render(self.screen)

        # Render moon (behind everything except tunnel)
        if self.matrix_mode and self.matrix_rain:
            self._render_moon(self.screen)

        # Render alley scene (behind rain but in front of moon)
        if self.matrix_mode and self.alley_scene:
            self.alley_scene.render(self.screen)

        # Render matrix rain on top of alley
        if self.matrix_mode and self.matrix_rain:
            self.matrix_rain.render(self.screen)

            # Render creatures (between rain and UI)
            if self.alley_rat:
                self.alley_rat.render(self.screen)
            if self.lurking_shadow:
                self.lurking_shadow.render(self.screen)

            # Render lightning bolt if active
            if self._lightning_active and self._lightning_bolt:
                self._render_lightning()

        if self.show_help:
            self._draw_help()
        else:
            self._draw_header()
            self._draw_panels()

        self.screen.refresh()

    def _draw_header(self):
        """Draw the header bar."""
        header = " BOUNDARY DAEMON"
        if self.client.is_demo_mode():
            header += " [DEMO]"
        # Show weather mode and framerate in matrix mode
        if self.matrix_mode:
            header += f" [{self._current_weather.display_name}]"
            header += f" [{self._framerate_options[self._framerate_index]}ms]"
            if not self._tunnel_enabled:
                header += " [TUNNEL OFF]"
            if not self._qte_enabled:
                header += " [QTE OFF]"
            if self._audio_muted:
                header += " [MUTED]"
        header += f"  │  Mode: {self.status.get('mode', 'UNKNOWN')}  │  "
        if self.status.get('is_frozen'):
            header += "⚠ MODE FROZEN  │  "
        header += f"Uptime: {self._format_duration(self.status.get('uptime', 0))}"
        if self.event_filter:
            header += f"  │  Filter: {self.event_filter}"

        # Pad to full width
        header = header.ljust(self.width - 1)

        # Use weather-blended color for header
        header_color = self._get_weather_text_color(Colors.HEADER)
        self.screen.attron(curses.color_pair(header_color) | curses.A_BOLD)
        self.screen.addstr(0, 0, header[:self.width-1])
        self.screen.attroff(curses.color_pair(header_color) | curses.A_BOLD)

    def _draw_panels(self):
        """Draw the main panels in a 2x2 grid."""
        # Calculate panel dimensions for 2x2 grid
        # Leave 1 row for header at top, boxes extend to bottom of screen
        available_height = self.height - 1
        available_width = self.width - 1  # Avoid last column curses error

        # Each panel gets half the width and half the height
        panel_width = available_width // 2
        panel_height = available_height // 2

        # Adjust for odd dimensions
        right_width = available_width - panel_width
        bottom_height = available_height - panel_height

        # Top row starts at y=1 (after header)
        # Bottom row starts at y=1+panel_height
        top_y = 1
        bottom_y = 1 + panel_height

        # Draw 2x2 grid: STATUS | ALERTS
        #                EVENTS | SIEM
        self._draw_status_panel(top_y, 0, panel_width, panel_height)
        self._draw_alerts_panel(top_y, panel_width, right_width, panel_height)
        self._draw_events_panel(bottom_y, 0, panel_width, bottom_height)
        self._draw_siem_panel(bottom_y, panel_width, right_width, bottom_height)

    def _draw_status_panel(self, y: int, x: int, width: int, height: int):
        """Draw the status panel with spaced out lines."""
        self._draw_box(y, x, width, height, "STATUS")

        row = y + 1
        col = x + 2

        # Connection status
        if self.client.is_demo_mode():
            self._addstr(row, col, "Connection: ", Colors.MUTED)
            self._addstr(row, col + 12, "DEMO MODE", Colors.STATUS_ERROR, bold=True)
            row += 2  # Extra space
            self._addstr(row, col, "(No daemon)", Colors.MUTED)
            row += 2  # Extra space
        else:
            self._addstr(row, col, "Connection: ", Colors.MUTED)
            if self.client._use_tcp:
                conn_text = f"TCP:{self.client.WINDOWS_PORT}"
            else:
                conn_text = "Socket"
            self._addstr(row, col + 12, conn_text, Colors.STATUS_OK)
            row += 2  # Extra space

        # Mode
        mode = self.status.get('mode', 'UNKNOWN')
        mode_color = Colors.STATUS_OK if mode in ('TRUSTED', 'AIRGAP', 'COLDROOM') else Colors.STATUS_WARN
        self._addstr(row, col, f"Mode: ", Colors.MUTED)
        self._addstr(row, col + 6, mode, mode_color, bold=True)
        row += 2  # Extra space

        # Tripwires
        tw_enabled = self.status.get('tripwire_enabled', False)
        tw_text = "✓ Enabled" if tw_enabled else "✗ Disabled"
        tw_color = Colors.STATUS_OK if tw_enabled else Colors.STATUS_ERROR
        self._addstr(row, col, "Tripwires: ", Colors.MUTED)
        self._addstr(row, col + 11, tw_text, tw_color)
        row += 2  # Extra space

        # Clock Monitor
        cm_enabled = self.status.get('clock_monitor_enabled', False)
        cm_text = "✓ Active" if cm_enabled else "✗ Inactive"
        cm_color = Colors.STATUS_OK if cm_enabled else Colors.STATUS_WARN
        self._addstr(row, col, "Clock: ", Colors.MUTED)
        self._addstr(row, col + 7, cm_text, cm_color)
        row += 2  # Extra space

        # Network Attestation
        na_enabled = self.status.get('network_attestation_enabled', False)
        na_text = "✓ Active" if na_enabled else "○ Inactive"
        na_color = Colors.STATUS_OK if na_enabled else Colors.MUTED
        self._addstr(row, col, "Network: ", Colors.MUTED)
        self._addstr(row, col + 9, na_text, na_color)
        row += 2  # Extra space

        # Events today
        events_count = self.status.get('events_today', 0)
        self._addstr(row, col, f"Events: {events_count:,}", Colors.MUTED)
        row += 2  # Extra space

        # Violations
        violations = self.status.get('violations', 0)
        v_color = Colors.STATUS_ERROR if violations > 0 else Colors.STATUS_OK
        self._addstr(row, col, f"Violations: {violations}", v_color)

    def _draw_events_panel(self, y: int, x: int, width: int, height: int):
        """Draw the events panel with footer shortcuts at bottom."""
        self._draw_box(y, x, width, height, f"EVENTS (last {len(self.events)})")

        row = y + 1
        col = x + 2
        # Reserve 1 row for shortcuts at bottom (inside the box)
        max_rows = height - 3
        display_width = width - 4

        for i, event in enumerate(self.events[:max_rows]):
            if row >= y + height - 2:  # Leave room for shortcuts
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

        # Draw shortcuts at bottom of events panel (inside the box)
        shortcut_row = y + height - 2
        if self.matrix_mode:
            shortcuts = "[:]CLI [w]Weather [m]Mode [a]Ack [e]Export [?]Help [q]Quit"
        else:
            shortcuts = "[m]Mode [a]Ack [e]Export [r]Refresh [/]Search [?]Help [q]Quit"

        # Center the shortcuts
        shortcuts = shortcuts[:display_width]
        self._addstr(shortcut_row, col, shortcuts, Colors.MUTED)

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
        """Draw the SIEM status panel with right-aligned title and text."""
        connected = self.siem_status.get('connected', False)
        title_color = Colors.STATUS_OK if connected else Colors.STATUS_ERROR
        # Draw box with empty title, then add right-aligned title manually
        self._draw_box(y, x, width, height, "")
        # Right-align the title
        title_str = " SIEM SHIPPING "
        title_x = x + width - len(title_str) - 1
        try:
            self.screen.attron(curses.color_pair(title_color) | curses.A_BOLD)
            self.screen.addstr(y, title_x, title_str)
            self.screen.attroff(curses.color_pair(title_color) | curses.A_BOLD)
        except curses.error:
            pass

        row = y + 1
        # Right-align text within the box (2 char padding from right edge)
        right_edge = x + width - 2

        # Connection status
        status_text = "✓ Connected" if connected else "✗ Disconnected"
        status_color = Colors.STATUS_OK if connected else Colors.STATUS_ERROR
        line = f"Status: {status_text}"
        self._addstr(row, right_edge - len(line), line, status_color)
        row += 1

        # Backend
        backend = self.siem_status.get('backend', 'unknown')
        line = f"Backend: {backend}"
        self._addstr(row, right_edge - len(line), line, Colors.MUTED)
        row += 1

        # Queue depth
        queue = self.siem_status.get('queue_depth', 0)
        queue_color = Colors.STATUS_OK if queue < 100 else Colors.STATUS_WARN
        line = f"Queue: {queue} events"
        self._addstr(row, right_edge - len(line), line, queue_color)
        row += 1

        # Events shipped
        shipped = self.siem_status.get('events_shipped_today', 0)
        line = f"Shipped today: {shipped:,}"
        self._addstr(row, right_edge - len(line), line, Colors.MUTED)

    def _draw_footer(self):
        """Draw the footer bar."""
        # Add weather shortcut in matrix mode
        if self.matrix_mode:
            shortcuts = "[:]CLI [w]Weather [t]Tunnel [m]Mode [c]Clear [l]Load [e]Export [?]Help [q]Quit"
        else:
            shortcuts = "[m]Mode [c]Clear [l]Load [e]Export [r]Refresh [/]Search [?]Help [q]Quit"

        # In demo mode, show connection hint
        if self.client.is_demo_mode():
            if sys.platform == 'win32':
                hint = " | Demo: Start daemon or check port 19847"
            else:
                hint = " | Demo: Start daemon (./api/boundary.sock)"
            footer = f" {shortcuts}{hint} ".ljust(self.width - 1)
        else:
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
            "  c    Clear events display",
            "  l    Load/recall events from daemon",
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
        ]

        # Add weather info if in matrix mode
        if self.matrix_mode:
            help_text.insert(8, "  w    Cycle weather (Matrix/Rain/Snow/Sand/Fog)")
            help_text.insert(9, "  t    Toggle 3D tunnel sky backdrop")
            help_text.insert(10, "")

        help_text.append("Press any key to close")

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

    def _get_weather_box_colors(self) -> Tuple[int, int, int, bool]:
        """Get box border colors based on current weather mode.

        Returns:
            (top_color, side_color, bottom_color, is_transparent)
        """
        if not self.matrix_mode:
            return (Colors.HEADER, Colors.HEADER, Colors.HEADER, False)

        weather = self._current_weather
        if weather == WeatherMode.CALM or weather == WeatherMode.MATRIX:
            # Transparent in calm/matrix mode - don't draw borders
            return (Colors.MATRIX_FADE3, Colors.MATRIX_FADE3, Colors.MATRIX_FADE3, True)
        elif weather == WeatherMode.SAND:
            # Grey in sand mode
            return (Colors.BOX_GREY, Colors.BOX_GREY, Colors.BOX_GREY, False)
        elif weather == WeatherMode.SNOW:
            # Brown on top and sides, white on bottom
            return (Colors.BOX_BROWN, Colors.BOX_BROWN, Colors.BOX_WHITE, False)
        elif weather == WeatherMode.RAIN:
            # Dark brown in rain mode
            return (Colors.BOX_DARK_BROWN, Colors.BOX_DARK_BROWN, Colors.BOX_DARK_BROWN, False)
        else:
            return (Colors.HEADER, Colors.HEADER, Colors.HEADER, False)

    def _draw_box(self, y: int, x: int, width: int, height: int, title: str, title_color: int = None):
        """Draw a box with title, using weather-based colors."""
        if title_color is None:
            title_color = Colors.HEADER

        # Blend title color with weather
        title_color = self._get_weather_text_color(title_color)

        # Get weather-based box colors
        top_color, side_color, bottom_color, is_transparent = self._get_weather_box_colors()

        # Skip drawing borders if transparent (calm/matrix mode)
        if is_transparent:
            # Just draw title if present
            if title:
                try:
                    title_str = f" {title} "
                    self.screen.attron(curses.color_pair(title_color) | curses.A_BOLD)
                    self.screen.addstr(y, x + 2, title_str[:width-4])
                    self.screen.attroff(curses.color_pair(title_color) | curses.A_BOLD)
                except curses.error:
                    pass
            return

        try:
            # Top border with weather color
            top_attr = curses.color_pair(top_color)
            if top_color == Colors.BOX_GREY:
                top_attr |= curses.A_DIM  # Make grey dimmer
            self.screen.attron(top_attr)
            self.screen.addch(y, x, curses.ACS_ULCORNER)
            self.screen.addch(y, x + width - 1, curses.ACS_URCORNER)
            for i in range(1, width - 1):
                self.screen.addch(y, x + i, curses.ACS_HLINE)
            self.screen.attroff(top_attr)

            # Title
            if title:
                title_str = f" {title} "
                self.screen.attron(curses.color_pair(title_color) | curses.A_BOLD)
                self.screen.addstr(y, x + 2, title_str[:width-4])
                self.screen.attroff(curses.color_pair(title_color) | curses.A_BOLD)

            # Side borders with weather color
            side_attr = curses.color_pair(side_color)
            if side_color == Colors.BOX_GREY:
                side_attr |= curses.A_DIM
            self.screen.attron(side_attr)
            for i in range(1, height - 1):
                self.screen.addch(y + i, x, curses.ACS_VLINE)
                self.screen.addch(y + i, x + width - 1, curses.ACS_VLINE)
            self.screen.attroff(side_attr)

            # Bottom border with weather color (may be different in snow)
            bottom_attr = curses.color_pair(bottom_color)
            if bottom_color == Colors.BOX_GREY:
                bottom_attr |= curses.A_DIM
            elif bottom_color == Colors.BOX_WHITE:
                bottom_attr |= curses.A_BOLD  # Make white brighter
            self.screen.attron(bottom_attr)
            self.screen.addch(y + height - 1, x, curses.ACS_LLCORNER)
            self.screen.addch(y + height - 1, x + width - 1, curses.ACS_LRCORNER)
            for i in range(1, width - 1):
                self.screen.addch(y + height - 1, x + i, curses.ACS_HLINE)
            self.screen.attroff(bottom_attr)
        except curses.error:
            pass

    def _get_weather_text_color(self, base_color: int) -> int:
        """Get weather-blended text color.

        Blends the base color with weather-appropriate tint.
        """
        if not self.matrix_mode:
            return base_color

        weather = self._current_weather
        # For certain base colors, blend with weather
        # Keep status colors (OK, WARN, ERROR) as-is for visibility
        if base_color in (Colors.STATUS_OK, Colors.STATUS_WARN, Colors.STATUS_ERROR):
            return base_color

        # Blend normal/muted text with weather colors
        if weather == WeatherMode.RAIN:
            if base_color in (Colors.NORMAL, Colors.MUTED, Colors.HEADER):
                return Colors.TEXT_RAIN
        elif weather == WeatherMode.SNOW:
            if base_color in (Colors.NORMAL, Colors.MUTED, Colors.HEADER):
                return Colors.TEXT_SNOW
        elif weather == WeatherMode.SAND:
            if base_color in (Colors.NORMAL, Colors.MUTED, Colors.HEADER):
                return Colors.TEXT_SAND
        # Matrix and Calm stay green (default)
        return base_color

    def _addstr(self, y: int, x: int, text: str, color: int = Colors.NORMAL, bold: bool = False):
        """Add string with color and bounds checking, blending with weather."""
        if y >= self.height or x >= self.width:
            return

        max_len = self.width - x - 1
        if max_len <= 0:
            return

        text = text[:max_len]

        # Apply weather-based color blending
        blended_color = self._get_weather_text_color(color)

        try:
            attr = curses.color_pair(blended_color)
            if bold:
                attr |= curses.A_BOLD
            self.screen.attron(attr)
            self.screen.addstr(y, x, text)
            self.screen.attroff(attr)
        except curses.error:
            pass

    def _show_mode_ceremony(self):
        """Show mode change dialog and allow mode selection."""
        modes = ['OPEN', 'RESTRICTED', 'TRUSTED', 'AIRGAP', 'COLDROOM', 'LOCKDOWN']
        current_mode = self.status.get('mode', 'UNKNOWN')
        selected = 0

        # Find current mode index
        for i, m in enumerate(modes):
            if m == current_mode:
                selected = i
                break

        while True:
            self.screen.clear()

            # Draw mode selection dialog
            box_width = 40
            box_height = len(modes) + 6
            start_y = (self.height - box_height) // 2
            start_x = (self.width - box_width) // 2

            self._draw_box(start_y, start_x, box_width, box_height, "MODE CHANGE")

            # Instructions
            self._addstr(start_y + 1, start_x + 2, "Select mode (↑↓) Enter to confirm", Colors.MUTED)
            self._addstr(start_y + 2, start_x + 2, "Press ESC to cancel", Colors.MUTED)

            # Mode options
            for i, mode in enumerate(modes):
                row = start_y + 4 + i
                if i == selected:
                    self._addstr(row, start_x + 2, f"> {mode}", Colors.SELECTED, bold=True)
                else:
                    color = Colors.STATUS_OK if mode == current_mode else Colors.NORMAL
                    self._addstr(row, start_x + 4, mode, color)

            # Render alley and matrix rain if in matrix mode
            if self.matrix_mode:
                if self.alley_scene:
                    self.alley_scene.render(self.screen)
                if self.matrix_rain:
                    self.matrix_rain.render(self.screen)

            self.screen.refresh()

            key = self.screen.getch()
            if key == 27:  # ESC
                return
            elif key == curses.KEY_UP:
                selected = (selected - 1) % len(modes)
            elif key == curses.KEY_DOWN:
                selected = (selected + 1) % len(modes)
            elif key in (curses.KEY_ENTER, 10, 13):
                new_mode = modes[selected]
                if new_mode != current_mode:
                    success, message = self.client.set_mode(new_mode)
                    self._show_message(message, Colors.STATUS_OK if success else Colors.STATUS_ERROR)
                    if success:
                        self._refresh_data()
                        # Announce mode change via prop plane
                        if self.alley_scene:
                            self.alley_scene.queue_plane_announcement(
                                f"★ MODE CHANGED: {new_mode} ★"
                            )
                return

    def _acknowledge_alert(self):
        """Acknowledge the first unacknowledged alert."""
        for alert in self.alerts:
            if alert.status == "NEW":
                success, message = self.client.acknowledge_alert(alert.alert_id)
                if success:
                    alert.status = "ACKNOWLEDGED"
                    self._show_message(f"Alert {alert.alert_id} acknowledged", Colors.STATUS_OK)
                else:
                    self._show_message(message, Colors.STATUS_ERROR)
                return
        self._show_message("No unacknowledged alerts", Colors.MUTED)

    def _export_events(self):
        """Export events to a JSON file."""
        export_path = f"boundary_events_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            events = self.client.export_events()
            with open(export_path, 'w') as f:
                json.dump(events, f, indent=2, default=str)
            self._show_message(f"Exported {len(events)} events to {export_path}", Colors.STATUS_OK)
        except Exception as e:
            self._show_message(f"Export failed: {e}", Colors.STATUS_ERROR)

    # Boundary Daemon tool definitions with help
    DAEMON_TOOLS = {
        # CLI Commands
        'query': {
            'desc': 'Query events from log',
            'usage': 'query <filter> [--last 24h] [--limit N]',
            'help': [
                "QUERY - Event Query Tool",
                "=" * 50,
                "",
                "Query events from the daemon's hash-chain log.",
                "",
                "USAGE:",
                "  query <filter>",
                "  query type:VIOLATION --last 24h",
                "  query contains:unauthorized",
                "",
                "FILTERS:",
                "  type:<TYPE>       - Event type (VIOLATION, TRIPWIRE, MODE_CHANGE, etc)",
                "  severity:>=HIGH   - Minimum severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)",
                "  contains:<text>   - Full text search in details",
                "  actor:<pattern>   - Filter by actor/agent",
                "  --last <time>     - Time range (1h, 24h, 7d)",
                "",
                "EXAMPLES:",
                "  query type:VIOLATION",
                "  query severity:>=HIGH --last 24h",
                "  query contains:passwd",
                "  query actor:agent-*",
            ],
            'subcommands': [],
        },
        'trace': {
            'desc': 'Trace and search events with details',
            'usage': 'trace <search_term>',
            'help': [
                "TRACE - Event Tracing Tool",
                "=" * 50,
                "",
                "Search and display detailed event information.",
                "",
                "USAGE:",
                "  trace <search_term>",
                "",
                "Searches event types and details, displays results",
                "in detailed box format with timestamps.",
                "",
                "EXAMPLES:",
                "  trace unauthorized",
                "  trace VIOLATION",
                "  trace sandbox",
            ],
            'subcommands': [],
        },
        'status': {
            'desc': 'Show daemon status',
            'usage': 'status',
            'help': [
                "STATUS - Daemon Status",
                "=" * 50,
                "",
                "Display current daemon status including:",
                "  - Current security mode",
                "  - Mode frozen state",
                "  - Uptime",
                "  - Event count",
                "  - Violation count",
                "  - Connection info",
            ],
            'subcommands': [],
        },
        'alerts': {
            'desc': 'Show all alerts',
            'usage': 'alerts',
            'help': [
                "ALERTS - Alert Management",
                "=" * 50,
                "",
                "Display all current security alerts.",
                "",
                "Shows:",
                "  - Alert severity (HIGH, MEDIUM, LOW)",
                "  - Alert message",
                "  - Acknowledgment status",
                "  - Timestamp",
            ],
            'subcommands': [],
        },
        'violations': {
            'desc': 'Show recent violations',
            'usage': 'violations',
            'help': [
                "VIOLATIONS - Security Violations",
                "=" * 50,
                "",
                "Display recent security violations including:",
                "  - Unauthorized tool access attempts",
                "  - Policy violations",
                "  - PII detection events",
                "  - Command injection attempts",
                "",
                "For full history, use: query type:VIOLATION --last 24h",
            ],
            'subcommands': [],
        },
        'mode': {
            'desc': 'Show or change security mode',
            'usage': 'mode [MODE]',
            'help': [
                "MODE - Security Mode Management",
                "=" * 50,
                "",
                "Show current mode or initiate mode change.",
                "",
                "AVAILABLE MODES:",
                "  OPEN       - Minimal restrictions, full tool access",
                "  RESTRICTED - Limited tool access, monitoring active",
                "  TRUSTED    - Verified tools only, enhanced logging",
                "  AIRGAP     - No network, local tools only",
                "  COLDROOM   - Read-only, no modifications allowed",
                "  LOCKDOWN   - Emergency mode, all actions blocked",
                "",
                "Mode changes require ceremony confirmation.",
            ],
            'subcommands': ['open', 'restricted', 'trusted', 'airgap', 'coldroom', 'lockdown'],
        },
        'sandbox': {
            'desc': 'Sandbox management',
            'usage': 'sandbox <command>',
            'help': [
                "SANDBOX - Sandbox Management",
                "=" * 50,
                "",
                "Manage isolated execution environments.",
                "",
                "SUBCOMMANDS:",
                "  sandbox list      - List active sandboxes",
                "  sandbox run       - Run command in sandbox",
                "  sandbox inspect   - Inspect sandbox details",
                "  sandbox kill      - Terminate sandbox",
                "  sandbox profiles  - List available profiles",
                "  sandbox metrics   - Show sandbox metrics",
                "",
                "Sandboxes provide isolation for untrusted code execution.",
            ],
            'subcommands': ['list', 'run', 'inspect', 'kill', 'profiles', 'metrics', 'test'],
        },
        'config': {
            'desc': 'Configuration management',
            'usage': 'config <command>',
            'help': [
                "CONFIG - Configuration Management",
                "=" * 50,
                "",
                "Manage daemon configuration.",
                "",
                "SUBCOMMANDS:",
                "  config show     - Display current configuration",
                "  config lint     - Check configuration for errors",
                "  config validate - Validate configuration",
                "",
                "Config file: /etc/boundary-daemon/boundary.conf",
                "Or set BOUNDARY_CONFIG environment variable.",
            ],
            'subcommands': ['show', 'lint', 'validate'],
        },
        'case': {
            'desc': 'Security case management',
            'usage': 'case <command>',
            'help': [
                "CASE - Security Case Management",
                "=" * 50,
                "",
                "Manage security investigation cases.",
                "",
                "SUBCOMMANDS:",
                "  case list       - List all cases",
                "  case show <id>  - Show case details",
                "  case create     - Create new case",
                "  case update     - Update case status",
                "  case close      - Close a case",
                "",
                "Cases track security incidents and investigations.",
            ],
            'subcommands': ['list', 'show', 'create', 'update', 'close'],
        },
        'tripwire': {
            'desc': 'Tripwire file monitoring',
            'usage': 'tripwire <command>',
            'help': [
                "TRIPWIRE - File Integrity Monitoring",
                "=" * 50,
                "",
                "Monitor critical files for unauthorized changes.",
                "",
                "SUBCOMMANDS:",
                "  tripwire status  - Show tripwire status",
                "  tripwire list    - List monitored files",
                "  tripwire check   - Run integrity check",
                "  tripwire add     - Add file to monitoring",
                "  tripwire remove  - Remove file from monitoring",
                "",
                "Tripwires detect modifications to sensitive files",
                "like /etc/passwd, config files, and binaries.",
            ],
            'subcommands': ['status', 'list', 'check', 'add', 'remove'],
        },
        'network': {
            'desc': 'Network security status',
            'usage': 'network',
            'help': [
                "NETWORK - Network Security",
                "=" * 50,
                "",
                "Display network security status including:",
                "  - Network trust level",
                "  - VPN status",
                "  - DNS security status",
                "  - ARP monitoring status",
                "  - Traffic anomaly detection",
                "",
                "Network restrictions vary by security mode.",
            ],
            'subcommands': ['status', 'trust', 'dns', 'arp'],
        },
        'pii': {
            'desc': 'PII detection status',
            'usage': 'pii',
            'help': [
                "PII - Personal Information Detection",
                "=" * 50,
                "",
                "Monitor PII detection and filtering.",
                "",
                "Shows:",
                "  - PII detections in agent output",
                "  - Redaction statistics",
                "  - Sensitive data patterns matched",
                "",
                "PII types: SSN, credit cards, emails, phone numbers,",
                "API keys, passwords, and other credentials.",
            ],
            'subcommands': ['status', 'stats', 'patterns'],
        },
        'ceremony': {
            'desc': 'Security ceremonies',
            'usage': 'ceremony <type>',
            'help': [
                "CEREMONY - Security Ceremonies",
                "=" * 50,
                "",
                "Initiate security ceremonies for sensitive operations.",
                "",
                "CEREMONY TYPES:",
                "  ceremony mode     - Mode change ceremony",
                "  ceremony verify   - Identity verification",
                "  ceremony unlock   - Unlock frozen mode",
                "",
                "Ceremonies require human confirmation for",
                "security-critical operations.",
            ],
            'subcommands': ['mode', 'verify', 'unlock'],
        },
        'export': {
            'desc': 'Export events to file',
            'usage': 'export <filename>',
            'help': [
                "EXPORT - Export Events",
                "=" * 50,
                "",
                "Export events to JSON file for analysis.",
                "",
                "USAGE:",
                "  export events.json",
                "  export /path/to/output.json",
                "",
                "Exports include:",
                "  - Timestamp",
                "  - Event type",
                "  - Event details",
            ],
            'subcommands': [],
        },
        'checklogs': {
            'desc': 'AI analysis of daemon logs',
            'usage': 'checklogs [--last N]',
            'help': [
                "CHECKLOGS - AI-Powered Log Analysis",
                "=" * 50,
                "",
                "Sends daemon logs to Ollama for intelligent analysis.",
                "Identifies issues, security concerns, and recommendations.",
                "",
                "USAGE:",
                "  checklogs           - Analyze last 50 events",
                "  checklogs --last N  - Analyze last N events",
                "",
                "ANALYSIS INCLUDES:",
                "  - Security violations and threats",
                "  - Mode changes and ceremonies",
                "  - Rate limiting events",
                "  - PII detection incidents",
                "  - System health issues",
                "  - Recommended actions",
                "",
                "REQUIRES:",
                "  - Ollama running locally (ollama serve)",
                "  - llama3.2 or compatible model",
            ],
            'subcommands': [],
        },
        'clear': {
            'desc': 'Clear CLI results',
            'usage': 'clear',
            'help': ["Clears the results display area."],
            'subcommands': [],
        },
        'help': {
            'desc': 'Show help',
            'usage': 'help [command]',
            'help': [
                "HELP - Command Help",
                "=" * 50,
                "",
                "Show help for commands.",
                "",
                "USAGE:",
                "  help           - Show all commands",
                "  help <command> - Show help for specific command",
                "",
                "EXAMPLES:",
                "  help query",
                "  help sandbox",
                "  help mode",
            ],
            'subcommands': [],
        },
    }

    def _gather_command_data(self, commands: List[str]) -> Dict[str, Any]:
        """Execute commands and gather their results for Ollama analysis."""
        results = {}

        for cmd in commands:
            cmd = cmd.strip().lower()
            try:
                if cmd == 'status':
                    status = self.client.get_status()
                    results['status'] = {
                        'mode': status.get('mode', 'UNKNOWN'),
                        'frozen': status.get('is_frozen', False),
                        'uptime': self._format_duration(status.get('uptime', 0)),
                        'events': status.get('total_events', 0),
                        'violations': status.get('violations', 0),
                        'demo_mode': self.client.is_demo_mode(),
                    }
                elif cmd == 'alerts':
                    alerts = self.client.get_alerts()
                    results['alerts'] = [
                        {'severity': a.severity, 'message': a.message, 'time': a.time_str, 'acked': a.acknowledged}
                        for a in alerts
                    ]
                elif cmd == 'violations':
                    violations = [e for e in self.events if 'VIOLATION' in e.event_type.upper()]
                    results['violations'] = [
                        {'time': v.time_short, 'type': v.event_type, 'details': v.details[:100]}
                        for v in violations[:20]
                    ]
                elif cmd == 'events':
                    events = self.client.get_events(limit=30)
                    results['events'] = [
                        {'time': e.time_short, 'type': e.event_type, 'details': e.details[:80]}
                        for e in events
                    ]
                elif cmd == 'mode':
                    status = self.client.get_status()
                    results['mode'] = {
                        'current': status.get('mode', 'UNKNOWN'),
                        'frozen': status.get('is_frozen', False),
                    }
                elif cmd == 'sandbox' or cmd == 'sandboxes':
                    results['sandboxes'] = [
                        {'id': s.id[:8], 'name': s.name, 'status': s.status, 'uptime': s.uptime_str}
                        for s in self.sandboxes
                    ]
            except Exception as e:
                results[cmd] = {'error': str(e)}

        return results

    def _send_to_ollama(self, message: str) -> List[str]:
        """Send a message to Ollama with automatic command execution."""
        if not self._ollama_client:
            return ["ERROR: Ollama not available. Start with: ollama serve"]

        if not self._ollama_client.is_available():
            return ["ERROR: Ollama not running. Start with: ollama serve"]

        lines = ["", f"You: {message}", ""]

        # Step 1: Ask Ollama if commands are needed
        command_detection_prompt = f"""User request: "{message}"

You are an assistant for the Boundary Daemon security system. Determine if the user's request requires running system commands to answer.

AVAILABLE COMMANDS:
- status: Get daemon status (mode, uptime, event count, violations)
- alerts: Get active security alerts
- violations: Get recent security violations
- events: Get recent system events
- mode: Get current security mode
- sandboxes: Get active sandbox information

If the user is asking about system health, security status, problems, alerts, or wants to check/diagnose their system, you MUST specify which commands to run.

RESPOND WITH ONLY ONE OF THESE FORMATS:
1. If commands needed: COMMANDS: status, alerts, violations
2. If no commands needed: NONE

Examples:
- "what's wrong with my computer" -> COMMANDS: status, alerts, violations, events
- "check my system" -> COMMANDS: status, alerts, violations
- "any security issues?" -> COMMANDS: alerts, violations
- "hello" -> NONE
- "what is a sandbox?" -> NONE

Your response (COMMANDS: ... or NONE):"""

        try:
            # Detect if commands are needed
            detection_response = self._ollama_client.generate(command_detection_prompt, system="You are a command router. Respond only with COMMANDS: list or NONE.")

            commands_to_run = []
            if detection_response and 'COMMANDS:' in detection_response.upper():
                # Parse commands from response
                cmd_part = detection_response.upper().split('COMMANDS:')[1].strip()
                cmd_part = cmd_part.split('\n')[0]  # Take first line only
                commands_to_run = [c.strip().lower() for c in cmd_part.split(',') if c.strip()]

            # Step 2: Execute commands if needed
            command_results = {}
            if commands_to_run:
                lines.append("  [Gathering system information...]")
                command_results = self._gather_command_data(commands_to_run)

            # Step 3: Generate natural language response
            context = ""
            for entry in self._cli_chat_history[-5:]:
                context += f"User: {entry['user']}\nAssistant: {entry['assistant']}\n\n"

            if command_results:
                # Build response with command data
                system_prompt = """You are a helpful security assistant for the Boundary Daemon system.
You have access to real system data and should analyze it to answer the user's question.
Be conversational but informative. Highlight any issues or concerns.
Keep responses concise (3-6 sentences) for the terminal interface.
If there are problems, explain what they mean and suggest actions."""

                data_summary = json.dumps(command_results, indent=2, default=str)
                prompt = f"""{context}User: {message}

SYSTEM DATA COLLECTED:
{data_summary}

Based on this data, provide a helpful natural language response to the user's question. If there are issues, explain them clearly. If everything looks good, say so."""

            else:
                # Regular chat without command data
                system_prompt = """You are a helpful assistant integrated into the Boundary Daemon CLI.
You help users understand system security, daemon operations, and answer questions.
Keep responses concise (2-4 sentences) since this is a terminal interface.
If the user asks you to check their system or look for problems, tell them you can do that - just ask!"""

                prompt = f"{context}User: {message}\nAssistant:"

            response = self._ollama_client.generate(prompt, system=system_prompt)

            if response:
                # Store in chat history
                self._cli_chat_history.append({'user': message, 'assistant': response})
                if len(self._cli_chat_history) > 20:
                    self._cli_chat_history = self._cli_chat_history[-20:]

                # Word wrap response
                for paragraph in response.split('\n'):
                    if not paragraph.strip():
                        lines.append("")
                        continue
                    words = paragraph.split()
                    current_line = "  "
                    for word in words:
                        if len(current_line) + len(word) + 1 > self.width - 4:
                            lines.append(current_line)
                            current_line = "  " + word
                        else:
                            current_line += (" " if len(current_line) > 2 else "") + word
                    if current_line.strip():
                        lines.append(current_line)
                lines.append("")
                return lines
            else:
                return lines + ["ERROR: No response from Ollama"]
        except Exception as e:
            return lines + [f"ERROR: Ollama error: {e}"]

    def _analyze_logs_with_ollama(self, num_events: int = 50) -> List[str]:
        """Analyze daemon logs using Ollama and return analysis lines."""
        if not self._ollama_client:
            return ["ERROR: Ollama not available. Start with: ollama serve"]

        if not self._ollama_client.is_available():
            return ["ERROR: Ollama not running. Start with: ollama serve"]

        lines = ["", "ANALYZING LOGS WITH OLLAMA...", "=" * 50, ""]

        # Gather system information
        try:
            status = self.client.get_status()
            events = self.client.get_events(limit=num_events)
            alerts = self.client.get_alerts()
        except Exception as e:
            return [f"ERROR: Failed to fetch daemon data: {e}"]

        # Build comprehensive log data for Ollama
        log_data = []

        # Add daemon status
        log_data.append("=== DAEMON STATUS ===")
        log_data.append(f"Mode: {status.get('mode', 'unknown')}")
        log_data.append(f"State: {status.get('state', 'unknown')}")
        log_data.append(f"Uptime: {status.get('uptime', 'unknown')}")
        log_data.append(f"Active Sandboxes: {status.get('sandboxes', {}).get('active', 0)}")
        log_data.append("")

        # Add active alerts
        log_data.append("=== ACTIVE ALERTS ===")
        if alerts:
            for alert in alerts:
                log_data.append(f"[{alert.severity}] {alert.message}")
                log_data.append(f"  Time: {alert.time_str}")
        else:
            log_data.append("No active alerts")
        log_data.append("")

        # Add recent events with full details
        log_data.append(f"=== RECENT EVENTS (last {len(events)}) ===")
        event_type_counts = {}
        for event in events:
            event_type_counts[event.event_type] = event_type_counts.get(event.event_type, 0) + 1
            log_data.append(f"[{event.time_short}] {event.event_type}: {event.details[:100]}")

        log_data.append("")
        log_data.append("=== EVENT TYPE SUMMARY ===")
        for etype, count in sorted(event_type_counts.items(), key=lambda x: -x[1]):
            log_data.append(f"  {etype}: {count}")

        # Comprehensive system prompt for log analysis
        system_prompt = """You are a security analyst AI integrated into the Boundary Daemon system.
Your job is to analyze security logs and provide actionable insights.

BOUNDARY DAEMON CONTEXT:
- Boundary Daemon is a security monitoring system for AI agents and system operations
- It enforces operation modes: OPEN (permissive), RESTRICTED (limited), LOCKDOWN (emergency)
- It monitors for security violations, PII leakage, rate limiting, and suspicious activity
- Mode changes require cryptographic ceremonies for security

EVENT TYPES TO WATCH FOR:
- VIOLATION: Security policy violations - HIGH PRIORITY
- MODE_CHANGE: Operation mode transitions - important for security posture
- RATE_LIMIT_*: Rate limiting events - may indicate abuse or attacks
- PII_DETECTED/BLOCKED/REDACTED: Privacy incidents
- CLOCK_JUMP/DRIFT: Time manipulation (potential tampering)
- ALERT: System alerts requiring attention
- SECURITY_SCAN: Antivirus/malware scan results

SEVERITY ASSESSMENT:
- CRITICAL: Immediate action required (violations, lockdowns, tampering)
- HIGH: Security concern requiring investigation
- MEDIUM: Notable event to monitor
- LOW: Informational

Analyze the logs and provide:
1. SUMMARY: Overall system health assessment (1-2 sentences)
2. ISSUES FOUND: List specific problems with severity
3. SECURITY CONCERNS: Any security-related findings
4. RECOMMENDATIONS: Actionable next steps

Keep response concise and terminal-friendly (max 20 lines)."""

        prompt = f"""Analyze these Boundary Daemon security logs and tell me if there are any issues with my system:

{chr(10).join(log_data)}

Provide a clear, actionable analysis."""

        try:
            lines.append("Sending to Ollama for analysis...")
            lines.append("")

            response = self._ollama_client.generate(prompt, system=system_prompt)

            if response:
                lines.append("ANALYSIS RESULTS:")
                lines.append("-" * 40)
                # Word wrap response for terminal
                for paragraph in response.split('\n'):
                    if not paragraph.strip():
                        lines.append("")
                        continue
                    words = paragraph.split()
                    current_line = ""
                    for word in words:
                        if len(current_line) + len(word) + 1 > self.width - 4:
                            lines.append(current_line)
                            current_line = word
                        else:
                            current_line += (" " if current_line else "") + word
                    if current_line:
                        lines.append(current_line)
                lines.append("")
                lines.append("-" * 40)
                lines.append(f"Analyzed {len(events)} events, {len(alerts)} alerts")
            else:
                lines.append("ERROR: No response from Ollama")
        except Exception as e:
            lines.append(f"ERROR: Analysis failed: {e}")

        return lines

    def _start_cli(self):
        """Start CLI mode for running commands and chatting with Ollama."""
        curses.curs_set(1)  # Show cursor
        cmd_text = ""
        cursor_pos = 0
        show_help_popup = False
        help_popup_tool = None

        # Initialize activity timer
        self._cli_last_activity = time.time()

        # Build autocomplete list from DAEMON_TOOLS (with / prefix)
        all_completions = ["/" + cmd for cmd in self.DAEMON_TOOLS.keys()]

        # Check Ollama status
        ollama_status = "connected" if (self._ollama_client and self._ollama_client.is_available()) else "offline"

        # Available commands help
        cli_help = [
            "BOUNDARY DAEMON CLI + OLLAMA CHAT",
            "=" * 60,
            "",
            f"  Ollama: {ollama_status}",
            "",
            "  Type a message to chat with Ollama",
            "  Use /command for daemon commands (e.g., /help, /status)",
            "",
            "COMMANDS (prefix with /):",
        ]
        for cmd, info in self.DAEMON_TOOLS.items():
            cli_help.append(f"  /{cmd:11} - {info['desc']}")
        cli_help.extend([
            "",
            "EXAMPLES:",
            "  What is a security violation?     (chat with Ollama)",
            "  /alerts                           (show daemon alerts)",
            "  /query type:VIOLATION --last 24h  (search events)",
            "",
            "Auto-hides after 5 minutes of inactivity",
        ])

        while True:
            # Check for inactivity timeout
            if time.time() - self._cli_last_activity > self._cli_timeout:
                # Clear results and exit
                self._cli_results = []
                self._cli_chat_history = []
                break

            self.screen.clear()

            # Draw CLI header with Ollama status
            header = "─" * (self.width - 1)
            self._addstr(0, 0, " BOUNDARY CLI ", Colors.HEADER)
            ollama_indicator = f" [Ollama: {ollama_status}] "
            self._addstr(0, 15, ollama_indicator, Colors.STATUS_OK if ollama_status == "connected" else Colors.STATUS_WARN)
            self._addstr(0, 15 + len(ollama_indicator), header[15 + len(ollama_indicator):], Colors.MUTED)

            # Draw results area (scrollable)
            results_height = self.height - 5
            if self._cli_results:
                for i, line in enumerate(self._cli_results[self._cli_results_scroll:]):
                    row = 2 + i
                    if row >= results_height:
                        break
                    # Color code based on content
                    if line.startswith("ERROR:") or "VIOLATION" in line or "CRITICAL" in line:
                        color = Colors.STATUS_ERROR
                    elif line.startswith("OK:") or "SUCCESS" in line:
                        color = Colors.STATUS_OK
                    elif line.startswith("You:"):
                        color = Colors.ACCENT
                    elif line.startswith("  ") or line.startswith("│"):
                        color = Colors.MUTED
                    elif "HIGH" in line:
                        color = Colors.STATUS_WARN
                    else:
                        color = Colors.NORMAL
                    self._addstr(row, 1, line[:self.width-3], color)

                # Scroll indicator
                if len(self._cli_results) > results_height - 2:
                    scroll_info = f"[{self._cli_results_scroll+1}-{min(self._cli_results_scroll+results_height-2, len(self._cli_results))}/{len(self._cli_results)}]"
                    self._addstr(1, self.width - len(scroll_info) - 2, scroll_info, Colors.MUTED)
            else:
                # Show help if no results
                for i, line in enumerate(cli_help):
                    row = 2 + i
                    if row >= results_height:
                        break
                    self._addstr(row, 2, line, Colors.MUTED)

            # Draw command line at bottom
            prompt_y = self.height - 2
            prompt_char = ">" if not cmd_text.startswith("/") else ":"
            self._addstr(prompt_y, 0, prompt_char + cmd_text + " ", Colors.HEADER)
            self._addstr(prompt_y, len(cmd_text) + 1, "_", Colors.ACCENT)

            # Draw shortcuts with timeout indicator
            remaining = max(0, int(self._cli_timeout - (time.time() - self._cli_last_activity)))
            timeout_str = f" [{remaining//60}:{remaining%60:02d}]"
            shortcuts = f"[Enter] Send  [Tab] Complete  [F1] Help  [ESC] Exit{timeout_str}"
            self._addstr(self.height - 1, 0, shortcuts[:self.width-1], Colors.MUTED)

            self.screen.refresh()

            # Use timeout to allow checking inactivity
            self.screen.timeout(1000)  # 1 second timeout
            key = self.screen.getch()

            if key == -1:  # Timeout, no key pressed
                continue

            # Key pressed - reset activity timer
            self._cli_last_activity = time.time()

            if key == 27:  # ESC
                break
            elif key in (curses.KEY_ENTER, 10, 13):
                if cmd_text.strip():
                    # Add to history
                    if not self._cli_history or self._cli_history[-1] != cmd_text:
                        self._cli_history.append(cmd_text)
                    self._cli_history_index = len(self._cli_history)

                    text = cmd_text.strip()
                    if text.startswith("/"):
                        # Execute as daemon command (strip the /)
                        self._execute_cli_command(text[1:])
                    else:
                        # Send to Ollama
                        response_lines = self._send_to_ollama(text)
                        self._cli_results.extend(response_lines)

                    cmd_text = ""
                    self._cli_results_scroll = max(0, len(self._cli_results) - (self.height - 6))
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                cmd_text = cmd_text[:-1]
            elif key == curses.KEY_UP:
                # History navigation
                if self._cli_history and self._cli_history_index > 0:
                    self._cli_history_index -= 1
                    cmd_text = self._cli_history[self._cli_history_index]
            elif key == curses.KEY_DOWN:
                if self._cli_history_index < len(self._cli_history) - 1:
                    self._cli_history_index += 1
                    cmd_text = self._cli_history[self._cli_history_index]
                else:
                    self._cli_history_index = len(self._cli_history)
                    cmd_text = ""
            elif key == curses.KEY_PPAGE:  # Page Up
                if show_help_popup:
                    # Scroll help popup
                    pass
                else:
                    self._cli_results_scroll = max(0, self._cli_results_scroll - 10)
            elif key == curses.KEY_NPAGE:  # Page Down
                if show_help_popup:
                    pass
                else:
                    max_scroll = max(0, len(self._cli_results) - (self.height - 6))
                    self._cli_results_scroll = min(max_scroll, self._cli_results_scroll + 10)
            elif key == curses.KEY_F1 or key == 265:  # F1 - show help for current command
                # Get the first word being typed (strip / for command lookup)
                first_word = cmd_text.split()[0].lstrip("/") if cmd_text.split() else ""
                if first_word in self.DAEMON_TOOLS:
                    help_popup_tool = first_word
                    show_help_popup = True
                else:
                    # Show general help
                    show_help_popup = True
                    help_popup_tool = None
            elif key == 9:  # Tab - smart autocomplete (only for /commands)
                if cmd_text.startswith("/"):
                    parts = cmd_text.split()
                    if len(parts) == 0 or (len(parts) == 1 and not cmd_text.endswith(' ')):
                        # Complete command name
                        prefix = parts[0] if parts else "/"
                        for comp in all_completions:
                            if comp.startswith(prefix):
                                cmd_text = comp + " "
                                break
                    elif len(parts) >= 1:
                        # Complete subcommand
                        base_cmd = parts[0].lstrip("/")
                        if base_cmd in self.DAEMON_TOOLS:
                            subcommands = self.DAEMON_TOOLS[base_cmd].get('subcommands', [])
                            if subcommands:
                                prefix = parts[1] if len(parts) > 1 else ""
                                for sub in subcommands:
                                    if sub.startswith(prefix):
                                        cmd_text = f"/{base_cmd} {sub} "
                                        break
            elif 32 <= key <= 126:  # Printable characters
                cmd_text += chr(key)

            # Draw help popup if active
            if show_help_popup:
                self._draw_help_popup(help_popup_tool)
                self.screen.refresh()
                popup_key = self.screen.getch()
                if popup_key == 27 or popup_key == curses.KEY_F1 or popup_key == 265 or popup_key in (10, 13):
                    show_help_popup = False
                continue

        curses.curs_set(0)  # Hide cursor

    def _draw_help_popup(self, tool_name: Optional[str] = None):
        """Draw a help popup window for a tool."""
        # Calculate popup dimensions
        popup_width = min(60, self.width - 4)
        popup_height = min(25, self.height - 4)
        popup_x = (self.width - popup_width) // 2
        popup_y = (self.height - popup_height) // 2

        # Get help content
        if tool_name and tool_name in self.DAEMON_TOOLS:
            tool = self.DAEMON_TOOLS[tool_name]
            help_lines = tool['help']
            title = f" {tool_name.upper()} HELP "
        else:
            help_lines = [
                "BOUNDARY DAEMON CLI HELP",
                "=" * 40,
                "",
                "Available commands:",
                "",
            ]
            for cmd, info in self.DAEMON_TOOLS.items():
                help_lines.append(f"  {cmd:12} - {info['desc']}")
            help_lines.extend([
                "",
                "Type 'help <command>' for detailed help.",
                "Press F1 while typing a command for quick help.",
            ])
            title = " CLI HELP "

        # Draw popup border
        try:
            # Top border
            self._addstr(popup_y, popup_x, "┌" + "─" * (popup_width - 2) + "┐", Colors.HEADER)
            # Title
            title_x = popup_x + (popup_width - len(title)) // 2
            self._addstr(popup_y, title_x, title, Colors.ACCENT)

            # Content area
            for i in range(popup_height - 2):
                row = popup_y + 1 + i
                # Side borders
                self._addstr(row, popup_x, "│", Colors.HEADER)
                self._addstr(row, popup_x + popup_width - 1, "│", Colors.HEADER)
                # Content
                if i < len(help_lines):
                    line = help_lines[i][:popup_width - 4]
                    self._addstr(row, popup_x + 2, line, Colors.NORMAL)

            # Bottom border
            self._addstr(popup_y + popup_height - 1, popup_x, "└" + "─" * (popup_width - 2) + "┘", Colors.HEADER)

            # Close hint
            close_hint = " [ESC/Enter] Close "
            self._addstr(popup_y + popup_height - 1, popup_x + popup_width - len(close_hint) - 2, close_hint, Colors.MUTED)
        except curses.error:
            pass

    def _execute_cli_command(self, cmd: str):
        """Execute a CLI command and populate results."""
        parts = cmd.split(maxsplit=1)
        command = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        self._cli_results = []

        try:
            if command == 'help':
                if args and args in self.DAEMON_TOOLS:
                    # Show specific tool help
                    tool = self.DAEMON_TOOLS[args]
                    self._cli_results = tool['help'].copy()
                else:
                    # Show general help
                    self._cli_results = [
                        "BOUNDARY DAEMON CLI",
                        "=" * 50,
                        "",
                        "COMMANDS:",
                    ]
                    for cmd_name, info in self.DAEMON_TOOLS.items():
                        usage = info['usage']
                        self._cli_results.append(f"  {usage:24} - {info['desc']}")
                    self._cli_results.extend([
                        "",
                        "Type 'help <command>' for detailed help on any command.",
                        "Press F1 while typing for quick context help.",
                        "",
                        "EXAMPLES:",
                        "  query type:VIOLATION --last 24h",
                        "  trace unauthorized",
                        "  sandbox list",
                        "  tripwire status",
                    ])

            elif command == 'clear':
                self._cli_results = ["Results cleared."]

            elif command == 'checklogs':
                # Parse --last N argument
                num_events = 50  # Default
                if args:
                    parts = args.split()
                    for i, part in enumerate(parts):
                        if part == '--last' and i + 1 < len(parts):
                            try:
                                num_events = int(parts[i + 1])
                                num_events = min(max(num_events, 10), 200)  # Clamp 10-200
                            except ValueError:
                                pass
                self._cli_results = self._analyze_logs_with_ollama(num_events)

            elif command == 'status':
                status = self.client.get_status()
                self._cli_results = [
                    "DAEMON STATUS",
                    "=" * 40,
                    f"  Mode:       {status.get('mode', 'UNKNOWN')}",
                    f"  Frozen:     {status.get('is_frozen', False)}",
                    f"  Uptime:     {self._format_duration(status.get('uptime', 0))}",
                    f"  Events:     {status.get('total_events', 0)}",
                    f"  Violations: {status.get('violations', 0)}",
                    f"  Connection: {'TCP:19847' if self.client._use_tcp else self.client.socket_path}",
                    f"  Demo Mode:  {self.client.is_demo_mode()}",
                ]

            elif command == 'alerts':
                alerts = self.client.get_alerts()
                self._cli_results = [f"ALERTS ({len(alerts)} total)", "=" * 40]
                for alert in alerts:
                    ack = "✓" if alert.acknowledged else "○"
                    self._cli_results.append(f"  {ack} [{alert.severity}] {alert.message}")
                    self._cli_results.append(f"      Time: {alert.time_str}")
                if not alerts:
                    self._cli_results.append("  No alerts.")

            elif command == 'violations':
                # Query violations from events
                violations = [e for e in self.events if 'VIOLATION' in e.event_type.upper()]
                self._cli_results = [f"RECENT VIOLATIONS ({len(violations)})", "=" * 40]
                for v in violations[:20]:
                    self._cli_results.append(f"  [{v.time_short}] {v.event_type}")
                    self._cli_results.append(f"      {v.details[:60]}")
                if not violations:
                    self._cli_results.append("  No violations in recent events.")
                    self._cli_results.append("  Use 'query type:VIOLATION --last 24h' for full search.")

            elif command == 'query':
                self._cli_results = self._execute_query(args)

            elif command == 'trace':
                self._cli_results = self._execute_trace(args)

            elif command == 'mode':
                if args:
                    # Try to change mode (would need ceremony in real use)
                    self._cli_results = [
                        f"Mode change to '{args}' requires ceremony.",
                        "Use 'm' key from main dashboard to initiate mode change.",
                    ]
                else:
                    status = self.client.get_status()
                    self._cli_results = [
                        f"Current Mode: {status.get('mode', 'UNKNOWN')}",
                        f"Frozen: {status.get('is_frozen', False)}",
                    ]

            elif command == 'export':
                if not args:
                    self._cli_results = ["ERROR: Specify output file (e.g., export events.json)"]
                else:
                    try:
                        events = self.client.get_events(1000)
                        export_data = [{'time': e.time_str, 'type': e.event_type, 'details': e.details} for e in events]
                        with open(args, 'w') as f:
                            json.dump(export_data, f, indent=2)
                        self._cli_results = [f"OK: Exported {len(events)} events to {args}"]
                    except Exception as e:
                        self._cli_results = [f"ERROR: Export failed: {e}"]

            else:
                self._cli_results = [
                    f"ERROR: Unknown command '{command}'",
                    "Type 'help' for available commands.",
                ]

        except Exception as e:
            self._cli_results = [f"ERROR: {e}"]

    def _execute_query(self, query_str: str) -> List[str]:
        """Execute a query command."""
        results = ["QUERY RESULTS", "=" * 40]

        # Parse query parameters
        query_lower = query_str.lower()
        events = self.events

        # Filter by type
        if 'type:' in query_lower:
            import re
            type_match = re.search(r'type:(\w+)', query_lower)
            if type_match:
                event_type = type_match.group(1).upper()
                events = [e for e in events if event_type in e.event_type.upper()]

        # Filter by severity
        if 'severity:' in query_lower:
            severity_map = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            import re
            sev_match = re.search(r'severity:>=?(\w+)', query_lower)
            if sev_match:
                min_sev = severity_map.get(sev_match.group(1).lower(), 0)
                # Filter events with severity (would need actual severity field)
                events = [e for e in events if any(s in e.event_type.upper() for s in ['HIGH', 'CRITICAL', 'VIOLATION', 'ERROR'])]

        # Full text search
        if 'contains:' in query_lower:
            import re
            text_match = re.search(r'contains:(\S+)', query_lower)
            if text_match:
                search_text = text_match.group(1)
                events = [e for e in events if search_text.lower() in e.details.lower() or search_text.lower() in e.event_type.lower()]

        # Simple text search (no prefix)
        remaining = query_str
        for prefix in ['type:', 'severity:', 'contains:', '--last']:
            import re
            remaining = re.sub(rf'{prefix}\S*\s*', '', remaining, flags=re.IGNORECASE)
        remaining = remaining.strip()
        if remaining and not remaining.startswith('-'):
            events = [e for e in events if remaining.lower() in e.details.lower() or remaining.lower() in e.event_type.lower()]

        results.append(f"Found {len(events)} events matching: {query_str}")
        results.append("")

        for e in events[:30]:
            results.append(f"  [{e.time_short}] {e.event_type}")
            results.append(f"      {e.details[:70]}")

        if len(events) > 30:
            results.append(f"  ... and {len(events) - 30} more")

        if not events:
            results.append("  No matching events found.")
            results.append("  Try: query type:VIOLATION")
            results.append("       query contains:unauthorized")

        return results

    def _execute_trace(self, search_text: str) -> List[str]:
        """Trace/search for events with detailed output."""
        results = ["TRACE RESULTS", "=" * 40]

        if not search_text:
            results.append("Usage: trace <search_term>")
            results.append("Example: trace unauthorized")
            return results

        # Search through events
        matches = []
        for e in self.events:
            if search_text.lower() in e.event_type.lower() or search_text.lower() in e.details.lower():
                matches.append(e)

        results.append(f"Tracing '{search_text}': {len(matches)} matches")
        results.append("")

        for i, e in enumerate(matches[:15]):
            results.append(f"┌─ Event {i+1} ─────────────────────────")
            results.append(f"│ Time:    {e.time_str}")
            results.append(f"│ Type:    {e.event_type}")
            results.append(f"│ Details: {e.details[:50]}")
            if len(e.details) > 50:
                results.append(f"│          {e.details[50:100]}")
            results.append(f"└{'─' * 40}")
            results.append("")

        if len(matches) > 15:
            results.append(f"... and {len(matches) - 15} more matches")

        if not matches:
            results.append("No matches found.")
            results.append("Try a different search term.")

        return results

    def _start_search(self):
        """Start event search/filter with text input."""
        curses.curs_set(1)  # Show cursor
        search_text = ""

        while True:
            self.screen.clear()

            # Draw search bar at top
            self._addstr(0, 0, "Search: ", Colors.HEADER)
            self._addstr(0, 8, search_text + "_", Colors.NORMAL)
            self._addstr(0, self.width - 20, "[Enter] Apply [ESC] Cancel", Colors.MUTED)

            # Show filtered events preview
            filtered = [e for e in self.events if search_text.lower() in e.event_type.lower()
                       or search_text.lower() in e.details.lower()]
            self._addstr(2, 0, f"Matching events: {len(filtered)}", Colors.MUTED)

            for i, event in enumerate(filtered[:10]):
                row = 4 + i
                if row >= self.height - 1:
                    break
                self._addstr(row, 2, event.time_short, Colors.MUTED)
                self._addstr(row, 12, event.event_type[:15], Colors.ACCENT)
                self._addstr(row, 28, event.details[:self.width-30], Colors.NORMAL)

            self.screen.refresh()

            key = self.screen.getch()
            if key == 27:  # ESC
                self.event_filter = ""
                break
            elif key in (curses.KEY_ENTER, 10, 13):
                self.event_filter = search_text
                break
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                search_text = search_text[:-1]
            elif 32 <= key <= 126:  # Printable characters
                search_text += chr(key)

        curses.curs_set(0)  # Hide cursor

    def _show_message(self, message: str, color: int = Colors.NORMAL):
        """Show a temporary message overlay."""
        msg_width = min(len(message) + 4, self.width - 4)
        msg_x = (self.width - msg_width) // 2
        msg_y = self.height // 2

        self._draw_box(msg_y - 1, msg_x - 2, msg_width + 4, 3, "")
        self._addstr(msg_y, msg_x, message[:msg_width], color)
        self.screen.refresh()
        time.sleep(1.5)

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
    # Show connection status before entering curses mode
    print("Connecting to Boundary Daemon...")

    # Create client first to check connection
    client = DashboardClient(socket_path)

    if client.is_demo_mode():
        print("\n" + "=" * 60)
        print("WARNING: Could not connect to Boundary Daemon")
        print("=" * 60)
        print("\nSearched for daemon at:")
        for path in client._socket_paths[:5]:
            exists = "FOUND" if os.path.exists(path) else "not found"
            print(f"  - {path} [{exists}]")
        if sys.platform == 'win32':
            print(f"  - TCP 127.0.0.1:{client.WINDOWS_PORT} [not responding]")
        print("\nRunning in DEMO MODE with simulated data.")
        print("To connect to real daemon, start boundary-daemon.exe first.")
        print("=" * 60 + "\n")
        import time
        time.sleep(2)  # Give user time to read
    else:
        if client._use_tcp:
            print(f"Connected to daemon via TCP on port {client.WINDOWS_PORT}")
        else:
            print(f"Connected to daemon at {client.socket_path}")

    dashboard = Dashboard(refresh_interval=refresh_interval, socket_path=socket_path,
                         matrix_mode=matrix_mode, client=client)
    dashboard.run()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Boundary Daemon Dashboard")
    parser.add_argument("--refresh", "-r", type=float, default=2.0,
                       help="Refresh interval in seconds (e.g., 2.0, 1.0, 0.5, 0.01=10ms, 0.005=5ms)")
    parser.add_argument("--socket", "-s", type=str,
                       help="Path to daemon socket")
    # Secret Matrix mode - not shown in help
    parser.add_argument("--matrix", action="store_true",
                       help=argparse.SUPPRESS)

    args = parser.parse_args()
    run_dashboard(refresh_interval=args.refresh, socket_path=args.socket,
                  matrix_mode=args.matrix)
