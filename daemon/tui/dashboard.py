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


class WeatherMode(Enum):
    """Weather modes for Matrix-style effects."""
    MATRIX = "matrix"      # Classic green Matrix rain
    RAIN = "rain"          # Blue rain
    SNOW = "snow"          # White/gray snow
    SAND = "sand"          # Brown/yellow sandstorm

    @property
    def display_name(self) -> str:
        """Get display name for the weather mode."""
        return {
            WeatherMode.MATRIX: "Matrix",
            WeatherMode.RAIN: "Rain",
            WeatherMode.SNOW: "Snow",
            WeatherMode.SAND: "Sandstorm",
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
    }

    # Weather-specific speed multipliers (relative to base speeds)
    WEATHER_SPEED_MULT = {
        WeatherMode.MATRIX: 1.0,
        WeatherMode.RAIN: 1.2,   # Rain falls fast
        WeatherMode.SNOW: 0.4,   # Base snow speed (modified per-depth below)
        WeatherMode.SAND: 0.15,  # Sand falls very slowly (blows horizontally instead)
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
    }

    # Weather-specific horizontal movement
    WEATHER_HORIZONTAL = {
        WeatherMode.MATRIX: (0, 0),       # No horizontal movement
        WeatherMode.RAIN: (-0.1, 0.1),    # Slight wind variation
        WeatherMode.SNOW: (-0.4, 0.4),    # Gentle drift both ways
        WeatherMode.SAND: (1.5, 3.0),     # Strong wind blowing right
    }

    # Weather-specific color mappings (bright, dim, fade1, fade2)
    WEATHER_COLORS = {
        WeatherMode.MATRIX: (Colors.MATRIX_BRIGHT, Colors.MATRIX_DIM, Colors.MATRIX_FADE1, Colors.MATRIX_FADE2),
        WeatherMode.RAIN: (Colors.RAIN_BRIGHT, Colors.RAIN_DIM, Colors.RAIN_FADE1, Colors.RAIN_FADE2),
        WeatherMode.SNOW: (Colors.SNOW_BRIGHT, Colors.SNOW_DIM, Colors.SNOW_FADE, Colors.SNOW_FADE),
        WeatherMode.SAND: (Colors.SAND_BRIGHT, Colors.SAND_DIM, Colors.SAND_FADE, Colors.SAND_FADE),
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

    def set_quick_melt_zones(self, sidewalk_y: int, mailbox_bounds: Tuple[int, int, int, int], street_y: int):
        """Set zones where snow melts very quickly (sidewalk, mailbox, traffic lines).

        Args:
            sidewalk_y: Y coordinate of the sidewalk/curb
            mailbox_bounds: (x, y, width, height) of the mailbox
            street_y: Y coordinate of the street (for traffic lines)
        """
        self._quick_melt_sidewalk_y = sidewalk_y
        self._quick_melt_mailbox = mailbox_bounds
        self._quick_melt_street_y = street_y

    def _is_in_quick_melt_zone(self, x: int, y: int) -> bool:
        """Check if a position is in a quick-melt zone (sidewalk, mailbox, traffic line)."""
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

        self.drops.append({
            'x': start_x,
            'y': start_y,
            'speed': random.uniform(speed_min, speed_max) * speed_mult,
            'length': random.randint(len_min, effective_max_len),
            'char_offset': random.randint(0, len(weather_chars[depth]) - 1),
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

        # Add new drops to maintain density
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

    # Cafe storefront (well-lit, between buildings) - taller size
    CAFE = [
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
        " |L(R) ",  # Red lights - right side has brackets
        " |L(R) ",  # Yellow lights
        " |L(R) ",  # Green lights
        " '===' ",
        "   ||  ",
        "   ||  ",
        "   ||  ",
        "   ||  ",
        "   ||  ",
        "   ||  ",
        "   ||  ",
        "   ||  ",
    ]

    # Car sprites - large side views (3 rows tall, longer)
    CAR_RIGHT = [
        "    ___[######]___    ",
        "   |   |====|    |    ",
        "  (o)============(o)  ",
    ]
    CAR_LEFT = [
        "    ___[######]___    ",
        "   |    |====|   |    ",
        "  (o)============(o)  ",
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

    # Tree sprites for windy city effect
    TREE = [
        "   (@@)   ",
        "  (@@@@@) ",
        " (@@@@@@@@)",
        "  (@@@@@) ",
        "    ||    ",
        "    ||    ",
        "   _||_   ",
    ]

    # Tree blowing right (wind from left)
    TREE_WINDY_RIGHT = [
        "    (@@)  ",
        "   (@@@@@)",
        "  (@@@@@@@)",
        "   (@@@@) ",
        "    ||    ",
        "    ||    ",
        "   _||_   ",
    ]

    # Tree blowing left (wind from right)
    TREE_WINDY_LEFT = [
        "  (@@)    ",
        "(@@@@@)   ",
        "(@@@@@@@) ",
        " (@@@@)   ",
        "    ||    ",
        "    ||    ",
        "   _||_   ",
    ]

    # Debris sprites for windy weather
    DEBRIS_NEWSPAPER = ['▪', '▫', '□', '▢']
    DEBRIS_TRASH = ['~', '°', '·', '∘']
    DEBRIS_LEAVES = ['*', '✦', '✧', '⁕']

    # Wind wisp characters
    WIND_WISPS = ['~', '≈', '≋', '～', '-', '=']

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

    # Person with hat (= on head) - with leg animation
    PERSON_HAT_RIGHT_FRAMES = [
        [" = ", " O ", "/| ", "/| "],   # Hat, right leg forward
        [" = ", " O ", " |\\", "|| "],   # Hat, legs together
        [" = ", " O ", "/| ", "|\\ "],   # Hat, left leg back
        [" = ", " O ", " |\\", "|| "],   # Hat, legs together
    ]
    PERSON_HAT_LEFT_FRAMES = [
        [" = ", " O ", " |\\", " |\\"],  # Hat, left leg forward
        [" = ", " O ", "/| ", " ||"],   # Hat, legs together
        [" = ", " O ", " |\\", " /|"],  # Hat, right leg back
        [" = ", " O ", "/| ", " ||"],   # Hat, legs together
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
    # 140 chars wide, dense city skyline with various building heights
    CITYSCAPE = [
        "         T                    |~|                 T              T                    |~|              T           ",  # Row 0
        "   ___  /|\\        ___       |=|    ___         /|\\   ___      /|\\        ___       |=|    ___      /|\\   ___    ",  # Row 1
        "  |   | |=|  ___  |   |  ___ |=|   |   |  ___  |=|=| |   | ___ |=|  ___  |   |  ___ |=|   |   | ___ |=|=| |   |   ",  # Row 2
        "  |[ ]| |=| |   | |[ ]| |   ||=|   |[ ]| |   | |=|=| |[ ]||   ||=| |   | |[ ]| |   ||=|   |[ ]||   ||=|=| |[ ]|   ",  # Row 3
        "  |[ ]| |=| |[ ]| |[ ]| |[ ]||=|   |[ ]| |[ ]| |=|=| |[ ]||[ ]||=| |[ ]| |[ ]| |[ ]||=|   |[ ]||[ ]||=|=| |[ ]|   ",  # Row 4
        "  |[ ]| |=| |[ ]| |[ ]| |[ ]||=|   |[ ]| |[ ]| |=|=| |[ ]||[ ]||=| |[ ]| |[ ]| |[ ]||=|   |[ ]||[ ]||=|=| |[ ]|   ",  # Row 5
        "  |[ ]| |=| |[ ]| |[ ]| |[ ]||=|   |[ ]| |[ ]| |=|=| |[ ]||[ ]||=| |[ ]| |[ ]| |[ ]||=|   |[ ]||[ ]||=|=| |[ ]|   ",  # Row 6
        "  |[ ]| |=| |[ ]| |[ ]| |[ ]||=|   |[ ]| |[ ]| |=|=| |[ ]||[ ]||=| |[ ]| |[ ]| |[ ]||=|   |[ ]||[ ]||=|=| |[ ]|   ",  # Row 7
        "  |___| |=| |___| |___| |___||=|   |___| |___| |=|=| |___||___||=| |___| |___| |___||=|   |___||___||=|=| |___|   ",  # Row 8
        "        |=|              |   ||=|              |=|=|      |   ||=|              |   ||=|        |  ||=|=|         ",  # Row 9
        "        |=|              |[ ]||=|              |=|=|      |[ ]||=|              |[ ]||=|        |[ ]||=|=|         ",  # Row 10
        "        |=|              |[ ]||=|              |=|=|      |[ ]||=|              |[ ]||=|        |[ ]||=|=|         ",  # Row 11
        "        |=|              |___||=|              |___|      |___||=|              |___||=|        |___||___|         ",  # Row 12
        "        |_|                  |_|                              |_|                  |_|                            ",  # Row 13
    ]

    # Building wireframe - 2X TALL, 2X WIDE with mixed window sizes, two doors with stoops
    BUILDING = [
        "                        _____                                  ",
        "       __O__           |     |                  __O__          ",
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
        "            |[####]|                    |[####]|                ",
        "            |[####]|                    |[####]|                ",
        "            |      |                    |      |                ",
        "            | [==] |                    | [==] |                ",
        "____________|______|____________________|______|________________",
        "      ______======______          ______======______            ",
    ]

    # Second building (right side) - 2X TALL, 2X WIDE with two doors with stoops
    BUILDING2 = [
        "              _____                                  ___   ",
        "             |     |     __O__              __O__   |   |  ",
        "      [===]  |     |    / === \\            / === \\  |   |  ",
        "      [===]  |_____|   (==//\\==)          (==//\\==) |___|  ",
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
        "            |[####]|                    |[####]|            ",
        "            |[####]|                    |[####]|            ",
        "            |      |                    |      |            ",
        "            | [==] |                    | [==] |            ",
        "____________|______|____________________|______|____________",
        "      ______======______          ______======______        ",
    ]

    # Window positions for people animation (relative to building sprite)
    # Each entry is (row_offset, col_offset) for the middle of a window
    BUILDING_WINDOW_POSITIONS = [
        (8, 7), (8, 22), (8, 30), (8, 44),      # First row (row 8 is middle of window)
        (14, 7), (14, 22), (14, 30), (14, 44),  # Second row
        (20, 7), (20, 22), (20, 30), (20, 44),  # Third row
        (26, 7), (26, 22), (26, 30), (26, 44),  # Fourth row
        (32, 7), (32, 22), (32, 30), (32, 44),  # Fifth row
    ]
    BUILDING2_WINDOW_POSITIONS = [
        (8, 9), (8, 24), (8, 38), (8, 52),      # First row
        (14, 9), (14, 24), (14, 38), (14, 52),  # Second row
        (20, 9), (20, 24), (20, 38), (20, 52),  # Third row
        (26, 9), (26, 24), (26, 38), (26, 52),  # Fourth row
        (32, 9), (32, 24), (32, 38), (32, 52),  # Fifth row
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
        # Close-up car (perspective effect - shrinks as it passes)
        self._closeup_car: Dict = None
        self._closeup_car_timer = 0
        # Pedestrians on the street
        self._pedestrians: List[Dict] = []
        self._pedestrian_spawn_timer = 0
        # Street light flicker effect
        self._street_light_positions: List[Tuple[int, int]] = []
        self._street_light_flicker = [1.0, 1.0]  # Brightness per light (0-1)
        self._flicker_timer = 0
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
        # Manholes and drains with occasional steam
        self._manhole_positions: List[Tuple[int, int]] = []  # (x, y)
        self._drain_positions: List[Tuple[int, int]] = []  # (x, y)
        self._steam_effects: List[Dict] = []  # {x, y, frame, timer, duration}
        self._steam_spawn_timer = 0
        # Windy city weather - debris, leaves, wind wisps
        self._debris: List[Dict] = []  # {x, y, char, type, speed}
        self._leaves: List[Dict] = []  # {x, y, char, speed, wobble}
        self._wind_wisps: List[Dict] = []  # {x, y, chars, speed}
        self._debris_spawn_timer = 0
        self._wind_wisp_timer = 0
        self._tree_positions: List[Tuple[int, int]] = []  # (x, y) for trees
        self._tree_sway_frame = 0
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
        self._qte_wave = 0  # Current wave of meteors
        self._qte_total_waves = 5  # Total waves per event
        self._qte_pending_keys: List[str] = []  # Keys player needs to press
        # Skyline buildings with animated window lights
        self._skyline_windows: List[Dict] = []  # {x, y, on, timer, toggle_time}
        self._skyline_buildings: List[Dict] = []  # {x, y, width, height, windows}
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
                     '  ~~           ~~  '],
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

        # Create smaller main clouds - move slower
        num_clouds = max(2, self.width // 50)
        for i in range(num_clouds):
            # Main cloud body - slow
            self._clouds.append({
                'x': random.uniform(0, self.width),
                'y': random.randint(3, 6),  # Upper area
                'speed': random.uniform(0.03, 0.08),  # Slow movement for small clouds
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
                    'speed': random.uniform(0.02, 0.05),  # Slowest for wisps
                    'type': 'wisp',
                    'char': random.choice(['~', '≈', '-', '.']),
                    'length': random.randint(3, 8),
                })

    def _update_clouds(self):
        """Update cloud positions - drift in wind direction."""
        for cloud in self._clouds:
            # Clouds move in wind direction (closer/lower clouds can vary slightly)
            # Cumulus clouds (closer) may have slight delay in direction change for dynamic look
            cloud['x'] += cloud['speed'] * self._wind_direction

            # Wrap around based on wind direction
            if cloud['type'] in ['main', 'cumulus']:
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

    def _update_wind(self):
        """Update windy city weather - debris, leaves, and wind wisps."""
        curb_y = self.height - 4
        street_y = self.height - 3

        # Update wind direction timer - change direction every 3-15 minutes
        self._wind_direction_timer += 1
        if self._wind_direction_timer >= self._wind_direction_change_interval:
            self._wind_direction_timer = 0
            self._wind_direction *= -1  # Flip direction
            self._wind_direction_change_interval = random.randint(10800, 54000)  # 3-15 min at ~60fps

        # Update tree sway animation
        self._tree_sway_frame = (self._tree_sway_frame + 1) % 20

        # Spawn debris (newspapers, trash) on streets - spawn from upwind side
        self._debris_spawn_timer += 1
        if self._debris_spawn_timer >= random.randint(15, 40):
            self._debris_spawn_timer = 0
            if len(self._debris) < 8:
                debris_type = random.choice(['newspaper', 'trash'])
                chars = self.DEBRIS_NEWSPAPER if debris_type == 'newspaper' else self.DEBRIS_TRASH
                # Spawn from upwind side
                if self._wind_direction > 0:
                    spawn_x = -5.0  # Wind blowing right, spawn from left
                else:
                    spawn_x = float(self.width + 5)  # Wind blowing left, spawn from right
                self._debris.append({
                    'x': spawn_x,
                    'y': float(random.choice([curb_y, street_y, street_y - 1])),
                    'char': random.choice(chars),
                    'type': debris_type,
                    'speed': random.uniform(0.8, 2.0),
                    'wobble': random.uniform(0, 6.28),
                })

        # Spawn wind wisps in sky - spawn from upwind side
        self._wind_wisp_timer += 1
        if self._wind_wisp_timer >= random.randint(30, 60):
            self._wind_wisp_timer = 0
            if len(self._wind_wisps) < 5:
                wisp_length = random.randint(3, 8)
                wisp_chars = ''.join([random.choice(self.WIND_WISPS) for _ in range(wisp_length)])
                if self._wind_direction > 0:
                    spawn_x = -5.0  # Wind blowing right
                else:
                    spawn_x = float(self.width + 5)  # Wind blowing left
                self._wind_wisps.append({
                    'x': spawn_x,
                    'y': float(random.randint(3, self.height // 3)),
                    'chars': wisp_chars,
                    'speed': random.uniform(1.0, 2.5),
                })

        # Spawn leaves from trees
        for tree_x, tree_y in self._tree_positions:
            if random.random() < 0.03:  # 3% chance per tree per frame
                if len(self._leaves) < 15:
                    self._leaves.append({
                        'x': float(tree_x + random.randint(2, 7)),
                        'y': float(tree_y + random.randint(0, 3)),
                        'char': random.choice(self.DEBRIS_LEAVES),
                        'speed': random.uniform(0.5, 1.5),
                        'fall_speed': random.uniform(0.1, 0.3),
                        'wobble': random.uniform(0, 6.28),
                    })

        # Update debris positions - move in wind direction
        new_debris = []
        for d in self._debris:
            d['x'] += d['speed'] * self._wind_direction  # Blow in wind direction
            d['wobble'] += 0.3
            d['y'] += math.sin(d['wobble']) * 0.2  # Wobble up/down
            # Keep on screen
            if -10 < d['x'] < self.width + 10:
                new_debris.append(d)
        self._debris = new_debris

        # Update wind wisps - move in wind direction
        new_wisps = []
        for w in self._wind_wisps:
            w['x'] += w['speed'] * self._wind_direction
            if -len(w['chars']) - 5 < w['x'] < self.width + 10:
                new_wisps.append(w)
        self._wind_wisps = new_wisps

        # Update leaves - blow in wind direction
        new_leaves = []
        for leaf in self._leaves:
            leaf['x'] += leaf['speed'] * self._wind_direction  # Blow in wind direction
            leaf['y'] += leaf['fall_speed']  # Fall down
            leaf['wobble'] += 0.2
            leaf['x'] += math.sin(leaf['wobble']) * 0.3  # Wobble
            # Keep if on screen and above street
            if -5 < leaf['x'] < self.width + 5 and leaf['y'] < street_y + 2:
                new_leaves.append(leaf)
        self._leaves = new_leaves

    def _update_qte(self):
        """Update meteor QTE event - quick time event."""
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
            return

        self._qte_timer += 1

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

            # Check wave completion
            active_meteors = [m for m in self._qte_meteors if m['called']]
            uncalled_meteors = [m for m in self._qte_meteors if not m['called']]
            if len(active_meteors) == 0 and len(uncalled_meteors) == 0 and len(self._qte_missiles) == 0:
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

        for window in self._skyline_windows:
            if not window['animated']:
                continue

            window['timer'] += 1
            if window['timer'] >= window['toggle_time']:
                window['timer'] = 0
                window['on'] = not window['on']
                # Update the scene with new window state (only if in visible region)
                px, py = window['x'], window['y']
                if vis_left <= px <= vis_right and 0 <= py < self.height:
                    if window['on']:
                        self.scene[py][px] = ('▪', Colors.RAT_YELLOW)
                    else:
                        self.scene[py][px] = ('▫', Colors.ALLEY_DARK)

    def _render_clouds(self, screen):
        """Render cloud layer."""
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

        # Calculate building positions first for overlap avoidance
        self._building_x = 9
        building1_right = self._building_x + len(self.BUILDING[0])
        self._building2_x = self.width - len(self.BUILDING2[0]) - 11 if self.width > 60 else self.width

        # Calculate cafe position early for overlap avoidance
        gap_center = (building1_right + self._building2_x) // 2
        cafe_width = len(self.CAFE[0])
        cafe_left = gap_center - cafe_width // 2 - 11
        cafe_right = cafe_left + cafe_width

        # Draw distant buildings FIRST (furthest back) - only in gap between buildings
        self._draw_distant_buildings(gap_center, ground_y, building1_right, self._building2_x)

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

        # Draw second building on the right side
        # Shifted 6 chars toward center (left)
        # Uses grey blocks on bottom half story, red bricks on upper portions
        if self.width > 60:
            self._building2_x = self.width - len(self.BUILDING2[0]) - 11
            self._building2_y = ground_y - len(self.BUILDING2) + 1
            self._draw_building(self.BUILDING2, self._building2_x, max(1, self._building2_y))

        # Draw street lights between buildings (in the gap)
        self._draw_street_lights(ground_y)

        # Draw curb/sidewalk - store positions for front-layer rendering
        self._sidewalk_positions = []
        for x in range(self.width - 1):
            # Store sidewalk position for rendering on top of scene (but behind sprites)
            self._sidewalk_positions.append((x, curb_y, '▄', Colors.ALLEY_MID))

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

        # Place trees - spread across the gap between buildings
        self._tree_positions = []
        tree_height = len(self.TREE)
        tree_width = len(self.TREE[0])
        building2_left = self._building2_x if self._building2_x > 0 else self.width
        gap_width = building2_left - building1_right

        # Tree 1: left side of gap
        tree1_x = building1_right + 8
        # Tree 2: middle-right of gap
        tree2_x = building1_right + gap_width // 2 + 20
        # Tree 3: right side of gap (before building 2)
        tree3_x = building2_left - tree_width - 12

        for tree_x in [tree1_x, tree2_x, tree3_x]:
            # Check tree fits in gap and doesn't overlap with cafe
            cafe_left = getattr(self, 'cafe_x', 0)
            cafe_right = cafe_left + len(self.CAFE[0]) if hasattr(self, 'cafe_x') else 0
            overlaps_cafe = cafe_left - 5 < tree_x < cafe_right + 5

            if tree_x > building1_right + 2 and tree_x + tree_width < building2_left - 2 and not overlaps_cafe:
                tree_y = ground_y - tree_height + 1
                self._tree_positions.append((tree_x, tree_y))
                self._draw_tree(tree_x, tree_y)

        # Place dumpster to the LEFT of building 1 (above curb)
        self.dumpster_x = 2
        self.dumpster_y = ground_y - len(self.DUMPSTER) + 1
        self._draw_sprite(self.DUMPSTER, self.dumpster_x, self.dumpster_y, Colors.ALLEY_MID)

        # Place box in front of left building
        building1_right = self._building_x + len(self.BUILDING[0])
        building2_left = self._building2_x if self._building2_x > 0 else self.width
        gap_center = (building1_right + building2_left) // 2
        self.box_x = self._building_x + 5  # In front of left building
        self.box_y = ground_y - len(self.BOX) + 1
        self._draw_box_with_label(self.box_x, self.box_y)

        # Place blue mailbox near building 1 (shifted 2 chars left)
        self.mailbox_x = self._building_x + len(self.BUILDING[0]) + 1
        self.mailbox_y = ground_y - len(self.MAILBOX) + 1
        self._draw_sprite(self.MAILBOX, self.mailbox_x, self.mailbox_y, Colors.ALLEY_BLUE)

        # Calculate cafe position first (shifted 11 chars left)
        self.cafe_x = gap_center - len(self.CAFE[0]) // 2 - 18  # 4 more left (was -14)
        self.cafe_y = ground_y - len(self.CAFE) + 1

        # Place well-lit Cafe between buildings (center of gap)
        self._draw_cafe(self.cafe_x, self.cafe_y)

        # Draw crosswalk between cafe and right building
        cafe_right = self.cafe_x + len(self.CAFE[0])
        self._crosswalk_x = cafe_right + 1
        self._crosswalk_width = 32  # Store for car occlusion
        self._draw_crosswalk(self._crosswalk_x, curb_y, street_y)

        # Draw street sign near crosswalk (shifted 12 chars right)
        sign_x = self._crosswalk_x + self._crosswalk_width // 2 - len(self.STREET_SIGN[0]) // 2 + 12
        sign_y = ground_y - len(self.STREET_SIGN) + 1
        self._draw_street_sign(sign_x, sign_y)

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
        """Draw building street numbers near doorways."""
        # Building 1 numbers - "1742" and "1744" for the two doors
        # Find door positions in BUILDING sprite
        door_row = len(self.BUILDING) - 7  # Row with doors
        # Draw numbers above doors
        number1_x = self._building_x + 14  # Above first door
        number2_x = self._building_x + 42  # Above second door
        number_y = self._building_y + door_row - 1

        # Building 1 - odd side (1741, 1743)
        numbers1 = "1741"
        numbers2 = "1743"
        for i, char in enumerate(numbers1):
            px = number1_x + i
            if 0 <= px < self.width - 1 and 0 <= number_y < self.height:
                self.scene[number_y][px] = (char, Colors.ALLEY_LIGHT)
        for i, char in enumerate(numbers2):
            px = number2_x + i
            if 0 <= px < self.width - 1 and 0 <= number_y < self.height:
                self.scene[number_y][px] = (char, Colors.ALLEY_LIGHT)

        # Building 2 numbers - even side (1742, 1744)
        if self._building2_x > 0:
            number3_x = self._building2_x + 14
            number4_x = self._building2_x + 42
            number_y2 = self._building2_y + door_row - 1
            numbers3 = "1742"
            numbers4 = "1744"
            for i, char in enumerate(numbers3):
                px = number3_x + i
                if 0 <= px < self.width - 1 and 0 <= number_y2 < self.height:
                    self.scene[number_y2][px] = (char, Colors.ALLEY_LIGHT)
            for i, char in enumerate(numbers4):
                px = number4_x + i
                if 0 <= px < self.width - 1 and 0 <= number_y2 < self.height:
                    self.scene[number_y2][px] = (char, Colors.ALLEY_LIGHT)

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
        """Draw solid double-line cloud cover at top of screen."""
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

    def _draw_distant_buildings(self, center_x: int, ground_y: int, left_boundary: int, right_boundary: int):
        """Draw static cityscape backdrop in the gap between main buildings."""
        # Initialize skyline windows list
        self._skyline_windows = []
        self._skyline_buildings = []

        # Store visibility bounds
        self._skyline_visible_left = left_boundary + 1
        self._skyline_visible_right = right_boundary - 1

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
            if py < 2 or py >= self.height:
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
                elif char in '|_/\\':
                    # Building structure
                    color = Colors.ALLEY_DARK
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
            tree_sprite = self.TREE_WINDY_RIGHT  # Wind blowing right
        else:
            tree_sprite = self.TREE_WINDY_LEFT  # Wind blowing left
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
                        # Use neutral colors for cafe structure, warm for interior
                        if char in 'SHELLCAFE' or char in 'OPEN':
                            color = Colors.ALLEY_LIGHT  # Text - neutral white
                        elif char in '[]=' or char == '~':
                            color = Colors.ALLEY_MID  # Windows - gray, no glow
                        elif char == 'O' and inside_cafe:
                            color = Colors.ALLEY_DARK  # People silhouettes - dark
                        elif char in '/\\':
                            color = Colors.ALLEY_DARK  # People arms - dark
                        elif char == '|':
                            color = Colors.ALLEY_MID  # Walls - gray
                        elif char in '_.-':
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

    def _spawn_car(self):
        """Spawn a new car on the street."""
        # Randomly choose direction
        if random.random() < 0.5:
            # Car going right (spawn on left)
            self._cars.append({
                'x': -8.0,
                'direction': 1,
                'speed': random.uniform(0.8, 1.5),
                'sprite': self.CAR_RIGHT,
            })
        else:
            # Car going left (spawn on right)
            self._cars.append({
                'x': float(self.width + 2),
                'direction': -1,
                'speed': random.uniform(0.8, 1.5),
                'sprite': self.CAR_LEFT,
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

        # Update street light flicker
        self._update_street_light_flicker()

        # Update window people
        self._update_window_people()

        # Update cafe people in Shell Cafe
        self._update_cafe_people()

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

        # Update skyline window lights
        self._update_skyline_windows()

        # Update meteor damage overlays
        self._update_damage_overlays()

    def _update_cars(self):
        """Update car positions and spawn new cars."""
        # Spawn new cars occasionally
        self._car_spawn_timer += 1
        if self._car_spawn_timer >= random.randint(40, 100):
            if len(self._cars) < 3:  # Max 3 cars at once
                self._spawn_car()
            self._car_spawn_timer = 0

        # Update car positions
        new_cars = []
        for car in self._cars:
            car['x'] += car['direction'] * car['speed']

            # Keep car if it's still on screen (with margin)
            if -10 < car['x'] < self.width + 10:
                new_cars.append(car)

        self._cars = new_cars

    def _update_closeup_car(self):
        """Update close-up car perspective effect (stays in place, grows then shrinks)."""
        # Spawn new close-up car occasionally
        self._closeup_car_timer += 1
        if self._closeup_car is None and self._closeup_car_timer >= random.randint(200, 400):
            self._closeup_car_timer = 0
            # Calculate position between right street light and traffic light
            building1_right = self._building_x + len(self.BUILDING[0]) if hasattr(self, '_building_x') else 70
            building2_left = self._building2_x if hasattr(self, '_building2_x') else self.width - 60
            gap_center = (building1_right + building2_left) // 2
            # Right street light is at gap_center + 38
            # Traffic light is at box_x + BOX width + 100
            street_light_x = gap_center + 38
            traffic_light_x = self.box_x + len(self.BOX[0]) + 100 if hasattr(self, 'box_x') else self.width - 20
            # Position car between street light and traffic light
            car_x = (street_light_x + traffic_light_x) // 2
            self._closeup_car = {
                'x': float(car_x),
                'direction': random.choice([-1, 1]),  # Face left or right
                'scale': 0.5,  # Start small
                'phase': 0,    # 0=growing, 1=shrinking
                'scale_speed': 0.15,  # Faster grow/shrink
            }

        # Update close-up car
        if self._closeup_car:
            car = self._closeup_car
            # Car stays in place, only scale changes
            if car['phase'] == 0:
                # Growing phase
                car['scale'] += car['scale_speed']
                if car['scale'] >= 3.0:
                    car['scale'] = 3.0
                    car['phase'] = 1  # Switch to shrinking
            else:
                # Shrinking phase
                car['scale'] -= car['scale_speed']
                if car['scale'] <= 0.5:
                    self._closeup_car = None  # Done, remove car

    def _spawn_pedestrian(self):
        """Spawn a new pedestrian on the sidewalk with random accessories."""
        # Randomly choose person type (basic, hat, briefcase, skirt)
        person_type_idx = random.randint(0, len(self.PERSON_TYPES_RIGHT) - 1)

        # Randomly choose direction
        if random.random() < 0.5:
            # Pedestrian going right (spawn on left)
            self._pedestrians.append({
                'x': -5.0,
                'direction': 1,
                'speed': random.uniform(0.3, 0.6),  # Slower than cars
                'frames': self.PERSON_TYPES_RIGHT[person_type_idx],
                'frame_idx': 0,
                'frame_timer': 0,
            })
        else:
            # Pedestrian going left (spawn on right)
            self._pedestrians.append({
                'x': float(self.width + 2),
                'direction': -1,
                'speed': random.uniform(0.3, 0.6),
                'frames': self.PERSON_TYPES_LEFT[person_type_idx],
                'frame_idx': 0,
                'frame_timer': 0,
            })

    def _update_pedestrians(self):
        """Update pedestrian positions and spawn new pedestrians."""
        # Check if meteor event is active - pedestrians should panic
        meteor_active = self._qte_active and self._qte_state == 'active'

        # Spawn new pedestrians frequently
        self._pedestrian_spawn_timer += 1
        spawn_interval = random.randint(8, 25)  # Spawn faster for more people
        if self._pedestrian_spawn_timer >= spawn_interval:
            max_peds = 6 if meteor_active else 18  # Fewer during meteor (they're running away)
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
                ped['frame_timer'] += 1
                if ped['frame_timer'] >= 3:  # Normal arm swing
                    ped['frame_timer'] = 0
                    ped['frame_idx'] = (ped['frame_idx'] + 1) % len(ped['frames'])

            ped['x'] += ped['direction'] * ped['speed']

            # Keep pedestrian if still on screen (with margin)
            if -10 < ped['x'] < self.width + 10:
                new_pedestrians.append(ped)

        self._pedestrians = new_pedestrians

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
        """Draw vanishing street with ==== line across (no crosswalk stripes)."""
        crosswalk_width = 32

        # Draw "====" line across the street instead of crosswalk stripes
        for cx in range(crosswalk_width):
            px = x + cx
            if 0 <= px < self.width - 1:
                if street_y < self.height:
                    self.scene[street_y][px] = ('=', Colors.RAT_YELLOW)

        # Draw vanishing street effect above
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
        Door knobs rendered in gold.
        """
        total_rows = len(sprite)
        # Grey block section: bottom 11 rows (half story with door, one row lower)
        grey_start_row = total_rows - 7  # 4 less grey (was -11), 4 more brick
        # Brick character for even texture
        brick_char = '▓'

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

        for row_idx, row in enumerate(sprite):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height:
                    # Row 0 is rooftop items (satellite dishes, antennas) - grey
                    if row_idx == 0 and char != ' ':
                        self.scene[py][px] = (char, Colors.GREY_BLOCK)
                        continue

                    # Check if inside a window
                    inside_window = is_inside_window(row, col_idx)

                    if char != ' ':
                        # Determine color based on character and position
                        if char in '[]=' or (char == '-' and row_idx == 1):
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
                        # Fill window interior with dark background (prevents seeing through to distant buildings)
                        if inside_window:
                            self.scene[py][px] = (' ', Colors.ALLEY_DARK)
                            # Store window interior position for layering
                            self._window_interior_positions.append((px, py))
                            continue

                        if row_idx >= 4 and row_idx < grey_start_row:
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

    def render(self, screen):
        """Render the alley scene to the screen with proper layering."""
        # Render clouds first (behind everything)
        self._render_clouds(screen)

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

        # Render window people silhouettes (behind window frames)
        self._render_window_people(screen)

        # Render cafe people in Shell Cafe lower window
        self._render_cafe_people(screen)

        # Render window frames on top of window people (so people appear inside)
        self._render_window_frames(screen)

        # Render sidewalk/curb on top of scene but behind all sprites
        self._render_sidewalk(screen)

        # Render street light flicker effects
        self._render_street_light_flicker(screen)

        # Render steam effects from manholes/drains
        self._render_steam(screen)

        # Render meteor damage overlays
        self._render_damage_overlays(screen)

        # Render wind effects (debris, leaves, wisps)
        self._render_wind(screen)

        # Render pedestrians on the sidewalk
        self._render_pedestrians(screen)

        # Render Woman in Red event (on top of regular pedestrians)
        self._render_woman_red(screen)

        # Render traffic light (dynamic - lights change)
        self._render_traffic_light(screen)

        # Render close-up car (perspective effect)
        self._render_closeup_car(screen)

        # Render horizontal cars on the street LAST (on top of everything)
        self._render_cars(screen)

        # Render QTE event (meteors, missiles, explosions, NPC) on top of everything
        self._render_qte(screen)

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
        """Render meteor damage overlays on the scene."""
        for overlay in self._damage_overlays:
            px = overlay['x']
            py = overlay['y']
            if 0 <= px < self.width - 1 and 0 <= py < self.height:
                try:
                    # Damage fades from bright to dim as timer increases
                    fade_progress = overlay['timer'] / overlay['fade_time']
                    if fade_progress < 0.3:
                        # Fresh damage - bright red/orange
                        attr = curses.color_pair(Colors.BRICK_RED)
                    elif fade_progress < 0.6:
                        # Aging damage - dim
                        attr = curses.color_pair(Colors.ALLEY_MID) | curses.A_DIM
                    else:
                        # Old damage - very dim
                        attr = curses.color_pair(Colors.ALLEY_DARK) | curses.A_DIM
                    screen.attron(attr)
                    screen.addstr(py, px, overlay['char'])
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_wind(self, screen):
        """Render wind effects - debris, leaves, and wisps."""
        # Render debris (newspapers, trash) on streets
        for d in self._debris:
            px = int(d['x'])
            py = int(d['y'])
            if 0 <= px < self.width - 1 and 0 <= py < self.height:
                try:
                    if d['type'] == 'newspaper':
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

    def _render_qte(self, screen):
        """Render the meteor QTE event - meteors, missiles, explosions, NPC."""
        if not self._qte_active:
            return

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
            # Draw Woman waving
            wave_frame = (self._woman_red_timer // 10) % len(self.WOMAN_RED_WAVE_FRAMES)
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
        """Render cars on the street."""
        # Cars are 2 rows tall, bottom row at street level
        street_y = self.height - 1
        # Cars can't render above the 1/5th line
        min_car_y = self.height // 5

        for car in self._cars:
            x = int(car['x'])
            sprite = car['sprite']
            sprite_height = len(sprite)

            for row_idx, row in enumerate(sprite):
                for col_idx, char in enumerate(row):
                    px = x + col_idx
                    # Position sprite so bottom row is at street level
                    py = street_y - (sprite_height - 1 - row_idx)

                    # Don't render cars above the 1/5th line
                    if 0 <= px < self.width - 1 and min_car_y <= py < self.height and char != ' ':
                        try:
                            # Cars are white/bright
                            attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_BOLD
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_pedestrians(self, screen):
        """Render pedestrians on the sidewalk (curb level) with arm animation."""
        # Pedestrians walk on the curb/sidewalk area (moved up 2 rows)
        curb_y = self.height - 4

        for ped in self._pedestrians:
            x = int(ped['x'])
            # Get current animation frame
            frames = ped.get('frames', [])
            frame_idx = ped.get('frame_idx', 0)
            if frames and frame_idx < len(frames):
                sprite = frames[frame_idx]
            else:
                continue

            sprite_height = len(sprite)

            for row_idx, row in enumerate(sprite):
                for col_idx, char in enumerate(row):
                    px = x + col_idx
                    # Position sprite so bottom row is at curb level
                    py = curb_y - (sprite_height - 1 - row_idx)

                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        try:
                            # Pedestrians in muted color
                            attr = curses.color_pair(Colors.ALLEY_MID)
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
                    " (__)  (__)  (__)",
                ]
            else:
                sprite = [
                    ".============.  ",
                    "/              \\",
                    "|  [O]      [O]  |",
                    "|________________|",
                    "(__)  (__)  (__) ",
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
                    " ()  ",
                ]
            else:
                sprite = [
                    ".==. ",
                    "|OO|",
                    " () ",
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
        """Render flickering light effects under street lights."""
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
        """Render the 3 people in Shell Cafe's lower window with animated arms."""
        if not hasattr(self, 'cafe_x') or not hasattr(self, 'cafe_y'):
            return

        # Lower window is at row 14-15 of CAFE sprite (0-indexed)
        # The window content area starts at column 4 and spans ~20 chars
        window_row = 14  # Row with people heads
        body_row = 15    # Row with bodies/arms
        window_start_col = 4  # Start of window content area

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

    def _render_traffic_light(self, screen):
        """Render the traffic light with current light states."""
        # Position traffic light on right side of scene (shifted 20 more chars right)
        light_x = min(self.width - 10, self.box_x + len(self.BOX[0]) + 100)
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
        self._demo_mode = False
        self._demo_event_offset = 0
        self._use_tcp = False  # Flag for Windows TCP mode

        # Build dynamic socket paths based on where daemon might create them
        self._socket_paths = self._build_socket_paths()

        # Try to find working socket
        if not self.socket_path:
            self.socket_path = self._find_socket()

        # Resolve token after finding socket (token might be near socket)
        self._token = self._resolve_token()

        # On Windows, try TCP first (more reliable than Unix sockets)
        if sys.platform == 'win32':
            if self._try_tcp_connection():
                self._connected = True
                self._use_tcp = True
                logger.info(f"Connected to daemon via TCP on port {self.WINDOWS_PORT}")
            else:
                # Fallback to socket test (unlikely to work on Windows)
                self._connected = self._test_connection()
        else:
            # On Unix, try socket first, then TCP as fallback
            self._connected = self._test_connection()
            if not self._connected:
                if self._try_tcp_connection():
                    self._connected = True
                    self._use_tcp = True
                    logger.info(f"Connected to daemon via TCP on port {self.WINDOWS_PORT}")

        if not self._connected:
            self._demo_mode = True
            logger.info("Daemon not available, running in demo mode")

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
        """Resolve API token from environment or file."""
        # Environment variable
        token = os.environ.get('BOUNDARY_API_TOKEN')
        if token:
            return token.strip()

        # Build token file paths based on socket location
        token_paths = []

        # If we found a socket, look for token near it
        if self.socket_path:
            socket_dir = os.path.dirname(self.socket_path)
            parent_dir = os.path.dirname(socket_dir)
            token_paths.append(os.path.join(parent_dir, 'config', 'api_tokens.json'))
            token_paths.append(os.path.join(socket_dir, 'api_tokens.json'))

        # Package root config
        package_root = Path(__file__).parent.parent.parent
        token_paths.append(str(package_root / 'config' / 'api_tokens.json'))

        # Standard locations
        token_paths.extend([
            './config/api_tokens.json',
            os.path.expanduser('~/.boundary-daemon/config/api_tokens.json'),
            os.path.expanduser('~/.agent-os/api_token'),
            '/etc/boundary-daemon/api_token',
        ])

        for path in token_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        content = f.read().strip()
                        if path.endswith('.json'):
                            data = json.loads(content)
                            # Token file format: {"tokens": [{"token": "...", ...}]}
                            if isinstance(data, dict):
                                if 'token' in data:
                                    return data['token']
                                if 'tokens' in data and data['tokens']:
                                    # Get first non-expired token
                                    for tok in data['tokens']:
                                        if isinstance(tok, dict) and 'token' in tok:
                                            return tok['token']
                            elif isinstance(data, list) and data:
                                return data[0].get('token')
                        else:
                            return content
                except (IOError, json.JSONDecodeError) as e:
                    logger.debug(f"Failed to read token from {path}: {e}")
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
        self._demo_mode = not self._connected
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
                        self._demo_mode = False
                        logger.info(f"Connected to daemon at {path}")
                        return True
                    self.socket_path = old_path

        # Try TCP connection (Windows primary, Unix fallback)
        if self._try_tcp_connection():
            self._connected = True
            self._demo_mode = False
            self._use_tcp = True
            logger.info(f"Connected to daemon via TCP {self.WINDOWS_HOST}:{self.WINDOWS_PORT}")
            return True

        return False

    def is_demo_mode(self) -> bool:
        """Check if running in demo mode."""
        return self._demo_mode

    def get_status(self) -> Dict:
        """Get daemon status."""
        if self._demo_mode:
            return self._demo_status()

        response = self._send_request('status')
        if response.get('success'):
            status = response.get('status', {})
            # Map API response to dashboard format
            return {
                'mode': status.get('mode', 'UNKNOWN').upper(),
                'mode_since': datetime.utcnow().isoformat(),
                'uptime': status.get('uptime_seconds', 0),
                'events_today': status.get('events_today', 0),
                'violations': status.get('tripwire_count', 0),
                'tripwire_enabled': True,
                'clock_monitor_enabled': status.get('online', False),
                'network_attestation_enabled': status.get('network_state', 'unknown') != 'isolated',
                'is_frozen': status.get('lockdown_active', False),
            }
        return self._demo_status()

    def get_events(self, limit: int = 20) -> List[DashboardEvent]:
        """Get recent events."""
        if self._demo_mode:
            return self._demo_events(limit)

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
        return self._demo_events(limit)

    def get_alerts(self) -> List[DashboardAlert]:
        """Get active alerts."""
        if self._demo_mode:
            return self._demo_alerts()

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
        return self._demo_alerts()

    def get_sandboxes(self) -> List[SandboxStatus]:
        """Get active sandboxes."""
        if self._demo_mode:
            return self._demo_sandboxes()

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
        return self._demo_sandboxes()

    def get_siem_status(self) -> Dict:
        """Get SIEM shipping status."""
        if self._demo_mode:
            return self._demo_siem()

        response = self._send_request('get_siem_status')
        if response.get('success'):
            return response.get('siem_status', self._demo_siem())
        return self._demo_siem()

    def set_mode(self, mode: str, reason: str = '') -> Tuple[bool, str]:
        """Request mode change."""
        if self._demo_mode:
            return False, "Demo mode - daemon not connected"

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
        if self._demo_mode:
            return True, "Demo mode - alert acknowledged locally"

        response = self._send_request('acknowledge_alert', {'alert_id': alert_id})
        if response.get('success'):
            return True, response.get('message', 'Alert acknowledged')
        return False, response.get('error', 'Failed to acknowledge alert')

    def export_events(self, start_time: Optional[str] = None,
                      end_time: Optional[str] = None) -> List[Dict]:
        """Export events for a time range."""
        if self._demo_mode:
            return [e.__dict__ for e in self._demo_events(100)]

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

    # Demo mode data generators
    def _demo_status(self) -> Dict:
        """Generate demo status."""
        modes = ['TRUSTED', 'RESTRICTED', 'AIRGAP']
        return {
            'mode': modes[int(time.time() / 30) % len(modes)],
            'mode_since': datetime.utcnow().isoformat(),
            'uptime': int(time.time()) % 86400,
            'events_today': 1247 + int(time.time()) % 100,
            'violations': random.randint(0, 2),
            'tripwire_enabled': True,
            'clock_monitor_enabled': True,
            'network_attestation_enabled': True,
            'is_frozen': False,
        }

    def _demo_events(self, limit: int) -> List[DashboardEvent]:
        """Generate demo events with variety."""
        events = []
        base_time = datetime.utcnow()
        self._demo_event_offset = (self._demo_event_offset + 1) % 100

        event_types = [
            ("MODE_CHANGE", "INFO", "Mode transitioned to TRUSTED"),
            ("POLICY_DECISION", "INFO", "Tool request approved: file_read"),
            ("SANDBOX_START", "INFO", "Sandbox sandbox-{:03d} started"),
            ("TOOL_REQUEST", "INFO", "Agent requested network access"),
            ("HEALTH_CHECK", "INFO", "Health check passed"),
            ("API_REQUEST", "INFO", "API request from integration"),
            ("TRIPWIRE", "WARN", "File modification detected: /etc/passwd"),
            ("CLOCK_DRIFT", "WARN", "Clock drift detected: 45s"),
            ("VIOLATION", "ERROR", "Unauthorized tool access attempt"),
            ("PII_DETECTED", "WARN", "PII detected in agent output"),
        ]

        for i in range(min(limit, 15)):
            idx = (i + self._demo_event_offset) % len(event_types)
            etype, sev, details = event_types[idx]
            details = details.format(i) if '{' in details else details
            events.append(DashboardEvent(
                timestamp=(base_time - timedelta(seconds=i*30 + random.randint(0, 10))).isoformat(),
                event_type=etype,
                details=details,
                severity=sev,
            ))

        return events

    def _demo_alerts(self) -> List[DashboardAlert]:
        """Generate demo alerts."""
        alerts = [
            DashboardAlert(
                alert_id="alert-001",
                timestamp=datetime.utcnow().isoformat(),
                severity="HIGH",
                message="Prompt injection attempt detected in agent input",
                status="NEW",
                source="prompt_injection",
            ),
            DashboardAlert(
                alert_id="alert-002",
                timestamp=(datetime.utcnow() - timedelta(hours=1)).isoformat(),
                severity="MEDIUM",
                message="Clock drift warning (150s) - NTP sync recommended",
                status="ACKNOWLEDGED",
                source="clock_monitor",
            ),
        ]
        # Randomly add more alerts
        if random.random() < 0.3:
            alerts.append(DashboardAlert(
                alert_id=f"alert-{random.randint(100, 999)}",
                timestamp=(datetime.utcnow() - timedelta(minutes=random.randint(5, 60))).isoformat(),
                severity=random.choice(["LOW", "MEDIUM", "HIGH"]),
                message=random.choice([
                    "Unusual network activity detected",
                    "Memory usage threshold exceeded",
                    "Configuration file modified",
                    "Authentication failure detected",
                ]),
                status="NEW",
                source="monitor",
            ))
        return alerts

    def _demo_sandboxes(self) -> List[SandboxStatus]:
        """Generate demo sandbox status."""
        sandboxes = [
            SandboxStatus(
                sandbox_id="sandbox-001",
                profile="standard",
                status="running",
                memory_used=256*1024*1024 + random.randint(0, 100*1024*1024),
                memory_limit=1024*1024*1024,
                cpu_percent=25.5 + random.random() * 20,
                uptime=1800 + int(time.time()) % 3600,
            ),
        ]
        if random.random() < 0.5:
            sandboxes.append(SandboxStatus(
                sandbox_id="sandbox-002",
                profile="restricted",
                status="running",
                memory_used=128*1024*1024 + random.randint(0, 50*1024*1024),
                memory_limit=512*1024*1024,
                cpu_percent=10.0 + random.random() * 15,
                uptime=600 + random.randint(0, 600),
            ))
        return sandboxes

    def _demo_siem(self) -> Dict:
        """Generate demo SIEM status."""
        return {
            'connected': True,
            'backend': 'kafka',
            'last_shipped': datetime.utcnow().isoformat(),
            'queue_depth': random.randint(5, 50),
            'events_shipped_today': 5432 + int(time.time()) % 1000,
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
            # Connect snow filter so snow only collects on roofs/sills, not building faces
            self.matrix_rain.set_snow_filter(self.alley_scene.is_valid_snow_position)
            # Connect roof/sill checker so snow on roofs/sills lasts 10x longer
            self.matrix_rain.set_roof_sill_checker(self.alley_scene.is_roof_or_sill)
            # Connect street light glow positions so snow melts faster in warm light
            self.matrix_rain.set_glow_positions(self.alley_scene._street_light_positions)
            # Set quick-melt zones (sidewalk, mailbox, street) so snow melts very fast there
            sidewalk_y = self.height - 4  # curb_y
            street_y = self.height - 3
            mailbox_bounds = (self.alley_scene.mailbox_x, self.alley_scene.mailbox_y,
                              len(self.alley_scene.MAILBOX[0]), len(self.alley_scene.MAILBOX))
            self.matrix_rain.set_quick_melt_zones(sidewalk_y, mailbox_bounds, street_y)
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
                            self.matrix_rain.set_quick_melt_zones(sidewalk_y, mailbox_bounds, street_y)
                        self.matrix_rain.resize(self.width, self.height)
                        if self.alley_rat:
                            self.alley_rat.resize(self.width, self.height)
                            self.alley_rat.set_hiding_spots(self.alley_scene)
                        if self.lurking_shadow:
                            self.lurking_shadow.resize(self.width, self.height)
                    self.matrix_rain.update()

                    # Update alley scene (traffic light)
                    if self.alley_scene:
                        self.alley_scene.update()

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
            if self.alley_rat:
                self.alley_rat.resize(self.width, self.height)
                self.alley_rat.set_hiding_spots(self.alley_scene)
            if self.lurking_shadow:
                self.lurking_shadow.resize(self.width, self.height)
        self.screen.clear()

    def _update_dimensions(self):
        """Update terminal dimensions."""
        self.height, self.width = self.screen.getmaxyx()

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
        elif key == ord('f') or key == ord('F'):
            # Cycle framerate (only in matrix mode)
            if self.matrix_mode:
                self._framerate_index = (self._framerate_index + 1) % len(self._framerate_options)
                # Apply new framerate immediately
                if self.screen:
                    self.screen.timeout(self._framerate_options[self._framerate_index])

    def _draw(self):
        """Draw the dashboard."""
        self.screen.clear()

        # Render moon first (furthest back - behind everything)
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
        header += f"  │  Mode: {self.status.get('mode', 'UNKNOWN')}  │  "
        if self.status.get('is_frozen'):
            header += "⚠ MODE FROZEN  │  "
        header += f"Uptime: {self._format_duration(self.status.get('uptime', 0))}"
        if self.event_filter:
            header += f"  │  Filter: {self.event_filter}"

        # Pad to full width
        header = header.ljust(self.width - 1)

        self.screen.attron(curses.color_pair(Colors.HEADER) | curses.A_BOLD)
        self.screen.addstr(0, 0, header[:self.width-1])
        self.screen.attroff(curses.color_pair(Colors.HEADER) | curses.A_BOLD)

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
        """Draw the status panel."""
        self._draw_box(y, x, width, height, "STATUS")

        row = y + 1
        col = x + 2

        # Connection status
        if self.client.is_demo_mode():
            self._addstr(row, col, "Connection: ", Colors.MUTED)
            self._addstr(row, col + 12, "DEMO MODE", Colors.STATUS_ERROR, bold=True)
            row += 1
            self._addstr(row, col, "(No daemon)", Colors.MUTED)
            row += 1
        else:
            self._addstr(row, col, "Connection: ", Colors.MUTED)
            if self.client._use_tcp:
                conn_text = f"TCP:{self.client.WINDOWS_PORT}"
            else:
                conn_text = "Socket"
            self._addstr(row, col + 12, conn_text, Colors.STATUS_OK)
            row += 1

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
            shortcuts = "[w]Weather [m]Mode [a]Ack [e]Export [r]Refresh [?]Help [q]Quit"
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
        # Add weather shortcut in matrix mode
        if self.matrix_mode:
            shortcuts = "[w]Weather [m]Mode [a]Ack [e]Export [r]Refresh [?]Help [q]Quit"
        else:
            shortcuts = "[m]Mode [a]Ack [e]Export [r]Refresh [/]Search [?]Help [q]Quit"

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
            help_text.insert(6, "  w    Cycle weather (Matrix/Rain/Snow/Sand/Fog)")
            help_text.insert(7, "")

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
                       help="Refresh interval in seconds")
    parser.add_argument("--socket", "-s", type=str,
                       help="Path to daemon socket")
    # Secret Matrix mode - not shown in help
    parser.add_argument("--matrix", action="store_true",
                       help=argparse.SUPPRESS)

    args = parser.parse_args()
    run_dashboard(refresh_interval=args.refresh, socket_path=args.socket,
                  matrix_mode=args.matrix)
