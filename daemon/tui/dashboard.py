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
    FOG_BRIGHT = 30      # Bright fog (white)
    FOG_DIM = 31         # Dim fog (gray)

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
        # Fog (gray/white)
        curses.init_pair(Colors.FOG_BRIGHT, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.FOG_DIM, curses.COLOR_WHITE, curses.COLOR_BLACK)


class WeatherMode(Enum):
    """Weather modes for Matrix-style effects."""
    MATRIX = "matrix"      # Classic green Matrix rain
    RAIN = "rain"          # Blue rain
    SNOW = "snow"          # White/gray snow
    SAND = "sand"          # Brown/yellow sandstorm
    FOG = "fog"            # Gray fog/mist

    @property
    def display_name(self) -> str:
        """Get display name for the weather mode."""
        return {
            WeatherMode.MATRIX: "Matrix",
            WeatherMode.RAIN: "Rain",
            WeatherMode.SNOW: "Snow",
            WeatherMode.SAND: "Sandstorm",
            WeatherMode.FOG: "Fog",
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
        WeatherMode.FOG: [
            " .",  # Layer 0: Thin mist
            " .·",  # Layer 1: Light fog
            ".·:",  # Layer 2: Medium fog
            "·:░",  # Layer 3: Thick fog
            "░▒",  # Layer 4: Dense fog
        ],
    }

    # Weather-specific speed multipliers (relative to base speeds)
    WEATHER_SPEED_MULT = {
        WeatherMode.MATRIX: 1.0,
        WeatherMode.RAIN: 1.2,   # Rain falls fast
        WeatherMode.SNOW: 0.4,   # Base snow speed (modified per-depth below)
        WeatherMode.SAND: 0.15,  # Sand falls very slowly (blows horizontally instead)
        WeatherMode.FOG: 0.15,   # Fog drifts very slowly
    }

    # Snow-specific speeds: big flakes fall FASTER than small ones (opposite of rain)
    SNOW_DEPTH_SPEEDS = [
        0.3,   # Layer 0: Small flakes - slowest
        0.4,   # Layer 1: Small-medium
        0.6,   # Layer 2: Medium
        0.9,   # Layer 3: Big - faster
        1.2,   # Layer 4: Biggest - fastest
    ]

    # Weather-specific length multipliers (sand/snow = short particles)
    WEATHER_LENGTHS = {
        WeatherMode.MATRIX: None,  # Use default DEPTH_LENGTHS
        WeatherMode.RAIN: None,    # Use default DEPTH_LENGTHS
        WeatherMode.SNOW: [(1, 1), (1, 1), (1, 2), (1, 2), (1, 2)],  # Single flakes
        WeatherMode.SAND: [(1, 1), (1, 1), (1, 1), (1, 2), (1, 2)],  # Tiny grains
        WeatherMode.FOG: [(1, 2), (1, 2), (1, 3), (2, 3), (2, 4)],   # Small wisps
    }

    # Weather-specific horizontal movement
    WEATHER_HORIZONTAL = {
        WeatherMode.MATRIX: (0, 0),       # No horizontal movement
        WeatherMode.RAIN: (-0.1, 0.1),    # Slight wind variation
        WeatherMode.SNOW: (-0.4, 0.4),    # Gentle drift both ways
        WeatherMode.SAND: (1.5, 3.0),     # Strong wind blowing right
        WeatherMode.FOG: (-0.2, 0.2),     # Gentle drift
    }

    # Weather-specific color mappings (bright, dim, fade1, fade2)
    WEATHER_COLORS = {
        WeatherMode.MATRIX: (Colors.MATRIX_BRIGHT, Colors.MATRIX_DIM, Colors.MATRIX_FADE1, Colors.MATRIX_FADE2),
        WeatherMode.RAIN: (Colors.RAIN_BRIGHT, Colors.RAIN_DIM, Colors.RAIN_FADE1, Colors.RAIN_FADE2),
        WeatherMode.SNOW: (Colors.SNOW_BRIGHT, Colors.SNOW_DIM, Colors.SNOW_FADE, Colors.SNOW_FADE),
        WeatherMode.SAND: (Colors.SAND_BRIGHT, Colors.SAND_DIM, Colors.SAND_FADE, Colors.SAND_FADE),
        WeatherMode.FOG: (Colors.FOG_BRIGHT, Colors.FOG_DIM, Colors.FOG_DIM, Colors.FOG_DIM),
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
        (2, 5),    # Layer 0: Short streaks
        (4, 8),    # Layer 1: Medium-short
        (8, 14),   # Layer 2: Medium
        (14, 22),  # Layer 3: Long
        (20, 35),  # Layer 4: Very long trails
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

        # Fog-specific state
        self._fog_particles: List[Dict] = []
        if weather_mode == WeatherMode.FOG:
            self._init_fog()

        # Snow-specific state: stuck snowflakes that fade over time
        self._stuck_snow: List[Dict] = []

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
            self._fog_particles = []
            self._stuck_snow = []
            self._snow_gusts = []
            self._sand_gusts = []
            self._init_drops()
            if mode == WeatherMode.FOG:
                self._init_fog()
            if mode == WeatherMode.SNOW:
                self._init_snow_gusts()
            if mode == WeatherMode.SAND:
                self._init_sand_gusts()

    def cycle_weather(self) -> WeatherMode:
        """Cycle to the next weather mode and return the new mode."""
        modes = list(WeatherMode)
        current_idx = modes.index(self.weather_mode)
        next_idx = (current_idx + 1) % len(modes)
        new_mode = modes[next_idx]
        self.set_weather_mode(new_mode)
        return new_mode

    def _init_fog(self):
        """Initialize fog particles in clustered patches."""
        self._fog_particles = []
        # Create fog as clustered patches, not random scatter
        num_patch_centers = max(5, self.width // 20)

        for _ in range(num_patch_centers):
            # Each patch has a center point
            center_x = random.uniform(0, self.width)
            center_y = random.uniform(0, self.height)
            patch_dx = random.uniform(-0.2, 0.2)  # Whole patch drifts together
            patch_dy = random.uniform(-0.05, 0.05)

            # Create particles clustered around the center
            patch_size = random.randint(8, 20)
            for _ in range(patch_size):
                # Particles spread around center with gaussian-like distribution
                offset_x = random.gauss(0, 4)
                offset_y = random.gauss(0, 3)
                self._fog_particles.append({
                    'x': center_x + offset_x,
                    'y': center_y + offset_y,
                    'dx': patch_dx + random.uniform(-0.05, 0.05),  # Slight individual variation
                    'dy': patch_dy + random.uniform(-0.02, 0.02),
                    'char': random.choice(['░', '▒', '▓', '·', '.', ':', '∴']),
                    'opacity': random.uniform(0.4, 1.0),
                    'size': random.choice([1, 1, 1, 2, 2, 3]),  # 1=small, 2=medium, 3=big
                })

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
            # Normal: spawn across width, start above screen
            start_x = random.randint(0, self.width - 1)
            start_y = random.randint(-self.height, 0)

        self.drops.append({
            'x': start_x,
            'y': start_y,
            'speed': random.uniform(speed_min, speed_max) * speed_mult,
            'length': random.randint(len_min, min(len_max, self.height // 2)),
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

        # Update fog particles if in fog mode
        if self.weather_mode == WeatherMode.FOG:
            self._update_fog()

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
        # Limit total stuck snow to prevent memory issues
        if len(self._stuck_snow) < 200:
            self._stuck_snow.append({
                'x': x,
                'y': y,
                'depth': depth,
                'char': char,
                'life': random.randint(40, 120),  # Frames until fully melted
                'max_life': 120,
            })

    def _update_stuck_snow(self):
        """Update stuck snow - slowly fade/melt away."""
        new_stuck = []
        for snow in self._stuck_snow:
            snow['life'] -= 1
            if snow['life'] > 0:
                new_stuck.append(snow)
        self._stuck_snow = new_stuck

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

    def _update_fog(self):
        """Update fog particle positions."""
        for particle in self._fog_particles:
            # Drift slowly
            particle['x'] += particle['dx']
            particle['y'] += particle['dy']

            # Wrap around screen edges
            if particle['x'] < 0:
                particle['x'] = self.width - 1
            elif particle['x'] >= self.width:
                particle['x'] = 0
            if particle['y'] < 0:
                particle['y'] = self.height - 1
            elif particle['y'] >= self.height:
                particle['y'] = 0

            # Slowly change opacity
            particle['opacity'] += random.uniform(-0.05, 0.05)
            particle['opacity'] = max(0.2, min(1.0, particle['opacity']))

            # Occasionally change drift direction
            if random.random() < 0.01:
                particle['dx'] = random.uniform(-0.3, 0.3)
                particle['dy'] = random.uniform(-0.1, 0.1)

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

        # Update fog particles for new dimensions
        if self.weather_mode == WeatherMode.FOG:
            # Keep particles in bounds or reinitialize if size changed significantly
            if abs(width - old_width) > 10 or abs(height - old_height) > 5:
                self._init_fog()
            else:
                for p in self._fog_particles:
                    if p['x'] >= width:
                        p['x'] = width - 1
                    if p['y'] >= height:
                        p['y'] = height - 1

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

        # Render fog particles first (behind everything)
        if self.weather_mode == WeatherMode.FOG:
            self._render_fog(screen)

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

    def _render_fog(self, screen):
        """Render fog particles with size-based rendering."""
        for particle in self._fog_particles:
            try:
                x = int(particle['x'])
                y = int(particle['y'])
                size = particle.get('size', 1)

                if 0 <= x < self.width - 1 and 0 <= y < self.height - 1:
                    # Bigger particles are more prominent
                    if size >= 3 or particle['opacity'] > 0.7:
                        attr = curses.color_pair(Colors.FOG_BRIGHT) | curses.A_BOLD
                    elif size >= 2 or particle['opacity'] > 0.4:
                        attr = curses.color_pair(Colors.FOG_DIM)
                    else:
                        attr = curses.color_pair(Colors.FOG_DIM) | curses.A_DIM

                    screen.attron(attr)
                    # Big particles render as larger characters
                    if size >= 3:
                        char = random.choice(['▓', '█', '▒'])
                    elif size >= 2:
                        char = random.choice(['▒', '░', '▓'])
                    else:
                        char = particle['char']
                    screen.addstr(y, x, char)
                    screen.attroff(attr)
            except curses.error:
                pass

    def _render_char(self, screen, y: int, x: int, char: str, pos: int, depth: int):
        """Render a single character with depth-appropriate styling."""
        # Depth 0 = farthest/dimmest, Depth 4 = nearest/brightest
        # Get weather-appropriate colors
        bright, dim, fade1, fade2 = self._get_weather_colors()

        if depth == 0:
            # Farthest layer - very dim, no head highlight
            if pos < 2:
                attr = curses.color_pair(fade2) | curses.A_DIM
            else:
                # Use fade2 with more dimming for Matrix, just dim for others
                if self.weather_mode == WeatherMode.MATRIX:
                    attr = curses.color_pair(Colors.MATRIX_FADE3) | curses.A_DIM
                else:
                    attr = curses.color_pair(fade2) | curses.A_DIM
        elif depth == 1:
            # Far layer - dim
            if pos == 0:
                attr = curses.color_pair(fade1)
            elif pos < 3:
                attr = curses.color_pair(fade1) | curses.A_DIM
            else:
                attr = curses.color_pair(fade2) | curses.A_DIM
        elif depth == 2:
            # Middle layer - normal
            if pos == 0:
                attr = curses.color_pair(dim) | curses.A_BOLD
            elif pos < 3:
                attr = curses.color_pair(dim)
            elif pos < 6:
                attr = curses.color_pair(fade1) | curses.A_DIM
            else:
                attr = curses.color_pair(fade2) | curses.A_DIM
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
                attr = curses.color_pair(fade2) | curses.A_DIM
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
                attr = curses.color_pair(fade2)

        screen.attron(attr)
        screen.addstr(y, x, char)
        screen.attroff(attr)


class AlleyScene:
    """
    Procedurally generated back alley scene for Matrix background.
    Creates a perspective view of a dark alley with buildings, windows,
    fire escapes, and urban details. Uses ASCII-safe characters for
    better terminal compatibility.
    """

    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height
        self.scene: List[List[Tuple[str, int]]] = []  # (char, color_id)
        self._seed = 42  # Fixed seed for consistent scene
        self._generate_scene()

    def resize(self, width: int, height: int):
        """Regenerate scene for new dimensions."""
        self.width = width
        self.height = height
        self._generate_scene()

    def _generate_scene(self):
        """Generate the alley scene."""
        if self.width <= 0 or self.height <= 0:
            self.scene = []
            return

        # Use fixed seed for deterministic scene (no flickering)
        rng = random.Random(self._seed)

        # Initialize with empty space
        self.scene = [[(' ', Colors.ALLEY_DARK) for _ in range(self.width)]
                      for _ in range(self.height)]

        # Calculate perspective points
        center_x = self.width // 2
        horizon_y = self.height // 3  # Vanishing point
        ground_y = self.height - 1

        # Draw buildings on left side
        self._draw_building_left(0, center_x // 3, horizon_y, ground_y, rng)

        # Draw buildings on right side
        self._draw_building_right(self.width - center_x // 3, self.width, horizon_y, ground_y, rng)

        # Draw alley floor with perspective lines
        self._draw_floor(center_x, horizon_y, ground_y)

        # Add some atmospheric details
        self._add_details(center_x, horizon_y, ground_y, rng)

    def _draw_building_left(self, x_start: int, x_end: int, y_top: int, y_bottom: int, rng):
        """Draw left building with windows and fire escape."""
        if x_end <= x_start:
            return

        for y in range(y_top, min(y_bottom + 1, self.height)):
            # Building edge gets closer to center as we go up (perspective)
            progress = (y - y_top) / max(1, (y_bottom - y_top))
            edge_x = int(x_start + (x_end - x_start) * (0.3 + 0.7 * progress))

            for x in range(x_start, min(edge_x, self.width)):
                if x >= self.width:
                    continue

                # Building wall - use simple ASCII
                if x == edge_x - 1:
                    # Building edge
                    self.scene[y][x] = ('|', Colors.ALLEY_MID)
                elif (y - y_top) % 4 == 0 and x > x_start + 1:
                    # Horizontal lines (floors)
                    self.scene[y][x] = ('-', Colors.ALLEY_DARK)
                elif (y - y_top) % 4 == 2 and (x - x_start) % 6 in [2, 3]:
                    # Windows - use hash for consistency
                    window_lit = ((x * 7 + y * 13) % 10) < 3  # Deterministic "random"
                    if window_lit:
                        # Lit window (blue)
                        self.scene[y][x] = ('#', Colors.ALLEY_BLUE)
                    else:
                        # Dark window
                        self.scene[y][x] = ('[', Colors.ALLEY_DARK)
                elif x == edge_x - 2 and (y - y_top) % 2 == 0:
                    # Fire escape
                    self.scene[y][x] = ('+', Colors.ALLEY_MID)
                else:
                    # Brick texture
                    if (y + x) % 3 == 0:
                        self.scene[y][x] = ('.', Colors.ALLEY_DARK)

    def _draw_building_right(self, x_start: int, x_end: int, y_top: int, y_bottom: int, rng):
        """Draw right building with windows."""
        if x_end <= x_start or x_start >= self.width:
            return

        for y in range(y_top, min(y_bottom + 1, self.height)):
            # Building edge gets closer to center as we go up (perspective)
            progress = (y - y_top) / max(1, (y_bottom - y_top))
            edge_x = int(x_end - (x_end - x_start) * (0.3 + 0.7 * progress))

            for x in range(max(0, edge_x), min(x_end, self.width)):
                if x >= self.width:
                    continue

                # Building wall - use simple ASCII
                if x == edge_x:
                    # Building edge
                    self.scene[y][x] = ('|', Colors.ALLEY_MID)
                elif (y - y_top) % 4 == 0 and x < x_end - 2:
                    # Horizontal lines (floors)
                    self.scene[y][x] = ('-', Colors.ALLEY_DARK)
                elif (y - y_top) % 4 == 2 and (x_end - x) % 5 in [2, 3]:
                    # Windows
                    window_lit = ((x * 11 + y * 17) % 10) < 2  # Deterministic "random"
                    if window_lit:
                        # Lit window (blue)
                        self.scene[y][x] = ('#', Colors.ALLEY_BLUE)
                    else:
                        # Dark window
                        self.scene[y][x] = (']', Colors.ALLEY_DARK)
                elif x == edge_x + 1 and (y - y_top) % 3 == 0:
                    # Pipes
                    self.scene[y][x] = ('I', Colors.ALLEY_MID)
                else:
                    # Brick texture
                    if (y + x) % 4 == 0:
                        self.scene[y][x] = (':', Colors.ALLEY_DARK)

    def _draw_floor(self, center_x: int, horizon_y: int, ground_y: int):
        """Draw alley floor with perspective."""
        for y in range(horizon_y, min(ground_y + 1, self.height)):
            # Width of visible floor increases as we go down
            progress = (y - horizon_y) / max(1, (ground_y - horizon_y))
            floor_half_width = int(progress * (self.width // 4))

            left_x = max(0, center_x - floor_half_width)
            right_x = min(self.width - 1, center_x + floor_half_width)

            for x in range(left_x, right_x + 1):
                if x >= self.width:
                    continue

                # Perspective lines pointing to vanishing point
                dist_from_center = abs(x - center_x)
                if dist_from_center <= 1:
                    # Center line (wet reflection)
                    if y % 2 == 0:
                        self.scene[y][x] = (':', Colors.ALLEY_BLUE)
                elif (x + y) % 7 == 0:
                    # Cobblestone pattern
                    self.scene[y][x] = ('.', Colors.ALLEY_MID)
                elif (x - center_x + y) % 5 == 0:
                    # Perspective lines
                    self.scene[y][x] = ('.', Colors.ALLEY_DARK)

    def _add_details(self, center_x: int, horizon_y: int, ground_y: int, rng):
        """Add urban details like dumpsters, signs, etc."""
        # Dumpster on left side near bottom - simple ASCII box
        dumpster_y = ground_y - 2
        dumpster_x = center_x // 4

        if dumpster_y > horizon_y and dumpster_x + 5 < center_x:
            if dumpster_y < self.height and dumpster_x + 4 < self.width:
                # Dumpster body - simple ASCII
                for dx in range(4):
                    if dumpster_x + dx < self.width:
                        self.scene[dumpster_y][dumpster_x + dx] = ('=', Colors.ALLEY_MID)
                        if dumpster_y + 1 < self.height:
                            self.scene[dumpster_y + 1][dumpster_x + dx] = ('#', Colors.ALLEY_DARK)

        # Neon sign on right building
        sign_y = horizon_y + 2
        sign_x = self.width - self.width // 5

        if sign_y < self.height - 2 and sign_x + 3 < self.width:
            # Simple neon effect
            if sign_x < self.width:
                self.scene[sign_y][sign_x] = ('*', Colors.ALLEY_BLUE)
            if sign_x + 1 < self.width:
                self.scene[sign_y][sign_x + 1] = ('*', Colors.ALLEY_BLUE)

        # Steam vent - deterministic
        if ground_y - 1 < self.height and center_x - 5 >= 0:
            steam_x = center_x - 5
            if steam_x < self.width:
                for dy in range(min(3, ground_y - horizon_y)):
                    y_pos = ground_y - 1 - dy
                    if 0 <= y_pos < self.height:
                        # Deterministic steam pattern
                        if (dy + steam_x) % 2 == 0:
                            self.scene[y_pos][steam_x] = ('~', Colors.ALLEY_MID)

        # Distant vanishing point details
        if horizon_y > 0 and horizon_y < self.height:
            # Hint of street at end of alley
            for dx in range(-2, 3):
                x = center_x + dx
                if 0 <= x < self.width:
                    self.scene[horizon_y][x] = ('=', Colors.ALLEY_BLUE)

    def render(self, screen):
        """Render the alley scene to the screen."""
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

    # Rat animation frames - each frame is a complete 2-row sprite
    RAT_FRAMES = {
        'right': [
            ["~,.,", " `` "],  # Frame 1: running right
            [" ,.,~", "  `` "],  # Frame 2: running right (shifted)
        ],
        'left': [
            [",.,~", " `` "],  # Frame 1: running left
            ["~,., ", "``  "],  # Frame 2: running left (shifted)
        ],
        'idle': [
            ["<O.O>", " vvv "],  # Sitting rat, alert
            ["<o.o>", " vvv "],  # Sitting rat, relaxed
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
            # Spawn near the dumpster (lower left area)
            self.x = float(random.randint(2, max(3, self.width // 4)))
            self.y = float(self.height - random.randint(3, 6))
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
        # Stay in the lower third of the screen, edges
        floor_y = self.height * 2 // 3

        if random.random() < 0.3:
            # Sometimes pause (idle)
            self.target_x = self.x
            self.target_y = self.y
            self.pause_counter = random.randint(10, 30)
            self.speed = 0
            self.direction = 'idle'
        else:
            # Scurry to a new spot
            self.target_x = float(random.randint(1, max(2, self.width // 3)))
            self.target_y = float(random.randint(floor_y, self.height - 2))
            self.speed = random.uniform(0.5, 1.2)

            # Set direction based on movement
            if self.target_x > self.x:
                self.direction = 'right'
            else:
                self.direction = 'left'

    def update(self):
        """Update rat position and animation."""
        if not self.active:
            return

        self.frame_counter += 1

        # Animate every few frames
        if self.frame_counter % 4 == 0:
            frames = self.RAT_FRAMES.get(self.direction, self.RAT_FRAMES['idle'])
            self.frame = (self.frame + 1) % len(frames)

        # Handle pause
        if self.pause_counter > 0:
            self.pause_counter -= 1
            if self.pause_counter == 0:
                self._pick_new_target()
            return

        # Move towards target
        if self.speed > 0:
            dx = self.target_x - self.x
            dy = self.target_y - self.y
            dist = math.sqrt(dx * dx + dy * dy)

            if dist < 0.5:
                # Reached target
                if self._hiding and self.x < 0:
                    # Fully hidden, deactivate
                    self.active = False
                    self.visible = False
                else:
                    self._pick_new_target()
            else:
                # Move towards target
                self.x += (dx / dist) * self.speed
                self.y += (dy / dist) * self.speed

    def render(self, screen):
        """Render the rat."""
        if not self.visible or not self.active:
            return

        frames = self.RAT_FRAMES.get(self.direction, self.RAT_FRAMES['idle'])
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
        # Lurk in the corners/edges of the alley
        positions = []

        # Top corners (in the distance)
        horizon_y = self.height // 3
        positions.append((random.randint(2, 8), horizon_y + random.randint(1, 3)))
        positions.append((self.width - random.randint(4, 10), horizon_y + random.randint(1, 3)))

        # Side edges (behind buildings)
        mid_y = self.height // 2
        positions.append((random.randint(0, 4), mid_y + random.randint(-2, 4)))
        positions.append((self.width - random.randint(2, 6), mid_y + random.randint(-2, 4)))

        # Pick one
        pos = random.choice(positions)
        self.x = max(0, min(pos[0], self.width - 3))
        self.y = max(0, min(pos[1], self.height - 2))

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

        # Test connection - try socket first, then TCP
        self._connected = self._test_connection()

        # On Windows (or if socket fails), try TCP connection
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
            screen.timeout(100)  # 100ms for smooth rain animation
            screen.bkgd(' ', curses.color_pair(Colors.MATRIX_DIM))
            self._update_dimensions()
            self.alley_scene = AlleyScene(self.width, self.height)
            self.matrix_rain = MatrixRain(self.width, self.height)
            # Initialize creatures
            self.alley_rat = AlleyRat(self.width, self.height)
            self.lurking_shadow = LurkingShadow(self.width, self.height)
            # Schedule first lightning strike (5-30 minutes from now)
            self._lightning_next_time = time.time() + random.uniform(300, 1800)
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
                        self.matrix_rain.resize(self.width, self.height)
                        if self.alley_rat:
                            self.alley_rat.resize(self.width, self.height)
                        if self.lurking_shadow:
                            self.lurking_shadow.resize(self.width, self.height)
                    self.matrix_rain.update()

                    # Update creatures based on alert state
                    self._update_creatures()

                    # Check for lightning strike
                    self._update_lightning()

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
            if self.alley_rat:
                self.alley_rat.resize(self.width, self.height)
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

    def _draw(self):
        """Draw the dashboard."""
        self.screen.clear()

        # Render alley scene first (furthest back)
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
        # Show weather mode in matrix mode
        if self.matrix_mode:
            header += f" [{self._current_weather.display_name}]"
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
        # Leave 1 row for header at top
        available_height = self.height - 1
        available_width = self.width

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
