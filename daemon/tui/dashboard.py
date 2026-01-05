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


class MatrixRain:
    """Digital rain effect from The Matrix with depth simulation."""

    # 5 depth layers - each with different character sets (simple=far, complex=near)
    # Layer 0: Farthest - simple dots and lines
    # Layer 4: Nearest - full katakana and symbols
    DEPTH_CHARS = [
        ".-·:;",  # Layer 0: Farthest - minimal
        ".|!:;+-=",  # Layer 1: Simple ASCII
        "0123456789+-*/<>=$#",  # Layer 2: Numbers and symbols
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",  # Layer 3: Alphanumeric
        "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789$#@&",  # Layer 4: Nearest - full
    ]

    # Speed ranges for each depth layer (min, max) - farther = slower, nearer = faster
    DEPTH_SPEEDS = [
        (0.3, 0.5),   # Layer 0: Slowest (farthest)
        (0.5, 0.8),   # Layer 1
        (0.8, 1.2),   # Layer 2: Medium
        (1.2, 1.8),   # Layer 3
        (1.8, 2.5),   # Layer 4: Fastest (nearest)
    ]

    # Tail lengths for each depth (shorter = farther, longer = nearer)
    DEPTH_LENGTHS = [
        (3, 6),    # Layer 0
        (4, 8),    # Layer 1
        (6, 12),   # Layer 2
        (8, 16),   # Layer 3
        (12, 20),  # Layer 4
    ]

    # Distribution of drops across layers (more in middle layers for balance)
    DEPTH_WEIGHTS = [0.10, 0.15, 0.30, 0.25, 0.20]

    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height
        self.drops: List[Dict] = []
        self._target_drops = max(8, width * 3 // 20)  # 50% more rain!
        self._init_drops()

        # Flicker state
        self._frame_count = 0
        self._global_flicker = 0.0  # 0-1 intensity of global flicker
        self._intermittent_flicker = False  # Major flicker event active

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
        len_min, len_max = self.DEPTH_LENGTHS[depth]

        self.drops.append({
            'x': random.randint(0, self.width - 1),
            'y': random.randint(-self.height, 0),
            'speed': random.uniform(speed_min, speed_max),
            'length': random.randint(len_min, min(len_max, self.height // 2)),
            'char_offset': random.randint(0, len(self.DEPTH_CHARS[depth]) - 1),
            'depth': depth,
            'phase': 0.0,
        })

    def update(self):
        """Update rain drop positions and flicker state."""
        self._frame_count += 1

        # Update flicker states
        # Rapid low-level flicker - subtle constant shimmer (sine wave oscillation)
        self._global_flicker = 0.15 + 0.1 * math.sin(self._frame_count * 0.3)

        # Intermittent major flicker - brief stutter every few seconds (2-8% chance per frame)
        if random.random() < 0.003:
            self._intermittent_flicker = True
        elif self._intermittent_flicker and random.random() < 0.3:
            self._intermittent_flicker = False

        new_drops = []
        for drop in self.drops:
            drop['phase'] += drop['speed']
            drop['y'] = int(drop['phase'])

            # Roll through characters as the drop falls (faster roll for nearer drops)
            roll_speed = 1 + drop['depth']  # Layers 0-4 roll at speeds 1-5
            drop['char_offset'] = (drop['char_offset'] + roll_speed) % len(self.DEPTH_CHARS[drop['depth']])

            # Keep drop if still on screen
            if drop['y'] - drop['length'] < self.height:
                new_drops.append(drop)

        self.drops = new_drops

        # Add new drops to maintain density
        while len(self.drops) < self._target_drops:
            self._add_drop()

    def resize(self, width: int, height: int):
        """Handle terminal resize."""
        old_width = self.width
        self.width = width
        self.height = height
        self._target_drops = max(8, width * 3 // 20)  # 50% more rain!

        # Remove drops that are now out of bounds
        self.drops = [d for d in self.drops if d['x'] < width]

        # Add more drops if window got bigger
        if width > old_width:
            for _ in range(max(1, (width - old_width) * 3 // 20)):
                self._add_drop()

    def render(self, screen):
        """Render rain drops with depth-based visual effects and flicker."""
        # Sort drops by depth so farther ones render first (get overwritten by nearer)
        sorted_drops = sorted(self.drops, key=lambda d: d['depth'])

        for drop in sorted_drops:
            depth = drop['depth']
            chars = self.DEPTH_CHARS[depth]

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

                    # More character mutation flicker for nearer drops
                    if random.random() < 0.02 * (depth + 1):
                        char = random.choice(chars)

                    # Rapid flicker can also swap characters briefly
                    if random.random() < self._global_flicker * 0.15:
                        char = random.choice(chars)

                    try:
                        self._render_char(screen, y, drop['x'], char, i, depth)
                    except curses.error:
                        pass

    def _render_char(self, screen, y: int, x: int, char: str, pos: int, depth: int):
        """Render a single character with depth-appropriate styling."""
        # Depth 0 = farthest/dimmest, Depth 4 = nearest/brightest

        if depth == 0:
            # Farthest layer - very dim, no head highlight
            if pos < 2:
                attr = curses.color_pair(Colors.MATRIX_FADE2) | curses.A_DIM
            else:
                attr = curses.color_pair(Colors.MATRIX_FADE3) | curses.A_DIM
        elif depth == 1:
            # Far layer - dim
            if pos == 0:
                attr = curses.color_pair(Colors.MATRIX_FADE1)
            elif pos < 3:
                attr = curses.color_pair(Colors.MATRIX_FADE1) | curses.A_DIM
            else:
                attr = curses.color_pair(Colors.MATRIX_FADE2) | curses.A_DIM
        elif depth == 2:
            # Middle layer - normal
            if pos == 0:
                attr = curses.color_pair(Colors.MATRIX_DIM) | curses.A_BOLD
            elif pos < 3:
                attr = curses.color_pair(Colors.MATRIX_DIM)
            elif pos < 6:
                attr = curses.color_pair(Colors.MATRIX_FADE1) | curses.A_DIM
            else:
                attr = curses.color_pair(Colors.MATRIX_FADE2) | curses.A_DIM
        elif depth == 3:
            # Near layer - bright
            if pos == 0:
                attr = curses.color_pair(Colors.MATRIX_BRIGHT) | curses.A_BOLD
            elif pos == 1:
                attr = curses.color_pair(Colors.MATRIX_DIM) | curses.A_BOLD
            elif pos < 5:
                attr = curses.color_pair(Colors.MATRIX_DIM)
            elif pos < 9:
                attr = curses.color_pair(Colors.MATRIX_FADE1)
            else:
                attr = curses.color_pair(Colors.MATRIX_FADE2) | curses.A_DIM
        else:  # depth == 4
            # Nearest layer - brightest, boldest
            if pos == 0:
                attr = curses.color_pair(Colors.MATRIX_BRIGHT) | curses.A_BOLD
            elif pos == 1:
                attr = curses.color_pair(Colors.MATRIX_BRIGHT)
            elif pos < 4:
                attr = curses.color_pair(Colors.MATRIX_DIM) | curses.A_BOLD
            elif pos < 8:
                attr = curses.color_pair(Colors.MATRIX_DIM)
            elif pos < 12:
                attr = curses.color_pair(Colors.MATRIX_FADE1)
            else:
                attr = curses.color_pair(Colors.MATRIX_FADE2)

        screen.attron(attr)
        screen.addstr(y, x, char)
        screen.attroff(attr)


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

        # Build dynamic socket paths based on where daemon might create them
        self._socket_paths = self._build_socket_paths()

        # Try to find working socket
        if not self.socket_path:
            self.socket_path = self._find_socket()

        # Resolve token after finding socket (token might be near socket)
        self._token = self._resolve_token()

        # Test connection
        self._connected = self._test_connection()
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
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cwd']):
                try:
                    cmdline = proc.info.get('cmdline') or []
                    cmdline_str = ' '.join(cmdline).lower()
                    # Look for boundary daemon process
                    if 'boundary' in cmdline_str and 'daemon' in cmdline_str:
                        cwd = proc.info.get('cwd')
                        if cwd:
                            logger.debug(f"Found daemon process {proc.info['pid']} at {cwd}")
                            return cwd
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except ImportError:
            pass
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
            return response.get('success', False)
        except Exception as e:
            logger.debug(f"Connection test failed: {e}")
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
            if sys.platform == 'win32':
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

        # Try each socket path
        for path in self._socket_paths:
            if os.path.exists(path):
                old_path = self.socket_path
                self.socket_path = path
                # Refresh token in case it changed
                self._token = self._resolve_token()
                if self._test_connection():
                    self._connected = True
                    self._demo_mode = False
                    logger.info(f"Connected to daemon at {path}")
                    return True
                self.socket_path = old_path

        # Also try Windows TCP on Windows
        if sys.platform == 'win32':
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                sock.connect((self.WINDOWS_HOST, self.WINDOWS_PORT))
                sock.close()
                self._connected = True
                self._demo_mode = False
                logger.info(f"Connected to daemon via TCP {self.WINDOWS_HOST}:{self.WINDOWS_PORT}")
                return True
            except Exception:
                pass

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
            self.matrix_rain = MatrixRain(self.width, self.height)
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
                        self.matrix_rain.resize(self.width, self.height)
                    self.matrix_rain.update()

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
        if self.matrix_mode and self.matrix_rain:
            self.matrix_rain.resize(self.width, self.height)
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

    def _draw(self):
        """Draw the dashboard."""
        self.screen.clear()

        # Render matrix rain in background first
        if self.matrix_mode and self.matrix_rain:
            self.matrix_rain.render(self.screen)

            # Render lightning bolt if active
            if self._lightning_active and self._lightning_bolt:
                self._render_lightning()

        if self.show_help:
            self._draw_help()
        else:
            self._draw_header()
            self._draw_panels()
            self._draw_footer()

        self.screen.refresh()

    def _draw_header(self):
        """Draw the header bar."""
        header = " BOUNDARY DAEMON"
        if self.client.is_demo_mode():
            header += " [DEMO]"
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
        shortcuts = "[m]Mode [a]Ack [e]Export [r]Refresh [/]Search [?]Help [q]Quit"
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

            # Render matrix rain if in matrix mode
            if self.matrix_mode and self.matrix_rain:
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
