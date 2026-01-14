#!/usr/bin/env python3
"""
ASCII Art Editor - Standalone tool for creating and editing TUI sprites

Features:
- Create new ASCII art with labels
- Load and modify existing sprites from dashboard.py
- Draw with keyboard (characters, lines, boxes)
- 16 color support with preview (8 normal + 8 bright)
- Visual cursor with multiple styles (block, underline, crosshair)
- Multi-frame animation support with frame navigation
- Export to Python code format
- Undo/redo support

Usage:
    python -m daemon.tui.art_editor
    python -m daemon.tui.art_editor --load CAR_RIGHT
    python -m daemon.tui.art_editor --new 20x10 --name MY_SPRITE

Keyboard Controls:
    Arrow keys  - Move cursor
    Any char    - Draw character at cursor
    Space       - Clear cell
    Ctrl+S      - Save/Export
    Ctrl+Z      - Undo
    Ctrl+Y      - Redo
    Ctrl+L      - Load sprite
    Ctrl+N      - New canvas
    Ctrl+R      - Resize canvas
    Tab         - Cycle colors
    Shift+Tab   - Cycle colors backward
    F1          - Help
    F2          - Cycle cursor style
    < / >       - Previous/Next frame (animation)
    Ctrl+F      - Add new frame
    Ctrl+D      - Delete current frame
    Ctrl+G      - Play/preview animation
    Escape/Q    - Quit
"""

import argparse
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Handle curses import for Windows (windows-curses not available for Python 3.14+)
curses = None
CURSES_AVAILABLE = False
try:
    import curses
    CURSES_AVAILABLE = True
except ImportError:
    # Try to find Python 3.12 on Windows for curses support
    pass


def _try_relaunch_with_py312() -> bool:
    """Try to relaunch with Python 3.12 if available (for Windows curses support)."""
    if sys.platform != 'win32':
        return False

    try:
        # Check if py launcher can find Python 3.12
        result = subprocess.run(
            ['py', '-3.12', '--version'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # Relaunch with Python 3.12
            print(f"Relaunching with Python 3.12 for curses support...")
            subprocess.run(['py', '-3.12'] + sys.argv)
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return False


@dataclass
class Cell:
    """A single cell in the art canvas."""
    char: str = ' '
    color: int = 0  # Color pair index


@dataclass
class ArtCanvas:
    """The editable art canvas."""
    width: int
    height: int
    name: str = "UNNAMED_SPRITE"
    cells: List[List[Cell]] = field(default_factory=list)

    def __post_init__(self):
        if not self.cells:
            self.cells = [[Cell() for _ in range(self.width)] for _ in range(self.height)]

    def get(self, row: int, col: int) -> Cell:
        if 0 <= row < self.height and 0 <= col < self.width:
            return self.cells[row][col]
        return Cell()

    def set(self, row: int, col: int, char: str, color: int = 0):
        if 0 <= row < self.height and 0 <= col < self.width:
            self.cells[row][col] = Cell(char, color)

    def clear(self):
        self.cells = [[Cell() for _ in range(self.width)] for _ in range(self.height)]

    def to_string_list(self) -> List[str]:
        """Convert canvas to list of strings (sprite format)."""
        lines = []
        for row in self.cells:
            line = ''.join(cell.char for cell in row)
            lines.append(line)
        return lines

    def from_string_list(self, lines: List[str]):
        """Load canvas from list of strings."""
        self.height = len(lines)
        self.width = max(len(line) for line in lines) if lines else 1
        self.cells = []
        for line in lines:
            row = []
            for i in range(self.width):
                char = line[i] if i < len(line) else ' '
                row.append(Cell(char, 0))
            self.cells.append(row)

    def resize(self, new_width: int, new_height: int):
        """Resize canvas, preserving existing content."""
        new_cells = [[Cell() for _ in range(new_width)] for _ in range(new_height)]
        for row in range(min(self.height, new_height)):
            for col in range(min(self.width, new_width)):
                new_cells[row][col] = self.cells[row][col]
        self.cells = new_cells
        self.width = new_width
        self.height = new_height

    def copy(self) -> 'ArtCanvas':
        """Create a deep copy of the canvas."""
        new_canvas = ArtCanvas(self.width, self.height, self.name)
        new_canvas.cells = [[Cell(c.char, c.color) for c in row] for row in self.cells]
        return new_canvas


class UndoManager:
    """Manages undo/redo history."""

    def __init__(self, max_history: int = 100):
        self.history: List[List[List[Cell]]] = []
        self.redo_stack: List[List[List[Cell]]] = []
        self.max_history = max_history

    def save_state(self, cells: List[List[Cell]]):
        """Save current state for undo."""
        # Deep copy cells
        state = [[Cell(c.char, c.color) for c in row] for row in cells]
        self.history.append(state)
        if len(self.history) > self.max_history:
            self.history.pop(0)
        self.redo_stack.clear()

    def undo(self, current_cells: List[List[Cell]]) -> Optional[List[List[Cell]]]:
        """Undo last action, returns previous state."""
        if self.history:
            # Save current for redo
            state = [[Cell(c.char, c.color) for c in row] for row in current_cells]
            self.redo_stack.append(state)
            return self.history.pop()
        return None

    def redo(self, current_cells: List[List[Cell]]) -> Optional[List[List[Cell]]]:
        """Redo last undone action."""
        if self.redo_stack:
            # Save current for undo
            state = [[Cell(c.char, c.color) for c in row] for row in current_cells]
            self.history.append(state)
            return self.redo_stack.pop()
        return None


class SpriteLibrary:
    """Loads and manages sprites from dashboard.py."""

    def __init__(self):
        self.sprites: Dict[str, List[str]] = {}
        self._load_from_dashboard()

    def _load_from_dashboard(self):
        """Parse dashboard.py to extract sprite definitions."""
        dashboard_path = Path(__file__).parent / 'dashboard.py'
        if not dashboard_path.exists():
            return

        try:
            with open(dashboard_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Find sprite definitions (variable = [...] patterns)
            # Match patterns like: SPRITE_NAME = [\n"...",\n"...",\n]
            pattern = r'^\s+([A-Z][A-Z0-9_]+)\s*=\s*\[\s*\n((?:\s*"[^"]*",?\s*\n)+)\s*\]'

            for match in re.finditer(pattern, content, re.MULTILINE):
                name = match.group(1)
                lines_text = match.group(2)

                # Extract individual strings
                lines = []
                for line_match in re.finditer(r'"([^"]*)"', lines_text):
                    lines.append(line_match.group(1))

                if lines:
                    self.sprites[name] = lines

            # Also find frame-based sprites (lists of lists)
            frame_pattern = r'^\s+([A-Z][A-Z0-9_]+_FRAMES)\s*=\s*\[\s*\n((?:\s*\[[^\]]+\],?\s*\n)+)\s*\]'
            for match in re.finditer(frame_pattern, content, re.MULTILINE):
                name = match.group(1)
                # Just note it exists, frames are complex
                if name not in self.sprites:
                    self.sprites[name] = ["# Frame-based sprite - edit individual frames"]

        except Exception as e:
            print(f"Warning: Could not load sprites from dashboard.py: {e}")

    def get_sprite(self, name: str) -> Optional[List[str]]:
        return self.sprites.get(name)

    def list_sprites(self) -> List[str]:
        return sorted(self.sprites.keys())


class ArtEditor:
    """Main ASCII art editor application."""

    # Color definitions - initialized lazily to avoid accessing curses at class level
    # when curses is not available (Windows without windows-curses)
    COLORS = None

    # Cursor styles
    CURSOR_STYLES = ["block", "underline", "crosshair", "corners"]

    @classmethod
    def _get_colors(cls):
        """Get color definitions, initializing lazily if needed.

        Returns 16 colors: 8 normal + 8 bright variants.
        """
        if cls.COLORS is None and curses is not None:
            cls.COLORS = [
                # Normal colors (0-7)
                ("White", curses.COLOR_WHITE, curses.COLOR_BLACK, False),
                ("Red", curses.COLOR_RED, curses.COLOR_BLACK, False),
                ("Green", curses.COLOR_GREEN, curses.COLOR_BLACK, False),
                ("Yellow", curses.COLOR_YELLOW, curses.COLOR_BLACK, False),
                ("Blue", curses.COLOR_BLUE, curses.COLOR_BLACK, False),
                ("Magenta", curses.COLOR_MAGENTA, curses.COLOR_BLACK, False),
                ("Cyan", curses.COLOR_CYAN, curses.COLOR_BLACK, False),
                ("Gray", curses.COLOR_WHITE, curses.COLOR_BLACK, False),
                # Bright colors (8-15) - use A_BOLD for brightness
                ("Bright White", curses.COLOR_WHITE, curses.COLOR_BLACK, True),
                ("Bright Red", curses.COLOR_RED, curses.COLOR_BLACK, True),
                ("Bright Green", curses.COLOR_GREEN, curses.COLOR_BLACK, True),
                ("Bright Yellow", curses.COLOR_YELLOW, curses.COLOR_BLACK, True),
                ("Bright Blue", curses.COLOR_BLUE, curses.COLOR_BLACK, True),
                ("Bright Magenta", curses.COLOR_MAGENTA, curses.COLOR_BLACK, True),
                ("Bright Cyan", curses.COLOR_CYAN, curses.COLOR_BLACK, True),
                ("Bright Gray", curses.COLOR_WHITE, curses.COLOR_BLACK, True),
            ]
        return cls.COLORS or []

    def __init__(self, initial_width: int = 30, initial_height: int = 10,
                 sprite_name: str = "NEW_SPRITE"):
        self.canvas = ArtCanvas(initial_width, initial_height, sprite_name)
        self.cursor_row = 0
        self.cursor_col = 0
        self.current_color = 0
        self.undo_manager = UndoManager()
        self.sprite_library = SpriteLibrary()
        self.running = True
        self.screen = None
        self.message = ""
        self.message_time = 0
        self.show_help = False
        self.show_sprite_list = False
        self.sprite_list_scroll = 0
        self.selected_sprite_idx = 0
        self.drawing_mode = "char"  # char, line, box
        self.line_start: Optional[Tuple[int, int]] = None

        # Visual cursor settings
        self.cursor_style = 0  # Index into CURSOR_STYLES
        self.cursor_blink = True
        self.cursor_blink_state = True
        self.cursor_blink_counter = 0

        # Animation frames support
        self.frames: List[ArtCanvas] = [self.canvas]  # List of frames
        self.current_frame = 0  # Current frame index
        self.animation_playing = False
        self.animation_speed = 200  # ms per frame

        # UI layout
        self.canvas_offset_y = 3
        self.canvas_offset_x = 2

    def init_colors(self):
        """Initialize color pairs for 16 colors plus UI colors."""
        curses.start_color()
        curses.use_default_colors()

        # Initialize 16 color pairs (colors are stored with bright flag in tuple)
        for i, (name, fg, bg, bright) in enumerate(self._get_colors()):
            try:
                curses.init_pair(i + 1, fg, bg)
            except curses.error:
                pass

        # Special colors for UI (pairs 20-29)
        curses.init_pair(20, curses.COLOR_BLACK, curses.COLOR_WHITE)  # Cursor highlight
        curses.init_pair(21, curses.COLOR_WHITE, curses.COLOR_BLUE)   # Header
        curses.init_pair(22, curses.COLOR_YELLOW, curses.COLOR_BLACK) # Status bar
        curses.init_pair(23, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Success message
        curses.init_pair(24, curses.COLOR_RED, curses.COLOR_BLACK)    # Error message
        curses.init_pair(25, curses.COLOR_CYAN, curses.COLOR_BLACK)   # Frame indicator
        curses.init_pair(26, curses.COLOR_BLACK, curses.COLOR_YELLOW) # Cursor crosshair

    def show_message(self, msg: str, is_error: bool = False):
        """Show a status message."""
        self.message = msg
        self.message_time = 50  # Frames to show
        self.message_is_error = is_error

    def load_sprite(self, name: str) -> bool:
        """Load a sprite from the library."""
        sprite = self.sprite_library.get_sprite(name)
        if sprite:
            self.undo_manager.save_state(self.canvas.cells)
            self.canvas.from_string_list(sprite)
            self.canvas.name = name
            self.cursor_row = 0
            self.cursor_col = 0
            self.show_message(f"Loaded: {name}")
            return True
        self.show_message(f"Sprite not found: {name}", is_error=True)
        return False

    def export_to_python(self) -> str:
        """Export canvas as Python code. Supports multi-frame animation export."""
        if len(self.frames) == 1:
            # Single frame export
            lines = self.canvas.to_string_list()

            # Escape backslashes and quotes
            escaped_lines = []
            for line in lines:
                escaped = line.replace('\\', '\\\\').replace('"', '\\"')
                escaped_lines.append(f'        "{escaped}",')

            code = f'''    # {self.canvas.name} - Generated by Art Editor
    # Size: {self.canvas.width}x{self.canvas.height}
    {self.canvas.name} = [
{chr(10).join(escaped_lines)}
    ]
'''
        else:
            # Multi-frame animation export
            frame_code_parts = []
            for i, frame in enumerate(self.frames):
                lines = frame.to_string_list()
                escaped_lines = []
                for line in lines:
                    escaped = line.replace('\\', '\\\\').replace('"', '\\"')
                    escaped_lines.append(f'            "{escaped}",')
                frame_code = f'''        [  # Frame {i + 1}
{chr(10).join(escaped_lines)}
        ],'''
                frame_code_parts.append(frame_code)

            code = f'''    # {self.canvas.name}_FRAMES - Generated by Art Editor
    # Size: {self.canvas.width}x{self.canvas.height}, Frames: {len(self.frames)}
    {self.canvas.name}_FRAMES = [
{chr(10).join(frame_code_parts)}
    ]
'''
        return code

    def save_to_file(self, filename: Optional[str] = None):
        """Save sprite to a file. Multi-frame sprites are saved with frame markers."""
        if not filename:
            suffix = "_frames" if len(self.frames) > 1 else ""
            filename = f"{self.canvas.name.lower()}{suffix}.txt"

        # Save as plain text
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                if len(self.frames) == 1:
                    for line in self.canvas.to_string_list():
                        f.write(line + '\n')
                else:
                    # Multi-frame format with separators
                    for i, frame in enumerate(self.frames):
                        f.write(f"--- Frame {i + 1} ---\n")
                        for line in frame.to_string_list():
                            f.write(line + '\n')
                        f.write('\n')
            self.show_message(f"Saved {len(self.frames)} frame(s) to {filename}")
            return True
        except Exception as e:
            self.show_message(f"Save failed: {e}", is_error=True)
            return False

    def save_python_snippet(self, filename: Optional[str] = None):
        """Save as Python code snippet."""
        if not filename:
            filename = f"{self.canvas.name.lower()}_sprite.py"

        try:
            code = self.export_to_python()
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"# Generated by Art Editor - {datetime.now().isoformat()}\n\n")
                f.write(code)
            self.show_message(f"Python saved to {filename}")
            return True
        except Exception as e:
            self.show_message(f"Save failed: {e}", is_error=True)
            return False

    def draw(self):
        """Draw the editor UI."""
        self.screen.clear()
        height, width = self.screen.getmaxyx()

        # Update cursor blink state
        self.cursor_blink_counter += 1
        if self.cursor_blink_counter >= 10:  # Blink every ~500ms at 50ms refresh
            self.cursor_blink_counter = 0
            self.cursor_blink_state = not self.cursor_blink_state

        # Header with frame info
        frame_info = f" Frame {self.current_frame + 1}/{len(self.frames)}" if len(self.frames) > 1 else ""
        header = f" ART EDITOR - {self.canvas.name} ({self.canvas.width}x{self.canvas.height}){frame_info} "
        header += f"| Color: {self._get_colors()[self.current_color][0]} "
        header += f"| Cursor: {self.CURSOR_STYLES[self.cursor_style]} "
        header = header.ljust(width - 1)

        try:
            self.screen.attron(curses.color_pair(21) | curses.A_BOLD)
            self.screen.addstr(0, 0, header[:width-1])
            self.screen.attroff(curses.color_pair(21) | curses.A_BOLD)
        except curses.error:
            pass

        # Shortcuts bar
        shortcuts = "[Arrows]Move [Tab]Color [F1]Help [F2]Cursor [</>]Frames [Ctrl+S]Save [Q]Quit"
        try:
            self.screen.attron(curses.color_pair(22))
            self.screen.addstr(1, 0, shortcuts[:width-1])
            self.screen.attroff(curses.color_pair(22))
        except curses.error:
            pass

        # Canvas border
        canvas_top = self.canvas_offset_y - 1
        canvas_left = self.canvas_offset_x - 1
        canvas_bottom = self.canvas_offset_y + self.canvas.height
        canvas_right = self.canvas_offset_x + self.canvas.width

        # Draw border
        try:
            # Top border
            self.screen.addstr(canvas_top, canvas_left, '┌' + '─' * self.canvas.width + '┐')
            # Bottom border
            if canvas_bottom < height - 2:
                self.screen.addstr(canvas_bottom, canvas_left, '└' + '─' * self.canvas.width + '┘')
            # Side borders
            for row in range(self.canvas.height):
                y = self.canvas_offset_y + row
                if y < height - 2:
                    self.screen.addstr(y, canvas_left, '│')
                    if canvas_right < width - 1:
                        self.screen.addstr(y, canvas_right, '│')
        except curses.error:
            pass

        # Draw canvas content with visual cursor
        cursor_style = self.CURSOR_STYLES[self.cursor_style]
        show_cursor = self.cursor_blink_state or not self.cursor_blink

        for row in range(self.canvas.height):
            for col in range(self.canvas.width):
                cell = self.canvas.get(row, col)
                y = self.canvas_offset_y + row
                x = self.canvas_offset_x + col

                if y >= height - 2 or x >= width - 1:
                    continue

                try:
                    is_cursor_pos = (row == self.cursor_row and col == self.cursor_col)
                    is_cursor_row = (row == self.cursor_row)
                    is_cursor_col = (col == self.cursor_col)

                    # Determine base color attribute
                    if cell.color > 0:
                        color_idx = cell.color
                        colors = self._get_colors()
                        if color_idx <= len(colors):
                            is_bright = colors[color_idx - 1][3]  # Check bright flag
                            attr = curses.color_pair(color_idx)
                            if is_bright:
                                attr |= curses.A_BOLD
                        else:
                            attr = curses.A_NORMAL
                    else:
                        attr = curses.A_NORMAL

                    char = cell.char if cell.char else ' '

                    # Apply cursor styling based on cursor style
                    if show_cursor:
                        if cursor_style == "block" and is_cursor_pos:
                            # Block cursor: reverse video
                            attr = curses.color_pair(20) | curses.A_REVERSE
                        elif cursor_style == "underline" and is_cursor_pos:
                            # Underline cursor: underline attribute
                            attr |= curses.A_UNDERLINE | curses.A_BOLD
                        elif cursor_style == "crosshair":
                            # Crosshair: highlight entire row and column
                            if is_cursor_pos:
                                attr = curses.color_pair(26) | curses.A_BOLD
                            elif is_cursor_row or is_cursor_col:
                                attr |= curses.A_DIM
                        elif cursor_style == "corners" and is_cursor_pos:
                            # Corners style: show with bright reverse
                            attr = curses.color_pair(20) | curses.A_REVERSE | curses.A_BOLD

                    self.screen.addstr(y, x, char, attr)
                except curses.error:
                    pass

        # Draw corner indicators for "corners" cursor style
        if show_cursor and cursor_style == "corners":
            self._draw_cursor_corners(height, width)

        # Draw cursor position indicator and frame info
        pos_info = f"Cursor: ({self.cursor_row}, {self.cursor_col})"
        if len(self.frames) > 1:
            pos_info += f"  |  Frame: {self.current_frame + 1}/{len(self.frames)} [</>] [Ctrl+F:Add] [Ctrl+D:Del]"
        try:
            self.screen.addstr(canvas_bottom + 1, self.canvas_offset_x, pos_info)
        except curses.error:
            pass

        # Draw color palette (16 colors in 2 rows)
        palette_y = canvas_bottom + 2
        if palette_y < height - 1:
            try:
                self.screen.addstr(palette_y, self.canvas_offset_x, "Colors: ")
                colors = self._get_colors()
                # First row: colors 0-7 (normal)
                for i in range(min(8, len(colors))):
                    name, _, _, is_bright = colors[i]
                    marker = "█" if i == self.current_color else "▪"
                    attr = curses.color_pair(i + 1)
                    if i == self.current_color:
                        attr |= curses.A_BOLD
                    self.screen.addstr(marker, attr)
                    self.screen.addstr(" ")

                # Second row: colors 8-15 (bright) if space available
                palette_y2 = canvas_bottom + 3
                if palette_y2 < height - 1 and len(colors) > 8:
                    self.screen.addstr(palette_y2, self.canvas_offset_x, "        ")
                    for i in range(8, min(16, len(colors))):
                        name, _, _, is_bright = colors[i]
                        marker = "█" if i == self.current_color else "▪"
                        attr = curses.color_pair(i + 1)
                        if is_bright:
                            attr |= curses.A_BOLD
                        if i == self.current_color:
                            attr |= curses.A_REVERSE
                        self.screen.addstr(marker, attr)
                        self.screen.addstr(" ")
            except curses.error:
                pass

        # Draw frame indicators if multiple frames exist
        if len(self.frames) > 1:
            frame_y = canvas_bottom + 4 if canvas_bottom + 4 < height - 2 else canvas_bottom + 3
            if frame_y < height - 1:
                try:
                    frame_bar = "Frames: "
                    for i in range(len(self.frames)):
                        if i == self.current_frame:
                            frame_bar += f"[{i+1}] "
                        else:
                            frame_bar += f" {i+1}  "
                    self.screen.addstr(frame_y, self.canvas_offset_x, frame_bar,
                                       curses.color_pair(25))
                except curses.error:
                    pass

        # Draw message
        if self.message and self.message_time > 0:
            msg_y = height - 2
            try:
                color = curses.color_pair(24) if self.message_is_error else curses.color_pair(23)
                self.screen.attron(color)
                self.screen.addstr(msg_y, 0, self.message[:width-1])
                self.screen.attroff(color)
            except curses.error:
                pass
            self.message_time -= 1

        # Draw help overlay
        if self.show_help:
            self._draw_help_overlay()

        # Draw sprite list overlay
        if self.show_sprite_list:
            self._draw_sprite_list_overlay()

        self.screen.refresh()

    def _draw_cursor_corners(self, height: int, width: int):
        """Draw corner indicators for the 'corners' cursor style."""
        y = self.canvas_offset_y + self.cursor_row
        x = self.canvas_offset_x + self.cursor_col

        # Draw corner brackets around cursor position
        corner_attr = curses.color_pair(25) | curses.A_BOLD
        try:
            # Top-left corner indicator (above and left)
            if y > self.canvas_offset_y and x > self.canvas_offset_x:
                self.screen.addstr(y - 1, x - 1, "┌", corner_attr)
            # Top-right corner indicator
            if y > self.canvas_offset_y and x < self.canvas_offset_x + self.canvas.width - 1:
                self.screen.addstr(y - 1, x + 1, "┐", corner_attr)
            # Bottom-left corner indicator
            if y < self.canvas_offset_y + self.canvas.height - 1 and x > self.canvas_offset_x:
                self.screen.addstr(y + 1, x - 1, "└", corner_attr)
            # Bottom-right corner indicator
            if y < self.canvas_offset_y + self.canvas.height - 1 and x < self.canvas_offset_x + self.canvas.width - 1:
                self.screen.addstr(y + 1, x + 1, "┘", corner_attr)
        except curses.error:
            pass

    def _draw_help_overlay(self):
        """Draw help overlay."""
        height, width = self.screen.getmaxyx()

        help_text = [
            "╔════════════════════════════════════════════════════════════════╗",
            "║                      ART EDITOR HELP                           ║",
            "╠════════════════════════════════════════════════════════════════╣",
            "║  Navigation:                                                   ║",
            "║    Arrow Keys    - Move cursor                                 ║",
            "║    Home/End      - Start/end of row                            ║",
            "║    PgUp/PgDn     - Top/bottom of canvas                        ║",
            "║                                                                ║",
            "║  Drawing:                                                      ║",
            "║    Any character - Draw at cursor                              ║",
            "║    Space         - Clear cell                                  ║",
            "║    Tab           - Cycle through colors (16 colors)            ║",
            "║    Shift+Tab     - Cycle colors backward                       ║",
            "║    Backspace     - Clear and move left                         ║",
            "║                                                                ║",
            "║  File Operations:                                              ║",
            "║    Ctrl+S        - Save to file                                ║",
            "║    Ctrl+P        - Save as Python code                         ║",
            "║    Ctrl+L        - Load sprite from library                    ║",
            "║    Ctrl+N        - New canvas                                  ║",
            "║                                                                ║",
            "║  Edit:                                                         ║",
            "║    Ctrl+Z        - Undo                                        ║",
            "║    Ctrl+Y        - Redo                                        ║",
            "║    Ctrl+R        - Resize canvas                               ║",
            "║                                                                ║",
            "║  Animation Frames:                                             ║",
            "║    < / ,         - Previous frame                              ║",
            "║    > / .         - Next frame                                  ║",
            "║    Ctrl+F        - Add new frame (copy current)                ║",
            "║    Ctrl+D        - Delete current frame                        ║",
            "║    Ctrl+G        - Play/preview animation                      ║",
            "║                                                                ║",
            "║  Cursor & Display:                                             ║",
            "║    F1            - Toggle this help                            ║",
            "║    F2            - Cycle cursor style (block/line/cross/corner)║",
            "║    Q / Escape    - Quit                                        ║",
            "╚════════════════════════════════════════════════════════════════╝",
            "                     Press any key to close                       ",
        ]

        box_height = len(help_text)
        box_width = len(help_text[0])
        start_y = max(0, (height - box_height) // 2)
        start_x = max(0, (width - box_width) // 2)

        for i, line in enumerate(help_text):
            try:
                self.screen.addstr(start_y + i, start_x, line[:width-1],
                                   curses.color_pair(21))
            except curses.error:
                pass

    def _draw_sprite_list_overlay(self):
        """Draw sprite list for loading."""
        height, width = self.screen.getmaxyx()

        sprites = self.sprite_library.list_sprites()
        if not sprites:
            sprites = ["(No sprites found in dashboard.py)"]

        box_height = min(20, len(sprites) + 4)
        box_width = min(50, width - 4)
        start_y = max(0, (height - box_height) // 2)
        start_x = max(0, (width - box_width) // 2)

        # Draw box
        try:
            self.screen.addstr(start_y, start_x, "╔" + "═" * (box_width - 2) + "╗", curses.color_pair(21))
            self.screen.addstr(start_y + 1, start_x, "║" + " SELECT SPRITE TO LOAD ".center(box_width - 2) + "║", curses.color_pair(21))
            self.screen.addstr(start_y + 2, start_x, "╠" + "═" * (box_width - 2) + "╣", curses.color_pair(21))

            visible_count = box_height - 4
            for i in range(visible_count):
                sprite_idx = self.sprite_list_scroll + i
                if sprite_idx >= len(sprites):
                    break

                sprite_name = sprites[sprite_idx]
                if sprite_idx == self.selected_sprite_idx:
                    line = f"║ > {sprite_name}".ljust(box_width - 1) + "║"
                    attr = curses.color_pair(21) | curses.A_REVERSE
                else:
                    line = f"║   {sprite_name}".ljust(box_width - 1) + "║"
                    attr = curses.color_pair(21)

                self.screen.addstr(start_y + 3 + i, start_x, line[:width-1], attr)

            self.screen.addstr(start_y + box_height - 1, start_x,
                              "╚" + "═" * (box_width - 2) + "╝", curses.color_pair(21))
        except curses.error:
            pass

    def handle_input(self, key: int):
        """Handle keyboard input."""
        # Help overlay
        if self.show_help:
            self.show_help = False
            return

        # Sprite list overlay
        if self.show_sprite_list:
            sprites = self.sprite_library.list_sprites()
            if key == curses.KEY_UP and self.selected_sprite_idx > 0:
                self.selected_sprite_idx -= 1
                if self.selected_sprite_idx < self.sprite_list_scroll:
                    self.sprite_list_scroll = self.selected_sprite_idx
            elif key == curses.KEY_DOWN and self.selected_sprite_idx < len(sprites) - 1:
                self.selected_sprite_idx += 1
                if self.selected_sprite_idx >= self.sprite_list_scroll + 16:
                    self.sprite_list_scroll += 1
            elif key == ord('\n') or key == curses.KEY_ENTER:
                if sprites:
                    self.load_sprite(sprites[self.selected_sprite_idx])
                self.show_sprite_list = False
            elif key == 27:  # Escape
                self.show_sprite_list = False
            return

        # Navigation
        if key == curses.KEY_UP:
            self.cursor_row = max(0, self.cursor_row - 1)
        elif key == curses.KEY_DOWN:
            self.cursor_row = min(self.canvas.height - 1, self.cursor_row + 1)
        elif key == curses.KEY_LEFT:
            self.cursor_col = max(0, self.cursor_col - 1)
        elif key == curses.KEY_RIGHT:
            self.cursor_col = min(self.canvas.width - 1, self.cursor_col + 1)
        elif key == curses.KEY_HOME:
            self.cursor_col = 0
        elif key == curses.KEY_END:
            self.cursor_col = self.canvas.width - 1
        elif key == curses.KEY_PPAGE:  # Page Up
            self.cursor_row = 0
        elif key == curses.KEY_NPAGE:  # Page Down
            self.cursor_row = self.canvas.height - 1

        # Function keys
        elif key == curses.KEY_F1:
            self.show_help = True
        elif key == curses.KEY_F2:
            # Cycle cursor style
            self.cursor_style = (self.cursor_style + 1) % len(self.CURSOR_STYLES)
            self.show_message(f"Cursor style: {self.CURSOR_STYLES[self.cursor_style]}")

        # Frame navigation with < > or , .
        elif key in (ord('<'), ord(',')):
            self._goto_previous_frame()
        elif key in (ord('>'), ord('.')):
            self._goto_next_frame()

        # Control keys
        elif key == 19:  # Ctrl+S
            self.save_to_file()
        elif key == 16:  # Ctrl+P
            self.save_python_snippet()
        elif key == 12:  # Ctrl+L
            self.show_sprite_list = True
            self.selected_sprite_idx = 0
            self.sprite_list_scroll = 0
        elif key == 14:  # Ctrl+N
            self._prompt_new_canvas()
        elif key == 26:  # Ctrl+Z
            result = self.undo_manager.undo(self.canvas.cells)
            if result:
                self.canvas.cells = result
                self.frames[self.current_frame] = self.canvas  # Keep frame in sync
                self.show_message("Undo")
            else:
                self.show_message("Nothing to undo", is_error=True)
        elif key == 25:  # Ctrl+Y
            result = self.undo_manager.redo(self.canvas.cells)
            if result:
                self.canvas.cells = result
                self.frames[self.current_frame] = self.canvas  # Keep frame in sync
                self.show_message("Redo")
            else:
                self.show_message("Nothing to redo", is_error=True)
        elif key == 18:  # Ctrl+R
            self._prompt_resize()
        elif key == 6:  # Ctrl+F - Add new frame
            self._add_frame()
        elif key == 4:  # Ctrl+D - Delete current frame
            self._delete_frame()
        elif key == 7:  # Ctrl+G - Play animation
            self._play_animation()

        # Tab - cycle colors forward
        elif key == ord('\t'):
            self.current_color = (self.current_color + 1) % len(self._get_colors())
            self.show_message(f"Color: {self._get_colors()[self.current_color][0]}")
        # Shift+Tab - cycle colors backward
        elif key == curses.KEY_BTAB or key == 353:
            self.current_color = (self.current_color - 1) % len(self._get_colors())
            self.show_message(f"Color: {self._get_colors()[self.current_color][0]}")

        # Backspace
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            self.undo_manager.save_state(self.canvas.cells)
            self.canvas.set(self.cursor_row, self.cursor_col, ' ', 0)
            if self.cursor_col > 0:
                self.cursor_col -= 1

        # Quit
        elif key in (ord('q'), ord('Q'), 27):  # q, Q, Escape
            self.running = False

        # Drawing - printable characters
        elif 32 <= key <= 126:
            self.undo_manager.save_state(self.canvas.cells)
            char = chr(key)
            self.canvas.set(self.cursor_row, self.cursor_col, char, self.current_color + 1)
            # Auto-advance cursor
            if self.cursor_col < self.canvas.width - 1:
                self.cursor_col += 1

    def _prompt_new_canvas(self):
        """Prompt for new canvas dimensions."""
        curses.echo()
        height, width = self.screen.getmaxyx()

        try:
            self.screen.addstr(height - 3, 0, "New canvas - Width: ")
            self.screen.refresh()
            width_str = self.screen.getstr(height - 3, 20, 5).decode('utf-8')

            self.screen.addstr(height - 3, 26, " Height: ")
            self.screen.refresh()
            height_str = self.screen.getstr(height - 3, 35, 5).decode('utf-8')

            self.screen.addstr(height - 3, 41, " Name: ")
            self.screen.refresh()
            name = self.screen.getstr(height - 3, 48, 20).decode('utf-8')

            new_width = int(width_str) if width_str else 30
            new_height = int(height_str) if height_str else 10
            new_name = name.upper().replace(' ', '_') if name else "NEW_SPRITE"

            self.canvas = ArtCanvas(new_width, new_height, new_name)
            self.frames = [self.canvas]  # Reset to single frame
            self.current_frame = 0
            self.cursor_row = 0
            self.cursor_col = 0
            self.undo_manager = UndoManager()
            self.show_message(f"Created new canvas: {new_name} ({new_width}x{new_height})")

        except (ValueError, curses.error) as e:
            self.show_message(f"Invalid input: {e}", is_error=True)
        finally:
            curses.noecho()

    def _prompt_resize(self):
        """Prompt to resize canvas."""
        curses.echo()
        height, width = self.screen.getmaxyx()

        try:
            self.screen.addstr(height - 3, 0, f"Resize - Current: {self.canvas.width}x{self.canvas.height} New Width: ")
            self.screen.refresh()
            width_str = self.screen.getstr(height - 3, 50, 5).decode('utf-8')

            self.screen.addstr(height - 3, 56, " Height: ")
            self.screen.refresh()
            height_str = self.screen.getstr(height - 3, 65, 5).decode('utf-8')

            new_width = int(width_str) if width_str else self.canvas.width
            new_height = int(height_str) if height_str else self.canvas.height

            self.undo_manager.save_state(self.canvas.cells)
            self.canvas.resize(new_width, new_height)
            self.cursor_row = min(self.cursor_row, new_height - 1)
            self.cursor_col = min(self.cursor_col, new_width - 1)
            self.show_message(f"Resized to {new_width}x{new_height}")

        except (ValueError, curses.error) as e:
            self.show_message(f"Invalid input: {e}", is_error=True)
        finally:
            curses.noecho()

    # =========================================================================
    # Frame Management Methods for Animation Support
    # =========================================================================

    def _goto_previous_frame(self):
        """Navigate to the previous frame."""
        if len(self.frames) <= 1:
            self.show_message("Only one frame exists. Use Ctrl+F to add frames.")
            return

        # Save current frame state
        self.frames[self.current_frame] = self.canvas

        # Go to previous frame (wrap around)
        self.current_frame = (self.current_frame - 1) % len(self.frames)
        self.canvas = self.frames[self.current_frame]
        self.undo_manager = UndoManager()  # Reset undo for new frame

        # Clamp cursor to new canvas bounds
        self.cursor_row = min(self.cursor_row, self.canvas.height - 1)
        self.cursor_col = min(self.cursor_col, self.canvas.width - 1)

        self.show_message(f"Frame {self.current_frame + 1}/{len(self.frames)}")

    def _goto_next_frame(self):
        """Navigate to the next frame."""
        if len(self.frames) <= 1:
            self.show_message("Only one frame exists. Use Ctrl+F to add frames.")
            return

        # Save current frame state
        self.frames[self.current_frame] = self.canvas

        # Go to next frame (wrap around)
        self.current_frame = (self.current_frame + 1) % len(self.frames)
        self.canvas = self.frames[self.current_frame]
        self.undo_manager = UndoManager()  # Reset undo for new frame

        # Clamp cursor to new canvas bounds
        self.cursor_row = min(self.cursor_row, self.canvas.height - 1)
        self.cursor_col = min(self.cursor_col, self.canvas.width - 1)

        self.show_message(f"Frame {self.current_frame + 1}/{len(self.frames)}")

    def _add_frame(self):
        """Add a new frame (copy of current frame)."""
        # Save current frame state
        self.frames[self.current_frame] = self.canvas

        # Create a copy of the current frame
        new_frame = self.canvas.copy()

        # Insert the new frame after the current frame
        insert_pos = self.current_frame + 1
        self.frames.insert(insert_pos, new_frame)

        # Move to the new frame
        self.current_frame = insert_pos
        self.canvas = self.frames[self.current_frame]
        self.undo_manager = UndoManager()

        self.show_message(f"Added frame {self.current_frame + 1}/{len(self.frames)} (copy of previous)")

    def _delete_frame(self):
        """Delete the current frame."""
        if len(self.frames) <= 1:
            self.show_message("Cannot delete the only frame!", is_error=True)
            return

        # Remove current frame
        del self.frames[self.current_frame]

        # Adjust current frame index if needed
        if self.current_frame >= len(self.frames):
            self.current_frame = len(self.frames) - 1

        # Update canvas to the new current frame
        self.canvas = self.frames[self.current_frame]
        self.undo_manager = UndoManager()

        # Clamp cursor to new canvas bounds
        self.cursor_row = min(self.cursor_row, self.canvas.height - 1)
        self.cursor_col = min(self.cursor_col, self.canvas.width - 1)

        self.show_message(f"Deleted frame. Now at frame {self.current_frame + 1}/{len(self.frames)}")

    def _play_animation(self):
        """Play animation preview of all frames."""
        if len(self.frames) <= 1:
            self.show_message("Need at least 2 frames for animation. Use Ctrl+F to add frames.")
            return

        # Save current frame state
        self.frames[self.current_frame] = self.canvas
        original_frame = self.current_frame

        self.show_message("Playing animation... Press any key to stop")
        self.screen.refresh()

        # Play through frames
        self.animation_playing = True
        frame_delay = self.animation_speed / 1000.0  # Convert ms to seconds

        try:
            self.screen.nodelay(True)  # Non-blocking input
            cycles = 0
            max_cycles = 3  # Play 3 cycles then stop

            while self.animation_playing and cycles < max_cycles:
                for i in range(len(self.frames)):
                    # Check for key press to stop
                    key = self.screen.getch()
                    if key != -1:
                        self.animation_playing = False
                        break

                    # Show frame
                    self.current_frame = i
                    self.canvas = self.frames[i]
                    self.draw()

                    # Wait for frame delay
                    time.sleep(frame_delay)

                cycles += 1

        finally:
            self.screen.nodelay(False)
            self.animation_playing = False

        # Restore to original frame
        self.current_frame = original_frame
        self.canvas = self.frames[self.current_frame]
        self.show_message(f"Animation stopped. Frame {self.current_frame + 1}/{len(self.frames)}")

    def _resize_all_frames(self, new_width: int, new_height: int):
        """Resize all frames to the same dimensions."""
        for frame in self.frames:
            frame.resize(new_width, new_height)

        # Update current canvas reference
        self.canvas = self.frames[self.current_frame]

        # Clamp cursor
        self.cursor_row = min(self.cursor_row, new_height - 1)
        self.cursor_col = min(self.cursor_col, new_width - 1)

        self.show_message(f"All {len(self.frames)} frames resized to {new_width}x{new_height}")

    def run(self, screen):
        """Main editor loop."""
        self.screen = screen
        curses.curs_set(0)
        self.init_colors()
        screen.timeout(50)  # 50ms refresh

        while self.running:
            self.draw()

            try:
                key = screen.getch()
                if key != -1:
                    self.handle_input(key)
            except KeyboardInterrupt:
                self.running = False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='ASCII Art Editor for TUI Sprites')
    parser.add_argument('--load', '-l', type=str, help='Load a sprite by name')
    parser.add_argument('--new', '-n', type=str, help='Create new canvas with size WIDTHxHEIGHT (e.g., 20x10)')
    parser.add_argument('--name', type=str, default='NEW_SPRITE', help='Name for the sprite')
    parser.add_argument('--list', action='store_true', help='List available sprites and exit')

    args = parser.parse_args()

    # List sprites mode
    if args.list:
        lib = SpriteLibrary()
        print("Available sprites in dashboard.py:")
        print("-" * 40)
        for name in lib.list_sprites():
            sprite = lib.get_sprite(name)
            if sprite:
                print(f"  {name} ({len(sprite[0])}x{len(sprite)})")
        return

    if not CURSES_AVAILABLE:
        if sys.platform == 'win32':
            # Try to relaunch with Python 3.12
            if _try_relaunch_with_py312():
                return  # Successfully relaunched
            print("Error: curses library not available on Windows.")
            print("")
            print("windows-curses is not available for Python 3.14+.")
            print("")
            print("To use the Art Editor, install Python 3.12:")
            print("  1. Download from https://www.python.org/downloads/release/python-3120/")
            print("  2. Run: py -3.12 -m pip install windows-curses")
            print("  3. Re-run this command (it will auto-detect Python 3.12)")
        else:
            print("Error: curses library not available.")
        sys.exit(1)

    # Parse dimensions
    width, height = 30, 10
    if args.new:
        try:
            parts = args.new.lower().split('x')
            width = int(parts[0])
            height = int(parts[1]) if len(parts) > 1 else 10
        except (ValueError, IndexError):
            print(f"Invalid size format: {args.new}. Use WIDTHxHEIGHT (e.g., 20x10)")
            sys.exit(1)

    # Create editor
    editor = ArtEditor(width, height, args.name)

    # Load initial sprite if specified
    if args.load:
        if not editor.sprite_library.get_sprite(args.load):
            print(f"Warning: Sprite '{args.load}' not found. Starting with empty canvas.")
            print("Available sprites:", ', '.join(editor.sprite_library.list_sprites()[:10]), "...")

    def run_editor(screen):
        if args.load:
            editor.load_sprite(args.load)
        editor.run(screen)

    try:
        curses.wrapper(run_editor)
    except KeyboardInterrupt:
        pass

    print(f"\nExiting Art Editor. Sprite: {editor.canvas.name}")
    if len(editor.frames) == 1:
        print("\nFinal sprite content:")
        print("-" * 40)
        for line in editor.canvas.to_string_list():
            print(f'"{line}",')
        print("-" * 40)
    else:
        print(f"\nFinal animation content ({len(editor.frames)} frames):")
        print("-" * 40)
        for i, frame in enumerate(editor.frames):
            print(f"# Frame {i + 1}:")
            print("[")
            for line in frame.to_string_list():
                print(f'    "{line}",')
            print("],")
        print("-" * 40)


if __name__ == '__main__':
    main()
