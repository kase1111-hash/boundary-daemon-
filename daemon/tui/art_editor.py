#!/usr/bin/env python3
"""
ASCII Art Editor - Standalone tool for creating and editing TUI sprites

Features:
- Create new ASCII art with labels
- Load and modify existing sprites from dashboard.py
- Draw with keyboard (characters, lines, boxes)
- Color support with preview
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
    Tab         - Cycle colors
    F1          - Help
    Escape/Q    - Quit
"""

import argparse
import curses
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

# Handle curses import for Windows
try:
    import curses
    CURSES_AVAILABLE = True
except ImportError:
    curses = None
    CURSES_AVAILABLE = False


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

    # Color definitions (matching dashboard.py Colors class)
    COLORS = [
        ("Default", curses.COLOR_WHITE, curses.COLOR_BLACK),
        ("Red", curses.COLOR_RED, curses.COLOR_BLACK),
        ("Green", curses.COLOR_GREEN, curses.COLOR_BLACK),
        ("Yellow", curses.COLOR_YELLOW, curses.COLOR_BLACK),
        ("Blue", curses.COLOR_BLUE, curses.COLOR_BLACK),
        ("Magenta", curses.COLOR_MAGENTA, curses.COLOR_BLACK),
        ("Cyan", curses.COLOR_CYAN, curses.COLOR_BLACK),
        ("White Bold", curses.COLOR_WHITE, curses.COLOR_BLACK),
    ]

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

        # UI layout
        self.canvas_offset_y = 3
        self.canvas_offset_x = 2

    def init_colors(self):
        """Initialize color pairs."""
        curses.start_color()
        curses.use_default_colors()

        for i, (name, fg, bg) in enumerate(self.COLORS):
            try:
                curses.init_pair(i + 1, fg, bg)
            except curses.error:
                pass

        # Special colors for UI
        curses.init_pair(20, curses.COLOR_BLACK, curses.COLOR_WHITE)  # Cursor
        curses.init_pair(21, curses.COLOR_WHITE, curses.COLOR_BLUE)   # Header
        curses.init_pair(22, curses.COLOR_YELLOW, curses.COLOR_BLACK) # Status
        curses.init_pair(23, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Success
        curses.init_pair(24, curses.COLOR_RED, curses.COLOR_BLACK)    # Error

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
        """Export canvas as Python code."""
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
        return code

    def save_to_file(self, filename: str = None):
        """Save sprite to a file."""
        if not filename:
            filename = f"{self.canvas.name.lower()}.txt"

        # Save as plain text
        try:
            with open(filename, 'w') as f:
                for line in self.canvas.to_string_list():
                    f.write(line + '\n')
            self.show_message(f"Saved to {filename}")
            return True
        except Exception as e:
            self.show_message(f"Save failed: {e}", is_error=True)
            return False

    def save_python_snippet(self, filename: str = None):
        """Save as Python code snippet."""
        if not filename:
            filename = f"{self.canvas.name.lower()}_sprite.py"

        try:
            code = self.export_to_python()
            with open(filename, 'w') as f:
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

        # Header
        header = f" ART EDITOR - {self.canvas.name} ({self.canvas.width}x{self.canvas.height}) "
        header += f"| Color: {self.COLORS[self.current_color][0]} "
        header += f"| Mode: {self.drawing_mode.upper()} "
        header = header.ljust(width - 1)

        try:
            self.screen.attron(curses.color_pair(21) | curses.A_BOLD)
            self.screen.addstr(0, 0, header[:width-1])
            self.screen.attroff(curses.color_pair(21) | curses.A_BOLD)
        except curses.error:
            pass

        # Shortcuts bar
        shortcuts = "[Arrows]Move [Space]Clear [Tab]Color [Ctrl+S]Save [Ctrl+L]Load [Ctrl+N]New [F1]Help [Q]Quit"
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

        # Draw canvas content
        for row in range(self.canvas.height):
            for col in range(self.canvas.width):
                cell = self.canvas.get(row, col)
                y = self.canvas_offset_y + row
                x = self.canvas_offset_x + col

                if y >= height - 2 or x >= width - 1:
                    continue

                try:
                    # Highlight cursor position
                    if row == self.cursor_row and col == self.cursor_col:
                        attr = curses.color_pair(20) | curses.A_REVERSE
                    elif cell.color > 0:
                        attr = curses.color_pair(cell.color)
                    else:
                        attr = curses.A_NORMAL

                    char = cell.char if cell.char else ' '
                    self.screen.addstr(y, x, char, attr)
                except curses.error:
                    pass

        # Draw cursor position indicator
        pos_info = f"Cursor: ({self.cursor_row}, {self.cursor_col})"
        try:
            self.screen.addstr(canvas_bottom + 1, self.canvas_offset_x, pos_info)
        except curses.error:
            pass

        # Draw color palette
        palette_y = canvas_bottom + 2
        if palette_y < height - 1:
            try:
                self.screen.addstr(palette_y, self.canvas_offset_x, "Colors: ")
                for i, (name, _, _) in enumerate(self.COLORS):
                    marker = "█" if i == self.current_color else "▪"
                    attr = curses.color_pair(i + 1)
                    if i == self.current_color:
                        attr |= curses.A_BOLD
                    self.screen.addstr(marker, attr)
                    self.screen.addstr(" ")
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

    def _draw_help_overlay(self):
        """Draw help overlay."""
        height, width = self.screen.getmaxyx()

        help_text = [
            "╔══════════════════════════════════════════════════════════╗",
            "║                    ART EDITOR HELP                       ║",
            "╠══════════════════════════════════════════════════════════╣",
            "║  Navigation:                                             ║",
            "║    Arrow Keys    - Move cursor                           ║",
            "║    Home/End      - Start/end of row                      ║",
            "║    PgUp/PgDn     - Top/bottom of canvas                  ║",
            "║                                                          ║",
            "║  Drawing:                                                ║",
            "║    Any character - Draw at cursor                        ║",
            "║    Space         - Clear cell                            ║",
            "║    Tab           - Cycle through colors                  ║",
            "║    Backspace     - Clear and move left                   ║",
            "║                                                          ║",
            "║  File Operations:                                        ║",
            "║    Ctrl+S        - Save to file                          ║",
            "║    Ctrl+P        - Save as Python code                   ║",
            "║    Ctrl+L        - Load sprite from library              ║",
            "║    Ctrl+N        - New canvas                            ║",
            "║                                                          ║",
            "║  Edit:                                                   ║",
            "║    Ctrl+Z        - Undo                                  ║",
            "║    Ctrl+Y        - Redo                                  ║",
            "║    Ctrl+R        - Resize canvas                         ║",
            "║                                                          ║",
            "║  Other:                                                  ║",
            "║    F1            - Toggle this help                      ║",
            "║    Q / Escape    - Quit                                  ║",
            "╚══════════════════════════════════════════════════════════╝",
            "                  Press any key to close                    ",
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
                self.show_message("Undo")
            else:
                self.show_message("Nothing to undo", is_error=True)
        elif key == 25:  # Ctrl+Y
            result = self.undo_manager.redo(self.canvas.cells)
            if result:
                self.canvas.cells = result
                self.show_message("Redo")
            else:
                self.show_message("Nothing to redo", is_error=True)
        elif key == 18:  # Ctrl+R
            self._prompt_resize()

        # Tab - cycle colors
        elif key == ord('\t'):
            self.current_color = (self.current_color + 1) % len(self.COLORS)
            self.show_message(f"Color: {self.COLORS[self.current_color][0]}")

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
        print("Error: curses library not available.")
        if sys.platform == 'win32':
            print("Try: pip install windows-curses")
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
    print("\nFinal sprite content:")
    print("-" * 40)
    for line in editor.canvas.to_string_list():
        print(f'"{line}",')
    print("-" * 40)


if __name__ == '__main__':
    main()
