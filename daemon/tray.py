#!/usr/bin/env python3
"""
System Tray Integration for Boundary Daemon

Provides system tray icon with menu for controlling the daemon.
Supports minimize-to-tray on Windows.

Requires: pystray, Pillow
    pip install pystray Pillow
"""

import logging
import os
import sys
import threading
from pathlib import Path
from typing import Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .boundary_daemon import BoundaryDaemon

from .policy_engine import Operator

logger = logging.getLogger(__name__)

# Check for required dependencies
try:
    import pystray
    from pystray import MenuItem as Item
    HAS_PYSTRAY = True
except ImportError:
    HAS_PYSTRAY = False
    pystray = None
    Item = None

try:
    from PIL import Image, ImageDraw
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    Image = None
    ImageDraw = None

# Windows-specific imports for console hiding
IS_WINDOWS = os.name == 'nt'
if IS_WINDOWS:
    try:
        import ctypes
        from ctypes import wintypes  # noqa: F401
        HAS_CTYPES = True
    except ImportError:
        HAS_CTYPES = False
        ctypes = None
else:
    HAS_CTYPES = False
    ctypes = None


class WindowsConsoleManager:
    """Manages Windows console window visibility and intercepts close/minimize."""

    SW_HIDE = 0
    SW_SHOW = 5
    SW_MINIMIZE = 6
    SW_RESTORE = 9

    # Console control signals
    CTRL_C_EVENT = 0
    CTRL_BREAK_EVENT = 1
    CTRL_CLOSE_EVENT = 2
    CTRL_LOGOFF_EVENT = 5
    CTRL_SHUTDOWN_EVENT = 6

    def __init__(self):
        self._hwnd = None
        self._visible = True
        self._close_callback = None
        self._handler_set = False
        if IS_WINDOWS and HAS_CTYPES:
            self._kernel32 = ctypes.windll.kernel32
            self._user32 = ctypes.windll.user32
            self._hwnd = self._kernel32.GetConsoleWindow()

    @property
    def is_available(self) -> bool:
        """Check if console management is available."""
        return IS_WINDOWS and HAS_CTYPES and self._hwnd is not None

    def hide(self) -> bool:
        """Hide the console window."""
        if not self.is_available:
            return False
        try:
            self._user32.ShowWindow(self._hwnd, self.SW_HIDE)
            self._visible = False
            return True
        except Exception as e:
            logger.debug(f"Failed to hide console: {e}")
            return False

    def show(self) -> bool:
        """Show the console window."""
        if not self.is_available:
            return False
        try:
            self._user32.ShowWindow(self._hwnd, self.SW_SHOW)
            self._user32.SetForegroundWindow(self._hwnd)
            self._visible = True
            return True
        except Exception as e:
            logger.debug(f"Failed to show console: {e}")
            return False

    def minimize(self) -> bool:
        """Minimize the console window."""
        if not self.is_available:
            return False
        try:
            self._user32.ShowWindow(self._hwnd, self.SW_MINIMIZE)
            return True
        except Exception as e:
            logger.debug(f"Failed to minimize console: {e}")
            return False

    def is_visible(self) -> bool:
        """Check if console is currently visible."""
        return self._visible

    def toggle(self) -> bool:
        """Toggle console visibility."""
        if self._visible:
            return self.hide()
        else:
            return self.show()

    def set_close_handler(self, callback: Callable) -> bool:
        """
        Set a handler for console close events.
        When X button is clicked, callback is called and window hides instead of closing.

        Args:
            callback: Function to call on close event

        Returns:
            True if handler was set successfully
        """
        if not self.is_available or self._handler_set:
            return False

        self._close_callback = callback

        # Define the handler function type
        HANDLER_TYPE = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_ulong)

        def console_handler(ctrl_type):
            """Handle console control events."""
            if ctrl_type == self.CTRL_CLOSE_EVENT:
                # User clicked X - hide to tray instead of closing
                self.hide()
                if self._close_callback:
                    self._close_callback()
                return True  # Handled - don't close
            elif ctrl_type in (self.CTRL_C_EVENT, self.CTRL_BREAK_EVENT):
                # Ctrl+C or Ctrl+Break - let them through for graceful shutdown
                return False
            elif ctrl_type in (self.CTRL_LOGOFF_EVENT, self.CTRL_SHUTDOWN_EVENT):
                # System logoff/shutdown - allow it
                return False
            return False

        # Store reference to prevent garbage collection
        self._handler = HANDLER_TYPE(console_handler)

        try:
            # Set the console control handler
            result = self._kernel32.SetConsoleCtrlHandler(self._handler, True)
            if result:
                self._handler_set = True
                logger.debug("Console close handler installed")
                return True
            else:
                logger.debug("Failed to set console control handler")
                return False
        except Exception as e:
            logger.debug(f"Error setting console handler: {e}")
            return False

    def disable_close_button(self) -> bool:
        """
        Disable the close button on the console window.
        User must use tray menu to exit.

        Returns:
            True if successful
        """
        if not self.is_available:
            return False

        try:
            # Get system menu handle
            GWL_STYLE = -16
            WS_SYSMENU = 0x80000

            # Remove close button from system menu
            SC_CLOSE = 0xF060
            MF_BYCOMMAND = 0x00000000
            MF_GRAYED = 0x00000001

            hmenu = self._user32.GetSystemMenu(self._hwnd, False)
            if hmenu:
                self._user32.EnableMenuItem(hmenu, SC_CLOSE, MF_BYCOMMAND | MF_GRAYED)
                return True
        except Exception as e:
            logger.debug(f"Failed to disable close button: {e}")
        return False


class TrayIcon:
    """
    System tray icon for Boundary Daemon.

    Provides:
    - Tray icon with current mode indicator
    - Right-click menu for mode switching
    - Show/Hide console toggle
    - Exit option
    """

    def __init__(
        self,
        daemon: Optional['BoundaryDaemon'] = None,
        on_exit: Optional[Callable] = None,
        auto_hide: bool = True,
    ):
        """
        Initialize tray icon.

        Args:
            daemon: BoundaryDaemon instance for mode control
            on_exit: Callback when exit is selected
            auto_hide: Auto-hide console on startup (Windows only)
        """
        self.daemon = daemon
        self._on_exit = on_exit
        self._auto_hide = auto_hide
        self._icon: Optional[pystray.Icon] = None
        self._console = WindowsConsoleManager()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    @property
    def is_available(self) -> bool:
        """Check if tray icon support is available."""
        return HAS_PYSTRAY and HAS_PIL

    def _get_icon_path(self, name: str) -> Optional[Path]:
        """Get path to an icon file."""
        # Try different locations
        locations = [
            Path(__file__).parent.parent / 'assets' / name,
            Path(__file__).parent / 'assets' / name,
            Path.cwd() / 'assets' / name,
        ]
        for loc in locations:
            if loc.exists():
                return loc
        return None

    def _create_default_icon(self, size: int = 64) -> 'Image':
        """Create a simple default icon if no icon file is found."""
        img = Image.new('RGB', (size, size), 'white')
        draw = ImageDraw.Draw(img)

        # Draw a simple boundary symbol
        margin = size // 8
        draw.rectangle(
            [margin, margin, size - margin, size - margin],
            outline='black',
            width=max(2, size // 16)
        )

        # Draw inner circle (eye)
        inner_margin = size // 4
        draw.ellipse(
            [inner_margin, inner_margin, size - inner_margin, size - inner_margin],
            outline='black',
            width=max(2, size // 16)
        )

        # Draw pupil
        center = size // 2
        pupil_size = size // 8
        draw.ellipse(
            [center - pupil_size, center - pupil_size,
             center + pupil_size, center + pupil_size],
            fill='black'
        )

        return img

    def _load_icon(self) -> 'Image':
        """Load the appropriate icon for current state."""
        icon_name = 'icon.ico'

        # Try to get mode-specific icon
        if self.daemon:
            try:
                mode = self.daemon.get_current_mode()
                mode_icon = f'tray_{mode.name}.ico'
                icon_path = self._get_icon_path(mode_icon)
                if icon_path:
                    return Image.open(icon_path)
            except Exception:
                pass

        # Try main icon
        icon_path = self._get_icon_path(icon_name)
        if icon_path:
            try:
                return Image.open(icon_path)
            except Exception as e:
                logger.debug(f"Failed to load icon: {e}")

        # Fall back to generated icon
        return self._create_default_icon()

    def _get_mode_name(self) -> str:
        """Get current mode name for display."""
        if self.daemon:
            try:
                mode = self.daemon.policy_engine.get_current_mode()
                return mode.name
            except Exception:
                pass
        return "UNKNOWN"

    def _create_menu(self) -> pystray.Menu:
        """Create the tray icon menu."""
        from .boundary_daemon import BoundaryMode

        def make_mode_action(mode):
            def action(icon, item):
                if self.daemon:
                    try:
                        # Use the proper request_mode_change method with HUMAN operator
                        success, message = self.daemon.request_mode_change(
                            mode, Operator.HUMAN, "Changed via system tray"
                        )
                        if success:
                            self._update_icon()
                        else:
                            logger.warning(f"Mode change denied: {message}")
                    except Exception as e:
                        logger.error(f"Failed to set mode: {e}")
            return action

        def is_current_mode(mode):
            def check(item):
                if self.daemon:
                    try:
                        # Get mode from policy engine
                        return self.daemon.policy_engine.get_current_mode() == mode
                    except Exception:
                        pass
                return False
            return check

        # Build menu items
        menu_items = [
            Item(
                f'Boundary Daemon - {self._get_mode_name()}',
                None,
                enabled=False
            ),
            pystray.Menu.SEPARATOR,
        ]

        # Mode selection submenu
        mode_items = []
        for mode in BoundaryMode:
            mode_items.append(
                Item(
                    mode.name,
                    make_mode_action(mode),
                    checked=is_current_mode(mode),
                    radio=True
                )
            )

        menu_items.append(
            Item('Mode', pystray.Menu(*mode_items))
        )

        menu_items.append(pystray.Menu.SEPARATOR)

        # Console visibility toggle (Windows only)
        if self._console.is_available:
            menu_items.append(
                Item(
                    'Show Console',
                    self._on_toggle_console,
                    checked=lambda item: self._console.is_visible()
                )
            )
            menu_items.append(pystray.Menu.SEPARATOR)

        # Exit
        menu_items.append(Item('Exit', self._on_exit_clicked))

        return pystray.Menu(*menu_items)

    def _on_toggle_console(self, icon, item):
        """Toggle console visibility."""
        self._console.toggle()

    def _on_exit_clicked(self, icon, item):
        """Handle exit menu click."""
        self.stop()
        if self._on_exit:
            self._on_exit()

    def _update_icon(self):
        """Update the tray icon image."""
        if self._icon:
            try:
                self._icon.icon = self._load_icon()
                self._icon.title = f"Boundary Daemon - {self._get_mode_name()}"
            except Exception as e:
                logger.debug(f"Failed to update icon: {e}")

    def _on_icon_clicked(self, icon, item):
        """Handle icon double-click (show console)."""
        if self._console.is_available:
            self._console.show()

    def _on_console_close(self):
        """Called when user clicks X button on console - minimize to tray."""
        logger.info("Console minimized to system tray (right-click tray icon to exit)")

    def _run_icon(self):
        """Run the tray icon (called in separate thread)."""
        try:
            self._icon = pystray.Icon(
                'boundary-daemon',
                self._load_icon(),
                f"Boundary Daemon - {self._get_mode_name()}",
                menu=self._create_menu()
            )

            # Set up default action (double-click)
            self._icon.default_action = self._on_icon_clicked

            # Set up close button handler (X button hides to tray)
            if self._console.is_available:
                self._console.set_close_handler(self._on_console_close)

            # Auto-hide console if requested
            if self._auto_hide and self._console.is_available:
                # Small delay to let the console show startup messages
                threading.Timer(1.0, self._console.hide).start()

            # Run the icon (blocks until stopped)
            self._icon.run()

        except Exception as e:
            logger.error(f"Tray icon error: {e}")
            self._running = False

    def start(self) -> bool:
        """
        Start the tray icon.

        Returns:
            True if started successfully
        """
        if not self.is_available:
            logger.warning("System tray not available (install pystray and Pillow)")
            return False

        if self._running:
            return True

        self._running = True
        self._thread = threading.Thread(target=self._run_icon, daemon=True)
        self._thread.start()

        logger.info("System tray icon started")
        return True

    def stop(self):
        """Stop the tray icon."""
        self._running = False

        # Show console before exiting
        if self._console.is_available:
            self._console.show()

        if self._icon:
            try:
                self._icon.stop()
            except Exception:
                pass
            self._icon = None

        logger.info("System tray icon stopped")

    def update_mode(self):
        """Update icon when mode changes."""
        self._update_icon()


def create_tray_icon(
    daemon: Optional['BoundaryDaemon'] = None,
    on_exit: Optional[Callable] = None,
    auto_hide: bool = True,
) -> Optional[TrayIcon]:
    """
    Create and start a tray icon.

    Args:
        daemon: BoundaryDaemon instance
        on_exit: Callback when exit is selected
        auto_hide: Auto-hide console on startup

    Returns:
        TrayIcon instance or None if not available
    """
    tray = TrayIcon(daemon=daemon, on_exit=on_exit, auto_hide=auto_hide)

    if not tray.is_available:
        logger.warning(
            "System tray requires pystray and Pillow. "
            "Install with: pip install pystray Pillow"
        )
        return None

    if tray.start():
        return tray

    return None


if __name__ == '__main__':
    # Test the tray icon standalone
    import time

    print("Testing tray icon...")
    print("Right-click the tray icon for menu")
    print("Press Ctrl+C to exit")

    def on_exit():
        print("Exit requested")
        sys.exit(0)

    tray = create_tray_icon(on_exit=on_exit, auto_hide=False)

    if tray:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            tray.stop()
    else:
        print("Tray icon not available")
        print("Install requirements: pip install pystray Pillow")
