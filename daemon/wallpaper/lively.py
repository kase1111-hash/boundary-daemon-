"""
Lively Wallpaper Integration

Integrates with Lively Wallpaper (https://github.com/rocksdanister/lively)
to run the Boundary Daemon Matrix dashboard as an animated desktop wallpaper.

Requirements:
    - Windows 10/11
    - Lively Wallpaper installed (free from Microsoft Store or GitHub)

Usage:
    boundaryctl wallpaper start   # Start dashboard as wallpaper
    boundaryctl wallpaper stop    # Stop wallpaper
    boundaryctl wallpaper status  # Check if running
"""

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class LivelyNotFoundError(Exception):
    """Raised when Lively Wallpaper is not installed."""
    pass


class LivelyWallpaper:
    """
    Integration with Lively Wallpaper for animated desktop wallpapers.

    Lively Wallpaper is a free, open-source tool that allows setting
    animated wallpapers on Windows. This class provides methods to:
    - Detect Lively installation
    - Create wallpaper configurations
    - Start/stop the dashboard as a wallpaper
    """

    # Common Lively installation paths
    LIVELY_PATHS = [
        # Microsoft Store installation
        Path(os.environ.get('LOCALAPPDATA', '')) / 'Lively Wallpaper',
        # GitHub/Installer installation
        Path(os.environ.get('PROGRAMFILES', '')) / 'Lively Wallpaper',
        Path(os.environ.get('PROGRAMFILES(X86)', '')) / 'Lively Wallpaper',
        # Portable installation
        Path.home() / 'Lively Wallpaper',
    ]

    # Lively command utility name
    LIVELY_CMD = 'livelycu.exe'
    LIVELY_EXE = 'Lively.exe'

    def __init__(self):
        self.lively_path: Optional[Path] = None
        self.lively_exe: Optional[Path] = None
        self.library_path: Optional[Path] = None
        self._detect_lively()

    def _detect_lively(self) -> None:
        """Detect Lively Wallpaper installation."""
        # First check if livelycu is in PATH
        livelycu = shutil.which('livelycu')
        if livelycu:
            self.lively_exe = Path(livelycu)
            self.lively_path = self.lively_exe.parent
            self.library_path = self._find_library()
            return

        # Check common installation paths
        for path in self.LIVELY_PATHS:
            if not path.exists():
                continue

            # Look for Lively.exe or livelycu.exe
            exe_path = path / self.LIVELY_EXE
            cmd_path = path / self.LIVELY_CMD

            if cmd_path.exists():
                self.lively_exe = cmd_path
                self.lively_path = path
                self.library_path = self._find_library()
                return
            elif exe_path.exists():
                self.lively_exe = exe_path
                self.lively_path = path
                self.library_path = self._find_library()
                return

    def _find_library(self) -> Optional[Path]:
        """Find Lively wallpaper library path."""
        # Library is typically in AppData
        library = Path(os.environ.get('LOCALAPPDATA', '')) / 'Lively Wallpaper' / 'Library' / 'wallpapers'
        if library.exists():
            return library

        # Or relative to installation
        if self.lively_path:
            library = self.lively_path / 'Library' / 'wallpapers'
            if library.exists():
                return library

        return None

    @property
    def is_installed(self) -> bool:
        """Check if Lively is installed."""
        return self.lively_exe is not None and self.lively_exe.exists()

    def _run_command(self, *args, timeout: int = 30) -> subprocess.CompletedProcess:
        """Run a Lively command."""
        if not self.is_installed:
            raise LivelyNotFoundError(
                "Lively Wallpaper not found. Install from:\n"
                "  - Microsoft Store: https://apps.microsoft.com/detail/9NTM2QC6QWS7\n"
                "  - GitHub: https://github.com/rocksdanister/lively/releases"
            )

        cmd = [str(self.lively_exe)] + list(args)
        logger.debug(f"Running Lively command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            return result
        except subprocess.TimeoutExpired:
            logger.error(f"Lively command timed out: {cmd}")
            raise
        except Exception as e:
            logger.error(f"Lively command failed: {e}")
            raise

    def create_wallpaper_config(self, output_dir: Path) -> Path:
        """
        Create a Lively wallpaper configuration for the dashboard.

        This creates a minimal web-based wallpaper that launches
        the terminal dashboard in matrix mode.

        Args:
            output_dir: Directory to create wallpaper config in

        Returns:
            Path to the created wallpaper directory
        """
        wallpaper_dir = output_dir / 'BoundaryDaemonMatrix'
        wallpaper_dir.mkdir(parents=True, exist_ok=True)

        # Create LivelyInfo.json (wallpaper metadata)
        lively_info = {
            "AppVersion": "2.0.0.0",
            "Title": "Boundary Daemon Matrix",
            "Desc": "Cyberpunk Matrix dashboard with rain, buildings, and security events",
            "Author": "Boundary Daemon",
            "License": "",
            "Type": 1,  # 1 = Application
            "FileName": "launch.bat",
            "Arguments": "",
            "IsAbsolutePath": False,
            "Preview": "preview.gif",
            "Thumbnail": "thumbnail.png"
        }

        with open(wallpaper_dir / 'LivelyInfo.json', 'w') as f:
            json.dump(lively_info, f, indent=2)

        # Create launcher batch script
        # Find boundaryctl path
        boundaryctl_path = self._find_boundaryctl()

        launcher_script = f'''@echo off
REM Boundary Daemon Matrix Wallpaper Launcher
REM This script is called by Lively Wallpaper

cd /d "%~dp0"

REM Use Python module execution for reliability
python -m daemon.tui.dashboard --matrix

REM Fallback to boundaryctl if available
if errorlevel 1 (
    if exist "{boundaryctl_path}" (
        "{boundaryctl_path}" dashboard --matrix
    ) else (
        boundaryctl dashboard --matrix
    )
)

REM Keep window open on error for debugging
if errorlevel 1 pause
'''

        with open(wallpaper_dir / 'launch.bat', 'w') as f:
            f.write(launcher_script)

        # Create a simple preview placeholder
        self._create_preview_placeholder(wallpaper_dir)

        logger.info(f"Created wallpaper config at: {wallpaper_dir}")
        return wallpaper_dir

    def _find_boundaryctl(self) -> str:
        """Find the boundaryctl executable path."""
        # Check if in PATH
        boundaryctl = shutil.which('boundaryctl')
        if boundaryctl:
            return boundaryctl

        # Check common locations
        possible_paths = [
            Path(sys.prefix) / 'Scripts' / 'boundaryctl.exe',
            Path(sys.prefix) / 'bin' / 'boundaryctl',
            Path.home() / '.local' / 'bin' / 'boundaryctl',
        ]

        for path in possible_paths:
            if path.exists():
                return str(path)

        return 'boundaryctl'  # Hope it's in PATH

    def _create_preview_placeholder(self, wallpaper_dir: Path) -> None:
        """Create placeholder preview files."""
        # Create a minimal 1x1 PNG (placeholder)
        # This is a valid 1x1 black PNG
        png_data = bytes([
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # PNG signature
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,  # IHDR chunk
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,  # 1x1
            0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
            0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,  # IDAT chunk
            0x54, 0x08, 0xD7, 0x63, 0x60, 0x60, 0x60, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x01, 0x27, 0x34, 0x27,
            0x0A, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,  # IEND chunk
            0x44, 0xAE, 0x42, 0x60, 0x82
        ])

        with open(wallpaper_dir / 'thumbnail.png', 'wb') as f:
            f.write(png_data)

        with open(wallpaper_dir / 'preview.gif', 'wb') as f:
            f.write(png_data)  # GIF will just show as broken, that's fine

    def install_wallpaper(self) -> Path:
        """
        Install the dashboard wallpaper to Lively library.

        Returns:
            Path to installed wallpaper directory
        """
        if not self.library_path:
            # Create in temp and let Lively import it
            temp_dir = Path(tempfile.gettempdir()) / 'boundary-daemon-wallpaper'
            temp_dir.mkdir(exist_ok=True)
            return self.create_wallpaper_config(temp_dir)

        return self.create_wallpaper_config(self.library_path)

    def start(self, monitor: int = 0) -> bool:
        """
        Start the dashboard as a wallpaper.

        Args:
            monitor: Monitor index (0 = primary, -1 = all)

        Returns:
            True if started successfully
        """
        if not self.is_installed:
            raise LivelyNotFoundError(
                "Lively Wallpaper not found. Install from:\n"
                "  - Microsoft Store: https://apps.microsoft.com/detail/9NTM2QC6QWS7\n"
                "  - GitHub: https://github.com/rocksdanister/lively/releases"
            )

        # Install/update wallpaper config
        wallpaper_path = self.install_wallpaper()

        # Start Lively if not running
        self._ensure_lively_running()

        # Set the wallpaper
        result = self._run_command(
            'setwp',
            '--file', str(wallpaper_path),
            '--monitor', str(monitor)
        )

        if result.returncode != 0:
            logger.error(f"Failed to set wallpaper: {result.stderr}")
            return False

        logger.info("Dashboard wallpaper started successfully")
        return True

    def stop(self, monitor: int = -1) -> bool:
        """
        Stop the wallpaper.

        Args:
            monitor: Monitor index (-1 = all monitors)

        Returns:
            True if stopped successfully
        """
        if not self.is_installed:
            return True  # Nothing to stop

        result = self._run_command(
            'closewp',
            '--monitor', str(monitor)
        )

        return result.returncode == 0

    def pause(self) -> bool:
        """Pause wallpaper playback."""
        if not self.is_installed:
            return False

        result = self._run_command('--play', 'false')
        return result.returncode == 0

    def resume(self) -> bool:
        """Resume wallpaper playback."""
        if not self.is_installed:
            return False

        result = self._run_command('--play', 'true')
        return result.returncode == 0

    def set_volume(self, volume: int) -> bool:
        """
        Set wallpaper audio volume.

        Args:
            volume: Volume level 0-100
        """
        if not self.is_installed:
            return False

        volume = max(0, min(100, volume))
        result = self._run_command('--volume', str(volume))
        return result.returncode == 0

    def _ensure_lively_running(self) -> None:
        """Ensure Lively application is running."""
        # Try to show app (will start it if not running)
        try:
            self._run_command('--showApp', 'true', timeout=10)
            time.sleep(1)  # Give it time to start
            # Minimize it back
            self._run_command('--showApp', 'false', timeout=5)
        except Exception as e:
            logger.warning(f"Could not ensure Lively is running: {e}")

    def get_status(self) -> Dict[str, Any]:
        """
        Get wallpaper status information.

        Returns:
            Status dictionary with installation and running state
        """
        return {
            'installed': self.is_installed,
            'lively_path': str(self.lively_path) if self.lively_path else None,
            'library_path': str(self.library_path) if self.library_path else None,
            'platform': sys.platform,
            'supported': sys.platform == 'win32',
        }


def check_lively_installation() -> bool:
    """Quick check if Lively is available."""
    try:
        lively = LivelyWallpaper()
        return lively.is_installed
    except Exception:
        return False
