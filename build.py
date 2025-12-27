#!/usr/bin/env python3
"""
Boundary Daemon Build Script

Cross-platform build script that compiles the daemon into a standalone executable
using PyInstaller. Works on Windows, Linux, and macOS.

Usage:
    python build.py [options]

Options:
    --onefile       Create a single executable (default)
    --onedir        Create a directory with executable and dependencies
    --debug         Include debug symbols
    --clean         Clean build artifacts before building
    --no-confirm    Don't ask for confirmation
"""

import os
import sys
import shutil
import subprocess
import argparse
from pathlib import Path


def check_python_version():
    """Ensure Python 3.8+ is being used."""
    if sys.version_info < (3, 8):
        print("ERROR: Python 3.8 or higher is required")
        sys.exit(1)
    print(f"Python version: {sys.version}")


def install_pyinstaller():
    """Install PyInstaller if not present."""
    try:
        import PyInstaller
        print(f"PyInstaller version: {PyInstaller.__version__}")
    except ImportError:
        print("Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])


def install_dependencies():
    """Install project dependencies."""
    requirements_file = Path("requirements.txt")
    if requirements_file.exists():
        print("Installing dependencies...")
        subprocess.call([sys.executable, "-m", "pip", "install", "-r", str(requirements_file)])


def clean_build():
    """Remove previous build artifacts."""
    print("Cleaning previous build artifacts...")
    for folder in ["build", "dist", "__pycache__"]:
        if os.path.exists(folder):
            shutil.rmtree(folder)

    # Remove .spec files
    for spec_file in Path(".").glob("*.spec"):
        spec_file.unlink()


def build_executable(onefile=True, debug=False, noconfirm=True):
    """Build the executable using PyInstaller."""
    print("\n" + "=" * 50)
    print("Building Boundary Daemon Executable")
    print("=" * 50 + "\n")

    # Determine platform-specific settings
    separator = ";" if sys.platform == "win32" else ":"
    app_name = "boundary-daemon"
    main_script = Path("daemon") / "boundary_daemon.py"

    if not main_script.exists():
        print(f"ERROR: Main script not found: {main_script}")
        sys.exit(1)

    # Build PyInstaller command
    cmd = [
        sys.executable, "-m", "PyInstaller",
        f"--name={app_name}",
        "--console",
        f"--add-data=daemon{separator}daemon",
        f"--add-data=api{separator}api",
        # Hidden imports for all monitoring modules
        "--hidden-import=daemon.memory_monitor",
        "--hidden-import=daemon.resource_monitor",
        "--hidden-import=daemon.health_monitor",
        "--hidden-import=daemon.queue_monitor",
        "--hidden-import=daemon.monitoring_report",
        "--hidden-import=daemon.event_logger",
        "--hidden-import=daemon.policy_engine",
        "--hidden-import=daemon.state_monitor",
        "--hidden-import=daemon.telemetry",
        "--hidden-import=daemon.auth.api_auth",
        "--hidden-import=api.boundary_api",
        "--collect-submodules=daemon",
        "--collect-submodules=api",
    ]

    if onefile:
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")

    if debug:
        cmd.append("--debug=all")

    if noconfirm:
        cmd.append("--noconfirm")

    cmd.append("--clean")
    cmd.append(str(main_script))

    print("Running:", " ".join(cmd))
    print()

    result = subprocess.run(cmd)
    return result.returncode == 0


def post_build():
    """Post-build tasks: copy configs, create run scripts."""
    dist_path = Path("dist")

    # Copy config directory if it exists
    config_src = Path("config")
    if config_src.exists():
        config_dst = dist_path / "config"
        if config_dst.exists():
            shutil.rmtree(config_dst)
        shutil.copytree(config_src, config_dst)
        print("Copied configuration files to dist/config")

    # Create platform-specific run script
    if sys.platform == "win32":
        run_script = dist_path / "run-daemon.bat"
        run_script.write_text(
            '@echo off\n'
            'echo Starting Boundary Daemon...\n'
            'boundary-daemon.exe %*\n'
            'pause\n'
        )
        print(f"Created {run_script}")
    else:
        run_script = dist_path / "run-daemon.sh"
        run_script.write_text(
            '#!/bin/bash\n'
            'echo "Starting Boundary Daemon..."\n'
            'DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n'
            '"$DIR/boundary-daemon" "$@"\n'
        )
        run_script.chmod(0o755)
        print(f"Created {run_script}")


def main():
    parser = argparse.ArgumentParser(description="Build Boundary Daemon executable")
    parser.add_argument("--onefile", action="store_true", default=True,
                        help="Create a single executable (default)")
    parser.add_argument("--onedir", action="store_true",
                        help="Create a directory with executable and dependencies")
    parser.add_argument("--debug", action="store_true",
                        help="Include debug symbols")
    parser.add_argument("--clean", action="store_true",
                        help="Clean build artifacts before building")
    parser.add_argument("--no-confirm", action="store_true", default=True,
                        help="Don't ask for confirmation")
    args = parser.parse_args()

    print("=" * 50)
    print("Boundary Daemon Build Script")
    print("=" * 50)
    print()

    # Pre-build checks
    check_python_version()
    install_pyinstaller()
    install_dependencies()

    if args.clean:
        clean_build()

    # Build
    onefile = not args.onedir
    success = build_executable(onefile=onefile, debug=args.debug, noconfirm=args.no_confirm)

    if success:
        post_build()
        print("\n" + "=" * 50)
        print("BUILD SUCCESSFUL!")
        print("=" * 50)

        exe_name = "boundary-daemon.exe" if sys.platform == "win32" else "boundary-daemon"
        print(f"\nExecutable: dist/{exe_name}")
        print("\nTo run:")
        print(f"  cd dist && ./{exe_name}")
    else:
        print("\n" + "=" * 50)
        print("BUILD FAILED!")
        print("=" * 50)
        sys.exit(1)


if __name__ == "__main__":
    main()
