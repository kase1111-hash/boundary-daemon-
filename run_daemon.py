#!/usr/bin/env python3
"""
Boundary Daemon Entry Point

This script serves as the main entry point for both:
- Running as a module: python -m daemon.boundary_daemon
- Running as a standalone executable: boundary-daemon.exe

It handles the import path setup required for PyInstaller builds.
"""

import sys
import os
import subprocess
import threading
import time

def setup_path():
    """Setup Python path for standalone execution."""
    # Get the directory where this script is located
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        base_path = sys._MEIPASS
    else:
        # Running as script
        base_path = os.path.dirname(os.path.abspath(__file__))

    # Add base path to sys.path if not already there
    if base_path not in sys.path:
        sys.path.insert(0, base_path)

    # Also add parent directory for local development
    parent_path = os.path.dirname(base_path)
    if parent_path not in sys.path:
        sys.path.insert(0, parent_path)


def handle_service_command(args) -> None:
    """Handle Linux service management commands."""
    if sys.platform != 'linux':
        print("Error: Service management is only supported on Linux.")
        print("For macOS, use launchd. For Windows, use Task Scheduler.")
        sys.exit(1)

    # Get the path to the setup script
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))

    setup_script = os.path.join(base_path, 'scripts', 'setup-linux-boot.py')

    if not os.path.exists(setup_script):
        print(f"Error: Setup script not found: {setup_script}")
        sys.exit(1)

    # Build the command
    if args.install_service:
        cmd = [sys.executable, setup_script, '--enable']
    elif args.remove_service:
        cmd = [sys.executable, setup_script, '--uninstall']
    elif args.service_status:
        cmd = [sys.executable, setup_script, '--status']
    else:
        return

    # Run the setup script
    try:
        result = subprocess.run(cmd)
        sys.exit(result.returncode)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"Error running setup script: {e}")
        sys.exit(1)


def main():
    """Main entry point."""
    setup_path()

    # Now import and run the daemon
    try:
        from daemon.boundary_daemon import BoundaryDaemon, BoundaryMode
    except ImportError as e:
        print(f"Import error: {e}")
        print("Attempting alternative import...")
        try:
            # Try direct import for frozen executable
            import daemon.boundary_daemon as bd
            BoundaryDaemon = bd.BoundaryDaemon
            BoundaryMode = bd.BoundaryMode
        except ImportError as e2:
            print(f"Failed to import daemon: {e2}")
            sys.exit(1)

    import argparse

    parser = argparse.ArgumentParser(description='Boundary Daemon - Trust Boundary Enforcement')
    parser.add_argument('--mode', choices=['open', 'restricted', 'trusted', 'airgap', 'coldroom', 'lockdown'],
                        default='open', help='Initial boundary mode')
    parser.add_argument('--log-dir', default='./logs', help='Directory for log files')
    parser.add_argument('--skip-integrity-check', action='store_true',
                        help='Skip integrity verification (DANGEROUS - dev only)')
    parser.add_argument('--tray', action='store_true', default=(os.name == 'nt'),
                        help='Enable system tray icon (default on Windows)')
    parser.add_argument('--no-tray', action='store_true',
                        help='Disable system tray icon')
    parser.add_argument('--no-auto-hide', action='store_true',
                        help='Do not auto-hide console when using --tray')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('--trace', '-t', action='store_true',
                        help='Enable trace logging (ultra-verbose)')
    parser.add_argument('--log-json', action='store_true',
                        help='Output logs in JSON format')
    parser.add_argument('--log-file', type=str,
                        help='Additional log file path for detailed logging')

    # Linux service management options
    service_group = parser.add_argument_group('Linux Service Management')
    service_group.add_argument('--install-service', action='store_true',
                               help='Install and enable systemd service for boot startup (Linux only, requires root)')
    service_group.add_argument('--remove-service', action='store_true',
                               help='Remove systemd service (Linux only, requires root)')
    service_group.add_argument('--service-status', action='store_true',
                               help='Show systemd service status (Linux only)')

    args = parser.parse_args()

    # Handle service management commands (Linux only)
    if args.install_service or args.remove_service or args.service_status:
        handle_service_command(args)
        sys.exit(0)

    # Setup enhanced logging if available
    try:
        from daemon.logging_config import setup_logging
        setup_logging(
            verbose=args.verbose,
            trace=args.trace,
            log_file=args.log_file,
            console=True,
            json_format=args.log_json,
        )
        if args.verbose:
            print("Verbose logging enabled")
        if args.trace:
            print("Trace logging enabled (ultra-verbose)")
    except ImportError:
        # Enhanced logging not available, use basic setup
        import logging
        level = logging.DEBUG if args.verbose or args.trace else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s %(levelname)s [%(name)s] %(message)s'
        )

    # Parse mode
    mode_map = {
        'open': BoundaryMode.OPEN,
        'restricted': BoundaryMode.RESTRICTED,
        'trusted': BoundaryMode.TRUSTED,
        'airgap': BoundaryMode.AIRGAP,
        'coldroom': BoundaryMode.COLDROOM,
        'lockdown': BoundaryMode.LOCKDOWN,
    }
    initial_mode = mode_map.get(args.mode, BoundaryMode.OPEN)

    # Create and run daemon
    print("=" * 70)
    print("Boundary Daemon - Trust Boundary Enforcement System")
    print("=" * 70)

    tray_icon = None

    try:
        daemon = BoundaryDaemon(
            log_dir=args.log_dir,
            initial_mode=initial_mode,
            skip_integrity_check=args.skip_integrity_check,
        )

        daemon.start()

        # Set up system tray if requested (default on Windows)
        use_tray = args.tray and not args.no_tray
        if use_tray:
            try:
                from daemon.tray import create_tray_icon

                shutdown_event = threading.Event()

                def on_tray_exit():
                    shutdown_event.set()

                tray_icon = create_tray_icon(
                    daemon=daemon,
                    on_exit=on_tray_exit,
                    auto_hide=not args.no_auto_hide,
                )

                if tray_icon:
                    print("System tray icon active - right-click tray icon for menu")
                    print("  - Closing (X) or minimizing hides to system tray")
                    print("  - Double-click tray icon to show console")
                    print("  - Use 'Exit' in tray menu to quit")
                    if not args.no_auto_hide:
                        print("Console will minimize to tray in 1 second...")
                else:
                    print("System tray not available (install: pip install pystray Pillow)")

                # Wait for shutdown signal from tray or keyboard
                try:
                    while not shutdown_event.is_set():
                        time.sleep(0.5)
                except KeyboardInterrupt:
                    pass

            except ImportError as e:
                print(f"Tray icon not available: {e}")
                print("Install requirements: pip install pystray Pillow")
                # Fall back to normal operation
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass
        else:
            # Keep running until interrupted (normal mode)
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

        # Cleanup
        if tray_icon:
            tray_icon.stop()

        daemon.stop()

    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
