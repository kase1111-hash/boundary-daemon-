#!/usr/bin/env python3
"""
Linux Boot Startup Setup Script for Boundary Daemon

This script provides a simple way to enable or disable the boundary daemon
to start automatically on Linux boot using systemd.

Usage:
    sudo python3 scripts/setup-linux-boot.py --enable
    sudo python3 scripts/setup-linux-boot.py --disable
    sudo python3 scripts/setup-linux-boot.py --status

For full installation with watchdog services, use scripts/setup-watchdog.sh instead.
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


# ANSI color codes
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color


def print_status(msg: str) -> None:
    print(f"{Colors.GREEN}[OK]{Colors.NC} {msg}")


def print_warning(msg: str) -> None:
    print(f"{Colors.YELLOW}[WARN]{Colors.NC} {msg}")


def print_error(msg: str) -> None:
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}")


def print_info(msg: str) -> None:
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {msg}")


def check_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def check_systemd() -> bool:
    """Check if systemd is available."""
    return shutil.which('systemctl') is not None


def get_project_dir() -> Path:
    """Get the project root directory."""
    script_dir = Path(__file__).resolve().parent
    return script_dir.parent


def run_command(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check
        )
        return result
    except subprocess.CalledProcessError as e:
        print_error(f"Command failed: {' '.join(cmd)}")
        if e.stderr:
            print(f"  Error: {e.stderr.strip()}")
        raise


def is_service_installed() -> bool:
    """Check if the boundary-daemon service is installed."""
    service_path = Path('/etc/systemd/system/boundary-daemon.service')
    return service_path.exists()


def is_service_enabled() -> bool:
    """Check if the service is enabled for boot."""
    result = run_command(['systemctl', 'is-enabled', 'boundary-daemon.service'], check=False)
    return result.returncode == 0 and result.stdout.strip() == 'enabled'


def is_service_active() -> bool:
    """Check if the service is currently running."""
    result = run_command(['systemctl', 'is-active', 'boundary-daemon.service'], check=False)
    return result.returncode == 0 and result.stdout.strip() == 'active'


def create_directories() -> None:
    """Create required directories for the daemon."""
    directories = [
        '/var/log/boundary-daemon',
        '/var/run/boundary-daemon',
        '/etc/boundary-daemon',
    ]

    for dir_path in directories:
        path = Path(dir_path)
        if not path.exists():
            path.mkdir(parents=True, mode=0o700)
            print_status(f"Created {dir_path}")
        else:
            print_info(f"Directory exists: {dir_path}")


def install_daemon_files(project_dir: Path) -> None:
    """Install daemon files to /opt/boundary-daemon."""
    install_dir = Path('/opt/boundary-daemon')

    if install_dir.exists():
        print_warning("Installation directory exists, updating...")
    else:
        install_dir.mkdir(parents=True)

    # Copy daemon package
    daemon_src = project_dir / 'daemon'
    daemon_dst = install_dir / 'daemon'
    if daemon_src.exists():
        if daemon_dst.exists():
            shutil.rmtree(daemon_dst)
        shutil.copytree(daemon_src, daemon_dst)
        print_status("Installed daemon package")

    # Copy api package
    api_src = project_dir / 'api'
    api_dst = install_dir / 'api'
    if api_src.exists():
        if api_dst.exists():
            shutil.rmtree(api_dst)
        shutil.copytree(api_src, api_dst)
        print_status("Installed api package")

    # Copy config if it exists and not already present
    config_src = project_dir / 'config'
    config_dst = Path('/etc/boundary-daemon')
    if config_src.exists() and config_dst.exists():
        for config_file in config_src.glob('*'):
            dst_file = config_dst / config_file.name
            if not dst_file.exists():
                shutil.copy2(config_file, dst_file)
                print_status(f"Copied config: {config_file.name}")


def install_service(project_dir: Path) -> None:
    """Install the systemd service file."""
    service_src = project_dir / 'systemd' / 'boundary-daemon.service'
    service_dst = Path('/etc/systemd/system/boundary-daemon.service')

    if not service_src.exists():
        print_error(f"Service file not found: {service_src}")
        sys.exit(1)

    shutil.copy2(service_src, service_dst)
    print_status("Installed boundary-daemon.service")

    # Reload systemd
    run_command(['systemctl', 'daemon-reload'])
    print_status("Reloaded systemd daemon")


def enable_boot_startup() -> None:
    """Enable the service to start on boot."""
    if not check_root():
        print_error("This operation requires root privileges. Run with sudo.")
        sys.exit(1)

    if not check_systemd():
        print_error("systemd is required but not found on this system.")
        print_info("This script only supports systemd-based Linux distributions.")
        sys.exit(1)

    project_dir = get_project_dir()

    print(f"\n{Colors.BLUE}Enabling Boundary Daemon boot startup...{Colors.NC}\n")

    # Create directories
    create_directories()

    # Install daemon files
    install_daemon_files(project_dir)

    # Install service file
    install_service(project_dir)

    # Enable the service
    run_command(['systemctl', 'enable', 'boundary-daemon.service'])
    print_status("Enabled boundary-daemon.service for boot startup")

    print(f"\n{Colors.GREEN}Boot startup enabled successfully!{Colors.NC}")
    print("\nThe daemon will now start automatically on system boot.")
    print("\nUseful commands:")
    print("  Start now:     sudo systemctl start boundary-daemon")
    print("  Stop:          sudo systemctl stop boundary-daemon")
    print("  Status:        sudo systemctl status boundary-daemon")
    print("  View logs:     sudo journalctl -u boundary-daemon -f")
    print("\nTo disable boot startup: sudo python3 scripts/setup-linux-boot.py --disable")


def disable_boot_startup() -> None:
    """Disable the service from starting on boot."""
    if not check_root():
        print_error("This operation requires root privileges. Run with sudo.")
        sys.exit(1)

    if not check_systemd():
        print_error("systemd is required but not found on this system.")
        sys.exit(1)

    print(f"\n{Colors.BLUE}Disabling Boundary Daemon boot startup...{Colors.NC}\n")

    if not is_service_installed():
        print_warning("Service is not installed.")
        return

    # Stop the service if running
    if is_service_active():
        run_command(['systemctl', 'stop', 'boundary-daemon.service'])
        print_status("Stopped boundary-daemon.service")

    # Disable the service
    if is_service_enabled():
        run_command(['systemctl', 'disable', 'boundary-daemon.service'])
        print_status("Disabled boundary-daemon.service")
    else:
        print_info("Service was not enabled")

    print(f"\n{Colors.GREEN}Boot startup disabled successfully!{Colors.NC}")
    print("\nThe daemon will no longer start automatically on boot.")
    print("\nNote: The service file is still installed. To completely remove:")
    print("  sudo rm /etc/systemd/system/boundary-daemon.service")
    print("  sudo systemctl daemon-reload")


def uninstall_service() -> None:
    """Completely uninstall the service."""
    if not check_root():
        print_error("This operation requires root privileges. Run with sudo.")
        sys.exit(1)

    if not check_systemd():
        print_error("systemd is required but not found on this system.")
        sys.exit(1)

    print(f"\n{Colors.BLUE}Uninstalling Boundary Daemon service...{Colors.NC}\n")

    if not is_service_installed():
        print_warning("Service is not installed.")
        return

    # Stop the service if running
    if is_service_active():
        run_command(['systemctl', 'stop', 'boundary-daemon.service'])
        print_status("Stopped boundary-daemon.service")

    # Disable the service
    if is_service_enabled():
        run_command(['systemctl', 'disable', 'boundary-daemon.service'])
        print_status("Disabled boundary-daemon.service")

    # Remove the service file
    service_path = Path('/etc/systemd/system/boundary-daemon.service')
    if service_path.exists():
        service_path.unlink()
        print_status("Removed service file")

    # Reload systemd
    run_command(['systemctl', 'daemon-reload'])
    print_status("Reloaded systemd daemon")

    print(f"\n{Colors.GREEN}Service uninstalled successfully!{Colors.NC}")
    print("\nNote: Installation files in /opt/boundary-daemon were NOT removed.")
    print("To remove completely: sudo rm -rf /opt/boundary-daemon")


def show_status() -> None:
    """Show the current service status."""
    if not check_systemd():
        print_error("systemd is required but not found on this system.")
        sys.exit(1)

    print(f"\n{Colors.BLUE}Boundary Daemon Service Status{Colors.NC}\n")

    # Check if installed
    installed = is_service_installed()
    if installed:
        print_status("Service is installed")
    else:
        print_warning("Service is NOT installed")
        print("\nTo enable boot startup: sudo python3 scripts/setup-linux-boot.py --enable")
        return

    # Check if enabled for boot
    enabled = is_service_enabled()
    if enabled:
        print_status("Boot startup is ENABLED")
    else:
        print_warning("Boot startup is DISABLED")

    # Check if running
    active = is_service_active()
    if active:
        print_status("Service is RUNNING")
    else:
        print_warning("Service is NOT running")

    # Show detailed status
    print(f"\n{Colors.BLUE}Detailed Status:{Colors.NC}")
    result = run_command(['systemctl', 'status', 'boundary-daemon.service', '--no-pager'], check=False)
    print(result.stdout)

    # Check directories
    print(f"\n{Colors.BLUE}Installation Directories:{Colors.NC}")
    directories = [
        '/opt/boundary-daemon',
        '/var/log/boundary-daemon',
        '/var/run/boundary-daemon',
        '/etc/boundary-daemon',
    ]
    for dir_path in directories:
        if Path(dir_path).exists():
            print_status(f"{dir_path} exists")
        else:
            print_warning(f"{dir_path} NOT found")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Setup Boundary Daemon to start on Linux boot',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 scripts/setup-linux-boot.py --enable     Enable boot startup
  sudo python3 scripts/setup-linux-boot.py --disable    Disable boot startup
  sudo python3 scripts/setup-linux-boot.py --uninstall  Remove service completely
  python3 scripts/setup-linux-boot.py --status          Check current status

For full installation with watchdog services, use:
  sudo ./scripts/setup-watchdog.sh --install
"""
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--enable', action='store_true',
                       help='Enable daemon to start on boot')
    group.add_argument('--disable', action='store_true',
                       help='Disable daemon from starting on boot')
    group.add_argument('--uninstall', action='store_true',
                       help='Completely uninstall the service')
    group.add_argument('--status', action='store_true',
                       help='Show current service status')

    args = parser.parse_args()

    # Check platform
    if sys.platform != 'linux':
        print_error("This script only supports Linux systems.")
        print_info("For macOS, use launchd. For Windows, use the Task Scheduler.")
        sys.exit(1)

    if args.enable:
        enable_boot_startup()
    elif args.disable:
        disable_boot_startup()
    elif args.uninstall:
        uninstall_service()
    elif args.status:
        show_status()


if __name__ == '__main__':
    main()
