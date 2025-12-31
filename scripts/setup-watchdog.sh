#!/bin/bash
#
# Boundary Daemon Watchdog Setup Script
#
# This script sets up the external watchdog system for the boundary daemon.
# The watchdog monitors the daemon and triggers emergency lockdown if it fails.
#
# WHAT IT DOES:
# 1. Creates required directories
# 2. Installs systemd service files
# 3. Enables and starts the services
# 4. Verifies the setup
#
# USAGE:
#   sudo ./scripts/setup-watchdog.sh [OPTIONS]
#
# OPTIONS:
#   --install      Install and enable all services
#   --uninstall    Remove all services
#   --status       Show current status
#   --secondary    Also install secondary watchdog (redundancy)
#   --help         Show this help
#
# REQUIREMENTS:
# - Root privileges (sudo)
# - systemd
# - Python 3.8+
# - iptables or nftables (for lockdown)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SYSTEMD_DIR="/etc/systemd/system"
INSTALL_DIR="/opt/boundary-daemon"
LOG_DIR="/var/log/boundary-daemon"
RUN_DIR="/var/run/boundary-daemon"
CONFIG_DIR="/etc/boundary-daemon"

# Service files
DAEMON_SERVICE="boundary-daemon.service"
WATCHDOG_SERVICE="boundary-watchdog.service"
WATCHDOG_SECONDARY_SERVICE="boundary-watchdog-secondary.service"

print_header() {
    echo -e "${BLUE}"
    echo "======================================================================"
    echo "  Boundary Daemon Watchdog Setup"
    echo "======================================================================"
    echo -e "${NC}"
}

print_status() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (sudo)"
        exit 1
    fi
}

check_requirements() {
    echo "Checking requirements..."

    # Check systemd
    if ! command -v systemctl &> /dev/null; then
        print_error "systemd is required but not found"
        exit 1
    fi
    print_status "systemd found"

    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is required but not found"
        exit 1
    fi
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    print_status "Python $PYTHON_VERSION found"

    # Check iptables or nftables
    if command -v iptables &> /dev/null; then
        print_status "iptables found"
    elif command -v nft &> /dev/null; then
        print_status "nftables found"
    else
        print_warning "Neither iptables nor nftables found - lockdown may not work"
    fi

    echo ""
}

create_directories() {
    echo "Creating directories..."

    mkdir -p "$LOG_DIR"
    chmod 700 "$LOG_DIR"
    print_status "Created $LOG_DIR"

    mkdir -p "$RUN_DIR"
    chmod 700 "$RUN_DIR"
    print_status "Created $RUN_DIR"

    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    print_status "Created $CONFIG_DIR"

    echo ""
}

install_project() {
    echo "Installing boundary daemon to $INSTALL_DIR..."

    if [[ -d "$INSTALL_DIR" ]]; then
        print_warning "Installation directory exists, updating..."
    else
        mkdir -p "$INSTALL_DIR"
    fi

    # Copy project files
    cp -r "$PROJECT_DIR/daemon" "$INSTALL_DIR/"
    cp -r "$PROJECT_DIR/api" "$INSTALL_DIR/"
    cp "$PROJECT_DIR/boundary-watchdog" "$INSTALL_DIR/"

    # Make watchdog executable
    chmod +x "$INSTALL_DIR/boundary-watchdog"

    # Create symlink in /usr/bin
    ln -sf "$INSTALL_DIR/boundary-watchdog" /usr/bin/boundary-watchdog

    print_status "Installed to $INSTALL_DIR"
    print_status "Created symlink /usr/bin/boundary-watchdog"

    echo ""
}

install_services() {
    local with_secondary=$1

    echo "Installing systemd services..."

    # Install main daemon service
    cp "$PROJECT_DIR/systemd/$DAEMON_SERVICE" "$SYSTEMD_DIR/"
    print_status "Installed $DAEMON_SERVICE"

    # Install primary watchdog service
    cp "$PROJECT_DIR/systemd/$WATCHDOG_SERVICE" "$SYSTEMD_DIR/"
    print_status "Installed $WATCHDOG_SERVICE"

    # Install secondary watchdog if requested
    if [[ "$with_secondary" == "true" ]]; then
        cp "$PROJECT_DIR/systemd/$WATCHDOG_SECONDARY_SERVICE" "$SYSTEMD_DIR/"
        print_status "Installed $WATCHDOG_SECONDARY_SERVICE"
    fi

    # Reload systemd
    systemctl daemon-reload
    print_status "Reloaded systemd"

    echo ""
}

enable_services() {
    local with_secondary=$1

    echo "Enabling services..."

    systemctl enable "$DAEMON_SERVICE"
    print_status "Enabled $DAEMON_SERVICE"

    systemctl enable "$WATCHDOG_SERVICE"
    print_status "Enabled $WATCHDOG_SERVICE"

    if [[ "$with_secondary" == "true" ]]; then
        systemctl enable "$WATCHDOG_SECONDARY_SERVICE"
        print_status "Enabled $WATCHDOG_SECONDARY_SERVICE"
    fi

    echo ""
}

start_services() {
    local with_secondary=$1

    echo "Starting services..."

    systemctl start "$DAEMON_SERVICE"
    sleep 2

    if systemctl is-active --quiet "$DAEMON_SERVICE"; then
        print_status "Started $DAEMON_SERVICE"
    else
        print_error "Failed to start $DAEMON_SERVICE"
        journalctl -u "$DAEMON_SERVICE" --no-pager -n 20
        exit 1
    fi

    systemctl start "$WATCHDOG_SERVICE"
    sleep 1

    if systemctl is-active --quiet "$WATCHDOG_SERVICE"; then
        print_status "Started $WATCHDOG_SERVICE"
    else
        print_warning "Watchdog may take a moment to connect to daemon"
    fi

    if [[ "$with_secondary" == "true" ]]; then
        systemctl start "$WATCHDOG_SECONDARY_SERVICE"
        sleep 1

        if systemctl is-active --quiet "$WATCHDOG_SECONDARY_SERVICE"; then
            print_status "Started $WATCHDOG_SECONDARY_SERVICE"
        fi
    fi

    echo ""
}

show_status() {
    echo -e "${BLUE}Service Status:${NC}"
    echo ""

    for service in "$DAEMON_SERVICE" "$WATCHDOG_SERVICE" "$WATCHDOG_SECONDARY_SERVICE"; do
        if systemctl list-unit-files | grep -q "^$service"; then
            status=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")
            enabled=$(systemctl is-enabled "$service" 2>/dev/null || echo "disabled")

            case $status in
                active)
                    echo -e "  ${GREEN}●${NC} $service: $status ($enabled)"
                    ;;
                inactive)
                    echo -e "  ${YELLOW}○${NC} $service: $status ($enabled)"
                    ;;
                failed)
                    echo -e "  ${RED}●${NC} $service: $status ($enabled)"
                    ;;
                *)
                    echo -e "  ${YELLOW}?${NC} $service: $status ($enabled)"
                    ;;
            esac
        fi
    done

    echo ""

    # Check for lockdown indicator
    if [[ -f "$RUN_DIR/LOCKDOWN" ]]; then
        echo -e "${RED}WARNING: System is in LOCKDOWN state!${NC}"
        cat "$RUN_DIR/LOCKDOWN"
        echo ""
    fi

    # Show daemon socket status
    if [[ -S "$RUN_DIR/daemon.sock" ]]; then
        print_status "Daemon watchdog socket: $RUN_DIR/daemon.sock"
    else
        print_warning "Daemon watchdog socket not found"
    fi
}

uninstall_services() {
    echo "Uninstalling services..."

    # Stop services
    for service in "$WATCHDOG_SECONDARY_SERVICE" "$WATCHDOG_SERVICE" "$DAEMON_SERVICE"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service"
            print_status "Stopped $service"
        fi
    done

    # Disable services
    for service in "$WATCHDOG_SECONDARY_SERVICE" "$WATCHDOG_SERVICE" "$DAEMON_SERVICE"; do
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            systemctl disable "$service"
            print_status "Disabled $service"
        fi
    done

    # Remove service files
    for service in "$DAEMON_SERVICE" "$WATCHDOG_SERVICE" "$WATCHDOG_SECONDARY_SERVICE"; do
        if [[ -f "$SYSTEMD_DIR/$service" ]]; then
            rm "$SYSTEMD_DIR/$service"
            print_status "Removed $SYSTEMD_DIR/$service"
        fi
    done

    # Remove symlink
    if [[ -L "/usr/bin/boundary-watchdog" ]]; then
        rm /usr/bin/boundary-watchdog
        print_status "Removed /usr/bin/boundary-watchdog symlink"
    fi

    systemctl daemon-reload
    print_status "Reloaded systemd"

    echo ""
    print_warning "Installation directory $INSTALL_DIR was NOT removed"
    print_warning "Log directory $LOG_DIR was NOT removed"
    print_warning "Remove manually if desired"
}

show_help() {
    echo "Boundary Daemon Watchdog Setup Script"
    echo ""
    echo "Usage: sudo $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --install      Install and enable all services"
    echo "  --uninstall    Remove all services"
    echo "  --status       Show current status"
    echo "  --secondary    Also install secondary watchdog for redundancy"
    echo "  --help         Show this help"
    echo ""
    echo "Examples:"
    echo "  sudo $0 --install              # Basic installation"
    echo "  sudo $0 --install --secondary  # Install with redundant watchdog"
    echo "  sudo $0 --status               # Check service status"
    echo "  sudo $0 --uninstall            # Remove all services"
    echo ""
    echo "Security Architecture:"
    echo ""
    echo "  ┌─────────────────────────────────────────────────────────┐"
    echo "  │                     systemd                              │"
    echo "  │  (restarts services, triggers halt on repeated failure) │"
    echo "  └─────────────────────────────────────────────────────────┘"
    echo "                            │"
    echo "                            ▼"
    echo "  ┌─────────────────────────────────────────────────────────┐"
    echo "  │              boundary-daemon.service                     │"
    echo "  │  (policy decisions, audit logging, enforcement)          │"
    echo "  └─────────────────────────────────────────────────────────┘"
    echo "                            │"
    echo "          ┌─────────────────┴─────────────────┐"
    echo "          ▼                                   ▼"
    echo "  ┌───────────────────┐           ┌───────────────────────┐"
    echo "  │ boundary-watchdog │◄─────────►│ boundary-watchdog     │"
    echo "  │    (primary)      │           │    (secondary)        │"
    echo "  └───────────────────┘           └───────────────────────┘"
    echo "          │                                   │"
    echo "          └─────────────────┬─────────────────┘"
    echo "                            ▼"
    echo "                    ┌─────────────┐"
    echo "                    │  LOCKDOWN   │"
    echo "                    │ (iptables)  │"
    echo "                    └─────────────┘"
    echo ""
}

verify_installation() {
    echo "Verifying installation..."

    local errors=0

    # Check files
    for file in "$SYSTEMD_DIR/$DAEMON_SERVICE" "$SYSTEMD_DIR/$WATCHDOG_SERVICE" "/usr/bin/boundary-watchdog"; do
        if [[ -f "$file" ]] || [[ -L "$file" ]]; then
            print_status "Found $file"
        else
            print_error "Missing $file"
            ((errors++))
        fi
    done

    # Check directories
    for dir in "$LOG_DIR" "$RUN_DIR" "$CONFIG_DIR" "$INSTALL_DIR"; do
        if [[ -d "$dir" ]]; then
            print_status "Found $dir"
        else
            print_error "Missing $dir"
            ((errors++))
        fi
    done

    echo ""

    if [[ $errors -eq 0 ]]; then
        print_status "Verification passed"
    else
        print_error "Verification failed with $errors error(s)"
        exit 1
    fi
}

# Main
print_header

case "${1:-}" in
    --install)
        check_root
        check_requirements
        create_directories
        install_project

        with_secondary="false"
        if [[ "${2:-}" == "--secondary" ]]; then
            with_secondary="true"
        fi

        install_services "$with_secondary"
        enable_services "$with_secondary"
        start_services "$with_secondary"
        verify_installation

        echo -e "${GREEN}Installation complete!${NC}"
        echo ""
        show_status

        echo ""
        echo "Next steps:"
        echo "  1. Check logs: journalctl -u boundary-daemon -f"
        echo "  2. Check watchdog: journalctl -u boundary-watchdog -f"
        echo "  3. Test: ./boundaryctl status"
        ;;

    --uninstall)
        check_root
        uninstall_services
        echo -e "${GREEN}Uninstallation complete!${NC}"
        ;;

    --status)
        show_status
        ;;

    --help|"")
        show_help
        ;;

    *)
        print_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac
