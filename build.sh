#!/bin/bash
# Boundary Daemon Build Script
# Compiles the daemon into a standalone executable using PyInstaller

set -e

echo "========================================"
echo "Boundary Daemon Build Script"
echo "========================================"
echo

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 is not installed"
    echo "Please install Python 3.8+ and try again"
    exit 1
fi

# Check if PyInstaller is installed
if ! python3 -c "import PyInstaller" &> /dev/null; then
    echo "PyInstaller not found. Installing..."
    pip3 install pyinstaller
fi

# Install dependencies
echo "Checking dependencies..."
pip3 install -r requirements.txt 2>/dev/null || true

# Create directories
mkdir -p dist build

# Set build options
MAIN_SCRIPT="daemon/boundary_daemon.py"
APP_NAME="boundary-daemon"

echo
echo "Building $APP_NAME..."
echo

# Build the executable
python3 -m PyInstaller \
    --name="$APP_NAME" \
    --onefile \
    --console \
    --add-data "daemon:daemon" \
    --add-data "api:api" \
    --hidden-import=daemon.memory_monitor \
    --hidden-import=daemon.resource_monitor \
    --hidden-import=daemon.health_monitor \
    --hidden-import=daemon.queue_monitor \
    --hidden-import=daemon.monitoring_report \
    --hidden-import=daemon.event_logger \
    --hidden-import=daemon.policy_engine \
    --hidden-import=daemon.state_monitor \
    --hidden-import=daemon.telemetry \
    --hidden-import=daemon.auth.api_auth \
    --hidden-import=api.boundary_api \
    --collect-submodules=daemon \
    --collect-submodules=api \
    --noconfirm \
    --clean \
    "$MAIN_SCRIPT"

echo
echo "========================================"
echo "Build completed successfully!"
echo "========================================"
echo
echo "Executable location: dist/$APP_NAME"
echo

# Copy config files
if [ -d "config" ]; then
    echo "Copying configuration files..."
    cp -r config dist/
fi

# Create run script
cat > dist/run-daemon.sh << 'EOF'
#!/bin/bash
echo "Starting Boundary Daemon..."
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$DIR/boundary-daemon" "$@"
EOF
chmod +x dist/run-daemon.sh

echo
echo "To run the daemon:"
echo "  cd dist"
echo "  ./boundary-daemon"
echo
echo "Or use: ./dist/run-daemon.sh"
echo
