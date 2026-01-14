#!/bin/bash
# Boundary Daemon - Run daemon and Matrix TUI
# Runs daemon in background and displays the TUI

cd "$(dirname "$0")" || exit 1

# Check if daemon is already running
if pgrep -f "python.*daemon" > /dev/null 2>&1; then
    echo "Daemon already running"
else
    echo "Starting Boundary Daemon in background..."
    python3 -m daemon --mode trusted &
    DAEMON_PID=$!

    # Wait for socket to be created
    echo "Waiting for daemon to initialize..."
    for _ in {1..10}; do
        if [ -S "api/boundary.sock" ]; then
            echo "Daemon ready (PID: $DAEMON_PID)"
            break
        fi
        sleep 0.5
    done
fi

# Start the Matrix TUI
echo "Launching Matrix TUI..."
python3 -m daemon.tui.dashboard --matrix

# Note: Daemon continues running in background after TUI exits
# Kill with: pkill -f "python.*daemon"
