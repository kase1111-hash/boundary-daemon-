#!/bin/bash
# Boundary Daemon ASCII Art Editor Launcher
# Interactive sprite editor for creating and modifying TUI assets

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Change to project directory
cd "$PROJECT_DIR" || exit 1

# Run the art editor
echo "Starting ASCII Art Editor..."
python3 -m daemon.tui.art_editor "$@"
