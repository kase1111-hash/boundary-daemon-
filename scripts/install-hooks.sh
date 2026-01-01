#!/usr/bin/env bash
#
# Install git hooks for Boundary Daemon
#
# This script configures git to use the hooks in .githooks/
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Installing git hooks for Boundary Daemon..."

# Check if we're in a git repository
if [ ! -d "$REPO_ROOT/.git" ]; then
    echo "Error: Not a git repository. Run this script from within the repository."
    exit 1
fi

# Configure git to use the .githooks directory
cd "$REPO_ROOT"
git config core.hooksPath .githooks

# Make hooks executable
chmod +x .githooks/*

echo ""
echo "Git hooks installed successfully!"
echo ""
echo "Installed hooks:"
for hook in .githooks/*; do
    if [ -f "$hook" ]; then
        echo "  - $(basename "$hook")"
    fi
done
echo ""
echo "To disable hooks temporarily, use: git commit --no-verify"
echo "To uninstall hooks, run: git config --unset core.hooksPath"
