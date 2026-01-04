#!/usr/bin/env python3
"""
TUI Integration Tests.

Run with: python -m pytest tests/test_tui.py -v
Or directly: python tests/test_tui.py
"""

import sys
import asyncio
import os
import tempfile
import shutil
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Suppress verbose logging
logging.disable(logging.WARNING)
os.environ['TERM'] = 'xterm-256color'


async def test_tui_screens():
    """Test TUI screen navigation and widget rendering."""
    from daemon.boundary_daemon import BoundaryDaemon
    from daemon.policy_engine import BoundaryMode
    from tui.app import (
        BoundaryDaemonTUI, DashboardScreen, ModeControlScreen,
        EventLogScreen, TripwireScreen, SettingsScreen,
        ModeIndicator, HealthIndicator
    )

    log_dir = tempfile.mkdtemp(prefix='tui_test_')

    try:
        daemon = BoundaryDaemon(
            log_dir=log_dir,
            initial_mode=BoundaryMode.OPEN,
            skip_integrity_check=True
        )

        app = BoundaryDaemonTUI(daemon=daemon)

        async with app.run_test() as pilot:
            await asyncio.sleep(0.5)

            # Test 1: Dashboard loads
            assert isinstance(app.screen, DashboardScreen), \
                f"Expected DashboardScreen, got {app.screen.__class__.__name__}"

            # Test 2: Mode indicator shows correct mode
            mi = app.screen.query_one('#mode-indicator', ModeIndicator)
            assert mi.mode == "OPEN", f"Expected OPEN, got {mi.mode}"

            # Test 3: Navigation to Mode Control
            await pilot.press('m')
            await asyncio.sleep(0.3)
            assert isinstance(app.screen, ModeControlScreen)

            # Test 4: Navigation back to Dashboard
            await pilot.press('d')
            await asyncio.sleep(0.3)
            assert isinstance(app.screen, DashboardScreen)

            # Test 5: Navigation to Events
            await pilot.press('e')
            await asyncio.sleep(0.3)
            assert isinstance(app.screen, EventLogScreen)

            # Test 6: Navigation to Tripwires
            await pilot.press('t')
            await asyncio.sleep(0.3)
            assert isinstance(app.screen, TripwireScreen)

            # Test 7: Navigation to Settings
            await pilot.press('s')
            await asyncio.sleep(0.3)
            assert isinstance(app.screen, SettingsScreen)

            # Test 8: ESC returns to Dashboard
            await pilot.press('escape')
            await asyncio.sleep(0.3)
            assert isinstance(app.screen, DashboardScreen)

    finally:
        shutil.rmtree(log_dir, ignore_errors=True)


async def test_tui_demo_mode():
    """Test TUI runs in demo mode without daemon."""
    from tui.app import BoundaryDaemonTUI, DashboardScreen

    app = BoundaryDaemonTUI(daemon=None)

    async with app.run_test() as pilot:
        await asyncio.sleep(0.3)

        # Should start on dashboard even without daemon
        assert isinstance(app.screen, DashboardScreen)

        # Navigation should still work
        await pilot.press('m')
        await asyncio.sleep(0.3)
        # Screen name check
        assert "ModeControl" in app.screen.__class__.__name__


def run_tests():
    """Run all TUI tests."""
    print("=== TUI Integration Tests ===\n")

    tests = [
        ("Screen Navigation", test_tui_screens),
        ("Demo Mode", test_tui_demo_mode),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            asyncio.run(test_func())
            print(f"[PASS] {name}")
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {name}: {e}")
            failed += 1

    print(f"\n=== Results: {passed} passed, {failed} failed ===")
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
