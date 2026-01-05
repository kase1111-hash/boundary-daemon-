@echo off
REM Boundary Daemon TUI Launcher
REM Runs the terminal dashboard for monitoring the daemon

setlocal enabledelayedexpansion

REM Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
set "PROJECT_DIR=%SCRIPT_DIR%.."

REM Change to project directory
cd /d "%PROJECT_DIR%"

REM Check if Python 3.12 is available (needed for windows-curses)
py -3.12 --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Starting Boundary Daemon TUI with Python 3.12...
    py -3.12 -m daemon.tui.dashboard %*
    goto :end
)

REM Fall back to default Python
python --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Starting Boundary Daemon TUI...
    python -m daemon.tui.dashboard %*
    goto :end
)

REM Try py launcher
py --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Starting Boundary Daemon TUI...
    py -m daemon.tui.dashboard %*
    goto :end
)

echo ERROR: Python not found. Please install Python 3.12 or later.
echo Download from: https://www.python.org/downloads/
pause
exit /b 1

:end
