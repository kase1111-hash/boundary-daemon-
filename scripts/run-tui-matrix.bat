@echo off
REM Boundary Daemon TUI Launcher - Matrix Mode
REM Runs the terminal dashboard with the secret Matrix theme

setlocal enabledelayedexpansion

REM Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
set "PROJECT_DIR=%SCRIPT_DIR%.."

REM Change to project directory
cd /d "%PROJECT_DIR%"

REM Check if Python 3.12 is available (needed for windows-curses)
py -3.12 --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Entering the Matrix...
    py -3.12 -m daemon.tui.dashboard --matrix %*
    goto :end
)

REM Fall back to default Python
python --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Entering the Matrix...
    python -m daemon.tui.dashboard --matrix %*
    goto :end
)

REM Try py launcher
py --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Entering the Matrix...
    py -m daemon.tui.dashboard --matrix %*
    goto :end
)

echo ERROR: Python not found. Please install Python 3.12 or later.
echo Download from: https://www.python.org/downloads/
pause
exit /b 1

:end
