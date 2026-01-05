@echo off
REM Boundary Daemon TUI - Windows Startup Script
REM
REM INSTALLATION:
REM 1. Press Win+R, type: shell:startup
REM 2. Copy this file (or create a shortcut to it) into the Startup folder
REM 3. The TUI will now start automatically when you log in
REM
REM To run in Matrix mode, edit the line below and add --matrix

setlocal enabledelayedexpansion

REM Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
set "PROJECT_DIR=%SCRIPT_DIR%.."

REM Wait a few seconds for system to stabilize after login
timeout /t 5 /nobreak >nul

REM Change to project directory
cd /d "%PROJECT_DIR%"

REM Check if Python 3.12 is available (needed for windows-curses)
py -3.12 --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    REM Start in a new console window with a nice title
    start "Boundary Daemon TUI" cmd /k "py -3.12 -m daemon.tui.dashboard"
    goto :end
)

REM Fall back to default Python
python --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    start "Boundary Daemon TUI" cmd /k "python -m daemon.tui.dashboard"
    goto :end
)

REM Try py launcher
py --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    start "Boundary Daemon TUI" cmd /k "py -m daemon.tui.dashboard"
    goto :end
)

REM If Python not found, show error
echo Boundary Daemon TUI: Python not found
echo Please install Python 3.12 from https://www.python.org/downloads/
pause

:end
