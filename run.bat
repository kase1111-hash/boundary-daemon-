@echo off
:: Boundary Daemon - Admin Mode with Matrix TUI
:: Runs daemon in background and displays the TUI

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Change to script directory
cd /d "%~dp0"

echo ============================================
echo  Boundary Daemon Launcher
echo ============================================
echo.

:: Check Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found in PATH
    echo Please install Python and add it to PATH
    pause
    exit /b 1
)

:: Kill any existing daemon processes
echo Stopping any existing daemon processes...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq boundary*" >nul 2>&1

:: Start daemon in a new minimized window (not fully hidden, so we can debug)
echo Starting Boundary Daemon...
start /MIN "Boundary Daemon" cmd /c "python -m daemon --mode trusted 2>&1 | tee daemon.log"

:: Wait for daemon to initialize and create TCP listener
echo Waiting for daemon to initialize (checking TCP port 19847)...
set RETRIES=0
:WAIT_LOOP
timeout /t 1 /nobreak >nul
set /a RETRIES+=1

:: Check if daemon is listening on port 19847
netstat -an | findstr "19847.*LISTENING" >nul
if %errorlevel% equ 0 (
    echo Daemon is ready - TCP port 19847 active
    goto :DAEMON_READY
)

if %RETRIES% lss 10 (
    echo   Still waiting... [%RETRIES%/10]
    goto :WAIT_LOOP
)

echo.
echo WARNING: Daemon may not have started properly.
echo Check daemon.log for errors.
echo Continuing anyway...
echo.

:DAEMON_READY
:: Start the Matrix TUI (visible)
echo.
echo Launching Matrix TUI...
echo ============================================
python -m daemon.tui.dashboard --matrix

:: When TUI exits, offer to stop daemon
echo.
echo TUI closed.
choice /C YN /M "Stop the daemon process"
if %errorlevel% equ 1 (
    taskkill /F /FI "WINDOWTITLE eq Boundary Daemon" >nul 2>&1
    echo Daemon stopped.
)

pause
