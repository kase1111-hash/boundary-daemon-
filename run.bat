@echo off
:: Boundary Daemon - Admin Mode with Matrix TUI
:: Runs daemon in background (system tray) and displays only the TUI

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Change to script directory
cd /d "%~dp0"

:: Create VBS helper to run daemon hidden
echo Set WshShell = CreateObject("WScript.Shell") > "%temp%\run_hidden.vbs"
echo WshShell.Run "cmd /c cd /d ""%~dp0"" && python -m daemon --mode trusted", 0, False >> "%temp%\run_hidden.vbs"

:: Start the daemon hidden in background (minimized to system tray)
echo Starting Boundary Daemon in background...
cscript //nologo "%temp%\run_hidden.vbs"

:: Wait for daemon to initialize and create socket
echo Waiting for daemon to initialize...
timeout /t 4 /nobreak >nul

:: Verify socket was created
if exist "api\boundary.sock" (
    echo Daemon ready - socket created
) else (
    echo Warning: Socket not found, daemon may still be starting...
    timeout /t 2 /nobreak >nul
)

:: Start the Matrix TUI (visible)
echo Launching Matrix TUI...
python -m daemon.tui.dashboard --matrix

:: Cleanup
del "%temp%\run_hidden.vbs" 2>nul
