@echo off
REM Boundary Daemon Build Script
REM Compiles the daemon into a standalone executable using PyInstaller

setlocal enabledelayedexpansion

echo ========================================
echo Boundary Daemon Build Script
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ and try again
    pause
    exit /b 1
)

REM Check if PyInstaller is installed
python -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo PyInstaller not found. Installing...
    pip install pyinstaller
    if errorlevel 1 (
        echo ERROR: Failed to install PyInstaller
        pause
        exit /b 1
    )
)

REM Check if required dependencies are installed
echo Checking dependencies...
pip install -r requirements.txt >nul 2>&1

REM Create dist directory if it doesn't exist
if not exist "dist" mkdir dist
if not exist "build" mkdir build

REM Set build options
set MAIN_SCRIPT=daemon\boundary_daemon.py
set APP_NAME=boundary-daemon
set ICON_PATH=
set EXTRA_DATA=--add-data "config;config"

REM Check for icon file
if exist "assets\icon.ico" (
    set ICON_PATH=--icon=assets\icon.ico
)

echo.
echo Building %APP_NAME%...
echo.

REM Build the executable
python -m PyInstaller ^
    --name=%APP_NAME% ^
    --onefile ^
    --console ^
    %ICON_PATH% ^
    --add-data "daemon;daemon" ^
    --add-data "api;api" ^
    --hidden-import=daemon.memory_monitor ^
    --hidden-import=daemon.resource_monitor ^
    --hidden-import=daemon.health_monitor ^
    --hidden-import=daemon.queue_monitor ^
    --hidden-import=daemon.monitoring_report ^
    --hidden-import=daemon.event_logger ^
    --hidden-import=daemon.policy_engine ^
    --hidden-import=daemon.state_monitor ^
    --hidden-import=daemon.telemetry ^
    --hidden-import=daemon.auth.api_auth ^
    --hidden-import=api.boundary_api ^
    --collect-submodules=daemon ^
    --collect-submodules=api ^
    --noconfirm ^
    --clean ^
    %MAIN_SCRIPT%

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo ========================================
echo Build completed successfully!
echo ========================================
echo.
echo Executable location: dist\%APP_NAME%.exe
echo.

REM Optional: Copy config files to dist
if exist "config" (
    echo Copying configuration files...
    xcopy /E /I /Y "config" "dist\config" >nul
)

REM Create a run script in dist
echo @echo off > dist\run-daemon.bat
echo echo Starting Boundary Daemon... >> dist\run-daemon.bat
echo %APP_NAME%.exe %%* >> dist\run-daemon.bat
echo pause >> dist\run-daemon.bat

echo.
echo To run the daemon:
echo   cd dist
echo   %APP_NAME%.exe
echo.
echo Or use: dist\run-daemon.bat
echo.

pause
