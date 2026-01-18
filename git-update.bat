@echo off
REM ============================================================================
REM Git Update Script for Boundary Daemon
REM Fetches and pulls the latest changes from the remote repository
REM ============================================================================

setlocal

REM Change to script directory
cd /d "%~dp0"

echo.
echo ============================================
echo  Git Update - Boundary Daemon
echo ============================================
echo.

REM Check if git is available
git --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Git is not installed or not in PATH
    echo Please install Git and try again
    pause
    exit /b 1
)

REM Check if we're in a git repository
git rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 (
    echo ERROR: Not a git repository
    echo Please run this script from the repository root
    pause
    exit /b 1
)

REM Show current branch
for /f "tokens=*" %%a in ('git branch --show-current') do set CURRENT_BRANCH=%%a
echo Current branch: %CURRENT_BRANCH%
echo.

REM Fetch latest changes
echo Fetching latest changes...
git fetch --all
if errorlevel 1 (
    echo ERROR: Failed to fetch from remote
    pause
    exit /b 1
)
echo.

REM Pull latest changes
echo Pulling latest changes...
git pull
if errorlevel 1 (
    echo.
    echo WARNING: Pull failed. You may have local changes or merge conflicts.
    echo Use 'git status' to check the repository state.
    pause
    exit /b 1
)

echo.
echo ============================================
echo  Update complete!
echo ============================================
echo.

endlocal
