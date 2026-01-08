@echo off
echo Boundary Daemon - ASCII Art Editor
echo ===================================
echo.

REM Check if windows-curses is installed, install if not
python -c "import curses" 2>nul
if errorlevel 1 (
    echo Installing windows-curses...
    pip install windows-curses
    echo.
)

REM Get the directory where this batch file is located
cd /d "%~dp0"

REM Run the art editor
echo Starting Art Editor...
echo.
python art_editor.py %*

pause
