@echo off
REM Start Secure Lens AI Flask Backend (Windows)
REM This batch file sets the PYTHONPATH and starts the Flask development server

cd /d "%~dp0"

REM Set PYTHONPATH to include venv site-packages
setlocal
set "PYTHONPATH=%CD%\venv\Lib\site-packages;%PYTHONPATH%"

echo ========================================
echo Secure Lens AI Backend Server
echo ========================================
echo PYTHONPATH: %PYTHONPATH%
echo.
echo Starting Flask server...
echo Server will run on: http://localhost:5000
echo Press Ctrl+C to stop
echo.

python run.py

pause
