@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

:: Prefer python, then python3, then py
where python >nul 2>&1
if not errorlevel 1 (
    python "%~dp0vault.py" %*
    exit /b !ERRORLEVEL!
)

where python3 >nul 2>&1
if not errorlevel 1 (
    python3 "%~dp0vault.py" %*
    exit /b !ERRORLEVEL!
)

where py >nul 2>&1
if not errorlevel 1 (
    py "%~dp0vault.py" %*
    exit /b !ERRORLEVEL!
)

echo Python was not found. Please install Python and add it to PATH.
pause
exit /b 1