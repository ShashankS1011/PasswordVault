@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

echo.
echo ========================================
echo   Secure Password Vault - Build Script
echo ========================================
echo.

:: Check if Python is available
where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python was not found in PATH.
    echo Please install Python and make sure it is added to PATH.
    pause
    exit /b 1
)

echo [1/3] Installing compatible build dependencies...
python -m pip install -r requirements-dev.txt
if errorlevel 1 (
    echo.
    echo [ERROR] Failed to install required packages.
    pause
    exit /b 1
)

echo.
echo [2/3] Building standalone vault.exe ...
echo.

python -m PyInstaller ^
    --onefile ^
    --noconfirm ^
    --clean ^
    vault.spec

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed. Scroll up to see the details.
    pause
    exit /b 1
)

echo.
echo [3/3] Cleaning temporary files...
if exist "build" rmdir /s /q "build"

echo.
echo ========================================
echo   BUILD SUCCESSFUL!
echo ========================================
echo.
echo Your standalone executable is here:
echo.
echo     %~dp0dist\vault.exe
echo.
echo You can now copy vault.exe anywhere and run it
echo without needing Python installed.
echo.
pause
exit /b 0