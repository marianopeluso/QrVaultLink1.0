@echo off
REM QRVaultLink v1.0 - Windows Installation Script
REM This script checks for Python, optionally creates a venv, and installs dependencies

setlocal enabledelayedexpansion

echo.
echo ================================================================================
echo                   QRVaultLink v1.0 - Windows Installation
echo ================================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] Python not found!
    echo.
    echo To install Python:
    echo   1. Download from: https://www.python.org/downloads/
    echo   2. During installation, CHECK "Add Python to PATH"
    echo   3. During installation, CHECK "Add Python to environment variables"
    echo   4. After installation, RESTART YOUR COMPUTER
    echo   5. Open a NEW Command Prompt window
    echo   6. Run this script again
    echo.
    echo IMPORTANT: If you already installed Python but see this error,
    echo you likely forgot to check "Add Python to PATH"
    echo Uninstall Python and reinstall, checking ALL the boxes!
    echo.
    pause
    exit /b 1
)

echo [OK] Python found:
python --version
echo.

REM Verify pip
pip --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] pip not found. Please reinstall Python with "Add Python to PATH" checked.
    pause
    exit /b 1
)

echo [OK] pip found:
pip --version
echo.

REM Get current directory
set "CURRENT_DIR=%cd%"
echo [INFO] Installation directory: %CURRENT_DIR%
echo.

REM Ask about venv
set /p VENV_CHOICE="Do you want to create a virtual environment (venv)? (y/n): "

if /i "%VENV_CHOICE%"=="y" (
    echo.
    echo [INFO] Creating virtual environment...
    python -m venv venv
    
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    
    echo [OK] Virtual environment created
    echo.
    echo [INFO] Activating virtual environment...
    call venv\Scripts\activate.bat
    
    if errorlevel 1 (
        echo [ERROR] Failed to activate virtual environment
        pause
        exit /b 1
    )
    
    echo [OK] Virtual environment activated
    echo.
) else (
    echo [INFO] Skipping virtual environment creation
    echo.
)

REM Upgrade pip
echo [INFO] Upgrading pip...
python -m pip install --upgrade pip --quiet
if errorlevel 1 (
    echo [WARNING] pip upgrade encountered issues, continuing anyway...
)
echo [OK] pip is ready
echo.

REM Install dependencies
echo [INFO] Installing dependencies...
echo.

REM Required dependencies
echo   - Installing cryptography (REQUIRED)...
pip install --quiet cryptography>=41.0.0
if errorlevel 1 (
    echo   [ERROR] cryptography installation failed. This is required.
    pause
    exit /b 1
) else (
    echo   [OK] cryptography installed
)
echo.

echo   - Installing qrcode with PIL support (REQUIRED)...
pip install --quiet "qrcode[pil]>=8.0"
if errorlevel 1 (
    echo   [ERROR] qrcode installation failed. This is required.
    pause
    exit /b 1
) else (
    echo   [OK] qrcode[pil] installed
)
echo.

REM Optional dependencies with graceful fallback
echo [INFO] Installing optional dependencies (graceful fallback if failed)...
echo.

echo   - Installing colorama (optional - for colored terminal output)...
pip install --quiet colorama>=0.4.6
if errorlevel 1 (
    echo   [WARNING] colorama installation failed (optional, continuing)
) else (
    echo   [OK] colorama installed
)
echo.

echo   - Installing opencv-python (optional - for webcam QR scanning)...
pip install --quiet opencv-python>=4.8.0
if errorlevel 1 (
    echo   [WARNING] opencv-python installation failed (optional, continuing)
) else (
    echo   [OK] opencv-python installed
)
echo.

echo   - Installing pyzbar (optional - for QR code decoding)...
pip install --quiet pyzbar>=0.1.9
if errorlevel 1 (
    echo   [WARNING] pyzbar installation failed (optional, continuing)
) else (
    echo   [OK] pyzbar installed
)
echo.

echo ================================================================================
echo                         Installation Complete!
echo ================================================================================
echo.

if /i "%VENV_CHOICE%"=="y" (
    echo [INFO] Virtual environment is ACTIVE
    echo.
    echo To launch QRVaultLink:
    echo   python qrvaultlink_v1_0.py
    echo.
    echo When done, deactivate the venv with:
    echo   deactivate
    echo.
) else (
    echo [INFO] No virtual environment was created
    echo.
    echo To launch QRVaultLink:
    echo   python qrvaultlink_v1_0.py
    echo.
)

echo [NOTE] Make sure qrvaultlink_v1_0.py is in: %CURRENT_DIR%
echo.
echo ================================================================================
echo.
echo [INFO] Features:
echo   REQUIRED:
echo   - Encryption/Decryption: cryptography
echo   - QR code generation: qrcode[pil]
echo.
echo   OPTIONAL:
echo   - Colored output: colorama
echo   - Webcam scanning: opencv-python + pyzbar
echo.
echo If any optional dependency failed to install, QRVaultLink will continue
echo to work with graceful fallback (some features may be limited).
echo.
echo ================================================================================
echo.

pause
