# 🚀 QRVaultLink v1.0 - Installation Guide

## Quick Start

### 1. Install Python
Requires Python 3.7 or newer:
```bash
python3 --version
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

This installs:
- `cryptography>=41.0.0` - AES-256-GCM, RSA-4096, PBKDF2
- `qrcode[pil]>=8.0` - QR code generation with PIL support

**Optional** (for enhanced features):
- `opencv-python>=4.8.0` - Webcam scanning support
- `pyzbar>=0.1.9` - QR code decoding from webcam
- `colorama>=0.4.6` - Colored terminal output

### 3. Run QRVaultLink
```bash
python3 qrvaultlink_v1_0.py
```

---

## Complete Installation Steps

### Step 1: Download QRVaultLink
```bash
# Clone or download the file
# Ensure you have: qrvaultlink_v1_0.py
```

### Step 2: Create Virtual Environment (Recommended)
```bash
python3 -m venv venv

# Activate on Linux/macOS
source venv/bin/activate

# Activate on Windows
venv\Scripts\activate
```

### Step 3: Upgrade pip
```bash
pip install --upgrade pip
```

### Step 4: Install Required Dependencies
```bash
pip install -r requirements.txt
```

### Step 5: (Optional) Install Enhanced Features
```bash
# For webcam QR scanning:
pip install opencv-python pyzbar

# For colored output:
pip install colorama
```

### Step 6: Verify Installation
```bash
python3 -c "import cryptography, qrcode; print('✓ Required dependencies installed')"
```

### Step 7: Run Application
```bash
python3 qrvaultlink_v1_0.py
```

---

## Installation on Specific Platforms

### Windows
1. Download Python 3.10+ from https://www.python.org/downloads/
2. **IMPORTANT**: Check "Add Python to PATH" during installation
3. Open Command Prompt and run:
```bash
python -m pip install -r requirements.txt
python qrvaultlink_v1_0.py
```

For detailed Windows setup, see `WINDOWS_PYTHON_INSTALLATION_GUIDE.md`

### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run application
python3 qrvaultlink_v1_0.py
```

### Linux (Fedora/RHEL)
```bash
sudo dnf install python3 python3-pip python3-venv

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run application
python3 qrvaultlink_v1_0.py
```

### macOS
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python@3.11

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run application
python3 qrvaultlink_v1_0.py
```

---

## Troubleshooting

### "python3: command not found"
- Windows: Python not installed or not in PATH. See `WINDOWS_PYTHON_INSTALLATION_GUIDE.md`
- Linux: Run `sudo apt install python3`
- macOS: Run `brew install python@3.11`

### ImportError: No module named 'cryptography'
```bash
pip install cryptography>=41.0.0 --upgrade
```

### ImportError: No module named 'qrcode'
```bash
pip install qrcode[pil]>=8.0
```

### Webcam Not Working / "Cannot open webcam"
- Make sure `opencv-python` and `pyzbar` are installed:
```bash
pip install opencv-python pyzbar
```
- Check camera permissions in system settings
- QRVaultLink works without webcam - you can decrypt files from images/folders instead

### ImportError: No module named 'pyzbar'
```bash
pip install pyzbar

# If it fails, system libraries may be needed:
# Linux: sudo apt install libzbar0
# macOS: brew install zbar
```

### Colored Output Not Working
Optional - install colorama for colored terminal output:
```bash
pip install colorama>=0.4.6
```
Without it, output will be monochrome but fully functional.

---

## Virtual Environment (Recommended)

Using a virtual environment keeps dependencies isolated:

```bash
# Create venv
python3 -m venv venv

# Activate venv
source venv/bin/activate          # Linux/macOS
# or
venv\Scripts\activate              # Windows

# Install dependencies in venv
pip install -r requirements.txt

# Run application
python3 qrvaultlink_v1_0.py

# Deactivate when done
deactivate
```

---

## Minimal Installation (No Webcam)
If you don't need webcam scanning:
```bash
pip install cryptography>=41.0.0 qrcode[pil]>=8.0
python3 qrvaultlink_v1_0.py
```

---

## Full Installation (With All Optional Features)
```bash
pip install -r requirements.txt
pip install opencv-python pyzbar colorama
python3 qrvaultlink_v1_0.py
```

---

## Verify Installation

Check core components:
```bash
python3 << 'VERIFY'
import sys
import cryptography
import qrcode

print("✓ Python version:", sys.version.split()[0])
print("✓ cryptography:", cryptography.__version__)
print("✓ qrcode:", qrcode.__version__)
print("\n✓ Core dependencies installed successfully!")

# Check optional components
try:
    import cv2
    print("✓ opencv-python:", cv2.__version__, "(webcam enabled)")
except ImportError:
    print("⊘ opencv-python not installed (webcam disabled - optional)")

try:
    import pyzbar
    print("✓ pyzbar installed (QR decoding from webcam enabled)")
except ImportError:
    print("⊘ pyzbar not installed (QR decoding from webcam disabled - optional)")

try:
    import colorama
    print("✓ colorama installed (colored output enabled)")
except ImportError:
    print("⊘ colorama not installed (monochrome output - optional)")
VERIFY
```

---

## First Run

When you run QRVaultLink for the first time, it creates:
- `qrcodes_out/` - Output folder for generated QR code images
- `received/` - Folder for files to be decrypted
- `logvault/` - Audit log directory

These are created automatically.

---

## Next Steps

1. Run `python3 qrvaultlink_v1_0.py`
2. Main menu appears with 6 options:
   - [1] Create QR Codes
   - [2] Read QR Codes and Decrypt Files
   - [3] Scan QR from Webcam
   - [4] View Audit Logs
   - [5] Credits
   - [6] Exit

3. See `QUICKSTART.md` for detailed usage instructions

---

## Support

- Check the main menu (option 5) for credits and information
- All errors display helpful error messages
- Audit logs saved in `logvault/audit.log` for troubleshooting
