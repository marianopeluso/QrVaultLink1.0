# QRVaultLink Installation - Quick Start

## Choose Your Platform

### Windows
1. Download `install_qrvaultlink_windows.bat`
2. Place it in your QRVaultLink folder (alongside `qrvaultlink_v1_0.py`)
3. Double-click `install_qrvaultlink_windows.bat`
4. Follow the prompts

### macOS or Linux
1. Download the appropriate script:
   - macOS: `install_qrvaultlink_macos.sh`
   - Linux: `install_qrvaultlink_linux.sh`
2. Place it in your QRVaultLink folder
3. Open terminal in that folder and run:
   ```bash
   chmod +x install_qrvaultlink_*.sh
   ./install_qrvaultlink_*.sh
   ```
4. Follow the prompts

## Alternative: Manual Installation with pip

If you prefer to install manually:

```bash
# Install required dependencies only
pip install -r requirements.txt

# Or install with optional features too
pip install -r requirements.txt -r requirements-optional.txt

# Then run QRVaultLink
python3 qrvaultlink_v1_0.py
```

## What Gets Installed

### Required (Always)
- **cryptography** - Encryption engine (AES-256, RSA-4096, PBKDF2)
- **qrcode[pil]** - QR code generation

### Optional (Graceful Fallback)
- **colorama** - Colored terminal output
- **opencv-python** - Webcam support
- **pyzbar** - QR code reading from webcam

## After Installation

Launch QRVaultLink:
```bash
python3 qrvaultlink_v1_0.py        # Linux/macOS
python qrvaultlink_v1_0.py         # Windows
```

If you created a virtual environment, deactivate it when done:
```bash
deactivate
```

## Troubleshooting

**Python not found?**
- Windows: Make sure you installed Python and added it to PATH
- macOS: Install with Homebrew: `brew install python@3.11`
- Linux: Install with your package manager (apt, dnf, etc)

**Installation script fails?**
- Check your internet connection
- Try running with administrator/sudo privileges
- See `INSTALLER_ADAPTATION_GUIDE.md` for detailed troubleshooting

**Missing features?**
- Optional dependencies can fail gracefully
- QRVaultLink will still work with core features
- You can install missing optional deps later individually

## Files Included

- `install_qrvaultlink_windows.bat` - Windows installer
- `install_qrvaultlink_macos.sh` - macOS installer
- `install_qrvaultlink_linux.sh` - Linux installer
- `requirements.txt` - Required dependencies (for pip)
- `requirements-optional.txt` - Optional dependencies (for pip)
- `INSTALLER_ADAPTATION_GUIDE.md` - Detailed documentation

## Support

For issues specific to dependencies:
- **cryptography:** https://cryptography.io/
- **qrcode:** https://github.com/lincolnloop/python-qrcode
- **opencv:** https://opencv.org/
- **pyzbar:** https://github.com/NaturalHistoryMuseum/pyzbar

---

**QRVaultLink v1.0** - Cross-platform QR code encryption tool
