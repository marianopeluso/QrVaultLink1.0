# QRVaultLink v1.0 - Quick Start Guide

## Installation (2 minutes)

### Windows
```bash
python -m pip install cryptography qrcode[pil]
python qrvaultlink_v1_0.py
```

### macOS / Linux
```bash
python3 -m pip install cryptography qrcode[pil]
python3 qrvaultlink_v1_0.py
```

### Using Automated Installers (Recommended)
- **Windows:** Double-click `install_qrvaultlink_windows.bat`
- **Linux:** `bash install_qrvaultlink_linux.sh`
- **macOS:** `bash install_qrvaultlink_macos.sh`

---

## Main Menu

When you launch QRVaultLink, you'll see this menu:

```
========================================
    QRVaultLink v1.0 - Main Menu
========================================
1) 📝 Create QR Codes
2) 📂 Read QR Codes and Decrypt Files
3) 📷 Scan QR from Webcam
4) 📋 View Audit Logs
5) ℹ️ Credits
6) 👋 Exit

Select option: 
```

---

## Common Operations

### Create Readable QR Code (NONE - No Encryption)

1. Press `[1]` → Create QR Codes
2. Press `[1]` → File
3. Enter file path
4. Choose encryption → `[1]` No encryption
5. QR code displayed - scannable with any QR reader

**Best for:** Non-sensitive data, quick sharing

### Create Password-Protected QR Code (AES-256)

1. Press `[1]` → Create QR Codes
2. Press `[1]` → File
3. Enter file path
4. Choose encryption → `[2]` AES (password)
5. Enter password (min 8 chars: uppercase, lowercase, digit, or special char)
6. Confirm password
7. QR code(s) displayed and optionally saved as `.aes` file

**Requirements:** Password min 8 chars with at least 2 of: uppercase, lowercase, digit, special char

### Create Text QR Code

1. Press `[1]` → Create QR Codes
2. Press `[2]` → Text
3. Enter text to encrypt
4. Choose encryption: NONE [1], AES [2], or RSA [3]
5. QR code(s) generated

**Limits:**
- No encryption: ~500 characters (single QR)
- With encryption: ~1200 bytes per QR code

### Decrypt QR Codes from Folder

1. Press `[2]` → Read QR Codes and Decrypt Files
2. Choose folder:
   - `[1]` Output folder (default output location)
   - `[2]` Received folder (default received location)
   - `[3]` Custom folder (enter path)
   - `[4]` Current folder

3. Program automatically:
   - Scans folder for `.png` QR images
   - Reconstructs multi-part QR codes
   - Decrypts and verifies files

4. For encrypted files (AES or RSA):
   - **AES:** Enter password
   - **RSA:** Select private key file (`.pem`)

5. Original file restored to folder with `_decrypted` suffix

### Scan QR Code with Webcam

1. Press `[3]` → Scan QR from Webcam
2. Point webcam at QR code
3. Program automatically detects and decodes QR codes
4. Press `CTRL+C` to stop
5. Detected frames saved, multi-part codes reassembled

**Requirements:** `opencv-python` and `pyzbar` (optional - see Troubleshooting if missing)

### View Operation History

1. Press `[4]` → View Audit Logs
2. Displays all encryption/decryption operations with:
   - Operation type
   - Encryption method (AES/RSA/NONE)
   - Status (OK/FAILED)
   - Timestamps
   - File sizes

---

## Encryption Methods

### NONE (No Encryption)
- ✅ Readable QR code, scannable by any reader
- ✅ Fastest option
- ⚠️ Data is visible in plain text
- 📏 Capacity: ~500 chars (single QR), up to 2.9 KB with QR v40

### AES-256-GCM (Password-Based)
- ✅ Military-grade encryption
- ✅ PBKDF2 key derivation (600,000 iterations)
- ✅ Easy to share (just password)
- ⚠️ Password strength matters
- 📏 ~1200 bytes per QR code (after compression)
- 📄 Files saved with `.aes` extension

### RSA-4096 (Public Key Encryption)
- ✅ Asymmetric encryption
- ✅ Share public key safely
- ✅ Only private key owner can decrypt
- ⚠️ Slower than AES
- 📏 ~1200 bytes per QR code (after compression)
- 📄 Files saved with `.rsa` extension
- 🔑 Requires private key file to decrypt

---

## File Management

### Folders Used

- **output/** - Generated QR code images and encrypted files
- **received/** - Place encrypted files here for decryption
- **audit_logs/** - Operation history logs

### File Extensions

| Extension | Meaning |
|-----------|---------|
| `.png` | QR code image |
| `_1_of_5.png` | Multi-part QR (part 1 of 5) |
| `.aes` | AES-256 encrypted file |
| `.rsa` | RSA-4096 encrypted file |
| `.pem` | RSA key file (public or private) |

---

## QR Code Capacity

| Encryption | Single QR | Multi-QR | Notes |
|------------|-----------|----------|-------|
| NONE | 500 chars | N/A | Readable by any scanner |
| AES-256 | 1200 bytes | 0.2 MB max | After gzip compression |
| RSA-4096 | 1200 bytes | 0.2 MB max | After gzip compression |

**Multi-part codes:**
- Automatically numbered (1/5, 2/5, etc.)
- Can scan in any order
- Includes checksums for integrity

---

## Requirements

### Minimum
- Python 3.7+
- pip
- Internet (first installation only)

### Dependencies

**Required:**
- `cryptography>=41.0.0` - Encryption engine
- `qrcode[pil]>=8.0` - QR code generation

**Optional (with graceful fallback):**
- `opencv-python>=4.8.0` - Webcam support
- `pyzbar>=0.1.9` - QR code detection from webcam
- `colorama>=0.4.6` - Colored terminal output

---

## Troubleshooting

**Python not found?**
- Windows: Install from https://www.python.org/downloads/ (check "Add Python to PATH")
- Linux: `sudo apt install python3 python3-pip`
- macOS: `brew install python@3.11`
- See `WINDOWS_PYTHON_INSTALLATION_GUIDE.md` for detailed Windows setup

**pip not found?**
```bash
python -m pip install cryptography qrcode[pil]
# or on macOS/Linux:
python3 -m pip install cryptography qrcode[pil]
```

**Webcam not working?**
```bash
pip install opencv-python pyzbar
```
- Ensure camera permissions granted to terminal/IDE
- Check camera is connected
- Try different camera (if multiple available)

**"Invalid password" on decrypt?**
- Check CAPS LOCK
- Verify you're using correct password
- Passwords are case-sensitive

**"Cannot open webcam" error?**
- Check camera is plugged in
- Ensure no other app is using camera
- Try restarting terminal
- Check camera permissions in system settings

**Large file not encoding?**
- Files >0.2 MB can generate many QR codes
- Program splits into ~1200 byte chunks
- All parts needed for decryption

**QR code won't scan?**
- Verify brightness and contrast
- Ensure full QR code is visible
- Try closer to camera
- Check for glare or shadows

---

## Security Best Practices

1. **Strong Passwords** - Use 12+ chars with mix of types
2. **Backup Keys** - Keep RSA private keys in secure location
3. **Verify Fingerprints** - Compare key info when sharing public keys
4. **Use HTTPS** - Transfer QR codes via secure channels
5. **Check History** - Review audit logs for security
6. **Close Program** - Exit when done to clear memory

---

## Advanced Features

### Automatic Compression
- Gzip level 9 compression applied before encryption
- Reduces QR code count for large files
- Transparent to user

### File Verification
- SHA-256 hash included with every encryption
- Automatically verified on decryption
- Ensures file integrity

### Multi-Part QR Codes
- Automatic splitting for files >1200 bytes
- Each code numbered and checksummed
- Scan in any order - sequence detected automatically

### Cross-Platform
- Works on Windows, macOS, Linux
- SSH/headless support
- Portable - no special installation

---

## What's in QRVaultLink v1.0?

✅ **Three Encryption Options** - NONE, AES-256-GCM, RSA-4096  
✅ **Cross-Platform** - Windows, macOS, Linux, SSH  
✅ **Multi-Part Support** - Handle files up to 0.2 MB  
✅ **Webcam Scanning** - Live QR detection with opencv-python  
✅ **File Verification** - SHA-256 hash validation  
✅ **Audit Logging** - Track all operations  
✅ **Automatic Compression** - Gzip level 9 before encryption  

---

## Performance

- **Encryption Speed:** ~100-500 MB/s (AES-256)
- **QR Generation:** <1 second per QR code
- **Decryption Speed:** Same as encryption
- **Compression Ratio:** ~60-80% for text, ~10-20% for binaries

---

## Tips & Tricks

💡 Use **NONE encryption** for internal/trusted QR codes (faster)  
💡 Use **AES** for password-protected sharing (easy to remember)  
💡 Use **RSA** for asymmetric encryption (share public key, only you decrypt)  
💡 Save QR code images for offline sharing  
💡 Check audit logs periodically for security review  
💡 Test decryption immediately after encryption to verify workflow  

---

## Documentation

- [README_INSTALLATION.md](README_INSTALLATION.md) - Full installation guide
- [WINDOWS_PYTHON_INSTALLATION_GUIDE.md](WINDOWS_PYTHON_INSTALLATION_GUIDE.md) - Windows setup details
- [INSTALLER_ADAPTATION_GUIDE.md](INSTALLER_ADAPTATION_GUIDE.md) - Installer information
- [qrvaultlink_v1_0.py](qrvaultlink_v1_0.py) - Source code with comments

---

## License

MIT License - See LICENSE in source repository

---

**QRVaultLink v1.0 - Secure QR Code Encryption**  
*Last Updated: 2025*
