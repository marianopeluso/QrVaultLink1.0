# QRVaultLink v1.0

**Cross-platform encrypted QR code generator and decoder with enterprise-grade security.**

[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)]()
[![Security](https://img.shields.io/badge/Security-AES256--RSA4096-blue)]()
[![Python](https://img.shields.io/badge/Python-3.7%2B-blue)]()
[![License](https://img.shields.io/badge/License-MIT-green)]()

## 🎯 What is QRVaultLink?

QRVaultLink transforms files into encrypted QR codes for **secure visual file transfer**. Instead of email or cloud services, you can transfer sensitive data (SSH keys, API tokens, passwords, documents) as QR codes—physically secure, instantly verifiable, no network required.

**Key use cases:**
- Share SSH/GPG private keys between machines
- Transfer API credentials and security tokens  
- Exchange small encrypted files without email/cloud
- Create offline-scannable backups
- Air-gap secure data exchange
- Educational security demonstrations

### Why FileSecureSuite Compatibility?

QRVaultLink is built on the **FSS1 encryption standard** used by FileSecureSuite, creating a **unified security ecosystem**. This means:

✅ Encrypt with QRVaultLink → Decrypt with FileSecureSuite  
✅ Encrypt with FileSecureSuite → Decrypt with QRVaultLink  
✅ Cross-tool file compatibility  
✅ Enterprise-grade standardized encryption  

This creates a modular security toolkit where each tool specializes (QR codes, file encryption, key management) but speaks the same cryptographic language.

### How It Works: The Conversion & Encryption Flow

```
INPUT FILE/TEXT
       ↓
   ENCRYPTION (AES-256-GCM or RSA-4096)
       ↓
   FSS1 FORMAT (magic + hash + metadata + ciphertext)
       ↓
   COMPRESSION (gzip level 9, on encrypted data)
       ↓
   BASE64 ENCODING (QR-safe representation)
       ↓
   QR CODE GENERATION (single or multi-part)
       ↓
OUTPUT: .png QR code image(s)
```

### The FSS1 Format

QRVaultLink uses the **FSS1 (FileSecureSuite v1)** standardized format:

```
[Magic: FSS1] + [Version: 1] + [File Hash: SHA-256] + [Metadata: salt/nonce/key-length]
                             ↓
                    Ciphertext (encrypted data with GCM authentication tag)
```

Every encrypted file includes a cryptographic hash of the original plaintext, enabling **instant verification** that decrypted data is correct and hasn't been tampered with.

**Real-world example:**
1. You have a 2KB SSH key
2. QRVaultLink encrypts it with AES-256-GCM → FSS1 format with embedded SHA-256 hash (~2.1KB encrypted)
3. Compresses the encrypted data with gzip → ~1.2KB
4. Encodes as Base64 → ~1.6KB
5. Automatically splits across 2 QR codes (2600 bytes each in base64)
6. Generates `key_1_of_2.png` and `key_2_of_2.png`
7. When scanned: QRVaultLink automatically reconstructs, decompresses, and decrypts your original SSH key
8. SHA-256 hash verification confirms integrity

---

## 🎯 Features

- **Three Encryption Modes**
  - NONE: Readable QR codes (no encryption)
  - AES-256-GCM: Password-based encryption (PBKDF2, 600,000 iterations)
  - RSA-4096: Public key encryption with hybrid mode

- **QR Code Support**
  - Readable QR: up to 1200 bytes (~1.2 KB)
  - Single QR: up to 2953 bytes (~2.95 KB) [Version 40]
  - Multi-QR: up to 0.2 MB [2600-byte chunks]
 
- **Cross-Platform**
  - Windows, Linux, macOS
  - Headless SSH support
  - Console-based interface (no GUI)

- **Security**
  - FSS1 format (FileSecureSuite compatible)
  - PBKDF2-SHA256: 600,000 iterations
  - SHA-256 integrity verification
  - Secure password input (hidden)

- **User Experience**
  - Clean terminal menus
  - Multi-file selection options
  - Password retry logic (3 attempts)
  - Audit logging of all operations
  - Real-time webcam QR scanning (optional)

## 📦 Requirements

**Required:**
- Python 3.7 or newer
- cryptography >= 41.0.0
- qrcode[pil] >= 8.0

**Optional (for enhanced features):**
- opencv-python >= 4.8.0 (webcam scanning)
- pyzbar >= 0.1.9 (QR code detection from webcam)
- colorama >= 0.4.6 (colored terminal output)

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the application
python3 qrvaultlink_v1_0.py
```

See `QUICKSTART.md` for detailed usage instructions.

## 📋 Main Menu

The application presents a 6-option menu:

**[1] 📝 Create QR Codes**
- Convert file or text into encrypted QR codes
- Choose from: File or Text input
- Select encryption: NONE, AES-256-GCM, or RSA-4096
- Handles files up to 0.2 MB (multi-part automatic)

**[2] 📂 Read QR Codes and Decrypt Files**
- Scan folder for QR code images (.png)
- Reconstruct multi-part QR codes automatically
- Decrypt with password (AES) or private key (RSA)
- Choose from: Output, Received, Custom, or Current folder

**[3] 📷 Scan QR from Webcam**
- Live webcam scanning (requires opencv-python & pyzbar)
- Automatically detects and decodes QR codes
- Saves captured frames
- Press CTRL+C to stop

**[4] 📋 View Audit Logs**
- Review all encryption/decryption operations
- Shows operation type, method, status, timestamps
- File for compliance and security tracking

**[5] ℹ️ Credits**
- Version information
- Features list
- Requirements

**[6] 👋 Exit**
- Close the application

## 🔐 Security

### Encryption Methods

**NONE (No Encryption)**
- Readable by any QR scanner
- Useful for non-sensitive data sharing
- Capacity: ~500 characters, up to 2.9 KB with QR v40

**AES-256-GCM (Password-Based)**
- Military-grade authenticated encryption
- Password must be 8+ chars with 2+ character types
- PBKDF2 with 600,000 iterations
- Each operation uses random salt/IV
- Capacity: ~1200 bytes per QR (after compression)

**RSA-4096 (Public Key)**
- Asymmetric encryption
- Hybrid: RSA encrypts AES key, AES encrypts data
- Public key can be shared safely
- Only private key owner can decrypt
- Capacity: ~1200 bytes per QR (after compression)

### Security Features
- No plaintext stored to disk
- SHA-256 hash verification for every file
- Secure password input (hidden from terminal)
- Cross-tool compatibility with FileSecureSuite
- Audit logging for all operations

## 💻 Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Windows | ✓ Full | Console mode, PATH setup required |
| Linux | ✓ Full | Terminal UI, SSH/headless compatible |
| macOS | ✓ Full | Terminal UI, Homebrew compatible |
| SSH | ✓ Full | Headless mode, file-based only |

## 🔄 Interoperability

**100% Compatible with FileSecureSuite v1.0.5**

- Same FSS1 format
- Same PBKDF2 iterations (600,000)
- Bidirectional encryption/decryption
- All files fully interchangeable

✓ Encrypt with QRVaultLink → Decrypt with FileSecureSuite  
✓ Encrypt with FileSecureSuite → Decrypt with QRVaultLink

## 📊 Performance

| Operation | Approx. Time | Notes |
|-----------|--------------|-------|
| QR Generation | <1 second | Single QR code |
| QR Reading (webcam) | <2 seconds | Multi-part auto-detected |
| Encryption (AES) | Variable | Depends on file size |
| Decryption | Variable | Depends on file size |

## 📄 File Extensions

| Extension | Meaning |
|-----------|---------|
| `.png` | QR code image |
| `_1_of_5.png` | Multi-part QR (1 of 5) |
| `.aes` | AES-256 encrypted file |
| `.rsa` | RSA-4096 encrypted file |
| `.pem` | RSA key file (public/private) |

## 🛠️ Installation Guides

### Minimal (No Webcam)
```bash
pip install cryptography>=41.0.0 qrcode[pil]>=8.0
```

### Full (With Webcam)
```bash
pip install -r requirements.txt
```

### Platform-Specific

**Windows:**
```bash
python -m pip install -r requirements.txt
python qrvaultlink_v1_0.py
```

**Linux/macOS:**
```bash
pip install -r requirements.txt
python3 qrvaultlink_v1_0.py
```

See `INSTALLATION.md` for detailed platform instructions.

## 🎯 QR Code Capacity

| Encryption | Single QR | Multi-QR | Notes |
|------------|-----------|----------|-------|
| NONE | 500 chars | N/A | Readable by any scanner |
| AES-256 | 1200 bytes | 0.2 MB | After gzip compression |
| RSA-4096 | 1200 bytes | 0.2 MB | After gzip compression |

Multi-part QR codes are automatically:
- Numbered (1/5, 2/5, etc.)
- Checksummed for integrity
- Can be scanned in any order

## ✨ What's in v1.0

✓ Cross-platform (Windows, Linux, macOS, SSH)  
✓ Three encryption options (NONE, AES-256, RSA-4096)  
✓ Multi-part QR support up to 0.2 MB  
✓ Automatic file compression (gzip level 9)  
✓ SHA-256 verification hash  
✓ Webcam scanning with opencv-python  
✓ FileSecureSuite FSS1 format compatibility  
✓ Audit logging  
✓ Graceful fallback for optional dependencies  

## 📖 Documentation

- `QUICKSTART.md` - Quick start guide with examples
- `INSTALLATION.md` - Detailed installation for all platforms
- `WINDOWS_PYTHON_INSTALLATION_GUIDE.md` - Windows setup guide
- `README_INSTALLATION.md` - General installation notes
- `SECURITY.md` - Security policy and cryptographic details


## 🌐 Tested Environments

- ✓ Windows 10/11
- ✓ Ubuntu 20.04 LTS / 22.04 LTS
- ✓ Debian 11/12
- ✓ Fedora 38/39
- ✓ macOS 12+ (Intel/Apple Silicon)
- ✓ SSH headless environments

## ⚠️ Notes

- **Webcam optional**: Works without opencv-python/pyzbar (file-based only)
- **Colored output optional**: Graceful fallback to monochrome
- **Console-only**: No GUI (terminal-based interface)
- **Cross-platform path handling**: Automatic (os.path.join)
- **Disk space check**: Fails safely if insufficient space

## 🚀 Getting Started

1. **Install**: `pip install -r requirements.txt`
2. **Run**: `python3 qrvaultlink_v1_0.py`
3. **Create QR**: Press [1] → File → Choose encryption
4. **Decrypt**: Press [2] → Choose folder → Enter password/key
5. **Scan webcam**: Press [3] (if opencv-python installed)

See `QUICKSTART.md` for detailed examples.

## 📋 License

MIT License

## 👤 Author

Mariano Peluso

---

**Last Updated**: December 2024  
**Version**: 1.0  
**Status**: Production Ready  
**Compatibility**: FileSecureSuite v1.0.5  
