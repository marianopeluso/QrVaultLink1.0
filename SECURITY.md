# 🔐 QRVaultLink - Security Policy

**QRVaultLink - Cross-platform encrypted QR code generation with AES-256-GCM and RSA-4096**

## Release Verification

All QRVaultLink releases are cryptographically signed with GPG to ensure authenticity and integrity.

### How to Verify a Release

#### Step 1: Import the Public Key (First Time Only)

```bash
# Download the public key
curl -O https://github.com/marianopeluso/QRVaultLink/raw/main/qrvaultlink_pub.asc

# Import it into GPG
gpg --import qrvaultlink_pub.asc
```

#### Step 2: Download the Release Files

```bash
# Download from GitHub Releases
VERSION="1.0"
BASE_URL="https://github.com/marianopeluso/QRVaultLink/releases/download/v${VERSION}"

# Download archive and signature
curl -LO "${BASE_URL}/qrvaultlink.zip"
curl -LO "${BASE_URL}/qrvaultlink.zip.asc"
curl -LO "${BASE_URL}/qrvaultlink.zip.sha256"
```

#### Step 3: Verify the GPG Signature

```bash
gpg --verify qrvaultlink.zip.asc qrvaultlink.zip
```

**Expected output:**
```
gpg: Signature made [DATE]
gpg:                using RSA key F20494B9FAB53C10
gpg: Good signature from "Mariano Peluso <mariano@peluso.me>"
```

✅ **"Good signature"** means the file is authentic and hasn't been tampered with.

#### Step 4: Verify the Checksum

```bash
# Verify SHA-256
sha256sum -c qrvaultlink.zip.sha256

# Or manually compare
sha256sum qrvaultlink.zip
cat qrvaultlink.zip.sha256
```

**Expected output:**
```
qrvaultlink.zip: OK
```

### Windows Users

**Install GPG:**
1. Download Gpg4win: https://www.gpg4win.org/download.html
2. Install with default options

**Verify signature:**
```cmd
gpg --verify qrvaultlink.zip.asc qrvaultlink.zip
```

**Verify checksum (without GPG):**
```cmd
certutil -hashfile qrvaultlink.zip SHA256
```
Compare the output with the hash in `qrvaultlink.zip.sha256`

---

## Public Key Fingerprint

**Email:** `mariano@peluso.me`  
**Key ID:** `F20494B9FAB53C10`  
**Subkey:** `1D883A3031F0BA94`  
**Fingerprint:** `0FD97EB855F7C5BB1048D424F20494B9FAB53C10`  
**Added:** October 25, 2025

The public key is available:
- On GitHub: https://github.com/marianopeluso.gpg
- In this repository: [`qrvaultlink_pub.asc`](./qrvaultlink_pub.asc)
- On keyservers: `keys.openpgp.org`
- In GitHub Releases

To verify the key fingerprint locally:
```bash
gpg --fingerprint mariano@peluso.me
```

**Verify authenticity:** Compare the fingerprint above with your import result to ensure the key is authentic.

---

## Security Best Practices

When using QRVaultLink:

1. **Verify every release** before installation
2. **Use strong passwords** for AES-256 encryption (12+ chars with mixed case, numbers, symbols)
3. **Keep private RSA keys secure** and backed up in a safe location
4. **Verify key fingerprints** when sharing public keys
5. **Verify file integrity** after decryption using the embedded SHA-256 hash
6. **Update regularly** to get security patches and improvements
7. **Test on small files first** before encrypting critical data

---

## Key Management Security

### Private Key Protection

When using RSA-4096 encryption in QRVaultLink:

- **Strong Password Protection** - Private keys should be encrypted with strong passwords
- **Secure Storage** - Keep private key files in secure, backed-up locations
- **Access Control** - Limit file permissions to your user account only
- **Key Rotation** - Consider generating new keys periodically for sensitive operations

### Password Requirements for AES-256

Passwords used for AES-256 encryption should:
- **Minimum 12 characters** (strongly recommended)
- **At least one uppercase letter**
- **At least one lowercase letter**
- **At least one digit**
- **At least one special character**

This ensures high entropy and resistance to brute-force attacks.

### Public Key Export

When sharing RSA public keys:

- **Verify fingerprints** before trusting a public key
- **Communicate through secure channels** when sharing keys
- **Compare fingerprints** using multiple channels for verification
- **Test decryption** on small files before trusting production data

---

## Reporting Security Vulnerabilities

We take security seriously. If you discover a security vulnerability in QRVaultLink:

### Please DO:
- ✅ Email us privately at: **mariano@peluso.me**
- ✅ Provide detailed steps to reproduce
- ✅ Allow us 90 days to fix before public disclosure
- ✅ Include proof-of-concept code if possible

### Please DO NOT:
- ❌ Open a public GitHub issue
- ❌ Disclose the vulnerability publicly before we've patched it
- ❌ Exploit the vulnerability maliciously

### Response Timeline

- **Initial Response:** Within 48 hours
- **Status Update:** Within 7 days
- **Fix Target:** Within 30-90 days (depending on severity)

### Hall of Fame

We'll acknowledge security researchers who responsibly disclose vulnerabilities.

---

## Supported Versions

| Version | Status             | Support Until |
| ------- | ------------------ | ------------- |
| 1.0     | ✅ Active support  | TBD           |
| < 1.0   | ❌ No longer supported | - |

---

## Cryptographic Details

### Encryption Algorithms

**AES-256-GCM:**
- Key size: 256 bits
- IV/Nonce: 12 bytes (randomly generated)
- Authentication: Built-in GCM authentication tag
- Mode: Authenticated encryption with associated data (AEAD)
- Key Derivation: PBKDF2-HMAC-SHA256 with 600,000 iterations
- Implementation: Python cryptography library (OpenSSL backend)

**RSA-4096:**
- Key size: 4096 bits
- Padding: OAEP (Optimal Asymmetric Encryption Padding)
- Hash: SHA-256
- MGF: MGF1 with SHA-256
- Use: Hybrid encryption for AES key exchange
- Key Format: PEM (Privacy Enhanced Mail)

**PBKDF2:**
- Hash Algorithm: SHA-256
- Iterations: 600,000 (industry standard, OWASP recommended)
- Salt: 16 bytes (randomly generated)
- Output: 32 bytes (256-bit key)
- RFC Compliance: PKCS #5 v2.0

### Random Number Generation

QRVaultLink uses `os.urandom()` for cryptographic random number generation, which is:
- Suitable for cryptographic use
- Platform-specific:
  - Linux: `/dev/urandom`
  - Windows: `CryptGenRandom()` via OpenSSL
  - macOS: Kernel secure random number generator
- Non-blocking and entropy-sufficient
- Suitable for generating keys, IVs, and salts

### Hash Functions

- **SHA-256** - Used for file integrity verification, key derivation, and fingerprinting
- **HMAC** - For integrity verification of encrypted data
- **File Fingerprint** - SHA-256 hash of original plaintext embedded in encrypted file

---

## File Format Security

### FSS1 Format Structure

QRVaultLink uses the FSS1 (FileSecureSuite v1) format for encrypted files:

- **Magic Number:** `FSS1` (4 bytes) - Format identifier
- **Version Byte:** Version identifier for forward compatibility
- **Encryption Method:** Identifier for encryption type (AES-256, RSA, etc.)
- **Metadata:** Encryption parameters (salt, nonce, key information)
- **File Hash:** SHA-256 hash of original plaintext
- **Ciphertext:** Encrypted data with GCM authentication

### Hash Verification Process

1. Decryption extracts the embedded file hash
2. Decrypted plaintext is hashed with SHA-256
3. Hash is compared using constant-time comparison
4. Mismatch indicates corruption or tampering

### Constant-Time Comparison

Sensitive hash comparisons use `hmac.compare_digest()`:
- Prevents timing attacks
- Takes same time regardless of where bytes match
- Cryptographically secure comparison

---

## QR Code Security

### Capacity and Limitations

QRVaultLink generates QR codes with specific capacity constraints:

- **Single QR Maximum:** ~2.9 KB (Version 40 QR code)
- **Smartphone-Scannable:** ~500 characters (recommended for mobile scanning)
- **Multi-QR Support:** Files larger than single QR capacity are split across multiple codes
- **Chunk Size:** 1200 bytes per chunk for optimal reliability and scanning

### QR Code Data Encoding

- **Data Compression:** gzip level 9 compression (before encryption)
- **Encoding:** Base64 encoding for safe QR representation
- **Readable Mode:** NONE encryption allows readable QR codes for text/data without secrets

---

## Dependencies

QRVaultLink relies on several libraries. We monitor them for vulnerabilities:

### Required
- **cryptography>=41.0.0** - NIST-approved cryptographic primitives from OpenSSL
- **qrcode[pil]>=8.0** - QR code generation
- **pyzbar** - QR code reading from images/webcam

### Optional (with graceful fallback)
- **opencv-python** - Webcam QR code scanning (CV2_AVAILABLE flag)
- **colorama>=0.4.6** - Terminal colors
- **pyperclip>=1.8.2** - Clipboard operations

Run `pip install --upgrade -r requirements.txt` regularly to get security updates.

---

## Compliance

### Open Source License

QRVaultLink is released under the MIT License. See [LICENSE](./LICENSE) file for details.

### Standards & Certifications

QRVaultLink implements:
- **NIST SP 800-38D** - Galois/Counter Mode (GCM)
- **NIST SP 800-132** - PBKDF2 key derivation
- **PKCS #1 v2.2** - RSA cryptography standard
- **FIPS 180-4** - SHA hash standards
- **ISO/IEC 18004** - QR Code standard

### Enterprise Compliance

Suitable for use in organizations requiring:
- **GDPR** - Data protection (encryption recommended)
- **HIPAA** - Healthcare data security
- **ISO 27001** - Information security management
- **PCI DSS** - Payment card data security
- **SOC 2** - Security controls

### Export Compliance

This software uses cryptographic functions. Some countries may have restrictions on the import, possession, use, and/or re-export of encryption software. Please check your local laws before using or distributing this software.

**United States:** Subject to EAR (Export Administration Regulations) for items on the Commerce Control List.

---

## Platform-Specific Security Considerations

### Linux/macOS
- Uses `os.statvfs()` for disk space verification
- Full support for RSA key generation and management
- Headless SSH environment compatible

### Windows
- Uses `shutil.disk_usage()` for disk space verification
- Full support for RSA key generation and management
- Console color support via colorama

### Cross-Platform
- File path handling normalized across all platforms
- Terminal compatibility ensures proper display on all systems
- QR code generation and scanning consistent across platforms

---

## Additional Resources

- [Installation Guide](./INSTALLATION.md)
- [Quick Start Guide](./README.md)
- [Python Cryptography Library](https://cryptography.io/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/)
- [QR Code Standard](https://www.iso.org/standard/62952.html)

---

## Updates and Announcements

Security updates will be announced via:
- GitHub Releases
- Repository Security Advisories
- Commit messages with `[SECURITY]` tag
- Email notifications (if subscribed)

Subscribe to repository notifications to stay informed.

---

## Version 1.0 Security Features

### Core Security
- ✅ AES-256-GCM encryption with authenticated encryption
- ✅ RSA-4096 hybrid encryption support
- ✅ PBKDF2 key derivation with 600,000 iterations
- ✅ SHA-256 file integrity verification
- ✅ Constant-time hash comparison to prevent timing attacks

### QR Code Security
- ✅ Multi-QR support for large files
- ✅ Gzip compression before encryption
- ✅ Base64 encoding for safe QR representation
- ✅ Readable QR mode for non-sensitive data
- ✅ Optimal chunk sizing for reliability

### Cross-Platform Support
- ✅ Windows, Linux, macOS compatibility
- ✅ Headless SSH environment support
- ✅ Platform-specific disk space verification
- ✅ Terminal compatibility across all platforms

### User Experience
- ✅ Clear encryption mode selection
- ✅ Secure password input (no echo)
- ✅ File verification feedback
- ✅ Comprehensive error handling

---

**Last Updated:** 2025-12-05  
**Version:** 1.0  
**Status:** Security Review Completed  
**Contact:** mariano@peluso.me
