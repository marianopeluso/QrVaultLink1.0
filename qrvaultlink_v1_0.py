#!/usr/bin/env python3
"""
QRVaultLink - QR Code Encryption Tool

Cross-platform tool for creating and decrypting encrypted QR codes.
Supports NONE (readable), AES-256-GCM, and RSA-4096 hybrid encryption.

Features:
- Multiple encryption modes (NONE, AES-256, RSA-4096)
- Readable QR codes for small text (≤1200 bytes)
- Multi-part QR codes for large files
- Cross-platform support (Windows, Linux, macOS, SSH)
- File verification with SHA-256 hash
- FSS1 format for FileSecureSuite compatibility

Encryption: AES-256-GCM (AEAD) + RSA-4096 (hybrid) + PBKDF2 (600,000 iterations)
"""

import os
import sys
import uuid
import time
import base64
import getpass
import warnings
import platform
import contextlib
import io
import hashlib
import struct
import datetime
import traceback
import re
from typing import List, Optional, Tuple
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
import gzip
import json
import qrcode
from PIL import Image

try:
    import cv2
    from pyzbar import pyzbar
    CV2_AVAILABLE = True
    CV2_ERROR = None
except ImportError as e:
    CV2_AVAILABLE = False
    CV2_ERROR = str(e)  # Track which library failed
except Exception as e:
    CV2_AVAILABLE = False
    CV2_ERROR = f"Unexpected error loading CV2/pyzbar: {str(e)}"

# Colorama for colored terminal output (matches FileSecureSuite style)
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    # Fallback: define dummy color classes
    class Fore:
        GREEN = RED = YELLOW = CYAN = ""
    class Style:
        BRIGHT = RESET_ALL = ""

# Disable deprecation and PIL warnings from external libraries
warnings.filterwarnings('ignore', category=DeprecationWarning)
warnings.filterwarnings('ignore', message='.*PIL.*')

import logging
logging.basicConfig(
    level=logging.CRITICAL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
# Keep logging handlers intact for audit trail
logging.getLogger('PIL').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)
logging.getLogger('cryptography').setLevel(logging.CRITICAL)
try:
    import ctypes
    if hasattr(ctypes, 'CDLL'):
        # Disable stderr output for C libraries on Linux/macOS
        libc = ctypes.CDLL(None)
        dup_stderr = ctypes.CDLL(None).dup2
except Exception:
    pass

# ============================================================================
# CROSS-PLATFORM SUPPORT
# ============================================================================

# Detect if terminal supports unicode properly
UNICODE_SAFE = True
try:
    import sys
    if sys.platform == 'win32':
        try:
            import os
            os.system('chcp 65001 >nul 2>&1')
        except Exception:
            UNICODE_SAFE = False
    test_emoji = 'test'
    test_emoji.encode(sys.stdout.encoding if sys.stdout.encoding else 'utf-8')
except Exception:
    UNICODE_SAFE = False

# Symbol mapping for cross-platform compatibility
SYMBOLS = {
    'check': '✅' if UNICODE_SAFE else '✅',
    'error': '❌' if UNICODE_SAFE else '❌',
    'warn': '⚠️' if UNICODE_SAFE else '⚠️',
    'info': 'ℹ️' if UNICODE_SAFE else 'ℹ️',
    'search': '🔍' if UNICODE_SAFE else '🔍',
    'lock': '🔐' if UNICODE_SAFE else '🔐',
    'key': '🔑' if UNICODE_SAFE else '🔑',
    'folder': '📁' if UNICODE_SAFE else '📁',
    'stats': '📊' if UNICODE_SAFE else '📊',
    'note': '📝' if UNICODE_SAFE else '📝',
    'list': '📋' if UNICODE_SAFE else '📋',
    'package': '📦' if UNICODE_SAFE else '📦',
    'image': '🖼️' if UNICODE_SAFE else '🖼️',
    'save': '💾' if UNICODE_SAFE else '💾',
    'done': '✓' if UNICODE_SAFE else '✓',
    'unlock': '🔓' if UNICODE_SAFE else '🔓',
}

# ============================================================================
# COLOR FUNCTIONS (matching FileSecureSuite style)
# ============================================================================

def color_success(text):
    """Colorize text as success (green)."""
    return f"{Fore.GREEN}{text}{Style.RESET_ALL}" if HAS_COLORAMA else text

def color_error(text):
    """Colorize text as error (red)."""
    return f"{Fore.RED}{text}{Style.RESET_ALL}" if HAS_COLORAMA else text

def color_warning(text):
    """Colorize text as warning (yellow)."""
    return f"{Fore.YELLOW}{text}{Style.RESET_ALL}" if HAS_COLORAMA else text

def color_info(text):
    """Colorize text as info (cyan)."""
    return f"{Fore.CYAN}{text}{Style.RESET_ALL}" if HAS_COLORAMA else text

def color_bright(text):
    """Colorize text as bright (bold)."""
    return f"{Style.BRIGHT}{text}{Style.RESET_ALL}" if HAS_COLORAMA else text

@contextlib.contextmanager
def suppress_stderr():
    """
    Context manager to suppress Python-level stderr output.
    
    NOTE: This uses contextlib.redirect_stderr which is safe and portable.
    It silences Python stderr but NOT C-level warnings (e.g., from zbar).
    For true C-level suppression on all platforms, use with caution.
    
    For Windows/multithreaded safety: Uses Python-only redirection.
    """
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            yield
    except Exception as e:
        log_operation("Stderr Suppress", "", "IO_REDIRECT", "FAILED", error=str(e))
        yield

# ============================================================================
# CONFIGURATION
# ============================================================================
MAX_FILE_SIZE_MB = 0.2

# Handle both Python script and PyInstaller exe execution
if getattr(sys, 'frozen', False):
    # Running as compiled exe (PyInstaller)
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # Running as Python script
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

OUT_DIR = os.path.join(BASE_DIR, "qrcodes_out")
RECV_DIR = os.path.join(BASE_DIR, "received")
LOG_DIR = os.path.join(BASE_DIR, "logvault")
LOG_FILE = os.path.join(LOG_DIR, "audit.log")
MIN_RSA_KEY_SIZE = 4096  # Minimum 4096-bit RSA key required
MIN_DISK_SPACE_MB = 10
PBKDF2_ITERATIONS = 600000
SALT_SIZE = 16
AESGCM_NONCE_SIZE = 12

# ============================================================================
# LOGGING SYSTEM (From FileSecureSuite)
# ============================================================================

def ensure_log_dir():
    """Create logvault directory for audit logs."""
    try:
        os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
        os.chmod(LOG_DIR, 0o700)
    except Exception as e:
        print(f"⚠️  Log directory error: {e}")


def log_operation(operation: str, filepath: str = "", method: str = "", status: str = "OK",
                  file_hash: str = "", error: str = "", additional: str = "", traceback_str: str = "",
                  redact_sensitive: bool = True):
    """
    Log operation to audit.log file in logvault folder.
    
    Args:
        operation: Operation name (e.g., "AES Encrypt", "RSA Decrypt")
        filepath: File path involved (basename extracted for privacy)
        method: Encryption method (AES, RSA, NONE)
        status: Operation status (OK, FAILED)
        file_hash: SHA256 hash of file (REDACTED by default for privacy)
        error: Error message if operation failed
        additional: Additional context (size, count, etc.)
        traceback_str: Exception traceback (truncated)
        redact_sensitive: If True (default), do NOT log hash fragments
    
    Privacy by default:
      ✅ Hashes are redacted (default redact_sensitive=True)
      ✅ Only operation metadata logged
      ✅ No sensitive data exposed
    
    For debug (if needed):
      - Set redact_sensitive=False to log hash as [REDACTED] placeholder
      - Still does NOT expose actual hash value
    """
    ensure_log_dir()
    try:
        timestamp = datetime.datetime.now().isoformat()
        basename = os.path.basename(filepath) if filepath else filepath
        log_entry = f"[{timestamp}] {operation:20} | file: {basename:40} | method: {method:6} | status: {status:10}"
        
        # PRIVACY: Hash fragments should NEVER be logged (information leak)
        # If redact_sensitive=False, we log a placeholder, but NOT the actual hash
        if file_hash and not redact_sensitive:
            log_entry += " | hash: [REDACTED]"
        
        if additional:
            log_entry += f" | {additional}"
        if error:
            log_entry += f" | ERROR: {error}"
        if traceback_str:
            log_entry += f" | traceback: {traceback_str[:300]}"
        
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry + '\n')
            f.flush()
            try:
                os.fsync(f.fileno())
            except (AttributeError, OSError):
                pass
        
        try:
            os.chmod(LOG_FILE, 0o600)
        except (AttributeError, OSError):
            pass
    except Exception as e:
        print(f"⚠️  Audit log error: {e}")


def log_exception(operation: str, filepath: str, method: str, exception: Exception, include_traceback: bool = True):
    """
    Log exception with optional traceback.
    Set include_traceback=False for sensitive operations (decrypt, password-related)
    to avoid logging potentially sensitive data in traceback.
    """
    tb_str = traceback.format_exc()[:1000] if include_traceback else ""
    log_operation(operation, filepath, method, "FAILED", error=str(exception), traceback_str=tb_str)


def get_audit_log() -> Optional[str]:
    """Read and return audit log contents."""
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                return f.read()
    except Exception:
        pass
    return None

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def is_text_file(data: bytes) -> bool:
    """
    Detect if data is text (try multiple encodings).
    Returns True if successfully decoded as text, False if binary.
    """
    encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1', 'ascii']
    for encoding in encodings:
        try:
            data.decode(encoding)
            return True
        except (UnicodeDecodeError, LookupError):
            continue
    return False

def decode_text_file(data: bytes) -> str:
    """
    Decode text file trying multiple encodings.
    Returns decoded text or empty string if binary.
    """
    encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1', 'ascii']
    for encoding in encodings:
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return ""

def is_headless() -> bool:
    """Check if running in headless environment (no display)."""
    return not os.environ.get('DISPLAY') and not os.environ.get('WAYLAND_DISPLAY')

def ensure_dirs():
    """Create required directories if they don't exist."""
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(RECV_DIR, exist_ok=True)

def check_disk_space(path: str, required_mb: int = MIN_DISK_SPACE_MB) -> bool:
    """
    Check if sufficient disk space is available (cross-platform).
    
    SECURITY: Returns False on ANY error (fail-safe) - prevents writes on uncertain space
    """
    try:
        if not os.path.exists(path):
            print(f"⚠️ Path does not exist: {path}")
            log_operation("Check Disk Space", path, "DISK_CHECK", "FAILED", error="Path does not exist")
            return False
        
        if sys.platform == 'win32':
            import shutil
            free_bytes = shutil.disk_usage(path).free
            free_mb = free_bytes / (1024 * 1024)
        else:
            stat_info = os.statvfs(path)
            free_mb = (stat_info.f_bavail * stat_info.f_frsize) / (1024 * 1024)
        
        if free_mb < required_mb:
            print(f"⚠️ Insufficient disk space: {free_mb:.2f} MB free, {required_mb} MB required")
            log_operation("Check Disk Space", path, "DISK_CHECK", "FAILED", error=f"Insufficient space: {free_mb:.2f} MB < {required_mb} MB")
            return False
        
        return True
    except PermissionError as e:
        print(f"❌ Permission denied checking disk space: {path}")
        log_operation("Check Disk Space", path, "DISK_CHECK", "FAILED", error=f"Permission denied: {str(e)}")
        return False
    except OSError as e:
        print(f"❌ OS error checking disk space: {path}")
        log_operation("Check Disk Space", path, "DISK_CHECK", "FAILED", error=f"OS error: {str(e)}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error checking disk space: {path}")
        log_exception("Check Disk Space", path, "DISK_CHECK", e)
        return False  # FAIL-SAFE: Never allow on exception

def safe_input(prompt: str, password: bool = False) -> Optional[str]:
    """Safely get user input with interrupt handling."""
    try:
        if password:
            return getpass.getpass(prompt)
        return input(prompt).strip()
    except KeyboardInterrupt:
        print("\n⚠️ Operation cancelled, returning to menu...")
        return None
    except EOFError:
        return None

def sanitize_path(path_input: str) -> str:
    """
    Remove surrounding quotes from file paths.
    Handles both single and double quotes that Windows may include when dragging files.
    
    Args:
        path_input: Raw path string from user input
    
    Returns:
        Cleaned path string without quotes
    """
    if not path_input:
        return path_input
    
    path_clean = path_input.strip()
    
    # Remove surrounding quotes (single or double)
    if len(path_clean) >= 2:
        if (path_clean[0] == '"' and path_clean[-1] == '"') or \
           (path_clean[0] == "'" and path_clean[-1] == "'"):
            path_clean = path_clean[1:-1]
    
    # Also remove escaped quotes
    path_clean = path_clean.replace('\\"', '"').replace("\\'", "'")
    
    return path_clean

def sha256_bytes(data: bytes) -> str:
    """Compute SHA256 checksum of bytes (v1.2 security patch)."""
    return hashlib.sha256(data).hexdigest()

def estimate_qr_count(data_size: int) -> int:
    """
    Estimate number of QR codes needed for given data size.
    
    Strategy: 
    1. Create a test payload similar to actual data
    2. Actually compress with gzip to get real compression ratio
    3. Base64 encode to get real overhead
    4. Calculate actual chunks needed (2600-byte chunks)
    
    Args:
        data_size: Size of data in bytes (before compression)
    
    Returns:
        Estimated number of QR codes
    """
    try:
        # Create test data representative of actual file
        test_data = os.urandom(min(data_size, 10240))
        
        compressed = gzip.compress(test_data, compresslevel=9)
        compression_ratio = len(compressed) / len(test_data)
        estimated_compressed = int(data_size * compression_ratio)
        estimated_b64 = int(estimated_compressed * 1.34)
        
        chunk_size = 2600
        available_per_chunk = chunk_size - 121
        num_qr = estimated_b64 // available_per_chunk
        if estimated_b64 % available_per_chunk:
            num_qr += 1
        
        return max(1, num_qr)
    except Exception:
        compressed_size = int(data_size * 0.5 * 1.34)
        available = 2600 - 121
        return max(1, (compressed_size // available) + (1 if compressed_size % available else 0))

def check_file_size_limit(file_path: str) -> bool:
    """
    Check if file size is within acceptable limits for QR generation.
    Files > 0.2 MB are rejected.
    
    Args:
        file_path: Path to the file
    
    Returns:
        True if file is within limits, False if too large or error
    
    SECURITY: Returns False on ANY error (fail-safe) - never allow unknown files
    """
    try:
        if not os.path.exists(file_path):
            print(f"⚠️ File does not exist: {file_path}")
            log_operation("Check File Size", file_path, "VALIDATION", "FAILED", error="File does not exist")
            return False
        
        if not os.path.isfile(file_path):
            print(f"⚠️ Path is not a file: {file_path}")
            log_operation("Check File Size", file_path, "VALIDATION", "FAILED", error="Path is not a regular file")
            return False
        
        file_size = os.path.getsize(file_path)
        file_size_mb = file_size / (1024 * 1024)
        
        if file_size_mb > MAX_FILE_SIZE_MB:
            return False
        else:
            return True
    except PermissionError as e:
        print(f"❌ Permission denied reading file: {file_path}")
        log_operation("Check File Size", file_path, "VALIDATION", "FAILED", error=f"Permission denied: {str(e)}")
        return False
    except OSError as e:
        print(f"❌ OS error reading file size: {file_path}")
        log_operation("Check File Size", file_path, "VALIDATION", "FAILED", error=f"OS error: {str(e)}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error checking file size: {file_path}")
        log_exception("Check File Size", file_path, "VALIDATION", e)
        return False  # FAIL-SAFE: Never allow on exception

# ============================================================================
# CRYPTOGRAPHY - KEY DERIVATION
# ============================================================================

def derive_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    Derive a cryptographic key from a password using PBKDF2.
    
    Args:
        password: The password string
        salt: Optional salt (generated if not provided)
    
    Returns:
        Tuple of (derived_key, salt)
    """
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key, salt

# ============================================================================
# CRYPTOGRAPHY - AES
# ============================================================================

def aes_encrypt(data: bytes, password: str) -> bytes:
    """
    Encrypt data using AES-256-GCM (AEAD - authenticated encryption) in FSS1 format.
    v1.4 Upgrade: Now uses FSS1 format with embedded hash for FileSecureSuite compatibility.
    
    FSS1 Format: magic(4) + version(1) + hash_len(4) + hash(32) + salt(16) + nonce(12) + ciphertext+tag(variable)
    
    Returns:
        FSS1 formatted encrypted blob
    """
    try:
        # Calculate SHA256 of original data (for integrity verification)
        file_hash = hashlib.sha256(data).digest() 
        file_hash_hex = file_hash.hex()
        
        key, salt = derive_key_from_password(password)
        aesgcm = AESGCM(key)
        nonce = os.urandom(AESGCM_NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)
        magic = b"FSS1"
        version = struct.pack('>B', 1)  # Version 1 = PBKDF2 + AES-256-GCM
        hash_len = struct.pack('>I', len(file_hash)) 
        
        result = magic + version + hash_len + file_hash + salt + nonce + ciphertext
        log_operation("AES Encrypt", "", "AES", "OK", additional=f"data_size={len(data)}")
        return result
    except Exception as e:
        log_exception("AES Encrypt", "", "AES", e, include_traceback=False)
        raise

def aes_decrypt(enc: bytes, password: str) -> Tuple[bytes, str]:
    """
    Decrypt AES-256-GCM encrypted data in FSS1 format with authentication verification.
    
    Expected FSS1 format: magic(4) + version(1) + hash_len(4) + hash(32) + salt(16) + nonce(12) + ciphertext+tag(variable)
    
    Returns:
        Tuple of (plaintext, hash_hex) for integrity verification
    """
    try:
        # Validate FSS1 format
        if not enc.startswith(b"FSS1"):
            raise ValueError("Invalid file format - not FSS1 compatible")
        
        if len(enc) < (4 + 1 + 4 + 32 + 16 + 12 + 16):  # Minimum viable encrypted blob
            raise ValueError("Encrypted blob too short")
        
        # Parse FSS1 header
        version = enc[4]
        if version != 1:
            raise ValueError(f"Unsupported FSS1 version: {version}")
        
        hash_len = struct.unpack('>I', enc[5:9])[0]
        if hash_len != 32:
            raise ValueError(f"Invalid hash length: {hash_len}")
        
        # Extract hash and crypto material
        file_hash_hex = enc[9:9+32].hex()
        salt = enc[9+32:9+32+16]
        nonce = enc[9+32+16:9+32+28]
        ciphertext = enc[9+32+28:]
        
        # Decrypt with password-derived key
        key, _ = derive_key_from_password(password, salt)
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
            
            # CRITICAL SECURITY: Verify plaintext hash matches FSS1 header
            computed_hash = hashlib.sha256(plaintext).digest().hex()
            if computed_hash != file_hash_hex:
                error_msg = f"Hash mismatch: expected {file_hash_hex}, got {computed_hash}"
                log_operation("AES Decrypt", "", "AES", "FAILED", error=error_msg)
                raise ValueError(f"INTEGRITY CHECK FAILED: {error_msg}")
            
            log_operation("AES Decrypt", "", "AES", "OK", additional=f"plaintext_size={len(plaintext)}")
            return plaintext, file_hash_hex
        except InvalidTag:
            log_operation("AES Decrypt", "", "AES", "FAILED", error="Authentication failed - wrong password or corrupted data")
            raise ValueError("Authentication failed: incorrect password or corrupted data")
    except Exception as e:
        log_exception("AES Decrypt", "", "AES", e, include_traceback=False)
        raise

# ============================================================================
# CRYPTOGRAPHY - RSA HYBRID
# ============================================================================

def load_and_verify_rsa_public_key(key_path: str) -> Optional[str]:
    """
    Load RSA public key from PEM file and display key info.
    
    Args:
        key_path: Path to PEM file with public key
    
    Returns:
        PEM key content as string if valid, None otherwise
    """
    try:
        if not os.path.exists(key_path):
            print("❌ Public key file not found")
            return None
        
        with open(key_path, 'r') as f:
            pubpem = f.read()
        
        # Load key to get size info
        pub_key = serialization.load_pem_public_key(pubpem.encode(), backend=default_backend())
        key_size = pub_key.key_size
        
        # Display key info
        print(f"✅ RSA Key Loaded: {key_size} bits")
        
        return pubpem
    except Exception as e:
        print(f"❌ Error loading RSA key: {e}")
        return None

def validate_rsa_key(public_key) -> bool:
    """Validate RSA public key meets minimum requirements."""
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Invalid key type: must be RSA public key")
    if public_key.key_size < MIN_RSA_KEY_SIZE:
        raise ValueError(f"RSA key too small: {public_key.key_size} bits (minimum {MIN_RSA_KEY_SIZE} required)")
    return True

def rsa_encrypt_hybrid(data: bytes, pubkey_pem: str) -> bytes:
    """
    Encrypt using RSA-4096 hybrid encryption with AES-256-GCM in FSS1 format.
    v1.4 Upgrade: Now uses FSS1 format with embedded hash for FileSecureSuite compatibility.
    
    Process:
    1. Calculate SHA256 hash of original data
    2. Generate random AES-256 key and nonce
    3. Encrypt AES key with RSA-4096 OAEP (SHA-256)
    4. Encrypt payload with AES-256-GCM
    5. Return FSS1 formatted blob
    
    FSS1 Format (RSA): magic(4) + version(1) + hash_len(4) + hash(32) + key_len(2) + 
                       encrypted_key(variable) + salt(16) + nonce(12) + ciphertext+tag(variable)
    
    Note: Salt is included for FSS1 compatibility with FileSecureSuite (even though not used for RSA).
    
    Returns:
        FSS1 formatted encrypted blob
    """
    try:
        # Calculate SHA256 of original data (for integrity verification)
        file_hash = hashlib.sha256(data).digest() 
        file_hash_hex = file_hash.hex()
        
        symkey = os.urandom(32)  # AES-256 key
        salt = os.urandom(16)    # Random salt (FSS1 compatibility - not used in RSA, but included in format)
        nonce = os.urandom(AESGCM_NONCE_SIZE)  # GCM nonce
        
        # Encrypt payload with AES-256-GCM (authenticated)
        cipher = AESGCM(symkey)
        ciphertext = cipher.encrypt(nonce, data, associated_data=None)
        
        # Encrypt AES key with RSA-4096 OAEP
        pub = serialization.load_pem_public_key(pubkey_pem.encode(), backend=default_backend())
        validate_rsa_key(pub)
        enc_key = pub.encrypt(
            symkey,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        magic = b"FSS1"
        version = struct.pack('>B', 1)  # Version 1 = RSA-4096 + AES-256-GCM
        hash_len = struct.pack('>I', len(file_hash)) 
        key_len = len(enc_key).to_bytes(2, 'big')
        
        result = magic + version + hash_len + file_hash + key_len + enc_key + salt + nonce + ciphertext
        log_operation("RSA Encrypt", "", "RSA", "OK", additional=f"data_size={len(data)}")
        return result
    except Exception as e:
        log_exception("RSA Encrypt", "", "RSA", e, include_traceback=False)
        raise

def rsa_decrypt_hybrid(enc: bytes, privkey_path: str, privpass: str = None) -> Tuple[bytes, str]:
    """
    Decrypt RSA-4096 hybrid encryption with AES-256-GCM in FSS1 format.
    
    Expected FSS1 format (RSA): magic(4) + version(1) + hash_len(4) + hash(32) + key_len(2) + 
                                encrypted_key(variable) + salt(16) + nonce(12) + ciphertext+tag(variable)
    
    Salt in RSA Format - FSS1 STANDARD COMPLIANCE:
    ================================================
    - Salt is included in FSS1 format for structural consistency with AES variant
    - In RSA mode: salt is NOT used for key derivation (RSA key is random, not derived)
    - In AES mode: salt IS used for PBKDF2 key derivation
    - This maintains format consistency across both encryption modes
    - Salt is extracted but discarded during RSA decryption
    - Keeping salt in format ensures compatibility with FileSecureSuite and other FSS1 tools
    
    Returns:
        Tuple of (plaintext, hash_hex) for integrity verification
    
    Raises:
        ValueError: If format validation, RSA decryption, or hash verification fails
    """
    # Parse FSS1 header and validate format
    if not enc.startswith(b"FSS1"):
        raise ValueError("Invalid file format - not FSS1 compatible")
    
    if len(enc) < (4 + 1 + 4 + 32 + 2 + 100 + 16 + 12 + 16):  # Minimum viable encrypted blob
        raise ValueError("Invalid RSA blob: too short")
    
    # Parse FSS1 header
    version = enc[4]
    if version != 1:
        raise ValueError(f"Unsupported FSS1 version: {version}")
    
    hash_len = struct.unpack('>I', enc[5:9])[0]
    if hash_len != 32:
        raise ValueError(f"Invalid hash length: {hash_len}")
    
    # Extract hash and key length
    file_hash_hex = enc[9:9+32].hex()
    key_len = int.from_bytes(enc[9+32:9+32+2], 'big')
    
    if key_len < 100 or key_len > 1024:
        raise ValueError(f"Invalid RSA key size: {key_len}")
    
    # Extract crypto material (FSS1 format parsing)
    enc_key = enc[9+32+2:9+32+2+key_len]
    # NOTE: salt extracted for format compliance, but not used in RSA decryption
    # (only used in AES mode for PBKDF2 key derivation)
    salt = enc[9+32+2+key_len:9+32+2+key_len+16]
    nonce = enc[9+32+2+key_len+16:9+32+2+key_len+28]
    ciphertext = enc[9+32+2+key_len+28:]
    
    try:
        # Step 1: Load RSA private key
        with open(privkey_path, 'rb') as f:
            priv = serialization.load_pem_private_key(
                f.read(),
                password=privpass.encode() if privpass else None,
                backend=default_backend()
            )
        
        # Step 2: Decrypt AES key using RSA-4096 OAEP
        try:
            symkey = priv.decrypt(
                enc_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
        except Exception as e:
            error_msg = f'RSA decryption failed: {str(e)}'
            log_operation("RSA Decrypt", "", "RSA", "FAILED", error=error_msg)
            raise ValueError(error_msg)
        
        # Validate decrypted AES key
        if len(symkey) != 32:
            error_msg = f'Decrypted key length invalid: got {len(symkey)}, expected 32'
            log_operation("RSA Decrypt", "", "RSA", "FAILED", error=error_msg)
            raise ValueError(error_msg)
        
        # Step 3: Decrypt payload with AES-256-GCM (authenticated)
        try:
            cipher = AESGCM(symkey)
            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
        except InvalidTag:
            error_msg = "Authentication failed: RSA-decrypted key is invalid or ciphertext is corrupted"
            log_operation("RSA Decrypt", "", "RSA", "FAILED", error=error_msg)
            raise ValueError(error_msg)
        
        # Step 4: CRITICAL SECURITY - Verify plaintext hash matches FSS1 header
        computed_hash = hashlib.sha256(plaintext).digest().hex()
        if computed_hash != file_hash_hex:
            error_msg = f"Hash mismatch: expected {file_hash_hex}, got {computed_hash}"
            log_operation("RSA Decrypt", "", "RSA", "FAILED", error=error_msg)
            raise ValueError(f"INTEGRITY CHECK FAILED: {error_msg}")
        
        log_operation("RSA Decrypt", "", "RSA", "OK", additional=f"plaintext_size={len(plaintext)}")
        return plaintext, file_hash_hex
        
    except Exception as e:
        log_exception("RSA Decrypt", "", "RSA", e, include_traceback=False)
        raise

# ============================================================================
# QR CODE UTILITIES
# ============================================================================

def _unique_outname(name: str) -> str:
    """Generate unique filename with UUID suffix to avoid overwrites."""
    base, ext = os.path.splitext(name)
    uid = uuid.uuid4().hex[:8]
    timestamp = int(time.time() * 1000) % 100000
    return f"{base}__{uid}_{timestamp}{ext}"

def safe_filename(filename: str) -> str:
    """
    CRITICAL SECURITY: Sanitize filename to prevent path-traversal attacks.
    
    - Strips directory components with os.path.basename()
    - Removes dangerous characters
    - Prevents .. and other traversal attempts
    - Returns safe filename suitable for use in OUT_DIR/RECV_DIR
    
    Args:
        filename: Potentially malicious filename from QR payload/user
    
    Returns:
        Sanitized safe filename (no path separators or traversal sequences)
    """
    import re
    
    if not filename:
        return "file"
    
    filename = os.path.basename(filename)
    filename = filename.replace('\x00', '').replace('\r', '').replace('\n', '')
    filename = filename.replace('..', '').replace('./', '').replace('~', '')
    filename = re.sub(r'[^a-zA-Z0-9._\-]', '_', filename)
    filename = filename.lstrip('.')
    filename = filename[:255]
    
    if not filename or filename == '':
        filename = 'recovered_file'
    
    return filename

def verify_output_path(output_path: str, allowed_dir: str) -> bool:
    """
    CRITICAL SECURITY: Verify that output path is within allowed directory.
    Prevents symlink/path-traversal attacks even after sanitization.
    
    Args:
        output_path: Full path to write file
        allowed_dir: Directory that must contain the file
    
    Returns:
        True if output_path is safely within allowed_dir, False otherwise
    """
    try:
        # Normalize both paths to absolute, resolving symlinks
        real_output = os.path.realpath(os.path.abspath(output_path))
        real_allowed = os.path.realpath(os.path.abspath(allowed_dir))
        
        # Check if output is under allowed directory
        common = os.path.commonpath([real_allowed, real_output])
        return common == real_allowed
    except (ValueError, OSError):
        return False

def build_payload_header(uid: str, idx: int, total: int, filename: str, alg: str) -> str:
    """Build JSON header for multi-part QR payloads."""
    header = {"id": uid, "i": idx, "t": total, "n": filename, "a": alg}
    return json.dumps(header, separators=(',', ':'))

def save_qr_image_from_payload(payload: str, out_path: str):
    """Generate and save a QR code image from payload string."""
    try:
        qr = qrcode.QRCode(
            version=None,  # Auto-detect version
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4
        )
        qr.add_data(payload)
        qr.make(fit=True)
        
        # Verify version is within limits
        if qr.version > 40:
            raise ValueError(f"QR version {qr.version} exceeds maximum (40). Payload too large: {len(payload)} chars")
        
        img = qr.make_image(fill_color='black', back_color='white')
        img.save(out_path)
    except Exception as e:
        raise ValueError(f"Failed to generate QR code: {str(e)}")

# ============================================================================
# QR CREATION - NONE MODE (TEXT)
# ============================================================================

def create_qr_images_for_none_text(text: str, filename: str, ask_encoding: bool = False) -> Tuple[List[str], str]:
    """
    Create QR code(s) for plain text (NONE mode).
    
    If text <= 1200 bytes and ask_encoding=True: ask user for encoding preference
    If text > 1200 bytes: automatically use compressed base64
    
    Args:
        text: Text to encode
        filename: Base filename
        ask_encoding: If True and text <= 1200, ask user for readable or base64
    
    Returns:
        Tuple of (list_of_qr_paths, unique_filename_used)
    """
    text_size = len(text)
    
    if text_size <= 1200 and ask_encoding:
        print("\n📝 ENCODING OPTIONS FOR NONE MODE:")
        print("1) Readable text (raw UTF-8)")
        print("2) Base64 compressed (smaller QR)")
        encoding_choice = safe_input("Choose encoding (1-2): ")
        
        if encoding_choice == '1':
            safe_name = _unique_outname(filename)
            
            qr_name = f"{os.path.splitext(safe_name)[0]}_1_of_1_{filename}.png"
            qr_path = os.path.join(OUT_DIR, qr_name)
            save_qr_image_from_payload(text, qr_path)
            print(f"✓ Created 1 readable QR code")
            
            save_choice = safe_input("Save text file? (yes/no): ").strip().lower()
            if save_choice in ['yes', 'y', 'si', 's']:
                out_path = os.path.join(OUT_DIR, safe_name)
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(text)
                print(f"✅ Text file saved: {out_path}")
            else:
                print(f"⊘ Text file not saved")
            
            return [qr_path], safe_name
        elif encoding_choice == '2':
            # Create compressed QR
            print(f"✓ Creating compressed QR code...")
            data_bytes = text.encode('utf-8')
            return create_qr_images_from_bytes_with_unique(data_bytes, filename, 'NONE')
        else:
            print("❌ Invalid choice")
            return [], ""
    elif text_size <= 1200:
        # Text fits in 1 QR but no asking - default to readable
        safe_name = _unique_outname(filename)
        
        qr_name = f"{os.path.splitext(safe_name)[0]}_1_of_1_{filename}.png"
        qr_path = os.path.join(OUT_DIR, qr_name)
        save_qr_image_from_payload(text, qr_path)
        print(f"✓ Created 1 readable QR code")
        
        save_choice = safe_input("Save text file? (yes/no): ").strip().lower()
        if save_choice in ['yes', 'y', 'si', 's']:
            out_path = os.path.join(OUT_DIR, safe_name)
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(text)
            print(f"✅ Text file saved: {out_path}")
        else:
            print(f"⊘ Text file not saved")
        
        return [qr_path], safe_name
    else:
        # Text > 1200 bytes - automatic compression (no question asked)
        print(f"✓ Text is {text_size} bytes (exceeds 1200 byte readable limit)")
        print(f"✓ Creating compressed multi-QR code(s)...")
        data_bytes = text.encode('utf-8')
        return create_qr_images_from_bytes_with_unique(data_bytes, filename, 'NONE')

def create_qr_images_from_bytes_with_unique(data_bytes: bytes, filename: str, alg: str, uid: str = None) -> Tuple[List[str], str]:
    """
    Create QR codes from binary data with compression and chunking.
    WITH VERIFICATION that all files are created on disk.
    
    Strategy:
    1. Compress entire file with gzip
    2. Encode compressed data as base64
    3. Split base64 into 2600-byte chunks
    4. Create QR code for each chunk with header
    5. VERIFY all files exist on disk
    
    Args:
        data_bytes: Binary data to encode
        filename: Base filename for output
        alg: Encryption algorithm used (NONE, AES, RSA)
        uid: Optional unique ID for multi-part encoding
    
    Returns:
        Tuple of (list_of_qr_paths, unique_filename_used)
    """
    compressed = gzip.compress(data_bytes, compresslevel=9)
    data_checksum = sha256_bytes(data_bytes)
    b64 = base64.b64encode(compressed)
    chunk_size = 2600
    chunks = [b64[i:i+chunk_size] for i in range(0, len(b64), chunk_size)]
    
    total = len(chunks)
    if uid is None:
        uid = str(uuid.uuid4())
    safe_filename = _unique_outname(filename)
    out_files = []
    failed_files = []
    for i, chunk_bytes in enumerate(chunks, start=1):
        # Decode chunk back to string for payload
        ch = chunk_bytes.decode('ascii')
        header_dict = {
            "id": uid, 
            "i": i, 
            "t": total, 
            "n": safe_filename, 
            "a": alg, 
            "checksum": data_checksum,
            "c": 1  # compression flag: 1 = gzip compressed
        }
        header = json.dumps(header_dict, separators=(',', ':'))
        payload = header + "\n" + ch
        qr_name = f"{uid}_{i:03d}_of_{total}_{safe_filename}.png"
        qr_path = os.path.join(OUT_DIR, qr_name)
        save_qr_image_from_payload(payload, qr_path)
        out_files.append(qr_path)
    
    # VERIFY all files exist on disk
    print(f"\n✓ Verifying {total} QR code file(s) on disk...")
    verified_files = []
    for i, qr_path in enumerate(out_files, start=1):
        if os.path.exists(qr_path):
            file_size = os.path.getsize(qr_path)
            verified_files.append(qr_path)
            print(f"  ✓ Part {i}/{total}: {os.path.basename(qr_path)} ({file_size} bytes)")
        else:
            failed_files.append(qr_path)
            print(f"  ❌ Part {i}/{total}: MISSING - {os.path.basename(qr_path)}")
    if len(verified_files) != total:
        print(f"\n❌ VERIFICATION FAILED: {len(verified_files)}/{total} files created")
        print(f"   Missing: {total - len(verified_files)} file(s)")
        for missing in failed_files:
            print(f"   - {missing}")
        raise IOError(f"Failed to create all {total} QR code files. Only {len(verified_files)} of {total} saved.")
    else:
        print(f"✓ ALL {total} QR files verified successfully!")
    
    return out_files, safe_filename

def create_from_text(text: str, alg: str, password: str = None, pubkey_pem: str = None, name: str = 'message.txt') -> dict:
    """Create QR code(s) from text with specified encryption."""
    ensure_dirs()
    try:
        if not check_disk_space(OUT_DIR):
            raise IOError("Insufficient disk space")
        
        text_bytes = text.encode('utf-8')
        text_size = len(text_bytes)
        
        if alg == 'NONE':
            log_operation("Create QR - Text", name, "NONE", "OK", additional=f"size={text_size}")
            print(f"\n📊 Text size: {text_size} bytes")
            
            if text_size <= 1200:
                print(f"✓ Text fits in 1 QR code (readable limit: 1200 bytes)")
                
                # For PEM format, extract only the PEM content
                if '-----BEGIN' in text and '-----END' in text:
                    start_idx = text.find('-----BEGIN')
                    end_idx = text.find('-----END')
                    if start_idx != -1 and end_idx != -1:
                        end_idx = text.find('\n', end_idx)
                        if end_idx == -1:
                            end_idx = len(text)
                        pem_text = text[start_idx:end_idx]
                        pem_clean = pem_text.replace('\n', '')
                        print(f"✓ PEM format detected - cleaned for QR scanning")
                        qr_files, saved_name = create_qr_images_for_none_text(pem_clean, name, ask_encoding=True)
                        return {'saved': os.path.join(OUT_DIR, saved_name), 'qrs': qr_files, 'uid': None}
                
                # Regular text - ask for encoding
                qr_files, saved_name = create_qr_images_for_none_text(text, name, ask_encoding=True)
                return {'saved': os.path.join(OUT_DIR, saved_name), 'qrs': qr_files, 'uid': None}
            else:
                # Text > 1200 bytes - automatic compression (no question asked)
                print(f"⚠️  Text exceeds 1200 byte readable limit")
                print(f"✓ Creating compressed multi-QR code(s)...")
                qr_files, saved_name = create_qr_images_for_none_text(text, name, ask_encoding=False)
                return {'saved': os.path.join(OUT_DIR, saved_name), 'qrs': qr_files, 'uid': None}
        elif alg == 'AES':
            if not password:
                raise ValueError('AES requires a password')
            print(color_info(f"\n📊 Text size: {text_size} bytes"))
            enc = aes_encrypt(text_bytes, password)
            print(color_info(f"📦 Encrypted size: {len(enc)} bytes"))
            saved_name = _unique_outname(name + '.aes')
            
            qr_files, uid = create_qr_images_from_bytes_with_unique(enc, saved_name, 'AES')
            print(color_success(f"🖼️  Created {len(qr_files)} QR code(s)"))
            
            save_choice = safe_input("Save encrypted file? (yes/no): ").strip().lower()
            if save_choice in ['yes', 'y', 'si', 's']:
                outpath = os.path.join(OUT_DIR, saved_name)
                try:
                    with open(outpath, 'wb') as f:
                        f.write(enc)
                    print(color_success(f"✅ Encrypted file saved: {outpath}"))
                    log_operation("Save File - AES Text", saved_name, "AES", "OK", additional=f"size={len(enc)}")
                except IOError as e:
                    print(color_error(f"❌ Failed to save file: {e}"))
                    log_exception("Save File - AES Text", outpath, "AES", e)
                    outpath = None
            else:
                print(f"⊘ Encrypted file not saved")
                outpath = None
            
            return {'saved': outpath, 'qrs': qr_files, 'uid': uid}
        elif alg == 'RSA':
            if not pubkey_pem:
                raise ValueError('RSA requires a public key PEM')
            print(color_info(f"\n📊 Text size: {text_size} bytes"))
            enc = rsa_encrypt_hybrid(text_bytes, pubkey_pem)
            print(color_info(f"📦 Encrypted size: {len(enc)} bytes"))
            saved_name = _unique_outname(name + '.rsa')
            
            qr_files, uid = create_qr_images_from_bytes_with_unique(enc, saved_name, 'RSA')
            print(color_success(f"🖼️  Created {len(qr_files)} QR code(s)"))
            
            save_choice = safe_input("Save encrypted file? (yes/no): ").strip().lower()
            if save_choice in ['yes', 'y', 'si', 's']:
                outpath = os.path.join(OUT_DIR, saved_name)
                try:
                    with open(outpath, 'wb') as f:
                        f.write(enc)
                    print(color_success(f"✅ Encrypted file saved: {outpath}"))
                    log_operation("Save File - RSA Text", saved_name, "RSA", "OK", additional=f"size={len(enc)}")
                except IOError as e:
                    print(color_error(f"❌ Failed to save file: {e}"))
                    log_exception("Save File - RSA Text", outpath, "RSA", e)
                    outpath = None
            else:
                print(f"⊘ Encrypted file not saved")
                outpath = None
            
            return {'saved': outpath, 'qrs': qr_files, 'uid': uid}
        else:
            raise ValueError('Unsupported algorithm')
    except Exception as e:
        log_exception("Create QR - Text", name, alg, e)
        raise

def create_from_file(path: str, alg: str, password: str = None, pubkey_pem: str = None) -> dict:
    """Create QR code(s) from file with specified encryption."""
    ensure_dirs()
    try:
        if not check_disk_space(OUT_DIR):
            raise IOError("Insufficient disk space")
        
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        with open(path, 'rb') as f:
            data = f.read()
        base = os.path.basename(path)
        file_size = len(data)
        
        if alg == 'NONE':
            is_text = is_text_file(data)
            
            if is_text:
                text = decode_text_file(data)
                print(f"\n📊 File size: {file_size} bytes (Text detected)")
                log_operation("Create QR - File", base, "NONE", "OK", additional=f"type=text, size={file_size}")
                
                if file_size <= 1200:
                    print(f"✓ File fits in 1 QR code (readable limit: 1200 bytes)")
                    
                    # For PEM format, extract only the PEM content
                    if '-----BEGIN' in text and '-----END' in text:
                        start_idx = text.find('-----BEGIN')
                        end_idx = text.find('-----END')
                        if start_idx != -1 and end_idx != -1:
                            end_idx = text.find('\n', end_idx)
                            if end_idx == -1:
                                end_idx = len(text)
                            pem_text = text[start_idx:end_idx]
                            pem_clean = pem_text.replace('\n', '')
                            print(f"✓ PEM format detected - cleaned for QR scanning")
                            qr_files, saved_name = create_qr_images_for_none_text(pem_clean, base, ask_encoding=True)
                            return {'saved': os.path.join(OUT_DIR, saved_name), 'qrs': qr_files, 'uid': None}
                    
                    # Regular text file - ask for encoding
                    qr_files, saved_name = create_qr_images_for_none_text(text, base, ask_encoding=True)
                    return {'saved': os.path.join(OUT_DIR, saved_name), 'qrs': qr_files, 'uid': None}
                else:
                    # Text > 1200 bytes - automatic compression (no question asked)
                    print(f"⚠️  File exceeds 1200 byte readable limit")
                    print(f"✓ Creating compressed multi-QR code(s)...")
                    qr_files, saved_name = create_qr_images_for_none_text(text, base, ask_encoding=False)
                    return {'saved': os.path.join(OUT_DIR, saved_name), 'qrs': qr_files, 'uid': None}
            else:
                # Binary file - automatic compression (no question asked)
                file_ext = os.path.splitext(base)[1].lower()
                file_type = "PDF" if file_ext == ".pdf" else "binary file"
                print(f"\n⚠️  {file_type.upper()} detected: {file_size} bytes")
                print(f"✓ Creating compressed {file_type}...")
                log_operation("Create QR - File", base, "NONE", "OK", additional=f"type={file_type}, size={file_size}")
                qr_files, saved_name = create_qr_images_from_bytes_with_unique(data, base, 'NONE')
                
                return {'saved': os.path.join(OUT_DIR, saved_name), 'qrs': qr_files, 'uid': None}
        elif alg == 'AES':
            if not password:
                raise ValueError('AES requires a password')
            print(color_info(f"\n📊 File size: {file_size} bytes"))
            enc = aes_encrypt(data, password)
            print(color_info(f"📦 Encrypted size: {len(enc)} bytes"))
            saved_name = _unique_outname(base + '.aes')
            
            qr_files, uid = create_qr_images_from_bytes_with_unique(enc, saved_name, 'AES')
            print(color_success(f"🖼️  Created {len(qr_files)} QR code(s)"))
            
            save_choice = safe_input("Save encrypted file? (yes/no): ").strip().lower()
            if save_choice in ['yes', 'y', 'si', 's']:
                outpath = os.path.join(OUT_DIR, saved_name)
                try:
                    with open(outpath, 'wb') as f:
                        f.write(enc)
                    print(color_success(f"✅ Encrypted file saved: {outpath}"))
                    log_operation("Save File - AES", saved_name, "AES", "OK", additional=f"size={len(enc)}")
                except IOError as e:
                    print(color_error(f"❌ Failed to save file: {e}"))
                    log_exception("Save File - AES", outpath, "AES", e)
                    outpath = None
            else:
                print(f"⊘ Encrypted file not saved")
                outpath = None
            
            return {'saved': outpath, 'qrs': qr_files, 'uid': uid}
        elif alg == 'RSA':
            if not pubkey_pem:
                raise ValueError('RSA requires a public key PEM')
            print(color_info(f"\n📊 File size: {file_size} bytes"))
            enc = rsa_encrypt_hybrid(data, pubkey_pem)
            print(color_info(f"📦 Encrypted size: {len(enc)} bytes"))
            saved_name = _unique_outname(base + '.rsa')
            
            qr_files, uid = create_qr_images_from_bytes_with_unique(enc, saved_name, 'RSA')
            print(color_success(f"🖼️  Created {len(qr_files)} QR code(s)"))
            
            save_choice = safe_input("Save encrypted file? (yes/no): ").strip().lower()
            if save_choice in ['yes', 'y', 'si', 's']:
                outpath = os.path.join(OUT_DIR, saved_name)
                try:
                    with open(outpath, 'wb') as f:
                        f.write(enc)
                    print(color_success(f"✅ Encrypted file saved: {outpath}"))
                    log_operation("Save File - RSA", saved_name, "RSA", "OK", additional=f"size={len(enc)}")
                except IOError as e:
                    print(color_error(f"❌ Failed to save file: {e}"))
                    log_exception("Save File - RSA", outpath, "RSA", e)
                    outpath = None
            else:
                print(f"⊘ Encrypted file not saved")
                outpath = None
            
            return {'saved': outpath, 'qrs': qr_files, 'uid': uid}
        else:
            raise ValueError('Unsupported algorithm')
    except Exception as e:
        log_exception("Create QR - File", path, alg, e)
        raise

# ============================================================================
# QR READING AND DECODING
# ============================================================================

def decode_qr_from_image(img_path: str) -> List[str]:
    """
    Decode QR codes from image file, returns list of decoded strings.
    
    IMPORTANT: Requires cv2 and pyzbar libraries.
    If libraries unavailable, logs warning and returns empty list.
    
    NOTE: Configured to decode ONLY QR codes (not DataBar, PDF417, etc.)
    This prevents zbar assertion warnings for unsupported barcode types.
    
    Returns:
        List of decoded QR payloads, empty list if failed or libraries missing
    """
    if not CV2_AVAILABLE:
        # Log clearly why decoding failed
        log_operation("Decode QR - Image", img_path, "QR_READ", "FAILED", 
                     error=f"CV2/pyzbar not available: {CV2_ERROR}")
        return []
    
    try:
        frame = cv2.imread(img_path)
        if frame is None:
            log_operation("Decode QR - Image", img_path, "QR_READ", "FAILED", 
                         error="Could not read image file (invalid format or corrupted)")
            return []
        
        # Suppress zbar warnings and decode ONLY QR codes (not DataBar, PDF417, etc.)
        with suppress_stderr():
    
            from pyzbar.pyzbar import ZBarSymbol
            # Decode ONLY QR codes to prevent zbar assertion warnings
            decoded = pyzbar.decode(frame, symbols=[ZBarSymbol.QRCODE])
        
        payloads = []
        for d in decoded:
            try:
                payloads.append(d.data.decode('utf-8'))
            except (UnicodeDecodeError, AttributeError):
                # Skip QR codes that can't be decoded as UTF-8
                continue
        
        if payloads:
            log_operation("Decode QR - Image", img_path, "QR_READ", "OK", 
                         additional=f"qr_count={len(payloads)}")
        else:
            log_operation("Decode QR - Image", img_path, "QR_READ", "OK", 
                         additional="No QR codes found in image")
        
        return payloads
    except Exception as e:
        log_exception("Decode QR - Image", img_path, "QR_READ", e)
        return []

def reassemble_payloads(payloads: List[str]) -> dict:
    """Reassemble multi-part QR payloads and return results with checksum verification."""
    raw_results = {}
    header_payloads = []
    
    for p in payloads:
        is_multipart = False
        try:
            h, ch = p.split('\n', 1)
            meta = json.loads(h)
            if 'id' in meta and 'i' in meta and 't' in meta:
                is_multipart = True
                header_payloads.append(p)
        except Exception:
            pass
        
        if not is_multipart:
            # Keep readable text files, but skip numeric artifacts
            # Artifacts are small numeric strings like "0125662064033692"
            is_artifact = len(p) < 50 and p.replace(' ', '').replace('\n', '').isdigit()
            if not is_artifact:
                uid = 'message__' + uuid.uuid4().hex[:8]
                raw_results[uid] = {'complete': True, 'data': p.encode('utf-8'), 'meta': {'n': f"{uid}.txt", 'a': 'NONE'}}
    
    assembled = {}
    if header_payloads:
        groups = {}
        for p in header_payloads:
            try:
                h, ch = p.split('\n', 1)
                meta = json.loads(h)
                uid = meta.get('id')
                if uid not in groups:
                    groups[uid] = {'meta': meta, 'chunks': {}}
                groups[uid]['chunks'][int(meta.get('i'))] = ch
            except Exception:
                continue
        for uid, obj in groups.items():
            meta = obj['meta']
            chunks = obj['chunks']
            total = int(meta['t'])
            if len(chunks) != total:
                missing = [i for i in range(1, total + 1) if i not in chunks]
                assembled[uid] = {'complete': False, 'have': len(chunks), 'total': total, 'missing': missing, 'meta': meta}
                continue
            ordered = ''.join(chunks[i] for i in range(1, total + 1))
            try:
                # Decode base64 and decompress with gzip
                compressed = base64.b64decode(ordered)
                data = gzip.decompress(compressed)
                if 'checksum' in meta and meta['checksum']:
                    calculated_checksum = sha256_bytes(data)
                    stored_checksum = meta['checksum']
                    if calculated_checksum != stored_checksum:
                        assembled[uid] = {
                            'complete': False, 
                            'error': f'Checksum mismatch! Expected {stored_checksum}, got {calculated_checksum}. File may be corrupted.',
                            'meta': meta
                        }
                        continue
                
                assembled[uid] = {'complete': True, 'data': data, 'meta': meta}
            except Exception as e:
                assembled[uid] = {'complete': False, 'error': str(e), 'meta': meta}
    
    results = {}
    results.update(raw_results)
    results.update(assembled)
    return results

def read_and_reconstruct_qr(folder: str) -> Tuple[List[str], dict]:
    """
    Read QR codes from folder and reconstruct payloads.
    
    Returns:
        Tuple of (payloads, results)
    """
    try:
        files = os.listdir(folder)
    except Exception as e:
        print(f"❌ Cannot read folder: {e}")
        return [], {}
    
    if not files:
        print(f"📂 Folder is empty: {folder}")
        return [], {}
    
    print(f"🔍 Scanning folder: {folder}")
    payloads = []
    image_count = 0
    for fn in sorted(files):
        if fn.lower().endswith(('.png', '.jpg', '.jpeg')):
            image_count += 1
            try:
                img_path = os.path.join(folder, fn)
                decoded = decode_qr_from_image(img_path)
                if decoded:
                    payloads.extend(decoded)
            except Exception as e:
                print(f"⚠️ Error reading {fn}: {e}")
                continue
    
    print(f"📊 Found {image_count} image(s), decoded {len(payloads)} QR payload(s)")
    
    if not payloads:
        print("⚠️ No QR codes found in images")
        return [], {}
    
    results = reassemble_payloads(payloads)
    print(f"📦 Reassembled into {len(results)} file(s)")
    return payloads, results

def display_reconstructed_files(results: dict) -> int:
    """
    Display and save reconstructed files from QR results.
    Asks user if they want to decrypt encrypted files.
    Max 3 attempts for password/key before saving encrypted.
    
    Returns:
        Count of successfully saved files or None to exit
    """
    saved_count = 0
    if not results:
        print("ℹ️ No files to save")
        return 0
    
    # First pass: collect all files to process
    file_list = []
    incomplete_files = []
    for uid, res in results.items():
        meta = res.get('meta', {})
        if res.get('complete'):
            raw_fname = meta.get('n') if meta else f"{uid}.txt"
            fname = safe_filename(raw_fname)  # SECURITY: Sanitize filename
            alg = meta.get('a', 'NONE')
            
            # Include all files (raw and multipart)
            file_list.append((uid, res, meta, fname, alg))
        else:
            # Track incomplete files for reporting
            raw_fname = meta.get('n') if meta else f"{uid}.txt"
            fname = safe_filename(raw_fname)  # SECURITY: Sanitize filename
            reason = res.get('error', 'Unknown error')
            incomplete_files.append((fname, reason))
    
    print(f"📊 Processing {len(results)} result(s), {len(file_list)} complete file(s)")
    
    # Show incomplete files with reasons (including checksum failures)
    if incomplete_files:
        print(f"\n⚠️ {len(incomplete_files)} file(s) could not be reconstructed:")
        for fname, reason in incomplete_files:
            if 'Checksum mismatch' in reason:
                print(f"  ❌ {fname}: CHECKSUM VALIDATION FAILED - {reason}")
            elif 'Missing' in reason:
                print(f"  ⚠️ {fname}: {reason}")
            else:
                print(f"  ⚠️ {fname}: {reason}")
    
    if not file_list:
        print("ℹ️ No valid files found")
        return 0
    
    # Show preview of all files
    print(f"\n📋 Found {len(file_list)} valid file(s) to process:")
    for idx, (uid, res, meta, fname, alg) in enumerate(file_list, 1):
        alg_label = f"[{alg}]" if alg != 'NONE' else "[Unencrypted]"
        checksum_icon = "✓" if 'checksum' in meta and meta['checksum'] else ""
        compressed = "📦" if meta.get('c') == 1 else ""
        print(f"{idx}) {fname} {alg_label} {checksum_icon} {compressed}")
    
    # Now process each file
    for file_idx, (uid, res, meta, fname, alg) in enumerate(file_list, 1):
        print(f"\n--- Processing file {file_idx}/{len(file_list)}: {fname} ---")
        
        # Show compression status
        if meta.get('c') == 1:
            print("ℹ️ File was gzip compressed (will be decompressed)")
        if 'checksum' in meta and meta['checksum']:
            print(f"✓ Checksum validation: PASSED")
            print(f"  SHA256: {meta['checksum'][:16]}...")
        
        try:
            if alg == 'AES':
                outp = os.path.join(RECV_DIR, fname)
                
                # SECURITY: Verify output path is within RECV_DIR
                if not verify_output_path(outp, RECV_DIR):
                    print(f"❌ SECURITY ERROR: Malicious path detected: {outp}")
                    log_operation("Read QR - Path Traversal Blocked", fname, "AES", "BLOCKED", error=f"Malicious path: {outp}")
                    continue
                
                try:
                    with open(outp, 'wb') as f:
                        f.write(res['data'])
                    print(color_success(f"✅ Saved: {outp} ({len(res['data'])} bytes)"))
                    log_operation("Read QR - Save (AES)", fname, "AES", "OK", additional=f"size={len(res['data'])}")
                    saved_count += 1
                except IOError as e:
                    print(color_error(f"❌ Failed to save file: {e}"))
                    log_exception("Read QR - Save (AES)", outp, "AES", e)
                    continue
                
                # Ask if user wants to decrypt
                print(f"\n🔐 File {file_idx}/{len(file_list)} is AES encrypted: {fname}")
                decrypt_choice = safe_input("Decrypt now? (yes/no): ").lower().strip()
                if decrypt_choice not in ['yes', 'y', 'si', 's']:
                    print("⚠️ Use Menu 2 to decrypt later")
                    continue  # Skip this file and move to next
                
                decrypted_data = None
                attempts = 0
                max_attempts = 3
                
                while attempts < max_attempts and not decrypted_data:
                    attempts += 1
                    pwd = safe_input(f"🔑 Enter AES password (attempt {attempts}/{max_attempts}): ", password=True)
                    if not pwd:
                        log_operation("Read QR - AES Decrypt", fname, "AES", "SKIPPED", error="User cancelled password entry")
                        print("⚠️ Decryption skipped")
                        break
                    try:
                        decrypted_data, file_hash = aes_decrypt(res['data'], pwd)
                        print("✅ Password correct!")
                        print(f"📝 File hash: {file_hash}")
                        log_operation("Read QR - AES Decrypt", fname, "AES", "OK")
                    except Exception as e:
                        error_msg = str(e)[:100]
                        log_operation("Read QR - AES Decrypt", fname, "AES", "FAILED", error=f"Wrong password (attempt {attempts})")
                        if attempts < max_attempts:
                            print(f"❌ Wrong password. {max_attempts - attempts} attempt(s) remaining")
                        else:
                            print(f"❌ Max attempts reached")
                            log_operation("Read QR - AES Decrypt", fname, "AES", "FAILED", error="Max password attempts exceeded")
                
                if decrypted_data:
                    try:
                        original_data = gzip.decompress(decrypted_data)
                        print("✓ Decompressed to original file format")
                        
                        # Verify checksum if present
                        if 'checksum' in meta and meta['checksum']:
                            file_checksum = sha256_bytes(original_data)
                            if file_checksum == meta['checksum']:
                                print(f"✓ Checksum PASSED: {meta['checksum'][:16]}...")
                            else:
                                print(f"⚠️ Checksum mismatch (may indicate corruption)")
                        
                        decrypted_data = original_data
                    except Exception as e:
                        # Not gzip - file is already in original format
                        print(f"ℹ️ File is not gzip compressed (raw format)")
                    
                    # Save decrypted version
                    fname_dec = fname.replace('.aes', '_decrypted')
                    fname_dec = safe_filename(fname_dec)  # SECURITY: Re-sanitize
                    outp_dec = os.path.join(RECV_DIR, fname_dec)
                    
                    # SECURITY: Verify output path is within RECV_DIR
                    if not verify_output_path(outp_dec, RECV_DIR):
                        print(f"❌ SECURITY ERROR: Malicious path detected: {outp_dec}")
                        log_operation("Read QR - Path Traversal Blocked", fname_dec, "AES", "BLOCKED", error=f"Malicious path: {outp_dec}")
                        continue
                    
                    try:
                        with open(outp_dec, 'wb') as f:
                            f.write(decrypted_data)
                        file_size = len(decrypted_data)
                        print(color_success(f"✅ Decrypted and saved: {outp_dec} ({file_size} bytes)"))
                        log_operation("Read QR - AES Save", fname_dec, "AES", "OK", additional=f"size={file_size}")
                    except IOError as e:
                        print(color_error(f"❌ Failed to save decrypted file: {e}"))
                        log_exception("Read QR - AES Save", outp_dec, "AES", e)
                        continue
                
            elif alg == 'RSA':
                outp = os.path.join(RECV_DIR, fname)
                
                # SECURITY: Verify output path is within RECV_DIR
                if not verify_output_path(outp, RECV_DIR):
                    print(f"❌ SECURITY ERROR: Malicious path detected: {outp}")
                    log_operation("Read QR - Path Traversal Blocked", fname, "RSA", "BLOCKED", error=f"Malicious path: {outp}")
                    continue
                
                try:
                    with open(outp, 'wb') as f:
                        f.write(res['data'])
                    print(color_success(f"✅ Saved: {outp} ({len(res['data'])} bytes)"))
                    log_operation("Read QR - Save (RSA)", fname, "RSA", "OK", additional=f"size={len(res['data'])}")
                    saved_count += 1
                except IOError as e:
                    print(color_error(f"❌ Failed to save file: {e}"))
                    log_exception("Read QR - Save (RSA)", outp, "RSA", e)
                    continue
                
                # Ask if user wants to decrypt
                print(f"\n🔐 File {file_idx}/{len(file_list)} is RSA encrypted: {fname}")
                decrypt_choice = safe_input("Decrypt now? (yes/no): ").lower().strip()
                if decrypt_choice not in ['yes', 'y', 'si', 's']:
                    print("⚠️ Use Menu 2 to decrypt later")
                    continue  # Skip this file and move to next
                
                decrypted_data = None
                attempts = 0
                max_attempts = 3
                
                while attempts < max_attempts and not decrypted_data:
                    attempts += 1
                    priv_path = safe_input(f"🔑 Enter private key PEM path (attempt {attempts}/{max_attempts}): ")
                    if not priv_path:
                        log_operation("Read QR - RSA Decrypt", fname, "RSA", "SKIPPED", error="User cancelled key entry")
                        print("⚠️ Decryption skipped")
                        break
                    
                    priv_path = sanitize_path(priv_path)
                    if not os.path.exists(priv_path):
                        log_operation("Read QR - RSA Decrypt", fname, "RSA", "FAILED", error=f"Key file not found: {priv_path}")
                        if attempts < max_attempts:
                            print(f"❌ Private key not found. {max_attempts - attempts} attempt(s) remaining")
                        else:
                            print(f"❌ Max attempts reached")
                            log_operation("Read QR - RSA Decrypt", fname, "RSA", "FAILED", error="Max key path attempts exceeded")
                        continue
                    
                    print(f"✓ Key file loaded")
                    pwd_attempts = 0
                    while pwd_attempts < max_attempts and not decrypted_data:
                        pwd_attempts += 1
                        priv_pw = safe_input(f"🔑 Private key password (attempt {pwd_attempts}/{max_attempts}) [if empty press enter]: ", password=True)
                        try:
                            decrypted_data, file_hash = rsa_decrypt_hybrid(res['data'], priv_path, priv_pw if priv_pw else None)
                            print("✅ Private key correct!")
                            print(f"📝 File hash: {file_hash}")
                            log_operation("Read QR - RSA Decrypt", fname, "RSA", "OK")
                        except Exception as e:
                            log_operation("Read QR - RSA Decrypt", fname, "RSA", "FAILED", error=f"Wrong password/key (attempt {pwd_attempts})")
                            if pwd_attempts < max_attempts:
                                print(f"❌ Wrong password. {max_attempts - pwd_attempts} attempt(s) remaining")
                            else:
                                print(f"❌ Max password attempts reached for this key")
                
                if decrypted_data:
                    try:
                        original_data = gzip.decompress(decrypted_data)
                        print("✓ Decompressed to original file format")
                        
                        # Verify checksum if present
                        if 'checksum' in meta and meta['checksum']:
                            file_checksum = sha256_bytes(original_data)
                            if file_checksum == meta['checksum']:
                                print(f"✓ Checksum PASSED: {meta['checksum'][:16]}...")
                            else:
                                print(f"⚠️ Checksum mismatch (may indicate corruption)")
                        
                        decrypted_data = original_data
                    except Exception as e:
                        # Not gzip - file is already in original format
                        print(f"ℹ️ File is not gzip compressed (raw format)")
                    
                    # Save decrypted version
                    fname_dec = fname.replace('.rsa', '_decrypted')
                    fname_dec = safe_filename(fname_dec)  # SECURITY: Re-sanitize
                    outp_dec = os.path.join(RECV_DIR, fname_dec)
                    
                    # SECURITY: Verify output path is within RECV_DIR
                    if not verify_output_path(outp_dec, RECV_DIR):
                        print(f"❌ SECURITY ERROR: Malicious path detected: {outp_dec}")
                        log_operation("Read QR - Path Traversal Blocked", fname_dec, "RSA", "BLOCKED", error=f"Malicious path: {outp_dec}")
                        continue
                    
                    try:
                        with open(outp_dec, 'wb') as f:
                            f.write(decrypted_data)
                        file_size = len(decrypted_data)
                        print(color_success(f"✅ Decrypted and saved: {outp_dec} ({file_size} bytes)"))
                        log_operation("Read QR - RSA Save", fname_dec, "RSA", "OK", additional=f"size={file_size}")
                    except IOError as e:
                        print(color_error(f"❌ Failed to save decrypted file: {e}"))
                        log_exception("Read QR - RSA Save", outp_dec, "RSA", e)
                        continue
                
            else:
                # NONE mode - just save
                outp = os.path.join(RECV_DIR, fname)
                
                # SECURITY: Verify output path is within RECV_DIR
                if not verify_output_path(outp, RECV_DIR):
                    print(f"❌ SECURITY ERROR: Malicious path detected: {outp}")
                    log_operation("Read QR - Path Traversal Blocked", fname, "NONE", "BLOCKED", error=f"Malicious path: {outp}")
                    continue
                
                try:
                    with open(outp, 'wb') as f:
                        f.write(res['data'])
                    file_size = len(res['data'])
                    print(color_success(f"✅ Saved: {outp} ({file_size} bytes)"))
                    saved_count += 1
                    log_operation("Read QR - Save (NONE)", fname, "NONE", "OK", additional=f"size={file_size}")
                except IOError as e:
                    print(color_error(f"❌ Failed to save file: {e}"))
                    log_exception("Read QR - Save (NONE)", outp, "NONE", e)
                    continue
                
        except Exception as e:
            error_msg = str(e)[:150]
            print(f"❌ Unexpected error with {fname}: {e}")
            log_exception("Read QR - Process File", fname, "UNKNOWN", e)
    
    return saved_count

# ============================================================================
# MENU FUNCTIONS
# ============================================================================

def prompt_create():
    """Menu: Create QR codes."""
    try:
        os.system('clear' if sys.platform != 'win32' else 'cls')
        print("\n" + "=" * 40)
        print("    📝 CREATE QR CODES")
        print("=" * 40)
        print("LIMITS:")
        print("  • Readable QR: up to 1200 bytes (~1.2 KB)")
        print("  • Single QR: up to 2.9 KB")
        print(f"  • Multi-QR: up to {MAX_FILE_SIZE_MB} MB")
        print()
        print("SELECT:")
        print("1) File")
        print("2) Text")
        choice = safe_input("Select option: ")
        if choice == '1':
            # Loop to allow retrying with different files
            while True:
                path = safe_input("📁 File path: ")
                if not path:
                    os.system('clear' if sys.platform != 'win32' else 'cls')
                    return
                path = sanitize_path(path)
                if not os.path.exists(path):
                    print("❌ File not found")
                    continue
                if not check_file_size_limit(path):
                    file_size_mb = os.path.getsize(path) / (1024 * 1024)
                    file_size = os.path.getsize(path)
                    qr_count = estimate_qr_count(file_size)
                    print()
                    print("❌ FILE TOO LARGE - REJECTED")
                    print(f"   File size: {file_size_mb:.2f} MB (max: {MAX_FILE_SIZE_MB} MB)")
                    print(f"   Would generate: ~{qr_count} QR codes")
                    print()
                    choice = safe_input("Try another file? (yes/no): ").lower().strip()
                    if choice in ['yes', 'y', 'si', 's']:
                        continue
                    else:
                        print("⚠️ Returning to main menu...")
                        os.system('clear' if sys.platform != 'win32' else 'cls')
                        return
                
                # File size is OK - show confirmation and break loop
                file_size_mb = os.path.getsize(path) / (1024 * 1024)
                file_size = os.path.getsize(path)
                qr_count = estimate_qr_count(file_size)
                print()
                print("✅ FILE SIZE OK")
                print(f"   File size: {file_size_mb:.2f} MB ({file_size} bytes)")
                print(f"   QR codes needed: {qr_count} (multi-QR with 2600 byte chunks)")
                print()
                break  # Exit loop, file is valid
            
            alg = choose_encryption()
            if not alg:
                os.system('clear' if sys.platform != 'win32' else 'cls')
                return
            
            print()
            print("📋 SUMMARY:")
            print(f"   Algorithm: {alg}")
            print(f"   QR codes to create: {qr_count}")
            print()
            confirm = safe_input("Proceed with QR creation? (yes/no): ").lower().strip()
            if confirm not in ['yes', 'y', 'si', 's']:
                print("⚠️ Operation cancelled, returning to main menu...")
                os.system('clear' if sys.platform != 'win32' else 'cls')
                return
            
            print()
            print("⏳ Creating QR codes...")
            print()
            
            try:
                if alg == 'AES':
                    print(color_info("PASSWORD REQUIREMENTS:"))
                    print("  • Minimum 8 characters")
                    print("  • At least 2 of: uppercase, lowercase, digit, special character")
                    print()
                    pwd = get_aes_password_with_confirmation()
                    if not pwd:
                        os.system('clear' if sys.platform != 'win32' else 'cls')
                        return
                    res = create_from_file(path, 'AES', password=pwd)
                elif alg == 'RSA':
                    pub_path = safe_input("🔑 Public key PEM path: ")
                    if not pub_path:
                        os.system('clear' if sys.platform != 'win32' else 'cls')
                        return
                    pub_path = sanitize_path(pub_path)
                    pubpem = load_and_verify_rsa_public_key(pub_path)
                    if not pubpem:
                        os.system('clear' if sys.platform != 'win32' else 'cls')
                        return
                    res = create_from_file(path, 'RSA', pubkey_pem=pubpem)
                else:
                    res = create_from_file(path, 'NONE')
                
                if res is None:
                    print("❌ Error: Operation returned no result")
                    os.system('clear' if sys.platform != 'win32' else 'cls')
                    return
                
                # Show results with verification
                num_qrs = len(res['qrs'])
                print()
                print("=" * 50)
                print("✅ QR CREATION COMPLETED SUCCESSFULLY")
                print("=" * 50)
                print(f"QR codes created: {num_qrs}")
                print(f"File saved: {res['saved']}")
                print()
                
                # Verify each file
                print("📋 VERIFICATION - Checking all QR files on disk:")
                verified = 0
                for i, qr_file in enumerate(res['qrs'], 1):
                    if os.path.exists(qr_file):
                        file_size = os.path.getsize(qr_file)
                        print(f"  ✓ Part {i}/{num_qrs}: {file_size} bytes")
                        verified += 1
                    else:
                        print(f"  ❌ Part {i}/{num_qrs}: MISSING!")
                
                print()
                if verified == num_qrs:
                    print(f"✓ CONFIRMED: All {num_qrs} QR files exist on disk")
                else:
                    print(f"⚠️ WARNING: Only {verified}/{num_qrs} files found!")
                print()
                print(f"📁 Location: {OUT_DIR}")
                print(f"📋 Logs available in: logvault/audit.log")
                print("=" * 50)
                print()
            except Exception as e:
                # Log full error to audit trail, show friendly message to user
                log_exception("Create QR - File", path, alg, e)
                print(f"❌ Error: Failed to create QR codes")
                print(f"ℹ️ Check logvault/audit.log for details")
        elif choice == '2':
            text = safe_input("Enter text: ")
            if not text:
                os.system('clear' if sys.platform != 'win32' else 'cls')
                return
            alg = choose_encryption()
            if not alg:
                os.system('clear' if sys.platform != 'win32' else 'cls')
                return
            try:
                if alg == 'AES':
                    print(color_info("PASSWORD REQUIREMENTS:"))
                    print("  • Minimum 8 characters")
                    print("  • At least 2 of: uppercase, lowercase, digit, special character")
                    print()
                    pwd = get_aes_password_with_confirmation()
                    if not pwd:
                        os.system('clear' if sys.platform != 'win32' else 'cls')
                        return
                    res = create_from_text(text, 'AES', password=pwd)
                elif alg == 'RSA':
                    pub_path = safe_input("🔑 Public key PEM path: ")
                    if not pub_path:
                        os.system('clear' if sys.platform != 'win32' else 'cls')
                        return
                    pub_path = sanitize_path(pub_path)
                    pubpem = load_and_verify_rsa_public_key(pub_path)
                    if not pubpem:
                        os.system('clear' if sys.platform != 'win32' else 'cls')
                        return
                    res = create_from_text(text, 'RSA', pubkey_pem=pubpem)
                else:
                    res = create_from_text(text, 'NONE')
                
                if res is None:
                    print("❌ Error: Operation returned no result")
                    os.system('clear' if sys.platform != 'win32' else 'cls')
                    return
                    
                print(f"✅ File saved: {res['saved']}")
                print(f"🖼️ QR(s) created: {len(res['qrs'])}")
                print(f"📋 Logs available in: logvault/audit.log")
                print()
            except Exception as e:
                # Log full error to audit trail, show friendly message to user
                log_exception("Create QR - Text", "message.txt", alg, e)
                print(f"❌ Error: Failed to create QR codes")
                print(f"ℹ️ Check logvault/audit.log for details")
        else:
            os.system('clear' if sys.platform != 'win32' else 'cls')
            return
        
        # Ask if user wants to continue or return to main menu
        while True:
            print()
            choice = safe_input("Do you want to create more QR codes? (yes/no): ").lower().strip()
            if choice in ['yes', 'y', 'si', 's']:
                os.system('clear' if sys.platform != 'win32' else 'cls')
                return prompt_create()  # Restart the function
            elif choice in ['no', 'n', 'no', 'non']:
                os.system('clear' if sys.platform != 'win32' else 'cls')
                return
            else:
                print("❌ Invalid choice. Please enter yes or no")
    except KeyboardInterrupt:
        print("\n⚠️ Operation cancelled, returning to main menu...")

def choose_encryption() -> Optional[str]:
    """Menu: Choose encryption type and return algorithm code."""
    print("\n🔐 ENCRYPTION TYPE:")
    print("1) No encryption")
    print("2) AES (password)")
    print("3) RSA (public key)")
    print("4) 👋 Back to menu")
    c = safe_input("Choose option (1-4): ")
    if c == '1':
        return 'NONE'
    if c == '2':
        return 'AES'
    if c == '3':
        return 'RSA'
    if c == '4':
        return None
    print("❌ Invalid choice")
    return None

def validate_aes_password(password: str) -> bool:
    """
    Validate AES password meets FileSecureSuite security standards.
    
    Requirements:
      • Minimum 8 characters
      • At least 2 of: uppercase, lowercase, digit, special char
    
    Args:
        password: Password to validate
    
    Returns:
        True if valid, False otherwise
    """
    if not password or len(password) < 8:
        print("❌ Password must be at least 8 characters long")
        return False
    
    categories = 0
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    if has_upper:
        categories += 1
    if has_lower:
        categories += 1
    if has_digit:
        categories += 1
    if has_special:
        categories += 1
    
    if categories < 2:
        print("❌ Password must contain at least 2 of: uppercase, lowercase, digit, special character")
        return False
    
    return True

def get_aes_password_with_confirmation() -> Optional[str]:
    """
    Get AES password with validation and confirmation.
    User must enter the same password twice and pass security validation.
    
    Returns:
        Valid password or None if validation fails
    """
    while True:
        pwd = safe_input("🔑 AES password: ", password=True)
        if not pwd:
            return None
        
        if not validate_aes_password(pwd):
            continue
        
        pwd_confirm = safe_input("🔑 Confirm password: ", password=True)
        if not pwd_confirm:
            return None
        
        if pwd != pwd_confirm:
            print("❌ Passwords do not match")
            continue
        
        return pwd

def prompt_webcam_menu():
    """Menu: Scan QR codes from webcam and save captured frames."""
    if not CV2_AVAILABLE:
        print("❌ OpenCV / pyzbar not available")
        print(f"   Reason: {CV2_ERROR}")
        print("   Install with: pip install opencv-python pyzbar")
        log_operation("Scan Webcam", "", "WEBCAM", "FAILED", error=f"OpenCV/pyzbar not available: {CV2_ERROR}")
        os.system('clear' if sys.platform != 'win32' else 'cls')
        return
    ensure_dirs()
    ensure_log_dir()
    os.system('clear' if sys.platform != 'win32' else 'cls')
    print("\n" + "=" * 40)
    print("    📷 SCAN QR FROM WEBCAM")
    print("=" * 40)
    print("Show QR codes to webcam. Press CTRL+C to stop.")
    
    log_operation("Scan Webcam", "", "WEBCAM", "STARTED", additional="Webcam scanning initiated")
    
    try:
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            print("❌ Cannot open webcam. Check if camera is connected.")
            log_operation("Scan Webcam", "", "WEBCAM", "FAILED", error="Cannot open webcam - check camera connection")
            os.system('clear' if sys.platform != 'win32' else 'cls')
            return
            
        seen = set()
        qr_count = 0
        frame_count = 0
        log_operation("Scan Webcam", "", "WEBCAM", "OK", additional="Webcam opened successfully")
        
        while True:
            ret, frame = cap.read()
            if not ret:
                time.sleep(0.1)
                continue
            
            frame_count += 1
            
            # Decode QR codes (ONLY QR codes, not DataBar or PDF417)
            try:
                with suppress_stderr():
                    from pyzbar.pyzbar import ZBarSymbol
                    # Decode ONLY QR codes to prevent zbar assertion warnings
                    decoded = pyzbar.decode(frame, symbols=[ZBarSymbol.QRCODE])
            except Exception as e:
                # Silently continue on pyzbar errors
                continue
            
            for d in decoded:
                try:
                    txt = d.data.decode('utf-8')
                except Exception:
                    continue
                if txt in seen:
                    continue
                seen.add(txt)
                fname = f"{uuid.uuid4().hex[:8]}.png"
                path = os.path.join(RECV_DIR, fname)
                img = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
                img.save(path)
                print(f"💾 QR saved: {path}")
                qr_count += 1
                log_operation("Scan Webcam - Save QR", fname, "WEBCAM", "OK", additional=f"qr_count={qr_count}")
    except KeyboardInterrupt:
        print(color_warning(f"\n⚠️ Webcam reading stopped ({qr_count} QR code(s) saved)"))
        log_operation("Scan Webcam", "", "WEBCAM", "STOPPED", additional=f"User interrupted - {qr_count} QR codes saved, {frame_count} frames processed")
        safe_input("Press Enter to return to main menu...")
    except Exception as e:
        error_msg = str(e)[:100]
        print(color_error(f"❌ Webcam error: {e}"))
        log_exception("Scan Webcam", "", "WEBCAM", e)
        safe_input("Press Enter to return to main menu...")
    finally:
        try:
            cap.release()
            log_operation("Scan Webcam", "", "WEBCAM", "CLOSED", additional=f"Webcam session ended - total QR: {qr_count}")
        except Exception:
            pass
        os.system('clear' if sys.platform != 'win32' else 'cls')

def decrypt_encrypted_files(folder: str) -> bool:
    """
    Decrypt existing .aes/.rsa files in a folder.
    Used when already-reconstructed files need decryption.
    
    Returns:
        True if user wants to decrypt more files (restart folder selection)
        False if user wants to return to main menu
    """
    try:
        files = os.listdir(folder)
    except Exception as e:
        print(f"❌ Cannot read folder: {e}")
        os.system('clear' if sys.platform != 'win32' else 'cls')
        return False
    
    enc_files = [os.path.join(folder, f) for f in files if f.endswith(('.aes', '.rsa'))]
    
    if not enc_files:
        print("⚠️ No encrypted files (.aes, .rsa) found")
        os.system('clear' if sys.platform != 'win32' else 'cls')
        return False
    
    print("\n📋 Encrypted files found:")
    for i, p in enumerate(enc_files, 1):
        file_ext = os.path.splitext(p)[1]
        type_label = "[AES]" if file_ext == '.aes' else "[RSA]"
        print(f"{i}) {os.path.basename(p)} {type_label}")
    
    print("\nOPTIONS:")
    print("  • Number(s): '1', '1,2', or '1, 2'")
    print("  • 'all': decrypt all files")
    print("  • Enter or 'back': return to menu")
    
    # Loop for file selection with retry
    while True:
        choice = safe_input("\nSelect file(s) to decrypt: ").strip().lower()
        
        # Empty input or 'back' - return to menu
        if not choice or choice == 'back':
            os.system('clear' if sys.platform != 'win32' else 'cls')
            return False
        
        # Parse choice
        file_indices = []
        
        if choice == 'all':
            # Decrypt all files
            file_indices = list(range(len(enc_files)))
        else:
            # Parse comma-separated numbers
            try:
                parts = [p.strip() for p in choice.split(',')]
                for part in parts:
                    idx = int(part) - 1
                    if idx < 0 or idx >= len(enc_files):
                        raise ValueError(f"Invalid range: {part}")
                    file_indices.append(idx)
                
                # Remove duplicates and sort
                file_indices = sorted(set(file_indices))
            except (ValueError, IndexError):
                print(f"❌ Invalid choice. Valid options:")
                print(f"   - Single: '1'")
                print(f"   - Multiple: '1,2' or '1, 2, 3'")
                print(f"   - All: 'all'")
                continue
        
        # Decrypt selected files
        for idx in file_indices:
            path = enc_files[idx]
            decrypted_data = None
            attempts = 0
            max_attempts = 3
            
            print(f"\n🔐 File: {os.path.basename(path)}")
            
            if path.endswith('.aes'):
                retry_file = True
                while retry_file:
                    decrypted_data = None
                    attempts = 0
                    while attempts < max_attempts and not decrypted_data:
                        attempts += 1
                        pwd = safe_input(f"🔑 Enter AES password (attempt {attempts}/{max_attempts}): ", password=True)
                        if not pwd:
                            print("⚠️ Password input cancelled")
                            # Ask if user wants to retry
                            retry_pwd = safe_input("Try again? (yes/no): ").strip().lower()
                            if retry_pwd in ['yes', 'y', 'si', 's']:
                                attempts -= 1  # Don't count this as an attempt
                                continue
                            else:
                                break
                        try:
                            with open(path, 'rb') as f:
                                decrypted_data, file_hash = aes_decrypt(f.read(), pwd)
                            print("✅ Password correct!")
                            print(f"📝 File hash: {file_hash}")
                            log_operation("Decrypt File - AES", os.path.basename(path), "AES", "OK")
                        except Exception as e:
                            log_operation("Decrypt File - AES", os.path.basename(path), "AES", "FAILED", error=f"Wrong password (attempt {attempts})")
                            if attempts < max_attempts:
                                print(f"❌ Wrong password. {max_attempts - attempts} attempt(s) remaining")
                            else:
                                print(f"❌ Max password attempts reached")
                    
                    # After password attempts
                    if not decrypted_data:
                        print("\n⚠️ Decryption failed for this file:")
                        print(f"   {os.path.basename(path)}")
                        print("\nOPTIONS:")
                        print("1) Try again with different password")
                        print("2) Skip this file")
                        print("3) Return to menu 2")
                        
                        choice = safe_input("Select option (1-3): ").strip()
                        if choice == '1':
                            retry_file = True  # Retry this file
                        elif choice == '2':
                            retry_file = False  # Skip to next file
                        elif choice == '3':
                            os.system('clear' if sys.platform != 'win32' else 'cls')
                            return False
                        else:
                            print("❌ Invalid choice. Enter 1, 2, or 3")
                            retry_file = True
                    else:
                        retry_file = False  # Successfully decrypted, move to next file
                
                if decrypted_data:
                    try:
                        decompressed_data = gzip.decompress(decrypted_data)
                        print("✓ Decompressed to original file")
                        decrypted_data = decompressed_data
                    except Exception:
                        # Not gzip compressed, use as-is
                        print("ℹ️ File is not gzip compressed (raw/binary format)")
                    
                    base_name = os.path.basename(path).replace('.aes', '')
                    safe_out = _unique_outname(base_name + '_decrypted')
                    outp = os.path.join(RECV_DIR, safe_out)
                    try:
                        with open(outp, 'wb') as f:
                            f.write(decrypted_data)
                        file_size = len(decrypted_data)
                        print(color_success(f"✅ Decrypted and saved: {outp} ({file_size} bytes)"))
                        log_operation("Decrypt File - AES Save", safe_out, "AES", "OK", additional=f"size={file_size}")
                    except IOError as e:
                        print(color_error(f"❌ Failed to save decrypted file: {e}"))
                        log_exception("Decrypt File - AES Save", outp, "AES", e)
            
            elif path.endswith('.rsa'):
                retry_file = True
                while retry_file:
                    decrypted_data = None
                    key_attempts = 0
                    while key_attempts < max_attempts and not decrypted_data:
                        key_attempts += 1
                        priv_path = safe_input(f"🔑 Enter private key PEM path (attempt {key_attempts}/{max_attempts}): ")
                        if not priv_path:
                            print("⚠️ Key path input cancelled")
                            # Ask if user wants to retry
                            retry_key = safe_input("Try again? (yes/no): ").strip().lower()
                            if retry_key in ['yes', 'y', 'si', 's']:
                                key_attempts -= 1  # Don't count this as an attempt
                                continue
                            else:
                                break
                        
                        priv_path = sanitize_path(priv_path)
                        if not os.path.exists(priv_path):
                            log_operation("Decrypt File - RSA", os.path.basename(path), "RSA", "FAILED", error=f"Key file not found: {priv_path}")
                            print(f"❌ Private key not found: {priv_path}")
                            if key_attempts < max_attempts:
                                print(f"   {max_attempts - key_attempts} key attempt(s) remaining")
                            continue
                        
                        # Key found, now try passwords (3 attempts per key)
                        print(f"✓ Key file loaded")
                        pwd_attempts = 0
                        while pwd_attempts < max_attempts and not decrypted_data:
                            pwd_attempts += 1
                            priv_pw = safe_input(f"🔑 Private key password (attempt {pwd_attempts}/{max_attempts}) [if empty press enter]: ", password=True)
                            try:
                                with open(path, 'rb') as f:
                                    decrypted_data, file_hash = rsa_decrypt_hybrid(f.read(), priv_path, priv_pw if priv_pw else None)
                                print("✅ Private key and password correct!")
                                print(f"📝 File hash: {file_hash}")
                                log_operation("Decrypt File - RSA", os.path.basename(path), "RSA", "OK")
                            except Exception as e:
                                log_operation("Decrypt File - RSA", os.path.basename(path), "RSA", "FAILED", error=f"Wrong password/key (attempt {pwd_attempts})")
                                if pwd_attempts < max_attempts:
                                    print(f"❌ Wrong password or invalid key. {max_attempts - pwd_attempts} attempt(s) remaining")
                                else:
                                    print(f"❌ Max password attempts reached for this key")
                        
                        # After password attempts with this key
                        if not decrypted_data and key_attempts < max_attempts:
                            print(f"\n⚠️ All {max_attempts} password attempts failed for this key")
                            retry_key_choice = safe_input("Try with a different key? (yes/no): ").strip().lower()
                            if retry_key_choice not in ['yes', 'y', 'si', 's']:
                                break  # Stop trying different keys
                    
                    # After all key attempts
                    if not decrypted_data:
                        print("\n⚠️ Decryption failed for this file:")
                        print(f"   {os.path.basename(path)}")
                        print("\nOPTIONS:")
                        print("1) Try again with different key/password")
                        print("2) Skip this file")
                        print("3) Return to menu 2")
                        
                        choice = safe_input("Select option (1-3): ").strip()
                        if choice == '1':
                            retry_file = True  # Retry this file
                        elif choice == '2':
                            retry_file = False  # Skip to next file
                        elif choice == '3':
                            os.system('clear' if sys.platform != 'win32' else 'cls')
                            return False
                        else:
                            print("❌ Invalid choice. Enter 1, 2, or 3")
                            retry_file = True
                    else:
                        retry_file = False  # Successfully decrypted, move to next file
                
                if decrypted_data:
                    try:
                        decompressed_data = gzip.decompress(decrypted_data)
                        print("✓ Decompressed to original file")
                        decrypted_data = decompressed_data
                    except Exception:
                        # Not gzip compressed, use as-is
                        print("ℹ️ File is not gzip compressed (raw/binary format)")
                    
                    base_name = os.path.basename(path).replace('.rsa', '')
                    safe_out = _unique_outname(base_name + '_decrypted')
                    outp = os.path.join(RECV_DIR, safe_out)
                    try:
                        with open(outp, 'wb') as f:
                            f.write(decrypted_data)
                        file_size = len(decrypted_data)
                        print(color_success(f"✅ Decrypted and saved: {outp} ({file_size} bytes)"))
                        log_operation("Decrypt File - RSA Save", safe_out, "RSA", "OK", additional=f"size={file_size}")
                    except IOError as e:
                        print(color_error(f"❌ Failed to save decrypted file: {e}"))
                        log_exception("Decrypt File - RSA Save", outp, "RSA", e)
        
        # Exit file selection loop after processing files
        break
    
    # After processing all selected files, ask if continue or return to menu
    print("\n" + "=" * 50)
    continue_choice = safe_input("Decrypt more files? (yes/no): ").strip().lower()
    if continue_choice in ['yes', 'y', 'si', 's']:
        # Return True to restart prompt_decrypt_menu (choose new folder)
        os.system('clear' if sys.platform != 'win32' else 'cls')
        return True
    else:
        # Return to main menu
        os.system('clear' if sys.platform != 'win32' else 'cls')
        return False

def prompt_decrypt_menu():
    """Menu: Read QR codes and decrypt encrypted files."""
    try:
        os.system('clear' if sys.platform != 'win32' else 'cls')
        print("\n" + "=" * 40)
        print("    🔓 READ QR CODES AND DECRYPT")
        print("=" * 40)
        print("1) Output folder")
        print("2) Received folder")
        print("3) Custom folder")
        print("4) Current folder")
        choice = safe_input("Choose folder (1-4): ")
        
        if choice == '1':
            folder = OUT_DIR
        elif choice == '2':
            folder = RECV_DIR
        elif choice == '3':
            folder = safe_input("Enter folder path: ")
            if not folder:
                os.system('clear' if sys.platform != 'win32' else 'cls')
                return
            folder = sanitize_path(folder)
            if not os.path.exists(folder):
                print("❌ Folder not found")
                os.system('clear' if sys.platform != 'win32' else 'cls')
                return
        elif choice == '4':
            folder = os.getcwd()
        else:
            print("❌ Invalid choice")
            os.system('clear' if sys.platform != 'win32' else 'cls')
            return
        
        # Scan folder, reconstruct and decrypt QR codes
        payloads, results = read_and_reconstruct_qr(folder)
        if results:
            display_reconstructed_files(results)
            
            # Ask if user wants to decrypt more files
            print("\n" + "=" * 50)
            continue_choice = safe_input("Decrypt more files? (yes/no): ").strip().lower()
            if continue_choice in ['yes', 'y', 'si', 's']:
                os.system('clear' if sys.platform != 'win32' else 'cls')
                return prompt_decrypt_menu()  # Restart to choose new folder
            else:
                os.system('clear' if sys.platform != 'win32' else 'cls')
                return  # Return to main menu
        try:
            files = os.listdir(folder)
            enc_files = [f for f in files if f.endswith(('.aes', '.rsa'))]
            if enc_files:
                print(f"\n📋 Found {len(enc_files)} encrypted file(s) in folder")
                result = decrypt_encrypted_files(folder)
                # If user wants to decrypt more files (from different folder), restart
                if result:
                    os.system('clear' if sys.platform != 'win32' else 'cls')
                    return prompt_decrypt_menu()
                else:
                    # User wants to return to main menu
                    return
        except Exception:
            pass
        
        os.system('clear' if sys.platform != 'win32' else 'cls')
        return
    
    except KeyboardInterrupt:
        print("\n⚠️ Operation cancelled, returning to main menu...")
        os.system('clear' if sys.platform != 'win32' else 'cls')

# ============================================================================
# MAIN MENU
# ============================================================================

def show_credits():
    """Display Credits page."""
    os.system('clear' if sys.platform != 'win32' else 'cls')
    print("\n" + "=" * 50)
    print(color_bright("    🔐 QRVAULTLINK v1.0"))
    print("=" * 50)
    print()
    print(color_info("ABOUT:"))
    print("""QRVaultLink is a cross-platform tool for secure QR code 
encryption and reconstruction. Create multi-part encrypted 
QR codes for data sharing with automatic verification.
FSS1 format ensures compatibility with FileSecureSuite.
""")
    print(color_info("KEY FEATURES:"))
    print("""✓ AES-256-GCM encryption (AEAD - authenticated encryption)
✓ RSA-4096 hybrid encryption (public/private keys)
✓ NONE mode (unencrypted, standard QR scanners)
✓ Multi-part QR codes (large files support)
✓ Automatic gzip compression (level 9)
✓ Webcam QR scanning (live capture)
✓ Cross-platform (Windows, Linux, macOS, SSH)
✓ File verification & hash validation
✓ FSS1 format (FileSecureSuite compatible)
""")
    print(color_info("LIMITS:"))
    print("""✓ Readable QR: up to 1200 bytes (~1.2 KB)
✓ Single QR: up to 2953 bytes (~2.95 KB) [Version 40]
✓ Multi-QR: up to 0.2 MB [2600-byte chunks]
""")
    print(color_info("SECURITY FEATURES:"))
    print("""✓ FSS1 Magic Header ("FSS1")
✓ Embedded SHA256 hash (for integrity verification)
✓ AES-256-GCM AEAD (stronger than AES+HMAC)
✓ PBKDF2 600k iterations (OpenSSL 3.0 standard)
✓ RSA-4096 OAEP/SHA-256 (hybrid encryption)
✓ Hash validation on decrypt (AES & RSA)
""")
    print(color_info("DEPENDENCIES:"))
    print("qrcode, pillow, cryptography, pyzbar, opencv, colorama")
    print()
    print("-" * 50)
    print(color_bright("⚡ SUPPORT & DONATIONS"))
    print("-" * 50)
    print("""
If you find QRVaultLink useful, please consider supporting
the project with a Lightning Network donation.

""")
    print(color_warning("Lightning Address:"))
    print("""lnurl1dp68gurn8ghj7ampd3kx2ar0veekzar0wd5xjtnrdakj7tnhv4kxctttdehhwm30d3h82unvwqhk6ctjd9skummcxu6qs3rtcq
""")
    
    while True:
        print("\nOptions:")
        print("[1] View QR Code to Donate")
        print("[2] Return to Main Menu")
        choice = safe_input("Select option (1-2): ")
        
        if choice == '1':
            show_lightning_donation_qr()
            break  # Return directly to main menu after viewing QR
        elif choice == '2':
            os.system('clear' if sys.platform != 'win32' else 'cls')
            return
        else:
            print("❌ Invalid choice")

def show_lightning_donation_qr():
    """Display Lightning Network donation QR code."""
    os.system('clear' if sys.platform != 'win32' else 'cls')
    print(color_bright("""
Lightning Network Donation QR Code
"""))
    print("Scan this QR code with your Lightning wallet to donate:")
    print()
    
    try:
        lightning_addr = "lnurl1dp68gurn8ghj7ampd3kx2ar0veekzar0wd5xjtnrdakj7tnhv4kxctttdehhwm30d3h82unvwqhk6ctjd9skummcxu6qs3rtcq"
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(lightning_addr)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
        print(f"\n{color_warning('Lightning Address:')}\n{lightning_addr}")
        print(color_success("\nThank you for your support! ⚡"))
    except Exception as e:
        print(color_error(f"❌ Error generating QR code: {e}"))
    
    safe_input("\nPress Enter to continue...")
    os.system('clear' if sys.platform != 'win32' else 'cls')

def show_creation_logs_summary(source_type: str, source_name: str, encryption_type: str):
    """Display a summary of logs just created for this operation."""
    log_content = get_audit_log()
    if not log_content:
        return
    
    lines = log_content.strip().split('\n')
    if not lines:
        return
    
    print("\n" + "=" * 60)
    print("📊 AUDIT LOG SUMMARY - CREATE OPERATION")
    print("=" * 60)
    
    # Filter logs for this operation (last 5 lines usually enough for one create)
    relevant_logs = []
    for line in reversed(lines[-10:]):  # Check last 10 lines
        if source_name in line or encryption_type in line or "Create QR" in line:
            relevant_logs.insert(0, line)
    
    if relevant_logs:
        print(f"\nOperation: Create QR - {source_type}")
        print(f"Source: {source_name}")
        print(f"Encryption: {encryption_type}")
        print(f"\nLogs:")
        for log_line in relevant_logs:
            # Extract just the important parts
            if "status: OK" in log_line:
                print(f"  ✅ {log_line}")
            elif "status: FAILED" in log_line:
                print(f"  ❌ {log_line}")
            elif "ERROR" in log_line:
                print(f"  ⚠️ {log_line}")
            else:
                print(f"  📝 {log_line}")
    
    print("=" * 60)

def view_logs():
    """Display audit logs from logvault."""
    os.system('clear' if sys.platform != 'win32' else 'cls')
    print("\n" + "=" * 50)
    print("    📋 Audit Logs (logvault/audit.log)")
    print("=" * 50)
    
    log_content = get_audit_log()
    
    if log_content:
        print("\n" + log_content)
    else:
        print("\n(No logs yet)")
    
    safe_input("\nPress Enter to return to menu...")
    os.system('clear' if sys.platform != 'win32' else 'cls')

def main_menu():
    """Main application loop."""
    ensure_dirs()
    ensure_log_dir()
    menu = {
        '1': ('📝 Create QR Codes', prompt_create),
        '2': ('📂 Read QR Codes and Decrypt Files', prompt_decrypt_menu),
        '3': ('📷 Scan QR from Webcam', prompt_webcam_menu),
        '4': ('📋 View Audit Logs', view_logs),
        '5': ('ℹ️ Credits', show_credits),
        '6': ('👋 Exit', lambda: sys.exit(0))
    }
    while True:
        try:
            print("\n" + "=" * 40)
            print("    QRVaultLink v1.0 - Main Menu")
            print("=" * 40)
            for k, v in menu.items():
                print(f"{k}) {v[0]}")
            choice = safe_input("\nSelect option: ")
            if not choice:
                continue
            if choice in menu:
                menu[choice][1]()
            else:
                print("❌ Invalid choice")
        except KeyboardInterrupt:
            print("\n⚠️ Returning to main menu...")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    try:
        if '--help' in sys.argv or '-h' in sys.argv:
            print("""
============================================================
           QRVaultLink v1.4 - Help Menu
============================================================

Usage:
  python3 qrvaultlink_v1_4_FSS1_FORMAT.py            # Start application

Features:
  - Create QR codes from files or text
  - Support for multiple encryption modes: NONE, AES, RSA
  - Read and decode QR codes from folders or webcam
  - Decrypt encrypted files
  - Cross-platform compatibility (Windows, Linux, macOS)
  - Headless environment support (SSH)

Encryption Methods:
  NONE: No encryption, raw QR codes (standard QR readers compatible)
  AES:  Password-based encryption with PBKDF2 key derivation
        Requires password: min 8 chars, with uppercase or number
  RSA:  Hybrid encryption with public/private key pairs

Examples:
  python3 qrvaultlink_v1_1_8.py                     # Start normally

Log Messages:
  ✅ Success operations
  ❌ Error conditions
  ⚠️  Warnings and cancellations
  📋 Information messages
            """)
            sys.exit(0)
        
        main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 QRVaultLink v1.4 closed")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)
