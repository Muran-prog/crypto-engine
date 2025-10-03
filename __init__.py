"""
Enhanced Asynchronous Cryptographic Engine for Password Managers
==============================================================

A high-performance, zero-knowledge cryptographic engine designed for password managers.
Features two-stage encryption, block-level encryption, extensible architecture,
comprehensive account management, and advanced security protections.

Security Features:
- AES-256-GCM encryption with authenticated data
- PBKDF2/Scrypt key derivation with timing attack protection
- Secure memory wiping and constant-time operations
- Zero-knowledge architecture with client-side encryption
- Protection against side-channel attacks

Author: Muran-prog
License: MIT
Version: 2.0
"""

from .config.crypto_config import CryptoConfig
from .models.enums import KeyDerivationMethod, ExportFormat
from .models.encrypted_block import EncryptedBlock
from .models.account_info import AccountInfo
from .core.engine import AsyncCryptoEngine
from .core.secure_memory import SecureBytes, secure_memory_context
from .api.password_manager import PasswordManagerCrypto
from .exceptions import (
    CryptoError,
    AuthenticationError,
    EncryptionError,
    AccountError,
    ExportError,
)

__version__ = "2.0"
__author__ = "Muran-prog"
__license__ = "MIT"

__all__ = [
    # Configuration
    "CryptoConfig",
    # Enums
    "KeyDerivationMethod",
    "ExportFormat",
    # Models
    "EncryptedBlock",
    "AccountInfo",
    # Core Engine
    "AsyncCryptoEngine",
    "SecureBytes",
    "secure_memory_context",
    # High-Level API
    "PasswordManagerCrypto",
    # Exceptions
    "CryptoError",
    "AuthenticationError",
    "EncryptionError",
    "AccountError",
    "ExportError",
]
