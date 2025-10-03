"""
Enumeration types for the cryptographic engine.

This module defines all enum types used throughout the crypto engine,
providing type-safe constants for various operations.

Author: Muran-prog
License: MIT
Version: 2.0
"""

from enum import Enum


class KeyDerivationMethod(Enum):
    """Supported key derivation methods for master password hashing."""

    PBKDF2 = "pbkdf2"
    SCRYPT = "scrypt"


class ExportFormat(Enum):
    """Supported export formats for secure data export."""

    JSON = "json"
    CSV = "csv"
    ENCRYPTED_BACKUP = "encrypted_backup"
