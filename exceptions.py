"""
Custom exception hierarchy for the cryptographic engine.

This module defines all exception types used throughout the crypto engine,
providing a clear and structured error handling mechanism.

Author: Muran-prog
License: MIT
Version: 2.0
"""


class CryptoError(Exception):
    """Base exception for cryptographic operations."""

    pass


class AuthenticationError(CryptoError):
    """Raised when authentication fails."""

    pass


class EncryptionError(CryptoError):
    """Raised when encryption operations fail."""

    pass


class AccountError(CryptoError):
    """Raised when account management operations fail."""

    pass


class ExportError(CryptoError):
    """Raised when data export operations fail."""

    pass
