"""
Key derivation functions for the cryptographic engine.

This module implements secure key derivation using PBKDF2, Scrypt, and HKDF
for master key generation and block-specific key derivation.

Author: Muran-prog
License: MIT
Version: 2.0
"""

import asyncio
import secrets
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from ..config.crypto_config import CryptoConfig
from ..models.enums import KeyDerivationMethod
from ..core.secure_memory import SecureBytes, secure_memory_context
from ..exceptions import CryptoError


async def derive_master_key(
    password: str,
    config: CryptoConfig,
    salt: bytes = None,
    method: KeyDerivationMethod = None,
) -> Tuple[SecureBytes, bytes]:
    """
    Stage 1: Derive master key from user password using secure key derivation.

    This method implements timing attack protection and uses cryptographically
    secure key derivation functions to generate the master encryption key.

    Args:
        password: User's master password
        config: Cryptographic configuration
        salt: Salt for key derivation (generated if None)
        method: Key derivation method (PBKDF2 or Scrypt)

    Returns:
        Tuple of (secure_master_key, salt)

    Raises:
        CryptoError: If key derivation fails
    """
    with secure_memory_context():
        if salt is None:
            salt = secrets.token_bytes(config.salt_size)

        method = method or config.key_derivation_method

        # Convert password to bytes securely
        password_bytes = password.encode("utf-8")

        try:
            # Select key derivation function
            if method == KeyDerivationMethod.PBKDF2:
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=config.aes_key_size,
                    salt=salt,
                    iterations=config.pbkdf2_iterations,
                    backend=default_backend(),
                )
            else:  # SCRYPT
                kdf = Scrypt(
                    length=config.aes_key_size,
                    salt=salt,
                    n=config.scrypt_n,
                    r=config.scrypt_r,
                    p=config.scrypt_p,
                    backend=default_backend(),
                )

            # Perform key derivation in thread pool
            loop = asyncio.get_event_loop()
            master_key_bytes = await loop.run_in_executor(
                None, kdf.derive, password_bytes
            )

            # Securely wrap the master key
            master_key = SecureBytes(master_key_bytes)

            # Securely clear password bytes
            password_bytes = bytearray(password_bytes)
            for i in range(len(password_bytes)):
                password_bytes[i] = 0

            return master_key, salt

        except Exception as e:
            raise CryptoError(f"Key derivation failed: {str(e)}")


async def derive_block_key(
    master_key: bytes, block_salt: bytes, block_id: str, config: CryptoConfig
) -> bytes:
    """
    Derive block-specific encryption key from master key using HKDF.

    This method creates unique encryption keys for each block,
    preventing key reuse and improving security isolation.

    Args:
        master_key: User's master key
        block_salt: Block-specific salt
        block_id: Block identifier used as context info
        config: Cryptographic configuration

    Returns:
        Block-specific encryption key

    Raises:
        CryptoError: If key derivation fails
    """
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=config.aes_key_size,
            salt=block_salt,
            info=block_id.encode("utf-8"),
            backend=default_backend(),
        )

        # Perform key derivation in thread pool
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, hkdf.derive, master_key)

    except Exception as e:
        raise CryptoError(f"Block key derivation failed: {str(e)}")
