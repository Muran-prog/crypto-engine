"""
Authentication and user verification operations.

This module implements secure user authentication with timing attack
protection and account lockout mechanisms.

Author: Muran-prog
License: MIT
Version: 2.0
"""

import asyncio
import base64
import hashlib
import time
import logging
from typing import Tuple
from cryptography.hazmat.primitives import constant_time

from ..config.crypto_config import CryptoConfig
from ..models.account_info import AccountInfo
from ..core.secure_memory import SecureBytes
from .key_derivation import derive_master_key
from ..exceptions import AuthenticationError

logger = logging.getLogger(__name__)


async def authenticate_user(
    password: str,
    account_info: AccountInfo,
    config: CryptoConfig
) -> Tuple[bool, SecureBytes]:
    """
    Authenticate user with timing attack protection and account lockout.
    
    This method implements a standard verification mechanism. It derives a key
    from the provided password and salt, hashes the derived key, and then
    compares this new hash against the stored verifier hash in constant time.
    
    Args:
        password: User's password
        account_info: Account information containing salt and the verifier hash
        config: Cryptographic configuration
        
    Returns:
        Tuple of (success, master_key or None)
        
    Raises:
        AuthenticationError: If account is locked
    """
    start_time = time.time()
    
    # Moved lockout check outside the main try/except block.
    # This ensures that if the account is locked, an AuthenticationError is
    # raised immediately instead of being caught and suppressed as a generic failure.
    if account_info.account_locked:
        await _enforce_minimum_auth_time(start_time, config)
        raise AuthenticationError("Account is locked due to too many failed attempts")

    derived_key: SecureBytes = None
    try:
        # Decode verification materials from AccountInfo
        stored_salt = base64.b64decode(account_info.master_key_salt)
        stored_verifier_hash = base64.b64decode(account_info.master_key_verifier_hash)
        
        # Manually manage key lifecycle to prevent premature wiping by a `with` block.
        # The key is only wiped on authentication failure.
        derived_key, _ = await derive_master_key(password, config, stored_salt)
        
        # Hash the derived key to create a verifier
        derived_hash = hashlib.sha256(bytes(derived_key)).digest()
        
        # Perform constant-time comparison against the stored verifier
        if not constant_time.bytes_eq(derived_hash, stored_verifier_hash):
            raise AuthenticationError("Password verification failed")

        # --- SUCCESS PATH ---
        # The key is valid, return it. Do NOT wipe it.
        logger.info("User authentication successful")
        return True, derived_key
        
    except Exception as e:
        # --- FAILURE PATH ---
        # If authentication fails for any reason, securely wipe the derived key.
        if derived_key:
            derived_key.wipe()

        # Handle failed login attempts
        if account_info:
            account_info.failed_login_attempts += 1
            if account_info.failed_login_attempts >= 5:
                account_info.account_locked = True
                logger.warning("Account locked due to excessive failed login attempts")
        
        logger.warning(f"Authentication failed: {type(e).__name__}")
        return False, None
        
    finally:
        # Always enforce minimum time to protect against timing attacks
        await _enforce_minimum_auth_time(start_time, config)


async def _enforce_minimum_auth_time(start_time: float, config: CryptoConfig) -> None:
    """
    Enforce minimum authentication time to prevent timing attacks.
    
    Args:
        start_time: Time when authentication started
        config: Cryptographic configuration
    """
    elapsed = (time.time() - start_time) * 1000  # Convert to milliseconds
    min_delay = config.min_auth_delay_ms
    
    if elapsed < min_delay:
        delay_needed = (min_delay - elapsed) / 1000  # Convert back to seconds
        await asyncio.sleep(delay_needed)