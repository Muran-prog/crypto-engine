"""
Configuration parameters for cryptographic operations.

This module contains all security-relevant parameters and configuration
settings used throughout the cryptographic engine.

Author: Muran-prog
License: MIT
Version: 2.0
"""

from dataclasses import dataclass
from ..models.enums import KeyDerivationMethod


@dataclass
class CryptoConfig:
    """
    Configuration parameters for cryptographic operations.
    
    This class contains all security-relevant parameters used throughout
    the cryptographic engine. Values are set to meet current security
    best practices as of 2024.
    """
    # Stage 1: User key derivation parameters
    key_derivation_method: KeyDerivationMethod = KeyDerivationMethod.SCRYPT
    pbkdf2_iterations: int = 600_000  # OWASP 2023 recommendation
    scrypt_n: int = 32768  # 2^15 - memory cost parameter
    scrypt_r: int = 8      # Block size parameter
    scrypt_p: int = 1      # Parallelization parameter
    salt_size: int = 32    # 256-bit salt
    
    # Stage 2: Block encryption parameters
    aes_key_size: int = 32     # AES-256 (32 bytes)
    gcm_nonce_size: int = 12   # 96-bit nonce for GCM
    gcm_tag_size: int = 16     # 128-bit authentication tag
    
    # RSA parameters for key exchange (if needed)
    rsa_key_size: int = 4096   # RSA-4096 for future-proofing
    
    # HMAC parameters for integrity verification
    hmac_key_size: int = 32    # 256-bit HMAC key
    
    # Timing attack protection
    constant_time_compare: bool = True
    min_auth_delay_ms: int = 100  # Minimum authentication delay
    
    # Memory security
    secure_memory_wipe: bool = True
    force_garbage_collection: bool = True
    
    # Export security
    export_pbkdf2_iterations: int = 1_000_000  # Higher iterations for exports
    backup_compression: bool = True