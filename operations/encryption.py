"""
Block encryption and decryption operations using AES-256-GCM.

This module implements the core encryption and decryption logic for
data blocks with authenticated encryption.

Author: Muran-prog
License: MIT
Version: 2.0
"""

import asyncio
import json
import secrets
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from ..config.crypto_config import CryptoConfig
from ..models.encrypted_block import EncryptedBlock
from ..core.secure_memory import SecureBytes, secure_memory_context
from .key_derivation import derive_block_key
from ..exceptions import EncryptionError, CryptoError

logger = logging.getLogger(__name__)


async def encrypt_block(
    data: Dict[str, Any],
    master_key: bytes,
    config: CryptoConfig,
    block_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> EncryptedBlock:
    """
    Stage 2: Encrypt a complete data block using AES-256-GCM.
    
    This method encrypts entire data structures as atomic units,
    providing both confidentiality and authenticity.
    
    Args:
        data: Dictionary containing all fields to encrypt
        master_key: User's master encryption key
        config: Cryptographic configuration
        block_id: Unique identifier for the block
        metadata: Additional unencrypted metadata
        
    Returns:
        EncryptedBlock containing encrypted data and metadata
        
    Raises:
        EncryptionError: If encryption fails
    """
    with secure_memory_context():
        block_id = block_id or secrets.token_hex(16)
        metadata = metadata or {}
        
        try:
            # Serialize data to JSON with consistent ordering
            json_data = json.dumps(data, sort_keys=True, ensure_ascii=False)
            plaintext = json_data.encode('utf-8')
            
            # Generate cryptographically secure random values
            nonce = secrets.token_bytes(config.gcm_nonce_size)
            block_salt = secrets.token_bytes(config.salt_size)
            
            # Derive block-specific encryption key
            block_key = await derive_block_key(
                master_key, block_salt, block_id, config
            )
            
            with SecureBytes(block_key) as secure_block_key:
                # Initialize AES-GCM cipher
                cipher = Cipher(
                    algorithms.AES(bytes(secure_block_key)),
                    modes.GCM(nonce),
                    backend=default_backend()
                )
                encryptor = cipher.encryptor()
                
                # Add block ID as additional authenticated data
                encryptor.authenticate_additional_data(block_id.encode())
                
                # Perform encryption in thread pool to avoid blocking
                loop = asyncio.get_event_loop()
                ciphertext = await loop.run_in_executor(
                    None, 
                    lambda: encryptor.update(plaintext) + encryptor.finalize()
                )
                
                # Create encrypted block with integrity verification
                encrypted_block = EncryptedBlock(
                    id=block_id,
                    encrypted_data=ciphertext,
                    nonce=nonce,
                    tag=encryptor.tag,
                    salt=block_salt,
                    metadata=metadata,
                    timestamp=datetime.now(timezone.utc).isoformat()
                )
                
                logger.debug(f"Successfully encrypted block {block_id}")
                return encrypted_block
                
        except Exception as e:
            raise EncryptionError(f"Block encryption failed: {str(e)}")


async def decrypt_block(
    encrypted_block: EncryptedBlock,
    master_key: bytes,
    config: CryptoConfig
) -> Dict[str, Any]:
    """
    Decrypt a complete data block using AES-256-GCM.
    
    This method decrypts encrypted blocks and verifies their integrity
    using authenticated encryption.
    
    Args:
        encrypted_block: The encrypted block to decrypt
        master_key: User's master decryption key
        config: Cryptographic configuration
        
    Returns:
        Dictionary containing decrypted data
        
    Raises:
        CryptoError: If decryption or verification fails
    """
    with secure_memory_context():
        # Verify block integrity first
        if not encrypted_block.verify_integrity():
            raise CryptoError("Block integrity verification failed")
        
        try:
            # Derive block-specific decryption key
            block_key = await derive_block_key(
                master_key,
                encrypted_block.salt,
                encrypted_block.id,
                config
            )
            
            with SecureBytes(block_key) as secure_block_key:
                # Initialize AES-GCM cipher for decryption
                cipher = Cipher(
                    algorithms.AES(bytes(secure_block_key)),
                    modes.GCM(encrypted_block.nonce, encrypted_block.tag),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                
                # Verify additional authenticated data
                decryptor.authenticate_additional_data(encrypted_block.id.encode())
                
                # Perform decryption in thread pool
                loop = asyncio.get_event_loop()
                plaintext = await loop.run_in_executor(
                    None,
                    lambda: (decryptor.update(encrypted_block.encrypted_data) + 
                           decryptor.finalize())
                )
                
                # Deserialize JSON data
                json_data = plaintext.decode('utf-8')
                data = json.loads(json_data)
                
                logger.debug(f"Successfully decrypted block {encrypted_block.id}")
                return data
                
        except Exception as e:
            raise CryptoError(f"Block decryption failed: {str(e)}")