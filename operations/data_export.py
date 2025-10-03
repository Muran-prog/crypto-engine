"""
Data export and import operations.

This module implements secure data export in multiple formats (JSON, CSV,
encrypted backup) and encrypted backup import functionality.

Author: Muran-prog
License: MIT
Version: 2.0
"""

import base64
import json
import secrets
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from ..config.crypto_config import CryptoConfig
from ..models.enums import ExportFormat
from ..models.encrypted_block import EncryptedBlock
from ..models.account_info import AccountInfo
from ..core.secure_memory import SecureBytes, secure_memory_context
from .encryption import decrypt_block
from ..exceptions import ExportError

logger = logging.getLogger(__name__)


async def export_data(
    encrypted_blocks: List[EncryptedBlock],
    master_key: bytes,
    config: CryptoConfig,
    export_format: ExportFormat = ExportFormat.JSON,
    export_password: Optional[str] = None,
    account_info: Optional[AccountInfo] = None
) -> bytes:
    """
    Export user data in specified format with optional encryption.
    
    This method provides secure data export capabilities with multiple
    format options and optional additional encryption for backups.
    
    Args:
        encrypted_blocks: All encrypted blocks to export
        master_key: User's master key for decryption
        config: Cryptographic configuration
        export_format: Format for export (JSON, CSV, or encrypted backup)
        export_password: Optional password for backup encryption
        account_info: Optional account information for backup metadata
        
    Returns:
        Exported data as bytes
        
    Raises:
        ExportError: If export operation fails
    """
    logger.info(f"Starting data export in {export_format.value} format")
    
    try:
        with secure_memory_context():
            # Decrypt all blocks for export
            decrypted_data = []
            for block in encrypted_blocks:
                try:
                    data = await decrypt_block(block, master_key, config)
                    # Add metadata
                    data["_block_id"] = block.id
                    data["_timestamp"] = block.timestamp
                    data["_metadata"] = block.metadata
                    decrypted_data.append(data)
                except Exception as e:
                    logger.warning(f"Failed to decrypt block {block.id} for export: {str(e)}")
            
            # Format data according to export format
            if export_format == ExportFormat.JSON:
                export_data = json.dumps({
                    "version": "2.0",
                    "export_timestamp": datetime.now(timezone.utc).isoformat(),
                    "entry_count": len(decrypted_data),
                    "entries": decrypted_data
                }, indent=2, ensure_ascii=False).encode('utf-8')
            
            elif export_format == ExportFormat.CSV:
                import csv
                from io import StringIO
                
                csv_buffer = StringIO()
                if decrypted_data:
                    # Get all possible field names
                    fieldnames = set()
                    for entry in decrypted_data:
                        fieldnames.update(entry.keys())
                    fieldnames = sorted(fieldnames)
                    
                    writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(decrypted_data)
                
                export_data = csv_buffer.getvalue().encode('utf-8')
            
            elif export_format == ExportFormat.ENCRYPTED_BACKUP:
                # Create encrypted backup with additional password
                if not export_password:
                    raise ExportError("Export password required for encrypted backup")
                
                # Serialize data
                backup_data = {
                    "version": "2.0",
                    "backup_timestamp": datetime.now(timezone.utc).isoformat(),
                    "entry_count": len(decrypted_data),
                    "account_info": account_info.to_dict() if account_info else None,
                    "entries": decrypted_data
                }
                
                json_data = json.dumps(backup_data, ensure_ascii=False)
                plaintext = json_data.encode('utf-8')
                
                # Encrypt backup with export password
                export_salt = secrets.token_bytes(config.salt_size)
                export_kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=config.aes_key_size,
                    salt=export_salt,
                    iterations=config.export_pbkdf2_iterations,
                    backend=default_backend()
                )
                
                export_key = export_kdf.derive(export_password.encode('utf-8'))
                export_nonce = secrets.token_bytes(config.gcm_nonce_size)
                
                with SecureBytes(export_key) as secure_export_key:
                    cipher = Cipher(
                        algorithms.AES(bytes(secure_export_key)),
                        modes.GCM(export_nonce),
                        backend=default_backend()
                    )
                    encryptor = cipher.encryptor()
                    
                    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
                    
                    # Package encrypted backup
                    backup_package = {
                        "format": "encrypted_backup",
                        "version": "2.0",
                        "salt": base64.b64encode(export_salt).decode(),
                        "nonce": base64.b64encode(export_nonce).decode(),
                        "tag": base64.b64encode(encryptor.tag).decode(),
                        "data": base64.b64encode(ciphertext).decode(),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    
                    export_data = json.dumps(backup_package, indent=2).encode('utf-8')
            
            logger.info(f"Data export completed: {len(export_data)} bytes")
            return export_data
            
    except Exception as e:
        raise ExportError(f"Data export failed: {str(e)}")


async def import_encrypted_backup(
    backup_data: bytes,
    export_password: str,
    config: CryptoConfig
) -> List[Dict[str, Any]]:
    """
    Import data from encrypted backup.
    
    Args:
        backup_data: Encrypted backup data
        export_password: Password used for backup encryption
        config: Cryptographic configuration
        
    Returns:
        List of imported entry data
        
    Raises:
        ExportError: If import fails
    """
    logger.info("Starting encrypted backup import")
    
    try:
        with secure_memory_context():
            # Parse backup package
            backup_json = backup_data.decode('utf-8')
            backup_package = json.loads(backup_json)
            
            if backup_package.get("format") != "encrypted_backup":
                raise ExportError("Invalid backup format")
            
            # Extract encryption parameters
            export_salt = base64.b64decode(backup_package["salt"])
            export_nonce = base64.b64decode(backup_package["nonce"])
            export_tag = base64.b64decode(backup_package["tag"])
            ciphertext = base64.b64decode(backup_package["data"])
            
            # Derive decryption key
            export_kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=config.aes_key_size,
                salt=export_salt,
                iterations=config.export_pbkdf2_iterations,
                backend=default_backend()
            )
            
            export_key = export_kdf.derive(export_password.encode('utf-8'))
            
            with SecureBytes(export_key) as secure_export_key:
                # Decrypt backup
                cipher = Cipher(
                    algorithms.AES(bytes(secure_export_key)),
                    modes.GCM(export_nonce, export_tag),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                
                # Parse decrypted data
                backup_json = plaintext.decode('utf-8')
                backup_data = json.loads(backup_json)
                
                entries = backup_data.get("entries", [])
                logger.info(f"Successfully imported {len(entries)} entries from backup")
                
                return entries
                
    except Exception as e:
        raise ExportError(f"Backup import failed: {str(e)}")