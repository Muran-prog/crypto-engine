"""
Enhanced high-level API for password manager integration.

This module provides a simplified interface for common password manager
operations while maintaining full security and all advanced features.

Author: Muran-prog
License: MIT
Version: 2.0
"""

import base64
import hashlib
import secrets
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone

from ..config.crypto_config import CryptoConfig
from ..models.enums import ExportFormat
from ..models.encrypted_block import EncryptedBlock
from ..models.account_info import AccountInfo
from ..core.engine import AsyncCryptoEngine
from ..core.secure_memory import secure_memory_context
from ..exceptions import CryptoError, AuthenticationError

logger = logging.getLogger(__name__)


class PasswordManagerCrypto:
    """
    Enhanced high-level API for password manager integration.
    
    This class provides a simplified interface for common password manager
    operations while maintaining full security and all advanced features.
    
    Features:
    - Simple account management
    - Secure entry storage and retrieval
    - Data export and import
    - Password changes and account deletion
    - Comprehensive error handling
    
    Example usage:
        ```python
        crypto = PasswordManagerCrypto()
        
        # Registration
        salt = await crypto.register_user("master_password")
        
        # Login
        await crypto.login("master_password", salt)
        
        # Store entry
        entry = {
            "title": "GitHub",
            "username": "user@example.com", 
            "password": "secret123",
            "url": "https://github.com",
            "notes": "Work account"
        }
        encrypted_block = await crypto.store_entry(entry)
        
        # Retrieve entry
        decrypted_entry = await crypto.get_entry(encrypted_block)
        
        # Export data
        export_data = await crypto.export_data([encrypted_block])
        ```
    """
    
    def __init__(self, config: Optional[CryptoConfig] = None):
        """
        Initialize the password manager crypto interface.
        
        Args:
            config: Optional cryptographic configuration
        """
        self.engine = AsyncCryptoEngine(config)
        self._entries: Dict[str, EncryptedBlock] = {}
        
        logger.info("PasswordManagerCrypto initialized")
    
    async def register_user(self, master_password: str, user_id: Optional[str] = None) -> AccountInfo:
        """
        Register a new user account.
        
        This process derives a master key, creates a secure verifier hash from it,
        and stores the salt and verifier hash in the AccountInfo object.
        
        Args:
            master_password: User's master password
            user_id: Optional user identifier
            
        Returns:
            AccountInfo object containing all data needed for future authentications
            
        Raises:
            CryptoError: If registration fails
        """
        logger.info("Registering new user account")
        
        try:
            with secure_memory_context():
                # Derive master key and generate salt
                master_key, salt = await self.engine.derive_master_key(master_password)
                
                verifier_hash: Optional[bytes] = None
                with master_key:
                    # Create a verifier hash from the master key itself
                    verifier_hash = hashlib.sha256(bytes(master_key)).digest()

                # Create account information with all necessary crypto materials
                user_id = user_id or secrets.token_hex(16)
                account_info = AccountInfo(
                    user_id=user_id,
                    created_at=datetime.now(timezone.utc).isoformat(),
                    master_key_salt=base64.b64encode(salt).decode(),
                    master_key_verifier_hash=base64.b64encode(verifier_hash).decode(),
                )
            
            logger.info(f"User {user_id} registered successfully")
            return account_info
            
        except Exception as e:
            raise CryptoError(f"User registration failed: {str(e)}")
    
    async def login(self, master_password: str, account_info: AccountInfo) -> bool:
        """
        Authenticate user and start session.
        
        Args:
            master_password: User's master password
            account_info: User's account information, containing salt and verifier
            
        Returns:
            True if login successful
            
        Raises:
            AuthenticationError: If login fails
        """
        logger.info(f"User login attempt for {account_info.user_id}")
        
        success = await self.engine.authenticate_user(master_password, account_info)
        
        if success:
            logger.info(f"User {account_info.user_id} logged in successfully")
        else:
            logger.warning(f"Login failed for user {account_info.user_id}")
        
        return success
    
    async def store_entry(
        self,
        entry_data: Dict[str, Any],
        entry_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> EncryptedBlock:
        """
        Store a password entry with full encryption.
        
        Args:
            entry_data: Dictionary containing entry fields
            entry_id: Optional entry identifier
            metadata: Optional metadata (not encrypted)
            
        Returns:
            EncryptedBlock containing encrypted entry
            
        Raises:
            AuthenticationError: If user is not authenticated
            EncryptionError: If encryption fails
        """
        # Add automatic metadata
        auto_metadata = {
            "entry_type": entry_data.get("type", "unknown"),
            "created_at": datetime.now(timezone.utc).isoformat(),
            **(metadata or {})
        }
        
        encrypted_block = await self.engine.encrypt_block(
            entry_data, entry_id, auto_metadata
        )
        
        # Store in local cache
        self._entries[encrypted_block.id] = encrypted_block
        
        logger.debug(f"Entry stored: {entry_data.get('title', 'Untitled')}")
        return encrypted_block
    
    async def get_entry(self, encrypted_block: EncryptedBlock) -> Dict[str, Any]:
        """
        Retrieve and decrypt a password entry.
        
        Args:
            encrypted_block: The encrypted entry
            
        Returns:
            Decrypted entry data
            
        Raises:
            AuthenticationError: If user is not authenticated
            CryptoError: If decryption fails
        """
        return await self.engine.decrypt_block(encrypted_block)
    
    async def update_entry(
        self,
        encrypted_block: EncryptedBlock,
        updated_data: Dict[str, Any]
    ) -> EncryptedBlock:
        """
        Update an existing entry with new data.
        
        Args:
            encrypted_block: Current encrypted entry
            updated_data: New data for the entry
            
        Returns:
            New encrypted block with updated data
            
        Raises:
            AuthenticationError: If user is not authenticated
            EncryptionError: If encryption fails
        """
        # Preserve original metadata but update timestamp
        updated_metadata = encrypted_block.metadata.copy()
        updated_metadata["updated_at"] = datetime.now(timezone.utc).isoformat()
        
        new_block = await self.engine.encrypt_block(
            updated_data,
            encrypted_block.id,
            updated_metadata
        )
        
        # Update local cache
        self._entries[new_block.id] = new_block
        
        logger.debug(f"Entry updated: {new_block.id}")
        return new_block
    
    async def delete_entry(self, entry_id: str) -> bool:
        """
        Delete a specific entry.
        
        Args:
            entry_id: ID of the entry to delete
            
        Returns:
            True if deletion successful
        """
        if entry_id in self._entries:
            del self._entries[entry_id]
            logger.debug(f"Entry deleted: {entry_id}")
            return True
        return False
    
    async def bulk_delete_entries(self, entry_ids: List[str]) -> int:
        """
        Delete multiple entries in bulk from the local cache.
        
        This method is the source of truth for deletion. It calculates which
        entries can be deleted, removes them from its internal state, and then
        notifies the crypto engine to update its counters.
        
        Args:
            entry_ids: List of entry IDs to delete
            
        Returns:
            Number of entries successfully deleted
        """
        if not self.engine.is_authenticated():
            raise AuthenticationError("User not authenticated")

        deleted_count = 0
        # Use a set for efficient checking of which IDs to delete
        ids_to_delete = set(entry_ids)

        # Iterate over a copy of keys to safely delete from the dictionary
        for entry_id in list(self._entries.keys()):
            if entry_id in ids_to_delete:
                del self._entries[entry_id]
                deleted_count += 1
        
        # If any entries were deleted, notify the engine to update its metadata
        if deleted_count > 0:
            await self.engine.bulk_delete_entries(deleted_count)
        
        logger.info(f"Bulk delete completed: {deleted_count}/{len(entry_ids)} entries deleted")
        return deleted_count
    
    async def change_master_password(
        self,
        old_password: str,
        new_password: str
    ) -> Tuple[bytes, bytes, List[EncryptedBlock]]:
        """
        Change user's master password and re-encrypt all entries.
        
        This method now correctly updates its internal entry cache with the
        newly re-encrypted entries to maintain session consistency.
        
        Args:
            old_password: Current password (used for session verification)
            new_password: New password
            
        Returns:
            Tuple of (new_salt, new_verifier_hash, re_encrypted_entries) which
            must be used to update the user's account record in persistent storage.
            
        Raises:
            AuthenticationError: If user is not authenticated
            CryptoError: If re-encryption fails
        """
        all_entries = list(self._entries.values())
        new_salt, new_verifier_hash, re_encrypted_entries = await self.engine.change_master_password(
            old_password, new_password, all_entries
        )
        
        # THE FIX: Update local cache with the newly re-encrypted entries.
        # This ensures the session state remains consistent after the password change.
        self._entries.clear()
        for entry in re_encrypted_entries:
            self._entries[entry.id] = entry
        
        logger.info("Master password changed successfully")
        return new_salt, new_verifier_hash, re_encrypted_entries
    
    async def delete_account(self, password: str, account_info: AccountInfo) -> bool:
        """
        Permanently delete user account and all data.
        
        Args:
            password: User's master password for confirmation
            account_info: The user's account information for authentication
            
        Returns:
            True if account deletion successful
            
        Raises:
            AuthenticationError: If password verification fails
        """
        success = await self.engine.delete_account(password, account_info)
        
        if success:
            # Clear all local data
            self._entries.clear()
            logger.info("Account deleted successfully")
        
        return success
    
    async def export_data(
        self,
        export_format: ExportFormat = ExportFormat.JSON,
        export_password: Optional[str] = None
    ) -> bytes:
        """
        Export all user data in specified format.
        
        Args:
            export_format: Format for export
            export_password: Optional password for encrypted backups
            
        Returns:
            Exported data as bytes
            
        Raises:
            ExportError: If export fails
        """
        all_entries = list(self._entries.values())
        return await self.engine.export_data(all_entries, export_format, export_password)
    
    async def import_backup(self, backup_data: bytes, export_password: str) -> int:
        """
        Import entries from encrypted backup.
        
        Args:
            backup_data: Encrypted backup data
            export_password: Password for backup decryption
            
        Returns:
            Number of entries imported
            
        Raises:
            ExportError: If import fails
        """
        entries_data = await self.engine.import_encrypted_backup(backup_data, export_password)
        
        imported_count = 0
        for entry_data in entries_data:
            # Remove metadata fields before storing
            clean_data = {k: v for k, v in entry_data.items() if not k.startswith('_')}
            
            try:
                encrypted_block = await self.store_entry(clean_data)
                imported_count += 1
            except Exception as e:
                logger.warning(f"Failed to import entry: {str(e)}")
        
        logger.info(f"Imported {imported_count} entries from backup")
        return imported_count
    
    def get_entries_summary(self) -> Dict[str, Any]:
        """
        Get summary of stored entries.
        
        Returns:
            Dictionary containing entry statistics
        """
        entry_types = {}
        total_entries = len(self._entries)
        
        for entry in self._entries.values():
            entry_type = entry.metadata.get("entry_type", "unknown")
            entry_types[entry_type] = entry_types.get(entry_type, 0) + 1
        
        return {
            "total_entries": total_entries,
            "entry_types": entry_types,
            "is_authenticated": self.engine.is_authenticated(),
            "account_info": self.engine.get_account_info()
        }
    
    async def logout(self) -> None:
        """
        End user session and clear all sensitive data.
        """
        await self.engine.clear_session()
        self._entries.clear()
        logger.info("User logged out successfully")