"""
Enhanced Asynchronous Cryptographic Engine for Password Managers.

This module contains the core AsyncCryptoEngine class that orchestrates
all cryptographic operations with comprehensive security features.

Author: Muran-prog
License: MIT
Version: 2.0
"""

import gc
import hashlib
import logging
from typing import Dict, Optional, List, Tuple, Any
from datetime import datetime, timezone

from ..config.crypto_config import CryptoConfig
from ..models.enums import ExportFormat
from ..models.enums import KeyDerivationMethod
from ..models.encrypted_block import EncryptedBlock
from ..models.account_info import AccountInfo
from .secure_memory import SecureBytes
from ..operations.key_derivation import derive_master_key
from ..operations.authentication import authenticate_user
from ..operations.encryption import encrypt_block, decrypt_block
from ..operations.data_export import export_data, import_encrypted_backup
from ..exceptions import AuthenticationError, CryptoError, AccountError

logger = logging.getLogger(__name__)


class AsyncCryptoEngine:
    """
    Enhanced asynchronous cryptographic engine for password managers.

    This engine provides a complete cryptographic solution with:
    - Two-stage encryption (user-derived key + block encryption)
    - Zero-knowledge architecture with client-side encryption
    - Comprehensive account management
    - Timing attack protection
    - Secure memory handling
    - Data export capabilities
    """

    def __init__(self, config: Optional[CryptoConfig] = None):
        """
        Initialize the cryptographic engine.

        Args:
            config: Cryptographic configuration parameters
        """
        self.config = config or CryptoConfig()
        self._master_key: Optional[SecureBytes] = None
        self._session_keys: Dict[str, SecureBytes] = {}
        self._account_info: Optional[AccountInfo] = None
        self._is_authenticated = False

        # Timing attack protection
        self._last_auth_time = 0.0

        logger.info("AsyncCryptoEngine initialized with enhanced security features")

    async def derive_master_key(
        self,
        password: str,
        salt: Optional[bytes] = None,
        method: Optional["KeyDerivationMethod"] = None,
    ) -> Tuple[SecureBytes, bytes]:
        """
        Stage 1: Derive master key from user password using secure key derivation.

        This method implements timing attack protection and uses cryptographically
        secure key derivation functions to generate the master encryption key.

        Args:
            password: User's master password
            salt: Salt for key derivation (generated if None)
            method: Key derivation method (PBKDF2 or Scrypt)

        Returns:
            Tuple of (secure_master_key, salt)

        Raises:
            CryptoError: If key derivation fails
        """
        return await derive_master_key(password, self.config, salt, method)

    async def authenticate_user(self, password: str, account_info: AccountInfo) -> bool:
        """
        Authenticate user with timing attack protection and account lockout.

        This method implements a standard verification mechanism. It derives a key
        from the provided password and salt, hashes the derived key, and then
        compares this new hash against the stored verifier hash in constant time.

        Args:
            password: User's password
            account_info: Account information containing salt and the verifier hash

        Returns:
            True if authentication successful

        Raises:
            AuthenticationError: If account is locked
        """
        success, master_key = await authenticate_user(
            password, account_info, self.config
        )

        if success:
            # --- SUCCESS PATH ---
            # The key is valid, assign it to the session. Do NOT wipe it.
            self._master_key = master_key
            self._account_info = account_info
            self._is_authenticated = True

            # Update account info on successful login
            account_info.last_login = datetime.now(timezone.utc).isoformat()
            account_info.failed_login_attempts = 0

            logger.info("User authentication successful")
            return True
        else:
            return False

    async def encrypt_block(
        self,
        data: Dict[str, Any],
        block_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EncryptedBlock:
        """
        Stage 2: Encrypt a complete data block using AES-256-GCM.

        This method encrypts entire data structures as atomic units,
        providing both confidentiality and authenticity.

        Args:
            data: Dictionary containing all fields to encrypt
            block_id: Unique identifier for the block
            metadata: Additional unencrypted metadata

        Returns:
            EncryptedBlock containing encrypted data and metadata

        Raises:
            AuthenticationError: If user is not authenticated
            EncryptionError: If encryption fails
        """
        if not self._is_authenticated or not self._master_key:
            raise AuthenticationError("User not authenticated")

        encrypted_block = await encrypt_block(
            data, bytes(self._master_key), self.config, block_id, metadata
        )

        # Update entry count
        if self._account_info:
            self._account_info.entry_count += 1

        return encrypted_block

    async def decrypt_block(self, encrypted_block: EncryptedBlock) -> Dict[str, Any]:
        """
        Decrypt a complete data block using AES-256-GCM.

        This method decrypts encrypted blocks and verifies their integrity
        using authenticated encryption.

        Args:
            encrypted_block: The encrypted block to decrypt

        Returns:
            Dictionary containing decrypted data

        Raises:
            AuthenticationError: If user is not authenticated
            CryptoError: If decryption or verification fails
        """
        if not self._is_authenticated or not self._master_key:
            raise AuthenticationError("User not authenticated")

        return await decrypt_block(
            encrypted_block, bytes(self._master_key), self.config
        )

    async def change_master_password(
        self,
        old_password: str,
        new_password: str,
        encrypted_blocks: List[EncryptedBlock],
    ) -> Tuple[bytes, bytes, List[EncryptedBlock]]:
        """
        Change user's master password, re-encrypt all blocks, and create a new
        verifier hash.

        This method safely changes the master password by decrypting all
        blocks with the old key and re-encrypting with the new key. It also
        generates the new salt and new verifier hash required to update the
        user's account information. The new master key is correctly persisted
        in the session upon success.

        Args:
            old_password: Current master password (not used, relies on session auth)
            new_password: New master password
            encrypted_blocks: All user's encrypted blocks

        Returns:
            Tuple of (new_salt, new_verifier_hash, re_encrypted_blocks)

        Raises:
            AuthenticationError: If user is not authenticated
            CryptoError: If re-encryption fails
        """
        logger.info("Starting master password change operation")

        if not self._is_authenticated or not self._master_key:
            raise AuthenticationError("User must be authenticated to change password")

        old_master_key = self._master_key
        new_master_key, new_salt = await self.derive_master_key(new_password)
        new_verifier_hash: Optional[bytes] = None

        try:
            # Create the new verifier hash from the new master key
            new_verifier_hash = hashlib.sha256(bytes(new_master_key)).digest()

            re_encrypted_blocks = []
            for i, block in enumerate(encrypted_blocks):
                # Decrypt with old key (from session)
                decrypted_data = await self.decrypt_block(block)

                # Temporarily switch to new key for encryption
                self._master_key = new_master_key
                new_block = await self.encrypt_block(
                    decrypted_data, block.id, block.metadata
                )
                re_encrypted_blocks.append(new_block)

                # Restore old key to session in case of failure on next iteration
                self._master_key = old_master_key

                if (i + 1) % 100 == 0:
                    logger.debug(f"Re-encrypted {i+1}/{len(encrypted_blocks)} blocks")

            # --- SUCCESS ---
            # All blocks re-encrypted. Finalize the key switch.
            self._master_key = new_master_key

            if self._account_info:
                self._account_info.last_password_change = datetime.now(
                    timezone.utc
                ).isoformat()

            logger.info("Master password change completed successfully")
            return new_salt, new_verifier_hash, re_encrypted_blocks

        except Exception as e:
            # --- FAILURE ---
            # Restore the original master key to the session
            self._master_key = old_master_key
            # Securely wipe the new key that failed to be applied
            new_master_key.wipe()
            raise CryptoError(f"Password change failed: {str(e)}")
        finally:
            # Securely wipe the old master key from memory as it's no longer needed
            # in this local scope. The session key is now either the new key or the restored old key.
            if old_master_key:
                old_master_key.wipe()

    async def delete_account(self, password: str, account_info: AccountInfo) -> bool:
        """
        Securely delete user account and all associated data.

        This method permanently removes all user data and credentials
        with secure memory wiping. It requires re-authentication for security.

        Args:
            password: User's master password for confirmation
            account_info: The user's account information for authentication

        Returns:
            True if account deletion successful

        Raises:
            AuthenticationError: If password verification fails or account is locked.
        """
        logger.warning("Account deletion requested")

        try:
            # Re-authenticate for security using a temporary engine to avoid state pollution.
            temp_engine = AsyncCryptoEngine(self.config)
            auth_success = await temp_engine.authenticate_user(password, account_info)
            if not auth_success:
                # This path is taken for a standard password mismatch.
                raise AuthenticationError("Invalid password for account deletion")

            # Clear all session data of the main engine
            await self.clear_session()

            # In a real implementation, you would delete from persistent storage here
            logger.info("Account successfully deleted")
            return True

        except AuthenticationError as e:
            # This catches both the explicit "invalid password" error from above and
            # any error propagated from authenticate_user (e.g., "account is locked").
            logger.error(f"Account deletion failed: {e}")
            raise  # Re-raise the informative exception to the caller.
        except Exception as e:
            logger.error(
                f"An unexpected error occurred during account deletion: {str(e)}"
            )
            raise AccountError(f"Account deletion failed: {str(e)}")

    async def bulk_delete_entries(self, deleted_count: int) -> None:
        """
        Updates the internal account entry count after a bulk delete operation.

        This method does not perform the deletion itself but updates the
        account metadata based on the number of entries deleted by a higher-level manager.

        Args:
            deleted_count: The number of entries that were successfully deleted.

        Raises:
            AuthenticationError: If user is not authenticated.
        """
        if not self._is_authenticated:
            raise AuthenticationError("User not authenticated")

        if self._account_info and deleted_count > 0:
            self._account_info.entry_count = max(
                0, self._account_info.entry_count - deleted_count
            )
            logger.info(
                f"Account entry count updated. Removed {deleted_count} entries."
            )

    async def export_data(
        self,
        encrypted_blocks: List[EncryptedBlock],
        export_format: ExportFormat = ExportFormat.JSON,
        export_password: Optional[str] = None,
    ) -> bytes:
        """
        Export user data in specified format with optional encryption.

        This method provides secure data export capabilities with multiple
        format options and optional additional encryption for backups.

        Args:
            encrypted_blocks: All encrypted blocks to export
            export_format: Format for export (JSON, CSV, or encrypted backup)
            export_password: Optional password for backup encryption

        Returns:
            Exported data as bytes

        Raises:
            AuthenticationError: If user is not authenticated
            ExportError: If export operation fails
        """
        if not self._is_authenticated:
            raise AuthenticationError("User not authenticated")

        export_result = await export_data(
            encrypted_blocks,
            bytes(self._master_key),
            self.config,
            export_format,
            export_password,
            self._account_info,
        )

        # Update export count
        if self._account_info:
            self._account_info.export_count += 1

        return export_result

    async def import_encrypted_backup(
        self, backup_data: bytes, export_password: str
    ) -> List[Dict[str, Any]]:
        """
        Import data from encrypted backup.

        Args:
            backup_data: Encrypted backup data
            export_password: Password used for backup encryption

        Returns:
            List of imported entry data

        Raises:
            ExportError: If import fails
        """
        return await import_encrypted_backup(backup_data, export_password, self.config)

    async def clear_session(self) -> None:
        """
        Clear all session data and cached keys with secure memory wiping.

        This method ensures that all sensitive data is properly removed
        from memory when the session ends.
        """
        logger.info("Clearing session data")

        # Securely wipe master key
        if self._master_key:
            self._master_key.wipe()
            self._master_key = None

        # Securely wipe session keys
        for key in self._session_keys.values():
            key.wipe()
        self._session_keys.clear()

        # Clear other session data
        self._account_info = None
        self._is_authenticated = False
        self._last_auth_time = 0.0

        # Force garbage collection
        if self.config.force_garbage_collection:
            for _ in range(3):
                gc.collect()

        logger.info("Session cleared successfully")

    def is_authenticated(self) -> bool:
        """Check if user is currently authenticated."""
        return self._is_authenticated and self._master_key is not None

    def get_account_info(self) -> Optional[AccountInfo]:
        """Get current account information."""
        return self._account_info
