"""
Tests for cryptographic operations (key derivation, authentication, encryption).
"""

import unittest
import secrets
import base64
import hashlib
from datetime import datetime, timezone

from crypto_engine.config.crypto_config import CryptoConfig
from crypto_engine.models.enums import KeyDerivationMethod
from crypto_engine.models.account_info import AccountInfo
from crypto_engine.models.encrypted_block import EncryptedBlock
from crypto_engine.operations.key_derivation import derive_master_key, derive_block_key
from crypto_engine.operations.authentication import authenticate_user
from crypto_engine.operations.encryption import encrypt_block, decrypt_block
from crypto_engine.exceptions import CryptoError, AuthenticationError
from .test_utils import async_test


class TestKeyDerivation(unittest.TestCase):
    """Test key derivation functions."""

    @async_test
    async def test_derive_master_key_pbkdf2(self):
        """Test master key derivation with PBKDF2."""
        config = CryptoConfig(
            key_derivation_method=KeyDerivationMethod.PBKDF2,
            pbkdf2_iterations=100_000,  # Reduced for testing
        )

        password = "test_password_123"
        master_key, salt = await derive_master_key(password, config)

        self.assertEqual(len(master_key), config.aes_key_size)
        self.assertEqual(len(salt), config.salt_size)

        # Same password + salt should produce same key
        master_key2, _ = await derive_master_key(password, config, salt=salt)
        self.assertEqual(bytes(master_key), bytes(master_key2))

        # Clean up
        master_key.wipe()
        master_key2.wipe()

    @async_test
    async def test_derive_master_key_scrypt(self):
        """Test master key derivation with Scrypt."""
        config = CryptoConfig(
            key_derivation_method=KeyDerivationMethod.SCRYPT,
            scrypt_n=1024,  # Reduced for testing
        )

        password = "test_password_456"
        master_key, salt = await derive_master_key(password, config)

        self.assertEqual(len(master_key), config.aes_key_size)
        self.assertEqual(len(salt), config.salt_size)

        master_key.wipe()

    @async_test
    async def test_derive_block_key(self):
        """Test block-specific key derivation."""
        config = CryptoConfig()

        master_key = secrets.token_bytes(32)
        block_salt = secrets.token_bytes(32)
        block_id = "test_block_001"

        block_key = await derive_block_key(master_key, block_salt, block_id, config)

        self.assertEqual(len(block_key), config.aes_key_size)

        # Same inputs should produce same key
        block_key2 = await derive_block_key(master_key, block_salt, block_id, config)
        self.assertEqual(block_key, block_key2)

        # Different block_id should produce different key
        block_key3 = await derive_block_key(
            master_key, block_salt, "different_id", config
        )
        self.assertNotEqual(block_key, block_key3)


class TestAuthentication(unittest.TestCase):
    """Test authentication operations."""

    @async_test
    async def test_successful_authentication(self):
        """Test successful user authentication."""
        config = CryptoConfig(min_auth_delay_ms=50)  # Reduced for testing
        password = "correct_password"

        # Create account
        master_key, salt = await derive_master_key(password, config)
        verifier_hash = hashlib.sha256(bytes(master_key)).digest()
        master_key.wipe()

        account = AccountInfo(
            user_id="test_user",
            created_at=datetime.now(timezone.utc).isoformat(),
            master_key_salt=base64.b64encode(salt).decode(),
            master_key_verifier_hash=base64.b64encode(verifier_hash).decode(),
        )

        # Authenticate
        success, key = await authenticate_user(password, account, config)

        self.assertTrue(success)
        self.assertIsNotNone(key)
        self.assertEqual(account.failed_login_attempts, 0)

        key.wipe()

    @async_test
    async def test_failed_authentication(self):
        """Test failed authentication with wrong password."""
        config = CryptoConfig(min_auth_delay_ms=50)
        password = "correct_password"

        master_key, salt = await derive_master_key(password, config)
        verifier_hash = hashlib.sha256(bytes(master_key)).digest()
        master_key.wipe()

        account = AccountInfo(
            user_id="test_user",
            created_at=datetime.now(timezone.utc).isoformat(),
            master_key_salt=base64.b64encode(salt).decode(),
            master_key_verifier_hash=base64.b64encode(verifier_hash).decode(),
        )

        # Try wrong password
        success, key = await authenticate_user("wrong_password", account, config)

        self.assertFalse(success)
        self.assertIsNone(key)
        self.assertEqual(account.failed_login_attempts, 1)

    @async_test
    async def test_account_lockout(self):
        """Test account lockout after multiple failed attempts."""
        config = CryptoConfig(min_auth_delay_ms=50)
        password = "correct_password"

        master_key, salt = await derive_master_key(password, config)
        verifier_hash = hashlib.sha256(bytes(master_key)).digest()
        master_key.wipe()

        account = AccountInfo(
            user_id="test_user",
            created_at=datetime.now(timezone.utc).isoformat(),
            master_key_salt=base64.b64encode(salt).decode(),
            master_key_verifier_hash=base64.b64encode(verifier_hash).decode(),
        )

        # Fail 5 times
        for i in range(5):
            await authenticate_user("wrong_password", account, config)

        self.assertTrue(account.account_locked)

        # Try to authenticate with correct password on locked account
        with self.assertRaises(AuthenticationError):
            await authenticate_user(password, account, config)


class TestEncryption(unittest.TestCase):
    """Test encryption and decryption operations."""

    @async_test
    async def test_encrypt_decrypt_block(self):
        """Test basic encryption and decryption."""
        config = CryptoConfig()
        master_key = secrets.token_bytes(32)

        data = {
            "username": "test_user",
            "password": "secret_pass_123",
            "notes": "Test entry",
        }

        # Encrypt
        encrypted = await encrypt_block(data, master_key, config)

        self.assertIsInstance(encrypted, EncryptedBlock)
        self.assertTrue(encrypted.verify_integrity())

        # Decrypt
        decrypted = await decrypt_block(encrypted, master_key, config)

        self.assertEqual(decrypted, data)

    @async_test
    async def test_encryption_with_custom_block_id(self):
        """Test encryption with custom block ID."""
        config = CryptoConfig()
        master_key = secrets.token_bytes(32)

        data = {"test": "data"}
        block_id = "custom_block_id_123"

        encrypted = await encrypt_block(data, master_key, config, block_id=block_id)

        self.assertEqual(encrypted.id, block_id)

    @async_test
    async def test_encryption_with_metadata(self):
        """Test encryption with metadata."""
        config = CryptoConfig()
        master_key = secrets.token_bytes(32)

        data = {"secret": "value"}
        metadata = {"type": "test", "category": "demo"}

        encrypted = await encrypt_block(data, master_key, config, metadata=metadata)

        self.assertEqual(encrypted.metadata, metadata)

    @async_test
    async def test_decryption_with_wrong_key(self):
        """Test decryption with wrong key fails."""
        config = CryptoConfig()
        master_key = secrets.token_bytes(32)
        wrong_key = secrets.token_bytes(32)

        data = {"test": "data"}

        encrypted = await encrypt_block(data, master_key, config)

        with self.assertRaises(CryptoError):
            await decrypt_block(encrypted, wrong_key, config)

    @async_test
    async def test_decryption_with_corrupted_data(self):
        """Test decryption with corrupted data fails."""
        config = CryptoConfig()
        master_key = secrets.token_bytes(32)

        data = {"test": "data"}
        encrypted = await encrypt_block(data, master_key, config)

        # Corrupt the encrypted data
        encrypted.encrypted_data = b"corrupted_data"
        encrypted.checksum = encrypted._calculate_checksum()  # Recalculate checksum

        with self.assertRaises(CryptoError):
            await decrypt_block(encrypted, master_key, config)
