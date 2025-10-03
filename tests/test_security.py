"""
Tests for security features and secure memory handling.
"""

import unittest
import secrets

from crypto_engine.config.crypto_config import CryptoConfig
from crypto_engine.core.secure_memory import SecureBytes, secure_memory_context
from crypto_engine.operations.encryption import encrypt_block
from crypto_engine.api.password_manager import PasswordManagerCrypto
from crypto_engine.exceptions import AuthenticationError
from .test_utils import async_test


class TestSecureMemory(unittest.TestCase):
    """Test secure memory handling."""

    def test_secure_bytes_creation(self):
        """Test SecureBytes creation."""
        data = b"sensitive_data_12345"
        secure = SecureBytes(data)

        self.assertEqual(len(secure), len(data))
        self.assertEqual(bytes(secure), data)

    def test_secure_bytes_wipe(self):
        """Test SecureBytes memory wiping."""
        data = b"secret_password"
        secure = SecureBytes(data)

        # Wipe the data
        secure.wipe()

        self.assertEqual(len(secure), 0)

    def test_secure_bytes_context_manager(self):
        """Test SecureBytes as context manager."""
        data = b"context_test_data"

        with SecureBytes(data) as secure:
            self.assertEqual(bytes(secure), data)

        # After exiting context, data should be wiped
        self.assertEqual(len(secure), 0)

    def test_secure_memory_context(self):
        """Test secure_memory_context context manager."""
        # Should not raise any exceptions
        with secure_memory_context():
            _ = b"test_data"
            # Context ensures garbage collection


class TestSecurityFeatures(unittest.TestCase):
    """Test security features and protections."""

    @async_test
    async def test_timing_attack_protection(self):
        """Test that authentication has minimum delay."""
        import time

        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)

        # Test with correct password
        start = time.time()
        await crypto.login(password, account)
        correct_duration = time.time() - start
        await crypto.logout()

        # Test with wrong password
        start = time.time()
        await crypto.login("wrong_password", account)
        wrong_duration = time.time() - start

        # Both should take at least min_auth_delay_ms
        min_delay_seconds = crypto.engine.config.min_auth_delay_ms / 1000

        self.assertGreater(correct_duration, min_delay_seconds * 0.9)
        self.assertGreater(wrong_duration, min_delay_seconds * 0.9)

    @async_test
    async def test_account_lockout_mechanism(self):
        """Test account lockout after failed attempts."""
        crypto = PasswordManagerCrypto()
        password = "correct_password"

        account = await crypto.register_user(password)

        # Try wrong password 5 times
        for i in range(5):
            success = await crypto.login("wrong_password", account)
            self.assertFalse(success)

        # Account should be locked
        self.assertTrue(account.account_locked)
        self.assertEqual(account.failed_login_attempts, 5)

        # Even correct password should fail
        with self.assertRaises(AuthenticationError):
            await crypto.login(password, account)

    @async_test
    async def test_secure_memory_cleanup(self):
        """Test that sensitive data is cleaned up."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)
        await crypto.login(password, account)

        # Store entry
        await crypto.store_entry({"title": "Test", "password": "secret"})

        # Logout should clear all sensitive data
        await crypto.logout()

        self.assertFalse(crypto.engine.is_authenticated())
        self.assertIsNone(crypto.engine._master_key)

    @async_test
    async def test_block_integrity_verification(self):
        """Test that block integrity is verified."""
        config = CryptoConfig()
        master_key = secrets.token_bytes(32)

        data = {"test": "data"}
        encrypted = await encrypt_block(data, master_key, config)

        # Verify initial integrity
        self.assertTrue(encrypted.verify_integrity())

        # Corrupt the data
        original_data = encrypted.encrypted_data
        encrypted.encrypted_data = b"corrupted"

        # Integrity check should fail
        self.assertFalse(encrypted.verify_integrity())

        # Restore for cleanup
        encrypted.encrypted_data = original_data

    @async_test
    async def test_constant_time_comparison(self):
        """Test that constant time comparison is used."""
        config = CryptoConfig()

        # Config should enable constant time comparison
        self.assertTrue(config.constant_time_compare)
