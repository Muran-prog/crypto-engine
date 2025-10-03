"""
Tests for error handling throughout the system.
"""

import unittest

from crypto_engine.api.password_manager import PasswordManagerCrypto
from crypto_engine.models.enums import ExportFormat
from crypto_engine.exceptions import AuthenticationError, ExportError
from .test_utils import async_test


class TestErrorHandling(unittest.TestCase):
    """Test error handling throughout the system."""

    @async_test
    async def test_encryption_without_authentication(self):
        """Test that operations require authentication."""
        crypto = PasswordManagerCrypto()

        with self.assertRaises(AuthenticationError):
            await crypto.store_entry({"title": "Test"})

    @async_test
    async def test_decryption_without_authentication(self):
        """Test decryption requires authentication."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        # Create and encrypt entry
        account = await crypto.register_user(password)
        await crypto.login(password, account)
        encrypted = await crypto.store_entry({"title": "Test"})
        await crypto.logout()

        # Try to decrypt without auth
        with self.assertRaises(AuthenticationError):
            await crypto.get_entry(encrypted)

    @async_test
    async def test_bulk_delete_without_authentication(self):
        """Test bulk delete requires authentication."""
        crypto = PasswordManagerCrypto()

        with self.assertRaises(AuthenticationError):
            await crypto.bulk_delete_entries(["id1", "id2"])

    @async_test
    async def test_export_without_authentication(self):
        """Test export requires authentication."""
        crypto = PasswordManagerCrypto()

        with self.assertRaises(AuthenticationError):
            await crypto.export_data(ExportFormat.JSON)

    @async_test
    async def test_invalid_encrypted_backup_format(self):
        """Test importing invalid backup format."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)
        await crypto.login(password, account)

        invalid_backup = b'{"format": "invalid", "data": "test"}'

        with self.assertRaises(ExportError):
            await crypto.import_backup(invalid_backup, "password")

        await crypto.logout()
