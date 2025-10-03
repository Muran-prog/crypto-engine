"""
Tests for high-level PasswordManagerCrypto API.
"""

import unittest
import base64

from crypto_engine.api.password_manager import PasswordManagerCrypto
from crypto_engine.models.encrypted_block import EncryptedBlock
from .test_utils import async_test


class TestPasswordManagerCrypto(unittest.TestCase):
    """Test high-level PasswordManagerCrypto API."""

    @async_test
    async def test_user_registration(self):
        """Test user registration."""
        crypto = PasswordManagerCrypto()
        password = "test_password_123"

        account = await crypto.register_user(password, user_id="test_user")

        self.assertEqual(account.user_id, "test_user")
        self.assertIsNotNone(account.master_key_salt)
        self.assertIsNotNone(account.master_key_verifier_hash)
        self.assertEqual(account.entry_count, 0)

    @async_test
    async def test_login_logout(self):
        """Test login and logout."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)
        success = await crypto.login(password, account)

        self.assertTrue(success)
        self.assertTrue(crypto.engine.is_authenticated())

        await crypto.logout()

        self.assertFalse(crypto.engine.is_authenticated())

    @async_test
    async def test_store_and_retrieve_entry(self):
        """Test storing and retrieving entries."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)
        await crypto.login(password, account)

        # Store entry
        entry_data = {
            "title": "Test Entry",
            "username": "user@example.com",
            "password": "secret123",
            "url": "https://example.com",
            "notes": "Test notes",
        }

        encrypted = await crypto.store_entry(entry_data)

        self.assertIsInstance(encrypted, EncryptedBlock)

        # Retrieve entry
        decrypted = await crypto.get_entry(encrypted)

        self.assertEqual(decrypted["title"], entry_data["title"])
        self.assertEqual(decrypted["username"], entry_data["username"])
        self.assertEqual(decrypted["password"], entry_data["password"])

        await crypto.logout()

    @async_test
    async def test_update_entry(self):
        """Test updating entries."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)
        await crypto.login(password, account)

        # Store original
        original = {"title": "Original", "password": "pass1"}
        encrypted = await crypto.store_entry(original)

        # Update
        updated = {"title": "Updated", "password": "pass2"}
        new_encrypted = await crypto.update_entry(encrypted, updated)

        # Verify update
        decrypted = await crypto.get_entry(new_encrypted)

        self.assertEqual(decrypted["title"], "Updated")
        self.assertEqual(decrypted["password"], "pass2")

        await crypto.logout()

    @async_test
    async def test_delete_entry(self):
        """Test deleting entries."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)
        await crypto.login(password, account)

        # Store and delete
        entry = {"title": "To Delete"}
        encrypted = await crypto.store_entry(entry)

        success = await crypto.delete_entry(encrypted.id)

        self.assertTrue(success)

        # Try to delete again
        success = await crypto.delete_entry(encrypted.id)

        self.assertFalse(success)

        await crypto.logout()

    @async_test
    async def test_bulk_delete_entries(self):
        """Test bulk deletion of entries."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)
        await crypto.login(password, account)

        # Store multiple entries
        entries = []
        for i in range(5):
            encrypted = await crypto.store_entry({"title": f"Entry {i}"})
            entries.append(encrypted)

        # Bulk delete
        ids_to_delete = [e.id for e in entries[:3]]
        deleted_count = await crypto.bulk_delete_entries(ids_to_delete)

        self.assertEqual(deleted_count, 3)

        summary = crypto.get_entries_summary()
        self.assertEqual(summary["total_entries"], 2)

        await crypto.logout()

    @async_test
    async def test_change_master_password(self):
        """Test changing master password."""
        crypto = PasswordManagerCrypto()
        old_password = "old_password_123"
        new_password = "new_password_456"

        account = await crypto.register_user(old_password)
        await crypto.login(old_password, account)

        # Store some entries
        original_data = []
        for i in range(3):
            data = {"title": f"Entry {i}", "data": f"data_{i}"}
            await crypto.store_entry(data)
            original_data.append(data)

        # Verify we have 3 entries
        summary = crypto.get_entries_summary()
        self.assertEqual(summary["total_entries"], 3)

        # Change password
        new_salt, new_verifier, re_encrypted = await crypto.change_master_password(
            old_password, new_password
        )

        # Verify all entries were re-encrypted
        self.assertEqual(len(re_encrypted), 3)

        # Verify entries are still accessible after password change (without logout)
        summary_after_change = crypto.get_entries_summary()
        self.assertEqual(summary_after_change["total_entries"], 3)

        # Verify we can decrypt the re-encrypted blocks
        for i, block in enumerate(re_encrypted):
            decrypted = await crypto.get_entry(block)
            self.assertIn("title", decrypted)
            self.assertIn("data", decrypted)

        # Update account with new credentials
        account.master_key_salt = base64.b64encode(new_salt).decode()
        account.master_key_verifier_hash = base64.b64encode(new_verifier).decode()

        await crypto.logout()

        # Login with new password should work
        crypto2 = PasswordManagerCrypto()
        success = await crypto2.login(new_password, account)
        self.assertTrue(success)

        # Old password should not work
        crypto3 = PasswordManagerCrypto()
        success = await crypto3.login(old_password, account)
        self.assertFalse(success)

        await crypto2.logout()

    @async_test
    async def test_get_entries_summary(self):
        """Test getting entries summary."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)
        await crypto.login(password, account)

        # Store entries with different types
        await crypto.store_entry({"title": "Entry 1", "type": "website"})
        await crypto.store_entry({"title": "Entry 2", "type": "website"})
        await crypto.store_entry({"title": "Entry 3", "type": "email"})

        summary = crypto.get_entries_summary()

        self.assertEqual(summary["total_entries"], 3)
        self.assertEqual(summary["entry_types"]["website"], 2)
        self.assertEqual(summary["entry_types"]["email"], 1)
        self.assertTrue(summary["is_authenticated"])

        await crypto.logout()
