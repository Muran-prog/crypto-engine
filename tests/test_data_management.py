"""
Tests for data export/import and account management.
"""

import unittest
import json

from crypto_engine.api.password_manager import PasswordManagerCrypto
from crypto_engine.models.enums import ExportFormat
from crypto_engine.exceptions import AuthenticationError, ExportError
from .test_utils import async_test


class TestDataExport(unittest.TestCase):
    """Test data export and import functionality."""

    @async_test
    async def test_json_export(self):
        """Test JSON export."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)
        await crypto.login(password, account)

        # Store entries
        for i in range(3):
            await crypto.store_entry({"title": f"Entry {i}", "data": f"value_{i}"})

        # Export
        export_data = await crypto.export_data(ExportFormat.JSON)

        self.assertIsInstance(export_data, bytes)

        # Parse JSON
        json_data = json.loads(export_data.decode("utf-8"))

        self.assertEqual(json_data["version"], "2.0")
        self.assertEqual(json_data["entry_count"], 3)
        self.assertIn("entries", json_data)

        await crypto.logout()

    @async_test
    async def test_csv_export(self):
        """Test CSV export."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)
        await crypto.login(password, account)

        # Store entries
        await crypto.store_entry(
            {"title": "Entry 1", "username": "user1", "password": "pass1"}
        )
        await crypto.store_entry(
            {"title": "Entry 2", "username": "user2", "password": "pass2"}
        )

        # Export
        export_data = await crypto.export_data(ExportFormat.CSV)

        self.assertIsInstance(export_data, bytes)

        # Parse CSV
        csv_content = export_data.decode("utf-8")
        lines = csv_content.strip().split("\n")

        self.assertGreater(len(lines), 1)  # Header + data rows
        self.assertIn("title", lines[0])  # Check header

        await crypto.logout()

    @async_test
    async def test_encrypted_backup_export_import(self):
        """Test encrypted backup export and import."""
        crypto = PasswordManagerCrypto()
        password = "test_password"
        backup_password = "backup_password_123"

        account = await crypto.register_user(password)
        await crypto.login(password, account)

        # Store entries
        entries_data = []
        for i in range(5):
            entry = {"title": f"Entry {i}", "data": f"value_{i}"}
            await crypto.store_entry(entry)
            entries_data.append(entry)

        # Export encrypted backup
        backup_data = await crypto.export_data(
            ExportFormat.ENCRYPTED_BACKUP, export_password=backup_password
        )

        self.assertIsInstance(backup_data, bytes)

        # Clear all entries
        entry_ids = list(crypto._entries.keys())
        await crypto.bulk_delete_entries(entry_ids)

        summary = crypto.get_entries_summary()
        self.assertEqual(summary["total_entries"], 0)

        # Import backup
        imported_count = await crypto.import_backup(backup_data, backup_password)

        self.assertEqual(imported_count, 5)

        summary = crypto.get_entries_summary()
        self.assertEqual(summary["total_entries"], 5)

        await crypto.logout()

    @async_test
    async def test_import_with_wrong_password(self):
        """Test import with wrong password fails."""
        crypto = PasswordManagerCrypto()
        password = "test_password"
        backup_password = "backup_password_123"

        account = await crypto.register_user(password)
        await crypto.login(password, account)

        await crypto.store_entry({"title": "Test Entry"})

        # Export
        backup_data = await crypto.export_data(
            ExportFormat.ENCRYPTED_BACKUP, export_password=backup_password
        )

        # Try to import with wrong password
        with self.assertRaises(ExportError):
            await crypto.import_backup(backup_data, "wrong_password")

        await crypto.logout()


class TestAccountManagement(unittest.TestCase):
    """Test account management operations."""

    @async_test
    async def test_delete_account(self):
        """Test account deletion."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)
        await crypto.login(password, account)

        # Store some data
        await crypto.store_entry({"title": "Entry 1"})
        await crypto.store_entry({"title": "Entry 2"})

        # Delete account
        success = await crypto.delete_account(password, account)

        self.assertTrue(success)
        self.assertFalse(crypto.engine.is_authenticated())
        self.assertEqual(len(crypto._entries), 0)

    @async_test
    async def test_delete_account_wrong_password(self):
        """Test account deletion with wrong password fails."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)
        await crypto.login(password, account)

        # Try to delete with wrong password
        with self.assertRaises(AuthenticationError):
            await crypto.delete_account("wrong_password", account)

        # Account should still be accessible
        self.assertTrue(crypto.engine.is_authenticated())

        await crypto.logout()

    @async_test
    async def test_delete_account_locked(self):
        """Test deleting locked account fails."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)

        # Lock the account
        account.account_locked = True

        # Try to delete
        with self.assertRaises(AuthenticationError):
            await crypto.delete_account(password, account)
