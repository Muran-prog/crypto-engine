"""
Tests for edge cases and boundary conditions.
"""

import unittest

from crypto_engine.api.password_manager import PasswordManagerCrypto
from .test_utils import async_test


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""

    @async_test
    async def test_empty_data_encryption(self):
        """Test encrypting empty data."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)
        await crypto.login(password, account)

        # Empty dict
        encrypted = await crypto.store_entry({})
        decrypted = await crypto.get_entry(encrypted)

        self.assertEqual(decrypted, {})

        await crypto.logout()

    @async_test
    async def test_large_data_encryption(self):
        """Test encrypting large data."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)
        await crypto.login(password, account)

        # Create large entry
        large_data = {
            "title": "Large Entry",
            "notes": "x" * 10000,  # 10KB of data
            "data": list(range(1000)),
        }

        encrypted = await crypto.store_entry(large_data)
        decrypted = await crypto.get_entry(encrypted)

        self.assertEqual(decrypted, large_data)

        await crypto.logout()

    @async_test
    async def test_unicode_data(self):
        """Test encrypting unicode data."""
        crypto = PasswordManagerCrypto()
        password = "test_password"

        account = await crypto.register_user(password)
        await crypto.login(password, account)

        # Unicode data
        unicode_data = {
            "title": "Тестова запись",
            "username": "用户名",
            "password": "كلمة السر",
            "notes": "📝 Эмодзи и символы ©®™",
        }

        encrypted = await crypto.store_entry(unicode_data)
        decrypted = await crypto.get_entry(encrypted)

        self.assertEqual(decrypted, unicode_data)

        await crypto.logout()

    @async_test
    async def test_special_characters_in_password(self):
        """Test password with special characters."""
        crypto = PasswordManagerCrypto()
        password = "P@ssw0rd!#$%^&*()_+-=[]{}|;':\",./<>?"

        account = await crypto.register_user(password)
        success = await crypto.login(password, account)

        self.assertTrue(success)

        await crypto.logout()

    @async_test
    async def test_very_long_password(self):
        """Test very long password."""
        crypto = PasswordManagerCrypto()
        password = "a" * 1000  # 1000 character password

        account = await crypto.register_user(password)
        success = await crypto.login(password, account)

        self.assertTrue(success)

        await crypto.logout()

    @async_test
    async def test_multiple_simultaneous_logins(self):
        """Test multiple crypto instances with same account."""
        password = "test_password"

        # Create account
        crypto1 = PasswordManagerCrypto()
        account = await crypto1.register_user(password, user_id="shared_user")

        # Login from multiple instances
        crypto2 = PasswordManagerCrypto()
        crypto3 = PasswordManagerCrypto()

        success1 = await crypto1.login(password, account)
        success2 = await crypto2.login(password, account)
        success3 = await crypto3.login(password, account)

        self.assertTrue(success1)
        self.assertTrue(success2)
        self.assertTrue(success3)

        # All should be able to operate independently
        await crypto1.store_entry({"title": "Entry 1"})
        await crypto2.store_entry({"title": "Entry 2"})
        await crypto3.store_entry({"title": "Entry 3"})

        await crypto1.logout()
        await crypto2.logout()
        await crypto3.logout()
