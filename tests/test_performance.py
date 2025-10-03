"""
Tests for performance characteristics.
"""

import unittest
import time

from crypto_engine.api.password_manager import PasswordManagerCrypto
from .test_utils import async_test


class TestPerformance(unittest.TestCase):
    """Test performance characteristics."""
    
    @async_test
    async def test_batch_encryption_performance(self):
        """Test batch encryption performance."""
        crypto = PasswordManagerCrypto()
        password = "test_password"
        
        account = await crypto.register_user(password)
        await crypto.login(password, account)
        
        # Encrypt 100 entries
        start = time.time()
        
        for i in range(100):
            await crypto.store_entry({"title": f"Entry {i}", "data": f"value_{i}"})
        
        duration = time.time() - start
        
        # Should complete in reasonable time (adjust threshold as needed)
        self.assertLess(duration, 30.0)  # 30 seconds for 100 entries
        
        avg_time = duration / 100
        print(f"\nAverage encryption time: {avg_time*1000:.2f}ms per entry")
        
        await crypto.logout()
    
    @async_test
    async def test_password_change_performance(self):
        """Test password change performance with multiple entries."""
        crypto = PasswordManagerCrypto()
        old_password = "old_password"
        new_password = "new_password"
        
        account = await crypto.register_user(old_password)
        await crypto.login(old_password, account)
        
        # Create 50 entries
        for i in range(50):
            await crypto.store_entry({"title": f"Entry {i}"})
        
        # Change password
        start = time.time()
        new_salt, new_verifier, re_encrypted = await crypto.change_master_password(
            old_password,
            new_password
        )
        duration = time.time() - start
        
        # Should complete in reasonable time
        self.assertLess(duration, 30.0)  # 30 seconds for 50 entries
        
        print(f"\nPassword change time for 50 entries: {duration:.2f}s")
        
        await crypto.logout()