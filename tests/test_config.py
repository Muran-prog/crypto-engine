"""
Tests for CryptoConfig configuration.
"""

import unittest
from crypto_engine.config.crypto_config import CryptoConfig
from crypto_engine.models.enums import KeyDerivationMethod


class TestCryptoConfig(unittest.TestCase):
    """Test CryptoConfig dataclass."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = CryptoConfig()
        
        self.assertEqual(config.key_derivation_method, KeyDerivationMethod.SCRYPT)
        self.assertEqual(config.pbkdf2_iterations, 600_000)
        self.assertEqual(config.scrypt_n, 32768)
        self.assertEqual(config.scrypt_r, 8)
        self.assertEqual(config.scrypt_p, 1)
        self.assertEqual(config.salt_size, 32)
        self.assertEqual(config.aes_key_size, 32)
        self.assertEqual(config.gcm_nonce_size, 12)
        self.assertEqual(config.gcm_tag_size, 16)
        self.assertTrue(config.constant_time_compare)
        self.assertEqual(config.min_auth_delay_ms, 100)
        self.assertTrue(config.secure_memory_wipe)
        self.assertTrue(config.force_garbage_collection)
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = CryptoConfig(
            key_derivation_method=KeyDerivationMethod.PBKDF2,
            pbkdf2_iterations=1_000_000,
            min_auth_delay_ms=200
        )
        
        self.assertEqual(config.key_derivation_method, KeyDerivationMethod.PBKDF2)
        self.assertEqual(config.pbkdf2_iterations, 1_000_000)
        self.assertEqual(config.min_auth_delay_ms, 200)