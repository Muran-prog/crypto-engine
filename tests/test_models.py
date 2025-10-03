"""
Tests for data models (Enums, EncryptedBlock, AccountInfo).
"""

import unittest
import secrets
from datetime import datetime, timezone

from crypto_engine.models.enums import KeyDerivationMethod, ExportFormat
from crypto_engine.models.encrypted_block import EncryptedBlock
from crypto_engine.models.account_info import AccountInfo


class TestEnums(unittest.TestCase):
    """Test enumeration types."""
    
    def test_key_derivation_method_enum(self):
        """Test KeyDerivationMethod enum."""
        self.assertEqual(KeyDerivationMethod.PBKDF2.value, "pbkdf2")
        self.assertEqual(KeyDerivationMethod.SCRYPT.value, "scrypt")
        
        # Test enum by value
        self.assertEqual(KeyDerivationMethod("pbkdf2"), KeyDerivationMethod.PBKDF2)
    
    def test_export_format_enum(self):
        """Test ExportFormat enum."""
        self.assertEqual(ExportFormat.JSON.value, "json")
        self.assertEqual(ExportFormat.CSV.value, "csv")
        self.assertEqual(ExportFormat.ENCRYPTED_BACKUP.value, "encrypted_backup")


class TestEncryptedBlock(unittest.TestCase):
    """Test EncryptedBlock model."""
    
    def test_encrypted_block_creation(self):
        """Test creating an EncryptedBlock."""
        block = EncryptedBlock(
            id="test_block_001",
            encrypted_data=b"encrypted_payload",
            nonce=secrets.token_bytes(12),
            tag=secrets.token_bytes(16),
            salt=secrets.token_bytes(32),
            metadata={"type": "test"},
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
        self.assertEqual(block.id, "test_block_001")
        self.assertEqual(block.version, "2.0")
        self.assertIsNotNone(block.checksum)
    
    def test_checksum_calculation(self):
        """Test checksum calculation and verification."""
        block = EncryptedBlock(
            id="test_block_002",
            encrypted_data=b"test_data",
            nonce=b"nonce" * 2 + b"no",
            tag=b"tag" * 4,
            salt=b"salt" * 8,
            metadata={},
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
        # Checksum should be calculated automatically
        self.assertIsNotNone(block.checksum)
        self.assertEqual(len(block.checksum), 64)  # SHA-256 hex = 64 chars
        
        # Verify integrity
        self.assertTrue(block.verify_integrity())
    
    def test_block_serialization(self):
        """Test block to_dict and from_dict."""
        original_block = EncryptedBlock(
            id="test_block_003",
            encrypted_data=b"data_to_serialize",
            nonce=secrets.token_bytes(12),
            tag=secrets.token_bytes(16),
            salt=secrets.token_bytes(32),
            metadata={"author": "test"},
            timestamp="2024-01-01T00:00:00"
        )
        
        # Serialize to dict
        block_dict = original_block.to_dict()
        
        self.assertIn("id", block_dict)
        self.assertIn("encrypted_data", block_dict)
        self.assertIn("checksum", block_dict)
        
        # Deserialize from dict
        reconstructed_block = EncryptedBlock.from_dict(block_dict)
        
        self.assertEqual(reconstructed_block.id, original_block.id)
        self.assertEqual(reconstructed_block.encrypted_data, original_block.encrypted_data)
        self.assertEqual(reconstructed_block.checksum, original_block.checksum)
        self.assertTrue(reconstructed_block.verify_integrity())
    
    def test_invalid_block_deserialization(self):
        """Test deserializing invalid block data."""
        invalid_data = {"id": "test", "missing": "fields"}
        
        with self.assertRaises(ValueError):
            EncryptedBlock.from_dict(invalid_data)


class TestAccountInfo(unittest.TestCase):
    """Test AccountInfo model."""
    
    def test_account_info_creation(self):
        """Test creating AccountInfo."""
        account = AccountInfo(
            user_id="test_user",
            created_at="2024-01-01T00:00:00",
            master_key_salt="salt_base64",
            master_key_verifier_hash="hash_base64"
        )
        
        self.assertEqual(account.user_id, "test_user")
        self.assertEqual(account.entry_count, 0)
        self.assertEqual(account.failed_login_attempts, 0)
        self.assertFalse(account.account_locked)
        self.assertEqual(account.version, "2.0")
    
    def test_account_info_serialization(self):
        """Test AccountInfo to_dict and from_dict."""
        original = AccountInfo(
            user_id="user123",
            created_at="2024-01-01T00:00:00",
            master_key_salt="salt",
            master_key_verifier_hash="hash",
            entry_count=10,
            failed_login_attempts=2
        )
        
        # Serialize
        account_dict = original.to_dict()
        
        # Deserialize
        reconstructed = AccountInfo.from_dict(account_dict)
        
        self.assertEqual(reconstructed.user_id, original.user_id)
        self.assertEqual(reconstructed.entry_count, original.entry_count)
        self.assertEqual(reconstructed.failed_login_attempts, original.failed_login_attempts)