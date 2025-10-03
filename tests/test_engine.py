"""
Tests for AsyncCryptoEngine class.
"""

import unittest
import base64
import hashlib
from datetime import datetime, timezone

from crypto_engine.core.engine import AsyncCryptoEngine
from crypto_engine.models.account_info import AccountInfo
from crypto_engine.models.encrypted_block import EncryptedBlock
from crypto_engine.exceptions import AuthenticationError
from .test_utils import async_test


class TestAsyncCryptoEngine(unittest.TestCase):
    """Test AsyncCryptoEngine class."""
    
    @async_test
    async def test_engine_initialization(self):
        """Test engine initialization."""
        engine = AsyncCryptoEngine()
        
        self.assertIsNotNone(engine.config)
        self.assertFalse(engine.is_authenticated())
        self.assertIsNone(engine.get_account_info())
    
    @async_test
    async def test_engine_authentication_flow(self):
        """Test complete authentication flow."""
        engine = AsyncCryptoEngine()
        password = "test_password_123"
        
        # Derive key and create account
        master_key, salt = await engine.derive_master_key(password)
        verifier_hash = hashlib.sha256(bytes(master_key)).digest()
        master_key.wipe()
        
        account = AccountInfo(
            user_id="engine_test_user",
            created_at=datetime.now(timezone.utc).isoformat(),
            master_key_salt=base64.b64encode(salt).decode(),
            master_key_verifier_hash=base64.b64encode(verifier_hash).decode()
        )
        
        # Authenticate
        success = await engine.authenticate_user(password, account)
        
        self.assertTrue(success)
        self.assertTrue(engine.is_authenticated())
        self.assertIsNotNone(engine.get_account_info())
        
        await engine.clear_session()
    
    @async_test
    async def test_engine_encrypt_decrypt(self):
        """Test engine encryption and decryption."""
        engine = AsyncCryptoEngine()
        password = "test_password"
        
        # Setup
        master_key, salt = await engine.derive_master_key(password)
        verifier_hash = hashlib.sha256(bytes(master_key)).digest()
        master_key.wipe()
        
        account = AccountInfo(
            user_id="test",
            created_at=datetime.now(timezone.utc).isoformat(),
            master_key_salt=base64.b64encode(salt).decode(),
            master_key_verifier_hash=base64.b64encode(verifier_hash).decode()
        )
        
        await engine.authenticate_user(password, account)
        
        # Test encryption
        data = {"test": "data", "number": 123}
        encrypted = await engine.encrypt_block(data)
        
        self.assertIsInstance(encrypted, EncryptedBlock)
        
        # Test decryption
        decrypted = await engine.decrypt_block(encrypted)
        
        self.assertEqual(decrypted, data)
        
        await engine.clear_session()
    
    @async_test
    async def test_engine_encryption_without_auth(self):
        """Test encryption without authentication fails."""
        engine = AsyncCryptoEngine()
        
        with self.assertRaises(AuthenticationError):
            await engine.encrypt_block({"test": "data"})
    
    @async_test
    async def test_engine_session_clearing(self):
        """Test session clearing."""
        engine = AsyncCryptoEngine()
        password = "test_password"
        
        # Setup and authenticate
        master_key, salt = await engine.derive_master_key(password)
        verifier_hash = hashlib.sha256(bytes(master_key)).digest()
        master_key.wipe()
        
        account = AccountInfo(
            user_id="test",
            created_at=datetime.now(timezone.utc).isoformat(),
            master_key_salt=base64.b64encode(salt).decode(),
            master_key_verifier_hash=base64.b64encode(verifier_hash).decode()
        )
        
        await engine.authenticate_user(password, account)
        self.assertTrue(engine.is_authenticated())
        
        # Clear session
        await engine.clear_session()
        
        self.assertFalse(engine.is_authenticated())
        self.assertIsNone(engine.get_account_info())