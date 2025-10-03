"""
Secure memory handling utilities for sensitive cryptographic data.

This module provides classes and utilities for automatic memory wiping,
preventing information leakage through memory dumps or swap files.

Author: Muran-prog
License: MIT
Version: 2.0
"""

import gc
import secrets
import weakref
from contextlib import contextmanager


class SecureBytes:
    """
    Secure byte array that automatically wipes memory on deletion.
    
    This class provides automatic memory wiping for sensitive data
    to prevent information leakage through memory dumps or swap files.
    """
    
    def __init__(self, data: bytes):
        """
        Initialize secure bytes container.
        
        Args:
            data: Sensitive byte data to store securely
        """
        self._data = bytearray(data)
        self._size = len(data)
        # Register for cleanup when object is garbage collected
        self._finalizer = weakref.finalize(self, self._secure_wipe, self._data)
    
    def __bytes__(self) -> bytes:
        """Return bytes representation."""
        return bytes(self._data)
    
    def __len__(self) -> int:
        """Return length of data."""
        return self._size
    
    def __enter__(self) -> 'SecureBytes':
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with secure wipe."""
        self.wipe()
    
    def wipe(self) -> None:
        """Securely wipe the data from memory."""
        if self._data:
            self._secure_wipe(self._data)
            self._data.clear()
            self._size = 0
    
    @staticmethod
    def _secure_wipe(data: bytearray) -> None:
        """
        Securely overwrite memory with random data.
        
        Args:
            data: Bytearray to wipe securely
        """
        if not data:
            return
        
        # Overwrite with random data multiple times
        for _ in range(3):
            for i in range(len(data)):
                data[i] = secrets.randbits(8)
        
        # Final overwrite with zeros
        for i in range(len(data)):
            data[i] = 0


@contextmanager
def secure_memory_context():
    """
    Context manager for secure memory operations.
    
    Ensures garbage collection and memory clearing after sensitive operations.
    """
    try:
        yield
    finally:
        # Force garbage collection to clear temporary objects
        gc.collect()
        # Additional cleanup attempts
        for _ in range(3):
            gc.collect()