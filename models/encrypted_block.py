"""
Encrypted block data model with integrity verification.

This module defines the EncryptedBlock dataclass, which represents
a complete encrypted unit with all necessary metadata for decryption
and verification.

Author: Muran-prog
License: MIT
Version: 2.0
"""

import base64
import hashlib
from dataclasses import dataclass
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import constant_time


@dataclass
class EncryptedBlock:
    """
    Container for encrypted data blocks with comprehensive metadata.

    This class represents a complete encrypted unit that contains all
    necessary information for decryption and verification.
    """

    id: str  # Unique block identifier
    encrypted_data: bytes  # Encrypted payload
    nonce: bytes  # AES-GCM nonce
    tag: bytes  # Authentication tag
    salt: bytes  # Block-specific salt
    metadata: Dict[str, Any]  # Unencrypted metadata
    timestamp: str  # ISO format timestamp
    version: str = "2.0"  # Engine version
    checksum: Optional[str] = None  # Optional integrity checksum

    def __post_init__(self):
        """Calculate checksum after initialization."""
        if self.checksum is None:
            self.checksum = self._calculate_checksum()

    def _calculate_checksum(self) -> str:
        """
        Calculate SHA-256 checksum of encrypted data for integrity verification.

        Returns:
            Hexadecimal checksum string
        """
        hasher = hashlib.sha256()
        hasher.update(self.encrypted_data)
        hasher.update(self.nonce)
        hasher.update(self.tag)
        hasher.update(self.salt)
        return hasher.hexdigest()

    def verify_integrity(self) -> bool:
        """
        Verify block integrity using checksum.

        Returns:
            True if integrity check passes
        """
        return constant_time.bytes_eq(
            self.checksum.encode(), self._calculate_checksum().encode()
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization.

        Returns:
            Dictionary representation suitable for JSON serialization
        """
        return {
            "id": self.id,
            "encrypted_data": base64.b64encode(self.encrypted_data).decode(),
            "nonce": base64.b64encode(self.nonce).decode(),
            "tag": base64.b64encode(self.tag).decode(),
            "salt": base64.b64encode(self.salt).decode(),
            "metadata": self.metadata,
            "timestamp": self.timestamp,
            "version": self.version,
            "checksum": self.checksum,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EncryptedBlock":
        """
        Create instance from dictionary.

        Args:
            data: Dictionary containing block data

        Returns:
            EncryptedBlock instance

        Raises:
            ValueError: If dictionary format is invalid
        """
        try:
            return cls(
                id=data["id"],
                encrypted_data=base64.b64decode(data["encrypted_data"]),
                nonce=base64.b64decode(data["nonce"]),
                tag=base64.b64decode(data["tag"]),
                salt=base64.b64decode(data["salt"]),
                metadata=data["metadata"],
                timestamp=data["timestamp"],
                version=data.get("version", "2.0"),
                checksum=data.get("checksum"),
            )
        except (KeyError, ValueError) as e:
            raise ValueError(f"Invalid encrypted block format: {e}")
