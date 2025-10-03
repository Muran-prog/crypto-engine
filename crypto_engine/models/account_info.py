"""
Account information data model.

This module defines the AccountInfo dataclass for managing user account
metadata and cryptographic materials.

Author: Muran-prog
License: MIT
Version: 2.0
"""

from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional


@dataclass
class AccountInfo:
    """
    Account information and metadata.

    Contains non-sensitive account information used for
    account management operations, along with cryptographic materials
    for master key verification.
    """

    user_id: str
    created_at: str

    # Cryptographic materials for master key verification
    master_key_salt: str  # Base64 encoded salt for master key derivation
    master_key_verifier_hash: str  # Base64 encoded SHA-256 hash of the master key

    last_login: Optional[str] = None
    last_password_change: Optional[str] = None
    entry_count: int = 0
    failed_login_attempts: int = 0
    account_locked: bool = False
    backup_count: int = 0
    export_count: int = 0
    version: str = "2.0"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccountInfo":
        """Create instance from dictionary."""
        return cls(**data)
