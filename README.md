# 🛡️ Crypto Core Engine

[![Python Version][python-shield]][python-url]
[![MIT License][license-shield]][license-url]
[![Build Status][build-shield]][build-url]
[![Code Style: Black][black-shield]][black-url]

**A robust, asynchronous, zero-knowledge cryptographic engine for building secure applications like password manager bots.**

This repository contains a high-performance core engine that provides all the security features necessary to store user data in a format that is inaccessible even to the server owner. It is designed from the ground up to be secure, flexible, and easy to integrate into modern asynchronous Python applications.

## 🚀 Key Features

- **Zero-Knowledge Architecture:** All encryption and decryption logic is designed to run on the client-side (e.g., within a bot's logic). Master passwords and derived keys are never transmitted or stored server-side, ensuring only the end-user can access their data.
- **State-of-the-Art Encryption:** Utilizes `AES-256-GCM` for authenticated encryption, ensuring both the confidentiality and integrity of every piece of data.
- **Secure Key Derivation:** Employs modern, memory-hard key derivation functions, with **Scrypt** as the default and **PBKDF2-HMAC-SHA256** as a configurable alternative, to securely generate a master key from a user's password.
- **Per-Entry Encryption Keys:** Each stored entry is encrypted with a unique key derived from the user's master key using `HKDF-SHA256`. This cryptographic isolation prevents key reuse and thwarts correlation attacks.
- **Robust Security Protections:**
  - **Timing Attack Resistance:** Implements a minimum authentication delay and uses constant-time comparison to prevent information leakage through response time analysis.
  - **Account Lockout:** A built-in mechanism mitigates brute-force attacks by locking an account after multiple consecutive failed login attempts.
- **Secure Memory Handling:** A custom `SecureBytes` class automatically and explicitly wipes sensitive data (keys, passwords) from RAM after use, protecting against memory dumps and swap file leakage.
- **Dual-Layer API:**
  - **High-Level API (`PasswordManagerCrypto`):** A simplified facade for rapid integration into application logic. It manages session state and a local entry cache.
  - **Low-Level API (`AsyncCryptoEngine`):** Direct access to the core cryptographic operations for flexible, fine-grained control.
- **Fully Asynchronous:** Built entirely on `asyncio` for high performance and seamless integration into modern async frameworks (e.g., `aiogram`, `FastAPI`).
- **Comprehensive Data Models:** Clear data classes (`AccountInfo`, `EncryptedBlock`) for managing user metadata and encrypted payloads, with built-in integrity verification.
- **Flexible Data Export/Import:** Supports data export to `JSON`, `CSV`, and the creation of fully encrypted backups protected by a separate password.

## 🏛️ Architectural Overview

The engine is built on the principle of separation of concerns, creating distinct layers that handle specific responsibilities. This makes it modular, testable, and easily extensible.

```mermaid
graph TD
    subgraph "Application Layer (e.g., Telegram Bot)"
        A[User Input: Password, Data] --> B{Bot Logic};
    end

    subgraph "Crypto Engine (This Repository)"
        B --> C[🔐 High-Level API (PasswordManagerCrypto)];
        C --> D[⚙️ Core Engine (AsyncCryptoEngine)];
        D -- Manages State & Orchestrates --> E(🔧 Crypto Operations);
        E -- Uses --> F[🛡️ Cryptography Primitives (AES, Scrypt)];
    end

    subgraph "Data Models"
        G[AccountInfo]
        H[EncryptedBlock]
    end

    subgraph "Storage (e.g., Database)"
        I[Persisted AccountInfo]
        J[Persisted EncryptedBlocks]
    end

    B -- Stores/Retrieves --> I;
    B -- Stores/Retrieves --> J;
    C -- Uses --> G;
    C -- Manages --> H;

    style A fill:#fff,stroke:#333,stroke-width:2px
```

### The Zero-Knowledge Principle

The core design tenet is that the server *never* has access to the user's master password or the derived master key.
1.  The user provides their master password to the bot/client.
2.  The bot's logic, using this engine, retrieves the user's `AccountInfo` (containing the salt and verifier).
3.  All key derivation and authentication happen *within the bot's runtime memory*.
4.  If successful, the master key exists *only* in the `AsyncCryptoEngine`'s session, wrapped in a `SecureBytes` object.
5.  All subsequent encryption/decryption operations for that session use this in-memory key.
6.  Upon logout, the `clear_session` method is called, which securely wipes the key from memory.

## 🔬 Core Concepts Deep Dive

#### `PasswordManagerCrypto` (The High-Level Facade)
This is the primary entry point for most applications. It acts as a stateful wrapper around the `AsyncCryptoEngine`. Its responsibilities include:
-   Simplifying the user registration and login process.
-   Maintaining an in-memory cache (`_entries`) of `EncryptedBlock` objects for an active session.
-   Providing simple methods like `store_entry`, `get_entry`, and `update_entry` that operate on the local cache and the underlying engine.

#### `AsyncCryptoEngine` (The Core)
This is the stateless heart of the library. It holds the master key for an authenticated session and orchestrates all cryptographic tasks.
-   Holds the master key in a `SecureBytes` object.
-   Performs authentication by coordinating with the `authentication` operation.
-   Delegates encryption/decryption tasks to the `encryption` operations.
-   Handles complex logic like changing the master password, which involves decrypting all data with the old key and re-encrypting with a new one.

#### `AccountInfo` (The Account Record)
A dataclass representing the non-sensitive metadata for a user account. This object is **safe to store in a database in plain text**.
-   `user_id`, `created_at`: Basic user metadata.
-   `master_key_salt`: The unique salt used to derive the user's master key. This is public.
-   `master_key_verifier_hash`: A SHA-256 hash of the *derived master key*. It is used to verify the password is correct without ever storing the password or the key itself.
-   `account_locked`, `failed_login_attempts`: Fields to manage the account lockout security feature.

#### `EncryptedBlock` (The Secure Payload)
A dataclass representing a single, securely stored piece of data. This is the object that should be persisted in your database for each user entry.
-   `id`: A unique identifier for the block, used as "additional authenticated data" (AAD) in the AES-GCM encryption.
-   `encrypted_data`: The raw ciphertext.
-   `salt`: A unique, per-block salt used to derive the block's unique encryption key from the master key.
-   `nonce`, `tag`: Cryptographic values required for AES-GCM decryption and authentication.
-   `checksum`: An additional SHA-256 hash of all cryptographic components, providing a fast, non-cryptographic integrity check before attempting decryption.

#### `SecureBytes` (The Memory Guardian)
A custom `bytes`-like class that wraps sensitive data in a `bytearray`. It uses `weakref.finalize` to register a cleanup function that overwrites the memory with random data and then zeroes it out when the object is garbage collected. This significantly reduces the risk of sensitive keys being exposed in memory dumps or system swap files.

## 🔐 Security Design Deep Dive

### Authentication Flow
1.  **Input**: User's password and `AccountInfo` object.
2.  **Key Derivation**: The engine uses the provided password and the `master_key_salt` from `AccountInfo` to re-derive the master key using Scrypt or PBKDF2. This is a computationally intensive process, which is the first line of defense against brute-force attacks.
3.  **Verification**: The newly derived key is hashed with SHA-256.
4.  **Comparison**: This new hash is compared to the `master_key_verifier_hash` from `AccountInfo` using `constant_time.bytes_eq` to prevent timing attacks.
5.  **Timing Protection**: Regardless of success or failure, the entire operation is padded with `asyncio.sleep` to ensure it takes at least `min_auth_delay_ms`, further mitigating timing attacks.

### Encryption Flow
1.  **Input**: A dictionary of data and the authenticated session's master key.
2.  **Per-Block Salt**: A new, cryptographically secure 32-byte salt (`block_salt`) is generated for this specific block.
3.  **Per-Block Key Derivation**: A unique encryption key for this block is derived using `HKDF-SHA256`. The inputs are:
    -   The user's `master_key`.
    -   The new `block_salt`.
    -   The block's `id` as "info" context.
4.  **Encryption**: The data (serialized to JSON) is encrypted using `AES-256-GCM` with the unique block key. The block `id` is used as Additional Authenticated Data (AAD), cryptographically binding the ciphertext to its identifier.
5.  **Output**: An `EncryptedBlock` object is created, containing the ciphertext, salt, nonce, GCM tag, and other metadata.

## 🔧 Installation and Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Muran-prog/crypto-engine
    cd crypto-core-bot
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv venv
    # Windows
    venv\Scripts\activate
    # macOS / Linux
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    -   For production/general use:
        ```bash
        pip install -r requirements.txt
        ```
    -   For development (including testing and linting tools):
        ```bash
        pip install -r requirements-dev.txt
        ```

## ⚡ Usage Example

This example demonstrates the basic workflow using the high-level `PasswordManagerCrypto` API.

```python
import asyncio
from crypto_engine.api.password_manager import PasswordManagerCrypto

async def main():
    # Initialize the high-level API
    crypto = PasswordManagerCrypto()

    # 1. Register a new user
    master_password = "SuperSecurePassword123!@#"
    account_info = await crypto.register_user(master_password, user_id="telegram_user_123")
    print(f"User {account_info.user_id} registered. Store this AccountInfo object.")

    # 2. Log in (authenticate)
    await crypto.login(master_password, account_info)
    print("Login successful. Session is active.")

    # 3. Store a secret entry
    entry_data = {
        "title": "GitHub",
        "username": "muran@example.com",
        "password": "github_secret_password_!@#"
    }
    encrypted_block = await crypto.store_entry(entry_data)
    print(f"Entry '{entry_data['title']}' stored. Store this EncryptedBlock object.")

    # 4. Retrieve and decrypt the entry
    decrypted_entry = await crypto.get_entry(encrypted_block)
    print(f"Decrypted password: {decrypted_entry['password']}")

    # 5. Log out and clear memory
    await crypto.logout()
    print("Session terminated. All keys wiped from memory.")

if __name__ == "__main__":
    asyncio.run(main())
```

## 🧪 Testing

The engine includes a comprehensive test suite with **80+ tests** organized into modular components for maintainability and clarity.

### Test Structure

Tests are organized into focused modules:

```
tests/
├── test_config.py              # Configuration validation
├── test_models.py              # Data models (Enums, EncryptedBlock, AccountInfo)
├── test_security.py            # Security features and memory management
├── test_crypto_operations.py  # Key derivation, authentication, encryption
├── test_engine.py              # AsyncCryptoEngine core functionality
├── test_api.py                 # High-level PasswordManagerCrypto API
├── test_data_management.py    # Export/import and account operations
├── test_error_handling.py     # Exception handling
├── test_edge_cases.py         # Boundary conditions
└── test_performance.py        # Performance benchmarks
```

For detailed testing documentation, see [tests/README.md](tests/README.md).

### Running Tests

**Run all tests:**
```bash
python -m crypto_engine.tests.run_tests --verbose
```

**Common options:**
```bash
# Skip performance tests for faster execution
python -m crypto_engine.tests.run_tests --fast

# Run specific test module
python -m crypto_engine.tests.run_tests --specific TestEncryption

# Stop on first failure
python -m crypto_engine.tests.run_tests --failfast
```

**Using pytest or unittest:**
```bash
# Run all tests with pytest
pytest crypto_engine/tests/ -v

# Run specific module
python -m unittest crypto_engine.tests.test_api -v
```

### Test Coverage

The test suite validates:
- **Core Cryptography**: Key derivation (PBKDF2, Scrypt), AES-256-GCM encryption
- **Security Features**: Timing attack protection, account lockout, secure memory wiping
- **Data Integrity**: Checksums, GCM authentication tags, block verification
- **API Operations**: Registration, login/logout, entry management, password changes
- **Export/Import**: JSON, CSV, encrypted backups
- **Error Handling**: Authentication failures, invalid inputs, corrupted data
- **Edge Cases**: Empty data, large payloads, unicode, special characters
- **Performance**: Batch operations (100+ entries), password changes

## 🤝 Contributing

Contributions are welcome! If you have ideas for improvements, suggestions, or have found a bug, please create an [Issue](https://github.com/Muran-prog/crypto-engine/issues) or submit a [Pull Request](https://github.com/Muran-prog/crypto-engine/pulls).

### Development Setup

1. Fork and clone the repository
2. Install development dependencies: `pip install -r requirements-dev.txt`
3. Make your changes
4. Run the test suite: `python -m crypto_engine.tests.run_tests`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---
*Crafted with care by [Muran-prog](https://github.com/Muran-prog)*

<!-- Badges -->
[python-shield]: https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python
[python-url]: https://www.python.org/
[license-shield]: https://img.shields.io/github/license/Muran-prog/crypto-engine?style=for-the-badge
[license-url]: https://github.com/Muran-prog/crypto-engine/blob/main/LICENSE
[build-shield]: https://img.shields.io/github/actions/workflow/status/Muran-prog/crypto-engine/python-app.yml?branch=main&style=for-the-badge
[build-url]: https://github.com/Muran-prog/crypto-engine/actions
[black-shield]: https://img.shields.io/badge/code%20style-black-000000.svg?style=for-the-badge
[black-url]: https://github.com/psf/black