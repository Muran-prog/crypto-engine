# Test Suite Documentation

Comprehensive test suite for the Python Cryptographic Engine. This suite contains over 80 unit tests organized into modular components, ensuring all aspects of the cryptographic system work correctly and securely.

## Table of Contents

- [Overview](#overview)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
- [Test Coverage](#test-coverage)
- [Writing New Tests](#writing-new-tests)
- [CI/CD Integration](#cicd-integration)

## Overview

The test suite validates:

- **Cryptographic Operations**: Key derivation (PBKDF2, Scrypt), encryption (AES-256-GCM), authentication
- **Security Features**: Timing attack protection, account lockout, secure memory handling
- **Data Integrity**: Checksums, block verification, data serialization
- **API Functionality**: User registration, login/logout, entry management
- **Export/Import**: JSON, CSV, encrypted backups
- **Error Handling**: Authentication failures, invalid inputs, edge cases
- **Performance**: Batch operations, password changes, large datasets

All tests are asynchronous and use Python's `asyncio` for proper async/await testing.

## Test Structure

The test suite is organized into logical modules for maintainability and clarity:

```
tests/
├── __init__.py                  # Package initialization with exports
├── run_tests.py                 # Test runner script with CLI options
├── test_utils.py                # Shared utilities (async_test decorator)
├── test_config.py               # Configuration tests
├── test_models.py               # Data model tests (Enums, EncryptedBlock, AccountInfo)
├── test_security.py             # Security and memory management tests
├── test_crypto_operations.py   # Cryptographic operation tests
├── test_engine.py               # AsyncCryptoEngine tests
├── test_api.py                  # High-level API tests (PasswordManagerCrypto)
├── test_data_management.py     # Data export/import and account management
├── test_error_handling.py      # Error and exception handling tests
├── test_edge_cases.py          # Edge cases and boundary conditions
└── test_performance.py         # Performance benchmarks
```

### Module Breakdown

| Module | Tests | Description |
|--------|-------|-------------|
| `test_config.py` | 2 | Default and custom configuration validation |
| `test_models.py` | 9 | Data models: enums, encrypted blocks, account info |
| `test_security.py` | 9 | Secure memory, timing attacks, lockout mechanisms |
| `test_crypto_operations.py` | 10 | Key derivation, authentication, encryption/decryption |
| `test_engine.py` | 5 | Core engine functionality and session management |
| `test_api.py` | 8 | User-facing API operations |
| `test_data_management.py` | 7 | Data export, import, and account operations |
| `test_error_handling.py` | 5 | Error conditions and exception handling |
| `test_edge_cases.py` | 6 | Boundary conditions and special cases |
| `test_performance.py` | 2 | Performance benchmarks for batch operations |

## Running Tests

### Quick Start

```bash
# Run all tests
python -m crypto_engine.tests.run_tests

# Run with verbose output
python -m crypto_engine.tests.run_tests --verbose

# Skip performance tests (faster execution)
python -m crypto_engine.tests.run_tests --fast

# Stop on first failure
python -m crypto_engine.tests.run_tests --failfast
```

### Running Specific Test Classes

```bash
# Run only encryption tests
python -m crypto_engine.tests.run_tests --specific TestEncryption

# Run only API tests
python -m crypto_engine.tests.run_tests --specific TestPasswordManagerCrypto

# Run only security tests
python -m crypto_engine.tests.run_tests --specific TestSecurityFeatures
```

### Using Standard Test Runners

```bash
# Using pytest
pytest crypto_engine/tests/ -v
pytest crypto_engine/tests/test_api.py -v

# Using unittest
python -m unittest crypto_engine.tests.test_api -v
python -m unittest crypto_engine.tests.test_api.TestPasswordManagerCrypto.test_login_logout
```

### Running Individual Modules

```bash
# Run a specific test module
python -m unittest crypto_engine.tests.test_crypto_operations

# Run with discovery
python -m unittest discover -s crypto_engine/tests -p "test_*.py" -v
```

## Test Coverage

### Core Functionality

- ✅ **Configuration**: Default values, custom settings
- ✅ **Key Derivation**: PBKDF2 (100K+ iterations), Scrypt (configurable parameters)
- ✅ **Encryption**: AES-256-GCM with per-block keys
- ✅ **Authentication**: Success/failure, timing protection, account lockout
- ✅ **Session Management**: Login, logout, session clearing
- ✅ **Entry Management**: Store, retrieve, update, delete, bulk operations

### Security Features

- ✅ **Secure Memory**: Automatic wiping, context managers
- ✅ **Timing Attack Protection**: Minimum authentication delay (100ms default)
- ✅ **Account Lockout**: 5 failed attempts trigger lockout
- ✅ **Data Integrity**: SHA-256 checksums, GCM authentication tags
- ✅ **Key Isolation**: Unique per-block keys derived from master key

### Data Operations

- ✅ **Serialization**: Block and account info to/from dictionaries
- ✅ **Export Formats**: JSON, CSV, encrypted backups
- ✅ **Import/Restore**: Encrypted backup restoration with password
- ✅ **Password Changes**: Re-encryption of all entries with new master key

### Edge Cases

- ✅ **Empty Data**: Empty dictionaries, null values
- ✅ **Large Data**: 10KB+ entries, 1000+ item lists
- ✅ **Unicode**: Multi-language strings, emojis, special characters
- ✅ **Long Passwords**: 1000+ character passwords
- ✅ **Special Characters**: Full ASCII special character set
- ✅ **Concurrent Access**: Multiple instances, simultaneous logins

### Error Conditions

- ✅ **Invalid Authentication**: Wrong passwords, locked accounts
- ✅ **Missing Authentication**: Operations without login
- ✅ **Corrupted Data**: Invalid blocks, tampered checksums
- ✅ **Invalid Inputs**: Malformed backup data, wrong keys
- ✅ **Authorization Failures**: Account deletion with wrong password

## Writing New Tests

### Test Structure

All tests follow this structure:

```python
import unittest
from crypto_engine.api.password_manager import PasswordManagerCrypto
from .test_utils import async_test

class TestNewFeature(unittest.TestCase):
    """Test description."""
    
    @async_test
    async def test_specific_behavior(self):
        """Test what happens when..."""
        # Arrange
        crypto = PasswordManagerCrypto()
        password = "test_password"
        
        # Act
        account = await crypto.register_user(password)
        await crypto.login(password, account)
        
        # Assert
        self.assertTrue(crypto.engine.is_authenticated())
        
        # Cleanup
        await crypto.logout()
```

### Best Practices

1. **Use Descriptive Names**: Test names should clearly describe what they test
2. **One Assertion Per Concept**: Focus each test on a single behavior
3. **Reduce Test Parameters**: Use minimal iterations for faster tests (e.g., 100K PBKDF2 iterations instead of 600K)
4. **Clean Up Resources**: Always logout/clear sessions after tests
5. **Test Both Success and Failure**: Verify expected behavior and error handling
6. **Use Context Managers**: Leverage `with` statements for secure memory contexts

### Adding Tests to Existing Modules

1. Identify the appropriate module based on functionality
2. Add your test class or method to that module
3. Follow the existing naming conventions
4. Update `__init__.py` if adding a new test class
5. Run the specific module to verify: `python -m unittest crypto_engine.tests.test_<module>`

### Creating New Test Modules

If adding a new area of functionality:

1. Create `test_<feature>.py` in the tests directory
2. Import necessary dependencies and `test_utils`
3. Define test classes with clear docstrings
4. Add imports to `tests/__init__.py`
5. Update `run_tests.py` to include the new module
6. Update this README with the new module information

## CI/CD Integration

### GitHub Actions

Example workflow configuration:

```yaml
name: Run Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        pip install -e .
        pip install pytest pytest-cov
    
    - name: Run tests
      run: |
        python -m crypto_engine.tests.run_tests --fast
    
    - name: Run with coverage
      run: |
        pytest crypto_engine/tests/ --cov=crypto_engine --cov-report=xml
```

### Coverage Reports

Generate coverage reports using `pytest-cov`:

```bash
# Install coverage tools
pip install pytest pytest-cov

# Run with coverage
pytest crypto_engine/tests/ --cov=crypto_engine --cov-report=html

# View report
open htmlcov/index.html
```

### Performance Benchmarks

Performance tests are skipped by default with `--fast` flag for CI/CD:

```bash
# Run performance tests locally
python -m crypto_engine.tests.run_tests --specific TestPerformance

# Expected results:
# - 100 encryptions: < 30 seconds
# - 50-entry password change: < 30 seconds
```

## Troubleshooting

### Common Issues

**Tests fail with `ModuleNotFoundError`**
- Ensure you've installed the package: `pip install -e .`
- Check your Python path includes the project root

**Async tests hang or timeout**
- Verify you're using the `@async_test` decorator
- Check for missing `await` statements in async functions

**Performance tests fail**
- Performance tests have timeout thresholds
- Run on a reasonably fast machine or adjust thresholds
- Use `--fast` to skip performance tests

**Import errors in tests**
- All test modules should import from their own package using relative imports
- Update `__init__.py` if you've added new test classes

## Contributing

When contributing tests:

1. Ensure all existing tests pass
2. Add tests for new features
3. Maintain the modular structure
4. Follow the existing code style
5. Update documentation as needed
6. Run the full test suite before submitting PRs

## License

This test suite is part of the crypto-core-bot project and is licensed under the MIT License.