#!/usr/bin/env python3
"""
A convenient script for running the cryptographic engine tests.

Usage:
    python -m crypto_engine.tests.run_tests          # Run all tests
    python -m crypto_engine.tests.run_tests --fast   # Skip performance tests
    python -m crypto_engine.tests.run_tests --verbose # Verbose output
    python -m crypto_engine.tests.run_tests --specific TestClassName  # Run a specific test class

Author: Muran-prog
License: MIT
Version: 2.0
"""

import sys
import argparse
import unittest

# Import all test cases from modular test files
from .test_config import TestCryptoConfig
from .test_models import TestEnums, TestEncryptedBlock, TestAccountInfo
from .test_security import TestSecureMemory, TestSecurityFeatures
from .test_crypto_operations import TestKeyDerivation, TestAuthentication, TestEncryption
from .test_engine import TestAsyncCryptoEngine
from .test_api import TestPasswordManagerCrypto
from .test_data_management import TestDataExport, TestAccountManagement
from .test_error_handling import TestErrorHandling
from .test_edge_cases import TestEdgeCases
from .test_performance import TestPerformance


def main():
    """Main function to run the tests."""
    parser = argparse.ArgumentParser(
        description='Run tests for the cryptographic engine'
    )
    parser.add_argument(
        '--fast',
        action='store_true',
        help='Skip slow performance tests'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--specific',
        type=str,
        help='Run only the specified test class'
    )
    parser.add_argument(
        '--failfast', '-f',
        action='store_true',
        help='Stop on the first error or failure'
    )
    
    args = parser.parse_args()
    
    # Create the test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # All test classes
    test_classes = [
        TestCryptoConfig,
        TestEnums,
        TestEncryptedBlock,
        TestAccountInfo,
        TestSecureMemory,
        TestKeyDerivation,
        TestAuthentication,
        TestEncryption,
        TestAsyncCryptoEngine,
        TestPasswordManagerCrypto,
        TestDataExport,
        TestAccountManagement,
        TestErrorHandling,
        TestSecurityFeatures,
        TestEdgeCases,
    ]
    
    # Add performance tests unless --fast is specified
    if not args.fast:
        test_classes.append(TestPerformance)
    
    # If a specific class is requested
    if args.specific:
        # Find the class by name
        test_class = None
        for tc in test_classes:
            if tc.__name__ == args.specific:
                test_class = tc
                break
        
        if test_class:
            print(f"\nRunning specific tests: {args.specific}")
            tests = loader.loadTestsFromTestCase(test_class)
            suite.addTests(tests)
        else:
            print(f"Error: Test class '{args.specific}' not found")
            print("\nAvailable classes:")
            for tc in test_classes:
                print(f"  - {tc.__name__}")
            return 1
    else:
        # Load all tests
        print("\nRunning all crypto engine tests...\n")
        for test_class in test_classes:
            tests = loader.loadTestsFromTestCase(test_class)
            suite.addTests(tests)
    
    # Configure the runner
    verbosity = 2 if args.verbose else 1
    runner = unittest.TextTestRunner(
        verbosity=verbosity,
        failfast=args.failfast
    )
    
    # Run the tests
    result = runner.run(suite)
    
    # Print the results
    print("\n" + "=" * 70)
    print("TEST RESULTS")
    print("=" * 70)
    print(f"Total tests run: {result.testsRun}")
    passed_count = result.testsRun - len(result.failures) - len(result.errors)
    print(f"Passed:          {passed_count}")
    print(f"Failed:          {len(result.failures)}")
    print(f"Errors:          {len(result.errors)}")
    print(f"Skipped:         {len(result.skipped)}")
    print("=" * 70)
    
    if result.wasSuccessful():
        print("\nAll tests passed successfully!\n")
        return 0
    else:
        print("\nSome tests failed or encountered errors.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())