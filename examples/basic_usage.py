"""
Basic usage example for the refactored cryptographic engine.

To run:
    python examples/basic_usage.py
"""

import asyncio

from crypto_engine.api.password_manager import PasswordManagerCrypto
from crypto_engine.models.enums import ExportFormat
from crypto_engine.exceptions import AuthenticationError


async def main():
    """Demonstrates the basic functionality of the crypto engine."""

    print("=" * 60)
    print("Cryptographic Engine Test")
    print("=" * 60)

    # Initialization
    print("\n1. Initializing the engine...")
    crypto = PasswordManagerCrypto()
    print("✓ Engine initialized")

    # Register a new user
    print("\n2. Registering a new user...")
    master_password = "SuperSecure123!@#"
    account_info = await crypto.register_user(master_password, user_id="test_user")
    print(f"✓ User registered: {account_info.user_id}")
    print(f"  Created at: {account_info.created_at}")

    # Log in
    print("\n3. Logging in...")
    login_success = await crypto.login(master_password, account_info)
    if login_success:
        print("✓ Login successful")
    else:
        print("✗ Login failed")
        return

    # Store password entries
    print("\n4. Storing password entries...")

    entries = [
        {
            "title": "GitHub",
            "username": "muran@example.com",
            "password": "github_secret_123",
            "url": "https://github.com",
            "notes": "Work account",
            "type": "website",
        },
        {
            "title": "Gmail",
            "username": "muran@gmail.com",
            "password": "gmail_pass_456",
            "url": "https://gmail.com",
            "notes": "Personal email",
            "type": "email",
        },
        {
            "title": "AWS",
            "username": "admin",
            "password": "aws_secret_789",
            "url": "https://aws.amazon.com",
            "notes": "Cloud server",
            "type": "cloud",
        },
    ]

    encrypted_blocks = []
    for entry in entries:
        block = await crypto.store_entry(entry)
        encrypted_blocks.append(block)
        print(f"✓ Stored: {entry['title']} (ID: {block.id[:16]}...)")

    # Get entry statistics
    print("\n5. Getting entry statistics...")
    summary = crypto.get_entries_summary()
    print(f"✓ Total entries: {summary['total_entries']}")
    print(f"  Entry types: {summary['entry_types']}")
    print(f"  Authenticated: {summary['is_authenticated']}")

    # Read an entry
    print("\n6. Reading an entry...")
    first_block = encrypted_blocks[0]
    decrypted_entry = await crypto.get_entry(first_block)
    print(f"✓ Decrypted entry: {decrypted_entry['title']}")
    print(f"  Username: {decrypted_entry['username']}")
    print(f"  Password: {'*' * len(decrypted_entry['password'])}")
    print(f"  URL: {decrypted_entry['url']}")

    # Update an entry
    print("\n7. Updating an entry...")
    updated_data = decrypted_entry.copy()
    updated_data["password"] = "new_github_password_999"
    updated_data["notes"] = "Password updated"
    updated_block = await crypto.update_entry(first_block, updated_data)
    print(f"✓ Entry updated: {updated_block.id[:16]}...")

    # Export data to JSON
    print("\n8. Exporting data to JSON...")
    json_export = await crypto.export_data(ExportFormat.JSON)
    print(f"✓ Exported to JSON: {len(json_export)} bytes")
    print(f"  First 100 characters: {json_export[:100].decode('utf-8')}...")

    # Export data to CSV
    print("\n9. Exporting data to CSV...")
    csv_export = await crypto.export_data(ExportFormat.CSV)
    print(f"✓ Exported to CSV: {len(csv_export)} bytes")
    lines = csv_export.decode("utf-8").split("\n")
    print(f"  Headers: {lines[0]}")

    # Create an encrypted backup
    print("\n10. Creating an encrypted backup...")
    backup_password = "BackupPass123!"
    backup_data = await crypto.export_data(
        ExportFormat.ENCRYPTED_BACKUP, export_password=backup_password
    )
    print(f"✓ Backup created: {len(backup_data)} bytes")

    # Test deleting an entry
    print("\n11. Deleting an entry...")
    second_block_id = encrypted_blocks[1].id
    delete_success = await crypto.delete_entry(second_block_id)
    if delete_success:
        print(f"✓ Entry deleted: {second_block_id[:16]}...")

    summary = crypto.get_entries_summary()
    print(f"  Entries remaining: {summary['total_entries']}")

    # Bulk delete
    print("\n12. Bulk deleting entries...")
    ids_to_delete = [block.id for block in encrypted_blocks[2:]]
    deleted_count = await crypto.bulk_delete_entries(ids_to_delete)
    print(f"✓ Entries deleted: {deleted_count}")

    # Import from backup
    print("\n13. Importing from backup...")
    imported_count = await crypto.import_backup(backup_data, backup_password)
    print(f"✓ Imported entries: {imported_count}")

    summary = crypto.get_entries_summary()
    print(f"  Total entries after import: {summary['total_entries']}")

    # Change master password
    print("\n14. Changing master password...")
    new_master_password = "NewSuperSecure456!@#"
    new_salt, new_verifier, re_encrypted = await crypto.change_master_password(
        master_password, new_master_password
    )
    print("✓ Master password changed")
    print(f"  Blocks re-encrypted: {len(re_encrypted)}")

    # Update account_info with the new credentials
    import base64

    account_info.master_key_salt = base64.b64encode(new_salt).decode()
    account_info.master_key_verifier_hash = base64.b64encode(new_verifier).decode()

    # Log out
    print("\n15. Logging out...")
    await crypto.logout()
    print("✓ Session terminated")

    # Re-log in with the new password
    print("\n16. Re-logging in with new password...")
    login_success = await crypto.login(new_master_password, account_info)
    if login_success:
        print("✓ Login with new password successful")

    # Check data after password change
    summary = crypto.get_entries_summary()
    print(f"  Entries available: {summary['total_entries']}")

    # Final cleanup
    print("\n17. Final cleanup...")
    await crypto.logout()
    print("✓ All data wiped from memory")

    print("\n" + "=" * 60)
    print("Test completed successfully!")
    print("=" * 60)


async def test_error_handling():
    """Tests error handling scenarios."""

    print("\n" + "=" * 60)
    print("Error Handling Test")
    print("=" * 60)

    crypto = PasswordManagerCrypto()

    # Registration
    master_password = "TestPass123"
    account_info = await crypto.register_user(master_password)
    await crypto.login(master_password, account_info)

    # Test: attempt to log in with the wrong password
    print("\n1. Testing wrong password...")
    crypto2 = PasswordManagerCrypto()
    try:
        success = await crypto2.login("WrongPassword", account_info)
        if not success:
            print("✓ Wrong password correctly rejected")
    except AuthenticationError as e:
        print(f"✓ Caught exception: {e}")

    # Test: account lockout after multiple attempts
    print("\n2. Testing account lockout...")
    for i in range(5):
        try:
            await crypto2.login("WrongPassword", account_info)
        except AuthenticationError:
            pass

    if account_info.account_locked:
        print("✓ Account locked after 5 failed attempts")
        print(f"  Failed attempts: {account_info.failed_login_attempts}")

    # Test: operation without authentication
    print("\n3. Testing operation without authentication...")
    crypto3 = PasswordManagerCrypto()
    try:
        await crypto3.store_entry({"title": "test"})
        print("✗ Operation succeeded without authentication (should not happen)")
    except AuthenticationError:
        print("✓ Operation without authentication correctly blocked")

    await crypto.logout()

    print("\n" + "=" * 60)
    print("Error handling test completed")
    print("=" * 60)


if __name__ == "__main__":
    # Run the main test
    asyncio.run(main())

    # Run the error handling test
    asyncio.run(test_error_handling())
