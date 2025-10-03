"""
Пример базового использования рефакторенного криптографического движка.

Запуск:
    python examples/basic_usage.py
"""

import asyncio

from crypto_engine.api.password_manager import PasswordManagerCrypto
from crypto_engine.models.enums import ExportFormat
from crypto_engine.exceptions import AuthenticationError, CryptoError


async def main():
    """Демонстрация базового функционала криптографического движка."""
    
    print("=" * 60)
    print("Тестирование криптографического движка")
    print("=" * 60)
    
    # Инициализация
    print("\n1. Инициализация движка...")
    crypto = PasswordManagerCrypto()
    print("✓ Движок инициализирован")
    
    # Регистрация пользователя
    print("\n2. Регистрация нового пользователя...")
    master_password = "SuperSecure123!@#"
    account_info = await crypto.register_user(master_password, user_id="test_user")
    print(f"✓ Пользователь зарегистрирован: {account_info.user_id}")
    print(f"  Создан: {account_info.created_at}")
    
    # Вход в систему
    print("\n3. Вход в систему...")
    login_success = await crypto.login(master_password, account_info)
    if login_success:
        print("✓ Вход выполнен успешно")
    else:
        print("✗ Ошибка входа")
        return
    
    # Сохранение записей
    print("\n4. Сохранение записей паролей...")
    
    entries = [
        {
            "title": "GitHub",
            "username": "muran@example.com",
            "password": "github_secret_123",
            "url": "https://github.com",
            "notes": "Рабочий аккаунт",
            "type": "website"
        },
        {
            "title": "Gmail",
            "username": "muran@gmail.com",
            "password": "gmail_pass_456",
            "url": "https://gmail.com",
            "notes": "Личная почта",
            "type": "email"
        },
        {
            "title": "AWS",
            "username": "admin",
            "password": "aws_secret_789",
            "url": "https://aws.amazon.com",
            "notes": "Облачный сервер",
            "type": "cloud"
        }
    ]
    
    encrypted_blocks = []
    for entry in entries:
        block = await crypto.store_entry(entry)
        encrypted_blocks.append(block)
        print(f"✓ Сохранено: {entry['title']} (ID: {block.id[:16]}...)")
    
    # Получение статистики
    print("\n5. Статистика записей...")
    summary = crypto.get_entries_summary()
    print(f"✓ Всего записей: {summary['total_entries']}")
    print(f"  Типы записей: {summary['entry_types']}")
    print(f"  Аутентифицирован: {summary['is_authenticated']}")
    
    # Чтение записи
    print("\n6. Чтение записи...")
    first_block = encrypted_blocks[0]
    decrypted_entry = await crypto.get_entry(first_block)
    print(f"✓ Расшифрована запись: {decrypted_entry['title']}")
    print(f"  Username: {decrypted_entry['username']}")
    print(f"  Password: {'*' * len(decrypted_entry['password'])}")
    print(f"  URL: {decrypted_entry['url']}")
    
    # Обновление записи
    print("\n7. Обновление записи...")
    updated_data = decrypted_entry.copy()
    updated_data['password'] = 'new_github_password_999'
    updated_data['notes'] = 'Обновлен пароль'
    updated_block = await crypto.update_entry(first_block, updated_data)
    print(f"✓ Запись обновлена: {updated_block.id[:16]}...")
    
    # Экспорт в JSON
    print("\n8. Экспорт данных в JSON...")
    json_export = await crypto.export_data(ExportFormat.JSON)
    print(f"✓ Экспортировано в JSON: {len(json_export)} байт")
    print(f"  Первые 100 символов: {json_export[:100].decode('utf-8')}...")
    
    # Экспорт в CSV
    print("\n9. Экспорт данных в CSV...")
    csv_export = await crypto.export_data(ExportFormat.CSV)
    print(f"✓ Экспортировано в CSV: {len(csv_export)} байт")
    lines = csv_export.decode('utf-8').split('\n')
    print(f"  Заголовки: {lines[0]}")
    
    # Создание зашифрованной резервной копии
    print("\n10. Создание зашифрованной резервной копии...")
    backup_password = "BackupPass123!"
    backup_data = await crypto.export_data(
        ExportFormat.ENCRYPTED_BACKUP,
        export_password=backup_password
    )
    print(f"✓ Резервная копия создана: {len(backup_data)} байт")
    
    # Тест удаления записи
    print("\n11. Удаление записи...")
    second_block_id = encrypted_blocks[1].id
    delete_success = await crypto.delete_entry(second_block_id)
    if delete_success:
        print(f"✓ Запись удалена: {second_block_id[:16]}...")
    
    summary = crypto.get_entries_summary()
    print(f"  Осталось записей: {summary['total_entries']}")
    
    # Массовое удаление
    print("\n12. Массовое удаление...")
    ids_to_delete = [block.id for block in encrypted_blocks[2:]]
    deleted_count = await crypto.bulk_delete_entries(ids_to_delete)
    print(f"✓ Удалено записей: {deleted_count}")
    
    # Импорт из резервной копии
    print("\n13. Импорт из резервной копии...")
    imported_count = await crypto.import_backup(backup_data, backup_password)
    print(f"✓ Импортировано записей: {imported_count}")
    
    summary = crypto.get_entries_summary()
    print(f"  Всего записей после импорта: {summary['total_entries']}")
    
    # Смена мастер-пароля
    print("\n14. Смена мастер-пароля...")
    new_master_password = "NewSuperSecure456!@#"
    new_salt, new_verifier, re_encrypted = await crypto.change_master_password(
        master_password,
        new_master_password
    )
    print(f"✓ Мастер-пароль изменен")
    print(f"  Перешифровано блоков: {len(re_encrypted)}")
    
    # Обновляем account_info с новыми данными
    import base64
    account_info.master_key_salt = base64.b64encode(new_salt).decode()
    account_info.master_key_verifier_hash = base64.b64encode(new_verifier).decode()
    
    # Выход
    print("\n15. Выход из системы...")
    await crypto.logout()
    print("✓ Сессия завершена")
    
    # Повторный вход с новым паролем
    print("\n16. Повторный вход с новым паролем...")
    login_success = await crypto.login(new_master_password, account_info)
    if login_success:
        print("✓ Вход с новым паролем успешен")
    
    # Проверка данных после смены пароля
    summary = crypto.get_entries_summary()
    print(f"  Записей доступно: {summary['total_entries']}")
    
    # Финальная очистка
    print("\n17. Финальная очистка...")
    await crypto.logout()
    print("✓ Все данные очищены из памяти")
    
    print("\n" + "=" * 60)
    print("Тестирование завершено успешно!")
    print("=" * 60)


async def test_error_handling():
    """Тестирование обработки ошибок."""
    
    print("\n" + "=" * 60)
    print("Тестирование обработки ошибок")
    print("=" * 60)
    
    crypto = PasswordManagerCrypto()
    
    # Регистрация
    master_password = "TestPass123"
    account_info = await crypto.register_user(master_password)
    await crypto.login(master_password, account_info)
    
    # Тест: попытка входа с неверным паролем
    print("\n1. Тест неверного пароля...")
    crypto2 = PasswordManagerCrypto()
    try:
        success = await crypto2.login("WrongPassword", account_info)
        if not success:
            print("✓ Неверный пароль корректно отклонен")
    except AuthenticationError as e:
        print(f"✓ Поймано исключение: {e}")
    
    # Тест: блокировка аккаунта после множественных попыток
    print("\n2. Тест блокировки аккаунта...")
    for i in range(5):
        try:
            await crypto2.login("WrongPassword", account_info)
        except AuthenticationError:
            pass
    
    if account_info.account_locked:
        print("✓ Аккаунт заблокирован после 5 неудачных попыток")
        print(f"  Неудачных попыток: {account_info.failed_login_attempts}")
    
    # Тест: попытка операции без аутентификации
    print("\n3. Тест операции без аутентификации...")
    crypto3 = PasswordManagerCrypto()
    try:
        await crypto3.store_entry({"title": "test"})
        print("✗ Операция прошла без аутентификации (не должно быть)")
    except AuthenticationError:
        print("✓ Операция без аутентификации корректно заблокирована")
    
    await crypto.logout()
    
    print("\n" + "=" * 60)
    print("Тестирование ошибок завершено")
    print("=" * 60)


if __name__ == "__main__":
    # Запуск основного теста
    asyncio.run(main())
    
    # Запуск теста обработки ошибок
    asyncio.run(test_error_handling())