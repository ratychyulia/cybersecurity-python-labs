"""Головна точка входу для Лабораторної роботи №2 (команди demo та analyze)."""

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Імпорт класів моделі та аналізатора
from labs.lab02.task1 import Admin, AuditLog, User, UserAccount
from labs.lab02.task2 import analyze_activity


def run_demo() -> None:
    """Демонстрація функціоналу Завдання 1 (ООП-модель безпеки)."""
    print("=" * 60)
    print("ДЕМОНСТРАЦІЯ ЗАВДАННЯ 1: ООП МОДЕЛЬ КОРИСТУВАЧА ТА СЕСІЙ")
    print("=" * 60)

    # 1. Валідація email та пароль у User
    print("\n[1] Створення користувача та валідація email:")
    user = User("sec_analyst", "analyst_01@corp.ua")
    user.set_password("CorrectHorseBatteryStaple2026!")
    print(f"  Створено користувача: {user}")
    try:
        print("  Спроба встановити некоректний email 'bad-email@':")
        user.email = "bad-email@"
    except ValueError as e:
        print(f"  [Очікувана помилка]: {e}")
    user.email = "mark_analyst@domain.com"
    print(f"  Оновлений email: {user.email}")

    # 2. Наслідування та права в Admin
    print("\n[2] Успадкування та керування правами (Admin):")
    admin = Admin("superadmin", "admin_root@corp.ua")
    admin.grant_permission("READ_LOGS")
    admin.grant_permission("MANAGE_USERS")
    print(f"  Створено адміністратора: {admin}")
    print(f"  Має право 'READ_LOGS'?: {admin.has_permission('READ_LOGS')}")
    print(f"  Має право 'DELETE_DB'?: {admin.has_permission('DELETE_DB')}")
    admin.revoke_permission("MANAGE_USERS")
    print(f"  Після відкликання MANAGE_USERS: {admin}")

    # 3. Композиція, вхід та аудит у UserAccount
    print("\n[3] Композиція (UserAccount) та перевірка входу:")
    audit = AuditLog()
    account = UserAccount(user, audit_log=audit)
    print("  Спроба входу з неправильним паролем:")
    ok = account.login("sec_analyst", "WrongPassword!", "192.168.1.100")
    print(f"  Результат входу: {ok} | Авторизовано: {account.is_authenticated()}")
    print("  Спроба входу з правильним паролем:")
    ok = account.login("sec_analyst", "CorrectHorseBatteryStaple2026!", "192.168.1.100")
    print(f"  Результат входу: {ok} | Авторизовано: {account.is_authenticated()}")

    # 4. Перевірка таймауту сесії (900 с)
    print("\n[4] Перевірка таймауту сесії (симуляція минулого часу):")
    if account.session:
        account.session.last_activity = datetime.now(timezone.utc) - timedelta(
            seconds=1000
        )
    print(f"  Сесія після 1000 с бездіяльності активна?: {account.is_authenticated()}")

    # 5. Повторний вхід та вихід (logout)
    print("\n[5] Повторний вхід та вихід із системи (logout):")
    account.login("sec_analyst", "CorrectHorseBatteryStaple2026!", "10.0.0.5")
    print(f"  Сесія активна: {account.is_authenticated()}")
    account.logout()
    print(f"  Після logout сесія активна?: {account.is_authenticated()}")

    # 6. Dunder-методи __getitem__ та __setitem__
    print("\n[6] Робота зі спеціальними методами __getitem__ та __setitem__:")
    print(f"  account['user']: {account['user']}")
    try:
        print("  Спроба отримати заблокований ключ '__password_hash':")
        _ = account["__password_hash"]
    except KeyError as e:
        print(f"  [Очікувана помилка]: {e}")
    try:
        print("  Спроба призначити некоректний тип у account['user'] = 123:")
        account["user"] = 123
    except TypeError as e:
        print(f"  [Очікувана помилка]: {e}")

    # 7. Звіт AuditLog
    print("\n[7] Фінальний звіт AuditLog:")
    for r in audit.show_all():
        ts = r.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"  [{ts}] {r.username:<15} -> {r.action}")
    print("=" * 60)


def main() -> None:
    """Парсинг аргументів CLI та виклик підкоманд demo та analyze."""
    parser = argparse.ArgumentParser(description="CLI-утиліта кібербезпеки (ЛР №2)")
    sub = parser.add_subparsers(dest="command", help="Доступні команди")

    # Підкоманда demo
    sub.add_parser("demo", help="Демонстрація ООП (Завдання 1)")

    # Підкоманда analyze (Варіант 7)
    an = sub.add_parser("analyze", help="Аналіз журналів активності (Варіант 7)")
    an.add_argument(
        "--activity-log",
        type=Path,
        default=Path("labs/lab02/data/activity.csv"),
        help="Вхідний CSV",
    )
    an.add_argument(
        "--after-hours", action="store_true", help="Фільтр позаробочого часу"
    )
    an.add_argument(
        "--out-report",
        type=Path,
        default=Path("labs/lab02/data/off_hours_audit.json"),
        help="Вихідний JSON",
    )
    an.add_argument(
        "--log-file",
        type=Path,
        default=Path("labs/lab02/data/activity_audit.log"),
        help="Файл логу",
    )

    args = parser.parse_args()
    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        analyze_activity(
            args.activity_log, args.out_report, args.after_hours, args.log_file
        )
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
