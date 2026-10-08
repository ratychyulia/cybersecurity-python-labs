"""Модуль реалізації моделі користувача, безпечних сесій та аудиту (Завдання 1)."""

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

PBKDF2_ITERATIONS: int = 100_000
SESSION_TIMEOUT_SEC: int = 900
EMAIL_REGEX: re.Pattern[str] = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
)


class User:
    """Базовий клас облікового запису користувача."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        active: bool = True,
    ) -> None:
        self.username = username
        self.role = role
        self.active = active
        self._email = ""
        self.email = email  # Валідація через @property setter
        # Приватні поля хешу та солі
        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not EMAIL_REGEX.match(value):
            raise ValueError(f"Некоректний формат email: '{value}'")
        self._email = value

    # Допоміжний метод для уникнення дублювання логіки PBKDF2
    def _hash(self, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)

    def set_password(self, password: str) -> None:
        """Генерація солі та збереження хешу пароля."""
        self.__password_salt = os.urandom(16)
        self.__password_hash = self._hash(password, self.__password_salt)

    def check_password(self, password: str) -> bool:
        """Безпечна перевірка пароля через compare_digest."""
        if not (self.__password_hash and self.__password_salt):
            return False
        return hmac.compare_digest(
            self.__password_hash, self._hash(password, self.__password_salt)
        )

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        status = "active" if self.active else "inactive"
        return f"User(username='{self.username}', email='{self.email}', role='{self.role}', status='{status}')"


class Admin(User):
    """Клас адміністратора з правами доступу (наслідування)."""

    def __init__(
        self,
        username: str,
        email: str,
        permissions: list[str] | set[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(username, email, role="admin", active=active)
        self.permissions: set[str] = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        perms = ", ".join(sorted(self.permissions)) if self.permissions else "none"
        status = "active" if self.active else "inactive"
        return f"Admin(username='{self.username}', email='{self.email}', status='{status}', permissions=[{perms}])"


class Session:
    """Клас керування сеансом користувача."""

    def __init__(
        self,
        ip: str,
        login_time: datetime | None = None,
        last_activity: datetime | None = None,
    ) -> None:
        self.ip = ip
        self.login_time = login_time or datetime.now(timezone.utc)
        self.last_activity = last_activity or self.login_time

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec повинен бути позитивним числом")
        return (datetime.now(timezone.utc) - self.last_activity) <= timedelta(
            seconds=timeout_sec
        )


@dataclass(frozen=True)
class AuditRecord:
    """Незмінний запис аудиту системи."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал подій безпеки."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> None:
        self._records.append(AuditRecord(datetime.now(timezone.utc), username, action))

    def show_all(self) -> list[AuditRecord]:
        return list(self._records)


class UserAccount:
    """Клас облікового запису (композиція User, Session, AuditLog)."""

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.user = user
        self.session = session
        self.audit_log = audit_log or AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if (
            self.user.username != username
            or not self.user.active
            or not self.user.check_password(password)
        ):
            self.audit_log.add_log(username, "login_failure")
            return False
        self.session = Session(ip)
        self.session.touch()
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        # Сеанс активний, якщо існує і не прострочений
        return self.session is not None and self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        if self.session:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str) -> Any:
        if key in ("user", "session", "audit_log"):
            return getattr(self, key)
        raise KeyError(f"Ключ '{key}' недоступний або захищений")

    def __setitem__(self, key: str, value: Any) -> None:
        # Валідація типів для дозволених атрибутів
        allowed_types = {
            "user": User,
            "session": (Session, type(None)),
            "audit_log": AuditLog,
        }
        if key not in allowed_types:
            raise KeyError(f"Ключ '{key}' не дозволений для модифікації")
        if not isinstance(value, allowed_types[key]):
            raise TypeError(f"Некоректний тип значення для '{key}'")
        setattr(self, key, value)
