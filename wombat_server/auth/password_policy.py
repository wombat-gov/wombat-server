"""Password policy shared by user creation, admin reset, and self-service change.

The policy is intentionally simple and explainable: length first, then a small
common-password denylist, then username reuse and all-one-character-class
checks. Do not replace this with an unmaintained complexity score.
"""
from __future__ import annotations

from wombat_server.config import settings


class PasswordPolicyError(ValueError):
    """Raised when a proposed password does not satisfy the policy."""


# Deliberately small. A full breach-corpus check belongs in a dedicated
# service; this catches the passwords operators actually type in a hurry.
_COMMON_PASSWORDS = {
    "password",
    "password1",
    "password123",
    "password1234",
    "qwerty",
    "qwerty123",
    "12345678",
    "123456789",
    "1234567890",
    "letmein",
    "welcome",
    "admin",
    "administrator",
    "changeme",
    "change-me",
    "wombat",
    "wombatpass",
}


def validate_password(
    password: str,
    username: str = "",
    *,
    min_length: int | None = None,
) -> None:
    """Raise :class:`PasswordPolicyError` if *password* is not acceptable."""
    minimum = settings.wombat_password_min_length if min_length is None else min_length
    if len(password) < minimum:
        raise PasswordPolicyError(f"Password must be at least {minimum} characters.")
    if password.lower() in _COMMON_PASSWORDS:
        raise PasswordPolicyError("Password is too common.")
    if username and password.lower() == username.lower():
        raise PasswordPolicyError("Password must not equal the username.")
    if password.isdigit() or password.isalpha():
        raise PasswordPolicyError("Password must mix letters with numbers or symbols.")
