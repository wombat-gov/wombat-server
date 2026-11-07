"""TOTP / recovery-code MFA helpers.

WebAuthn storage is present on the model; the passkey ceremony is a follow-up.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid

import pyotp
from sqlalchemy.ext.asyncio import AsyncSession

from wombat_server.config import settings
from wombat_server.models import UserMFA
from wombat_server.secret_enc import decrypt_field, encrypt_field

RECOVERY_CODE_COUNT = 10
_TOTP_STEP_SECONDS = 30
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=settings.wombat_mfa_issuer,
    )


def normalize_code(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isalnum())


def verify_totp(secret: str, code: str, last_counter: int | None = None) -> int | None:
    """Return the accepted time-step, or None. Rejects a reused/older step."""
    normalized = normalize_code(code)
    if len(normalized) != 6 or not normalized.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    current = int(time.time()) // _TOTP_STEP_SECONDS
    for counter in (current - 1, current, current + 1):
        expected = totp.at(counter * _TOTP_STEP_SECONDS)
        if hmac.compare_digest(expected, normalized):
            if last_counter is not None and counter <= last_counter:
                return None
            return counter
    return None


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_ALPHABET) for _ in range(8))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def hash_recovery_code(user_id: uuid.UUID, code: str) -> str:
    return hashlib.sha256(
        f"{user_id}:{normalize_code(code)}".encode()
    ).hexdigest()


def hash_recovery_codes(user_id: uuid.UUID, codes: list[str]) -> list[str]:
    return [hash_recovery_code(user_id, code) for code in codes]


def consume_recovery_code(
    user_id: uuid.UUID,
    hashes: list[str],
    code: str,
) -> tuple[bool, list[str]]:
    target = hash_recovery_code(user_id, code)
    matched = False
    remaining: list[str] = []
    for stored in hashes:
        if not matched and hmac.compare_digest(str(stored), target):
            matched = True
            continue
        remaining.append(stored)
    return matched, remaining


async def get_mfa(db: AsyncSession, user_id: uuid.UUID) -> UserMFA | None:
    return await db.get(UserMFA, user_id)


async def get_or_create_mfa(db: AsyncSession, user_id: uuid.UUID) -> UserMFA:
    mfa = await db.get(UserMFA, user_id)
    if mfa is None:
        mfa = UserMFA(user_id=user_id, recovery_codes_hash=[], webauthn_credentials=[])
        db.add(mfa)
        await db.flush()
    return mfa


async def set_totp_secret(db: AsyncSession, user_id: uuid.UUID, secret: str) -> UserMFA:
    mfa = await get_or_create_mfa(db, user_id)
    mfa.totp_secret_enc = await encrypt_field(secret)
    mfa.totp_enabled = False
    return mfa


async def get_totp_secret(mfa: UserMFA) -> str | None:
    if not mfa.totp_secret_enc:
        return None
    return await decrypt_field(mfa.totp_secret_enc)


def is_mfa_enabled(mfa: UserMFA | None) -> bool:
    return bool(
        mfa
        and (mfa.totp_enabled or bool(mfa.webauthn_credentials))
    )


def mfa_required_for_role(role: str) -> bool:
    return settings.wombat_mfa_enabled and role in settings.mfa_required_roles_list


def mfa_methods(mfa: UserMFA | None) -> list[str]:
    methods: list[str] = []
    if mfa and mfa.totp_enabled:
        methods.append("totp")
    if mfa and mfa.webauthn_credentials:
        methods.append("webauthn")
    if mfa and mfa.recovery_codes_hash:
        methods.append("recovery")
    return methods


def mfa_qr_svg(uri: str) -> str | None:
    try:
        import segno

        return segno.make(uri).svg_inline()
    except Exception:
        return None
