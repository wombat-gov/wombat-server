"""JWT creation and verification.

Access tokens are short-lived HS256 JWTs signed with WOMBAT_JWT_SECRET.
Refresh tokens are opaque random strings stored hashed in the database.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import jwt

from wombat_server.config import settings

_ALGORITHM = "HS256"


def create_access_token(
    user_id: uuid.UUID,
    username: str,
    role: str,
    family_id: uuid.UUID | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.wombat_jwt_expire_minutes),
    }
    if family_id is not None:
        payload["family_id"] = str(family_id)
    return jwt.encode(payload, settings.wombat_jwt_secret, algorithm=_ALGORITHM)


def create_mfa_token(user_id: uuid.UUID) -> str:
    """Short-lived token proving the password step succeeded."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "type": "mfa",
        "iat": now,
        "exp": now + timedelta(minutes=settings.wombat_mfa_token_minutes),
    }
    return jwt.encode(payload, settings.wombat_jwt_secret, algorithm=_ALGORITHM)


def decode_mfa_token(token: str) -> dict:
    payload = jwt.decode(token, settings.wombat_jwt_secret, algorithms=[_ALGORITHM])
    if payload.get("type") != "mfa":
        raise ValueError("not an MFA token")
    return payload



def decode_access_token(token: str) -> dict:
    """Decode and verify an access token.  Raises ``PyJWTError`` on failure."""
    return jwt.decode(token, settings.wombat_jwt_secret, algorithms=[_ALGORITHM])
