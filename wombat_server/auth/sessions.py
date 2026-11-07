"""Session records linked to refresh-token families."""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Request
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from wombat_server.auth.cookies import REFRESH_COOKIE
from wombat_server.config import settings
from wombat_server.models import RefreshToken, Session, User


def hash_ip(ip: str) -> str:
    return hashlib.sha256(
        f"{ip}|{settings.wombat_jwt_secret}".encode()
    ).hexdigest()[:32]


def label_for_user_agent(user_agent: str) -> str:
    ua = user_agent or ""
    browser = next(
        (name for name in ("Edge", "Chrome", "Firefox", "Safari") if name in ua),
        "Browser",
    )
    platform = next(
        (name for name in ("Windows", "macOS", "Linux", "Android", "iOS") if name in ua),
        "",
    )
    if platform:
        return f"{browser} on {platform}"
    return browser


async def create_session(
    db: AsyncSession,
    user: User,
    family_id: uuid.UUID,
    request: Request,
) -> Session:
    now = datetime.now(timezone.utc)
    user_agent = request.headers.get("user-agent", "")[:512]
    session = Session(
        user_id=user.id,
        family_id=family_id,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(days=settings.wombat_session_absolute_days),
        user_agent=user_agent,
        ip_hash=hash_ip(request.client.host if request.client else ""),
        label=label_for_user_agent(user_agent),
        mandant_id=user.mandant_id,
    )
    db.add(session)
    return session


async def revoke_session(
    db: AsyncSession,
    session: Session,
    reason: str,
    revoked_by: uuid.UUID | None = None,
) -> None:
    if session.revoked_at is not None:
        return
    session.revoked_at = datetime.now(timezone.utc)
    session.revoked_by = revoked_by
    session.revoked_reason = reason[:200]


async def revoke_family(
    db: AsyncSession,
    family_id: uuid.UUID,
    reason: str,
    revoked_by: uuid.UUID | None = None,
) -> None:
    result = await db.execute(select(Session).where(Session.family_id == family_id))
    session = result.scalar_one_or_none()
    if session is not None:
        await revoke_session(db, session, reason, revoked_by)
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked.is_(False))
        .values(revoked=True)
    )


async def revoke_user_sessions(
    db: AsyncSession,
    user_id: uuid.UUID,
    reason: str,
    revoked_by: uuid.UUID | None = None,
    except_family: uuid.UUID | None = None,
) -> int:
    stmt = select(Session).where(
        Session.user_id == user_id,
        Session.revoked_at.is_(None),
    )
    if except_family is not None:
        stmt = stmt.where(Session.family_id != except_family)
    sessions = list((await db.execute(stmt)).scalars().all())
    for session in sessions:
        await revoke_session(db, session, reason, revoked_by)
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == session.family_id, RefreshToken.revoked.is_(False))
            .values(revoked=True)
        )
    return len(sessions)


async def enforce_session_policy(db: AsyncSession, session: Session) -> bool:
    """Return False and revoke the session if it is idle/expired/revoked."""
    now = datetime.now(timezone.utc)
    if session.revoked_at is not None:
        return False
    if session.expires_at <= now:
        await revoke_session(db, session, "absolute_timeout")
        return False
    idle_cutoff = session.last_seen_at + timedelta(minutes=settings.wombat_session_idle_minutes)
    if idle_cutoff <= now:
        await revoke_session(db, session, "idle_timeout")
        return False
    session.last_seen_at = now
    return True


async def current_family_id(db: AsyncSession, request: Request) -> uuid.UUID | None:
    raw = request.cookies.get(REFRESH_COOKIE)
    if not raw:
        return None
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    result = await db.execute(
        select(RefreshToken.family_id).where(RefreshToken.token_hash == token_hash)
    )
    return result.scalar_one_or_none()
