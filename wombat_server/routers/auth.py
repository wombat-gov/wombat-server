"""Authentication endpoints: login, refresh, logout, /me, and user management."""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from wombat_server.auth.deps import (
    ROLE_HIERARCHY,
    AuthContext,
    adopt_mandate_of,
    get_auth_context,
    get_current_user,
    get_scoped_db,
    load_user_by_id,
    require_role,
    set_login_username,
)
from wombat_server.auth.jwt_utils import create_access_token, create_mfa_token, decode_mfa_token
from wombat_server.auth.cookies import (
    REFRESH_COOKIE,
    clear_session_cookies,
    set_session_cookies,
)
from wombat_server.auth.mfa import (
    consume_recovery_code,
    generate_recovery_codes,
    generate_totp_secret,
    get_mfa,
    get_totp_secret,
    hash_recovery_codes,
    is_mfa_enabled,
    mfa_methods,
    mfa_qr_svg,
    mfa_required_for_role,
    provisioning_uri,
    set_totp_secret,
    verify_totp,
)
from wombat_server.auth.password_policy import PasswordPolicyError, validate_password
from wombat_server.auth.providers.local import authenticate_local, hash_password, verify_password
from wombat_server.auth.rate_limit import login_ip_limiter
from wombat_server.auth.sessions import (
    create_session,
    current_family_id,
    enforce_session_policy,
    revoke_family,
    revoke_session,
    revoke_user_sessions,
)
from wombat_server.audit_chain import chain_event
from wombat_server.config import settings
from wombat_server.observability.metrics import login_failures, login_locked
from wombat_server.database import get_db
from wombat_server.models import (
    ApiKey,
    ApiKeyUsageLog,
    Mandant,
    RefreshToken,
    Session,
    User,
    UserAuditLog,
    UserGroup,
)
from wombat_server.syslog import emit_admin_audit_event

router = APIRouter(prefix="/auth", tags=["auth"])

# App-validated, not a DB CHECK constraint — same convention as admin.py's
# _VALID_MANDATE_TYPES. group_admin/group_viewer are Phase 6b / ADR-004.
_VALID_HOLDING_ROLES = {"holding_admin", "holding_viewer", "group_admin", "group_viewer"}


def _hash(raw: str) -> str:
    # False positive for py/weak-sensitive-data-hashing: refresh tokens and
    # API keys are generated with secrets.token_urlsafe/token_hex and are not
    # passwords. See auth/providers/local.py for bcrypt password hashing.
    return hashlib.sha256(  # lgtm[py/weak-sensitive-data-hashing]
        raw.encode()
    ).hexdigest()


def _ip(request: Request) -> str:
    """Client IP after uvicorn's trusted-proxy resolution.

    Do not read X-Forwarded-For here: uvicorn's ProxyHeadersMiddleware only
    trusts it from the configured proxy addresses and writes the resolved
    peer into request.client. Trusting the raw header would let any caller
    spoof audit IPs and rate-limit keys.
    """
    return request.client.host if request.client else ""


# A fixed bcrypt hash used to equalize the timing of an unknown-username
# login with a known one. The plaintext is irrelevant and never accepted.
_DUMMY_PASSWORD_HASH = hash_password("wombat-dummy-timing-password")


async def _audit(
    db: AsyncSession,
    actor_id: uuid.UUID | None,
    action: str,
    detail: dict,
    ip: str = "",
    mandant_id: uuid.UUID | None = None,
) -> None:
    # caller is responsible for commit
    event = UserAuditLog(
        actor_id=actor_id, action=action, detail=detail, ip=ip, mandant_id=mandant_id,
    )
    await chain_event(db, event)
    db.add(event)
    emit_admin_audit_event(
        action=action,
        detail=detail,
        ip=ip,
        mandant_id=str(mandant_id) if mandant_id else None,
        actor_id=str(actor_id) if actor_id else None,
    )
    # caller is responsible for commit


async def _issue_session(
    db: AsyncSession,
    user: User,
    request: Request,
    response: Response,
    *,
    audit_action: str = "login",
) -> dict:
    """Create a refresh-token family + session row and set the browser cookies."""
    now = datetime.now(timezone.utc)
    active = list(
        (
            await db.execute(
                select(Session)
                .where(Session.user_id == user.id, Session.revoked_at.is_(None))
                .order_by(Session.created_at)
            )
        ).scalars().all()
    )
    if len(active) >= settings.wombat_session_max:
        for old in active[: len(active) - settings.wombat_session_max + 1]:
            await revoke_session(db, old, "max_sessions_exceeded")
            await db.execute(
                update(RefreshToken)
                .where(
                    RefreshToken.family_id == old.family_id,
                    RefreshToken.revoked.is_(False),
                )
                .values(revoked=True)
            )

    family_id = uuid.uuid4()
    raw_refresh = secrets.token_urlsafe(48)
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=_hash(raw_refresh),
            family_id=family_id,
            expires_at=now + timedelta(days=settings.wombat_jwt_refresh_days),
        )
    )
    await create_session(db, user, family_id, request)
    access_token = create_access_token(user.id, user.username, user.role, family_id)

    user.last_login_at = now
    user.failed_login_count = 0
    user.locked_until = None
    user.last_failed_login_at = None
    await _audit(
        db, user.id, audit_action, {},
        ip=_ip(request), mandant_id=user.mandant_id,
    )
    await db.commit()
    await login_ip_limiter.reset(_ip(request))

    if settings.wombat_cookie_auth:
        set_session_cookies(response, access_token, raw_refresh)

    mfa = await get_mfa(db, user.id)
    return {
        "access_token": access_token,
        "refresh_token": raw_refresh,
        "token_type": "bearer",
        "user": user,
        "mfa_enrollment_required": mfa_required_for_role(user.role) and not is_mfa_enabled(mfa),
    }


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    display_name: str
    image_url: str = ""
    role: str
    auth_provider: str
    is_active: bool
    last_login_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    mandant_id: uuid.UUID | None = None
    holding_role: str | None = None  # None | "holding_admin" | "holding_viewer" | "group_admin" | "group_viewer"
    must_change_password: bool = False
    email: str = ""
    external_id: str | None = None

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut
    mfa_enrollment_required: bool = False


class MfaChallengeResponse(BaseModel):
    mfa_required: bool = True
    mfa_token: str
    methods: list[str] = []


class MfaChallengeRequest(BaseModel):
    mfa_token: str
    code: str
    method: str = "totp"


class MfaSetupRequest(BaseModel):
    current_password: str


class MfaSetupOut(BaseModel):
    secret: str
    otpauth_uri: str
    qr_svg: str | None = None


class MfaVerifyRequest(BaseModel):
    code: str


class MfaDisableRequest(BaseModel):
    current_password: str
    code: str


class MfaStatusOut(BaseModel):
    enabled: bool
    methods: list[str]
    recovery_codes_remaining: int
    required: bool


class SessionOut(BaseModel):
    id: uuid.UUID
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    label: str = ""
    user_agent: str = ""
    current: bool = False


class RefreshRequest(BaseModel):
    refresh_token: str | None = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class AccessTokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    username: str
    password: str = Field(min_length=12)
    display_name: str = ""
    image_url: str = ""
    role: str = "clevel"
    group: str | None = None  # Optional group name to assign to user
    # Explicit target mandate — holding_admin only (see create_user).
    # Omitted (the common case): falls back to the acting user's own
    # effective mandate, same as before this field existed. Mirrors
    # ApiKeyCreate.mandant_id's identical pattern below — a holding-only
    # admin creating a user previously had nowhere to assign a mandate at
    # all (the identical gap for API keys was fixed first).
    mandant_id: uuid.UUID | None = None


class UserUpdate(BaseModel):
    display_name: str | None = None
    image_url: str | None = None
    role: str | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12)
    group: str | None = None  # Optional group name to add to user
    # Phase 3.4 — only ever applied when the acting user is holding_admin
    # (enforced in update_user below, not by the schema).
    mandant_id: uuid.UUID | None = None
    holding_role: str | None = None  # "" clears it; None leaves it unchanged. See _VALID_HOLDING_ROLES.


# ── Auth endpoints ────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse | MfaChallengeResponse)
async def login(
    request: Request,
    response: Response,
    payload: LoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Exchange username + password for a session cookie and/or bearer tokens."""
    ip = _ip(request)
    if not await login_ip_limiter.allow(ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(settings.wombat_login_ip_window_seconds)},
        )

    # Auth-bootstrap carve-out: at this point we know only the submitted
    # username, not the user's id or mandate — see
    # db_migrations/activate_multi_mandant_ddl.py and auth/deps.py.
    await set_login_username(db, payload.username)

    # Load the candidate first so lockout state can be checked without
    # revealing whether the username exists (the error stays generic).
    candidate = (
        await db.execute(
            select(User).where(
                User.username == payload.username,
                User.auth_provider == "local",
            )
        )
    ).scalar_one_or_none()
    now = datetime.now(timezone.utc)

    if candidate is not None and candidate.locked_until and candidate.locked_until > now:
        retry_after = max(1, int((candidate.locked_until - now).total_seconds()))
        login_failures.inc()
        await adopt_mandate_of(
            db, candidate.mandant_id,
            is_holding_admin=candidate.holding_role == "holding_admin",
            is_holding_viewer=candidate.holding_role == "holding_viewer",
        )
        await _audit(
            db, candidate.id, "login_failed", {"reason": "locked"},
            ip=ip, mandant_id=candidate.mandant_id,
        )
        await db.commit()
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={"Retry-After": str(retry_after)},
        )

    record = await authenticate_local(db, payload.username, payload.password)
    if record is None:
        login_failures.inc()
        if candidate is not None:
            await adopt_mandate_of(
                db, candidate.mandant_id,
                is_holding_admin=candidate.holding_role == "holding_admin",
                is_holding_viewer=candidate.holding_role == "holding_viewer",
            )
            candidate.failed_login_count = (candidate.failed_login_count or 0) + 1
            candidate.last_failed_login_at = now
            if candidate.failed_login_count >= settings.wombat_login_max_failures:
                candidate.locked_until = now + timedelta(minutes=settings.wombat_login_lock_minutes)
                login_locked.inc()
                await _audit(
                    db, candidate.id, "account_locked",
                    {
                        "failed_attempts": candidate.failed_login_count,
                        "locked_until": candidate.locked_until.isoformat(),
                    },
                    ip=ip, mandant_id=candidate.mandant_id,
                )
            await _audit(
                db, candidate.id, "login_failed",
                {"failed_attempts": candidate.failed_login_count},
                ip=ip, mandant_id=candidate.mandant_id,
            )
            await db.commit()
        else:
            # Unknown username: spend the same bcrypt time as a real check so
            # response timing does not reveal account existence.
            verify_password(payload.password, _DUMMY_PASSWORD_HASH)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

    user = await db.get(User, record.id)
    await adopt_mandate_of(
        db, user.mandant_id,
        is_holding_admin=user.holding_role == "holding_admin",
        is_holding_viewer=user.holding_role == "holding_viewer",
    )

    mfa = await get_mfa(db, user.id)
    if is_mfa_enabled(mfa):
        await _audit(
            db, user.id, "login_mfa_required", {},
            ip=ip, mandant_id=user.mandant_id,
        )
        await db.commit()
        return {
            "mfa_required": True,
            "mfa_token": create_mfa_token(user.id),
            "methods": mfa_methods(mfa),
        }

    return await _issue_session(db, user, request, response)


@router.post("/refresh", response_model=AccessTokenResponse)
async def refresh_token(
    request: Request,
    response: Response,
    payload: RefreshRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Rotate a refresh token: revoke the presented one, issue a fresh one.

    If a revoked token is presented it indicates a replay attack — every token
    in the same family is immediately revoked, forcing re-authentication on all
    devices that shared this token chain.

    The token comes from the request body (CLI/CI) or, when absent, from the
    HttpOnly ``wombat_refresh`` cookie (dashboard).
    """
    raw_token = payload.refresh_token or request.cookies.get(REFRESH_COOKIE)
    if not raw_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")
    token_hash = _hash(raw_token)
    result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    rt = result.scalar_one_or_none()

    if rt is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    if rt.revoked:
        # Replay of an already-rotated token — assume theft, invalidate the whole family.
        # RefreshToken itself isn't mandate-scoped, but the UserAuditLog
        # entry below is — load the user (known id, bootstrap carve-out)
        # and adopt its mandate so that insert's WITH CHECK passes.
        replay_user = await load_user_by_id(db, rt.user_id)
        await adopt_mandate_of(
            db, replay_user.mandant_id if replay_user else None,
            is_holding_admin=bool(replay_user and replay_user.holding_role == "holding_admin"),
            is_holding_viewer=bool(replay_user and replay_user.holding_role == "holding_viewer"),
        )
        await revoke_family(db, rt.family_id, "revoked_token_replay", revoked_by=rt.user_id)
        await _audit(db, rt.user_id, "token.family_revoked",
                     {"family_id": str(rt.family_id), "reason": "revoked_token_replay"},
                     ip=_ip(request), mandant_id=replay_user.mandant_id if replay_user else None)
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            detail="Refresh token already used — all sessions invalidated. Please log in again.")

    if rt.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        await revoke_family(db, rt.family_id, "refresh_token_expired", revoked_by=rt.user_id)
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired.")

    # Bootstrap carve-out: rt.user_id is already known, same shape as JWT
    # validation — see auth/deps.py.
    user = await load_user_by_id(db, rt.user_id)
    if user is None or not user.is_active:
        await revoke_family(db, rt.family_id, "user_inactive")
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive.")

    session = (
        await db.execute(select(Session).where(Session.family_id == rt.family_id))
    ).scalar_one_or_none()
    if session is None:
        # Compatibility for tokens issued before the sessions table existed.
        await create_session(db, user, rt.family_id, request)
    elif not await enforce_session_policy(db, session):
        await revoke_family(db, rt.family_id, "session_invalid")
        await db.commit()
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or revoked. Please log in again.",
        )

    # Rotate: revoke the old token, issue a new one in the same family.
    rt.revoked = True
    raw_new = secrets.token_urlsafe(48)
    db.add(RefreshToken(
        user_id=user.id,
        token_hash=_hash(raw_new),
        family_id=rt.family_id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.wombat_jwt_refresh_days),
    ))
    await db.commit()

    access_token = create_access_token(user.id, user.username, user.role, rt.family_id)
    if settings.wombat_cookie_auth:
        set_session_cookies(response, access_token, raw_new)

    return {
        "access_token": access_token,
        "refresh_token": raw_new,
        "token_type": "bearer",
    }


@router.post("/logout", status_code=204)
async def logout(
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
    payload: RefreshRequest | None = Body(default=None),
) -> None:
    """Revoke the supplied (or cookie-bound) refresh token and clear cookies."""
    raw_token = (payload.refresh_token if payload else None) or request.cookies.get(REFRESH_COOKIE)
    if raw_token:
        token_hash = _hash(raw_token)
        result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
        rt = result.scalar_one_or_none()
        if rt:
            logout_user = await load_user_by_id(db, rt.user_id)
            await adopt_mandate_of(
                db, logout_user.mandant_id if logout_user else None,
                is_holding_admin=bool(logout_user and logout_user.holding_role == "holding_admin"),
                is_holding_viewer=bool(logout_user and logout_user.holding_role == "holding_viewer"),
            )
            await revoke_family(db, rt.family_id, "logout", revoked_by=rt.user_id)
            await _audit(db, rt.user_id, "logout", {}, ip=_ip(request), mandant_id=logout_user.mandant_id if logout_user else None)
            await db.commit()
    clear_session_cookies(response)


@router.get("/me", response_model=UserOut)
async def me(
    user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Return the authenticated user's profile."""
    return user


@router.post("/change-password", status_code=204)
async def change_password(
    request: Request,
    response: Response,
    payload: ChangePasswordRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Change the caller's password, revoke every refresh token, clear cookies."""
    if user.auth_provider != "local" or not user.password_hash:
        raise HTTPException(400, detail="Password login is not enabled for this account.")
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(400, detail="Current password is incorrect.")
    try:
        validate_password(payload.new_password, user.username)
    except PasswordPolicyError as exc:
        raise HTTPException(400, detail=str(exc))

    await adopt_mandate_of(
        db, user.mandant_id,
        is_holding_admin=user.holding_role == "holding_admin",
        is_holding_viewer=user.holding_role == "holding_viewer",
    )
    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False
    # Revoke every existing session, then issue this browser a fresh one so the
    # user is not bounced to the login page after rotating.
    await revoke_user_sessions(db, user.id, "password_changed", revoked_by=user.id)
    await _issue_session(db, user, request, response, audit_action="password_changed")


@router.get("/sessions", response_model=list[SessionOut])
async def list_my_sessions(
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[SessionOut]:
    """List the caller's active sessions, newest first."""
    current = await current_family_id(db, request)
    rows = (
        await db.execute(
            select(Session)
            .where(Session.user_id == user.id, Session.revoked_at.is_(None))
            .order_by(Session.created_at.desc())
        )
    ).scalars().all()
    return [
        SessionOut(
            id=row.id,
            created_at=row.created_at,
            last_seen_at=row.last_seen_at,
            expires_at=row.expires_at,
            revoked_at=row.revoked_at,
            label=row.label,
            user_agent=row.user_agent,
            current=row.family_id == current,
        )
        for row in rows
    ]


@router.delete("/sessions/{session_id}", status_code=204)
async def revoke_my_session(
    session_id: uuid.UUID,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    session = await db.get(Session, session_id)
    if session is None or session.user_id != user.id:
        raise HTTPException(404, detail="Session not found.")
    await revoke_family(db, session.family_id, "session_revoked", revoked_by=user.id)
    await _audit(
        db, user.id, "session_revoked", {"session_id": str(session_id)},
        ip="", mandant_id=user.mandant_id,
    )
    await db.commit()


@router.delete("/sessions", response_model=dict)
async def revoke_other_sessions(
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Revoke every session except the one making this request."""
    current = await current_family_id(db, request)
    count = await revoke_user_sessions(
        db, user.id, "sessions_revoked_all",
        revoked_by=user.id, except_family=current,
    )
    await _audit(
        db, user.id, "sessions_revoked_all", {"count": count},
        ip="", mandant_id=user.mandant_id,
    )
    await db.commit()
    return {"revoked": count}


@router.get("/users/{user_id}/sessions", response_model=list[SessionOut])
async def admin_list_sessions(
    user_id: uuid.UUID,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> list[SessionOut]:
    rows = (
        await db.execute(
            select(Session)
            .where(Session.user_id == user_id, Session.revoked_at.is_(None))
            .order_by(Session.created_at.desc())
        )
    ).scalars().all()
    return [
        SessionOut(
            id=row.id,
            created_at=row.created_at,
            last_seen_at=row.last_seen_at,
            expires_at=row.expires_at,
            revoked_at=row.revoked_at,
            label=row.label,
            user_agent=row.user_agent,
        )
        for row in rows
    ]


@router.delete("/users/{user_id}/sessions", response_model=dict)
async def admin_revoke_sessions(
    user_id: uuid.UUID,
    acting_user: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> dict:
    count = await revoke_user_sessions(
        db, user_id, "admin_revoked_all", revoked_by=acting_user.id,
    )
    await _audit(
        db, acting_user.id, "sessions_revoked_all",
        {"target_user_id": str(user_id), "count": count},
        mandant_id=acting_user.mandant_id,
    )
    await db.commit()
    return {"revoked": count}


@router.get("/mfa", response_model=MfaStatusOut)
async def mfa_status(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MfaStatusOut:
    mfa = await get_mfa(db, user.id)
    return MfaStatusOut(
        enabled=is_mfa_enabled(mfa),
        methods=mfa_methods(mfa),
        recovery_codes_remaining=len(mfa.recovery_codes_hash) if mfa else 0,
        required=mfa_required_for_role(user.role),
    )


@router.post("/mfa/totp/setup", response_model=MfaSetupOut)
async def mfa_totp_setup(
    payload: MfaSetupRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MfaSetupOut:
    if not user.password_hash or not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(400, detail="Current password is incorrect.")
    secret = generate_totp_secret()
    await set_totp_secret(db, user.id, secret)
    uri = provisioning_uri(secret, user.username)
    await _audit(
        db, user.id, "mfa_setup_started", {"method": "totp"},
        mandant_id=user.mandant_id,
    )
    await db.commit()
    return MfaSetupOut(secret=secret, otpauth_uri=uri, qr_svg=mfa_qr_svg(uri))


@router.post("/mfa/totp/verify", response_model=dict)
async def mfa_totp_verify(
    payload: MfaVerifyRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    mfa = await get_mfa(db, user.id)
    secret = await get_totp_secret(mfa) if mfa else None
    if mfa is None or not secret:
        raise HTTPException(400, detail="Start MFA setup first.")
    counter = verify_totp(secret, payload.code, mfa.last_totp_counter)
    if counter is None:
        raise HTTPException(400, detail="Invalid or already-used code.")
    mfa.totp_enabled = True
    mfa.last_totp_counter = counter
    codes = generate_recovery_codes()
    mfa.recovery_codes_hash = hash_recovery_codes(user.id, codes)
    await _audit(
        db, user.id, "mfa_enabled", {"method": "totp", "recovery_codes": len(codes)},
        mandant_id=user.mandant_id,
    )
    await db.commit()
    return {"recovery_codes": codes}


@router.post("/mfa/recovery-codes", response_model=dict)
async def mfa_regenerate_recovery_codes(
    payload: MfaSetupRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    if not user.password_hash or not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(400, detail="Current password is incorrect.")
    mfa = await get_mfa(db, user.id)
    if mfa is None or not is_mfa_enabled(mfa):
        raise HTTPException(400, detail="MFA is not enabled.")
    codes = generate_recovery_codes()
    mfa.recovery_codes_hash = hash_recovery_codes(user.id, codes)
    await _audit(
        db, user.id, "mfa_recovery_codes_regenerated",
        {"count": len(codes)}, mandant_id=user.mandant_id,
    )
    await db.commit()
    return {"recovery_codes": codes}


@router.post("/mfa/disable", status_code=204)
async def mfa_disable(
    payload: MfaDisableRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    if not user.password_hash or not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(400, detail="Current password is incorrect.")
    mfa = await get_mfa(db, user.id)
    if mfa is None or not is_mfa_enabled(mfa):
        raise HTTPException(400, detail="MFA is not enabled.")

    valid = False
    if mfa.totp_enabled:
        secret = await get_totp_secret(mfa)
        if secret and verify_totp(secret, payload.code, mfa.last_totp_counter) is not None:
            valid = True
    if not valid and mfa.recovery_codes_hash:
        matched, remaining = consume_recovery_code(user.id, mfa.recovery_codes_hash, payload.code)
        if matched:
            mfa.recovery_codes_hash = remaining
            valid = True
    if not valid:
        raise HTTPException(400, detail="Invalid code.")

    mfa.totp_enabled = False
    mfa.totp_secret_enc = None
    mfa.recovery_codes_hash = []
    mfa.webauthn_credentials = []
    mfa.last_totp_counter = None
    await _audit(
        db, user.id, "mfa_disabled", {}, mandant_id=user.mandant_id,
    )
    await db.commit()


@router.post("/mfa/challenge", response_model=TokenResponse)
async def mfa_challenge(
    request: Request,
    response: Response,
    payload: MfaChallengeRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Complete login with a TOTP or recovery code after the password step."""
    try:
        data = decode_mfa_token(payload.mfa_token)
        user_id = uuid.UUID(data["sub"])
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired MFA token.")

    user = await load_user_by_id(db, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive.")
    await adopt_mandate_of(
        db, user.mandant_id,
        is_holding_admin=user.holding_role == "holding_admin",
        is_holding_viewer=user.holding_role == "holding_viewer",
    )

    mfa = await get_mfa(db, user.id)
    if not is_mfa_enabled(mfa) or mfa is None:
        raise HTTPException(400, detail="MFA is not enabled for this account.")

    valid = False
    if payload.method == "recovery":
        matched, remaining = consume_recovery_code(user.id, mfa.recovery_codes_hash, payload.code)
        if matched:
            mfa.recovery_codes_hash = remaining
            valid = True
            await _audit(
                db, user.id, "mfa_recovery_used", {}, mandant_id=user.mandant_id,
            )
    elif mfa.totp_enabled:
        secret = await get_totp_secret(mfa)
        counter = verify_totp(secret, payload.code, mfa.last_totp_counter) if secret else None
        if counter is not None:
            mfa.last_totp_counter = counter
            valid = True

    if not valid:
        await _audit(
            db, user.id, "mfa_challenge_failed", {"method": payload.method},
            ip=_ip(request), mandant_id=user.mandant_id,
        )
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code.")

    return await _issue_session(db, user, request, response, audit_action="mfa_success")


@router.get("/me/prefs")
async def get_my_prefs(
    user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Return the current user's stored UI preferences."""
    return user.prefs or {}


@router.put("/me/prefs", status_code=204)
async def put_my_prefs(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    payload: dict[str, Any] = Body(...),
) -> None:
    """Persist the current user's UI preferences (full replace)."""
    await db.execute(update(User).where(User.id == user.id).values(prefs=payload))
    await db.commit()


class ProfileUpdate(BaseModel):
    display_name: str | None = None
    image_url: str | None = None


@router.put("/me/profile", response_model=UserOut)
async def update_my_profile(
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    payload: ProfileUpdate = Body(...),
) -> User:
    """Update the authenticated user's profile (display_name, image_url)."""
    changed_fields: list[str] = []
    if payload.display_name is not None:
        user.display_name = payload.display_name
        changed_fields.append("display_name")
    if payload.image_url is not None:
        user.image_url = payload.image_url
        changed_fields.append("image_url")
    if not changed_fields:
        return user
    await _audit(db, user.id, "user.update_profile", {
        "fields": changed_fields,
    }, ip=_ip(request), mandant_id=auth.mandant_id)
    await db.commit()
    await db.refresh(user)
    return user


# ── User management (requires engineer role) ─────────────────────────────────

@router.get("/users", response_model=list[UserOut])
async def list_users(
    _: Annotated[User, Depends(require_role("engineer"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> list[User]:
    result = await db.execute(select(User).order_by(User.created_at))
    return list(result.scalars().all())


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    request: Request,
    payload: UserCreate,
    acting_user: Annotated[User, Depends(require_role("engineer"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> User:
    if payload.role not in ROLE_HIERARCHY:
        raise HTTPException(400, detail=f"Invalid role. Choose from: {', '.join(ROLE_HIERARCHY)}")
    try:
        validate_password(payload.password, payload.username)
    except PasswordPolicyError as exc:
        raise HTTPException(400, detail=str(exc))
    # A holding_admin outranks any single mandate's own "admin" — their
    # bypass is already full cross-mandate RLS access, so gating this on
    # the literal base role alone would wrongly block them (holding_role
    # and role are independent fields; see update_user below). Checked via
    # the request's *effective* flag, not the permanent holding_role, so a
    # holding_admin who has narrowed into one mandate via X-Mandant-Context
    # is held to that mandate's own admin requirement, same as everywhere
    # else narrowing applies.
    if payload.role == "admin" and acting_user.role != "admin" and not auth.is_holding_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Only an admin can assign the 'admin' role.")
    existing = await db.execute(select(User).where(User.username == payload.username))
    if existing.scalar_one_or_none():
        raise HTTPException(409, detail=f"Username '{payload.username}' already exists.")

    # New users join the creating admin's own mandate by default.
    # payload.mandant_id (mirrors create_api_key's identical pattern) lets
    # a holding_admin target a *specific* mandate directly instead — an
    # ordinary admin explicitly naming a mandate other than their own would
    # be a privilege-escalation path, not a convenience.
    target_mandant_id = auth.mandant_id
    if payload.mandant_id is not None:
        if not auth.is_holding_admin:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail="Only a holding_admin can target a specific mandant_id when creating a user.",
            )
        target_mandant = await db.get(Mandant, payload.mandant_id)
        if target_mandant is None or not target_mandant.is_active:
            raise HTTPException(400, detail="Unknown or inactive mandant_id.")
        target_mandant_id = payload.mandant_id
    elif auth.is_holding_admin and auth.mandant_id is None:
        # A holding-only admin (no personal mandate) has nothing to
        # inherit — unlike create_api_key, this wouldn't crash
        # (users.mandant_id is nullable) but would silently create a
        # dead-end account with no mandate-scoped or holding access at
        # all. Reject cleanly instead, unless they named a target above.
        raise HTTPException(
            400,
            detail="A holding-only admin has no mandate to assign this user to. "
                   "Switch to a mandate-scoped account, or pass mandant_id explicitly.",
        )
    user = User(
        username=payload.username,
        display_name=payload.display_name,
        image_url=payload.image_url,
        role=payload.role,
        auth_provider="local",
        password_hash=hash_password(payload.password),
        mandant_id=target_mandant_id,
    )
    db.add(user)
    await db.flush()   # get user.id before audit row

    # Assign group to user if specified
    if payload.group:
        existing_group = await db.execute(
            select(UserGroup).where(
                UserGroup.user_id == user.id,
                UserGroup.group_name == payload.group
            )
        )
        if existing_group.scalar_one_or_none() is None:
            user_group = UserGroup(
                user_id=user.id,
                group_name=payload.group,
                provider="*"
            )
            db.add(user_group)

    # Tag with the *target's* own mandate, not the actor's — same reasoning
    # as update_user/delete_user below: a holding_admin creating a user in
    # mandate X while themselves unnarrowed should still produce an audit
    # row that mandate X's own admin can see.
    await _audit(db, acting_user.id, "user.create", {
        "target_id": str(user.id),
        "target_username": user.username,
        "target_role": user.role,
        "target_group": payload.group,
    }, ip=_ip(request), mandant_id=target_mandant_id)
    await db.commit()
    await db.refresh(user)
    return user


@router.put("/users/{user_id}", response_model=UserOut)
async def update_user(
    request: Request,
    user_id: uuid.UUID,
    payload: UserUpdate,
    acting_user: Annotated[User, Depends(require_role("engineer"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, detail="User not found.")
    # Same holding_admin bypass as create_user above.
    if (user.role == "admin" or payload.role == "admin") and acting_user.role != "admin" and not auth.is_holding_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Only an admin can modify an admin account or grant the 'admin' role.")
    changed_fields: list[str] = []
    if payload.display_name is not None:
        user.display_name = payload.display_name
        changed_fields.append("display_name")
    if payload.image_url is not None:
        user.image_url = payload.image_url
        changed_fields.append("image_url")
    if payload.role is not None:
        if payload.role not in ROLE_HIERARCHY:
            raise HTTPException(400, detail=f"Invalid role. Choose from: {', '.join(ROLE_HIERARCHY)}")
        user.role = payload.role
        changed_fields.append("role")
    if payload.is_active is not None:
        user.is_active = payload.is_active
        changed_fields.append("is_active")
    if payload.password is not None:
        try:
            validate_password(payload.password, user.username)
        except PasswordPolicyError as exc:
            raise HTTPException(400, detail=str(exc))
        user.password_hash = hash_password(payload.password)
        # An admin-initiated reset must be rotated by the user on next login.
        user.must_change_password = True
        changed_fields.append("password")
    if payload.group is not None:
        # Add user to specified group
        existing_group = await db.execute(
            select(UserGroup).where(
                UserGroup.user_id == user.id,
                UserGroup.group_name == payload.group
            )
        )
        if existing_group.scalar_one_or_none() is None:
            user_group = UserGroup(
                user_id=user.id,
                group_name=payload.group,
                provider="*"
            )
            db.add(user_group)
            changed_fields.append("group")

    # Phase 3.4 — mandate/holding_role assignment, holding_admin only.
    # Uses model_fields_set (not `is not None`) for mandant_id specifically,
    # because None is itself a valid, meaningful value here (a holding-only
    # account with no personal mandate) — "the field was sent" and "the
    # field was sent as null" are different things a plain None default
    # can't distinguish.
    wants_mandant_change = "mandant_id" in payload.model_fields_set
    wants_holding_role_change = payload.holding_role is not None
    if wants_mandant_change or wants_holding_role_change:
        if not auth.is_holding_admin:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, detail="Only a holding_admin can reassign a user's mandant or holding role."
            )
        if wants_mandant_change:
            if payload.mandant_id is not None:
                target_mandant = await db.get(Mandant, payload.mandant_id)
                if target_mandant is None:
                    raise HTTPException(400, detail="Mandant not found.")
            user.mandant_id = payload.mandant_id
            changed_fields.append("mandant_id")
        if wants_holding_role_change:
            new_holding_role = payload.holding_role or None  # "" clears it
            if new_holding_role is not None and new_holding_role not in _VALID_HOLDING_ROLES:
                raise HTTPException(
                    400,
                    detail=f"holding_role must be one of {sorted(_VALID_HOLDING_ROLES)}, or empty to clear.",
                )
            user.holding_role = new_holding_role
            changed_fields.append("holding_role")

        # Phase 6b / ADR-004 — group_admin/group_viewer administer the
        # subtree rooted at their *own* mandant_id; unlike holding_admin/
        # holding_viewer (who administer the whole holding and may
        # legitimately have no personal mandate), a group role with no
        # mandate at all has no subtree to administer. Checked once here,
        # after both possible mutations above, so it catches every path to
        # that state: setting the role with no mandate ever assigned,
        # clearing mandant_id while the role is already a group one, or
        # (defensively) both in the same request.
        if user.holding_role in ("group_admin", "group_viewer") and user.mandant_id is None:
            raise HTTPException(
                400,
                detail="group_admin/group_viewer requires the user to already have a mandant assigned — "
                       "their own mandant is the root of the subtree they administer.",
            )

    # Tag with the *target's* mandate, not the actor's — a holding_admin
    # (who may have no personal mandate at all) editing a mandate-scoped
    # user should still produce an audit row that user's own mandate admin
    # can see, not one that's only visible at the holding level. Falls back
    # to NULL (holding-level-only visibility) only if the target also has
    # none — e.g. editing another holding-only account.
    await _audit(db, acting_user.id, "user.update", {
        "target_id": str(user.id),
        "target_username": user.username,
        "fields": changed_fields,
    }, ip=_ip(request), mandant_id=user.mandant_id)
    await db.commit()
    await db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    request: Request,
    user_id: uuid.UUID,
    acting_user: Annotated[User, Depends(require_role("engineer"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> None:
    if acting_user.id == user_id:
        raise HTTPException(400, detail="Cannot delete your own account.")
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, detail="User not found.")
    # Same holding_admin bypass as create_user above.
    if user.role == "admin" and acting_user.role != "admin" and not auth.is_holding_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Only an admin can delete an admin account.")
    # Same reasoning as update_user: tag with the target's own mandate.
    await _audit(db, acting_user.id, "user.delete", {
        "target_id": str(user.id),
        "target_username": user.username,
        "target_role": user.role,
    }, ip=_ip(request), mandant_id=user.mandant_id)
    await db.delete(user)
    await db.commit()


@router.get("/users/{user_id}", response_model=UserOut)
async def get_user(
    user_id: uuid.UUID,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> User:
    """Return full profile for a single user (admin only)."""
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, detail="User not found.")
    return user


class UserAuditLogOut(BaseModel):
    id: uuid.UUID
    actor_id: uuid.UUID | None
    action: str
    detail: dict
    ip: str
    timestamp: datetime

    model_config = {"from_attributes": True}


@router.get("/users/{user_id}/logs", response_model=list[UserAuditLogOut])
async def get_user_logs(
    user_id: uuid.UUID,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    limit: int = 100,
) -> list[UserAuditLog]:
    """Return the most recent audit log entries where the actor is this user (admin only)."""
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, detail="User not found.")
    result = await db.execute(
        select(UserAuditLog)
        .where(UserAuditLog.actor_id == user_id)
        .order_by(UserAuditLog.timestamp.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


# ── API key management (admin only) ──────────────────────────────────────────

class ApiKeyOut(BaseModel):
    id: uuid.UUID
    name: str
    key_prefix: str
    created_by: uuid.UUID | None
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None = None
    # Which mandate this key's ingested runs get tagged with — None only in
    # single_tenant mode. Exposed so a holding_admin (who can see every
    # mandate's keys, via RLS bypass) can actually tell them apart; this was
    # a real gap before — the dashboard's API key list had no way to show,
    # or let anyone audit, which mandate an existing key belonged to.
    mandant_id: uuid.UUID | None = None

    model_config = {"from_attributes": True}


class ApiKeyCreateResponse(ApiKeyOut):
    """Returned only on creation — includes the raw key (shown once)."""
    raw_key: str


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    # Explicit target mandate — holding_admin only (see create_api_key).
    # Omitted (the common case): falls back to the acting user's own
    # effective mandate, same as before this field existed. Lets a
    # holding_admin create a mandate-specific key directly, instead of the
    # only previously-available path (switch the dashboard's Global Context
    # Switcher into that mandate first, *then* create the key, with no
    # indication anywhere of which mandate the result would actually get).
    mandant_id: uuid.UUID | None = None


@router.get("/api-keys", response_model=list[ApiKeyOut])
async def list_api_keys(
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> list[ApiKey]:
    """List all DB-stored API keys (admin only)."""
    result = await db.execute(select(ApiKey).order_by(ApiKey.created_at))
    return list(result.scalars().all())


@router.post("/api-keys", response_model=ApiKeyCreateResponse, status_code=201)
async def create_api_key(
    payload: ApiKeyCreate,
    acting_user: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> dict:
    """Generate a new API key (admin only). The raw key is returned once — store it securely.

    ``payload.mandant_id`` lets a holding_admin target a *specific* mandate
    directly, rather than the only previously-available path (switch the
    dashboard's Global Context Switcher into that mandate, then create the
    key with no visible confirmation of which mandate it would land on).
    Holding_admin-only: an ordinary admin explicitly naming a mandate other
    than their own would be a privilege-escalation path (minting a key for
    data they can't otherwise see), not a convenience.
    """
    target_mandant_id = auth.mandant_id
    if payload.mandant_id is not None:
        if not auth.is_holding_admin:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail="Only a holding_admin can target a specific mandant_id when creating an API key.",
            )
        target_mandant = await db.get(Mandant, payload.mandant_id)
        if target_mandant is None or not target_mandant.is_active:
            raise HTTPException(400, detail="Unknown or inactive mandant_id.")
        target_mandant_id = payload.mandant_id
    # Unlike users/user_audit_logs, api_keys.mandant_id is NOT exempted from
    # NOT NULL once activated (Phase 1) — a mandate-less key would have no
    # mandate to tag ingested runs with, which defeats its purpose. A
    # holding-only admin (no personal mandate) with no explicit
    # payload.mandant_id has nothing sensible to fall back to; reject
    # cleanly rather than crash with a raw NotNullViolationError.
    if target_mandant_id is None:
        raise HTTPException(
            400, detail="A holding-only admin has no mandate to tag this key with. Pass mandant_id explicitly."
        )
    raw_key = "wombat_" + secrets.token_hex(24)
    key_hash = _hash(raw_key)
    key_prefix = raw_key[:16]

    api_key = ApiKey(
        name=payload.name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        created_by=acting_user.id,
        is_active=True,
        mandant_id=target_mandant_id,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    return {
        "id": api_key.id,
        "name": api_key.name,
        "key_prefix": api_key.key_prefix,
        "created_by": api_key.created_by,
        "is_active": api_key.is_active,
        "created_at": api_key.created_at,
        "last_used_at": api_key.last_used_at,
        "mandant_id": api_key.mandant_id,
        "raw_key": raw_key,
    }


@router.delete("/api-keys/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: uuid.UUID,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> None:
    """Revoke (deactivate) a DB-stored API key (admin only)."""
    api_key = await db.get(ApiKey, key_id)
    if api_key is None:
        raise HTTPException(404, detail="API key not found.")
    api_key.is_active = False
    await db.commit()


class ApiKeyUsageLogOut(BaseModel):
    id: uuid.UUID
    used_at: datetime
    endpoint: str
    run_id: uuid.UUID | None
    project: str
    branch: str
    score: int | None
    ip: str

    model_config = {"from_attributes": True}


@router.get("/api-keys/{key_id}/logs", response_model=list[ApiKeyUsageLogOut])
async def get_api_key_logs(
    key_id: uuid.UUID,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    limit: int = 50,
) -> list[ApiKeyUsageLog]:
    """Return the most recent usage log entries for a specific API key (admin only)."""
    api_key = await db.get(ApiKey, key_id)
    if api_key is None:
        raise HTTPException(404, detail="API key not found.")
    result = await db.execute(
        select(ApiKeyUsageLog)
        .where(ApiKeyUsageLog.api_key_id == key_id)
        .order_by(ApiKeyUsageLog.used_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())
