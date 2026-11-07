"""Desktop device authorization (Wave D).

RFC 8628-style flow:

1. ``POST /auth/device/start`` (unauthenticated, rate-limited) returns a raw
   device code, a short human user code, and a browser verification URL.
2. The user opens the URL and approves the request with their normal browser
   session (cookie auth, CSRF-protected form). The page is server-rendered so
   remote/SSO deployments do not need a dashboard route for it.
3. ``POST /auth/device/token`` exchanges the approved, one-time device code for
   an opaque long-lived device token. Only its SHA-256 hash is stored.
4. ``get_current_user`` accepts that token as a Bearer credential; the user and
   role are re-resolved on every request, and ``GET/DELETE /auth/devices`` lets
   the owner list and revoke tokens.

Device codes and devices are authentication-bootstrap tables (like sessions),
so they are not RLS-enabled; every device query is scoped by ``user_id``.
"""
from __future__ import annotations

import hashlib
import html
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from wombat_server.audit_chain import chain_event
from wombat_server.auth.cookies import ACCESS_COOKIE, CSRF_COOKIE
from wombat_server.auth.deps import (
    AuthContext,
    adopt_mandate_of,
    get_auth_context,
    get_scoped_db,
    load_user_by_id,
)
from wombat_server.auth.jwt_utils import decode_access_token
from wombat_server.auth.rate_limit import RateLimiter
from wombat_server.config import settings
from wombat_server.database import get_db
from wombat_server.models import Device, DeviceCode, User, UserAuditLog
from wombat_server.schemas import (
    DeviceOut,
    DeviceStartRequest,
    DeviceStartResponse,
    DeviceTokenRequest,
    DeviceTokenResponse,
    DeviceUserOut,
    Envelope,
    Meta,
)
from wombat_server.syslog import emit_admin_audit_event

router = APIRouter(prefix="/auth", tags=["auth"])

USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
DEVICE_TOKEN_PREFIX = "wombat_dev_"
_PENDING_DETAIL = "authorization_pending"

start_ip_limiter = RateLimiter(
    "device-start-ip",
    settings.wombat_device_start_ip_limit,
    settings.wombat_device_start_ip_window_seconds,
)
poll_ip_limiter = RateLimiter(
    "device-poll-ip",
    settings.wombat_device_poll_ip_limit,
    settings.wombat_device_poll_ip_window_seconds,
)


def _hash(raw: str) -> str:
    # Device codes/tokens are high-entropy secrets, not passwords; SHA-256 is
    # the correct lookup index (same rationale as refresh_tokens/API keys).
    return hashlib.sha256(raw.encode()).hexdigest()


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _ip_hash(request: Request) -> str:
    return hashlib.sha256(_ip(request).encode()).hexdigest()


def _clean_text(raw: str, limit: int) -> str:
    text = "".join(char for char in raw if char.isprintable()).strip()
    return " ".join(text.split())[:limit]


def _new_user_code() -> str:
    left = "".join(secrets.choice(USER_CODE_ALPHABET) for _ in range(4))
    right = "".join(secrets.choice(USER_CODE_ALPHABET) for _ in range(4))
    return f"{left}-{right}"


def _normalize_user_code(raw: str) -> str:
    value = "".join(char for char in raw.upper() if char.isalnum())
    if len(value) != 8:
        return ""
    return f"{value[:4]}-{value[4:]}"


def _base_url(request: Request) -> str:
    if settings.wombat_public_url:
        return settings.wombat_public_url.rstrip("/")
    return str(request.base_url).rstrip("/")


def _dashboard_url(request: Request) -> str:
    if settings.wombat_dashboard_url:
        return settings.wombat_dashboard_url.rstrip("/")
    if settings.wombat_public_url:
        return settings.wombat_public_url.rstrip("/")
    if settings.wombat_env == "local":
        return "http://localhost:3000"
    return _base_url(request)


def _verify_url(request: Request, user_code: str) -> str:
    return f"{_base_url(request)}/api/v1/auth/device/verify?user_code={quote(user_code)}"


def _page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{html.escape(title)}</title>
<style>
  :root {{ color-scheme: dark; --bg:#0b0f14; --surface:#141a22; --border:#2a3442;
          --text:#e6edf5; --muted:#93a3b5; --accent:#4f8cff; --ok:#3fb950; --err:#f85149; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         padding:24px; background:var(--bg); color:var(--text);
         font:14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
  .card {{ width:100%; max-width:440px; background:var(--surface); border:1px solid var(--border);
          border-radius:14px; padding:26px; box-shadow:0 18px 50px rgba(0,0,0,.45); }}
  .brand {{ color:var(--muted); font-size:10px; font-weight:700; letter-spacing:.16em;
           text-transform:uppercase; margin:0 0 10px; }}
  h1 {{ margin:0 0 10px; font-size:20px; }}
  p {{ margin:0 0 12px; color:var(--muted); }}
  .code {{ margin:18px 0; padding:12px; text-align:center; border:1px dashed var(--border);
          border-radius:10px; font:700 24px ui-monospace, SFMono-Regular, Menlo, monospace;
          letter-spacing:.12em; color:var(--text); }}
  .device {{ margin:14px 0; padding:12px; border-radius:10px; background:#10161e;
            border:1px solid var(--border); }}
  .device strong {{ color:var(--text); }}
  .device span {{ color:var(--muted); font-size:12px; display:block; }}
  .actions {{ display:flex; gap:10px; margin-top:20px; }}
  button, .button {{ flex:1; display:inline-block; text-align:center; padding:10px 14px;
          border-radius:9px; border:1px solid var(--border); background:#1b232d; color:var(--text);
          font:inherit; font-weight:600; cursor:pointer; text-decoration:none; }}
  button.primary {{ background:var(--accent); border-color:var(--accent); color:#fff; }}
  button.danger {{ color:var(--err); }}
  .ok {{ color:var(--ok); }}
  .err {{ color:var(--err); }}
  .foot {{ margin-top:18px; font-size:11px; color:var(--muted); }}
</style>
</head>
<body><main class="card"><div class="brand">WOMBATpass</div>{body}</main></body>
</html>"""
    return HTMLResponse(
        document,
        status_code=status_code,
        headers={
            "Content-Security-Policy": (
                "default-src 'none'; style-src 'unsafe-inline'; "
                "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
            ),
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
        },
    )


async def _audit(
    db: AsyncSession,
    actor_id: uuid.UUID | None,
    action: str,
    detail: dict,
    ip: str,
    mandant_id: uuid.UUID | None,
) -> None:
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


async def _cookie_user(request: Request, db: AsyncSession) -> User | None:
    token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        return None
    try:
        payload = decode_access_token(token)
        if payload.get("type") != "access":
            return None
        user = await load_user_by_id(db, uuid.UUID(payload["sub"]))
    except Exception:
        return None
    if user is None or not user.is_active:
        return None
    return user


async def _find_code(db: AsyncSession, user_code: str) -> DeviceCode | None:
    normalized = _normalize_user_code(user_code)
    if not normalized:
        return None
    return (
        await db.execute(select(DeviceCode).where(DeviceCode.user_code == normalized))
    ).scalar_one_or_none()


def _state_error(code: DeviceCode, now: datetime) -> str | None:
    if code.denied_at is not None:
        return "denied"
    if code.consumed_at is not None:
        return "used"
    if code.expires_at <= now:
        return "expired"
    return None


@router.post("/device/start", response_model=DeviceStartResponse)
async def device_start(
    request: Request,
    payload: DeviceStartRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DeviceStartResponse:
    if not settings.wombat_device_auth_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Device authorization is disabled.")
    if not await start_ip_limiter.allow(_ip(request)):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many device authorization requests. Try again later.",
            headers={"Retry-After": str(settings.wombat_device_start_ip_window_seconds)},
        )

    device_name = _clean_text(payload.device_name, 100)
    if not device_name:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="device_name must not be blank.")

    now = datetime.now(timezone.utc)
    # Opportunistic cleanup; expired codes are useless after a day.
    await db.execute(
        delete(DeviceCode).where(DeviceCode.expires_at < now - timedelta(days=1))
    )

    raw_code = secrets.token_urlsafe(32)
    code_hash = _hash(raw_code)
    expires_at = now + timedelta(seconds=settings.wombat_device_code_ttl_seconds)

    for _attempt in range(5):
        user_code = _new_user_code()
        code = DeviceCode(
            code_hash=code_hash,
            user_code=user_code,
            device_name=device_name,
            client=_clean_text(payload.client, 100),
            expires_at=expires_at,
            ip_hash=_ip_hash(request),
            user_agent=str(request.headers.get("user-agent", ""))[:500],
        )
        db.add(code)
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            continue
        return DeviceStartResponse(
            device_code=raw_code,
            user_code=user_code,
            verification_url=_verify_url(request, user_code),
            interval=max(1, settings.wombat_device_poll_interval),
            expires_in=max(1, settings.wombat_device_code_ttl_seconds),
        )

    raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="Could not allocate a device code.")


@router.get("/device/verify", response_class=HTMLResponse)
async def device_verify(
    request: Request,
    user_code: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> HTMLResponse:
    """Browser approval page. Signed-out users are pointed at the dashboard
    login; signed-in users get Approve/Deny buttons."""
    if not settings.wombat_device_auth_enabled:
        return _page("Not available", "<h1>Device sign-in is not enabled</h1>", 404)

    code = await _find_code(db, user_code)
    if code is None:
        return _page(
            "Unknown code",
            "<h1 class='err'>Unknown or malformed code</h1>"
            "<p>Check the code shown by WOMBATpass and try again.</p>",
            404,
        )

    now = datetime.now(timezone.utc)
    state = _state_error(code, now)
    if state == "expired":
        return _page("Expired", "<h1 class='err'>This code has expired</h1>"
                     "<p>Start the sign-in again from WOMBATpass.</p>", 410)
    if state == "denied":
        return _page("Denied", "<h1 class='err'>This request was denied</h1>", 410)
    if state == "used":
        return _page("Already used", "<h1>This code has already been used</h1>", 410)
    if code.approved_at is not None:
        return _page("Approved", "<h1 class='ok'>This device is already approved</h1>"
                     "<p>Return to WOMBATpass; it will finish signing in automatically.</p>")

    user = await _cookie_user(request, db)
    device_box = (
        "<div class='device'><strong>Device</strong>"
        f"<span>{html.escape(code.device_name or 'WOMBATpass Desktop')}</span>"
        f"<span>Requested {html.escape(code.created_at.strftime('%Y-%m-%d %H:%M UTC'))}</span>"
        "</div>"
    )

    if user is None:
        dashboard = _dashboard_url(request)
        retry = f"{request.url.path}?user_code={quote(code.user_code)}"
        return _page(
            "Sign in to approve",
            "<h1>Sign in to approve this device</h1>"
            "<p>WOMBATpass wants to sign in as you. First sign in to the dashboard "
            "in this browser, then approve the request.</p>"
            f"{device_box}"
            f"<p>Your code: <strong>{html.escape(code.user_code)}</strong></p>"
            f"<div class='actions'><a class='button primary' href='{html.escape(dashboard)}/#/login'>"
            "Sign in to the dashboard</a></div>"
            f"<form method='get' action='{html.escape(request.url.path)}' class='actions'>"
            f"<input type='hidden' name='user_code' value='{html.escape(code.user_code)}' />"
            "<button type='submit'>I've signed in — reload</button></form>"
            f"<p class='foot'>After signing in, return to this page:<br>{html.escape(str(request.url))}</p>",
        )

    csrf = request.cookies.get(CSRF_COOKIE, "")
    if not csrf:
        return _page(
            "Session error",
            "<h1 class='err'>Your session has no CSRF token</h1>"
            "<p>Sign out of the dashboard and sign in again, then reload this page.</p>",
            400,
        )

    await adopt_mandate_of(
        db, user.mandant_id,
        is_holding_admin=user.holding_role == "holding_admin",
        is_holding_viewer=user.holding_role == "holding_viewer",
    )

    return _page(
        "Approve device",
        f"<h1>Approve this device?</h1>"
        f"<p>WOMBATpass is requesting access as <strong>{html.escape(user.username)}</strong>.</p>"
        f"{device_box}"
        f"<p>Your code: <strong class='code'>{html.escape(code.user_code)}</strong></p>"
        f"<form method='post' action='/api/v1/auth/device/approve'>"
        f"<input type='hidden' name='csrf' value='{html.escape(csrf)}' />"
        f"<input type='hidden' name='user_code' value='{html.escape(code.user_code)}' />"
        "<div class='actions'>"
        "<button type='submit' name='action' value='deny' class='danger'>Deny</button>"
        "<button type='submit' name='action' value='approve' class='primary'>Approve</button>"
        "</div></form>"
        "<p class='foot'>Only approve this if you started the sign-in in WOMBATpass. "
        "The device will receive a revocable token.</p>",
    )


@router.post("/device/approve", response_class=HTMLResponse)
async def device_approve(
    request: Request,
    user_code: Annotated[str, Form()],
    action: Annotated[str, Form()],
    csrf: Annotated[str, Form()],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> HTMLResponse:
    """Approve or deny a pending code. Cookie-authenticated and CSRF-protected.

    The CSRF middleware exempts this path because an HTML form cannot set the
    X-CSRF-Token header; the same double-submit check is done here using the
    hidden form field and the non-HttpOnly ``wombat_csrf`` cookie.
    """
    if not settings.wombat_device_auth_enabled:
        return _page("Not available", "<h1>Device sign-in is not enabled</h1>", 404)

    cookie_csrf = request.cookies.get(CSRF_COOKIE, "")
    if not cookie_csrf or not csrf or not secrets.compare_digest(cookie_csrf, csrf):
        return _page("CSRF", "<h1 class='err'>Security check failed</h1>"
                     "<p>Reload the page and try again.</p>", 403)

    user = await _cookie_user(request, db)
    if user is None:
        return _page("Sign in required", "<h1>Sign in required</h1>"
                     "<p>Your browser session expired. Sign in again and reload the approval page.</p>", 401)

    code = await _find_code(db, user_code)
    if code is None:
        return _page("Unknown code", "<h1 class='err'>Unknown or malformed code</h1>", 404)

    now = datetime.now(timezone.utc)
    state = _state_error(code, now)
    if state is not None:
        label = {
            "expired": "This code has expired",
            "denied": "This request was already denied",
            "used": "This code has already been used",
        }[state]
        return _page("Code unavailable", f"<h1 class='err'>{label}</h1>", 410)

    await adopt_mandate_of(
        db, user.mandant_id,
        is_holding_admin=user.holding_role == "holding_admin",
        is_holding_viewer=user.holding_role == "holding_viewer",
    )

    if action != "approve":
        code.denied_at = now
        await _audit(
            db, user.id, "device.denied",
            {"user_code": code.user_code, "device_name": code.device_name},
            _ip(request), user.mandant_id,
        )
        await db.commit()
        return _page("Denied", "<h1>Request denied</h1>"
                     "<p>WOMBATpass was not signed in. You can close this page.</p>")

    if code.approved_at is not None:
        return _page("Approved", "<h1 class='ok'>Already approved</h1>"
                     "<p>Return to WOMBATpass.</p>")

    code.approved_by = user.id
    code.approved_at = now
    await _audit(
        db, user.id, "device.approve",
        {"user_code": code.user_code, "device_name": code.device_name},
        _ip(request), user.mandant_id,
    )
    await db.commit()

    return _page(
        "Device approved",
        "<h1 class='ok'>Device approved</h1>"
        f"<p><strong>{html.escape(code.device_name or 'WOMBATpass Desktop')}</strong> "
        "can now finish signing in.</p>"
        "<p>You can close this page and return to WOMBATpass.</p>",
    )


@router.post("/device/token", response_model=DeviceTokenResponse)
async def device_token(
    request: Request,
    payload: DeviceTokenRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DeviceTokenResponse:
    if not settings.wombat_device_auth_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Device authorization is disabled.")

    code_hash = _hash(payload.device_code)
    limiter_key = f"{_ip(request)}:{code_hash[:16]}"
    if not await poll_ip_limiter.allow(limiter_key):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many polls. Slow down.",
            headers={"Retry-After": str(settings.wombat_device_poll_interval)},
        )

    code = (
        await db.execute(select(DeviceCode).where(DeviceCode.code_hash == code_hash))
    ).scalar_one_or_none()
    if code is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid_grant")

    now = datetime.now(timezone.utc)
    if code.denied_at is not None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="access_denied")
    if code.consumed_at is not None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid_grant")
    if code.expires_at <= now:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="expired_token")
    if code.approved_at is None or code.approved_by is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=_PENDING_DETAIL,
            headers={"Retry-After": str(settings.wombat_device_poll_interval)},
        )

    # One-time exchange: lock the row, then re-check state under the lock.
    locked = (
        await db.execute(
            select(DeviceCode).where(DeviceCode.id == code.id).with_for_update()
        )
    ).scalar_one()
    if locked.consumed_at is not None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid_grant")
    if locked.approved_at is None or locked.approved_by is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=_PENDING_DETAIL)

    user = await load_user_by_id(db, locked.approved_by)
    if user is None or not user.is_active:
        locked.consumed_at = now
        await db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="access_denied")

    raw_token = f"{DEVICE_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"
    device = Device(
        user_id=user.id,
        name=locked.device_name,
        token_hash=_hash(raw_token),
        mandant_id=user.mandant_id,
        user_agent=locked.user_agent,
        ip_hash=_ip_hash(request),
    )
    locked.consumed_at = now
    db.add(device)
    await db.flush()

    await adopt_mandate_of(
        db, user.mandant_id,
        is_holding_admin=user.holding_role == "holding_admin",
        is_holding_viewer=user.holding_role == "holding_viewer",
    )
    await _audit(
        db, user.id, "device.token_issued",
        {"device_id": str(device.id), "device_name": device.name},
        _ip(request), user.mandant_id,
    )
    await db.commit()
    await db.refresh(device)

    return DeviceTokenResponse(
        device_token=raw_token,
        device=DeviceOut(
            id=device.id,
            name=device.name,
            created_at=device.created_at,
            last_used_at=device.last_used_at,
            revoked_at=device.revoked_at,
            current=False,
        ),
        user=DeviceUserOut(
            id=user.id,
            username=user.username,
            display_name=user.display_name,
            role=user.role,
        ),
    )


def _device_out(device: Device, current_id: str | None) -> DeviceOut:
    return DeviceOut(
        id=device.id,
        name=device.name,
        created_at=device.created_at,
        last_used_at=device.last_used_at,
        revoked_at=device.revoked_at,
        current=bool(current_id) and str(device.id) == current_id,
    )


@router.get("/devices", response_model=Envelope[list[DeviceOut]])
async def list_devices(
    request: Request,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> Envelope[list[DeviceOut]]:
    rows = (
        await db.execute(
            select(Device)
            .where(Device.user_id == auth.user.id)
            .order_by(Device.created_at.desc())
        )
    ).scalars().all()
    current_id = getattr(request.state, "device_id", None)
    return Envelope(
        data=[_device_out(device, current_id) for device in rows],
        meta=Meta(total=len(rows)),
    )


@router.delete("/devices/{device_id}", status_code=204)
async def revoke_device(
    request: Request,
    device_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> Response:
    device = (
        await db.execute(
            select(Device).where(
                Device.id == device_id,
                Device.user_id == auth.user.id,
            )
        )
    ).scalar_one_or_none()
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Device not found.")
    if device.revoked_at is None:
        device.revoked_at = datetime.now(timezone.utc)
        device.revoked_reason = "user"
        await _audit(
            db, auth.user.id, "device.revoke",
            {"device_id": str(device.id), "device_name": device.name},
            _ip(request), auth.mandant_id,
        )
        await db.commit()
    return Response(status_code=204)
