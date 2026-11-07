"""HttpOnly browser session cookies and CSRF token helpers.

The dashboard never stores bearer tokens. Login/refresh set these cookies; the
Bearer header path remains for CLI and CI clients.
"""
from __future__ import annotations

import secrets

from fastapi import Response

from wombat_server.config import settings

ACCESS_COOKIE = "wombat_access"
REFRESH_COOKIE = "wombat_refresh"
CSRF_COOKIE = "wombat_csrf"
REFRESH_PATH = "/api/v1/auth"


def _base_kwargs() -> dict:
    kwargs: dict = {
        "secure": settings.wombat_cookie_secure,
        "samesite": settings.wombat_cookie_samesite,
    }
    if settings.wombat_cookie_domain:
        kwargs["domain"] = settings.wombat_cookie_domain
    return kwargs


def set_session_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
) -> None:
    """Set access, refresh, and CSRF cookies on *response*."""
    base = _base_kwargs()
    refresh_samesite = base["samesite"]
    # The refresh cookie is scoped to the auth endpoints. Strict is safe for
    # same-site fetch calls and is a second line of defense behind CSRF.
    if refresh_samesite == "lax":
        refresh_samesite = "strict"

    response.set_cookie(
        ACCESS_COOKIE,
        access_token,
        max_age=settings.wombat_jwt_expire_minutes * 60,
        path="/",
        httponly=True,
        **base,
    )
    response.set_cookie(
        REFRESH_COOKIE,
        refresh_token,
        max_age=settings.wombat_jwt_refresh_days * 86_400,
        path=REFRESH_PATH,
        httponly=True,
        **{**base, "samesite": refresh_samesite},
    )
    response.set_cookie(
        CSRF_COOKIE,
        secrets.token_urlsafe(32),
        max_age=settings.wombat_jwt_refresh_days * 86_400,
        path="/",
        httponly=False,
        **base,
    )


def clear_session_cookies(response: Response) -> None:
    """Delete all session cookies using matching paths/attributes."""
    base = _base_kwargs()
    response.delete_cookie(ACCESS_COOKIE, path="/", **base)
    response.delete_cookie(REFRESH_COOKIE, path=REFRESH_PATH, **base)
    response.delete_cookie(CSRF_COOKIE, path="/", **base)
