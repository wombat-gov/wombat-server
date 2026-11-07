"""CSRF protection for cookie-authenticated unsafe requests.

Bearer-authenticated requests (CLI/CI) are exempt: they do not rely on ambient
credentials. Login is exempt because there is no session yet, but its Origin is
still validated by the CORS configuration.
"""
from __future__ import annotations

import re
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from wombat_server.auth.cookies import ACCESS_COOKIE, CSRF_COOKIE, REFRESH_COOKIE
from wombat_server.config import settings

_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# These endpoints accept an explicit refresh token in the body for CLI/CI.
# The refresh cookie is SameSite=Strict and path-scoped; the dashboard still
# sends the CSRF header, but enforcing it here would break the dual-mode
# Bearer flow during the cookie migration window.
_EXEMPT_PATHS = {
    "/api/v1/auth/login",
    "/api/v1/auth/refresh",
    "/api/v1/auth/logout",
    # MFA challenge carries a short-lived mfa_token, not ambient credentials.
    "/api/v1/auth/mfa/challenge",
    # Device flow endpoints do not use ambient cookie credentials: the app
    # is unauthenticated when it starts/polls, and the browser approval form
    # performs its own double-submit check with a hidden field (browsers
    # cannot set X-CSRF-Token on a plain form).
    "/api/v1/auth/device/start",
    "/api/v1/auth/device/token",
    "/api/v1/auth/device/approve",
}

_LOCAL_ORIGIN_RE = re.compile(
    r"^https?://(localhost|127\.0\.0\.1|cloud\.waf2p)(:\d+)?$"
)


def _origin_allowed(origin: str) -> bool:
    if origin in settings.cors_origins_list:
        return True
    return settings.wombat_env == "local" and bool(_LOCAL_ORIGIN_RE.match(origin))


class CSRFMiddleware(BaseHTTPMiddleware):
    """Require a double-submit CSRF token for cookie-auth unsafe requests."""

    async def dispatch(self, request: Request, call_next):
        if (
            not settings.wombat_csrf_enabled
            or request.method not in _UNSAFE_METHODS
            or request.url.path in _EXEMPT_PATHS
        ):
            return await call_next(request)

        # Explicit bearer credentials are not ambient; CSRF does not apply.
        if request.headers.get("authorization"):
            return await call_next(request)

        has_session = request.cookies.get(ACCESS_COOKIE) or request.cookies.get(REFRESH_COOKIE)
        if not has_session:
            return await call_next(request)

        cookie_token = request.cookies.get(CSRF_COOKIE)
        header_token = request.headers.get("x-csrf-token")
        if not cookie_token or not header_token or not secrets.compare_digest(cookie_token, header_token):
            return JSONResponse({"detail": "CSRF validation failed."}, status_code=403)

        origin = request.headers.get("origin")
        if origin and not _origin_allowed(origin):
            return JSONResponse({"detail": "Origin not allowed."}, status_code=403)

        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Defense-in-depth headers on every API response.

    The edge proxy sets the browser-facing CSP and HSTS; these headers make the
    API safe even if it is reached directly inside the private network.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), interest-cohort=()",
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        return response
