"""Unit tests for Wave 1 security primitives.

These do not need a database: password policy, cookie attributes, CSRF
middleware, the rate limiter, and trusted-proxy IP resolution.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.responses import Response
from fastapi.testclient import TestClient
from starlette.requests import Request

from wombat_server.auth.cookies import (
    ACCESS_COOKIE,
    CSRF_COOKIE,
    REFRESH_COOKIE,
    set_session_cookies,
)
from wombat_server.auth.csrf import CSRFMiddleware
from wombat_server.auth.password_policy import PasswordPolicyError, validate_password
from wombat_server.auth.rate_limit import RateLimiter
from wombat_server.routers.auth import _ip


class TestPasswordPolicy:
    def test_rejects_short_password(self) -> None:
        with pytest.raises(PasswordPolicyError, match="at least 12"):
            validate_password("short", "alice")

    def test_rejects_common_password(self) -> None:
        with pytest.raises(PasswordPolicyError, match="too common"):
            validate_password("password1234", "alice")

    def test_rejects_username_reuse(self) -> None:
        with pytest.raises(PasswordPolicyError, match="username"):
            validate_password("alicealicealice", "alicealicealice")

    def test_rejects_single_character_class(self) -> None:
        with pytest.raises(PasswordPolicyError, match="mix letters"):
            validate_password("123456789012", "alice")

    def test_accepts_reasonable_password(self) -> None:
        validate_password("correct-horse-battery", "alice")


class TestSessionCookies:
    def test_access_and_csrf_attributes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from wombat_server.config import settings
        monkeypatch.setattr(settings, "wombat_cookie_secure", True)
        response = Response()
        set_session_cookies(response, "access-token", "refresh-token")
        cookies = response.headers.getlist("set-cookie")

        access = next(h for h in cookies if h.startswith(f"{ACCESS_COOKIE}="))
        assert "HttpOnly" in access
        assert "Secure" in access
        assert "SameSite=lax" in access
        assert "Path=/" in access

        refresh = next(h for h in cookies if h.startswith(f"{REFRESH_COOKIE}="))
        assert "HttpOnly" in refresh
        assert "Path=/api/v1/auth" in refresh
        assert "SameSite=strict" in refresh

        csrf = next(h for h in cookies if h.startswith(f"{CSRF_COOKIE}="))
        assert "HttpOnly" not in csrf
        assert "Secure" in csrf


def _csrf_client() -> TestClient:
    app = FastAPI()
    app.add_middleware(CSRFMiddleware)

    @app.post("/mutate")
    def mutate() -> dict[str, bool]:
        return {"ok": True}

    return TestClient(app)


class TestCSRFMiddleware:
    def test_request_without_session_is_allowed(self) -> None:
        client = _csrf_client()
        assert client.post("/mutate").status_code == 200

    def test_cookie_session_without_csrf_is_rejected(self) -> None:
        client = _csrf_client()
        client.cookies.set(ACCESS_COOKIE, "session")
        assert client.post("/mutate").status_code == 403

    def test_cookie_session_with_matching_csrf_is_allowed(self) -> None:
        client = _csrf_client()
        client.cookies.set(ACCESS_COOKIE, "session")
        client.cookies.set(CSRF_COOKIE, "token")
        response = client.post("/mutate", headers={"X-CSRF-Token": "token"})
        assert response.status_code == 200

    def test_bearer_requests_are_exempt(self) -> None:
        client = _csrf_client()
        client.cookies.set(ACCESS_COOKIE, "session")
        client.cookies.set(CSRF_COOKIE, "token")
        response = client.post("/mutate", headers={"Authorization": "Bearer cli"})
        assert response.status_code == 200

    def test_foreign_origin_is_rejected(self) -> None:
        client = _csrf_client()
        client.cookies.set(ACCESS_COOKIE, "session")
        client.cookies.set(CSRF_COOKIE, "token")
        response = client.post(
            "/mutate",
            headers={"X-CSRF-Token": "token", "Origin": "https://evil.example"},
        )
        assert response.status_code == 403


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_sliding_window_and_reset(self) -> None:
        limiter = RateLimiter("test", limit=2, window_seconds=60)
        assert await limiter.allow("client")
        assert await limiter.allow("client")
        assert not await limiter.allow("client")
        await limiter.reset("client")
        assert await limiter.allow("client")


class TestTrustedProxyIp:
    def test_ignores_spoofed_forwarded_for(self) -> None:
        request = Request({
            "type": "http",
            "client": ("1.2.3.4", 12345),
            "headers": [(b"x-forwarded-for", b"9.9.9.9")],
        })
        assert _ip(request) == "1.2.3.4"
