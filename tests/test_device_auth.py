"""Wave D: desktop device authorization tests."""
from __future__ import annotations

import hashlib
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import text

from tests.conftest import MandantTestDb
from tests.test_mandants import seed_user


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


@pytest.fixture(autouse=True)
def _clear_rate_limits():
    from wombat_server.routers.device_auth import poll_ip_limiter, start_ip_limiter

    start_ip_limiter._hits.clear()
    poll_ip_limiter._hits.clear()
    yield
    start_ip_limiter._hits.clear()
    poll_ip_limiter._hits.clear()


async def _start(client: AsyncClient, name: str = "WOMBATpass Desktop (test)") -> dict:
    response = await client.post(
        "/api/v1/auth/device/start",
        json={"device_name": name, "client": "test"},
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _login(client: AsyncClient, username: str, password: str) -> None:
    response = await client.post(
        "/api/v1/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text


async def _approve(client: AsyncClient, user_code: str, action: str = "approve") -> object:
    csrf = client.cookies.get("wombat_csrf")
    assert csrf
    return await client.post(
        "/api/v1/auth/device/approve",
        data={"user_code": user_code, "action": action, "csrf": csrf},
    )


async def _issue_token(client: AsyncClient, device_code: str) -> dict:
    response = await client.post(
        "/api/v1/auth/device/token", json={"device_code": device_code}
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_device_start_returns_code_and_verification_url(app_client: AsyncClient) -> None:
    started = await _start(app_client)

    assert len(started["device_code"]) > 20
    assert len(started["user_code"]) == 9 and started["user_code"][4] == "-"
    assert started["expires_in"] > 0
    assert started["interval"] >= 1
    assert "/api/v1/auth/device/verify?user_code=" in started["verification_url"]
    assert started["user_code"] in started["verification_url"]


@pytest.mark.asyncio
async def test_device_start_validation(app_client: AsyncClient) -> None:
    blank = await app_client.post("/api/v1/auth/device/start", json={"device_name": "   "})
    assert blank.status_code == 400
    too_long = await app_client.post(
        "/api/v1/auth/device/start", json={"device_name": "x" * 101}
    )
    assert too_long.status_code == 422


@pytest.mark.asyncio
async def test_disabled_returns_404(app_client: AsyncClient, monkeypatch) -> None:
    from wombat_server.config import settings

    monkeypatch.setattr(settings, "wombat_device_auth_enabled", False)
    response = await app_client.post(
        "/api/v1/auth/device/start", json={"device_name": "desktop"}
    )
    assert response.status_code == 404
    assert (
        await app_client.get("/api/v1/auth/device/verify", params={"user_code": "AAAA-BBBB"})
    ).status_code == 404


@pytest.mark.asyncio
async def test_verify_page_requires_browser_session(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    started = await _start(app_client)
    page = await app_client.get(
        "/api/v1/auth/device/verify", params={"user_code": started["user_code"]}
    )
    assert page.status_code == 200
    assert "Sign in to approve this device" in page.text
    assert "Sign in to the dashboard" in page.text
    assert started["user_code"] in page.text

    # Approval without a browser session must not work, even with a CSRF value.
    denied = await app_client.post(
        "/api/v1/auth/device/approve",
        data={"user_code": started["user_code"], "action": "approve", "csrf": "nope"},
    )
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_full_device_flow_list_and_revoke(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    await seed_user(mandant_db, username="device-admin", role="admin", password="correct-horse")
    await _login(app_client, "device-admin", "correct-horse")

    started = await _start(app_client, "WOMBATpass Desktop (macOS)")
    page = await app_client.get(
        "/api/v1/auth/device/verify", params={"user_code": started["user_code"]}
    )
    assert page.status_code == 200
    assert "Approve this device?" in page.text
    assert "device-admin" in page.text

    approved = await _approve(app_client, started["user_code"])
    assert approved.status_code == 200, approved.text
    assert "Device approved" in approved.text

    issued = await _issue_token(app_client, started["device_code"])
    token = issued["device_token"]
    assert token.startswith("wombat_dev_")
    assert issued["user"]["username"] == "device-admin"
    assert issued["device"]["name"] == "WOMBATpass Desktop (macOS)"

    headers = {"Authorization": f"Bearer {token}"}
    me = await app_client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["username"] == "device-admin"

    listing = await app_client.get("/api/v1/auth/devices", headers=headers)
    assert listing.status_code == 200
    devices = listing.json()["data"]
    assert len(devices) == 1
    assert devices[0]["current"] is True
    assert devices[0]["name"] == "WOMBATpass Desktop (macOS)"

    revoked = await app_client.delete(
        f"/api/v1/auth/devices/{devices[0]['id']}", headers=headers
    )
    assert revoked.status_code == 204
    assert (await app_client.get("/api/v1/auth/me", headers=headers)).status_code == 401

    # Reusing the one-time device code after exchange must fail.
    reuse = await app_client.post(
        "/api/v1/auth/device/token", json={"device_code": started["device_code"]}
    )
    assert reuse.status_code == 400
    assert reuse.json()["detail"] == "invalid_grant"


@pytest.mark.asyncio
async def test_pending_and_denied_codes(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    await seed_user(mandant_db, username="device-denier", role="engineer", password="correct-horse")
    await _login(app_client, "device-denier", "correct-horse")

    pending = await _start(app_client)
    response = await app_client.post(
        "/api/v1/auth/device/token", json={"device_code": pending["device_code"]}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "authorization_pending"

    denied = await _approve(app_client, pending["user_code"], action="deny")
    assert denied.status_code == 200
    assert "Request denied" in denied.text

    response = await app_client.post(
        "/api/v1/auth/device/token", json={"device_code": pending["device_code"]}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "access_denied"


@pytest.mark.asyncio
async def test_expired_code(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    await seed_user(mandant_db, username="device-expiry", role="engineer", password="correct-horse")
    await _login(app_client, "device-expiry", "correct-horse")
    started = await _start(app_client)

    async with mandant_db.owner_sessionmaker() as session:
        await session.execute(
            text("UPDATE device_codes SET expires_at = now() - interval '1 minute' WHERE code_hash = :h"),
            {"h": _hash(started["device_code"])},
        )
        await session.commit()

    response = await app_client.post(
        "/api/v1/auth/device/token", json={"device_code": started["device_code"]}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "expired_token"

    page = await app_client.get(
        "/api/v1/auth/device/verify", params={"user_code": started["user_code"]}
    )
    assert page.status_code == 410


@pytest.mark.asyncio
async def test_device_cannot_revoke_another_users_device(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    await seed_user(mandant_db, username="device-a", role="engineer", password="correct-horse")
    await _login(app_client, "device-a", "correct-horse")
    started = await _start(app_client)
    await _approve(app_client, started["user_code"])
    issued = await _issue_token(app_client, started["device_code"])
    headers = {"Authorization": f"Bearer {issued['device_token']}"}

    other_user_id = await seed_user(
        mandant_db, username="device-b", role="engineer", password="correct-horse"
    )
    other_id = uuid.uuid4()
    async with mandant_db.owner_sessionmaker() as session:
        await session.execute(
            text(
                "INSERT INTO devices (id, user_id, name, token_hash) "
                "VALUES (:id, :user_id, 'other', :hash)"
            ),
            {"id": other_id, "user_id": other_user_id, "hash": _hash("other-token")},
        )
        await session.commit()

    response = await app_client.delete(
        f"/api/v1/auth/devices/{other_id}", headers=headers
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_start_rate_limit(app_client: AsyncClient) -> None:
    from wombat_server.routers.device_auth import start_ip_limiter

    original_limit = start_ip_limiter.limit
    start_ip_limiter.limit = 2
    try:
        assert (await app_client.post(
            "/api/v1/auth/device/start", json={"device_name": "one"}
        )).status_code == 200
        assert (await app_client.post(
            "/api/v1/auth/device/start", json={"device_name": "two"}
        )).status_code == 200
        limited = await app_client.post(
            "/api/v1/auth/device/start", json={"device_name": "three"}
        )
        assert limited.status_code == 429
        assert limited.headers.get("retry-after")
    finally:
        start_ip_limiter.limit = original_limit
