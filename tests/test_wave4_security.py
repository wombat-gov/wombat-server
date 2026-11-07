"""Wave 4 integration tests: sessions, TOTP MFA, SCIM, and audit integrity."""
from __future__ import annotations

import time
import uuid

import pyotp
import pytest
from sqlalchemy import text

from wombat_server.auth.providers.local import hash_password
from wombat_server.config import settings


async def seed_user(
    mandant_db,
    *,
    username: str = "alice",
    role: str = "admin",
    password: str = "correct-horse",
) -> uuid.UUID:
    user_id = uuid.uuid4()
    async with mandant_db.owner_sessionmaker() as session:
        await session.execute(
            text(
                "INSERT INTO users (id, username, display_name, role, auth_provider, "
                "password_hash, is_active, prefs, mandant_id, holding_role, "
                "must_change_password, failed_login_count, email, external_id) "
                "VALUES (:id, :username, :username, :role, 'local', :hash, true, "
                "'{}'::jsonb, NULL, NULL, false, 0, '', NULL)"
            ),
            {
                "id": user_id,
                "username": username,
                "role": role,
                "hash": hash_password(password),
            },
        )
        await session.commit()
    return user_id


def csrf_headers(client) -> dict[str, str]:
    token = client.cookies.get("wombat_csrf")
    return {"X-CSRF-Token": token} if token else {}


async def login(client, username="alice", password="correct-horse"):
    client.cookies.clear()
    return await client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )


async def test_login_creates_and_revokes_a_session(mandant_db, app_client) -> None:
    await seed_user(mandant_db)

    response = await login(app_client)
    assert response.status_code == 200, response.text

    response = await app_client.get("/api/v1/auth/sessions")
    assert response.status_code == 200, response.text
    sessions = response.json()
    assert len(sessions) == 1
    assert sessions[0]["current"] is True
    assert sessions[0]["label"]

    session_id = sessions[0]["id"]
    response = await app_client.delete(
        f"/api/v1/auth/sessions/{session_id}",
        headers=csrf_headers(app_client),
    )
    assert response.status_code == 204, response.text

    # The refresh cookie now points at a revoked family.
    response = await app_client.post("/api/v1/auth/refresh", json={})
    assert response.status_code == 401, response.text


async def test_totp_enrollment_and_login_challenge(mandant_db, app_client) -> None:
    await seed_user(mandant_db)

    response = await login(app_client)
    assert response.status_code == 200, response.text

    response = await app_client.post(
        "/api/v1/auth/mfa/totp/setup",
        json={"current_password": "correct-horse"},
        headers=csrf_headers(app_client),
    )
    assert response.status_code == 200, response.text
    secret = response.json()["secret"]

    totp = pyotp.TOTP(secret)
    response = await app_client.post(
        "/api/v1/auth/mfa/totp/verify",
        json={"code": totp.now()},
        headers=csrf_headers(app_client),
    )
    assert response.status_code == 200, response.text
    recovery_codes = response.json()["recovery_codes"]
    assert len(recovery_codes) == 10

    response = await login(app_client)
    assert response.status_code == 200, response.text
    challenge = response.json()
    assert challenge["mfa_required"] is True
    assert "totp" in challenge["methods"]

    next_code = totp.at((int(time.time()) // 30 + 1) * 30)
    response = await app_client.post(
        "/api/v1/auth/mfa/challenge",
        json={"mfa_token": challenge["mfa_token"], "code": next_code, "method": "totp"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["user"]["username"] == "alice"

    # A recovery code is single-use.
    response = await login(app_client)
    challenge = response.json()
    response = await app_client.post(
        "/api/v1/auth/mfa/challenge",
        json={"mfa_token": challenge["mfa_token"], "code": recovery_codes[0], "method": "recovery"},
    )
    assert response.status_code == 200, response.text

    response = await login(app_client)
    challenge = response.json()
    response = await app_client.post(
        "/api/v1/auth/mfa/challenge",
        json={"mfa_token": challenge["mfa_token"], "code": recovery_codes[0], "method": "recovery"},
    )
    assert response.status_code == 401, response.text


async def test_audit_chain_detects_tampering(mandant_db, app_client) -> None:
    await seed_user(mandant_db)
    response = await login(app_client)
    assert response.status_code == 200, response.text

    response = await app_client.post(
        "/api/v1/audit/events",
        json={
            "client_id": "test-audit-1",
            "actor": "alice",
            "category": "scan",
            "action": "scan_received",
            "subject_id": "run-1",
            "subject_type": "run",
            "summary": "test",
            "timestamp": "2026-11-07T00:00:00Z",
        },
        headers=csrf_headers(app_client),
    )
    assert response.status_code == 201, response.text

    response = await app_client.get("/api/v1/admin/audit/verify")
    assert response.status_code == 200, response.text
    assert response.json()["valid"] is True

    async with mandant_db.owner_sessionmaker() as session:
        row_id = (
            await session.execute(
                text("SELECT id FROM user_audit_logs ORDER BY timestamp LIMIT 1")
            )
        ).scalar_one()
        await session.execute(
            text("UPDATE user_audit_logs SET action = 'tampered' WHERE id = :id"),
            {"id": row_id},
        )
        await session.commit()

    response = await app_client.get("/api/v1/admin/audit/verify")
    assert response.status_code == 200, response.text
    assert response.json()["valid"] is False


async def test_scim_provisions_and_deprovisions_a_user(
    mandant_db, app_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "wombat_scim_enabled", True)
    monkeypatch.setattr(settings, "wombat_scim_token", "scim-test-token")
    monkeypatch.setattr(settings, "wombat_scim_mandant_slug", "")

    headers = {"Authorization": "Bearer scim-test-token"}
    response = await app_client.post(
        "/scim/v2/Users",
        headers=headers,
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "scim.alice",
            "displayName": "SCIM Alice",
            "emails": [{"value": "alice@example.com", "type": "work", "primary": True}],
            "active": True,
            "externalId": "ext-1",
        },
    )
    assert response.status_code == 201, response.text
    user = response.json()
    assert user["userName"] == "scim.alice"
    assert user["emails"][0]["value"] == "alice@example.com"

    response = await app_client.get("/scim/v2/Users", headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["totalResults"] >= 1

    response = await app_client.delete(f"/scim/v2/Users/{user['id']}", headers=headers)
    assert response.status_code == 204, response.text

    response = await app_client.get(f"/scim/v2/Users/{user['id']}", headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["active"] is False


async def test_data_export_and_anonymize(mandant_db, app_client) -> None:
    await seed_user(mandant_db, username="admin1", role="admin")
    target_id = await seed_user(mandant_db, username="target", role="engineer")

    response = await login(app_client, "admin1", "correct-horse")
    assert response.status_code == 200, response.text

    response = await app_client.get(f"/api/v1/admin/users/{target_id}/export")
    assert response.status_code == 200, response.text
    assert response.json()["user"]["username"] == "target"

    response = await app_client.post(
        f"/api/v1/admin/users/{target_id}/anonymize",
        headers=csrf_headers(app_client),
    )
    assert response.status_code == 204, response.text

    response = await app_client.get(f"/api/v1/admin/users/{target_id}/export")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["user"]["display_name"] == "Deleted user"
    assert body["user"]["is_active"] is False
