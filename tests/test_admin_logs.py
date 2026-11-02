"""Tests for the admin/security audit log endpoint and syslog helper."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi import status
from httpx import AsyncClient

from tests.conftest import MandantTestDb
from tests.test_mandants import bearer, seed_user
from wombat_server.models import SyslogConfig, UserAuditLog
from wombat_server.syslog import build_syslog_message


async def _seed_log(mandant_db: MandantTestDb, actor_id: uuid.UUID, action: str) -> None:
    async with mandant_db.owner_sessionmaker() as session:
        session.add(
            UserAuditLog(
                id=uuid.uuid4(),
                actor_id=actor_id,
                action=action,
                detail={"foo": "bar"},
                ip="127.0.0.1",
                timestamp=datetime.now(timezone.utc),
            )
        )
        await session.commit()


@pytest.mark.asyncio
async def test_admin_logs_require_admin(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    user_id = await seed_user(mandant_db, username="engineer-tester", role="engineer")
    resp = await app_client.get(
        "/api/v1/admin/logs",
        headers=bearer(user_id, "engineer-tester", "engineer"),
    )
    assert resp.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_admin_logs_lists_events(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    admin_id = await seed_user(mandant_db, username="admin-tester", role="admin")
    headers = bearer(admin_id, "admin-tester", "admin")
    await _seed_log(mandant_db, admin_id, "login")
    await _seed_log(mandant_db, admin_id, "user.create")

    resp = await app_client.get("/api/v1/admin/logs", headers=headers)
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()["data"]
    assert len(data) == 2
    actions = {e["action"] for e in data}
    assert actions == {"login", "user.create"}
    # actor username resolved
    assert data[0]["actor_username"] == "admin-tester"


@pytest.mark.asyncio
async def test_admin_logs_action_filter(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    admin_id = await seed_user(mandant_db, username="admin-tester", role="admin")
    headers = bearer(admin_id, "admin-tester", "admin")
    await _seed_log(mandant_db, admin_id, "login")
    await _seed_log(mandant_db, admin_id, "logout")

    resp = await app_client.get("/api/v1/admin/logs?action=login", headers=headers)
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()["data"]
    assert len(data) == 1
    assert data[0]["action"] == "login"


@pytest.mark.asyncio
async def test_admin_logs_limit(mandant_db: MandantTestDb, app_client: AsyncClient) -> None:
    admin_id = await seed_user(mandant_db, username="admin-tester", role="admin")
    headers = bearer(admin_id, "admin-tester", "admin")
    for _ in range(5):
        await _seed_log(mandant_db, admin_id, "login")

    resp = await app_client.get("/api/v1/admin/logs?limit=2", headers=headers)
    assert resp.status_code == status.HTTP_200_OK
    assert len(resp.json()["data"]) == 2


@pytest.mark.asyncio
async def test_syslog_config_requires_admin(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    user_id = await seed_user(mandant_db, username="engineer-tester", role="engineer")
    resp = await app_client.get(
        "/api/v1/admin/syslog-config",
        headers=bearer(user_id, "engineer-tester", "engineer"),
    )
    assert resp.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_syslog_config_crud(mandant_db: MandantTestDb, app_client: AsyncClient) -> None:
    admin_id = await seed_user(mandant_db, username="admin-tester", role="admin")
    headers = bearer(admin_id, "admin-tester", "admin")

    resp = await app_client.get("/api/v1/admin/syslog-config", headers=headers)
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()["data"]
    assert data["enabled"] is False
    assert data["host"] == ""

    payload = {
        "enabled": True,
        "host": "syslog.example.com",
        "port": 514,
        "protocol": "tcp",
        "syslog_format": "rfc5424",
        "facility": 13,
        "tls_enabled": True,
        "program_tag": "wombat-admin",
        "severity_overrides": {"login_success": 3},
    }
    resp = await app_client.put("/api/v1/admin/syslog-config", json=payload, headers=headers)
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()["data"]
    assert data["enabled"] is True
    assert data["host"] == "syslog.example.com"
    assert data["protocol"] == "tcp"
    assert data["tls_enabled"] is True
    assert data["severity_overrides"] == {"login_success": 3}

    resp = await app_client.get("/api/v1/admin/syslog-config", headers=headers)
    assert resp.json()["data"]["host"] == "syslog.example.com"


@pytest.mark.asyncio
async def test_syslog_config_test_endpoint_no_host(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    admin_id = await seed_user(mandant_db, username="admin-tester", role="admin")
    resp = await app_client.post(
        "/api/v1/admin/syslog-config/test",
        headers=bearer(admin_id, "admin-tester", "admin"),
    )
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["data"]["success"] is False


def test_build_syslog_message_rfc5424() -> None:
    config = SyslogConfig(facility=13, syslog_format="rfc5424", program_tag="wombat-admin")
    msg = build_syslog_message(
        config,
        action="login",
        detail={"user": "alice"},
        ip="10.0.0.1",
        actor_id=str(uuid.uuid4()),
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
    )
    assert msg.startswith(b"<110>1 2026-01-01T12:00:00+00:00")
    assert b'"action":"login"' in msg


def test_build_syslog_message_rfc3164() -> None:
    config = SyslogConfig(facility=13, syslog_format="rfc3164", program_tag="wombat-admin")
    msg = build_syslog_message(config, action="logout", detail={}, ip="")
    assert msg.startswith(b"<110>")
    assert b"wombat-admin" in msg


def test_build_syslog_message_severity_override() -> None:
    config = SyslogConfig(
        facility=13,
        syslog_format="rfc5424",
        program_tag="wombat-admin",
        severity_overrides={"login": 3},
    )
    msg = build_syslog_message(config, action="login", detail={}, ip="")
    # facility 13, severity 3 => PRI = 13*8 + 3 = 107
    assert msg.startswith(b"<107>")
