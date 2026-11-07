"""Per-user notification visibility and deep-link tests (UI Wave U6)."""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.conftest import MandantTestDb
from tests.test_mandants import bearer, seed_user


async def _create(client: AsyncClient, token: str, payload: dict) -> dict:
    response = await client.post("/api/v1/notifications", json=payload, headers=token)
    assert response.status_code == 200, response.text
    return response.json()["data"]


@pytest.mark.asyncio
async def test_notifications_are_per_user_and_role_scoped(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    admin = await seed_user(mandant_db, username="n-admin", role="admin")
    engineer = await seed_user(mandant_db, username="n-engineer", role="engineer")
    clevel = await seed_user(mandant_db, username="n-clevel", role="clevel")
    other = await seed_user(mandant_db, username="n-other", role="engineer")
    admin_headers = bearer(admin, "n-admin", "admin")
    engineer_headers = bearer(engineer, "n-engineer", "engineer")
    clevel_headers = bearer(clevel, "n-clevel", "clevel")
    other_headers = bearer(other, "n-other", "engineer")

    direct = await _create(app_client, admin_headers, {
        "title": "Direct",
        "message": "for the engineer",
        "target_user_id": str(engineer),
        "link_route": "findings",
        "link_run_id": "run-123",
        "project": "demo",
    })
    assert direct["target_user_id"] == str(engineer)
    assert direct["link_route"] == "findings"
    assert direct["link_run_id"] == "run-123"
    assert direct["project"] == "demo"

    role = await _create(app_client, admin_headers, {
        "title": "Engineers",
        "message": "for engineers",
        "target_role": "engineer",
    })
    everyone = await _create(app_client, admin_headers, {
        "title": "Everyone",
        "message": "all users",
    })

    own = await app_client.get("/api/v1/notifications", headers=engineer_headers)
    assert own.status_code == 200
    own_titles = {item["title"] for item in own.json()["data"]}
    assert {"Direct", "Engineers", "Everyone"} <= own_titles

    other_titles = {
        item["title"]
        for item in (await app_client.get("/api/v1/notifications", headers=other_headers)).json()["data"]
    }
    assert "Direct" not in other_titles
    assert "Engineers" in other_titles
    assert "Everyone" in other_titles

    clevel_titles = {
        item["title"]
        for item in (await app_client.get("/api/v1/notifications", headers=clevel_headers)).json()["data"]
    }
    assert "Direct" not in clevel_titles
    assert "Engineers" not in clevel_titles
    assert "Everyone" in clevel_titles

    admin_titles = {
        item["title"]
        for item in (await app_client.get("/api/v1/notifications", headers=admin_headers)).json()["data"]
    }
    assert {"Direct", "Engineers", "Everyone"} <= admin_titles

    # An invisible id is indistinguishable from missing.
    response = await app_client.put(
        f"/api/v1/notifications/{direct['id']}/read",
        json={"is_read": True},
        headers=other_headers,
    )
    assert response.status_code == 404

    response = await app_client.put(
        f"/api/v1/notifications/{direct['id']}/read",
        json={"is_read": True},
        headers=engineer_headers,
    )
    assert response.status_code == 200
    assert response.json()["data"]["is_read"] is True

    # read-all only touches the caller's visible rows.
    response = await app_client.put("/api/v1/notifications/read-all", headers=clevel_headers)
    assert response.status_code == 200
    clevel_items = (
        await app_client.get("/api/v1/notifications", headers=clevel_headers)
    ).json()["data"]
    assert all(item["is_read"] for item in clevel_items)
    other_items = (
        await app_client.get("/api/v1/notifications", headers=other_headers)
    ).json()["data"]
    assert any(not item["is_read"] for item in other_items)


@pytest.mark.asyncio
async def test_notification_pagination_and_filters(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    admin = await seed_user(mandant_db, username="page-admin", role="admin")
    headers = bearer(admin, "page-admin", "admin")
    for index in range(5):
        await _create(app_client, headers, {
            "title": f"Page {index}",
            "message": "message",
            "category": "warning" if index % 2 else "info",
        })

    first = await app_client.get(
        "/api/v1/notifications", params={"limit": 2, "offset": 0}, headers=headers
    )
    second = await app_client.get(
        "/api/v1/notifications", params={"limit": 2, "offset": 2}, headers=headers
    )
    assert first.status_code == 200 and second.status_code == 200
    assert first.json()["meta"]["total"] == 5
    ids = [item["id"] for item in first.json()["data"]]
    ids += [item["id"] for item in second.json()["data"]]
    assert len(ids) == 4 and len(set(ids)) == 4

    warnings = await app_client.get(
        "/api/v1/notifications", params={"category": "warning"}, headers=headers
    )
    assert warnings.status_code == 200
    assert warnings.json()["data"]
    assert all(item["category"] == "warning" for item in warnings.json()["data"])


@pytest.mark.asyncio
async def test_notification_invalid_target_role_and_user(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    admin = await seed_user(mandant_db, username="bad-admin", role="admin")
    headers = bearer(admin, "bad-admin", "admin")

    bad_role = await app_client.post(
        "/api/v1/notifications",
        json={"title": "x", "message": "y", "target_role": "nobody"},
        headers=headers,
    )
    assert bad_role.status_code == 400

    missing_user = await app_client.post(
        "/api/v1/notifications",
        json={"title": "x", "message": "y", "target_user_id": "00000000-0000-0000-0000-000000000000"},
        headers=headers,
    )
    assert missing_user.status_code == 400
