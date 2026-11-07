"""Wave A: desktop summary endpoint tests (requires PostgreSQL)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from httpx import AsyncClient

from tests.conftest import MandantTestDb
from tests.test_mandants import bearer, seed_user
from wombat_server.models import Notification, Run


async def _seed_run(
    mandant_db: MandantTestDb,
    *,
    project: str,
    score: int,
    created_at: datetime | None = None,
    findings: list[dict] | None = None,
) -> uuid.UUID:
    run_id = uuid.uuid4()
    async with mandant_db.owner_sessionmaker() as session:
        session.add(
            Run(
                id=run_id,
                project=project,
                branch="main",
                git_sha="abc123",
                triggered_by="test",
                iac_framework="terraform",
                stage="dev",
                score=score,
                findings=findings or [],
                controls_loaded=10,
                controls_run=10,
                pillar_scores={},
                run_metadata={},
                created_at=created_at or datetime.now(timezone.utc),
            )
        )
        await session.commit()
    return run_id


async def _seed_notification(mandant_db: MandantTestDb) -> None:
    async with mandant_db.owner_sessionmaker() as session:
        session.add(
            Notification(
                id=str(uuid.uuid4()),
                title="Summary test",
                message="hello",
                category="info",
                triggered_by="test",
                target_role=None,
            )
        )
        await session.commit()


@pytest.mark.asyncio
async def test_desktop_summary_requires_auth(app_client: AsyncClient) -> None:
    response = await app_client.get("/api/v1/desktop/summary")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_desktop_summary_empty(mandant_db: MandantTestDb, app_client: AsyncClient) -> None:
    user_id = await seed_user(mandant_db, username="summary-empty", role="admin")
    response = await app_client.get(
        "/api/v1/desktop/summary",
        headers=bearer(user_id, "summary-empty", "admin"),
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["latest_run"] is None
    assert data["trend"] == []
    assert data["projects"] == []
    assert data["notifications"]["unread"] == 0
    assert data["digest"]["runs_24h"] == 0


@pytest.mark.asyncio
async def test_desktop_summary_latest_run_and_digest(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    user_id = await seed_user(mandant_db, username="summary-run", role="admin")
    run_id = await _seed_run(
        mandant_db,
        project="demo",
        score=42,
        findings=[
            {"control_id": "C1", "status": "FAIL", "severity": "HIGH", "resource": "r1"},
            {"control_id": "C2", "status": "PASS", "severity": "LOW", "resource": "r2"},
        ],
    )
    await _seed_notification(mandant_db)

    response = await app_client.get(
        "/api/v1/desktop/summary",
        headers=bearer(user_id, "summary-run", "admin"),
    )
    assert response.status_code == 200
    data = response.json()["data"]

    latest = data["latest_run"]
    assert latest["id"] == str(run_id)
    assert latest["project"] == "demo"
    assert latest["score"] == 42
    assert latest["failed_controls"] == 1
    assert latest["critical"] == 0
    assert latest["high"] == 1
    assert latest["pass_rate"] == 50
    assert latest["controls_run"] == 10
    assert data["trend"] == [42]
    assert data["projects"] == ["demo"]
    assert data["notifications"]["unread"] == 1
    assert data["digest"]["runs_24h"] == 1
    assert data["digest"]["projects_24h"] == 1


@pytest.mark.asyncio
async def test_desktop_summary_project_filter(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    user_id = await seed_user(mandant_db, username="summary-filter", role="admin")
    now = datetime.now(timezone.utc)
    await _seed_run(mandant_db, project="demo", score=42, created_at=now, findings=[])
    await _seed_run(mandant_db, project="other", score=80, created_at=now, findings=[])

    response = await app_client.get(
        "/api/v1/desktop/summary",
        params={"project": "other"},
        headers=bearer(user_id, "summary-filter", "admin"),
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["selected_project"] == "other"
    assert data["latest_run"]["project"] == "other"
    assert data["latest_run"]["score"] == 80
    assert data["trend"] == [80]
    assert set(data["projects"]) == {"demo", "other"}
