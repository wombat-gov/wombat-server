"""Wave C: global search endpoint tests."""
from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient

from tests.conftest import MandantTestDb
from tests.test_mandants import bearer, seed_user
from wombat_server.models import (
    Control,
    ProjectPassport,
    RiskAcceptance,
    Run,
    RunFinding,
    Waiver,
)


async def _seed_search_data(mandant_db: MandantTestDb) -> uuid.UUID:
    run_id = uuid.uuid4()
    async with mandant_db.owner_sessionmaker() as session:
        session.add(
            Run(
                id=run_id,
                project="wombat-demo",
                branch="main",
                git_sha="abc",
                triggered_by="test",
                iac_framework="terraform",
                stage="dev",
                score=42,
                findings=[],
                controls_loaded=10,
                controls_run=10,
                pillar_scores={},
                run_metadata={},
            )
        )
        session.add(
            RunFinding(
                run_id=run_id,
                check_id="waf-sec-130.tf.aws.s3-public-access",
                check_title="S3 bucket must block public access",
                control_id="WAF-SEC-130",
                pillar="security",
                severity="high",
                status="FAIL",
                resource="aws_s3_bucket.demo",
                message="Public access block missing",
            )
        )
        session.add(
            Control(
                id="WAF-SEC-130",
                pillar="security",
                severity="high",
                type=[],
                description="S3 buckets must have all public access block settings enabled.",
                checks=[],
                regulatory_mapping=[],
                source="wombat",
            )
        )
        session.add(
            Waiver(
                id="WAF-SEC-130",
                reason="Accepted for the legacy bucket",
                owner="security",
                project="wombat-demo",
            )
        )
        session.add(
            RiskAcceptance(
                id="RISK-42",
                reason="Legacy bucket migration",
                approver="ciso",
                owner="security",
                risk_level="accepted",
                residual_risk="low",
                project="wombat-demo",
            )
        )
        session.add(
            ProjectPassport(
                project="wombat-demo",
                display_name="Wombat Demo",
                description="Demo project for the desktop app",
                owner="platform",
            )
        )
        await session.commit()
    return run_id


@pytest.mark.asyncio
async def test_search_requires_auth(app_client: AsyncClient) -> None:
    response = await app_client.get("/api/v1/search", params={"q": "wombat"})
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_search_validation(mandant_db: MandantTestDb, app_client: AsyncClient) -> None:
    user_id = await seed_user(mandant_db, username="search-validation", role="engineer")
    headers = bearer(user_id, "search-validation", "engineer")

    assert (await app_client.get("/api/v1/search", params={"q": ""}, headers=headers)).status_code == 422
    assert (
        await app_client.get("/api/v1/search", params={"q": "x" * 101}, headers=headers)
    ).status_code == 422


@pytest.mark.asyncio
async def test_search_runs_and_projects(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    user_id = await seed_user(mandant_db, username="search-runs", role="engineer")
    headers = bearer(user_id, "search-runs", "engineer")
    await _seed_search_data(mandant_db)

    response = await app_client.get("/api/v1/search", params={"q": "wombat"}, headers=headers)
    assert response.status_code == 200
    items = response.json()["data"]
    types = {item["type"] for item in items}
    assert "run" in types
    assert "project" in types
    run = next(item for item in items if item["type"] == "run")
    assert run["title"] == "wombat-demo"
    assert run["route"] == "dashboard"
    assert run["run_id"] == run["id"]
    assert run["score"] == 42


@pytest.mark.asyncio
async def test_search_type_filter_and_findings(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    user_id = await seed_user(mandant_db, username="search-findings", role="engineer")
    headers = bearer(user_id, "search-findings", "engineer")
    run_id = await _seed_search_data(mandant_db)

    response = await app_client.get(
        "/api/v1/search",
        params={"q": "bucket", "types": "findings"},
        headers=headers,
    )
    assert response.status_code == 200
    items = response.json()["data"]
    assert items
    assert all(item["type"] == "finding" for item in items)
    assert items[0]["route"] == "findings"
    assert items[0]["run_id"] == str(run_id)


@pytest.mark.asyncio
async def test_search_controls_waivers_risks(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    user_id = await seed_user(mandant_db, username="search-controls", role="engineer")
    headers = bearer(user_id, "search-controls", "engineer")
    await _seed_search_data(mandant_db)

    response = await app_client.get(
        "/api/v1/search",
        params={"q": "WAF-SEC", "types": "controls,waivers"},
        headers=headers,
    )
    assert response.status_code == 200
    items = response.json()["data"]
    types = {item["type"] for item in items}
    assert "control" in types
    assert "waiver" in types
    assert all(item["type"] in {"control", "waiver"} for item in items)

    response = await app_client.get(
        "/api/v1/search",
        params={"q": "legacy", "types": "risks"},
        headers=headers,
    )
    assert response.status_code == 200
    risks = response.json()["data"]
    assert risks
    assert risks[0]["type"] == "risk"
    assert risks[0]["route"] == "risk"


@pytest.mark.asyncio
async def test_search_unknown_type_returns_empty(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    user_id = await seed_user(mandant_db, username="search-unknown", role="engineer")
    headers = bearer(user_id, "search-unknown", "engineer")
    await _seed_search_data(mandant_db)

    response = await app_client.get(
        "/api/v1/search",
        params={"q": "wombat", "types": "unknown"},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["data"] == []
