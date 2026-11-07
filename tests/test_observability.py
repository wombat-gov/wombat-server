"""Tests for liveness/readiness, metrics, and request correlation."""
from __future__ import annotations


async def test_livez(app_client) -> None:
    response = await app_client.get("/livez")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_health_is_a_livez_alias(app_client) -> None:
    response = await app_client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_readyz_reports_dependencies(app_client) -> None:
    response = await app_client.get("/readyz")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "ok"
    assert body["components"]["database"] == "ok"
    assert body["components"]["migrations"] == "ok"
    assert body["components"]["controls"].startswith("ok")


async def test_metrics_are_exposed(app_client) -> None:
    response = await app_client.get("/metrics")
    assert response.status_code == 200
    assert "http_request" in response.text or "wombat_" in response.text


async def test_request_id_is_echoed(app_client) -> None:
    response = await app_client.get(
        "/livez", headers={"X-Request-ID": "test-request-123"}
    )
    assert response.status_code == 200
    assert response.headers["x-request-id"] == "test-request-123"


async def test_request_id_is_generated_when_missing(app_client) -> None:
    response = await app_client.get("/does-not-exist")
    assert response.status_code == 404
    assert len(response.headers["x-request-id"]) >= 8
