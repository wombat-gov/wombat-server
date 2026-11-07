"""Wave B: asynchronous scan jobs and upload security."""
from __future__ import annotations

import io
import shutil
import tarfile
import uuid
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from httpx import AsyncClient

from tests.conftest import MandantTestDb
from tests.test_mandants import bearer, seed_user
from wombat_server.models import Run, ScanJob
from wombat_server.path_safety import scan_base_dir


def _zip_bytes(files: dict[str, bytes], symlink: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = 0o120777 << 16
            archive.writestr(info, "/etc/passwd")
    return buffer.getvalue()


def _tar_gz_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


async def _seed_job(
    mandant_db: MandantTestDb,
    *,
    status: str = "queued",
    **fields,
) -> uuid.UUID:
    job_id = uuid.uuid4()
    async with mandant_db.owner_sessionmaker() as session:
        session.add(
            ScanJob(
                id=job_id,
                status=status,
                project="worker-test",
                path=".",
                **fields,
            )
        )
        await session.commit()
    return job_id


@pytest.mark.asyncio
async def test_scan_job_lifecycle(mandant_db: MandantTestDb, app_client: AsyncClient) -> None:
    user_id = await seed_user(mandant_db, username="job-engineer", role="engineer")
    headers = bearer(user_id, "job-engineer", "engineer")

    response = await app_client.post(
        "/api/v1/scans",
        json={"path": ".", "project": "job-demo"},
        headers=headers,
    )
    assert response.status_code == 202
    job = response.json()["data"]
    assert job["status"] == "queued"
    assert job["project"] == "job-demo"
    job_id = job["id"]

    response = await app_client.get(f"/api/v1/scans/{job_id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["data"]["id"] == job_id

    response = await app_client.get("/api/v1/scans?limit=10", headers=headers)
    assert response.status_code == 200
    assert any(item["id"] == job_id for item in response.json()["data"])

    response = await app_client.post(f"/api/v1/scans/{job_id}/cancel", headers=headers)
    assert response.status_code == 200
    assert response.json()["data"]["status"] == "cancelled"

    response = await app_client.post(f"/api/v1/scans/{job_id}/cancel", headers=headers)
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_upload_valid_zip_creates_job(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    user_id = await seed_user(mandant_db, username="upload-engineer", role="engineer")
    headers = bearer(user_id, "upload-engineer", "engineer")
    archive = _zip_bytes({"main.tf": b'resource "aws_s3_bucket" "b" {}'})

    response = await app_client.post(
        "/api/v1/scans/upload",
        files={"file": ("iac.zip", archive, "application/zip")},
        data={"project": "upload-demo", "iac": "terraform"},
        headers=headers,
    )
    assert response.status_code == 202
    job = response.json()["data"]
    assert job["status"] == "queued"
    assert job["project"] == "upload-demo"

    target = Path(scan_base_dir()) / ".upload-scans" / job["id"]
    try:
        assert (target / "main.tf").is_file()
        # Cancelling a queued upload job removes its extracted directory.
        response = await app_client.post(f"/api/v1/scans/{job['id']}/cancel", headers=headers)
        assert response.status_code == 200
        assert not target.exists()
    finally:
        shutil.rmtree(target, ignore_errors=True)


@pytest.mark.asyncio
async def test_upload_valid_tar_gz(mandant_db: MandantTestDb, app_client: AsyncClient) -> None:
    user_id = await seed_user(mandant_db, username="upload-tar", role="engineer")
    headers = bearer(user_id, "upload-tar", "engineer")
    archive = _tar_gz_bytes({"main.tf": b'resource "aws_s3_bucket" "b" {}'})

    response = await app_client.post(
        "/api/v1/scans/upload",
        files={"file": ("iac.tar.gz", archive, "application/gzip")},
        data={"project": "tar-demo"},
        headers=headers,
    )
    assert response.status_code == 202
    job = response.json()["data"]
    target = Path(scan_base_dir()) / ".upload-scans" / job["id"]
    try:
        assert (target / "main.tf").is_file()
    finally:
        target_response = await app_client.post(
            f"/api/v1/scans/{job['id']}/cancel", headers=headers
        )
        assert target_response.status_code == 200
        shutil.rmtree(target, ignore_errors=True)


@pytest.mark.asyncio
async def test_upload_rejects_path_traversal(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    user_id = await seed_user(mandant_db, username="upload-slip", role="engineer")
    headers = bearer(user_id, "upload-slip", "engineer")
    archive = _zip_bytes({"../evil.tf": b"resource \"aws_s3_bucket\" \"b\" {}"})

    response = await app_client.post(
        "/api/v1/scans/upload",
        files={"file": ("evil.zip", archive, "application/zip")},
        headers=headers,
    )
    assert response.status_code == 400
    assert not (Path(scan_base_dir()).parent / "evil.tf").exists()


@pytest.mark.asyncio
async def test_upload_rejects_symlink(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    user_id = await seed_user(mandant_db, username="upload-link", role="engineer")
    headers = bearer(user_id, "upload-link", "engineer")
    archive = _zip_bytes({}, symlink="link.tf")

    response = await app_client.post(
        "/api/v1/scans/upload",
        files={"file": ("link.zip", archive, "application/zip")},
        headers=headers,
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_upload_rejects_archive_without_iac(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    user_id = await seed_user(mandant_db, username="upload-empty", role="engineer")
    headers = bearer(user_id, "upload-empty", "engineer")
    archive = _zip_bytes({"readme.txt": b"nothing to scan"})

    response = await app_client.post(
        "/api/v1/scans/upload",
        files={"file": ("readme.zip", archive, "application/zip")},
        headers=headers,
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_worker_succeeds_and_fails(
    mandant_db: MandantTestDb, monkeypatch: pytest.MonkeyPatch
) -> None:
    from wombat_server import scan_jobs
    from wombat_server.scan_service import ScanServiceError

    @asynccontextmanager
    async def owner_session():
        async with mandant_db.owner_sessionmaker() as session:
            yield session

    monkeypatch.setattr(scan_jobs, "get_owner_session", owner_session)

    success_job = await _seed_job(mandant_db)

    async def fake_success(db, **kwargs):
        run = Run(id=uuid.uuid4(), project="worker-test", score=5, findings=[], pillar_scores={})
        db.add(run)
        await db.commit()
        return run

    monkeypatch.setattr(scan_jobs, "execute_scan", fake_success)
    assert await scan_jobs._claim_job() == success_job
    await scan_jobs._process_job(success_job)

    async with mandant_db.owner_sessionmaker() as session:
        job = await session.get(ScanJob, success_job)
        assert job.status == "succeeded"
        assert job.progress == 100
        assert job.run_id is not None

    failure_job = await _seed_job(mandant_db)

    async def fake_failure(db, **kwargs):
        raise ScanServiceError("engine exploded")

    monkeypatch.setattr(scan_jobs, "execute_scan", fake_failure)
    assert await scan_jobs._claim_job() == failure_job
    await scan_jobs._process_job(failure_job)

    async with mandant_db.owner_sessionmaker() as session:
        job = await session.get(ScanJob, failure_job)
        assert job.status == "failed"
        assert "engine exploded" in job.error


@pytest.mark.asyncio
async def test_scan_retry_and_filters(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    user_id = await seed_user(mandant_db, username="retry-engineer", role="engineer")
    headers = bearer(user_id, "retry-engineer", "engineer")

    created = await app_client.post(
        "/api/v1/scans",
        json={"path": ".", "project": "retry-demo"},
        headers=headers,
    )
    assert created.status_code == 202
    original = created.json()["data"]
    await app_client.post(f"/api/v1/scans/{original['id']}/cancel", headers=headers)

    retried = await app_client.post(f"/api/v1/scans/{original['id']}/retry", headers=headers)
    assert retried.status_code == 202, retried.text
    retry_job = retried.json()["data"]
    assert retry_job["id"] != original["id"]
    assert retry_job["status"] == "queued"
    assert retry_job["project"] == "retry-demo"
    assert retry_job["triggered_by"] == "retry"

    active_retry = await app_client.post(f"/api/v1/scans/{retry_job['id']}/retry", headers=headers)
    assert active_retry.status_code == 409

    filtered = await app_client.get(
        "/api/v1/scans",
        params={"status": "queued", "project": "retry-demo", "limit": 10},
        headers=headers,
    )
    assert filtered.status_code == 200
    body = filtered.json()
    assert body["meta"]["total"] == 1
    assert body["data"][0]["id"] == retry_job["id"]

    missing = await app_client.post("/api/v1/scans/00000000-0000-0000-0000-000000000000/retry", headers=headers)
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_uploaded_job_retry_requires_folder_again(
    mandant_db: MandantTestDb, app_client: AsyncClient
) -> None:
    user_id = await seed_user(mandant_db, username="upload-retry", role="engineer")
    headers = bearer(user_id, "upload-retry", "engineer")
    archive = _zip_bytes({"main.tf": b'resource "aws_s3_bucket" "b" {}'})
    created = await app_client.post(
        "/api/v1/scans/upload",
        files={"file": ("iac.zip", archive, "application/zip")},
        data={"project": "upload-retry-demo"},
        headers=headers,
    )
    assert created.status_code == 202
    job_id = created.json()["data"]["id"]
    await app_client.post(f"/api/v1/scans/{job_id}/cancel", headers=headers)

    retry = await app_client.post(f"/api/v1/scans/{job_id}/retry", headers=headers)
    assert retry.status_code == 409
    assert "folder" in retry.json()["detail"].lower()
