"""Asynchronous scan jobs and IaC archive uploads (Wave B)."""
from __future__ import annotations

import os
import shutil
import stat
import tarfile
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from wombat_server.auth.deps import AuthContext, get_auth_context, get_scoped_db, require_role
from wombat_server.config import settings
from wombat_server.events import publish_event
from wombat_server.models import ScanJob, User
from wombat_server.path_safety import resolve_scan_path, scan_base_dir
from wombat_server.schemas import Envelope, Meta, ScanJobCreate, ScanJobOut

router = APIRouter(prefix="/scans", tags=["scans"])

_ALLOWED_EXTENSIONS = {
    ".tf", ".tfvars", ".hcl", ".yaml", ".yml", ".json", ".template", ".bicep",
}
_UPLOAD_DIR = ".upload-scans"


def _allowed_file(name: str) -> bool:
    lower = name.lower()
    parts = PurePosixPath(lower.replace("\\", "/")).parts
    if not parts:
        return False
    if any(part == "__macosx" for part in parts):
        return False
    base = parts[-1]
    # macOS AppleDouble/metadata files and other hidden files are not IaC.
    if base.startswith("._") or base == ".ds_store":
        return False
    if base.startswith(".") and not (base.endswith(".pulumi.yaml") or base.endswith(".cdk.json")):
        return False
    return (
        Path(base).suffix in _ALLOWED_EXTENSIONS
        or base.endswith(".pulumi.yaml")
        or base.endswith(".cdk.json")
    )


def _safe_relative(name: str) -> Path:
    normalized = PurePosixPath(name.replace("\\", "/"))
    if normalized.is_absolute() or not normalized.parts:
        raise ValueError(f"Unsafe archive path: {name}")
    if any(part in ("..", "") for part in normalized.parts):
        raise ValueError(f"Unsafe archive path: {name}")
    return Path(*normalized.parts)


def _limits() -> tuple[int, int, int]:
    return (
        settings.wombat_scan_upload_max_files,
        settings.wombat_scan_upload_max_extracted_mb * 1024 * 1024,
        settings.wombat_scan_upload_max_mb * 1024 * 1024,
    )


def _extract_zip(archive: Path, target: Path) -> int:
    max_files, max_extracted, _ = _limits()
    seen = 0
    written = 0
    total = 0
    with zipfile.ZipFile(archive) as bundle:
        for info in bundle.infolist():
            if info.is_dir():
                continue
            seen += 1
            if seen > max_files:
                raise ValueError(f"Archive contains more than {max_files} files.")
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError("Symlinks are not allowed in scan archives.")
            if not _allowed_file(info.filename):
                continue
            written += 1
            total += info.file_size
            if total > max_extracted:
                raise ValueError("Archive expands beyond the configured limit.")
            dest = target / _safe_relative(info.filename)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(info) as source, dest.open("wb") as out:
                shutil.copyfileobj(source, out)
    return written


def _extract_tar(archive: Path, target: Path) -> int:
    max_files, max_extracted, _ = _limits()
    seen = 0
    written = 0
    total = 0
    with tarfile.open(archive, "r:*") as bundle:
        for member in bundle.getmembers():
            if member.isdir():
                continue
            seen += 1
            if seen > max_files:
                raise ValueError(f"Archive contains more than {max_files} files.")
            if member.issym() or member.islnk() or member.ischr() or member.isblk() or member.isfifo():
                raise ValueError("Links and device files are not allowed in scan archives.")
            if not member.isfile():
                continue
            if not _allowed_file(member.name):
                continue
            written += 1
            total += member.size
            if total > max_extracted:
                raise ValueError("Archive expands beyond the configured limit.")
            dest = target / _safe_relative(member.name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                continue
            with source, dest.open("wb") as out:
                shutil.copyfileobj(source, out)
    return written


def _scan_root() -> Path:
    return Path(scan_base_dir()).resolve()


def _job_out(job: ScanJob) -> ScanJobOut:
    return ScanJobOut.model_validate(job, from_attributes=True)


def _requested_by(user: User) -> str:
    return user.username


@router.post("", response_model=Envelope[ScanJobOut], status_code=status.HTTP_202_ACCEPTED)
async def create_scan_job(
    payload: ScanJobCreate,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    user: Annotated[User, Depends(require_role("engineer"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> Envelope[ScanJobOut]:
    # Validate early so the job does not fail later for a bad path.
    resolve_scan_path(payload.path)

    job = ScanJob(
        status="queued",
        project=payload.project,
        path=payload.path,
        iac=payload.iac,
        branch=payload.branch,
        stage=payload.stage,
        triggered_by=payload.triggered_by or "ui",
        progress=0,
        requested_by=_requested_by(user),
        mandant_id=auth.mandant_id,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)
    await publish_event(
        "scan.queued",
        {"job_id": str(job.id), "project": job.project},
        mandate_id=job.mandant_id,
    )
    return Envelope(data=_job_out(job))


@router.post("/upload", response_model=Envelope[ScanJobOut], status_code=status.HTTP_202_ACCEPTED)
async def upload_scan(
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    user: Annotated[User, Depends(require_role("engineer"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    file: UploadFile = File(...),
    project: str = Form(""),
    iac: str = Form("terraform"),
    branch: str = Form(""),
    stage: str = Form(""),
) -> Envelope[ScanJobOut]:
    if not settings.wombat_scan_enabled:
        raise HTTPException(status_code=503, detail="Server-side scanning is disabled (WOMBAT_SCAN_ENABLED=false).")

    _max_files, _max_extracted, max_compressed = _limits()
    job_id = uuid.uuid4()
    root = _scan_root()
    target = (root / _UPLOAD_DIR / str(job_id)).resolve()
    if target != root and root not in target.parents:
        raise HTTPException(status_code=500, detail="Invalid upload target.")

    archive: Path | None = None
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.mkdir(parents=True, exist_ok=True)
        archive = target.parent / f"{job_id}.upload"

        written = 0
        with archive.open("wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_compressed:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Archive exceeds the {settings.wombat_scan_upload_max_mb} MB limit.",
                    )
                out.write(chunk)

        name = (file.filename or "").lower()
        with archive.open("rb") as probe:
            magic = probe.read(4)
        if name.endswith(".zip") or magic.startswith(b"PK"):
            files = _extract_zip(archive, target)
        elif name.endswith((".tar.gz", ".tgz", ".tar")) or magic.startswith(b"\x1f\x8b"):
            files = _extract_tar(archive, target)
        else:
            raise ValueError("Only .zip and .tar.gz archives are accepted.")
        if files == 0:
            raise ValueError("No IaC files were found in the archive.")

        job = ScanJob(
            id=job_id,
            status="queued",
            project=project.strip() or f"upload-{str(job_id)[:8]}",
            path=str(target),
            iac=iac or "terraform",
            branch=branch,
            stage=stage or "upload",
            triggered_by="upload",
            progress=0,
            requested_by=_requested_by(user),
            cleanup_path=str(target),
            mandant_id=auth.mandant_id,
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        await publish_event(
            "scan.queued",
            {"job_id": str(job.id), "project": job.project},
            mandate_id=job.mandant_id,
        )
        return Envelope(data=_job_out(job))
    except HTTPException:
        shutil.rmtree(target, ignore_errors=True)
        raise
    except ValueError as error:
        shutil.rmtree(target, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(error)) from error
    finally:
        if archive is not None:
            archive.unlink(missing_ok=True)


@router.get("", response_model=Envelope[list[ScanJobOut]])
async def list_scan_jobs(
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    _: Annotated[User, Depends(require_role("engineer"))],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    status: str | None = None,
    project: str | None = None,
) -> Envelope[list[ScanJobOut]]:
    conditions = []
    if status:
        conditions.append(ScanJob.status == status)
    if project:
        conditions.append(ScanJob.project == project)
    total = int(
        (
            await db.execute(
                select(func.count()).select_from(ScanJob).where(*conditions)
            )
        ).scalar_one()
        or 0
    )
    jobs = (
        await db.execute(
            select(ScanJob)
            .where(*conditions)
            .order_by(ScanJob.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
    ).scalars().all()
    return Envelope(data=[_job_out(job) for job in jobs], meta=Meta(total=total))


@router.post("/{job_id}/retry", response_model=Envelope[ScanJobOut], status_code=status.HTTP_202_ACCEPTED)
async def retry_scan_job(
    job_id: str,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    user: Annotated[User, Depends(require_role("engineer"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> Envelope[ScanJobOut]:
    """Queue a fresh job from a path-based scan job.

    Uploaded jobs are rejected: their extracted temporary directory is removed
    after the run, so the app must ask the user to choose the folder again.
    """
    try:
        parsed = uuid.UUID(job_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail="Scan job not found") from error
    job = await db.get(ScanJob, parsed)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.status in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="This scan job is still active.")
    if not job.path or not Path(job.path).exists():
        raise HTTPException(
            status_code=409,
            detail="The original scan source no longer exists. Choose the folder again.",
        )
    try:
        source = resolve_scan_path(job.path)
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=409,
            detail="The original scan source is no longer available. Choose the folder again.",
        ) from error

    retry = ScanJob(
        status="queued",
        project=job.project,
        path=str(source),
        iac=job.iac,
        branch=job.branch,
        stage=job.stage,
        triggered_by="retry",
        progress=0,
        requested_by=_requested_by(user),
        mandant_id=auth.mandant_id,
    )
    db.add(retry)
    await db.commit()
    await db.refresh(retry)
    await publish_event(
        "scan.queued",
        {"job_id": str(retry.id), "project": retry.project},
        mandate_id=retry.mandant_id,
    )
    return Envelope(data=_job_out(retry))


@router.get("/{job_id}", response_model=Envelope[ScanJobOut])
async def get_scan_job(
    job_id: str,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    _: Annotated[User, Depends(require_role("engineer"))],
) -> Envelope[ScanJobOut]:
    try:
        parsed = uuid.UUID(job_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail="Scan job not found") from error
    job = await db.get(ScanJob, parsed)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return Envelope(data=_job_out(job))


@router.post("/{job_id}/cancel", response_model=Envelope[ScanJobOut])
async def cancel_scan_job(
    job_id: str,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    _: Annotated[User, Depends(require_role("engineer"))],
) -> Envelope[ScanJobOut]:
    try:
        parsed = uuid.UUID(job_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail="Scan job not found") from error
    job = await db.get(ScanJob, parsed)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.status != "queued":
        raise HTTPException(
            status_code=409,
            detail=f"Job is {job.status}; only queued jobs can be cancelled.",
        )
    job.status = "cancelled"
    from datetime import datetime, timezone

    job.finished_at = datetime.now(timezone.utc)
    cleanup_path = job.cleanup_path
    await db.commit()
    await db.refresh(job)
    if cleanup_path:
        from wombat_server.scan_jobs import _cleanup

        _cleanup(cleanup_path)
    await publish_event(
        "scan.cancelled",
        {"job_id": str(job.id), "project": job.project},
        mandate_id=job.mandant_id,
    )
    return Envelope(data=_job_out(job))
