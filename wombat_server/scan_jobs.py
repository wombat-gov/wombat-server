"""In-process worker for asynchronous scan jobs (Wave B).

The worker uses the owner/superuser session so it can claim queued jobs across
mandates; the API itself stays RLS-scoped. One worker is started per process;
``FOR UPDATE SKIP LOCKED`` makes the claim safe if several replicas run.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from wombat_server.config import settings
from wombat_server.database import get_owner_session
from wombat_server.events import publish_event
from wombat_server.models import ScanJob
from wombat_server.path_safety import scan_base_dir
from wombat_server.scan_service import ScanServiceError, execute_scan

logger = logging.getLogger(__name__)


async def _claim_job() -> uuid.UUID | None:
    async with get_owner_session() as session:
        job = (
            await session.execute(
                select(ScanJob)
                .where(ScanJob.status == "queued")
                .order_by(ScanJob.created_at.asc())
                .limit(1)
                .with_for_update(skip_locked=True)
            )
        ).scalar_one_or_none()
        if job is None:
            return None
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        job.progress = 5
        await session.commit()
        return job.id


def _cleanup(path: str | None) -> None:
    if not path:
        return
    try:
        base = Path(scan_base_dir()).resolve()
        target = Path(path).resolve()
        if target != base and base in target.parents:
            shutil.rmtree(target, ignore_errors=True)
        else:
            logger.warning("refusing to clean scan path outside base: %s", target)
    except Exception:
        logger.exception("scan cleanup failed for %s", path)


async def _process_job(job_id: uuid.UUID) -> None:
    async with get_owner_session() as session:
        job = await session.get(ScanJob, job_id)
        if job is None or job.status != "running":
            return

        async def progress(value: int, stage: str) -> None:
            job.progress = max(0, min(100, value))
            await session.commit()
            await publish_event(
                "scan.progress",
                {
                    "job_id": str(job.id),
                    "progress": job.progress,
                    "stage": stage,
                    "project": job.project,
                },
                mandate_id=job.mandant_id,
            )

        try:
            run = await execute_scan(
                session,
                path=job.path,
                iac=job.iac,
                project=job.project,
                branch=job.branch,
                stage=job.stage,
                triggered_by=job.triggered_by,
                mandate_id=job.mandant_id,
                progress=progress,
            )
            job.status = "succeeded"
            job.run_id = run.id
            job.progress = 100
            job.error = None
            job.finished_at = datetime.now(timezone.utc)
            await session.commit()
            logger.info("scan job succeeded", extra={"job_id": str(job.id), "run_id": str(run.id)})
        except ScanServiceError as error:
            job.status = "failed"
            job.error = str(error)[:2000]
            job.finished_at = datetime.now(timezone.utc)
            await session.commit()
            await publish_event(
                "scan.failed",
                {"job_id": str(job.id), "project": job.project, "error": job.error},
                mandate_id=job.mandant_id,
            )
            logger.warning("scan job failed: %s", error)
        except Exception as error:  # pragma: no cover - defensive
            logger.exception("scan job crashed")
            job.status = "failed"
            job.error = str(error)[:2000]
            job.finished_at = datetime.now(timezone.utc)
            await session.commit()
            await publish_event(
                "scan.failed",
                {"job_id": str(job.id), "project": job.project, "error": job.error},
                mandate_id=job.mandant_id,
            )
        finally:
            cleanup_path = job.cleanup_path
        _cleanup(cleanup_path)


async def scan_worker_loop() -> None:
    """Poll and process queued scan jobs until cancelled."""
    logger.info("scan job worker started")
    poll = max(0.2, float(getattr(settings, "wombat_scan_job_poll_seconds", 1.0)))
    while True:
        try:
            job_id = await _claim_job()
            if job_id is None:
                await asyncio.sleep(poll)
                continue
            await _process_job(job_id)
        except asyncio.CancelledError:
            logger.info("scan job worker stopped")
            raise
        except Exception:
            logger.exception("scan job worker loop error")
            await asyncio.sleep(2)
