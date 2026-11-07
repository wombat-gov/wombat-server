"""Shared scan execution used by the job worker (and reusable by /scan later)."""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from wombat_server.config import settings
from wombat_server.events import publish_event
from wombat_server.models import Run
from wombat_server.path_safety import resolve_scan_path
from wombat_server.schemas import FindingSchema

logger = logging.getLogger(__name__)

_VALID_PILLARS = [
    "security", "cost", "operations", "performance",
    "reliability", "sovereign", "sustainability", "agentic",
]

ProgressCallback = Callable[[int, str], Awaitable[None]]


class ScanServiceError(RuntimeError):
    """A scan failed for a user-actionable reason."""


async def _report(progress: ProgressCallback | None, value: int, stage: str) -> None:
    if progress is None:
        return
    try:
        await progress(value, stage)
    except Exception:
        logger.exception("Failed to report scan progress")


def _normalize_pillar(name: str) -> str:
    return "operations" if name == "operational" else name


async def execute_scan(
    db: AsyncSession,
    *,
    path: str,
    iac: str = "terraform",
    project: str = "",
    branch: str = "",
    stage: str = "",
    triggered_by: str = "ui",
    mandate_id: uuid.UUID | None = None,
    progress: ProgressCallback | None = None,
) -> Run:
    """Run the engine against a server-side path and persist the result."""
    if not getattr(settings, "wombat_scan_enabled", True):
        raise ScanServiceError("Server-side scanning is disabled (WOMBAT_SCAN_ENABLED=false).")

    try:
        from wombat.runner import ScanConfig, run_scan  # type: ignore[import]
    except ImportError as exc:
        raise ScanServiceError(
            "wombat-core is not importable on this server. "
            "Reinstall with: pip install wombat-core"
        ) from exc

    scan_path = resolve_scan_path(path)
    controls_dir = Path(settings.wombat_controls_dir)
    if not controls_dir.exists():
        raise ScanServiceError(
            f"Controls directory not found: {controls_dir.resolve()}. "
            "Set WOMBAT_CONTROLS_DIR to the path containing your Wombat YAML files."
        )

    await _report(progress, 10, "validating")

    try:
        _report_obj, result = await asyncio.to_thread(
            run_scan,
            ScanConfig(
                paths=[scan_path],
                controls_dir=controls_dir,
                iac=iac,
                project=project,
                branch=branch,
                stage=stage,
                triggered_by=triggered_by,
                upload_source=True,
            ),
        )
    except (FileNotFoundError, ValueError) as exc:
        raise ScanServiceError(str(exc)) from exc
    except Exception as exc:  # pragma: no cover - engine-specific
        logger.exception("scan engine failed")
        raise ScanServiceError(f"Scan failed: {exc}") from exc

    await _report(progress, 65, "persisting")

    pillar_scores: dict[str, int] = {pillar: 0 for pillar in _VALID_PILLARS}
    for pillar, score in result.pillar_scores.items():
        normalized = _normalize_pillar(pillar)
        if normalized in pillar_scores:
            pillar_scores[normalized] = score

    run = Run(
        id=uuid.uuid4(),
        project=result.project,
        branch=result.branch,
        git_sha=result.git_sha,
        triggered_by=result.triggered_by,
        run_metadata=result.run,
        iac_framework=result.iac_framework,
        stage=result.stage,
        score=result.score,
        pillar_scores=pillar_scores,
        findings=[finding.model_dump() for finding in result.findings],
        path=result.path,
        controls_loaded=result.controls_loaded,
        controls_run=result.controls_run,
        detected_regions=result.detected_regions,
        source_paths=result.source_paths,
        controls_meta=[control.model_dump() for control in result.controls_meta],
        secret_findings=[finding.model_dump() for finding in result.secret_findings],
        plan_changes=result.plan_changes,
        source_snapshot=result.source_snapshot,
        mandant_id=mandate_id,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    run.completed_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(run)

    # Keep the normalised finding rows in sync with the JSON snapshot.
    from wombat_server.routers.runs import _finding_rows

    server_findings = [FindingSchema(**finding.model_dump()) for finding in result.findings]
    if server_findings:
        db.add_all(_finding_rows(run.id, server_findings, mandate_id))
        await db.commit()

    try:
        from wombat_server.routers.achievements import evaluate_and_record_achievements

        await evaluate_and_record_achievements(db, run)
    except Exception:
        logger.exception("achievement evaluation failed for run %s", run.id)

    await _report(progress, 90, "finalizing")

    await publish_event(
        "run.created",
        {
            "id": str(run.id),
            "project": run.project,
            "branch": run.branch,
            "score": run.score,
            "stage": run.stage,
            "created_at": run.created_at.isoformat(),
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        },
        mandate_id=run.mandant_id,
    )
    await publish_event(
        "scan.completed",
        {"run_id": str(run.id), "project": run.project, "score": run.score},
        mandate_id=run.mandant_id,
    )

    return run
