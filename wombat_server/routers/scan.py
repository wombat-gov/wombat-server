"""POST /scan — run the Wombat engine against a server-side IaC path and persist as a Run.

Unlike /sandbox (ephemeral, IaC-snippet only), this endpoint:
  1. Accepts a filesystem path accessible to the server process
  2. Runs the full wombat engine (same controls as the CLI)
  3. Persists the result as a Run record in the database
  4. Returns a RunSummary identical to what POST /runs would return

Security
--------
All paths are resolved and checked to be within WOMBAT_SCAN_BASE_DIR.  When
that variable is unset the base defaults to the server's working directory,
so arbitrary absolute paths are never accepted by default.

The endpoint can be disabled entirely by setting WOMBAT_SCAN_ENABLED=false.
"""
from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from wombat_server.auth.deps import IngestAuth, require_ingest, require_role
from wombat_server.config import settings
from wombat_server.database import get_db
from wombat_server.events import publish_event
from wombat_server.models import ApiKeyUsageLog, Run, User
from wombat_server.path_safety import resolve_scan_path
from wombat_server.schemas import Envelope, FindingSchema, RunSummary

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["scan"])

# Valid pillar values (matching the schema and dashboard)
_VALID_PILLARS = ["security", "cost", "operations", "performance", "reliability", "sovereign", "sustainability", "agentic"]

# Lazy-checked once per process startup
_wombat_available: bool | None = None


def _check_wombat() -> bool:
    global _wombat_available
    if _wombat_available is None:
        try:
            import wombat  # noqa: F401
            _wombat_available = True
        except ImportError:
            _wombat_available = False
    return _wombat_available


# ── Request schema ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    path: str
    iac: str = "terraform"
    project: str = ""
    branch: str = ""
    stage: str = ""
    triggered_by: str = "ui"


# ── Path validation ───────────────────────────────────────────────────────────

def _resolve_and_validate(raw: str) -> Path:
    """Resolve *raw* and confine it to the configured scan base directory."""
    return resolve_scan_path(raw)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/status")
async def scan_status(
    _: Annotated[User, Depends(require_role("clevel"))],
) -> dict:
    """Check whether server-side scanning is available."""
    controls_dir = Path(settings.wombat_controls_dir)
    base_raw = (settings.wombat_scan_base_dir or "").strip()
    return {
        "enabled": getattr(settings, "wombat_scan_enabled", True),
        "engine_available": _check_wombat(),
        "controls_dir": str(controls_dir.resolve()),
        "controls_dir_exists": controls_dir.exists(),
        "scan_base_dir": base_raw or None,
    }


@router.post("", response_model=Envelope[RunSummary], status_code=201)
async def trigger_scan(
    request: Request,
    payload: ScanRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    auth: Annotated[IngestAuth, Depends(require_ingest)],
) -> Envelope[RunSummary]:
    """Trigger a Wombat scan on a server-side path and persist the result."""

    if not getattr(settings, "wombat_scan_enabled", True):
        raise HTTPException(status_code=503, detail="Server-side scanning is disabled (WOMBAT_SCAN_ENABLED=false).")

    if not _check_wombat():
        raise HTTPException(
            status_code=503,
            detail=(
                "wombat-core is not importable on this server. "
                "Reinstall with: pip install wombat-core"
            ),
        )

    # Validate & resolve scan target path
    scan_path = _resolve_and_validate(payload.path)

    # Validate controls directory
    controls_dir = Path(settings.wombat_controls_dir)
    if not controls_dir.exists():
        raise HTTPException(
            status_code=503,
            detail=(
                f"Controls directory not found: {controls_dir.resolve()}. "
                "Set WOMBAT_CONTROLS_DIR to the path containing your Wombat YAML files."
            ),
        )

    # All wombat imports are lazy so the server starts without wombat-core
    from wombat.runner import ScanConfig, run_scan  # type: ignore[import]

    try:
        _report, result = run_scan(ScanConfig(
            paths=[scan_path],
            controls_dir=controls_dir,
            iac=payload.iac,
            project=payload.project,
            branch=payload.branch,
            stage=payload.stage,
            triggered_by=payload.triggered_by,
            upload_source=True,
        ))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc

    # Normalize pillar names: database may have "operational", use "operations" for consistency
    def normalize_pillar(p: str) -> str:
        if p == "operational":
            return "operations"
        return p

    # Ensure all valid pillars are represented (score 0 if missing)
    pillar_scores: dict[str, int] = {p: 0 for p in _VALID_PILLARS}
    for p, score in result.pillar_scores.items():
        normalized = normalize_pillar(p)
        if normalized in pillar_scores:
            pillar_scores[normalized] = score

    # Persist as a Run record
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
        findings=[f.model_dump() for f in result.findings],
        path=result.path,
        controls_loaded=result.controls_loaded,
        controls_run=result.controls_run,
        detected_regions=result.detected_regions,
        source_paths=result.source_paths,
        controls_meta=[c.model_dump() for c in result.controls_meta],
        secret_findings=[sf.model_dump() for sf in result.secret_findings],
        plan_changes=result.plan_changes,
        source_snapshot=result.source_snapshot,
        mandant_id=auth.mandant_id,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    from wombat_server.routers.achievements import evaluate_and_record_achievements
    from wombat_server.routers.runs import _finding_rows
    server_findings = [FindingSchema(**f.model_dump()) for f in result.findings]
    if server_findings:
        db.add_all(_finding_rows(run.id, server_findings, auth.mandant_id))
        await db.commit()

    await evaluate_and_record_achievements(db, run)

    # Write a usage log row when a DB-tracked API key was used
    if auth.api_key_id is not None:
        client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "")
        db.add(ApiKeyUsageLog(
            api_key_id=auth.api_key_id,
            endpoint="POST /scan",
            run_id=run.id,
            project=run.project,
            branch=run.branch,
            score=run.score,
            ip=client_ip,
        ))
        await db.commit()

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

    return Envelope(data=RunSummary.model_validate(run, from_attributes=True))
