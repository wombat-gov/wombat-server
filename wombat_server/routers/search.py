"""Global search for the desktop command palette (Wave C).

One endpoint, ranked across runs, findings, controls, waivers, risks and
projects. RLS scopes every query to the caller's mandate.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from wombat_server.auth.deps import get_scoped_db
from wombat_server.models import Control, ProjectPassport, RiskAcceptance, Run, RunFinding, Waiver
from wombat_server.schemas import Envelope, Meta, SearchResult

router = APIRouter(prefix="/search", tags=["search"])

ALL_TYPES = ("runs", "findings", "controls", "waivers", "risks", "projects")


def _like(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _sim(column, query: str):
    return func.similarity(func.lower(column), query.lower())


@router.get("", response_model=Envelope[list[SearchResult]])
async def search(
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    q: Annotated[str, Query(min_length=1, max_length=100)],
    types: Annotated[str, Query()] = ",".join(ALL_TYPES),
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> Envelope[list[SearchResult]]:
    query = q.strip()
    if not query:
        return Envelope(data=[], meta=Meta(total=0))

    selected = {item.strip().lower() for item in types.split(",") if item.strip()}
    selected &= set(ALL_TYPES)
    pattern = _like(query)
    results: list[SearchResult] = []

    if "runs" in selected:
        rank = _sim(Run.project, query).label("rank")
        rows = (
            await db.execute(
                select(Run, rank)
                .where(or_(Run.project.ilike(pattern, escape="\\"), Run.branch.ilike(pattern, escape="\\")))
                .order_by(rank.desc(), Run.created_at.desc())
                .limit(limit * 2)
            )
        ).all()
        seen_projects: set[str] = set()
        for run, score in rows:
            key = (run.project or "").lower() or str(run.id)
            if key in seen_projects:
                continue
            seen_projects.add(key)
            subtitle = f"{run.score}/100 · {run.stage or run.branch or 'run'}"
            results.append(
                SearchResult(
                    type="run",
                    id=str(run.id),
                    title=run.project or "run",
                    subtitle=subtitle,
                    route="dashboard",
                    run_id=str(run.id),
                    score=run.score,
                    rank=float(score or 0),
                )
            )

    if "findings" in selected:
        rank = _sim(RunFinding.check_title, query).label("rank")
        rows = (
            await db.execute(
                select(RunFinding, Run.project, rank)
                .join(Run, Run.id == RunFinding.run_id)
                .where(
                    or_(
                        RunFinding.check_title.ilike(pattern, escape="\\"),
                        RunFinding.control_id.ilike(pattern, escape="\\"),
                        RunFinding.check_id.ilike(pattern, escape="\\"),
                    )
                )
                .order_by(rank.desc(), RunFinding.id)
                .limit(limit)
            )
        ).all()
        for finding, project, score in rows:
            subtitle = " · ".join(
                part for part in (finding.severity, finding.status, project) if part
            )
            results.append(
                SearchResult(
                    type="finding",
                    id=str(finding.id),
                    title=finding.check_title or finding.control_id or finding.check_id or "finding",
                    subtitle=subtitle,
                    route="findings",
                    run_id=str(finding.run_id),
                    rank=float(score or 0),
                )
            )

    if "controls" in selected:
        rank = _sim(Control.id, query).label("rank")
        rows = (
            await db.execute(
                select(Control, rank)
                .where(
                    or_(
                        Control.id.ilike(pattern, escape="\\"),
                        Control.description.ilike(pattern, escape="\\"),
                    )
                )
                .order_by(rank.desc(), Control.id)
                .limit(limit)
            )
        ).all()
        for control, score in rows:
            results.append(
                SearchResult(
                    type="control",
                    id=control.id,
                    title=control.id,
                    subtitle=control.description or " · ".join(
                        part for part in (control.pillar, control.severity) if part
                    ),
                    route="catalogue",
                    rank=float(score or 0),
                )
            )

    if "waivers" in selected:
        rank = _sim(Waiver.id, query).label("rank")
        rows = (
            await db.execute(
                select(Waiver, rank)
                .where(
                    or_(
                        Waiver.id.ilike(pattern, escape="\\"),
                        Waiver.reason.ilike(pattern, escape="\\"),
                        Waiver.project.ilike(pattern, escape="\\"),
                    )
                )
                .order_by(rank.desc(), Waiver.id)
                .limit(limit)
            )
        ).all()
        for waiver, score in rows:
            results.append(
                SearchResult(
                    type="waiver",
                    id=waiver.id,
                    title=waiver.id,
                    subtitle=" · ".join(part for part in (waiver.reason, waiver.project) if part),
                    route="waivers",
                    rank=float(score or 0),
                )
            )

    if "risks" in selected:
        rank = _sim(RiskAcceptance.id, query).label("rank")
        rows = (
            await db.execute(
                select(RiskAcceptance, rank)
                .where(
                    or_(
                        RiskAcceptance.id.ilike(pattern, escape="\\"),
                        RiskAcceptance.reason.ilike(pattern, escape="\\"),
                        RiskAcceptance.project.ilike(pattern, escape="\\"),
                    )
                )
                .order_by(rank.desc(), RiskAcceptance.id)
                .limit(limit)
            )
        ).all()
        for risk, score in rows:
            results.append(
                SearchResult(
                    type="risk",
                    id=risk.id,
                    title=risk.id,
                    subtitle=" · ".join(
                        part for part in (risk.reason, risk.project, risk.risk_level) if part
                    ),
                    route="risk",
                    rank=float(score or 0),
                )
            )

    if "projects" in selected:
        rank = _sim(ProjectPassport.project, query).label("rank")
        rows = (
            await db.execute(
                select(ProjectPassport, rank)
                .where(
                    or_(
                        ProjectPassport.project.ilike(pattern, escape="\\"),
                        ProjectPassport.display_name.ilike(pattern, escape="\\"),
                        ProjectPassport.description.ilike(pattern, escape="\\"),
                    )
                )
                .order_by(rank.desc(), ProjectPassport.project)
                .limit(limit)
            )
        ).all()
        for passport, score in rows:
            results.append(
                SearchResult(
                    type="project",
                    id=passport.project,
                    title=passport.display_name or passport.project,
                    subtitle=passport.description or passport.owner or "",
                    route="projectoverview",
                    rank=float(score or 0),
                )
            )

    results.sort(key=lambda item: item.rank, reverse=True)
    limited = results[:limit]
    return Envelope(data=limited, meta=Meta(total=len(limited)))
