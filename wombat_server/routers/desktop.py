"""Desktop app summary endpoint — one call for the menu-bar widgets."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from wombat_server import __version__
from wombat_server.auth.deps import AuthContext, get_auth_context, get_scoped_db
from wombat_server.models import Notification, RiskAcceptance, Run, Waiver
from wombat_server.notification_visibility import visible_notifications
from wombat_server.schemas import (
    DesktopDigest,
    DesktopGovernance,
    DesktopGovernanceItem,
    DesktopLatestRun,
    DesktopNotifications,
    DesktopSummary,
    Envelope,
)

router = APIRouter(prefix="/desktop", tags=["desktop"])


def _finding_stats(run: Run) -> dict[str, int | None]:
    """Summarise the run's stored findings the same way the dashboard does:
    WAIVED wins, then FAIL, for the distinct control count."""
    findings = run.findings or []
    statuses_by_control: dict[str, list[str]] = {}
    for finding in findings:
        control_id = finding.get("control_id")
        if not control_id:
            continue
        statuses_by_control.setdefault(str(control_id), []).append(
            str(finding.get("status", "")).upper()
        )

    failed_controls = sum(
        1 for statuses in statuses_by_control.values()
        if "WAIVED" not in statuses and "FAIL" in statuses
    )
    fails = [f for f in findings if str(f.get("status", "")).upper() == "FAIL"]
    passes = sum(1 for f in findings if str(f.get("status", "")).upper() == "PASS")
    total = len(findings)

    return {
        "failed_controls": failed_controls,
        "critical": sum(1 for f in fails if str(f.get("severity", "")).upper() == "CRITICAL"),
        "high": sum(1 for f in fails if str(f.get("severity", "")).upper() == "HIGH"),
        "pass_rate": round(passes / total * 100) if total else None,
    }


@router.get("/summary", response_model=Envelope[DesktopSummary])
async def desktop_summary(
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    project: Annotated[str | None, Query()] = None,
) -> Envelope[DesktopSummary]:
    """Aggregated data for the desktop menu-bar widgets.

    Everything is RLS-scoped; the optional project filter narrows the latest
    run, trend and digest (the project list stays global for the filter UI).
    """
    order = (Run.created_at.desc(), Run.id.desc())

    latest_stmt = select(Run)
    trend_stmt = select(Run.score)
    digest_stmt = select(
        func.count(),
        func.count(distinct(Run.project)),
    )
    if project:
        latest_stmt = latest_stmt.where(Run.project == project)
        trend_stmt = trend_stmt.where(Run.project == project)
        digest_stmt = digest_stmt.where(Run.project == project)

    latest = (
        await db.execute(latest_stmt.order_by(*order).limit(1))
    ).scalar_one_or_none()

    score_rows = (
        await db.execute(trend_stmt.order_by(*order).limit(10))
    ).scalars().all()
    trend = [int(score or 0) for score in reversed(score_rows)]

    project_rows = (
        await db.execute(select(Run.project).distinct().order_by(Run.project).limit(200))
    ).scalars().all()
    projects = [name for name in project_rows if name]

    unread = int(
        (
            await db.execute(
                select(func.count())
                .select_from(Notification)
                .where(
                    visible_notifications(auth.user),
                    Notification.is_read.is_(False),
                )
            )
        ).scalar_one()
        or 0
    )

    today = date.today()
    waiver_rows = (
        await db.execute(select(Waiver).where(Waiver.expires.is_not(None)))
    ).scalars().all()
    risk_rows = (
        await db.execute(select(RiskAcceptance).where(RiskAcceptance.expires.is_not(None)))
    ).scalars().all()

    governance_items: list[DesktopGovernanceItem] = []
    for kind, rows in (("waiver", waiver_rows), ("risk", risk_rows)):
        for row in rows:
            if row.expires is None:
                continue
            governance_items.append(
                DesktopGovernanceItem(
                    type=kind,
                    project=row.project or "",
                    days=(row.expires - today).days,
                    expires=row.expires,
                )
            )
    expired = [item for item in governance_items if item.days < 0]
    expiring = [item for item in governance_items if 0 <= item.days <= 7]
    next_items = sorted([*expired, *expiring], key=lambda item: item.days)[:3]

    since = datetime.now(timezone.utc) - timedelta(hours=24)
    runs_24h, projects_24h = (
        await db.execute(digest_stmt.where(Run.created_at >= since))
    ).one()

    latest_run = None
    if latest is not None:
        stats = _finding_stats(latest)
        latest_run = DesktopLatestRun(
            id=latest.id,
            project=latest.project,
            branch=latest.branch,
            stage=latest.stage,
            iac_framework=latest.iac_framework,
            score=latest.score,
            failed_controls=int(stats["failed_controls"] or 0),
            critical=int(stats["critical"] or 0),
            high=int(stats["high"] or 0),
            pass_rate=stats["pass_rate"],
            controls_run=latest.controls_run,
            controls_loaded=latest.controls_loaded,
            created_at=latest.created_at,
            completed_at=latest.completed_at,
        )

    return Envelope(
        data=DesktopSummary(
            generated_at=datetime.now(timezone.utc),
            version=__version__,
            latest_run=latest_run,
            trend=trend,
            projects=projects,
            selected_project=project or "",
            notifications=DesktopNotifications(unread=unread),
            governance=DesktopGovernance(
                expiring=len(expiring),
                expired=len(expired),
                next=next_items,
            ),
            digest=DesktopDigest(
                runs_24h=int(runs_24h or 0),
                projects_24h=int(projects_24h or 0),
            ),
        )
    )
