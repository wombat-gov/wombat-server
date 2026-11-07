"""Liveness, readiness, and version-independent health checks."""
from __future__ import annotations

import logging
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from wombat_server.config import settings
from wombat_server.database import get_db

log = logging.getLogger("wombat_server.health")

router = APIRouter(tags=["health"])

_HEAD_CACHE: str | None = None


def _alembic_head() -> str | None:
    global _HEAD_CACHE
    if _HEAD_CACHE is not None:
        return _HEAD_CACHE
    ini = Path("alembic.ini")
    script_dir = Path("alembic")
    if not ini.exists() or not script_dir.exists():
        return None
    cfg = Config(str(ini))
    cfg.set_main_option("script_location", str(script_dir))
    _HEAD_CACHE = ScriptDirectory.from_config(cfg).get_current_head()
    return _HEAD_CACHE


@router.get("/livez")
async def livez() -> dict[str, str]:
    """Process liveness only. Safe for a Kubernetes liveness probe."""
    return {"status": "ok"}


@router.get("/health")
async def health() -> dict[str, str]:
    """Backward-compatible alias for /livez."""
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Dependency readiness: database, migrations, and the controls catalogue.

    Returns 503 with a component map when a dependency is unhealthy. It never
    returns a DSN, file path, or stack trace.
    """
    components: dict[str, str] = {}
    healthy = True

    try:
        await db.execute(text("SELECT 1"))
        components["database"] = "ok"
    except Exception:
        log.warning("readiness: database check failed", exc_info=True)
        components["database"] = "error"
        healthy = False

    try:
        result = await db.execute(text("SELECT version_num FROM alembic_version"))
        current = result.scalar_one_or_none()
        head = _alembic_head()
        if head and current == head:
            components["migrations"] = "ok"
        else:
            components["migrations"] = "out_of_date"
            healthy = False
    except Exception:
        log.warning("readiness: migration check failed", exc_info=True)
        components["migrations"] = "error"
        healthy = False

    try:
        controls_dir = Path(settings.wombat_controls_dir)
        files = list(controls_dir.glob("*.yaml")) + list(controls_dir.glob("*.yml"))
        if files:
            components["controls"] = f"ok ({len(files)})"
        else:
            components["controls"] = "empty"
            healthy = False
    except Exception:
        components["controls"] = "error"
        healthy = False

    return JSONResponse(
        {"status": "ok" if healthy else "degraded", "components": components},
        status_code=200 if healthy else 503,
    )
