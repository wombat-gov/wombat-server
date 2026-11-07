"""Prometheus metrics and application counters.

The counters are no-ops when prometheus_client is not installed, so importing
this module can never break the app in a minimal runtime.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI

from wombat_server.config import settings

log = logging.getLogger("wombat_server.metrics")

login_failures: Any
login_locked: Any
runs_ingested: Any
db_pool_in_use: Any
controls_loaded: Any


class _NoopCounter:
    def inc(self, *args, **kwargs) -> None:  # noqa: D401 - intentionally tiny
        return None


class _NoopGauge:
    def set(self, *args, **kwargs) -> None:
        return None

    def set_function(self, *args, **kwargs) -> None:
        return None


try:
    from prometheus_client import Counter, Gauge

    login_failures = Counter(
        "wombat_login_failures_total",
        "Failed password logins (valid or unknown username).",
    )
    login_locked = Counter(
        "wombat_login_locked_total",
        "Accounts locked after repeated failed logins.",
    )
    runs_ingested = Counter(
        "wombat_runs_ingested_total",
        "Scan runs ingested through POST /api/v1/runs.",
    )
    db_pool_in_use = Gauge(
        "wombat_db_pool_in_use",
        "Checked-out connections in the runtime database pool.",
    )
    controls_loaded = Gauge(
        "wombat_controls_loaded",
        "YAML control files visible to the server.",
    )
except Exception:  # pragma: no cover - minimal runtime without prometheus
    login_failures = _NoopCounter()
    login_locked = _NoopCounter()
    runs_ingested = _NoopCounter()
    db_pool_in_use = _NoopGauge()
    controls_loaded = _NoopGauge()


def setup_metrics(app: FastAPI) -> None:
    """Expose /metrics and register gauges. No-op when disabled or unavailable."""
    if not settings.wombat_metrics_enabled:
        return
    try:
        from prometheus_fastapi_instrumentator import Instrumentator

        Instrumentator(
            should_group_status_codes=True,
            should_ignore_untemplated=True,
            excluded_handlers=["/metrics", "/health", "/livez", "/readyz"],
        ).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)
    except Exception:
        log.warning("Prometheus instrumentation unavailable", exc_info=True)
        return

    try:
        from wombat_server.database import engine

        checkedout = getattr(engine.pool, "checkedout", None)
        if callable(checkedout):
            db_pool_in_use.set_function(lambda: float(checkedout()))
    except Exception:
        pass

    try:
        controls_dir = Path(settings.wombat_controls_dir)
        controls_loaded.set(
            len(list(controls_dir.glob("*.yaml"))) + len(list(controls_dir.glob("*.yml")))
        )
    except Exception:
        pass
