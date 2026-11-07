"""Optional OpenTelemetry tracing and Sentry error reporting.

Both are lazy and environment-gated: the app starts normally with neither a
collector nor a DSN configured.
"""
from __future__ import annotations

import logging

from fastapi import FastAPI

from wombat_server import __version__
from wombat_server.config import settings

log = logging.getLogger("wombat_server.tracing")


def setup_tracing(app: FastAPI) -> None:
    if not settings.wombat_otel_enabled:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

        from wombat_server.database import engine

        exporter = (
            OTLPSpanExporter(endpoint=settings.wombat_otel_endpoint)
            if settings.wombat_otel_endpoint
            else OTLPSpanExporter()
        )
        provider = TracerProvider(
            resource=Resource.create(
                {"service.name": "wombat-server", "service.version": __version__}
            ),
            sampler=TraceIdRatioBased(max(0.0, min(1.0, settings.wombat_otel_sample_rate))),
        )
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        FastAPIInstrumentor.instrument_app(app)
        SQLAlchemyInstrumentor().instrument(engine=engine.sync_engine)
        log.info("OpenTelemetry tracing enabled")
    except Exception:
        log.warning("OpenTelemetry setup failed; continuing without tracing", exc_info=True)


def setup_sentry() -> None:
    if not settings.wombat_sentry_dsn:
        return
    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration

        sentry_sdk.init(
            dsn=settings.wombat_sentry_dsn,
            environment=settings.wombat_sentry_environment or settings.wombat_env,
            release=__version__,
            send_default_pii=False,
            traces_sample_rate=max(0.0, min(1.0, settings.wombat_otel_sample_rate)),
            integrations=[FastApiIntegration()],
        )
        log.info("Sentry error reporting enabled")
    except Exception:
        log.warning("Sentry setup failed; continuing without error reporting", exc_info=True)
