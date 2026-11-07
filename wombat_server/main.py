"""WOMBATpass server entry point."""
from __future__ import annotations

import asyncio
import logging
import os
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from starlette.middleware.trustedhost import TrustedHostMiddleware

from wombat_server.auth.csrf import CSRFMiddleware, SecurityHeadersMiddleware
from wombat_server.config import settings, validate_runtime_settings
from wombat_server.database import get_db
from wombat_server.models import Validation
from wombat_server.observability.health import router as health_router
from wombat_server.observability.logging import configure_logging
from wombat_server.observability.metrics import setup_metrics
from wombat_server.observability.middleware import RequestContextMiddleware
from wombat_server.observability.tracing import setup_sentry, setup_tracing
from wombat_server.routers.admin import router as admin_router
from wombat_server.routers.auth import router as auth_router
from wombat_server.routers.controls import router as controls_router
from wombat_server.routers.control_packs import router as control_packs_router
from wombat_server.routers.evidence import router as evidence_router
from wombat_server.routers.risks import router as risks_router
from wombat_server.routers.runs import router as runs_router
from wombat_server.routers.sandbox import router as sandbox_router
from wombat_server.routers.scan import router as scan_router
from wombat_server.routers.achievements import router as achievements_router
from wombat_server.routers.badges import router as badges_router
from wombat_server.routers.leaderboard import router as leaderboard_router
from wombat_server.routers.projects import router as projects_router
from wombat_server.routers.sso import router as sso_router
from wombat_server.routers.scim import router as scim_router
from wombat_server.routers.compliance_audit import router as compliance_audit_router
from wombat_server.routers.waivers import router as waivers_router
from wombat_server.routers.findings_comments import router as findings_comments_router
from wombat_server.routers.secret_findings_comments import router as secret_findings_comments_router
from wombat_server.routers.widgets import router as widgets_router
from wombat_server.routers.notifications import router as notifications_router
from wombat_server.routers.pipelines import router as pipelines_router
from wombat_server.routers.update_checker import router as update_router
from wombat_server.routers.auto_fix import router as auto_fix_router
from wombat_server.routers.validations import router as validations_router
from wombat_server.validation_service import ValidationService, load_validation_service

# Framework update info path - configurable via environment variable
_FRAMEWORK_UPDATE_INFO_PATH = os.environ.get(
    "WOMBAT_UPDATE_INFO_PATH", "/app/framework-update-info.yml"
)

# Configure structured logging once, before the app starts serving.
configure_logging()

app = FastAPI(
    title="wombat-server",
    version="1.2.0",
    description="REST API for persisting and querying WOMBATpass scan results.",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    openapi_tags=[
        {"name": "auth", "description": "Login, token refresh, logout, user management."},
        {"name": "runs", "description": "Scan run results ingestion and retrieval."},
        {"name": "pipelines", "description": "CI/CD pipeline metrics and trends."},
        {"name": "controls", "description": "Wombat control catalogue management."},
        {"name": "control-packs", "description": "Versioned control pack import, activation and rollback."},
        {"name": "waivers", "description": "Team-shared waiver records."},
        {"name": "risks", "description": "Team-shared risk acceptance records."},
        {"name": "sandbox", "description": "Run the real Wombat engine against arbitrary IaC snippets (currently HCL)."},
        {"name": "scan", "description": "Run the Wombat engine against a server-side IaC path and persist the result."},
        {"name": "auto-fix", "description": "Preview, apply, and roll back automated IaC remediations."},
        {"name": "sso", "description": "SSO configuration and login flows (OIDC, SAML2)."},
        {"name": "evidence", "description": "Locked, immutable evidence packages for audit handouts with QR codes."},
        {"name": "projects", "description": "Project passport — per-project metadata, editable by admin and architect."},
        {"name": "achievements", "description": "Verified maturity achievements with public proof-of-excellence pages."},
        {"name": "badges", "description": "Live SVG status badges for READMEs — shields.io-style, no auth required."},
        {"name": "leaderboard", "description": "Hall of Fame — top sovereign and most improved projects."},
        {"name": "audit", "description": "Server-side compliance audit log — waiver, risk, scan, and finding events."},
        {"name": "findings-comments", "description": "Team collaboration on findings — comments, notifications, and remediation tracking."},
        {"name": "widgets", "description": "Widget management — create dashboards for compliance data display on computers, TVs, or web pages."},
        {"name": "validations", "description": "Official cryptographic validation of WOMBATpass runs — certificate chain and badges."},
    ],
)

# In local development, allow any localhost/private-network origin so the Vite
# dev server (or a dashboard served from any local port/host) can call the API
# without manually maintaining CORS_ORIGINS. Production keeps the strict list.
_LOCAL_ORIGIN_REGEX = (
    r"https?://([a-zA-Z0-9.-]+|localhost|127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?$"
    if settings.wombat_env == "local"
    else None
)

# Local development: allow any localhost/cloud.waf2p origin regardless of port,
# so the dashboard works whether served through docker host networking, a custom
# DNS entry in /etc/hosts, or a Vite dev server on any port.
_cors_origins = settings.cors_origins_list
_cors_origin_regex = None
if settings.wombat_env == "local":
    _cors_origin_regex = r"^http://(localhost|cloud\.waf2p)(:\d+)?$"

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_origin_regex=_LOCAL_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[],
)

# Reject Host-header injection before routing. Outside local, an empty
# allowlist is a startup error (see validate_runtime_settings), so this is
# only permissive in development.
if settings.allowed_hosts_list:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.allowed_hosts_list,
    )

# Defense-in-depth headers on API responses; CSRF applies only to
# cookie-authenticated unsafe requests (Bearer/API-key clients are exempt).
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CSRFMiddleware)
# Outer-most: correlate and log every request, including CSRF rejections.
app.add_middleware(RequestContextMiddleware)


@app.exception_handler(Exception)
async def _unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
    """Log unexpected failures and return a correlation ID, never a traceback."""
    request_id = getattr(request.state, "request_id", "")
    logging.getLogger("wombat_server.error").exception(
        "Unhandled exception", extra={"request_id": request_id}
    )
    return JSONResponse(
        {"detail": "Internal server error", "request_id": request_id},
        status_code=500,
    )

app.include_router(auth_router, prefix="/api/v1")
app.include_router(admin_router, prefix="/api/v1")
app.include_router(compliance_audit_router, prefix="/api/v1")
app.include_router(sso_router, prefix="/api/v1")
app.include_router(scim_router)
app.include_router(achievements_router, prefix="/api/v1")
app.include_router(badges_router, prefix="/api/v1")
app.include_router(leaderboard_router, prefix="/api/v1")
app.include_router(runs_router, prefix="/api/v1")
app.include_router(pipelines_router, prefix="/api/v1")
app.include_router(controls_router, prefix="/api/v1")
app.include_router(control_packs_router, prefix="/api/v1")
app.include_router(waivers_router, prefix="/api/v1")
app.include_router(risks_router, prefix="/api/v1")
app.include_router(evidence_router, prefix="/api/v1")
app.include_router(projects_router, prefix="/api/v1")
app.include_router(findings_comments_router, prefix="/api/v1")
app.include_router(secret_findings_comments_router, prefix="/api/v1")
app.include_router(sandbox_router, prefix="/api/v1")
app.include_router(scan_router, prefix="/api/v1")
app.include_router(widgets_router, prefix="/api/v1")
app.include_router(notifications_router, prefix="/api/v1")
app.include_router(update_router, prefix="/api/v1")
app.include_router(auto_fix_router, prefix="/api/v1")
# Liveness/readiness routes (/livez, /health, /readyz).
app.include_router(health_router)


# Module-level validation service singleton for public trust endpoints.
_validation_service: ValidationService | None = None


def _get_validation_service() -> ValidationService:
    global _validation_service
    if _validation_service is None:
        keys_dir = settings.wombat_validation_keys_dir or None
        subca_cert_path = settings.wombat_server_subca_cert or None
        _validation_service = load_validation_service(
            keys_dir=keys_dir,
            subca_cert_path=subca_cert_path,
        )
    return _validation_service


@app.get("/api/v1/validations/root.crt", tags=["validations"])
async def get_root_certificate() -> Response:
    """Publish the Wombat root CA certificate (public trust anchor)."""
    service = _get_validation_service()
    return Response(
        content=service.root_cert_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="wombat-root.crt"'},
    )


@app.get("/api/v1/validations/server.crt", tags=["validations"])
async def get_server_certificate() -> Response:
    """Publish this wombat-server's gateway-issued sub-CA certificate.

    The dashboard and CLI include this certificate when submitting validation
    runs to the central Wombat gateway so the gateway can verify the server's
    identity against its registered certificate registry.
    """
    service = _get_validation_service()
    cert_pem = service.server_subca_certificate_pem
    return Response(
        content=cert_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="wombat-server.crt"'},
    )


@app.get("/api/v1/revocations", tags=["validations"])
async def get_revocation_list(
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return a signed list of all revoked validation IDs (public).

    The list is signed by the Wombat server intermediate key so verifiers can
    check it offline against the published root certificate.
    """
    result = await db.execute(select(Validation.validation_id).where(Validation.status == "revoked"))
    revoked_ids = sorted(row[0] for row in result.all())

    service = _get_validation_service()
    return service.sign_revocation_list(revoked_validation_ids=revoked_ids)


app.include_router(validations_router, prefix="/api/v1")


@app.get("/framework-update-info.yml", tags=["updates"])
async def get_framework_update_info() -> FileResponse:
    """Serve the framework update information YAML file.

    This endpoint returns the auto-generated update info file that contains
    version information from the public Wombat framework repository on GitHub.
    """
    if not os.path.exists(_FRAMEWORK_UPDATE_INFO_PATH):
        raise HTTPException(status_code=404, detail="Update info not available yet")
    return FileResponse(
        _FRAMEWORK_UPDATE_INFO_PATH, media_type="text/yaml", filename="framework-update-info.yml"
    )


@app.get("/version", tags=["health"])
async def version() -> dict[str, str]:
    """Return version information for the server and wombat-core."""
    from wombat_server import __version__ as server_version
    try:
        from importlib.metadata import version as _pkg_version
        try:
            core_version = _pkg_version("wombat-core")
        except Exception:
            # Deprecated: the package was published as wafpass-core before the rebrand.
            core_version = _pkg_version("wafpass-core")
    except Exception:
        core_version = "unknown"
    return {
        "server_version": server_version,
        "core_version": core_version,
        # Current field names.
        "wombat_server": server_version,
        "wombat_core": core_version,
        # Deprecated WAFpass-era aliases, kept for older dashboards/clients.
        "wafpass_server": server_version,
        "wafpass_core": core_version,
    }


# Background task for hourly update checking
_update_checker_task: asyncio.Task | None = None


async def _hourly_update_checker() -> None:
    """Background task that runs hourly update checks."""
    import asyncio
    from wombat_server.update_checker import generate_update_info

    while True:
        try:
            # Run the update check using configurable path
            await generate_update_info(_FRAMEWORK_UPDATE_INFO_PATH)
            logging.getLogger("wombat_server").info("Framework update check completed")
        except Exception as e:
            logging.getLogger("wombat_server").error(f"Framework update check failed: {e}")

        # Sleep for 1 hour (3600 seconds)
        await asyncio.sleep(3600)


def _validate_startup_config() -> None:
    """Fail fast if required secrets are missing or still placeholders."""
    import sys

    logger = logging.getLogger("wombat_server")
    try:
        # Force the Pydantic model to validate; this catches placeholder JWT secrets.
        settings.model_validate(settings.model_dump())
    except ValueError as exc:
        logger.error("Invalid server configuration: %s", exc)
        sys.exit(1)

    required = ["WOMBAT_JWT_SECRET"]
    missing = [k for k in required if not getattr(settings, k.lower(), None)]
    if missing:
        logger.error(
            "Missing required environment variables: %s. "
            "Run 'wombat init --mode dashboard' to generate a valid .env file.",
            ", ".join(missing),
        )
        sys.exit(1)


async def seed_bootstrap_admin_if_empty(logger: logging.Logger) -> None:
    """Create the bootstrap admin user if the users table is empty.

    Extracted into its own function so it's directly testable, independent
    of _configure_logging_and_seed_admin()'s logging setup, config
    validation, and background update-checker task — none of which this
    needs or should pull in just to verify this one behaviour.
    """
    if not settings.wombat_admin_password:
        return  # seeding disabled

    from sqlalchemy import select, func
    from sqlalchemy.ext.asyncio import AsyncSession
    from wombat_server.database import get_owner_connection
    from wombat_server.models import User
    from wombat_server.auth.providers.local import hash_password

    # Owner connection, not the pooled AsyncSessionLocal: once multi-mandant
    # mode is active, a plain RLS-enforced session sees ZERO rows here
    # regardless of how many users actually exist (no mandate/holding GUC
    # is ever set for this startup-time check), which made this block
    # conclude "table is empty" on every restart and try to insert a
    # second bootstrap admin — which then itself failed RLS's WITH CHECK
    # (no mandate, no holding flag), crashing the entire startup. Found via
    # a real crash-loop (9 restarts) on a live instance already in
    # multi_mandant mode. This check is a privileged, one-time bootstrap
    # action, same category as Alembic migrations and the activation DDL —
    # it belongs on the owner role, which RLS does not apply to at all,
    # not on ordinary runtime traffic's role.
    async with get_owner_connection() as conn:
        db = AsyncSession(bind=conn)
        count = (await db.execute(select(func.count()).select_from(User))).scalar_one()
        if count > 0:
            logger.info("Users already exist — skipping admin seeding")
            return  # users already exist — don't overwrite anything

        admin = User(
            username=settings.wombat_admin_username,
            display_name="Administrator",
            role=settings.wombat_admin_role,
            auth_provider="local",
            password_hash=hash_password(settings.wombat_admin_password),
            must_change_password=settings.wombat_force_password_rotation,
        )
        db.add(admin)
        await db.commit()
        logger.info(
            "Seeded admin user '%s' with role '%s'.",
            settings.wombat_admin_username,
            settings.wombat_admin_role,
        )


@app.on_event("startup")
async def _configure_logging_and_seed_admin() -> None:
    """Configure logging, validate config, and create the bootstrap admin user if no users exist."""
    global _update_checker_task

    # Validate secrets before serving traffic; tests/imports use permissive defaults.
    validate_runtime_settings()

    logger = logging.getLogger("wombat_server")
    logger.info("=== Wombat Server starting ===")

    # Validate configuration before attempting database connections.
    _validate_startup_config()

    # Generate initial update info on startup (always run, regardless of seeding)
    logger.info("Generating initial framework update info...")
    try:
        from wombat_server.update_checker import generate_update_info
        await generate_update_info(_FRAMEWORK_UPDATE_INFO_PATH)
        logging.getLogger("wombat_server").info("Initial framework update info generated successfully")
    except Exception as e:
        logging.getLogger("wombat_server").error(f"Failed to generate initial update info: {e}")
        import traceback
        logging.getLogger("wombat_server").error(f"Traceback: {traceback.format_exc()}")

    await seed_bootstrap_admin_if_empty(logger)

    logger.info("=== Wombat Server ready ===")

    # Start the hourly update checker task
    _update_checker_task = asyncio.create_task(_hourly_update_checker())


# Observability wiring. Metrics are on by default; tracing and Sentry are
# no-ops unless their endpoint/DSN is configured.
setup_sentry()
setup_metrics(app)
setup_tracing(app)


def start() -> None:
    uvicorn.run("wombat_server.main:app", host="0.0.0.0", port=8000, reload=False)  # nosec B104


def legacy_start() -> None:
    """Deprecated ``wafpass-server`` console-script alias for :func:`start`."""
    from wombat_server.compat import warn_legacy

    warn_legacy("The 'wafpass-server' command", replacement="'wombat-server'")
    start()


if __name__ == "__main__":
    start()
