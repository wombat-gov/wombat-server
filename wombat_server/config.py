"""Application configuration via environment variables."""
from __future__ import annotations

import os
import secrets

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from wombat_server.compat import promote_legacy_env

# Promote legacy WAFPASS_* settings before Settings() reads the environment.
promote_legacy_env()

_DEFAULT_JWT_SECRET = "change-me-in-production-wombat-secret-key"
_LEGACY_DEFAULT_JWT_SECRET = "change-me-in-production-wafpass-secret-key"
_JWT_SECRET_PLACEHOLDERS = {
    _DEFAULT_JWT_SECRET,
    _LEGACY_DEFAULT_JWT_SECRET,
    "",
    "change-me-in-production",
}


def _generate_random_secret() -> str:
    """Return a URL-safe random secret suitable for JWT signing."""
    return secrets.token_urlsafe(32)


def _generate_random_secret() -> str:
    """Return a URL-safe random secret suitable for JWT signing."""
    return secrets.token_urlsafe(32)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Owner/superuser role. Used only by Alembic migrations and the one-time
    # multi-mandant activation DDL — never for ordinary request traffic.
    # Postgres superusers always bypass row-level security, so routing
    # ordinary queries through this role would make every RLS policy a
    # silent no-op (see decisions/adrs/ADR-003-multi-mandant-tenancy.md).
    database_url: str = "postgresql+asyncpg://wombat:wombat@localhost:5432/wombat"

    # Least-privilege, non-superuser role for every ordinary request. This
    # is what wombat_server.database.get_db() actually connects with.
    # Defaults to a local "wombat_app" role — see db-init/02-wombat-app-role.sql.
    runtime_database_url: str = "postgresql+asyncpg://wombat_app:wombat_app@localhost:5432/wombat"

    wombat_env: str = "local"

    # CORS origins (comma-separated)
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # Path to Wombat YAML control files used by the sandbox engine.
    # Defaults to a "controls" directory next to the server's working directory.
    wombat_controls_dir: str = "controls"

    # ── Authentication ────────────────────────────────────────────────────────
    # IMPORTANT: set a strong random value in production.
    wombat_jwt_secret: str = _DEFAULT_JWT_SECRET
    # Access token lifetime in minutes (default 60 min).
    wombat_jwt_expire_minutes: int = 60
    # Refresh token lifetime in days (default 7 days).
    wombat_jwt_refresh_days: int = 7

    # Bootstrap admin user — created once on first startup if users table is empty.
    # Leave wombat_admin_password empty to disable auto-seeding.
    wombat_admin_username: str = "admin"
    wombat_admin_password: str = ""
    wombat_admin_role: str = "admin"

    # Pre-shared API key for machine-to-machine access (CI/CD --push workflow).
    # Empty = disabled.  Set X-Api-Key header to this value on POST /runs / POST /scan.
    wombat_api_key: str = ""

    # ── Browser session / network hardening ───────────────────────────────────
    # Cookie session (BFF) mode: the server sets HttpOnly cookies; the dashboard
    # never stores a bearer token. Bearer tokens remain available for CLI/CI.
    wombat_cookie_auth: bool = True
    # False by default so `http://localhost` development works. Non-local
    # environments are required to set it true (validated at startup).
    wombat_cookie_secure: bool = False
    wombat_cookie_domain: str = ""
    wombat_cookie_samesite: str = "lax"
    wombat_csrf_enabled: bool = True

    # Comma-separated Host/Origin allowlist. Required outside local.
    # Example: wombat.example.com,api.example.com
    wombat_allowed_hosts: str = ""

    # Number of trusted reverse proxies in front of the server. 0 = direct
    # exposure (not recommended); 1 = one edge proxy such as Caddy/Traefik.
    wombat_trusted_proxy_count: int = 0

    # Force a password rotation after bootstrap/admin reset. Disable only for
    # automated end-to-end environments; leave true in production.
    wombat_force_password_rotation: bool = True

    # ── Login protection ──────────────────────────────────────────────────────
    wombat_login_max_failures: int = 5
    wombat_login_lock_minutes: int = 15
    wombat_login_ip_limit: int = 20          # attempts per window per IP
    wombat_login_ip_window_seconds: int = 60
    # Redis-backed limiter for multi-replica deployments. Empty = in-memory.
    wombat_redis_url: str = ""

    # ── Password policy ───────────────────────────────────────────────────────
    wombat_password_min_length: int = 12
    wombat_admin_password_min_length: int = 16

    # ── Sessions ──────────────────────────────────────────────────────────────
    wombat_session_idle_minutes: int = 480
    wombat_session_absolute_days: int = 7
    wombat_session_max: int = 10

    # ── MFA ───────────────────────────────────────────────────────────────────
    wombat_mfa_enabled: bool = True
    wombat_mfa_required_roles: str = "admin,ciso"
    wombat_mfa_issuer: str = "WOMBATpass"
    wombat_mfa_token_minutes: int = 5

    # ── SCIM 2.0 ──────────────────────────────────────────────────────────────
    wombat_scim_enabled: bool = False
    wombat_scim_token: str = ""
    wombat_scim_mandant_slug: str = ""
    wombat_scim_default_role: str = "engineer"

    # ── Observability ─────────────────────────────────────────────────────────
    # JSON logs to stdout by default; set "text" for local development.
    wombat_log_format: str = "json"
    wombat_log_level: str = "INFO"
    # Prometheus /metrics. The edge does not proxy it; scrape the app directly.
    wombat_metrics_enabled: bool = True
    # OpenTelemetry traces (OTLP). Disabled until a collector is configured.
    wombat_otel_enabled: bool = False
    wombat_otel_endpoint: str = ""
    wombat_otel_sample_rate: float = 0.1
    # Sentry error tracking. Disabled until a DSN is configured.
    wombat_sentry_dsn: str = ""
    wombat_sentry_environment: str = ""


    # In multi-mandant mode the legacy shared key has no natural mandate, so
    # it is rejected unless an operator explicitly maps it to one via this
    # mandant slug. Empty = reject the legacy shared key after activation.
    wombat_legacy_api_key_mandant_slug: str = ""

    # Public base URL used to build absolute links in QR codes and audit reports.
    # Set this to the externally reachable address of the server, e.g.
    # https://wombat.example.com  (no trailing slash).
    # Falls back to the Host header of the incoming request when left empty.
    wombat_public_url: str = ""

    # Server-side scan settings
    # Set WOMBAT_SCAN_ENABLED=false to disable POST /scan entirely.
    wombat_scan_enabled: bool = True
    # Base directory for server-side scan and auto-fix paths. Every supplied
    # path is resolved and confined to this directory; symlinks that escape it
    # are rejected. When empty the server's working directory is used.
    wombat_scan_base_dir: str = ""

    # Optional waivers file used by the auto-fixer to skip waived checks.
    wombat_waivers_file: str = ""

    # Base path for Wombat framework repositories.
    # Legacy: used by the update checker to locate a local framework clone.
    # Defaults to /app for containerized deployments.
    wombat_base_path: str = "/app"

    # Public Git URL for the Wombat framework repository.
    # The update checker fetches version and commit information from this repo.
    wombat_framework_repo_url: str = "https://github.com/WAF2p/framework"

    # Branch to read framework version/commit information from.
    wombat_framework_branch: str = "main"

    # ── At-rest encryption for SSO secrets ───────────────────────────────────
    # Backend: "local" (default) | "aws_sm" | "vault_transit"
    wombat_secrets_backend: str = "local"

    # Local backend — provide a Fernet-compatible key (32 bytes, URL-safe base64)
    # or any passphrase (PBKDF2-derived).  Defaults to derivation from
    # WOMBAT_JWT_SECRET when empty — set this explicitly in production.
    wombat_encryption_key: str = ""

    # AWS Secrets Manager backend
    aws_region: str = "us-east-1"

    # HashiCorp Vault Transit backend
    vault_addr: str = "http://127.0.0.1:8200"
    vault_token: str = ""
    vault_transit_key: str = "wombat"
    vault_transit_mount: str = "transit"

    # ── Admin audit log forwarding ────────────────────────────────────────────
    # Optional remote syslog/SIEM endpoint for security/admin events. Disabled by
    # default; set WOMBAT_SYSLOG_ENABLED=true and a host to forward every audit
    # event as it is recorded. Works with any RFC 3164 / RFC 5424 receiver such as
    # Microsoft Sentinel, Splunk, rsyslog, or logstash.
    wombat_syslog_enabled: bool = False
    wombat_syslog_host: str = ""
    wombat_syslog_port: int = 514
    wombat_syslog_protocol: str = "udp"  # udp | tcp
    wombat_syslog_format: str = "rfc5424"  # rfc3164 | rfc5424
    wombat_syslog_facility: int = 13  # 13 = log audit, standard for security events

    @model_validator(mode="after")
    def _validate_secrets(self) -> "Settings":
        """Enforce strong secrets on every explicit Settings() construction."""
        if self.wombat_jwt_secret in _JWT_SECRET_PLACEHOLDERS:
            raise ValueError(
                "WOMBAT_JWT_SECRET must be set to a strong random value. "
                "The default / placeholder value is not allowed in any environment. "
                "Generate a random 32-byte secret and set it via the WOMBAT_JWT_SECRET "
                "environment variable. If you are running locally, use 'wombat init --mode dashboard' "
                "to generate a valid .env file."
            )
        if self.wombat_env != "local" and not self.wombat_encryption_key:
            raise ValueError(
                "WOMBAT_ENCRYPTION_KEY must be set in non-local environments. "
                "Without it, SSO secrets are derived from WOMBAT_JWT_SECRET, "
                "which is insecure if that secret is ever rotated or leaked."
            )
        if self.wombat_env != "local":
            if self.wombat_encryption_key and self.wombat_encryption_key == self.wombat_jwt_secret:
                raise ValueError(
                    "WOMBAT_ENCRYPTION_KEY must be independent of WOMBAT_JWT_SECRET."
                )
            if len(self.wombat_admin_password) < self.wombat_admin_password_min_length:
                raise ValueError(
                    f"WOMBAT_ADMIN_PASSWORD must be at least "
                    f"{self.wombat_admin_password_min_length} characters in non-local environments."
                )
            if self.wombat_api_key.lower() in {"key", "changeme", "change-me"}:
                raise ValueError(
                    "WOMBAT_API_KEY is still a placeholder. Set a strong random value "
                    "or leave it empty to disable API-key authentication."
                )
            if self.wombat_cookie_auth and not self.wombat_cookie_secure:
                raise ValueError(
                    "WOMBAT_COOKIE_SECURE must be true when cookie authentication is enabled "
                    "outside local development."
                )
        return self

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def allowed_hosts_list(self) -> list[str]:
        raw = self.wombat_allowed_hosts.strip()
        if raw:
            return [h.strip() for h in raw.split(",") if h.strip()]
        # Local development is permissive; non-local is fail-closed.
        return ["*"] if self.wombat_env == "local" else []

    @property
    def mfa_required_roles_list(self) -> list[str]:
        return [r.strip() for r in self.wombat_mfa_required_roles.split(",") if r.strip()]


def validate_runtime_settings() -> None:
    """Validate that the running server has production-grade secrets.

    Called once during application startup. Import-time construction of the
    global `settings` singleton is intentionally permissive for tests/CI.
    """
    if settings.wombat_env == "local":
        return
    if settings.wombat_jwt_secret in _JWT_SECRET_PLACEHOLDERS:
        raise ValueError(
            "WOMBAT_JWT_SECRET must be set to a strong random value. "
            "The default / placeholder value is not allowed in any environment. "
            "Generate a random 32-byte secret and set it via the WOMBAT_JWT_SECRET "
            "environment variable."
        )
    if not settings.wombat_encryption_key:
        raise ValueError(
            "WOMBAT_ENCRYPTION_KEY must be set in non-local environments. "
            "Without it, SSO secrets are derived from WOMBAT_JWT_SECRET, "
            "which is insecure if that secret is ever rotated or leaked."
        )
    if settings.wombat_encryption_key == settings.wombat_jwt_secret:
        raise ValueError("WOMBAT_ENCRYPTION_KEY must be independent of WOMBAT_JWT_SECRET.")
    if len(settings.wombat_admin_password) < settings.wombat_admin_password_min_length:
        raise ValueError(
            f"WOMBAT_ADMIN_PASSWORD must be at least "
            f"{settings.wombat_admin_password_min_length} characters outside local development."
        )
    if not settings.allowed_hosts_list:
        raise ValueError(
            "WOMBAT_ALLOWED_HOSTS must list the public Host values outside local development."
        )
    if not settings.wombat_public_url:
        raise ValueError(
            "WOMBAT_PUBLIC_URL must be set outside local development so links and QR codes "
            "do not depend on the Host header."
        )
    if settings.wombat_cookie_auth and not settings.wombat_cookie_secure:
        raise ValueError(
            "WOMBAT_COOKIE_SECURE must be true when cookie authentication is enabled."
        )


def _load_settings() -> Settings:
    """Load settings safely for import-time use.

    In local/test environments we auto-generate a random JWT secret if none is
    configured, so that importing the package never raises during pytest
    collection. Explicit Settings() construction still enforces strong secrets.
    """
    # When the environment explicitly requests a non-local profile, let pydantic
    # run normally so misconfiguration surfaces immediately.
    explicit_env = os.environ.get("WOMBAT_ENV", "local")
    if explicit_env != "local":
        return Settings()

    # Local mode: if the secret is still the placeholder, use a generated value.
    env_secret = os.environ.get("WOMBAT_JWT_SECRET", _DEFAULT_JWT_SECRET)
    if env_secret in _JWT_SECRET_PLACEHOLDERS:
        return Settings(wombat_jwt_secret=_generate_random_secret(), wombat_env="local")
    return Settings()


settings = _load_settings()
