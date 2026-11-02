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
        return self

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


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
