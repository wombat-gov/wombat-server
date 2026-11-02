# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
This release is the coordinated WAFPass → WOMBATpass rebrand and is versioned as
a minor release at the project owner's request; treat the rename as breaking and
pin exact versions.

## [1.2.0] - 2026-11-02

### Breaking changes

- Renamed the distribution and console script from `wafpass-server` to
  **`wombat-server`**.
- Renamed the import package from `wafpass_server` to **`wombat_server`**.
- Renamed the repository from `WAF2p/wafpass-server` to
  `wombat-gov/wombat-server`.
- Environment variables now use the `WOMBAT_*` prefix instead of `WAFPASS_*`.
- The dashboard and API clients use the `/api/v1/*` endpoints. Reverse proxies
  and CORS configurations must forward `/api` rather than individual paths such
  as `/runs` or `/controls`.

Legacy compatibility is retained for one migration window:

- `wafpass-server` remains a deprecated console-script alias for
  `wombat-server`.
- `import wafpass_server` is served by the shim in `wafpass_server/__init__.py`.
- `WAFPASS_*` settings are promoted to `WOMBAT_*` by
  `wombat_server.compat.promote_legacy_env()`.
- `/version` returns the canonical `wombat_server` / `wombat_core` keys and the
  deprecated `wafpass_server` / `wafpass_core` aliases.

These aliases are deprecated and will be removed in a future release.

### Changed

- Branding, documentation, Docker image names and compose service names now use
  WOMBATpass/wombat.
- Package metadata and repository URLs point at the `wombat-gov` organisation.
- FastAPI application version and `/version` now report `1.2.0`.

### Migration

1. Replace `pip install wafpass-server` with `pip install wombat-server`.
2. Replace `import wafpass_server` with `import wombat_server`.
3. Replace the `wafpass-server` command with `wombat-server`.
4. Rename `WAFPASS_*` environment variables to `WOMBAT_*`.
5. Update Docker/compose service names and the Dockerfile path
   (`wombat-server/Dockerfile`).
6. Forward `/api` to the server in reverse proxies and include the dashboard
   origins in CORS.
7. Update CI and pins from `WAF2p/wafpass-server` to
   `wombat-gov/wombat-server`, and pin `wombat-server==1.2.0` if needed.

### Companion releases

- `wombat-core` 1.2.0
- `wombat-dashboard` 1.2.0
- `wombat-mcp` 0.2.0
- `wombat-action` 0.2.0
