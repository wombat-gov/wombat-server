"""Deprecated-name compatibility for the WAFpass → WOMBATpass migration.

Environment variables were prefixed ``WAFPASS_`` before the rebrand.  New
installations use ``WOMBAT_``; this module promotes legacy names (from the
process environment *and* from the ``.env`` file) so existing deployments keep
working while emitting a deprecation warning.
"""

from __future__ import annotations

import os
import warnings
from pathlib import Path
from typing import MutableMapping

ENV_PREFIX = "WOMBAT_"
LEGACY_ENV_PREFIX = "WAFPASS_"

_promoted = False


def warn_legacy(what: str, *, replacement: str | None = None) -> None:
    """Emit a consistent deprecation warning for an old WAFpass name."""
    suffix = f" Use {replacement} instead." if replacement else ""
    warnings.warn(
        f"{what} is deprecated after the WAF++ → Wombat rebrand.{suffix}",
        FutureWarning,
        stacklevel=3,
    )


def _promote(mapping: MutableMapping[str, str]) -> None:
    for key in list(mapping):
        if not key.startswith(LEGACY_ENV_PREFIX):
            continue
        new_key = ENV_PREFIX + key[len(LEGACY_ENV_PREFIX):]
        if new_key in mapping:
            continue
        mapping[new_key] = mapping[key]
        warn_legacy(f"Environment variable {key}", replacement=new_key)


def promote_legacy_env(env_file: str | Path = ".env") -> None:
    """Copy legacy ``WAFPASS_*`` settings to their ``WOMBAT_*`` names.

    New names always win.  Values are also promoted from the dotenv file,
    because pydantic-settings reads that file separately from ``os.environ``.
    """
    global _promoted
    if _promoted:
        return
    _promoted = True

    _promote(os.environ)

    path = Path(env_file)
    if not path.exists():
        return
    try:
        from dotenv import dotenv_values
    except ImportError:  # pragma: no cover - python-dotenv is a hard dependency
        return

    values = {k: v for k, v in dotenv_values(path).items() if v is not None}
    legacy = {k: v for k, v in values.items() if k.startswith(LEGACY_ENV_PREFIX)}
    for key, value in legacy.items():
        new_key = ENV_PREFIX + key[len(LEGACY_ENV_PREFIX):]
        if new_key in os.environ or new_key in values:
            continue
        os.environ[new_key] = value
        warn_legacy(f"Environment variable {key} in {path}", replacement=new_key)
