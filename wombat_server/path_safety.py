"""Path-confinement helpers for server-side filesystem operations.

The scan and auto-fix endpoints accept a path from an authenticated caller.
CodeQL correctly treats that value as tainted, so every path must be resolved
and checked against an explicit base directory before it reaches a filesystem
sink.  The base defaults to the server's working directory when
``WOMBAT_SCAN_BASE_DIR`` is unset — a secure default that keeps the historical
"scan the workspace" workflow available without allowing arbitrary absolute
paths.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from fastapi import HTTPException

from wombat_server.config import settings

_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SCAN_BASE_SETTING = "WOMBAT_SCAN_BASE_DIR"


def scan_base_dir() -> Path:
    """Return the resolved directory every scan/auto-fix path must stay inside."""
    configured = (settings.wombat_scan_base_dir or "").strip()
    return Path(configured).expanduser().resolve() if configured else Path.cwd().resolve()


def resolve_scan_path(raw: str) -> Path:
    """Resolve *raw* and require the result to live inside :func:`scan_base_dir`.

    The ``relative_to`` check happens after ``resolve()`` so symlinks that point
    outside the base are rejected as well.  An unset base is not "allow
    everything" any more: it confines paths to the server's working directory.
    """
    base = scan_base_dir()
    try:
        supplied = Path(raw).expanduser()
        resolved = supplied.resolve() if supplied.is_absolute() else (base / supplied).resolve()
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid path: {raw}") from exc

    # Normalise both sides with realpath() and require the resolved path to be
    # the base itself or to start with "base + separator".  This is the
    # canonical containment check (and the form CodeQL recognises as a
    # path-injection sanitizer); the Path.relative_to() check below keeps the
    # same guarantee for callers that operate on Path objects.
    base_real = os.path.realpath(base)
    resolved_real = os.path.realpath(resolved)
    if resolved_real != base_real and not resolved_real.startswith(base_real + os.sep):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Path '{raw}' is outside the allowed scan base directory ({base}). "
                f"Set {_SCAN_BASE_SETTING} to the workspace root you want to allow."
            ),
        )
    try:
        Path(resolved_real).relative_to(base_real)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Path '{raw}' is outside the allowed scan base directory ({base}). "
                f"Set {_SCAN_BASE_SETTING} to the workspace root you want to allow."
            ),
        ) from exc

    safe_path = Path(resolved_real)
    if not safe_path.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist on the server: {safe_path}")
    if not (safe_path.is_dir() or safe_path.is_file()):
        raise HTTPException(status_code=400, detail=f"Path is not a file or directory: {safe_path}")
    return safe_path


def safe_temp_filename(raw: str, default: str = "main.tf") -> str:
    """Return a single safe filename component, never a path.

    The sandbox writes user-supplied HCL into a temporary directory.  Passing a
    filename such as ``../../etc/passwd`` would escape that directory, so only
    a plain basename made of letters, digits, dots, underscores and hyphens is
    accepted.
    """
    candidate = (raw or "").strip()
    if not candidate:
        return default
    if "/" in candidate or "\\" in candidate or not _SAFE_FILENAME.fullmatch(candidate):
        raise HTTPException(
            status_code=400,
            detail="Invalid filename: use a plain file name without path separators.",
        )
    return candidate
