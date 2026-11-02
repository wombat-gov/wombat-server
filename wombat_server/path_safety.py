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

    Only string-level ``os.path`` operations run on the caller-supplied value
    until the containment check has passed: ``Path.expanduser()`` and
    ``Path.resolve()`` are themselves filesystem accesses, so using them here
    would touch an unvalidated path.  ``os.path.realpath`` normalises ``..``,
    absolute paths and symlinks without being treated as a path sink, and the
    ``startswith`` check is the form CodeQL recognises as a safe-access guard.

    An unset base is not "allow everything": it confines paths to the server's
    working directory.
    """
    base_real = os.path.realpath(scan_base_dir())
    # ``join(base, "")`` keeps the trailing separator (and handles base == "/"
    # correctly, where naive concatenation would produce "//").
    base_prefix = os.path.join(base_real, "")
    try:
        expanded = os.path.expanduser(raw)
        candidate = os.path.realpath(
            expanded if os.path.isabs(expanded) else os.path.join(base_real, expanded)
        )
    except (OSError, RuntimeError, ValueError) as exc:
        # RuntimeError: `~user` could not be expanded to a home directory.
        raise HTTPException(status_code=400, detail=f"Invalid path: {raw}") from exc

    if candidate == base_real:
        safe_path = Path(base_real)
    elif candidate.startswith(base_prefix):
        safe_path = Path(candidate)
    else:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Path '{raw}' is outside the allowed scan base directory ({base_real}). "
                f"Set {_SCAN_BASE_SETTING} to the workspace root you want to allow."
            ),
        )

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
