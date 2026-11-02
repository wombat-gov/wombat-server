"""Unit tests for the scan/auto-fix path-confinement helpers."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException

from wombat_server import path_safety


def test_relative_path_inside_base_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = tmp_path / "workspace"
    (base / "infra").mkdir(parents=True)
    monkeypatch.setattr(path_safety.settings, "wombat_scan_base_dir", str(base))

    assert path_safety.resolve_scan_path("infra") == (base / "infra").resolve()


def test_absolute_path_inside_base_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = tmp_path / "workspace"
    target = base / "infra"
    target.mkdir(parents=True)
    monkeypatch.setattr(path_safety.settings, "wombat_scan_base_dir", str(base))

    assert path_safety.resolve_scan_path(str(target)) == target.resolve()


def test_relative_traversal_outside_base_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = tmp_path / "workspace"
    base.mkdir()
    (tmp_path / "outside").mkdir()
    monkeypatch.setattr(path_safety.settings, "wombat_scan_base_dir", str(base))

    with pytest.raises(HTTPException) as exc:
        path_safety.resolve_scan_path("../outside")
    assert exc.value.status_code == 400


def test_absolute_path_outside_base_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = tmp_path / "workspace"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setattr(path_safety.settings, "wombat_scan_base_dir", str(base))

    with pytest.raises(HTTPException) as exc:
        path_safety.resolve_scan_path(str(outside))
    assert exc.value.status_code == 400


def test_symlink_escape_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = tmp_path / "workspace"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = base / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are not available in this environment")
    monkeypatch.setattr(path_safety.settings, "wombat_scan_base_dir", str(base))

    with pytest.raises(HTTPException) as exc:
        path_safety.resolve_scan_path("link")
    assert exc.value.status_code == 400


def test_unset_base_confines_to_working_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(path_safety.settings, "wombat_scan_base_dir", "")

    assert path_safety.resolve_scan_path(".") == Path.cwd().resolve()


def test_safe_temp_filename_accepts_a_plain_basename() -> None:
    assert path_safety.safe_temp_filename("main.tf") == "main.tf"
    assert path_safety.safe_temp_filename("") == "main.tf"


@pytest.mark.parametrize("name", ["../escape.tf", "..", "/etc/passwd", "nested/main.tf", "a\\b.tf", ".env"])
def test_safe_temp_filename_rejects_path_traversal(name: str) -> None:
    with pytest.raises(HTTPException) as exc:
        path_safety.safe_temp_filename(name)
    assert exc.value.status_code == 400
