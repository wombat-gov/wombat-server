#!/usr/bin/env python
"""Export the OpenAPI schema to openapi.json.

CI regenerates this file and fails on a diff, so an API change is always a
deliberate, reviewed change. Run from the server repository root:

    python scripts/export_openapi.py
"""
from __future__ import annotations

import json
from pathlib import Path

from wombat_server.main import app


def main() -> None:
    target = Path(__file__).resolve().parents[1] / "openapi.json"
    target.write_text(
        json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {target}")


if __name__ == "__main__":
    main()
