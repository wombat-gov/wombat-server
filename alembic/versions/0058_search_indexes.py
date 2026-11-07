"""add pg_trgm search indexes (Wave C)

Revision ID: 0058
Revises: 0057
Create Date: 2026-11-07 00:00:05.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0058"
down_revision: Union[str, None] = "0057"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (index name, table, column)
_SEARCH_INDEXES = [
    ("ix_runs_project_trgm", "runs", "project"),
    ("ix_runs_branch_trgm", "runs", "branch"),
    ("ix_run_findings_check_id_trgm", "run_findings", "check_id"),
    ("ix_run_findings_check_title_trgm", "run_findings", "check_title"),
    ("ix_run_findings_control_id_trgm", "run_findings", "control_id"),
    ("ix_controls_id_trgm", "controls", "id"),
    ("ix_controls_description_trgm", "controls", "description"),
    ("ix_waivers_id_trgm", "waivers", "id"),
    ("ix_waivers_reason_trgm", "waivers", "reason"),
    ("ix_waivers_project_trgm", "waivers", "project"),
    ("ix_risk_acceptances_id_trgm", "risk_acceptances", "id"),
    ("ix_risk_acceptances_reason_trgm", "risk_acceptances", "reason"),
    ("ix_risk_acceptances_project_trgm", "risk_acceptances", "project"),
    ("ix_project_passports_project_trgm", "project_passports", "project"),
    ("ix_project_passports_display_name_trgm", "project_passports", "display_name"),
    ("ix_project_passports_description_trgm", "project_passports", "description"),
]


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    for name, table, column in _SEARCH_INDEXES:
        op.execute(
            f'CREATE INDEX IF NOT EXISTS {name} ON "{table}" '
            f'USING gin ("{column}" gin_trgm_ops)'
        )


def downgrade() -> None:
    for name, _table, _column in _SEARCH_INDEXES:
        op.execute(f'DROP INDEX IF EXISTS {name}')
