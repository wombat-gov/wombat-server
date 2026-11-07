"""add scan_jobs for asynchronous scans (Wave B)

Revision ID: 0057
Revises: 0056
Create Date: 2026-11-07 00:00:04.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0057"
down_revision: Union[str, None] = "0056"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_GROUP_USING_BRANCH = (
    "(current_setting('app.is_group_admin', true) = 'true' "
    "OR current_setting('app.is_group_viewer', true) = 'true') "
    "AND mandant_id IN (SELECT descendant_id FROM mandant_ancestry "
    "WHERE ancestor_id::text = current_setting('app.current_mandant_id', true))"
)
_GROUP_CHECK_BRANCH = (
    "current_setting('app.is_group_admin', true) = 'true' "
    "AND mandant_id IN (SELECT descendant_id FROM mandant_ancestry "
    "WHERE ancestor_id::text = current_setting('app.current_mandant_id', true))"
)


def _policy_sql() -> str:
    using = [
        "mandant_id::text = current_setting('app.current_mandant_id', true)",
        "current_setting('app.is_holding_admin', true) = 'true'",
        "current_setting('app.is_holding_viewer', true) = 'true'",
        _GROUP_USING_BRANCH,
    ]
    check = [
        "mandant_id::text = current_setting('app.current_mandant_id', true)",
        "current_setting('app.is_holding_admin', true) = 'true'",
        _GROUP_CHECK_BRANCH,
    ]
    using_sql = "\n        OR ".join(using)
    check_sql = "\n        OR ".join(check)
    return (
        'CREATE POLICY scan_jobs_tenant_isolation ON "scan_jobs"\n'
        "    USING (\n        " + using_sql + "\n    )\n"
        "    WITH CHECK (\n        " + check_sql + "\n    );"
    )


def _current_instance_mode(bind) -> str | None:
    try:
        return bind.execute(
            sa.text("SELECT value FROM instance_settings WHERE key = 'instance_mode'")
        ).scalar()
    except Exception:
        return None


def upgrade() -> None:
    op.create_table(
        "scan_jobs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("status", sa.Text(), nullable=False, server_default="queued"),
        sa.Column("project", sa.Text(), nullable=False, server_default=""),
        sa.Column("path", sa.Text(), nullable=False, server_default=""),
        sa.Column("iac", sa.Text(), nullable=False, server_default="terraform"),
        sa.Column("branch", sa.Text(), nullable=False, server_default=""),
        sa.Column("stage", sa.Text(), nullable=False, server_default=""),
        sa.Column("triggered_by", sa.Text(), nullable=False, server_default="ui"),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("run_id", UUID(as_uuid=True), sa.ForeignKey("runs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("requested_by", sa.Text(), nullable=False, server_default=""),
        sa.Column("cleanup_path", sa.Text(), nullable=True),
        sa.Column("mandant_id", UUID(as_uuid=True), sa.ForeignKey("mandants.id", ondelete="CASCADE"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])
    op.create_index("ix_scan_jobs_created_at", "scan_jobs", ["created_at"])

    bind = op.get_bind()
    if _current_instance_mode(bind) == "multi_mandant":
        op.execute('ALTER TABLE "scan_jobs" ENABLE ROW LEVEL SECURITY;')
        op.execute('ALTER TABLE "scan_jobs" FORCE ROW LEVEL SECURITY;')
        op.execute(_policy_sql())


def downgrade() -> None:
    op.execute('DROP POLICY IF EXISTS scan_jobs_tenant_isolation ON "scan_jobs";')
    op.drop_index("ix_scan_jobs_created_at", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_status", table_name="scan_jobs")
    op.drop_table("scan_jobs")
