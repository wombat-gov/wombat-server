"""add per-user notification targets and deep links

Revision ID: 0060
Revises: 0059
Create Date: 2026-11-07 00:00:07.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0060"
down_revision: Union[str, None] = "0059"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("notifications", sa.Column("target_user_id", UUID(as_uuid=True), nullable=True))
    op.add_column("notifications", sa.Column("link_route", sa.Text(), nullable=False, server_default=""))
    op.add_column("notifications", sa.Column("link_run_id", sa.Text(), nullable=True))
    op.add_column("notifications", sa.Column("link_url", sa.Text(), nullable=False, server_default=""))
    op.add_column("notifications", sa.Column("project", sa.Text(), nullable=False, server_default=""))
    op.create_foreign_key(
        "fk_notifications_target_user_id", "notifications", "users",
        ["target_user_id"], ["id"], ondelete="SET NULL",
    )
    op.create_index(
        "ix_notifications_target_user_read_created",
        "notifications",
        ["target_user_id", "is_read", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_notifications_target_user_read_created", table_name="notifications")
    op.drop_constraint("fk_notifications_target_user_id", "notifications", type_="foreignkey")
    op.drop_column("notifications", "project")
    op.drop_column("notifications", "link_url")
    op.drop_column("notifications", "link_run_id")
    op.drop_column("notifications", "link_route")
    op.drop_column("notifications", "target_user_id")
