"""add SCIM identity fields to users

Revision ID: 0056
Revises: 0055
Create Date: 2026-11-07 00:00:03.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0056"
down_revision: Union[str, None] = "0055"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("email", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column("users", sa.Column("external_id", sa.Text(), nullable=True))
    op.create_index("ix_users_external_id", "users", ["external_id"])


def downgrade() -> None:
    op.drop_index("ix_users_external_id", table_name="users")
    op.drop_column("users", "external_id")
    op.drop_column("users", "email")
