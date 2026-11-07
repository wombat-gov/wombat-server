"""desktop device authorization (Wave D)

Revision ID: 0059
Revises: 0058
Create Date: 2026-11-07 00:00:06.000000

Both tables are authentication-bootstrap state, like ``sessions`` and
``refresh_tokens``, and are deliberately *not* RLS-enabled: a device code is
created before any user (and therefore any mandate) is known, and a device
token lookup happens before the user's mandate is resolved. Application code
scopes every device query to the authenticated user; only SHA-256 hashes of
the device code/token are stored.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0059"
down_revision: Union[str, None] = "0058"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "device_codes",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("code_hash", sa.Text(), nullable=False, unique=True),
        sa.Column("user_code", sa.Text(), nullable=False, unique=True),
        sa.Column("device_name", sa.Text(), nullable=False, server_default=""),
        sa.Column("client", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_by", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("denied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ip_hash", sa.Text(), nullable=False, server_default=""),
        sa.Column("user_agent", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_device_codes_expires_at", "device_codes", ["expires_at"])

    op.create_table(
        "devices",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "user_id", UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("name", sa.Text(), nullable=False, server_default=""),
        sa.Column("token_hash", sa.Text(), nullable=False, unique=True),
        sa.Column(
            "mandant_id", UUID(as_uuid=True),
            sa.ForeignKey("mandants.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("user_agent", sa.Text(), nullable=False, server_default=""),
        sa.Column("ip_hash", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_devices_user_id", "devices", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_devices_user_id", table_name="devices")
    op.drop_table("devices")
    op.drop_index("ix_device_codes_expires_at", table_name="device_codes")
    op.drop_table("device_codes")
