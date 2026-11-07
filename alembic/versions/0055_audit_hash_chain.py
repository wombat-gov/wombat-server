"""add tamper-evident audit hash chain

Adds sequence / prev_hash / entry_hash to both audit tables, backfills the
existing rows per tenant, and revokes UPDATE/DELETE from the runtime role so
ordinary application traffic cannot rewrite history.

Revision ID: 0055
Revises: 0054
Create Date: 2026-11-07 00:00:02.000000
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0055"
down_revision: Union[str, None] = "0054"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _hash(prev_hash: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + "|" + _canonical(payload)).encode()).hexdigest()


def _backfill(conn, table: str, fields: list[str]) -> None:
    select_columns = ", ".join(["id", *fields, "mandant_id"])
    rows = conn.execute(
        sa.text(f"SELECT {select_columns} FROM {table} ORDER BY timestamp, id")
    ).mappings().all()

    heads: dict[str, tuple[int, str]] = {}
    for row in rows:
        tenant = str(row["mandant_id"]) if row["mandant_id"] else "global"
        sequence, prev_hash = heads.get(tenant, (0, "GENESIS"))
        sequence += 1
        payload = {field: row[field] for field in ["id", *fields]}
        payload["mandant_id"] = tenant
        entry_hash = _hash(prev_hash, payload)
        conn.execute(
            sa.text(
                f"UPDATE {table} SET sequence = :sequence, prev_hash = :prev, "
                "entry_hash = :entry WHERE id = :id"
            ),
            {
                "sequence": sequence,
                "prev": prev_hash,
                "entry": entry_hash,
                "id": row["id"],
            },
        )
        heads[tenant] = (sequence, entry_hash)


def upgrade() -> None:
    for table in ("user_audit_logs", "compliance_audit_events"):
        op.add_column(table, sa.Column("sequence", sa.Integer(), nullable=True))
        op.add_column(table, sa.Column("prev_hash", sa.Text(), nullable=True))
        op.add_column(table, sa.Column("entry_hash", sa.Text(), nullable=True))

    conn = op.get_bind()
    _backfill(
        conn,
        "user_audit_logs",
        ["actor_id", "action", "detail", "ip", "timestamp"],
    )
    _backfill(
        conn,
        "compliance_audit_events",
        [
            "client_id",
            "actor",
            "category",
            "action",
            "subject_id",
            "subject_type",
            "summary",
            "before",
            "after",
            "timestamp",
            "created_by",
        ],
    )

    # The runtime role must be able to append and read, never rewrite.
    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
              IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'wombat_app') THEN
                EXECUTE 'REVOKE UPDATE, DELETE ON user_audit_logs FROM wombat_app';
                EXECUTE 'REVOKE UPDATE, DELETE ON compliance_audit_events FROM wombat_app';
              END IF;
            END
            $$;
            """
        )
    )


def downgrade() -> None:
    for table in ("user_audit_logs", "compliance_audit_events"):
        op.drop_column(table, "entry_hash")
        op.drop_column(table, "prev_hash")
        op.drop_column(table, "sequence")
