"""Tamper-evident hash chain for the two audit tables.

The chain is per tenant: each row's entry_hash covers its own canonical fields
plus the previous row's hash. The runtime role is append-only (see migration
0055), so a rewritten row is detectable.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, TypeVar, cast

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from wombat_server.models import ComplianceAuditEvent, UserAuditLog

GENESIS = "GENESIS"
AuditEvent = TypeVar("AuditEvent", UserAuditLog, ComplianceAuditEvent)


def tenant_key(mandant_id: uuid.UUID | None) -> str:
    return str(mandant_id) if mandant_id else "global"


def canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def entry_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + "|" + canonical(payload)).encode()).hexdigest()


def user_audit_payload(event: UserAuditLog) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "actor_id": str(event.actor_id) if event.actor_id else None,
        "action": event.action,
        "detail": event.detail or {},
        "ip": event.ip or "",
        "timestamp": event.timestamp,
        "mandant_id": tenant_key(event.mandant_id),
    }


def compliance_payload(event: ComplianceAuditEvent) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "client_id": event.client_id or "",
        "actor": event.actor or "",
        "category": event.category,
        "action": event.action,
        "subject_id": event.subject_id or "",
        "subject_type": event.subject_type or "",
        "summary": event.summary or "",
        "before": event.before,
        "after": event.after,
        "timestamp": event.timestamp,
        "created_by": str(event.created_by) if event.created_by else None,
        "mandant_id": tenant_key(event.mandant_id),
    }


def _payload_for(event: UserAuditLog | ComplianceAuditEvent) -> dict[str, Any]:
    if isinstance(event, UserAuditLog):
        return user_audit_payload(event)
    return compliance_payload(event)


async def chain_event(
    db: AsyncSession,
    event: UserAuditLog | ComplianceAuditEvent,
) -> None:
    """Assign sequence/prev_hash/entry_hash before the row is inserted."""
    if event.id is None:
        event.id = uuid.uuid4()
    if event.timestamp is None:
        event.timestamp = datetime.now(timezone.utc)

    table = event.__tablename__
    tenant = tenant_key(event.mandant_id)
    # Serialize appends per tenant so concurrent writers cannot fork the chain.
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
        {"key": f"audit:{table}:{tenant}"},
    )

    if isinstance(event, UserAuditLog):
        model: type[UserAuditLog] | type[ComplianceAuditEvent] = UserAuditLog
    else:
        model = ComplianceAuditEvent
    stmt = select(model).order_by(model.sequence.desc().nullslast()).limit(1)
    if event.mandant_id is None:
        stmt = stmt.where(model.mandant_id.is_(None))
    else:
        stmt = stmt.where(model.mandant_id == event.mandant_id)
    last = cast(
        UserAuditLog | ComplianceAuditEvent | None,
        (await db.execute(stmt)).scalar_one_or_none(),
    )
    event.sequence = (last.sequence or 0) + 1 if last else 1
    event.prev_hash = (last.entry_hash if last and last.entry_hash else GENESIS)
    event.entry_hash = entry_hash(event.prev_hash, _payload_for(event))


async def verify_chain(
    db: AsyncSession,
    model: type[AuditEvent],
    mandant_id: uuid.UUID | None,
) -> dict[str, Any]:
    stmt = select(model).order_by(model.sequence.asc())
    if mandant_id is None:
        stmt = stmt.where(model.mandant_id.is_(None))
    else:
        stmt = stmt.where(model.mandant_id == mandant_id)
    rows = list((await db.execute(stmt)).scalars().all())

    prev = GENESIS
    checked = 0
    for index, row in enumerate(rows, start=1):
        if row.sequence is None or row.entry_hash is None:
            continue
        payload = _payload_for(row)
        expected = entry_hash(prev, payload)
        if row.sequence != checked + 1 or row.prev_hash != prev or row.entry_hash != expected:
            return {
                "valid": False,
                "checked": checked,
                "head": prev,
                "first_invalid_sequence": row.sequence,
                "first_invalid_id": str(row.id),
            }
        checked += 1
        prev = row.entry_hash

    return {
        "valid": True,
        "checked": checked,
        "head": prev,
        "first_invalid_sequence": None,
        "first_invalid_id": None,
    }
