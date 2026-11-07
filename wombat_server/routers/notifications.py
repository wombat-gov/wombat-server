"""CRUD endpoints for notifications.

Notifications are visible to a user when they are targeted directly, match the
user's role audience, are untargeted, or the user is an admin. Link metadata
lets the desktop app open the exact run/route instead of a generic page.
"""
from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from wombat_server.auth.deps import (
    AuthContext,
    adopt_mandate_of,
    get_auth_context,
    get_scoped_db,
    require_role,
)
from wombat_server.events import publish_event
from wombat_server.models import Notification, User
from wombat_server.notification_visibility import visible_notifications
from wombat_server.schemas import (
    Envelope,
    Meta,
    NotificationCreate,
    NotificationOut,
    NotificationTestIn,
    NotificationTestOut,
    NotificationUpdateRead,
)

router = APIRouter(prefix="/notifications", tags=["notifications"])

_VALID_TARGET_ROLES = {None, "all", "admin", "clevel", "ciso", "architect", "engineer"}


async def _publish_notification(notification: Notification, action: str = "created") -> None:
    await publish_event(
        f"notification.{action}",
        {
            "id": notification.id,
            "title": notification.title,
            "category": notification.category,
            "target_role": notification.target_role,
            "target_user_id": str(notification.target_user_id) if notification.target_user_id else None,
            "link_route": notification.link_route,
            "link_run_id": notification.link_run_id,
            "link_url": notification.link_url,
            "project": notification.project,
        },
        mandate_id=notification.mandant_id,
    )


async def _target_mandate(
    db: AsyncSession,
    auth: AuthContext,
    target_user_id: uuid.UUID | None,
) -> tuple[uuid.UUID | None, uuid.UUID | None]:
    """Resolve a per-user target and adapt the session's mandate for the insert."""
    if target_user_id is None:
        return None, auth.mandant_id
    target = await db.get(User, target_user_id)
    if target is None or not target.is_active:
        raise HTTPException(400, detail="target_user_id does not reference an active user.")
    if target.mandant_id != auth.mandant_id:
        await adopt_mandate_of(
            db,
            target.mandant_id,
            is_holding_admin=auth.is_holding_admin,
            is_holding_viewer=auth.is_holding_viewer,
        )
    return target.id, target.mandant_id


def _validate_target_role(target_role: str | None) -> None:
    if target_role not in _VALID_TARGET_ROLES:
        raise HTTPException(400, detail="Invalid target_role.")


async def _create(
    payload: NotificationCreate,
    user: User,
    auth: AuthContext,
    db: AsyncSession,
) -> Notification:
    _validate_target_role(payload.target_role)
    target_user_id, mandant_id = await _target_mandate(db, auth, payload.target_user_id)
    notification = Notification(
        title=payload.title,
        message=payload.message,
        category=payload.category,
        triggered_by=user.username,
        target_role=payload.target_role,
        target_user_id=target_user_id,
        link_route=payload.link_route,
        link_run_id=payload.link_run_id,
        link_url=payload.link_url,
        project=payload.project,
        mandant_id=mandant_id,
    )
    db.add(notification)
    await db.commit()
    await db.refresh(notification)
    await _publish_notification(notification)
    return notification


@router.get("", response_model=Envelope[list[NotificationOut]])
async def list_notifications(  # noqa: F811
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    unread_only: bool = False,
    category: str | None = None,
) -> Envelope[list[NotificationOut]]:
    """List notifications visible to the caller, newest first."""
    visible = visible_notifications(auth.user)
    conditions = [visible]
    if unread_only:
        conditions.append(Notification.is_read.is_(False))
    if category:
        conditions.append(Notification.category == category)

    total = int(
        (
            await db.execute(
                select(func.count()).select_from(Notification).where(*conditions)
            )
        ).scalar_one()
        or 0
    )
    rows = (
        await db.execute(
            select(Notification)
            .where(*conditions)
            .order_by(Notification.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
    ).scalars().all()
    return Envelope(data=list(rows), meta=Meta(total=total))


@router.post("", response_model=Envelope[NotificationOut])
async def create_notification(
    payload: NotificationCreate,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    user: Annotated[User, Depends(require_role("admin"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> Envelope[NotificationOut]:
    """Create a new notification (admin)."""
    notification = await _create(payload, user, auth, db)
    return Envelope(data=notification)


@router.post("/trigger", response_model=Envelope[NotificationOut])
async def trigger_notification(
    payload: NotificationCreate,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    user: Annotated[User, Depends(require_role("admin"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> Envelope[NotificationOut]:
    """Alias for POST /notifications."""
    notification = await _create(payload, user, auth, db)
    return Envelope(data=notification)


@router.post("/test", response_model=Envelope[NotificationTestOut])
async def test_notification(
    payload: NotificationTestIn,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    user: Annotated[User, Depends(require_role("admin"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> Envelope[NotificationTestOut]:
    """Send a test notification. Returns the created notification."""
    notification = await _create(payload, user, auth, db)
    return Envelope(
        data=NotificationTestOut(
            id=notification.id,
            title=notification.title,
            message=notification.message,
            category=notification.category,
            is_read=notification.is_read,
            created_at=notification.created_at,
            triggered_by=notification.triggered_by,
            target_role=notification.target_role,
            target_user_id=notification.target_user_id,
            link_route=notification.link_route,
            link_run_id=notification.link_run_id,
            link_url=notification.link_url,
            project=notification.project,
        )
    )


@router.put("/{notification_id}/read", response_model=Envelope[NotificationOut])
async def mark_as_read(
    notification_id: str,
    payload: NotificationUpdateRead,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> Envelope[NotificationOut]:
    """Mark a visible notification as read."""
    notification = (
        await db.execute(
            select(Notification).where(
                Notification.id == notification_id,
                visible_notifications(auth.user),
            )
        )
    ).scalar_one_or_none()
    if notification is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    notification.is_read = payload.is_read
    await db.commit()
    await db.refresh(notification)
    await _publish_notification(notification, "updated")
    return Envelope(data=notification)


@router.put("/read-all", response_model=Envelope[dict])
async def mark_all_as_read(
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> Envelope[dict]:
    """Mark every visible notification as read."""
    await db.execute(
        update(Notification)
        .where(visible_notifications(auth.user), Notification.is_read.is_(False))
        .values(is_read=True)
    )
    await db.commit()
    await publish_event("notification.updated", {"action": "read_all"})
    return Envelope(data={"success": True})


@router.delete("/{notification_id}", status_code=204)
async def delete_notification(
    notification_id: str,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    _: Annotated[User, Depends(require_role("admin"))],
) -> None:
    """Delete a notification (admin)."""
    notification = await db.get(Notification, notification_id)
    if notification is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    mandate_id = notification.mandant_id
    await db.delete(notification)
    await db.commit()
    await publish_event(
        "notification.updated",
        {"id": notification_id, "action": "delete"},
        mandate_id=mandate_id,
    )
