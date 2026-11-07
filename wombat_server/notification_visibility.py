"""Shared visibility rule for per-user notifications."""
from __future__ import annotations

from sqlalchemy import and_, or_, true

from wombat_server.models import Notification, User


def visible_notifications(user: User):
    """SQLAlchemy clause: notifications the given user may list/mark.

    Admin keeps the historical "see all" behaviour. Everyone else sees:
    - notifications explicitly targeted at them, and
    - untargeted notifications whose role audience matches their role or is
      null/"all".
    """
    if user.role == "admin":
        return true()
    return or_(
        Notification.target_user_id == user.id,
        and_(
            Notification.target_user_id.is_(None),
            or_(
                Notification.target_role.is_(None),
                Notification.target_role == "all",
                Notification.target_role == user.role,
            ),
        ),
    )
