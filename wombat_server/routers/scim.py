"""SCIM 2.0 provisioning (Users and a lightweight Groups view).

The SCIM bearer token is separate from JWTs and is bound to one mandate via
WOMBAT_SCIM_MANDANT_SLUG. The router uses the owner connection because an IdP
provisions across the tenant boundary; every query is explicitly scoped to the
token's mandate.
"""
from __future__ import annotations

import re
import secrets
import uuid
from datetime import datetime
from typing import Annotated, Any, AsyncGenerator

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wombat_server.audit_chain import chain_event
from wombat_server.auth.sessions import revoke_user_sessions
from wombat_server.config import settings
from wombat_server.database import get_owner_connection
from wombat_server.models import Mandant, User, UserAuditLog, UserGroup

router = APIRouter(prefix="/scim/v2", tags=["scim"])

SCIM_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"


def _scim_error(status_code: int, detail: str) -> HTTPException:
    return HTTPException(
        status_code,
        detail={"schemas": [SCIM_ERROR], "detail": detail, "status": str(status_code)},
    )


def require_scim_token(authorization: str | None = Header(default=None)) -> None:
    if not settings.wombat_scim_enabled:
        raise _scim_error(status.HTTP_404_NOT_FOUND, "SCIM is disabled.")
    expected = settings.wombat_scim_token
    if not expected:
        raise _scim_error(status.HTTP_503_SERVICE_UNAVAILABLE, "SCIM token is not configured.")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise _scim_error(status.HTTP_401_UNAUTHORIZED, "Missing SCIM bearer token.")
    presented = authorization.split(" ", 1)[1].strip()
    if not secrets.compare_digest(presented, expected):
        raise _scim_error(status.HTTP_401_UNAUTHORIZED, "Invalid SCIM bearer token.")


async def get_scim_db() -> AsyncGenerator[AsyncSession, None]:
    async with get_owner_connection() as conn:
        async with AsyncSession(bind=conn) as session:
            yield session


async def _mandant_id(db: AsyncSession) -> uuid.UUID | None:
    slug = settings.wombat_scim_mandant_slug.strip()
    if not slug:
        return None
    mandant = (
        await db.execute(select(Mandant).where(Mandant.slug == slug))
    ).scalar_one_or_none()
    if mandant is None:
        raise _scim_error(status.HTTP_503_SERVICE_UNAVAILABLE, "SCIM mandate is not configured.")
    return mandant.id


async def _audit(
    db: AsyncSession,
    action: str,
    detail: dict[str, Any],
    mandant_id: uuid.UUID | None,
) -> None:
    event = UserAuditLog(actor_id=None, action=action, detail=detail, ip="", mandant_id=mandant_id)
    await chain_event(db, event)
    db.add(event)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _user_out(user: User) -> dict[str, Any]:
    return {
        "schemas": [SCIM_USER],
        "id": str(user.id),
        "userName": user.username,
        "displayName": user.display_name or user.username,
        "emails": (
            [{"value": user.email, "type": "work", "primary": True}]
            if user.email
            else []
        ),
        "active": user.is_active,
        "externalId": user.external_id,
        "meta": {
            "resourceType": "User",
            "created": _iso(user.created_at),
            "lastModified": _iso(user.updated_at),
        },
    }


def _list_response(resources: list[dict], total: int, start: int) -> dict[str, Any]:
    return {
        "schemas": [SCIM_LIST],
        "totalResults": total,
        "startIndex": start,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


class ScimEmail(BaseModel):
    value: str
    type: str = "work"
    primary: bool = True


class ScimUserIn(BaseModel):
    schemas: list[str] = []
    userName: str
    displayName: str = ""
    emails: list[ScimEmail] = []
    active: bool = True
    externalId: str | None = None
    groups: list[dict[str, Any]] = []


class ScimPatchOp(BaseModel):
    op: str
    path: str | None = None
    value: Any = None


class ScimPatch(BaseModel):
    schemas: list[str] = [SCIM_PATCH]
    Operations: list[ScimPatchOp] = []


def _primary_email(payload: ScimUserIn) -> str:
    if not payload.emails:
        return ""
    primary = next((e for e in payload.emails if e.primary), payload.emails[0])
    return primary.value


async def _find_user(db: AsyncSession, user_id: str, mandant_id: uuid.UUID | None) -> User:
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise _scim_error(status.HTTP_404_NOT_FOUND, "User not found.")
    stmt = select(User).where(User.id == uid)
    if mandant_id is None:
        stmt = stmt.where(User.mandant_id.is_(None))
    else:
        stmt = stmt.where(User.mandant_id == mandant_id)
    user = (await db.execute(stmt)).scalar_one_or_none()
    if user is None:
        raise _scim_error(status.HTTP_404_NOT_FOUND, "User not found.")
    return user


@router.get("/ServiceProviderConfig")
async def service_provider_config(_: None = Depends(require_scim_token)) -> dict[str, Any]:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "SCIM bearer token",
                "primary": True,
            }
        ],
    }


@router.get("/Users")
async def list_users(
    filter: str | None = Query(default=None),
    startIndex: int = Query(default=1, ge=1),
    count: int = Query(default=100, ge=1, le=200),
    _: None = Depends(require_scim_token),
    db: Annotated[AsyncSession, Depends(get_scim_db)] = None,
) -> dict[str, Any]:
    mandant_id = await _mandant_id(db)
    stmt = select(User)
    if mandant_id is None:
        stmt = stmt.where(User.mandant_id.is_(None))
    else:
        stmt = stmt.where(User.mandant_id == mandant_id)
    if filter:
        match = re.match(r'userName\s+eq\s+"([^"]+)"', filter, re.I)
        if match:
            stmt = stmt.where(User.username == match.group(1))
        else:
            match = re.match(r'externalId\s+eq\s+"([^"]+)"', filter, re.I)
            if match:
                stmt = stmt.where(User.external_id == match.group(1))
            else:
                raise _scim_error(status.HTTP_400_BAD_REQUEST, "Unsupported filter.")
    users = list((await db.execute(stmt.order_by(User.created_at))).scalars().all())
    total = len(users)
    page = users[startIndex - 1 : startIndex - 1 + count]
    return _list_response([_user_out(user) for user in page], total, startIndex)


@router.post("/Users", status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: ScimUserIn,
    _: None = Depends(require_scim_token),
    db: Annotated[AsyncSession, Depends(get_scim_db)] = None,
) -> dict[str, Any]:
    mandant_id = await _mandant_id(db)
    existing = (
        await db.execute(select(User).where(User.username == payload.userName))
    ).scalar_one_or_none()
    if existing is not None:
        raise _scim_error(status.HTTP_409_CONFLICT, "userName already exists.")
    user = User(
        username=payload.userName,
        display_name=payload.displayName or payload.userName,
        email=_primary_email(payload),
        external_id=payload.externalId,
        role=settings.wombat_scim_default_role,
        auth_provider="scim",
        password_hash=None,
        is_active=payload.active,
        mandant_id=mandant_id,
    )
    db.add(user)
    await db.flush()
    for group in payload.groups:
        name = str(group.get("display") or group.get("value") or "").strip()
        if name:
            db.add(UserGroup(user_id=user.id, group_name=name, provider="scim"))
    await _audit(db, "scim_user_created", {"username": user.username}, mandant_id)
    await db.commit()
    await db.refresh(user)
    return _user_out(user)


@router.get("/Users/{user_id}")
async def get_user(
    user_id: str,
    _: None = Depends(require_scim_token),
    db: Annotated[AsyncSession, Depends(get_scim_db)] = None,
) -> dict[str, Any]:
    return _user_out(await _find_user(db, user_id, await _mandant_id(db)))


@router.put("/Users/{user_id}")
async def replace_user(
    user_id: str,
    payload: ScimUserIn,
    _: None = Depends(require_scim_token),
    db: Annotated[AsyncSession, Depends(get_scim_db)] = None,
) -> dict[str, Any]:
    mandant_id = await _mandant_id(db)
    user = await _find_user(db, user_id, mandant_id)
    user.display_name = payload.displayName or user.display_name
    user.email = _primary_email(payload)
    user.external_id = payload.externalId
    user.is_active = payload.active
    if not payload.active:
        await revoke_user_sessions(db, user.id, "scim_deactivated")
    await _audit(db, "scim_user_updated", {"user_id": str(user.id)}, mandant_id)
    await db.commit()
    await db.refresh(user)
    return _user_out(user)


@router.patch("/Users/{user_id}")
async def patch_user(
    user_id: str,
    payload: ScimPatch,
    _: None = Depends(require_scim_token),
    db: Annotated[AsyncSession, Depends(get_scim_db)] = None,
) -> dict[str, Any]:
    mandant_id = await _mandant_id(db)
    user = await _find_user(db, user_id, mandant_id)
    for operation in payload.Operations:
        path = (operation.path or "").lower()
        op = operation.op.lower()
        value = operation.value
        if path in {"active", "urn:ietf:params:scim:schemas:core:2.0:user:active"}:
            user.is_active = bool(value)
            if not user.is_active:
                await revoke_user_sessions(db, user.id, "scim_deactivated")
        elif path == "displayname":
            user.display_name = str(value or "")
        elif path == "externalid":
            user.external_id = str(value) if value else None
        elif path == "emails":
            if isinstance(value, list) and value:
                user.email = str(value[0].get("value", ""))
        elif op == "remove" and path == "active":
            user.is_active = False
        else:
            raise _scim_error(status.HTTP_400_BAD_REQUEST, f"Unsupported patch path: {operation.path}")
    await _audit(db, "scim_user_updated", {"user_id": str(user.id)}, mandant_id)
    await db.commit()
    await db.refresh(user)
    return _user_out(user)


@router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deprovision_user(
    user_id: str,
    _: None = Depends(require_scim_token),
    db: Annotated[AsyncSession, Depends(get_scim_db)] = None,
) -> None:
    mandant_id = await _mandant_id(db)
    user = await _find_user(db, user_id, mandant_id)
    user.is_active = False
    await revoke_user_sessions(db, user.id, "scim_deprovisioned")
    await _audit(db, "scim_user_deprovisioned", {"user_id": str(user.id)}, mandant_id)
    await db.commit()


@router.get("/Groups")
async def list_groups(
    _: None = Depends(require_scim_token),
    db: Annotated[AsyncSession, Depends(get_scim_db)] = None,
) -> dict[str, Any]:
    mandant_id = await _mandant_id(db)
    stmt = select(UserGroup.group_name).distinct()
    if mandant_id is not None:
        stmt = stmt.join(User, User.id == UserGroup.user_id).where(User.mandant_id == mandant_id)
    names = [row[0] for row in (await db.execute(stmt)).all()]
    resources = [
        {"schemas": [SCIM_GROUP], "id": name, "displayName": name}
        for name in names
    ]
    return _list_response(resources, len(resources), 1)


@router.get("/Groups/{group_id}")
async def get_group(
    group_id: str,
    _: None = Depends(require_scim_token),
    db: Annotated[AsyncSession, Depends(get_scim_db)] = None,
) -> dict[str, Any]:
    mandant_id = await _mandant_id(db)
    stmt = select(UserGroup).where(UserGroup.group_name == group_id)
    if mandant_id is not None:
        stmt = stmt.join(User, User.id == UserGroup.user_id).where(User.mandant_id == mandant_id)
    members = list((await db.execute(stmt)).scalars().all())
    return {
        "schemas": [SCIM_GROUP],
        "id": group_id,
        "displayName": group_id,
        "members": [{"value": str(m.user_id)} for m in members],
    }


@router.delete("/Groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: str,
    _: None = Depends(require_scim_token),
    db: Annotated[AsyncSession, Depends(get_scim_db)] = None,
) -> None:
    mandant_id = await _mandant_id(db)
    stmt = select(UserGroup).where(UserGroup.group_name == group_id)
    if mandant_id is not None:
        stmt = stmt.join(User, User.id == UserGroup.user_id).where(User.mandant_id == mandant_id)
    for membership in (await db.execute(stmt)).scalars().all():
        await db.delete(membership)
    await _audit(db, "scim_group_deleted", {"group": group_id}, mandant_id)
    await db.commit()
