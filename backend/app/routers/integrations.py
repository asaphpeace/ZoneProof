"""
Integrations API (V2 plan D1). Admin only, tenant scoped.

Credentials go in on create and never come back: responses carry which fields
are set, never a value, masked or not. Errors are the fixed kinds from
job_registry, never vendor text.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import IntegrationConnection
from app.models.user import User
from app.routers.auth import _require_admin, get_current_user
from app.services import integration_service, integrations

router = APIRouter(prefix="/integrations", tags=["integrations"])


class ConnectionIn(BaseModel):
    vendor: str = Field(max_length=40)
    label: str = Field(default="", max_length=120)
    credentials: dict[str, str]


class FeedPatch(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = Field(default=None, ge=300, le=7 * 86400)


def _iso(dt):
    return dt.isoformat() if dt else None


def _out(conn: IntegrationConnection) -> dict:
    adapter = integrations.get(conn.vendor)
    labels = {f.key: f.label for f in adapter.feeds} if adapter else {}
    return {
        "id": str(conn.id), "vendor": conn.vendor, "label": conn.label,
        "vendor_label": adapter.label if adapter else conn.vendor,
        "status": conn.status, "last_error_kind": conn.last_error_kind,
        "last_tested_at": _iso(conn.last_tested_at),
        "credentials_set": list(adapter.credential_fields) if adapter else [],
        "feeds": [
            {
                "id": str(f.id), "key": f.feed_key, "label": labels.get(f.feed_key, f.feed_key),
                "enabled": f.enabled, "interval_seconds": f.interval_seconds,
                "last_started": _iso(f.last_started), "last_finished": _iso(f.last_finished),
                "last_ok": f.last_ok, "last_error_kind": f.last_error_kind,
                "last_count": f.last_count, "last_duration_s": f.last_duration_s,
                "next_run": _iso(integration_service.next_run(f)) if f.last_finished else None,
            }
            for f in conn.feeds
        ],
    }


async def _owned(db: AsyncSession, user: User, connection_id: uuid.UUID) -> IntegrationConnection:
    conn = await integration_service.get_connection(db, user.tenant_id, connection_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Integration not found")
    return conn


@router.get("/vendors")
async def vendors(user: User = Depends(get_current_user)):
    _require_admin(user)
    return [
        {"vendor": a.vendor, "label": a.label, "credential_fields": list(a.credential_fields),
         "feeds": [{"key": f.key, "label": f.label} for f in a.feeds]}
        for a in integrations.all_adapters()
    ]


@router.get("")
async def list_connections(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    _require_admin(user)
    rows = (await db.execute(
        select(IntegrationConnection).where(IntegrationConnection.tenant_id == user.tenant_id)
        .order_by(IntegrationConnection.created_at)
    )).scalars().all()
    return [_out(c) for c in rows]


@router.post("", status_code=201)
async def create(body: ConnectionIn, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    _require_admin(user)
    try:
        conn = await integration_service.create_connection(db, user.tenant_id, body.vendor, body.label, body.credentials)
    except integration_service.IntegrationError as e:
        raise HTTPException(status_code=422, detail=str(e))
    await db.commit()
    await db.refresh(conn)
    return _out(conn)


@router.post("/{connection_id}/test")
async def test(connection_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    _require_admin(user)
    conn = await _owned(db, user, connection_id)
    await integration_service.test_connection(db, conn)
    await db.commit()
    return _out(conn)


@router.post("/{connection_id}/feeds/{feed_id}/run")
async def run(connection_id: uuid.UUID, feed_id: uuid.UUID, db: AsyncSession = Depends(get_db),
              user: User = Depends(get_current_user)):
    _require_admin(user)
    conn = await _owned(db, user, connection_id)
    feed = next((f for f in conn.feeds if f.id == feed_id), None)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    await integration_service.run_feed(db, conn, feed)
    await db.commit()
    return _out(conn)


@router.patch("/{connection_id}/feeds/{feed_id}")
async def patch_feed(connection_id: uuid.UUID, feed_id: uuid.UUID, body: FeedPatch,
                     db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    _require_admin(user)
    conn = await _owned(db, user, connection_id)
    feed = next((f for f in conn.feeds if f.id == feed_id), None)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    if body.enabled is not None:
        feed.enabled = body.enabled
    if body.interval_seconds is not None:
        feed.interval_seconds = body.interval_seconds
    await db.commit()
    return _out(conn)


@router.delete("/{connection_id}", status_code=204)
async def delete(connection_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    _require_admin(user)
    conn = await _owned(db, user, connection_id)
    await db.delete(conn)
    await db.commit()
