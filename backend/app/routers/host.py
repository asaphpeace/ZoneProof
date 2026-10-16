import uuid as _uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Engagement, HostConnection
from app.models.user import User
from app.rate_limit import limiter
from app.routers.auth import get_current_user
from app.schemas.host_connection import (
    HostConnectionCreate, HostConnectionOut, HostConnectionRenameRequest, HostConnectionSetupOut,
)
from app.services import audit_service, host_scan_service
from app.services.crypto_service import encrypt_secret

router = APIRouter(prefix="/host-connections", tags=["host"])

_SETUP_INSTRUCTIONS = [
    "Create a dedicated, unprivileged user on the target host for Sentinel's read-only audit access (do not reuse an existing admin account).",
    "Append the public key below to that user's ~/.ssh/authorized_keys file.",
    "Confirm the user can run `lynis` (installed system-wide or available on its PATH) — no sudo is required or requested.",
]


def _to_out(c: HostConnection, engagement_status: str | None = None) -> HostConnectionOut:
    return HostConnectionOut(
        id=str(c.id), hostname_or_ip=c.hostname_or_ip, ssh_port=c.ssh_port, ssh_username=c.ssh_username,
        status=c.status, public_key_fingerprint=c.public_key_fingerprint, host_key_fingerprint=c.host_key_fingerprint,
        connected_at=c.connected_at.isoformat() if c.connected_at else None,
        last_scanned_at=c.last_scanned_at.isoformat() if c.last_scanned_at else None,
        last_scan_status=c.last_scan_status, last_scan_error=c.last_scan_error,
        created_at=c.created_at.isoformat(),
        engagement_id=str(c.engagement_id) if c.engagement_id else None,
        engagement_status=engagement_status,
        display_name=c.display_name,
    )


@router.get("", response_model=list[HostConnectionOut])
async def list_connections(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(HostConnection)
        .where(HostConnection.tenant_id == user.tenant_id)
        .order_by(HostConnection.created_at.desc())
    )
    connections = result.scalars().all()

    engagement_ids = {c.engagement_id for c in connections if c.engagement_id}
    status_by_engagement: dict[_uuid.UUID, str] = {}
    if engagement_ids:
        eng_result = await db.execute(select(Engagement.id, Engagement.status).where(Engagement.id.in_(engagement_ids)))
        status_by_engagement = {row[0]: row[1] for row in eng_result.all()}

    return [_to_out(c, status_by_engagement.get(c.engagement_id)) for c in connections]


@router.post("", response_model=HostConnectionSetupOut)
async def create_connection(
    payload: HostConnectionCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    private_pem, public_openssh, fingerprint = host_scan_service.generate_ssh_keypair()

    connection = HostConnection(
        id=_uuid.uuid4(),
        tenant_id=user.tenant_id,
        hostname_or_ip=payload.hostname_or_ip,
        ssh_port=payload.ssh_port,
        ssh_username=payload.ssh_username,
        encrypted_private_key=encrypt_secret(private_pem),
        public_key=public_openssh,
        public_key_fingerprint=fingerprint,
        status="pending_verification",
        connected_by_user_id=user.id,
    )
    db.add(connection)
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="host_connection.created",
        target_type="host_connection", target_id=str(connection.id), target_label=payload.hostname_or_ip,
    )
    await db.commit()

    return HostConnectionSetupOut(
        id=str(connection.id), hostname_or_ip=connection.hostname_or_ip, ssh_port=connection.ssh_port,
        ssh_username=connection.ssh_username, status=connection.status,
        public_key=public_openssh, public_key_fingerprint=fingerprint, instructions=_SETUP_INSTRUCTIONS,
    )


async def _get_connection(connection_id: str, db: AsyncSession, user: User) -> HostConnection:
    result = await db.execute(
        select(HostConnection).where(
            HostConnection.id == connection_id,
            HostConnection.tenant_id == user.tenant_id,
        )
    )
    connection = result.scalar_one_or_none()
    if not connection:
        raise HTTPException(status_code=404, detail="Host connection not found")
    return connection


@router.post("/{connection_id}/verify", response_model=HostConnectionOut)
async def verify_connection(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    connection = await _get_connection(connection_id, db, user)
    ok = await host_scan_service.verify_host_connection(db, connection)
    if not ok:
        raise HTTPException(status_code=400, detail="Could not connect — check the hostname/port and that the public key was installed")
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="host_connection.verified",
        target_type="host_connection", target_id=str(connection.id), target_label=connection.hostname_or_ip,
    )
    await db.commit()
    return _to_out(connection)


@router.post("/{connection_id}/rescan", response_model=HostConnectionOut)
@limiter.limit("5/minute")
async def rescan_connection_now(
    request: Request,
    connection_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    connection = await _get_connection(connection_id, db, user)
    if connection.status != "connected":
        raise HTTPException(status_code=400, detail="Connection is not active — verify it first")
    if not connection.engagement_id:
        raise HTTPException(status_code=400, detail="No engagement authorizes scanning this connection")

    result = await db.execute(select(Engagement).where(Engagement.id == connection.engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement or engagement.status != "active":
        raise HTTPException(status_code=400, detail="Engagement is not active")

    await host_scan_service.rescan_host_connection(db, engagement, connection)
    await db.refresh(connection)
    return _to_out(connection)


@router.post("/{connection_id}/revoke", response_model=HostConnectionOut)
async def revoke_connection(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    connection = await _get_connection(connection_id, db, user)
    connection.status = "revoked"
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="host_connection.revoked",
        target_type="host_connection", target_id=str(connection.id), target_label=connection.hostname_or_ip,
    )
    await db.commit()
    return _to_out(connection)


@router.patch("/{connection_id}", response_model=HostConnectionOut)
async def rename_connection(
    connection_id: str,
    payload: HostConnectionRenameRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Same reasoning as cloud.py's own rename_connection — hostname_or_ip
    is a real, stable technical fact but says nothing about what the
    machine actually is; that's a human judgment call, so it needs a
    human-editable field, audited with real before/after values."""
    connection = await _get_connection(connection_id, db, user)
    before = connection.display_name
    connection.display_name = (payload.display_name or "").strip() or None
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="host_connection.renamed",
        target_type="host_connection", target_id=str(connection.id), target_label=connection.hostname_or_ip,
        before={"display_name": before}, after={"display_name": connection.display_name},
    )
    await db.commit()
    return _to_out(connection)
