import uuid as _uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Engagement, OAuthAppConnection, OAuthGrant
from app.models.user import User
from app.rate_limit import limiter
from app.routers.auth import get_current_user
from app.schemas.oauth_app_risk import OAuthAppConnectionCreate, OAuthAppConnectionOut, OAuthGrantOut
from app.services import audit_service
from app.services.crypto_service import encrypt_secret
from app.services.oauth_app_risk_service import run_oauth_risk_scan, verify_connection

router = APIRouter(tags=["oauth-app-risk"])

_SETUP_INSTRUCTIONS = [
    "In your Entra ID admin center, create an App Registration dedicated to Sentinel Command (do not reuse an existing app).",
    "Grant it these Microsoft Graph *application* permissions, then have a Global Administrator click 'Grant admin consent': "
    "Application.Read.All, DelegatedPermissionGrant.Read.All, User.Read.All. All three are read-only.",
    "Create a client secret for the app registration (a certificate is stronger, but a client secret is simplest to start with) and paste its directory (tenant) ID, application (client) ID, and secret value below.",
]


def _connection_out(c: OAuthAppConnection) -> OAuthAppConnectionOut:
    return OAuthAppConnectionOut(
        id=str(c.id), provider=c.provider, ms_tenant_id=c.ms_tenant_id, ms_client_id=c.ms_client_id,
        status=c.status, connected_at=c.connected_at.isoformat() if c.connected_at else None,
        last_scanned_at=c.last_scanned_at.isoformat() if c.last_scanned_at else None,
        last_scan_status=c.last_scan_status, last_scan_error=c.last_scan_error,
        created_at=c.created_at.isoformat(),
    )


def _grant_out(g: OAuthGrant) -> OAuthGrantOut:
    return OAuthGrantOut(
        id=str(g.id), grantee_principal=g.grantee_principal, app_name=g.app_name, app_client_id=g.app_client_id,
        scopes=g.scopes, risk_tier=g.risk_tier,
        publisher_verified=g.publisher_verified, publisher_name=g.publisher_name,
        granted_at=g.granted_at.isoformat() if g.granted_at else None, discovered_at=g.discovered_at.isoformat(),
    )


async def _get_connection(connection_id: str, db: AsyncSession, user: User) -> OAuthAppConnection:
    result = await db.execute(
        select(OAuthAppConnection).where(OAuthAppConnection.id == connection_id, OAuthAppConnection.tenant_id == user.tenant_id)
    )
    connection = result.scalar_one_or_none()
    if not connection:
        raise HTTPException(status_code=404, detail="OAuth app connection not found")
    return connection


async def _get_or_create_oauth_engagement(db: AsyncSession, user: User) -> Engagement:
    """Auto-approved, same consent weight as an Exposure scan
    (OAUTH_APP_RISK_DESIGN.md Section 7) — read-only, no active testing, no
    employees directly targeted by anything Sentinel does. Mirrors
    exposure.py's _get_or_create_exposure_engagement exactly."""
    result = await db.execute(
        select(Engagement).where(
            Engagement.tenant_id == user.tenant_id, Engagement.tier == "oauth_risk", Engagement.status == "active",
        )
    )
    engagement = result.scalar_one_or_none()
    if engagement:
        return engagement

    engagement = Engagement(
        id=_uuid.uuid4(), tenant_id=user.tenant_id, tier="oauth_risk", status="active",
        approved_by_user_id=user.id, approved_at=datetime.now(timezone.utc),
    )
    db.add(engagement)
    await db.commit()
    await db.refresh(engagement)
    return engagement


@router.post("/oauth-app-connections", response_model=OAuthAppConnectionOut)
async def create_oauth_app_connection(
    payload: OAuthAppConnectionCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    connection = OAuthAppConnection(
        id=_uuid.uuid4(), tenant_id=user.tenant_id, provider="microsoft365",
        ms_tenant_id=payload.ms_tenant_id, ms_client_id=payload.ms_client_id,
        encrypted_client_secret=encrypt_secret(payload.ms_client_secret),
        status="pending_verification",
    )
    db.add(connection)
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="oauth_app_connection.created",
        target_type="oauth_app_connection", target_id=str(connection.id), target_label=payload.ms_tenant_id,
    )
    await db.commit()
    await db.refresh(connection)
    return _connection_out(connection)


@router.get("/oauth-app-connections/setup-instructions", response_model=list[str])
async def get_setup_instructions(user: User = Depends(get_current_user)):
    return _SETUP_INSTRUCTIONS


@router.get("/oauth-app-connections", response_model=list[OAuthAppConnectionOut])
async def list_oauth_app_connections(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    result = await db.execute(
        select(OAuthAppConnection).where(OAuthAppConnection.tenant_id == user.tenant_id).order_by(OAuthAppConnection.created_at.desc())
    )
    return [_connection_out(c) for c in result.scalars().all()]


@router.post("/oauth-app-connections/{connection_id}/verify", response_model=OAuthAppConnectionOut)
async def verify_oauth_app_connection(
    connection_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    connection = await _get_connection(connection_id, db, user)
    ok = await verify_connection(connection)
    if not ok:
        raise HTTPException(status_code=400, detail="Could not verify — check the tenant/client id and secret, and that admin consent was granted")

    engagement = await _get_or_create_oauth_engagement(db, user)
    connection.status = "connected"
    connection.connected_by_user_id = user.id
    connection.connected_at = datetime.now(timezone.utc)
    connection.engagement_id = engagement.id
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="oauth_app_connection.verified",
        target_type="oauth_app_connection", target_id=str(connection.id), target_label=connection.ms_tenant_id,
    )
    await db.commit()
    await db.refresh(connection)
    return _connection_out(connection)


@router.post("/oauth-app-connections/{connection_id}/scan", response_model=list[OAuthGrantOut])
@limiter.limit("5/minute")
async def scan_oauth_app_connection(
    request: Request, connection_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
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

    await run_oauth_risk_scan(db, engagement, connection)
    grants_result = await db.execute(
        select(OAuthGrant).where(OAuthGrant.connection_id == connection.id).order_by(OAuthGrant.discovered_at.desc())
    )
    return [_grant_out(g) for g in grants_result.scalars().all()]


@router.post("/oauth-app-connections/{connection_id}/revoke", response_model=OAuthAppConnectionOut)
async def revoke_oauth_app_connection(
    connection_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    connection = await _get_connection(connection_id, db, user)
    connection.status = "revoked"
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="oauth_app_connection.revoked",
        target_type="oauth_app_connection", target_id=str(connection.id), target_label=connection.ms_tenant_id,
    )
    await db.commit()
    return _connection_out(connection)


@router.get("/engagements/{engagement_id}/oauth-grants", response_model=list[OAuthGrantOut])
async def list_oauth_grants(
    engagement_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Engagement).where(Engagement.id == engagement_id, Engagement.tenant_id == user.tenant_id, Engagement.tier == "oauth_risk")
    )
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(status_code=404, detail="OAuth risk engagement not found")

    grants_result = await db.execute(
        select(OAuthGrant).where(OAuthGrant.engagement_id == engagement.id).order_by(OAuthGrant.discovered_at.desc())
    )
    return [_grant_out(g) for g in grants_result.scalars().all()]
