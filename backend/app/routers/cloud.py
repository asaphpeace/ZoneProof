import secrets
import uuid as _uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import CloudAccountConnection, CloudAsset, Engagement, Finding
from app.models.user import User
from app.rate_limit import limiter
from app.routers.auth import get_current_user
from app.schemas.cloud import (
    CloudAssetDetailOut, CloudAssetFindingOut, CloudAssetOut,
    CloudConnectionCreate, CloudConnectionSetupOut,
    CloudConnectionOut, CloudConnectionVerifyRequest, ConnectionRenameRequest,
    UpdateCloudAssetHighValueRequest,
)
from app.services import audit_service, cloud_scan_service

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

router = APIRouter(prefix="/cloud-connections", tags=["cloud"])

_SUPPORTED_PROVIDERS = {"aws"}  # azure, gcp follow once AWS proves the pipeline — BUILD_PLAN.md Phase 1 step 11


def _to_out(c: CloudAccountConnection, engagement_status: str | None = None) -> CloudConnectionOut:
    return CloudConnectionOut(
        id=str(c.id), provider=c.provider, status=c.status, role_arn=c.role_arn,
        connected_at=c.connected_at.isoformat() if c.connected_at else None,
        last_scanned_at=c.last_scanned_at.isoformat() if c.last_scanned_at else None,
        last_scan_status=c.last_scan_status, last_scan_error=c.last_scan_error,
        last_scan_results=c.last_scan_results or {},
        created_at=c.created_at.isoformat(),
        engagement_id=str(c.engagement_id) if c.engagement_id else None,
        engagement_status=engagement_status,
        display_name=c.display_name,
    )


@router.get("", response_model=list[CloudConnectionOut])
async def list_connections(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(CloudAccountConnection)
        .where(CloudAccountConnection.tenant_id == user.tenant_id)
        .order_by(CloudAccountConnection.created_at.desc())
    )
    connections = result.scalars().all()

    engagement_ids = {c.engagement_id for c in connections if c.engagement_id}
    status_by_engagement: dict[_uuid.UUID, str] = {}
    if engagement_ids:
        eng_result = await db.execute(select(Engagement.id, Engagement.status).where(Engagement.id.in_(engagement_ids)))
        status_by_engagement = {row[0]: row[1] for row in eng_result.all()}

    return [_to_out(c, status_by_engagement.get(c.engagement_id)) for c in connections]


@router.post("", response_model=CloudConnectionSetupOut)
async def create_connection(
    payload: CloudConnectionCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if payload.provider not in _SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Provider '{payload.provider}' is not yet supported")

    external_id = secrets.token_urlsafe(24)
    connection = CloudAccountConnection(
        id=_uuid.uuid4(),
        tenant_id=user.tenant_id,
        provider=payload.provider,
        external_id=external_id,
        status="pending_verification",
        connected_by_user_id=user.id,
    )
    db.add(connection)
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="cloud_connection.created",
        target_type="cloud_account_connection", target_id=str(connection.id), target_label=payload.provider,
    )
    await db.commit()

    setup = cloud_scan_service.generate_aws_connection_setup(external_id)
    return CloudConnectionSetupOut(
        id=str(connection.id), provider=connection.provider, status=connection.status,
        external_id=external_id, **setup,
    )


async def _get_connection(connection_id: str, db: AsyncSession, user: User) -> CloudAccountConnection:
    result = await db.execute(
        select(CloudAccountConnection).where(
            CloudAccountConnection.id == connection_id,
            CloudAccountConnection.tenant_id == user.tenant_id,
        )
    )
    connection = result.scalar_one_or_none()
    if not connection:
        raise HTTPException(status_code=404, detail="Cloud connection not found")
    return connection


@router.post("/{connection_id}/verify", response_model=CloudConnectionOut)
async def verify_connection(
    connection_id: str,
    payload: CloudConnectionVerifyRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    connection = await _get_connection(connection_id, db, user)
    connection.role_arn = payload.role_arn
    await db.commit()

    ok = await cloud_scan_service.verify_aws_connection(db, connection)
    if not ok:
        raise HTTPException(status_code=400, detail="Could not assume the provided role — check the role ARN and trust policy")
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="cloud_connection.verified",
        target_type="cloud_account_connection", target_id=str(connection.id), target_label=payload.role_arn,
    )
    await db.commit()
    return _to_out(connection)


@router.post("/{connection_id}/rescan", response_model=CloudConnectionOut)
@limiter.limit("5/minute")
async def rescan_connection_now(
    request: Request,
    connection_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Manual on-demand rescan — runs the same rescan_connection() pass the
    scheduler runs periodically (BUILD_PLAN.md's rescan job), just triggered
    immediately instead of waiting for the next interval. Backs the Coverage
    Map / Overview "Run Scan" action for Cloud Misconfiguration Defense,
    the one lineup feature with a real end-to-end scan pipeline."""
    connection = await _get_connection(connection_id, db, user)
    if connection.status != "connected":
        raise HTTPException(status_code=400, detail="Connection is not active — verify it first")
    if not connection.engagement_id:
        raise HTTPException(status_code=400, detail="No engagement authorizes scanning this connection")

    result = await db.execute(select(Engagement).where(Engagement.id == connection.engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement or engagement.status != "active":
        raise HTTPException(status_code=400, detail="Engagement is not active")

    await cloud_scan_service.rescan_connection(db, engagement, connection)
    await db.refresh(connection)
    return _to_out(connection)


def _asset_to_out(asset: CloudAsset, open_count: int, worst_severity: str | None) -> CloudAssetOut:
    return CloudAssetOut(
        id=str(asset.id), resource_type=asset.resource_type, resource_id=asset.resource_id,
        region=asset.region, tags=(asset.resource_metadata or {}).get("tags", {}),
        checked_by={
            k[:-len("_status")]: v for k, v in (asset.resource_metadata or {}).items() if k.endswith("_status")
        },
        open_findings_count=open_count, worst_open_severity=worst_severity,
        first_seen_at=asset.first_seen_at.isoformat(), last_seen_at=asset.last_seen_at.isoformat(),
        is_high_value=asset.is_high_value,
        high_value_set_at=asset.high_value_set_at.isoformat() if asset.high_value_set_at else None,
    )


@router.get("/{connection_id}/resources", response_model=list[CloudAssetOut])
async def list_resources(
    connection_id: str,
    resource_type: str | None = None,
    region: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Phase 38d — the Resource Explorer's primary list. Finding summary
    is computed via a real asset_id join (cheap, one bulk query) — a
    collapsed multi-region finding (asset_id=None) doesn't count toward
    any one resource's badge here; its real per-resource detail is still
    reachable from that resource's own detail page (below), which also
    matches on resource_uid/affected_resources, not just asset_id."""
    connection = await _get_connection(connection_id, db, user)

    query = select(CloudAsset).where(CloudAsset.cloud_account_connection_id == connection.id)
    if resource_type:
        query = query.where(CloudAsset.resource_type == resource_type)
    if region:
        query = query.where(CloudAsset.region == region)
    assets = (await db.execute(query.order_by(CloudAsset.resource_type, CloudAsset.resource_id))).scalars().all()
    if not assets:
        return []

    asset_ids = [a.id for a in assets]
    finding_result = await db.execute(
        select(Finding.asset_id, Finding.severity).where(
            Finding.asset_id.in_(asset_ids), Finding.status == "open",
        )
    )
    counts: dict[_uuid.UUID, int] = {}
    worst: dict[_uuid.UUID, str] = {}
    for asset_id, severity in finding_result.all():
        counts[asset_id] = counts.get(asset_id, 0) + 1
        if asset_id not in worst or _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(worst[asset_id], 0):
            worst[asset_id] = severity

    return [_asset_to_out(a, counts.get(a.id, 0), worst.get(a.id)) for a in assets]


@router.get("/{connection_id}/resources/{asset_id}", response_model=CloudAssetDetailOut)
async def get_resource_detail(
    connection_id: str,
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Matches findings by asset_id, resource_uid, AND affected_resources
    (Phase 38d) — a collapsed multi-region Finding has asset_id=None but
    still lists this resource in affected_resources, so it still needs to
    show up here even though it can't honestly attribute to just one
    resource on the list view's summary badge."""
    connection = await _get_connection(connection_id, db, user)
    result = await db.execute(
        select(CloudAsset).where(CloudAsset.id == asset_id, CloudAsset.cloud_account_connection_id == connection.id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Resource not found")

    finding_result = await db.execute(
        select(Finding).where(
            Finding.tenant_id == user.tenant_id,
            (Finding.asset_id == asset.id) | (Finding.resource_uid == asset.resource_id)
            | Finding.affected_resources.any(asset.resource_id),
        ).order_by(Finding.discovered_at.desc())
    )
    findings = finding_result.scalars().all()
    open_count = sum(1 for f in findings if f.status == "open")
    worst_severity = None
    for f in findings:
        if f.status != "open":
            continue
        if worst_severity is None or _SEVERITY_RANK.get(f.severity, 0) > _SEVERITY_RANK.get(worst_severity, 0):
            worst_severity = f.severity

    out = _asset_to_out(asset, open_count, worst_severity)
    return CloudAssetDetailOut(
        **out.model_dump(),
        findings=[
            CloudAssetFindingOut(
                id=str(f.id), tier=f.tier, severity=f.severity, title=f.title, status=f.status,
                check_id=f.check_id, detail=f.detail, remediation_guidance=f.remediation_guidance,
                region=f.region, extra=f.extra, discovered_at=f.discovered_at.isoformat(),
            )
            for f in findings
        ],
    )


@router.patch("/{connection_id}/resources/{asset_id}/high-value", response_model=CloudAssetOut)
async def update_resource_high_value(
    connection_id: str,
    asset_id: str,
    payload: UpdateCloudAssetHighValueRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Manual override of the heuristic default (resource_inventory_
    service.py's _infer_high_value). Once set here, high_value_set_by_
    user_id is permanently populated, which is what protects this from
    ever being silently recomputed on a later rescan — same guarantee as
    ReportedEmail.disposition. Audited with real before/after since this
    directly drives which attack paths the graph treats as reaching
    something that matters."""
    connection = await _get_connection(connection_id, db, user)
    result = await db.execute(
        select(CloudAsset).where(CloudAsset.id == asset_id, CloudAsset.cloud_account_connection_id == connection.id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Resource not found")

    before = asset.is_high_value
    asset.is_high_value = payload.is_high_value
    asset.high_value_set_by_user_id = user.id
    asset.high_value_set_at = datetime.now(timezone.utc)
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="cloud_asset.high_value_set",
        target_type="cloud_asset", target_id=str(asset.id), target_label=asset.resource_id,
        before={"is_high_value": before}, after={"is_high_value": asset.is_high_value},
    )
    await db.commit()

    finding_result = await db.execute(
        select(Finding.severity).where(Finding.asset_id == asset.id, Finding.status == "open")
    )
    severities = [row[0] for row in finding_result.all()]
    worst_severity = max(severities, key=lambda s: _SEVERITY_RANK.get(s, 0)) if severities else None
    return _asset_to_out(asset, len(severities), worst_severity)


@router.post("/{connection_id}/revoke", response_model=CloudConnectionOut)
async def revoke_connection(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    connection = await _get_connection(connection_id, db, user)
    connection.status = "revoked"
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="cloud_connection.revoked",
        target_type="cloud_account_connection", target_id=str(connection.id), target_label=connection.role_arn,
    )
    await db.commit()
    return _to_out(connection)


@router.patch("/{connection_id}", response_model=CloudConnectionOut)
async def rename_connection(
    connection_id: str,
    payload: ConnectionRenameRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """The one piece of "environment" identity nothing in the AWS API can
    supply — role_arn/account_id are real, stable technical facts, but
    whether an account is Production, Staging, or a specific client's
    sandbox is a human judgment call. Audited with real before/after values
    (matching engagement.py's schedule-edit convention) since a mislabel
    here could genuinely mislead whoever reads findings against it next."""
    connection = await _get_connection(connection_id, db, user)
    before = connection.display_name
    connection.display_name = (payload.display_name or "").strip() or None
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="cloud_connection.renamed",
        target_type="cloud_account_connection", target_id=str(connection.id), target_label=connection.role_arn,
        before={"display_name": before}, after={"display_name": connection.display_name},
    )
    await db.commit()
    return _to_out(connection)
