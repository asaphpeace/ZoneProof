"""
Tenant-wide Findings — real fix for a bug pattern found three times this
session (SimulateFixView only checking the first engagement, GraphView's
chokepoint needing a real tenant-wide query, FindingsView's host merge
silently dropping a second connected host): every screen was reinventing
its own "loop over the right engagements and merge" logic because the API
only ever offered per-engagement fetching, and some screens got it wrong.

This is the one real aggregate: every Finding for the tenant in one call,
each annotated with which real connection (hostname for host, account/role
for cloud) it came from — resolved centrally, here, instead of guessed or
re-derived per screen.
"""
import re
import uuid as _uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import CloudAccountConnection, CloudAsset, Finding, HostConnection, OAuthGrant
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.finding import FindingConnectionOut, FindingsListOut
from app.services.finding_presentation import finding_to_out

router = APIRouter(prefix="/findings", tags=["findings"])

_ROLE_ARN_RE = re.compile(r"^arn:aws:iam::(\d+):role/(.+)$")


def _cloud_connection_label(role_arn: str | None) -> str:
    if not role_arn:
        return "AWS account (pending verification)"
    match = _ROLE_ARN_RE.match(role_arn)
    if not match:
        return role_arn
    account_id, role_name = match.groups()
    return f"{account_id} · {role_name}"


@router.get("", response_model=FindingsListOut)
async def list_all_findings(
    tier: str | None = Query(None),
    connection_id: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Real connections first — every one with a linked engagement, whether
    # or not it has produced a finding yet (a freshly connected, not-yet-
    # scanned host is still a real, selectable filter option).
    cloud_result = await db.execute(
        select(CloudAccountConnection).where(
            CloudAccountConnection.tenant_id == user.tenant_id, CloudAccountConnection.engagement_id.is_not(None),
        )
    )
    cloud_connections = cloud_result.scalars().all()
    host_result = await db.execute(
        select(HostConnection).where(
            HostConnection.tenant_id == user.tenant_id, HostConnection.engagement_id.is_not(None),
        )
    )
    host_connections = host_result.scalars().all()

    connections_catalog = [
        FindingConnectionOut(id=str(c.id), tier="cloud", label=_cloud_connection_label(c.role_arn), display_name=c.display_name)
        for c in cloud_connections
    ] + [
        FindingConnectionOut(id=str(c.id), tier="host", label=c.hostname_or_ip, display_name=c.display_name)
        for c in host_connections
    ]

    # engagement_id -> connection, for resolving each finding below. A host
    # match is by exact hostname (resource_uid), since one engagement could
    # in principle hold more than one host connection (createEngagement
    # accepts a list) — falls back to the first host connection on that
    # engagement when resource_uid doesn't match any of them (e.g. a
    # non-host-specific finding tier that still landed on a host
    # engagement, which doesn't happen today but shouldn't silently lose
    # its label if it ever does).
    cloud_by_engagement: dict[_uuid.UUID, CloudAccountConnection] = {}
    for c in cloud_connections:
        cloud_by_engagement.setdefault(c.engagement_id, c)
    hosts_by_engagement: dict[_uuid.UUID, list[HostConnection]] = {}
    for c in host_connections:
        hosts_by_engagement.setdefault(c.engagement_id, []).append(c)

    query = select(Finding).where(Finding.tenant_id == user.tenant_id)
    if tier:
        query = query.where(Finding.tier == tier)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    result = await db.execute(query.order_by(Finding.discovered_at.desc()))
    findings = result.scalars().all()

    oauth_result = await db.execute(select(OAuthGrant.app_client_id, OAuthGrant.scopes).where(OAuthGrant.tenant_id == user.tenant_id))
    scopes_by_app_client_id: dict[str, list[str]] = {app_client_id: scopes for app_client_id, scopes in oauth_result.all()}

    # Real resource tags (Name, Environment, ...) — read live from CloudAsset,
    # never from Finding.extra, which can be stale for a finding created
    # before tag capture existed (see finding_reconciliation.py's own
    # asset_id-backfill fix for the identical staleness problem). One bulk
    # query for every asset_id actually referenced, not N+1 per finding.
    asset_ids = {f.asset_id for f in findings if f.asset_id}
    tags_by_asset_id: dict[_uuid.UUID, dict[str, str]] = {}
    if asset_ids:
        asset_result = await db.execute(select(CloudAsset.id, CloudAsset.resource_metadata).where(CloudAsset.id.in_(asset_ids)))
        for asset_id, metadata in asset_result.all():
            tags = (metadata or {}).get("tags") or {}
            if tags:
                tags_by_asset_id[asset_id] = tags

    out: list = []
    for f in findings:
        conn_id: str | None = None
        conn_label: str | None = None
        conn_display_name: str | None = None
        if f.tier == "host" and f.engagement_id in hosts_by_engagement:
            hosts = hosts_by_engagement[f.engagement_id]
            match = next((h for h in hosts if h.hostname_or_ip == f.resource_uid), hosts[0])
            conn_id, conn_label, conn_display_name = str(match.id), match.hostname_or_ip, match.display_name
        elif f.engagement_id in cloud_by_engagement:
            c = cloud_by_engagement[f.engagement_id]
            conn_id, conn_label, conn_display_name = str(c.id), _cloud_connection_label(c.role_arn), c.display_name

        if connection_id and conn_id != connection_id:
            continue
        out.append(finding_to_out(
            f, scopes_by_app_client_id, connection_id=conn_id, connection_label=conn_label,
            connection_display_name=conn_display_name, resource_tags=tags_by_asset_id.get(f.asset_id),
        ))

    return FindingsListOut(findings=out, connections=connections_catalog)
