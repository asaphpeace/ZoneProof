import uuid as _uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Domain, Engagement
from app.models.user import User
from app.rate_limit import limiter
from app.routers.auth import get_current_user
from app.schemas.finding import FindingOut
from app.services.exposure_scan_service import run_exposure_scan

router = APIRouter(prefix="/domains", tags=["exposure"])


async def _get_domain(domain_id: str, db: AsyncSession, user: User) -> Domain:
    result = await db.execute(
        select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id)
    )
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    return domain


async def _get_or_create_exposure_engagement(db: AsyncSession, user: User, domain: Domain) -> Engagement:
    """Same dev-only auto-approve pattern as cloud/host engagements — see
    engagement.py's approve_engagement docstring. Reuses an existing active
    exposure engagement for this domain rather than creating a new one on
    every scan."""
    result = await db.execute(
        select(Engagement).where(
            Engagement.tenant_id == user.tenant_id,
            Engagement.domain_id == domain.id,
            Engagement.tier == "exposure",
            Engagement.status == "active",
        )
    )
    engagement = result.scalar_one_or_none()
    if engagement:
        return engagement

    engagement = Engagement(
        id=_uuid.uuid4(),
        tenant_id=user.tenant_id,
        domain_id=domain.id,
        tier="exposure",
        status="active",
        approved_by_user_id=user.id,
        approved_at=datetime.now(timezone.utc),
    )
    db.add(engagement)
    await db.commit()
    await db.refresh(engagement)
    return engagement


@router.post("/{domain_id}/exposure-scan", response_model=list[FindingOut])
@limiter.limit("3/minute")
async def run_domain_exposure_scan(
    request: Request,
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    domain = await _get_domain(domain_id, db, user)
    if not domain.ownership_verified:
        raise HTTPException(status_code=400, detail="Domain ownership must be verified before running an exposure scan")

    engagement = await _get_or_create_exposure_engagement(db, user, domain)
    findings = await run_exposure_scan(db, engagement, domain)
    return [
        FindingOut(
            id=str(f.id), engagement_id=str(f.engagement_id), asset_id=None,
            tier=f.tier, severity=f.severity, title=f.title, status=f.status,
            check_id=f.check_id, resource_uid=f.resource_uid, detail=f.detail, remediation_guidance=f.remediation_guidance,
            discovered_at=f.discovered_at.isoformat(),
        )
        for f in findings
    ]
