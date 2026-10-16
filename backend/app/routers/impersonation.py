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
from app.schemas.impersonation import ImpersonationScanRequest
from app.services.impersonation_scan_service import run_impersonation_scan

router = APIRouter(prefix="/domains", tags=["impersonation"])


async def _get_domain(domain_id: str, db: AsyncSession, user: User) -> Domain:
    result = await db.execute(
        select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id)
    )
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    return domain


async def _get_or_create_impersonation_engagement(
    db: AsyncSession, user: User, domain: Domain, test_recipient_email: str | None,
) -> Engagement:
    """Same dev-only auto-approve pattern as exposure engagements — no
    employees are targeted by this tier, so it rides the same consent
    weight rather than requiring a dedicated e-signature (PHISHING_DESIGN.md
    Section 2.3)."""
    result = await db.execute(
        select(Engagement).where(
            Engagement.tenant_id == user.tenant_id,
            Engagement.domain_id == domain.id,
            Engagement.tier == "impersonation",
            Engagement.status == "active",
        )
    )
    engagement = result.scalar_one_or_none()
    if engagement:
        return engagement

    if not test_recipient_email:
        raise HTTPException(status_code=400, detail="test_recipient_email is required to start impersonation testing for this domain")

    engagement = Engagement(
        id=_uuid.uuid4(),
        tenant_id=user.tenant_id,
        domain_id=domain.id,
        tier="impersonation",
        scope={"test_recipient_email": test_recipient_email},
        status="active",
        approved_by_user_id=user.id,
        approved_at=datetime.now(timezone.utc),
    )
    db.add(engagement)
    await db.commit()
    await db.refresh(engagement)
    return engagement


@router.post("/{domain_id}/impersonation-scan", response_model=list[FindingOut])
@limiter.limit("3/minute")
async def run_domain_impersonation_scan(
    request: Request,
    domain_id: str,
    payload: ImpersonationScanRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    domain = await _get_domain(domain_id, db, user)
    if not domain.ownership_verified:
        raise HTTPException(status_code=400, detail="Domain ownership must be verified before running an impersonation scan")

    engagement = await _get_or_create_impersonation_engagement(db, user, domain, payload.test_recipient_email)
    findings = await run_impersonation_scan(db, engagement, domain)
    return [
        FindingOut(
            id=str(f.id), engagement_id=str(f.engagement_id), asset_id=None,
            tier=f.tier, severity=f.severity, title=f.title, status=f.status,
            check_id=f.check_id, resource_uid=f.resource_uid, detail=f.detail, remediation_guidance=f.remediation_guidance,
            discovered_at=f.discovered_at.isoformat(),
        )
        for f in findings
    ]
