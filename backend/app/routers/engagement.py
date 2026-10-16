import logging
import uuid as _uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models import CloudAccountConnection, CloudPrivEscPath, Engagement, Finding, HostConnection, OAuthGrant, Tenant
from app.models.user import User
from app.routers.auth import _require_admin_or_approver, get_current_user
from app.schemas.engagement import EngagementCreate, EngagementOut, EngagementScheduleUpdate, RequestSignaturePayload
from app.schemas.finding import CloudPrivEscPathOut, FindingOut
from app.services import audit_service, dropbox_sign_service
from app.services.finding_presentation import finding_to_out

log = logging.getLogger(__name__)

router = APIRouter(prefix="/engagements", tags=["engagements"])

_VALID_TIERS = {"cloud", "host", "exposure", "credential", "phishing", "impersonation", "oauth_risk", "reachability", "exploit"}


def _to_out(e: Engagement) -> EngagementOut:
    return EngagementOut(
        id=str(e.id), tier=e.tier, domain_id=str(e.domain_id) if e.domain_id else None,
        scope=e.scope, status=e.status,
        approved_at=e.approved_at.isoformat() if e.approved_at else None,
        expires_at=e.expires_at.isoformat() if e.expires_at else None,
        created_at=e.created_at.isoformat(),
        roe_signature_request_id=e.roe_signature_request_id, roe_doc_url=e.roe_doc_url,
    )


async def _get_engagement(engagement_id: str, db: AsyncSession, user: User) -> Engagement:
    result = await db.execute(
        select(Engagement).where(Engagement.id == engagement_id, Engagement.tenant_id == user.tenant_id)
    )
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return engagement


@router.get("", response_model=list[EngagementOut])
async def list_engagements(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Engagement).where(Engagement.tenant_id == user.tenant_id).order_by(Engagement.created_at.desc())
    )
    return [_to_out(e) for e in result.scalars().all()]


@router.post("", response_model=EngagementOut)
async def create_engagement(
    payload: EngagementCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if payload.tier not in _VALID_TIERS:
        raise HTTPException(status_code=400, detail=f"Unknown tier '{payload.tier}'")
    # Only the phishing tier touches real employees, so only it gets the
    # narrower admin-or-approver gate — every other tier (cloud/host/etc.)
    # keeps its existing any-tenant-user behavior unchanged.
    if payload.tier == "phishing":
        _require_admin_or_approver(user)

    connections: list[CloudAccountConnection] = []
    if payload.cloud_account_connection_ids:
        result = await db.execute(
            select(CloudAccountConnection).where(
                CloudAccountConnection.id.in_(payload.cloud_account_connection_ids),
                CloudAccountConnection.tenant_id == user.tenant_id,
            )
        )
        connections = list(result.scalars().all())
        found_ids = {str(c.id) for c in connections}
        missing = set(payload.cloud_account_connection_ids) - found_ids
        if missing:
            raise HTTPException(status_code=400, detail=f"Unknown cloud connection(s): {', '.join(missing)}")

    host_connections: list[HostConnection] = []
    if payload.host_connection_ids:
        result = await db.execute(
            select(HostConnection).where(
                HostConnection.id.in_(payload.host_connection_ids),
                HostConnection.tenant_id == user.tenant_id,
            )
        )
        host_connections = list(result.scalars().all())
        found_ids = {str(c.id) for c in host_connections}
        missing = set(payload.host_connection_ids) - found_ids
        if missing:
            raise HTTPException(status_code=400, detail=f"Unknown host connection(s): {', '.join(missing)}")

    # A connection already pointed at an engagement (from a prior
    # createEngagement call — e.g. a retried "Verify & Request Signature"
    # after a Dropbox Sign failure) must reuse that engagement rather than
    # be silently repointed at a new one: the old create-a-new-engagement-
    # every-time behavior orphaned the prior engagement (still nominally
    # active/draft in the DB, but with zero connections linked to it), which
    # silently broke both the manual rescan button and the recurring
    # scheduler (both join on connection.engagement_id).
    existing_engagement_ids = {
        c.engagement_id for c in [*connections, *host_connections] if c.engagement_id is not None
    }
    if len(existing_engagement_ids) > 1:
        raise HTTPException(
            status_code=400,
            detail="These connections are already linked to different engagements — reuse or revoke them individually instead of combining them into a new one.",
        )
    if existing_engagement_ids:
        engagement = await _get_engagement(str(next(iter(existing_engagement_ids))), db, user)
        return _to_out(engagement)

    engagement = Engagement(
        id=_uuid.uuid4(),
        tenant_id=user.tenant_id,
        domain_id=payload.domain_id,
        tier=payload.tier,
        scope=payload.scope,
        status="draft",
    )
    db.add(engagement)
    await db.flush()

    for connection in connections:
        connection.engagement_id = engagement.id
    for connection in host_connections:
        connection.engagement_id = engagement.id

    # Real gap, found and closed (Phishing Simulation roadmap — live E2E
    # simulation pass): every downstream engagement action (approve,
    # revoke, schedule change) was already audited; creation itself never
    # was. Not tier-restricted, matching every other engagement.* audit
    # action in this file — consistent trail regardless of which tier.
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="engagement.created",
        target_type="engagement", target_id=str(engagement.id), target_label=engagement.tier,
        after={"scope": engagement.scope},
    )
    await db.commit()
    return _to_out(engagement)


@router.post("/{engagement_id}/approve", response_model=EngagementOut)
async def approve_engagement(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Dev/test-only bypass: flips status straight to 'active' with no real
    signature. Gated behind command_allow_direct_engagement_approval, which
    must be False in any real deployment — the real gate is
    request_signature() below + the Dropbox Sign webhook confirming every
    signer actually signed. Kept only so the Tier 0 scan pipeline stays
    testable end-to-end without a real Dropbox Sign account.
    """
    if not settings.command_allow_direct_engagement_approval:
        raise HTTPException(
            status_code=403,
            detail="Direct approval is disabled — request a real signature via /request-signature",
        )
    engagement = await _get_engagement(engagement_id, db, user)
    engagement.status = "active"
    engagement.approved_by_user_id = user.id
    engagement.approved_at = datetime.now(timezone.utc)
    # Explicitly flagged as the dev-bypass path (not the real signature
    # flow) in the audit trail itself — this endpoint authorizes real
    # scanning/testing against live infrastructure with no signature, so
    # it must never be quietly indistinguishable from a real approval.
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="engagement.approved_dev_bypass",
        target_type="engagement", target_id=str(engagement.id), target_label=engagement.tier,
    )
    await db.commit()
    return _to_out(engagement)


@router.post("/{engagement_id}/request-signature", response_model=EngagementOut)
async def request_signature(
    engagement_id: str,
    payload: RequestSignaturePayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    The real approval gate (ARCHITECTURE.md Section 9): renders an
    engagement-specific rules-of-engagement PDF and sends it to Dropbox
    Sign for hosted (email-link) signing. The Engagement only reaches
    'active' once the /webhooks/dropbox-sign endpoint below confirms every
    signer actually signed — this call only gets it to 'pending_approval'.
    """
    engagement = await _get_engagement(engagement_id, db, user)
    if engagement.tier == "phishing":
        _require_admin_or_approver(user)
    if engagement.status != "draft":
        raise HTTPException(status_code=400, detail=f"Cannot request signature for a '{engagement.status}' engagement")

    tenant = await db.get(Tenant, user.tenant_id)
    signer_name = payload.signer_name or user.full_name or user.email
    signer_email = payload.signer_email or user.email

    try:
        signature_request_id, details_url = await dropbox_sign_service.create_signature_request(
            engagement, tenant, signer_name, signer_email,
        )
    except dropbox_sign_service.DropboxSignError as e:
        log.error("Dropbox Sign request failed: engagement_id=%s error=%s", engagement.id, e)
        raise HTTPException(status_code=502, detail=f"Could not send for signature: {e}")

    engagement.status = "pending_approval"
    engagement.roe_signature_request_id = signature_request_id
    engagement.roe_doc_url = details_url
    engagement.approved_by_user_id = user.id  # who authorized/initiated — approved_at waits for the real signature
    await db.commit()
    return _to_out(engagement)


@router.post("/webhooks/dropbox-sign")
async def dropbox_sign_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    """
    Dropbox Sign posts events as multipart/form-data with a single `json`
    field, and expects the literal text "Hello API Event Received" back or
    it will retry and eventually disable the endpoint — both documented,
    non-obvious requirements of their API, not a guess.
    """
    form = await request.form()
    raw_json = form.get("json")
    if not raw_json:
        raise HTTPException(status_code=400, detail="Missing json field")

    try:
        payload = dropbox_sign_service.verify_webhook_event(raw_json)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    event = payload.get("event", {})
    event_type = event.get("event_type")
    log.info("Dropbox Sign webhook: %s", event_type)

    if event_type == "signature_request_all_signed":
        signature_request_id = payload.get("signature_request", {}).get("signature_request_id")
        if signature_request_id:
            result = await db.execute(
                select(Engagement).where(Engagement.roe_signature_request_id == signature_request_id)
            )
            engagement = result.scalar_one_or_none()
            if engagement and engagement.status == "pending_approval":
                engagement.status = "active"
                engagement.approved_at = datetime.now(timezone.utc)
                await db.commit()
            elif not engagement:
                log.warning("Dropbox Sign webhook for unknown signature_request_id=%s", signature_request_id)

    return PlainTextResponse("Hello API Event Received")


@router.post("/{engagement_id}/revoke", response_model=EngagementOut)
async def revoke_engagement(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    engagement = await _get_engagement(engagement_id, db, user)
    if engagement.tier == "phishing":
        _require_admin_or_approver(user)
    engagement.status = "revoked"
    # The Emergency Stop — a real security-relevant action (ARCHITECTURE.md
    # Section 6) that must be independently reviewable after the fact.
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="engagement.revoked",
        target_type="engagement", target_id=str(engagement.id), target_label=engagement.tier,
    )
    await db.commit()
    return _to_out(engagement)


@router.patch("/{engagement_id}/schedule", response_model=EngagementOut)
async def update_engagement_schedule(
    engagement_id: str,
    payload: EngagementScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Real post-launch control over an already-active phishing
    simulation's cadence, recurring flag, and landing page — deliberately
    NOT extended to target_list_id, template_id, or content mode, since
    those define what a signed Rules of Engagement actually authorized
    (see dropbox_sign_service._cadence_line_html, which renders cadence
    verbatim into the real signed PDF). Changing audience/content
    post-signature would mean real sends no longer match what was signed
    off on; changing the cadence has the same real compliance
    consequence, which is why every change here is audited with the real
    before/after values, not silently absorbed into engagement.scope.

    poll_due_phishing_campaigns() re-reads cadence_days/recurring from
    scope fresh on every poll — there's no separate "next due" field to
    keep in sync, so an update here takes effect on the very next
    scheduler pass with no migration step needed."""
    engagement = await _get_engagement(engagement_id, db, user)
    if engagement.tier != "phishing":
        raise HTTPException(status_code=400, detail="Schedule editing is only meaningful for phishing-tier engagements")
    _require_admin_or_approver(user)
    if engagement.status != "active":
        raise HTTPException(status_code=400, detail=f"Engagement is '{engagement.status}', not 'active' — schedule changes only apply to an authorized, already-launched simulation")

    updates = payload.model_dump(exclude_unset=True)
    if "cadence_days" in updates and updates["cadence_days"] is not None and updates["cadence_days"] < 1:
        raise HTTPException(status_code=400, detail="cadence_days must be at least 1")

    before = {k: engagement.scope.get(k) for k in updates}
    # New dict, not an in-place mutation — Engagement.scope has no
    # MutableDict wrapper, so SQLAlchemy only detects a reassignment.
    # exclude_unset above already means `updates` only has fields the
    # caller actually sent — applied as-is, including an explicit null,
    # rather than silently dropping one.
    engagement.scope = {**engagement.scope, **updates}

    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="engagement.schedule_updated",
        target_type="engagement", target_id=str(engagement.id), target_label=engagement.tier,
        before=before, after=updates,
    )
    await db.commit()
    await db.refresh(engagement)
    return _to_out(engagement)


@router.get("/{engagement_id}/findings", response_model=list[FindingOut])
async def list_findings(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    engagement = await _get_engagement(engagement_id, db, user)
    result = await db.execute(
        select(Finding).where(Finding.engagement_id == engagement.id).order_by(Finding.discovered_at.desc())
    )

    # oauth_risk findings key check_id on an OAuth app's client_id, not a
    # scope — the actual scopes live on OAuthGrant, a separate table, so a
    # single query up front avoids an N+1 lookup per finding below.
    oauth_grant_result = await db.execute(
        select(OAuthGrant.app_client_id, OAuthGrant.scopes).where(OAuthGrant.engagement_id == engagement.id)
    )
    scopes_by_app_client_id: dict[str, list[str]] = {app_client_id: scopes for app_client_id, scopes in oauth_grant_result.all()}

    return [finding_to_out(f, scopes_by_app_client_id) for f in result.scalars().all()]


@router.get("/{engagement_id}/priv-esc-paths", response_model=list[CloudPrivEscPathOut])
async def list_priv_esc_paths(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    engagement = await _get_engagement(engagement_id, db, user)
    result = await db.execute(
        select(CloudPrivEscPath)
        .where(CloudPrivEscPath.engagement_id == engagement.id)
        .order_by(CloudPrivEscPath.discovered_at.desc())
    )
    return [
        CloudPrivEscPathOut(
            id=str(p.id), engagement_id=str(p.engagement_id),
            source_principal_arn=p.source_principal_arn, target_principal_arn=p.target_principal_arn,
            technique_chain=p.technique_chain,
            escalation_type=p.escalation_type, policy_name=p.policy_name, policy_arn=p.policy_arn,
            severity=p.severity, status=p.status,
            discovered_at=p.discovered_at.isoformat(),
            closed_at=p.closed_at.isoformat() if p.closed_at else None,
        )
        for p in result.scalars().all()
    ]
