from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Domain, DmarcAggregate, TlsAggregate, SslCert
from app.services.tls_service import tls_window_totals
from app.models.dns_record import DnsRecord
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.advisor import AdvisorOut
from app.services.advisor_service import (
    AdvisorContext,
    get_advisor_message,
    chat_with_context,
    generate_cert_summary,
    generate_dns_summary,
    compute_domain_journey_phase,
    compute_portfolio_journey_phase,
    _advisor_cache,
    _cache_key,
    compute_fingerprint,
    is_unchanged,
    remember_fingerprint,
)

router = APIRouter(prefix="/advisor", tags=["advisor"])


class ChatMessage(BaseModel):
    role: str   # user | assistant
    content: str

class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = []
    screen: str = "overview"
    domain_id: str | None = None


@router.get("", response_model=AdvisorOut)
async def get_advisor(
    screen: str = Query(..., description="overview|posture|dmarc|tls|roadmap|certs"),
    domain_id: str | None = Query(None),
    cached_only: bool = Query(False),
    force: bool = Query(False, description="Bypass the unchanged-data guard — used by the explicit Regenerate button"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    domain = None
    dmarc_stage = None
    dmarc_comp = None
    tls_stage = None
    tls_pass_pct = None
    fail_sources: list[str] = []
    cert_days = None

    if domain_id:
        result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id))
        domain = result.scalar_one_or_none()

    if domain:
        dmarc_stage = domain.dmarc_stage
        tls_stage = domain.mta_sts_stage

        # Compliance
        da = await db.execute(
            select(func.sum(DmarcAggregate.total_count), func.sum(DmarcAggregate.pass_count))
            .where(DmarcAggregate.domain_id == domain.id)
        )
        da_row = da.one()
        if da_row[0]:
            dmarc_comp = round(da_row[1] / da_row[0] * 100, 1)

        # Failing sources
        fa = await db.execute(
            select(DmarcAggregate.source_org)
            .where(DmarcAggregate.domain_id == domain.id, DmarcAggregate.fail_count > 0)
            .where(DmarcAggregate.classification != "spoof")
        )
        fail_sources = list({row[0] for row in fa.all()})

        # TLS
        tls_total, tls_ok, _ = await tls_window_totals(db, domain.id)
        if tls_total:
            tls_pass_pct = round(tls_ok / tls_total * 100, 1)

        # Certs
        certs = (await db.execute(select(SslCert).where(SslCert.domain_id == domain.id))).scalars().all()
        days_list = [c.days_remaining for c in certs if c.days_remaining is not None]
        cert_days = min(days_list) if days_list else None

    # Portfolio counts
    domains_result = await db.execute(
        select(Domain).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
    )
    all_domains = domains_result.scalars().all()
    reject_count      = sum(1 for d in all_domains if d.dmarc_stage == "reject")
    quarantine_count  = sum(1 for d in all_domains if d.dmarc_stage == "quarantine")
    monitor_count     = sum(1 for d in all_domains if d.dmarc_stage in ("none", "monitor") and d.dmarc_record_published)
    unprotected_count = sum(1 for d in all_domains if not d.dmarc_record_published)
    enforce_count     = sum(1 for d in all_domains if d.mta_sts_stage == "enforce")
    testing_count     = sum(1 for d in all_domains if d.mta_sts_stage == "testing")
    no_mta_sts_count  = sum(1 for d in all_domains if not d.mta_sts_stage or d.mta_sts_stage == "none")

    # Compute journey phase
    dmarc_record_published = domain.dmarc_record_published if domain else False
    if domain:
        journey_phase = compute_domain_journey_phase(dmarc_stage, tls_stage, dmarc_record_published)
    else:
        journey_phase = compute_portfolio_journey_phase(
            unprotected_count, reject_count, len(all_domains), enforce_count
        )

    # Threat surface — last 30 days, portfolio-level (only computed for overview/posture screens)
    threat_attempts = 0
    threat_blocked = 0
    threat_unblocked = 0
    threat_blocked_pct = 0.0
    most_targeted_domain: str | None = None
    most_targeted_attempts = 0

    if not domain and all_domains:
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        domain_ids = [d.id for d in all_domains]
        reject_ids = {d.id for d in all_domains if d.dmarc_stage == "reject"}

        # Total fail counts per domain in last 30 days
        threat_q = await db.execute(
            select(DmarcAggregate.domain_id, func.sum(DmarcAggregate.fail_count))
            .where(
                DmarcAggregate.domain_id.in_(domain_ids),
                DmarcAggregate.fail_count > 0,
                DmarcAggregate.period_begin >= cutoff,
            )
            .group_by(DmarcAggregate.domain_id)
        )
        threat_rows = threat_q.all()

        domain_name_map = {d.id: d.name for d in all_domains}
        per_domain_fails: dict = {}
        for row in threat_rows:
            did, total_fails = row[0], int(row[1] or 0)
            per_domain_fails[did] = total_fails
            threat_attempts += total_fails
            if did in reject_ids:
                threat_blocked += total_fails
            else:
                threat_unblocked += total_fails

        if threat_attempts > 0:
            threat_blocked_pct = round(threat_blocked / threat_attempts * 100, 1)

        if per_domain_fails:
            top_id = max(per_domain_fails, key=lambda d: per_domain_fails[d])
            most_targeted_domain = domain_name_map.get(top_id)
            most_targeted_attempts = per_domain_fails[top_id]

    ctx = AdvisorContext(
        screen=screen,
        domain_name=domain.name if domain else None,
        dmarc_stage=dmarc_stage,
        dmarc_comp=dmarc_comp,
        tls_stage=tls_stage,
        tls_pass_pct=tls_pass_pct,
        fail_sources=fail_sources,
        cert_days=cert_days,
        all_domains_count=len(all_domains),
        reject_count=reject_count,
        quarantine_count=quarantine_count,
        monitor_count=monitor_count,
        unprotected_count=unprotected_count,
        enforce_count=enforce_count,
        testing_count=testing_count,
        no_mta_sts_count=no_mta_sts_count,
        dmarc_record_published=dmarc_record_published,
        journey_phase=journey_phase,
        threat_attempts=threat_attempts,
        threat_blocked=threat_blocked,
        threat_unblocked=threat_unblocked,
        threat_blocked_pct=threat_blocked_pct,
        most_targeted_domain=most_targeted_domain,
        most_targeted_attempts=most_targeted_attempts,
    )

    result = await get_advisor_message(ctx, tenant_id=str(user.tenant_id), cached_only=cached_only, force=force)
    return AdvisorOut(**result)


async def _build_security_context(
    db: AsyncSession,
    user: User,
    screen: str,
    domain_id: str | None,
) -> dict:
    """Gather live security data to ground the chat response."""
    from app.models.user import Tenant

    tenant_res = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_res.scalar_one()

    domains_result = await db.execute(
        select(Domain).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
    )
    all_domains = domains_result.scalars().all()

    reject_count = sum(1 for d in all_domains if d.dmarc_stage == "reject")
    none_count = sum(1 for d in all_domains if not d.dmarc_record_published)
    monitor_count = sum(1 for d in all_domains if d.dmarc_stage in ("monitor", "none") and d.dmarc_record_published)
    quarantine_count = sum(1 for d in all_domains if d.dmarc_stage == "quarantine")
    tls_enforce = sum(1 for d in all_domains if d.mta_sts_stage == "enforce")
    tls_testing = sum(1 for d in all_domains if d.mta_sts_stage == "testing")

    # Portfolio DMARC compliance
    da = await db.execute(
        select(func.sum(DmarcAggregate.total_count), func.sum(DmarcAggregate.pass_count))
        .where(DmarcAggregate.domain_id.in_([d.id for d in all_domains]))
    )
    da_row = da.one()
    avg_comp = round(da_row[1] / da_row[0] * 100, 1) if da_row[0] else None

    # Cert alerts
    cert_alerts = 0
    for d in all_domains:
        certs = (await db.execute(select(SslCert).where(SslCert.domain_id == d.id))).scalars().all()
        if any(c.status in ("critical", "expired", "expiring_soon") for c in certs):
            cert_alerts += 1

    # Failing sources (portfolio-wide)
    fail_res = await db.execute(
        select(DmarcAggregate.source_org)
        .where(DmarcAggregate.domain_id.in_([d.id for d in all_domains]), DmarcAggregate.fail_count > 0)
        .limit(5)
    )
    fail_sources = list({row[0] for row in fail_res.all()})

    ctx: dict = {
        "workspace_name": tenant.name,
        "screen": screen,
        "total_domains": len(all_domains),
        "dmarc_reject_count": reject_count,
        "dmarc_none_count": none_count,
        "dmarc_monitor_count": monitor_count,
        "dmarc_quarantine_count": quarantine_count,
        "avg_dmarc_comp": avg_comp,
        "tls_enforce_count": tls_enforce,
        "tls_testing_count": tls_testing,
        "cert_alerts": cert_alerts,
        "fail_sources": fail_sources,
    }

    # Domain-specific context
    if domain_id:
        res = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id))
        domain = res.scalar_one_or_none()
        if domain:
            da2 = await db.execute(
                select(func.sum(DmarcAggregate.total_count), func.sum(DmarcAggregate.pass_count))
                .where(DmarcAggregate.domain_id == domain.id)
            )
            dr = da2.one()
            d_comp = round(dr[1] / dr[0] * 100, 1) if dr[0] else None
            fa2 = await db.execute(
                select(DmarcAggregate.source_org)
                .where(DmarcAggregate.domain_id == domain.id, DmarcAggregate.fail_count > 0)
            )
            d_fails = list({row[0] for row in fa2.all()})
            ctx.update({
                "domain_name": domain.name,
                "dmarc_stage": domain.dmarc_stage,
                "tls_stage": domain.mta_sts_stage,
                "dmarc_comp": d_comp,
                "fail_sources": d_fails,
            })

    return ctx


@router.post("/chat")
async def chat(
    body: ChatRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    from app.services.advisor_service import get_chat_memory, save_chat_turn

    ctx = await _build_security_context(db, user, body.screen, body.domain_id)

    # If the caller didn't send history (e.g. AskFollowUp.vue remounted on
    # a different page), fall back to what the server remembers for this
    # user+screen+domain — server-side memory the frontend doesn't need to
    # manage itself. An explicit history from the caller is trusted as-is.
    history = [{"role": m.role, "content": m.content} for m in body.history]
    if not history:
        history = get_chat_memory(str(user.id), body.screen, body.domain_id)

    result = await chat_with_context(
        user_message=body.message,
        history=history,
        context=ctx,
    )
    save_chat_turn(str(user.id), body.screen, body.domain_id, body.message, result["reply"])
    return {
        "reply": result["reply"],
        "model": result.get("model", ""),
        "citations": result.get("citations", []),
    }


@router.get("/cert-summary")
async def get_cert_summary(
    domain_id: str | None = Query(None),
    cached_only: bool = Query(False),
    force: bool = Query(False, description="Bypass the unchanged-data guard — used by the explicit Regenerate button"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Generate an AI cert posture summary.
    Without domain_id: portfolio-wide.
    With domain_id: domain-specific.
    """
    domains_result = await db.execute(
        select(Domain).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
    )
    all_domains = {str(d.id): d.name for d in domains_result.scalars().all()}

    if domain_id:
        if domain_id not in all_domains:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Domain not found")
        cert_result = await db.execute(
            select(SslCert).where(SslCert.domain_id == domain_id)
        )
        certs_raw = cert_result.scalars().all()
        domain_name = all_domains[domain_id]
    else:
        cert_result = await db.execute(
            select(SslCert).where(SslCert.domain_id.in_(list(all_domains.keys())))
        )
        certs_raw = cert_result.scalars().all()
        domain_name = None

    certs = [
        {
            "host": c.host,
            "domain": all_domains.get(str(c.domain_id), ""),
            "status": c.status,
            "days_remaining": c.days_remaining,
            "host_type": c.host_type,
            "tls_version": c.tls_version,
            "starttls_supported": c.starttls_supported,
            "hostname_valid": c.hostname_valid,
        }
        for c in certs_raw
    ]

    cert_cache_key = _cache_key(str(user.tenant_id), "certs", domain_id or None)
    if cached_only:
        cached = _advisor_cache.get(cert_cache_key)
        if cached:
            return cached

    # Skip the LLM call if the cert set looks identical to last time —
    # nothing changed, so the cached narration is still accurate.
    # force=True (explicit Regenerate click) always bypasses this.
    fingerprint = compute_fingerprint({"certs": certs, "domain_name": domain_name})
    if not force and is_unchanged(cert_cache_key, fingerprint):
        cached = _advisor_cache.get(cert_cache_key)
        if cached:
            return cached

    result = await generate_cert_summary(certs, domain_name)
    _advisor_cache[cert_cache_key] = result
    remember_fingerprint(cert_cache_key, fingerprint)
    return result


@router.get("/dns-summary")
async def get_dns_summary(
    domain_id: str | None = Query(None),
    cached_only: bool = Query(False),
    force: bool = Query(False, description="Bypass the unchanged-data guard — used by the explicit Regenerate button"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    domains_result = await db.execute(
        select(Domain).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
    )
    all_domains = {str(d.id): d.name for d in domains_result.scalars().all()}

    domain_name: str | None = None
    if domain_id:
        if domain_id not in all_domains:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Domain not found")
        domain_name = all_domains[domain_id]
        records_q = select(DnsRecord).where(DnsRecord.domain_id == domain_id)
    else:
        records_q = select(DnsRecord).where(DnsRecord.domain_id.in_(list(all_domains.keys())))

    records_result = await db.execute(records_q.order_by(DnsRecord.detected_at.desc()).limit(200))
    records = records_result.scalars().all()

    cache_key = _cache_key(str(user.tenant_id), "dns_timeline", domain_id or None)
    if cached_only:
        cached = _advisor_cache.get(cache_key)
        if cached:
            return cached

    # Build summary counts
    total = len(records)
    alerts = [r for r in records if r.risk_severity == "critical"]
    warnings = [r for r in records if r.risk_severity == "warn"]
    added = [r for r in records if r.previous_value is None and r.current_value]
    removed = [r for r in records if r.previous_value and r.current_value is None]
    modified = [r for r in records if r.previous_value and r.current_value]
    recent_alerts = [
        {"type": r.record_type, "host": r.record_host, "summary": r.change_summary or ""}
        for r in alerts[:3]
    ]

    # Skip the LLM call if the timeline summary is identical to last time.
    # force=True (explicit Regenerate click) always bypasses this.
    fingerprint = compute_fingerprint({
        "domain_name": domain_name, "total": total, "alert_count": len(alerts),
        "warning_count": len(warnings), "added_count": len(added),
        "removed_count": len(removed), "modified_count": len(modified),
        "recent_alerts": recent_alerts,
    })
    if not force and is_unchanged(cache_key, fingerprint):
        cached = _advisor_cache.get(cache_key)
        if cached:
            return cached

    result = await generate_dns_summary(
        domain_name=domain_name,
        total=total,
        alert_count=len(alerts),
        warning_count=len(warnings),
        added_count=len(added),
        removed_count=len(removed),
        modified_count=len(modified),
        recent_alerts=recent_alerts,
    )
    _advisor_cache[cache_key] = result
    remember_fingerprint(cache_key, fingerprint)
    return result
