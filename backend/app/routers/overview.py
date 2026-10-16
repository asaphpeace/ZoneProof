"""Tenant-wide overview: KPIs + per-domain summary for the portfolio view."""
from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select, func, case
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Domain, DmarcAggregate, TlsAggregate, SslCert, SentinelSnapshot
from app.services.tls_service import tls_window_totals
from app.models.user import User, Tenant
from app.services import brand_exposure as brand_exposure_service
from app.routers.auth import get_current_user
from app.schemas.overview import (
    TenantOverviewOut, DomainKpiOut, CertAlertOut, SentinelScoreOut,
    ThreatSurfaceOut, ThreatTargetOut, ThreatSourceOut, PortfolioCertOut,
    ReportDataOut, ReportDomainRow, ScoreTrendPoint,
    SenderRow, SenderInventoryOut, RecommendationItem, NarrativeOut,
    PortfolioReadinessRollupOut, ReadinessBlockerCategoryOut, ReadinessBlockerDomainOut,
)
from app.schemas.tls import TlsDomainSummaryOut
from app.services.posture_service import compute_posture, compute_sentinel_score, DomainSentinelInput
from app.services.cloud_scan_service import compute_tenant_cloud_posture_score
from app.services.exploitability_service import compute_tenant_verified_exploitability_score
from app.services.phishing_service import compute_tenant_human_risk_score
from app.services.advisor_service import generate_report_narrative
from app.services.recommendation_data import build_domain_input
from app.services.recommendation_engine import evaluate_domain, Direction, Recommendation
from app.services.plan_limits import require_feature


def _iso_monday(d: date) -> date:
    """Return the Monday of the ISO week containing d."""
    return d - timedelta(days=d.weekday())

router = APIRouter(prefix="/overview", tags=["overview"])


@router.get("", response_model=TenantOverviewOut)
async def get_tenant_overview(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()

    domains_result = await db.execute(
        select(Domain).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
    )
    domains = domains_result.scalars().all()

    domain_kpis: list[DomainKpiOut] = []
    cert_expiry_list: list[CertAlertOut] = []
    total_volume = 0
    total_tls = 0
    comp_vals: list[float] = []
    tls_pass_vals: list[float] = []
    cert_alerts = 0

    # DMARC distribution counters
    dmarc_none_count = 0
    dmarc_monitor_count = 0
    dmarc_quarantine_count = 0
    dmarc_reject_count = 0

    # TLS distribution counters
    tls_enforce_count = 0
    tls_testing_count = 0
    tls_none_count = 0

    for d in domains:
        # ── DMARC aggregates ───────────────────────────────────────────────────
        da_result = await db.execute(
            select(
                func.sum(DmarcAggregate.total_count),
                func.sum(DmarcAggregate.pass_count),
            ).where(DmarcAggregate.domain_id == d.id)
        )
        da_row = da_result.one()
        vol = int(da_row[0] or 0)
        d_pass = int(da_row[1] or 0)
        comp = round(d_pass / vol * 100, 1) if vol else None
        total_volume += vol

        # ── TLS aggregates ─────────────────────────────────────────────────────
        tls_total, tls_pass, _ = await tls_window_totals(db, d.id)
        tls_pct = round(tls_pass / tls_total * 100, 1) if tls_total else None
        total_tls += tls_total

        # ── Cert health ────────────────────────────────────────────────────────
        cert_result = await db.execute(
            select(SslCert).where(SslCert.domain_id == d.id)
        )
        certs = cert_result.scalars().all()
        min_days = min((c.days_remaining for c in certs if c.days_remaining is not None), default=None)

        # Determine worst cert status for this domain
        cert_status: str | None = None
        for c in certs:
            if c.status == "expired":
                cert_status = "expired"
                break
            elif c.status == "critical" and cert_status != "expired":
                cert_status = "critical"
            elif c.status == "expiring_soon" and cert_status not in ("expired", "critical"):
                cert_status = "expiring_soon"

        if cert_status in ("critical", "expired", "expiring_soon"):
            cert_alerts += 1
            cert_expiry_list.append(CertAlertOut(
                domain=d.name,
                days_remaining=min_days,
                status=cert_status,
            ))

        # ── Posture / grade ────────────────────────────────────────────────────
        posture = compute_posture(d.dmarc_stage, comp, d.mta_sts_stage, tls_pct, min_days)

        # ── Distribution counters ──────────────────────────────────────────────
        stage = d.dmarc_stage or "none"
        if stage == "reject":
            dmarc_reject_count += 1
        elif stage == "quarantine":
            dmarc_quarantine_count += 1
        elif stage in ("monitor", "none") and d.dmarc_record_published:
            dmarc_monitor_count += 1
        else:
            dmarc_none_count += 1

        mta = d.mta_sts_stage or "none"
        if mta == "enforce":
            tls_enforce_count += 1
        elif mta == "testing":
            tls_testing_count += 1
        else:
            tls_none_count += 1

        if comp is not None:
            comp_vals.append(comp)
        if tls_pct is not None:
            tls_pass_vals.append(tls_pct)

        domain_kpis.append(DomainKpiOut(
            domain=d.name,
            grade=posture["grade"],
            grade_color=posture["color"],
            posture_score=posture["score"],
            dmarc_stage=d.dmarc_stage,
            mta_sts_stage=d.mta_sts_stage,
            mta_sts_hosting_mode=d.mta_sts_hosting_mode,
            dmarc_comp=comp,
            tls_pass_pct=tls_pct,
            tls_sessions=tls_total,
            volume=vol,
            min_cert_days=min_days,
            cert_status=cert_status,
        ))

    domain_kpis.sort(key=lambda x: x.posture_score, reverse=True)
    cert_expiry_list.sort(key=lambda x: (x.days_remaining is None, x.days_remaining))

    avg_comp = round(sum(comp_vals) / len(comp_vals), 1) if comp_vals else None
    avg_tls = round(sum(tls_pass_vals) / len(tls_pass_vals), 1) if tls_pass_vals else None

    # ── ZoneProof Score ─────────────────────────────────────────────────────────
    sentinel_inputs = [
        DomainSentinelInput(
            dmarc_stage=kpi.dmarc_stage,
            tls_stage=kpi.mta_sts_stage,
            tls_pass_pct=kpi.tls_pass_pct,
            min_cert_days=kpi.min_cert_days,
            cert_status=kpi.cert_status,
            volume=kpi.volume,
        )
        for kpi in domain_kpis
    ]
    cloud_posture_score = await compute_tenant_cloud_posture_score(db, user.tenant_id)
    human_risk_score = await compute_tenant_human_risk_score(db, user.tenant_id)
    verified_exploitability_score = await compute_tenant_verified_exploitability_score(db, user.tenant_id)
    brand_exposure = await brand_exposure_service.compute(db, user.tenant_id)
    sentinel = compute_sentinel_score(
        sentinel_inputs, cloud_posture_score=cloud_posture_score, human_risk_score=human_risk_score,
        verified_exploitability_score=verified_exploitability_score,
        brand_exposure_score=float(brand_exposure["score"]) if brand_exposure else None,
    )

    # Fetch last week's snapshot for delta
    this_monday = _iso_monday(date.today())
    last_monday = this_monday - timedelta(weeks=1)

    prev_snap = await db.execute(
        select(SentinelSnapshot)
        .where(
            SentinelSnapshot.tenant_id == user.tenant_id,
            SentinelSnapshot.week == last_monday,
        )
        .limit(1)
    )
    prev = prev_snap.scalar_one_or_none()
    delta = (sentinel.score - prev.score) if prev else None

    # Upsert this week's snapshot
    curr_snap = await db.execute(
        select(SentinelSnapshot)
        .where(
            SentinelSnapshot.tenant_id == user.tenant_id,
            SentinelSnapshot.week == this_monday,
        )
        .limit(1)
    )
    existing = curr_snap.scalar_one_or_none()
    if existing:
        existing.score        = sentinel.score
        existing.pillar_dmarc = sentinel.pillar_dmarc
        existing.pillar_tls   = sentinel.pillar_tls
        existing.pillar_certs = sentinel.pillar_certs
        snap = existing
    else:
        snap = SentinelSnapshot(
            id=uuid.uuid4(),
            tenant_id=user.tenant_id,
            week=this_monday,
            score=sentinel.score,
            pillar_dmarc=sentinel.pillar_dmarc,
            pillar_tls=sentinel.pillar_tls,
            pillar_certs=sentinel.pillar_certs,
        )
        db.add(snap)
    await db.commit()

    # Generate narrative in background if not yet done this week
    if not snap.narrative_summary:
        import asyncio
        from app.database import AsyncSessionLocal

        async def _bg_narrative(snap_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
            narr_data = {
                "workspace_name": tenant.name,
                "period_days": 30,
                "score": sentinel.score,
                "grade": sentinel.grade,
                "delta": delta,
                "avg_dmarc_comp": avg_comp,
                "threat_attempts": 0,
                "threat_blocked_pct": 0.0,
                "cert_alerts": cert_alerts,
                "total_domains": len(domains),
                "dmarc_reject_count": dmarc_reject_count,
                "dmarc_none_count": dmarc_none_count,
            }
            result = await generate_report_narrative(narr_data)
            async with AsyncSessionLocal() as bg_db:
                snap_res = await bg_db.execute(
                    select(SentinelSnapshot).where(SentinelSnapshot.id == snap_id)
                )
                s = snap_res.scalar_one_or_none()
                if s:
                    s.narrative_summary = result["summary"]
                    s.narrative_threats = result["threats"]
                    s.narrative_actions = result["actions"]
                    s.narrative_is_ai   = result["is_ai"]
                    s.narrative_generated_at = datetime.now(timezone.utc)
                    await bg_db.commit()

        asyncio.create_task(_bg_narrative(snap.id, user.tenant_id))

    sentinel_out = SentinelScoreOut(
        score=sentinel.score,
        grade=sentinel.grade,
        grade_color=sentinel.grade_color,
        grade_label=sentinel.grade_label,
        pillar_dmarc=sentinel.pillar_dmarc,
        pillar_tls=sentinel.pillar_tls,
        pillar_certs=sentinel.pillar_certs,
        volume_weighted=sentinel.volume_weighted,
        delta=delta,
        pillar_cloud_posture=sentinel.pillar_cloud_posture,
        pillar_human_risk=sentinel.pillar_human_risk,
        pillar_verified_exploitability=sentinel.pillar_verified_exploitability,
        pillar_brand_exposure=sentinel.pillar_brand_exposure,
    )

    # Legacy compat fields
    reject_count = dmarc_reject_count
    unprotected_count = dmarc_none_count
    in_progress_count = dmarc_monitor_count + dmarc_quarantine_count

    narrative_out: NarrativeOut | None = None
    if snap.narrative_summary:
        narrative_out = NarrativeOut(
            summary=snap.narrative_summary,
            threats=snap.narrative_threats,
            actions=snap.narrative_actions,
            generated_at=snap.narrative_generated_at.isoformat() if snap.narrative_generated_at else None,
            is_ai=snap.narrative_is_ai,
        )

    return TenantOverviewOut(
        tenant_name=tenant.name,
        plan=tenant.plan,
        total_domains=len(domains),
        at_reject=reject_count,
        in_progress=in_progress_count,
        unprotected=unprotected_count,
        avg_dmarc_comp=avg_comp,
        dmarc_none_count=dmarc_none_count,
        dmarc_monitor_count=dmarc_monitor_count,
        dmarc_quarantine_count=dmarc_quarantine_count,
        dmarc_reject_count=dmarc_reject_count,
        tls_enforce_count=tls_enforce_count,
        tls_testing_count=tls_testing_count,
        tls_none_count=tls_none_count,
        avg_tls_pass_pct=avg_tls,
        cert_alerts=cert_alerts,
        cert_expiry_list=cert_expiry_list,
        total_volume=total_volume,
        total_tls_sessions=total_tls,
        sentinel=sentinel_out,
        domains=domain_kpis,
        narrative=narrative_out,
    )


@router.get("/readiness-rollup", response_model=PortfolioReadinessRollupOut)
async def get_readiness_rollup(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    PAIN_POINT_RESOLUTION_PLAN.md's Portfolio Readiness Rollup — every
    single-domain readiness/disposition fix in this plan, rolled up across
    the tenant's whole domain list. An MSP managing 30 client domains needs
    "12 of 30 have an unresolved issue" without opening 30 domains one at a
    time; building every new feature single-domain-only and never rolling
    it up would recreate the exact gap this plan exists to close, one
    layer up.

    Reuses each domain's already-computed readiness state
    (build_domain_input + evaluate_domain, both pure/local-DB-only) rather
    than recomputing portfolio-specific logic — one source of truth.

    mta_sts_hosting deliberately does NOT do a live HTTPS check per domain
    here — that would mean N live network calls on every dashboard load.
    It uses the cheap local-DB proxy (managed mode chosen but DNS not yet
    detected as published) instead; the real live check still lives on
    MtaStsHostingStatus.vue per-domain, where one check at a time is fine.
    """
    from app.models.sender_recommendation import SenderRecommendation

    domains_result = await db.execute(
        select(Domain).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
    )
    all_domains = domains_result.scalars().all()

    platform_setup: list[ReadinessBlockerDomainOut] = []
    undispositioned: list[ReadinessBlockerDomainOut] = []
    mta_sts_pending: list[ReadinessBlockerDomainOut] = []
    blocking_sources: list[ReadinessBlockerDomainOut] = []

    for domain in all_domains:
        domain_input = await build_domain_input(db, domain)

        if domain_input.undispositioned_subdomains:
            undispositioned.append(ReadinessBlockerDomainOut(
                domain_id=str(domain.id), domain_name=domain.name,
                detail=f"{len(domain_input.undispositioned_subdomains)} subdomain(s) need a decision",
            ))

        recs = evaluate_domain(domain_input)
        for rec in recs:
            if rec.category == "dmarc" and rec.direction == Direction.HOLD and rec.blocking_reason and "failing alignment" in rec.blocking_reason:
                blocking_sources.append(ReadinessBlockerDomainOut(
                    domain_id=str(domain.id), domain_name=domain.name, detail=rec.blocking_reason,
                ))
                break

        if domain.mta_sts_hosting_mode == "managed" and not domain.mta_sts_published:
            mta_sts_pending.append(ReadinessBlockerDomainOut(
                domain_id=str(domain.id), domain_name=domain.name,
                detail="ZoneProof-hosted chosen, CNAME not yet detected",
            ))

        declared = (await db.execute(
            select(SenderRecommendation).where(
                SenderRecommendation.domain_id == domain.id,
                SenderRecommendation.classification == "declared_platform",
                SenderRecommendation.dismissed == False,
            )
        )).scalars().all()
        if declared:
            platform_setup.append(ReadinessBlockerDomainOut(
                domain_id=str(domain.id), domain_name=domain.name,
                detail=f"{len(declared)} declared platform(s) — verify setup is complete",
            ))

    categories = [
        ReadinessBlockerCategoryOut(category="platform_setup", label="Platform setup to verify", count=len(platform_setup), domains=platform_setup),
        ReadinessBlockerCategoryOut(category="undispositioned_subdomains", label="Undispositioned subdomains", count=len(undispositioned), domains=undispositioned),
        ReadinessBlockerCategoryOut(category="mta_sts_hosting", label="MTA-STS hosting not yet verified", count=len(mta_sts_pending), domains=mta_sts_pending),
        ReadinessBlockerCategoryOut(category="blocking_sources", label="Sources blocking enforcement", count=len(blocking_sources), domains=blocking_sources),
    ]
    return PortfolioReadinessRollupOut(categories=categories)


@router.get("/threat-surface", response_model=ThreatSurfaceOut)
async def get_threat_surface(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    days: int = 30,
):
    """
    Portfolio-wide spoofing/impersonation attempt summary.
    Counts DMARC-failing messages from suspicious sources (classification: spoof | unauth)
    across all tenant domains, split by disposition (blocked vs exposed).
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    domains_result = await db.execute(
        select(Domain).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
    )
    domains = domains_result.scalars().all()
    if not domains:
        return ThreatSurfaceOut(
            period_days=days, total_attempts=0, blocked=0, blocked_pct=0.0,
            exposed=0, unique_ips=0, unique_orgs=0,
            top_targeted=[], top_sources=[], has_data=False,
        )

    domain_ids = [d.id for d in domains]
    domain_stage = {d.id: d.dmarc_stage for d in domains}
    domain_name  = {d.id: d.name for d in domains}

    base_filter = [
        DmarcAggregate.domain_id.in_(domain_ids),
        DmarcAggregate.fail_count > 0,
        DmarcAggregate.classification.in_(["spoof", "unauth"]),
    ]

    agg_result = await db.execute(
        select(DmarcAggregate).where(*base_filter, DmarcAggregate.period_begin >= cutoff)
    )
    aggs = agg_result.scalars().all()

    # Fall back to all-time if no data in the requested window (e.g. historical seed data)
    if not aggs:
        agg_result = await db.execute(select(DmarcAggregate).where(*base_filter))
        aggs = agg_result.scalars().all()

    if not aggs:
        return ThreatSurfaceOut(
            period_days=days, total_attempts=0, blocked=0, blocked_pct=0.0,
            exposed=0, unique_ips=0, unique_orgs=0,
            top_targeted=[], top_sources=[], has_data=False,
        )

    total_attempts = 0
    blocked        = 0
    exposed        = 0
    seen_ips:  set[str] = set()
    seen_orgs: set[str] = set()

    # Per-domain tallies
    domain_tally: dict = defaultdict(lambda: {"attempts": 0, "blocked": 0, "exposed": 0})
    # Per-source tallies
    source_tally: dict = defaultdict(lambda: {"attempts": 0, "rdns": None, "asn": None, "ip": ""})

    for a in aggs:
        vol = a.fail_count
        is_blocked = a.disposition in ("quarantine", "reject")

        total_attempts += vol
        if is_blocked:
            blocked += vol
        else:
            exposed += vol

        seen_ips.add(a.source_ip)
        if a.source_org:
            seen_orgs.add(a.source_org)

        dt = domain_tally[a.domain_id]
        dt["attempts"] += vol
        if is_blocked:
            dt["blocked"] += vol
        else:
            dt["exposed"] += vol

        key = (a.source_org or a.source_ip, a.source_ip)
        st = source_tally[key]
        st["attempts"] += vol
        st["rdns"]     = st["rdns"] or a.rdns
        st["asn"]      = st["asn"]  or a.asn
        st["ip"]       = a.source_ip

    blocked_pct = round(blocked / total_attempts * 100, 1) if total_attempts else 0.0

    top_targeted = sorted(
        [
            ThreatTargetOut(
                domain=domain_name[did],
                attempts=v["attempts"],
                blocked=v["blocked"],
                blocked_pct=round(v["blocked"] / v["attempts"] * 100, 1) if v["attempts"] else 0.0,
                exposed=v["exposed"],
                dmarc_stage=domain_stage.get(did, "none"),
            )
            for did, v in domain_tally.items()
        ],
        key=lambda x: x.attempts,
        reverse=True,
    )[:5]

    top_sources = sorted(
        [
            ThreatSourceOut(
                source_org=org_ip[0] or org_ip[1],
                source_ip=v["ip"],
                attempts=v["attempts"],
                rdns=v["rdns"],
                asn=v["asn"],
            )
            for org_ip, v in source_tally.items()
        ],
        key=lambda x: x.attempts,
        reverse=True,
    )[:5]

    return ThreatSurfaceOut(
        period_days=days,
        total_attempts=total_attempts,
        blocked=blocked,
        blocked_pct=blocked_pct,
        exposed=exposed,
        unique_ips=len(seen_ips),
        unique_orgs=len(seen_orgs),
        top_targeted=top_targeted,
        top_sources=top_sources,
        has_data=True,
    )


@router.get("/tls-summary", response_model=list[TlsDomainSummaryOut])
async def get_tls_domain_summary(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Per-domain TLS summary for the All Domains view in MTA-STS screen."""
    domains_result = await db.execute(
        select(Domain).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
    )
    domains = domains_result.scalars().all()

    summaries = []
    for d in domains:
        total, succ, fail = await tls_window_totals(db, d.id)
        summaries.append(TlsDomainSummaryOut(
            domain_id=str(d.id),
            domain=d.name,
            mta_sts_stage=d.mta_sts_stage or "none",
            total_sessions=total,
            pass_pct=round(succ / total * 100, 1) if total else 0.0,
            failed_sessions=fail,
        ))
    summaries.sort(key=lambda x: x.total_sessions, reverse=True)
    return summaries


@router.get("/certs", response_model=list[PortfolioCertOut])
async def get_portfolio_certs(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """All SSL/TLS certificates across every tenant domain, sorted by urgency."""
    domains_result = await db.execute(
        select(Domain).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
    )
    domains = domains_result.scalars().all()
    domain_name = {d.id: d.name for d in domains}

    certs_result = await db.execute(
        select(SslCert).where(SslCert.domain_id.in_([d.id for d in domains]))
    )
    certs = certs_result.scalars().all()

    STATUS_ORDER = {"expired": 0, "critical": 1, "expiring_soon": 2, "error": 3, "ok": 4}

    def _sort_key(c: SslCert):
        order = STATUS_ORDER.get(c.status, 5)
        days = c.days_remaining if c.days_remaining is not None else 9999
        return (order, days)

    certs_sorted = sorted(certs, key=_sort_key)

    return [
        PortfolioCertOut(
            id=str(c.id),
            domain=domain_name.get(c.domain_id, ""),
            host=c.host,
            host_type=c.host_type or "https",
            subject_cn=c.subject_cn,
            issuer=c.issuer,
            san=c.san,
            not_after=c.not_after.isoformat() if c.not_after else None,
            days_remaining=c.days_remaining,
            tls_version=c.tls_version,
            starttls_supported=c.starttls_supported,
            hostname_valid=c.hostname_valid,
            status=c.status,
            probe_error=c.probe_error,
            probed_at=c.probed_at.isoformat(),
        )
        for c in certs_sorted
    ]


@router.get("/report-data", response_model=ReportDataOut)
async def get_report_data(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    period_days: int = 30,
):
    """Assembles all data required for the full PDF report."""
    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()

    domains_result = await db.execute(
        select(Domain).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
    )
    domains = domains_result.scalars().all()
    domain_ids = [d.id for d in domains]

    # Period cutoff — all DMARC/TLS data is scoped to this window
    cutoff = datetime.now(timezone.utc) - timedelta(days=period_days)

    domain_rows: list[ReportDomainRow] = []
    cert_expiry_list: list[CertAlertOut] = []
    sentinel_inputs: list[DomainSentinelInput] = []
    cert_alerts = 0
    total_volume = 0
    total_tls = 0
    comp_vals: list[float] = []
    dkim_vals: list[float] = []
    tls_pass_vals: list[float] = []
    dmarc_reject_count = 0
    dmarc_none_count = 0
    tls_enforce_count = 0
    tls_testing_count = 0
    tls_none_count = 0

    for d in domains:
        # ── DMARC compliance (period-scoped) ───────────────────────────────────
        da = await db.execute(
            select(func.sum(DmarcAggregate.total_count), func.sum(DmarcAggregate.pass_count))
            .where(DmarcAggregate.domain_id == d.id, DmarcAggregate.period_begin >= cutoff)
        )
        da_row = da.one()
        vol = int(da_row[0] or 0)
        d_pass = int(da_row[1] or 0)
        comp = round(d_pass / vol * 100, 1) if vol else None
        total_volume += vol

        # ── DKIM pass rate (period-scoped) ─────────────────────────────────────
        dk = await db.execute(
            select(
                func.sum(DmarcAggregate.total_count),
                func.sum(case((DmarcAggregate.dkim_aligned == True, DmarcAggregate.total_count), else_=0)),
            ).where(DmarcAggregate.domain_id == d.id, DmarcAggregate.period_begin >= cutoff)
        )
        dk_row = dk.one()
        dk_total = int(dk_row[0] or 0)
        dk_pass = int(dk_row[1] or 0)
        dkim_pass_pct = round(dk_pass / dk_total * 100, 1) if dk_total else None

        # ── TLS aggregates (period-scoped) ─────────────────────────────────────
        tls_total, tls_pass, _ = await tls_window_totals(db, d.id, period_days)
        tls_pct = round(tls_pass / tls_total * 100, 1) if tls_total else None
        total_tls += tls_total

        # ── Cert health ────────────────────────────────────────────────────────
        cert_result = await db.execute(select(SslCert).where(SslCert.domain_id == d.id))
        certs = cert_result.scalars().all()
        min_days = min((c.days_remaining for c in certs if c.days_remaining is not None), default=None)
        cert_status: str | None = None
        for c in certs:
            if c.status == "expired": cert_status = "expired"; break
            elif c.status == "critical" and cert_status != "expired": cert_status = "critical"
            elif c.status == "expiring_soon" and cert_status not in ("expired", "critical"): cert_status = "expiring_soon"

        if cert_status in ("critical", "expired", "expiring_soon"):
            cert_alerts += 1
            cert_expiry_list.append(CertAlertOut(domain=d.name, days_remaining=min_days, status=cert_status))

        posture = compute_posture(d.dmarc_stage, comp, d.mta_sts_stage, tls_pct, min_days)
        stage = d.dmarc_stage or "none"
        if stage == "reject": dmarc_reject_count += 1
        elif not d.dmarc_record_published: dmarc_none_count += 1
        mta = d.mta_sts_stage or "none"
        if mta == "enforce": tls_enforce_count += 1
        elif mta == "testing": tls_testing_count += 1
        else: tls_none_count += 1

        if comp is not None: comp_vals.append(comp)
        if dkim_pass_pct is not None: dkim_vals.append(dkim_pass_pct)
        if tls_pct is not None: tls_pass_vals.append(tls_pct)

        # ── Primary issue (plain-English per domain) ───────────────────────────
        primary_issue: str | None = None
        if not d.dmarc_record_published:
            primary_issue = "No DMARC record — anyone can impersonate this domain"
        elif stage == "monitor":
            primary_issue = "DMARC monitoring only (p=none) — no enforcement in place"
        elif stage == "quarantine" and comp is not None and comp < 95:
            primary_issue = f"Only {comp}% of mail passes authentication — align senders before advancing to reject"
        elif stage == "quarantine":
            primary_issue = "DMARC at quarantine — ready to advance to p=reject for full protection"
        elif cert_status in ("expired", "critical"):
            primary_issue = f"Certificate {cert_status} — renew immediately to avoid delivery failures"
        elif (d.mta_sts_stage or "none") == "none":
            primary_issue = "No MTA-STS policy — inbound delivery not required to use TLS"

        sentinel_inputs.append(DomainSentinelInput(
            dmarc_stage=d.dmarc_stage, tls_stage=d.mta_sts_stage,
            tls_pass_pct=tls_pct, min_cert_days=min_days,
            cert_status=cert_status, volume=vol,
        ))
        domain_rows.append(ReportDomainRow(
            domain=d.name, grade=posture["grade"], grade_color=posture["color"],
            dmarc_stage=d.dmarc_stage or "none", mta_sts_stage=d.mta_sts_stage or "none",
            dmarc_comp=comp, dkim_pass_pct=dkim_pass_pct, tls_pass_pct=tls_pct, volume=vol,
            cert_status=cert_status, min_cert_days=min_days,
            primary_issue=primary_issue,
        ))

    domain_rows.sort(key=lambda x: {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4}.get(x.grade, 0))
    cloud_posture_score = await compute_tenant_cloud_posture_score(db, user.tenant_id)
    human_risk_score = await compute_tenant_human_risk_score(db, user.tenant_id)
    verified_exploitability_score = await compute_tenant_verified_exploitability_score(db, user.tenant_id)
    brand_exposure = await brand_exposure_service.compute(db, user.tenant_id)
    sentinel = compute_sentinel_score(
        sentinel_inputs, cloud_posture_score=cloud_posture_score, human_risk_score=human_risk_score,
        verified_exploitability_score=verified_exploitability_score,
        brand_exposure_score=float(brand_exposure["score"]) if brand_exposure else None,
    )

    # ── Score trend (last 8 weekly snapshots) ─────────────────────────────────
    trend_result = await db.execute(
        select(SentinelSnapshot)
        .where(SentinelSnapshot.tenant_id == user.tenant_id)
        .order_by(SentinelSnapshot.week.desc())
        .limit(8)
    )
    trend_snaps = list(reversed(trend_result.scalars().all()))
    score_trend = [ScoreTrendPoint(week=str(s.week), score=s.score) for s in trend_snaps]

    # Delta vs start of trend window (not just last week)
    trend_delta: int | None = None
    if len(score_trend) >= 2:
        trend_delta = score_trend[-1].score - score_trend[0].score

    sentinel_out = SentinelScoreOut(
        score=sentinel.score, grade=sentinel.grade,
        grade_color=sentinel.grade_color, grade_label=sentinel.grade_label,
        pillar_dmarc=sentinel.pillar_dmarc, pillar_tls=sentinel.pillar_tls,
        pillar_certs=sentinel.pillar_certs, volume_weighted=sentinel.volume_weighted,
        delta=trend_delta,
        pillar_cloud_posture=sentinel.pillar_cloud_posture,
        pillar_human_risk=sentinel.pillar_human_risk,
        pillar_verified_exploitability=sentinel.pillar_verified_exploitability,
        pillar_brand_exposure=sentinel.pillar_brand_exposure,
    )

    # ── Sender inventory (three-bucket model) ─────────────────────────────────
    all_aggs_result = await db.execute(
        select(DmarcAggregate).where(
            DmarcAggregate.domain_id.in_(domain_ids),
            DmarcAggregate.period_begin >= cutoff,
        )
    )
    all_aggs = all_aggs_result.scalars().all()

    # Fall back to all-time if no period data
    if not all_aggs and domain_ids:
        all_aggs_result = await db.execute(
            select(DmarcAggregate).where(DmarcAggregate.domain_id.in_(domain_ids))
        )
        all_aggs = all_aggs_result.scalars().all()

    sender_data: dict = defaultdict(lambda: {
        "volume": 0, "pass": 0, "dkim": 0, "spf": 0,
        "top_ip": None, "classification": "unknown",
    })
    for a in all_aggs:
        key = (a.source_org or a.source_ip, a.classification or "unknown")
        b = sender_data[key]
        b["volume"] += a.total_count
        b["pass"]   += a.pass_count
        b["dkim"]   += a.total_count if a.dkim_aligned else 0
        b["spf"]    += a.total_count if a.spf_aligned else 0
        b["top_ip"] = b["top_ip"] or a.source_ip
        b["classification"] = a.classification or "unknown"

    auth_compliant:    list[SenderRow] = []
    auth_noncompliant: list[SenderRow] = []
    unauthorized:      list[SenderRow] = []
    total_auth_vol = 0
    total_unauth_vol = 0

    for (org, cls), data in sender_data.items():
        vol2 = data["volume"]
        if vol2 == 0:
            continue
        pass_pct  = round(data["pass"] / vol2 * 100, 1)
        dkim_pct  = round(data["dkim"] / vol2 * 100, 1)
        spf_pct   = round(data["spf"]  / vol2 * 100, 1)
        row = SenderRow(
            org=org, volume=vol2, pass_pct=pass_pct,
            dkim_aligned_pct=dkim_pct, spf_aligned_pct=spf_pct,
            top_ip=data["top_ip"],
        )
        if cls in ("spoof", "unauth"):
            unauthorized.append(row)
            total_unauth_vol += vol2
        elif cls == "authorized":
            total_auth_vol += vol2
            if pass_pct >= 95:
                auth_compliant.append(row)
            else:
                auth_noncompliant.append(row)
        else:
            # forwarded / unknown — treat as authorized, flag if non-compliant
            total_auth_vol += vol2
            if pass_pct >= 95:
                auth_compliant.append(row)
            else:
                auth_noncompliant.append(row)

    for lst in (auth_compliant, auth_noncompliant, unauthorized):
        lst.sort(key=lambda r: r.volume, reverse=True)

    sender_inventory = SenderInventoryOut(
        authorized_compliant=auth_compliant[:10],
        authorized_noncompliant=auth_noncompliant[:10],
        unauthorized=unauthorized[:10],
        total_authorized_volume=total_auth_vol,
        total_unauthorized_volume=total_unauth_vol,
    )

    # ── Structured recommendations — sourced from the rule-based recommendation
    # engine (recommendation_engine.py), the same gates that drive the alert
    # bell. The report never recommends an advance the alert engine wouldn't
    # also be willing to fire — one source of truth for "what should you do
    # next," so the report can't tell a client to advance while the live
    # system is independently holding them back.
    #
    # Two zero-state cases sit outside the engine's gates entirely — there is
    # nothing to measure yet, so they're handled as unconditional bootstrap
    # steps rather than a "holds at p=none, 0% compliance" message.
    _BOOTSTRAP_PRIORITY = 0
    _DIRECTION_PRIORITY = {Direction.REGRESSION: 1, Direction.ADVANCE: 2, Direction.HOLD: 4}
    _MTA_STS_BOOTSTRAP_PRIORITY = 3
    _DIRECTION_EFFORT_IMPACT = {
        Direction.REGRESSION: ("Low", "High"),
        Direction.ADVANCE: ("Low", "High"),
        Direction.HOLD: ("Medium", "Medium"),
    }

    raw_recs: list[tuple[int, RecommendationItem]] = []

    for d in domains:
        if not d.dmarc_record_published:
            raw_recs.append((_BOOTSTRAP_PRIORITY, RecommendationItem(
                priority=0, domain=d.name,
                action="Publish a DMARC record",
                detail="Start with p=none to begin collecting authentication data without affecting mail flow. This is the essential first step.",
                effort="Low", impact="High", category="dmarc",
            )))

        if (d.mta_sts_stage or "none") == "none":
            raw_recs.append((_MTA_STS_BOOTSTRAP_PRIORITY, RecommendationItem(
                priority=0, domain=d.name,
                action="Implement MTA-STS policy",
                detail="Without MTA-STS, senders are not required to use TLS. Publish an MTA-STS DNS record and policy file to enforce encrypted delivery.",
                effort="Medium", impact="Medium", category="tls",
            )))

        domain_input = await build_domain_input(db, d)
        for rec in evaluate_domain(domain_input):
            if rec.category == "dmarc" and not d.dmarc_record_published:
                continue  # covered by the bootstrap message above
            if rec.category == "tls" and (d.mta_sts_stage or "none") == "none":
                continue  # covered by the bootstrap message above
            effort, impact = _DIRECTION_EFFORT_IMPACT[rec.direction]
            detail = rec.body if not rec.blocking_reason else f"{rec.body} Blocked by: {rec.blocking_reason}."
            raw_recs.append((_DIRECTION_PRIORITY[rec.direction], RecommendationItem(
                priority=0, domain=d.name,
                action=rec.title, detail=detail,
                effort=effort, impact=impact, category=rec.category,
            )))

    raw_recs.sort(key=lambda pair: pair[0])
    recommendations: list[RecommendationItem] = []
    for i, (_, item) in enumerate(raw_recs[:10], start=1):
        item.priority = i
        recommendations.append(item)

    # ── Threat surface ─────────────────────────────────────────────────────────
    domain_stage_map = {d.id: d.dmarc_stage for d in domains}
    domain_name_map  = {d.id: d.name for d in domains}

    threat_filter = [
        DmarcAggregate.domain_id.in_(domain_ids),
        DmarcAggregate.fail_count > 0,
        DmarcAggregate.classification.in_(["spoof", "unauth"]),
    ]
    threat_result = await db.execute(
        select(DmarcAggregate).where(*threat_filter, DmarcAggregate.period_begin >= cutoff)
    )
    t_aggs = threat_result.scalars().all()
    if not t_aggs:
        threat_result = await db.execute(select(DmarcAggregate).where(*threat_filter))
        t_aggs = threat_result.scalars().all()

    if t_aggs:
        t_attempts = sum(a.fail_count for a in t_aggs)
        t_blocked  = sum(a.fail_count for a in t_aggs if a.disposition in ("quarantine", "reject"))
        t_exposed  = t_attempts - t_blocked
        seen_ips   = {a.source_ip for a in t_aggs}
        seen_orgs  = {a.source_org for a in t_aggs if a.source_org}
        domain_tally: dict = defaultdict(lambda: {"attempts": 0, "blocked": 0, "exposed": 0})
        source_tally: dict = defaultdict(lambda: {"attempts": 0, "rdns": None, "asn": None, "ip": ""})
        for a in t_aggs:
            fv = a.fail_count
            is_b = a.disposition in ("quarantine", "reject")
            domain_tally[a.domain_id]["attempts"] += fv
            domain_tally[a.domain_id]["blocked" if is_b else "exposed"] += fv
            k = (a.source_org or a.source_ip, a.source_ip)
            source_tally[k]["attempts"] += fv
            source_tally[k]["rdns"] = source_tally[k]["rdns"] or a.rdns
            source_tally[k]["asn"]  = source_tally[k]["asn"]  or a.asn
            source_tally[k]["ip"]   = a.source_ip
        top_targeted = sorted([
            ThreatTargetOut(
                domain=domain_name_map[did], attempts=v["attempts"],
                blocked=v["blocked"],
                blocked_pct=round(v["blocked"] / v["attempts"] * 100, 1) if v["attempts"] else 0.0,
                exposed=v["exposed"], dmarc_stage=domain_stage_map.get(did, "none"),
            )
            for did, v in domain_tally.items()
        ], key=lambda x: x.attempts, reverse=True)[:5]
        top_sources = sorted([
            ThreatSourceOut(
                source_org=k[0] or k[1], source_ip=v["ip"],
                attempts=v["attempts"], rdns=v["rdns"], asn=v["asn"],
            )
            for k, v in source_tally.items()
        ], key=lambda x: x.attempts, reverse=True)[:5]
        threat_out = ThreatSurfaceOut(
            period_days=period_days, total_attempts=t_attempts,
            blocked=t_blocked, blocked_pct=round(t_blocked / t_attempts * 100, 1) if t_attempts else 0.0,
            exposed=t_exposed, unique_ips=len(seen_ips), unique_orgs=len(seen_orgs),
            top_targeted=top_targeted, top_sources=top_sources, has_data=True,
        )
    else:
        threat_out = ThreatSurfaceOut(
            period_days=period_days, total_attempts=0, blocked=0, blocked_pct=0.0,
            exposed=0, unique_ips=0, unique_orgs=0, top_targeted=[], top_sources=[], has_data=False,
        )

    # ── Headline verdict ───────────────────────────────────────────────────────
    f_doms = [dr for dr in domain_rows if dr.grade == "F"]
    if threat_out.exposed > 0:
        n = len([t for t in top_targeted if t.exposed > 0])
        headline_verdict = (
            f"{threat_out.exposed:,} spoofed messages reached inboxes this period — "
            f"{n} domain{'s' if n != 1 else ''} lack DMARC enforcement."
        )
    elif f_doms:
        headline_verdict = (
            f"{len(f_doms)} domain{'s' if len(f_doms) != 1 else ''} "
            f"{'are' if len(f_doms) != 1 else 'is'} fully exposed to impersonation — "
            f"immediate action required."
        )
    elif sentinel.score >= 90:
        headline_verdict = (
            f"Email security fully enforced across all {len(domains)} domain{'s' if len(domains) != 1 else ''} "
            f"— no critical issues detected."
        )
    elif cert_alerts > 0:
        headline_verdict = (
            f"Strong posture overall with {cert_alerts} certificate alert{'s' if cert_alerts != 1 else ''} "
            f"requiring attention."
        )
    else:
        not_reject = sum(1 for dr in domain_rows if dr.dmarc_stage != "reject")
        headline_verdict = (
            f"Solid email security posture — {not_reject} domain{'s' if not_reject != 1 else ''} "
            f"not yet at full DMARC enforcement."
        )

    # ── Executive narrative (3 sentences) ─────────────────────────────────────
    grade_labels = {
        "A": "fully protected", "B": "a strong security posture",
        "C": "partial coverage with notable gaps", "D": "significant gaps that leave domains exposed",
        "F": "critical gaps requiring immediate attention",
    }
    s1 = (
        f"Your email infrastructure scores {sentinel.score}/100 (Grade {sentinel.grade}), "
        f"indicating {grade_labels.get(sentinel.grade, sentinel.grade_label)}."
    )

    if len(score_trend) >= 2:
        delta = score_trend[-1].score - score_trend[0].score
        if delta > 3:
            s2 = f"The portfolio score improved by {delta} points over the reporting period, reflecting active remediation progress."
        elif delta < -3:
            s2 = f"The portfolio score declined by {abs(delta)} points over the reporting period — review recent changes to sending infrastructure."
        else:
            s2 = "The portfolio score remained stable, with no significant shift in overall security posture during the period."
    else:
        reject_n = sum(1 for dr in domain_rows if dr.dmarc_stage == "reject")
        s2 = (
            f"{reject_n} of {len(domain_rows)} domain{'s' if len(domain_rows) != 1 else ''} "
            f"ha{'ve' if reject_n != 1 else 's'} DMARC at full enforcement (p=reject), "
            f"blocking unauthenticated senders outright."
        )

    no_dmarc_doms = [dr for dr in domain_rows if not dr.dmarc_stage or dr.dmarc_stage == "none"]
    if threat_out.exposed > 0:
        s3 = (
            f"Critically, {threat_out.exposed:,} spoofed messages reached recipient inboxes this period — "
            f"tighten DMARC policy on affected domains immediately."
        )
    elif no_dmarc_doms:
        names = ", ".join(dr.domain for dr in no_dmarc_doms[:3])
        more = f" and {len(no_dmarc_doms) - 3} more" if len(no_dmarc_doms) > 3 else ""
        s3 = (
            f"{names}{more} {'have' if len(no_dmarc_doms) != 1 else 'has'} no DMARC record, "
            f"leaving {'them' if len(no_dmarc_doms) != 1 else 'it'} fully open to impersonation."
        )
    else:
        s3 = (
            "The most impactful next step is advancing remaining domains from monitoring "
            "through quarantine to full rejection."
        )

    executive_narrative = f"{s1} {s2} {s3}"

    avg_dmarc  = round(sum(comp_vals) / len(comp_vals), 1) if comp_vals else None
    avg_dkim   = round(sum(dkim_vals) / len(dkim_vals), 1) if dkim_vals else None
    avg_tls    = round(sum(tls_pass_vals) / len(tls_pass_vals), 1) if tls_pass_vals else None

    # Load the most recent snapshot narrative for this tenant
    snap_result = await db.execute(
        select(SentinelSnapshot)
        .where(SentinelSnapshot.tenant_id == user.tenant_id)
        .order_by(SentinelSnapshot.week.desc())
        .limit(1)
    )
    latest_snap = snap_result.scalar_one_or_none()
    report_narrative: NarrativeOut | None = None
    if latest_snap and latest_snap.narrative_summary:
        report_narrative = NarrativeOut(
            summary=latest_snap.narrative_summary,
            threats=latest_snap.narrative_threats,
            actions=latest_snap.narrative_actions,
            generated_at=latest_snap.narrative_generated_at.isoformat() if latest_snap.narrative_generated_at else None,
            is_ai=latest_snap.narrative_is_ai,
        )
    elif not report_narrative:
        # Generate on-demand for the report if no snapshot narrative exists yet
        narr_data = {
            "workspace_name": tenant.name,
            "period_days": period_days,
            "score": sentinel.score,
            "grade": sentinel.grade,
            "delta": trend_delta,
            "avg_dmarc_comp": avg_dmarc,
            "threat_attempts": threat_out.total_attempts,
            "threat_blocked_pct": threat_out.blocked_pct,
            "cert_alerts": cert_alerts,
            "total_domains": len(domains),
            "dmarc_reject_count": dmarc_reject_count,
            "dmarc_none_count": dmarc_none_count,
        }
        narr = await generate_report_narrative(narr_data)
        report_narrative = NarrativeOut(
            summary=narr["summary"],
            threats=narr["threats"],
            actions=narr["actions"],
            generated_at=datetime.now(timezone.utc).isoformat(),
            is_ai=narr["is_ai"],
        )

    return ReportDataOut(
        brand_guard=brand_exposure,
        generated_at=datetime.now(timezone.utc).isoformat(),
        workspace_name=tenant.name,
        period_days=period_days,
        sentinel=sentinel_out,
        headline_verdict=headline_verdict,
        executive_narrative=executive_narrative,
        narrative=report_narrative,
        score_trend=score_trend,
        sender_inventory=sender_inventory,
        recommendations=recommendations,
        total_domains=len(domains),
        total_volume=total_volume,
        total_tls_sessions=total_tls,
        dmarc_reject_count=dmarc_reject_count,
        dmarc_none_count=dmarc_none_count,
        tls_enforce_count=tls_enforce_count,
        tls_testing_count=tls_testing_count,
        tls_none_count=tls_none_count,
        avg_dmarc_comp=avg_dmarc,
        avg_dkim_pass_pct=avg_dkim,
        avg_tls_pass_pct=avg_tls,
        cert_alerts=cert_alerts,
        threat=threat_out,
        domains=domain_rows,
        cert_expiry_list=cert_expiry_list,
    )


@router.get("/report-pdf")
async def get_report_pdf(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    period_days: int = 30,
):
    """
    Same data as /report-data, rendered to an actual PDF (headless Chromium
    via Playwright — see pdf_report_service.py) instead of returned as JSON.
    This is also what the scheduled-report background job emails as an
    attachment, so the manual download and the automated email are always
    byte-for-byte the same report layout.
    """
    from fastapi import Response
    from app.services.pdf_report_service import render_report_pdf

    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()
    require_feature(tenant, "pdf_report")

    report = await get_report_data(db=db, user=user, period_days=period_days)
    pdf_bytes = await render_report_pdf(report, brand_name=tenant.brand_name)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="sentinel-report-{report.generated_at[:10]}.pdf"'},
    )


@router.post("/narrative/regenerate", response_model=NarrativeOut)
async def regenerate_narrative(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Force-regenerate the AI narrative for the current week's snapshot."""
    from datetime import date, timedelta

    this_monday = date.today() - timedelta(days=date.today().weekday())

    snap_res = await db.execute(
        select(SentinelSnapshot)
        .where(SentinelSnapshot.tenant_id == user.tenant_id, SentinelSnapshot.week == this_monday)
        .limit(1)
    )
    snap = snap_res.scalar_one_or_none()
    if not snap:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="No snapshot for this week yet — visit the Overview first.")

    tenant_res = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_res.scalar_one()

    domains_result = await db.execute(
        select(Domain).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
    )
    domains = domains_result.scalars().all()

    dmarc_reject_count = sum(1 for d in domains if d.dmarc_stage == "reject")
    dmarc_none_count = sum(1 for d in domains if not d.dmarc_record_published)

    cert_alerts = 0
    for d in domains:
        certs = (await db.execute(select(SslCert).where(SslCert.domain_id == d.id))).scalars().all()
        if any(c.status in ("critical", "expired", "expiring_soon") for c in certs):
            cert_alerts += 1

    da = await db.execute(
        select(func.sum(DmarcAggregate.total_count), func.sum(DmarcAggregate.pass_count))
        .where(DmarcAggregate.domain_id.in_([d.id for d in domains]))
    )
    da_row = da.one()
    avg_comp = round(da_row[1] / da_row[0] * 100, 1) if da_row[0] else None

    narr_data = {
        "workspace_name": tenant.name,
        "period_days": 30,
        "score": snap.score,
        "grade": _score_to_grade(snap.score),
        "delta": None,
        "avg_dmarc_comp": avg_comp,
        "threat_attempts": 0,
        "threat_blocked_pct": 0.0,
        "cert_alerts": cert_alerts,
        "total_domains": len(domains),
        "dmarc_reject_count": dmarc_reject_count,
        "dmarc_none_count": dmarc_none_count,
    }
    result = await generate_report_narrative(narr_data)

    snap.narrative_summary = result["summary"]
    snap.narrative_threats = result["threats"]
    snap.narrative_actions = result["actions"]
    snap.narrative_is_ai = result["is_ai"]
    snap.narrative_generated_at = datetime.now(timezone.utc)
    await db.commit()

    return NarrativeOut(
        summary=result["summary"],
        threats=result["threats"],
        actions=result["actions"],
        generated_at=snap.narrative_generated_at.isoformat(),
        is_ai=result["is_ai"],
    )


def _score_to_grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"
