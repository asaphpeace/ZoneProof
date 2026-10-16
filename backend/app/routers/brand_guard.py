"""
Brand Guard API — protected brands, discovered candidates, and the triage
workflow. All routes are tenant-scoped; scan is rate-limited because it fans out
to DNS/RDAP/CT for hundreds of names.
"""
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import BrandNotifyChannel, BrandNotifyLog, BrandSubmission, BrandTakedown, BrandCampaign, BrandGraphEdge, BrandGraphNode, BrandCandidate, BrandCandidateEvent, BrandCandidateObservation, CandidateEvidence, BrandProfile, BrandScanRun, Domain, Tenant
from app.models.user import User
from app.rate_limit import limiter
from app.routers.auth import get_current_user
from app.schemas.brand_guard import (
    BrandGuardSummaryOut, CampaignDetailOut, CampaignOut, BrandProfileCreate, BrandProfileOut, BrandProfileUpdate, CandidateDetailOut,
    CandidateAssign, CandidateOut, CandidateStatusUpdate, ChannelCreate, ChannelUpdate, SubmissionCreate, SubmissionMove, TakedownCreate, TakedownEdit, TakedownMove, TakedownOut, EvidenceOut, LifecycleEventOut, ScanRunOut, SourceHealthOut, TimelineOut,
)
from app.services import audit_service, brand_funnel, brand_campaigns, brand_cases, brand_derivation, brand_evidence_pack, brand_blocklist, brand_defensive, brand_notify, brand_notify_dispatch, brand_takedown, brand_takedown_discovery, brand_graph, brand_fingerprint_service, brand_lifecycle as lifecycle, brand_reasoning, brand_taxonomy, brand_verdict
from app.services.brand_discovery_service import brand_warnings, to_unicode
from app.config import settings
from app.services.brand_guard_service import active_run_for, global_queue_depth, spawn_scan_run, start_scan_run, sync_campaigns, sync_graph
from app.services.brand_sources import list_health
from app.services.plan_limits import enforce_brand_guard_limit, enforce_scan_limits, get_limits

router = APIRouter(prefix="/brand-guard", tags=["brand-guard"])

_OPEN_STATUSES = ("new", "triaging", "suspicious", "monitoring")
# Registered-but-dormant lookalikes are tracked so we notice when one wakes up, but they don't belong in
# "needs review" unless something else (a suspicious/triaging verdict) says they do.
_DORMANT_STAGES = ("registered", "unregistered")
_ATTENTION_STATUSES = ("suspicious", "triaging")


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


async def _tenant(db: AsyncSession, user: User) -> Tenant:
    return (await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))).scalar_one()


async def _get_profile(db: AsyncSession, user: User, profile_id: str) -> BrandProfile:
    profile = (await db.execute(
        select(BrandProfile).where(BrandProfile.id == profile_id, BrandProfile.tenant_id == user.tenant_id)
    )).scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="Brand profile not found")
    return profile


def _run_out(r: BrandScanRun) -> ScanRunOut:
    return ScanRunOut(
        id=str(r.id), profile_id=str(r.profile_id), status=r.status, phase=r.phase,
        progress_done=r.progress_done or 0, progress_total=r.progress_total or 0, triggered_by=r.triggered_by,
        result=r.result, error=r.error, created_at=r.created_at.isoformat() if r.created_at else "",
        started_at=_iso(r.started_at), finished_at=_iso(r.finished_at),
    )


async def _profile_out(db: AsyncSession, profile: BrandProfile, tenant: Tenant) -> BrandProfileOut:
    domain = await db.get(Domain, profile.domain_id)
    latest = (await db.execute(
        select(BrandScanRun).where(BrandScanRun.profile_id == profile.id).order_by(BrandScanRun.created_at.desc()).limit(1)
    )).scalar_one_or_none()
    scans_today = (await db.execute(
        select(func.count()).select_from(BrandScanRun).where(
            BrandScanRun.tenant_id == profile.tenant_id, BrandScanRun.triggered_by == "manual",
            BrandScanRun.created_at >= datetime.now(timezone.utc) - timedelta(hours=24),
        )
    )).scalar_one()
    rows = (await db.execute(
        select(BrandCandidate.status, func.count()).where(BrandCandidate.profile_id == profile.id).group_by(BrandCandidate.status)
    )).all()
    limits = get_limits(tenant.plan)
    owned = {(domain.name if domain else "").lower(), *(d.lower() for d in profile.official_domains or [])}
    siblings = (await db.execute(
        select(Domain.name).where(Domain.tenant_id == profile.tenant_id).order_by(Domain.name)
    )).scalars().all()
    return BrandProfileOut(
        suggested_official_domains=[n for n in siblings if n.lower() not in owned],
        trademarks=profile.trademarks or [], fingerprint=({k: v for k, v in profile.fingerprint.items() if k != "similarity"} if profile.fingerprint else profile.fingerprint),     # the hashed comparison data stays server-side
        fingerprint_built_at=_iso(profile.fingerprint_built_at),
        id=str(profile.id), domain_id=str(profile.domain_id), primary_domain=domain.name if domain else "",
        brand_name=profile.brand_name, keywords=profile.keywords or [], official_domains=profile.official_domains or [],
        login_urls=profile.login_urls or [], is_active=profile.is_active,
        last_scanned_at=_iso(profile.last_scanned_at), last_ct_poll_at=_iso(profile.last_ct_poll_at),
        last_scan_error=profile.last_scan_error, candidate_counts={s: n for s, n in rows},
        ct_enabled=bool(limits["brand_guard_ct"]), max_candidates=limits["brand_guard_max_candidates"],
        latest_run=_run_out(latest) if latest else None,
        scans_today=scans_today, scan_quota=limits["brand_guard_manual_scans_per_day"],
        warnings=brand_warnings(domain.name if domain else "", profile.brand_name),
    )


async def _fill_assignees(db: AsyncSession, tenant_id, outs: list[CandidateOut]) -> None:
    """Put the owner's name next to the id the row carries (one query for the whole list)."""
    ids = {o.assignee["id"] for o in outs if o.assignee}
    if not ids:
        return
    rows = (await db.execute(select(User.id, User.email, User.full_name).where(User.tenant_id == tenant_id, User.id.in_(ids)))).all()
    names = {str(i): {"id": str(i), "email": e, "name": n or e} for i, e, n in rows}
    for o in outs:
        if o.assignee:
            o.assignee = names.get(o.assignee["id"])


def _candidate_out(c: BrandCandidate, evidence=None, campaign_name: str | None = None) -> CandidateOut:
    ev = list(evidence or [])
    reasoning = brand_reasoning.combine(ev)
    v = brand_verdict.verdict(c.identity_score, c.abuse_score, ev, reasoning)
    return CandidateOut(
        reasoning=reasoning, verdict=v,
        abuse_type=brand_taxonomy.classify_abuse_type(domain=c.candidate_domain, evidence=ev, enrichment=c.enrichment, verdict_key=v["key"], identity=c.identity_score, stage=c.stage), confidence=brand_verdict.confidence(ev), decision=brand_verdict.decision(c.status, c.reviewed_at is not None),
        why=brand_verdict.why_line(ev, v["key"]),
        campaign_id=str(c.campaign_id) if c.campaign_id else None, campaign_name=campaign_name if c.campaign_id else None,
        assignee={"id": str(c.assignee_user_id)} if c.assignee_user_id else None,
        sla=brand_cases.sla_state(c.status, c.due_at, c.resolved_at, datetime.now(timezone.utc), c.sla_hours or brand_cases.sla_hours(c.urgency)),
        id=str(c.id), profile_id=str(c.profile_id), candidate_domain=c.candidate_domain,
        candidate_domain_unicode=to_unicode(c.candidate_domain), status=c.status,
        identity_score=round(c.identity_score, 1), abuse_score=round(c.abuse_score, 1),
        impact=c.impact, urgency=c.urgency, threat_class=c.threat_class, sources=c.sources or [],
        enrichment=c.enrichment or {}, first_seen_at=c.first_seen_at.isoformat(), last_seen_at=c.last_seen_at.isoformat(),
        analyst_note=c.analyst_note, reviewed_at=_iso(c.reviewed_at),
        stage=c.stage, stage_label=lifecycle.STAGE_LABEL.get(c.stage, c.stage), stage_changed_at=_iso(c.stage_changed_at),
        last_observed_at=_iso(c.last_observed_at),
    )


@router.get("/sources", response_model=list[SourceHealthOut])
async def source_health(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Health of the shared discovery sources (e.g. the certificate feed), so a
    degraded feed is visible instead of silently producing fewer results."""
    return [
        SourceHealthOut(
            source=h["source"], label=h["label"], status=h["status"], consecutive_failures=h["consecutive_failures"],
            last_success_at=_iso(h["last_success_at"]), last_failure_at=_iso(h["last_failure_at"]),
            last_error=h["last_error"], last_latency_ms=h["last_latency_ms"], retry_after=_iso(h["retry_after"]),
        )
        for h in await list_health(db)
    ]


async def _campaign_names(db: AsyncSession, tenant_id, ids: set) -> dict:
    if not ids:
        return {}
    rows = (await db.execute(select(BrandCampaign.id, BrandCampaign.name).where(BrandCampaign.tenant_id == tenant_id, BrandCampaign.id.in_(ids)))).all()
    return {i: n for i, n in rows}


_LIVE_STAGES = ("resolving", "mail_enabled", "certified")


def _campaign_out(c: BrandCampaign, live: int) -> CampaignOut:
    return CampaignOut(
        id=str(c.id), profile_id=str(c.profile_id), name=c.name, verdict={"key": c.verdict, **brand_campaigns.VERDICT.get(c.verdict, brand_campaigns.VERDICT["not_enough"])},
        why=brand_campaigns.why_for(c.verdict, c.facts or [], c.member_count), member_count=c.member_count, live_count=live,
        first_seen_at=c.first_seen_at.isoformat(), updated_at=c.updated_at.isoformat(), facts=c.facts or [],
    )


@router.get("/campaigns", response_model=list[CampaignOut])
async def list_campaigns(profile_id: str | None = None, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Groups of look-alikes that appear to share an operator, strongest first."""
    stmt = select(BrandCampaign).where(BrandCampaign.tenant_id == user.tenant_id)
    if profile_id:
        stmt = stmt.where(BrandCampaign.profile_id == profile_id)
    camps = (await db.execute(stmt)).scalars().all()
    live = dict((await db.execute(
        select(BrandCandidate.campaign_id, func.count()).where(
            BrandCandidate.tenant_id == user.tenant_id, BrandCandidate.campaign_id.in_([c.id for c in camps] or [None]),
            BrandCandidate.stage.in_(_LIVE_STAGES)).group_by(BrandCandidate.campaign_id)
    )).all())
    order = {"likely_one_actor": 0, "possibly_related": 1, "probably_yours": 2, "not_enough": 3}
    camps.sort(key=lambda c: (order.get(c.verdict, 9), -c.member_count, c.name))
    return [_campaign_out(c, live.get(c.id, 0)) for c in camps]


async def _campaign_detail(db: AsyncSession, user: User, campaign_id: str) -> CampaignDetailOut:
    from sqlalchemy.orm import selectinload

    camp = (await db.execute(select(BrandCampaign).where(BrandCampaign.id == campaign_id, BrandCampaign.tenant_id == user.tenant_id))).scalar_one_or_none()
    if not camp:
        raise HTTPException(status_code=404, detail="Campaign not found")
    members = (await db.execute(
        select(BrandCandidate).options(selectinload(BrandCandidate.evidence))
        .where(BrandCandidate.campaign_id == camp.id, BrandCandidate.tenant_id == user.tenant_id)
        .order_by(BrandCandidate.abuse_score.desc(), BrandCandidate.candidate_domain)
    )).scalars().all()
    live = sum(1 for m in members if m.stage in _LIVE_STAGES)
    names = {m.candidate_domain for m in members}
    node_rows = {n.id: (n.kind, n.key) for n in (await db.execute(select(BrandGraphNode).where(BrandGraphNode.profile_id == camp.profile_id, BrandGraphNode.tenant_id == user.tenant_id))).scalars().all()}
    edge_tuples = [(node_rows[e.src_id], node_rows[e.dst_id], e.kind, {}) for e in (await db.execute(
        select(BrandGraphEdge).where(BrandGraphEdge.profile_id == camp.profile_id, BrandGraphEdge.tenant_id == user.tenant_id))).scalars().all()
        if e.src_id in node_rows and e.dst_id in node_rows]
    outs = [_candidate_out(m, m.evidence, camp.name) for m in members]
    await _fill_assignees(db, user.tenant_id, outs)
    return CampaignDetailOut(**_campaign_out(camp, live).model_dump(), members=outs,
                             graph=brand_graph.subgraph(edge_tuples, names))


@router.get("/campaigns/{campaign_id}", response_model=CampaignDetailOut)
async def get_campaign(campaign_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    return await _campaign_detail(db, user, campaign_id)


@router.post("/campaigns/{campaign_id}/members/{candidate_id}/remove", status_code=204)
async def remove_from_campaign(campaign_id: str, candidate_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """"This one is not part of that group." It stays out: a rescan will not put it back."""
    c = (await db.execute(
        select(BrandCandidate).where(BrandCandidate.id == candidate_id, BrandCandidate.campaign_id == campaign_id, BrandCandidate.tenant_id == user.tenant_id)
    )).scalar_one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="That candidate is not in this campaign")
    c.campaign_locked = True
    c.campaign_id = None
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="brand_guard.campaign_member_removed",
        target_type="brand_candidate", target_id=str(c.id), target_label=c.candidate_domain, before={"campaign_id": campaign_id}, after={"campaign_id": None},
    )
    profile = await db.get(BrandProfile, c.profile_id)
    if profile is not None:
        await sync_campaigns(db, profile)
    await db.commit()


@router.get("/funnel")
async def funnel(days: int = 30, profile_id: str | None = None, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Where the volume goes: how many items entered and left each stage of Brand Guard over the last `days` days (1 to 90), for the whole workspace
    or one brand, with the reasons things were dropped, plus the current spread of candidates by status. Counts only, no domain names."""
    from app.services import brand_probe_queue
    pid = None
    if profile_id:
        try:
            pid = uuid.UUID(profile_id)
        except ValueError:
            raise HTTPException(status_code=404, detail="Brand profile not found")
        await _get_profile(db, user, str(pid))              # 404 for another tenant's brand
    data = await brand_funnel.summarise(db, user.tenant_id, profile_id=pid, days=days)
    switches = {"probe": brand_probe_queue.enabled(), "render": brand_probe_queue.render_enabled()}
    for s in data["stages"]:
        s["state"] = "off" if (s["needs"] and not switches[s["needs"]]) else "on"
    data["switches"] = switches
    return data


@router.get("/summary", response_model=BrandGuardSummaryOut)
async def brand_guard_summary(profile_id: str | None = None, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Dashboard numbers for the whole workspace, or for one brand with ?profile_id=."""
    brands = (await db.execute(
        select(func.count()).select_from(BrandProfile).where(BrandProfile.tenant_id == user.tenant_id, BrandProfile.is_active == True)
    )).scalar_one()
    scope = [BrandCandidate.profile_id == profile_id] if profile_id else []
    pairs = (await db.execute(
        select(BrandCandidate.status, BrandCandidate.stage, func.count())
        .where(BrandCandidate.tenant_id == user.tenant_id, *scope).group_by(BrandCandidate.status, BrandCandidate.stage)
    )).all()
    rows: dict[str, int] = {}
    open_n = dormant_n = 0
    for st, stage, n in pairs:
        rows[st] = rows.get(st, 0) + n
        if st in _OPEN_STATUSES:
            if stage in _DORMANT_STAGES and st not in _ATTENTION_STATUSES:
                dormant_n += n
            else:
                open_n += n
    now = datetime.now(timezone.utc)
    undecided = _OPEN_STATUSES + ("confirmed", "takedown")
    new_24h = (await db.execute(
        select(func.count()).select_from(BrandCandidate).where(
            BrandCandidate.tenant_id == user.tenant_id, BrandCandidate.status.in_(_OPEN_STATUSES),
            BrandCandidate.first_seen_at >= now - timedelta(hours=24), *scope,
        )
    )).scalar_one()
    # "Went live": a look-alike we watched gain DNS resolution in the last 7 days. A name that was already resolving
    # when first seen is not counted (no event, and no way to say when it went live).
    went_live = (await db.execute(
        select(func.count(func.distinct(BrandCandidateEvent.candidate_id)))
        .join(BrandCandidate, BrandCandidate.id == BrandCandidateEvent.candidate_id)
        .where(BrandCandidateEvent.tenant_id == user.tenant_id, BrandCandidateEvent.kind == "flag_gained",
               BrandCandidateEvent.payload["flag"].astext == "resolving", BrandCandidateEvent.occurred_at >= now - timedelta(days=7),
               BrandCandidate.status.in_(undecided), *scope)
    )).scalar_one()
    hours, n = await _median_detect_hours(db, user.tenant_id, now, scope)
    return BrandGuardSummaryOut(
        brands=brands, open_candidates=open_n, dormant=dormant_n,
        suspicious=rows.get("suspicious", 0), confirmed=rows.get("confirmed", 0),
        takedown=rows.get("takedown", 0), false_positive=rows.get("false_positive", 0),
        new_24h=new_24h, went_live_7d=went_live, median_detect_hours=hours, median_detect_n=n,
    )


async def _median_detect_hours(db: AsyncSession, tenant_id, now: datetime, scope=()) -> tuple[float | None, int]:
    """Median hours from a domain's registration to the moment we first saw it, over candidates first seen in the last 90
    days whose registration date is known AND within 30 days before we saw it. A domain registered years ago and found
    only now says nothing about detection speed, so it is left out; the sample size is reported with the figure."""
    rows = (await db.execute(
        select(BrandCandidate.first_seen_at, BrandCandidate.enrichment)
        .where(BrandCandidate.tenant_id == tenant_id, BrandCandidate.first_seen_at >= now - timedelta(days=90), *scope).limit(2000)
    )).all()
    gaps: list[float] = []
    for first_seen, enrichment in rows:
        raw = (enrichment or {}).get("registered_at")
        if not raw:
            continue
        try:
            registered = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            continue
        if registered.tzinfo is None:
            registered = registered.replace(tzinfo=timezone.utc)
        hours = (first_seen - registered).total_seconds() / 3600
        if 0 <= hours <= 30 * 24:
            gaps.append(hours)
    if not gaps:
        return None, 0
    gaps.sort()
    mid = len(gaps) // 2
    return round(gaps[mid] if len(gaps) % 2 else (gaps[mid - 1] + gaps[mid]) / 2, 1), len(gaps)


@router.get("/profiles", response_model=list[BrandProfileOut])
async def list_profiles(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    tenant = await _tenant(db, user)
    profiles = (await db.execute(
        select(BrandProfile).where(BrandProfile.tenant_id == user.tenant_id).order_by(BrandProfile.created_at)
    )).scalars().all()
    return [await _profile_out(db, p, tenant) for p in profiles]


@router.post("/profiles", response_model=BrandProfileOut, status_code=201)
async def create_profile(
    payload: BrandProfileCreate, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    tenant = await _tenant(db, user)
    domain = (await db.execute(
        select(Domain).where(Domain.id == payload.domain_id, Domain.tenant_id == user.tenant_id)
    )).scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    # Same ownership gate as the impersonation scan: you can only ask us to hunt
    # for lookalikes of a domain you've proven you control.
    if not domain.ownership_verified:
        raise HTTPException(status_code=400, detail="Domain ownership must be verified before enabling Brand Guard")

    await enforce_brand_guard_limit(tenant, db)
    existing = (await db.execute(
        select(BrandProfile).where(BrandProfile.tenant_id == user.tenant_id, BrandProfile.domain_id == domain.id)
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Brand Guard is already enabled for this domain")

    profile = BrandProfile(
        tenant_id=user.tenant_id, domain_id=domain.id, brand_name=payload.brand_name.strip(),
        keywords=payload.keywords, official_domains=payload.official_domains, login_urls=payload.login_urls,
    )
    db.add(profile)
    await db.flush()  # assigns the id the audit entry refers to
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="brand_guard.profile_created",
        target_type="brand_profile", target_id=str(profile.id), target_label=profile.brand_name,
        after={"domain": domain.name, "keywords": profile.keywords, "official_domains": profile.official_domains},
    )
    await db.commit()
    await db.refresh(profile)
    return await _profile_out(db, profile, tenant)


@router.patch("/profiles/{profile_id}", response_model=BrandProfileOut)
async def update_profile(
    profile_id: str, payload: BrandProfileUpdate, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    profile = await _get_profile(db, user, profile_id)
    tenant = await _tenant(db, user)
    data = payload.model_dump(exclude_unset=True)
    if data.get("is_active") and not profile.is_active:
        await enforce_brand_guard_limit(tenant, db)
    before: dict = {}
    after: dict = {}
    for field, value in data.items():
        if value is None:
            continue
        value = value.strip() if isinstance(value, str) else value
        if getattr(profile, field) != value:
            before[field], after[field] = getattr(profile, field), value
        setattr(profile, field, value)
    if after:  # a request that changes nothing leaves no audit entry
        await audit_service.log(
            db, tenant_id=user.tenant_id, actor=user, action="brand_guard.profile_updated",
            target_type="brand_profile", target_id=str(profile.id), target_label=profile.brand_name, before=before, after=after,
        )
    await db.commit()
    await db.refresh(profile)
    return await _profile_out(db, profile, tenant)


@router.post("/profiles/{profile_id}/fingerprint", response_model=BrandProfileOut)
@limiter.limit("6/minute")
async def rebuild_fingerprint(
    request: Request, profile_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    """(Re)build the brand fingerprint from the customer's own public site and DNS. Safe to repeat; never raises for
    an unreachable site — the outcome (and what could not be learned) is recorded in the fingerprint itself."""
    profile = await _get_profile(db, user, profile_id)
    tenant = await _tenant(db, user)
    domain = await db.get(Domain, profile.domain_id)
    if domain is None:
        raise HTTPException(status_code=404, detail="Domain not found")
    fp = await brand_fingerprint_service.build_fingerprint(domain.name)
    profile.fingerprint = fp
    profile.fingerprint_built_at = datetime.now(timezone.utc)
    site = fp.get("site") or {}
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="brand_guard.fingerprint_rebuilt",
        target_type="brand_profile", target_id=str(profile.id), target_label=profile.brand_name,
        after={"site_read": bool(site), "title": site.get("title"), "nameservers": len(fp["dns"]["ns"]), "problems": len(fp["errors"])},
    )
    await db.commit()
    await db.refresh(profile)
    return await _profile_out(db, profile, tenant)


@router.delete("/profiles/{profile_id}", status_code=204)
async def delete_profile(profile_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    profile = await _get_profile(db, user, profile_id)
    counts = dict((await db.execute(
        select(BrandCandidate.status, func.count()).where(BrandCandidate.profile_id == profile.id).group_by(BrandCandidate.status)
    )).all())
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="brand_guard.profile_deleted",
        target_type="brand_profile", target_id=str(profile.id), target_label=profile.brand_name,
        before={"brand_name": profile.brand_name, "candidates_by_status": counts, "candidates_deleted": sum(counts.values())},
    )
    await db.delete(profile)
    await db.commit()


@router.post("/profiles/{profile_id}/scan", response_model=ScanRunOut, status_code=202)
@limiter.limit("3/minute")
async def run_scan(
    request: Request, profile_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    profile = await _get_profile(db, user, profile_id)
    tenant = await _tenant(db, user)
    if get_limits(tenant.plan)["brand_guard_brands"] == 0:
        raise HTTPException(status_code=403, detail={"code": "feature_not_available", "message": "Brand Guard is not available on your plan.", "upgrade_required": True})
    # An active run for this brand is simply handed back (no new cost), so it is exempt from the checks below.
    if await active_run_for(db, profile.id) is None:
        await enforce_scan_limits(tenant, db)
        if await global_queue_depth(db) >= settings.brand_guard_max_queued_scans:
            raise HTTPException(
                status_code=503, headers={"Retry-After": "60"},
                detail={"code": "scanner_busy", "message": "Brand Guard is busy scanning other brands. Try again in a minute or two.",
                        "retry_after_seconds": 60},
            )
    run, created = await start_scan_run(db, profile, triggered_by="manual")
    if created:
        await audit_service.log(
            db, tenant_id=user.tenant_id, actor=user, action="brand_guard.scan_started",
            target_type="brand_scan_run", target_id=str(run.id), target_label=profile.brand_name, after={"triggered_by": "manual"},
        )
        await db.commit()
    # Build the response from the in-memory row *before* handing the run to the
    # background task, so nothing here touches the session once the scan starts.
    out = _run_out(run)
    if created:
        spawn_scan_run(run.id)
    return out


@router.get("/scan-runs/{run_id}", response_model=ScanRunOut)
async def get_scan_run(run_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    run = (await db.execute(
        select(BrandScanRun).where(BrandScanRun.id == run_id, BrandScanRun.tenant_id == user.tenant_id)
    )).scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Scan run not found")
    return _run_out(run)


@router.get("/profiles/{profile_id}/scan-runs", response_model=list[ScanRunOut])
async def list_scan_runs(
    profile_id: str, limit: int = 10, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    await _get_profile(db, user, profile_id)
    runs = (await db.execute(
        select(BrandScanRun).where(BrandScanRun.profile_id == profile_id, BrandScanRun.tenant_id == user.tenant_id)
        .order_by(BrandScanRun.created_at.desc()).limit(min(max(limit, 1), 50))
    )).scalars().all()
    return [_run_out(r) for r in runs]


@router.get("/candidates", response_model=list[CandidateOut])
async def list_candidates(
    profile_id: str | None = None,
    status: str | None = None,
    min_abuse: float = 0,
    stage: str | None = None,
    assigned_to: str | None = None,          # "me", "none", or a user id
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    from sqlalchemy.orm import selectinload

    stmt = select(BrandCandidate).options(selectinload(BrandCandidate.evidence)).where(BrandCandidate.tenant_id == user.tenant_id)
    if profile_id:
        stmt = stmt.where(BrandCandidate.profile_id == profile_id)
    dormant = BrandCandidate.stage.in_(_DORMANT_STAGES)
    if status == "open":
        stmt = stmt.where(BrandCandidate.status.in_(_OPEN_STATUSES), or_(~dormant, BrandCandidate.status.in_(_ATTENTION_STATUSES)))
    elif status == "dormant":
        stmt = stmt.where(BrandCandidate.status.in_(_OPEN_STATUSES), and_(dormant, ~BrandCandidate.status.in_(_ATTENTION_STATUSES)))
    elif status == "cases":
        # a case is a look-alike a person took on: confirmed, in takedown, closed as removed, or reopened because it came back
        came_back = select(BrandCandidateEvent.id).where(BrandCandidateEvent.candidate_id == BrandCandidate.id, BrandCandidateEvent.kind == "resurrected").exists()
        # "monitoring" is also what a person's "Watch" is stored as, so it only counts when the candidate really came back after removal
        stmt = stmt.where(
            BrandCandidate.reviewed_by_user_id.is_not(None),
            or_(BrandCandidate.status.in_((*brand_cases.OPEN_CASE, *brand_cases.CLOSED_CASE)), and_(BrandCandidate.status == "monitoring", came_back)),
        )
    elif status:
        stmt = stmt.where(BrandCandidate.status == status)
    if min_abuse:
        stmt = stmt.where(BrandCandidate.abuse_score >= min_abuse)
    if stage:
        stmt = stmt.where(BrandCandidate.stage == stage)
    if assigned_to == "me":
        stmt = stmt.where(BrandCandidate.assignee_user_id == user.id)
    elif assigned_to == "none":
        stmt = stmt.where(BrandCandidate.assignee_user_id.is_(None))
    elif assigned_to:
        stmt = stmt.where(BrandCandidate.assignee_user_id == assigned_to)
    # Most dangerous first: abuse likelihood, then how well it passes as the brand.
    if status == "cases":
        stmt = stmt.order_by(BrandCandidate.due_at.asc().nulls_last(), BrandCandidate.abuse_score.desc()).limit(min(max(limit, 1), 500))
    else:
        stmt = stmt.order_by(BrandCandidate.abuse_score.desc(), BrandCandidate.identity_score.desc()).limit(min(max(limit, 1), 500))
    found = (await db.execute(stmt)).scalars().all()
    names = await _campaign_names(db, user.tenant_id, {c.campaign_id for c in found if c.campaign_id})
    outs = [_candidate_out(c, c.evidence, names.get(c.campaign_id)) for c in found]
    await _fill_assignees(db, user.tenant_id, outs)
    return outs


@router.get("/candidates/{candidate_id}", response_model=CandidateDetailOut)
async def get_candidate(candidate_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    from sqlalchemy.orm import selectinload

    c = (await db.execute(
        select(BrandCandidate).options(selectinload(BrandCandidate.evidence))
        .where(BrandCandidate.id == candidate_id, BrandCandidate.tenant_id == user.tenant_id)
    )).scalar_one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="Candidate not found")
    evidence = sorted(c.evidence, key=lambda e: abs(e.weight), reverse=True)
    out = _candidate_out(c, evidence, (await _campaign_names(db, user.tenant_id, {c.campaign_id})).get(c.campaign_id) if c.campaign_id else None)
    await _fill_assignees(db, user.tenant_id, [out])
    view = brand_verdict.evidence_view(evidence, c.enrichment)
    _, rule_id = brand_verdict.decide(c.identity_score, c.abuse_score, evidence, out.reasoning)
    derivation = brand_derivation.build(
        domain=c.candidate_domain, identity=c.identity_score, abuse=c.abuse_score, enrichment=c.enrichment, reasoning=out.reasoning,
        verdict_key=out.verdict["key"], rule_id=rule_id, decision=out.decision, not_found=view["not_found"],
        evidence=[{"signal": e.signal, "dimension": e.dimension, "weight": e.weight, "summary": e.summary, "data": e.data or {},
                   "observed_at": e.observed_at.isoformat() if e.observed_at else None} for e in evidence],
    )
    return CandidateDetailOut(
        **out.model_dump(),
        evidence_view=view, derivation=derivation,
        threat=brand_taxonomy.assess(domain=c.candidate_domain, evidence=evidence, enrichment=c.enrichment, verdict_key=out.verdict["key"], identity=c.identity_score, stage=c.stage),
        evidence=[
            EvidenceOut(id=str(e.id), signal=e.signal, dimension=e.dimension, weight=e.weight, summary=e.summary,
                        data=e.data or {}, observed_at=e.observed_at.isoformat())
            for e in evidence
        ],
        why_flagged=[e.summary for e in evidence if e.weight > 0],
    )


@router.get("/candidates/{candidate_id}/timeline", response_model=TimelineOut)
async def get_candidate_timeline(candidate_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """The candidate's lifecycle: the ladder with when each rung was first seen, the transition events,
    velocity features, and a summary of the observation history."""
    c = (await db.execute(
        select(BrandCandidate).where(BrandCandidate.id == candidate_id, BrandCandidate.tenant_id == user.tenant_id)
    )).scalar_one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="Candidate not found")
    events = (await db.execute(
        select(BrandCandidateEvent).where(BrandCandidateEvent.candidate_id == c.id).order_by(BrandCandidateEvent.occurred_at, BrandCandidateEvent.id)
    )).scalars().all()
    count, first_at, last_at = (await db.execute(
        select(func.count(), func.min(BrandCandidateObservation.observed_at), func.max(BrandCandidateObservation.observed_at))
        .where(BrandCandidateObservation.candidate_id == c.id)
    )).one()
    now = datetime.now(timezone.utc)
    return TimelineOut(
        stage=c.stage, stage_label=lifecycle.STAGE_LABEL.get(c.stage, c.stage),
        ladder=lifecycle.ladder(c.lifecycle), velocity=lifecycle.velocity(c.lifecycle, now),
        events=[
            LifecycleEventOut(id=str(e.id), kind=e.kind, occurred_at=e.occurred_at.isoformat(), window_start=_iso(e.window_start),
                              summary=brand_cases.describe(e.kind, e.payload or {}) or lifecycle.describe_event(e.kind, e.payload or {}), payload=e.payload or {})
            for e in events
        ],
        observations={"count": count, "first_at": _iso(first_at), "last_at": _iso(last_at)},
    )


@router.patch("/candidates/{candidate_id}/status", response_model=CandidateOut)
async def set_candidate_status(
    candidate_id: str, payload: CandidateStatusUpdate, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    from sqlalchemy.orm import selectinload

    c = (await db.execute(
        select(BrandCandidate).options(selectinload(BrandCandidate.evidence))
        .where(BrandCandidate.id == candidate_id, BrandCandidate.tenant_id == user.tenant_id)
    )).scalar_one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="Candidate not found")
    previous_status = c.status
    now = datetime.now(timezone.utc)
    c.status = payload.status
    if payload.status != previous_status:
        started = c.due_at is None
        c.due_at = brand_cases.start_clock(previous_status, payload.status, c.due_at, c.urgency, now)
        if started and c.due_at is not None:
            c.sla_hours = brand_cases.sla_hours(c.urgency)
        c.resolved_at = brand_cases.resolved_stamp(previous_status, payload.status, c.resolved_at, now)
        db.add(BrandCandidateEvent(
            id=uuid.uuid4(), candidate_id=c.id, tenant_id=c.tenant_id, kind="status_changed", occurred_at=now,
            payload={"from": previous_status, "to": payload.status, "by": user.full_name or user.email, **({"note": payload.note[:200]} if payload.note else {})},
        ))
    if payload.note is not None:
        c.analyst_note = payload.note
    # Stamping the reviewer is what stops the next automated rescan from
    # overriding a human decision (see brand_guard_service._apply_assessment).
    c.reviewed_by_user_id = user.id
    c.reviewed_at = datetime.now(timezone.utc)
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="brand_guard.candidate_status_changed",
        target_type="brand_candidate", target_id=str(c.id), target_label=c.candidate_domain,
        before={"status": previous_status},
        after={"status": c.status, **({"note": payload.note[:500]} if payload.note else {})},
    )
    profile = await db.get(BrandProfile, c.profile_id)
    if profile is not None:
        await sync_campaigns(db, profile)               # a decision can change who belongs in a campaign
        await sync_graph(db, profile)                   # ...and a confirmed look-alike makes its linked ones more suspicious, now
    await db.commit()
    c = (await db.execute(
        select(BrandCandidate).options(selectinload(BrandCandidate.evidence)).where(BrandCandidate.id == c.id).execution_options(populate_existing=True)
    )).scalar_one()
    names = await _campaign_names(db, user.tenant_id, {c.campaign_id}) if c.campaign_id else {}
    out = _candidate_out(c, c.evidence, names.get(c.campaign_id))
    await _fill_assignees(db, user.tenant_id, [out])
    return out


async def _build_pack(candidate_id: str, db: AsyncSession, user: User, *, generated_by: str | None = None, issuer: dict | None = None):
    detail = await get_candidate(candidate_id, db, user)         # tenant-scoped, 404 for anyone else's candidate
    timeline = await get_candidate_timeline(candidate_id, db, user)
    profile = await db.get(BrandProfile, uuid.UUID(detail.profile_id))
    domain = await db.get(Domain, profile.domain_id) if profile else None
    campaign = None
    if detail.campaign_id:
        cd = await _campaign_detail(db, user, detail.campaign_id)
        campaign = {"name": cd.name, "summary": cd.why, "members": [m.candidate_domain for m in cd.members]}
    pack = brand_evidence_pack.build(
        brand={"name": profile.brand_name if profile else "", "official_domains": sorted({*(profile.official_domains or []), *([domain.name] if domain else [])})},
        candidate={
            "domain": detail.candidate_domain, "domain_unicode": detail.candidate_domain_unicode, "verdict": detail.verdict.get("label"), "why": detail.why,
            "decision": detail.decision.get("label") if detail.decision.get("key") != "open" else None, "identity_score": detail.identity_score,
            "abuse_score": detail.abuse_score, "stage": detail.stage_label, "first_seen_at": detail.first_seen_at, "last_seen_at": detail.last_seen_at,
            "sources": detail.sources, "analyst_note": detail.analyst_note,
        },
        evidence=[{"signal": e.signal, "summary": e.summary, "weight": e.weight, "observed_at": e.observed_at, "data": e.data} for e in detail.evidence],
        timeline=[{"at": e.occurred_at, "summary": e.summary} for e in timeline.events],
        threat=detail.threat, campaign=campaign, generated_at=datetime.now(timezone.utc), generated_by=generated_by or user.full_name or user.email,
        issuer=issuer,
    )
    return detail, pack


@router.get("/candidates/{candidate_id}/evidence-pack")
async def evidence_pack(candidate_id: str, format: str = "json", db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """A self-contained, hash-stamped record of what was observed about one look-alike (JSON or PDF). Audit-logged: it leaves the product."""
    from fastapi import Response
    if format not in ("json", "pdf"):
        raise HTTPException(status_code=422, detail="format must be json or pdf")
    detail, pack = await _build_pack(candidate_id, db, user)
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="brand_guard.evidence_pack_exported", target_type="brand_candidate", target_id=candidate_id,
        target_label=detail.candidate_domain, after={"format": format, "hash": pack["integrity"]["hash"]},
    )
    await db.commit()
    stem = f"evidence-{detail.candidate_domain}-{pack['integrity']['hash'][:8]}"
    if format == "json":
        return Response(content=brand_evidence_pack.canonical({**pack}), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{stem}.json"'})
    from app.services.pdf_report_service import render_html_to_pdf
    return Response(content=await render_html_to_pdf(brand_evidence_pack.render_html(pack)), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{stem}.pdf"'})


_TAKEDOWN_ROLES = ("admin", "approver")


def _require_takedown_role(user: User) -> None:
    """Drafting and approving a complaint speaks for the brand owner; a read-only member may look but not do it.
    A workspace with one admin can approve its own drafts: no second person is required."""
    if user.role not in _TAKEDOWN_ROLES:
        raise HTTPException(status_code=403, detail="Only admins and approvers can draft or approve a takedown request.")


async def _evidence_level(db: AsyncSession, candidate_id) -> str:
    rows = (await db.execute(select(CandidateEvidence).where(CandidateEvidence.candidate_id == candidate_id))).scalars().all()
    _, level = brand_takedown.claims([{"signal": r.signal, "summary": r.summary, "observed_at": r.observed_at} for r in rows])
    return level


def _takedown_out(t: BrandTakedown, level: str | None = None) -> TakedownOut:
    return TakedownOut(
        evidence_level=level,
        id=str(t.id), candidate_id=str(t.candidate_id), route_kind=t.route_kind, route_label=t.route_label, how=t.how, target=t.target, certainty=t.certainty,
        subject=t.subject, body=t.body, status=t.status, allowed_next=list(brand_takedown.NEXT.get(t.status, ())), evidence_hash=t.evidence_hash,
        approved_at=_iso(t.approved_at), sent_at=_iso(t.sent_at), outcome_note=t.outcome_note, created_at=t.created_at.isoformat(),
        mailto=brand_takedown.mailto(t.target, t.subject, t.body) if t.how == "email" and "@" in t.target and t.status in ("approved", "sent") else None,
    )


async def _own_candidate(db: AsyncSession, user: User, candidate_id: str) -> BrandCandidate:
    c = (await db.execute(select(BrandCandidate).where(BrandCandidate.id == candidate_id, BrandCandidate.tenant_id == user.tenant_id))).scalar_one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="Candidate not found")
    return c


async def _own_takedown(db: AsyncSession, user: User, takedown_id: str) -> BrandTakedown:
    t = (await db.execute(select(BrandTakedown).where(BrandTakedown.id == takedown_id, BrandTakedown.tenant_id == user.tenant_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Takedown not found")
    return t


@router.get("/candidates/{candidate_id}/takedown-routes")
async def takedown_routes(candidate_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Who could remove this look-alike. Looks up the registrar's and host's public abuse contacts; never sends anything."""
    c = await _own_candidate(db, user, candidate_id)
    return {"routes": await brand_takedown_discovery.discover(c.candidate_domain, c.enrichment)}


@router.get("/candidates/{candidate_id}/takedowns", response_model=list[TakedownOut])
async def list_takedowns(candidate_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    c = await _own_candidate(db, user, candidate_id)
    rows = (await db.execute(select(BrandTakedown).where(BrandTakedown.candidate_id == c.id, BrandTakedown.tenant_id == user.tenant_id).order_by(BrandTakedown.created_at))).scalars().all()
    level = await _evidence_level(db, c.id)
    return [_takedown_out(t, level) for t in rows]


@router.post("/candidates/{candidate_id}/takedowns", response_model=TakedownOut, status_code=201)
async def create_takedown(candidate_id: str, payload: TakedownCreate, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Draft a complaint for one route. The draft is only text a person edits and approves; nothing is sent."""
    _require_takedown_role(user)
    c = await _own_candidate(db, user, candidate_id)
    route = payload.route.model_dump()
    if route["how"] == "email" and "@" not in route["target"]:
        raise HTTPException(status_code=422, detail="An email route needs an email address")
    detail, pack = await _build_pack(candidate_id, db, user)
    observations, level = brand_takedown.claims(pack["evidence"])
    draft = brand_takedown.draft(
        domain=c.candidate_domain, brand=pack["brand"]["name"], official_domains=pack["brand"]["official_domains"],
        observations=observations,
        pack_hash=None, route=route, sender_name=user.full_name or user.email, generated_at=datetime.now(timezone.utc),
    )
    t = BrandTakedown(
        id=uuid.uuid4(), tenant_id=user.tenant_id, candidate_id=c.id, route_kind=route["kind"], route_label=route["label"], how=route["how"], target=route["target"],
        certainty=route["certainty"], subject=draft["subject"], body=draft["body"], status="draft", evidence_hash=None, created_by_user_id=user.id,
    )
    db.add(t)
    await audit_service.log(db, tenant_id=user.tenant_id, actor=user, action="brand_guard.takedown_drafted", target_type="brand_candidate", target_id=str(c.id),
                            target_label=c.candidate_domain, after={"route": route["kind"], "target": route["target"], "certainty": route["certainty"]})
    await db.commit()
    await db.refresh(t)
    return _takedown_out(t, level)


@router.patch("/takedowns/{takedown_id}", response_model=TakedownOut)
async def edit_takedown(takedown_id: str, payload: TakedownEdit, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    _require_takedown_role(user)
    t = await _own_takedown(db, user, takedown_id)
    if t.status != "draft":
        raise HTTPException(status_code=409, detail="Only a draft can be edited. Send an approved one back to draft first.")
    t.subject, t.body = payload.subject, payload.body
    await db.commit()
    await db.refresh(t)
    return _takedown_out(t, await _evidence_level(db, t.candidate_id))


@router.post("/takedowns/{takedown_id}/status", response_model=TakedownOut)
async def move_takedown(takedown_id: str, payload: TakedownMove, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """draft -> approved (a person reviewed it) -> sent (a person says they sent it) -> acknowledged / removed / rejected."""
    _require_takedown_role(user)
    t = await _own_takedown(db, user, takedown_id)
    if payload.status not in brand_takedown.STATUSES:
        raise HTTPException(status_code=422, detail="Unknown status")
    if not brand_takedown.can_move(t.status, payload.status):
        raise HTTPException(status_code=409, detail=f"A {t.status} takedown cannot move to {payload.status}")
    now = datetime.now(timezone.utc)
    before = t.status
    t.status = payload.status
    if payload.status == "approved":
        t.approved_by_user_id, t.approved_at = user.id, now
    elif payload.status == "draft":
        t.approved_by_user_id, t.approved_at = None, None
    elif payload.status == "sent":
        t.sent_at = now
    if payload.note is not None:
        t.outcome_note = payload.note
    c = await db.get(BrandCandidate, t.candidate_id)
    await audit_service.log(db, tenant_id=user.tenant_id, actor=user, action=f"brand_guard.takedown_{payload.status}", target_type="brand_candidate", target_id=str(t.candidate_id),
                            target_label=c.candidate_domain if c else None, before={"status": before},
                            after={"status": payload.status, "route": t.route_kind, "target": t.target,
                                   **({"self_approved": t.created_by_user_id == user.id} if payload.status == "approved" else {})})
    if c is not None:
        db.add(BrandCandidateEvent(id=uuid.uuid4(), candidate_id=c.id, tenant_id=c.tenant_id, kind="takedown", occurred_at=now,
                                   payload={"by": user.full_name or user.email, "route": t.route_label, "to": payload.status}))
    await db.commit()
    await db.refresh(t)
    return _takedown_out(t, await _evidence_level(db, t.candidate_id))


@router.get("/defensive-registrations")
@limiter.limit("6/minute")
async def defensive_registrations(request: Request, profile_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Look-alike names worth registering first, ranked by a stated prior (see brand_defensive). Checks DNS for a shortlist, so it is rate-limited
    and run on request, never in the background. Nothing is registered or reserved for the person."""
    import asyncio
    from app.services import brand_discovery_service as disc
    from app.services.brand_guard_service import _dns_enrich

    profile = await _get_profile(db, user, profile_id)
    domain = await db.get(Domain, profile.domain_id)
    if domain is None:
        raise HTTPException(status_code=404, detail="The brand's primary domain no longer exists")
    generated = disc.generate_candidates(domain.name, profile.brand_name, list(profile.keywords or []))
    rows = (await db.execute(select(BrandCandidate.candidate_domain, BrandCandidate.status, BrandCandidate.threat_class).where(BrandCandidate.profile_id == profile.id))).all()
    known = {r[0] for r in rows} | {domain.name, *(profile.official_domains or [])}
    hostile = [(r[0], r[2]) for r in rows if r[1] in ("confirmed", "takedown", "suspicious")]
    ranked = brand_defensive.shortlist(generated, known, disc.split_registrable(domain.name)[1], hostile)
    sem = asyncio.Semaphore(15)

    async def check(d: str):
        async with sem:
            return d, (await _dns_enrich(d)).get("registered")
    registered = dict(await asyncio.gather(*(check(r["domain"]) for r in ranked)))
    return {**brand_defensive.advise(ranked, registered), "generated": len(generated), "already_tracked": len(known)}


MAX_CHANNELS = 10


def _mask(kind: str, target: str) -> str:
    if kind == "email":
        name, _, host = target.partition("@")
        return f"{name[:2]}…@{host}"
    from urllib.parse import urlparse
    u = urlparse(target)
    return f"{u.hostname}/…{target[-4:]}"


def _channel_out(c: BrandNotifyChannel) -> dict:
    from app.services.crypto_service import decrypt_secret
    try:
        shown = _mask(c.kind, decrypt_secret(c.target_enc))
    except ValueError:
        shown = "(unreadable: re-create this channel)"
    return {"id": str(c.id), "kind": c.kind, "label": c.label, "target": shown, "min_severity": c.min_severity, "digest": c.digest, "enabled": c.enabled,
            "signed": bool(c.secret_enc), "last_status": c.last_status, "last_error": c.last_error, "last_sent_at": _iso(c.last_sent_at), "last_digest_at": _iso(c.last_digest_at)}


async def _own_channel(db: AsyncSession, user: User, channel_id: str) -> BrandNotifyChannel:
    c = (await db.execute(select(BrandNotifyChannel).where(BrandNotifyChannel.id == channel_id, BrandNotifyChannel.tenant_id == user.tenant_id))).scalar_one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="Channel not found")
    return c


@router.get("/notification-channels")
async def list_channels(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    rows = (await db.execute(select(BrandNotifyChannel).where(BrandNotifyChannel.tenant_id == user.tenant_id).order_by(BrandNotifyChannel.created_at))).scalars().all()
    return [_channel_out(c) for c in rows]


@router.post("/notification-channels", status_code=201)
async def create_channel(payload: ChannelCreate, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Add where alerts go. The address is encrypted. A webhook gets a signing secret, shown once in this response and never again."""
    import secrets
    from app.services.crypto_service import encrypt_secret
    tenant = await _tenant(db, user)
    if get_limits(tenant.plan)["brand_guard_brands"] == 0:
        raise HTTPException(status_code=403, detail={"code": "feature_not_available", "message": "Brand Guard is not available on your plan.", "upgrade_required": True})
    try:
        target = brand_notify.validate_target(payload.kind, payload.target)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    if (await db.execute(select(func.count()).select_from(BrandNotifyChannel).where(BrandNotifyChannel.tenant_id == user.tenant_id))).scalar_one() >= MAX_CHANNELS:
        raise HTTPException(status_code=409, detail=f"You can have up to {MAX_CHANNELS} channels")
    secret = secrets.token_urlsafe(32) if payload.kind == "webhook" else None
    c = BrandNotifyChannel(id=uuid.uuid4(), tenant_id=user.tenant_id, kind=payload.kind, label=payload.label, target_enc=encrypt_secret(target), secret_enc=encrypt_secret(secret) if secret else None,
                           min_severity=payload.min_severity, digest=payload.digest, enabled=True, created_by_user_id=user.id)
    db.add(c)
    await audit_service.log(db, tenant_id=user.tenant_id, actor=user, action="brand_guard.channel_added", target_type="brand_notify_channel", target_id=str(c.id), target_label=f"{payload.kind}: {payload.label}")
    await db.commit()
    await db.refresh(c)
    return {**_channel_out(c), "secret": secret}


@router.patch("/notification-channels/{channel_id}")
async def update_channel(channel_id: str, payload: ChannelUpdate, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    c = await _own_channel(db, user, channel_id)
    for field in ("label", "min_severity", "digest", "enabled"):
        v = getattr(payload, field)
        if v is not None:
            setattr(c, field, v)
    await audit_service.log(db, tenant_id=user.tenant_id, actor=user, action="brand_guard.channel_changed", target_type="brand_notify_channel", target_id=str(c.id), target_label=f"{c.kind}: {c.label}")
    await db.commit()
    await db.refresh(c)
    return _channel_out(c)


@router.delete("/notification-channels/{channel_id}", status_code=204)
async def delete_channel(channel_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    c = await _own_channel(db, user, channel_id)
    await audit_service.log(db, tenant_id=user.tenant_id, actor=user, action="brand_guard.channel_removed", target_type="brand_notify_channel", target_id=str(c.id), target_label=f"{c.kind}: {c.label}")
    await db.delete(c)
    await db.commit()


@router.post("/notification-channels/{channel_id}/test")
@limiter.limit("6/minute")
async def test_channel(request: Request, channel_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Send a clearly-labelled test message so the person can see it arrive. Recorded in the log."""
    c = await _own_channel(db, user, channel_id)
    now = datetime.now(timezone.utc)
    alert = {"id": "test", "severity": "info", "title": "ZoneProof test message", "body": "If you can read this, Brand Guard alerts will reach this channel.", "action": None, "created_at": now.isoformat()}
    ok, err = await brand_notify_dispatch.deliver(db, c, alert, brand_notify_dispatch._link())
    c.last_status, c.last_error, c.last_sent_at = ("ok" if ok else "failed"), (err or None), now
    db.add(BrandNotifyLog(id=uuid.uuid4(), tenant_id=c.tenant_id, channel_id=c.id, alert_id=None, kind="test", status="ok" if ok else "failed", error=err, sent_at=now))
    await db.commit()
    return {"ok": ok, "error": err}


@router.get("/notification-log")
async def notification_log(limit: int = 30, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    rows = (await db.execute(
        select(BrandNotifyLog, BrandNotifyChannel.label, BrandNotifyChannel.kind).join(BrandNotifyChannel, BrandNotifyChannel.id == BrandNotifyLog.channel_id)
        .where(BrandNotifyLog.tenant_id == user.tenant_id).order_by(BrandNotifyLog.sent_at.desc()).limit(min(max(limit, 1), 100))
    )).all()
    return [{"id": str(r.id), "channel": label, "kind": ckind, "type": r.kind, "status": r.status, "error": r.error, "sent_at": r.sent_at.isoformat()} for r, label, ckind in rows]


@router.get("/siem-export")
async def siem_export(format: str = "jsonl", since: str | None = None, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Brand Guard alerts and every Brand Guard action in the audit log, as JSON lines or CEF, for a SIEM. Enterprise plan."""
    from fastapi import Response
    from app.models import Alert
    from app.models.audit_log import AuditLogEntry
    if format not in ("jsonl", "cef"):
        raise HTTPException(status_code=422, detail="format must be jsonl or cef")
    tenant = await _tenant(db, user)
    if tenant.plan != "enterprise":
        raise HTTPException(status_code=403, detail={"code": "feature_not_available", "message": "SIEM export is available on the Enterprise plan.", "current_plan": tenant.plan, "upgrade_required": True})
    start = datetime.now(timezone.utc) - timedelta(days=7)
    if since:
        try:
            start = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=422, detail="since must be an ISO date-time")
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
    alerts = (await db.execute(select(Alert).where(Alert.tenant_id == user.tenant_id, Alert.category == "brand", Alert.created_at >= start).order_by(Alert.created_at).limit(5000))).scalars().all()
    audits = (await db.execute(select(AuditLogEntry).where(AuditLogEntry.tenant_id == user.tenant_id, AuditLogEntry.action.like("brand_guard.%"), AuditLogEntry.created_at >= start).order_by(AuditLogEntry.created_at).limit(5000))).scalars().all()
    events = [{"kind": "brand_guard.alert", "name": a.title, "severity": a.severity, "at": a.created_at.isoformat(), "detail": a.body, "id": str(a.id)} for a in alerts]
    events += [{"kind": e.action, "name": e.action.replace("brand_guard.", "").replace("_", " "), "severity": "info", "at": e.created_at.isoformat(), "actor": e.actor_email, "target": e.target_label, "action": e.action, "id": str(e.id)} for e in audits]
    events.sort(key=lambda e: e["at"])
    body = brand_notify.to_jsonl(events) if format == "jsonl" else "".join(brand_notify.to_cef(e) + "\n" for e in events)
    return Response(content=body, media_type="text/plain; charset=utf-8", headers={"X-Event-Count": str(len(events))})


@router.get("/probe-status")
async def probe_status(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Whether page probing is switched on, and when the egress worker last collected a job. Read-only; the switch is a server setting."""
    from app.models import BrandProbeJob
    from app.services import brand_probe_queue
    last = (await db.execute(select(func.max(BrandProbeJob.claimed_at)))).scalar_one()
    mine = (await db.execute(select(func.count()).select_from(BrandProbeJob).where(BrandProbeJob.tenant_id == user.tenant_id, BrandProbeJob.status.in_(("queued", "claimed"))))).scalar_one()
    return {"enabled": brand_probe_queue.enabled(), "render_enabled": brand_probe_queue.render_enabled(), "worker_last_seen": _iso(last), "waiting": mine}


async def _capture_for(db: AsyncSession, user: User, candidate_id: str):
    from app.services import brand_capture
    try:
        cid = uuid.UUID(candidate_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found")
    return await brand_capture.latest(db, user.tenant_id, cid)


@router.get("/candidates/{candidate_id}/capture")
async def candidate_capture(candidate_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """What the sandboxed renderer saw on this look-alike's page: facts and a short text excerpt. Third-party content: tenant-scoped, time-limited."""
    from app.services import brand_capture, brand_probe_queue
    cap = await _capture_for(db, user, candidate_id)
    if cap is None:
        return {"available": False, "render_enabled": brand_probe_queue.render_enabled()}
    text = brand_capture.page_text(cap)
    cand = await db.get(BrandCandidate, cap.candidate_id)
    ref = await brand_capture.reference_for(db, user.tenant_id, cand.profile_id) if cand else None
    return {
        "available": True, "reference_available": bool(ref and ref.screenshot_enc), "profile_id": str(cand.profile_id) if cand else None, "render_enabled": brand_probe_queue.render_enabled(), "captured_at": _iso(cap.captured_at), "retain_until": _iso(cap.retain_until),
        "kept_for_case": bool(cand and cand.status in brand_capture.CASE_STATUSES), "title": cap.title, "final_url": cap.final_url, "forms": cap.forms or [],
        "nav_chain": cap.nav_chain or [], "stats": cap.stats or {}, "has_screenshot": bool(cap.screenshot_enc), "text_excerpt": (text or "")[:1200] or None,
    }


@router.get("/profiles/{profile_id}/reference/screenshot")
async def profile_reference_screenshot(profile_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """The customer's own page as the renderer saw it (the reference a look-alike is compared with), image only."""
    from fastapi import Response
    from app.services import brand_capture
    try:
        pid = uuid.UUID(profile_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found")
    row = await brand_capture.reference_for(db, user.tenant_id, pid)
    raw = brand_capture.reference_bytes(row) if row else None
    if raw is None:
        raise HTTPException(status_code=404, detail="No reference screenshot")
    return Response(content=raw, media_type=row.screenshot_mime, headers={
        "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; sandbox",
        "Content-Disposition": "inline; filename=\"reference.jpg\"" if row.screenshot_mime == "image/jpeg" else "inline; filename=\"reference.png\"",
    })


@router.get("/candidates/{candidate_id}/capture/screenshot")
async def candidate_capture_screenshot(candidate_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """The screenshot as an image and nothing else: signature checked before it was stored and again here, served with headers that stop a browser
    treating it as anything but an image."""
    from fastapi import Response
    from app.services import brand_capture
    cap = await _capture_for(db, user, candidate_id)
    raw = brand_capture.screenshot_bytes(cap) if cap else None
    if raw is None:
        raise HTTPException(status_code=404, detail="No screenshot")
    return Response(content=raw, media_type=cap.screenshot_mime, headers={
        "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; sandbox",
        "Content-Disposition": "inline; filename=\"page.jpg\"" if cap.screenshot_mime == "image/jpeg" else "inline; filename=\"page.png\"",
    })


_BLOCK_STATUSES = {"confirmed":("confirmed", "takedown"), "likely": ("confirmed", "takedown", "suspicious")}


async def _blocklist_domains(db: AsyncSession, user: User, profile_id: str | None, include: str) -> tuple[list[str], str]:
    if include not in _BLOCK_STATUSES:
        raise HTTPException(status_code=422, detail="include must be confirmed or likely")
    stmt = select(BrandCandidate.candidate_domain, BrandCandidate.profile_id).where(BrandCandidate.tenant_id == user.tenant_id, BrandCandidate.status.in_(_BLOCK_STATUSES[include]))
    profile = None
    if profile_id:
        profile = (await db.execute(select(BrandProfile).where(BrandProfile.id == profile_id, BrandProfile.tenant_id == user.tenant_id))).scalar_one_or_none()
        if profile is None:
            raise HTTPException(status_code=404, detail="Brand not found")
        stmt = stmt.where(BrandCandidate.profile_id == profile.id)
    rows = (await db.execute(stmt)).all()
    return brand_blocklist.clean([r[0] for r in rows]), (profile.brand_name if profile else "your brands")


@router.get("/blocklist")
async def blocklist(format: str = "plain", include: str = "confirmed", profile_id: str | None = None, download: bool = False,
                    db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Confirmed look-alikes as a rule file for the customer's own mail, DNS or browser filters. `include=likely` adds unreviewed suspicious ones
    (more coverage, some risk of blocking something legitimate). Audit-logged on download."""
    from fastapi import Response
    if format not in brand_blocklist.FORMATS:
        raise HTTPException(status_code=422, detail=f"format must be one of: {', '.join(brand_blocklist.FORMATS)}")
    domains, brand = await _blocklist_domains(db, user, profile_id, include)
    now = datetime.now(timezone.utc)
    text = brand_blocklist.render(format, domains, brand, now)
    label, media, ext = brand_blocklist.FORMATS[format]
    if download:
        await audit_service.log(db, tenant_id=user.tenant_id, actor=user, action="brand_guard.blocklist_exported", target_type="brand_profile", target_id=profile_id,
                                target_label=brand, after={"format": format, "include": include, "count": len(domains)})
        await db.commit()
    headers = {"Content-Disposition": f'attachment; filename="zoneproof-blocklist-{now.strftime("%Y%m%d")}.{ext}"', "X-Entry-Count": str(len(domains))} if download else {"X-Entry-Count": str(len(domains))}
    return Response(content=text, media_type=f"{media}; charset=utf-8", headers=headers)


def _submission_out(s: BrandSubmission) -> dict:
    return {"id": str(s.id), "candidate_id": str(s.candidate_id), "service": s.service, "label": brand_blocklist.SERVICES[s.service][0], "status": s.status, "note": s.note,
            "allowed_next": list(brand_blocklist.SUBMISSION_NEXT.get(s.status, ())), "created_at": s.created_at.isoformat(), "updated_at": s.updated_at.isoformat()}


@router.get("/candidates/{candidate_id}/report-links")
async def report_links(candidate_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Where to report this look-alike to the browser-protection services, with what we have recorded so far. Nothing is submitted for the person."""
    c = await _own_candidate(db, user, candidate_id)
    mine = {s.service: s for s in (await db.execute(select(BrandSubmission).where(BrandSubmission.candidate_id == c.id, BrandSubmission.tenant_id == user.tenant_id))).scalars().all()}
    return [{**brand_blocklist.report_link(k, c.candidate_domain), "submission": _submission_out(mine[k]) if k in mine else None} for k in brand_blocklist.SERVICES]


@router.post("/candidates/{candidate_id}/submissions", status_code=201)
async def record_submission(candidate_id: str, payload: SubmissionCreate, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """The person says they reported it to this service."""
    c = await _own_candidate(db, user, candidate_id)
    if (await db.execute(select(BrandSubmission.id).where(BrandSubmission.candidate_id == c.id, BrandSubmission.service == payload.service))).first():
        raise HTTPException(status_code=409, detail="Already recorded for this service")
    s = BrandSubmission(id=uuid.uuid4(), tenant_id=user.tenant_id, candidate_id=c.id, service=payload.service, status="submitted", note=payload.note, created_by_user_id=user.id)
    db.add(s)
    await audit_service.log(db, tenant_id=user.tenant_id, actor=user, action="brand_guard.report_submitted", target_type="brand_candidate", target_id=str(c.id),
                            target_label=c.candidate_domain, after={"service": payload.service})
    await db.commit()
    await db.refresh(s)
    return _submission_out(s)


@router.post("/submissions/{submission_id}/status")
async def move_submission(submission_id: str, payload: SubmissionMove, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    s = (await db.execute(select(BrandSubmission).where(BrandSubmission.id == submission_id, BrandSubmission.tenant_id == user.tenant_id))).scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Submission not found")
    if not brand_blocklist.can_move_submission(s.status, payload.status):
        raise HTTPException(status_code=409, detail=f"A {s.status} report cannot move to {payload.status}")
    before = s.status
    s.status = payload.status
    if payload.note is not None:
        s.note = payload.note
    await audit_service.log(db, tenant_id=user.tenant_id, actor=user, action=f"brand_guard.report_{payload.status}", target_type="brand_candidate", target_id=str(s.candidate_id),
                            before={"status": before}, after={"status": payload.status, "service": s.service})
    await db.commit()
    await db.refresh(s)
    return _submission_out(s)


@router.patch("/candidates/{candidate_id}/assignee", response_model=CandidateOut)
async def assign_candidate(candidate_id: str, payload: CandidateAssign, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    from sqlalchemy.orm import selectinload

    c = (await db.execute(
        select(BrandCandidate).options(selectinload(BrandCandidate.evidence))
        .where(BrandCandidate.id == candidate_id, BrandCandidate.tenant_id == user.tenant_id)
    )).scalar_one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="Candidate not found")
    target = None
    if payload.user_id:
        try:
            uid = uuid.UUID(payload.user_id)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid user id")
        target = (await db.execute(select(User).where(User.id == uid, User.tenant_id == user.tenant_id))).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="That person is not in your workspace")
    before = str(c.assignee_user_id) if c.assignee_user_id else None
    c.assignee_user_id = target.id if target else None
    if before != (str(target.id) if target else None):
        db.add(BrandCandidateEvent(
            id=uuid.uuid4(), candidate_id=c.id, tenant_id=c.tenant_id, kind="assigned", occurred_at=datetime.now(timezone.utc),
            payload={"by": user.full_name or user.email, "to": (target.full_name or target.email) if target else None},
        ))
        await audit_service.log(
            db, tenant_id=user.tenant_id, actor=user, action="brand_guard.candidate_assigned", target_type="brand_candidate", target_id=str(c.id),
            target_label=c.candidate_domain, before={"assignee": before}, after={"assignee": str(target.id) if target else None},
        )
    await db.commit()
    c = (await db.execute(
        select(BrandCandidate).options(selectinload(BrandCandidate.evidence)).where(BrandCandidate.id == c.id).execution_options(populate_existing=True)
    )).scalar_one()
    out = _candidate_out(c, c.evidence)
    await _fill_assignees(db, user.tenant_id, [out])
    return out
