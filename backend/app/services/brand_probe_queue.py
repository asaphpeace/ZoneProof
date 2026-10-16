"""The probe job queue: what gets probed, handing jobs to the egress worker, and applying what comes back (plan steps 7.1/7.2).

Everything here respects the kill switch (`settings.brand_probe_enabled`): while it is off nothing is queued, nothing is handed out, and a
late result is refused. The selection rules keep probing small and polite: only live look-alikes a person has not dismissed, resembling the
brand enough to matter (or already confirmed), at most once a day per host, with a per-tenant daily cap."""
from __future__ import annotations

import base64
import logging
import uuid
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import BrandCandidate, BrandProbeJob, BrandProfile, BrandReferenceCapture, Domain
from app.services import brand_funnel, brand_probe_analysis, brand_probe_protocol, brand_similarity
from app.services.brand_scoring_service import SUSPICIOUS_IDENTITY_THRESHOLD

log = logging.getLogger(__name__)
LIVE_STAGES = ("resolving", "mail_enabled", "certified")
DISMISSED = ("false_positive", "benign", "customer_owned", "partner", "ignored")
PROBE_STATUSES = ("confirmed", "takedown")


def enabled() -> bool:
    return bool(settings.brand_probe_enabled and settings.brand_probe_key)


def render_enabled() -> bool:
    """The renderer (a real browser in a throwaway container) has its own switch on top of the probe switch."""
    return bool(enabled() and settings.brand_render_enabled)


async def brand_ref(db: AsyncSession, profile: BrandProfile) -> dict:
    """What a look-alike's page is compared against: the brand's icon hash and hashed wording (from its fingerprint) and, if the renderer has
    captured it, the layout hash and accent palette of the brand's own page. Missing pieces are simply absent (no comparison, not a mismatch)."""
    sim = (profile.fingerprint or {}).get("similarity") or {}
    ref = {"icon_dhash": sim.get("icon_dhash"), "wording": sim.get("wording") or []}
    row = (await db.execute(select(BrandReferenceCapture).where(BrandReferenceCapture.profile_id == profile.id))).scalar_one_or_none()
    if row is not None:
        ref.update(layout=row.layout_hash, palette=row.palette)
    return ref


async def enqueue_reference(db: AsyncSession, profile: BrandProfile, now: datetime | None = None) -> bool:
    """Queue a render of the customer's OWN page, if there is none yet or it is older than the refresh interval. The renderer is off -> nothing."""
    if not render_enabled():
        return False
    now = now or datetime.now(timezone.utc)
    row = (await db.execute(select(BrandReferenceCapture).where(BrandReferenceCapture.profile_id == profile.id))).scalar_one_or_none()
    if row is not None and row.captured_at > now - timedelta(days=settings.brand_reference_refresh_days):
        return False
    pending = (await db.execute(select(func.count()).select_from(BrandProbeJob).where(
        BrandProbeJob.profile_id == profile.id, BrandProbeJob.kind == "ref",
        (BrandProbeJob.created_at >= now - timedelta(days=1)) | BrandProbeJob.status.in_(("queued", "claimed")),
    ))).scalar_one()
    if pending:
        return False
    domain = await db.get(Domain, profile.domain_id)
    if domain is None:
        return False
    db.add(BrandProbeJob(id=uuid.uuid4(), tenant_id=profile.tenant_id, candidate_id=None, profile_id=profile.id, host=domain.name, kind="ref", status="queued", created_at=now,
                         expires_at=now + timedelta(seconds=settings.brand_probe_job_ttl_seconds)))
    await db.flush()
    return True


def worth_rendering(status: str, facts: dict | None) -> bool:
    """Pure: should a look-alike whose light probe found these facts get a rendered look? Only pages that already look like something:
    a case a person is working, a password form, the brand's name in the title, or the brand's own icon. Never a page that redirects to the brand."""
    if not facts or not facts.get("reachable") or facts.get("redirects_to_brand") or status in DISMISSED:
        return False
    return bool(status in PROBE_STATUSES or facts.get("password_form") or facts.get("brand_in_title") or facts.get("favicon_matches_brand"))


async def enqueue_render(db: AsyncSession, cand: BrandCandidate, facts: dict | None, now: datetime | None = None, profile: BrandProfile | None = None) -> bool:
    """Queue one rendered look at this candidate if it is worth it, not done recently, and the tenant's daily render allowance has room.
    Every decision is counted for the funnel (with the reason a page was not queued). Nothing is counted while the renderer is off."""
    if not render_enabled():
        return False
    now = now or datetime.now(timezone.utc)

    async def counted(queued: bool, reason: str | None = None) -> bool:
        owner = profile or await db.get(BrandProfile, cand.profile_id)
        if owner is not None:
            await brand_funnel.record_safe(db, owner, "render_select", entered=1, passed=1 if queued else 0, detail={reason: 1} if reason else None)
        return queued

    if not worth_rendering(cand.status, facts):
        return await counted(False, "not_interesting")
    busy = (await db.execute(select(func.count()).select_from(BrandProbeJob).where(
        BrandProbeJob.candidate_id == cand.id, BrandProbeJob.kind == "render",
        (BrandProbeJob.created_at >= now - timedelta(days=settings.brand_render_host_interval_days)) | BrandProbeJob.status.in_(("queued", "claimed")),
    ))).scalar_one()
    if busy:
        return await counted(False, "rendered_recently")
    spent = (await db.execute(select(func.count()).select_from(BrandProbeJob).where(
        BrandProbeJob.tenant_id == cand.tenant_id, BrandProbeJob.kind == "render", BrandProbeJob.created_at >= now - timedelta(days=1),
    ))).scalar_one()
    if spent >= settings.brand_render_tenant_daily_cap:
        return await counted(False, "daily_cap")
    db.add(BrandProbeJob(id=uuid.uuid4(), tenant_id=cand.tenant_id, candidate_id=cand.id, host=cand.candidate_domain, kind="render", status="queued", created_at=now,
                         expires_at=now + timedelta(seconds=settings.brand_probe_job_ttl_seconds)))
    await db.flush()
    return await counted(True)


def eligible(status: str, stage: str, identity: float) -> bool:
    """Pure: should this look-alike be probed at all?"""
    if status in DISMISSED or stage not in LIVE_STAGES:
        return False
    return status in PROBE_STATUSES or identity >= SUSPICIOUS_IDENTITY_THRESHOLD


async def enqueue_due(db: AsyncSession, profile: BrandProfile, now: datetime | None = None) -> int:
    """Queue probes for this brand's eligible look-alikes. Returns jobs created. Does nothing while probing is off."""
    if not enabled():
        return 0
    now = now or datetime.now(timezone.utc)
    spent = (await db.execute(select(func.count()).select_from(BrandProbeJob).where(BrandProbeJob.tenant_id == profile.tenant_id, BrandProbeJob.kind == "light", BrandProbeJob.created_at >= now - timedelta(days=1)))).scalar_one()
    room = max(settings.brand_probe_tenant_daily_cap - spent, 0)
    rows = (await db.execute(select(BrandCandidate).where(BrandCandidate.profile_id == profile.id, BrandCandidate.stage.in_(LIVE_STAGES), BrandCandidate.status.not_in(DISMISSED)).order_by(BrandCandidate.abuse_score.desc()))).scalars().all()
    recent = {r[0] for r in (await db.execute(select(BrandProbeJob.candidate_id).where(
        BrandProbeJob.candidate_id.in_([c.id for c in rows] or [uuid.uuid4()]), BrandProbeJob.kind == "light",
        (BrandProbeJob.created_at >= now - timedelta(hours=settings.brand_probe_host_interval_hours)) | BrandProbeJob.status.in_(("queued", "claimed")),
    ))).all()}
    made = 0
    why = {"probed_recently": 0, "not_similar_enough": 0, "daily_cap": 0}
    for c in rows:
        if c.id in recent:
            why["probed_recently"] += 1
        elif not eligible(c.status, c.stage, c.identity_score):
            why["not_similar_enough"] += 1
        elif made >= room:
            why["daily_cap"] += 1
        else:
            db.add(BrandProbeJob(id=uuid.uuid4(), tenant_id=c.tenant_id, candidate_id=c.id, host=c.candidate_domain, kind="light", status="queued",
                                 expires_at=now + timedelta(seconds=settings.brand_probe_job_ttl_seconds)))
            made += 1
    await db.flush()
    await brand_funnel.record_safe(db, profile, "probe_select", entered=len(rows), passed=made, detail=why)
    return made


async def claim(db: AsyncSession, now: datetime | None = None) -> BrandProbeJob | None:
    """Hand the oldest waiting job to the worker. Expired jobs are marked so they are never handed out. None while probing is off."""
    if not enabled():
        return None
    now = now or datetime.now(timezone.utc)
    stale = (await db.execute(select(BrandProbeJob).where(BrandProbeJob.status.in_(("queued", "claimed")), BrandProbeJob.expires_at < now))).scalars().all()
    for j in stale:
        j.status = "expired"
    await _count_expired(db, stale)
    kinds = ("light", "render", "ref") if render_enabled() else ("light",)    # a render job waits (and expires) while the renderer is off
    job = (await db.execute(select(BrandProbeJob).where(BrandProbeJob.status == "queued", BrandProbeJob.kind.in_(kinds), BrandProbeJob.expires_at >= now).order_by(BrandProbeJob.created_at).limit(1).with_for_update(skip_locked=True))).scalars().first()
    if job is not None:
        job.status, job.claimed_at = "claimed", now
    await db.commit()
    return job


async def _count_expired(db: AsyncSession, jobs: list[BrandProbeJob]) -> None:
    """Jobs that ran out of time without a result mean the worker is down, offline or behind: counted per brand at the stage they stalled in."""
    if not jobs:
        return
    by: dict[tuple, int] = {}
    cand_ids = [j.candidate_id for j in jobs if j.candidate_id and j.kind in ("light", "render")]
    owner = {cid: pid for cid, pid in (await db.execute(select(BrandCandidate.id, BrandCandidate.profile_id).where(BrandCandidate.id.in_(cand_ids or [uuid.uuid4()])))).all()}
    for j in jobs:
        pid = owner.get(j.candidate_id)
        if pid is not None:
            key = (j.tenant_id, pid, "probe_done" if j.kind == "light" else "render_done")
            by[key] = by.get(key, 0) + 1
    for (tenant_id, pid, stage), n in by.items():
        await brand_funnel.record_safe(db, SimpleNamespace(id=pid, tenant_id=tenant_id), stage, entered=n, passed=0, detail={"expired_unclaimed": n})


async def _record_similarity(db: AsyncSession, profile: BrandProfile, sim: dict | None) -> None:
    """Count one comparison with the brand (only when one was made) and which kinds of resemblance it found."""
    if not sim:
        return
    flagged = {}
    if (sim.get("icon") or {}).get("similar"):
        flagged["icon"] = 1
    if (sim.get("wording") or {}).get("shared", 0) >= brand_similarity.WORDING_COPY:
        flagged["wording"] = 1
    if (sim.get("visual") or {}).get("similar"):
        flagged["layout"] = 1
    await brand_funnel.record_safe(db, profile, "similarity", entered=1, passed=1 if flagged else 0, detail=flagged)


async def complete(db: AsyncSession, job_id, raw_result, now: datetime | None = None) -> str:
    """Apply a worker's result. Returns 'ok', 'unknown', 'stale' (not claimed, expired or already done) or 'disabled'. The page HTML never leaves this function."""
    if not enabled():
        return "disabled"
    now = now or datetime.now(timezone.utc)
    job = (await db.execute(select(BrandProbeJob).where(BrandProbeJob.id == job_id).with_for_update())).scalar_one_or_none()
    if job is None:
        return "unknown"
    if job.status != "claimed" or job.expires_at < now:
        return "stale"
    if job.kind in ("render", "ref") and not render_enabled():
        return "disabled"
    cleaned = brand_probe_protocol.clean_result(raw_result)
    if job.kind == "ref":
        return await _complete_reference(db, job, cleaned, now)
    cand = await db.get(BrandCandidate, job.candidate_id)
    profile = await db.get(BrandProfile, cand.profile_id) if cand else None
    if cand is None or profile is None:
        job.status, job.error, job.completed_at = "failed", "candidate gone", now
        await db.commit()
        return "ok"
    if job.kind == "render":
        return await _complete_render(db, job, cleaned, cand, profile, now)
    facts = brand_probe_analysis.analyse(
        cleaned, host=job.host, official_domains=list(profile.official_domains or []), brand_words=_brand_words(profile),
        brand_favicon_sha256=((((profile.fingerprint or {}).get("site") or {}).get("favicon") or {}).get("sha256")), ct_issued_at=(cand.enrichment or {}).get("ct_cert_issued_at"),
        brand_ref=await brand_ref(db, profile),
    )
    facts["at"] = now.isoformat()
    reachable = bool(facts.get("reachable"))
    await brand_funnel.record_safe(db, profile, "probe_done", entered=1, passed=1 if reachable else 0,
                                   detail=None if reachable else {("unreachable" if cleaned.get("ok") else "worker_error"): 1})
    await _record_similarity(db, profile, facts.get("similarity"))
    job.status, job.completed_at, job.result = ("done" if cleaned.get("ok") else "failed"), now, facts
    job.error = None if cleaned.get("ok") else (cleaned.get("error") or "probe failed")
    e = dict(cand.enrichment or {})
    facts = brand_probe_analysis.merge_render(facts, (e.get("probe") or {}).get("rendered"))      # a fresh light probe keeps the last rendered look
    e["probe"] = facts
    cand.enrichment = e
    if cleaned.get("ok"):
        await enqueue_render(db, cand, facts, now, profile)
    await db.commit()
    await _rescore(db, profile, cand)
    return "ok"


async def _rescore(db: AsyncSession, profile: BrandProfile, cand: BrandCandidate) -> None:
    try:
        from app.services.brand_guard_service import rescore_profile
        await rescore_profile(db, profile, {cand.candidate_domain})
        await db.commit()
    except Exception:
        log.exception("Brand probe: rescoring after a result failed")
        await db.rollback()


async def _complete_reference(db: AsyncSession, job: BrandProbeJob, cleaned: dict, now: datetime) -> str:
    """Apply a render of the customer's own page: keep it as the reference, then redo the visual comparison of every look-alike already rendered."""
    from app.services import brand_capture, brand_similarity
    profile = await db.get(BrandProfile, job.profile_id) if job.profile_id else None
    shot = ((cleaned.get("render") or {}).get("screenshot_b64"))
    if profile is None or not cleaned.get("ok") or not shot:
        job.status, job.completed_at, job.error = "failed", now, (cleaned.get("error") or "no screenshot of the brand's page")
        await db.commit()
        return "ok"
    raw = base64.b64decode(shot)
    if brand_similarity.is_blank(raw):                      # a flat picture would be kept for 30 days as "what your page looks like"
        job.status, job.completed_at, job.error = "failed", now, "the page rendered blank (its styles or images did not load)"
        await db.commit()
        return "ok"
    layout, palette = brand_similarity.dhash(raw, 16), brand_similarity.palette(raw)
    row = await brand_capture.store_reference(db, profile=profile, shot_b64=shot, layout=layout, palette=palette, now=now)
    job.status, job.completed_at, job.result = ("done" if row else "failed"), now, {"layout": layout, "palette": palette}
    job.error = None if row else "not an image"
    await db.commit()
    if row:
        await _reapply_visual(db, profile)
    return "ok"


async def _reapply_visual(db: AsyncSession, profile: BrandProfile) -> None:
    """A new reference arrived: recompute the visual comparison for the look-alikes that already have a rendered look, and rescore them."""
    ref = await brand_ref(db, profile)
    rows = (await db.execute(select(BrandCandidate).where(BrandCandidate.profile_id == profile.id))).scalars().all()
    changed: set[str] = set()
    for c in rows:
        probe = (c.enrichment or {}).get("probe") or {}
        if not probe.get("rendered"):
            continue
        redone = brand_probe_analysis.recompare_visual(probe["rendered"], ref)
        sim = dict(probe.get("similarity") or {})
        if (redone.get("similarity") or {}).get("visual"):
            sim["visual"] = redone["similarity"]["visual"]
        else:
            sim.pop("visual", None)
        e = dict(c.enrichment)
        e["probe"] = {**probe, "rendered": redone, "similarity": sim}          # (not merge_render again: that would forget the form was script-built)
        c.enrichment = e
        changed.add(c.candidate_domain)
    await db.commit()
    if changed:
        try:
            from app.services.brand_guard_service import rescore_profile
            await rescore_profile(db, profile, changed)
            await db.commit()
        except Exception:
            log.exception("Brand probe: rescoring after a new reference failed")
            await db.rollback()


async def _complete_render(db: AsyncSession, job: BrandProbeJob, cleaned: dict, cand: BrandCandidate, profile: BrandProfile, now: datetime) -> str:
    """Apply a rendered look: store the screenshot and text (encrypted, time-limited), add the rendered page's facts to the candidate's probe
    facts, rescore. Only small extracted facts go on the job and the candidate; the screenshot and text live only in brand_page_captures."""
    from app.services import brand_capture
    render = cleaned.get("render")
    if not cleaned.get("ok") or not render:
        job.status, job.completed_at, job.error = "failed", now, (cleaned.get("error") or "nothing was rendered")
        await brand_funnel.record_safe(db, profile, "render_done", entered=1, passed=0, detail={"failed": 1})
        await db.commit()
        return "ok"
    rendered = brand_probe_analysis.analyse_render(render, host=job.host, official_domains=list(profile.official_domains or []), brand_words=_brand_words(profile), brand_ref=await brand_ref(db, profile))
    rendered["at"] = now.isoformat()
    await brand_capture.store(db, job_id=job.id, cand=cand, render={**render, "screenshot_b64": None} if rendered.get("blank") else render, now=now)    # the text is kept, a flat picture is not
    await brand_funnel.record_safe(db, profile, "render_done", entered=1, passed=1 if rendered.get("has_screenshot") else 0,
                                   detail=None if rendered.get("has_screenshot") else ({"blank": 1} if rendered.get("blank") else {"no_screenshot": 1}))
    await _record_similarity(db, profile, rendered.get("similarity"))
    e = dict(cand.enrichment or {})
    e["probe"] = brand_probe_analysis.merge_render(e.get("probe"), rendered)
    cand.enrichment = e
    job.status, job.completed_at, job.result = "done", now, {"rendered": rendered}
    await db.commit()
    await _rescore(db, profile, cand)
    return "ok"


def _brand_words(profile: BrandProfile) -> list[str]:
    import re
    name = (profile.brand_name or "").lower()
    first = name.split()[0] if name.split() else ""            # "Acme Financial" is usually written "Acme"; later words ("financial") are too generic to count
    words = {re.sub(r"[^a-z0-9]", "", name), re.sub(r"[^a-z0-9]", "", first)} | {re.sub(r"[^a-z0-9]", "", k.lower()) for k in (profile.keywords or [])}
    return sorted(w for w in words if len(w) >= 3)
