"""
Brand Guard — scan orchestration.

discover (permutations + CT) → enrich (DNS, RDAP) → assess (brand_scoring_
service) → persist candidate + evidence → alert once on genuinely suspicious
ones. Network I/O lives here; scoring and generation are pure and tested on
their own.

Noise control is the point of this module: hundreds of permutations are
generated but only ones with *some* sign of life (resolving DNS, a known
registration date, or a CT certificate) are persisted, so a customer sees
tens of reviewable candidates instead of thousands of unregistered names.

CT monitoring uses crt.sh's JSON search as a polled source. It is a pragmatic
Phase 1 sensor — free, no API key — not a streaming feed: crt.sh is rate-limited
and occasionally slow, so failures are recorded on the profile
(last_scan_error) and never abort the permutation scan. A streaming CT source
(CertStream or similar) slots in behind `fetch_ct_candidates` without changing
anything downstream.
"""
from __future__ import annotations

import asyncio
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone

import dns.exception
import dns.resolver
import httpx
from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from typing import Awaitable, Callable

from app.config import settings
from app.models import (
    Alert, BrandCandidate, BrandCandidateEvent, BrandCandidateObservation, BrandProfile, BrandRegistrationCache, BrandScanRun,
    CandidateEvidence, Domain,
)
from app.models.brand_guard import SCAN_ACTIVE_STATUSES
from app.models.user import Tenant
from app.services import brand_funnel, brand_notify_dispatch, brand_probe_queue
from app.services import audit_service, brand_feeds, brand_fingerprint_service, brand_campaigns, brand_cases, brand_ct_stream, brand_firstparty, brand_graph, brand_nrd, brand_infra_signals as infra, brand_lifecycle as lifecycle, brand_mail_intent
from app.services.brand_corroboration import badges_from_signals
from app.services.brand_baseline import is_shared_hosting, is_shared_nameservers, shares_infrastructure
from app.services.brand_baseline import mail_provider as _mail_provider_of
from app.services import brand_sources as sources
from app.services.brand_discovery_service import (
    brand_words, generate_candidates, matches_brand_fingerprint, platform_suffix, registrable_domain, split_registrable,
    subdomain_brand_abuse,
)
from app.services.brand_scoring_service import SUSPICIOUS_ABUSE_THRESHOLD, SUSPICIOUS_IDENTITY_THRESHOLD, Assessment, assess_candidate
from app.services.dns_resolver import resolver
from app.services.domain_age_service import RegistrationInfo, lookup_registration_details
from app.services.brand_throttle import dns_throttle, rdap_throttle
from app.services.plan_limits import get_limits

log = logging.getLogger(__name__)

_DNS_CONCURRENCY = 25
_RDAP_CONCURRENCY = 5
_CT_POLL_INTERVAL = timedelta(hours=6)     # default; settings.brand_guard_ct_poll_minutes overrides


def _ct_poll_interval() -> timedelta:
    return timedelta(minutes=max(settings.brand_guard_ct_poll_minutes, 15))
_CT_FIRST_LOOKBACK_DAYS = 30

# Statuses an automated rescan may move. Anything an analyst has set
# (confirmed, false_positive, takedown, ...) is never overwritten.
# Registration dates are public facts that don't change: trust a found date for a fortnight (ownership can
# lapse and the name be re-registered), and retry a lookup that produced nothing after a few hours.
_REG_FOUND_TTL = timedelta(days=14)
_REG_MISS_TTL = timedelta(hours=6)

_AUTO_MANAGED = ("new", "monitoring", "triaging", "suspicious")

# (phase, done, total) - called from the scan's own coroutine only (never from
# the concurrent lookup tasks), because it writes through the run's session.
ProgressFn = Callable[[str, int, int], Awaitable[None]]
_CLUSTER_MIN_IDENTITY = 40
_MAX_PIVOT_OWNER_LOOKUPS = 30        # only names that already resemble the brand (by name alone) take part in campaign clustering
_PROGRESS_STEP = 10  # write progress roughly every N completed lookups, not each one


# Subdomain-abuse names taken from certificate logs per scan. Each is one more name to resolve, and many such hosts are
# legitimate customer subdomains at software vendors, so the intake is bounded.
_MAX_SUBDOMAIN_CANDIDATES = 25


def brand_words_for(profile: BrandProfile, primary_domain: str) -> list[str]:
    """The words the brand name is made of, for word-order matching (see discovery.brand_words)."""
    return brand_words(split_registrable(primary_domain)[0], profile.brand_name)


def brand_tokens_for(profile: BrandProfile, primary_domain: str) -> list[str]:
    label = split_registrable(primary_domain)[0]
    tokens = {label}
    collapsed = re.sub(r"[^a-z0-9]", "", (profile.brand_name or "").lower())
    if len(collapsed) >= 3:
        tokens.add(collapsed)
    return sorted(tokens)


# ── Enrichment ───────────────────────────────────────────────────────────────

async def _query(name: str, rtype: str) -> tuple[str, list[str]]:
    """(outcome, values). The outcome is what makes registration observable: NXDOMAIN means the name
    does not exist; NoAnswer means it EXISTS but has no records of that type (registered, nothing set up);
    'error' means DNS could not say (never treated as 'not registered')."""
    try:
        async with dns_throttle.slot():       # process-wide: concurrent scans share one budget of resolver queries
            answers = await resolver.resolve(name, rtype)
        return "answer", sorted(str(r).rstrip(".").lower() for r in answers)
    except dns.resolver.NXDOMAIN:
        return "nxdomain", []
    except dns.resolver.NoAnswer:
        return "noanswer", []
    except dns.exception.DNSException:
        return "error", []


async def _dns_enrich(domain: str) -> dict:
    """Passive DNS facts for a candidate. NS is asked first: most generated permutations don't exist,
    so one NXDOMAIN answer settles them without spending three more queries.
    `registered` is True/False, or None when DNS could not say."""
    ns_state, ns_values = await _query(domain, "NS")
    if ns_state == "nxdomain":
        return {"has_a": False, "has_aaaa": False, "has_mx": False, "registered": False, "ns": [], "a": [], "mx": []}
    (a_state, a_values), (aaaa_state, _), (mx_state, mx_values) = await asyncio.gather(
        _query(domain, "A"), _query(domain, "AAAA"), _query(domain, "MX"),
    )
    states = [ns_state, a_state, aaaa_state, mx_state]
    if any(x in ("answer", "noanswer") for x in states):
        registered: bool | None = True
    elif "nxdomain" in states:
        registered = False
    else:
        registered = None
    return {
        "has_a": a_state == "answer", "has_aaaa": aaaa_state == "answer", "has_mx": mx_state == "answer",
        "registered": registered, "ns": ns_values if ns_state == "answer" else [],
        "a": a_values if a_state == "answer" else [],       # compared with the customer's own addresses (plan 2.0)
        "mx": [m.split()[-1].rstrip(".").lower() for m in mx_values] if mx_state == "answer" else [],   # mail hosts (plan 2.3)
    }


async def _probe_mail(domain: str, mx_hosts: list[str]) -> dict | None:
    """Mail-authentication facts for one candidate (plan 2.3), or None if they could not be read. A module-level
    indirection so tests never touch real DNS."""
    try:
        return await brand_mail_intent.probe_mail(domain, _query, mx_hosts=mx_hosts, mail_provider=_mail_provider_of(mx_hosts))
    except Exception:
        log.debug("Mail probe failed for %s", domain, exc_info=True)
        return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _cached_registrations(db: AsyncSession, apexes: set[str], details_out: dict | None = None) -> dict[str, datetime | None]:
    """Fresh entries from the shared cross-tenant registration cache, keyed by apex domain. A fresh entry
    may hold None (a recent lookup that found nothing): that is a valid answer for a few hours. The registry's extra
    facts (registrar, re-registration, ...) are copied into `details_out` when given."""
    if not apexes:
        return {}
    rows = (await db.execute(
        select(BrandRegistrationCache).where(BrandRegistrationCache.apex_domain.in_(apexes)).execution_options(populate_existing=True)
    )).scalars().all()
    now = _now()
    fresh = [r for r in rows if now - r.checked_at < (_REG_FOUND_TTL if r.found else _REG_MISS_TTL)]
    if details_out is not None:
        details_out.update({r.apex_domain: r.details for r in fresh if r.details})
    return {r.apex_domain: r.registered_at for r in fresh}


async def _store_registrations(db: AsyncSession, results: dict[str, datetime | None], details: dict[str, dict] | None = None) -> None:
    for apex, registered_at in results.items():
        values = {"registered_at": registered_at, "found": registered_at is not None, "source": "rdap", "checked_at": _now(),
                  "details": (details or {}).get(apex)}
        await db.execute(
            pg_insert(BrandRegistrationCache).values(apex_domain=apex, **values)
            .on_conflict_do_update(index_elements=["apex_domain"], set_=values)
        )


async def _registration_date(client: httpx.AsyncClient, domain: str) -> "RegistrationInfo | datetime | None":
    """What the registry says about the domain: a RegistrationInfo (creation date plus registrar, re-registration, ...),
    or None. (A bare datetime is also accepted by the pipeline — see _split_registration — which keeps simple test
    doubles simple.)"""
    try:
        async with rdap_throttle.slot():
            return await lookup_registration_details(client, registrable_domain(domain))
    except Exception:
        log.debug("Registration lookup failed for %s", domain, exc_info=True)
        return None


def _split_registration(value) -> tuple[datetime | None, dict | None]:
    """(registered_at, details) from whatever a registration lookup returned."""
    if value is None:
        return None, None
    if isinstance(value, datetime):
        return value, None
    return value.registered_at, value.details()


async def _probe_hosting(domain: str) -> dict | None:
    """Is the look-alike's www name a CNAME to a free hosting platform? One DNS query. {"cname", "platform"} or None.
    A module-level indirection so tests never touch real DNS."""
    try:
        state, values = await _query(f"www.{domain}", "CNAME")
    except Exception:
        return None
    if state != "answer" or not values:
        return None
    target = values[0].rstrip(".").lower()
    return {"cname": target, "platform": platform_suffix(target)}


_OWNER_CACHE: dict = {}
_OWNER_CACHE_TTL = timedelta(hours=12)


async def _ip_owner(address: str) -> dict | None:
    """Network owner of a server address (ASN registry over DNS), or None. A module-level indirection for tests."""
    hit = _OWNER_CACHE.get(address)
    if hit and hit[0] > _now():
        return hit[1]
    try:
        owner = await brand_fingerprint_service.network_owner(address, _query)
    except Exception:
        return None                                      # a failed lookup is not remembered as "no owner"
    _OWNER_CACHE[address] = (_now() + _OWNER_CACHE_TTL, owner)
    while len(_OWNER_CACHE) > 2000:
        _OWNER_CACHE.pop(min(_OWNER_CACHE, key=lambda k: _OWNER_CACHE[k][0]))
    return owner


# ── CT source ────────────────────────────────────────────────────────────────
# Retries, health tracking and the circuit breaker live in brand_sources.py;
# this is the seam the scan (and tests) call.

async def fetch_ct_candidates(db: AsyncSession, tokens: list[str], since: datetime) -> dict[str, dict]:
    return await sources.fetch_ct_candidates(db, tokens, since)


async def process_stream_hits(db: AsyncSession, profile: BrandProfile, tenant: Tenant, discovered: dict[str, dict]) -> dict:
    """Take names the live certificate stream matched to this brand through the same pipeline as a scan (DNS, registration date,
    mail intent, scoring, alerts), without a full rescan. `discovered` has the shape `_process_discovered` documents."""
    limits = get_limits(tenant.plan)
    domain = await db.get(Domain, profile.domain_id)
    if domain is None or not discovered:
        return {"new_candidates": 0, "alerts": 0, "evaluated": 0}
    summary = await _process_discovered(
        db, profile, domain.name, discovered, max_candidates=limits["brand_guard_max_candidates"], recheck_existing=False,
    )
    try:
        async with db.begin_nested():
            await brand_campaigns.sync(db, profile, brand_tokens_for(profile, domain.name))
            await sync_graph(db, profile)
    except Exception:
        log.exception("Brand Guard campaign or graph update failed after a stream flush")
    await db.commit()
    await brand_notify_dispatch.dispatch_new(db, tenant.id)
    return summary


async def rescore_profile(db: AsyncSession, profile: BrandProfile, domains: set[str] | None = None) -> int:
    """Re-assess candidates from what is ALREADY stored (no network), so a change that only concerns stored facts (suspicion flowing from a
    newly confirmed look-alike, for instance) shows up now instead of at the next scan. Respects a person's decision exactly as a scan does.
    Returns how many candidates were re-assessed."""
    domain = await db.get(Domain, profile.domain_id)
    if domain is None:
        return 0
    primary = domain.name
    tokens = brand_tokens_for(profile, primary)
    official = list(profile.official_domains or [])
    words = brand_words_for(profile, primary)
    baseline = (profile.fingerprint or {}).get("dns")
    stmt = select(BrandCandidate).where(BrandCandidate.profile_id == profile.id)
    now = _now()
    n = 0
    for row in (await db.execute(stmt)).scalars().all():
        if domains is not None and row.candidate_domain not in domains:
            continue
        if row.status in ("customer_owned", "partner", "false_positive", "benign", "ignored", "removed"):
            continue
        enrichment = dict(row.enrichment or {})
        velocity = lifecycle.velocity(row.lifecycle, now) if row.lifecycle else {}
        assessment = assess_candidate(
            row.candidate_domain, primary_domain=primary, official_domains=official, brand_tokens=tokens, discovery_class=row.threat_class,
            enrichment=enrichment, lifecycle=velocity, brand_words=words, baseline=baseline,
        )
        previous = row.status
        _apply_assessment(row, assessment, {"sources": []}, enrichment, now)
        if row.status == "suspicious" and previous != "suspicious" and row.reviewed_by_user_id is None:
            await audit_service.log(
                db, tenant_id=profile.tenant_id, actor=None, action="brand_guard.candidate_flagged_suspicious",
                target_type="brand_candidate", target_id=str(row.id), target_label=row.candidate_domain, before={"status": previous},
                after={"status": "suspicious", "identity_score": round(assessment.identity_score), "abuse_score": round(assessment.abuse_score)},
            )
        await _replace_evidence(db, row, assessment, now, is_new=False)
        if assessment.should_alert and row.alerted_at is None and row.status in _AUTO_MANAGED:
            db.add(Alert(
                id=uuid.uuid4(), domain_id=profile.domain_id, tenant_id=profile.tenant_id,
                severity="critical" if assessment.urgency == "high" else "warn", category="brand",
                title=f"Possible brand impersonation: {row.candidate_domain}",
                body=(f"{row.candidate_domain} resembles {profile.brand_name} (identity {round(assessment.identity_score)}%, abuse likelihood {round(assessment.abuse_score)}%). "
                      + " ".join(s.summary for s in assessment.signals[:3])),
                action="Open Brand Guard, review the evidence, and confirm or dismiss this candidate.",
            ))
            row.alerted_at = now
        n += 1
    await db.flush()
    return n


async def sync_graph(db: AsyncSession, profile: BrandProfile) -> dict:
    """Rebuild the brand's evidence graph, refresh suspicion that flows from known-bad look-alikes, and re-assess the candidates it reached."""
    result = await brand_graph.sync(db, profile)
    if result["changed"]:
        result["rescored"] = await rescore_profile(db, profile)
    return result


async def sync_campaigns(db: AsyncSession, profile: BrandProfile) -> dict:
    """Rebuild one brand's campaigns (after a scan, or after a person's decision changes who belongs in one)."""
    domain = await db.get(Domain, profile.domain_id)
    return await brand_campaigns.sync(db, profile, brand_tokens_for(profile, domain.name if domain else ""))


# ── Core pipeline ────────────────────────────────────────────────────────────

async def _process_discovered(
    db: AsyncSession, profile: BrandProfile, primary_domain: str, discovered: dict[str, dict], *, max_candidates: int | None,
    progress: ProgressFn | None = None, recheck_existing: bool = True,
) -> dict:
    """discovered: {domain: {"class": str|None, "sources": [str], "ct": {"issued_at": ...}|None}}"""
    tokens = brand_tokens_for(profile, primary_domain)
    official = list(profile.official_domains or [])

    existing_rows = (await db.execute(select(BrandCandidate).where(BrandCandidate.profile_id == profile.id))).scalars().all()
    existing = {c.candidate_domain: c for c in existing_rows}
    # Re-check everything already tracked on every pass — that's how a dormant
    # lookalike that goes live (or a removed one that comes back) is noticed.
    # A full scan re-checks everything. A stream flush handles only the names the stream just saw, so a busy hour does not
    # redo DNS for hundreds of look-alikes every few seconds.
    for known, row in existing.items() if recheck_existing else ():
        discovered.setdefault(known, {"class": row.threat_class, "sources": []})

    dns_sem = asyncio.Semaphore(_DNS_CONCURRENCY)

    async def _enrich_dns(domain: str) -> tuple[str, dict]:
        async with dns_sem:
            return domain, await _dns_enrich(domain)

    dns_results: dict[str, dict] = {}
    total = len(discovered)
    if progress:
        await progress("dns", 0, total)
    for n, fut in enumerate(asyncio.as_completed([_enrich_dns(d) for d in discovered]), start=1):
        domain_name, enrichment_result = await fut
        dns_results[domain_name] = enrichment_result
        if progress and n % _PROGRESS_STEP == 0:
            await progress("dns", n, total)

    # Registration dates are stable public facts, so they are fetched as rarely as possible:
    #   1. already on this candidate's record from an earlier scan  -> no lookup at all;
    #   2. in the shared cross-tenant cache (another brand or tenant looked it up recently);
    #   3. otherwise ONE RDAP/WHOIS call, throttled across the whole process.
    targets = [
        d for d, e in dns_results.items()
        if (e.get("has_a") or e.get("has_aaaa") or e.get("has_mx") or e.get("registered") or discovered[d].get("ct") or discovered[d].get("nrd"))
        and not platform_suffix(d)
    ]  # a name under a hosting platform isn't registered, so a registration lookup is meaningless
    on_record: dict[str, datetime] = {}
    stored_dates: dict[str, datetime] = {}
    for d in targets:
        row = existing.get(d)
        known = (row.enrichment or {}) if row is not None else {}
        if known.get("registered_at"):
            stored_dates[d] = lifecycle._dt(known["registered_at"])
            # A candidate first scored before step 2.4 has a date but never had its registry extras (registrar,
            # re-registration) read: it is looked up ONCE more, then flagged so the registry is not asked again.
            if known.get("registration") or known.get("registration_checked"):
                on_record[d] = stored_dates[d]
    need = [d for d in targets if d not in on_record]
    cached_details: dict[str, dict] = {}
    cached = await _cached_registrations(db, {registrable_domain(d) for d in need}, cached_details)
    apexes = sorted({registrable_domain(d) for d in need} - set(cached))

    fresh: dict[str, datetime | None] = {}
    fresh_details: dict[str, dict] = {}
    if apexes:
        rdap_sem = asyncio.Semaphore(_RDAP_CONCURRENCY)
        async with httpx.AsyncClient(timeout=10.0) as client:
            async def _rdap(apex: str) -> None:
                async with rdap_sem:
                    registered_at, details = _split_registration(await _registration_date(client, apex))
                    fresh[apex] = registered_at
                    if details:
                        fresh_details[apex] = details

            if progress:
                await progress("registration", 0, len(apexes))
            for n, fut in enumerate(asyncio.as_completed([_rdap(a) for a in apexes]), start=1):
                await fut
                if progress and n % _PROGRESS_STEP == 0:
                    await progress("registration", n, len(apexes))
        await _store_registrations(db, fresh, fresh_details)

    registered: dict[str, datetime | None] = {}
    reg_details: dict[str, dict] = {}
    checked: set[str] = set()
    for d in targets:
        apex = registrable_domain(d)
        registered[d] = on_record.get(d) or cached.get(apex) or fresh.get(apex) or stored_dates.get(d)
        looked_up = d in on_record or bool(cached.get(apex) or fresh.get(apex))
        if looked_up:
            checked.add(d)
        row = existing.get(d)
        known = (row.enrichment or {}).get("registration") if row is not None else None
        found = known or cached_details.get(apex) or fresh_details.get(apex)     # carried over so a later scan still has them
        if found:
            reg_details[d] = found
    cost = {
        "names_checked": len(discovered), "rdap_targets": len(targets), "rdap_already_on_record": len(on_record),
        "rdap_cache_hits": len({registrable_domain(d) for d in need} & set(cached)), "rdap_lookups": len(apexes),
    }

    # Email intent (plan 2.3): for names that EXIST and are not the customer's own, read SPF/DMARC (and DKIM when the
    # name looks mail-capable). Public DNS, so it costs queries, not requests to anyone; subdomain hosts are skipped
    # because mail authentication lives on the registrable name.
    owned = {registrable_domain(d) for d in [primary_domain, *official]}
    mail_targets = [
        d for d, e in dns_results.items()
        if (e.get("registered") or e.get("has_a") or e.get("has_mx")) and registrable_domain(d) == d
        and not platform_suffix(d) and d not in owned
    ]
    mail_results: dict[str, dict | None] = {}
    hosting_results: dict[str, dict | None] = {}
    if mail_targets:
        mail_sem = asyncio.Semaphore(_DNS_CONCURRENCY)

        async def _mail(d: str) -> tuple[str, dict | None, dict | None]:
            async with mail_sem:
                mail, hosting = await asyncio.gather(_probe_mail(d, dns_results[d].get("mx") or []), _probe_hosting(d))
                return d, mail, hosting

        if progress:
            await progress("mail", 0, len(mail_targets))
        for n, fut in enumerate(asyncio.as_completed([_mail(d) for d in mail_targets]), start=1):
            d, result, hosting = await fut
            mail_results[d] = result
            hosting_results[d] = hosting
            if progress and n % _PROGRESS_STEP == 0:
                await progress("mail", n, len(mail_targets))
    cost["mail_probes"] = len(mail_targets)

    # Campaign clustering (plan 2.4): look-alikes of THIS brand that share a registration batch, a certificate,
    # nameservers or a server. Only names that already resemble the brand take part — clustering the many unrelated
    # registered permutations would be noise — and a cluster touching the customer's own infrastructure scores nothing.
    baseline_dns = (profile.fingerprint or {}).get("dns")
    brand_words_ = brand_words_for(profile, primary_domain)
    members: dict[str, infra.ClusterMember] = {}
    for d in mail_targets:
        name_identity = assess_candidate(
            d, primary_domain=primary_domain, official_domains=official, brand_tokens=tokens, discovery_class=None, enrichment={}, brand_words=brand_words_,
        ).identity_score
        if name_identity < _CLUSTER_MIN_IDENTITY:
            continue
        e = dns_results[d]
        defensive = any(f["signal"] == "defensive_mail_posture" for f in brand_mail_intent.intent_findings(mail_results.get(d)))
        ct_meta = discovered[d].get("ct") or {}
        earlier = (existing[d].enrichment or {}) if d in existing else {}
        members[d] = infra.ClusterMember(
            registered_at=registered.get(d), ns=tuple(e.get("ns") or ()), a=tuple(e.get("a") or ()),
            cert_ids=frozenset(ct_meta.get("cert_ids") or earlier.get("cert_ids") or ()),
            benign=bool(shares_infrastructure(e, baseline_dns)) or defensive, shared_ns=is_shared_nameservers(list(e.get("ns") or [])),
        )
    ip_counts: dict[str, int] = {}
    for m in members.values():
        for ip in set(m.a):
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    # an address counts as shared hosting unless its network owner is positively known and is not a hosting platform
    candidate_ips = [ip for ip, n in ip_counts.items() if n >= infra.MIN_SHARED_SERVER_MEMBERS][:10]
    owners = await asyncio.gather(*[_ip_owner(ip) for ip in candidate_ips]) if candidate_ips else []
    dedicated = {ip for ip, owner in zip(candidate_ips, owners) if owner and not is_shared_hosting(owner.get("name"))}
    cluster_by_domain = infra.cluster_hints(members, shared_hosting_ips=frozenset(ip for ip in ip_counts if ip not in dedicated))
    cost["cluster_members"] = len(members)

    # First-party pivot (plan 2.6): addresses that sent mail as the customer's domain and failed DMARC.
    spoofers = {"ips": {}, "asns": {}}
    spoofer_findings: dict[str, list[dict]] = {}
    spoofers_checked: int | None = None            # None = the DMARC data could not be read this time (never claimed as "checked")
    try:
        domain_ids = [r for r in (await db.execute(
            select(Domain.id).where(Domain.tenant_id == profile.tenant_id, Domain.name.in_([primary_domain, *official])))).scalars().all()]
        spoofers = await brand_firstparty.load_spoofers(db, domain_ids, owner_of=_ip_owner)
        spoofers_checked = len(spoofers["ips"])
        if spoofers["ips"]:
            first_ips = {d: (dns_results[d].get("a") or [None])[0] for d in members}
            wanted = sorted({ip for ip in first_ips.values() if ip})[:_MAX_PIVOT_OWNER_LOOKUPS] if spoofers["asns"] else []
            looked = dict(zip(wanted, await asyncio.gather(*[_ip_owner(ip) for ip in wanted]))) if wanted else {}
            for d, e in dns_results.items():
                found = brand_firstparty.spoofer_pivot_findings(e.get("a"), looked.get(first_ips.get(d)), spoofers)
                if found:
                    spoofer_findings[d] = found
    except Exception:
        log.exception("Brand Guard DMARC pivot failed")
    cost["spoofer_ips"] = len(spoofers["ips"])

    if progress:
        await progress("scoring", 0, len(discovered))

    existing_ids = {r.id for r in existing_rows}
    new_count = alerted = 0
    budget = None if max_candidates is None else max(max_candidates - len(existing), 0)
    funnel = {"new_examined": 0, "unregistered": 0, "plan_cap": 0, "customer_owned": 0, "scored": 0, "by_status": {}}      # for the funnel counters

    for domain, meta in discovered.items():
        enrichment = dict(dns_results[domain])
        if domain not in existing:
            funnel["new_examined"] += 1
        platform = platform_suffix(domain)
        if platform:
            enrichment["platform_suffix"] = platform
        reg = registered.get(domain)
        if reg:
            enrichment["registered_at"] = reg.isoformat()
        if mail_results.get(domain):
            enrichment["mail"] = mail_results[domain]
        if hosting_results.get(domain):
            enrichment["hosting"] = hosting_results[domain]
        if reg_details.get(domain):
            enrichment["registration"] = reg_details[domain]
        if domain in checked:
            enrichment["registration_checked"] = True
        feed_hits = brand_feeds.lookup(domain)
        if feed_hits:
            enrichment["feeds"] = feed_hits
        if cluster_by_domain.get(domain):
            enrichment["clusters"] = cluster_by_domain[domain]
        if meta.get("reported"):
            enrichment["reported_emails"] = meta["reported"]
        if spoofer_findings.get(domain):
            enrichment["spoofer_pivot"] = spoofer_findings[domain]
        if spoofers_checked is not None:
            enrichment["spoofer_ips_checked"] = spoofers_checked
        if meta.get("nrd"):
            enrichment["nrd_listed_on"] = meta["nrd"]["listed_on"]
        ct = meta.get("ct")
        if ct:
            enrichment["ct_hit"] = True
            enrichment["ct_cert_issued_at"] = ct["issued_at"]
            if ct.get("cert_ids"):
                enrichment["cert_ids"] = ct["cert_ids"]
            if ct.get("issuer"):
                enrichment["cert_issuer"] = ct["issuer"]
        elif existing.get(domain) is not None:          # certificate facts seen on an earlier pass are kept, not forgotten
            previous = existing[domain].enrichment or {}
            for key in ("cert_ids", "cert_issuer"):
                if previous.get(key):
                    enrichment[key] = previous[key]

        now = _now()
        resolving = bool(enrichment.get("has_a") or enrichment.get("has_aaaa"))
        mail = bool(enrichment.get("has_mx"))
        registered_flag = True if (enrichment.get("registered") or reg is not None or meta.get("nrd")) else enrichment.get("registered")
        row = existing.get(domain)
        adv = lifecycle.advance(
            row.lifecycle if row is not None else None,
            lifecycle.Observation(at=now, registered=registered_flag, resolving=resolving, mail=mail, certified=bool(ct),
                                  ns=tuple(enrichment.get("ns") or ()), registered_at=reg),
        )
        # A name that doesn't exist and has no other sign of life isn't worth a row. A REGISTERED name is
        # (plan 2.1): a dormant lookalike is exactly the one that may wake up later.
        if row is None and (adv.skipped or adv.state is None or adv.state["stage"] == "unregistered"):
            funnel["unregistered"] += 1
            continue
        if not row and budget is not None and budget <= 0:
            funnel["plan_cap"] += 1
            continue  # plan cap reached for this brand
        velocity = lifecycle.velocity(adv.state, now) if adv.state else {}
        assessment = assess_candidate(
            domain, primary_domain=primary_domain, official_domains=official, brand_tokens=tokens,
            discovery_class=meta.get("class"), enrichment=enrichment, lifecycle=velocity,
            brand_words=brand_words_for(profile, primary_domain),
            baseline=(profile.fingerprint or {}).get("dns"),
        )
        if assessment.suggested_status == "customer_owned" and not row:
            funnel["customer_owned"] += 1
            continue

        if not row:
            row = BrandCandidate(
                id=uuid.uuid4(), tenant_id=profile.tenant_id, profile_id=profile.id,
                candidate_domain=domain, status="new", first_seen_at=now,
            )
            db.add(row)
            await db.flush()          # history rows below reference this candidate
            existing[domain] = row
            new_count += 1
            if budget is not None:
                budget -= 1
        previous_status = row.status
        _apply_assessment(row, assessment, meta, enrichment, now)
        funnel["scored"] += 1
        funnel["by_status"][row.status] = funnel["by_status"].get(row.status, 0) + 1
        if row.status == "suspicious" and previous_status != "suspicious" and row.reviewed_by_user_id is None:
            # An automated verdict that triggers notifications is a security-relevant event: audited with no actor.
            await audit_service.log(
                db, tenant_id=profile.tenant_id, actor=None, action="brand_guard.candidate_flagged_suspicious",
                target_type="brand_candidate", target_id=str(row.id), target_label=domain,
                before={"status": previous_status},
                after={"status": "suspicious", "identity_score": round(assessment.identity_score), "abuse_score": round(assessment.abuse_score)},
            )
        await _replace_evidence(db, row, assessment, now, is_new=row.id not in existing_ids)
        _record_lifecycle(db, row, adv, enrichment, reg, now)
        if brand_cases.is_resurrection(row.status, row.reviewed_by_user_id is not None, row.stage, [e.kind for e in adv.events]):
            # A look-alike a person closed as removed is live again: reopen it for monitoring and say so, once.
            row.status = "monitoring"
            row.resolved_at = None
            db.add(BrandCandidateEvent(id=uuid.uuid4(), candidate_id=row.id, tenant_id=row.tenant_id, kind="resurrected", occurred_at=now, payload={"stage": row.stage}))
            db.add(Alert(
                id=uuid.uuid4(), domain_id=profile.domain_id, tenant_id=profile.tenant_id, severity="critical", category="brand",
                title=f"Removed look-alike is back: {domain}",
                body=f"{domain} was closed as removed but resolves again ({lifecycle.STAGE_LABEL.get(row.stage, row.stage).lower()}).",
                action="Open Brand Guard and reopen the case, or send a fresh takedown.",
            ))
            alerted += 1

        activated = next((e for e in adv.events if e.kind == "activated"), None)
        if activated and assessment.identity_score >= SUSPICIOUS_IDENTITY_THRESHOLD and row.status in _AUTO_MANAGED:
            days = activated.payload.get("days_dormant")
            db.add(Alert(
                id=uuid.uuid4(), domain_id=profile.domain_id, tenant_id=profile.tenant_id,
                severity="critical" if assessment.abuse_score >= SUSPICIOUS_ABUSE_THRESHOLD else "warn", category="brand",
                title=f"Dormant lookalike just went live: {domain}",
                body=(
                    f"{domain} resembles {profile.brand_name} (identity {round(assessment.identity_score)}%). It was registered"
                    + (f" about {days} days ago" if days is not None else "") + f" and sat unused until we noticed it {lifecycle.STAGE_LABEL[activated.payload['to']].lower()} "
                    "between our last two checks."
                ),
                action="Open Brand Guard, review the lifecycle and evidence, and confirm or dismiss this candidate.",
            ))
            row.alerted_at = now
            alerted += 1
        elif assessment.should_alert and row.alerted_at is None and row.status in _AUTO_MANAGED:
            db.add(Alert(
                id=uuid.uuid4(), domain_id=profile.domain_id, tenant_id=profile.tenant_id,
                severity="critical" if assessment.urgency == "high" else "warn", category="brand",
                title=f"Possible brand impersonation: {domain}",
                body=(
                    f"{domain} resembles {profile.brand_name} (identity {round(assessment.identity_score)}%, "
                    f"abuse likelihood {round(assessment.abuse_score)}%). "
                    + " ".join(s.summary for s in assessment.signals[:3])
                ),
                action="Open Brand Guard, review the evidence, and confirm or dismiss this candidate.",
            ))
            row.alerted_at = now
            alerted += 1

    await db.flush()
    await brand_funnel.record_safe(db, profile, "live", entered=funnel["new_examined"], passed=new_count,
                                   detail={"unregistered": funnel["unregistered"], "plan_cap": funnel["plan_cap"], "customer_owned": funnel["customer_owned"]})
    await brand_funnel.record_safe(db, profile, "scored", entered=funnel["scored"], passed=funnel["by_status"].get("suspicious", 0),
                                   detail={f"status_{k}": v for k, v in funnel["by_status"].items()})
    return {"new_candidates": new_count, "alerts": alerted, "evaluated": len(discovered), "cost": cost}


def _record_lifecycle(db: AsyncSession, row: BrandCandidate, adv: "lifecycle.Advance", enrichment: dict, reg: datetime | None, now: datetime) -> None:
    """Persist the new lifecycle state, and the history rows the state machine says are due."""
    if adv.state is None:
        return
    row.lifecycle = adv.state
    row.stage = adv.state["stage"]
    row.stage_changed_at = lifecycle._dt(adv.state.get("stage_changed_at"))
    row.last_observed_at = now
    if adv.write_observation:
        db.add(BrandCandidateObservation(
            id=uuid.uuid4(), candidate_id=row.id, tenant_id=row.tenant_id, observed_at=now, stage=adv.state["stage"],
            registered=adv.state.get("registered"), resolving=adv.state["resolving"], mail=adv.state["mail"],
            certified=adv.state["certified"], ns=adv.state.get("ns") or [], registered_at=reg,
            source="ct" if enrichment.get("ct_hit") else "scan",
        ))
    for ev in adv.events:
        db.add(BrandCandidateEvent(
            id=uuid.uuid4(), candidate_id=row.id, tenant_id=row.tenant_id, kind=ev.kind, occurred_at=ev.observed_at,
            window_start=ev.window_start, payload=ev.payload,
        ))


def _apply_assessment(row: BrandCandidate, a: Assessment, meta: dict, enrichment: dict, now: datetime) -> None:
    row.identity_score = a.identity_score
    row.abuse_score = a.abuse_score
    row.impact = a.impact
    row.urgency = a.urgency
    row.threat_class = a.threat_class or meta.get("class")
    badges = badges_from_signals(a.signals)         # short corroboration chips for the list (popular, parked, on a blocklist...)
    if badges:
        enrichment["badges"] = badges
    row.enrichment = enrichment
    row.last_seen_at = now
    row.last_assessed_at = now
    row.sources = sorted(set(row.sources or []) | set(meta.get("sources", [])))
    if a.suggested_status == "customer_owned":
        row.status = "customer_owned"
    elif row.status in _AUTO_MANAGED and row.reviewed_by_user_id is None:
        row.status = "new" if a.suggested_status == "monitoring" and row.status == "new" else a.suggested_status


async def _replace_evidence(db: AsyncSession, row: BrandCandidate, a: Assessment, now: datetime, *, is_new: bool) -> None:
    # Signals are a pure function of current state, so the latest assessment
    # replaces the old set rather than piling up near-duplicates each scan.
    # (A bulk DELETE, not row.evidence iteration — lazy loads aren't allowed
    # on an async session.)
    if not is_new:
        await db.execute(delete(CandidateEvidence).where(CandidateEvidence.candidate_id == row.id))
    for s in a.signals:
        db.add(CandidateEvidence(
            id=uuid.uuid4(), candidate_id=row.id, signal=s.signal, dimension=s.dimension,
            weight=s.weight, summary=s.summary, data=s.data, observed_at=now,
        ))


# ── Public entry points ──────────────────────────────────────────────────────

async def scan_profile(
    db: AsyncSession, profile: BrandProfile, tenant: Tenant, *, include_ct: bool | None = None, permutations: bool = True,
    progress: ProgressFn | None = None,
) -> dict:
    """Full pass for one brand. Never raises for a single-sensor failure —
    CT errors are recorded on the profile, permutation results still land."""
    limits = get_limits(tenant.plan)
    domain = await db.get(Domain, profile.domain_id)
    if domain is None:
        raise ValueError("Brand profile's primary domain no longer exists")

    if progress:
        await progress("discovering", 0, 0)
    tokens = brand_tokens_for(profile, domain.name)
    discovered: dict[str, dict] = {}
    if permutations:
        discovered = {
            d: {"class": klass, "sources": ["permutation"]}
            for d, klass in generate_candidates(domain.name, profile.brand_name, list(profile.keywords or [])).items()
        }

    # Per-plan budget on names evaluated (each costs DNS queries). The generator orders candidates by how
    # likely an attacker is to register the class, so trimming drops the long tail, not the obvious ones.
    budget = {"limit": limits.get("brand_guard_scan_budget"), "generated": len(discovered), "trimmed": 0}
    if budget["limit"] and len(discovered) > budget["limit"]:
        discovered = dict(list(discovered.items())[: budget["limit"]])
        budget["trimmed"] = budget["generated"] - budget["limit"]

    errors: list[str] = []
    do_ct = limits["brand_guard_ct"] if include_ct is None else (include_ct and limits["brand_guard_ct"])
    if do_ct:
        since = profile.last_ct_poll_at or (datetime.now(timezone.utc) - timedelta(days=_CT_FIRST_LOOKBACK_DAYS))
        if progress:
            await progress("certificates", 0, 0)
        try:
            ct_hits = await fetch_ct_candidates(db, tokens, since)
            official = {registrable_domain(d) for d in [domain.name, *(profile.official_domains or [])]}
            official_names = [domain.name, *(profile.official_domains or [])]
            subdomain_hosts = 0
            for host, ct in ct_hits.items():
                if host in official:
                    continue
                if matches_brand_fingerprint(host, tokens):
                    entry = discovered.setdefault(host, {"class": None, "sources": []})
                    entry["sources"] = sorted(set(entry["sources"]) | {"ct_log"})
                    entry["ct"] = ct
                    continue
                # The registrable name shows no brand, but a certificate was issued for a host that carries the brand in
                # its subdomain (paypal.com.evil.xyz). Tracked under the full host, not the shared registrable name.
                for sub_host, issued_at in (ct.get("hosts") or {}).items():
                    if subdomain_hosts >= _MAX_SUBDOMAIN_CANDIDATES:
                        break
                    if subdomain_brand_abuse(sub_host, tokens, official_names):
                        entry = discovered.setdefault(sub_host, {"class": "subdomain_abuse", "sources": []})
                        entry["sources"] = sorted(set(entry["sources"]) | {"ct_log"})
                        entry["ct"] = {"issued_at": issued_at}
                        subdomain_hosts += 1
            profile.last_ct_poll_at = datetime.now(timezone.utc)
        except sources.SourceUnavailable as e:
            # Non-fatal by design: permutation results still land, and last_ct_poll_at
            # is left alone so the next cycle retries the same window.
            errors.append(f"{e}. Certificate monitoring will retry automatically.")

    # Newly registered domains (plan 2.6b): names nobody guessed, found the day after registration. Same plan gate as CT.
    if do_ct:
        await brand_nrd.refresh(db)
        official_apexes = {registrable_domain(d) for d in [domain.name, *(profile.official_domains or [])]}
        for host, nrd in (await brand_nrd.find(tokens, official_apexes)).items():
            entry = discovered.setdefault(host, {"class": None, "sources": []})
            entry["sources"] = sorted(set(entry["sources"]) | {"new_registration"})
            entry["nrd"] = nrd

    # Reported phish (plan 2.6): domains from emails the customer's own people forwarded. Never fails the scan.
    try:
        leads = brand_firstparty.reported_leads(
            await brand_firstparty.load_reported(db, profile.tenant_id), tokens, [profile.brand_name or ""],
            {registrable_domain(d) for d in [domain.name, *(profile.official_domains or [])]},
        )
        for host, entries in leads.items():
            entry = discovered.setdefault(host, {"class": None, "sources": []})
            entry["sources"] = sorted(set(entry["sources"]) | {"reported_email"})
            entry["reported"] = entries
    except Exception:
        log.exception("Brand Guard reported-email pivot failed")

    # Public abuse feeds for corroboration (plan 2.5): two list downloads at most every 30 minutes, shared by all scans.
    # Done before any scan work is pending, because recording source health commits.
    await brand_feeds.refresh(db)
    found_by: dict[str, int] = {}
    for meta in discovered.values():
        for src in meta.get("sources") or []:
            found_by[f"found_{src}"] = found_by.get(f"found_{src}", 0) + 1
    await brand_funnel.record_safe(db, profile, "discover", entered=len(discovered) + budget["trimmed"], passed=len(discovered),
                                   detail={**found_by, "trimmed_by_plan_budget": budget["trimmed"]})
    summary = await _process_discovered(
        db, profile, domain.name, discovered, max_candidates=limits["brand_guard_max_candidates"], progress=progress,
    )
    try:
        async with db.begin_nested():                      # a campaign problem must never cost the scan its results
            summary["campaigns"] = await brand_campaigns.sync(db, profile, brand_tokens_for(profile, domain.name))
    except Exception:
        log.exception("Brand Guard campaign grouping failed")
    try:
        async with db.begin_nested():
            summary["graph"] = await sync_graph(db, profile)
    except Exception:
        log.exception("Brand Guard evidence graph failed")
    try:
        async with db.begin_nested():
            summary["probes_queued"] = await brand_probe_queue.enqueue_due(db, profile)       # 0 while the kill switch is off
            await brand_probe_queue.enqueue_reference(db, profile)                            # the brand's own page, for comparison (renderer switch)
    except Exception:
        log.exception("Brand Guard probe queueing failed")
    if permutations:
        profile.last_scanned_at = datetime.now(timezone.utc)
    profile.last_scan_error = "; ".join(errors) or None
    await db.commit()
    summary["ct_enabled"] = bool(do_ct)
    summary["budget"] = budget
    summary["errors"] = errors
    return summary


# ── Scan runs (background execution) ─────────────────────────────────────────

# asyncio keeps only weak references to tasks, so a fire-and-forget scan could be
# garbage-collected mid-flight. Holding them here keeps them alive until done.
_TASKS: dict[uuid.UUID, asyncio.Task] = {}


def _session_factory():
    """Fresh DB session for a background run (the request's session is gone by
    the time the scan executes). Indirection exists so tests can substitute one."""
    from app.database import AsyncSessionLocal
    return AsyncSessionLocal()


async def start_scan_run(db: AsyncSession, profile: BrandProfile, *, triggered_by: str) -> tuple[BrandScanRun, bool]:
    """Returns (run, created). If a scan for this brand is already queued or
    running, that run is returned with created=False - never a second one. The
    partial unique index makes that true even if two requests race."""
    async def _active() -> BrandScanRun | None:
        return (await db.execute(
            select(BrandScanRun).where(BrandScanRun.profile_id == profile.id, BrandScanRun.status.in_(SCAN_ACTIVE_STATUSES))
        )).scalar_one_or_none()

    existing = await _active()
    if existing:
        return existing, False
    run = BrandScanRun(id=uuid.uuid4(), tenant_id=profile.tenant_id, profile_id=profile.id, status="queued", triggered_by=triggered_by)
    db.add(run)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        existing = await _active()
        if existing:
            return existing, False
        raise
    return run, True


_SLOTS: dict = {"sem": None, "size": None}


def scan_slot() -> asyncio.Semaphore:
    """Caps how many scans EXECUTE at once across all tenants; the rest wait as 'queued'. (A scan that is
    waiting holds no database session.)"""
    size = max(1, int(settings.brand_guard_max_concurrent_scans))
    if _SLOTS["sem"] is None or _SLOTS["size"] != size:
        _SLOTS["sem"], _SLOTS["size"] = asyncio.Semaphore(size), size
    return _SLOTS["sem"]


async def global_queue_depth(db: AsyncSession) -> int:
    """Scans queued or running, across every tenant — the input to backpressure."""
    return (await db.execute(select(func.count()).select_from(BrandScanRun).where(BrandScanRun.status.in_(SCAN_ACTIVE_STATUSES)))).scalar_one()


async def active_run_for(db: AsyncSession, profile_id: uuid.UUID) -> BrandScanRun | None:
    return (await db.execute(
        select(BrandScanRun).where(BrandScanRun.profile_id == profile_id, BrandScanRun.status.in_(SCAN_ACTIVE_STATUSES))
    )).scalar_one_or_none()


def spawn_scan_run(run_id: uuid.UUID) -> asyncio.Task:
    task = asyncio.create_task(execute_scan_run(run_id))
    _TASKS[run_id] = task
    task.add_done_callback(lambda _t, rid=run_id: _TASKS.pop(rid, None))
    return task


async def wait_for_run(run_id: uuid.UUID) -> None:
    """Await an in-flight run (used by tests; no-op if it already finished)."""
    task = _TASKS.get(run_id)
    if task:
        await task


async def execute_scan_run(run_id: uuid.UUID) -> None:
    async with scan_slot():
        async with _session_factory() as db:
            run = await db.get(BrandScanRun, run_id)
            if run is None:
                return
            profile = await db.get(BrandProfile, run.profile_id)
            tenant = await db.get(Tenant, run.tenant_id)
            if profile is None or tenant is None:
                await _finish_run(db, run_id, "failed", error="Brand profile no longer exists.")
                return
            await _run_scan(db, run, profile, tenant)


async def _finish_run(db: AsyncSession, run_id: uuid.UUID, status: str, *, result: dict | None = None, error: str | None = None) -> None:
    await db.execute(
        update(BrandScanRun).where(BrandScanRun.id == run_id)
        .values(status=status, result=result, error=error, phase=None, finished_at=datetime.now(timezone.utc))
    )
    await db.commit()


def _human_duration(seconds: int) -> str:
    return f"{seconds // 60} minutes" if seconds >= 60 else f"{seconds} seconds"


async def _run_scan(
    db: AsyncSession, run: BrandScanRun, profile: BrandProfile, tenant: Tenant, *,
    include_ct: bool | None = None, permutations: bool = True,
) -> None:
    """Drives one run to a terminal state. Never raises - a failed scan is a
    recorded outcome, not an exception for the caller to handle."""
    run_id = run.id
    run.status, run.started_at, run.phase = "running", datetime.now(timezone.utc), "discovering"
    await db.commit()

    async def progress(phase: str, done: int, total: int) -> None:
        run.phase, run.progress_done, run.progress_total = phase, done, total
        await db.commit()

    try:
        summary = await asyncio.wait_for(
            scan_profile(db, profile, tenant, include_ct=include_ct, permutations=permutations, progress=progress),
            timeout=settings.brand_guard_scan_timeout_seconds,
        )
    except asyncio.TimeoutError:
        await db.rollback()
        log.error("Brand Guard scan timed out: run_id=%s profile_id=%s", run_id, profile.id)
        await _finish_run(db, run_id, "failed", error=f"Scan timed out after {_human_duration(settings.brand_guard_scan_timeout_seconds)}.")
    except Exception as e:
        await db.rollback()
        log.exception("Brand Guard scan failed: run_id=%s profile_id=%s", run_id, profile.id)
        await _finish_run(db, run_id, "failed", error=f"Scan failed unexpectedly ({type(e).__name__}). It will be retried on the next cycle.")
    else:
        await _finish_run(db, run_id, "succeeded", result=summary)
        await brand_notify_dispatch.dispatch_new(db, tenant.id)          # never raises; a channel problem cannot fail a scan


async def recover_interrupted_runs(db: AsyncSession) -> int:
    """Startup hook: a run left queued/running by a previous process is dead
    (the task died with it). Mark it failed so the UI stops showing progress
    and the brand's one-active-run slot is freed."""
    result = await db.execute(
        update(BrandScanRun).where(BrandScanRun.status.in_(SCAN_ACTIVE_STATUSES))
        .values(status="failed", error="Interrupted by a server restart.", phase=None, finished_at=datetime.now(timezone.utc))
    )
    await db.commit()
    return result.rowcount or 0


async def scan_due_profiles(db: AsyncSession) -> int:
    """Scheduler entry point. Due-ness is per plan (starter monthly, pro/msp
    weekly), computed from last_scanned_at like the Tier A impersonation job.
    Each scan runs inline as a recorded run, one brand at a time."""
    now = datetime.now(timezone.utc)
    rows = (await db.execute(
        select(BrandProfile, Tenant)
        .join(Tenant, Tenant.id == BrandProfile.tenant_id)
        .where(BrandProfile.is_active == True)
    )).all()

    # Decide what's due up front and keep only ids: a failed scan rolls the
    # session back, which expires every loaded object, so later iterations must
    # re-load instead of touching stale ORM rows.
    due: list[tuple[uuid.UUID, uuid.UUID, bool]] = []
    for profile, tenant in rows:
        limits = get_limits(tenant.plan)
        if limits["brand_guard_brands"] == 0:
            continue  # plan no longer includes Brand Guard
        full_due = profile.last_scanned_at is None or profile.last_scanned_at < now - timedelta(days=limits["brand_guard_scan_days"])
        ct_due = limits["brand_guard_ct"] and (
            profile.last_ct_poll_at is None or profile.last_ct_poll_at < now - _ct_poll_interval()
        )
        if full_due or ct_due:
            due.append((profile.id, tenant.id, full_due))

    processed = 0
    for profile_id, tenant_id, full_due in due:
        profile = await db.get(BrandProfile, profile_id)
        tenant = await db.get(Tenant, tenant_id)
        if profile is None or tenant is None:
            continue
        run, created = await start_scan_run(db, profile, triggered_by="scheduled")
        if not created:
            continue  # a manual scan for this brand is already running
        await _run_scan(db, run, profile, tenant, include_ct=True, permutations=full_due)
        processed += 1
    return processed
