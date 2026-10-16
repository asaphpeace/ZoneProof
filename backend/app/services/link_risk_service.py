"""
Composite link risk score for Real-Threat Reports (Phishing Simulation
roadmap Phase 32, extending Phase 26's ReportedEmail/urls_found pipeline).

Combines a known-threat lookup with domain-age, TLD-reputation, and
URL-structure signals into a single 0-100 score, a 3-tier plain-language
verdict (likely_safe / uncertain / likely_dangerous), and a one-sentence
explanation naming the dominant reason — never raw scan data. This
product's whole positioning is "give a clear verdict," matching the
Sentinel Score / Human Risk Score precedent elsewhere in this codebase.

Two vendor decisions, settled by real research before this was written,
not assumption:
  - Google's Safe Browsing API's own ToS prohibits commercial-product
    use. Web Risk API is Google's commercially-licensed sibling product,
    built on the same threat-list data, with a 100k-calls/month free tier
    — effectively free at this product's per-report-triage volume.
  - RDAP (not legacy WHOIS) is the correct approach for domain age on
    every TLD except one: `.za` (this product's own home TLD — .co.za/
    .org.za/.net.za/.web.za etc.) has NO RDAP coverage at all, confirmed
    by parsing the live IANA bootstrap file. Those domains fall back to
    a raw-socket legacy WHOIS query against whois.registry.net.za,
    mirroring cert_service.py's existing asyncio.open_connection pattern.

Critical honesty constraint, load-bearing for the UI copy this feeds:
Web Risk is a REACTIVE known-bad-list lookup, not an active scan. A
"clean" result means "not on Google's known-threat list," never "verified
safe" — a brand-new attacker domain will very plausibly come back clean.
No explanation string produced here may say "safe" or "verified" for a
clean result; the honest phrasing is "no known risk signals found."

Caching split, deliberately asymmetric:
  - Domain age is a stable fact — cached per apex domain for
    _DOMAIN_AGE_CACHE_TTL_DAYS (ownership can transfer, so not forever).
  - Web Risk's threat lists can flip within hours. DomainReputationCache
    still stores the last-known verdict for display/debugging value, but
    it is NEVER treated as authoritative for a fresh score — every real
    scoring pass calls Web Risk live per exact URL regardless of that
    row's age.

Follows breach_monitoring_service.py's house pattern for an optional
third-party API: an unset key degrades to "not checked" (never a crash),
and no single URL's lookup failure aborts the rest of a batch.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.domain_reputation_cache import DomainReputationCache
from app.models.reported_email import ReportedEmail

_log = logging.getLogger(__name__)

_WEB_RISK_URL = "https://webrisk.googleapis.com/v1/uris:search"
_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_ZA_WHOIS_HOST = "whois.registry.net.za"
_ZA_WHOIS_PORT = 43

_DOMAIN_AGE_CACHE_TTL_DAYS = 60
_RDAP_BOOTSTRAP_TTL_DAYS = 7

# Interisle "Phishing Landscape 2025" + Spamhaus Domain Reputation Update
# (Apr-Sept 2025): .xyz/.top show measurably elevated abuse (94%/103%
# registration growth correlating with abuse volume). .tk/.ga/.cf are
# DELIBERATELY weak here, not the legacy heavy penalty older threat-intel
# advice would suggest — Freenom (who ran them as free ccTLDs) lost ICANN
# accreditation Nov 2023 and exited the domain business Feb 2024; ~12.6M
# of those domains went inactive and malicious volume on them dropped
# ~87%. .ml is a partial exception (independent registry now, still
# active) but still not a strong signal. Smallest-weighted signal in the
# composite score on purpose — noisy, secondary, small table.
_TLD_REPUTATION_DELTA: dict[str, int] = {"xyz": -8, "top": -8, "ml": -3, "tk": -2, "ga": -2, "cf": -2}

_KNOWN_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy",
})

# Curated, not exhaustive — a small watchlist of commonly-impersonated
# brand names, used only to flag a mismatch between "this hostname
# mentions a trusted name" and "this hostname IS that trusted name's own
# domain." False negatives (a real brand not in this list) just mean no
# bonus signal, never a false accusation.
_BRAND_KEYWORDS = frozenset({
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
    "dhl", "fedex", "office365", "outlook",
})

# .za has no RDAP support at all. A handful of extra multi-label public
# suffixes are hardcoded rather than pulling in a public-suffix-list
# dependency — same "small explicit table, not a comprehensive database"
# call already made for TLD reputation above. Anything not in this set
# falls back to the plain last-two-labels rule.
_MULTI_LABEL_SUFFIXES = frozenset({"co.za", "org.za", "net.za", "web.za", "gov.za", "ac.za"})

_ZA_CREATION_DATE_RE = re.compile(r"Creation Date:\s*(\d{4}-\d{2}-\d{2})", re.I)

_rdap_bootstrap_cache: dict[str, str] | None = None
_rdap_bootstrap_fetched_at: datetime | None = None


# ---------------------------------------------------------------------
# Pure functions — no network, fully unit-testable
# ---------------------------------------------------------------------

def _registrable_domain(hostname: str) -> str:
    host = (hostname or "").strip().lower().rstrip(".")
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def compute_url_structure_heuristics(url: str) -> dict:
    """Independent, additive structural red flags — each one is a real,
    well-documented phishing technique, not a stylistic guess."""
    flags = {
        "is_ip_literal": False, "is_punycode": False, "has_userinfo_trick": False,
        "subdomain_depth": 0, "brand_keyword_hit": None, "is_known_shortener": False,
    }
    reasons: list[tuple[int, str]] = []

    try:
        split = urlsplit(url)
    except ValueError:
        return {"delta": 0, "reasons": reasons, **flags}

    hostname = (split.hostname or "").lower()
    if not hostname:
        return {"delta": 0, "reasons": reasons, **flags}

    if split.username is not None:
        flags["has_userinfo_trick"] = True
        reasons.append((20, "The link hides its real destination behind an '@' after what looks like a trusted address."))

    try:
        ipaddress.ip_address(hostname)
        flags["is_ip_literal"] = True
        reasons.append((15, "The link points to a raw IP address instead of a normal domain name."))
    except ValueError:
        pass

    labels = hostname.split(".")
    if any(label.startswith("xn--") for label in labels):
        flags["is_punycode"] = True
        reasons.append((12, "The domain uses encoded international characters, a technique sometimes used to disguise a look-alike of a trusted brand."))

    apex = _registrable_domain(hostname)
    apex_labels = apex.split(".")
    subdomain_labels = labels[: len(labels) - len(apex_labels)] if len(labels) > len(apex_labels) else []
    flags["subdomain_depth"] = len(subdomain_labels)
    if flags["subdomain_depth"] > 3:
        reasons.append((8, "The link uses an unusually long chain of subdomains, a common way to bury a fake address."))

    if not flags["is_ip_literal"]:
        apex_root = apex_labels[0] if apex_labels else ""
        for keyword in _BRAND_KEYWORDS:
            if keyword in hostname and keyword != apex_root:
                flags["brand_keyword_hit"] = keyword
                reasons.append((15, f"The domain mentions '{keyword}' but isn't {keyword}'s real domain — a common impersonation pattern."))
                break

    if apex in _KNOWN_SHORTENERS:
        flags["is_known_shortener"] = True
        reasons.append((10, "This is a link-shortening service — the real destination can't be seen without following it."))

    delta = -sum(magnitude for magnitude, _ in reasons)
    return {"delta": delta, "reasons": reasons, **flags}


def _domain_age_score_delta(registered_at: datetime | None, now: datetime) -> tuple[int, str | None]:
    # Never penalize what can't be determined — matches this codebase's
    # existing None-over-fabrication discipline elsewhere (e.g.
    # compute_tenant_human_risk_score's treatment of insufficient data).
    if registered_at is None:
        return 0, None
    age_days = max(0, (now - registered_at).days)
    if age_days < 7:
        return -40, "This domain was registered within the last week — brand-new domains are frequently used in phishing attacks."
    if age_days < 30:
        return -25, "This domain was registered less than a month ago, a common pattern for short-lived phishing campaigns."
    if age_days < 90:
        return -10, "This domain was registered within the last few months and is still relatively new."
    if age_days < 365:
        return -3, "This domain has been registered for under a year."
    return 0, None


def _tld_reputation_delta(apex_domain: str) -> tuple[int, str | None]:
    labels = apex_domain.split(".")
    tld = labels[-1] if labels else ""
    delta = _TLD_REPUTATION_DELTA.get(tld)
    if not delta:
        return 0, None
    return delta, f"This domain's .{tld} extension has a measurably higher phishing rate than most TLDs."


def _score_to_grade(score: float) -> str:
    # Mirrors app/routers/phishing.py's own _score_to_grade exactly — same
    # thresholds, kept as a small local copy rather than a cross-module
    # import, following that function's own established precedent.
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


def _verdict_from_score(score: int) -> str:
    if score >= 70:
        return "likely_safe"
    if score >= 40:
        return "uncertain"
    return "likely_dangerous"


def compute_composite_score(
    *, structure: dict, domain_age_delta: int, domain_age_reason: str | None,
    tld_delta: int, tld_reason: str | None,
    web_risk_checked: bool, web_risk_matched: bool, web_risk_threat_types: list[str],
) -> dict:
    score = max(0, min(100, 100 + structure["delta"] + domain_age_delta + tld_delta))

    if web_risk_matched:
        # A confirmed match floors the verdict regardless of how clean
        # everything else looks — a real known-bad signal shouldn't be
        # diluted by soft heuristics.
        score = min(score, 15)
        kind = "phishing" if "SOCIAL_ENGINEERING" in web_risk_threat_types else "malware"
        explanation = f"Google's threat intelligence has flagged this link as a known {kind} site."
    else:
        candidates: list[tuple[int, str]] = list(structure["reasons"])
        if domain_age_reason:
            candidates.append((abs(domain_age_delta), domain_age_reason))
        if tld_reason:
            candidates.append((abs(tld_delta), tld_reason))
        if candidates:
            candidates.sort(key=lambda c: c[0], reverse=True)
            explanation = candidates[0][1]
        else:
            # Never "safe" or "verified" — a clean Web Risk result only
            # means "not on Google's known-threat list," not a guarantee.
            explanation = "No known risk signals found for this link."

    return {"score": score, "verdict": _verdict_from_score(score), "grade": _score_to_grade(score), "explanation": explanation}


# ---------------------------------------------------------------------
# Network functions — each degrades to an honest "unknown" on failure,
# never raises out to a caller.
# ---------------------------------------------------------------------

async def _web_risk_lookup(client: httpx.AsyncClient, url: str) -> dict | None:
    if not settings.web_risk_api_key:
        return None
    try:
        resp = await client.get(
            _WEB_RISK_URL,
            params={"uri": url, "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "key": settings.web_risk_api_key},
        )
        resp.raise_for_status()
        body = resp.json()
    except httpx.HTTPError as e:
        _log.warning("Web Risk lookup failed for url=%s: %s", url, e)
        return None
    threat = body.get("threat")
    if not threat:
        return {"matched": False, "threat_types": []}
    return {"matched": True, "threat_types": threat.get("threatTypes", [])}


async def _rdap_bootstrap(client: httpx.AsyncClient) -> dict[str, str]:
    global _rdap_bootstrap_cache, _rdap_bootstrap_fetched_at
    now = datetime.now(timezone.utc)
    if _rdap_bootstrap_cache is not None and _rdap_bootstrap_fetched_at is not None:
        if (now - _rdap_bootstrap_fetched_at).days < _RDAP_BOOTSTRAP_TTL_DAYS:
            return _rdap_bootstrap_cache
    try:
        resp = await client.get(_RDAP_BOOTSTRAP_URL)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as e:
        _log.warning("RDAP bootstrap fetch failed: %s", e)
        return _rdap_bootstrap_cache or {}

    mapping: dict[str, str] = {}
    for entry in data.get("services", []):
        if len(entry) < 2:
            continue
        tlds, bases = entry[0], entry[1]
        base = bases[0] if bases else None
        if not base:
            continue
        for tld in tlds:
            mapping[tld.lower()] = base.rstrip("/")
    _rdap_bootstrap_cache = mapping
    _rdap_bootstrap_fetched_at = now
    return mapping


async def _lookup_domain_age_rdap(client: httpx.AsyncClient, apex_domain: str) -> datetime | None:
    tld = apex_domain.rsplit(".", 1)[-1]
    bootstrap = await _rdap_bootstrap(client)
    base = bootstrap.get(tld)
    if not base:
        # Not fatal — some TLDs with a working RDAP endpoint are missing
        # from the bootstrap file (e.g. .io); a hardcoded override map is
        # over-engineering for v1. Falls through to "age unknown."
        _log.info("No RDAP endpoint known for TLD=%s (apex_domain=%s) — domain age left unknown", tld, apex_domain)
        return None
    try:
        resp = await client.get(f"{base}/domain/{apex_domain}")
    except httpx.HTTPError as e:
        _log.info("RDAP lookup failed for apex_domain=%s: %s", apex_domain, e)
        return None
    if resp.status_code != 200:
        return None
    data = resp.json()
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            date_str = event.get("eventDate")
            if date_str:
                try:
                    return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                except ValueError:
                    return None
    return None


async def _lookup_domain_age_za_whois(apex_domain: str) -> datetime | None:
    """.za has no RDAP support at all — confirmed by parsing the live
    IANA bootstrap file. Raw-socket legacy WHOIS, mirroring
    cert_service.py's exact asyncio.open_connection/asyncio.wait_for
    pattern (needed because a hanging DNS resolve or connect can blow
    past a socket's own internal timeout otherwise)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(_ZA_WHOIS_HOST, _ZA_WHOIS_PORT), timeout=10
        )
        writer.write(f"{apex_domain}\r\n".encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(-1), timeout=10)
        writer.close()
        await writer.wait_closed()
    except (OSError, asyncio.TimeoutError) as e:
        _log.info("za WHOIS lookup failed for apex_domain=%s: %s", apex_domain, e)
        return None

    text = raw.decode(errors="replace")
    m = _ZA_CREATION_DATE_RE.search(text)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


async def _lookup_domain_age(client: httpx.AsyncClient, apex_domain: str) -> tuple[datetime | None, str | None]:
    if apex_domain.endswith(".za"):
        registered_at = await _lookup_domain_age_za_whois(apex_domain)
        return registered_at, ("za_whois" if registered_at else None)
    registered_at = await _lookup_domain_age_rdap(client, apex_domain)
    return registered_at, ("rdap" if registered_at else None)


async def _get_domain_cache_entry(
    db: AsyncSession, client: httpx.AsyncClient, apex_domain: str, *, force_refresh: bool = False,
) -> DomainReputationCache:
    result = await db.execute(select(DomainReputationCache).where(DomainReputationCache.apex_domain == apex_domain))
    entry = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)

    needs_refresh = (
        force_refresh or entry is None or entry.domain_age_checked_at is None
        or (now - entry.domain_age_checked_at).days >= _DOMAIN_AGE_CACHE_TTL_DAYS
    )
    if not needs_refresh:
        return entry

    registered_at, source = await _lookup_domain_age(client, apex_domain)
    tld_delta, _ = _tld_reputation_delta(apex_domain)

    if entry is None:
        entry = DomainReputationCache(id=uuid.uuid4(), apex_domain=apex_domain)
        db.add(entry)
    entry.domain_registered_at = registered_at
    entry.domain_age_source = source
    entry.domain_age_checked_at = now
    entry.tld_reputation_delta = tld_delta
    await db.flush()
    return entry


async def score_url(db: AsyncSession, client: httpx.AsyncClient, url: str, *, force_refresh: bool = False) -> dict:
    """Scores one URL. Any unexpected failure is caught here rather than
    aborting the whole batch — the caller always gets one honest entry
    per URL, never a partial/missing result."""
    try:
        split = urlsplit(url)
        hostname = (split.hostname or "").lower()
        if not hostname:
            raise ValueError("URL has no hostname")

        structure = compute_url_structure_heuristics(url)

        web_risk = await _web_risk_lookup(client, url)
        web_risk_checked = web_risk is not None
        web_risk_matched = bool(web_risk and web_risk["matched"])
        web_risk_threat_types = web_risk["threat_types"] if web_risk else []

        if structure["is_ip_literal"]:
            # An IP literal has no real "domain" — treating its octets as
            # one (e.g. "192.0.2.5" -> a fake apex "2.5") would trigger a
            # pointless RDAP lookup and pollute the cache with a garbage
            # row. Scored purely on the structural signal instead.
            domain_age_delta, domain_age_reason = 0, None
            tld_delta, tld_reason = 0, None
            domain_age_days, domain_age_source, tld_for_signals = None, None, None
        else:
            apex_domain = _registrable_domain(hostname)
            cache_entry = await _get_domain_cache_entry(db, client, apex_domain, force_refresh=force_refresh)
            if web_risk_checked:
                cache_entry.web_risk_last_verdict = "match" if web_risk_matched else "clean"
                cache_entry.web_risk_checked_at = datetime.now(timezone.utc)

            now = datetime.now(timezone.utc)
            domain_age_delta, domain_age_reason = _domain_age_score_delta(cache_entry.domain_registered_at, now)
            tld_delta, tld_reason = _tld_reputation_delta(apex_domain)
            domain_age_days = (now - cache_entry.domain_registered_at).days if cache_entry.domain_registered_at else None
            domain_age_source = cache_entry.domain_age_source
            tld_for_signals = apex_domain.rsplit(".", 1)[-1]

        composite = compute_composite_score(
            structure=structure, domain_age_delta=domain_age_delta, domain_age_reason=domain_age_reason,
            tld_delta=tld_delta, tld_reason=tld_reason,
            web_risk_checked=web_risk_checked, web_risk_matched=web_risk_matched,
            web_risk_threat_types=web_risk_threat_types,
        )

        return {
            "url": url, "score": composite["score"], "verdict": composite["verdict"], "grade": composite["grade"],
            "explanation": composite["explanation"],
            "signals": {
                "web_risk": {"checked": web_risk_checked, "matched": web_risk_matched, "threat_types": web_risk_threat_types},
                "domain_age_days": domain_age_days,
                "domain_age_source": domain_age_source,
                "tld": tld_for_signals,
                "structure": {k: v for k, v in structure.items() if k not in ("delta", "reasons")},
            },
        }
    except Exception as e:
        _log.warning("Scoring failed for url=%s: %s", url, e)
        return {
            "url": url, "score": None, "verdict": "uncertain", "grade": None,
            "explanation": "Could not be scored — a lookup failed. Try re-scanning.",
            "signals": {},
        }


async def score_urls(db: AsyncSession, urls: list[str], *, force_refresh: bool = False) -> list[dict]:
    """Scores a batch. One URL's failure (handled inside score_url) never
    aborts the others. Does not commit — the caller owns the transaction
    boundary (ingestion commits the whole report; the rescan endpoint
    commits once after audit-logging)."""
    results = []
    async with httpx.AsyncClient(timeout=20.0) as client:
        for url in urls:
            results.append(await score_url(db, client, url, force_refresh=force_refresh))
    return results


async def score_report_urls_best_effort(db: AsyncSession, report: ReportedEmail, *, force_refresh: bool = False) -> None:
    """The ingestion/rescan entry point. Must never block report creation
    or a rescan request on an external API failure — on any error, logs
    and returns without touching report.url_risk (leaves it at None or
    stale, which is honest and rescanable)."""
    if not report.urls_found:
        return
    try:
        results = await score_urls(db, report.urls_found, force_refresh=force_refresh)
    except Exception as e:
        _log.warning("Link risk scoring failed for report_id=%s: %s", report.id, e)
        return
    report.url_risk = results
    report.url_risk_scored_at = datetime.now(timezone.utc)
    db.add(report)
