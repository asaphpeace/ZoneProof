"""
Brand Guard — first-party pivots (plan step 2.6).

Two kinds of evidence only the customer's own account has:

  1. Reported phish. When an employee forwards a suspicious email to the tenant's report address (Phishing module), the
     domains in it are a lead no outside source can match: a human saw this lure, addressed to this company. A reported
     email that names the brand, or links to / comes from a brand look-alike, makes its domains candidates; the email is
     linked from the candidate. Emails the analyst marked "false positive" are ignored.

  2. DMARC reports. The aggregate reports list the server addresses that send mail claiming to be the customer's domain
     and FAIL authentication (spoofers). A candidate whose website or mail server sits on the same address — or, more
     weakly, the same network — as such a spoofer is probably the same operator.

Pure functions plus two small loaders. Weights are hand-set heuristics (Stage 3 calibrates). Privacy: nothing about the
reporter is used or stored here (reporter identity is pseudonymised elsewhere); only the email id, its disposition and
when it arrived are kept on the candidate.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.services import brand_popularity
from app.services.brand_baseline import is_shared_hosting
from app.services.brand_discovery_service import matches_brand_fingerprint, platform_suffix, registrable_domain

REPORTED_WEIGHT = 20.0
REPORTED_CONFIRMED_WEIGHT = 35.0       # the analyst confirmed the email as malicious
REPORTED_IDENTITY_WEIGHT = 45.0        # the email names the brand but the DOMAIN does not (so the name signals say nothing)
SAME_ADDRESS_WEIGHT = 15.0
SAME_NETWORK_WEIGHT = 6.0

LOOKBACK_DAYS = 90
MAX_EMAILS = 300
MAX_HOSTS_PER_SCAN = 40
MAX_EMAILS_PER_HOST = 3
MAX_SPOOFER_IPS = 200
MAX_OWNER_LOOKUPS = 30
MIN_SPOOF_MESSAGES = 1
_MIN_TOKEN_LEN = 4                     # shorter names ("dpd") are matched as whole words only, to avoid ordinary-word hits
_SPOOF_CLASSES = ("spoof", "unauth")


def host_of(url: str) -> str | None:
    try:
        host = (urlsplit(url if "//" in url else "//" + url).hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if not host or "." not in host or ":" in host or all(c.isdigit() or c == "." for c in host):
        return None                    # a raw IP or no host: nothing to register-check
    return host


def mentions_brand(text: str, names: list[str]) -> bool:
    """Does free text name the brand? Whole words only, so 'dpd' is not found inside 'adpdf'."""
    hay = (text or "").lower()
    for name in names:
        n = (name or "").strip().lower()
        if len(n) >= 3 and re.search(r"(?<![a-z0-9])" + re.escape(n) + r"(?![a-z0-9])", hay):
            return True
    return False


def _as_utc(value) -> str | None:
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()
    return str(value) if value else None


def reported_leads(emails, tokens: list[str], brand_names: list[str], official: set[str]) -> dict[str, list[dict]]:
    """{host: [{"email_id", "received_at", "disposition", "mentions_brand", "name_match"}]} for the reported emails that
    concern this brand. `emails` are ReportedEmail rows (or anything with the same attributes)."""
    out: dict[str, list[dict]] = {}
    names = [*brand_names, *[t for t in tokens if len(t) >= _MIN_TOKEN_LEN]]
    for em in emails:
        if (em.disposition or "new") == "false_positive":
            continue
        mention = mentions_brand(" ".join(filter(None, [em.original_subject, em.body_text_excerpt, em.original_from])), names)
        hosts = []
        for url in em.urls_found or []:
            h = host_of(str(url))
            if h:
                hosts.append(h)
        if em.original_from_domain:
            h = host_of(em.original_from_domain)
            if h:
                hosts.append(h)
        for host in dict.fromkeys(hosts):
            apex = registrable_domain(host)
            if apex in official:
                continue
            # a well-known site is not a lead: shorteners, mail providers, big senders. A subdomain on a hosting platform
            # IS one (that is exactly where lures live), so the popularity filter only protects ordinary registered names.
            if not platform_suffix(host) and brand_popularity.rank_of(apex) is not None:
                continue
            name_match = bool(matches_brand_fingerprint(host, tokens))
            if not (mention or name_match):
                continue                # an email about something else, linking somewhere unrelated
            entries = out.setdefault(host, [])
            if len(entries) < MAX_EMAILS_PER_HOST:
                entries.append({"email_id": str(em.id), "received_at": _as_utc(em.received_at), "disposition": em.disposition or "new",
                                "mentions_brand": mention, "name_match": name_match})
    # the most-reported hosts first, then a hard cap, so one chatty campaign cannot flood a scan
    ranked = sorted(out.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:MAX_HOSTS_PER_SCAN]
    return dict(ranked)


def reported_findings(entries: list[dict] | None) -> list[dict]:
    """Scoring evidence for a candidate that appears in reported emails. Two findings at most:
    abuse (a person received this) and identity (the email names the brand while the domain's name does not)."""
    if not entries:
        return []
    confirmed = any(e.get("disposition") == "confirmed_malicious" for e in entries)
    n = len(entries)
    weight = REPORTED_CONFIRMED_WEIGHT if confirmed else REPORTED_WEIGHT
    how = "confirmed as malicious by your team" if confirmed else "forwarded to your report address"
    out = [{"signal": "reported_by_employee", "dimension": "abuse", "weight": weight,
            "data": {"emails": [e["email_id"] for e in entries], "confirmed": confirmed},
            "summary": f"Appeared in {n} suspicious email{'s' if n != 1 else ''} {how} — a real message reached your people from this name."}]
    if any(e.get("mentions_brand") and not e.get("name_match") for e in entries):
        out.append({"signal": "reported_brand_mention", "dimension": "identity", "weight": REPORTED_IDENTITY_WEIGHT,
                    "data": {"emails": [e["email_id"] for e in entries]},
                    "summary": "The reported email names your brand, although this domain's name does not — the name alone would not have flagged it."})
    return out


def spoofer_pivot_findings(candidate_ips, candidate_owner: dict | None, spoofers: dict) -> list[dict]:
    """`spoofers` is load_spoofers' result: {"ips": {ip: {"messages", "owner"}}, "asns": {number: name}}.
    Same address as a sender that failed DMARC for the customer's domain, else (weaker) the same network — unless the
    network is a big shared host or cloud, where it proves nothing."""
    ips = spoofers.get("ips") or {}
    hit = [ip for ip in dict.fromkeys(candidate_ips or []) if ip in ips]
    if hit:
        info = ips[hit[0]]
        shared = is_shared_hosting((info.get("owner") or {}).get("name") or (candidate_owner or {}).get("name"))
        weight = SAME_ADDRESS_WEIGHT * (0.5 if shared else 1.0)
        return [{"signal": "same_network_as_spoofer", "weight": weight,
                 "data": {"match": "address", "ips": hit[:3], "messages": int(info.get("messages", 0)), "shared_host": shared},
                 "summary": f"Its server address ({hit[0]}) also sent {int(info.get('messages', 0)):,} email(s) pretending to be your domain that failed authentication"
                            + (" — but it is a shared host, so the link is weaker." if shared else " — probably the same operator.")}]
    number = (candidate_owner or {}).get("number")
    if number is not None and number in (spoofers.get("asns") or {}) and not is_shared_hosting(candidate_owner.get("name")):
        return [{"signal": "same_network_as_spoofer", "weight": SAME_NETWORK_WEIGHT,
                 "data": {"match": "network", "asn": number, "name": candidate_owner.get("name")},
                 "summary": f"Hosted on the same network ({candidate_owner.get('name') or 'AS' + str(number)}) as a sender that failed authentication pretending to be your domain — a weak link."}]
    return []


async def load_reported(db: AsyncSession, tenant_id, *, now: datetime | None = None) -> list:
    from app.models.reported_email import ReportedEmail
    since = (now or datetime.now(timezone.utc)) - timedelta(days=LOOKBACK_DAYS)
    rows = await db.execute(
        select(ReportedEmail).where(ReportedEmail.tenant_id == tenant_id, ReportedEmail.received_at >= since)
        .order_by(ReportedEmail.received_at.desc()).limit(MAX_EMAILS)
    )
    return list(rows.scalars().all())


async def load_spoofers(db: AsyncSession, domain_ids: list, *, owner_of, now: datetime | None = None) -> dict:
    """Server addresses that sent mail as the customer's domain and failed authentication in the last LOOKBACK_DAYS,
    from the DMARC rollups. `owner_of(ip)` -> {"number", "name"} | None (an ASN lookup, injected so tests need no network)."""
    from app.models.dmarc_report import DmarcAggregate
    if not domain_ids:
        return {"ips": {}, "asns": {}}
    since = (now or datetime.now(timezone.utc)) - timedelta(days=LOOKBACK_DAYS)
    rows = (await db.execute(
        select(DmarcAggregate.source_ip, DmarcAggregate.fail_count, DmarcAggregate.total_count)
        .where(DmarcAggregate.domain_id.in_(domain_ids), DmarcAggregate.classification.in_(_SPOOF_CLASSES),
               DmarcAggregate.period_end >= since)
    )).all()
    totals: dict[str, int] = {}
    for ip, fail, total in rows:
        totals[ip] = totals.get(ip, 0) + int(fail or total or 0)
    busiest = sorted((ip for ip, n in totals.items() if n >= MIN_SPOOF_MESSAGES), key=lambda ip: -totals[ip])[:MAX_SPOOFER_IPS]
    ips: dict[str, dict] = {}
    asns: dict[int, str] = {}
    for n, ip in enumerate(busiest):
        owner = None
        if n < MAX_OWNER_LOOKUPS:               # address matching covers all of them; network lookups only the busiest
            try:
                owner = await owner_of(ip)
            except Exception:
                owner = None
        ips[ip] = {"messages": totals[ip], "owner": owner}
        if owner and owner.get("number") is not None and not is_shared_hosting(owner.get("name")):
            asns[int(owner["number"])] = owner.get("name") or ""
    return {"ips": ips, "asns": asns}
