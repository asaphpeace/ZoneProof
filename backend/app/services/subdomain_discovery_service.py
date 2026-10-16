"""
Passive subdomain discovery — Part 1 of GUIDED_ONBOARDING_PLAN.md (folded in
alongside DNS hand-holding). Three passive sources, ranked by signal:

  1. Sentinel's own ingested DMARC data — zero external calls, highest signal
     for "does this subdomain actually send mail" (the question that matters
     for deciding whether it needs its own DMARC alignment attention).
  2. Certificate Transparency logs via crt.sh — free, no API key, but can be
     slow or return 502 under load; degrades to an empty result, never
     blocks or raises.
  3. SAN fields on certificates Sentinel already probed (cert_service.py).

All three are safe to run even before ownership verification — they only
read public/already-owned data.

A fourth source, active DNS probing, is implemented here too but gated
hard: it only ever runs for ownership-verified domains, and is never wired
into the public no-auth /scan endpoint. Active probing on an unverified
domain would turn this into a free subdomain-enumeration tool against a
domain the requester doesn't necessarily own — the plan is explicit that
this distinction matters. Two checks, both deliberately small:
  - a short, curated wordlist of email-relevant candidates (not a generic
    brute-force — scoped to what's actually relevant to email security)
  - a one-line AXFR (zone transfer) attempt, which almost always fails on
    a correctly configured server and is free/instant either way
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from dataclasses import dataclass, field

import dns.exception
import dns.query
import dns.zone
import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Domain, DmarcAggregate, SslCert
from app.services.dns_resolver import resolver

log = logging.getLogger(__name__)

_CT_TIMEOUT = 15.0
_WILDCARD_PREFIX = re.compile(r"^\*\.")

# Deliberately bounded and scoped to email security — not a generic
# subdomain brute-force wordlist. Names are grouped by what they are for, and
# every one of them is something a mail or messaging setup commonly uses.
# Each candidate gets one A/CNAME lookup. Only run for ownership-verified
# domains (see discover_subdomains_with_status).
_ACTIVE_CANDIDATES = [
    # mailbox and webmail
    "mail", "mail1", "mail2", "webmail", "owa", "exchange", "ecp", "ews", "zimbra", "roundcube",
    # mail transport
    "smtp", "smtp1", "smtp2", "smtps", "mx", "mx1", "mx2", "mx3", "mailgw", "gateway", "relay",
    "mailrelay", "outbound", "inbound", "imap", "imaps", "pop", "pop3", "mailer",
    # client configuration and policy
    "autodiscover", "autoconfig", "mta-sts", "lyncdiscover", "activesync",
    # bulk, transactional and tracking senders
    "email", "em", "e", "bounce", "bounces", "news", "newsletter", "marketing", "campaign",
    "notify", "notifications", "noreply", "alerts", "mg", "sg", "ses", "postmark", "list", "lists",
    "go", "track", "click", "links",
    # identity and remote access that mail setups depend on
    "adfs", "sts", "fs", "sso", "auth", "vpn", "remote", "sip", "cpanel",
]
_ACTIVE_CONCURRENCY = 10
_AXFR_TIMEOUT = 5.0
# SRV service names that point email clients at servers.
_SRV_NAMES = ["_autodiscover._tcp", "_submission._tcp", "_submissions._tcp", "_imap._tcp", "_imaps._tcp", "_pop3s._tcp"]
_SPF_LOOKUP_BUDGET = 10   # RFC 7208 limit on DNS-querying terms


@dataclass
class DiscoveredSubdomain:
    hostname: str
    sources: list[str] = field(default_factory=list)
    sends_mail: bool = False
    mail_volume: int = 0
    already_monitored: bool = False


_HOSTNAME_RE = re.compile(r"^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")


def _is_hostname(value: str) -> bool:
    """A DNS name, not an email address or free text (certificates carry both)."""
    return bool(_HOSTNAME_RE.match(value)) and len(value) <= 253


def _is_subdomain(hostname: str, root: str) -> bool:
    hostname = hostname.strip().lower().rstrip(".")
    root = root.strip().lower()
    return hostname.endswith("." + root) and hostname != root and _is_hostname(hostname)


async def _from_dmarc(db: AsyncSession, domain: Domain) -> dict[str, int]:
    """hostname -> total mail volume, for header_from values that are subdomains."""
    stmt = (
        select(DmarcAggregate.header_from, func.sum(DmarcAggregate.total_count))
        .where(DmarcAggregate.domain_id == domain.id)
        .group_by(DmarcAggregate.header_from)
    )
    rows = (await db.execute(stmt)).all()
    out: dict[str, int] = {}
    for header_from, total in rows:
        if header_from and _is_subdomain(header_from, domain.name):
            out[header_from.strip().lower()] = int(total or 0)
    return out


async def _from_certs(db: AsyncSession, domain: Domain) -> set[str]:
    """Sibling hostnames from SAN fields on certs Sentinel already probed."""
    stmt = select(SslCert.san).where(SslCert.domain_id == domain.id, SslCert.san.is_not(None))
    rows = (await db.execute(stmt)).scalars().all()
    out: set[str] = set()
    for san_field in rows:
        for entry in (san_field or "").split(","):
            entry = entry.strip().lower()
            if entry and not _WILDCARD_PREFIX.match(entry) and _is_subdomain(entry, domain.name):
                out.add(entry)
    return out


_CT_ATTEMPTS = 2
_CT_CACHE_TTL = 6 * 3600
# domain -> (stored_at, hostnames). Only successful lookups are stored, so a
# timeout is retried on the next scan instead of being remembered as "none".
_ct_cache: dict[str, tuple[float, set[str]]] = {}


async def _from_ct_logs_with_status(domain_name: str) -> tuple[set[str], str]:
    """
    crt.sh JSON endpoint. No official rate limit, but response times of
    3-30s and occasional 502s under load are normal. Retries once, then gives
    up without raising. The status says which of ok | cached | timed_out |
    failed happened, so the caller can tell "none found" from "could not ask".
    """
    key = domain_name.strip().lower()
    cached = _ct_cache.get(key)
    if cached and time.monotonic() - cached[0] < _CT_CACHE_TTL:
        return set(cached[1]), "cached"

    url = f"https://crt.sh/?q=%25.{domain_name}&output=json"
    data = None
    status = "failed"
    for attempt in range(_CT_ATTEMPTS):
        try:
            async with httpx.AsyncClient(timeout=_CT_TIMEOUT) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
            break
        except httpx.TimeoutException:
            status = "timed_out"
        except Exception:
            status = "failed"
        if attempt + 1 < _CT_ATTEMPTS:
            await asyncio.sleep(1.0)

    if data is None:
        log.warning("CT log lookup %s for %s after %d attempts", status, domain_name, _CT_ATTEMPTS)
        return set(), status

    out: set[str] = set()
    for entry in data:
        for raw in (entry.get("name_value") or "").split("\n"):
            host = raw.strip().lower()
            if host and not _WILDCARD_PREFIX.match(host) and _is_subdomain(host, domain_name):
                out.add(host)
    _ct_cache[key] = (time.monotonic(), set(out))
    return out, "ok"


async def _from_ct_logs(domain_name: str) -> set[str]:
    """Hostnames only; kept for callers that do not need the source status."""
    hosts, _ = await _from_ct_logs_with_status(domain_name)
    return hosts


async def _answers(host: str, rdtype: str) -> frozenset[str] | None:
    """The answer set for one name and type, or None when it does not resolve."""
    try:
        res = await resolver.resolve(host, rdtype)
    except dns.exception.DNSException:
        return None
    return frozenset(r.to_text().lower() for r in res)


async def _wildcard_profile(domain_name: str) -> frozenset[str]:
    """
    Answers a random, certainly-unused label gets. If the zone has a wildcard
    record, every guess "resolves" to the same thing and means nothing. An
    empty set means no wildcard was found.
    """
    probe = f"zp-{uuid.uuid4().hex[:12]}.{domain_name}"
    seen: set[str] = set()
    for rdtype in ("A", "AAAA", "CNAME"):
        got = await _answers(probe, rdtype)
        if got:
            seen |= got
    return frozenset(seen)


async def _probe_active(domain_name: str) -> tuple[set[str], bool]:
    """
    One A/CNAME lookup per curated candidate, bounded concurrency, and a
    wildcard check so a wildcard zone does not report every guess as found.
    Returns (hostnames, wildcard_detected). Only called for ownership-
    verified domains; see discover_subdomains_with_status()'s allow_active gate.
    """
    wildcard = await _wildcard_profile(domain_name)
    gate = asyncio.Semaphore(_ACTIVE_CONCURRENCY)
    out: set[str] = set()

    async def _check(candidate: str) -> None:
        host = f"{candidate}.{domain_name}"
        async with gate:
            for rdtype in ("A", "CNAME"):
                got = await _answers(host, rdtype)
                if got is None:
                    continue
                # Same answers as a name that cannot exist: the wildcard, not a real host.
                if wildcard and got <= wildcard:
                    return
                out.add(host)
                return

    await asyncio.gather(*(_check(c) for c in _ACTIVE_CANDIDATES))
    return out, bool(wildcard)


async def _from_active_dns(domain_name: str) -> set[str]:
    """Hostnames only; kept for callers that do not need the wildcard flag."""
    hosts, _ = await _probe_active(domain_name)
    return hosts


# ── The domain's own published records ───────────────────────────────────────

def _host_in(value: str, domain_name: str) -> str | None:
    """A hostname (or the host part of an address) if it is a subdomain of the domain."""
    value = value.strip().strip("<>").lower().rstrip(".")
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    value = value.split("/", 1)[0].split(":", 1)[0]
    return value if value and _is_subdomain(value, domain_name) else None


async def _txt(name: str) -> list[str]:
    try:
        res = await resolver.resolve(name, "TXT")
    except dns.exception.DNSException:
        return []
    return ["".join(b.decode("utf-8", "replace") for b in r.strings) for r in res]


async def _spf_hosts(domain_name: str, name: str, depth: int, budget: list[int], seen: set[str]) -> set[str]:
    """Subdomains named by an SPF record, following include/redirect inside the domain."""
    if depth > 3 or budget[0] <= 0 or name in seen:
        return set()
    seen.add(name)
    out: set[str] = set()
    for txt in await _txt(name):
        if not txt.lower().startswith("v=spf1"):
            continue
        for term in txt.split()[1:]:
            term = term.lstrip("+-~?")
            key, sep, val = term.partition(":")
            if not sep:
                key, sep, val = term.partition("=")
            key = key.lower()
            if key not in {"include", "a", "mx", "exists", "ptr", "redirect"} or not val:
                continue
            host = _host_in(val.split("/")[0], domain_name)
            if host:
                out.add(host)
                if key in {"include", "redirect"}:
                    budget[0] -= 1
                    out |= await _spf_hosts(domain_name, host, depth + 1, budget, seen)
    return out


async def _from_own_records(domain_name: str) -> set[str]:
    """
    Subdomains the domain publishes itself: MX targets, hosts named in SPF
    (following includes that stay inside the domain), DMARC and TLS-RPT report
    addresses, SRV targets for mail clients, and a published MTA-STS host.
    These are the domain's own public records, the same lookups any mail
    server makes, so this runs for every domain and needs nothing from the
    customer.
    """
    out: set[str] = set()

    async def _mx() -> None:
        try:
            for r in await resolver.resolve(domain_name, "MX"):
                host = _host_in(str(r.exchange), domain_name)
                if host:
                    out.add(host)
        except dns.exception.DNSException:
            pass

    async def _spf() -> None:
        out.update(await _spf_hosts(domain_name, domain_name, 0, [_SPF_LOOKUP_BUDGET], set()))

    async def _report_addresses(name: str) -> None:
        for txt in await _txt(name):
            for m in re.finditer(r"(?:rua|ruf)=([^;]+)", txt, re.I):
                for target in m.group(1).split(","):
                    cleaned = target.replace("mailto:", "").replace("https://", "").replace("http://", "")
                    host = _host_in(cleaned, domain_name)
                    if host:
                        out.add(host)

    async def _srv(label: str) -> None:
        try:
            for r in await resolver.resolve(f"{label}.{domain_name}", "SRV"):
                host = _host_in(str(r.target), domain_name)
                if host:
                    out.add(host)
        except dns.exception.DNSException:
            pass

    async def _mta_sts() -> None:
        host = f"mta-sts.{domain_name}"
        if await _answers(host, "A") or await _answers(host, "CNAME"):
            out.add(host)

    await asyncio.gather(
        _mx(), _spf(), _mta_sts(),
        _report_addresses(f"_dmarc.{domain_name}"), _report_addresses(f"_smtp._tls.{domain_name}"),
        *(_srv(lbl) for lbl in _SRV_NAMES),
    )
    return out


# ── Coverage of subdomains nobody listed ──────────────────────────────────────

def _tags(record: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in record.split(";"):
        k, sep, v = part.strip().partition("=")
        if sep:
            out[k.strip().lower()] = v.strip().lower()
    return out


def coverage_from_record(record: str | None) -> dict:
    """
    What a parent DMARC record does to a subdomain nobody has listed. This
    needs no enumeration: a subdomain without its own _dmarc record inherits sp=,
    or p= when sp= is absent (np= for names that do not exist, where published).
    Receivers apply it to mail that fails both SPF and DKIM alignment.
    """
    if not record:
        return {
            "dmarc_found": False, "policy": None, "subdomain_policy": None, "np_policy": None,
            "effective_subdomain_policy": None, "level": "open",
            "summary": "No DMARC record was found, so nothing tells receivers to act on mail sent from any subdomain of this domain.",
        }
    tags = _tags(record)
    p, sp, np_ = tags.get("p"), tags.get("sp"), tags.get("np")
    pct = tags.get("pct", "100")
    effective = np_ or sp or p
    partial_pct = pct.isdigit() and int(pct) < 100
    if effective == "reject" and not partial_pct:
        level, text = "protected", "Mail from unlisted subdomains that fails DMARC is rejected by receivers that honour the policy."
    elif effective in ("reject", "quarantine"):
        level, text = "partial", (
            f"Unlisted subdomains are covered by '{effective}'"
            + (f" for {pct}% of mail" if partial_pct else "")
            + ", so some spoofed mail can still be delivered."
        )
    else:
        level, text = "open", "Unlisted subdomains inherit a policy of none, so receivers report on spoofed mail but do not stop it."
    where = "sp=" if sp else "p="
    return {
        "dmarc_found": True, "policy": p, "subdomain_policy": sp, "np_policy": np_,
        "effective_subdomain_policy": effective, "level": level,
        "summary": f"Subdomains without their own DMARC record follow {where}{sp or p}. {text}",
    }


async def check_subdomain_coverage(domain_name: str) -> dict:
    records = [t for t in await _txt(f"_dmarc.{domain_name}") if t.lower().startswith("v=dmarc1")]
    return coverage_from_record(records[0] if records else None)


def _axfr_attempt_sync(domain_name: str, nameservers: list[str]) -> set[str]:
    """
    Zone transfer attempt — almost always refused by a correctly configured
    DNS server (that's the expected, common outcome, not an error). dnspython's
    xfr is synchronous, so this runs off the event loop via asyncio.to_thread.
    """
    out: set[str] = set()
    for ns in nameservers[:2]:  # at most 2 — this is a courtesy try, not a sweep
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain_name, timeout=_AXFR_TIMEOUT, lifetime=_AXFR_TIMEOUT))
            for name in zone.nodes.keys():
                host = f"{name}.{domain_name}".lower() if str(name) != "@" else domain_name.lower()
                if _is_subdomain(host, domain_name):
                    out.add(host)
            if out:
                break
        except Exception:
            continue
    return out


async def _from_axfr(domain_name: str, nameservers: list[str]) -> set[str]:
    if not nameservers:
        return set()
    try:
        return await asyncio.to_thread(_axfr_attempt_sync, domain_name, nameservers)
    except Exception:
        return set()


async def discover_subdomains(
    db: AsyncSession, domain: Domain, allow_active: bool = False
) -> list[DiscoveredSubdomain]:
    """Hostnames only; see discover_subdomains_with_status for per-source state."""
    found, _ = await discover_subdomains_with_status(db, domain, allow_active=allow_active)
    return found


async def discover_subdomains_with_status(
    db: AsyncSession, domain: Domain, allow_active: bool = False
) -> tuple[list[DiscoveredSubdomain], dict[str, str]]:
    """
    allow_active gates the active-probing sources (wordlist + AXFR) — the
    caller must only pass True for ownership-verified domains, and must
    never pass True from the public /scan endpoint. Passive sources
    (dmarc/cert/ct) always run regardless.

    Returns the merged list and a per-source status, so "nothing found" can be
    told apart from "a source could not be asked":
      dmarc, cert: ok
      ct:          ok | cached | timed_out | failed
      dns_active:  ok | skipped_unverified
    """
    dmarc_hits = await _from_dmarc(db, domain)
    cert_hits = await _from_certs(db, domain)

    wildcard_detected = False

    async def _active() -> tuple[set[str], set[str]]:
        nonlocal wildcard_detected
        hits, wildcard_detected = await _probe_active(domain.name)
        axfr: set[str] = set()
        try:
            answers = await resolver.resolve(domain.name, "NS")
            nameservers = [str(r.target).rstrip(".") for r in answers]
            axfr = await _from_axfr(domain.name, nameservers)
        except dns.exception.DNSException:
            pass
        return hits, axfr

    # The CT lookup is the slow, unreliable part; run it alongside the DNS
    # probes instead of after them.
    ct_task = asyncio.create_task(_from_ct_logs_with_status(domain.name))
    own_task = asyncio.create_task(_from_own_records(domain.name))
    active_hits: set[str] = set()
    axfr_hits: set[str] = set()
    if allow_active:
        active_hits, axfr_hits = await _active()
    ct_hits, ct_status = await ct_task
    try:
        own_hits = await own_task
        own_status = "ok"
    except Exception:
        log.warning("Own-record lookup failed for %s", domain.name, exc_info=True)
        own_hits, own_status = set(), "failed"

    sources = {
        "dmarc": "ok",
        "cert": "ok",
        "dns_records": own_status,
        "ct": ct_status,
        "dns_active": ("wildcard_filtered" if wildcard_detected else "ok") if allow_active else "skipped_unverified",
    }

    merged: dict[str, DiscoveredSubdomain] = {}

    def _get(hostname: str) -> DiscoveredSubdomain:
        return merged.setdefault(hostname, DiscoveredSubdomain(hostname=hostname))

    for hostname, volume in dmarc_hits.items():
        d = _get(hostname)
        d.sources.append("dmarc")
        d.sends_mail = True
        d.mail_volume = volume

    for hostname in cert_hits:
        _get(hostname).sources.append("cert")

    for hostname in ct_hits:
        _get(hostname).sources.append("ct")

    for hostname in own_hits:
        _get(hostname).sources.append("dns-records")

    for hostname in active_hits:
        _get(hostname).sources.append("dns-active")

    for hostname in axfr_hits:
        _get(hostname).sources.append("axfr")

    if not merged:
        return [], sources

    existing = (await db.execute(
        select(Domain.name).where(Domain.tenant_id == domain.tenant_id, Domain.is_active == True)
    )).scalars().all()
    existing_set = {n.lower() for n in existing}

    results = list(merged.values())
    for r in results:
        r.already_monitored = r.hostname in existing_set

    # Mail-sending subdomains first — this is meant to surface "what needs
    # DMARC attention", not just dump a flat list of hostnames found.
    results.sort(key=lambda r: (not r.sends_mail, -r.mail_volume, r.hostname))
    return results, sources
