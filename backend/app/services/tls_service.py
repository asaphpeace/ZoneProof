"""
TLS / MTA-STS record generation, policy file generation, aggregation.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import dns.exception
import httpx
from app.services.dns_resolver import resolver as _resolver
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Domain, TlsPolicy, TlsAggregate
from app.services.reporting_address import rua_mailto
from app.config import settings


DEFAULT_TLS_WINDOW_DAYS = 30


async def tls_window_totals(db: AsyncSession, domain_id, days: int = DEFAULT_TLS_WINDOW_DAYS) -> tuple[int, int, int]:
    """
    (total, successful, failed) sessions from reports whose period ends in the last `days`.

    TlsAggregate rows are rebuilt from every policy ever received and stamped with the
    month start, so they cannot be windowed; the raw policies carry the real period.
    """
    from datetime import timedelta
    from app.models import TlsReport
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    row = (await db.execute(
        select(
            func.coalesce(func.sum(TlsPolicy.total_successful_session_count), 0),
            func.coalesce(func.sum(TlsPolicy.total_failure_session_count), 0),
        )
        .join(TlsReport, TlsPolicy.report_id == TlsReport.id)
        .where(TlsPolicy.domain_id == domain_id, TlsReport.period_end >= cutoff)
    )).one()
    ok, bad = int(row[0]), int(row[1])
    return ok + bad, ok, bad


# ── Record / policy generation ─────────────────────────────────────────────────

def generate_tlsrpt_record(domain_name: str, slug: str) -> str:
    """TLS-RPT TXT record for _smtp._tls.<domain>."""
    return f"v=TLSRPTv1; rua={rua_mailto(slug)}"


def generate_mta_sts_policy(domain_name: str, mx_hosts: list[str], mode: str = "testing", policy_id: str | None = None) -> str:
    """
    MTA-STS policy file content (RFC 8461 §3.2).
    mode: testing | enforce | none
    policy_id: the id: field — senders use this to detect changes. If not
    supplied, falls back to a timestamp (adequate for self-hosted; for
    managed hosting the caller should pass domain.mta_sts_policy_id so the
    DNS TXT record and the served file stay in sync).
    """
    pid = policy_id or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    lines = [
        "version: STSv1",
        f"mode: {mode}",
        f"id: {pid}",
        f"max_age: {86400 if mode == 'testing' else 604800}",
    ]
    for mx in mx_hosts:
        lines.append(f"mx: {mx}")
    return "\n".join(lines)


async def resolve_mx_hosts(domain_name: str) -> list[str]:
    """
    Live MX lookup, used to build an MTA-STS policy that actually
    authorizes real MX hosts. Without this, generate_mta_sts_policy() was
    always called with an empty list, which per RFC 8461 means a sender
    finds no mx: pattern matching the domain's real MX hosts and falls
    back to acting as if there's no policy at all — every previously
    published policy was silently a no-op regardless of mode.
    """
    try:
        answers = await _resolver.resolve(domain_name, "MX")
        return sorted(str(mx.exchange).rstrip(".") for mx in answers)
    except dns.exception.DNSException:
        return []


def generate_mta_sts_dns_record(domain_name: str, policy_id: str) -> str:
    """_mta-sts.<domain> TXT record."""
    return f"v=STSv1; id={policy_id}"


_MTA_STS_NEXT_STAGE = {"none": "testing", "testing": "enforce"}


def generate_record_diff(domain: Domain) -> dict[str, str]:
    current = f"mode: {domain.mta_sts_stage}"
    next_stage = _MTA_STS_NEXT_STAGE.get(domain.mta_sts_stage, "enforce")
    proposed = f"mode: {next_stage}"
    return {
        "host": f"mta-sts.{domain.name}/.well-known/mta-sts.txt",
        "current": current,
        "proposed": proposed,
    }


# ── DNS check ─────────────────────────────────────────────────────────────────

async def check_tlsrpt_dns(domain_name: str) -> dict:
    try:
        answers = await _resolver.resolve(f"_smtp._tls.{domain_name}", "TXT")
        for rdata in answers:
            txt = "".join(s.decode() for s in rdata.strings)
            if "TLSRPTv1" in txt:
                return {"exists": True, "record": txt, "error": None}
        return {"exists": False, "record": None, "error": None}
    except dns.exception.DNSException as e:
        return {"exists": False, "record": None, "error": str(e)}


async def check_mta_sts_dns(domain_name: str) -> dict:
    try:
        answers = await _resolver.resolve(f"_mta-sts.{domain_name}", "TXT")
        for rdata in answers:
            txt = "".join(s.decode() for s in rdata.strings)
            if "STSv1" in txt:
                return {"exists": True, "record": txt, "error": None}
        return {"exists": False, "record": None, "error": None}
    except dns.exception.DNSException as e:
        return {"exists": False, "record": None, "error": str(e)}


async def fetch_mta_sts_policy(domain_name: str) -> dict:
    """
    Fetch the actual MTA-STS policy file over HTTPS and parse its `mode:` line.

    This is the only place `mode` (testing/enforce/none) ever actually lives —
    the `_mta-sts.<domain>` DNS TXT record only ever contains `v=STSv1; id=...`,
    never the mode. Any code that wants to know whether a domain is really at
    testing or enforce — as opposed to just "has *a* policy file" — has to
    fetch this URL, not just check DNS.

    Returns {"reachable": bool, "mode": str|None, "raw": str|None, "error": str|None}
    """
    url = f"https://mta-sts.{domain_name}/.well-known/mta-sts.txt"
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            resp = await client.get(url)
        if resp.status_code != 200:
            return {"reachable": False, "mode": None, "raw": None, "error": f"HTTP {resp.status_code}"}
        raw = resp.text
        mode = None
        for line in raw.splitlines():
            line = line.strip()
            if line.lower().startswith("mode:"):
                mode = line.split(":", 1)[1].strip().lower()
                break
        return {"reachable": True, "mode": mode, "raw": raw, "error": None}
    except httpx.HTTPError as e:
        return {"reachable": False, "mode": None, "raw": None, "error": str(e)}


# ── Aggregation ────────────────────────────────────────────────────────────────

async def rebuild_tls_aggregates(db: AsyncSession, domain_id: uuid.UUID) -> None:
    await db.execute(
        text("DELETE FROM tls_aggregates WHERE domain_id = :did"),
        {"did": str(domain_id)},
    )

    from sqlalchemy.orm import selectinload
    stmt = (
        select(TlsPolicy)
        .where(TlsPolicy.domain_id == domain_id)
        .options(selectinload(TlsPolicy.failure_details))
    )
    result = await db.execute(stmt)
    policies = result.scalars().all()

    groups: dict[tuple, dict] = {}
    for p in policies:
        key = (p.policy_mx_host or p.policy_domain, p.domain_id)
        if key not in groups:
            groups[key] = {
                "domain_id": domain_id,
                "mx_host": p.policy_mx_host or p.policy_domain,
                "reporter_org": "",
                "total_sessions": 0,
                "successful_sessions": 0,
                "failed_sessions": 0,
                "top_failure_reason": None,
                "top_failure_count": 0,
            }
        g = groups[key]
        g["total_sessions"] += p.total_successful_session_count + p.total_failure_session_count
        g["successful_sessions"] += p.total_successful_session_count
        g["failed_sessions"] += p.total_failure_session_count

        for fd in p.failure_details:
            if fd.failed_session_count > g["top_failure_count"]:
                g["top_failure_count"] = fd.failed_session_count
                g["top_failure_reason"] = fd.result_type

    now = datetime.now(timezone.utc)
    for key, g in groups.items():
        agg = TlsAggregate(
            id=uuid.uuid4(),
            period_begin=now.replace(day=1, hour=0, minute=0, second=0, microsecond=0),
            period_end=now,
            computed_at=now,
            **g,
        )
        db.add(agg)

    await db.commit()


# ── Plain-English TLS failure reason ──────────────────────────────────────────

FAILURE_REASONS: dict[str, str] = {
    # RFC 8460 failure types describe the RECEIVING side as the sender saw it: these
    # reports are about mail delivered to your domain, so "the server" is your MX.
    "starttls-not-supported":       "A sender connected to your mail server and could not start encryption: your server did not offer STARTTLS to it. If only one sender reports this, the cause is more likely on the network path than on your server.",
    "certificate-host-mismatch":    "The certificate your mail server presented does not match the MX hostname the sender connected to.",
    "certificate-expired":          "The certificate your mail server presented has expired. Renew it immediately.",
    "certificate-not-trusted":      "The certificate your mail server presented is not signed by a trusted Certificate Authority.",
    "validation-failure":           "TLS certificate validation failed for an unspecified reason.",
    "tlsa-invalid":                 "The TLSA (DANE) record doesn't match the certificate presented.",
    "dnssec-invalid":               "DNSSEC validation failed for this domain.",
    "sts-policy-fetch-error":       "The MTA-STS policy file could not be fetched — check mta-sts.<domain>/.well-known/mta-sts.txt.",
    "sts-policy-invalid":           "The MTA-STS policy file was fetched but its content is invalid.",
    "sts-webpki-invalid":           "The certificate presented does not satisfy the MTA-STS WebPKI requirements.",
    "no-policy-found":              "No MTA-STS policy was found for this domain.",
}


def explain_tls_failure(result_type: str) -> str:
    return FAILURE_REASONS.get(result_type, f"Unknown failure type: {result_type}. Check RFC 8460 for the full list.")
