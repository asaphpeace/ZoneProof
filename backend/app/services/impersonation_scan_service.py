"""
Sentinel Command Phishing Tier A — Spoof Proof (PHISHING_DESIGN.md Section 2).
No employees are targeted; both checks run against the domain itself:

  1. Lookalike domain scan — passive DNS recon over a curated set of
     homograph/typosquat permutations, same "curated, not exhaustive"
     posture as exposure_scan_service.py's takeover fingerprint list.
  2. Spoof send test — actually attempt to deliver a message claiming to
     be from the customer's own domain to a mailbox they designate, and
     observe whether their SPF/DKIM/DMARC policy blocks it.

PHISHING_DESIGN.md originally assumed the spoof send would reuse V1's
SendGrid path. That doesn't hold up: transactional ESPs deliberately
enforce sender-domain verification to prevent exactly this kind of
spoofing, so SendGrid cannot be asked to send as a domain we don't own.
Real DMARC-testing tools solve this by connecting directly, over raw SMTP,
to the *recipient's* mail server from an IP with no SPF authorization for
the sender domain — which is the actual scenario being tested, and is
exactly what an unauthenticated attacker's send would look like. Sentinel's
own outbound IP naturally satisfies "unauthorized" here; no special
infrastructure is needed beyond outbound SMTP capability from wherever the
backend runs. Worth flagging: several cloud providers (e.g. AWS) block
outbound port 25 by default and require an explicit request to lift it —
a real deployment blocker to resolve before this runs anywhere but a
developer machine, not a design problem with the technique itself.
"""
from __future__ import annotations

import asyncio
import email.utils
import logging
import re
import smtplib
import uuid
from datetime import datetime, timedelta, timezone

import dns.exception
import dns.resolver
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import Domain, Engagement, Finding
from app.services.dns_resolver import resolver

_log = logging.getLogger(__name__)

# Curated homoglyph substitutions — sequences attackers commonly swap
# because they render near-identically in most fonts. Not exhaustive; new
# ones surface over time the same way exposure_scan_service.py's takeover
# fingerprint list does.
_HOMOGLYPH_SUBSTITUTIONS = [
    ("o", "0"), ("l", "1"), ("i", "1"), ("rn", "m"), ("m", "rn"), ("vv", "w"), ("w", "vv"),
]
_ALT_TLDS = ["com", "net", "org", "co", "io"]
_MAX_CANDIDATES = 40


def _generate_lookalike_permutations(domain: str) -> list[str]:
    if "." not in domain:
        return []
    label, _, tld = domain.partition(".")
    if len(label) < 2:
        return []

    candidates: set[str] = set()

    for i in range(len(label)):
        candidates.add(f"{label[:i]}{label[i+1:]}.{tld}")  # omission
        candidates.add(f"{label[:i]}{label[i]}{label[i:]}.{tld}")  # duplication
    for i in range(len(label) - 1):
        swapped = label[:i] + label[i + 1] + label[i] + label[i + 2:]
        candidates.add(f"{swapped}.{tld}")  # adjacent transposition

    for old, new in _HOMOGLYPH_SUBSTITUTIONS:
        if old in label:
            candidates.add(f"{label.replace(old, new, 1)}.{tld}")

    mid = len(label) // 2
    if 0 < mid < len(label):
        candidates.add(f"{label[:mid]}-{label[mid:]}.{tld}")  # hyphen insertion

    for alt_tld in _ALT_TLDS:
        if alt_tld != tld:
            candidates.add(f"{label}.{alt_tld}")

    candidates.discard(domain)
    candidates = {c for c in candidates if re.fullmatch(r"[a-z0-9-]+\.[a-z]+", c)}
    return sorted(candidates)[:_MAX_CANDIDATES]


async def check_lookalike_domains(domain: str) -> list[dict]:
    """Returns one entry per generated permutation found to have a live MX
    or A record — i.e. infrastructure that could actually send or host
    content under a name confusable with the real domain."""
    candidates = _generate_lookalike_permutations(domain)

    async def _check_one(candidate: str) -> dict | None:
        for record_type in ("MX", "A"):
            try:
                answers = await resolver.resolve(candidate, record_type)
                if answers:
                    return {"domain": candidate, "record_type": record_type}
            except dns.exception.DNSException:
                continue
        return None

    results = await asyncio.gather(*(_check_one(c) for c in candidates))
    return [r for r in results if r]


def _send_spoof_test_sync(domain: str, test_recipient_email: str) -> dict:
    recipient_domain = test_recipient_email.rsplit("@", 1)[-1]
    try:
        mx_answers = dns.resolver.resolve(recipient_domain, "MX")
        mx_host = str(min(mx_answers, key=lambda r: r.preference).exchange).rstrip(".")
    except dns.exception.DNSException as e:
        return {"outcome": "test_error", "detail": f"Could not resolve mail server for {recipient_domain}: {e}"}

    spoofed_from = f"security-test@{domain}"
    message = (
        f"From: Sentinel Security Test <{spoofed_from}>\r\n"
        f"To: {test_recipient_email}\r\n"
        f"Subject: Sentinel Command domain impersonation test\r\n"
        f"Date: {email.utils.formatdate(localtime=True)}\r\n"
        f"Message-ID: {email.utils.make_msgid()}\r\n\r\n"
        f"This message was sent by Sentinel Command as part of a consented domain-impersonation "
        f"test for {domain}. It originated from Sentinel's infrastructure, not an address at "
        f"{domain} -- its purpose is to check whether mail claiming to be from {domain} but sent "
        f"by an unauthorized party is correctly blocked. If you're reading this in your inbox, it "
        f"was not blocked, which is itself the finding.\r\n"
    )

    try:
        with smtplib.SMTP(mx_host, 25, timeout=15) as smtp:
            smtp.ehlo()
            if smtp.has_extn("starttls"):
                smtp.starttls()
                smtp.ehlo()
            smtp.sendmail(spoofed_from, [test_recipient_email], message)
        return {"outcome": "delivered", "detail": f"A message spoofing {spoofed_from} was accepted by {mx_host} without rejection."}
    except smtplib.SMTPResponseException as e:
        return {"outcome": "blocked", "detail": f"{mx_host} rejected the spoofed message ({e.smtp_code}: {e.smtp_error})."}
    except (smtplib.SMTPException, OSError) as e:
        return {"outcome": "test_error", "detail": f"Could not complete the test send via {mx_host}: {e}"}


async def send_spoof_test(domain: str, test_recipient_email: str) -> dict:
    return await asyncio.to_thread(_send_spoof_test_sync, domain, test_recipient_email)


async def run_impersonation_scan(db: AsyncSession, engagement: Engagement, domain: Domain) -> list[Finding]:
    """Never raises on an individual check failing to produce a result —
    a blocked/failed spoof test is recorded via last_scan_status/
    last_scan_error on the Engagement (the honest-failure pattern already
    used for CloudAccountConnection/HostConnection), not swallowed."""
    if not domain.ownership_verified:
        _log.info("Skipping impersonation scan — domain not ownership-verified: domain_id=%s", domain.id)
        return []

    test_recipient_email = (engagement.scope or {}).get("test_recipient_email")

    async def _no_test_recipient() -> dict:
        return {"outcome": "test_error", "detail": "No test_recipient_email configured for this engagement."}

    lookalike_hits, spoof_result = await asyncio.gather(
        check_lookalike_domains(domain.name),
        send_spoof_test(domain.name, test_recipient_email) if test_recipient_email else _no_test_recipient(),
    )

    findings: list[Finding] = []
    for hit in lookalike_hits:
        findings.append(Finding(
            id=uuid.uuid4(), tenant_id=domain.tenant_id, engagement_id=engagement.id, asset_id=None,
            tier="impersonation", severity="high",
            title=f"Lookalike domain resolves to live mail infrastructure: {hit['domain']}",
            status="open", check_id=f"IMPERSONATION-LOOKALIKE-{hit['domain']}",
            detail=f"{hit['domain']} (a lookalike of {domain.name}) has a live {hit['record_type']} record — it could be used to send convincing impersonation email.",
            remediation_guidance="Consider registering close variants defensively, or monitor them for active use in phishing campaigns.",
        ))
        db.add(findings[-1])

    if spoof_result["outcome"] == "delivered":
        finding = Finding(
            id=uuid.uuid4(), tenant_id=domain.tenant_id, engagement_id=engagement.id, asset_id=None,
            tier="impersonation", severity="critical",
            title=f"Spoofed email claiming to be from {domain.name} was not blocked",
            status="open", check_id="IMPERSONATION-SPOOF-SEND-TEST",
            detail=spoof_result["detail"],
            remediation_guidance="Tighten SPF/DKIM alignment and move the DMARC policy toward p=reject — an unauthorized sender was able to deliver mail claiming this domain.",
        )
        db.add(finding)
        findings.append(finding)

    engagement.last_scanned_at = datetime.now(timezone.utc)
    if spoof_result["outcome"] in ("test_error",):
        engagement.last_scan_status = "failed"
        engagement.last_scan_error = spoof_result["detail"]
    else:
        engagement.last_scan_status = "success"
        engagement.last_scan_error = None

    await db.commit()
    return findings


async def poll_all_due_impersonation_domains(db: AsyncSession) -> int:
    """Scheduler entry point — Tier A runs on a recurring cadence with no
    per-cycle consent (PHISHING_DESIGN.md Section 2.3), unlike Tier B's
    signed-cadence campaigns. 'Due' is computed from last_scanned_at rather
    than a separate tracked window, since each cycle is a stateless check,
    not an incremental poll over new events."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.command_impersonation_scan_interval_days)
    result = await db.execute(
        select(Engagement, Domain)
        .join(Domain, Engagement.domain_id == Domain.id)
        .where(
            Engagement.tier == "impersonation",
            Engagement.status == "active",
            or_(Engagement.last_scanned_at.is_(None), Engagement.last_scanned_at < cutoff),
        )
    )
    rows = result.all()
    polled = 0
    for engagement, domain in rows:
        try:
            await run_impersonation_scan(db, engagement, domain)
        except Exception:
            _log.exception("Scheduled impersonation scan failed unexpectedly: engagement_id=%s", engagement.id)
        polled += 1
    return polled
