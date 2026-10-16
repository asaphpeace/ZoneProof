"""
Reported-suspicious-email ingestion (Phishing Simulation roadmap Phase 26)
— the KnowBe4-equivalent "report a real suspicious email" pipeline, NOT
the Mimecast-equivalent automatic just-in-time response (that requires
Sentinel to sit in the customer's mail path, a different product
category — see PHISHING_PLATFORM_GAP_ANALYSIS.md).

Employees forward a suspicious email to their tenant's real forwarding
address (Tenant.phishing_report_slug @ settings.reporting_domain, same
slug-based routing convention imap_service.py already uses for DMARC/
TLS-RPT). This module parses the forwarded EmailMessage into a
ReportedEmail row. See app/models/reported_email.py's own docstring for
why the full raw message is deliberately never stored — only what a real
triage workflow needs.
"""
from __future__ import annotations

import logging
import re
import uuid
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.phishing import PhishingTargetList
from app.models.reported_email import ReportedEmail
from app.models.user import Tenant
from app.services.link_risk_service import score_report_urls_best_effort
from app.services.phishing_service import _hash_recipient

_log = logging.getLogger(__name__)

_URL_RE = re.compile(r'https?://[^\s<>"\')\]]+', re.I)
_BODY_EXCERPT_MAX_CHARS = 3000
_MAX_URLS = 20


def extract_urls(text: str) -> list[str]:
    """Real URLs found in the reported message's body, deduplicated and
    capped — the raw material a triage analyst actually needs to inspect
    a real lure, not the full body."""
    seen: list[str] = []
    for m in _URL_RE.findall(text or ""):
        if m not in seen:
            seen.append(m)
        if len(seen) >= _MAX_URLS:
            break
    return seen


def parse_authentication_results(msg: EmailMessage) -> dict:
    """Reads every Authentication-Results header (there can be more than
    one, once per relay hop) and pulls the first spf=/dkim=/dmarc= result
    token found for each mechanism. Confirmed via grep before writing
    this — nothing in this codebase parsed this header before this
    phase; every other SPF/DKIM/DMARC signal elsewhere operates on
    already-parsed DMARC aggregate-report fields, not a live message's
    own headers."""
    headers = msg.get_all("Authentication-Results", [])
    combined = " ".join(headers)
    result: dict = {"spf_result": None, "dkim_result": None, "dmarc_result": None, "auth_results_raw": combined or None}
    for mechanism in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mechanism}=(\w+)", combined, re.I)
        if m:
            result[f"{mechanism}_result"] = m.group(1).lower()
    return result


def _plain_text_body(msg: EmailMessage) -> str:
    """Prefers a real text/plain part; falls back to a crude HTML-tag
    strip of text/html rather than ever storing raw HTML — this excerpt
    may later be shown in the triage UI, and raw attacker-authored HTML
    (remote-tracking pixels, disguised links) must never be capable of
    rendering as HTML anywhere in this product."""
    try:
        plain = msg.get_body(preferencelist=("plain",))
        if plain is not None:
            return plain.get_content()
    except Exception:
        pass
    try:
        html_part = msg.get_body(preferencelist=("html",))
        if html_part is not None:
            html = html_part.get_content()
            return re.sub(r"<[^>]+>", " ", html)
    except Exception:
        pass
    return ""


def _first_address(header_value: str | None) -> str | None:
    addrs = getaddresses([header_value or ""])
    return addrs[0][1] if addrs and addrs[0][1] else None


def resolve_reported_message(outer: EmailMessage) -> tuple[EmailMessage, bool]:
    """Real forwarding clients attach the original message as a genuine
    message/rfc822 part when using 'Forward as attachment'; the far more
    common plain 'Forward' inlines the original as quoted text in the
    body instead, which this function deliberately does NOT attempt to
    reverse-parse — doing that reliably across every mail client's
    quoting format is genuinely unreliable, and a wrong guess would
    misattribute what a real message actually said. Returns
    (message_to_examine, is_the_real_original) so callers stay honest
    about which case happened, rather than silently presenting a guess
    as fact."""
    for part in outer.iter_attachments():
        if part.get_content_type() == "message/rfc822":
            payload = part.get_payload()
            inner = payload[0] if isinstance(payload, list) and payload else None
            if inner is not None:
                return inner, True
    return outer, False


async def parse_reported_email(db: AsyncSession, tenant: Tenant, outer_msg: EmailMessage) -> ReportedEmail:
    reporter_email = _first_address(outer_msg.get("From"))
    reporter_hash = _hash_recipient(reporter_email, tenant.id) if reporter_email else None

    inner, is_original_attached = resolve_reported_message(outer_msg)

    original_from = _first_address(inner.get("From"))
    original_from_domain = original_from.split("@")[-1].lower() if original_from and "@" in original_from else None

    original_date = None
    date_header = inner.get("Date")
    if date_header:
        try:
            original_date = parsedate_to_datetime(date_header)
        except (TypeError, ValueError):
            original_date = None

    body_text = _plain_text_body(inner)
    auth = parse_authentication_results(inner)

    report = ReportedEmail(
        id=uuid.uuid4(), tenant_id=tenant.id, reporter_hash=reporter_hash,
        original_subject=(inner.get("Subject") or None),
        original_from=original_from, original_from_domain=original_from_domain,
        original_date=original_date,
        body_text_excerpt=(body_text[:_BODY_EXCERPT_MAX_CHARS] or None) if body_text else None,
        urls_found=extract_urls(body_text),
        is_original_message_attached=is_original_attached,
        **auth,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    # Best-effort — scoring failure must never block report creation, and
    # the report row above is already safely persisted regardless of what
    # happens here. A failed scan just leaves url_risk at None, rescanable
    # later via POST /reported-emails/{id}/rescan-links.
    try:
        await score_report_urls_best_effort(db, report)
        await db.commit()
        await db.refresh(report)
    except Exception as e:
        _log.warning("Link risk scoring failed for report_id=%s: %s", report.id, e)

    return report


async def unmask_reporter(db: AsyncSession, report: ReportedEmail) -> str | None:
    """Admin-only, audit-logged at the router layer — same discipline as
    phishing.unmask_recipient. Unlike that function, a reported email's
    reporter isn't scoped to one known campaign's target list (they could
    be any real employee, possibly one never targeted by a simulation at
    all), so this searches every target list this tenant has ever
    created rather than one specific list. Returns None honestly when no
    match is found — the reporter may simply not be on any list Sentinel
    knows about yet, not a bug."""
    if not report.reporter_hash:
        return None
    result = await db.execute(select(PhishingTargetList).where(PhishingTargetList.tenant_id == report.tenant_id))
    for target_list in result.scalars().all():
        for entry in target_list.entries or []:
            email = entry.get("email")
            if email and _hash_recipient(email, report.tenant_id) == report.reporter_hash:
                return email
    return None
