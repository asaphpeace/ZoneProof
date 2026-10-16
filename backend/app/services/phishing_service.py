"""
Sentinel Command Phishing Tier B — Human Simulation (PHISHING_DESIGN.md
Section 3). A minimal custom send/track pipeline built on the existing
email_service.send_email (SendGrid) path — not Gophish, not a third party
(see PHISHING_DESIGN.md Section 3.1 for why). Unlike Tier A's spoof test,
this sends FROM Sentinel's own verified sending identity, never as the
customer's domain — a dedicated, generic sender, exactly as
ARCHITECTURE.md's original Tier 3 sketch specified.

Recipient identity is pseudonymized by construction, not by policy alone:
every PhishingEvent carries only a recipient_hash (HMAC-SHA256, keyed by a
per-tenant salt derived from settings.secret_key) and a recipient_token (a
random, unguessable value used purely as the unauthenticated tracking URL's
identifier). Unmasking re-hashes the *current* target list and matches —
no plaintext email is ever stored against an event row.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import qrcode
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import Domain, Engagement, PhishingCampaign, PhishingCustomTemplate, PhishingEvent, PhishingTargetList, TrainingAssignment
from app.models.user import Tenant
from app.services.email_service import send_email
from app.services.phishing_content_service import generate_campaign_content
from app.services.phishing_lesson_content import get_lesson_content

_log = logging.getLogger(__name__)

# Curated, built-in lure set — a starting point for customization, not a
# fixed catalog (PHISHING_DESIGN.md Section 3.1's original "no builder UI"
# tradeoff was revisited: an engagement's scope can carry subject_override/
# body_html_override, which launch_campaign prefers over these when
# present). Each subject/body is generic enough to be believable without
# impersonating any real brand.
_REPORT_LINK_HTML = (
    "<p style=\"font-size:11px;color:#888\">Not expecting this? "
    "<a href=\"{report_url}\">Report this email</a></p>"
)

BUILT_IN_TEMPLATES: dict[str, dict[str, str]] = {
    "password-expiry": {
        "label": "Password expiry notice",
        "category": "Credential harvest",
        "subject": "Action required: your password expires in 24 hours",
        "body_html": (
            "<p>Your account password is set to expire tomorrow. To avoid being locked out, "
            "please confirm your credentials using the link below before the deadline.</p>"
            "<p><a href=\"{click_url}\">Confirm my password</a></p>" + _REPORT_LINK_HTML
        ),
    },
    "shared-document": {
        "label": "Shared document",
        "category": "Credential harvest",
        "subject": "A document has been shared with you",
        "body_html": (
            "<p>A colleague has shared a document with you that requires your review. "
            "Please sign in to view it.</p>"
            "<p><a href=\"{click_url}\">View shared document</a></p>" + _REPORT_LINK_HTML
        ),
    },
    "it-support-request": {
        "label": "IT support verification",
        "category": "Credential harvest",
        "subject": "IT Support: please verify your account",
        "body_html": (
            "<p>Our IT team detected unusual sign-in activity on your account and has "
            "temporarily restricted access. Please verify your identity to restore access.</p>"
            "<p><a href=\"{click_url}\">Verify my account</a></p>" + _REPORT_LINK_HTML
        ),
    },
    "invoice-fraud": {
        "label": "Invoice payment update",
        "category": "Finance",
        "subject": "Updated bank details for outstanding invoice",
        "body_html": (
            "<p>Please find attached our updated banking details for the outstanding invoice on your account. "
            "Kindly review before processing the next payment run.</p>"
            "<p><a href=\"{click_url}\">Review updated invoice</a></p>" + _REPORT_LINK_HTML
        ),
    },
    "hr-benefits": {
        "label": "Benefits enrollment reminder",
        "category": "HR",
        "subject": "Action needed: benefits enrollment closes Friday",
        "body_html": (
            "<p>Open enrollment for this year's benefits closes Friday. If you haven't confirmed your "
            "selections yet, please do so now to avoid a lapse in coverage.</p>"
            "<p><a href=\"{click_url}\">Confirm my benefits</a></p>" + _REPORT_LINK_HTML
        ),
    },
    "package-delivery": {
        "label": "Package delivery issue",
        "category": "Delivery",
        "subject": "We could not deliver your package",
        "body_html": (
            "<p>A delivery attempt to your address was unsuccessful. Please confirm your details "
            "so we can reschedule delivery.</p>"
            "<p><a href=\"{click_url}\">Reschedule delivery</a></p>" + _REPORT_LINK_HTML
        ),
    },
    "exec-request": {
        "label": "Urgent request from leadership",
        "category": "Executive impersonation",
        "subject": "Quick favor — are you at your desk?",
        "body_html": (
            "<p>Are you available right now? I need help with something time-sensitive before a call "
            "and can't reach anyone else. Let me know as soon as you see this.</p>"
            "<p><a href=\"{click_url}\">Reply now</a></p>" + _REPORT_LINK_HTML
        ),
    },
    "calendar-invite": {
        "label": "Calendar invite",
        "category": "Meeting",
        "subject": "Invitation: Quarterly planning sync",
        "body_html": (
            "<p>You've been invited to a meeting. Please accept and review the attached agenda before "
            "the call.</p>"
            "<p><a href=\"{click_url}\">View invite</a></p>" + _REPORT_LINK_HTML
        ),
    },
    "software-update": {
        "label": "Required software update",
        "category": "IT",
        "subject": "Required: install the latest security update",
        "body_html": (
            "<p>A required security update is available for your device. Please install it today to "
            "stay compliant with company policy.</p>"
            "<p><a href=\"{click_url}\">Install update</a></p>" + _REPORT_LINK_HTML
        ),
    },
    "cloud-storage-share": {
        "label": "Cloud storage share",
        "category": "Credential harvest",
        "subject": "A file was shared with you via cloud storage",
        "body_html": (
            "<p>Someone shared a file with you. Sign in to your account to view and download it before "
            "the link expires.</p>"
            "<p><a href=\"{click_url}\">Open shared file</a></p>" + _REPORT_LINK_HTML
        ),
    },
    # QR-based lure (Phishing Simulation roadmap Phase 27) — a real,
    # well-documented pattern ("quishing"): attackers favor QR codes
    # specifically because they bypass URL-scanning mail filters, which is
    # itself the teachable point, so the body says so plainly rather than
    # just being a generic delivery notice with a QR bolted on.
    "qr-delivery-scan": {
        "label": "Delivery: scan to confirm receipt",
        "category": "Delivery",
        "subject": "Scan to confirm you received your package",
        "body_html": (
            "<p>Our driver attempted delivery but couldn't get a signature. Scan the code below with "
            "your phone camera to confirm receipt and avoid the package being returned to sender.</p>"
            "<p><img src=\"{qr_code}\" alt=\"Scan to confirm receipt\" width=\"160\" height=\"160\"></p>"
            + _REPORT_LINK_HTML
        ),
    },
}

# Landing pages a click can show — a real wizard-facing choice (Coverage
# Map plan phishing transformation, Phase 3), not the single hardcoded
# page this used to be. Every reference platform researched treats
# landing-page selection as an explicit step, since a generic page reads
# far less credibly than one that looks like the target's own systems.
# {company_name} is filled from the tenant's real brand_name (or plain
# name) at click time — never a placeholder left literal in what a real
# employee sees.
BUILT_IN_LANDING_PAGES: dict[str, dict[str, str]] = {
    "generic-sso": {
        "label": "Generic sign-in",
        "html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Sign in</title></head>
<body style="font-family:sans-serif;max-width:360px;margin:80px auto;">
  <h2>Sign in to continue</h2>
  <form method="POST" action="{submit_url}">
    <p><input name="username" placeholder="Username" style="width:100%;padding:8px;"></p>
    <p><input name="password" type="password" placeholder="Password" style="width:100%;padding:8px;"></p>
    <p><button type="submit" style="padding:8px 16px;">Sign in</button></p>
  </form>
  <p style="font-size:11px;color:#888;margin-top:24px">This page looks off? <a href="{lesson_url}">Learn why</a></p>
</body></html>""",
    },
    "it-portal": {
        "label": "IT service portal",
        "html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{company_name} IT Portal</title></head>
<body style="font-family:sans-serif;max-width:380px;margin:70px auto;">
  <div style="border:1px solid #d8dce3;border-radius:8px;padding:28px;">
    <div style="font-weight:700;font-size:15px;color:#1f3a5f;margin-bottom:18px;">{company_name} · IT Service Portal</div>
    <p style="font-size:13px;color:#555;margin-bottom:16px;">Verify your identity to restore account access.</p>
    <form method="POST" action="{submit_url}">
      <p><input name="username" placeholder="Employee ID or email" style="width:100%;padding:9px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px;"></p>
      <p><input name="password" type="password" placeholder="Password" style="width:100%;padding:9px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px;"></p>
      <p><button type="submit" style="padding:9px 18px;background:#1f3a5f;color:#fff;border:none;border-radius:4px;">Verify identity</button></p>
    </form>
  </div>
  <p style="font-size:11px;color:#888;margin-top:16px">This page looks off? <a href="{lesson_url}">Learn why</a></p>
</body></html>""",
    },
    "document-viewer": {
        "label": "Document sign-in",
        "html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Sign in to view document</title></head>
<body style="font-family:sans-serif;max-width:380px;margin:70px auto;">
  <div style="border:1px solid #d8dce3;border-radius:8px;padding:28px;text-align:center;">
    <div style="font-size:32px;margin-bottom:10px;">📄</div>
    <div style="font-weight:700;font-size:15px;margin-bottom:6px;">Sign in to view this document</div>
    <p style="font-size:12.5px;color:#666;margin-bottom:18px;">Shared with you via {company_name}</p>
    <form method="POST" action="{submit_url}" style="text-align:left;">
      <p><input name="username" placeholder="Email" style="width:100%;padding:9px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px;"></p>
      <p><input name="password" type="password" placeholder="Password" style="width:100%;padding:9px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px;"></p>
      <p><button type="submit" style="width:100%;padding:9px;background:#2a5b52;color:#fff;border:none;border-radius:4px;">Sign in</button></p>
    </form>
  </div>
  <p style="font-size:11px;color:#888;margin-top:16px;text-align:center">This page looks off? <a href="{lesson_url}">Learn why</a></p>
</body></html>""",
    },
}
_DEFAULT_LANDING_PAGE_ID = next(iter(BUILT_IN_LANDING_PAGES))

_LANDING_PAGE_RESULT_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Simulation notice</title></head>
<body style="font-family:sans-serif;max-width:480px;margin:80px auto;">
  <h2>This was a simulated phishing test</h2>
  <p>This page was part of an authorized security awareness exercise run by your
  organization via Sentinel Command. No password was stored — only the fact that a
  submission occurred was recorded, to help your organization measure and improve
  phishing awareness.</p>
  <p><a href="{lesson_url}" style="display:inline-block;padding:9px 16px;background:#2a5b52;color:#fff;text-decoration:none;border-radius:6px;">See what gave it away →</a></p>
</body></html>"""

# The positive-reinforcement page for the "Report this email" link — deliberately
# a different tone from the two pages above (this was the RIGHT call, not a
# gotcha), matching the research-confirmed "report rate is a success metric,
# not a failure one" framing.
_REPORT_LANDING_PAGE_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Nice catch</title></head>
<body style="font-family:sans-serif;max-width:480px;margin:80px auto;">
  <h2>Nice catch — this was a simulated phishing test</h2>
  <p>Reporting a suspicious email instead of clicking it is exactly the right move,
  every time. This message was part of an authorized security awareness exercise
  run by your organization via Sentinel Command — your report was recorded, and
  no further action is needed.</p>
</body></html>"""


def _hash_recipient(email: str, tenant_id: uuid.UUID) -> str:
    key = hashlib.sha256(f"{settings.secret_key}:{tenant_id}".encode()).digest()
    return hmac.new(key, email.strip().lower().encode(), hashlib.sha256).hexdigest()


# ── Target-list CSV diff (Phishing Simulation roadmap Phase 25) — a pure
# function, no DB access, so it's testable in isolation and reusable if a
# future caller needs it outside the one router endpoint. Matches by
# email (case-insensitive) since that's the only real identity a target-
# list entry has; every other field is compared for "changed" detection.

def _normalize_entry(e: dict) -> dict:
    # Email lowercased here too, not just at the dict-key level below — a
    # pure casing difference (Jane@Example.com vs jane@example.com) isn't
    # a real change, matching _hash_recipient's own lowercasing and how
    # every real send already resolves identity case-insensitively.
    return {
        "email": (e.get("email") or "").strip().lower(),
        "display_name": e.get("display_name") or None,
        "job_title": e.get("job_title") or None,
        "department": e.get("department") or None,
        "locale": e.get("locale") or None,
    }


def diff_target_list_entries(current: list[dict], proposed: list[dict]) -> dict:
    def _key(e: dict) -> str:
        return (e.get("email") or "").strip().lower()

    current_by_key = {_key(e): _normalize_entry(e) for e in current if _key(e)}
    proposed_by_key = {_key(e): _normalize_entry(e) for e in proposed if _key(e)}

    added = [proposed_by_key[k] for k in proposed_by_key if k not in current_by_key]
    removed = [current_by_key[k] for k in current_by_key if k not in proposed_by_key]
    changed = []
    unchanged_count = 0
    for k, after in proposed_by_key.items():
        before = current_by_key.get(k)
        if before is None:
            continue
        if after != before:
            changed.append({"email": after["email"], "before": before, "after": after})
        else:
            unchanged_count += 1

    return {"added": added, "removed": removed, "changed": changed, "unchanged_count": unchanged_count}


def _tracking_urls(token: str) -> dict[str, str]:
    base = settings.command_phishing_track_base_url.rstrip("/")
    return {
        "pixel_url": f"{base}/phishing-track/{token}/pixel.gif",
        "click_url": f"{base}/phishing-track/{token}/click",
        "submit_url": f"{base}/phishing-track/{token}/submit",
        "report_url": f"{base}/phishing-track/{token}/report",
        "lesson_url": f"{base}/phishing-track/{token}/lesson",
    }


def _generate_qr_data_uri(url: str) -> str:
    """A real, scannable QR code encoding the given URL, returned as an
    inline base64 PNG data URI (Phishing Simulation roadmap Phase 27) — same
    qrcode + io + base64 pattern already proven in this codebase for TOTP
    MFA setup (app/routers/auth.py's totp_setup route). Embedding it this
    way, rather than a real image attachment, needs zero changes to
    email_service.py's send_email(): body_html is passed to SendGrid as
    plain HTML with no rewriting, so a data: URI <img> just works."""
    qr = qrcode.QRCode(version=1, box_size=8, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"


def _render_content(
    template_id: str, subject_override: str | None, body_html_override: str | None,
    click_url: str, report_url: str,
) -> tuple[str, str]:
    """Custom content is preferred over the built-in template when
    provided. Click tracking must survive customization even if whoever
    edited the body dropped the {click_url} placeholder — a body with no
    trackable link defeats the whole point of tracking clicks — so a
    fallback link is appended rather than silently losing that signal.
    {report_url} gets the same treatment — a body that drops it still needs
    a real "report this" path, since report rate is the metric every
    reference platform treats as more meaningful than click rate.

    {qr_code} (Phishing Simulation roadmap Phase 27) is a third, optional
    placeholder — unlike {click_url}/{report_url} it has no fallback
    injection if missing, since a QR code is an intentional stylistic
    choice for a lure, not a tracking requirement the way the report link
    is; {click_url} already covers the tracking guarantee on its own."""
    template = BUILT_IN_TEMPLATES.get(template_id, {})
    subject = subject_override or template.get("subject", "")
    raw_body = body_html_override if body_html_override is not None else template.get("body_html", "")

    has_click = "{click_url}" in raw_body
    has_report = "{report_url}" in raw_body
    body_html = raw_body
    if has_click or has_report:
        body_html = body_html.replace("{click_url}", click_url).replace("{report_url}", report_url)
    if "{qr_code}" in body_html:
        body_html = body_html.replace("{qr_code}", _generate_qr_data_uri(click_url))
    if not has_click:
        body_html += f'<p><a href="{click_url}">Continue</a></p>'
    if not has_report:
        body_html += f'<p style="font-size:11px;color:#888">Not expecting this? <a href="{report_url}">Report this email</a></p>'
    return subject, body_html


def _recipient_role_summary(entries: list[dict]) -> str:
    """Aggregate, not per-recipient — content is still generated once per
    campaign (see launch_campaign's comment on why), so this can only ever
    shape the single email's overall pretext toward the roles actually on
    the list, never address any one recipient individually. Returns "" if
    no entry has a job_title, so the prompt doesn't mention roles at all
    when there's nothing real to say."""
    titles = [e.get("job_title") for e in entries if e.get("job_title")]
    if not titles:
        return ""
    sample = ", ".join(dict.fromkeys(titles[:5]))  # de-duped, order-preserving
    return f"{len(titles)} of {len(entries)} recipients on this list have a job title on file (e.g. {sample}) — the pretext may draw on these roles in general terms, but must stay plausible for anyone on the list, not just role-holders."


async def _dmarc_context_for_tenant(db: AsyncSession, tenant_id: uuid.UUID) -> str:
    """Best-effort DMARC posture summary for the tenant's primary domain —
    used only as LLM prompt context (Coverage Map plan Phase 7's "correlated
    with live DMARC posture", made real). Reads the already-monitored
    Domain row rather than a fresh live lookup — this is the same posture
    Sentinel already tracks for the customer, not a new external call.
    Returns "" (not an error) if there's no domain to check yet."""
    result = await db.execute(
        select(Domain).where(Domain.tenant_id == tenant_id, Domain.is_active == True)
        .order_by(Domain.ownership_verified.desc()).limit(1)
    )
    domain = result.scalar_one_or_none()
    if not domain:
        return ""
    if domain.dmarc_stage == "reject":
        return f"{domain.name} enforces DMARC at p=reject ({domain.dmarc_pct}%) — a spoofed sender claiming to be this domain would likely be blocked or flagged, so the lure should rely on plausibility rather than sender-address spoofing."
    if domain.dmarc_stage in ("quarantine", "monitor"):
        return f"{domain.name}'s DMARC policy is {domain.dmarc_stage} ({domain.dmarc_pct}%) — partial enforcement."
    return f"{domain.name} does not enforce DMARC (policy: {domain.dmarc_stage}) — a spoofed sender is more likely to reach the inbox unflagged."


async def resolve_campaign_content(
    db: AsyncSession, tenant_id: uuid.UUID, target_list: PhishingTargetList, template_id: str,
    subject_override: str | None, body_html_override: str | None, use_llm: bool, company_name: str,
) -> tuple[str | None, str | None, bool, str | None]:
    """The generation step, decoupled from actually sending anything —
    shared by the launch path below and by the content-preview endpoint
    (Coverage Map plan Phase 7's mandatory human-review-before-send rail).
    Returns (subject_override, body_html_override, llm_generated,
    dmarc_context) with {click_url} still a literal placeholder — real
    per-recipient substitution happens only at actual send time."""
    if not use_llm:
        return subject_override, body_html_override, False, None

    dmarc_context = await _dmarc_context_for_tenant(db, tenant_id)
    lure_category = template_id if template_id in BUILT_IN_TEMPLATES else next(iter(BUILT_IN_TEMPLATES))
    subject_override, body_html_override, llm_generated = await generate_campaign_content(
        lure_category, company_name, dmarc_context=dmarc_context,
        recipient_context=_recipient_role_summary(target_list.entries),
    )
    return subject_override, body_html_override, llm_generated, (dmarc_context or None)


async def launch_campaign(
    db: AsyncSession, engagement: Engagement, target_list: PhishingTargetList, template_id: str,
    subject_override: str | None = None, body_html_override: str | None = None,
    use_llm: bool = False, company_name: str = "your organization",
    approved_content: tuple[str | None, str | None, bool, str | None] | None = None,
    landing_page_id: str | None = None,
    entries_override: list[dict] | None = None,
    audience_label: str | None = None,
) -> PhishingCampaign:
    """approved_content, when given, is exactly what a human reviewed via
    resolve_campaign_content()+the preview endpoint — using it here instead
    of generating again guarantees what was approved is what ships, even
    though content is otherwise fresh-generated per launch (not cached).
    landing_page_id is stored on the campaign itself (not just read live
    from the engagement's scope at click time), so a later change to the
    engagement's default doesn't silently rewrite what an already-launched
    campaign's real recipients actually saw.

    entries_override/audience_label (Phishing Simulation roadmap Phase 15):
    when given, only entries_override is sent to — never target_list.entries
    — while target_list_id on the campaign still references the real,
    complete list. Callers (the router) resolve which subset of the list's
    entries a launch is scoped to; this function only knows how to send to
    whichever entries it's handed. None/None (the default) sends to every
    entry on the list, exactly as before this phase existed."""
    if template_id not in BUILT_IN_TEMPLATES and body_html_override is None and not use_llm:
        raise ValueError(f"Unknown template_id: {template_id}")
    if landing_page_id not in BUILT_IN_LANDING_PAGES:
        landing_page_id = _DEFAULT_LANDING_PAGE_ID

    campaign = PhishingCampaign(
        id=uuid.uuid4(), tenant_id=engagement.tenant_id, engagement_id=engagement.id,
        target_list_id=target_list.id, template_id=template_id, status="sending",
        landing_page_id=landing_page_id, audience_label=audience_label,
    )
    db.add(campaign)
    await db.flush()

    # Generated once per campaign launch, not per recipient — real cost/
    # rate-limit constraints, and every recipient in one campaign seeing
    # deliberately-varied wording wouldn't reflect a real phishing sender
    # anyway. Fresh again next cycle (Coverage Map plan Phase 7's "fresh
    # generation per campaign" decision), not cached across launches.
    if approved_content is not None:
        subject_override, body_html_override, llm_generated, dmarc_context = approved_content
        campaign.dmarc_context = dmarc_context
    else:
        subject_override, body_html_override, llm_generated, dmarc_context = await resolve_campaign_content(
            db, engagement.tenant_id, target_list, template_id,
            subject_override, body_html_override, use_llm, company_name,
        )
        campaign.dmarc_context = dmarc_context

    sent_body_html: str | None = None
    for entry in (entries_override if entries_override is not None else target_list.entries):
        recipient_email = entry.get("email")
        if not recipient_email:
            continue

        token = secrets.token_urlsafe(32)
        recipient_hash = _hash_recipient(recipient_email, engagement.tenant_id)
        urls = _tracking_urls(token)

        subject, body_html = _render_content(
            template_id, subject_override, body_html_override, urls["click_url"], urls["report_url"],
        )
        # The open-tracking pixel is always appended regardless of
        # customization — opens tracking must survive content edits the
        # same way click tracking does above.
        body_html += f'<img src="{urls["pixel_url"]}" width="1" height="1" style="display:none">'

        # send_email()'s real result decides the event, not an assumption —
        # a transport failure (Phishing Simulation roadmap Phase 17) must
        # never be silently recorded as "sent", or "100% delivered" could be
        # false. `sent` is only ever written for a genuine success.
        delivered = await send_email(db, recipient_email, subject, body_html)
        db.add(PhishingEvent(
            id=uuid.uuid4(), tenant_id=engagement.tenant_id, campaign_id=campaign.id,
            recipient_hash=recipient_hash, recipient_token=token,
            event_type="sent" if delivered else "send_failed",
        ))
        if delivered and sent_body_html is None:
            # Real evidence of what one actual recipient received this
            # cycle — captured once, from the first genuinely delivered
            # entry, since every recipient's body is identical except for
            # the embedded per-recipient tracking token.
            sent_body_html = body_html

    campaign.status = "complete"
    campaign.llm_generated = llm_generated
    campaign.subject_sent = subject_override
    campaign.body_html_sent = sent_body_html
    engagement.last_scanned_at = datetime.now(timezone.utc)
    engagement.last_scan_status = "success"
    engagement.last_scan_error = None
    await db.commit()
    await db.refresh(campaign)
    return campaign


async def _record_event(
    db: AsyncSession, token: str, event_type: str,
    ip_address: str | None = None, user_agent: str | None = None, destination_url: str | None = None,
) -> PhishingEvent | None:
    result = await db.execute(
        select(PhishingEvent).where(PhishingEvent.recipient_token == token, PhishingEvent.event_type == "sent")
    )
    sent_event = result.scalar_one_or_none()
    if not sent_event:
        return None  # unknown/expired token — nothing to attribute this to

    event = PhishingEvent(
        id=uuid.uuid4(), tenant_id=sent_event.tenant_id, campaign_id=sent_event.campaign_id,
        recipient_hash=sent_event.recipient_hash, recipient_token=token, event_type=event_type,
        ip_address=ip_address, user_agent=user_agent, destination_url=destination_url,
    )
    db.add(event)
    await db.commit()
    return event


async def record_open(db: AsyncSession, token: str, ip_address: str | None = None, user_agent: str | None = None) -> None:
    await _record_event(db, token, "opened", ip_address, user_agent, _tracking_urls(token)["pixel_url"])


async def record_click(db: AsyncSession, token: str, ip_address: str | None = None, user_agent: str | None = None) -> str:
    event = await _record_event(db, token, "clicked", ip_address, user_agent, _tracking_urls(token)["click_url"])
    urls = _tracking_urls(token)
    landing_page_id = _DEFAULT_LANDING_PAGE_ID
    company_name = "your organization"
    if event:
        campaign = await db.get(PhishingCampaign, event.campaign_id)
        if campaign:
            await _ensure_training_assignment(db, event, campaign, "clicked")
            landing_page_id = campaign.landing_page_id or _DEFAULT_LANDING_PAGE_ID
            tenant = await db.get(Tenant, event.tenant_id)
            if tenant:
                company_name = tenant.brand_name or tenant.name
                await _maybe_assign_training_course(db, tenant, campaign, event.recipient_hash)

    page = BUILT_IN_LANDING_PAGES.get(landing_page_id, BUILT_IN_LANDING_PAGES[_DEFAULT_LANDING_PAGE_ID])
    return page["html"].format(submit_url=urls["submit_url"], lesson_url=urls["lesson_url"], company_name=company_name)


async def record_credential_submit(
    db: AsyncSession, token: str, ip_address: str | None = None, user_agent: str | None = None,
) -> str:
    """The submitted username/password are deliberately never passed into
    this function at all — only the fact that a POST occurred is logged,
    per PHISHING_DESIGN.md's carryover of the original "never persists the
    actual password value" rule extended to the username too."""
    event = await _record_event(db, token, "credential_entered", ip_address, user_agent, _tracking_urls(token)["submit_url"])
    if event:
        campaign = await db.get(PhishingCampaign, event.campaign_id)
        if campaign:
            await _ensure_training_assignment(db, event, campaign, "credential_entered")
            tenant = await db.get(Tenant, event.tenant_id)
            if tenant:
                await _maybe_assign_training_course(db, tenant, campaign, event.recipient_hash)
    return _LANDING_PAGE_RESULT_HTML.format(lesson_url=_tracking_urls(token)["lesson_url"])


async def _maybe_assign_training_course(db: AsyncSession, tenant: Tenant, campaign: PhishingCampaign, recipient_hash: str) -> None:
    """No-op unless the tenant has configured auto_assign_training_course_id
    (Settings -> Training defaults). Additional to, not instead of, the
    always-on micro-lesson above — see compute_tenant_phishing_summary's
    comment on why these are kept as two separate metrics. Swallows its
    own failures: a broken email send or a missing course must never break
    the landing page the real recipient is looking at."""
    if not tenant.auto_assign_training_course_id:
        return
    try:
        target_list = await db.get(PhishingTargetList, campaign.target_list_id)
        if not target_list:
            return
        from app.services.training_course_service import assign_course_on_phishing_failure
        await assign_course_on_phishing_failure(db, tenant, campaign, target_list, recipient_hash)
    except Exception:
        _log.exception("Failed to auto-assign training course for tenant %s", tenant.id)


async def record_report(db: AsyncSession, token: str, ip_address: str | None = None, user_agent: str | None = None) -> str:
    """The recipient used the 'Report this email' link — a positive
    outcome, tracked as its own event_type so report rate (the metric
    every reference platform treats as more meaningful than click rate)
    is a real, queryable number rather than folded into 'clicked'."""
    await _record_event(db, token, "reported", ip_address, user_agent, _tracking_urls(token)["report_url"])
    return _REPORT_LANDING_PAGE_HTML


async def _find_sent_event(db: AsyncSession, token: str) -> PhishingEvent | None:
    result = await db.execute(
        select(PhishingEvent).where(PhishingEvent.recipient_token == token, PhishingEvent.event_type == "sent")
    )
    return result.scalar_one_or_none()


async def _ensure_training_assignment(
    db: AsyncSession, sent_event: PhishingEvent, campaign: PhishingCampaign, trigger_event_type: str,
) -> TrainingAssignment:
    """Get-or-create on the (tenant, campaign, recipient) unique
    constraint, so a repeat click never produces a second lesson. If a
    later trigger is more severe (credential_entered after an earlier
    bare click), the assignment's trigger is upgraded in place — the
    reporting should reflect the worst thing that happened, not just the
    first."""
    result = await db.execute(
        select(TrainingAssignment).where(
            TrainingAssignment.tenant_id == sent_event.tenant_id,
            TrainingAssignment.campaign_id == campaign.id,
            TrainingAssignment.recipient_hash == sent_event.recipient_hash,
        )
    )
    assignment = result.scalar_one_or_none()
    if assignment is None:
        assignment = TrainingAssignment(
            id=uuid.uuid4(), tenant_id=sent_event.tenant_id, campaign_id=campaign.id,
            recipient_hash=sent_event.recipient_hash, lure_category=campaign.template_id,
            trigger_event_type=trigger_event_type, status="assigned",
        )
        db.add(assignment)
    elif assignment.trigger_event_type == "clicked" and trigger_event_type == "credential_entered":
        assignment.trigger_event_type = trigger_event_type
    await db.commit()
    await db.refresh(assignment)
    return assignment


def _render_lesson_html(lesson: dict, token: str) -> str:
    flags_html = "".join(f"<li>{f}</li>" for f in lesson["red_flags"])
    options_html = "".join(
        f'<label style="display:block;margin:6px 0;font-size:13px;cursor:pointer">'
        f'<input type="radio" name="reflection_response" value="{o["key"]}" required> {o["label"]}</label>'
        for o in lesson["reflection_options"]
    )
    respond_url = _tracking_urls(token)["lesson_url"] + "/respond"
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{lesson["title"]}</title></head>
<body style="font-family:sans-serif;max-width:520px;margin:60px auto;padding:0 20px;background:#f4f5f7;color:#1a1c22;">
  <div style="background:#fff;border-radius:12px;padding:28px 32px;box-shadow:0 1px 3px rgba(0,0,0,.08);">
    <div style="display:inline-block;font-size:11px;font-weight:700;letter-spacing:.04em;color:#2a5b52;background:#e0efe5;padding:3px 10px;border-radius:999px;margin-bottom:14px;">SECURITY AWARENESS · 2 MIN</div>
    <h2 style="margin:0 0 12px;">{lesson["title"]}</h2>
    <p style="line-height:1.6;color:#444;">{lesson["what_happened"]}</p>
    <h3 style="font-size:14px;margin:22px 0 8px;">What gave it away</h3>
    <ul style="line-height:1.7;color:#333;padding-left:20px;">{flags_html}</ul>
    <form method="POST" action="{respond_url}" style="margin-top:24px;padding-top:20px;border-top:1px solid #e5e7eb;">
      <p style="font-size:13px;font-weight:600;margin:0 0 10px;">Before this, would any of these have caught your attention?</p>
      {options_html}
      <button type="submit" style="margin-top:12px;padding:9px 18px;background:#2a5b52;color:#fff;border:none;border-radius:6px;font-size:13px;cursor:pointer;">Done</button>
    </form>
  </div>
</body></html>"""


_LESSON_THANKS_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Thanks</title></head>
<body style="font-family:sans-serif;max-width:480px;margin:80px auto;">
  <h2>Thanks — noted</h2>
  <p>No further action needed. This was part of an authorized security awareness
  exercise run by your organization via Sentinel Command.</p>
</body></html>"""


async def render_lesson_page(db: AsyncSession, token: str) -> str | None:
    sent_event = await _find_sent_event(db, token)
    if not sent_event:
        return None  # unknown/expired token — silent, same convention as every other tracking route

    campaign = await db.get(PhishingCampaign, sent_event.campaign_id)
    if not campaign:
        return None

    # Reaching this page at all implies at least a click — lazily create
    # the assignment here too, so a direct hit on the lesson link always
    # has something to record against, not just the record_click() path.
    await _ensure_training_assignment(db, sent_event, campaign, "clicked")

    lesson = get_lesson_content(campaign.template_id, campaign.subject_sent, campaign.body_html_sent)
    return _render_lesson_html(lesson, token)


async def record_lesson_response(db: AsyncSession, token: str, reflection_response: str) -> str | None:
    sent_event = await _find_sent_event(db, token)
    if not sent_event:
        return None

    campaign = await db.get(PhishingCampaign, sent_event.campaign_id)
    if not campaign:
        return None

    assignment = await _ensure_training_assignment(db, sent_event, campaign, "clicked")
    assignment.reflection_response = reflection_response
    assignment.status = "completed"
    assignment.completed_at = datetime.now(timezone.utc)
    await db.commit()
    return _LESSON_THANKS_HTML


async def unmask_recipient(db: AsyncSession, campaign: PhishingCampaign, recipient_hash: str) -> dict | None:
    """Admin-only, audit-logged at the router layer. Re-hashes the target
    list's *current* entries rather than reversing a stored value — see
    module docstring."""
    result = await db.execute(select(PhishingTargetList).where(PhishingTargetList.id == campaign.target_list_id))
    target_list = result.scalar_one_or_none()
    if not target_list:
        return None

    for entry in target_list.entries:
        email = entry.get("email")
        if email and _hash_recipient(email, campaign.tenant_id) == recipient_hash:
            return {"email": email, "display_name": entry.get("display_name")}
    return None


async def compute_department_breakdown(db: AsyncSession, campaign: PhishingCampaign) -> list[dict]:
    """Real, privacy-preserving department-level results for one campaign.
    Re-hashes the target list's *current* entries (same technique as
    unmask_recipient above) to attribute each pseudonymized recipient_hash
    to a department, entirely server-side — the hash-to-department mapping
    itself never leaves this function. The response is aggregate counts
    only, never a per-person breakdown, and a department with zero real
    recipients on this campaign is simply absent, never a fabricated 0%.
    Entries with no department recorded are excluded rather than lumped
    into a misleading "Unknown" bucket."""
    result = await db.execute(select(PhishingTargetList).where(PhishingTargetList.id == campaign.target_list_id))
    target_list = result.scalar_one_or_none()
    if not target_list:
        return []

    hash_to_department: dict[str, str] = {}
    for entry in target_list.entries:
        email, department = entry.get("email"), entry.get("department")
        if email and department:
            hash_to_department[_hash_recipient(email, campaign.tenant_id)] = department
    if not hash_to_department:
        return []

    events_result = await db.execute(
        select(PhishingEvent.recipient_hash, PhishingEvent.event_type).where(PhishingEvent.campaign_id == campaign.id)
    )
    event_types_by_hash: dict[str, set[str]] = {}
    for recipient_hash, event_type in events_result.all():
        event_types_by_hash.setdefault(recipient_hash, set()).add(event_type)

    totals: dict[str, dict[str, int]] = {}
    for recipient_hash, event_types in event_types_by_hash.items():
        department = hash_to_department.get(recipient_hash)
        if not department or "sent" not in event_types:
            continue
        bucket = totals.setdefault(department, {"sent": 0, "clicked": 0, "credential_entered": 0})
        bucket["sent"] += 1
        if "clicked" in event_types:
            bucket["clicked"] += 1
        if "credential_entered" in event_types:
            bucket["credential_entered"] += 1

    return [
        {"department": department, **bucket}
        for department, bucket in sorted(totals.items(), key=lambda kv: -kv[1]["sent"])
    ]


# ── Custom-template difficulty gating (Phishing Simulation roadmap Phase
# 23) — PhishingCustomTemplate.difficulty existed as authoring metadata
# with nothing enforcing it. The bar chosen here is deliberately grounded
# in what already exists (a completed TrainingAssignment) rather than
# inventing a "beginner track" concept that belongs to the not-yet-built
# course library (Phase 24) — every real recipient on the target list
# needs at least one completed post-click lesson on record before a
# medium/high-difficulty lure is offered against them.

async def is_target_list_training_ready(db: AsyncSession, tenant_id: uuid.UUID, target_list: "PhishingTargetList") -> bool:
    entries = target_list.entries or []
    hashes = {_hash_recipient(e["email"], tenant_id) for e in entries if e.get("email")}
    if not hashes:
        return False  # nothing to protect, but also no track record to justify a harder lure
    completed_result = await db.execute(
        select(TrainingAssignment.recipient_hash)
        .where(
            TrainingAssignment.tenant_id == tenant_id,
            TrainingAssignment.recipient_hash.in_(hashes),
            TrainingAssignment.status == "completed",
        )
        .distinct()
    )
    completed_hashes = set(completed_result.scalars().all())
    return hashes.issubset(completed_hashes)


class CustomTemplateNotLaunchable(Exception):
    """Raised with a real, user-facing reason — never a generic 'not
    allowed'. Caught and translated to a 400 by the manual launch route,
    and caught by the recurring scheduler to skip just that cycle (see
    poll_due_phishing_campaigns) rather than crash the whole poll pass."""


async def validate_custom_template_for_launch(
    db: AsyncSession, tenant_id: uuid.UUID, template_id: str, target_list: "PhishingTargetList", use_llm: bool,
) -> None:
    """No-op for a real built-in template_id. Shared by the manual launch
    route and the recurring scheduler specifically so eligibility is
    re-verified on every single cycle — a target list can change between
    cycles (new people added who haven't completed training yet), so a
    check made only once at first launch would erode over time."""
    if template_id in BUILT_IN_TEMPLATES:
        return
    custom_template = None
    try:
        custom_template = await db.get(PhishingCustomTemplate, uuid.UUID(template_id))
    except ValueError:
        pass
    if not custom_template or custom_template.tenant_id != tenant_id:
        raise CustomTemplateNotLaunchable(f"Unknown template_id '{template_id}'")
    if use_llm:
        raise CustomTemplateNotLaunchable("Custom templates are static content — turn off AI generation, or pick a built-in lure category instead")
    if custom_template.difficulty in ("medium", "high"):
        ready = await is_target_list_training_ready(db, tenant_id, target_list)
        if not ready:
            raise CustomTemplateNotLaunchable(
                f"'{custom_template.label}' is a {custom_template.difficulty}-difficulty lure — every recipient "
                f"on this target list needs at least one completed training assignment first"
            )


async def compute_department_training_completion(db: AsyncSession, tenant_id: uuid.UUID) -> list[dict]:
    """Real, privacy-preserving training-completion by department, across
    every campaign this tenant has ever run — not scoped to one campaign
    like compute_department_breakdown above. Each TrainingAssignment is
    resolved against its OWN campaign's target list (not a tenant-wide
    union of every list this tenant has ever had), so department
    attribution always reflects the real list that assignment came from.
    Same privacy discipline: the hash-to-department mapping never leaves
    this function, only aggregate counts."""
    assignment_result = await db.execute(
        select(TrainingAssignment.recipient_hash, TrainingAssignment.status, PhishingCampaign.target_list_id)
        .join(PhishingCampaign, PhishingCampaign.id == TrainingAssignment.campaign_id)
        .where(TrainingAssignment.tenant_id == tenant_id)
    )
    rows = assignment_result.all()
    if not rows:
        return []

    target_list_ids = {target_list_id for _, _, target_list_id in rows}
    lists_result = await db.execute(select(PhishingTargetList).where(PhishingTargetList.id.in_(target_list_ids)))
    hash_to_department: dict[str, str] = {}
    for target_list in lists_result.scalars().all():
        for entry in target_list.entries:
            email, department = entry.get("email"), entry.get("department")
            if email and department:
                hash_to_department[_hash_recipient(email, tenant_id)] = department
    if not hash_to_department:
        return []

    totals: dict[str, dict[str, int]] = {}
    for recipient_hash, status, _ in rows:
        department = hash_to_department.get(recipient_hash)
        if not department:
            continue
        bucket = totals.setdefault(department, {"assigned": 0, "completed": 0})
        bucket["assigned"] += 1
        if status == "completed":
            bucket["completed"] += 1

    return [
        {"department": department, **bucket}
        for department, bucket in sorted(totals.items(), key=lambda kv: -kv[1]["assigned"])
    ]


async def poll_due_phishing_campaigns(db: AsyncSession) -> int:
    """Scheduler entry point. One signed Rules-of-Engagement authorizes an
    ongoing cadence stated in the document itself — no per-cycle consent
    (PHISHING_DESIGN.md Section 3.3). Due-ness reuses the same
    last_scanned_at field Tier A uses, with the cadence read from this
    engagement's own scope rather than a single global interval."""
    result = await db.execute(
        select(Engagement).where(Engagement.tier == "phishing", Engagement.status == "active")
    )
    engagements = result.scalars().all()

    launched = 0
    for engagement in engagements:
        scope = engagement.scope or {}
        cadence_days = scope.get("cadence_days")
        target_list_id = scope.get("target_list_id")
        template_id = scope.get("template_id")
        if not (cadence_days and target_list_id and template_id):
            continue

        # A scheduled start time gates the FIRST launch only — once real
        # send history exists, this check is always satisfied (the time
        # has passed by definition), so it never blocks the recurring
        # cadence below.
        scheduled_start_at = scope.get("scheduled_start_at")
        if scheduled_start_at:
            try:
                scheduled_dt = datetime.fromisoformat(scheduled_start_at)
                if scheduled_dt.tzinfo is None:
                    scheduled_dt = scheduled_dt.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) < scheduled_dt:
                    continue
            except ValueError:
                _log.warning("Phishing engagement has an unparseable scheduled_start_at: engagement_id=%s", engagement.id)

        # A one-time engagement (recurring=False) never fires again once it
        # has a real send in its history — cadence_days is only meaningful
        # for a recurring engagement.
        if scope.get("recurring", True) is False and engagement.last_scanned_at is not None:
            continue

        due = engagement.last_scanned_at is None or engagement.last_scanned_at < (
            datetime.now(timezone.utc) - timedelta(days=cadence_days)
        )
        if not due:
            continue

        try:
            target_list_result = await db.execute(
                select(PhishingTargetList).where(PhishingTargetList.id == target_list_id)
            )
            target_list = target_list_result.scalar_one_or_none()
            if not target_list:
                _log.warning("Phishing engagement references a missing target list: engagement_id=%s", engagement.id)
                continue
            tenant = await db.get(Tenant, engagement.tenant_id)
            if tenant and tenant.phishing_paused:
                _log.info("Skipping due phishing campaign — tenant has HALT ALL SENDS active: engagement_id=%s", engagement.id)
                continue
            try:
                await validate_custom_template_for_launch(
                    db, engagement.tenant_id, template_id, target_list, bool(scope.get("llm_generate_fresh")),
                )
            except CustomTemplateNotLaunchable as e:
                # A real, expected outcome (e.g. the target list changed
                # and is no longer training-ready) — logged as info, not
                # exception, and this cycle is skipped rather than the
                # whole poll pass failing.
                _log.info("Skipping due phishing campaign — template not launchable: engagement_id=%s reason=%s", engagement.id, e)
                continue
            await launch_campaign(
                db, engagement, target_list, template_id,
                subject_override=scope.get("subject_override"), body_html_override=scope.get("body_html_override"),
                use_llm=bool(scope.get("llm_generate_fresh")), company_name=tenant.name if tenant else "your organization",
                landing_page_id=scope.get("landing_page_id"),
            )
            launched += 1
        except Exception:
            _log.exception("Scheduled phishing campaign launch failed unexpectedly: engagement_id=%s", engagement.id)

    return launched


# ── Human Risk score (Coverage Map plan phishing transformation, Phase 9) ────
# v1 weights, open to recalibration once real portfolio data exists across
# many tenants — documented here rather than derived from any external
# benchmark. Credential entry is weighted far above a bare click (giving up
# a password is the outcome that actually matters); reporting is rewarded,
# not just "not penalized"; failing to complete assigned training after a
# real miss compounds the risk rather than resetting it.
_HUMAN_RISK_CLICK_PENALTY = 30
_HUMAN_RISK_CREDENTIAL_PENALTY = 60
_HUMAN_RISK_REPORT_BONUS = 15
_HUMAN_RISK_TRAINING_INCOMPLETE_PENALTY = 15


async def compute_tenant_phishing_summary(db: AsyncSession, tenant_id: uuid.UUID) -> dict | None:
    """The raw counts and real rates behind compute_tenant_human_risk_score
    below — split out so a dashboard can show the actual component numbers
    (click rate, credential rate, report rate, training completion) rather
    than only the blended score. None means this tenant has never run a
    phishing campaign, never a fabricated 0 for every rate."""
    event_result = await db.execute(
        select(PhishingEvent.event_type, func.count())
        .where(PhishingEvent.tenant_id == tenant_id)
        .group_by(PhishingEvent.event_type)
    )
    counts = {event_type: count for event_type, count in event_result.all()}
    sent = counts.get("sent", 0)
    if sent == 0:
        return None

    click_rate = counts.get("clicked", 0) / sent
    credential_rate = counts.get("credential_entered", 0) / sent
    report_rate = counts.get("reported", 0) / sent

    training_result = await db.execute(
        select(TrainingAssignment.status, func.count())
        .where(TrainingAssignment.tenant_id == tenant_id)
        .group_by(TrainingAssignment.status)
    )
    training_counts = {status: count for status, count in training_result.all()}
    assigned = sum(training_counts.values())
    completed = training_counts.get("completed", 0)

    # Course-based training (Phishing Simulation roadmap Phase 24) is
    # deliberately kept as its OWN separate rate below, not merged into
    # the micro-lesson numbers above — the micro-lesson fires immediately
    # on the landing page regardless of whether a tenant has also
    # configured a deeper course, so a recipient can legitimately have
    # one without the other. Blending them would conflate two different
    # signals into one misleading rate. compute_tenant_human_risk_score's
    # formula below intentionally still scores on the micro-lesson rate
    # only — unchanged, so existing scoring behavior/tests aren't
    # disturbed by adding this new, additional, honestly-separate metric.
    from app.models.training_course import TrainingCourseAssignment
    course_training_result = await db.execute(
        select(TrainingCourseAssignment.status, func.count())
        .where(TrainingCourseAssignment.tenant_id == tenant_id, TrainingCourseAssignment.source == "phishing_failure")
        .group_by(TrainingCourseAssignment.status)
    )
    course_training_counts = {status: count for status, count in course_training_result.all()}
    course_assigned = sum(course_training_counts.values())
    course_completed = course_training_counts.get("completed", 0)
    course_training_completion_rate = (course_completed / course_assigned) if course_assigned else None
    assigned_rate = assigned / sent
    # None (not 1.0) when nothing's ever been assigned — "100% complete" of
    # zero assignments is a misleading thing to display, even though the
    # scoring formula below needs a neutral 1.0 to avoid penalizing a
    # tenant that's simply never had a real miss to assign training for.
    training_completion_rate = (completed / assigned) if assigned else None

    return {
        "sent": sent, "clicked": counts.get("clicked", 0), "credential_entered": counts.get("credential_entered", 0),
        "reported": counts.get("reported", 0), "click_rate": click_rate, "credential_rate": credential_rate,
        "report_rate": report_rate, "training_assigned": assigned, "training_completed": completed,
        "training_completion_rate": training_completion_rate, "_assigned_rate": assigned_rate,
        "course_training_assigned": course_assigned, "course_training_completed": course_completed,
        "course_training_completion_rate": course_training_completion_rate,
    }


async def get_tenant_watchlist(db: AsyncSession, tenant_id: uuid.UUID, limit: int = 10) -> list[dict]:
    """The real per-recipient history behind the Dashboard's Watchlist
    widget (Phishing Simulation roadmap Phase 30c) — the same cross-
    campaign aggregation get_engagement_recipients() already does in
    phishing.py, but tenant-wide instead of scoped to one engagement, and
    ranked so the riskiest real history surfaces first. _hash_recipient()
    is keyed only by tenant (not engagement/campaign), so grouping by
    recipient_hash tenant-wide correctly merges one person's full history
    across every engagement they've ever appeared on.

    Returns dicts shaped identically to EngagementRecipientOut (schemas/
    phishing.py) — deliberately, not a lighter summary shape, so the
    frontend can open the exact same evidence panel already built for the
    per-engagement People view directly from a Watchlist row, reusing its
    proven unmask flow instead of new drill-down UI. Still pseudonymized
    by construction: only a hash and real counts leave this function,
    never an identity."""
    events_result = await db.execute(
        select(PhishingEvent).where(PhishingEvent.tenant_id == tenant_id).order_by(PhishingEvent.occurred_at)
    )
    events = events_result.scalars().all()
    if not events:
        return []

    campaign_ids = {e.campaign_id for e in events}
    campaigns_result = await db.execute(select(PhishingCampaign).where(PhishingCampaign.id.in_(campaign_ids)))
    campaigns = {c.id: c for c in campaigns_result.scalars().all()}

    by_recipient: dict[str, list[PhishingEvent]] = {}
    for event in events:
        by_recipient.setdefault(event.recipient_hash, []).append(event)

    training_result = await db.execute(
        select(TrainingAssignment).where(TrainingAssignment.tenant_id == tenant_id).order_by(TrainingAssignment.assigned_at)
    )
    training_by_recipient: dict[str, list[TrainingAssignment]] = {}
    for t in training_result.scalars().all():
        training_by_recipient.setdefault(t.recipient_hash, []).append(t)

    rows = []
    for h, recipient_events in by_recipient.items():
        by_campaign: dict[uuid.UUID, list[PhishingEvent]] = {}
        for e in recipient_events:
            by_campaign.setdefault(e.campaign_id, []).append(e)

        campaign_summaries = sorted(
            (
                {
                    "campaign_id": str(cid), "launched_at": campaigns[cid].launched_at.isoformat(),
                    "event_types": sorted({e.event_type for e in evs}),
                }
                for cid, evs in by_campaign.items() if cid in campaigns
            ),
            key=lambda c: c["launched_at"],
        )
        trainings = training_by_recipient.get(h, [])
        credential_count = sum(1 for e in recipient_events if e.event_type == "credential_entered")
        click_count = sum(1 for evs in by_campaign.values() if any(e.event_type == "clicked" for e in evs))

        rows.append({
            "recipient_hash": h, "campaigns": campaign_summaries,
            "event_types": sorted({e.event_type for e in recipient_events}),
            "repeat_click_count": click_count,
            "training_status": trainings[-1].status if trainings else None,
            # Ranking only — not part of the schema, stripped before return.
            "_risk_rank": credential_count * 100 + click_count,
        })

    # Only real risk belongs on a "Watchlist" — someone who was sent a
    # campaign and never clicked or entered credentials isn't a risk
    # signal, just a person who was sent an email, so they're excluded
    # rather than padding the list with zero-risk rows.
    at_risk = [r for r in rows if r["_risk_rank"] > 0]
    at_risk.sort(key=lambda r: r["_risk_rank"], reverse=True)
    for r in at_risk:
        del r["_risk_rank"]
    return at_risk[:limit]


async def get_phishing_campaigns_summary(db: AsyncSession, tenant_id: uuid.UUID) -> list[dict]:
    """Every phishing campaign this tenant has ever launched, joined with
    its own event-type counts, in two grouped queries total (Phishing
    Simulation roadmap Phase 29b) — replaces what the landing page used to
    do as one list call per engagement plus one events call per campaign
    (485 requests on a real dev tenant). Mirrors the join+group-by shape
    already used by get_phishing_lure_stats() in the router, just grouped
    by campaign instead of by template, and left-joined (not inner-joined)
    so a campaign with zero events yet still appears with all-zero counts
    rather than silently vanishing."""
    campaigns_result = await db.execute(
        select(PhishingCampaign).where(PhishingCampaign.tenant_id == tenant_id).order_by(PhishingCampaign.launched_at.desc())
    )
    campaigns = campaigns_result.scalars().all()
    if not campaigns:
        return []

    counts_result = await db.execute(
        select(PhishingEvent.campaign_id, PhishingEvent.event_type, func.count())
        .where(PhishingEvent.campaign_id.in_([c.id for c in campaigns]))
        .group_by(PhishingEvent.campaign_id, PhishingEvent.event_type)
    )
    counts_by_campaign: dict[uuid.UUID, dict[str, int]] = {}
    for campaign_id, event_type, count in counts_result.all():
        counts_by_campaign.setdefault(campaign_id, {})[event_type] = count

    return [
        {
            "id": str(c.id), "engagement_id": str(c.engagement_id), "target_list_id": str(c.target_list_id),
            "template_id": c.template_id, "launched_at": c.launched_at.isoformat(), "dmarc_context": c.dmarc_context,
            "subject_sent": c.subject_sent,
            "sent": counts_by_campaign.get(c.id, {}).get("sent", 0),
            "opened": counts_by_campaign.get(c.id, {}).get("opened", 0),
            "clicked": counts_by_campaign.get(c.id, {}).get("clicked", 0),
            "credential_entered": counts_by_campaign.get(c.id, {}).get("credential_entered", 0),
            "reported": counts_by_campaign.get(c.id, {}).get("reported", 0),
        }
        for c in campaigns
    ]


async def compute_tenant_human_risk_score(db: AsyncSession, tenant_id: uuid.UUID) -> float | None:
    """0-100, mirroring cloud_scan_service.compute_tenant_cloud_posture_score's
    shape — None means this tenant has never run a phishing campaign
    (nothing to score yet), never a fabricated 0/100. Computed live across
    every campaign this tenant has ever launched, not just the most recent
    one, since a portfolio-level Human Risk figure should reflect a
    standing pattern rather than one cycle's result."""
    summary = await compute_tenant_phishing_summary(db, tenant_id)
    if summary is None:
        return None

    training_completion_rate = summary["training_completion_rate"] if summary["training_completion_rate"] is not None else 1.0
    score = 100.0
    score -= summary["click_rate"] * _HUMAN_RISK_CLICK_PENALTY
    score -= summary["credential_rate"] * _HUMAN_RISK_CREDENTIAL_PENALTY
    score += summary["report_rate"] * _HUMAN_RISK_REPORT_BONUS
    score -= summary["_assigned_rate"] * (1 - training_completion_rate) * _HUMAN_RISK_TRAINING_INCOMPLETE_PENALTY

    return max(0.0, min(100.0, score))


def _score_to_grade(score: float) -> str:
    # Mirrors app/routers/phishing.py's own _score_to_grade exactly — same
    # thresholds, kept as a small local copy rather than a cross-module
    # import, following that function's own established precedent for why
    # (private, stable, trivial; not worth a shared-utility module for one
    # five-line lookup used in two places).
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


def compute_human_risk_components(summary: dict | None, sentiment_score: float | None) -> list[dict]:
    """Breaks the single blended Human Risk Score into named, separately-
    graded components (Phishing Simulation roadmap Phase 30a) — a real
    gap against competitor dashboards that show sub-scores like "Human
    Error"/"Engagement"/"Knowledge"/"Sentiment". This product can't
    honestly show all of those: there is no graded knowledge-check
    anywhere in the codebase (the phishing micro-lesson's reflection
    question is explicitly non-graded, see phishing_lesson_content.py's
    own docstring), so "Knowledge" is deliberately absent here rather than
    invented. The 4 components below are exactly the four real signals
    this product already has — no new weights invented for the first
    three, they're the same _HUMAN_RISK_* constants already used to blend
    the single score, just left un-blended so each one means something on
    its own. `sentiment_score` (0-100 or None) comes from
    training_course_service.compute_tenant_survey_sentiment_score() — kept
    as a caller-supplied argument rather than queried here to avoid a
    circular import (that function lives in a module which already
    imports from this one).

    Takes the already-computed summary dict (no new query) — pass None
    when the tenant has never sent a campaign; components still render
    with real labels and an honestly-empty score/grade rather than
    vanishing entirely, matching how the rest of this dashboard treats
    "never run yet" as a real, nameable state."""
    def _component(label: str, score: float | None) -> dict:
        return {"label": label, "score": score, "grade": _score_to_grade(score) if score is not None else None}

    if summary is None:
        return [
            _component("Click & Credential Resistance", None),
            _component("Reporting Behavior", None),
            _component("Training Completion", None),
            _component("Culture", sentiment_score),
        ]

    resistance_score = max(0.0, 100.0
        - summary["click_rate"] * _HUMAN_RISK_CLICK_PENALTY
        - summary["credential_rate"] * _HUMAN_RISK_CREDENTIAL_PENALTY)
    reporting_score = summary["report_rate"] * 100.0
    training_rate = summary["training_completion_rate"]
    training_score = training_rate * 100.0 if training_rate is not None else None

    return [
        _component("Click & Credential Resistance", resistance_score),
        _component("Reporting Behavior", reporting_score),
        _component("Training Completion", training_score),
        _component("Culture", sentiment_score),
    ]


# ── Hesitation / dwell-time signal (Phishing Simulation roadmap Phase 12) ────
# Nobody in the researched competitor set measures the gap between opening a
# lure and acting on it — a click 2 seconds after open reads very
# differently from one 90 seconds after open, and today's outcome buckets
# ("opened only", "clicked") erase that distinction entirely. Computed live
# from PhishingEvent.occurred_at, which every event already carries — no new
# capture, same query-time-computation convention as
# compute_tenant_human_risk_score above.

def compute_dwell_seconds(events: list["PhishingEvent"]) -> float | None:
    """Seconds between a recipient's first `opened` event and their first
    `clicked`/`credential_entered` event at or after it. None when there's
    no open-then-act pair to measure — no open at all, no act at all, or
    (shouldn't happen, but degrade honestly rather than report nonsense) the
    only act on record precedes the open."""
    opened_at = min((e.occurred_at for e in events if e.event_type == "opened"), default=None)
    if opened_at is None:
        return None
    acted_at = min(
        (e.occurred_at for e in events if e.event_type in ("clicked", "credential_entered") and e.occurred_at >= opened_at),
        default=None,
    )
    if acted_at is None:
        return None
    return (acted_at - opened_at).total_seconds()
