"""
Real e-signature for the Engagement rules-of-engagement (RoE) gate —
ARCHITECTURE.md Section 9. Replaces the "TEMPORARY direct approval" bypass
in engagement.py with a genuine binding signature via Dropbox Sign
(formerly HelloSign): render an engagement-specific RoE document, send it
for hosted (email-link) signing, then flip the Engagement to 'active' only
once Dropbox Sign's webhook confirms every signer actually signed.

Hosted signing (Dropbox Sign emails the signer a link), not embedded
signing, deliberately for v1 — embedded signing needs a Dropbox Sign "API
App" (a client_id) configured on their dashboard first, which is an account
setup step nobody has done yet. Hosted signing needs only an API key and is
just as legally binding; embedded is a pure UX upgrade worth revisiting
once there's a real customer to justify it (ARCHITECTURE.md Section 9).

Text tags (`use_text_tags`), not manual x/y field placement — Dropbox
Sign auto-detects `[sig|req|signer1]`/`[date|req|signer1]` strings baked
into the PDF text and turns them into real signature/date fields. Far
simpler than computing pixel coordinates for a document whose length
varies with the engagement's scope.
"""
from __future__ import annotations

import hmac
import json
import logging
from datetime import datetime, timezone
from hashlib import sha256

import httpx
from playwright.async_api import async_playwright

from app.config import settings
from app.models import Engagement, Tenant

_log = logging.getLogger(__name__)

_API_BASE = "https://api.hellosign.com/v3"


class DropboxSignError(Exception):
    """Raised on any non-2xx response from Dropbox Sign — never swallowed,
    matching the rest of this codebase's no-silent-failure rule."""


def _scope_lines_html(tier: str, scope: dict) -> str:
    if not scope:
        return "<li>No additional scope restrictions specified.</li>"
    lines = []
    for key, value in scope.items():
        if not value:
            continue
        rendered = ", ".join(str(v) for v in value) if isinstance(value, list) else str(value)
        lines.append(f"<li><b>{key.replace('_', ' ')}:</b> {rendered}</li>")
    return "".join(lines) or "<li>No additional scope restrictions specified.</li>"


def _cadence_line_html(engagement: Engagement) -> str:
    """PHISHING_DESIGN.md Section 3.3: one signature authorizes an ongoing
    cadence, stated explicitly in the document itself, rather than
    requiring re-signature every cycle — this is that statement."""
    if engagement.tier != "phishing":
        return ""
    cadence_days = (engagement.scope or {}).get("cadence_days")
    if not cadence_days:
        return ""
    return (
        f"<li>This authorization covers simulated phishing campaigns run against the "
        f"target list referenced in scope every {cadence_days} days, on an ongoing basis, "
        f"until this authorization is revoked — not a single campaign.</li>"
    )


def build_roe_html(engagement: Engagement, tenant: Tenant, signer_name: str, signer_email: str) -> str:
    tier_label = {
        "cloud": "Cloud Account Posture Scanning", "host": "Host & Server Security Scanning",
        "exposure": "External Exposure & DNS Hygiene Scanning", "credential": "Credential Exposure Testing",
        "phishing": "Phishing Simulation", "impersonation": "Domain Impersonation Testing",
        "oauth_risk": "Third-Party OAuth App Risk Scanning",
        "reachability": "Network Reachability Testing", "exploit": "Live Exploitation",
    }.get(engagement.tier, engagement.tier)

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  @page {{ size: A4; margin: 25mm 20mm; }}
  body {{ font-family: Georgia, 'Times New Roman', serif; color: #1a1a2e; font-size: 12px; line-height: 1.6; }}
  h1 {{ font-size: 18px; border-bottom: 2px solid #333; padding-bottom: 10px; }}
  h2 {{ font-size: 13px; text-transform: uppercase; letter-spacing: .5px; margin-top: 22px; }}
  .meta {{ color: #555; font-size: 11px; margin-bottom: 20px; }}
  ul {{ margin: 6px 0; padding-left: 20px; }}
  .sig-block {{ margin-top: 50px; }}
  .sig-line {{ margin-top: 40px; border-top: 1px solid #333; width: 260px; padding-top: 4px; }}
</style></head>
<body>
  <h1>Rules of Engagement — {tier_label}</h1>
  <div class="meta">Prepared for {tenant.name} · Engagement ID {engagement.id} · {datetime.now(timezone.utc).strftime('%Y-%m-%d')}</div>

  <p>This document authorizes Sentinel Command to perform the security testing described below against
  the infrastructure and/or personnel explicitly listed in scope, for the tenant named above. No testing
  outside this scope is authorized by this signature.</p>

  <h2>Scope of engagement</h2>
  <ul>{_scope_lines_html(engagement.tier, engagement.scope)}</ul>

  <h2>Authorization terms</h2>
  <ul>
    {_cadence_line_html(engagement)}
    <li>This authorization may be revoked at any time by the tenant; revocation halts all in-progress and
    future testing under this engagement immediately.</li>
    <li>Testing is limited to the read-only or non-destructive methods appropriate to the tier above;
    Sentinel Command will not intentionally cause service disruption, data loss, or data exfiltration
    beyond what is required to demonstrate a finding.</li>
    <li>Any evidence captured (screenshots, sample data, credentials proof) will be handled per Sentinel's
    data retention and privacy policy.</li>
  </ul>

  <div class="sig-block">
    <h2>Signature</h2>
    <p>{signer_name} &lt;{signer_email}&gt;, on behalf of {tenant.name}</p>
    <div class="sig-line">[sig|req|signer1]</div>
    <div class="sig-line" style="margin-top:20px;">[date|req|signer1]</div>
  </div>
</body></html>"""


async def render_roe_pdf(engagement: Engagement, tenant: Tenant, signer_name: str, signer_email: str) -> bytes:
    html = build_roe_html(engagement, tenant, signer_name, signer_email)
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        try:
            page = await browser.new_page()
            await page.set_content(html, wait_until="load")
            pdf_bytes = await page.pdf(format="A4", print_background=True)
        finally:
            await browser.close()
    return pdf_bytes


async def create_signature_request(
    engagement: Engagement, tenant: Tenant, signer_name: str, signer_email: str,
) -> tuple[str, str]:
    """Sends the RoE for hosted signing. Returns (signature_request_id, details_url).
    Raises DropboxSignError on any failure — never returns a falsy/placeholder
    id that a caller could mistake for success."""
    if not settings.dropbox_sign_api_key:
        raise DropboxSignError("Dropbox Sign is not configured (dropbox_sign_api_key unset)")

    pdf_bytes = await render_roe_pdf(engagement, tenant, signer_name, signer_email)

    data = {
        "title": f"Sentinel Command — Rules of Engagement ({engagement.tier})",
        "subject": "Signature requested: Sentinel Command Rules of Engagement",
        "message": (
            f"Please review and sign the Rules of Engagement authorizing Sentinel Command's "
            f"{engagement.tier} testing for {tenant.name}."
        ),
        "signers[0][email_address]": signer_email,
        "signers[0][name]": signer_name,
        "metadata[engagement_id]": str(engagement.id),
        "use_text_tags": "1",
        "hide_text_tags": "1",
        "test_mode": "1" if settings.dropbox_sign_test_mode else "0",
    }
    files = {"file[0]": ("rules_of_engagement.pdf", pdf_bytes, "application/pdf")}

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{_API_BASE}/signature_request/send",
            data=data, files=files,
            auth=(settings.dropbox_sign_api_key, ""),
        )
    if resp.status_code >= 400:
        raise DropboxSignError(f"Dropbox Sign send failed ({resp.status_code}): {resp.text[:500]}")

    body = resp.json()
    sig_request = body["signature_request"]
    return sig_request["signature_request_id"], sig_request.get("details_url", "")


def verify_webhook_event(raw_json_str: str) -> dict:
    """Dropbox Sign posts webhooks as multipart/form-data with a single
    `json` field (not a raw JSON body like Stripe's), and authenticates the
    callback via `event.event_hash` — an HMAC-SHA256 of event_time+event_type
    keyed with the API key, not a separate webhook secret. Raises ValueError
    on a missing key or a hash mismatch; never trust an unverified event."""
    if not settings.dropbox_sign_api_key:
        raise ValueError("Dropbox Sign is not configured (dropbox_sign_api_key unset)")

    payload = json.loads(raw_json_str)
    event = payload.get("event", {})
    event_time = event.get("event_time", "")
    event_type = event.get("event_type", "")
    claimed_hash = event.get("event_hash", "")

    expected_hash = hmac.new(
        settings.dropbox_sign_api_key.encode(), f"{event_time}{event_type}".encode(), sha256,
    ).hexdigest()

    if not claimed_hash or not hmac.compare_digest(claimed_hash, expected_hash):
        raise ValueError("Dropbox Sign webhook event_hash verification failed")

    return payload
