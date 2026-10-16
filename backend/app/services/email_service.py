"""
Transactional email via the SendGrid HTTP API (Phishing Simulation
roadmap Phase 17 — replaces the previous plain-SMTP transport, which had
no bounce/complaint visibility at all; this is also what finally makes
phishing_service.py's own module docstring, which already claimed
"SendGrid" before this phase existed, actually true).

send_email() never raises — a failed send logs the error and returns False
so callers can decide whether to surface anything to the user. The dominant
pattern in this codebase is "best-effort side effect, never blocks the
primary transaction."

If SENDGRID_API_KEY is unset (local dev, CI), send_email() logs the
rendered subject/recipient/body to stdout instead of calling the API, so
nothing requires a live SendGrid account to run.

Every real send is checked against the suppression list first — real
bounces/complaints/unsubscribes recorded via the
/webhooks/sendgrid/events receiver (app/routers/webhooks.py). This is an
operational anti-abuse control across *all* outbound ZoneProof mail
(invites, reports, phishing sends alike), not a phishing-specific concern,
so it lives here rather than in one feature.
"""
from __future__ import annotations

import base64
import logging

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import EmailSuppression

log = logging.getLogger(__name__)

_SENDGRID_MAIL_SEND_URL = "https://api.sendgrid.com/v3/mail/send"


class Attachment:
    """One file to attach — content is raw bytes."""

    def __init__(self, filename: str, content: bytes, mime_type: str = "application/octet-stream"):
        self.filename = filename
        self.content = content
        self.mime_type = mime_type


def _wrap_html(title: str, body_html: str) -> str:
    return f"""
    <div style="font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 560px; margin: 0 auto; color: #1a1a2e;">
      <div style="padding: 24px 0; border-bottom: 2px solid #5b5cf0;">
        <span style="font-weight: 800; font-size: 20px; letter-spacing: -.3px;">Zone<span style="color:#5b5cf0">Proof</span></span>
      </div>
      <div style="padding: 28px 0;">
        <h2 style="font-size: 17px; margin: 0 0 16px;">{title}</h2>
        {body_html}
      </div>
      <div style="padding: 16px 0; border-top: 1px solid #e5e7eb; color: #888; font-size: 11px;">
        ZoneProof — DMARC, MTA-STS &amp; brand protection
      </div>
    </div>
    """


def _startup_check() -> None:
    if settings.sendgrid_api_key:
        log.info("Email: SendGrid configured (from=%s)", settings.email_from_address)
    else:
        log.warning(
            "Email: SENDGRID_API_KEY is not set — all emails will be logged to stdout only. "
            "Set SENDGRID_API_KEY in .env to enable real delivery."
        )


_startup_check()


async def _is_suppressed(db: AsyncSession, to: str) -> bool:
    """Real bounces/complaints/unsubscribes recorded from actual SendGrid
    webhook events — never sent to a second time. Takes the caller's own
    session (every real caller — a router or a service function — already
    has one in scope) rather than opening a standalone one, so this stays
    correctly testable against the test database instead of silently
    reaching for whatever `DATABASE_URL` happens to be configured."""
    row = await db.scalar(select(EmailSuppression).where(EmailSuppression.email == to.strip().lower()))
    return row is not None


async def send_email(
    db: AsyncSession,
    to: str,
    subject: str,
    body_html: str,
    *,
    title: str | None = None,
    text_body: str | None = None,
    attachments: list[Attachment] | None = None,
) -> bool:
    html = _wrap_html(title, body_html) if title else body_html

    if await _is_suppressed(db, to):
        log.info("Email suppressed (real prior bounce/complaint/unsubscribe), not sending: to=%s", to)
        return False

    if not settings.sendgrid_api_key:
        att_note = f" [+{len(attachments)} attachment(s): {', '.join(a.filename for a in attachments)}]" if attachments else ""
        log.info("EMAIL [dev mode, no SENDGRID_API_KEY] to=%s subject=%r%s\n%s", to, subject, att_note, text_body or body_html)
        return True

    content = []
    if text_body:
        content.append({"type": "text/plain", "value": text_body})
    content.append({"type": "text/html", "value": html})

    payload: dict = {
        "personalizations": [{"to": [{"email": to}]}],
        "from": {"email": settings.email_from_address, "name": settings.email_from_name},
        "subject": subject,
        "content": content,
    }
    if attachments:
        payload["attachments"] = [
            {
                "content": base64.b64encode(a.content).decode("ascii"),
                "filename": a.filename,
                "type": a.mime_type,
                "disposition": "attachment",
            }
            for a in attachments
        ]

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                _SENDGRID_MAIL_SEND_URL,
                json=payload,
                headers={"Authorization": f"Bearer {settings.sendgrid_api_key}"},
            )
        if resp.status_code >= 300:
            log.warning("SendGrid send failed to %s: status=%d body=%s", to, resp.status_code, resp.text[:500])
            return False
        return True
    except httpx.HTTPError as e:
        log.warning("SendGrid send raised a network error to %s: %s", to, e)
        return False
    except Exception as e:
        log.warning("SendGrid send raised an unexpected error to %s: %s", to, e)
        return False
