"""
LLM-generated phishing simulation content (Coverage Map plan Phase 7) — a
fresh subject + HTML body generated at campaign-launch time via Anthropic,
following advisor_service.py's pattern exactly: reuse settings.anthropic_api_key,
a tightly-scoped system prompt, and a mandatory deterministic fallback (the
existing BUILT_IN_TEMPLATES in phishing_service.py) if the key is unset or
the call/response is malformed — this service must never be the reason a
campaign fails to send.

Safety rail: {click_url} tracking survives regardless of what the LLM
returns — phishing_service._render_content() already guarantees this
(appending a fallback link if the placeholder is missing), enforced in
code, never trusted to the model. This module adds a second belt-and-
braces check (reject and fall back to the static template rather than
send a body that dropped the placeholder), since a human never reviews
generated content before send in the "fresh every launch" mode.
"""
from __future__ import annotations

import json
import logging

import anthropic

from app.config import settings

_log = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You write the subject line and HTML body for an authorized phishing security-awareness simulation. It is sent only to employees of an organization whose administrator has signed a Rules of Engagement specifically authorizing this exercise — never to anyone outside that consented program.

Respond with ONLY a JSON object of this exact shape, nothing else: {"subject": "...", "body_html": "..."}

Requirements for body_html:
- A complete, realistic corporate email: a plausible sending context, a clear single call to action, professional tone — not exaggerated or cartoonish.
- Inline CSS only (no <style> blocks — many email clients strip them). A simple, email-client-safe layout (basic divs/tables), not raw unstyled text.
- Must include the exact literal placeholder {click_url} inside one <a href="{click_url}"> link — this is the only way the simulation is tracked, so it must appear verbatim.
- Should also include the exact literal placeholder {report_url} inside a small, low-emphasis "report this email" link (e.g. "Not expecting this? Report this email.") — real phishing-awareness programs measure how many people report a suspicious email, not just how many click one.
- Must NOT ask the recipient to type a password or any credential directly into the email itself — the click destination is a separate simulated page that handles that; the email's only job is to make the click plausible.
- Must NOT impersonate a specific named real company, government agency, brand, or public figure — the lure should feel generic-corporate, not a forgery of an identifiable real entity.
- Roughly 80-160 words in the body."""


def _prompt_for(lure_category: str, company_name: str, dmarc_context: str, recipient_context: str) -> str:
    lines = [
        f"Lure category: {lure_category}",
        f"Target company name (use naturally, do not overuse it): {company_name}",
    ]
    if recipient_context:
        lines.append(f"Recipient context: {recipient_context}")
    if dmarc_context:
        lines.append(
            f"Target domain's email-authentication posture (for calibrating how urgent/plausible a spoofed "
            f"sender would seem in real life — do not mention DMARC/SPF/email-authentication to the recipient "
            f"at all): {dmarc_context}"
        )
    lines.append("Write the subject and body_html JSON now.")
    return "\n".join(lines)


async def generate_campaign_content(
    lure_category: str, company_name: str, dmarc_context: str = "", recipient_context: str = "",
) -> tuple[str, str, bool]:
    """Returns (subject, body_html, was_llm_generated). Never raises —
    falls back to BUILT_IN_TEMPLATES[lure_category] (or the first available
    template if lure_category isn't a known key) on any failure, matching
    every other optional-LLM code path in this codebase."""
    if not settings.anthropic_api_key:
        return _fallback(lure_category)

    try:
        client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
        response = await client.messages.create(
            model=settings.advisor_claude_model,
            max_tokens=800,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": _prompt_for(lure_category, company_name, dmarc_context, recipient_context)}],
        )
        content = response.content[0].text.strip()
        start, end = content.find("{"), content.rfind("}") + 1
        parsed = json.loads(content[start:end])
        subject, body_html = parsed["subject"], parsed["body_html"]
        if not subject or "{click_url}" not in body_html:
            raise ValueError("Generated content missing subject or the required {click_url} placeholder")
        return subject, body_html, True
    except Exception as e:
        _log.warning("LLM phishing content generation failed, falling back to static template: error=%s", e)
        return _fallback(lure_category)


def _fallback(lure_category: str) -> tuple[str, str, bool]:
    # Deferred import — phishing_service.py imports this module to call
    # generate_campaign_content(), so importing BUILT_IN_TEMPLATES from it
    # at module load time would be a circular import.
    from app.services.phishing_service import BUILT_IN_TEMPLATES

    template = BUILT_IN_TEMPLATES.get(lure_category) or next(iter(BUILT_IN_TEMPLATES.values()))
    return template["subject"], template["body_html"], False
