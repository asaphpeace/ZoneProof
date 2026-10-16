"""
Identity & Credential Hygiene — breach-monitoring half (Coverage Map plan
Phase 5). Calls HaveIBeenPwned's breach-check API for every email on the
tenant's phishing target lists (reused rather than inventing a third
"employee roster" concept — same recipient list Tier B human-simulation
campaigns already use, per the plan's own decision).

Never displays or stores the actual leaked password/data — only which
named breach(es) matched and when, the same "real evidence without
reproducing sensitive material" discipline as every other scan pass here.

Follows advisor_service.py's pattern for an optional third-party
dependency: a missing/unset API key degrades cleanly (returns None, not a
crash or a 500), never a hard failure.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import Engagement, Finding, PhishingTargetList
from app.services.exploitability_service import score_and_stamp
from app.services.finding_reconciliation import reconcile_findings

_log = logging.getLogger(__name__)

_HIBP_BASE = "https://haveibeenpwned.com/api/v3"
_USER_AGENT = "SentinelCommand-CredentialHygiene"

# HaveIBeenPwned's own documented rate limit for a standard API key is one
# request per ~1.5s — confirm against the actual key's tier once obtained;
# this default is deliberately conservative rather than optimistic.
_RATE_LIMIT_DELAY_SECONDS = 1.6


class HibpNotConfiguredError(Exception):
    """Raised when hibp_api_key is unset — callers treat this as 'optional
    module not enabled', the same honest-non-failure status Inspector's
    SubscriptionRequiredException already gets, not a scan failure."""


async def _check_breaches_for_email(client: httpx.AsyncClient, email: str) -> list[dict]:
    resp = await client.get(
        f"{_HIBP_BASE}/breachedaccount/{email}",
        params={"truncateResponse": "false"},
        headers={"hibp-api-key": settings.hibp_api_key, "User-Agent": _USER_AGENT},
    )
    if resp.status_code == 404:
        return []  # HIBP's real "no breaches found" response — not an error
    if resp.status_code == 401:
        raise RuntimeError("HIBP API key was rejected (401) — check hibp_api_key")
    if resp.status_code == 429:
        raise RuntimeError("HIBP rate limit exceeded (429)")
    resp.raise_for_status()
    return resp.json()


def _finding_for_breaches(tenant_id: uuid.UUID, engagement_id: uuid.UUID, email: str, breaches: list[dict]) -> Finding:
    names = [b.get("Name", "Unknown") for b in breaches]
    most_recent = max((b.get("BreachDate", "") for b in breaches), default="")
    severity = "critical" if any(b.get("IsSensitive") for b in breaches) else "high"
    return Finding(
        id=uuid.uuid4(), tenant_id=tenant_id, engagement_id=engagement_id, asset_id=None,
        tier="credential", severity=severity,
        title=f"{email} found in {len(breaches)} breach{'es' if len(breaches) != 1 else ''}",
        status="open", check_id="hibp_breach_match", resource_uid=email,
        detail=f"{email} appears in: {', '.join(names)}. Most recent breach dated {most_recent or 'unknown'}. "
               "The actual leaked credentials are never retrieved or stored by Sentinel — only that a match exists.",
        remediation_guidance="Force a password reset for this account and confirm MFA is enabled — a breached password is often reused elsewhere.",
    )


async def run_breach_monitoring_scan(
    db: AsyncSession, engagement: Engagement, tenant_id: uuid.UUID,
    error_detail: dict | None = None,
) -> list[Finding] | None:
    """Same honest-failure/reconciliation shape as the rest of this
    codebase's scan passes. Returns None if hibp_api_key isn't configured —
    callers treat that as 'optional module not enabled,' not a failure."""
    if not settings.hibp_api_key:
        if error_detail is not None:
            error_detail["message"] = "HaveIBeenPwned API key not configured"
        return None

    lists_result = await db.execute(select(PhishingTargetList).where(PhishingTargetList.tenant_id == tenant_id))
    target_lists = lists_result.scalars().all()
    emails = sorted({entry.get("email") for tl in target_lists for entry in (tl.entries or []) if entry.get("email")})
    if not emails:
        return []

    candidates: list[Finding] = []
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            for i, email in enumerate(emails):
                if i > 0:
                    await asyncio.sleep(_RATE_LIMIT_DELAY_SECONDS)
                breaches = await _check_breaches_for_email(client, email)
                if breaches:
                    candidates.append(_finding_for_breaches(tenant_id, engagement.id, email, breaches))
    except (httpx.HTTPError, RuntimeError) as e:
        _log.warning("Breach monitoring scan failed: tenant_id=%s error=%s", tenant_id, e)
        if error_detail is not None:
            error_detail["message"] = str(e)
        return None

    for c in candidates:
        score_and_stamp(c)

    return await reconcile_findings(
        db, engagement_id=engagement.id,
        scope=[Finding.tier == "credential", Finding.check_id == "hibp_breach_match"],
        candidates=candidates,
        key_fn=lambda f: (f.check_id, f.resource_uid),
    )
