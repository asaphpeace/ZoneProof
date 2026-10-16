"""
Independent email-authentication evidence for a phishing campaign report
(Coverage Map plan phishing transformation, Phase 6) — the wedge no
pure-play security-awareness competitor (KnowBe4, Proofpoint, Microsoft
Defender ASsT, Hoxhunt) can produce, because none of them monitor the
target organization's real email-authentication infrastructure.

Computed live at report-view time, not stored as a launch-time snapshot,
so it always reflects the domain's current DMARC posture rather than
going stale the moment new aggregate reports land. Returns None (never a
fabricated zero) when there's genuinely nothing to cite yet.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Engagement, Finding
from app.models.dmarc_report import DmarcAggregate

_SPOOF_TEST_CHECK_ID = "IMPERSONATION-SPOOF-SEND-TEST"
_WINDOW_DAYS = 30


async def get_email_auth_evidence(
    db: AsyncSession, tenant_id: uuid.UUID, domain_id: uuid.UUID | None, around: datetime,
) -> dict | None:
    """Real, independently-observed evidence for the domain a phishing
    campaign targeted:
    - unaligned/failing DMARC aggregate volume in the ~60-day window
      around the campaign (DmarcAggregate rows already ingested from real
      aggregate reports — not a new scan).
    - Sentinel's own most recent spoofed-send test result for that domain
      (impersonation_scan_service.py), cited as a second, independent
      confirmation.
    Returns None if domain_id is unset or neither signal has any data —
    an honest "no evidence yet" rather than a zero-filled block that looks
    like a real, checked, clean result."""
    if not domain_id:
        return None

    window_start = around - timedelta(days=_WINDOW_DAYS)
    window_end = around + timedelta(days=_WINDOW_DAYS)

    agg_result = await db.execute(
        select(func.coalesce(func.sum(DmarcAggregate.unaligned_count), 0), func.coalesce(func.sum(DmarcAggregate.total_count), 0))
        .where(
            DmarcAggregate.domain_id == domain_id,
            DmarcAggregate.period_begin >= window_start,
            DmarcAggregate.period_begin <= window_end,
        )
    )
    unaligned_count, total_count = agg_result.one()

    eng_result = await db.execute(
        select(Engagement.id).where(
            Engagement.tenant_id == tenant_id, Engagement.tier == "impersonation", Engagement.domain_id == domain_id,
        )
    )
    engagement_ids = [row[0] for row in eng_result.all()]

    spoof_finding: Finding | None = None
    if engagement_ids:
        finding_result = await db.execute(
            select(Finding)
            .where(Finding.engagement_id.in_(engagement_ids), Finding.check_id == _SPOOF_TEST_CHECK_ID)
            .order_by(Finding.discovered_at.desc())
            .limit(1)
        )
        spoof_finding = finding_result.scalars().first()

    if not unaligned_count and spoof_finding is None:
        return None

    return {
        "window_days": _WINDOW_DAYS * 2,
        "unaligned_message_count": int(unaligned_count),
        "total_message_count": int(total_count),
        "spoof_test_status": spoof_finding.status if spoof_finding else None,
        "spoof_test_detail": spoof_finding.detail if spoof_finding else None,
        "spoof_test_date": spoof_finding.discovered_at.isoformat() if spoof_finding else None,
    }
