"""Brand exposure: how exposed a tenant is to look-alike domains right now, as a 0-100 pillar for the Sentinel score (plan step 8.8).

Same convention as the other optional pillars: None means "no signal" (no active brand, or never scanned), and then the Sentinel score is
exactly what it was before, so nothing moves for a tenant that does not use Brand Guard. Once there is a signal, the pillar blends in at
the same weight as Human Risk.

The penalties below are EXPERT-SET ASSUMPTIONS, not measurements: what a confirmed live look-alike or a missed deadline is worth against the
score is a judgement. They are exposed (and returned with the score) so a report can say exactly what moved it."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

LIVE_STAGES = ("resolving", "mail_enabled", "certified")
OPEN_CASE = ("confirmed", "takedown")
UNDECIDED = ("suspicious", "triaging")

PER_LIVE_CONFIRMED, CAP_LIVE_CONFIRMED = 15, 60       # a confirmed look-alike that is live is the strongest sign of exposure
PER_OVERDUE, CAP_OVERDUE = 10, 30                      # a case nobody acted on in time
PER_UNDECIDED_LIVE, CAP_UNDECIDED_LIVE = 4, 20         # live look-alikes still waiting for a person's decision


def score(live_confirmed: int, overdue: int, undecided_live: int) -> dict:
    """{score, components: [{label, count, points}]}. Pure."""
    parts = [
        ("Confirmed look-alikes that are live", live_confirmed, min(PER_LIVE_CONFIRMED * live_confirmed, CAP_LIVE_CONFIRMED)),
        ("Cases past their deadline", overdue, min(PER_OVERDUE * overdue, CAP_OVERDUE)),
        ("Live look-alikes waiting for a decision", undecided_live, min(PER_UNDECIDED_LIVE * undecided_live, CAP_UNDECIDED_LIVE)),
    ]
    penalty = min(100, sum(p for _, _, p in parts))
    return {"score": 100 - penalty, "components": [{"label": l, "count": c, "points": -p} for l, c, p in parts if c]}


async def compute(db: AsyncSession, tenant_id) -> dict | None:
    """The tenant's exposure, or None when there is nothing to measure yet."""
    from app.models import BrandCandidate, BrandProfile

    profiles = (await db.execute(select(BrandProfile.id, BrandProfile.last_scanned_at).where(BrandProfile.tenant_id == tenant_id, BrandProfile.is_active == True))).all()  # noqa: E712
    if not profiles or not any(p[1] for p in profiles):
        return None
    active = [p[0] for p in profiles]
    rows = (await db.execute(select(BrandCandidate.status, BrandCandidate.stage, BrandCandidate.due_at).where(BrandCandidate.tenant_id == tenant_id, BrandCandidate.profile_id.in_(active)))).all()
    now = datetime.now(timezone.utc)
    live_confirmed = sum(1 for st, stage, _ in rows if st in OPEN_CASE and stage in LIVE_STAGES)
    overdue = sum(1 for st, _, due in rows if st in OPEN_CASE and due is not None and due < now)
    undecided = sum(1 for st, stage, _ in rows if st in UNDECIDED and stage in LIVE_STAGES)
    out = score(live_confirmed, overdue, undecided)
    return {**out, "brands": len(active), "open_cases": sum(1 for st, _, _ in rows if st in OPEN_CASE), "need_decision": sum(1 for st, _, _ in rows if st in UNDECIDED)}


async def compute_score(db: AsyncSession, tenant_id) -> float | None:
    d = await compute(db, tenant_id)
    return float(d["score"]) if d else None
