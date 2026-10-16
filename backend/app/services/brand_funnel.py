"""Funnel counters: how many items enter and leave each stage of Brand Guard, per brand per day.

Why: the pipeline is a cascade (cheap checks first, expensive ones last), and nobody can tune or price it without knowing where the volume
goes. These counters record, at the points where the code already decides, how many things came in, how many went on, and why the rest did not.
They hold counts only: no domain names, nothing about an individual look-alike.

Recording never breaks the work it describes: `record_safe` swallows its own failures. Every count is a number of items at that stage in the
period, so units differ between stages (names, candidates, jobs); the UI says so rather than pretending it is one shrinking pile.
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import BrandCandidate, BrandFunnelCount

log = logging.getLogger(__name__)

# key, label, unit of what is counted, what "passed" means. Order is the funnel's order.
STAGES: list[dict] = [
    {"key": "discover", "label": "Find candidates", "unit": "names", "passed_means": "sent on to a DNS check", "needs": None},
    {"key": "live", "label": "Keep real, live names", "unit": "new names", "passed_means": "kept as a candidate", "needs": None},
    {"key": "scored", "label": "Score and explain", "unit": "candidates", "passed_means": "scored suspicious", "needs": None},
    {"key": "probe_select", "label": "Pick who to visit", "unit": "live look-alikes", "passed_means": "queued for a visit", "needs": "probe"},
    {"key": "probe_done", "label": "Light probe", "unit": "visits", "passed_means": "page was reachable", "needs": "probe"},
    {"key": "render_select", "label": "Pick pages to render", "unit": "probed pages", "passed_means": "queued for a render", "needs": "render"},
    {"key": "render_done", "label": "Render", "unit": "renders", "passed_means": "produced a screenshot", "needs": "render"},
    {"key": "similarity", "label": "Compare with your brand", "unit": "pages compared", "passed_means": "resembled your brand", "needs": "probe"},
]
STAGE_KEYS = [s["key"] for s in STAGES]

# What the funnel is still missing, shown next to the stage it belongs to. Edit this list as pieces are built; it is the one place that says so.
NOT_BUILT: list[dict] = [
    {"after": "discover", "label": "Learned generators", "plan": "5.2 to 5.4"},
    {"after": "live", "label": "Plausibility model", "plan": "5.1"},
    {"after": "scored", "label": "Calibration", "plan": "3.2"},
    {"after": "scored", "label": "Learning from analyst decisions", "plan": "9.1"},
    {"after": "probe_done", "label": "Opt-out list and a contact URL for the probe", "plan": None},
    {"after": "render_done", "label": "Asset, image, colour and page-structure matches", "plan": None},
    {"after": "similarity", "label": "Logo extraction and text-in-image checks", "plan": None},
    {"after": "similarity", "label": "AI explanation layer, with its cost gates", "plan": "6.1 to 6.4"},
    {"after": "similarity", "label": "Screenshot in the evidence pack", "plan": None},
    {"after": "similarity", "label": "Metrics dashboard", "plan": "9.2"},
]
MAX_DETAIL_KEYS = 24
_KEY = re.compile(r"^[a-z0-9_]{1,40}$")


def _clean_detail(detail: dict | None) -> dict[str, int]:
    out: dict[str, int] = {}
    if not isinstance(detail, dict):
        return out
    for k, v in detail.items():
        if isinstance(k, str) and _KEY.match(k) and isinstance(v, int) and not isinstance(v, bool) and v > 0 and len(out) < MAX_DETAIL_KEYS:
            out[k] = v
    return out


async def record(db: AsyncSession, profile, stage: str, *, entered: int = 0, passed: int = 0, detail: dict | None = None, day: date | None = None) -> None:
    """Add to today's counters for one stage of one brand. Increments are atomic (one upsert), so concurrent workers and scans do not lose counts."""
    if stage not in STAGE_KEYS:
        raise ValueError(f"unknown funnel stage: {stage}")
    entered, passed = max(int(entered), 0), max(int(passed), 0)
    clean = _clean_detail(detail)
    if not (entered or passed or clean):
        return
    await db.execute(text("""
        INSERT INTO brand_funnel_counts (id, tenant_id, profile_id, day, stage, entered, passed, detail)
        VALUES (:id, :tenant, :profile, :day, :stage, :entered, :passed, CAST(:detail AS jsonb))
        ON CONFLICT (profile_id, day, stage) DO UPDATE SET
            entered = brand_funnel_counts.entered + EXCLUDED.entered,
            passed = brand_funnel_counts.passed + EXCLUDED.passed,
            detail = COALESCE((
                SELECT jsonb_object_agg(k, COALESCE((brand_funnel_counts.detail ->> k)::bigint, 0) + COALESCE((EXCLUDED.detail ->> k)::bigint, 0))
                FROM jsonb_object_keys(brand_funnel_counts.detail || EXCLUDED.detail) AS k
            ), '{}'::jsonb)
    """), {"id": uuid.uuid4(), "tenant": profile.tenant_id, "profile": profile.id, "day": day or datetime.now(timezone.utc).date(),
           "stage": stage, "entered": entered, "passed": passed, "detail": json.dumps(clean)})


async def record_safe(db: AsyncSession, profile, stage: str, **kw) -> None:
    """record(), but a failure here is logged and ignored: counting must never cost a scan or a probe its result."""
    try:
        async with db.begin_nested():
            await record(db, profile, stage, **kw)
    except Exception:
        log.exception("Brand Guard funnel counter failed (%s)", stage)


async def summarise(db: AsyncSession, tenant_id, *, profile_id=None, days: int = 30, today: date | None = None) -> dict:
    """The funnel for one brand (or all of a tenant's brands) over the last `days` days, with a zero-filled daily series per stage and the current
    spread of candidates by status."""
    days = max(1, min(int(days), 90))
    today = today or datetime.now(timezone.utc).date()
    since = today - timedelta(days=days - 1)
    q = select(BrandFunnelCount).where(BrandFunnelCount.tenant_id == tenant_id, BrandFunnelCount.day >= since, BrandFunnelCount.day <= today)
    if profile_id is not None:
        q = q.where(BrandFunnelCount.profile_id == profile_id)
    rows = (await db.execute(q)).scalars().all()
    by_stage: dict[str, dict] = {s["key"]: {"entered": 0, "passed": 0, "detail": {}, "daily": {}} for s in STAGES}
    for r in rows:
        s = by_stage.get(r.stage)
        if s is None:
            continue
        s["entered"] += int(r.entered or 0)
        s["passed"] += int(r.passed or 0)
        for k, v in (r.detail or {}).items():
            s["detail"][k] = s["detail"].get(k, 0) + int(v)
        d = s["daily"].setdefault(r.day, [0, 0])
        d[0] += int(r.entered or 0)
        d[1] += int(r.passed or 0)
    series_days = [since + timedelta(days=i) for i in range(days)]
    stages = []
    for meta in STAGES:
        s = by_stage[meta["key"]]
        stages.append({
            **meta, "entered": s["entered"], "passed": s["passed"], "dropped": max(s["entered"] - s["passed"], 0),
            "pass_rate": round(s["passed"] / s["entered"], 3) if s["entered"] else None,
            "detail": dict(sorted(s["detail"].items(), key=lambda kv: -kv[1])),
            "daily": [{"day": d.isoformat(), "entered": s["daily"].get(d, [0, 0])[0], "passed": s["daily"].get(d, [0, 0])[1]} for d in series_days],
        })
    sq = select(BrandCandidate.status, func.count()).where(BrandCandidate.tenant_id == tenant_id).group_by(BrandCandidate.status)
    if profile_id is not None:
        sq = sq.where(BrandCandidate.profile_id == profile_id)
    outcomes = {status: n for status, n in (await db.execute(sq)).all()}
    return {"days": days, "since": since.isoformat(), "until": today.isoformat(), "profile_id": str(profile_id) if profile_id else None, "stages": stages, "outcomes": outcomes,
            "not_built": NOT_BUILT}
