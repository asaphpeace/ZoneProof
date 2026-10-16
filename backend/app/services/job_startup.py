"""
When each background job first runs after the server starts.

Every job used to sleep one full interval before its first run, so a server
restarted more often than a job's interval (a daily cert probe on a server
that restarts nightly, a 6 hour rescan on a dev server) never ran it at all.

The first run is now decided per job from what the database already knows:

  due_aware      the job itself only acts on work that is due (its own
                 last-run or schedule check), so it can safely run shortly
                 after start.
  hint           the job does its whole batch every time it fires, so it
                 runs at start only if the newest result it produced is older
                 than its interval; otherwise it waits out the remainder.
  interval_only  nothing persisted says when it last ran, so it keeps the old
                 behaviour: wait one interval.

First runs are staggered so a restart does not start everything at once.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Awaitable, Callable

from sqlalchemy import func, select

DUE_AWARE = "due_aware"
HINT = "hint"
INTERVAL_ONLY = "interval_only"

STAGGER_BASE_S = 20     # first job starts this long after the server
STAGGER_STEP_S = 7      # each following job waits this much longer


def initial_delay(
    interval: int, last_run: datetime | None, now: datetime, slot: int, policy: str, *, catch_up: bool = True,
) -> float:
    """Seconds to wait before a job's first run."""
    if not catch_up or policy == INTERVAL_ONLY:
        return float(interval)
    stagger = float(STAGGER_BASE_S + slot * STAGGER_STEP_S)
    if policy == DUE_AWARE or last_run is None:
        return min(float(interval), stagger)
    if last_run.tzinfo is None:
        last_run = last_run.replace(tzinfo=timezone.utc)
    age = (now - last_run).total_seconds()
    if age >= interval:
        return min(float(interval), stagger)
    # Ran recently: wait out the rest of the interval (never longer than a full one).
    return min(float(interval), max(stagger, interval - max(age, 0.0)))


# ── "when did this job last produce something?" ──────────────────────────────

async def _max(column, *where) -> datetime | None:
    from app.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        stmt = select(func.max(column))
        for w in where:
            stmt = stmt.where(w)
        return (await db.execute(stmt)).scalar()


async def last_cert_probe() -> datetime | None:
    from app.models import SslCert
    return await _max(SslCert.probed_at)


async def last_dns_check() -> datetime | None:
    from app.models import Domain
    return await _max(Domain.last_checked_at, Domain.is_active == True)  # noqa: E712


async def last_cloud_scan() -> datetime | None:
    from app.models.cloud_account_connection import CloudAccountConnection as C
    return await _max(C.last_scanned_at, C.status == "connected")


async def last_host_scan() -> datetime | None:
    from app.models.host_connection import HostConnection as H
    return await _max(H.last_scanned_at, H.status == "connected")


async def last_oauth_scan() -> datetime | None:
    from app.models.oauth_app_connection import OAuthAppConnection as O
    return await _max(O.last_scanned_at, O.status == "connected")


Hint = Callable[[], Awaitable[datetime | None]]
