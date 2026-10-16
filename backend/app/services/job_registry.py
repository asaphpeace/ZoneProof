"""
What the background jobs have actually done.

The jobs in main.py run inside the API process and used to leave no trace
beyond a log line, so "is the cert probe running?" had no answer in the app.
This keeps the last run of each in memory and, after every run, writes it to
the job_runs table (persist). The Data sources page overlays the stored row on
the in-memory state (overlay), so a restart does not wipe the history and a
standby instance shows what the leader did. If the write fails the job is not
affected and the page falls back to this process's own view.

Exception text is never stored. A job failure is reduced to a short, fixed
kind so the page can say what went wrong without exposing hostnames, paths or
stack frames to the browser. The full text stays in the server log.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Callable

log = logging.getLogger(__name__)

PROCESS_STARTED_AT = datetime.now(timezone.utc)

# Fixed vocabulary shown to the user.
KINDS = ("timed_out", "connection_failed", "login_rejected", "unexpected")


def classify(exc: BaseException | None) -> str:
    """Reduce an exception to one of KINDS without keeping its message."""
    if exc is None:
        return "unexpected"
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "timed_out"
    name = type(exc).__name__.lower()
    text = str(exc).lower()
    if "timeout" in name or "timed out" in text:
        return "timed_out"
    if any(w in text for w in ("authentication", "login", "credentials", "unauthorized", "forbidden", "403", "401")):
        return "login_rejected"
    if isinstance(exc, (ConnectionError, OSError)) or any(w in name for w in ("connect", "network", "dns", "resolve")):
        return "connection_failed"
    return "unexpected"


@dataclass
class JobState:
    key: str
    label: str
    provides: str
    interval: Callable[[], int]
    runs: int = 0
    failures: int = 0
    last_started: datetime | None = None
    last_finished: datetime | None = None
    last_ok: bool | None = None
    last_failure_kind: str | None = None
    last_duration_s: float | None = None
    running: bool = False
    first_run_at: datetime | None = None
    startup_policy: str | None = None
    _failed_this_run: bool = field(default=False, repr=False)
    _t0: float = field(default=0.0, repr=False)


_jobs: dict[str, JobState] = {}

# leader: this process runs the jobs. standby: another instance does. disabled: scheduler switched off here.
# unknown: the lifespan has not decided yet (also the case in tests that never start the app).
_role: str = "unknown"
_role_since: datetime | None = None


def set_role(role: str) -> None:
    global _role, _role_since
    if role != _role:
        _role, _role_since = role, datetime.now(timezone.utc)


def role() -> tuple[str, datetime | None]:
    return _role, _role_since


def register(key: str, label: str, provides: str, interval: Callable[[], int]) -> None:
    _jobs[key] = JobState(key=key, label=label, provides=provides, interval=interval)


def set_first_run(key: str, when: datetime, policy: str) -> None:
    j = _jobs.get(key)
    if j:
        j.first_run_at = when
        j.startup_policy = policy


def start(key: str) -> None:
    j = _jobs.get(key)
    if not j:
        return
    j.running = True
    j._failed_this_run = False
    j._t0 = time.monotonic()
    j.last_started = datetime.now(timezone.utc)


def fail(key: str, exc: BaseException | None = None) -> None:
    """A job caught its own exception. Called from the job's except block."""
    j = _jobs.get(key)
    if not j:
        return
    j._failed_this_run = True
    j.last_failure_kind = classify(exc)


def finish(key: str) -> None:
    j = _jobs.get(key)
    if not j:
        return
    j.running = False
    j.runs += 1
    j.last_finished = datetime.now(timezone.utc)
    j.last_duration_s = round(time.monotonic() - j._t0, 2)
    j.last_ok = not j._failed_this_run
    if j._failed_this_run:
        j.failures += 1
    else:
        j.last_failure_kind = None


def snapshot() -> list[JobState]:
    return list(_jobs.values())


def reset() -> None:
    """For tests."""
    global _role, _role_since
    _jobs.clear()
    _role, _role_since = "unknown", None


async def persist(key: str, session_factory=None) -> None:
    """Write this job's just-finished run to job_runs. Never raises: history must not break a job."""
    j = _jobs.get(key)
    if not j or j.last_finished is None:
        return
    try:
        from sqlalchemy.dialects.postgresql import insert
        from app.models import JobRun
        if session_factory is None:
            from app.database import AsyncSessionLocal as session_factory
        failed = 1 if j.last_ok is False else 0
        values = dict(
            job_key=key, runs=1, failures=failed, last_started=j.last_started, last_finished=j.last_finished,
            last_ok=j.last_ok, last_failure_kind=j.last_failure_kind, last_duration_s=j.last_duration_s,
        )
        stmt = insert(JobRun).values(**values)
        stmt = stmt.on_conflict_do_update(
            index_elements=[JobRun.job_key],
            set_=dict(
                runs=JobRun.runs + 1,
                failures=JobRun.failures + failed,
                last_started=stmt.excluded.last_started,
                last_finished=stmt.excluded.last_finished,
                last_ok=stmt.excluded.last_ok,
                last_failure_kind=stmt.excluded.last_failure_kind,
                last_duration_s=stmt.excluded.last_duration_s,
                updated_at=datetime.now(timezone.utc),
            ),
        )
        async with session_factory() as db:
            await db.execute(stmt)
            await db.commit()
    except Exception as e:
        log.warning("could not store job history for %s: %s", key, type(e).__name__)


def overlay(j: JobState, row) -> JobState:
    """This job's state with the stored history applied. A local run newer than the stored one wins."""
    if row is None:
        return j
    if j.last_finished and row.last_finished and j.last_finished > row.last_finished:
        return j
    return replace(
        j, runs=row.runs, failures=row.failures, last_started=row.last_started, last_finished=row.last_finished,
        last_ok=row.last_ok, last_failure_kind=row.last_failure_kind, last_duration_s=row.last_duration_s,
    )
