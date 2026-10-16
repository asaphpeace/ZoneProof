"""When background jobs first run after a restart (G1)."""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.services import job_startup as js
from tests.factories import make_domain, make_tenant

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
DAY = 86400


# ── the decision ─────────────────────────────────────────────────────────────

def test_interval_only_jobs_keep_waiting_a_full_interval():
    assert js.initial_delay(DAY, None, NOW, 0, js.INTERVAL_ONLY) == DAY


def test_due_aware_jobs_start_shortly_after_the_server():
    assert js.initial_delay(DAY, None, NOW, 0, js.DUE_AWARE) == js.STAGGER_BASE_S


def test_first_runs_are_staggered_by_slot():
    delays = [js.initial_delay(DAY, None, NOW, i, js.DUE_AWARE) for i in range(4)]
    assert delays == sorted(delays) and len(set(delays)) == 4


def test_a_batch_job_that_never_ran_starts_shortly():
    assert js.initial_delay(DAY, None, NOW, 2, js.HINT) == js.STAGGER_BASE_S + 2 * js.STAGGER_STEP_S


def test_a_batch_job_that_is_overdue_starts_shortly():
    last = NOW - timedelta(seconds=DAY + 60)
    assert js.initial_delay(DAY, last, NOW, 0, js.HINT) == js.STAGGER_BASE_S


def test_a_batch_job_that_ran_recently_waits_out_the_rest_of_its_interval():
    last = NOW - timedelta(hours=6)
    assert js.initial_delay(DAY, last, NOW, 0, js.HINT) == pytest.approx(DAY - 6 * 3600)


def test_a_batch_job_that_ran_a_moment_ago_never_waits_longer_than_one_interval():
    assert js.initial_delay(DAY, NOW, NOW, 0, js.HINT) == DAY
    assert js.initial_delay(DAY, NOW + timedelta(hours=3), NOW, 0, js.HINT) == DAY   # clock skew


def test_a_short_interval_is_never_exceeded_by_the_stagger():
    assert js.initial_delay(10, None, NOW, 13, js.DUE_AWARE) == 10


def test_naive_timestamps_are_treated_as_utc():
    last = (NOW - timedelta(hours=1)).replace(tzinfo=None)
    assert js.initial_delay(DAY, last, NOW, 0, js.HINT) == pytest.approx(DAY - 3600)


def test_the_switch_restores_the_old_timing_for_every_policy():
    for policy in (js.DUE_AWARE, js.HINT, js.INTERVAL_ONLY):
        assert js.initial_delay(DAY, None, NOW, 0, policy, catch_up=False) == DAY


# ── the loop ─────────────────────────────────────────────────────────────────

@pytest.fixture
def fast(monkeypatch):
    monkeypatch.setattr(js, "STAGGER_BASE_S", 0.02)
    monkeypatch.setattr(js, "STAGGER_STEP_S", 0.0)


async def _run_for(loop_factory, seconds):
    task = asyncio.create_task(loop_factory())
    await asyncio.sleep(seconds)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


def _task(fn, seconds, **kw):
    from app.main import _make_interval_task
    return _make_interval_task(fn, seconds, **kw)


async def test_a_due_aware_job_runs_at_start_not_after_a_whole_interval(fast):
    calls = []

    async def job():
        calls.append(1)
    await _run_for(_task(job, 3600, policy=js.DUE_AWARE), 0.3)
    assert len(calls) == 1


async def test_an_interval_only_job_does_not_run_at_start(fast):
    calls = []

    async def job():
        calls.append(1)
    await _run_for(_task(job, 3600, policy=js.INTERVAL_ONLY), 0.3)
    assert calls == []


async def test_a_recently_run_batch_job_does_not_run_at_start(fast):
    calls = []

    async def job():
        calls.append(1)

    async def last():
        return datetime.now(timezone.utc)
    await _run_for(_task(job, 3600, policy=js.HINT, last_run=last), 0.3)
    assert calls == []


async def test_an_overdue_batch_job_runs_at_start(fast):
    calls = []

    async def job():
        calls.append(1)

    async def last():
        return datetime.now(timezone.utc) - timedelta(days=2)
    await _run_for(_task(job, 3600, policy=js.HINT, last_run=last), 0.3)
    assert len(calls) == 1


async def test_a_failing_hint_falls_back_to_waiting_one_interval(fast):
    calls = []

    async def job():
        calls.append(1)

    async def last():
        raise RuntimeError("database not ready")
    await _run_for(_task(job, 3600, policy=js.HINT, last_run=last), 0.3)
    assert calls == []


async def test_the_loop_survives_a_job_that_raises(fast):
    calls = []

    async def job():
        calls.append(1)
        raise RuntimeError("boom")
    await _run_for(_task(job, 0.05, policy=js.DUE_AWARE), 0.4)
    assert len(calls) >= 2


async def test_the_switch_off_restores_waiting(fast, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "jobs_run_overdue_at_start", False)
    calls = []

    async def job():
        calls.append(1)
    await _run_for(_task(job, 3600, policy=js.DUE_AWARE), 0.3)
    assert calls == []


async def test_the_registry_learns_when_a_job_is_first_due(fast):
    from app.services import job_registry

    async def job():
        pass
    job._job_key = "g1_probe"
    job_registry.register("g1_probe", "Probe", "x", lambda: 3600)
    await _run_for(_task(job, 3600, policy=js.DUE_AWARE), 0.1)
    state = next(j for j in job_registry.snapshot() if j.key == "g1_probe")
    assert state.first_run_at is not None and state.startup_policy == js.DUE_AWARE
    assert (state.first_run_at - datetime.now(timezone.utc)).total_seconds() < 5


# ── the database hints ───────────────────────────────────────────────────────

class _Ctx:
    def __init__(self, db):
        self.db = db

    async def __aenter__(self):
        return self.db

    async def __aexit__(self, *a):
        return False


async def test_dns_hint_is_the_newest_check_among_active_domains(db_session, monkeypatch):
    import app.database as database
    tenant = await make_tenant(db_session)
    a = await make_domain(db_session, tenant, name="a.hint.test")
    b = await make_domain(db_session, tenant, name="b.hint.test")
    gone = await make_domain(db_session, tenant, name="gone.hint.test")
    a.last_checked_at = NOW - timedelta(days=3)
    b.last_checked_at = NOW - timedelta(hours=2)
    gone.last_checked_at = NOW
    gone.is_active = False
    await db_session.flush()
    monkeypatch.setattr(database, "AsyncSessionLocal", lambda: _Ctx(db_session))
    assert await js.last_dns_check() == NOW - timedelta(hours=2)


async def test_dns_hint_is_none_when_nothing_was_ever_checked(db_session, monkeypatch):
    import app.database as database
    tenant = await make_tenant(db_session)
    await make_domain(db_session, tenant, name="never.hint.test")
    monkeypatch.setattr(database, "AsyncSessionLocal", lambda: _Ctx(db_session))
    assert await js.last_dns_check() is None
