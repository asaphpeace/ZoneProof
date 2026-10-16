"""G2: job history survives a restart and is visible to a standby instance."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import JobRun
from app.services import job_registry


@pytest.fixture(autouse=True)
def _fresh_registry():
    saved = dict(job_registry._jobs)
    job_registry.reset()
    yield
    job_registry._jobs.clear()
    job_registry._jobs.update(saved)


def _factory(db_session):
    """A session factory that reuses the test's rolled-back session."""
    class Ctx:
        async def __aenter__(self): return db_session
        async def __aexit__(self, *a): return False
    return lambda: Ctx()


async def _run(db_session, key, fail=False):
    job_registry.start(key)
    if fail:
        job_registry.fail(key, TimeoutError())
    job_registry.finish(key)
    await job_registry.persist(key, _factory(db_session))


@pytest.mark.asyncio
async def test_counters_accumulate_in_the_database(db_session):
    job_registry.register("j", "Job", "x", lambda: 60)
    await _run(db_session, "j")
    await _run(db_session, "j", fail=True)
    await _run(db_session, "j")
    row = (await db_session.execute(select(JobRun).where(JobRun.job_key == "j"))).scalar_one()
    assert (row.runs, row.failures, row.last_ok, row.last_failure_kind) == (3, 1, True, None)


@pytest.mark.asyncio
async def test_a_restarted_process_shows_the_stored_history(db_session):
    job_registry.register("j", "Job", "x", lambda: 60)
    await _run(db_session, "j", fail=True)
    row = (await db_session.execute(select(JobRun))).scalar_one()

    job_registry.reset()                                   # restart: memory is empty
    job_registry.register("j", "Job", "x", lambda: 60)
    shown = job_registry.overlay(job_registry.snapshot()[0], row)
    assert (shown.runs, shown.failures, shown.last_ok, shown.last_failure_kind) == (1, 1, False, "timed_out")
    assert shown.last_finished == row.last_finished


def test_a_newer_local_run_beats_a_lagging_stored_row():
    job_registry.register("j", "Job", "x", lambda: 60)
    job_registry.start("j"); job_registry.finish("j")
    local = job_registry.snapshot()[0]
    stale = JobRun(job_key="j", runs=9, failures=0, last_finished=local.last_finished - timedelta(hours=1))
    assert job_registry.overlay(local, stale) is local
    assert job_registry.overlay(local, None) is local


@pytest.mark.asyncio
async def test_a_failing_store_never_breaks_the_job():
    job_registry.register("j", "Job", "x", lambda: 60)
    job_registry.start("j"); job_registry.finish("j")

    def broken():
        raise ConnectionError("db at 10.0.0.5 unreachable")
    await job_registry.persist("j", broken)               # must not raise
