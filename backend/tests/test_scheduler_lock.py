"""C1: only one instance runs the background jobs (a Postgres advisory lock leader election)."""
import asyncio
import os
import uuid

import pytest

from app.services import job_registry
from app.services.scheduler_lock import LeaderLock, asyncpg_dsn, lock_key, run_scheduler


# ── helpers ──────────────────────────────────────────────────────────────────

class FakeConn:
    def __init__(self, got=True, fail_after=None):
        self.got = got
        self.closed = False
        self.queries = []
        self.fail_after = fail_after

    async def fetchval(self, sql, *args):
        self.queries.append(sql)
        if self.fail_after is not None and len(self.queries) > self.fail_after:
            raise ConnectionError("gone")
        if "pg_try_advisory_lock" in sql:
            return self.got
        return 1

    async def close(self):
        self.closed = True


def fake_connect(conn=None, error=None):
    async def connect(dsn, timeout=None):
        if error:
            raise error
        return conn
    return connect


# ── key and DSN ──────────────────────────────────────────────────────────────

def test_key_is_stable_signed_64_bit_and_differs_by_schema():
    assert lock_key() == lock_key("")
    assert lock_key("dev_live") != lock_key("")
    assert lock_key() == lock_key("public")
    assert -(2 ** 63) <= lock_key("x") < 2 ** 63


def test_sqlalchemy_url_becomes_an_asyncpg_dsn():
    assert asyncpg_dsn("postgresql+asyncpg://u:p@h:5432/db") == "postgresql://u:p@h:5432/db"
    assert asyncpg_dsn("postgresql://u:p@h/db") == "postgresql://u:p@h/db"


# ── LeaderLock with a fake connection ────────────────────────────────────────

async def test_acquire_holds_the_connection_open():
    conn = FakeConn(got=True)
    lock = LeaderLock("dsn", 1, connect=fake_connect(conn))
    assert await lock.try_acquire() is True
    assert lock.held and not conn.closed
    assert await lock.try_acquire() is True            # already ours; no second connection


async def test_when_another_server_holds_it_the_connection_is_closed_again():
    conn = FakeConn(got=False)
    lock = LeaderLock("dsn", 1, connect=fake_connect(conn))
    assert await lock.try_acquire() is False
    assert conn.closed and not lock.held


async def test_an_unreachable_database_is_not_leadership_and_does_not_raise():
    lock = LeaderLock("dsn", 1, connect=fake_connect(error=OSError("refused")))
    assert await lock.try_acquire() is False


async def test_a_dead_connection_means_leadership_is_gone():
    conn = FakeConn(got=True, fail_after=1)
    lock = LeaderLock("dsn", 1, connect=fake_connect(conn))
    assert await lock.try_acquire() is True
    assert await lock.still_held() is False
    assert not lock.held and conn.closed


async def test_release_unlocks_and_closes():
    conn = FakeConn(got=True)
    lock = LeaderLock("dsn", 1, connect=fake_connect(conn))
    await lock.try_acquire()
    await lock.release()
    assert any("pg_advisory_unlock" in q for q in conn.queries)
    assert conn.closed and not lock.held


# ── the real thing: two contenders on one database ───────────────────────────

def _dsn():
    return asyncpg_dsn(os.environ.get("TEST_DATABASE_URL", "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel_test"))


async def test_only_one_of_two_contenders_leads_and_the_other_takes_over():
    key = int.from_bytes(uuid.uuid4().bytes[:8], "big", signed=True)
    a, b = LeaderLock(_dsn(), key), LeaderLock(_dsn(), key)
    try:
        assert await a.try_acquire() is True
        assert await b.try_acquire() is False          # a is the leader
        assert await a.still_held() is True
        await a.release()
        assert await b.try_acquire() is True           # b takes over
    finally:
        await a.release()
        await b.release()


async def test_a_leader_that_dies_without_releasing_hands_over():
    key = int.from_bytes(uuid.uuid4().bytes[:8], "big", signed=True)
    a, b = LeaderLock(_dsn(), key), LeaderLock(_dsn(), key)
    try:
        assert await a.try_acquire() is True
        a._conn._transport.abort()                      # the process or network dies: no unlock is sent
        await asyncio.sleep(0.3)
        assert await b.try_acquire() is True
        assert await a.still_held() is False
    finally:
        await a.release()
        await b.release()


# ── the election loop ────────────────────────────────────────────────────────

class ScriptedLock:
    """try_acquire answers from a list; still_held from another."""
    def __init__(self, acquire, held=()):
        self.acquire = list(acquire)
        self.held_answers = list(held)
        self.released = False
        self.acquired_calls = 0

    async def try_acquire(self):
        self.acquired_calls += 1
        return self.acquire.pop(0) if self.acquire else False

    async def still_held(self):
        return self.held_answers.pop(0) if self.held_answers else True

    async def release(self):
        self.released = True


async def _drive(lock, start_jobs, seconds):
    roles = []
    task = asyncio.create_task(run_scheduler(lock, start_jobs, roles.append, retry_seconds=0.02, beat_seconds=0.02))
    await asyncio.sleep(seconds)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    return roles


class Jobs:
    def __init__(self):
        self.started = 0
        self.cancelled = 0

    async def start(self):
        self.started += 1

        async def forever():
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                self.cancelled += 1
                raise
        return [asyncio.create_task(forever())]


async def test_a_standby_never_starts_jobs():
    lock, jobs = ScriptedLock([False] * 50), Jobs()
    roles = await _drive(lock, jobs.start, 0.2)
    assert jobs.started == 0
    assert set(roles) == {"standby"}
    assert lock.released


async def test_the_leader_starts_jobs_once_and_stops_them_on_shutdown():
    lock, jobs = ScriptedLock([True]), Jobs()
    roles = await _drive(lock, jobs.start, 0.2)
    assert jobs.started == 1
    assert roles == ["leader"]
    assert jobs.cancelled == 1 and lock.released


async def test_losing_the_lock_stops_the_jobs_before_contending_again():
    lock = ScriptedLock(acquire=[True, False, False, True], held=[False])
    jobs = Jobs()
    roles = await _drive(lock, jobs.start, 0.4)
    assert roles[0] == "leader" and "standby" in roles
    assert jobs.started == 2 and jobs.cancelled >= 1       # stopped first, started again on regaining it


async def test_a_job_list_that_is_empty_does_not_restart_in_a_loop():
    async def start_nothing():
        return []
    lock = ScriptedLock([True])
    await _drive(lock, start_nothing, 0.2)
    assert lock.acquired_calls == 1


# ── the Data sources page knows the role ─────────────────────────────────────

@pytest.fixture(autouse=True)
def _clean_registry():
    job_registry.reset()
    yield
    job_registry.reset()


async def test_standby_instances_say_another_server_runs_the_jobs(auth_client):
    client, _ = auth_client
    job_registry.register("j", "Job", "x", lambda: 3600)
    job_registry.set_role("standby")
    body = (await client.get("/sources/health")).json()
    assert body["scheduler"]["role"] == "standby"
    job = next(j for j in body["jobs"] if j["key"] == "j")
    assert job["status"] == "standby" and "Another server" in job["note"]


async def test_the_leader_reports_normal_job_states(auth_client):
    client, _ = auth_client
    job_registry.register("j", "Job", "x", lambda: 3600)
    job_registry.start("j"); job_registry.finish("j")
    job_registry.set_role("leader")
    body = (await client.get("/sources/health")).json()
    assert body["scheduler"]["role"] == "leader" and body["scheduler"]["since"]
    assert next(j for j in body["jobs"] if j["key"] == "j")["status"] == "ok"


async def test_a_switched_off_scheduler_is_stated(auth_client):
    client, _ = auth_client
    job_registry.register("j", "Job", "x", lambda: 3600)
    job_registry.set_role("disabled")
    job = next(j for j in (await client.get("/sources/health")).json()["jobs"] if j["key"] == "j")
    assert job["status"] == "not_here"
