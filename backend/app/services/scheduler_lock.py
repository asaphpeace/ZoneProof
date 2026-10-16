"""
One scheduler per database: a leader lock.

The background jobs run inside the API process. Started on two containers
they would run twice (duplicate emails, double scans, racing writes). This
makes the job runner a leader election over a Postgres session-level advisory
lock:

  * every instance with SCHEDULER_ENABLED contends for the lock;
  * the holder (the leader) starts the jobs, the others stand by;
  * the lock belongs to a dedicated connection, so if the leader's process or
    network dies, Postgres releases it and a standby takes over within
    SCHEDULER_LOCK_RETRY_SECONDS, and catches up overdue jobs on the way in
    (see job_startup.py);
  * a leader that finds its lock connection gone stops its jobs first and then
    contends again, so two instances never believe they are leader together.

Limits worth knowing:
  * A connection pooler in transaction mode (PgBouncer, RDS Proxy) does not
    keep session-level locks. Point SCHEDULER_LOCK_DATABASE_URL at the
    database directly when the app itself goes through a pooler.
  * The lock is per database and schema, so a dev server on its own schema
    does not contend with one on another schema of the same database.
  * Job history (the Data sources page) is still per process; only the leader
    has any.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Awaitable, Callable

log = logging.getLogger(__name__)


def lock_key(schema: str = "") -> int:
    """A stable signed 64-bit key for pg_advisory_lock, namespaced by schema."""
    digest = hashlib.sha256(f"zoneproof-scheduler:{schema or 'public'}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def asyncpg_dsn(url: str) -> str:
    """The SQLAlchemy URL the app uses, as a plain asyncpg DSN."""
    for prefix in ("postgresql+asyncpg://", "postgres+asyncpg://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix):]
    return url


class LeaderLock:
    """A session-level advisory lock held on its own connection."""

    def __init__(self, dsn: str, key: int, *, connect: Callable[..., Awaitable] | None = None, timeout: float = 10.0):
        self._dsn = dsn
        self._key = key
        self._connect = connect
        self._timeout = timeout
        self._conn = None

    async def _open(self):
        connect = self._connect
        if connect is None:
            import asyncpg
            connect = asyncpg.connect
        return await connect(self._dsn, timeout=self._timeout)

    @property
    def held(self) -> bool:
        return self._conn is not None

    async def try_acquire(self) -> bool:
        """True if this call took the lock (or already holds it). Never raises."""
        if self._conn is not None:
            return True
        conn = None
        try:
            conn = await self._open()
            got = await conn.fetchval("SELECT pg_try_advisory_lock($1)", self._key)
        except Exception as e:  # database unreachable: not leader, try again later
            log.warning("Scheduler lock: could not ask the database (%s)", type(e).__name__)
            await self._close(conn)
            return False
        if not got:
            await self._close(conn)
            return False
        self._conn = conn
        return True

    async def still_held(self) -> bool:
        """The lock lives and dies with its connection, so a working connection means we still hold it."""
        if self._conn is None:
            return False
        try:
            await self._conn.fetchval("SELECT 1")
            return True
        except Exception as e:
            log.warning("Scheduler lock: connection lost (%s); leadership is gone", type(e).__name__)
            await self._close(self._conn)
            self._conn = None
            return False

    async def release(self) -> None:
        conn, self._conn = self._conn, None
        if conn is None:
            return
        try:
            await conn.fetchval("SELECT pg_advisory_unlock($1)", self._key)
        except Exception:
            pass
        await self._close(conn)

    @staticmethod
    async def _close(conn) -> None:
        if conn is None:
            return
        try:
            await asyncio.wait_for(conn.close(), timeout=5)
        except Exception:
            pass


async def run_scheduler(
    lock: LeaderLock,
    start_jobs: Callable[[], Awaitable[list[asyncio.Task]]],
    on_role: Callable[[str], None],
    *,
    retry_seconds: float,
    beat_seconds: float,
) -> None:
    """
    Contend for the lock; while leader, keep the jobs running and check the lock
    on a heartbeat. Cancelling this coroutine stops the jobs and releases the lock.
    """
    tasks: list[asyncio.Task] = []
    leader = False

    async def stop_jobs():
        nonlocal tasks
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        tasks = []

    try:
        while True:
            if not leader:
                if await lock.try_acquire():
                    log.info("Scheduler: this server is the leader; starting background jobs")
                    leader = True
                    on_role("leader")
                    tasks = await start_jobs()
                else:
                    on_role("standby")
                    await asyncio.sleep(retry_seconds)
                continue
            await asyncio.sleep(beat_seconds)
            if not await lock.still_held():
                log.warning("Scheduler: leadership lost; stopping background jobs and standing by")
                await stop_jobs()
                leader = False
                on_role("standby")
    finally:
        await stop_jobs()
        await lock.release()
