"""
Live certificate stream worker (plan step 2.6b).

    python -m app.workers.ct_stream            # run until stopped
    python -m app.workers.ct_stream --seconds 120   # run for a fixed time (smoke test / demo)

A SEPARATE process from the API on purpose: it holds long-lived connections, runs all day, and must not share a restart with
web requests. It needs BRAND_GUARD_ENABLED=true and the same database. It never touches PathProof tables; it reads active
brand profiles and writes candidates through the same pipeline a scan uses.

What it does
  1. follows the tiled CT logs of the configured families (all their current and upcoming shards), reading each 256-entry data
     tile as soon as it is complete (seconds behind the log's head on busy logs);
  2. matches every certificate name against every protected brand (brand_ct_stream.StreamMatcher: a cheap necessary-condition
     filter, then the same name rules a scan uses);
  3. every few seconds hands the matches to `process_stream_hits` (DNS, registration date, mail intent, scoring, alerts);
  4. remembers where it was (ct_stream_cursors) so a restart resumes; if it falls too far behind it jumps ahead and says so;
  5. reports its health in the same source-health strip customers see.

Honest limits: only the families named in configuration are followed (a certificate logged only elsewhere is missed); the log's
signature is not verified (a certificate here is a lead, never evidence); and it sees certificates, not registrations: a name
that never gets a certificate is found by the new-registration list or the permutation scan instead.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.config import settings
from app.services import brand_ct_stream as stream, brand_sources as sources, ct_log_list as loglist, ct_tiles as tiles
from app.services.brand_ct_stream import HitBuffer, RecentNames, StreamBrand, StreamMatcher

log = logging.getLogger("ct_stream")

HTTP_TIMEOUT = 30.0
USER_AGENT = "ZoneProof-BrandGuard/1.0 (certificate-transparency monitor)"
TILE_CONCURRENCY = 4              # tiles of one log fetched at once (a busy log produces a tile every ~1.4 s and answers in ~1 s)
IDLE_POLL = 5.0                   # seconds between checkpoint looks when a log has nothing new
BRAND_REFRESH = 300.0             # how often the list of protected brands is re-read
LOG_LIST_REFRESH = 6 * 3600.0
HEALTH_EVERY = 30.0
STALE_AFTER = 180.0               # no progress from any log for this long = unhealthy
MAX_BACKOFF = 120.0


class FetchError(Exception):
    pass


# ── Following one log ────────────────────────────────────────────────────────

@dataclass
class Cursor:
    next_index: int | None = None
    tree_size: int = 0
    lag_seconds: float | None = None
    entries_seen: int = 0
    entries_skipped: int = 0
    names_matched: int = 0


@dataclass
class LogFollower:
    log: loglist.TileLog
    client: httpx.AsyncClient
    cursor: Cursor = field(default_factory=Cursor)
    backlog_tiles: int = 1500
    failures: int = 0
    last_progress: float = 0.0          # time.monotonic() of the last tile read
    last_ok: float = 0.0                # ... of the last successful request
    wire_bytes: int = 0                 # bytes actually downloaded (compressed, as sent), for capacity planning

    async def _get(self, path: str) -> bytes:
        try:
            r = await self.client.get(self.log.url + path)
        except httpx.HTTPError as e:
            raise FetchError(type(e).__name__) from e
        self.wire_bytes += getattr(r, "num_bytes_downloaded", 0)
        if r.status_code == 404:
            raise FileNotFoundError(path)
        if r.status_code != 200:
            raise FetchError(f"HTTP {r.status_code}")
        return r.content

    async def tree_size(self) -> int:
        data = await self._get("checkpoint")
        try:
            return tiles.parse_checkpoint(data.decode("utf-8", errors="replace"))[1]
        except tiles.TileError as e:
            raise FetchError("bad checkpoint") from e

    async def step(self, on_sightings) -> int:
        """One pass: read every complete tile between the cursor and the head (a bounded number at a time).
        Returns the number of entries read. `on_sightings(sightings, log)` is called per tile, in log order."""
        size = await self.tree_size()
        self.last_ok = time.monotonic()
        c = self.cursor
        c.tree_size = size
        head_tile = size // tiles.TILE_WIDTH                      # tiles [0, head_tile) are complete
        if c.next_index is None:
            c.next_index = head_tile * tiles.TILE_WIDTH            # first run: start at the head, not the beginning of history
            return 0
        first = c.next_index // tiles.TILE_WIDTH
        behind = head_tile - first
        if behind > self.backlog_tiles:                           # hopelessly behind: skip ahead, and say so
            skipped = (behind - 1) * tiles.TILE_WIDTH
            log.warning("%s: %d tiles behind, skipping %d entries", self.log.name, behind, skipped)
            c.entries_skipped += skipped
            first = head_tile - 1
            c.next_index = first * tiles.TILE_WIDTH
        if first >= head_tile:
            return 0
        wanted = list(range(first, min(head_tile, first + TILE_CONCURRENCY)))
        results = await asyncio.gather(*[self._tile(i) for i in wanted], return_exceptions=True)
        done = 0
        for index, res in zip(wanted, results):
            if isinstance(res, FileNotFoundError):
                break                                              # published later than the checkpoint says: try again next pass
            if isinstance(res, Exception):
                raise res
            sightings = res
            if sightings:
                c.lag_seconds = max(0.0, time.time() - max(s.logged_at_ms for s in sightings) / 1000)
            c.entries_seen += tiles.TILE_WIDTH
            c.next_index = (index + 1) * tiles.TILE_WIDTH
            c.names_matched += on_sightings(sightings, self.log)
            self.last_progress = time.monotonic()
            done += tiles.TILE_WIDTH
        return done

    async def _tile(self, index: int) -> list[tiles.CertSighting]:
        data = await self._get("tile/data/" + tiles.tile_path(index))
        try:
            return tiles.parse_tile(data)
        except tiles.TileError as e:
            log.warning("%s: tile %d unreadable (%s); skipped", self.log.name, index, e)
            return []


# ── Brands ───────────────────────────────────────────────────────────────────

async def load_brands(db) -> list[StreamBrand]:
    """Active brands whose plan includes certificate monitoring, with the tokens and official names the matcher needs."""
    from app.models import BrandProfile, Domain, Tenant
    from app.services.brand_discovery_service import registrable_domain
    from app.services.brand_guard_service import brand_tokens_for
    from app.services.plan_limits import get_limits

    rows = (await db.execute(
        select(BrandProfile, Domain, Tenant).join(Domain, Domain.id == BrandProfile.domain_id).join(Tenant, Tenant.id == BrandProfile.tenant_id)
        .where(BrandProfile.is_active == True)  # noqa: E712
    )).all()
    out: list[StreamBrand] = []
    for profile, domain, tenant in rows:
        if not get_limits(tenant.plan).get("brand_guard_ct"):
            continue
        names = [domain.name, *(profile.official_domains or [])]
        out.append(StreamBrand(
            profile_id=str(profile.id), tenant_id=str(profile.tenant_id), tokens=tuple(brand_tokens_for(profile, domain.name)),
            official_apexes=frozenset(registrable_domain(n) for n in names), official_names=tuple(names),
        ))
    return out


# ── Cursors and health ───────────────────────────────────────────────────────

async def load_cursors(db) -> dict[str, Cursor]:
    from app.models import CtStreamCursor
    rows = (await db.execute(select(CtStreamCursor))).scalars().all()
    return {r.log_id: Cursor(r.next_index, r.tree_size, r.lag_seconds, r.entries_seen, r.entries_skipped, r.names_matched) for r in rows}


async def save_cursor(db, log_id: str, c: Cursor) -> None:
    from app.models import CtStreamCursor
    if c.next_index is None:
        return
    values = dict(next_index=c.next_index, tree_size=c.tree_size, lag_seconds=c.lag_seconds, entries_seen=c.entries_seen,
                  entries_skipped=c.entries_skipped, names_matched=c.names_matched, updated_at=datetime.now(timezone.utc))
    stmt = pg_insert(CtStreamCursor).values(log_id=log_id, **values).on_conflict_do_update(index_elements=["log_id"], set_=values)
    await db.execute(stmt)
    await db.commit()


# ── The worker ───────────────────────────────────────────────────────────────

class Worker:
    def __init__(self, *, session_factory, client_factory=None, families=None, extra_logs=None, log_list_fetcher=None) -> None:
        self.session_factory = session_factory
        self.client_factory = client_factory or (lambda: httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}, follow_redirects=True))
        self.families = tuple(families or [f.strip() for f in settings.ct_stream_families.split(",") if f.strip()] or loglist.DEFAULT_FAMILIES)
        self.extra_logs = list(extra_logs if extra_logs is not None else [u for u in settings.ct_stream_extra_logs.split(",") if u.strip()])
        self.log_list_fetcher = log_list_fetcher
        self.matcher = StreamMatcher([])
        self.buffer = HitBuffer()
        self.recent = RecentNames()
        self.followers: dict[str, LogFollower] = {}
        self.tasks: dict[str, asyncio.Task] = {}
        self.stop = asyncio.Event()
        self.dropped_by_cap = 0
        self.matched_total = 0
        self.errors: dict[str, str] = {}
        self.client: httpx.AsyncClient | None = None
        self.started = time.monotonic()

    # matching (called per tile, synchronous and fast)
    def on_sightings(self, sightings: list[tiles.CertSighting], log_: loglist.TileLog) -> int:
        n = 0
        for s in sightings:
            for brand, key, klass, ct in self.matcher.match(s):
                self.buffer.add(brand, key, klass, ct)
                n += 1
        self.matched_total += n
        return n

    async def refresh_brands(self) -> None:
        async with self.session_factory() as db:
            brands = await load_brands(db)
        self.matcher = StreamMatcher(brands)
        log.info("following certificates for %d brand(s)", len(brands))

    async def fetch_log_list(self) -> dict | None:
        if self.log_list_fetcher is not None:
            return await self.log_list_fetcher()
        try:
            r = await self.client.get(loglist.LOG_LIST_URL)
            return r.json() if r.status_code == 200 else None
        except (httpx.HTTPError, ValueError):
            return None

    async def refresh_logs(self) -> None:
        wanted = loglist.resolve(await self.fetch_log_list(), self.families) + loglist.custom_logs(self.extra_logs)
        ids = {l.id for l in wanted}
        async with self.session_factory() as db:
            saved = await load_cursors(db)
        for l in wanted:
            if l.id not in self.followers:
                f = LogFollower(l, self.client, cursor=saved.get(l.id, Cursor()), backlog_tiles=settings.ct_stream_backlog_tiles)
                self.followers[l.id] = f
                self.tasks[l.id] = asyncio.create_task(self.follow(f), name=f"ct:{l.id}")
                log.info("following %s", l.name)
        for gone in [i for i in self.followers if i not in ids]:           # a shard that has aged out of the list
            self.tasks.pop(gone).cancel()
            self.followers.pop(gone)
            log.info("stopped following %s", gone)

    async def follow(self, f: LogFollower) -> None:
        backoff = 1.0
        while not self.stop.is_set():
            try:
                done = await f.step(self.on_sightings)
                f.failures = 0
                backoff = 1.0
                self.errors.pop(f.log.id, None)
                if f.cursor.next_index is not None and done:
                    async with self.session_factory() as db:
                        await save_cursor(db, f.log.id, f.cursor)
                if done == 0:
                    await self._sleep(IDLE_POLL)
            except asyncio.CancelledError:
                raise
            except Exception as e:                                           # a log that fails is retried with backoff, never fatal
                f.failures += 1
                self.errors[f.log.id] = f"{type(e).__name__}: {e}"[:160]
                log.warning("%s: %s (retry in %.0fs)", f.log.name, e, backoff)
                await self._sleep(backoff)
                backoff = min(MAX_BACKOFF, backoff * 2)

    async def _sleep(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self.stop.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    async def flush(self) -> dict:
        """Hand the buffered matches to the scoring pipeline, brand by brand. Never raises."""
        from app.models import BrandProfile, Tenant
        from app.services.brand_guard_service import process_stream_hits

        self.dropped_by_cap += self.buffer.dropped
        self.buffer.dropped = 0
        pending = self.buffer.drain()
        summary = {"brands": 0, "names": 0}
        for profile_id, names in pending.items():
            fresh = {k: v for k, v in names.items() if self.recent.fresh(profile_id, k)}
            if len(fresh) > settings.ct_stream_max_per_flush:
                self.dropped_by_cap += len(fresh) - settings.ct_stream_max_per_flush
                fresh = dict(list(fresh.items())[: settings.ct_stream_max_per_flush])
            if not fresh:
                continue
            try:
                async with self.session_factory() as db:
                    profile = await db.get(BrandProfile, profile_id)
                    tenant = await db.get(Tenant, profile.tenant_id) if profile else None
                    if profile is None or tenant is None or not profile.is_active:
                        continue
                    await process_stream_hits(db, profile, tenant, fresh)
                summary["brands"] += 1
                summary["names"] += len(fresh)
            except Exception:
                log.exception("flush failed for brand %s", profile_id)
        return summary

    async def report_health(self) -> None:
        now = time.monotonic()
        progressed = [f for f in self.followers.values() if f.last_progress and now - f.last_progress < STALE_AFTER]
        reachable = [f for f in self.followers.values() if f.last_ok and now - f.last_ok < STALE_AFTER]
        ok = bool(self.followers) and len(reachable) == len(self.followers)      # partial reachability is reported as degraded, with the reason
        lags = [f.cursor.lag_seconds for f in self.followers.values() if f.cursor.lag_seconds is not None]
        error = None
        if not self.followers:
            error = "no logs configured"
        elif not reachable:
            error = next(iter(self.errors.values()), "no log reachable")
        elif len(reachable) < len(self.followers):
            error = f"{len(self.followers) - len(reachable)} of {len(self.followers)} logs unreachable"
        async with self.session_factory() as db:
            await sources._record(db, stream.STREAM_SOURCE, ok=ok, latency_ms=int(max(lags) * 1000) if lags else None, error=error)
        if progressed:
            mb = sum(f.wire_bytes for f in self.followers.values()) / 1e6
            per_day = mb / max(1.0, now - self.started) * 86400 / 1000
            log.info("stream: %d log(s) reading, lag %.0fs, %d matched, %d dropped by cap, %.0f MB downloaded (about %.0f GB/day at this rate)",
                     len(progressed), max(lags) if lags else -1, self.matched_total, self.dropped_by_cap, mb, per_day)

    async def run(self, seconds: float | None = None) -> None:
        self.client = self.client_factory()
        started = time.monotonic()
        try:
            await self.refresh_brands()
            await self.refresh_logs()
            next_brands = next_logs = next_health = time.monotonic()
            next_brands += BRAND_REFRESH
            next_logs += LOG_LIST_REFRESH
            next_health += HEALTH_EVERY
            while not self.stop.is_set():
                await self._sleep(settings.ct_stream_flush_seconds)
                await self.flush()
                now = time.monotonic()
                if now >= next_health:
                    next_health = now + HEALTH_EVERY
                    try:
                        await self.report_health()
                    except Exception:
                        log.exception("health report failed")
                if now >= next_brands:
                    next_brands = now + BRAND_REFRESH
                    try:
                        await self.refresh_brands()
                    except Exception:
                        log.exception("brand refresh failed")
                if now >= next_logs:
                    next_logs = now + LOG_LIST_REFRESH
                    try:
                        await self.refresh_logs()
                    except Exception:
                        log.exception("log list refresh failed")
                if seconds is not None and now - started >= seconds:
                    break
        finally:
            self.stop.set()
            for t in self.tasks.values():
                t.cancel()
            await asyncio.gather(*self.tasks.values(), return_exceptions=True)
            try:
                await self.flush()
                await self.report_health()
            except Exception:
                log.exception("final flush failed")
            await self.client.aclose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Follow Certificate Transparency logs and feed Brand Guard.")
    parser.add_argument("--seconds", type=float, default=None, help="stop after this many seconds (default: run until interrupted)")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if not settings.brand_guard_enabled:
        raise SystemExit("BRAND_GUARD_ENABLED is not true: refusing to run. The stream feeds Brand Guard and must be switched on deliberately.")
    from app.database import AsyncSessionLocal
    worker = Worker(session_factory=AsyncSessionLocal)
    try:
        asyncio.run(worker.run(args.seconds))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
