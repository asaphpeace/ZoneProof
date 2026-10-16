"""The live certificate stream worker (app/workers/ct_stream.py): following a log, handing matches to the pipeline, restarts, health."""
import asyncio
import time
import uuid
from datetime import datetime, timezone

import httpx
import pytest
from sqlalchemy import select

from app.models import BrandCandidate, BrandProfile, CtStreamCursor
from app.services import brand_ct_stream as bs, brand_guard_service as svc, brand_sources, ct_log_list as ll, ct_tiles as t
from app.workers import ct_stream as w
from tests.ct_helpers import checkpoint, full_tile, tile
from tests.factories import make_domain, make_tenant
from tests.test_brand_guard_api import _Borrowed

BASE = "https://log.example/2026h2/"
LOG = ll.TileLog("Test log", "custom", BASE, None, None)
NOW_MS = lambda: int(time.time() * 1000)  # noqa: E731


def serve(size, tiles_by_index, *, fail=None, calls=None):
    """A fake log: /checkpoint says `size`; /tile/data/<path> serves tiles_by_index[index]."""
    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path[len("/2026h2/"):]
        if calls is not None:
            calls.append(path)
        if fail and path in fail:
            return httpx.Response(fail[path])
        if path == "checkpoint":
            return httpx.Response(200, content=checkpoint(size))
        if path.startswith("tile/data/"):
            for index, data in tiles_by_index.items():
                if path == "tile/data/" + t.tile_path(index):
                    return httpx.Response(200, content=data)
            return httpx.Response(404)
        return httpx.Response(404)
    return handler


def follower(handler, **kw):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return w.LogFollower(LOG, client, **kw)


class Sink:
    def __init__(self):
        self.tiles = []

    def __call__(self, sightings, log_):
        self.tiles.append([s.names[0] for s in sightings])
        return 0


# ── following one log ──

async def test_first_run_starts_at_the_head_and_reads_nothing():
    calls = []
    f = follower(serve(256 * 10 + 40, {}, calls=calls))
    sink = Sink()
    assert await f.step(sink) == 0
    assert f.cursor.next_index == 256 * 10 and sink.tiles == [] and calls == ["checkpoint"]


async def test_new_complete_tiles_are_read_in_order_and_the_cursor_advances():
    ts = NOW_MS()
    f = follower(serve(256 * 12, {10: full_tile("a", ts), 11: full_tile("b", ts + 1000)}), cursor=w.Cursor(next_index=256 * 10))
    sink = Sink()
    assert await f.step(sink) == 512
    assert [x[0] for x in sink.tiles] == ["a0.example.net", "b0.example.net"]
    c = f.cursor
    assert c.next_index == 256 * 12 and c.entries_seen == 512 and c.tree_size == 256 * 12 and c.lag_seconds is not None and c.lag_seconds < 30


async def test_a_partial_tile_at_the_head_is_not_read():
    calls = []
    f = follower(serve(256 * 3 + 100, {2: full_tile("x", NOW_MS())}, calls=calls), cursor=w.Cursor(next_index=256 * 2))
    await f.step(Sink())
    assert f.cursor.next_index == 256 * 3 and not any(c.endswith("003") for c in calls)


async def test_a_tile_not_yet_published_stops_the_pass_without_error_or_advance():
    f = follower(serve(256 * 5, {3: full_tile("a", NOW_MS())}), cursor=w.Cursor(next_index=256 * 3))
    sink = Sink()
    assert await f.step(sink) == 256                                  # tile 3 read; tile 4 is a 404
    assert f.cursor.next_index == 256 * 4


async def test_a_server_error_raises_and_does_not_advance_past_the_failure():
    f = follower(serve(256 * 5, {3: full_tile("a", NOW_MS())}, fail={"tile/data/004": 503}), cursor=w.Cursor(next_index=256 * 3))
    with pytest.raises(w.FetchError):
        await f.step(Sink())
    assert f.cursor.next_index == 256 * 3 or f.cursor.next_index == 256 * 4          # nothing at or beyond the failed tile


async def test_a_bad_checkpoint_is_a_fetch_error():
    handler = lambda req: httpx.Response(200, content=b"garbage")                      # noqa: E731
    with pytest.raises(w.FetchError):
        await follower(handler).step(Sink())
    with pytest.raises(w.FetchError):
        await follower(lambda r: httpx.Response(500)).step(Sink())


async def test_tiles_are_processed_in_log_order_even_when_fetched_together():
    ts = NOW_MS()
    tiles_ = {i: full_tile(f"t{i}-", ts + i) for i in range(20, 24)}
    f = follower(serve(256 * 24, tiles_), cursor=w.Cursor(next_index=256 * 20))
    sink = Sink()
    await f.step(sink)
    assert [x[0] for x in sink.tiles] == ["t20-0.example.net", "t21-0.example.net", "t22-0.example.net", "t23-0.example.net"]


async def test_far_behind_skips_ahead_and_counts_what_it_skipped():
    f = follower(serve(256 * 100, {99: full_tile("h", NOW_MS())}), cursor=w.Cursor(next_index=0), backlog_tiles=10)
    sink = Sink()
    await f.step(sink)
    assert f.cursor.entries_skipped == 99 * 256 and f.cursor.next_index == 256 * 100 and [x[0] for x in sink.tiles] == ["h0.example.net"]


async def test_an_unreadable_tile_is_skipped_but_the_cursor_moves_on():
    f = follower(serve(256 * 4, {3: b"\x00\x01garbage"}), cursor=w.Cursor(next_index=256 * 3))
    sink = Sink()
    await f.step(sink)
    assert sink.tiles == [[]] and f.cursor.next_index == 256 * 4


async def test_nothing_new_returns_zero():
    f = follower(serve(256 * 5 + 7, {}), cursor=w.Cursor(next_index=256 * 5))
    assert await f.step(Sink()) == 0


async def test_matches_per_tile_are_added_to_the_cursor_counter():
    ts = NOW_MS()
    f = follower(serve(256 * 3, {2: full_tile("m", ts)}), cursor=w.Cursor(next_index=256 * 2))
    await f.step(lambda sightings, log_: 5)
    assert f.cursor.names_matched == 5


# ── database-backed pieces ──

@pytest.fixture
def session_factory(db_session):
    return lambda: _Borrowed(db_session)


async def brand_with(db_session, plan="pro", name="acmefinancial.co.za", official=()):
    tenant = await make_tenant(db_session, name=f"T-{uuid.uuid4().hex[:6]}", plan=plan)
    domain = await make_domain(db_session, tenant, name=name)
    domain.ownership_verified = True
    profile = BrandProfile(id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, brand_name="Acme Financial", keywords=[], official_domains=list(official))
    db_session.add(profile)
    await db_session.commit()
    return tenant, profile


async def test_only_active_brands_on_plans_with_certificate_monitoring_are_followed(db_session):
    _, pro = await brand_with(db_session, "pro", "acmefinancial.co.za", official=["acmefin.com"])
    await brand_with(db_session, "free", "freebrand.co.za")
    _, off = await brand_with(db_session, "pro", "inactive.co.za")
    off.is_active = False
    await db_session.commit()
    brands = await w.load_brands(db_session)
    assert [b.profile_id for b in brands] == [str(pro.id)]
    assert "acmefinancial" in brands[0].tokens and brands[0].official_apexes == {"acmefinancial.co.za", "acmefin.com"}


async def test_cursors_survive_a_restart_and_are_updated_in_place(db_session):
    await w.save_cursor(db_session, "log.example/2026h2", w.Cursor(256 * 7, 5000, 3.5, 100, 2, 4))
    await w.save_cursor(db_session, "log.example/2026h2", w.Cursor(256 * 9, 5200, 1.0, 300, 2, 6))
    await w.save_cursor(db_session, "other", w.Cursor(None))                       # a log not started yet is not stored
    loaded = await w.load_cursors(db_session)
    assert list(loaded) == ["log.example/2026h2"]
    c = loaded["log.example/2026h2"]
    assert (c.next_index, c.tree_size, c.entries_seen, c.names_matched) == (256 * 9, 5200, 300, 6)
    assert len((await db_session.execute(select(CtStreamCursor))).scalars().all()) == 1


def fake_network(monkeypatch, resolving):
    calls = []

    async def dns(name):
        calls.append(name)
        return {"has_a": name in resolving, "has_mx": False, "registered": name in resolving, "a": [], "ns": []}

    async def reg(client, name):
        return None

    monkeypatch.setattr(svc, "_dns_enrich", dns)
    monkeypatch.setattr(svc, "_registration_date", reg)
    return calls


def new_worker(session_factory, **kw):
    return w.Worker(session_factory=session_factory, client_factory=kw.pop("client_factory", lambda: httpx.AsyncClient()), families=["custom"], extra_logs=[], **kw)


async def test_a_flush_turns_matches_into_candidates_through_the_normal_pipeline(db_session, session_factory, monkeypatch):
    _, profile = await brand_with(db_session)
    calls = fake_network(monkeypatch, {"acmefinancial-pay.xyz"})
    worker = new_worker(session_factory)
    await worker.refresh_brands()
    sightings = [t.CertSighting(("login.acmefinancial-pay.xyz", "acmefinancial-pay.xyz"), NOW_MS(), None, "Let's Encrypt", "f" * 64, False),
                 t.CertSighting(("unrelated.example.org",), NOW_MS(), None, "LE", "e" * 64, False)]
    assert worker.on_sightings(sightings, LOG) == 1
    assert (await worker.flush()) == {"brands": 1, "names": 1}
    rows = (await db_session.execute(select(BrandCandidate).where(BrandCandidate.profile_id == profile.id))).scalars().all()
    assert [r.candidate_domain for r in rows] == ["acmefinancial-pay.xyz"]
    row = rows[0]
    assert "ct_stream" in row.sources and row.enrichment["ct_hit"] is True and row.enrichment["cert_ids"] == ["f" * 64] and row.enrichment["cert_issuer"] == "Let's Encrypt"
    assert calls == ["acmefinancial-pay.xyz"]                       # only the stream's name was looked up, nothing else re-checked


async def test_a_flush_does_not_recheck_candidates_that_are_already_tracked(db_session, session_factory, monkeypatch):
    _, profile = await brand_with(db_session)
    db_session.add(BrandCandidate(id=uuid.uuid4(), tenant_id=profile.tenant_id, profile_id=profile.id, candidate_domain="acmefinancial-old.xyz", status="monitoring", stage="registered"))
    await db_session.commit()
    calls = fake_network(monkeypatch, {"acmefinancial-new.xyz"})
    worker = new_worker(session_factory)
    await worker.refresh_brands()
    worker.on_sightings([t.CertSighting(("acmefinancial-new.xyz",), NOW_MS(), None, "LE", "d" * 64, False)], LOG)
    await worker.flush()
    assert calls == ["acmefinancial-new.xyz"]


async def test_repeat_names_are_not_handed_over_again_within_the_window(db_session, session_factory, monkeypatch):
    await brand_with(db_session)
    calls = fake_network(monkeypatch, {"acmefinancial-pay.xyz"})
    worker = new_worker(session_factory)
    await worker.refresh_brands()
    s = t.CertSighting(("acmefinancial-pay.xyz",), NOW_MS(), None, "LE", "c" * 64, False)
    worker.on_sightings([s], LOG)
    await worker.flush()
    worker.on_sightings([s], LOG)
    assert (await worker.flush()) == {"brands": 0, "names": 0}
    assert calls == ["acmefinancial-pay.xyz"]


async def test_a_burst_is_capped_per_flush_and_the_excess_is_counted(db_session, session_factory, monkeypatch):
    await brand_with(db_session)
    names = [f"acmefinancial-{i}.xyz" for i in range(5)]
    fake_network(monkeypatch, set(names))
    monkeypatch.setattr(w.settings, "ct_stream_max_per_flush", 2)
    worker = new_worker(session_factory)
    await worker.refresh_brands()
    worker.on_sightings([t.CertSighting((n,), NOW_MS(), None, "LE", f"{i:064d}", False) for i, n in enumerate(names)], LOG)
    assert (await worker.flush())["names"] == 2 and worker.dropped_by_cap == 3


async def test_names_dropped_by_the_buffer_itself_are_counted_too(db_session, session_factory, monkeypatch):
    await brand_with(db_session)
    fake_network(monkeypatch, set())
    monkeypatch.setattr(bs, "MAX_PENDING_PER_PROFILE", 1)
    worker = new_worker(session_factory)
    await worker.refresh_brands()
    worker.on_sightings([t.CertSighting((f"acmefinancial-{i}.xyz",), NOW_MS(), None, "LE", f"{i:064d}", False) for i in range(3)], LOG)
    await worker.flush()
    assert worker.dropped_by_cap == 2 and worker.buffer.dropped == 0


async def test_a_flush_for_a_brand_that_has_gone_inactive_is_skipped(db_session, session_factory, monkeypatch):
    _, profile = await brand_with(db_session)
    calls = fake_network(monkeypatch, {"acmefinancial-pay.xyz"})
    worker = new_worker(session_factory)
    await worker.refresh_brands()
    worker.on_sightings([t.CertSighting(("acmefinancial-pay.xyz",), NOW_MS(), None, "LE", "b" * 64, False)], LOG)
    profile.is_active = False
    await db_session.commit()
    assert (await worker.flush()) == {"brands": 0, "names": 0} and calls == []


async def test_a_failing_pipeline_never_crashes_the_flush(db_session, session_factory, monkeypatch):
    await brand_with(db_session)

    async def boom(*a, **k):
        raise RuntimeError("db down")

    monkeypatch.setattr(svc, "process_stream_hits", boom)
    worker = new_worker(session_factory)
    await worker.refresh_brands()
    worker.on_sightings([t.CertSighting(("acmefinancial-pay.xyz",), NOW_MS(), None, "LE", "a" * 64, False)], LOG)
    assert (await worker.flush()) == {"brands": 0, "names": 0}


# ── health ──

async def test_health_is_reported_and_only_then_shown(db_session, session_factory):
    assert "ct_stream" not in {h["source"] for h in await brand_sources.list_health(db_session)}
    worker = new_worker(session_factory)
    f = w.LogFollower(LOG, httpx.AsyncClient())
    f.last_ok = time.monotonic()
    f.cursor.lag_seconds = 4.0
    worker.followers[LOG.id] = f
    await worker.report_health()
    row = next(h for h in await brand_sources.list_health(db_session) if h["source"] == "ct_stream")
    assert row["status"] == "healthy" and row["last_latency_ms"] == 4000 and row["label"] == "Live certificate stream"


async def test_unreachable_logs_make_the_stream_degraded_with_a_reason(db_session, session_factory):
    worker = new_worker(session_factory)
    good, bad = w.LogFollower(LOG, httpx.AsyncClient()), w.LogFollower(ll.TileLog("b", "custom", "https://b.example/", None, None), httpx.AsyncClient())
    good.last_ok = time.monotonic()
    worker.followers = {"a": good, "b": bad}
    worker.errors = {"b": "FetchError: HTTP 503"}
    await worker.report_health()
    row = next(h for h in await brand_sources.list_health(db_session) if h["source"] == "ct_stream")
    assert row["status"] == "degraded" and "1 of 2 logs unreachable" in row["last_error"]


async def test_no_logs_is_reported_as_a_problem(db_session, session_factory):
    worker = new_worker(session_factory)
    await worker.report_health()
    row = next(h for h in await brand_sources.list_health(db_session) if h["source"] == "ct_stream")
    assert row["status"] == "degraded" and row["last_error"] == "no logs configured"


# ── end to end ──

async def test_the_worker_follows_a_log_and_creates_a_candidate_end_to_end(db_session, session_factory, monkeypatch):
    _, profile = await brand_with(db_session)
    fake_network(monkeypatch, {"acmefinancial-secure.xyz"})
    monkeypatch.setattr(w, "IDLE_POLL", 0.05)
    monkeypatch.setattr(w.settings, "ct_stream_flush_seconds", 1)
    ts = NOW_MS()
    state = {"size": 256 * 5}
    hit_tile = tile([([f"acmefinancial-secure.xyz", "www.acmefinancial-secure.xyz"] if i == 7 else [f"filler{i}.example.net"], ts + i, i % 2 == 0) for i in range(256)])

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path[len("/2026h2/"):]
        if path == "checkpoint":
            return httpx.Response(200, content=checkpoint(state["size"]))
        if path == "tile/data/" + t.tile_path(5):
            return httpx.Response(200, content=hit_tile)
        return httpx.Response(404)

    async def list_fetcher():
        return None

    worker = w.Worker(session_factory=session_factory, client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
                      families=["custom"], extra_logs=[BASE], log_list_fetcher=list_fetcher)
    task = asyncio.create_task(worker.run(seconds=6))
    await asyncio.sleep(0.6)
    state["size"] = 256 * 6                                       # the log grows by one complete tile, the one holding the lead
    await task
    rows = (await db_session.execute(select(BrandCandidate).where(BrandCandidate.profile_id == profile.id))).scalars().all()
    assert [r.candidate_domain for r in rows] == ["acmefinancial-secure.xyz"]
    assert "ct_stream" in rows[0].sources and rows[0].enrichment["ct_hit"] is True
    cursor = (await db_session.execute(select(CtStreamCursor))).scalars().one()
    assert cursor.next_index == 256 * 6 and cursor.names_matched >= 1
    assert "ct_stream" in {h["source"] for h in await brand_sources.list_health(db_session)}
