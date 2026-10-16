"""
Step 0.6 — scan cost and capacity guard: process-wide politeness limits, the shared registration cache
(and the "already on record" shortcut), per-plan budgets and quotas, execution slots and backpressure.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import func, select

from app.config import settings
from app.models import BrandProfile, BrandRegistrationCache, BrandScanRun
from app.models.user import Tenant
from app.services import brand_guard_service as svc
from app.services import brand_sources as bs
from app.services import brand_throttle as th
from app.services import plan_limits
from tests.factories import make_domain, make_tenant, make_user

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _reset_throttles():
    for t in (th.dns_throttle, th.rdap_throttle, th.crt_throttle):
        t.reset()
    svc._SLOTS.update(sem=None, size=None)
    yield
    for t in (th.dns_throttle, th.rdap_throttle, th.crt_throttle):
        t.reset()
    svc._SLOTS.update(sem=None, size=None)


class FakeTime:
    """A clock and a sleep that agree: sleeping advances the clock, nothing really waits."""
    def __init__(self):
        self.now = 1000.0
        self.sleeps: list[float] = []

    def clock(self):
        return self.now

    async def sleep(self, seconds):
        self.sleeps.append(round(seconds, 3))
        self.now += seconds

    def install(self, monkeypatch):
        monkeypatch.setattr(th, "_clock", self.clock)
        monkeypatch.setattr(th, "_sleep", self.sleep)


# ── throttle ─────────────────────────────────────────────────────────────────

async def test_concurrency_is_capped_across_all_callers():
    t = th.Throttle("t", lambda: 3)

    async def work():
        async with t.slot():
            await asyncio.sleep(0.01)

    await asyncio.gather(*(work() for _ in range(12)))
    assert t.max_in_flight == 3 and t.calls == 12 and t.in_flight == 0


async def test_min_interval_spaces_call_starts(monkeypatch):
    clock = FakeTime()
    clock.install(monkeypatch)
    t = th.Throttle("t", lambda: 5, lambda: 1.0)
    starts = []

    async def work():
        async with t.slot():
            starts.append(clock.now)

    await asyncio.gather(*(work() for _ in range(4)))
    gaps = [round(b - a, 3) for a, b in zip(starts, starts[1:])]
    assert gaps == [1.0, 1.0, 1.0], "even concurrent callers start a second apart"
    assert clock.sleeps == [1.0, 1.0, 1.0] and t.max_in_flight <= 5


async def test_no_spacing_means_no_waiting(monkeypatch):
    clock = FakeTime()
    clock.install(monkeypatch)
    t = th.Throttle("t", lambda: 5)
    await asyncio.gather(*(asyncio.sleep(0) for _ in range(1)))
    async with t.slot():
        pass
    assert clock.sleeps == []


async def test_a_failing_call_releases_its_slot():
    t = th.Throttle("t", lambda: 1)
    for _ in range(3):
        with pytest.raises(RuntimeError):
            async with t.slot():
                raise RuntimeError("upstream failed")
    async with t.slot():
        pass
    assert t.in_flight == 0 and t.calls == 4


async def test_limits_are_read_at_use_time():
    size = {"n": 1}
    t = th.Throttle("t", lambda: size["n"])

    async def burst():
        async def work():
            async with t.slot():
                await asyncio.sleep(0.005)
        await asyncio.gather(*(work() for _ in range(8)))

    await burst()
    assert t.max_in_flight == 1
    size["n"] = 4
    t.max_in_flight = 0
    await burst()
    assert t.max_in_flight == 4


async def test_dns_queries_go_through_the_shared_throttle_across_concurrent_scans(monkeypatch):
    monkeypatch.setattr(settings, "brand_guard_dns_concurrency", 2)
    seen = {"now": 0, "max": 0}

    async def resolve(name, rtype):
        seen["now"] += 1
        seen["max"] = max(seen["max"], seen["now"])
        await asyncio.sleep(0.005)
        seen["now"] -= 1
        import dns.resolver
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(svc.resolver, "resolve", resolve)
    await asyncio.gather(*(svc._dns_enrich(f"name{i}.example") for i in range(10)))
    assert seen["max"] <= 2, "ten concurrent lookups never exceed the process-wide limit"
    assert th.dns_throttle.calls == 10


# ── certificate source: shared per-token cache and spacing ───────────────────

def _crt(handler, **kw):
    return bs.CrtShSource(client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)))


def _entry(host):
    return {"name_value": host, "entry_timestamp": (T0 - timedelta(days=1)).isoformat()}


async def test_crt_results_are_cached_per_token_and_expire(monkeypatch):
    monkeypatch.setattr(settings, "brand_guard_crt_min_interval_seconds", 0.0)
    clock = {"t": T0}
    monkeypatch.setattr(bs, "_now", lambda: clock["t"])
    calls = []

    def handler(req):
        calls.append(str(req.url))
        return httpx.Response(200, json=[_entry("secure-acmefinancial.com")])

    src = _crt(handler)
    since = T0 - timedelta(days=30)
    first = await src.fetch(["acmefinancial"], since)
    second = await src.fetch(["acmefinancial"], since)
    assert first == second and len(calls) == 1, "a second brand or scan within the TTL costs no request"

    clock["t"] = T0 + bs.TOKEN_CACHE_TTL + timedelta(seconds=1)
    await src.fetch(["acmefinancial"], since)
    assert len(calls) == 2

    await src.fetch(["otherbrandname"], since)
    assert len(calls) == 3, "the cache is per token"


async def test_a_failed_crt_request_is_never_cached(monkeypatch):
    monkeypatch.setattr(settings, "brand_guard_crt_min_interval_seconds", 0.0)

    async def no_sleep(_):
        pass

    monkeypatch.setattr(bs, "_sleep", no_sleep)
    state = {"ok": False, "n": 0}

    def handler(req):
        state["n"] += 1
        return httpx.Response(200, json=[]) if state["ok"] else httpx.Response(502)

    src = _crt(handler)
    with pytest.raises(bs.SourceError):
        await src.fetch(["acmefinancial"], T0 - timedelta(days=30))
    failed_calls = state["n"]
    state["ok"] = True
    assert await src.fetch(["acmefinancial"], T0 - timedelta(days=30)) == {}
    assert state["n"] == failed_calls + 1, "the outage was not remembered as an empty answer"


async def test_crt_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(settings, "brand_guard_crt_min_interval_seconds", 0.0)
    monkeypatch.setattr(bs, "TOKEN_CACHE_MAX", 2)
    src = _crt(lambda req: httpx.Response(200, json=[]))
    for token in ("alphabrand", "betabrand", "gammabrand", "deltabrand"):
        await src.fetch([token], T0 - timedelta(days=30))
    assert len(src._cache) == 2


async def test_crt_requests_are_spaced_by_the_politeness_interval(monkeypatch):
    clock = FakeTime()
    clock.install(monkeypatch)
    monkeypatch.setattr(settings, "brand_guard_crt_min_interval_seconds", 1.0)
    src = _crt(lambda req: httpx.Response(200, json=[]))
    await src.fetch(["alphabrand", "betabrand", "gammabrand"], T0 - timedelta(days=30))
    assert clock.sleeps == [1.0, 1.0], "three requests, each a second after the last"


# ── plan limits ──────────────────────────────────────────────────────────────

def test_every_plan_declares_the_cost_limits():
    L = plan_limits.PLAN_LIMITS
    assert all({"brand_guard_scan_budget", "brand_guard_manual_scans_per_day", "brand_guard_concurrent_scans"} <= set(v) for v in L.values())
    assert L["free"]["brand_guard_scan_budget"] == 0 and L["free"]["brand_guard_manual_scans_per_day"] == 0
    assert L["starter"]["brand_guard_scan_budget"] < L["pro"]["brand_guard_scan_budget"]
    assert L["starter"]["brand_guard_manual_scans_per_day"] < L["pro"]["brand_guard_manual_scans_per_day"] < L["msp"]["brand_guard_manual_scans_per_day"]
    assert L["enterprise"]["brand_guard_manual_scans_per_day"] is None and L["enterprise"]["brand_guard_concurrent_scans"] is None


# ── pipeline: registration cache, budget ─────────────────────────────────────

class _Borrowed:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *exc):
        return False


@pytest.fixture
def world(monkeypatch, db_session):
    w = {"clock": T0, "dns": {}, "reg": {}, "reg_calls": [], "dns_calls": []}

    async def fake_dns(domain):
        w["dns_calls"].append(domain)
        return w["dns"].get(domain, {"has_a": False, "has_aaaa": False, "has_mx": False, "registered": False, "ns": []})

    async def fake_reg(client, domain):
        w["reg_calls"].append(domain)
        return w["reg"].get(domain)

    async def fake_ct(db, tokens, since):
        return {}

    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_registration_date", fake_reg)
    monkeypatch.setattr(svc, "fetch_ct_candidates", fake_ct)
    monkeypatch.setattr(svc, "_now", lambda: w["clock"])
    monkeypatch.setattr(svc, "_session_factory", lambda: _Borrowed(db_session))
    return w


LIVE = {"has_a": True, "has_aaaa": False, "has_mx": False, "registered": True, "ns": []}


async def _profile(client, tenant, db_session, domain_name, *, plan="pro", email_suffix=""):
    tenant.plan = plan
    domain = await make_domain(db_session, tenant, name=domain_name)
    domain.ownership_verified = True
    await db_session.commit()
    resp = await client.post("/brand-guard/profiles", json={"domain_id": str(domain.id), "brand_name": domain_name.split(".")[0]})
    assert resp.status_code == 201, resp.text
    return uuid.UUID(resp.json()["id"])


async def _scan(db, profile_id) -> BrandScanRun:
    profile = await db.get(BrandProfile, profile_id)
    tenant = await db.get(Tenant, profile.tenant_id)
    run, _ = await svc.start_scan_run(db, profile, triggered_by="manual")
    await svc._run_scan(db, run, profile, tenant)
    await db.refresh(run)
    return run


async def test_a_registration_found_for_one_tenant_serves_every_other_tenant(auth_client, db_session, world):
    client, tenant = auth_client
    world["dns"]["acmefinancial.com"] = LIVE
    world["reg"]["acmefinancial.com"] = T0 - timedelta(days=900)
    first = await _profile(client, tenant, db_session, "acmefinancial.co.za")
    await _scan(db_session, first)
    assert world["reg_calls"] == ["acmefinancial.com"]
    cached = await db_session.get(BrandRegistrationCache, "acmefinancial.com")
    assert cached.found is True and cached.registered_at == T0 - timedelta(days=900)

    other = await make_tenant(db_session, name="Other Co", plan="pro")
    await make_user(db_session, other, email="other-cost@test.com", password="pass123")
    dom = await make_domain(db_session, other, name="acmefinancial.net")
    dom.ownership_verified = True
    prof = BrandProfile(id=uuid.uuid4(), tenant_id=other.id, domain_id=dom.id, brand_name="acmefinancial")
    db_session.add(prof)
    await db_session.commit()

    world["reg_calls"].clear()
    run = await _scan(db_session, prof.id)
    assert "acmefinancial.com" not in world["reg_calls"], "another tenant's lookup was reused, not repeated"
    assert run.result["cost"]["rdap_cache_hits"] >= 1


async def test_a_candidate_whose_registration_is_on_record_is_never_looked_up_again(auth_client, db_session, world):
    client, tenant = auth_client
    world["dns"]["acmefinancial.com"] = LIVE
    world["reg"]["acmefinancial.com"] = T0 - timedelta(days=900)
    pid = await _profile(client, tenant, db_session, "acmefinancial.co.za")
    await _scan(db_session, pid)

    await db_session.execute(BrandRegistrationCache.__table__.delete())     # even with an empty cache...
    await db_session.commit()
    world["reg_calls"].clear()
    world["clock"] = T0 + timedelta(days=30)
    run = await _scan(db_session, pid)
    assert world["reg_calls"] == [], "...the date stored on the candidate is enough"
    assert run.result["cost"]["rdap_already_on_record"] == 1 and run.result["cost"]["rdap_lookups"] == 0


async def test_cache_entries_expire_and_misses_are_retried_sooner(auth_client, db_session, world):
    client, tenant = auth_client
    world["dns"]["acmefinancial.com"] = LIVE
    world["reg"]["acmefinancial.com"] = None                   # the registry returned nothing
    pid = await _profile(client, tenant, db_session, "acmefinancial.co.za")
    await _scan(db_session, pid)
    assert world["reg_calls"] == ["acmefinancial.com"]
    assert (await db_session.get(BrandRegistrationCache, "acmefinancial.com")).found is False

    world["clock"] = T0 + timedelta(hours=2)
    await _scan(db_session, pid)
    assert world["reg_calls"] == ["acmefinancial.com"], "a recent miss is not retried at once"

    world["clock"] = T0 + timedelta(hours=7)
    world["reg"]["acmefinancial.com"] = T0 - timedelta(days=5)
    await _scan(db_session, pid)
    assert world["reg_calls"] == ["acmefinancial.com"] * 2, "after the short miss TTL it is tried again"
    assert (await db_session.get(BrandRegistrationCache, "acmefinancial.com")).found is True


async def test_cache_ttl_boundaries(db_session, world):
    """A found date is trusted for 14 days; an empty answer for 6 hours."""
    await svc._store_registrations(db_session, {"found.example": T0 - timedelta(days=100), "missed.example": None})
    asked = {"found.example", "missed.example"}

    def at(delta):
        world["clock"] = T0 + delta
        return svc._cached_registrations(db_session, asked)

    got = await at(timedelta(hours=5))
    assert set(got) == asked and got["found.example"] == T0 - timedelta(days=100) and got["missed.example"] is None
    assert set(await at(timedelta(hours=7))) == {"found.example"}, "the miss expired, the found date did not"
    assert set(await at(timedelta(days=13))) == {"found.example"}
    assert await at(timedelta(days=15)) == {}, "after a fortnight even a found date is looked up again"
    assert await svc._cached_registrations(db_session, set()) == {}


async def test_scan_budget_trims_the_long_tail_and_reports_it(auth_client, db_session, world, monkeypatch):
    client, tenant = auth_client
    monkeypatch.setitem(plan_limits.PLAN_LIMITS["starter"], "brand_guard_scan_budget", 20)
    starter = await _profile(client, tenant, db_session, "acmefinancial.co.za", plan="starter")
    run = await _scan(db_session, starter)
    assert len(world["dns_calls"]) == 20
    b = run.result["budget"]
    assert b["limit"] == 20 and b["generated"] > 20 and b["trimmed"] == b["generated"] - 20
    assert run.result["cost"]["names_checked"] == 20


async def test_a_larger_budget_does_not_trim(auth_client, db_session, world):
    client, tenant = auth_client
    pid = await _profile(client, tenant, db_session, "acmefinancial.co.za", plan="pro")
    run = await _scan(db_session, pid)
    assert run.result["budget"]["trimmed"] == 0 and run.result["budget"]["generated"] == len(world["dns_calls"])


# ── quotas, concurrency, backpressure (API) ──────────────────────────────────

async def _add_run(db, tenant_id, profile_id, *, status="succeeded", by="manual", age=timedelta(0)):
    run = BrandScanRun(id=uuid.uuid4(), tenant_id=tenant_id, profile_id=profile_id, status=status, triggered_by=by,
                       created_at=datetime.now(timezone.utc) - age)
    db.add(run)
    await db.commit()
    return run


async def test_manual_scan_quota_is_enforced_per_tenant_per_day(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    monkeypatch.setitem(plan_limits.PLAN_LIMITS["starter"], "brand_guard_manual_scans_per_day", 2)
    monkeypatch.setattr(svc, "spawn_scan_run", lambda run_id: None)
    pid = await _profile(client, tenant, db_session, "acmefinancial.co.za", plan="starter")

    await _add_run(db_session, tenant.id, pid, age=timedelta(hours=1))
    await _add_run(db_session, tenant.id, pid, by="scheduled")                       # scheduled runs don't count
    await _add_run(db_session, tenant.id, pid, age=timedelta(hours=30))               # older than 24h doesn't count
    assert (await client.post(f"/brand-guard/profiles/{pid}/scan")).status_code == 202   # 1 of 2 used -> allowed
    await db_session.execute(BrandScanRun.__table__.update().where(BrandScanRun.status == "queued").values(status="succeeded"))
    await db_session.commit()

    blocked = await client.post(f"/brand-guard/profiles/{pid}/scan")
    assert blocked.status_code == 429
    d = blocked.json()["detail"]
    assert d["code"] == "scan_quota_reached" and d["limit"] == 2 and d["current_count"] == 2 and d["upgrade_required"] is True
    assert "Scheduled scans keep running" in d["message"]


async def test_an_active_run_is_returned_even_when_the_quota_is_spent(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    monkeypatch.setitem(plan_limits.PLAN_LIMITS["starter"], "brand_guard_manual_scans_per_day", 1)
    pid = await _profile(client, tenant, db_session, "acmefinancial.co.za", plan="starter")
    active = await _add_run(db_session, tenant.id, pid, status="running")
    resp = await client.post(f"/brand-guard/profiles/{pid}/scan")
    assert resp.status_code == 202 and resp.json()["id"] == str(active.id), "asking again costs nothing"


async def test_profile_reports_manual_scans_used_and_the_allowance(auth_client, db_session):
    client, tenant = auth_client
    pid = await _profile(client, tenant, db_session, "acmefinancial.co.za", plan="starter")
    await _add_run(db_session, tenant.id, pid)
    p = (await client.get("/brand-guard/profiles")).json()[0]
    assert p["scans_today"] == 1 and p["scan_quota"] == plan_limits.PLAN_LIMITS["starter"]["brand_guard_manual_scans_per_day"]


async def test_per_tenant_concurrency_cap(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    monkeypatch.setitem(plan_limits.PLAN_LIMITS["pro"], "brand_guard_concurrent_scans", 1)
    monkeypatch.setattr(svc, "spawn_scan_run", lambda run_id: None)
    one = await _profile(client, tenant, db_session, "acmefinancial.co.za", plan="pro")
    two = await _profile(client, tenant, db_session, "bravofinancial.co.za", plan="pro")

    first = await client.post(f"/brand-guard/profiles/{one}/scan")
    assert first.status_code == 202
    second = await client.post(f"/brand-guard/profiles/{two}/scan")
    assert second.status_code == 429 and second.json()["detail"]["code"] == "scan_concurrency_limit"

    await db_session.execute(BrandScanRun.__table__.update().values(status="succeeded"))
    await db_session.commit()
    assert (await client.post(f"/brand-guard/profiles/{two}/scan")).status_code == 202


async def test_global_backpressure_refuses_new_scans_but_not_repeats(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    monkeypatch.setattr(settings, "brand_guard_max_queued_scans", 1)
    monkeypatch.setattr(svc, "spawn_scan_run", lambda run_id: None)
    one = await _profile(client, tenant, db_session, "acmefinancial.co.za", plan="enterprise")
    two = await _profile(client, tenant, db_session, "bravofinancial.co.za", plan="enterprise")

    assert (await client.post(f"/brand-guard/profiles/{one}/scan")).status_code == 202
    busy = await client.post(f"/brand-guard/profiles/{two}/scan")
    assert busy.status_code == 503 and busy.headers["Retry-After"] == "60"
    assert busy.json()["detail"]["code"] == "scanner_busy" and busy.json()["detail"]["retry_after_seconds"] == 60
    assert (await client.post(f"/brand-guard/profiles/{one}/scan")).status_code == 202, "re-asking for the run already in the queue is not refused"


# ── execution slots ──────────────────────────────────────────────────────────

async def test_only_the_configured_number_of_scans_execute_at_once(monkeypatch):
    monkeypatch.setattr(settings, "brand_guard_max_concurrent_scans", 2)
    state = {"now": 0, "max": 0}

    async def scan():
        async with svc.scan_slot():
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
            await asyncio.sleep(0.01)
            state["now"] -= 1

    await asyncio.gather(*(scan() for _ in range(8)))
    assert state["max"] == 2


async def test_a_run_waits_as_queued_until_a_slot_frees_and_holds_no_session_meanwhile(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    monkeypatch.setattr(settings, "brand_guard_max_concurrent_scans", 1)
    monkeypatch.setattr(svc, "_session_factory", lambda: _Borrowed(db_session))

    async def quick(*a, **k):
        return {"new_candidates": 0, "alerts": 0, "evaluated": 0, "ct_enabled": False, "errors": []}

    monkeypatch.setattr(svc, "scan_profile", quick)
    pid = await _profile(client, tenant, db_session, "acmefinancial.co.za", plan="pro")
    profile = await db_session.get(BrandProfile, pid)
    run, _ = await svc.start_scan_run(db_session, profile, triggered_by="manual")

    sem = svc.scan_slot()
    await sem.acquire()                                  # every slot is busy
    task = svc.spawn_scan_run(run.id)
    await asyncio.sleep(0.05)
    assert not task.done()
    assert (await db_session.execute(select(BrandScanRun.status).where(BrandScanRun.id == run.id))).scalar_one() == "queued"

    sem.release()
    await asyncio.wait_for(task, timeout=5)
    assert (await db_session.execute(select(BrandScanRun.status).where(BrandScanRun.id == run.id))).scalar_one() == "succeeded"
