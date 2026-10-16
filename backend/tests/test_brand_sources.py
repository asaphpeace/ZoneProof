"""
Tests for step 0.3 — certificate source hardening: bounded retries with
backoff, Retry-After handling, per-source health, the circuit breaker, and how
an unavailable source surfaces through the scan and the /sources endpoint.
No real network: crt.sh is simulated with httpx.MockTransport.
"""
import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.services import brand_guard_service as svc
from app.services import brand_sources as bs
from tests.factories import make_domain

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
SINCE = NOW - timedelta(days=30)


def _entry(names: str, when: datetime = NOW - timedelta(days=1)) -> dict:
    return {"name_value": names, "entry_timestamp": when.isoformat()}


def _source(handler) -> bs.CrtShSource:
    return bs.CrtShSource(client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)))


@pytest.fixture(autouse=True)
def _no_real_politeness_waits(monkeypatch):
    """The shared crt.sh limiter spaces real requests a second apart; these tests simulate many retries."""
    from app.config import settings
    from app.services.brand_throttle import crt_throttle
    monkeypatch.setattr(settings, "brand_guard_crt_min_interval_seconds", 0.0)
    crt_throttle.reset()
    yield
    crt_throttle.reset()


@pytest.fixture
def sleeps(monkeypatch):
    delays: list[float] = []

    async def fake_sleep(d):
        delays.append(d)

    monkeypatch.setattr(bs, "_sleep", fake_sleep)
    return delays


# ── retry / backoff (pure, no DB) ────────────────────────────────────────────

async def test_transient_failures_retry_with_growing_backoff_then_succeed(sleeps):
    calls = []

    def handler(req):
        calls.append(req)
        if len(calls) < 3:
            return httpx.Response(502)
        return httpx.Response(200, json=[_entry("secure-acmefinancial.com\n*.secure-acmefinancial.com")])

    found = await _source(handler).fetch(["acmefinancial"], SINCE)
    assert list(found) == ["secure-acmefinancial.com"]
    assert len(calls) == 3 and len(sleeps) == 2
    assert sleeps[1] > sleeps[0], "backoff must grow between attempts"


async def test_retry_after_is_honoured_and_capped(sleeps):
    seq = iter([httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(200, json=[])])
    await _source(lambda req: next(seq)).fetch(["acmefinancial"], SINCE)
    assert sleeps == [7.0]

    sleeps.clear()
    seq = iter([httpx.Response(429, headers={"Retry-After": "999"}), httpx.Response(200, json=[])])
    await _source(lambda req: next(seq)).fetch(["acmefinancial"], SINCE)
    assert sleeps == [bs.RETRY_AFTER_CAP_SECONDS]


@pytest.mark.parametrize("status", [400, 401, 403])
async def test_client_errors_are_not_retried(sleeps, status):
    calls = []

    def handler(req):
        calls.append(req)
        return httpx.Response(status)

    with pytest.raises(bs.SourceError) as exc:
        await _source(handler).fetch(["acmefinancial"], SINCE)
    assert exc.value.transient is False and exc.value.reason == f"HTTP {status}"
    assert len(calls) == 1 and sleeps == []


@pytest.mark.parametrize("status", [404, 408, 425, 500, 502, 520])
async def test_flaky_upstream_statuses_are_retried(sleeps, status):
    """crt.sh has been observed returning 404 and 502 for the same valid query."""
    seq = iter([httpx.Response(status), httpx.Response(200, json=[])])
    assert await _source(lambda req: next(seq)).fetch(["acmefinancial"], SINCE) == {}
    assert len(sleeps) == 1


async def test_retries_are_bounded_and_reason_is_customer_safe(sleeps):
    calls = []

    def handler(req):
        calls.append(req)
        return httpx.Response(503, text="<html>secret internal upstream detail https://crt.sh/?q=x</html>")

    with pytest.raises(bs.SourceError) as exc:
        await _source(handler).fetch(["acmefinancial"], SINCE)
    assert len(calls) == bs.MAX_ATTEMPTS
    assert exc.value.reason == "HTTP 503"
    assert "secret" not in str(exc.value) and "crt.sh" not in str(exc.value)


async def test_unreadable_200_body_is_treated_as_transient(sleeps):
    calls = []

    def handler(req):
        calls.append(req)
        return httpx.Response(200, text="<html>overloaded</html>")

    with pytest.raises(bs.SourceError) as exc:
        await _source(handler).fetch(["acmefinancial"], SINCE)
    assert exc.value.reason == "unreadable response" and len(calls) == bs.MAX_ATTEMPTS


async def test_timeouts_and_connection_errors_are_retried(sleeps):
    calls = []

    def handler(req):
        calls.append(req)
        if len(calls) == 1:
            raise httpx.ReadTimeout("slow", request=req)
        if len(calls) == 2:
            raise httpx.ConnectError("refused", request=req)
        return httpx.Response(200, json=[])

    assert await _source(handler).fetch(["acmefinancial"], SINCE) == {}
    assert len(calls) == 3


async def test_query_percent_wildcard_reaches_the_wire_as_25(sleeps):
    seen = []

    def handler(req):
        seen.append(str(req.url))
        return httpx.Response(200, json=[])

    await _source(handler).fetch(["acmefinancial"], SINCE)
    assert "q=%25acmefinancial%25" in seen[0]


async def test_short_tokens_skipped_and_old_certs_ignored(sleeps):
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(200, json=[
            _entry("fresh-acmefinancial.com", NOW - timedelta(days=2)),
            _entry("ancient-acmefinancial.com", NOW - timedelta(days=400)),
        ])

    found = await _source(handler).fetch(["abc", "acmefinancial"], SINCE)
    assert len(seen) == 1, "3-letter token must not be searched"
    assert list(found) == ["fresh-acmefinancial.com"]


# ── health + circuit breaker (DB) ────────────────────────────────────────────

class FakeSource:
    label = "Fake CT feed"

    def __init__(self, name="crt_sh", result=None, error=None, hang=False):
        self.name, self.result, self.error, self.hang, self.calls = name, result or {}, error, hang, 0

    async def fetch(self, tokens, since):
        self.calls += 1
        if self.hang:
            await asyncio.sleep(5)
        if self.error:
            raise self.error
        return self.result


async def _fetch(db, since=SINCE):
    return await bs.fetch_ct_candidates(db, ["acmefinancial"], since)


async def test_health_unknown_until_first_call_then_healthy(db_session, monkeypatch):
    src = FakeSource(result={"x-acmefinancial.com": {"issued_at": NOW.isoformat()}})
    monkeypatch.setattr(bs, "SOURCES", [src])
    assert (await bs.list_health(db_session))[0]["status"] == "unknown"

    assert await _fetch(db_session) == src.result
    h = (await bs.list_health(db_session))[0]
    assert h["status"] == "healthy" and h["consecutive_failures"] == 0
    assert h["last_success_at"] is not None and h["last_latency_ms"] is not None


async def test_failures_escalate_degraded_then_down_and_open_the_breaker(db_session, monkeypatch):
    clock = {"now": NOW}
    monkeypatch.setattr(bs, "_now", lambda: clock["now"])
    src = FakeSource(error=bs.SourceError("HTTP 502", transient=True))
    monkeypatch.setattr(bs, "SOURCES", [src])

    with pytest.raises(bs.SourceUnavailable) as e1:
        await _fetch(db_session)
    assert "HTTP 502" in str(e1.value)
    assert (await bs.list_health(db_session))[0]["status"] == "degraded"

    for _ in range(2):
        with pytest.raises(bs.SourceUnavailable):
            await _fetch(db_session)
    h = (await bs.list_health(db_session))[0]
    assert h["status"] == "down" and h["consecutive_failures"] == 3 and h["retry_after"] is not None
    assert h["last_error"] == "HTTP 502"

    calls_before = src.calls
    with pytest.raises(bs.SourceUnavailable) as open_err:
        await _fetch(db_session)
    assert src.calls == calls_before, "an open breaker must not call the source"
    assert "temporarily unavailable" in str(open_err.value) and "about 10 min" in str(open_err.value)
    assert "UTC" not in str(open_err.value), "no server-timezone clock times in customer messages"


async def test_breaker_allows_a_trial_after_cooldown_and_success_closes_it(db_session, monkeypatch):
    clock = {"now": NOW}
    monkeypatch.setattr(bs, "_now", lambda: clock["now"])
    src = FakeSource(error=bs.SourceError("HTTP 502", transient=True))
    monkeypatch.setattr(bs, "SOURCES", [src])
    for _ in range(3):
        with pytest.raises(bs.SourceUnavailable):
            await _fetch(db_session)

    clock["now"] = NOW + bs.BREAKER_COOLDOWN + timedelta(seconds=1)
    src.error, src.result = None, {"y-acmefinancial.com": {"issued_at": clock["now"].isoformat()}}
    before = src.calls
    assert await _fetch(db_session) == src.result
    assert src.calls == before + 1
    h = (await bs.list_health(db_session))[0]
    assert h["status"] == "healthy" and h["consecutive_failures"] == 0 and h["last_error"] is None and h["retry_after"] is None


async def test_failed_trial_reopens_the_breaker(db_session, monkeypatch):
    clock = {"now": NOW}
    monkeypatch.setattr(bs, "_now", lambda: clock["now"])
    src = FakeSource(error=bs.SourceError("HTTP 503", transient=True))
    monkeypatch.setattr(bs, "SOURCES", [src])
    for _ in range(3):
        with pytest.raises(bs.SourceUnavailable):
            await _fetch(db_session)

    clock["now"] = NOW + bs.BREAKER_COOLDOWN + timedelta(seconds=1)
    with pytest.raises(bs.SourceUnavailable):
        await _fetch(db_session)            # the trial call fails...
    calls = src.calls
    with pytest.raises(bs.SourceUnavailable):
        await _fetch(db_session)            # ...so the circuit is open again
    assert src.calls == calls


async def test_one_source_down_does_not_block_another(db_session, monkeypatch):
    bad = FakeSource(name="bad", error=bs.SourceError("HTTP 502", transient=True))
    good = FakeSource(name="good", result={"z-acmefinancial.com": {"issued_at": NOW.isoformat()}})
    monkeypatch.setattr(bs, "SOURCES", [bad, good])

    assert await _fetch(db_session) == good.result     # partial success is not an error
    by_name = {h["source"]: h for h in await bs.list_health(db_session)}
    assert by_name["bad"]["status"] == "degraded" and by_name["good"]["status"] == "healthy"


async def test_a_hanging_source_is_cut_off_and_recorded(db_session, monkeypatch):
    monkeypatch.setattr(bs, "TOTAL_BUDGET_SECONDS", 0.05)
    monkeypatch.setattr(bs, "SOURCES", [FakeSource(hang=True)])
    with pytest.raises(bs.SourceUnavailable) as e:
        await _fetch(db_session)
    assert "timed out" in str(e.value)
    assert (await bs.list_health(db_session))[0]["last_error"] == "timed out"


# ── through the scan and the API ─────────────────────────────────────────────

class _Borrowed:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *exc):
        return False


async def test_scan_survives_a_dead_certificate_source_and_reports_it(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    tenant.plan = "pro"
    domain = await make_domain(db_session, tenant, name="acmefinancial.co.za")
    domain.ownership_verified = True
    await db_session.commit()
    profile_id = (await client.post("/brand-guard/profiles", json={"domain_id": str(domain.id), "brand_name": "Acme Financial"})).json()["id"]

    async def fake_dns(d):
        return {"has_a": True, "has_mx": True} if d == "acmefinancia1.co.za" else {"has_a": False, "has_mx": False}

    async def fake_reg(c, d):
        return NOW - timedelta(days=2)

    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_registration_date", fake_reg)
    monkeypatch.setattr(svc, "_session_factory", lambda: _Borrowed(db_session))
    monkeypatch.setattr(bs, "SOURCES", [FakeSource(error=bs.SourceError("HTTP 502", transient=True))])

    # before any call the feed is "unknown"
    assert (await client.get("/brand-guard/sources")).json()[0]["status"] == "unknown"

    resp = await client.post(f"/brand-guard/profiles/{profile_id}/scan")
    await svc.wait_for_run(uuid.UUID(resp.json()["id"]))
    run = (await client.get(f"/brand-guard/scan-runs/{resp.json()['id']}")).json()

    assert run["status"] == "succeeded", "a dead CT feed must not fail the scan"
    assert run["result"]["new_candidates"] == 1, "permutation results still land"
    assert any("lookup failed (HTTP 502)" in e and "retry automatically" in e for e in run["result"]["errors"])
    assert not any("temporarily unavailable: " in e for e in run["result"]["errors"]), "message must not repeat itself"

    health = (await client.get("/brand-guard/sources")).json()[0]
    assert health["status"] == "degraded" and health["last_error"] == "HTTP 502" and health["consecutive_failures"] == 1

    profile = (await client.get("/brand-guard/profiles")).json()[0]
    assert profile["last_ct_poll_at"] is None, "failed poll must not advance the CT high-water mark"
