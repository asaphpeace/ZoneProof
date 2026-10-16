"""Plan 2.6b — newly registered domains as a discovery source. Hermetic: no network, injected clients."""
import base64
import io
import zipfile
from datetime import date, datetime, timezone

import httpx
import pytest

from app.services import brand_nrd, brand_sources as sources

REAL_REFRESH = brand_nrd.refresh
DAY = date(2026, 10, 2)
NOW = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)


def make_zip(names, inner="domain-names.txt"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(inner, "\n".join(names))
    return buf.getvalue()


def feed_with(days):
    f = brand_nrd.NrdFeed()
    f.days = {d: frozenset(n) for d, n in days.items()}
    return f


def test_url_is_base64_of_dated_zip_name():
    url = brand_nrd.url_for(date(2026, 10, 1))
    assert url.endswith("/MjAyNi0xMC0wMS56aXA=/nrd")
    assert base64.b64decode("MjAyNi0xMC0wMS56aXA=").decode() == "2026-10-01.zip"


def test_parse_zip_normalises_and_drops_junk():
    names = brand_nrd.parse_zip(make_zip(["Example.COM", "a.b.", "nodot", "has space.com", "", "x" * 300 + ".com"]))
    assert names == frozenset({"example.com", "a.b"})


@pytest.mark.parametrize("blob", [b"not a zip", make_zip([]), make_zip([""]), b""])
def test_parse_zip_rejects_bad_input(blob):
    with pytest.raises(ValueError):
        brand_nrd.parse_zip(blob)


def test_parse_zip_caps_decompressed_size(monkeypatch):
    monkeypatch.setattr(brand_nrd, "_MAX_TEXT_BYTES", 50)
    with pytest.raises(ValueError):
        brand_nrd.parse_zip(make_zip(["abcdefghij.com"] * 20))


def test_parse_zip_caps_compressed_size(monkeypatch):
    monkeypatch.setattr(brand_nrd, "_MAX_ZIP_BYTES", 10)
    with pytest.raises(ValueError):
        brand_nrd.parse_zip(make_zip(["abc.com"]))


def test_candidates_match_brand_exclude_official_and_report_day():
    feed = feed_with({date(2026, 10, 1): {"acme-refunds.com", "unrelated.com", "acme.com"}, date(2026, 9, 30): {"acmepay.net"}})
    out = brand_nrd.candidates(["acme"], {"acme.com"}, feed)
    assert "unrelated.com" not in out and "acme.com" not in out
    assert out["acme-refunds.com"] == {"listed_on": "2026-10-01"}
    assert out["acmepay.net"] == {"listed_on": "2026-09-30"}


def test_candidates_limit_keeps_newest_first():
    feed = feed_with({date(2026, 10, 1): {f"acme-new{i}.com" for i in range(5)}, date(2026, 9, 30): {"acme-old.com"}})
    out = brand_nrd.candidates(["acme"], set(), feed, limit=3)
    assert len(out) == 3 and all(v["listed_on"] == "2026-10-01" for v in out.values())


def test_candidates_empty_when_nothing_loaded():
    assert brand_nrd.candidates(["acme"], set(), brand_nrd.NrdFeed()) == {}


class FakeClient:
    def __init__(self, handler):
        self.handler = handler

    async def __aenter__(self):
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))

    async def __aexit__(self, *a):
        return None


@pytest.mark.asyncio
async def test_refresh_downloads_missing_days_and_records_health(db_session):
    seen = []

    def handler(req):
        seen.append(str(req.url))
        return httpx.Response(200, content=make_zip(["acme-x.com"]))

    feed = brand_nrd.NrdFeed()
    await REAL_REFRESH(db_session, client_factory=lambda: FakeClient(handler), now=NOW, today=DAY, feed=feed)
    assert sorted(feed.days) == [date(2026, 9, 29), date(2026, 9, 30), date(2026, 10, 1)]
    assert len(seen) == 3
    row = await sources._get_row(db_session, "nrd_whoisds")
    assert row.status == "healthy"
    # already loaded days are not downloaded again
    await REAL_REFRESH(db_session, client_factory=lambda: FakeClient(handler), now=NOW, today=DAY, feed=feed)
    assert len(seen) == 3


@pytest.mark.asyncio
async def test_refresh_drops_days_older_than_window(db_session):
    feed = feed_with({date(2026, 9, 1): {"old.com"}})
    await REAL_REFRESH(db_session, client_factory=lambda: FakeClient(lambda r: httpx.Response(200, content=make_zip(["a.com"]))), now=NOW, today=DAY, feed=feed)
    assert date(2026, 9, 1) not in feed.days


@pytest.mark.asyncio
async def test_unpublished_newest_day_is_not_a_failure(db_session):
    def handler(req):
        return httpx.Response(404) if base64.b64encode(b"2026-10-01.zip").decode() in str(req.url) else httpx.Response(200, content=make_zip(["a.com"]))

    feed = brand_nrd.NrdFeed()
    await REAL_REFRESH(db_session, client_factory=lambda: FakeClient(handler), now=NOW, today=DAY, feed=feed)
    assert date(2026, 10, 1) not in feed.days and len(feed.days) == 2
    row = await sources._get_row(db_session, "nrd_whoisds")
    assert row.status == "healthy" and row.last_failure_at is None       # never even a blip


@pytest.mark.asyncio
async def test_failure_is_recorded_and_retried_only_after_wait(db_session):
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(500)

    feed = feed_with({date(2026, 9, 29): {"a.com"}, date(2026, 9, 30): {"b.com"}})      # one day missing: one failure, breaker stays shut
    await REAL_REFRESH(db_session, client_factory=lambda: FakeClient(handler), now=NOW, today=DAY, feed=feed)
    assert date(2026, 10, 1) not in feed.days
    row = await sources._get_row(db_session, "nrd_whoisds")
    assert row.consecutive_failures == 1 and row.last_error == "HTTP 500"
    before = len(calls)
    await REAL_REFRESH(db_session, client_factory=lambda: FakeClient(handler), now=NOW, today=DAY, feed=feed)
    assert len(calls) == before          # inside the retry wait: nothing re-requested


@pytest.mark.asyncio
async def test_garbage_download_never_raises(db_session):
    feed = brand_nrd.NrdFeed()
    await REAL_REFRESH(db_session, client_factory=lambda: FakeClient(lambda r: httpx.Response(200, content=b"<html>")), now=NOW, today=DAY, feed=feed)
    assert feed.days == {}


def test_registered_as_health_source():
    assert brand_nrd.FEED in sources.EXTRA_HEALTH_SOURCES


# ── pipeline: a newly registered brand look-alike becomes a candidate with its own source ──

async def _scan_setup(db_session, monkeypatch, plan, nrd_names):
    import uuid
    from sqlalchemy import select
    from app.models import BrandCandidate, BrandProfile
    from app.services import brand_guard_service as svc
    from tests.factories import make_domain, make_tenant

    tenant = await make_tenant(db_session, name=f"Acme-{plan}", plan=plan)
    domain = await make_domain(db_session, tenant, name="acmefinancial.co.za")
    domain.ownership_verified = True
    profile = BrandProfile(id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, brand_name="Acme Financial", keywords=[], official_domains=[])
    db_session.add(profile)
    await db_session.commit()

    async def fake_dns(name):
        return {"has_a": name in nrd_names, "has_mx": False, "registered": name in nrd_names}

    async def fake_reg(client, name):
        return None

    async def fake_ct(db, tokens, since):
        return {}

    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_registration_date", fake_reg)
    monkeypatch.setattr(svc, "fetch_ct_candidates", fake_ct)
    monkeypatch.setattr(brand_nrd.FEED, "days", {date(2026, 10, 1): frozenset(nrd_names | {"unrelated-shop.com"})})
    await svc.scan_profile(db_session, profile, tenant, permutations=False)
    return (await db_session.execute(select(BrandCandidate).where(BrandCandidate.profile_id == profile.id))).scalars().all()


@pytest.mark.asyncio
async def test_scan_turns_new_registration_into_candidate(db_session, monkeypatch):
    rows = await _scan_setup(db_session, monkeypatch, "pro", {"acmefinancial-refunds.com"})
    assert [r.candidate_domain for r in rows] == ["acmefinancial-refunds.com"]
    assert "new_registration" in rows[0].sources
    assert rows[0].enrichment["nrd_listed_on"] == "2026-10-01"


@pytest.mark.asyncio
async def test_scan_without_certificate_monitoring_plan_ignores_nrd(db_session, monkeypatch):
    rows = await _scan_setup(db_session, monkeypatch, "free", {"acmefinancial-refunds.com"})
    assert rows == []


def test_matching_is_computed_once_per_day_and_dropped_with_the_day(monkeypatch):
    feed = feed_with({date(2026, 10, 1): {"acme-a.com"}})
    calls = []
    real = brand_nrd.matches_brand_fingerprint
    monkeypatch.setattr(brand_nrd, "matches_brand_fingerprint", lambda n, t: calls.append(n) or real(n, t))
    brand_nrd.candidates(["acme"], set(), feed)
    brand_nrd.candidates(["acme"], {"other.com"}, feed)        # same tokens, different official set: no re-matching
    assert calls == ["acme-a.com"]
    feed.days.clear()
    brand_nrd.candidates(["acme"], set(), feed)
    assert feed._hits == {}


@pytest.mark.asyncio
async def test_find_is_the_same_answer_off_the_loop():
    feed = feed_with({date(2026, 10, 1): {"acme-a.com", "zzz.com"}})
    assert await brand_nrd.find(["acme"], set(), feed) == brand_nrd.candidates(["acme"], set(), feed)
