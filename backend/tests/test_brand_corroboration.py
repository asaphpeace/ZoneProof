"""
Step 2.5 — corroboration and benign explainers: popularity (is the look-alike itself a well-known site?), parking services,
public abuse feeds (phishunt.io, URLhaus) with their refresh/failure handling, lookup rules, list badges, and the scan.

NOT claimed: weights are hand-set and abuse scoring cannot be measured offline. What WAS measured: only 2 of 488 suspected
phishing hosts sit on a top-100k domain, both multi-tenant platforms — which is why popularity never discounts a subdomain host.
DNS blocklists and Web Risk / VirusTotal are deliberately absent (licence / paid-key decision gate).
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select

from app.models import BrandCandidate, BrandProfile, BrandSourceHealth, CandidateEvidence
from app.services import brand_corroboration as corr
from app.services.brand_reasoning import points_for
from app.services import brand_feeds as feeds
from app.services import brand_guard_service as svc
from app.services import brand_popularity as pop
from app.services import brand_sources as sources
from app.services.brand_scoring_service import Signal, assess_candidate
from tests.factories import make_domain, make_tenant

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
# The suite's autouse fixture replaces brand_feeds.refresh with a no-op (no test may reach the network by accident);
# the refresh tests below need the real function, captured at import time before any fixture runs.
REAL_REFRESH = feeds.refresh


# ── popularity ───────────────────────────────────────────────────────────────

def test_popularity_list_is_present_and_ranks_known_sites():
    assert pop.sample_size() == 100_000
    assert pop.rank_of("google.com") == 1 and pop.rank_of("GOOGLE.com.") == 1
    assert pop.rank_of("surely-nobody-registered-this-9431.com") is None and pop.rank_of("") is None


def _ranked(lo, hi):
    return next(d for d, r in pop._ranks().items() if lo < r <= hi)


def test_a_registered_lookalike_that_is_a_top_site_is_discounted_more_the_more_popular_it_is():
    top, lower = _ranked(0, 10_000), _ranked(20_000, 100_000)
    a, b = corr.popularity_finding(top, top), corr.popularity_finding(lower, lower)
    assert a["weight"] == corr.POPULAR_TOP_WEIGHT and b["weight"] == corr.POPULAR_WEIGHT < 0 and abs(a["weight"]) > abs(b["weight"])
    assert f"#{pop.rank_of(top):,}" in a["summary"]
    assert corr.popularity_finding("surely-nobody-registered-this-9431.com", "surely-nobody-registered-this-9431.com") is None


def test_a_subdomain_host_or_a_name_on_a_hosting_platform_is_never_discounted_for_popularity():
    """Measured: both of the 2 phishing hosts that sit on a top-100k domain were multi-tenant platforms (hashnode.dev,
    a CDN). Abuse of popular platforms lives in subdomains, so the discount must never apply there."""
    apex = _ranked(0, 5_000)
    assert corr.popularity_finding(f"instagram-login.{apex}", apex) is None
    assert corr.popularity_finding(apex, apex, on_platform=True) is None
    assert corr.popularity_finding(apex, apex) is not None


def test_popularity_degrades_gracefully_when_the_list_is_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(pop, "_DATA", tmp_path / "absent.gz")
    pop._ranks.cache_clear()
    try:
        assert pop.rank_of("google.com") is None and pop.sample_size() == 0 and corr.popularity_finding("google.com", "google.com") is None
    finally:
        monkeypatch.undo()
        pop._ranks.cache_clear()


# ── parking ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("ns,service", [
    (["ns1.sedoparking.com", "ns2.sedoparking.com"], "Sedo"), (["ns1.dns-parking.com."], "Hostinger parking"),
    (["x.bodis.com"], "Bodis"), (["ns.above.com"], "Above.com"),
])
def test_parking_nameservers_are_recognised(ns, service):
    f = corr.parking_finding(ns)
    assert f["signal"] == "parked" and f["weight"] == points_for("parked", corr.PARKED_WEIGHT) < 0 and f["data"]["service"] == service and "stays on watch" in f["summary"]


@pytest.mark.parametrize("ns", [None, [], ["ns1.example.net"], ["ns1.notsedoparking.com"], ["sedoparking.com.evil.net"]])
def test_other_nameservers_are_not_parking(ns):
    assert corr.parking_finding(ns) is None


# ── feed evidence and badges ─────────────────────────────────────────────────

def test_feed_listings_are_corroboration_with_honest_wording():
    ph = corr.feed_findings([{"feed": "phishunt", "first_seen": "2026-09-30T20:01:39+00:00", "same_site": False, "detail": {"other_flags": 0}}])[0]
    assert ph["weight"] == corr.FEED_PHISHUNT_WEIGHT and "automated detection, not human-verified" in ph["summary"] and "2026-09-30" in ph["summary"]
    strong = corr.feed_findings([{"feed": "phishunt", "same_site": False, "detail": {"other_flags": 2}}])[0]
    assert strong["weight"] == corr.FEED_PHISHUNT_CORROBORATED_WEIGHT and "2 other service(s)" in strong["summary"]
    uh = corr.feed_findings([{"feed": "urlhaus", "same_site": True, "detail": {}}])[0]
    assert uh["weight"] == corr.FEED_URLHAUS_WEIGHT and "malware" in uh["summary"] and "same registered domain" in uh["summary"]


def test_feed_evidence_is_capped_when_several_feeds_agree():
    both = corr.feed_findings([{"feed": "phishunt", "same_site": False, "detail": {"other_flags": 3}}, {"feed": "urlhaus", "same_site": False, "detail": {}}])
    assert sum(f["weight"] for f in both) == pytest.approx(corr.FEED_POSITIVE_CAP, abs=0.2)
    assert corr.feed_findings(None) == [] and corr.feed_findings([{"feed": "unknown"}]) == []


def test_badges_mirror_the_evidence_in_a_fixed_order_without_duplicates():
    sigs = [Signal(n, "abuse", 0, "", {}) for n in ("same_hosting_ip", "parked", "on_phishing_feed", "same_nameservers", "new_registration")]
    assert corr.badges_from_signals(sigs) == [{"kind": "blocklist", "label": "On a blocklist"}, {"kind": "parked", "label": "Parked"},
                                              {"kind": "yours", "label": "Your infrastructure"}]
    assert corr.badges_from_signals([]) == []


# ── feed parsing ─────────────────────────────────────────────────────────────

PHISHUNT = json.dumps([
    {"url": "https://allegro-login.evil.example/x", "domain": "allegro-login.evil.example", "first_seen": "2026-09-30T20:01:39+00:00",
     "malicious_google": True, "malicious_phishtank": True, "malicious_openphish": False},
    {"url": "http://203.0.113.9/panel", "domain": "203.0.113.9"},                      # a raw address cannot corroborate a domain
    {"url": "https://bank.evil.example/a"}, {"url": "https://bank.evil.example/b"}, {"url": "https://bank.evil.example/c"}, {"url": "https://bank.evil.example/d"},
    "junk", {"no": "url"},
])

URLHAUS = """################################
# abuse.ch URLhaus Database Dump
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-09-30 21:32:09","http://malware.evil.example/i","online","2026-09-30 21:32:09","malware_download","mirai","https://urlhaus.abuse.ch/url/1/","r"
"2","2026-09-30 21:31:19","http://119.116.32.12:56334/i","online","2026-09-30 21:31:19","malware_download","None","https://urlhaus.abuse.ch/url/2/","r"
"3","2026-09-29 10:00:00","http://old.evil.example/i","offline","2026-09-29 10:00:00","malware_download","None","https://urlhaus.abuse.ch/url/3/","r"
"""


def test_phishunt_is_parsed_skipping_addresses_and_bounding_entries_per_host():
    idx = feeds.PhishuntFeed("phishunt", "phishunt.io", "u").parse(PHISHUNT)
    assert set(idx) == {"allegro-login.evil.example", "bank.evil.example"}
    assert idx["allegro-login.evil.example"][0]["detail"] == {"other_flags": 2} and len(idx["bank.evil.example"]) == feeds._ENTRIES_PER_HOST


def test_urlhaus_is_parsed_keeping_only_online_domain_hosts():
    idx = feeds.UrlhausFeed("urlhaus", "abuse.ch URLhaus", "u").parse(URLHAUS)
    assert set(idx) == {"malware.evil.example"} and idx["malware.evil.example"][0]["first_seen"] == "2026-09-30 21:32:09"


def test_malformed_feeds_raise_value_errors_the_refresh_can_handle():
    with pytest.raises(ValueError):
        feeds.PhishuntFeed("p", "p", "u").parse('{"not": "a list"}')
    with pytest.raises(json.JSONDecodeError):
        feeds.PhishuntFeed("p", "p", "u").parse("<html>")


# ── lookup ───────────────────────────────────────────────────────────────────

def _loaded(*pairs):
    f = feeds.PhishuntFeed("phishunt", "phishunt.io", "u")
    f.load({h: [{"feed": "phishunt", "label": "phishunt.io", "first_seen": "2026-09-30", "detail": {"other_flags": 0}}] for h in pairs}, NOW)
    return f


def test_lookup_distinguishes_an_exact_host_from_another_host_on_the_same_registered_domain():
    f = _loaded("login.evil-bank.example", "pay.evil-bank.example")
    assert feeds.lookup("login.evil-bank.example", [f])[0]["same_site"] is False
    assert feeds.lookup("evil-bank.example", [f])[0]["same_site"] is True, "the apex itself is not listed, but a host on it is"
    assert feeds.lookup("www.evil-bank.example", [f])[0]["same_site"] is True
    assert feeds.lookup("other-site.example", [f]) == [] and feeds.lookup("evil-bank.example.attacker.net", [f]) == []


def test_a_listed_tenant_of_a_hosting_platform_does_not_implicate_the_platform_or_its_other_tenants():
    f = _loaded("xfinity-login.weebly.com")
    assert feeds.lookup("xfinity-login.weebly.com", [f])[0]["same_site"] is False
    assert feeds.lookup("weebly.com", [f]) == [] and feeds.lookup("someone-else.weebly.com", [f]) == []


# ── refresh ──────────────────────────────────────────────────────────────────

def _client_factory(handler):
    return lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)


def _fresh_feed(cls=feeds.PhishuntFeed, name="phishunt"):
    return cls(name, name, f"https://{name}.example/feed")


async def test_refresh_downloads_parses_and_records_health(db_session):
    feed = _fresh_feed()
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, content=PHISHUNT.encode())
    await REAL_REFRESH(db_session, client_factory=_client_factory(handler), now=NOW, feeds=[feed])
    assert "allegro-login.evil.example" in feed.index and feed.fetched_at == NOW and len(calls) == 1
    row = (await db_session.execute(select(BrandSourceHealth).where(BrandSourceHealth.source == "phishunt"))).scalar_one()
    assert row.status == "healthy" and row.consecutive_failures == 0


async def test_refresh_is_skipped_until_the_interval_has_passed(db_session):
    feed = _fresh_feed()
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, content=PHISHUNT.encode())
    make = _client_factory(handler)
    await REAL_REFRESH(db_session, client_factory=make, now=NOW, feeds=[feed])
    await REAL_REFRESH(db_session, client_factory=make, now=NOW + feeds.REFRESH_INTERVAL - timedelta(seconds=1), feeds=[feed])
    assert len(calls) == 1
    await REAL_REFRESH(db_session, client_factory=make, now=NOW + feeds.REFRESH_INTERVAL, feeds=[feed])
    assert len(calls) == 2


@pytest.mark.parametrize("response", [
    lambda r: httpx.Response(503), lambda r: httpx.Response(404), lambda r: httpx.Response(200, content=b"<html>not json</html>"),
    lambda r: httpx.Response(200, content=b'{"a": 1}'), lambda r: (_ for _ in ()).throw(httpx.ConnectError("down")),
])
async def test_a_failing_feed_never_raises_and_is_recorded_as_a_failure(db_session, response):
    feed = _fresh_feed()
    await REAL_REFRESH(db_session, client_factory=_client_factory(response), now=NOW, feeds=[feed])      # must not raise
    assert feed.index == {}
    row = (await db_session.execute(select(BrandSourceHealth).where(BrandSourceHealth.source == "phishunt"))).scalar_one()
    assert row.consecutive_failures == 1 and row.last_error
    assert "phishunt.example" not in row.last_error, "a recorded reason never carries the feed URL"


async def test_stale_data_survives_a_short_outage_but_not_a_long_one(db_session):
    feed = _fresh_feed()
    ok = _client_factory(lambda r: httpx.Response(200, content=PHISHUNT.encode()))
    down = _client_factory(lambda r: httpx.Response(503))
    await REAL_REFRESH(db_session, client_factory=ok, now=NOW, feeds=[feed])
    await REAL_REFRESH(db_session, client_factory=down, now=NOW + timedelta(hours=1), feeds=[feed])
    assert "allegro-login.evil.example" in feed.index, "one failed refresh must not erase what we know"
    await REAL_REFRESH(db_session, client_factory=down, now=NOW + feeds.MAX_STALE + timedelta(minutes=1), feeds=[feed])
    assert feed.index == {} and feed.fetched_at is None, "an outage must not keep corroborating forever"


async def test_an_oversized_response_is_refused(db_session, monkeypatch):
    monkeypatch.setattr(feeds, "_MAX_BYTES", 1_000)
    feed = _fresh_feed()
    await REAL_REFRESH(db_session, client_factory=_client_factory(lambda r: httpx.Response(200, content=b"x" * 5_000)), now=NOW, feeds=[feed])
    assert feed.index == {}
    assert (await db_session.execute(select(BrandSourceHealth).where(BrandSourceHealth.source == "phishunt"))).scalar_one().last_error == "response too large"


async def test_the_feeds_appear_in_the_source_health_strip(db_session):
    names = [h["source"] for h in await sources.list_health(db_session)]
    assert {"phishunt", "urlhaus", sources.SOURCES[0].name} <= set(names)


# ── scoring ──────────────────────────────────────────────────────────────────

def _assess(cand, *, brand="dpd.com", tokens=("dpd",), **enr):
    return assess_candidate(cand, primary_domain=brand, official_domains=[], brand_tokens=list(tokens), discovery_class="typo", enrichment=enr, now=NOW)


def test_the_scorer_applies_each_corroboration_signal():
    rich = _assess(_ranked(0, 10_000), has_a=True, has_mx=True, ns=["ns1.sedoparking.com"],
                   feeds=[{"feed": "phishunt", "first_seen": "2026-09-30", "same_site": False, "detail": {"other_flags": 1}}])
    sig = {s.signal: s for s in rich.signals}
    assert {"popular_site", "parked", "on_phishing_feed"} <= set(sig)
    assert sig["popular_site"].weight < 0 and sig["parked"].weight < 0 and sig["on_phishing_feed"].weight == 35.0
    assert all(sig[k].dimension == "abuse" for k in ("popular_site", "parked", "on_phishing_feed"))


def test_a_popular_lookalike_is_cleared_but_the_same_name_as_a_subdomain_host_is_not():
    live = dict(has_a=True, has_mx=True)
    popular = _ranked(0, 10_000)
    apex = _assess(popular, **live)
    assert "popular_site" in {s.signal for s in apex.signals}
    sub = _assess(f"login.dpd.{popular}", **live)
    assert "popular_site" not in {s.signal for s in sub.signals}
    hosted = _assess("dpd-login.pages.dev", platform_suffix="pages.dev", **live)
    assert "popular_site" not in {s.signal for s in hosted.signals}


# ── pipeline ─────────────────────────────────────────────────────────────────

async def _profile(db):
    tenant = await make_tenant(db, name=f"T{uuid.uuid4().hex[:6]}", plan="pro")
    domain = await make_domain(db, tenant, name="acmefinancial.co.za")
    domain.ownership_verified = True
    profile = BrandProfile(id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, brand_name="Acme Financial", keywords=[], official_domains=[])
    db.add(profile)
    await db.commit()
    return tenant, profile


async def test_a_scan_attaches_feed_hits_scores_them_and_stores_list_badges(db_session, monkeypatch):
    tenant, profile = await _profile(db_session)
    listed, parked, quiet = "acmefinancial-pay.co.za", "acmefinancial-help.co.za", "acmefinancial-login.co.za"

    async def fake_dns(name):
        if name in (listed, parked, quiet):
            return {"has_a": True, "has_mx": False, "registered": True, "a": ["198.51.100.7"], "mx": [],
                    "ns": ["ns1.sedoparking.com"] if name == parked else ["ns1.x.net"]}
        return {"has_a": False, "has_mx": False, "registered": False, "ns": [], "a": [], "mx": []}

    async def no_reg(c, d):
        return None

    async def no_ct(db, tokens, since):
        return {}

    def fake_lookup(domain):
        if domain == listed:
            return [{"feed": "urlhaus", "label": "abuse.ch URLhaus", "first_seen": "2026-09-30", "same_site": False, "detail": {}}]
        return []
    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_registration_date", no_reg)
    monkeypatch.setattr(svc, "fetch_ct_candidates", no_ct)
    monkeypatch.setattr(svc.brand_feeds, "lookup", fake_lookup)
    await svc.scan_profile(db_session, profile, tenant, permutations=True)

    async def evidence(d):
        c = (await db_session.execute(select(BrandCandidate).where(BrandCandidate.candidate_domain == d))).scalar_one()
        rows = (await db_session.execute(select(CandidateEvidence).where(CandidateEvidence.candidate_id == c.id))).scalars().all()
        return c, {e.signal: e for e in rows}
    c1, e1 = await evidence(listed)
    c2, e2 = await evidence(parked)
    c3, e3 = await evidence(quiet)
    assert e1["on_phishing_feed"].weight == 30.0 and c1.enrichment["badges"] == [{"kind": "blocklist", "label": "On a blocklist"}]
    assert e2["parked"].weight < 0 and c2.enrichment["badges"] == [{"kind": "parked", "label": "Parked"}] and "on_phishing_feed" not in e2
    assert "badges" not in c3.enrichment and c1.abuse_score > c3.abuse_score > c2.abuse_score - 1
    assert c1.enrichment["feeds"][0]["feed"] == "urlhaus"
