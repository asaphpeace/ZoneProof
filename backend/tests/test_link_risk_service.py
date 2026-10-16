"""
Composite link risk score (Phishing Simulation roadmap Phase 32).

Pure functions (structure heuristics, domain-age tiers, TLD reputation,
composite scoring) are tested with zero network. Every external call —
Web Risk, RDAP, .za WHOIS — is faked, following test_breach_monitoring_scan.py's
existing _FakeResponse/fake-client pattern; this suite never hits a real
network endpoint and never needs a real API key.
"""
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.config import settings
from app.models.domain_reputation_cache import DomainReputationCache
from app.models.reported_email import ReportedEmail
from app.services import link_risk_service as svc


@pytest.fixture(autouse=True)
def _reset_rdap_bootstrap_cache():
    svc._rdap_bootstrap_cache = None
    svc._rdap_bootstrap_fetched_at = None
    yield
    svc._rdap_bootstrap_cache = None
    svc._rdap_bootstrap_fetched_at = None


class _FakeResponse:
    def __init__(self, body, status_code=200):
        self._body = body
        self.status_code = status_code

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPError(f"status {self.status_code}")


class _FakeGetClient:
    """Generic fake for a bare `client.get(url, params=...)` call, keyed by
    exact URL — matches how test_breach_monitoring_scan.py fakes httpx."""
    def __init__(self, responses: dict):
        self._responses = responses
        self.calls: list[str] = []

    async def get(self, url, params=None):
        self.calls.append(url)
        if url not in self._responses:
            raise AssertionError(f"unexpected URL requested: {url}")
        return self._responses[url]


class _RaisingGetClient:
    async def get(self, url, params=None):
        raise httpx.HTTPError("boom")


class _FakeWhoisWriter:
    def write(self, data):
        pass

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


class _FakeWhoisReader:
    def __init__(self, data: bytes):
        self._data = data

    async def read(self, n=-1):
        return self._data


# ── Pure: URL structure heuristics ──────────────────────────────────────

def test_ip_literal_host_flagged():
    result = svc.compute_url_structure_heuristics("http://192.0.2.10/login")
    assert result["is_ip_literal"] is True
    assert result["delta"] < 0


def test_punycode_label_flagged():
    result = svc.compute_url_structure_heuristics("http://xn--pypal-4ve.com/login")
    assert result["is_punycode"] is True
    assert result["delta"] < 0


def test_userinfo_at_trick_flagged():
    result = svc.compute_url_structure_heuristics("http://real-bank.com@evil.xyz/login")
    assert result["has_userinfo_trick"] is True
    assert result["delta"] < 0


def test_excessive_subdomain_depth_flagged():
    result = svc.compute_url_structure_heuristics("http://a.b.c.d.evil-domain.xyz/login")
    assert result["subdomain_depth"] > 3
    assert result["delta"] < 0


def test_brand_keyword_in_subdomain_flagged_when_apex_is_not_the_brand():
    result = svc.compute_url_structure_heuristics("http://paypal.security-check.xyz/login")
    assert result["brand_keyword_hit"] == "paypal"
    assert result["delta"] < 0


def test_brand_keyword_not_flagged_on_the_real_domain():
    result = svc.compute_url_structure_heuristics("http://www.paypal.com/login")
    assert result["brand_keyword_hit"] is None


def test_known_shortener_flagged():
    result = svc.compute_url_structure_heuristics("http://bit.ly/abc123")
    assert result["is_known_shortener"] is True
    assert result["delta"] < 0


def test_ordinary_url_has_no_flags_and_zero_delta():
    result = svc.compute_url_structure_heuristics("https://www.example.com/some/normal/path")
    assert result["delta"] == 0
    assert result["reasons"] == []


def test_registrable_domain_handles_co_za_apex():
    assert svc._registrable_domain("sub.example.co.za") == "example.co.za"


def test_registrable_domain_default_two_label_rule():
    assert svc._registrable_domain("sub.example.xyz") == "example.xyz"


# ── Pure: domain age / TLD reputation / composite scoring ──────────────

def test_unknown_domain_age_contributes_zero_delta():
    now = datetime.now(timezone.utc)
    assert svc._domain_age_score_delta(None, now) == (0, None)


def test_new_domain_penalized_more_than_old_domain():
    now = datetime.now(timezone.utc)
    new_delta, new_reason = svc._domain_age_score_delta(now - timedelta(days=2), now)
    old_delta, old_reason = svc._domain_age_score_delta(now - timedelta(days=1000), now)
    assert new_delta < old_delta
    assert old_delta == 0
    assert new_reason is not None
    assert old_reason is None


def test_tld_reputation_is_the_smallest_magnitude_signal():
    tld_max = max(abs(v) for v in svc._TLD_REPUTATION_DELTA.values())
    assert tld_max < 40   # largest domain-age penalty
    assert tld_max < 20   # largest structure-heuristic weight (userinfo trick)


def test_web_risk_match_floors_score_into_dangerous_regardless_of_clean_domain_age_and_tld():
    structure = {"delta": 0, "reasons": []}
    result = svc.compute_composite_score(
        structure=structure, domain_age_delta=0, domain_age_reason=None,
        tld_delta=0, tld_reason=None,
        web_risk_checked=True, web_risk_matched=True, web_risk_threat_types=["SOCIAL_ENGINEERING"],
    )
    assert result["score"] <= 15
    assert result["verdict"] == "likely_dangerous"
    assert "phishing" in result["explanation"].lower()


def test_clean_verdict_explanation_never_uses_the_words_safe_or_verified():
    structure = {"delta": 0, "reasons": []}
    result = svc.compute_composite_score(
        structure=structure, domain_age_delta=0, domain_age_reason=None,
        tld_delta=0, tld_reason=None,
        web_risk_checked=True, web_risk_matched=False, web_risk_threat_types=[],
    )
    assert result["verdict"] == "likely_safe"
    assert "safe" not in result["explanation"].lower()
    assert "verified" not in result["explanation"].lower()


# ── Web Risk lookup (mocked httpx) ──────────────────────────────────────

async def test_web_risk_lookup_returns_none_when_key_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "web_risk_api_key", "")
    result = await svc._web_risk_lookup(None, "http://example.com")
    assert result is None


async def test_web_risk_lookup_matched_on_threat_response(monkeypatch):
    monkeypatch.setattr(settings, "web_risk_api_key", "test-key")
    client = _FakeGetClient({svc._WEB_RISK_URL: _FakeResponse({"threat": {"threatTypes": ["SOCIAL_ENGINEERING"]}})})
    result = await svc._web_risk_lookup(client, "http://evil.example/login")
    assert result == {"matched": True, "threat_types": ["SOCIAL_ENGINEERING"]}


async def test_web_risk_lookup_clean_on_bare_response(monkeypatch):
    monkeypatch.setattr(settings, "web_risk_api_key", "test-key")
    client = _FakeGetClient({svc._WEB_RISK_URL: _FakeResponse({})})
    result = await svc._web_risk_lookup(client, "http://example.com")
    assert result == {"matched": False, "threat_types": []}


async def test_web_risk_lookup_returns_none_on_http_error(monkeypatch):
    monkeypatch.setattr(settings, "web_risk_api_key", "test-key")
    result = await svc._web_risk_lookup(_RaisingGetClient(), "http://example.com")
    assert result is None


# ── RDAP (mocked httpx) ──────────────────────────────────────────────────

async def test_rdap_lookup_parses_registration_event_date():
    bootstrap = {"services": [[["com"], ["https://rdap.example-registry.test/"]]]}
    domain = {"events": [{"eventAction": "registration", "eventDate": "2020-05-01T00:00:00Z"}]}
    client = _FakeGetClient({
        svc._RDAP_BOOTSTRAP_URL: _FakeResponse(bootstrap),
        "https://rdap.example-registry.test/domain/example.com": _FakeResponse(domain),
    })
    result = await svc._lookup_domain_age_rdap(client, "example.com")
    assert result == datetime(2020, 5, 1, tzinfo=timezone.utc)


async def test_rdap_lookup_returns_none_when_tld_missing_from_bootstrap():
    bootstrap = {"services": [[["com"], ["https://rdap.example-registry.test/"]]]}
    client = _FakeGetClient({svc._RDAP_BOOTSTRAP_URL: _FakeResponse(bootstrap)})
    result = await svc._lookup_domain_age_rdap(client, "example.io")
    assert result is None


async def test_rdap_bootstrap_is_cached_across_two_lookups():
    bootstrap = {"services": [[["com"], ["https://rdap.example-registry.test/"]]]}
    domain = {"events": [{"eventAction": "registration", "eventDate": "2020-05-01T00:00:00Z"}]}
    client = _FakeGetClient({
        svc._RDAP_BOOTSTRAP_URL: _FakeResponse(bootstrap),
        "https://rdap.example-registry.test/domain/one.com": _FakeResponse(domain),
        "https://rdap.example-registry.test/domain/two.com": _FakeResponse(domain),
    })
    await svc._lookup_domain_age_rdap(client, "one.com")
    await svc._lookup_domain_age_rdap(client, "two.com")
    assert client.calls.count(svc._RDAP_BOOTSTRAP_URL) == 1


# ── .za WHOIS fallback (mocked socket) ───────────────────────────────────

async def test_za_domain_uses_whois_fallback_not_rdap(monkeypatch):
    async def _raise_if_called(client, apex_domain):
        raise AssertionError("RDAP should never be called for a .za domain")
    monkeypatch.setattr(svc, "_lookup_domain_age_rdap", _raise_if_called)

    async def _fake_za_whois(apex_domain):
        return datetime(2024, 3, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(svc, "_lookup_domain_age_za_whois", _fake_za_whois)

    registered_at, source = await svc._lookup_domain_age(None, "example.co.za")
    assert source == "za_whois"
    assert registered_at == datetime(2024, 3, 1, tzinfo=timezone.utc)


async def test_za_whois_parses_creation_date_line(monkeypatch):
    async def fake_open_connection(host, port):
        assert host == svc._ZA_WHOIS_HOST
        assert port == svc._ZA_WHOIS_PORT
        body = b"Domain Name: example.co.za\r\nCreation Date: 2024-03-01\r\nRegistrar: Example\r\n"
        return _FakeWhoisReader(body), _FakeWhoisWriter()
    monkeypatch.setattr(svc.asyncio, "open_connection", fake_open_connection)

    result = await svc._lookup_domain_age_za_whois("example.co.za")
    assert result == datetime(2024, 3, 1, tzinfo=timezone.utc)


async def test_za_whois_connection_failure_returns_none_not_raise(monkeypatch):
    async def failing_open_connection(host, port):
        raise OSError("connection refused")
    monkeypatch.setattr(svc.asyncio, "open_connection", failing_open_connection)

    result = await svc._lookup_domain_age_za_whois("example.co.za")
    assert result is None


# ── Domain cache reuse / TTL / force-refresh (real DB, faked lookup) ───

async def test_domain_cache_reused_within_ttl(db_session, monkeypatch):
    monkeypatch.setattr(settings, "web_risk_api_key", "")
    calls = []

    async def fake_lookup(client, apex_domain):
        calls.append(apex_domain)
        return datetime(2020, 1, 1, tzinfo=timezone.utc), "rdap"
    monkeypatch.setattr(svc, "_lookup_domain_age", fake_lookup)

    await svc.score_url(db_session, None, "http://example.com/a")
    await svc.score_url(db_session, None, "http://example.com/b")

    assert calls == ["example.com"]


async def test_domain_cache_refreshed_after_ttl_expires(db_session, monkeypatch):
    monkeypatch.setattr(settings, "web_risk_api_key", "")
    stale = DomainReputationCache(
        id=uuid.uuid4(), apex_domain="stale-example.com",
        domain_registered_at=datetime(2020, 1, 1, tzinfo=timezone.utc), domain_age_source="rdap",
        domain_age_checked_at=datetime.now(timezone.utc) - timedelta(days=61),
    )
    db_session.add(stale)
    await db_session.commit()

    calls = []

    async def fake_lookup(client, apex_domain):
        calls.append(apex_domain)
        return datetime(2020, 1, 1, tzinfo=timezone.utc), "rdap"
    monkeypatch.setattr(svc, "_lookup_domain_age", fake_lookup)

    await svc.score_url(db_session, None, "http://stale-example.com/a")
    assert calls == ["stale-example.com"]


async def test_force_refresh_bypasses_cache_within_ttl(db_session, monkeypatch):
    monkeypatch.setattr(settings, "web_risk_api_key", "")
    fresh = DomainReputationCache(
        id=uuid.uuid4(), apex_domain="fresh-example.com",
        domain_registered_at=datetime(2020, 1, 1, tzinfo=timezone.utc), domain_age_source="rdap",
        domain_age_checked_at=datetime.now(timezone.utc),
    )
    db_session.add(fresh)
    await db_session.commit()

    calls = []

    async def fake_lookup(client, apex_domain):
        calls.append(apex_domain)
        return datetime(2020, 1, 1, tzinfo=timezone.utc), "rdap"
    monkeypatch.setattr(svc, "_lookup_domain_age", fake_lookup)

    await svc.score_url(db_session, None, "http://fresh-example.com/a", force_refresh=True)
    assert calls == ["fresh-example.com"]


async def test_score_urls_one_bad_url_does_not_abort_the_batch(db_session, monkeypatch):
    monkeypatch.setattr(settings, "web_risk_api_key", "")

    async def fake_lookup(client, apex_domain):
        return datetime(2020, 1, 1, tzinfo=timezone.utc), "rdap"
    monkeypatch.setattr(svc, "_lookup_domain_age", fake_lookup)

    results = await svc.score_urls(db_session, ["http://good-example.com/a", "not-a-real-url"])
    assert len(results) == 2
    good, bad = results
    assert good["score"] is not None
    assert bad["score"] is None
    assert bad["verdict"] == "uncertain"
    assert "could not be scored" in bad["explanation"].lower()


# ── score_report_urls_best_effort ───────────────────────────────────────

async def test_score_report_urls_best_effort_skips_when_no_urls(db_session, monkeypatch):
    calls = []

    async def tracking_score_urls(db, urls, **kwargs):
        calls.append(urls)
        return []
    monkeypatch.setattr(svc, "score_urls", tracking_score_urls)

    report = ReportedEmail(id=uuid.uuid4(), tenant_id=uuid.uuid4(), urls_found=[])
    await svc.score_report_urls_best_effort(db_session, report)
    assert calls == []
    assert report.url_risk is None


async def test_score_report_urls_best_effort_never_raises_and_leaves_url_risk_untouched_on_failure(db_session, monkeypatch):
    async def failing_score_urls(db, urls, **kwargs):
        raise RuntimeError("boom")
    monkeypatch.setattr(svc, "score_urls", failing_score_urls)

    report = ReportedEmail(id=uuid.uuid4(), tenant_id=uuid.uuid4(), urls_found=["http://example.com"])
    await svc.score_report_urls_best_effort(db_session, report)  # must not raise
    assert report.url_risk is None


async def test_score_report_urls_best_effort_populates_url_risk_on_success(db_session, monkeypatch):
    canned = [{"url": "http://example.com", "score": 90, "verdict": "likely_safe", "grade": "A", "explanation": "ok", "signals": {}}]

    async def fake_score_urls(db, urls, **kwargs):
        return canned
    monkeypatch.setattr(svc, "score_urls", fake_score_urls)

    report = ReportedEmail(id=uuid.uuid4(), tenant_id=uuid.uuid4(), urls_found=["http://example.com"])
    await svc.score_report_urls_best_effort(db_session, report)
    assert report.url_risk == canned
    assert report.url_risk_scored_at is not None
