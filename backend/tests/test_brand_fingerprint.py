"""
Step 2.0 — brand fingerprint and customer baseline:
  * safe_fetch: the SSRF guards (a tenant controls the DNS of the domain we fetch);
  * the page parser, the DNS/mail/ASN baseline builder (never raises);
  * the baseline comparison (same nameservers / same address, with the shared-platform guard);
  * the API: rebuild, trademarks, suggested official domains, tenant isolation, audit;
  * the pipeline: a look-alike on the customer's own infrastructure scores lower and says why.
"""
import uuid
from datetime import datetime, timezone

import httpx
import pytest
from sqlalchemy import select

from app.models import AuditLogEntry, BrandCandidate, BrandProfile, CandidateEvidence
from app.services import brand_baseline as bl
from app.services import brand_fingerprint_service as fps
from app.services import brand_guard_service as svc
from app.services import safe_fetch
from app.services.brand_scoring_service import assess_candidate
from tests.factories import make_domain, make_tenant, make_user

PUBLIC = "93.184.216.34"


# ── safe_fetch ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("ip,public", [
    ("8.8.8.8", True), (PUBLIC, True), ("2606:4700:4700::1111", True),
    ("127.0.0.1", False), ("10.1.2.3", False), ("192.168.0.9", False), ("172.16.5.5", False), ("169.254.169.254", False),
    ("100.64.0.1", False), ("0.0.0.0", False), ("::1", False), ("fe80::1", False), ("fc00::1", False), ("not-an-ip", False),
])
def test_only_globally_routable_addresses_are_public(ip, public):
    assert safe_fetch.is_public_address(ip) is public


class _Loop:
    def __init__(self, addrs):
        self.addrs = addrs

    async def getaddrinfo(self, host, port, type=None):
        return [(2, 1, 6, "", (a, 0)) for a in self.addrs]


async def test_one_private_address_anywhere_in_the_answer_rejects_the_name(monkeypatch):
    monkeypatch.setattr(safe_fetch.asyncio, "get_running_loop", lambda: _Loop([PUBLIC, "10.0.0.5"]))
    with pytest.raises(safe_fetch.FetchError, match="non-public"):
        await safe_fetch.resolve_public("sneaky.example")


async def test_a_public_answer_is_returned_ipv4_first(monkeypatch):
    monkeypatch.setattr(safe_fetch.asyncio, "get_running_loop", lambda: _Loop(["2606:4700:4700::1111", PUBLIC]))
    assert (await safe_fetch.resolve_public("ok.example"))[0] == PUBLIC


async def test_literal_internal_addresses_are_refused_without_a_lookup():
    for host in ("127.0.0.1", "169.254.169.254", "[::1]"):
        with pytest.raises(safe_fetch.FetchError):
            await safe_fetch.resolve_public(host)


def _factory(handler):
    return lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


async def _public_resolver(host):
    return [PUBLIC]


async def _fetch(url, handler, **kw):
    return await safe_fetch.fetch(url, resolver=kw.pop("resolver", _public_resolver), client_factory=_factory(handler), **kw)


async def test_the_connection_is_pinned_to_the_validated_address_with_the_real_name_for_host_and_tls():
    seen = {}

    def handler(request: httpx.Request):
        seen.update(host=request.url.host, header=request.headers["host"], sni=request.extensions.get("sni_hostname"), path=request.url.raw_path)
        return httpx.Response(200, headers={"content-type": "text/html; charset=utf-8"}, content=b"<html></html>")

    res = await _fetch("https://example.com/a?b=1", handler)
    assert seen == {"host": PUBLIC, "header": "example.com", "sni": "example.com", "path": b"/a?b=1"}
    assert res.url == "https://example.com/a?b=1" and res.status == 200 and res.content_type == "text/html"


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "ftp://example.com/", "gopher://example.com/", "javascript:alert(1)",
    "http://example.com:8080/", "https://example.com:22/", "https://user:pw@example.com/", "https:///nohost",
])
async def test_only_plain_web_urls_on_standard_ports_are_fetched(url):
    def handler(request):
        raise AssertionError("must not connect")
    with pytest.raises(safe_fetch.FetchError):
        await _fetch(url, handler)


async def test_a_redirect_to_an_internal_name_is_refused_even_though_the_first_hop_was_fine():
    async def resolver(host):
        if host == "internal.corp":
            raise safe_fetch.FetchError("refused: the name points at a non-public address")
        return [PUBLIC]

    def handler(request):
        return httpx.Response(302, headers={"location": "http://internal.corp/admin"})
    with pytest.raises(safe_fetch.FetchError, match="non-public"):
        await _fetch("https://example.com/", handler, resolver=resolver)


async def test_a_redirect_to_a_metadata_address_literal_is_refused():
    def handler(request):
        return httpx.Response(301, headers={"location": "http://169.254.169.254/latest/meta-data/"})
    async def resolver(host):          # the real validation for IP literals; a stub (no network) for the one real-looking name
        return [PUBLIC] if host == "example.com" else await safe_fetch.resolve_public(host)
    with pytest.raises(safe_fetch.FetchError, match="non-public"):
        await _fetch("https://example.com/", handler, resolver=resolver)


async def test_redirects_are_followed_a_few_times_then_stopped():
    hops = []

    def handler(request):
        hops.append(request.headers["host"])
        n = len(hops)
        return httpx.Response(302, headers={"location": f"https://h{n}.example.com/"})
    with pytest.raises(safe_fetch.FetchError, match="too many redirects"):
        await _fetch("https://example.com/", handler)
    assert len(hops) == safe_fetch.MAX_REDIRECTS + 1

    ok_hops = []

    def two_hops(request):
        ok_hops.append(request.headers["host"])
        if len(ok_hops) < 3:
            return httpx.Response(301, headers={"location": "/next"})
        return httpx.Response(200, headers={"content-type": "text/html"}, content=b"done")
    res = await _fetch("http://example.com/", two_hops)
    assert res.body == b"done" and res.url == "http://example.com/next"


async def test_a_response_larger_than_the_cap_is_truncated_not_buffered():
    def handler(request):
        return httpx.Response(200, headers={"content-type": "text/html"}, content=b"x" * 50_000)
    res = await _fetch("https://example.com/", handler, max_bytes=1_000)
    assert res.truncated and len(res.body) == 1_000


async def test_failures_carry_a_short_reason_and_never_the_address_or_body():
    def boom(request):
        raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed for 93.184.216.34")
    with pytest.raises(safe_fetch.FetchError) as e:
        await _fetch("https://example.com/", boom)
    assert "certificate" in str(e.value).lower() and PUBLIC not in str(e.value)

    def slow(request):
        raise httpx.ReadTimeout("slow")
    with pytest.raises(safe_fetch.FetchError, match="timed out"):
        await _fetch("https://example.com/", slow)


# ── page parser ──────────────────────────────────────────────────────────────

PAGE = """<!doctype html><html lang="en-ZA"><head>
<title>  Capitec Bank |
   Personal banking </title>
<meta name="description" content="Bank smarter. Simple.">
<meta property="og:site_name" content="Capitec">
<link rel="apple-touch-icon" href="/apple.png"><link rel="shortcut icon" href="/assets/fav.ico?v=3">
<script>var x = "ignore@script.example";</script></head>
<body><a href="https://www.facebook.com/capitec/?ref=nav#top">fb</a><a href="https://twitter.com/capitec">x</a>
<a href="/careers">c</a><a href="mailto:help@capitecbank.co.za?subject=hi">m</a><a href="tel:+27 86 010 5000">t</a>
<p>Write to info@capitecbank.co.za or logo@2x.png</p><a href="https://evil.example/facebook.com">not social</a></body></html>"""


def test_parser_extracts_the_identity_anchors():
    site = fps.parse_page(PAGE, "https://www.capitecbank.co.za/")
    assert site["title"] == "Capitec Bank | Personal banking"
    assert site["description"] == "Bank smarter. Simple." and site["site_name"] == "Capitec" and site["lang"] == "en-ZA"
    assert site["icon_href"] == "https://www.capitecbank.co.za/assets/fav.ico?v=3", "the real icon is preferred over the touch icon"
    assert site["social"] == [{"network": "facebook", "url": "https://www.facebook.com/capitec/"}, {"network": "x", "url": "https://twitter.com/capitec"}]
    assert site["emails"] == ["help@capitecbank.co.za", "info@capitecbank.co.za"]
    assert site["phones"] == ["+27860105000"]


def test_parser_ignores_script_text_image_names_and_lookalike_social_hosts():
    site = fps.parse_page(PAGE, "https://x.example/")
    assert "ignore@script.example" not in site["emails"] and not any("2x.png" in e for e in site["emails"])
    assert all("evil.example" not in s["url"] for s in site["social"])


def test_parser_survives_hostile_and_empty_input():
    for html in ("", "<<<>>>", "<title>" * 5000, "<a href=" * 2000, "\x00\x01<html", "<meta name=description>", "x" * 500_000):
        site = fps.parse_page(html, "https://x.example/")
        assert set(site) >= {"title", "description", "social", "emails", "phones"}
    huge = fps.parse_page("<title>" + "A" * 10_000 + "</title>" + "".join(f'<a href="mailto:a{i}@x.example">' for i in range(200)), "https://x.example/")
    assert len(huge["title"]) <= 300 and len(huge["emails"]) <= 10


_HOSTILE = {
    "repeated unterminated attribute": lambda: "<a href=" * 20_000,        # stdlib html.parser: 16 KB took 1.8 s, super-linear
    "long text with no tags": lambda: "x" * 500_000,                       # an email pattern over this took 15 s
    "unclosed comment": lambda: "<!--" + "a" * 100_000,
    "long run of address characters": lambda: "a@" * 150_000,
    "many open tags": lambda: "<p>" * 100_000,
    "unclosed attribute quotes": lambda: "<a " + 'x="' * 1_500,
}


@pytest.mark.parametrize("name", list(_HOSTILE))
def test_hostile_pages_are_parsed_in_bounded_time(name):
    """Regression for a real finding: a page we fetch is attacker-controllable, and the first implementation (stdlib
    html.parser plus an unbounded email pattern) could be stalled for seconds by a small crafted input."""
    import time
    html = _HOSTILE[name]()
    started = time.monotonic()
    fps.parse_page(html, "https://x.example/")
    assert time.monotonic() - started < 2.0, name


# ── baseline logic ───────────────────────────────────────────────────────────

def test_mail_provider_is_recognised_from_the_mx_hosts():
    assert bl.mail_provider(["acme-co-za.mail.protection.outlook.com"]) == "Microsoft 365"
    assert bl.mail_provider(["aspmx.l.google.com.", "alt1.aspmx.l.google.com"]) == "Google Workspace"
    assert bl.mail_provider(["mx1.example.net"]) is None and bl.mail_provider([]) is None
    assert bl.mail_provider(["evilprotection.outlook.com.attacker.net"]) is None, "the provider must be the END of the host name"


BASE = {"ns": ["ns1.own-dns.co.za", "ns2.own-dns.co.za"], "a": ["203.0.113.10"], "asn": {"number": 64500, "name": "ACME-HOSTING"},
        "shared_hosting": False, "shared_nameservers": False}


def test_same_nameservers_and_same_address_are_benign_explainers():
    found = {f["signal"]: f for f in bl.shares_infrastructure({"ns": ["ns2.own-dns.co.za.", "NS1.own-dns.co.za"], "a": ["203.0.113.10", "203.0.113.99"]}, BASE)}
    assert found["same_nameservers"]["weight"] == bl.SAME_NAMESERVERS_UNSHARED and found["same_nameservers"]["values"] == BASE["ns"]
    assert found["same_hosting_ip"]["weight"] == bl.SAME_ADDRESS and found["same_hosting_ip"]["values"] == ["203.0.113.10"]


def test_a_partial_nameserver_overlap_or_no_overlap_proves_nothing():
    assert bl.shares_infrastructure({"ns": ["ns1.own-dns.co.za"], "a": ["198.51.100.1"]}, BASE) == []
    assert bl.shares_infrastructure({"ns": ["ns1.other.net", "ns2.other.net"]}, BASE) == []
    assert bl.shares_infrastructure({"ns": ["ns1.own-dns.co.za"], "a": ["203.0.113.10"]}, None) == []
    assert bl.shares_infrastructure({}, BASE) == []


def test_sharing_a_cdn_address_with_the_customer_is_NOT_evidence_of_ownership():
    """The core safety rule: an attacker's site behind the same Cloudflare address as the customer must not look benign."""
    cdn = dict(BASE, a=["104.16.1.1"], asn={"number": 13335, "name": "CLOUDFLARENET, US"}, shared_hosting=True)
    assert bl.shares_infrastructure({"a": ["104.16.1.1"]}, cdn) == []
    unmarked = dict(BASE, a=["104.16.1.1"], shared_hosting=False, asn={"number": 13335, "name": "CLOUDFLARENET, US"})
    assert bl.shares_infrastructure({"a": ["104.16.1.1"]}, unmarked) == [], "judged by the owner name even if the flag is missing"


def test_shared_dns_platforms_count_for_much_less():
    cf = dict(BASE, ns=["bob.ns.cloudflare.com", "kim.ns.cloudflare.com"], shared_nameservers=True)
    (found,) = bl.shares_infrastructure({"ns": ["kim.ns.cloudflare.com", "bob.ns.cloudflare.com"]}, cf)
    assert found["weight"] == bl.SAME_NAMESERVERS_SHARED and found["shared_platform"] is True
    assert abs(bl.SAME_NAMESERVERS_SHARED) < abs(bl.SAME_NAMESERVERS_UNSHARED)


# ── builder ──────────────────────────────────────────────────────────────────

def _fake_fetch(pages: dict):
    async def fetch(url, **kw):
        r = pages.get(url)
        if isinstance(r, Exception):
            raise r
        if r is None:
            raise safe_fetch.FetchError("could not connect")
        return r
    return fetch


def _res(url, body=b"", status=200, ctype="text/html"):
    return safe_fetch.FetchResult(url=url, status=status, content_type=ctype, body=body, truncated=False)


def _fake_query(table: dict):
    async def q(name, rtype):
        return table.get((name, rtype), ("nxdomain", []))
    return q


DNS = {
    ("acme.co.za", "NS"): ("answer", ["ns2.own-dns.co.za.", "ns1.own-dns.co.za."]),
    ("acme.co.za", "A"): ("answer", ["203.0.113.10"]),
    ("acme.co.za", "MX"): ("answer", ["10 acme-co-za.mail.protection.outlook.com."]),
    ("10.113.0.203.origin.asn.cymru.com", "TXT"): ("answer", ['"64500 | 203.0.113.0/24 | ZA | afrinic | 2015-01-01"']),
    ("AS64500.asn.cymru.com", "TXT"): ("answer", ['"64500 | ZA | afrinic | 2015-01-01 | ACME-HOSTING, ZA"']),
}


async def test_build_fingerprint_collects_site_dns_mail_and_network_owner():
    pages = {
        "https://acme.co.za/": _res("https://acme.co.za/", PAGE.encode()),
        "https://acme.co.za/assets/fav.ico?v=3": _res("https://acme.co.za/assets/fav.ico?v=3", b"\x00\x00icon-bytes", ctype="image/x-icon"),
    }
    # the page above points the icon at www.capitecbank.co.za-relative paths; use the page's own host
    pages["https://acme.co.za/"] = _res("https://acme.co.za/", PAGE.encode())
    fp = await fps.build_fingerprint("acme.co.za", fetch=_fake_fetch(pages), query=_fake_query(DNS))
    assert fp["version"] == fps.FINGERPRINT_VERSION and fp["domain"] == "acme.co.za"
    assert fp["site"]["title"] == "Capitec Bank | Personal banking" and fp["site"]["status"] == 200 and "icon_href" not in fp["site"]
    assert fp["dns"]["ns"] == ["ns1.own-dns.co.za", "ns2.own-dns.co.za"] and fp["dns"]["a"] == ["203.0.113.10"]
    assert fp["dns"]["mx"] == ["acme-co-za.mail.protection.outlook.com"] and fp["dns"]["mail_provider"] == "Microsoft 365"
    assert fp["dns"]["asn"] == {"number": 64500, "name": "ACME-HOSTING, ZA"} and fp["dns"]["shared_hosting"] is False


async def test_the_favicon_is_hashed_and_a_missing_one_is_reported_not_fatal():
    import hashlib
    body = b"\x89PNG-bytes"
    pages = {"https://acme.co.za/": _res("https://acme.co.za/", b"<html><title>A</title></html>"),
             "https://acme.co.za/favicon.ico": _res("https://acme.co.za/favicon.ico", body, ctype="image/png")}
    fp = await fps.build_fingerprint("acme.co.za", fetch=_fake_fetch(pages), query=_fake_query(DNS))
    assert fp["site"]["favicon"]["sha256"] == hashlib.sha256(body).hexdigest() and fp["site"]["favicon"]["bytes"] == len(body)
    pages.pop("https://acme.co.za/favicon.ico")
    fp = await fps.build_fingerprint("acme.co.za", fetch=_fake_fetch(pages), query=_fake_query(DNS))
    assert fp["site"]["favicon"] is None and "No favicon could be read." in fp["errors"]


async def test_an_unreachable_site_still_yields_the_dns_baseline_and_says_why():
    fp = await fps.build_fingerprint("acme.co.za", fetch=_fake_fetch({}), query=_fake_query(DNS))
    assert fp["site"] is None and fp["dns"]["ns"] and any("Could not read the website: could not connect" in e for e in fp["errors"])


async def test_the_builder_never_raises_whatever_the_fetcher_or_resolver_does():
    async def exploding_fetch(url, **kw):
        raise RuntimeError("boom 93.184.216.34")

    async def flaky_query(name, rtype):
        return ("error", [])
    fp = await fps.build_fingerprint("acme.co.za", fetch=exploding_fetch, query=flaky_query)
    assert fp["site"] is None and fp["dns"]["ns"] == [] and fp["dns"]["asn"] is None
    assert not any("93.184" in e for e in fp["errors"]), "internal error text must not leak into what a user sees"
    assert any("DNS lookups" in e for e in fp["errors"])


async def test_https_failure_falls_back_to_http_and_non_html_or_error_pages_are_not_parsed():
    pages = {"https://acme.co.za/": safe_fetch.FetchError("could not connect"), "http://acme.co.za/": _res("http://acme.co.za/", b"<title>Plain</title>")}
    fp = await fps.build_fingerprint("acme.co.za", fetch=_fake_fetch(pages), query=_fake_query(DNS))
    assert fp["site"]["title"] == "Plain" and fp["site"]["url"] == "http://acme.co.za/"
    for bad in (_res("https://acme.co.za/", b"{}", ctype="application/json"), _res("https://acme.co.za/", b"<title>x</title>", status=503)):
        fp = await fps.build_fingerprint("acme.co.za", fetch=_fake_fetch({"https://acme.co.za/": bad, "http://acme.co.za/": bad}), query=_fake_query(DNS))
        assert fp["site"] is None


# ── API ──────────────────────────────────────────────────────────────────────

async def _verified(db, tenant, name):
    d = await make_domain(db, tenant, name=name)
    d.ownership_verified = True
    await db.commit()
    return d


async def _profile(client, tenant, db, name="acmefinancial.co.za"):
    tenant.plan = "pro"
    domain = await _verified(db, tenant, name)
    r = await client.post("/brand-guard/profiles", json={"domain_id": str(domain.id), "brand_name": "Acme Financial"})
    assert r.status_code == 201, r.text
    return r.json()


@pytest.fixture
def fake_builder(monkeypatch):
    calls = []

    async def build(domain, **kw):
        calls.append(domain)
        return {"version": 1, "built_at": datetime.now(timezone.utc).isoformat(), "domain": domain,
                "site": {"title": "Acme", "favicon": None, "social": [], "emails": [], "phones": []},
                "dns": {"ns": ["ns1.own-dns.co.za", "ns2.own-dns.co.za"], "a": ["203.0.113.10"], "mx": [], "mail_provider": None, "asn": None,
                        "shared_hosting": False, "shared_nameservers": False},
                "errors": []}
    monkeypatch.setattr(fps, "build_fingerprint", build)
    return calls


async def test_a_new_profile_has_no_fingerprint_until_one_is_built_and_rebuilds_are_stored_and_audited(auth_client, db_session, fake_builder):
    client, tenant = auth_client
    prof = await _profile(client, tenant, db_session)
    assert prof["fingerprint"] is None and prof["fingerprint_built_at"] is None and prof["trademarks"] == []

    r = await client.post(f"/brand-guard/profiles/{prof['id']}/fingerprint")
    assert r.status_code == 200, r.text
    out = r.json()
    assert fake_builder == ["acmefinancial.co.za"] and out["fingerprint"]["site"]["title"] == "Acme" and out["fingerprint_built_at"]
    stored = await client.get("/brand-guard/profiles")
    assert stored.json()[0]["fingerprint"]["dns"]["ns"] == ["ns1.own-dns.co.za", "ns2.own-dns.co.za"]

    entry = (await db_session.execute(select(AuditLogEntry).where(AuditLogEntry.action == "brand_guard.fingerprint_rebuilt"))).scalar_one()
    assert entry.after["site_read"] is True and entry.after["nameservers"] == 2 and entry.target_label == "Acme Financial"


async def test_another_tenant_cannot_rebuild_or_see_a_fingerprint(auth_client, db_session, fake_builder):
    client, tenant = auth_client
    prof = await _profile(client, tenant, db_session)
    other = await make_tenant(db_session, name="Other", plan="pro")
    stranger = await make_user(db_session, other, email="stranger@other.test")
    from app.routers.auth import get_current_user
    from app.main import app
    app.dependency_overrides[get_current_user] = lambda: stranger
    try:
        assert (await client.post(f"/brand-guard/profiles/{prof['id']}/fingerprint")).status_code == 404
        assert (await client.get("/brand-guard/profiles")).json() == []
    finally:
        app.dependency_overrides.pop(get_current_user, None)
    assert fake_builder == []


async def test_suggested_official_domains_are_the_tenants_other_domains_not_yet_listed(auth_client, db_session, fake_builder):
    client, tenant = auth_client
    prof = await _profile(client, tenant, db_session)
    await _verified(db_session, tenant, "acmefinancial.com")
    await _verified(db_session, tenant, "acme-insure.co.za")
    other = await make_tenant(db_session, name="Other2", plan="pro")
    await make_domain(db_session, other, name="not-mine.example")

    listed = (await client.get("/brand-guard/profiles")).json()[0]
    assert listed["suggested_official_domains"] == ["acme-insure.co.za", "acmefinancial.com"]      # never another tenant's, never itself

    r = await client.patch(f"/brand-guard/profiles/{prof['id']}", json={"official_domains": ["acmefinancial.com"]})
    assert r.json()["suggested_official_domains"] == ["acme-insure.co.za"]


async def test_trademarks_are_editable_validated_and_audited(auth_client, db_session, fake_builder):
    client, tenant = auth_client
    prof = await _profile(client, tenant, db_session)
    marks = [{"mark": " ACME ", "number": "2019/12345", "jurisdiction": "ZA"}, {"mark": "Acme Financial"}]
    r = await client.patch(f"/brand-guard/profiles/{prof['id']}", json={"trademarks": marks})
    assert r.status_code == 200, r.text
    assert r.json()["trademarks"] == [{"mark": "ACME", "number": "2019/12345", "jurisdiction": "ZA"}, {"mark": "Acme Financial", "number": "", "jurisdiction": ""}]
    assert (await client.patch(f"/brand-guard/profiles/{prof['id']}", json={"trademarks": [{"mark": ""}]})).status_code == 422
    assert (await client.patch(f"/brand-guard/profiles/{prof['id']}", json={"trademarks": [{"mark": "x" * 200}]})).status_code == 422
    assert (await client.patch(f"/brand-guard/profiles/{prof['id']}", json={"trademarks": [{"mark": f"m{i}"} for i in range(21)]})).status_code == 422
    entry = (await db_session.execute(select(AuditLogEntry).where(AuditLogEntry.action == "brand_guard.profile_updated"))).scalars().all()
    assert any("trademarks" in (e.after or {}) for e in entry)


# ── scoring and pipeline ─────────────────────────────────────────────────────

def _assess(candidate, enrichment, baseline):
    return assess_candidate(candidate, primary_domain="acmefinancial.co.za", official_domains=[], brand_tokens=["acmefinancial"],
                            discovery_class="combosquat", enrichment=enrichment, baseline=baseline)


def test_a_lookalike_on_the_customers_own_infrastructure_scores_lower_and_explains_itself():
    enrichment = {"has_a": True, "ns": BASE["ns"], "a": BASE["a"]}
    plain = _assess("acmefinancial-pay.co.za", enrichment, None)
    with_baseline = _assess("acmefinancial-pay.co.za", enrichment, BASE)
    sig = {s.signal: s for s in with_baseline.signals}
    assert {"same_nameservers", "same_hosting_ip"} <= set(sig)
    assert all(s.dimension == "abuse" and s.weight < 0 for k, s in sig.items() if k in ("same_nameservers", "same_hosting_ip"))
    assert with_baseline.abuse_score == plain.abuse_score - 30 or with_baseline.abuse_score == 0
    assert with_baseline.identity_score == plain.identity_score, "infrastructure never changes how much it resembles the brand"
    assert "probably yours" in sig["same_hosting_ip"].summary


def test_the_baseline_cannot_clear_an_attacker_on_the_same_cdn_address():
    cdn = dict(BASE, a=["104.16.1.1"], asn={"number": 13335, "name": "CLOUDFLARENET"}, shared_hosting=True, ns=["bob.ns.cloudflare.com", "kim.ns.cloudflare.com"], shared_nameservers=True)
    a = _assess("acmefinancial-login.co.za", {"has_a": True, "a": ["104.16.1.1"], "ns": ["x.ns.example", "y.ns.example"]}, cdn)
    assert not {"same_nameservers", "same_hosting_ip"} & {s.signal for s in a.signals}


async def test_scan_uses_the_stored_baseline_end_to_end(auth_client, db_session, monkeypatch, fake_builder):
    client, tenant = auth_client
    prof = await _profile(client, tenant, db_session)
    await client.post(f"/brand-guard/profiles/{prof['id']}/fingerprint")

    host = "acmefinancial-pay.co.za"

    async def fake_dns(name):
        if name == host:
            return {"has_a": True, "has_mx": False, "registered": True, "ns": ["ns1.own-dns.co.za", "ns2.own-dns.co.za"], "a": ["203.0.113.10"]}
        return {"has_a": False, "has_mx": False, "registered": False, "ns": [], "a": []}

    async def fake_reg(c, d):
        return None

    async def fake_ct(db, tokens, since):
        return {}
    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_registration_date", fake_reg)
    monkeypatch.setattr(svc, "fetch_ct_candidates", fake_ct)
    monkeypatch.setattr(svc, "_session_factory", lambda: _Borrowed(db_session))

    r = await client.post(f"/brand-guard/profiles/{prof['id']}/scan")
    assert r.status_code == 202
    await svc.wait_for_run(uuid.UUID(r.json()["id"]))
    cand = (await db_session.execute(select(BrandCandidate).where(BrandCandidate.candidate_domain == host))).scalar_one()
    signals = {e.signal for e in (await db_session.execute(select(CandidateEvidence).where(CandidateEvidence.candidate_id == cand.id))).scalars()}
    assert {"same_nameservers", "same_hosting_ip"} <= signals
    assert cand.enrichment["a"] == ["203.0.113.10"]


class _Borrowed:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *exc):
        return False
