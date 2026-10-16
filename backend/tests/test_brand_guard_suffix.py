"""
Step 2.0b — detector defects found by the 1.3 baseline:
  (a) multi-label public suffixes (x.com.br -> "com.br", x.co.uk -> "co.uk"), also breaking
      generation for customers whose own domain sits under one;
  (b) free-hosting subdomains collapsing to the platform apex (pages.dev);
  (c) short / common-word brand tokens: never matched (<=3 letters) or over-matched ('cash').
"""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.services import brand_discovery_service as disc
from app.services import brand_guard_service as svc
from app.services import public_suffix as psl
from app.services.brand_scoring_service import assess_candidate
from tests.factories import make_domain

DATA = Path(psl.__file__).resolve().parent.parent / "data"


# ── the vendored list ────────────────────────────────────────────────────────

def test_vendored_list_matches_its_manifest_and_carries_the_licence():
    manifest = json.loads((DATA / "public_suffix_list.manifest.json").read_text(encoding="utf8"))
    raw = (DATA / "public_suffix_list.dat").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == manifest["sha256"] and len(raw) == manifest["bytes"], "the list must stay unmodified"
    assert "Mozilla Public License" in manifest["licence"] and manifest["source"].startswith("https://publicsuffix.org/")
    text = raw.decode("utf8")
    assert "===BEGIN ICANN DOMAINS===" in text and "===BEGIN PRIVATE DOMAINS===" in text


# ── the PSL algorithm ────────────────────────────────────────────────────────

@pytest.mark.parametrize("host,suffix,registrable,sub,private", [
    ("example.com", "com", "example.com", "", False),
    ("www.example.com", "com", "example.com", "www", False),
    ("foo.bar.example.com", "com", "example.com", "foo.bar", False),
    ("facebook.com.br", "com.br", "facebook.com.br", "", False),
    ("brand.co.uk", "co.uk", "brand.co.uk", "", False),
    ("login.brand.com.au", "com.au", "brand.com.au", "login", False),
    ("brand.co.za", "co.za", "brand.co.za", "", False),
    ("x.pages.dev", "pages.dev", "x.pages.dev", "", True),
    ("login.brand.github.io", "github.io", "brand.github.io", "login", True),
    ("x.s3.amazonaws.com", "s3.amazonaws.com", "x.s3.amazonaws.com", "", True),
    # wildcard and exception rules (*.kobe.jp, !city.kobe.jp)
    ("a.b.kobe.jp", "b.kobe.jp", "a.b.kobe.jp", "", False),
    ("b.c.kobe.jp", "c.kobe.jp", "b.c.kobe.jp", "", False),
    ("city.kobe.jp", "kobe.jp", "city.kobe.jp", "", False),
    ("www.city.kobe.jp", "kobe.jp", "city.kobe.jp", "www", False),
    # normalisation: case, trailing dot, wildcard prefix, IDN
    ("EXAMPLE.CO.ZA.", "co.za", "example.co.za", "", False),
    ("*.brand.co.uk", "co.uk", "brand.co.uk", "", False),
    ("bücher.de", "de", "xn--bcher-kva.de", "", False),
    ("xn--pypal-4ve.com", "com", "xn--pypal-4ve.com", "", False),
    # an unknown suffix falls back to the implicit "*" rule
    ("host.nosuchtld", "nosuchtld", "host.nosuchtld", "", False),
])
def test_split_follows_the_public_suffix_algorithm(host, suffix, registrable, sub, private):
    s = psl.split(host)
    assert (s.suffix, s.registrable, s.subdomain, s.private) == (suffix, registrable, sub, private)


@pytest.mark.parametrize("host", ["co.uk", "com", "pages.dev", "localhost", "b.kobe.jp", "c.kobe.jp"])  # *.kobe.jp makes b.kobe.jp a suffix; kobe.jp itself is not
def test_a_bare_public_suffix_has_no_registrable_domain(host):
    assert psl.split(host).registrable is None


def test_ip_addresses_and_empty_input_do_not_crash():
    ip = psl.split("203.0.113.7")
    assert ip.is_ip and ip.registrable == "203.0.113.7" and ip.suffix == ""
    assert psl.split("").registrable is None and psl.split("   ").host == ""


# ── discovery uses it (defects a and b) ──────────────────────────────────────

@pytest.mark.parametrize("host,expected", [
    ("facebook.com.br", ("facebook", "com.br")),
    ("login.brand.co.uk", ("brand", "co.uk")),
    ("shop.brand.com.au", ("brand", "com.au")),
    ("acme.co.za", ("acme", "co.za")),
    ("www.acme.com", ("acme", "com")),
    ("brand-login.pages.dev", ("brand-login", "pages.dev")),
    ("co.uk", ("", "co.uk")),
    ("pages.dev", ("", "pages.dev")),
])
def test_split_registrable_understands_multi_label_and_platform_suffixes(host, expected):
    assert disc.split_registrable(host) == expected


def test_registrable_domain_and_platform_suffix():
    assert disc.registrable_domain("a.b.brand.com.br") == "brand.com.br"
    assert disc.registrable_domain("co.uk") == "co.uk"
    assert disc.platform_suffix("brand-login.pages.dev") == "pages.dev"
    assert disc.platform_suffix("brand.com") is None and disc.platform_suffix("pages.dev") is None


@pytest.mark.parametrize("customer_domain", ["brand.com.au", "brand.co.uk", "brand.com.br", "brand.co.in"])
def test_customers_on_multi_label_suffixes_get_sensible_permutations(customer_domain):
    """Before the fix the label was parsed as 'com'/'co' and every permutation was a permutation of that."""
    cands = disc.generate_candidates(customer_domain, "Brand")
    assert len(cands) > 40 and customer_domain not in cands
    labels = {disc.split_registrable(c)[0] for c in cands}
    assert "com" not in labels and "co" not in labels
    assert any(c.startswith("login-brand.") for c in cands) and "brand.net" in cands


def test_a_bare_suffix_generates_nothing():
    assert disc.generate_candidates("pages.dev") == {} and disc.generate_candidates("co.uk") == {}


def test_tld_swaps_include_commonly_abused_suffixes():
    cands = disc.generate_candidates("acmefinancial.co.za", "Acme Financial")
    assert {"acmefinancial.top", "acmefinancial.icu", "acmefinancial.click", "acmefinancial.com"} <= set(cands)


# ── token rules (defect c) ───────────────────────────────────────────────────

@pytest.mark.parametrize("label,token,expected", [
    ("acmefinancial", "acmefinancial", "exact"),
    ("secure-paypal-login", "paypal", "substring"),          # 6+ letters: distinctive, matches anywhere
    ("paypalsecure", "paypal", "substring"),
    ("paypla", "paypal", "near"),                             # typo-squat of a 6+ letter brand
    ("cash-app-login", "cash", "segment"),                    # 4-5 letters: whole word
    ("applesupport", "apple", "affix"),                       # ...or fused with a lure word
    ("secure-apple-id", "apple", "segment"),
    ("gls-groupptt", "gls", "segment"),                       # 3 letters: whole word only
    ("login-mtn", "mtn", "segment"),
    ("visitlancashire", "cash", None),                        # the false match the baseline found
    ("pineapple", "apple", None),
    ("glassworks", "gls", None),
    ("dpdn62", "dpd", None),                                  # known limit: fused into another word
    ("ab", "ab", None),
    ("", "paypal", None),
])
def test_token_match_tiers(label, token, expected):
    assert disc.token_match(label, token) == expected


def test_short_brands_cannot_match_inside_longer_words_but_long_brands_still_do():
    assert disc.matches_brand_fingerprint("visitlancashire.com", ["cash"]) is None
    assert disc.matches_brand_fingerprint("cash-app-login.com", ["cash"]) == "cash"
    assert disc.matches_brand_fingerprint("gls-group-tracking.de", ["gls"]) == "gls"
    assert disc.matches_brand_fingerprint("abcdef.com", ["abc"]) is None, "3-letter token inside a word stays unmatched"
    assert disc.matches_brand_fingerprint("secureacmefinancial.com", ["acmefinancial"]) == "acmefinancial"


def test_matching_works_under_multi_label_suffixes_and_platforms():
    assert disc.matches_brand_fingerprint("secure-paypal.com.br", ["paypal"]) == "paypal"
    assert disc.matches_brand_fingerprint("paypal-login.pages.dev", ["paypal"]) == "paypal"
    assert disc.matches_brand_fingerprint("pages.dev", ["paypal"]) is None, "the platform itself is never a brand match"
    assert disc.matches_brand_fingerprint("co.uk", ["co"]) is None


def test_the_unrelated_domains_from_the_baseline_are_no_longer_tied_to_brands():
    # freespins.com.co was a permutation of the label 'com' (the suffix bug); visitlancashire matched 'cash'
    assert "com.co" not in disc.generate_candidates("bradesco.com.br", "bradesco")
    assert disc.matches_brand_fingerprint("visitlancashire.com", ["cash", "cashapp"]) is None


# ── scoring uses the same rules ──────────────────────────────────────────────

def _identity(domain, *, brand="acmefinancial.co.za", tokens=("acmefinancial",), enrichment=None, klass=None):
    return assess_candidate(domain, primary_domain=brand, official_domains=[], brand_tokens=list(tokens), discovery_class=klass,
                            enrichment=enrichment or {})


def test_keyword_combo_signal_honours_the_token_tiers():
    assert "keyword_combo" in {s.signal for s in _identity("cash-app-login.com", brand="cash.app", tokens=("cash",)).signals}
    assert "keyword_combo" not in {s.signal for s in _identity("visitlancashire.com", brand="cash.app", tokens=("cash",)).signals}
    assert "keyword_combo" in {s.signal for s in _identity("gls-group-tracking.de", brand="gls.de", tokens=("gls",)).signals}
    assert "keyword_combo" in {s.signal for s in _identity("secure-acmefinancial-login.com").signals}


@pytest.mark.parametrize("platform", ["edgekey.net", "azurewebsites.net", "cloudfront.net", "global.ssl.fastly.net"])
def test_cdn_and_cloud_platforms_are_context_not_abuse_evidence(platform):
    """The Public Suffix List's private section lists CDNs and clouds as well as free site builders. Only the free hosts
    score (plan 2.4 follow-up: the live scan flagged DPD's own Akamai-hosted site)."""
    a = _identity(f"secure-acmefinancial-login.{platform}", enrichment={"platform_suffix": platform})
    sigs = {s.signal: s for s in a.signals}
    assert "platform_hosted" not in sigs
    assert sigs["cloud_platform_hosted"].weight == 0.0 and platform in sigs["cloud_platform_hosted"].summary
    free = _identity("secure-acmefinancial-login.pages.dev", enrichment={"platform_suffix": "pages.dev"})
    assert free.abuse_score - a.abuse_score >= 10


@pytest.mark.parametrize("platform", ["pages.dev", "github.io", "weebly.com", "dpdns.org", "de5.net", "duckdns.org"])
def test_free_hosts_and_free_subdomain_services_still_score(platform):
    sigs = {s.signal: s for s in _identity(f"secure-acmefinancial-login.{platform}", enrichment={"platform_suffix": platform}).signals}
    assert sigs["platform_hosted"].weight == 10.0 and "cloud_platform_hosted" not in sigs


def test_platform_hosted_adds_explicit_evidence_and_abuse_weight():
    plain = _identity("secure-acmefinancial-login.pages.dev")
    hosted = _identity("secure-acmefinancial-login.pages.dev", enrichment={"platform_suffix": "pages.dev"})
    sig = next(s for s in hosted.signals if s.signal == "platform_hosted")
    assert "pages.dev" in sig.summary and "registration age doesn't apply" in sig.summary and sig.data == {"platform_suffix": "pages.dev"}
    assert hosted.abuse_score == plain.abuse_score + 10
    assert "platform_hosted" not in {s.signal for s in plain.signals}


def test_brand_on_a_multi_label_suffix_scores_like_any_other():
    a = _identity("acmefinancial-login.com.br", brand="acmefinancial.com.br")
    assert "keyword_combo" in {s.signal for s in a.signals} and a.identity_score >= 55
    swap = _identity("acmefinancial.com", brand="acmefinancial.com.br", klass="tld_swap")
    assert swap.threat_class == "tld_swap" and swap.identity_score == 40


# ── brand profile warnings ───────────────────────────────────────────────────

def test_brand_warnings_by_name_length():
    assert any("3 letters or fewer" in w for w in disc.brand_warnings("dpd.com"))
    assert any("4-5 letters" in w for w in disc.brand_warnings("cash.app")) and any("4-5 letters" in w for w in disc.brand_warnings("apple.com"))
    assert disc.brand_warnings("acmefinancial.co.za") == []
    assert disc.brand_warnings("pages.dev") and "public suffix" in disc.brand_warnings("pages.dev")[0]


# ── pipeline: platform-hosted candidates (needs DB) ──────────────────────────

class _Borrowed:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *exc):
        return False


async def test_platform_hosted_candidate_skips_registration_lookup_and_is_explained(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    tenant.plan = "pro"
    domain = await make_domain(db_session, tenant, name="acmefinancial.co.za")
    domain.ownership_verified = True
    await db_session.commit()
    profile_id = (await client.post("/brand-guard/profiles", json={"domain_id": str(domain.id), "brand_name": "Acme Financial"})).json()["id"]

    host = "secure-acmefinancial-login.pages.dev"
    looked_up: list[str] = []

    async def fake_dns(d):
        return {"has_a": d == host, "has_mx": False}

    async def fake_reg(client_, d):
        looked_up.append(d)
        return datetime.now(timezone.utc) - timedelta(days=3)

    async def fake_ct(db, tokens, since):
        return {host: {"issued_at": datetime.now(timezone.utc).isoformat()}}

    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_registration_date", fake_reg)
    monkeypatch.setattr(svc, "fetch_ct_candidates", fake_ct)
    monkeypatch.setattr(svc, "_session_factory", lambda: _Borrowed(db_session))

    resp = await client.post(f"/brand-guard/profiles/{profile_id}/scan")
    await svc.wait_for_run(__import__("uuid").UUID(resp.json()["id"]))

    cand = next(c for c in (await client.get("/brand-guard/candidates")).json() if c["candidate_domain"] == host)
    assert cand["enrichment"]["platform_suffix"] == "pages.dev"
    assert host not in looked_up, "a subdomain on a platform has no registration date to look up"
    detail = (await client.get(f"/brand-guard/candidates/{cand['id']}")).json()
    assert any("free hosting platform" in line for line in detail["why_flagged"])


async def test_profile_exposes_name_matching_warnings(auth_client, db_session):
    client, tenant = auth_client
    tenant.plan = "pro"
    short = await make_domain(db_session, tenant, name="dpd.com")
    short.ownership_verified = True
    await db_session.commit()
    resp = await client.post("/brand-guard/profiles", json={"domain_id": str(short.id), "brand_name": "DPD"})
    assert resp.status_code == 201 and any("3 letters or fewer" in w for w in resp.json()["warnings"])
    assert (await client.get("/brand-guard/profiles")).json()[0]["warnings"] == resp.json()["warnings"]
