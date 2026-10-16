"""
Step 2.2 — lexical and South Africa-specific detection upgrades, plus subdomain brand abuse (A2-2):
new generator classes (ccTLD mimic, word order, sound-alike, bit-squat, Afrikaans/Zulu lures), the matching signals
in the scorer, mixed-script detection, subdomain abuse found through certificate logs, the supplemental platform
list, and the word-frequency context.

What these tests do NOT claim: the sound-alike, bit-squat and local-lure classes have no positives in the public
evaluation corpus, so their *value* is unmeasured; the tests only prove the mechanics.
"""
import gzip
import uuid
from datetime import datetime, timezone

import pytest

from app.models import BrandCandidate
from app.services import brand_background as bg
from app.services import brand_discovery_service as disc
from app.services import brand_guard_service as svc
from app.services import brand_sources as sources
from app.services import public_suffix as psl
from app.services.brand_scoring_service import assess_candidate
from sqlalchemy import select
from tests.factories import make_domain, make_tenant

BRAND = "capitecbank.co.za"
TOKENS = ["capitecbank", "capitec"]


def assess(candidate, *, brand=BRAND, tokens=None, words=None, klass=None, enrichment=None, official=None):
    return assess_candidate(
        candidate, primary_domain=brand, official_domains=official or [], brand_tokens=tokens or TOKENS,
        discovery_class=klass, enrichment=enrichment or {}, brand_words=words,
    )


def signals(a):
    return {s.signal: s for s in a.signals}


# ── generator ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def generated():
    return disc.generate_candidates("standardbank.co.za", "Standard Bank", [])


def _of(generated, klass):
    return {d for d, k in generated.items() if k == klass}


def test_cctld_mimic_names_are_generated(generated):
    assert {"standardbank-co-za.com", "standardbank-coza.com", "standardbankcoza.com",
            "standardbank.za.com", "standardbank.za.net", "standardbank.za.org"} <= _of(generated, "cctld_mimic")
    assert generated["standardbank-za.com"] == "combosquat"     # 'za' is also a plain suffix word; the first class to claim a name keeps it


def test_brand_dot_co_dot_za_dot_com_is_not_generated_because_it_is_not_a_registration(generated):
    # co.za.com is one shared name, so brand.co.za.com is a subdomain of it, not something an attacker registers.
    assert "standardbank.co.za.com" not in generated
    assert psl.split("standardbank.co.za.com").registrable == "co.za.com"


def test_word_order_swaps_the_brands_own_words(generated):
    assert _of(generated, "word_order") == {"bankstandard.co.za", "bank-standard.co.za"}


def test_afrikaans_and_zulu_lures_are_combined_with_the_brand(generated):
    assert {"standardbank-inteken.co.za", "standardbankrekening.co.za", "standardbank-akhawunti.co.za"} <= set(generated)
    assert generated["standardbank-inteken.co.za"] == "combosquat"


def test_sound_alikes_and_bit_squats_are_generated_and_sound_like_or_differ_by_one_bit(generated):
    sound, bits = _of(generated, "soundsquat"), _of(generated, "bitsquat")
    assert sound and bits
    assert all(disc.is_sound_alike(d.split(".")[0], "standardbank") for d in sound)
    assert all(disc.is_bit_flip(d.split(".")[0], "standardbank") for d in bits)


def test_every_generated_name_is_a_valid_distinct_hostname(generated):
    assert "standardbank.co.za" not in generated
    for name in generated:
        label = name.split(".")[0]
        assert disc.to_ascii(name) == name and not label.startswith("-") and not label.endswith("-")


def test_the_ceiling_still_holds_with_the_new_classes():
    assert len(disc.generate_candidates("capitecbank.co.za", "Capitec Bank", ["loan", "card", "app"])) <= disc.MAX_CANDIDATES


def test_a_single_word_brand_gets_no_word_order_names():
    names = disc.generate_candidates("fnb.co.za", "FNB", [])
    assert "word_order" not in set(names.values())


def test_short_brands_get_no_bit_squats_because_every_neighbour_is_someone_elses_domain():
    # live finding: dpd.com produced 9 registered one-bit neighbours (lpd.com, tpd.com ...) that were all unrelated
    assert "bitsquat" not in set(disc.generate_candidates("dpd.com", "DPD", []).values())
    assert "bitsquat" not in set(disc.generate_candidates("absa.co.za", "ABSA", []).values())
    assert "bitsquat" in set(disc.generate_candidates("capitec.co.za", "Capitec", []).values())
    assert assess("dqd.com", brand="dpd.com", tokens=["dpd"]).threat_class != "bitsquat"


# ── primitives ───────────────────────────────────────────────────────────────

def test_bit_flip_needs_exactly_one_character_and_one_bit():
    assert disc.is_bit_flip("bapitec", "capitec")           # 'c' 0x63 vs 'b' 0x62: one bit
    assert not disc.is_bit_flip("rapitec", "capitec")       # 'c' vs 'r': several bits
    assert not disc.is_bit_flip("bapitek", "capitec")       # two characters differ
    assert not disc.is_bit_flip("capitec", "capitec") and not disc.is_bit_flip("capite", "capitec")


def test_sound_alike_means_same_sound_not_same_letters():
    assert disc.is_sound_alike("kapitec", "capitec") and disc.is_sound_alike("fonepay", "phonepay")
    assert not disc.is_sound_alike("capital", "capitec")    # looks close, sounds different
    assert not disc.is_sound_alike("capitec", "capitec")
    assert not disc.is_sound_alike("dpe", "dpd"), "very short names are never judged by sound"


def test_mixed_script_is_letters_from_more_than_one_alphabet():
    assert disc.is_mixed_script("p" + "а" + "ypal")                       # Latin + Cyrillic а
    assert disc.scripts_in("p" + "а" + "ypal") == {"LATIN", "CYRILLIC"}
    assert not disc.is_mixed_script("paypal") and not disc.is_mixed_script("paypal-2024")   # digits/hyphens are no script
    assert not disc.is_mixed_script("аррӏе")                               # a WHOLE-script homograph is not "mixed"
    assert disc.is_mixed_script(disc.to_ascii("p" + "а" + "ypal.com").split(".")[0])      # works on the punycode form too


@pytest.mark.parametrize("label,name,expected", [
    ("standardbank", "Standard Bank", ["standard", "bank"]),
    ("capitecbank", "Capitec Bank", ["capitec", "bank"]),
    ("capitecbank", None, ["capitec", "bank"]),            # known word at the end
    ("first-national", None, ["first", "national"]),       # hyphenated label
    ("fnb", "FNB", ["fnb"]),
    ("discovery", "Discovery", ["discovery"]),
])
def test_brand_words_splits_what_it_can_and_leaves_the_rest(label, name, expected):
    assert disc.brand_words(label, name) == expected


def test_word_order_match_ignores_hyphens_and_needs_a_real_swap():
    assert disc.word_order_match("bank-standard", ["standard", "bank"]) and disc.word_order_match("bankstandard", ["standard", "bank"])
    assert not disc.word_order_match("standard-bank", ["standard", "bank"])      # the original order is the brand itself
    assert not disc.word_order_match("bank-standard", ["standardbank"])


def test_cctld_mimic_detects_the_brand_followed_by_a_local_tail():
    assert disc.cctld_mimic("capitec-co-za", ["capitec"]) == "coza" and disc.cctld_mimic("capitecza", ["capitec"]) == "za"
    assert disc.cctld_mimic("capitec", ["capitec"]) is None and disc.cctld_mimic("capitec-login", ["capitec"]) is None


# ── scoring ──────────────────────────────────────────────────────────────────

def test_cctld_mimic_scores_once_not_twice():
    a = assess("capitecbankcoza.com")
    assert a.threat_class == "cctld_mimic" and a.identity_score == 55.0
    assert "cctld_mimic" in signals(a) and "domain_similarity" not in signals(a) and "keyword_combo" not in signals(a)


def test_word_order_needs_the_brand_words_and_scores_without_similarity_double_counting():
    a = assess("bank-capitec.co.za", words=["capitec", "bank"], tokens=["capitecbank"])
    assert a.threat_class == "word_order" and a.identity_score == 50.0 and "domain_similarity" not in signals(a)
    assert assess("bank-capitec.co.za", tokens=["capitecbank"]).identity_score == 0.0, "without the words it cannot be recognised"


def test_bit_flip_and_sound_alike_are_named_not_called_typos():
    flip = assess("bapitec.co.za", tokens=["capitec"])
    assert flip.threat_class == "bitsquat" and "bit_flip" in signals(flip) and flip.identity_score == 45.0
    sound = assess("fonepay.co.za", brand="phonepay.co.za", tokens=["phonepay"])
    assert sound.threat_class == "soundsquat" and "sound_alike" in signals(sound) and sound.identity_score == 45.0


def test_a_sound_alike_found_through_the_scoring_path_alone_is_still_recognised():
    # the CT path has no discovery class: the scorer must recognise the technique itself
    assert assess("fonepay.co.za", brand="phonepay.co.za", tokens=["phonepay"], klass=None).threat_class == "soundsquat"


def test_afrikaans_and_zulu_words_count_as_credential_lures():
    for word in ("inteken", "akhawunti", "wagwoord"):
        a = assess(f"capitecbank-{word}.co.za")
        assert "credential_lure_word" in signals(a), word
        assert signals(a)["credential_lure_word"].data["word"] == word


def test_a_short_brand_next_to_a_local_lure_word_is_matched():
    assert disc.token_match("absa-inteken", "absa") == "segment"
    assert disc.token_match("absainteken", "absa") == "affix"


def test_mixed_script_is_an_abuse_signal_on_top_of_the_homoglyph_identity_signals():
    name = "capit" + "е" + "cbank.co.za"                       # Cyrillic е
    a = assess(disc.to_ascii(name))
    s = signals(a)
    assert a.threat_class == "homoglyph" and "mixed_script" in s and s["mixed_script"].dimension == "abuse"
    assert s["mixed_script"].data["scripts"] == ["Cyrillic", "Latin"]
    assert "mixed_script" not in signals(assess("capitec-login.com"))


def test_common_brand_words_are_explained_but_not_discounted():
    """Tried and rejected (plan 2.2): discounting common words cost 12 real phishing names to remove 12 hits."""
    a = assess("googleplex-travel.com", brand="google.com", tokens=["google"])
    kc = signals(a)["keyword_combo"]
    assert kc.weight == 55.0 and a.identity_score == 55.0
    assert kc.data["background_per_100k"] >= bg.COMMON_PER_100K and "popular domain names" in kc.summary
    rare = signals(assess("capitec-help.co.za", tokens=["capitec"]))["keyword_combo"]
    assert rare.weight == 55.0 and "popular domain names" not in rare.summary


# ── subdomain brand abuse (A2-2) ─────────────────────────────────────────────

@pytest.mark.parametrize("host,kind", [
    ("capitecbank.co.za.secure-id.xyz", "official_domain_in_subdomain"),
    ("capitecbank-co-za.login.example.net", "official_domain_in_subdomain"),
    ("login.capitec.secure-id.xyz", "brand_in_subdomain"),
    ("capitec-verify.something.top", "brand_in_subdomain"),
])
def test_brand_in_a_subdomain_of_an_unrelated_site_is_found(host, kind):
    found = disc.subdomain_brand_abuse(host, TOKENS, [BRAND])
    assert found and found["kind"] == kind and found["apex"] == psl.split(host).registrable


@pytest.mark.parametrize("host", [
    "capitecbank.co.za",                   # the customer's own domain
    "login.capitecbank.co.za",             # the customer's own subdomain
    "secure-id.xyz",                       # no subdomain at all
    "login.capitec-help.com",              # brand is in the REGISTRABLE name: the ordinary rules own it
    "www.pineapple-shop.com",              # nothing brand-like
    "203.0.113.7",                         # an IP address
])
def test_hosts_that_are_not_subdomain_abuse_are_left_alone(host):
    assert disc.subdomain_brand_abuse(host, TOKENS, [BRAND]) is None


def test_official_domain_in_a_subdomain_is_stronger_than_the_bare_brand_word():
    strong = assess("capitecbank.co.za.secure-id.xyz")
    weak = assess("login.capitec.secure-id.xyz")
    assert signals(strong)["subdomain_brand"].weight == 55.0 and signals(weak)["subdomain_brand"].weight == 35.0
    assert strong.threat_class == weak.threat_class == "subdomain_abuse"
    assert weak.identity_score < 55 <= strong.identity_score


def test_a_customers_own_extra_domains_are_not_flagged_as_subdomain_abuse():
    assert assess("capitecbank-extra.co.za.secure-id.xyz", official=["capitecbank-extra.co.za"]).identity_score >= 55
    a = assess("login.capitec.capitecfoundation.org", official=["capitecfoundation.org"])
    assert a.suggested_status == "customer_owned"


def test_known_limit_a_vendor_that_gives_customers_subdomains_is_a_weak_lead():
    """capitec.zendesk.com is a plausible genuine support portal. It surfaces as a LEAD (identity 35, below every
    alert threshold), never as an accusation. The false-lead rate on real hosts is not measured (the negative
    corpus has no subdomains) and is the reason the intake is capped per scan."""
    a = assess("capitec.zendesk.com")
    assert a.identity_score == 35.0 and a.suggested_status == "monitoring" and not a.should_alert


def test_an_old_established_apex_dampens_a_subdomain_lead():
    a = assess("login.capitec.zendesk.com", enrichment={"registered_at": datetime(2008, 1, 1, tzinfo=timezone.utc).isoformat(), "has_a": True})
    assert "established_domain" in signals(a)


# ── supplemental platforms ───────────────────────────────────────────────────

def test_platforms_missing_from_the_public_suffix_list_are_treated_as_platforms():
    assert "weebly.com" not in psl._PSL_PATH.read_text(encoding="utf8").splitlines()   # genuinely absent from the vendored list
    parts = psl.split("xfinity-login.weebly.com")
    assert parts.private and parts.registrable == "xfinity-login.weebly.com" and parts.suffix == "weebly.com"
    assert disc.platform_suffix("xfinity-login.weebly.com") == "weebly.com"


def test_a_supplemental_platform_never_overrides_the_list_and_ordinary_sites_are_unchanged():
    assert psl.split("a.b.github.io").registrable == "b.github.io"
    assert psl.split("shop.example.com").registrable == "example.com" and not psl.split("shop.example.com").private
    assert not (set(psl.SUPPLEMENTAL_PLATFORMS) & {"com", "net", "org", "co.za"})


# ── word-frequency context ───────────────────────────────────────────────────

def test_background_frequency_separates_common_words_from_distinctive_names():
    assert bg.sample_size() == 100_000
    assert bg.is_common("google") and bg.is_common("cash") and bg.is_common("visa")
    assert not bg.is_common("capitec") and not bg.is_common("takealot") and not bg.is_common("nedbank")
    assert bg.per_100k("capitec") < bg.COMMON_PER_100K <= bg.per_100k("google")


def test_background_frequency_degrades_gracefully_when_the_list_is_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(bg, "_DATA", tmp_path / "absent.gz")
    bg._labels.cache_clear(); bg.hits.cache_clear()
    try:
        assert bg.sample_size() == 0 and bg.per_100k("google") is None and not bg.is_common("google")
        a = assess("googleplex-travel.com", brand="google.com", tokens=["google"])
        assert a.identity_score == 55.0 and "background_per_100k" not in signals(a)["keyword_combo"].data
    finally:
        monkeypatch.undo()
        bg._labels.cache_clear(); bg.hits.cache_clear()


def test_the_reference_list_is_what_its_manifest_says():
    import hashlib, json
    from pathlib import Path
    data = Path(bg._DATA).parent
    manifest = json.loads((data / "popular_labels.manifest.json").read_text(encoding="utf8"))
    body = gzip.open(bg._DATA, "rb").read()
    assert hashlib.sha256(body).hexdigest() == manifest["sha256_of_labels"]
    assert manifest["labels"] == 100_000 and "CC BY 3.0" in manifest["source"]


# ── certificate-log source keeps the hostnames ───────────────────────────────

class _FakeResp:
    status_code = 200
    headers: dict = {}

    def __init__(self, data):
        self._d = data

    def json(self):
        return self._d


class _FakeClient:
    def __init__(self, data):
        self._data = data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, *a, **kw):
        return _FakeResp(self._data)


async def test_ct_source_returns_the_hostnames_behind_each_registrable_name():
    now = datetime.now(timezone.utc).isoformat()
    data = [{"entry_timestamp": now, "name_value": "login.capitec.evil.xyz\n*.evil.xyz\nevil.xyz\ncapitec-help.example.org"}]
    src = sources.CrtShSource(client_factory=lambda: _FakeClient(data))
    found = await src.fetch(["capitec"], datetime(2020, 1, 1, tzinfo=timezone.utc))
    assert set(found) == {"evil.xyz", "example.org"}
    assert found["evil.xyz"]["hosts"] == {"login.capitec.evil.xyz": found["evil.xyz"]["issued_at"]}   # the apex itself is not a "host"
    assert list(found["example.org"]["hosts"]) == ["capitec-help.example.org"]


async def test_ct_hostnames_kept_per_registrable_name_are_bounded():
    now = datetime.now(timezone.utc).isoformat()
    names = "\n".join(f"h{i}.capitec.evil.xyz" for i in range(40))
    src = sources.CrtShSource(client_factory=lambda: _FakeClient([{"entry_timestamp": now, "name_value": names}]))
    found = await src.fetch(["capitec"], datetime(2020, 1, 1, tzinfo=timezone.utc))
    assert len(found["evil.xyz"]["hosts"]) == sources._MAX_HOSTS_PER_APEX


# ── pipeline: a subdomain-abuse host becomes a candidate keyed by the FULL host ──

async def test_scan_tracks_subdomain_abuse_under_the_full_host(db_session, monkeypatch):
    tenant = await make_tenant(db_session, name="Acme", plan="pro")
    domain = await make_domain(db_session, tenant, name="acmefinancial.co.za")
    domain.ownership_verified = True
    from app.models import BrandProfile
    profile = BrandProfile(id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, brand_name="Acme Financial", keywords=[], official_domains=[])
    db_session.add(profile)
    await db_session.commit()

    host = "acmefinancial.co.za.secure-id.xyz"
    now = datetime.now(timezone.utc).isoformat()

    async def fake_dns(name):
        return {"has_a": name == host, "has_mx": False, "registered": name == host}

    async def fake_reg(client, name):
        return None

    async def fake_ct(db, tokens, since):
        return {"secure-id.xyz": {"issued_at": now, "hosts": {host: now}}}

    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_registration_date", fake_reg)
    monkeypatch.setattr(svc, "fetch_ct_candidates", fake_ct)

    summary = await svc.scan_profile(db_session, profile, tenant, permutations=False)
    rows = (await db_session.execute(select(BrandCandidate).where(BrandCandidate.profile_id == profile.id))).scalars().all()
    assert [r.candidate_domain for r in rows] == [host], summary          # the full host, NOT the shared registrable name
    row = rows[0]
    assert row.threat_class == "subdomain_abuse" and "ct_log" in row.sources
    assert row.identity_score == 65.0           # 55 for the official domain written inside the subdomain + 10 for the certificate


async def test_scan_ignores_ct_hosts_that_are_not_subdomain_abuse_and_caps_the_intake(db_session, monkeypatch):
    tenant = await make_tenant(db_session, name="Acme2", plan="pro")
    domain = await make_domain(db_session, tenant, name="acmefinancial.co.za")
    domain.ownership_verified = True
    from app.models import BrandProfile
    profile = BrandProfile(id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, brand_name="Acme Financial", keywords=[], official_domains=[])
    db_session.add(profile)
    await db_session.commit()

    now = datetime.now(timezone.utc).isoformat()
    many = {f"login.acmefinancial.vendor{i}.net": now for i in range(svc._MAX_SUBDOMAIN_CANDIDATES + 10)}

    async def fake_dns(name):
        return {"has_a": True, "has_mx": False, "registered": True}

    async def fake_reg(client, name):
        return None

    async def fake_ct(db, tokens, since):
        out = {f"vendor{i}.net": {"issued_at": now, "hosts": {h: now}} for i, h in enumerate(many)}
        out["harmless.org"] = {"issued_at": now, "hosts": {"www.harmless.org": now}}
        return out

    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_registration_date", fake_reg)
    monkeypatch.setattr(svc, "fetch_ct_candidates", fake_ct)

    await svc.scan_profile(db_session, profile, tenant, permutations=False)
    rows = (await db_session.execute(select(BrandCandidate).where(BrandCandidate.profile_id == profile.id))).scalars().all()
    assert len(rows) == svc._MAX_SUBDOMAIN_CANDIDATES
    assert all(r.threat_class == "subdomain_abuse" and r.candidate_domain != "www.harmless.org" for r in rows)
