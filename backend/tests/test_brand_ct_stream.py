"""Matching live certificate sightings to brands (brand_ct_stream.py). Pure: no network, no database."""
from datetime import datetime, timedelta, timezone

import pytest

from app.services import brand_ct_stream as bs, brand_sources
from app.services.brand_discovery_service import generate_candidates, matches_brand_fingerprint, registrable_domain, subdomain_brand_abuse
from app.services.ct_tiles import CertSighting

NOW_MS = 1_790_000_000_000


def brand(pid="p1", tokens=("acmefinancial", "acmefin"), official=("acmefinancial.co.za",)):
    return bs.StreamBrand(pid, "t1", tuple(tokens), frozenset(registrable_domain(o) for o in official), tuple(official))


def sighting(*names, sha="a" * 64, issuer="Let's Encrypt", ts=NOW_MS):
    return CertSighting(tuple(names), ts, None, issuer, sha, False)


# ── the necessary-condition prefilter must never reject what the real rules accept ──

@pytest.mark.parametrize("domain,keywords", [
    ("acmefinancial.co.za", ["pay", "login"]), ("capitec.co.za", ["bank"]), ("paypal.com", ["secure"]), ("standardbank.co.za", []),
    ("dpd.com", ["parcel"]), ("gls-group.eu", []), ("nedbank.co.za", ["money"]),
])
def test_prefilter_never_hides_a_match_the_full_rules_would_make(domain, keywords):
    label = domain.split(".")[0]
    tokens = (label, label.replace("-", ""))
    b = brand(tokens=tokens, official=(domain,))
    matcher = bs.StreamMatcher([b])
    generated = generate_candidates(domain, label.title(), keywords)
    assert len(generated) > 50
    misses = [d for d in generated if matches_brand_fingerprint(d, list(tokens)) and registrable_domain(d) not in b.official_apexes
              and not any(x[0] is b for x in matcher.match_host(d))]
    assert misses == []


def test_prefilter_keeps_near_misses_of_long_tokens_with_one_and_two_edits():
    long_token = "standardbankgroup"                              # 17 letters: budget 2
    matcher = bs.StreamMatcher([brand(tokens=(long_token,), official=("standardbankgroup.com",))])
    for variant in ["standardbankgrup.com", "standardbnakgroup.com", "stndardbankgroup.net", "standarbankgroup.org", "sstandardbankgroup.xyz"]:
        assert matches_brand_fingerprint(variant, [long_token]), variant
        assert matcher.match_host(variant), variant
    short = bs.StreamMatcher([brand(tokens=("paypal",), official=("paypal.com",))])        # 6 letters: budget 1
    for variant in ["paypa1.com", "paypall.com", "paypl.com", "payopal.net"]:
        if matches_brand_fingerprint(variant, ["paypal"]):
            assert short.match_host(variant), variant


def test_an_adjacent_swap_survives_the_prefilter():
    """The case that disproved the first version of the window argument: papyal is one swap from paypal."""
    assert matches_brand_fingerprint("papyal.com", ["paypal"])
    assert bs.StreamMatcher([brand(tokens=("paypal",), official=("paypal.com",))]).match_host("papyal.com")


def test_randomised_edits_never_slip_past_the_prefilter():
    import random
    rng = random.Random(20261002)
    letters = "abcdefghijklmnopqrstuvwxyz"
    checked = 0
    for _ in range(400):
        token = "".join(rng.choice(letters) for _ in range(rng.randint(6, 14)))
        label = token
        for _ in range(rng.randint(1, 2)):
            i = rng.randrange(len(label))
            op = rng.choice(["sub", "ins", "del", "swap"])
            if op == "sub":
                label = label[:i] + rng.choice(letters) + label[i + 1:]
            elif op == "ins":
                label = label[:i] + rng.choice(letters) + label[i:]
            elif op == "del" and len(label) > 3:
                label = label[:i] + label[i + 1:]
            elif op == "swap" and i + 1 < len(label):
                label = label[:i] + label[i + 1] + label[i] + label[i + 2:]
        host = label + ".com"
        official = (token + ".org",)
        if matches_brand_fingerprint(host, [token]) and registrable_domain(host) not in {registrable_domain(o) for o in official}:
            checked += 1
            assert bs.StreamMatcher([brand(tokens=(token,), official=official)]).match_host(host), (token, host)
    assert checked > 100                                  # the test is only meaningful if many of the edits are real matches


def test_confusable_lookalikes_survive_the_prefilter():
    matcher = bs.StreamMatcher([brand(tokens=("capitec",), official=("capitec.co.za",))])
    for variant in ["capitec-secure.com", "capit3c.com", "caplt3c.net", "xn--capite-8ve.com"]:
        assert bool(matches_brand_fingerprint(variant, ["capitec"])) == bool(matcher.match_host(variant)), variant


# ── what a match means ──

def test_registrable_lookalike_is_keyed_by_its_apex_and_lists_the_hosts():
    matcher = bs.StreamMatcher([brand()])
    got = matcher.match(sighting("login.acmefinancial-pay.xyz", "www.acmefinancial-pay.xyz", "acmefinancial-pay.xyz"))
    assert len(got) == 1
    b, key, klass, ct = got[0]
    assert (b.profile_id, key, klass) == ("p1", "acmefinancial-pay.xyz", "")
    assert set(ct["hosts"]) == {"login.acmefinancial-pay.xyz", "www.acmefinancial-pay.xyz"} and ct["issuer"] == "Let's Encrypt"
    assert ct["cert_ids"] == ["a" * 64]


def test_brand_hidden_in_a_subdomain_of_someone_elses_domain_is_keyed_by_the_full_host():
    matcher = bs.StreamMatcher([brand()])
    got = matcher.match(sighting("acmefinancial.co.za.secure-id.xyz"))
    assert [(k, c) for _, k, c, _ in got] == [("acmefinancial.co.za.secure-id.xyz", "subdomain_abuse")]


def test_the_customers_own_domains_and_unrelated_names_never_match():
    matcher = bs.StreamMatcher([brand(official=("acmefinancial.co.za", "acmefin.com"))])
    assert matcher.match(sighting("www.acmefinancial.co.za", "mail.acmefin.com", "acmefin.com", "unrelated-shop.net", "example.org")) == []


def test_each_brand_gets_its_own_hits_and_an_unrelated_brand_gets_none():
    a, c = brand("pa", ("acmefinancial",), ("acmefinancial.co.za",)), brand("pc", ("capitec",), ("capitec.co.za",))
    matcher = bs.StreamMatcher([a, c])
    hits = matcher.match(sighting("acmefinancial-login.com", "capitec-verify.net", "weather.example"))
    assert sorted((b.profile_id, k) for b, k, _, _ in hits) == [("pa", "acmefinancial-login.com"), ("pc", "capitec-verify.net")]


def test_one_cert_naming_the_same_apex_twice_is_one_hit():
    matcher = bs.StreamMatcher([brand()])
    assert len(matcher.match(sighting("acmefinancial-pay.xyz", "www.acmefinancial-pay.xyz", "m.acmefinancial-pay.xyz"))) == 1


def test_names_per_certificate_that_are_evaluated_are_capped(monkeypatch):
    monkeypatch.setattr(bs, "MAX_NAMES_PER_CERT_EVALUATED", 2)
    matcher = bs.StreamMatcher([brand()])
    assert matcher.match(sighting("x1.example.com", "x2.example.com", "acmefinancial-late.xyz")) == []


def test_no_brands_means_no_matches_and_short_tokens_are_ignored():
    assert bs.StreamMatcher([]).match(sighting("anything.com")) == []
    assert bs.StreamMatcher([brand(tokens=("ab",))]).match(sighting("ab-login.com")) == []


def test_windows():
    assert bs.windows("Ab-Cd1") == {"abc", "bcd", "cd1"} and bs.windows("ab") == set()


# ── buffering ──

def ct(issued="2026-10-02T10:00:00+00:00", hosts=None, cert="c1"):
    return {"issued_at": issued, "hosts": dict(hosts or {}), "cert_ids": [cert], "issuer": "LE"}


def test_buffer_merges_repeats_of_a_name_and_keeps_the_newest_time():
    buf, b = bs.HitBuffer(), brand()
    buf.add(b, "x.xyz", "", ct("2026-10-02T10:00:00+00:00", {"a.x.xyz": "2026-10-02T10:00:00+00:00"}, "c1"))
    buf.add(b, "x.xyz", "", ct("2026-10-02T11:00:00+00:00", {"a.x.xyz": "2026-10-02T11:00:00+00:00", "b.x.xyz": "2026-10-02T11:00:00+00:00"}, "c2"))
    assert len(buf) == 1
    meta = buf.drain()["p1"]["x.xyz"]
    assert meta["ct"]["issued_at"] == "2026-10-02T11:00:00+00:00" and meta["ct"]["cert_ids"] == ["c1", "c2"]
    assert meta["ct"]["hosts"]["a.x.xyz"] == "2026-10-02T11:00:00+00:00" and set(meta["ct"]["hosts"]) == {"a.x.xyz", "b.x.xyz"}
    assert meta["sources"] == ["ct_stream"] and meta["class"] is None and len(buf) == 0


def test_buffer_caps_hosts_certificates_and_pending_names(monkeypatch):
    monkeypatch.setattr(bs, "MAX_HOSTS_PER_CANDIDATE", 2)
    monkeypatch.setattr(bs, "MAX_CERTS_PER_CANDIDATE", 2)
    monkeypatch.setattr(bs, "MAX_PENDING_PER_PROFILE", 2)
    buf, b = bs.HitBuffer(), brand()
    for i in range(4):
        buf.add(b, "x.xyz", "", ct(hosts={f"h{i}.x.xyz": "2026-10-02T10:00:00+00:00"}, cert=f"c{i}"))
    meta = buf.per_profile["p1"]["x.xyz"]["ct"]
    assert len(meta["hosts"]) == 2 and meta["cert_ids"] == ["c0", "c1"]
    buf.add(b, "y.xyz", "", ct())
    buf.add(b, "z.xyz", "", ct())                                  # a third distinct name: over the cap
    assert len(buf) == 2 and buf.dropped == 1


def test_buffer_carries_the_subdomain_abuse_class():
    buf = bs.HitBuffer()
    buf.add(brand(), "acmefinancial.co.za.evil.xyz", "subdomain_abuse", ct())
    assert buf.drain()["p1"]["acmefinancial.co.za.evil.xyz"]["class"] == "subdomain_abuse"


def test_buffers_from_different_brands_are_separate():
    buf = bs.HitBuffer()
    buf.add(brand("a"), "x.xyz", "", ct())
    buf.add(brand("b"), "x.xyz", "", ct())
    assert set(buf.drain()) == {"a", "b"}


# ── do-not-repeat memory ──

def test_recent_names_are_remembered_for_the_ttl_per_brand():
    r = bs.RecentNames(ttl=timedelta(hours=1))
    t0 = datetime(2026, 10, 2, 12, tzinfo=timezone.utc)
    assert r.fresh("p1", "x.xyz", t0) is True
    assert r.fresh("p1", "x.xyz", t0 + timedelta(minutes=59)) is False
    assert r.fresh("p2", "x.xyz", t0) is True                                # another brand's lead is separate
    assert r.fresh("p1", "x.xyz", t0 + timedelta(minutes=61)) is True        # expired


def test_recent_names_memory_is_bounded():
    r = bs.RecentNames(limit=3)
    for i in range(10):
        r.fresh("p", f"n{i}.xyz")
    assert len(r._seen) == 3


# ── health registration ──

def test_the_stream_is_an_optional_health_source():
    assert bs.STREAM_SOURCE in brand_sources.EXTRA_HEALTH_SOURCES and bs.STREAM_SOURCE.optional is True
    assert bs.STREAM_SOURCE.name == "ct_stream"
