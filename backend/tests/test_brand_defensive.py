import uuid
from collections import Counter

from app.models import BrandProfile
from app.services import brand_defensive as bd
from tests.test_brand_graph import cand
from tests.test_brand_guard_api import _pro_profile


def test_a_visually_identical_name_outranks_a_weak_class_on_the_same_suffix():
    a, _ = bd.score("acmе.com", "homoglyph", "com", Counter(), Counter())
    b, _ = bd.score("acmf.com", "bitsquat", "com", Counter(), Counter())
    assert a > b


def test_the_brands_own_suffix_counts_as_the_best_suffix():
    own, why = bd.score("acme.xyz", "typo", "xyz", Counter(), Counter())
    other, _ = bd.score("acme.xyz", "typo", "com", Counter(), Counter())
    assert own > other and "same suffix as the brand" in why[1]


def test_what_is_already_used_against_the_brand_raises_the_score_but_only_up_to_a_cap():
    base, _ = bd.score("acme-x.top", "combosquat", "com", Counter(), Counter())
    boosted, why = bd.score("acme-x.top", "combosquat", "com", Counter({"combosquat": 1}), Counter({"top": 1}))
    capped, _ = bd.score("acme-x.top", "combosquat", "com", Counter({"combosquat": 99}), Counter({"top": 99}))
    assert boosted > base and any("already flagged" in w for w in why) and any("already use .top" in w for w in why)
    assert round(capped - base, 3) == bd.BOOST_CAP


def test_two_part_suffixes_are_recognised():
    assert bd._tld("acme.co.za") == "co.za" and bd._tld("acme.com") == "com" and bd._tld("acme.unknown.xyz") == "xyz"


def test_shortlist_skips_known_names_and_classes_with_no_prior_and_sorts_best_first():
    gen = {"acme.net": "tld_swap", "acme-pay.com": "combosquat", "known.com": "typo", "x.acme.com": "subdomain_abuse", "acm.com": "omission"}
    out = bd.shortlist(gen, {"known.com"}, "com", [])
    names = [r["domain"] for r in out]
    assert "known.com" not in names and "x.acme.com" not in names and names == sorted(names, key=lambda n: (-next(r["score"] for r in out if r["domain"] == n), n))
    assert out[0]["reasons"]


def test_shortlist_respects_its_limit():
    gen = {f"acme{i}.com": "typo" for i in range(100)}
    assert len(bd.shortlist(gen, set(), "com", [], limit=10)) == 10


def test_advise_keeps_only_names_dns_says_are_unregistered_and_counts_the_rest():
    ranked = [{"domain": f"{c}.com", "class": "typo", "score": s, "reasons": []} for c, s in (("a", 3), ("b", 2), ("c", 1), ("d", 0.5))]
    r = bd.advise(ranked, {"a.com": True, "b.com": False, "c.com": None, "d.com": False}, limit=5)
    assert [n["domain"] for n in r["names"]] == ["b.com", "d.com"] and (r["checked"], r["taken"], r["unknown"]) == (4, 1, 1)
    assert "confirm with your registrar" in r["names"][0]["availability"] and "not a measurement" in r["basis"]
    assert len(bd.advise(ranked, {x["domain"]: False for x in ranked}, limit=2)["names"]) == 2


async def test_api_ranks_unregistered_names_excludes_tracked_ones_and_never_registers_anything(auth_client, db_session, monkeypatch):
    from app.services import brand_discovery_service as disc
    from app.services import brand_guard_service as svc
    client, tenant = auth_client
    pid = await _pro_profile(client, tenant, db_session)
    profile = await db_session.get(BrandProfile, uuid.UUID(pid))
    db_session.add(cand(profile, "tracked.com", status="confirmed"))
    await db_session.commit()
    monkeypatch.setattr(disc, "generate_candidates", lambda *a, **k: {"tracked.com": "typo", "free-one.com": "typo", "taken-one.com": "typo", "free-two.net": "tld_swap"})
    seen = []

    async def fake_dns(d):
        seen.append(d)
        return {"registered": {"free-one.com": False, "free-two.net": False, "taken-one.com": True}[d]}
    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    r = (await client.get(f"/brand-guard/defensive-registrations?profile_id={pid}")).json()
    assert {n["domain"] for n in r["names"]} == {"free-one.com", "free-two.net"} and r["taken"] == 1 and "tracked.com" not in seen
    assert all("registrar" in n["availability"] for n in r["names"])


async def test_api_is_tenant_scoped(auth_client):
    client, _ = auth_client
    assert (await client.get(f"/brand-guard/defensive-registrations?profile_id={uuid.uuid4()}")).status_code == 404
