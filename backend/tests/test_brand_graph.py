"""The evidence graph, links and guilt propagation (app/services/brand_graph.py): pure rules, persistence, rescoring, and the API."""
import math
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import BrandCandidate, BrandGraphEdge, BrandGraphNode, BrandProfile, CandidateEvidence
from app.services import brand_graph as bg, brand_guard_service as svc
from app.services.brand_scoring_service import assess_candidate
from tests.factories import make_domain, make_tenant
from tests.test_brand_guard_api import _Borrowed

NOW = datetime(2026, 10, 2, 12, tzinfo=timezone.utc)


def rec(domain, **enrichment):
    return {"domain": domain, "enrichment": enrichment}


# ── extraction ──

def test_extract_makes_a_node_per_thing_and_a_typed_edge_per_observation():
    nodes, edges = bg.extract([rec("a-x.xyz", a=["203.0.113.7", "203.0.113.7"], ns=["NS1.Cheap.example."], mx=["mx.cheap.example"], cert_ids=["abc123"], cert_issuer="LE",
                                    registration={"registrar": "CheapHost"})])
    assert set(nodes) == {("domain", "a-x.xyz"), ("ip", "203.0.113.7"), ("nameserver", "ns1.cheap.example"), ("mail_host", "mx.cheap.example"),
                          ("certificate", "abc123"), ("registrar", "cheaphost")}
    assert sorted((dst[0], kind) for _, dst, kind, _ in edges) == sorted([("ip", "resolves_to"), ("nameserver", "uses_nameserver"), ("mail_host", "mails_via"),
                                                                          ("certificate", "covered_by"), ("registrar", "registered_via")])
    assert all(src == ("domain", "a-x.xyz") for src, _, _, _ in edges)


def test_extract_caps_each_kind_and_ignores_empty_values():
    ips = [f"203.0.113.{i}" for i in range(20)]
    nodes, _ = bg.extract([rec("a.xyz", a=ips + ["", None], ns=[], mx=None)])
    assert len([n for n in nodes if n[0] == "ip"]) == bg.MAX_PER_KIND["ip"]


def test_a_registration_batch_is_one_node_named_after_its_smallest_member():
    hint = lambda sibs: {"kind": "registration_batch", "siblings": sibs, "data": {"kind": "registration_batch"}}   # noqa: E731
    nodes, edges = bg.extract([rec("b.xyz", clusters=[hint(["a.xyz", "c.xyz"])]), rec("a.xyz", clusters=[hint(["b.xyz", "c.xyz"])]), rec("c.xyz", clusters=[hint(["a.xyz", "b.xyz"])])])
    assert [n for n in nodes if n[0] == "batch"] == [("batch", "batch:a.xyz")]
    assert sum(1 for _, dst, _, _ in edges if dst[0] == "batch") == 3


# ── links ──

def graph(*recs):
    return bg.extract(list(recs))[1]


def test_the_documented_assumptions_are_pinned():
    """These are hand-set assumptions (nothing measures them yet). Changing one must be a deliberate edit of this test and the docs."""
    assert (bg.HUB_LIMIT, bg.DECAY_PER_HOP, bg.MAX_HOPS, bg.HALF_LIFE_DAYS, bg.GUILT_POINTS) == (25, 0.6, 3, 45.0, 30.0)
    assert {k: v[1] for k, v in bg.LINK_KINDS.items()} == {"certificate": 0.9, "ip": 0.7, "nameserver": 0.5, "mail_host": 0.5, "batch": 0.3}


def test_a_link_gets_weaker_as_more_domains_share_the_node():
    two = graph(rec("a.xyz", a=["1.1.1.1"]), rec("b.xyz", a=["1.1.1.1"]))
    ten = graph(*[rec(f"d{i}.xyz", a=["1.1.1.1"]) for i in range(10)])
    w2 = bg.link_weights(two)[1][("ip", "1.1.1.1")]
    w10 = bg.link_weights(ten)[1][("ip", "1.1.1.1")]
    assert w2 == pytest.approx(0.7) and w10 == pytest.approx(0.7 / (1 + math.log(9))) and w10 < w2


def test_a_node_shared_by_too_many_domains_is_not_a_link_and_a_registrar_never_is():
    hub = graph(*[rec(f"d{i}.xyz", ns=["ns.big.example"]) for i in range(bg.HUB_LIMIT + 1)])
    assert bg.link_weights(hub) == ({}, {})
    edge = graph(*[rec(f"d{i}.xyz", ns=["ns.big.example"]) for i in range(bg.HUB_LIMIT)])
    assert ("nameserver", "ns.big.example") in bg.link_weights(edge)[0]
    reg = graph(rec("a.xyz", registration={"registrar": "R"}), rec("b.xyz", registration={"registrar": "R"}))
    assert bg.link_weights(reg) == ({}, {})


def test_a_certificate_links_more_strongly_than_a_nameserver_or_a_batch():
    base = {k: bg.LINK_KINDS[k][1] for k in bg.LINK_KINDS}
    assert base["certificate"] > base["ip"] > base["nameserver"] == base["mail_host"] > base["batch"]


# ── seeds and decay ──

@pytest.mark.parametrize("kw,expected", [
    (dict(status="confirmed", reviewed=True, feeds=None, reported=None), 1.0), (dict(status="takedown", reviewed=True, feeds=None, reported=None), 1.0),
    (dict(status="confirmed", reviewed=False, feeds=None, reported=None), 0.0),
    (dict(status="suspicious", reviewed=False, feeds=[{"feed": "phishunt"}], reported=None), 0.8),
    (dict(status="suspicious", reviewed=False, feeds=[{"feed": "urlhaus", "same_site": True}], reported=None), 0.0),
    (dict(status="suspicious", reviewed=False, feeds=None, reported=[{"disposition": "confirmed_malicious"}]), 1.0),
    (dict(status="suspicious", reviewed=False, feeds=None, reported=[{"disposition": "new"}]), 0.4),
    (dict(status="suspicious", reviewed=False, feeds=None, reported=None), 0.0),
])
def test_seed_strength(kw, expected):
    assert bg.seed_strength(**kw) == expected


def test_a_seed_halves_every_half_life_and_never_grows():
    assert bg.decayed(1.0, 0) == 1.0 and bg.decayed(1.0, bg.HALF_LIFE_DAYS) == pytest.approx(0.5) and bg.decayed(1.0, 2 * bg.HALF_LIFE_DAYS) == pytest.approx(0.25)
    assert bg.decayed(0.8, -5) == 0.8


# ── propagation ──

def chain():
    """seed.xyz -(cert)- a.xyz -(ip)- b.xyz -(ns)- c.xyz -(mx)- d.xyz"""
    return graph(rec("seed.xyz", cert_ids=["c1"]), rec("a.xyz", cert_ids=["c1"], a=["1.1.1.1"]), rec("b.xyz", a=["1.1.1.1"], ns=["ns.x"]), rec("c.xyz", ns=["ns.x"], mx=["mx.x"]),
                 rec("d.xyz", mx=["mx.x"]), rec("loner.xyz", a=["9.9.9.9"]))


ALL = {"seed.xyz", "a.xyz", "b.xyz", "c.xyz", "d.xyz", "loner.xyz"}


def test_suspicion_flows_along_shared_infrastructure_with_decay_per_hop_and_weight_per_link():
    g = bg.propagate_guilt({"seed.xyz": 1.0}, chain(), ALL)
    assert g["a.xyz"]["score"] == pytest.approx(0.9 * bg.DECAY_PER_HOP, abs=0.001) and g["a.xyz"]["hops"] == 1 and g["a.xyz"]["seed"] == "seed.xyz"
    assert g["b.xyz"]["score"] == pytest.approx(0.9 * 0.7 * bg.DECAY_PER_HOP ** 2, abs=0.001) and g["b.xyz"]["hops"] == 2
    assert [p["via_kind"] for p in g["b.xyz"]["path"]] == ["certificate", "ip"] and [p["to"] for p in g["b.xyz"]["path"]] == ["a.xyz", "b.xyz"]
    assert g["a.xyz"]["score"] > g["b.xyz"]["score"] > g["c.xyz"]["score"]


def test_it_stops_after_the_maximum_number_of_hops_and_never_reaches_unlinked_domains():
    g = bg.propagate_guilt({"seed.xyz": 1.0}, chain(), ALL)
    assert "d.xyz" not in g and bg.MAX_HOPS == 3 and "loner.xyz" not in g and "seed.xyz" not in g


def test_a_seed_is_never_overwritten_and_two_seeds_each_keep_their_own_strength():
    g = bg.propagate_guilt({"seed.xyz": 1.0, "c.xyz": 0.5}, chain(), ALL)
    assert "c.xyz" not in g                                                    # c is itself a seed, so it is not "guilty by link"
    assert g["b.xyz"]["seed"] == "c.xyz" or g["b.xyz"]["seed"] == "seed.xyz"


def test_a_weaker_seed_next_to_a_stronger_one_stays_a_seed_and_is_not_reported_as_guilty():
    g = bg.propagate_guilt({"seed.xyz": 1.0, "a.xyz": 0.1}, chain(), ALL)
    assert "a.xyz" not in g and "seed.xyz" not in g


def test_the_strongest_path_wins_when_there_are_several():
    edges = graph(rec("seed.xyz", cert_ids=["c1"], ns=["ns.x"]), rec("t.xyz", cert_ids=["c1"], ns=["ns.x"]))       # linked by a certificate AND a nameserver
    g = bg.propagate_guilt({"seed.xyz": 1.0}, edges, {"seed.xyz", "t.xyz"})
    assert g["t.xyz"]["path"][0]["via_kind"] == "certificate"


def test_domains_a_person_cleared_neither_carry_nor_receive_suspicion():
    g = bg.propagate_guilt({"seed.xyz": 1.0}, chain(), ALL - {"a.xyz"})
    assert "a.xyz" not in g and "b.xyz" not in g                                   # the only bridge was cleared


def test_a_weak_seed_gives_weaker_suspicion_and_a_tiny_one_gives_none():
    strong = bg.propagate_guilt({"seed.xyz": 1.0}, chain(), ALL)["a.xyz"]["score"]
    weak = bg.propagate_guilt({"seed.xyz": 0.4}, chain(), ALL)["a.xyz"]["score"]
    assert weak == pytest.approx(strong * 0.4, abs=0.002)
    assert bg.propagate_guilt({"seed.xyz": 0.001}, chain(), ALL) == {}


def test_shared_hub_infrastructure_carries_no_suspicion():
    edges = graph(rec("seed.xyz", ns=["ns.big"]), *[rec(f"d{i}.xyz", ns=["ns.big"]) for i in range(bg.HUB_LIMIT + 5)])
    assert bg.propagate_guilt({"seed.xyz": 1.0}, edges, {"seed.xyz"} | {f"d{i}.xyz" for i in range(bg.HUB_LIMIT + 5)}) == {}


# ── the evidence line and the scorer ──

def test_the_guilt_signal_is_an_assumption_weighted_line_that_names_the_path():
    g = bg.propagate_guilt({"seed.xyz": 1.0}, chain(), ALL)["b.xyz"]
    s = bg.guilt_signal(g)
    assert s["signal"] == "linked_to_known_bad" and s["weight"] == pytest.approx(bg.GUILT_POINTS * g["score"], abs=0.06)
    assert "seed.xyz" in s["summary"] and "assumption" in s["summary"] and s["data"]["basis"] == "expert" and len(s["data"]["path"]) == 2
    assert bg.guilt_signal(None) is None and bg.guilt_signal({"score": 0}) is None


def test_the_scorer_adds_the_line_and_it_raises_abuse():
    base = dict(primary_domain="acmefinancial.co.za", official_domains=[], brand_tokens=["acmefinancial"], discovery_class=None)
    plain = assess_candidate("acmefinancial-pay.xyz", enrichment={"has_a": True}, **base)
    g = bg.propagate_guilt({"seed.xyz": 1.0}, chain(), ALL)["a.xyz"]
    linked = assess_candidate("acmefinancial-pay.xyz", enrichment={"has_a": True, "guilt": g}, **base)
    assert linked.abuse_score == pytest.approx(plain.abuse_score + bg.guilt_signal(g)["weight"], abs=0.2)
    assert "linked_to_known_bad" in {s.signal for s in linked.signals} and "linked_to_known_bad" not in {s.signal for s in plain.signals}


# ── persistence ──

async def _brand(db_session, name="acmefinancial.co.za"):
    tenant = await make_tenant(db_session, name=f"T-{uuid.uuid4().hex[:6]}", plan="pro")
    domain = await make_domain(db_session, tenant, name=name)
    domain.ownership_verified = True
    profile = BrandProfile(id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, brand_name="Acme Financial", keywords=[], official_domains=[])
    db_session.add(profile)
    await db_session.commit()
    return tenant, profile


def cand(profile, domain, status="monitoring", reviewed=False, feeds=None, **enrichment):
    e = dict(enrichment)
    if feeds:
        e["feeds"] = feeds
    return BrandCandidate(id=uuid.uuid4(), tenant_id=profile.tenant_id, profile_id=profile.id, candidate_domain=domain, status=status, stage="resolving", enrichment=e,
                          first_seen_at=NOW - timedelta(days=1), reviewed_at=(datetime.now(timezone.utc) if reviewed else None), reviewed_by_user_id=None)


@pytest.mark.asyncio
async def test_sync_persists_nodes_and_edges_idempotently_and_removes_what_is_no_longer_observed(db_session):
    _, profile = await _brand(db_session)
    a, b = cand(profile, "acme-a.xyz", a=["1.1.1.1"], ns=["ns.x"]), cand(profile, "acme-b.xyz", a=["1.1.1.1"])
    db_session.add_all([a, b])
    await db_session.commit()
    first = await bg.sync(db_session, profile)
    assert first["nodes"] == 4 and first["edges"] == 3                      # 2 domains + 1 ip + 1 nameserver; 3 observations
    again = await bg.sync(db_session, profile)
    assert (again["nodes"], again["edges"]) == (4, 3)
    assert len((await db_session.execute(select(BrandGraphNode))).scalars().all()) == 4 and len((await db_session.execute(select(BrandGraphEdge))).scalars().all()) == 3
    a.enrichment = {"a": ["1.1.1.1"]}                                       # the nameserver is no longer observed
    await db_session.commit()
    await bg.sync(db_session, profile)
    kinds = sorted(n.kind for n in (await db_session.execute(select(BrandGraphNode))).scalars().all())
    assert kinds == ["domain", "domain", "ip"]                              # the orphaned nameserver node is gone too
    assert len((await db_session.execute(select(BrandGraphEdge))).scalars().all()) == 2                # ...and so is the edge that no longer holds


@pytest.mark.asyncio
async def test_an_edge_that_no_longer_holds_is_removed_even_when_both_of_its_nodes_remain(db_session):
    _, profile = await _brand(db_session)
    a, b = cand(profile, "acme-a.xyz", a=["1.1.1.1"]), cand(profile, "acme-b.xyz", a=["1.1.1.1"])
    db_session.add_all([a, b])
    await db_session.commit()
    await bg.sync(db_session, profile)
    a.enrichment = {}
    await db_session.commit()
    await bg.sync(db_session, profile)
    edges = (await db_session.execute(select(BrandGraphEdge))).scalars().all()
    assert len(edges) == 1 and len((await db_session.execute(select(BrandGraphNode))).scalars().all()) == 3      # a, b, and the ip b still uses


@pytest.mark.asyncio
async def test_edges_keep_their_first_seen_time_across_a_rebuild(db_session):
    _, profile = await _brand(db_session)
    db_session.add_all([cand(profile, "acme-a.xyz", a=["1.1.1.1"]), cand(profile, "acme-b.xyz", a=["1.1.1.1"])])
    await db_session.commit()
    await bg.sync(db_session, profile)
    edge = (await db_session.execute(select(BrandGraphEdge))).scalars().first()
    first = edge.first_seen_at
    await bg.sync(db_session, profile)
    await db_session.refresh(edge)
    assert edge.first_seen_at == first and edge.last_seen_at >= first


@pytest.mark.asyncio
async def test_sync_writes_guilt_onto_linked_candidates_and_clears_it_when_the_seed_goes(db_session):
    _, profile = await _brand(db_session)
    seed = cand(profile, "acme-seed.xyz", status="confirmed", reviewed=True, cert_ids=["c1"])
    other = cand(profile, "acme-other.xyz", cert_ids=["c1"])
    far = cand(profile, "acme-far.xyz", a=["9.9.9.9"])
    db_session.add_all([seed, other, far])
    await db_session.commit()
    out = await bg.sync(db_session, profile)
    assert out["seeds"] == 1 and out["guilty"] == 1 and out["changed"] == 1
    g = other.enrichment["guilt"]
    assert g["seed"] == "acme-seed.xyz" and g["hops"] == 1 and g["score"] > 0.4 and "guilt" not in far.enrichment and "guilt" not in seed.enrichment
    seed.status = "false_positive"                                           # the person changes their mind
    await db_session.commit()
    await bg.sync(db_session, profile)
    assert "guilt" not in other.enrichment


@pytest.mark.asyncio
async def test_a_persons_confirmation_counts_from_the_day_they_made_it_not_from_first_sighting(db_session):
    _, profile = await _brand(db_session)
    seed = cand(profile, "acme-seed.xyz", status="confirmed", reviewed=True, cert_ids=["c1"])
    seed.first_seen_at = NOW - timedelta(days=400)                              # seen long ago, confirmed just now
    other = cand(profile, "acme-other.xyz", cert_ids=["c1"])
    db_session.add_all([seed, other])
    await db_session.commit()
    await bg.sync(db_session, profile)
    assert other.enrichment["guilt"]["score"] > 0.5


@pytest.mark.asyncio
async def test_a_cleared_candidate_neither_receives_nor_carries_guilt(db_session):
    _, profile = await _brand(db_session)
    seed = cand(profile, "acme-seed.xyz", status="confirmed", reviewed=True, cert_ids=["c1"])
    cleared = cand(profile, "acme-cleared.xyz", status="partner", reviewed=True, cert_ids=["c1"])
    db_session.add_all([seed, cleared])
    await db_session.commit()
    out = await bg.sync(db_session, profile)
    assert out["guilty"] == 0 and "guilt" not in cleared.enrichment


@pytest.mark.asyncio
async def test_a_feed_listing_seeds_without_a_person_and_fades_with_age(db_session):
    _, profile = await _brand(db_session)
    listed = cand(profile, "acme-listed.xyz", feeds=[{"feed": "phishunt", "same_site": False}], cert_ids=["c1"])
    other = cand(profile, "acme-other.xyz", cert_ids=["c1"])
    db_session.add_all([listed, other])
    await db_session.commit()
    await bg.sync(db_session, profile)
    fresh = other.enrichment["guilt"]["score"]
    listed.first_seen_at = NOW - timedelta(days=200)
    await db_session.commit()
    await bg.sync(db_session, profile)
    old = other.enrichment.get("guilt", {"score": 0})["score"]
    assert old < fresh


@pytest.mark.asyncio
async def test_sync_only_touches_its_own_brand(db_session):
    _, profile = await _brand(db_session)
    _, other = await _brand(db_session, "otherbrand.co.za")
    db_session.add_all([cand(other, "o-a.xyz", a=["1.1.1.1"]), cand(other, "o-b.xyz", a=["1.1.1.1"])])
    await db_session.commit()
    await bg.sync(db_session, profile)
    assert (await db_session.execute(select(BrandGraphNode))).scalars().all() == []


# ── rescoring and the API ──

@pytest.fixture(autouse=True)
def _runs_use_test_session(db_session, monkeypatch):
    monkeypatch.setattr(svc, "_session_factory", lambda: _Borrowed(db_session))


@pytest.mark.asyncio
async def test_rescoring_applies_guilt_now_and_keeps_a_persons_decision(db_session):
    _, profile = await _brand(db_session)
    seed = cand(profile, "acmefinancial-seed.xyz", status="confirmed", reviewed=True, cert_ids=["c1"], a=["1.1.1.1"])
    other = cand(profile, "acmefinancial-pay.xyz", cert_ids=["c1"], a=["1.1.1.1"])
    decided = cand(profile, "acmefinancial-mine.xyz", status="partner", reviewed=True, cert_ids=["c1"])
    db_session.add_all([seed, other, decided])
    await db_session.commit()
    before = (await svc.rescore_profile(db_session, profile, {"acmefinancial-pay.xyz"}), other.abuse_score)[1]
    out = await svc.sync_graph(db_session, profile)
    assert out["rescored"] >= 1
    await db_session.refresh(other)
    assert other.abuse_score > before
    ev = (await db_session.execute(select(CandidateEvidence).where(CandidateEvidence.candidate_id == other.id))).scalars().all()
    line = next(e for e in ev if e.signal == "linked_to_known_bad")
    assert line.data["seed"] == "acmefinancial-seed.xyz" and line.weight > 0
    await db_session.refresh(decided)
    assert decided.status == "partner"


async def test_confirming_one_lookalike_through_the_api_raises_the_linked_ones_at_once(auth_client, db_session):
    from tests.test_brand_guard_api import _pro_profile
    client, tenant = auth_client
    profile = await db_session.get(BrandProfile, uuid.UUID(await _pro_profile(client, tenant, db_session)))
    a = cand(profile, "acmefinancial-a.xyz", status="suspicious", cert_ids=["c1"], a=["1.1.1.1"])
    b = cand(profile, "acmefinancial-b.xyz", status="monitoring", cert_ids=["c1"], a=["1.1.1.1"])
    db_session.add_all([a, b])
    await db_session.commit()
    await svc.rescore_profile(db_session, profile)
    await db_session.commit()
    await db_session.refresh(b)
    before = b.abuse_score
    resp = await client.patch(f"/brand-guard/candidates/{a.id}/status", json={"status": "confirmed"})
    assert resp.status_code == 200
    await db_session.refresh(b)
    assert b.abuse_score > before and b.enrichment["guilt"]["seed"] == "acmefinancial-a.xyz"
    detail = (await client.get(f"/brand-guard/candidates/{b.id}")).json()
    assert "linked_to_known_bad" in {e["signal"] for e in detail["evidence"]}


# ── what explains a group ──

def test_the_subgraph_lists_only_infrastructure_that_links_two_or_more_members_strongest_first():
    edges = graph(rec("a.xyz", cert_ids=["c1"], a=["1.1.1.1"], ns=["ns.x"]), rec("b.xyz", cert_ids=["c1"], a=["1.1.1.1"], ns=["ns.y"]),
                  rec("c.xyz", a=["1.1.1.1"]), rec("outsider.xyz", ns=["ns.x"]))
    sg = bg.subgraph(edges, {"a.xyz", "b.xyz", "c.xyz"})
    assert [s["id"] for s in sg["shared"]] == ["certificate:c1", "ip:1.1.1.1"]                    # ns.x is shared with someone outside the group: not an in-group link
    ip = next(s for s in sg["shared"] if s["kind"] == "ip")
    assert ip["members"] == ["a.xyz", "b.xyz", "c.xyz"] and ip["degree"] == 3 and 0 < ip["weight"] < 0.7
    assert {(l["domain"], l["node"]) for l in sg["links"]} >= {("a.xyz", "certificate:c1"), ("c.xyz", "ip:1.1.1.1")} and len(sg["links"]) == 5
    assert sg["domains"] == ["a.xyz", "b.xyz", "c.xyz"]


def test_a_batch_node_is_labelled_for_people_not_by_its_internal_key():
    hint = {"kind": "registration_batch", "siblings": ["b.xyz"], "data": {"kind": "registration_batch"}}
    edges = graph(rec("a.xyz", clusters=[hint]), rec("b.xyz", clusters=[{**hint, "siblings": ["a.xyz"]}]))
    assert bg.subgraph(edges, {"a.xyz", "b.xyz"})["shared"][0]["label"] == "registered together"


async def test_api_campaign_detail_explains_why_the_members_are_grouped(auth_client, db_session):
    from app.services import brand_campaigns as bc
    from tests.test_brand_guard_api import _pro_profile
    client, tenant = auth_client
    profile = await db_session.get(BrandProfile, uuid.UUID(await _pro_profile(client, tenant, db_session)))
    names = ["acme-a.xyz", "acme-b.xyz", "acme-c.xyz"]
    hints = lambda n: [{"signal": "shared_server_cluster", "kind": "shared_server", "weight": 6.0, "siblings": [x for x in names if x != n], "data": {"kind": "shared_server", "value": "1.1.1.1"}}]  # noqa: E731
    db_session.add_all([cand(profile, n, a=["1.1.1.1"], clusters=hints(n)) for n in names])
    await db_session.commit()
    await bg.sync(db_session, profile)
    await bc.sync(db_session, profile, ["acme"])
    await db_session.commit()
    cid = (await client.get("/brand-guard/campaigns")).json()[0]["id"]
    g = (await client.get(f"/brand-guard/campaigns/{cid}")).json()["graph"]
    assert [s["id"] for s in g["shared"]] == ["ip:1.1.1.1"] and g["shared"][0]["members"] == names and len(g["links"]) == 3
