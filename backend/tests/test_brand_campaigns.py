"""Brand Guard campaigns: grouping rules (pure), the stored groups (sync), and the API."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import BrandCampaign, BrandCandidate, BrandProfile
from app.services import brand_campaigns as bc, brand_guard_service as svc
from tests.factories import make_domain, make_tenant
from tests.test_brand_guard_api import _Borrowed, _fake_network, _pro_profile, _scan

NOW = datetime(2026, 10, 2, 12, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _background_runs_use_test_session(db_session, monkeypatch):
    monkeypatch.setattr(svc, "_session_factory", lambda: _Borrowed(db_session))


def hint(kind, siblings, value=None, weight=8.0):
    return {"signal": kind, "kind": kind, "weight": weight, "siblings": siblings, "data": {"kind": kind, "value": value, "siblings": siblings}}


def member(domain, clusters=(), registered_at=None, eligible=True, seen=NOW):
    return {"domain": domain, "clusters": list(clusters), "registered_at": registered_at, "first_seen_at": seen, "eligible": eligible}


def trio(kinds):
    """Three members linked by each of `kinds` (a registration batch needs no value; the others carry one)."""
    values = {"registration_batch": None, "shared_certificate": "123", "shared_nameservers": ["ns1.x.com", "ns2.x.com"], "shared_server": "203.0.113.5"}
    names = ["acme-a.xyz", "acme-b.xyz", "acme-c.xyz"]
    return [member(n, [hint(k, [x for x in names if x != n], values[k]) for k in kinds], registered_at=f"2026-09-29T21:0{i}:00+00:00")
            for i, n in enumerate(names)]


# ── grouping rules ──

@pytest.mark.parametrize("kinds,verdict", [
    (["registration_batch"], "not_enough"), (["registration_batch", "shared_nameservers"], "possibly_related"),
    (["registration_batch", "shared_nameservers", "shared_server"], "likely_one_actor"),
    (["shared_certificate", "shared_nameservers", "shared_server", "registration_batch"], "likely_one_actor"),
])
def test_verdict_counts_distinct_kinds_of_shared_fact(kinds, verdict):
    groups = bc.build_groups(trio(kinds))
    assert len(groups) == 1 and groups[0]["verdict"] == verdict and len(groups[0]["domains"]) == 3
    assert {f["kind"] for f in groups[0]["facts"]} == set(kinds)


def test_two_hints_of_the_same_kind_are_one_kind():
    members = trio(["shared_server"])
    members[0]["clusters"].append(hint("shared_server", ["acme-b.xyz"], "198.51.100.9"))
    assert bc.build_groups(members)[0]["verdict"] == "not_enough"


def test_a_benign_member_makes_it_probably_yours_whatever_else_matches():
    members = trio(["registration_batch", "shared_nameservers", "shared_server"])
    members[1]["clusters"][0]["weight"] = 0.0
    assert bc.build_groups(members)[0]["verdict"] == "probably_yours"


def test_facts_count_who_has_each_one_and_carry_their_values():
    members = trio(["shared_nameservers"])
    members[2]["clusters"] = []                                # the third is only linked in by the others
    members.append(member("acme-d.xyz", [hint("shared_server", ["acme-a.xyz"], "203.0.113.5")]))
    group = bc.build_groups(members)[0]
    ns = next(f for f in group["facts"] if f["kind"] == "shared_nameservers")
    assert ns["value"] == ["ns1.x.com", "ns2.x.com"] and ns["count"] == 2 and ns["of"] == 4
    server = next(f for f in group["facts"] if f["kind"] == "shared_server")
    assert server["value"] == "203.0.113.5" and server["count"] == 1


def test_registration_batch_fact_shows_the_date_range():
    group = bc.build_groups(trio(["registration_batch"]))[0]
    batch = group["facts"][0]
    assert batch["value"] == {"from": "2026-09-29T21:00:00+00:00", "to": "2026-09-29T21:02:00+00:00"}


def test_different_values_of_one_kind_are_separate_facts():
    a = [member("a-1.xyz", [hint("shared_server", ["a-2.xyz"], "1.1.1.1")]), member("a-2.xyz", [hint("shared_server", ["a-1.xyz"], "1.1.1.1")])]
    b = [member("b-1.xyz", [hint("shared_server", ["b-2.xyz"], "2.2.2.2")]), member("b-2.xyz", [hint("shared_server", ["b-1.xyz"], "2.2.2.2")])]
    groups = bc.build_groups(a + b)
    assert len(groups) == 2 and {g["facts"][0]["value"] for g in groups} == {"1.1.1.1", "2.2.2.2"}


def test_unlinked_names_and_singletons_make_no_group():
    assert bc.build_groups([member("x.com"), member("y.com", [hint("shared_server", ["not-a-candidate.com"], "1.1.1.1")])]) == []


def test_ineligible_members_neither_join_nor_connect():
    members = trio(["shared_server"])
    members[1]["eligible"] = False
    groups = bc.build_groups(members)
    assert len(groups) == 1 and groups[0]["domains"] == ["acme-a.xyz", "acme-c.xyz"]
    chain = [member("a.xyz", [hint("shared_server", ["b.xyz"], "1.1.1.1")]), member("b.xyz", [hint("shared_server", ["a.xyz", "c.xyz"], "1.1.1.1")], eligible=False),
             member("c.xyz", [hint("shared_server", ["b.xyz"], "1.1.1.1")])]
    assert bc.build_groups(chain) == []                        # the only bridge was decided harmless


def test_a_fact_that_only_links_to_someone_outside_the_group_is_not_counted():
    members = trio(["shared_server"])
    members[0]["clusters"].append(hint("shared_nameservers", ["decided-harmless.xyz"], ["ns1.x.com"]))
    members.append(member("decided-harmless.xyz", [hint("shared_nameservers", ["acme-a.xyz"], ["ns1.x.com"])], eligible=False))
    group = bc.build_groups(members)[0]
    assert {f["kind"] for f in group["facts"]} == {"shared_server"} and group["verdict"] == "not_enough"


def test_chains_connect_and_the_largest_group_comes_first():
    chain = [member("a.xyz", [hint("shared_server", ["b.xyz"], "1.1.1.1")]), member("b.xyz", [hint("shared_server", ["a.xyz", "c.xyz"], "1.1.1.1")]),
             member("c.xyz", [hint("shared_server", ["b.xyz"], "1.1.1.1")]),
             member("p.xyz", [hint("shared_server", ["q.xyz"], "2.2.2.2")]), member("q.xyz", [hint("shared_server", ["p.xyz"], "2.2.2.2")])]
    groups = bc.build_groups(chain)
    assert [g["domains"] for g in groups] == [["a.xyz", "b.xyz", "c.xyz"], ["p.xyz", "q.xyz"]]


def test_group_remembers_the_earliest_first_sighting():
    members = trio(["shared_server"])
    members[1]["first_seen_at"] = NOW - timedelta(days=3)
    assert bc.build_groups(members)[0]["first_seen_at"] == NOW - timedelta(days=3)


# ── naming and wording ──

def test_name_uses_the_word_most_members_add_to_the_brand():
    assert bc.name_for(["acme-login.xyz", "acmelogin-secure.com", "secure-acme.net"], ["acme"]) == "acme-secure cluster"
    assert bc.name_for(["acme-login.xyz", "login-acme.com", "acme-pay.net"], ["acme"]) == "acme-login cluster"


def test_numbered_batches_name_the_campaign_by_the_word_without_the_number():
    names = ["dpd-paketservicezentrum711.ink", "dpd-paketservicezentrum714.ink", "dpd-paketservicezentrum727.ink"]
    assert bc.name_for(names, ["dpd"]) == "dpd-paketservicezentrum cluster"


def test_short_words_and_one_off_words_do_not_name_a_campaign():
    assert bc.name_for(["acme-ab.xyz", "acme-ab.net"], ["acme"]) == "acme cluster"
    assert bc.name_for(["acme-login.xyz", "acme-pay.net"], ["acme"]) == "acme cluster"


def test_a_group_is_capped(monkeypatch):
    monkeypatch.setattr(bc, "MAX_MEMBERS", 2)
    assert len(bc.build_groups(trio(["shared_server"]))[0]["domains"]) == 2


def test_name_falls_back_to_the_brand_when_nothing_repeats():
    assert bc.name_for(["acme-a.xyz", "acme-b.xyz"], ["acme"]) == "acme cluster"
    assert bc.name_for(["x.com", "y.com"], []) == "brand cluster"


def test_why_sentences():
    assert "own infrastructure" in bc.why_for("probably_yours", [], 3)
    facts = [{"label": "Same nameservers"}, {"label": "Registered together"}]
    assert bc.why_for("likely_one_actor", facts, 3) == "3 look-alikes share these: same nameservers, registered together."
    assert "Only one thing links them (registered together)" in bc.why_for("not_enough", [{"label": "Registered together"}], 2)


# ── stored groups ──

async def _brand(db_session, name="acmefinancial.co.za"):
    tenant = await make_tenant(db_session, name=f"Acme-{uuid.uuid4().hex[:6]}", plan="pro")
    domain = await make_domain(db_session, tenant, name=name)
    domain.ownership_verified = True
    profile = BrandProfile(id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, brand_name="Acme Financial", keywords=[], official_domains=[])
    db_session.add(profile)
    await db_session.commit()
    return tenant, profile


def cand(profile, domain, clusters=(), status="suspicious", locked=False, registered="2026-09-29T21:00:00+00:00"):
    return BrandCandidate(id=uuid.uuid4(), tenant_id=profile.tenant_id, profile_id=profile.id, candidate_domain=domain, status=status,
                          enrichment={"clusters": list(clusters), "registered_at": registered}, campaign_locked=locked, stage="resolving")


def linked(profile, names, kind="shared_server", value="203.0.113.5"):
    return [cand(profile, n, [hint(kind, [x for x in names if x != n], value)]) for n in names]


async def _campaigns(db_session):
    return (await db_session.execute(select(BrandCampaign))).scalars().all()


@pytest.mark.asyncio
async def test_sync_creates_one_campaign_and_assigns_members(db_session):
    _, profile = await _brand(db_session)
    rows = linked(profile, ["acmefinancial-pay.xyz", "acmefinancial-pay.top", "acmefinancial-login.xyz"])
    db_session.add_all(rows + [cand(profile, "acmefinancial-alone.xyz")])
    await db_session.commit()
    out = await bc.sync(db_session, profile, ["acmefinancial"])
    camps = await _campaigns(db_session)
    assert out["campaigns"] == 1 and len(camps) == 1 and camps[0].member_count == 3 and camps[0].verdict == "not_enough"
    assert camps[0].name.endswith("cluster")
    assert {r.campaign_id for r in rows} == {camps[0].id}
    alone = (await db_session.execute(select(BrandCandidate).where(BrandCandidate.candidate_domain == "acmefinancial-alone.xyz"))).scalar_one()
    assert alone.campaign_id is None


@pytest.mark.asyncio
async def test_sync_is_idempotent_and_a_new_member_joins_the_same_campaign(db_session):
    _, profile = await _brand(db_session)
    names = ["acme-a.xyz", "acme-b.xyz"]
    db_session.add_all(linked(profile, names))
    await db_session.commit()
    await bc.sync(db_session, profile, ["acme"])
    first = (await _campaigns(db_session))[0]
    await bc.sync(db_session, profile, ["acme"])
    assert [c.id for c in await _campaigns(db_session)] == [first.id]

    for r in (await db_session.execute(select(BrandCandidate))).scalars().all():
        r.enrichment = {**r.enrichment, "clusters": [hint("shared_server", ["acme-a.xyz", "acme-b.xyz", "acme-c.xyz"], "203.0.113.5")]}
    db_session.add(cand(profile, "acme-c.xyz", [hint("shared_server", ["acme-a.xyz", "acme-b.xyz"], "203.0.113.5")]))
    await db_session.commit()
    await bc.sync(db_session, profile, ["acme"])
    camps = await _campaigns(db_session)
    assert [c.id for c in camps] == [first.id] and camps[0].member_count == 3


@pytest.mark.asyncio
async def test_two_campaigns_merge_into_the_oldest(db_session):
    _, profile = await _brand(db_session)
    db_session.add_all(linked(profile, ["a-1.xyz", "a-2.xyz"], value="1.1.1.1") + linked(profile, ["b-1.xyz", "b-2.xyz"], value="2.2.2.2"))
    await db_session.commit()
    await bc.sync(db_session, profile, ["acme"])
    camps = sorted(await _campaigns(db_session), key=lambda c: c.name)
    assert len(camps) == 2
    camps[1].created_at = camps[0].created_at + timedelta(hours=1)              # make "oldest" unambiguous
    oldest, newer = sorted(camps, key=lambda c: c.created_at)
    oldest_id, newer_id = oldest.id, newer.id
    by = {r.candidate_domain: r for r in (await db_session.execute(select(BrandCandidate))).scalars().all()}
    by["a-1.xyz"].enrichment = {**by["a-1.xyz"].enrichment, "clusters": [hint("shared_server", ["a-2.xyz", "b-1.xyz"], "1.1.1.1")]}
    by["b-1.xyz"].enrichment = {**by["b-1.xyz"].enrichment, "clusters": [hint("shared_server", ["b-2.xyz", "a-1.xyz"], "2.2.2.2")]}
    await db_session.commit()
    await bc.sync(db_session, profile, ["acme"])
    db_session.expire_all()
    camps = await _campaigns(db_session)
    assert len(camps) == 1 and camps[0].id == oldest_id and camps[0].member_count == 4
    assert newer_id not in {c.id for c in camps}
    assert {r.campaign_id for r in (await db_session.execute(select(BrandCandidate))).scalars().all()} == {oldest_id}


@pytest.mark.asyncio
async def test_a_decided_member_leaves_and_a_campaign_below_two_is_deleted(db_session):
    _, profile = await _brand(db_session)
    rows = linked(profile, ["acme-a.xyz", "acme-b.xyz"])
    db_session.add_all(rows)
    await db_session.commit()
    await bc.sync(db_session, profile, ["acme"])
    assert len(await _campaigns(db_session)) == 1
    rows[0].status = "partner"
    await db_session.commit()
    out = await bc.sync(db_session, profile, ["acme"])
    assert out["removed"] == 1 and await _campaigns(db_session) == []
    assert all(r.campaign_id is None for r in rows)


@pytest.mark.asyncio
async def test_a_locked_member_never_rejoins(db_session):
    _, profile = await _brand(db_session)
    rows = linked(profile, ["acme-a.xyz", "acme-b.xyz", "acme-c.xyz"])
    rows[2].campaign_locked = True
    db_session.add_all(rows)
    await db_session.commit()
    await bc.sync(db_session, profile, ["acme"])
    camp = (await _campaigns(db_session))[0]
    assert camp.member_count == 2 and rows[2].campaign_id is None


@pytest.mark.asyncio
async def test_same_name_gets_a_number(db_session):
    _, profile = await _brand(db_session)
    db_session.add_all(linked(profile, ["acme-a.xyz", "acme-b.xyz"], value="1.1.1.1") + linked(profile, ["acme-c.xyz", "acme-d.xyz"], value="2.2.2.2"))
    await db_session.commit()
    await bc.sync(db_session, profile, ["acme"])
    assert sorted(c.name for c in await _campaigns(db_session)) == ["acme cluster", "acme cluster 2"]


@pytest.mark.asyncio
async def test_sync_only_touches_its_own_brand(db_session):
    _, profile = await _brand(db_session)
    _, other = await _brand(db_session, "otherbrand.co.za")
    db_session.add_all(linked(other, ["acme-a.xyz", "acme-b.xyz"]))
    await db_session.commit()
    await bc.sync(db_session, profile, ["acme"])
    assert await _campaigns(db_session) == []


# ── API ──

async def _seed_campaign(client, tenant, db_session):
    profile_id = await _pro_profile(client, tenant, db_session)
    names = ["acme-a.xyz", "acme-b.xyz", "acme-c.xyz"]
    profile = await db_session.get(BrandProfile, uuid.UUID(profile_id))
    db_session.add_all(linked(profile, names, "shared_nameservers", ["ns1.x.com", "ns2.x.com"]))
    await db_session.commit()
    await bc.sync(db_session, profile, ["acme"])
    await db_session.commit()
    return profile_id


async def test_api_lists_campaigns_with_live_count_and_scopes_by_brand(auth_client, db_session):
    client, tenant = auth_client
    profile_id = await _seed_campaign(client, tenant, db_session)
    listed = (await client.get("/brand-guard/campaigns", params={"profile_id": profile_id})).json()
    assert len(listed) == 1
    c = listed[0]
    assert c["member_count"] == 3 and c["live_count"] == 3 and c["verdict"]["key"] == "not_enough" and c["why"]
    assert c["facts"][0]["label"] == "Same nameservers"
    assert (await client.get("/brand-guard/campaigns", params={"profile_id": str(uuid.uuid4())})).json() == []


async def test_api_campaign_detail_has_members_with_verdicts_and_candidates_know_their_campaign(auth_client, db_session):
    client, tenant = auth_client
    profile_id = await _seed_campaign(client, tenant, db_session)
    cid = (await client.get("/brand-guard/campaigns")).json()[0]["id"]
    detail = (await client.get(f"/brand-guard/campaigns/{cid}")).json()
    assert {m["candidate_domain"] for m in detail["members"]} == {"acme-a.xyz", "acme-b.xyz", "acme-c.xyz"}
    assert all(m["verdict"]["key"] and m["campaign_id"] == cid and m["campaign_name"] == detail["name"] for m in detail["members"])
    listed = (await client.get("/brand-guard/candidates", params={"profile_id": profile_id})).json()
    assert {c["campaign_id"] for c in listed} == {cid}
    one = (await client.get(f"/brand-guard/candidates/{listed[0]['id']}")).json()
    assert one["campaign_name"] == detail["name"]
    assert (await client.get(f"/brand-guard/campaigns/{uuid.uuid4()}")).status_code == 404


async def test_api_removing_a_member_keeps_it_out_and_a_decision_regroups(auth_client, db_session):
    client, tenant = auth_client
    await _seed_campaign(client, tenant, db_session)
    camp = (await client.get("/brand-guard/campaigns")).json()[0]
    detail = (await client.get(f"/brand-guard/campaigns/{camp['id']}")).json()
    victim = next(m for m in detail["members"] if m["candidate_domain"] == "acme-c.xyz")

    assert (await client.post(f"/brand-guard/campaigns/{camp['id']}/members/{victim['id']}/remove")).status_code == 204
    after = (await client.get(f"/brand-guard/campaigns/{camp['id']}")).json()
    assert after["member_count"] == 2 and "acme-c.xyz" not in {m["candidate_domain"] for m in after["members"]}
    assert (await client.post(f"/brand-guard/campaigns/{camp['id']}/members/{victim['id']}/remove")).status_code == 404   # no longer in it

    other = next(m for m in after["members"] if m["candidate_domain"] == "acme-a.xyz")
    changed = (await client.patch(f"/brand-guard/candidates/{other['id']}/status", json={"status": "partner"})).json()
    assert changed["campaign_id"] is None                                           # decided harmless: out of the group
    assert (await client.get("/brand-guard/campaigns")).json() == []                # one member left: no campaign


async def test_api_campaigns_are_tenant_scoped(auth_client, db_session):
    client, tenant = auth_client
    await _seed_campaign(client, tenant, db_session)
    other = await make_tenant(db_session, name="Intruder", plan="pro")
    camp = BrandCampaign(id=uuid.uuid4(), tenant_id=other.id, profile_id=(await db_session.execute(select(BrandProfile.id))).scalars().first(), name="theirs",
                         verdict="likely_one_actor", facts=[], member_count=2)
    db_session.add(camp)
    await db_session.commit()
    assert [c["name"] for c in (await client.get("/brand-guard/campaigns")).json()] != ["theirs"]
    assert (await client.get(f"/brand-guard/campaigns/{camp.id}")).status_code == 404


async def test_a_real_scan_groups_look_alikes_that_share_nameservers_and_a_batch(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    names = ["acmefinancia1.co.za", "acmefinancail.co.za", "acmefinancial-pay.co.za"]
    live = {n: {"has_a": True, "has_mx": False, "registered": True, "ns": ["ns1.cheap.example", "ns2.cheap.example"], "a": ["203.0.113.7"]} for n in names}
    _fake_network(monkeypatch, live=live, registered_days={n: 2 for n in names})
    run = await _scan(client, profile_id)
    assert run["status"] == "succeeded", run
    camps = (await client.get("/brand-guard/campaigns")).json()
    assert len(camps) == 1 and camps[0]["member_count"] == 3
    assert {f["kind"] for f in camps[0]["facts"]} >= {"shared_nameservers", "registration_batch"}
    assert camps[0]["verdict"]["key"] in {"possibly_related", "likely_one_actor"}


async def test_api_live_count_only_counts_members_that_resolve_and_strongest_campaigns_come_first(auth_client, db_session):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    profile = await db_session.get(BrandProfile, uuid.UUID(profile_id))
    big = linked(profile, ["big-a.xyz", "big-b.xyz", "big-c.xyz"], "shared_server", "1.1.1.1")
    big[2].stage = "registered"                                              # not live
    small = [cand(profile, n, [hint(k, [x for x in ("sm-a.xyz", "sm-b.xyz") if x != n], v) for k, v in
                              (("shared_server", "2.2.2.2"), ("shared_nameservers", ["n1.x", "n2.x"]), ("registration_batch", None))]) for n in ("sm-a.xyz", "sm-b.xyz")]
    db_session.add_all(big + small)
    await db_session.commit()
    await bc.sync(db_session, profile, ["acme"])
    await db_session.commit()
    listed = (await client.get("/brand-guard/campaigns")).json()
    assert [c["verdict"]["key"] for c in listed] == ["likely_one_actor", "not_enough"]       # strongest first, not biggest first
    assert [c["live_count"] for c in listed] == [2, 2] and [c["member_count"] for c in listed] == [2, 3]
