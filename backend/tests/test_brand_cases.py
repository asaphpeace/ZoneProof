from datetime import datetime, timedelta, timezone

import pytest

from app.services import brand_cases as bc

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def test_sla_hours_by_urgency_and_unknown_defaults_to_slowest():
    assert (bc.sla_hours("high"), bc.sla_hours("medium"), bc.sla_hours("low"), bc.sla_hours(None), bc.sla_hours("x")) == (4, 24, 72, 72, 72)


def test_clock_starts_on_confirm_and_is_not_restarted_by_takedown():
    due = bc.start_clock("new", "confirmed", None, "high", NOW)
    assert due == NOW + timedelta(hours=4)
    assert bc.start_clock("confirmed", "takedown", due, "high", NOW + timedelta(hours=2)) == due
    assert bc.start_clock("new", "watch", None, "high", NOW) is None


def test_sla_states():
    due = NOW + timedelta(hours=24)
    w = 24
    assert bc.sla_state("confirmed", due, None, NOW, w)["state"] == "on_track"
    assert bc.sla_state("confirmed", due, None, NOW + timedelta(hours=19), w)["state"] == "due_soon"   # 5h left, <= 6h
    assert bc.sla_state("confirmed", due, None, NOW + timedelta(hours=18), w)["state"] == "due_soon"   # exactly 6h left: the last quarter is inclusive
    assert bc.sla_state("confirmed", due, None, NOW + timedelta(hours=17), w)["state"] == "on_track"
    assert bc.sla_state("confirmed", due, None, NOW + timedelta(hours=25), w)["state"] == "breached"
    assert bc.sla_state("confirmed", None, None, NOW, w)["state"] == "none"


def test_closed_case_is_met_or_breached_by_when_it_was_closed():
    due = NOW
    assert bc.sla_state("removed", due, NOW - timedelta(hours=1), NOW, 24)["state"] == "met"
    assert bc.sla_state("removed", due, NOW + timedelta(hours=1), NOW, 24)["state"] == "breached"
    assert bc.sla_state("false_positive", due, None, NOW, 24)["state"] == "none"


def test_resolved_stamp():
    assert bc.resolved_stamp("takedown", "removed", None, NOW) == NOW
    assert bc.resolved_stamp("removed", "removed", NOW, NOW + timedelta(days=1)) == NOW
    assert bc.resolved_stamp("removed", "monitoring", NOW, NOW) is None


@pytest.mark.parametrize("status,reviewed,stage,events,expected", [
    ("removed", True, "resolving", ["activated"], True),
    ("removed", True, "certified", ["stage_changed"], True),
    ("removed", False, "resolving", ["activated"], False),      # not a person's closure
    ("confirmed", True, "resolving", ["activated"], False),
    ("removed", True, "registered", ["activated"], False),
    ("removed", True, "resolving", [], False),
])
def test_resurrection_rule(status, reviewed, stage, events, expected):
    assert bc.is_resurrection(status, reviewed, stage, events) is expected


def test_describe_case_events():
    assert "Ann" in bc.describe("assigned", {"by": "Ann", "to": "Bob"}) and "Bob" in bc.describe("assigned", {"by": "Ann", "to": "Bob"})
    assert "removed the assignee" in bc.describe("assigned", {"by": "Ann", "to": None})
    assert "confirmed" in bc.describe("status_changed", {"by": "Ann", "from": "new", "to": "confirmed"})
    assert "reopened" in bc.describe("resurrected", {})
    assert bc.describe("activated", {}) is None


# -- API ---------------------------------------------------------------------
import uuid

from app.models import BrandCandidate, BrandProfile
from tests.test_brand_graph import cand
from tests.test_brand_guard_api import _pro_profile


async def _one(client, tenant, db_session, status="new", urgency="high"):
    profile = await db_session.get(BrandProfile, uuid.UUID(await _pro_profile(client, tenant, db_session)))
    row = cand(profile, "acme-pay.xyz", status=status)
    row.urgency = urgency
    db_session.add(row)
    await db_session.commit()
    return str(row.id)


async def test_confirming_starts_the_clock_and_writes_a_timeline_line(auth_client, db_session):
    client, tenant = auth_client
    cid = await _one(client, tenant, db_session)
    r = (await client.patch(f"/brand-guard/candidates/{cid}/status", json={"status": "confirmed", "note": "login clone"})).json()
    assert r["sla"]["state"] == "on_track" and 3.5 < r["sla"]["hours_left"] <= 4
    lines = [e["summary"] for e in (await client.get(f"/brand-guard/candidates/{cid}/timeline")).json()["events"]]
    assert any("new → confirmed" in l and "login clone" in l for l in lines)
    r2 = (await client.patch(f"/brand-guard/candidates/{cid}/status", json={"status": "takedown"})).json()
    assert r2["sla"]["due_at"] == r["sla"]["due_at"]            # moving on does not restart the clock


async def test_removing_closes_the_case_and_reports_the_deadline_as_met(auth_client, db_session):
    client, tenant = auth_client
    cid = await _one(client, tenant, db_session)
    await client.patch(f"/brand-guard/candidates/{cid}/status", json={"status": "confirmed"})
    r = (await client.patch(f"/brand-guard/candidates/{cid}/status", json={"status": "removed"})).json()
    assert r["sla"]["state"] == "met"


async def test_assign_shows_the_owner_filters_and_can_be_cleared(auth_client, db_session):
    client, tenant = auth_client
    cid = await _one(client, tenant, db_session)
    me = (await client.get("/auth/me")).json()
    r = (await client.patch(f"/brand-guard/candidates/{cid}/assignee", json={"user_id": me["id"]})).json()
    assert r["assignee"]["id"] == me["id"] and r["assignee"]["email"]
    assert [c["id"] for c in (await client.get("/brand-guard/candidates?assigned_to=me")).json()] == [cid]
    assert (await client.get("/brand-guard/candidates?assigned_to=none")).json() == []
    assert any("assigned this" in e["summary"] for e in (await client.get(f"/brand-guard/candidates/{cid}/timeline")).json()["events"])
    cleared = (await client.patch(f"/brand-guard/candidates/{cid}/assignee", json={"user_id": None})).json()
    assert cleared["assignee"] is None


async def test_cannot_assign_to_someone_outside_the_workspace_or_a_bad_id(auth_client, db_session):
    client, tenant = auth_client
    cid = await _one(client, tenant, db_session)
    assert (await client.patch(f"/brand-guard/candidates/{cid}/assignee", json={"user_id": str(uuid.uuid4())})).status_code == 404
    assert (await client.patch(f"/brand-guard/candidates/{cid}/assignee", json={"user_id": "nope"})).status_code == 422


async def test_cases_list_holds_only_what_a_person_took_on_soonest_deadline_first(auth_client, db_session):
    client, tenant = auth_client
    profile = await db_session.get(BrandProfile, uuid.UUID(await _pro_profile(client, tenant, db_session)))
    for name, urg in (("acme-a.xyz", "low"), ("acme-b.xyz", "high"), ("acme-c.xyz", "medium")):
        row = cand(profile, name, status="new")
        row.urgency = urg
        db_session.add(row)
    await db_session.commit()
    ids = {c["candidate_domain"]: c["id"] for c in (await client.get("/brand-guard/candidates")).json()}
    for n in ("acme-a.xyz", "acme-b.xyz"):
        await client.patch(f"/brand-guard/candidates/{ids[n]}/status", json={"status": "confirmed"})
    got = [c["candidate_domain"] for c in (await client.get("/brand-guard/candidates?status=cases")).json()]
    assert got == ["acme-b.xyz", "acme-a.xyz"]                  # high urgency (4 h) before low (72 h); the untouched one is not a case


async def test_a_watched_lookalike_is_not_a_case_until_it_really_came_back(auth_client, db_session):
    from app.models import BrandCandidateEvent
    from datetime import datetime, timezone
    client, tenant = auth_client
    profile = await db_session.get(BrandProfile, uuid.UUID(await _pro_profile(client, tenant, db_session)))
    a, b = cand(profile, "acme-w.xyz", status="new"), cand(profile, "acme-r.xyz", status="new")
    db_session.add_all([a, b])
    await db_session.commit()
    for row in (a, b):
        await client.patch(f"/brand-guard/candidates/{row.id}/status", json={"status": "monitoring"})
    db_session.add(BrandCandidateEvent(id=uuid.uuid4(), candidate_id=b.id, tenant_id=b.tenant_id, kind="resurrected", occurred_at=datetime.now(timezone.utc), payload={}))
    await db_session.commit()
    assert [c["candidate_domain"] for c in (await client.get("/brand-guard/candidates?status=cases")).json()] == ["acme-r.xyz"]


async def test_a_rescore_after_confirming_does_not_change_the_deadline_window(auth_client, db_session):
    client, tenant = auth_client
    cid = await _one(client, tenant, db_session, urgency="high")
    await client.patch(f"/brand-guard/candidates/{cid}/status", json={"status": "confirmed"})
    row = await db_session.get(BrandCandidate, uuid.UUID(cid))
    await db_session.refresh(row)
    row.urgency = "low"                                          # what a later rescore might do
    await db_session.commit()
    sla = (await client.get(f"/brand-guard/candidates/{cid}")).json()["sla"]
    assert sla["state"] == "on_track" and sla["hours_left"] <= 4
