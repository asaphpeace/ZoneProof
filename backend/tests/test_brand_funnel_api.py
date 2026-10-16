"""GET /brand-guard/funnel: the numbers a person sees, what is switched off, what is missing, and who may look."""
import uuid
from datetime import datetime, timezone

from app.config import settings
from app.models import BrandProfile
from app.services import brand_funnel as bf
from tests.test_brand_graph import _brand
from tests.test_brand_guard_api import _pro_profile


def stage(data, key):
    return next(s for s in data["stages"] if s["key"] == key)


async def test_the_funnel_returns_every_stage_with_counts_reasons_and_a_daily_series(auth_client, db_session):
    client, tenant = auth_client
    pid = await _pro_profile(client, tenant, db_session)
    profile = await db_session.get(BrandProfile, uuid.UUID(pid))
    await bf.record(db_session, profile, "probe_select", entered=12, passed=3, detail={"probed_recently": 6, "daily_cap": 3})
    r = await client.get("/brand-guard/funnel?days=7")
    assert r.status_code == 200
    d = r.json()
    assert [s["key"] for s in d["stages"]] == bf.STAGE_KEYS and d["days"] == 7 and len(stage(d, "discover")["daily"]) == 7
    ps = stage(d, "probe_select")
    assert (ps["entered"], ps["passed"], ps["dropped"], ps["pass_rate"]) == (12, 3, 9, 0.25) and ps["detail"] == {"probed_recently": 6, "daily_cap": 3}
    assert ps["daily"][-1]["day"] == datetime.now(timezone.utc).date().isoformat() and ps["daily"][-1]["entered"] == 12
    assert {"label", "unit", "passed_means", "needs", "state"} <= set(ps) and isinstance(ps["passed_means"], str) and "outcomes" in d and isinstance(d["not_built"], list) and d["not_built"]


async def test_stages_that_need_the_worker_say_they_are_off_until_it_is_switched_on(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    await _pro_profile(client, tenant, db_session)
    d = (await client.get("/brand-guard/funnel")).json()
    assert d["switches"] == {"probe": False, "render": False}
    assert {s["key"]: s["state"] for s in d["stages"]} == {
        "discover": "on", "live": "on", "scored": "on", "probe_select": "off", "probe_done": "off", "render_select": "off", "render_done": "off", "similarity": "off"}
    monkeypatch.setattr(settings, "brand_probe_enabled", True)
    monkeypatch.setattr(settings, "brand_probe_key", "k" * 40)
    d = (await client.get("/brand-guard/funnel")).json()
    states = {s["key"]: s["state"] for s in d["stages"]}
    assert d["switches"] == {"probe": True, "render": False} and states["probe_select"] == "on" and states["similarity"] == "on" and states["render_select"] == "off"
    monkeypatch.setattr(settings, "brand_render_enabled", True)
    assert {s["key"]: s["state"] for s in (await client.get("/brand-guard/funnel")).json()["stages"]}["render_done"] == "on"


async def test_a_brand_can_be_selected_and_another_workspaces_brand_cannot(auth_client, db_session):
    client, tenant = auth_client
    pid = await _pro_profile(client, tenant, db_session)
    mine = await db_session.get(BrandProfile, uuid.UUID(pid))
    _, theirs = await _brand(db_session, name=f"other-{uuid.uuid4().hex[:6]}.co.za")
    await bf.record(db_session, mine, "discover", entered=5, passed=5)
    await bf.record(db_session, theirs, "discover", entered=900, passed=900)
    everything = (await client.get("/brand-guard/funnel")).json()
    assert stage(everything, "discover")["entered"] == 5                                  # the other workspace's 900 are not in the totals
    assert stage((await client.get(f"/brand-guard/funnel?profile_id={pid}")).json(), "discover")["entered"] == 5
    assert (await client.get(f"/brand-guard/funnel?profile_id={theirs.id}")).status_code == 404
    assert (await client.get("/brand-guard/funnel?profile_id=not-a-uuid")).status_code == 404
    assert (await client.get(f"/brand-guard/funnel?profile_id={uuid.uuid4()}")).status_code == 404


async def test_the_range_is_clamped_and_a_workspace_with_no_data_gets_zeros_not_an_error(auth_client, db_session):
    client, tenant = auth_client
    await _pro_profile(client, tenant, db_session)
    assert (await client.get("/brand-guard/funnel?days=0")).json()["days"] == 1
    assert (await client.get("/brand-guard/funnel?days=100000")).json()["days"] == 90
    d = (await client.get("/brand-guard/funnel")).json()
    assert all(s["entered"] == 0 and s["pass_rate"] is None for s in d["stages"]) and d["days"] == 30


async def test_the_not_built_list_points_only_at_real_stages(auth_client, db_session):
    assert all(item["after"] in bf.STAGE_KEYS and item["label"] for item in bf.NOT_BUILT)
    client, tenant = auth_client
    await _pro_profile(client, tenant, db_session)
    assert (await client.get("/brand-guard/funnel")).json()["not_built"] == bf.NOT_BUILT


async def test_the_funnel_needs_a_login(client):
    assert (await client.get("/brand-guard/funnel")).status_code in (401, 403)
