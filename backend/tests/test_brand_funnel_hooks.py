"""The funnel counters at the points where Brand Guard decides: what a scan found and dropped, who is picked for a visit and why not, what the
worker returned, and what resembled the brand. Each test checks that the numbers add up to what really happened."""
import base64
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.config import settings
from app.models import BrandFunnelCount, BrandProbeJob
from app.services import brand_funnel as bf
from app.services import brand_probe_queue as q
from app.services import plan_limits
from tests.test_brand_cost_guard import LIVE, _profile, _scan, world                                   # noqa: F401  (fixtures and helpers)
from tests.test_brand_probe_queue import NOW, _claimed, _setup, on                                      # noqa: F401
from tests.test_brand_render_data import _render_job, raw_render, render_on                              # noqa: F401
from tests.test_brand_similarity_flow import REF, COPY_HTML, light, b64, enc, logo                      # noqa: F401


async def stage(db, key, profile_id=None):
    q_ = select(BrandFunnelCount).where(BrandFunnelCount.stage == key)
    if profile_id is not None:
        q_ = q_.where(BrandFunnelCount.profile_id == profile_id)
    rows = (await db.execute(q_)).scalars().all()
    detail: dict = {}
    for r in rows:
        for k, v in (r.detail or {}).items():
            detail[k] = detail.get(k, 0) + v
    return sum(r.entered for r in rows), sum(r.passed for r in rows), detail


# ── a scan ─────────────────────────────────────────────────────────────────

async def test_a_scan_counts_names_found_dropped_kept_and_scored(auth_client, db_session, world):      # noqa: F811
    client, tenant = auth_client
    world["dns"]["acmefinancial.com"] = LIVE
    pid = await _profile(client, tenant, db_session, "acmefinancial.co.za")
    run = await _scan(db_session, pid)
    found_e, found_p, found_d = await stage(db_session, "discover", pid)
    live_e, live_p, live_d = await stage(db_session, "live", pid)
    scored_e, scored_p, scored_d = await stage(db_session, "scored", pid)
    assert found_e == found_p > 0 and found_d["found_permutation"] == found_p            # every name came from the permutation generator
    assert live_e == found_p                                                             # all were new: each was examined once
    assert live_p == run.result["new_candidates"] >= 1
    assert live_e == live_p + sum(live_d.get(k, 0) for k in ("unregistered", "plan_cap", "customer_owned"))       # nothing is unaccounted for
    assert live_d["unregistered"] == live_e - live_p                                     # in this world only one name is live
    assert scored_e >= live_p and sum(v for k, v in scored_d.items() if k.startswith("status_")) == scored_e
    assert scored_p == scored_d.get("status_suspicious", 0)


async def test_a_name_that_is_the_customers_own_domain_is_counted_as_dropped_for_that_reason(auth_client, db_session, world):      # noqa: F811
    client, tenant = auth_client
    world["dns"]["acmefinancial.com"] = LIVE
    pid = await _profile(client, tenant, db_session, "acmefinancial.co.za")
    from app.models import BrandProfile
    (await db_session.get(BrandProfile, pid)).official_domains = ["acmefinancial.com"]
    await db_session.commit()
    run = await _scan(db_session, pid)
    live_e, live_p, live_d = await stage(db_session, "live", pid)
    assert live_d.get("customer_owned") == 1 and live_p == run.result["new_candidates"]
    assert live_d["unregistered"] == live_e - live_p - 1                                 # (and it is not also counted as "not registered")


async def test_names_cut_by_the_plan_scan_budget_are_counted_as_found_but_not_sent_on(auth_client, db_session, world, monkeypatch):    # noqa: F811
    client, tenant = auth_client
    monkeypatch.setitem(plan_limits.PLAN_LIMITS["pro"], "brand_guard_scan_budget", 10)
    pid = await _profile(client, tenant, db_session, "acmefinancial.co.za")
    await _scan(db_session, pid)
    entered, passed, detail = await stage(db_session, "discover", pid)
    assert passed == 10 and detail["trimmed_by_plan_budget"] == entered - 10 > 0 and detail["found_permutation"] == 10


async def test_names_cut_by_the_plan_cap_are_counted_as_such(auth_client, db_session, world, monkeypatch):     # noqa: F811
    client, tenant = auth_client

    class AllLive(dict):
        def get(self, key, default=None):
            return LIVE
    world["dns"] = AllLive()
    monkeypatch.setitem(plan_limits.PLAN_LIMITS["pro"], "brand_guard_max_candidates", 2)
    pid = await _profile(client, tenant, db_session, "acmefinancial.co.za")
    run = await _scan(db_session, pid)
    live_e, live_p, live_d = await stage(db_session, "live", pid)
    assert live_p == run.result["new_candidates"] == 2
    assert live_d["plan_cap"] == live_e - 2 - live_d.get("customer_owned", 0) - live_d.get("unregistered", 0) > 0


async def test_a_second_scan_re_scores_known_candidates_but_only_counts_new_names_in_the_live_stage(auth_client, db_session, world):     # noqa: F811
    client, tenant = auth_client
    world["dns"]["acmefinancial.com"] = LIVE
    pid = await _profile(client, tenant, db_session, "acmefinancial.co.za")
    await _scan(db_session, pid)
    first_live = await stage(db_session, "live", pid)
    first_scored = await stage(db_session, "scored", pid)
    await _scan(db_session, pid)
    second_live = await stage(db_session, "live", pid)
    second_scored = await stage(db_session, "scored", pid)
    assert second_live[1] == first_live[1]                                               # no new candidates the second time
    assert second_live[0] - first_live[0] == first_live[0] - first_live[1]               # the unregistered names are examined again, the known candidate is not "new"
    assert second_scored[0] > first_scored[0]                                            # ...but it was scored again


async def test_a_failing_counter_never_costs_the_scan_its_results(auth_client, db_session, world, monkeypatch):    # noqa: F811
    client, tenant = auth_client
    world["dns"]["acmefinancial.com"] = LIVE

    async def boom(*a, **k):
        raise RuntimeError("counter table is gone")
    monkeypatch.setattr(bf, "record", boom)
    pid = await _profile(client, tenant, db_session, "acmefinancial.co.za")
    run = await _scan(db_session, pid)
    assert run.status == "succeeded" and run.result["new_candidates"] >= 1


# ── picking who to visit ───────────────────────────────────────────────────

async def test_who_is_picked_to_visit_and_why_not_are_counted(db_session, on, monkeypatch):            # noqa: F811
    monkeypatch.setattr(settings, "brand_probe_tenant_daily_cap", 1)
    _, profile, rows = await _setup(db_session,
                                    ("picked.xyz", "confirmed", "resolving", 90), ("second.xyz", "confirmed", "resolving", 80),
                                    ("recent.xyz", "confirmed", "resolving", 70), ("weak.xyz", "monitoring", "resolving", 5), ("dormant.xyz", "confirmed", "registered", 90),
                                    ("recentweak.xyz", "monitoring", "resolving", 5))
    for i, r in enumerate(rows):
        r.abuse_score = 100 - i * 10
    for idx, host in ((2, "recent.xyz"), (5, "recentweak.xyz")):
        db_session.add(BrandProbeJob(id=uuid.uuid4(), tenant_id=profile.tenant_id, candidate_id=rows[idx].id, host=host, kind="light", status="done", expires_at=NOW + timedelta(days=1),
                                     created_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    await db_session.commit()
    # (the cap is per tenant per day and the two recent jobs above already used two of today's allowance: leave room for exactly one more)
    monkeypatch.setattr(settings, "brand_probe_tenant_daily_cap", 3)
    assert await q.enqueue_due(db_session, profile) == 1
    entered, passed, detail = await stage(db_session, "probe_select", profile.id)
    assert (entered, passed) == (5, 1)                                                   # the dormant name is not live, so it never enters this stage
    assert detail == {"probed_recently": 2, "not_similar_enough": 1, "daily_cap": 1}     # a weak look-alike that was also visited recently counts as "recently", the first reason that applies
    assert passed + sum(detail.values()) == entered


async def test_nothing_is_counted_while_probing_is_off(db_session):
    _, profile, _ = await _setup(db_session, ("a.xyz", "confirmed", "resolving", 90))
    assert await q.enqueue_due(db_session, profile) == 0
    assert (await db_session.execute(select(BrandFunnelCount))).scalars().all() == []


# ── picking pages to render ────────────────────────────────────────────────

PW = {"reachable": True, "password_form": True, "brand_in_title": False, "favicon_matches_brand": False, "redirects_to_brand": False}


async def test_each_render_decision_is_counted_with_its_reason(db_session, render_on, monkeypatch):    # noqa: F811
    monkeypatch.setattr(settings, "brand_render_tenant_daily_cap", 1)
    _, profile, rows = await _setup(db_session, ("a.xyz", "monitoring", "resolving", 80), ("b.xyz", "monitoring", "resolving", 80), ("c.xyz", "monitoring", "resolving", 80))
    a, b, c = rows
    assert await q.enqueue_render(db_session, a, PW, NOW, profile) is True
    assert await q.enqueue_render(db_session, a, PW, NOW, profile) is False              # just rendered
    assert await q.enqueue_render(db_session, b, PW, NOW, profile) is False              # the tenant's daily allowance (1) is used
    assert await q.enqueue_render(db_session, c, {"reachable": True}, NOW, profile) is False       # an ordinary page
    entered, passed, detail = await stage(db_session, "render_select", profile.id)
    assert (entered, passed) == (4, 1) and detail == {"rendered_recently": 1, "daily_cap": 1, "not_interesting": 1}


async def test_nothing_is_counted_for_renders_while_the_renderer_is_off(db_session, on):               # noqa: F811
    _, profile, rows = await _setup(db_session, ("a.xyz", "monitoring", "resolving", 80))
    assert await q.enqueue_render(db_session, rows[0], PW, NOW, profile) is False
    assert await stage(db_session, "render_select") == (0, 0, {})


# ── what the worker returned ───────────────────────────────────────────────

async def test_visits_are_counted_by_outcome_and_the_similarity_found(db_session, on):                  # noqa: F811
    from app.models import BrandProfile
    from tests.test_brand_similarity import HOME
    _, profile, rows = await _setup(db_session, ("live.xyz", "monitoring", "resolving", 80), ("dead.xyz", "monitoring", "resolving", 80), ("odd.xyz", "monitoring", "resolving", 80),
                                    ("some.xyz", "monitoring", "resolving", 80))
    profile.fingerprint = {"similarity": {"icon_dhash": REF["icon_dhash"], "wording": REF["wording"]}}
    await db_session.commit()
    ok = await _claimed(db_session, profile, rows[0], "live.xyz")
    await q.complete(db_session, ok.id, light(favicon=enc(logo(11).resize((32, 32)))))                  # copies the brand's icon and wording
    dead = await _claimed(db_session, profile, rows[1], "dead.xyz")
    await q.complete(db_session, dead.id, {"ok": False, "error": "could not connect"})
    plain = await _claimed(db_session, profile, rows[2], "odd.xyz")
    await q.complete(db_session, plain.id, light("<title>Hello</title><p>" + " ".join(f"zebra{i} quartz{i % 7} lemon{i % 11}" for i in range(200)) + "</p>"))
    some = await _claimed(db_session, profile, rows[3], "some.xyz")                                      # a little overlap: compared, but not a copy
    await q.complete(db_session, some.id, light("<p>" + HOME[: len(HOME) // 6] + " " + " ".join(f"fresh{i} novel{i % 7} words{i % 13}" for i in range(260)) + "</p>"))
    assert await stage(db_session, "probe_done", profile.id) == (4, 3, {"worker_error": 1})
    s_e, s_p, s_d = await stage(db_session, "similarity", profile.id)
    assert (s_e, s_p) == (3, 1) and s_d == {"icon": 1, "wording": 1}                                    # the failed visit made no comparison; the partial overlap did not count


async def test_an_unreachable_page_is_counted_separately_from_a_worker_error(db_session, on):           # noqa: F811
    _, profile, rows = await _setup(db_session, ("a.xyz", "monitoring", "resolving", 80))
    job = await _claimed(db_session, profile, rows[0], "a.xyz")
    await q.complete(db_session, job.id, {"ok": True, "chain": [], "final_status": None, "content_type": None, "html": None})
    assert await stage(db_session, "probe_done", profile.id) == (1, 0, {"unreachable": 1})


async def test_renders_are_counted_by_outcome(db_session, render_on):                                    # noqa: F811
    _, profile, rows = await _setup(db_session, ("a.xyz", "monitoring", "resolving", 80))
    row = rows[0]
    row.enrichment = {"probe": {"reachable": True, "forms": [], "similarity": {}}}
    await db_session.commit()
    ok = await _render_job(db_session, profile, row)
    await q.complete(db_session, ok.id, {"ok": True, "render": raw_render()})
    bad = await _render_job(db_session, profile, row)
    await q.complete(db_session, bad.id, {"ok": False, "error": "render timed out"})
    assert await stage(db_session, "render_done", profile.id) == (2, 1, {"failed": 1})
    textonly = await _render_job(db_session, profile, row)                                              # a render that read the page but could not take a screenshot
    await q.complete(db_session, textonly.id, {"ok": True, "render": raw_render(screenshot_b64=None)})
    assert await stage(db_session, "render_done", profile.id) == (3, 1, {"failed": 1, "no_screenshot": 1})


async def test_jobs_that_expire_unclaimed_are_counted_at_the_stage_they_stalled_in(db_session, on, monkeypatch):   # noqa: F811
    monkeypatch.setattr(settings, "brand_render_enabled", True)
    _, profile, rows = await _setup(db_session, ("a.xyz", "monitoring", "resolving", 80), ("b.xyz", "monitoring", "resolving", 80))
    old = datetime.now(timezone.utc) - timedelta(minutes=30)
    for kind, row in (("light", rows[0]), ("light", rows[1]), ("render", rows[0])):
        db_session.add(BrandProbeJob(id=uuid.uuid4(), tenant_id=profile.tenant_id, candidate_id=row.id, host=row.candidate_domain, kind=kind, status="queued", expires_at=old, created_at=old))
    db_session.add(BrandProbeJob(id=uuid.uuid4(), tenant_id=profile.tenant_id, candidate_id=None, profile_id=profile.id, host="acmefinancial.co.za", kind="ref", status="queued", expires_at=old, created_at=old))
    await db_session.commit()
    assert await q.claim(db_session) is None
    assert await stage(db_session, "probe_done", profile.id) == (2, 0, {"expired_unclaimed": 2})
    assert await stage(db_session, "render_done", profile.id) == (1, 0, {"expired_unclaimed": 1})        # (the reference job belongs to no look-alike and is not counted)
    assert await q.claim(db_session) is None
    assert await stage(db_session, "probe_done", profile.id) == (2, 0, {"expired_unclaimed": 2})          # already expired: never counted twice
