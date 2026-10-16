"""The funnel counters: recording, merging, summarising, and never breaking the work they describe."""
import uuid
from datetime import date, timedelta

import pytest
from sqlalchemy import select

from app.models import BrandCandidate, BrandFunnelCount
from app.services import brand_funnel as bf
from tests.test_brand_graph import _brand, cand

D1, D2 = date(2026, 10, 5), date(2026, 10, 6)


async def _profile(db):
    tenant, profile = await _brand(db, name=f"f-{uuid.uuid4().hex[:8]}.co.za")
    return tenant, profile


async def rows(db, profile=None):
    q = select(BrandFunnelCount)
    if profile is not None:
        q = q.where(BrandFunnelCount.profile_id == profile.id)
    return (await db.execute(q)).scalars().all()


async def test_counts_accumulate_for_the_same_brand_day_and_stage(db_session):
    _, p = await _profile(db_session)
    for _ in range(3):
        await bf.record(db_session, p, "discover", entered=10, passed=4, detail={"trimmed": 2, "src_ct_log": 1}, day=D1)
    r = (await rows(db_session, p))[0]
    assert len(await rows(db_session, p)) == 1 and (r.entered, r.passed) == (30, 12) and r.detail == {"trimmed": 6, "src_ct_log": 3} and r.day == D1


async def test_detail_keys_merge_across_calls_including_keys_only_one_side_has(db_session):
    _, p = await _profile(db_session)
    await bf.record(db_session, p, "live", entered=5, passed=1, detail={"unregistered": 4}, day=D1)
    await bf.record(db_session, p, "live", entered=3, passed=1, detail={"plan_cap": 2}, day=D1)
    await bf.record(db_session, p, "live", entered=2, passed=0, detail={"unregistered": 1, "plan_cap": 1}, day=D1)
    r = (await rows(db_session, p))[0]
    assert (r.entered, r.passed) == (10, 2) and r.detail == {"unregistered": 5, "plan_cap": 3}


async def test_different_days_stages_and_brands_are_kept_apart(db_session):
    _, a = await _profile(db_session)
    _, b = await _profile(db_session)
    await bf.record(db_session, a, "discover", entered=1, day=D1)
    await bf.record(db_session, a, "discover", entered=2, day=D2)
    await bf.record(db_session, a, "live", entered=4, day=D1)
    await bf.record(db_session, b, "discover", entered=8, day=D1)
    assert sorted((r.stage, r.day, r.entered) for r in await rows(db_session, a)) == [("discover", D1, 1), ("discover", D2, 2), ("live", D1, 4)]
    assert [(r.entered) for r in await rows(db_session, b)] == [8]


async def test_nothing_is_written_for_an_all_zero_record_and_an_unknown_stage_is_refused(db_session):
    _, p = await _profile(db_session)
    await bf.record(db_session, p, "discover", day=D1)
    await bf.record(db_session, p, "discover", entered=0, passed=0, detail={}, day=D1)
    assert await rows(db_session, p) == []
    with pytest.raises(ValueError):
        await bf.record(db_session, p, "made_up", entered=1)
    await bf.record(db_session, p, "discover", entered=-5, passed=-1, day=D1)       # negatives are floored, not subtracted
    assert await rows(db_session, p) == []


def test_detail_is_cleaned_to_small_positive_integers_under_safe_keys():
    big = {f"k{i}": 1 for i in range(40)}
    assert len(bf._clean_detail(big)) == bf.MAX_DETAIL_KEYS
    assert bf._clean_detail({"ok": 3, "Bad Key": 2, "x" * 41: 1, "zero": 0, "neg": -1, "flag": True, "text": "5", "float": 1.5, 7: 3, "good_2": 1}) == {"ok": 3, "good_2": 1}
    assert bf._clean_detail(None) == {} and bf._clean_detail("nope") == {}


async def test_the_safe_wrapper_swallows_a_failure_and_leaves_the_transaction_usable(db_session, monkeypatch):
    _, p = await _profile(db_session)

    async def boom(*a, **k):
        raise RuntimeError("database exploded")
    monkeypatch.setattr(bf, "record", boom)
    await bf.record_safe(db_session, p, "discover", entered=1)                       # no exception
    monkeypatch.undo()
    await bf.record_safe(db_session, p, "discover", entered=2, day=D1)               # and the session still works
    assert [r.entered for r in await rows(db_session, p)] == [2]
    await bf.record_safe(db_session, p, "not_a_stage", entered=1)                    # a programming error is also contained here
    assert [r.entered for r in await rows(db_session, p)] == [2]


async def test_a_database_error_while_counting_does_not_poison_the_surrounding_transaction(db_session, monkeypatch):
    from sqlalchemy import text
    _, p = await _profile(db_session)

    async def bad_sql(db, profile, stage, **kw):
        await db.execute(text("SELECT 1 / 0"))                                       # a real database error, which aborts a transaction that has no savepoint
    monkeypatch.setattr(bf, "record", bad_sql)
    await bf.record_safe(db_session, p, "discover", entered=1)
    monkeypatch.undo()
    await bf.record_safe(db_session, p, "discover", entered=3, day=D1)               # the same transaction is still usable
    assert [r.entered for r in await rows(db_session, p)] == [3]


async def test_the_summary_totals_merges_details_fills_empty_days_and_computes_rates(db_session):
    tenant, p = await _profile(db_session)
    await bf.record(db_session, p, "probe_select", entered=20, passed=5, detail={"probed_recently": 10, "not_similar_enough": 5}, day=D1)
    await bf.record(db_session, p, "probe_select", entered=10, passed=5, detail={"probed_recently": 2, "daily_cap": 3}, day=D2)
    s = await bf.summarise(db_session, tenant.id, profile_id=p.id, days=3, today=D2)
    stage = next(x for x in s["stages"] if x["key"] == "probe_select")
    assert (stage["entered"], stage["passed"], stage["dropped"], stage["pass_rate"]) == (30, 10, 20, 0.333)
    assert stage["detail"] == {"probed_recently": 12, "not_similar_enough": 5, "daily_cap": 3} and list(stage["detail"])[0] == "probed_recently"      # biggest reason first
    assert [d["day"] for d in stage["daily"]] == ["2026-10-04", "2026-10-05", "2026-10-06"]
    assert [(d["entered"], d["passed"]) for d in stage["daily"]] == [(0, 0), (20, 5), (10, 5)]
    empty = next(x for x in s["stages"] if x["key"] == "discover")
    assert empty["entered"] == 0 and empty["pass_rate"] is None and empty["detail"] == {} and [x["key"] for x in s["stages"]] == bf.STAGE_KEYS


async def test_the_summary_window_excludes_older_days_and_clamps_the_range(db_session):
    tenant, p = await _profile(db_session)
    await bf.record(db_session, p, "discover", entered=100, day=D2 - timedelta(days=10))
    await bf.record(db_session, p, "discover", entered=7, day=D2)
    week = await bf.summarise(db_session, tenant.id, profile_id=p.id, days=7, today=D2)
    assert next(x for x in week["stages"] if x["key"] == "discover")["entered"] == 7 and week["days"] == 7
    assert (await bf.summarise(db_session, tenant.id, days=0, today=D2))["days"] == 1
    assert (await bf.summarise(db_session, tenant.id, days=9999, today=D2))["days"] == 90 == len((await bf.summarise(db_session, tenant.id, days=9999, today=D2))["stages"][0]["daily"])


async def test_the_summary_is_scoped_to_the_tenant_and_optionally_the_brand(db_session):
    t1, a = await _profile(db_session)
    t2, b = await _profile(db_session)
    a2 = (await _brand(db_session, name=f"g-{uuid.uuid4().hex[:6]}.co.za"))[1]
    await bf.record(db_session, a, "discover", entered=1, day=D1)
    await bf.record(db_session, b, "discover", entered=50, day=D1)
    get = lambda s: next(x for x in s["stages"] if x["key"] == "discover")["entered"]            # noqa: E731
    assert get(await bf.summarise(db_session, t1.id, days=30, today=D1)) == 1
    assert get(await bf.summarise(db_session, t2.id, days=30, today=D1)) == 50
    assert get(await bf.summarise(db_session, t1.id, profile_id=b.id, days=30, today=D1)) == 0      # another tenant's brand id shows nothing
    assert a2 is not None


async def test_the_summary_includes_the_current_spread_of_candidates_by_status(db_session):
    tenant, p = await _profile(db_session)
    db_session.add_all([cand(p, "a.xyz", status="suspicious"), cand(p, "b.xyz", status="suspicious"), cand(p, "c.xyz", status="confirmed"), cand(p, "d.xyz", status="false_positive")])
    await db_session.commit()
    s = await bf.summarise(db_session, tenant.id, profile_id=p.id)
    assert s["outcomes"] == {"suspicious": 2, "confirmed": 1, "false_positive": 1}
    other_t, other_p = await _profile(db_session)
    assert (await bf.summarise(db_session, other_t.id, profile_id=p.id))["outcomes"] == {}          # not another tenant's candidates


def test_every_stage_has_the_fields_the_screen_needs_and_unique_keys():
    assert len(set(bf.STAGE_KEYS)) == len(bf.STAGES) == 8
    for s in bf.STAGES:
        assert {"key", "label", "unit", "passed_means", "needs"} <= set(s) and s["needs"] in (None, "probe", "render")
