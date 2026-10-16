import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models import BrandCandidate, BrandProfile
from app.services import brand_exposure as be
from app.services.posture_service import DomainSentinelInput, compute_sentinel_score
from tests.factories import make_domain, make_tenant
from tests.test_brand_graph import _brand, cand

GOOD = [DomainSentinelInput(dmarc_stage="reject", tls_stage="enforce", tls_pass_pct=100, min_cert_days=90, cert_status=None, volume=100)]


def test_no_exposure_is_a_perfect_score_with_no_components():
    assert be.score(0, 0, 0) == {"score": 100, "components": []}


def test_penalties_add_up_and_each_has_a_cap():
    assert be.score(1, 0, 0)["score"] == 85 and be.score(0, 1, 0)["score"] == 90 and be.score(0, 0, 1)["score"] == 96
    assert be.score(100, 0, 0)["score"] == 100 - be.CAP_LIVE_CONFIRMED
    assert be.score(0, 100, 0)["score"] == 100 - be.CAP_OVERDUE
    assert be.score(0, 0, 100)["score"] == 100 - be.CAP_UNDECIDED_LIVE
    assert be.CAP_LIVE_CONFIRMED + be.CAP_OVERDUE + be.CAP_UNDECIDED_LIVE == 110      # the caps can add past 100, so the total is clamped


def test_the_score_never_goes_below_zero_and_components_name_what_moved_it():
    r = be.score(100, 100, 100)
    assert 0 <= r["score"] <= 100
    assert [c["points"] for c in be.score(2, 1, 3)["components"]] == [-30, -10, -12] and be.score(2, 1, 3)["score"] == 48


def test_the_sentinel_score_is_exactly_unchanged_when_there_is_no_brand_signal():
    base = compute_sentinel_score(GOOD)
    assert compute_sentinel_score(GOOD, brand_exposure_score=None) == base and base.pillar_brand_exposure is None


def test_a_brand_signal_blends_in_at_the_stated_weight_and_can_lower_the_score():
    base = compute_sentinel_score(GOOD)
    worse = compute_sentinel_score(GOOD, brand_exposure_score=0)
    assert worse.score < base.score and worse.pillar_brand_exposure == 0
    # email auth weight 20, brand 15: a perfect email score blended with 0 brand points is 20/35
    assert worse.score == round(100 * 20 / 35)
    assert compute_sentinel_score(GOOD, brand_exposure_score=100).score == base.score


async def _profile(db, scanned=True):
    tenant, profile = await _brand(db, name=f"acme-{uuid.uuid4().hex[:8]}.co.za")
    if scanned:
        profile.last_scanned_at = datetime.now(timezone.utc)
        await db.commit()
    return tenant, profile


async def test_compute_is_none_without_an_active_scanned_brand(db_session):
    t = await make_tenant(db_session, name="NoBrand")
    await db_session.commit()
    assert await be.compute(db_session, t.id) is None
    tenant, _ = await _profile(db_session, scanned=False)
    assert await be.compute(db_session, tenant.id) is None            # never scanned: nothing to measure yet
    assert await be.compute_score(db_session, tenant.id) is None


async def test_compute_counts_only_live_confirmed_overdue_and_undecided_live(db_session):
    tenant, profile = await _profile(db_session)
    now = datetime.now(timezone.utc)

    def mk(domain, status, stage="resolving", due=None):
        c = cand(profile, domain, status=status)
        c.stage, c.due_at = stage, due
        return c
    db_session.add_all([
        mk("a.xyz", "confirmed", due=now + timedelta(hours=2)), mk("b.xyz", "takedown", due=now - timedelta(hours=1)), mk("c.xyz", "confirmed", stage="registered"),
        mk("d.xyz", "suspicious"), mk("e.xyz", "suspicious", stage="registered"), mk("f.xyz", "false_positive"), mk("g.xyz", "removed", due=now - timedelta(days=1)),
    ])
    await db_session.commit()
    d = await be.compute(db_session, tenant.id)
    # live confirmed: a, b (c is not live) = 2 -> -30; overdue open cases: b = 1 -> -10; undecided live: d = 1 -> -4
    assert d["score"] == 56 and d["open_cases"] == 3 and d["need_decision"] == 2 and d["brands"] == 1
    assert [c["points"] for c in d["components"]] == [-30, -10, -4]


async def test_another_tenants_candidates_never_count(db_session):
    t1, p1 = await _profile(db_session)
    t2, p2 = await _profile(db_session)
    c = cand(p2, "x.xyz", status="confirmed")
    db_session.add(c)
    await db_session.commit()
    assert (await be.compute(db_session, t1.id))["score"] == 100 and (await be.compute(db_session, t2.id))["score"] == 85


async def test_an_inactive_brand_is_ignored(db_session):
    tenant, profile = await _profile(db_session)
    db_session.add(cand(profile, "x.xyz", status="confirmed"))
    profile.is_active = False
    await db_session.commit()
    assert await be.compute(db_session, tenant.id) is None


def test_the_report_section_appears_only_for_brand_guard_tenants_escapes_and_admits_it_is_judgement():
    from app.services.pdf_report_service import _brand_guard_section_html
    assert _brand_guard_section_html(None) == ""
    html = _brand_guard_section_html({"score": 70, "brands": 2, "open_cases": 3, "need_decision": 4, "components": [{"label": "A <b>x</b>", "count": 1, "points": -15}]})
    assert "70/100" in html and "2 protected brand" in html and "&lt;b&gt;x&lt;/b&gt;" in html and "judgement calls" in html
    assert "No live look-alikes" in _brand_guard_section_html({"score": 100, "brands": 1, "open_cases": 0, "need_decision": 0, "components": []})


async def test_the_overview_and_report_data_carry_the_pillar_only_when_there_is_a_signal(auth_client, db_session):
    from tests.test_brand_guard_api import _pro_profile
    client, tenant = auth_client
    pid = await _pro_profile(client, tenant, db_session)
    ov = (await client.get("/overview")).json()["sentinel"]
    assert ov["pillar_brand_exposure"] is None
    profile = await db_session.get(BrandProfile, uuid.UUID(pid))
    profile.last_scanned_at = datetime.now(timezone.utc)
    row = cand(profile, "x.xyz", status="confirmed")
    db_session.add(row)
    await db_session.commit()
    ov = (await client.get("/overview")).json()["sentinel"]
    assert ov["pillar_brand_exposure"] == 85
    rep = (await client.get("/overview/report-data")).json()
    assert rep["brand_guard"]["score"] == 85 and rep["sentinel"]["pillar_brand_exposure"] == 85


async def test_a_look_alike_being_triaged_counts_as_waiting_for_a_decision(db_session):
    tenant, profile = await _profile(db_session)
    a, b = cand(profile, "t1.xyz", status="triaging"), cand(profile, "t2.xyz", status="suspicious")
    a.stage = b.stage = "resolving"
    db_session.add_all([a, b])
    await db_session.commit()
    d = await be.compute(db_session, tenant.id)
    assert d["need_decision"] == 2 and d["score"] == 100 - 2 * be.PER_UNDECIDED_LIVE
