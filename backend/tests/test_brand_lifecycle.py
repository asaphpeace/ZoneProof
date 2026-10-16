"""
Step 2.1 — the pure lifecycle model: stage derivation, transition events, velocity features.
No database, no network.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.services import brand_lifecycle as lc

T0 = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def obs(at, *, registered=True, resolving=False, mail=False, certified=False, ns=(), registered_at=None):
    return lc.Observation(at=at, registered=registered, resolving=resolving, mail=mail, certified=certified, ns=tuple(ns), registered_at=registered_at)


def kinds(adv):
    return [e.kind for e in adv.events]


# ── stage derivation ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("args,expected", [
    ((False, False, False, False), "unregistered"),
    ((None, False, False, False), "unregistered"),
    ((True, False, False, False), "registered"),
    ((True, True, False, False), "resolving"),
    ((True, False, True, False), "mail_enabled"),
    ((True, True, True, False), "mail_enabled"),
    ((True, True, True, True), "certified"),
    ((False, False, False, True), "certified"),
])
def test_derive_stage_takes_the_highest_rung(args, expected):
    assert lc.derive_stage(*args) == expected


def test_stage_order_is_the_ladder():
    assert lc.STAGES == ("unregistered", "registered", "resolving", "mail_enabled", "certified")
    assert [lc.STAGE_RANK[s] for s in lc.STAGES] == [0, 1, 2, 3, 4]


# ── first observation ────────────────────────────────────────────────────────

def test_first_observation_creates_state_baseline_and_one_event():
    adv = lc.advance(None, obs(T0, resolving=True, mail=True, ns=["b.ns", "a.ns"]))
    assert kinds(adv) == ["first_observed"] and adv.write_observation
    s = adv.state
    assert s["stage"] == "mail_enabled" and s["ns"] == ["a.ns", "b.ns"]
    assert set(s["baseline"]) == {"registered", "resolving", "mail"}, "flags already true at discovery are baseline, not progression"
    assert adv.events[0].window_start is None and adv.events[0].payload["stage"] == "mail_enabled"


def test_an_unknown_first_observation_concludes_nothing():
    adv = lc.advance(None, obs(T0, registered=None))
    assert adv.skipped and adv.state is None and adv.events == [] and not adv.write_observation


def test_unknown_registration_later_keeps_the_previous_answer():
    state = lc.advance(None, obs(T0)).state
    adv = lc.advance(state, obs(T0 + timedelta(hours=1), registered=None))
    assert adv.state["registered"] is True and adv.state["stage"] == "registered" and adv.events == []


# ── transitions ──────────────────────────────────────────────────────────────

def test_dormant_domain_waking_up_emits_activation_with_dormancy_length():
    reg = T0 - timedelta(days=40)
    s1 = lc.advance(None, obs(T0, registered_at=reg)).state
    t1 = T0 + timedelta(days=3)
    adv = lc.advance(s1, obs(t1, resolving=True, registered_at=reg))
    assert kinds(adv) == ["flag_gained", "stage_changed", "activated"]
    act = adv.events[-1]
    assert act.payload["days_dormant"] == 43 and act.payload["to"] == "resolving"
    assert act.observed_at == t1 and act.window_start == T0, "we only know it happened between the two observations"
    assert adv.state["stage"] == "resolving" and adv.state["stage_changed_at"] == t1.isoformat()
    assert adv.write_observation


def test_activation_only_fires_when_leaving_the_dormant_rungs():
    s = lc.advance(None, obs(T0, resolving=True)).state
    adv = lc.advance(s, obs(T0 + timedelta(days=1), resolving=True, mail=True))
    assert "activated" not in kinds(adv) and "stage_changed" in kinds(adv)
    assert [e.payload for e in adv.events if e.kind == "stage_changed"][0] == {"from": "resolving", "to": "mail_enabled", "direction": "up"}


def test_going_dark_is_recorded_as_a_regression_not_an_activation():
    s = lc.advance(None, obs(T0, resolving=True)).state
    adv = lc.advance(s, obs(T0 + timedelta(days=2), resolving=False))
    assert kinds(adv) == ["flag_lost", "stage_changed"]
    assert adv.events[1].payload["direction"] == "down" and adv.state["stage"] == "registered"


def test_a_certificate_is_sticky():
    s = lc.advance(None, obs(T0, resolving=True, certified=True)).state
    adv = lc.advance(s, obs(T0 + timedelta(hours=6), resolving=True, certified=False))
    assert adv.state["certified"] is True and adv.state["stage"] == "certified" and adv.events == []


def test_nameserver_change_is_an_event_but_first_ns_is_not():
    s = lc.advance(None, obs(T0)).state
    assert "ns_changed" not in kinds(lc.advance(s, obs(T0 + timedelta(hours=1), ns=["ns1.parking.example"])))
    s2 = lc.advance(s, obs(T0 + timedelta(hours=1), ns=["ns1.parking.example"])).state
    adv = lc.advance(s2, obs(T0 + timedelta(days=1), ns=["ns1.cloudflare.example", "ns2.cloudflare.example"]))
    assert kinds(adv) == ["ns_changed"] and adv.events[0].payload["from"] == ["ns1.parking.example"]


def test_nothing_changed_means_no_events_and_no_row_until_the_heartbeat():
    s = lc.advance(None, obs(T0, resolving=True)).state
    quiet = lc.advance(s, obs(T0 + timedelta(hours=6), resolving=True))
    assert quiet.events == [] and not quiet.write_observation
    assert quiet.state["last_obs_at"] == (T0 + timedelta(hours=6)).isoformat(), "the observation time still advances"
    beat = lc.advance(quiet.state, obs(T0 + timedelta(hours=31), resolving=True))
    assert beat.events == [] and beat.write_observation, "one heartbeat row once the last observation is a day old"


def test_event_window_starts_at_the_previous_observation_even_without_a_written_row():
    s = lc.advance(None, obs(T0)).state
    s = lc.advance(s, obs(T0 + timedelta(hours=6))).state             # quiet pass, no row written
    adv = lc.advance(s, obs(T0 + timedelta(hours=12), resolving=True))
    assert adv.events[0].window_start == T0 + timedelta(hours=6)


# ── velocity ─────────────────────────────────────────────────────────────────

def test_dormant_candidate_reports_how_long_it_has_been_dormant():
    reg = T0 - timedelta(days=20)
    s = lc.advance(None, obs(T0, registered_at=reg)).state
    v = lc.velocity(s, T0 + timedelta(days=5))
    assert v["dormant"] and v["dormant_days"] == 25 and not v["activated"] and v["stage"] == "registered"


def test_activation_after_dormancy_is_reported():
    reg = T0 - timedelta(days=30)
    s = lc.advance(None, obs(T0, registered_at=reg)).state
    s = lc.advance(s, obs(T0 + timedelta(days=4), resolving=True, registered_at=reg)).state
    v = lc.velocity(s, T0 + timedelta(days=5))
    assert v["activated"] and v["days_dormant_before_activation"] == 34 and not v["dormant"]
    assert [g["flag"] for g in v["gained_after_discovery"]] == ["resolving"]


def test_discovered_already_active_is_not_counted_as_activation_or_progression():
    s = lc.advance(None, obs(T0, resolving=True, mail=True, certified=True)).state
    v = lc.velocity(s, T0 + timedelta(days=30))
    assert v["activated"] is False and v["fast_progression"] is False and v["gained_after_discovery"] == []


def test_fast_progression_needs_two_rungs_gained_after_discovery_within_a_week():
    s = lc.advance(None, obs(T0)).state
    s = lc.advance(s, obs(T0 + timedelta(days=1), resolving=True)).state
    assert lc.velocity(s, T0 + timedelta(days=2))["fast_progression"] is False, "one rung is not a pattern"
    s = lc.advance(s, obs(T0 + timedelta(days=3), resolving=True, mail=True)).state
    v = lc.velocity(s, T0 + timedelta(days=4))
    assert v["fast_progression"] is True and v["progression_hours"] == 48.0

    slow = lc.advance(None, obs(T0)).state
    slow = lc.advance(slow, obs(T0 + timedelta(days=1), resolving=True)).state
    slow = lc.advance(slow, obs(T0 + timedelta(days=20), resolving=True, mail=True)).state
    assert lc.velocity(slow, T0 + timedelta(days=21))["fast_progression"] is False


def test_age_in_stage_and_empty_state():
    s = lc.advance(None, obs(T0, resolving=True)).state
    assert lc.velocity(s, T0 + timedelta(hours=10))["age_in_stage_hours"] == 10.0
    assert lc.velocity(None, T0) == {} and lc.ladder(None)[0]["reached"] is False


def test_ladder_marks_baseline_rungs_and_the_current_one():
    s = lc.advance(None, obs(T0)).state
    s = lc.advance(s, obs(T0 + timedelta(days=1), resolving=True)).state
    rows = {r["stage"]: r for r in lc.ladder(s)}
    assert rows["registered"]["reached"] and rows["registered"]["baseline"] and not rows["registered"]["current"]
    assert rows["resolving"]["reached"] and not rows["resolving"]["baseline"] and rows["resolving"]["current"]
    assert rows["resolving"]["first_seen_at"] == (T0 + timedelta(days=1)).isoformat()
    assert not rows["mail_enabled"]["reached"] and not rows["certified"]["reached"]
    assert list(rows) == ["registered", "resolving", "mail_enabled", "certified"]
