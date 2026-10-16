"""
Step 2.1 — lifecycle in the scan pipeline: registered-but-dormant domains are tracked (they were
dropped before), history is written only when it carries information, activation raises one
alert, and the API exposes stage, timeline and the dormant/open split.
"""
import importlib.util
import uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone

import dns.exception
import dns.resolver
import pytest
from sqlalchemy import func, select, text

from app.models import (
    Alert, BrandCandidate, BrandCandidateEvent, BrandCandidateObservation, BrandProfile,
)
from app.models.user import Tenant
from app.services import brand_guard_service as svc
from app.services import brand_lifecycle as lc
from app.services.brand_scoring_service import assess_candidate
from tests.factories import make_domain, make_tenant, make_user

T0 = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
LOOKALIKE = "acmefinancia1.co.za"        # a generated homoglyph of acmefinancial.co.za (high identity)


class _Borrowed:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *exc):
        return False


# ── the DNS probe (registration is observable) ───────────────────────────────

class _Answer(str):
    pass


def _fake_resolver(monkeypatch, table: dict):
    """table[(name, rtype)] -> list of values | an exception instance. Anything absent is NXDOMAIN."""
    calls: list[tuple[str, str]] = []

    async def resolve(name, rtype):
        calls.append((name, rtype))
        outcome = table.get((name, rtype), dns.resolver.NXDOMAIN())
        if isinstance(outcome, Exception):
            raise outcome
        return [_Answer(v) for v in outcome]

    monkeypatch.setattr(svc.resolver, "resolve", resolve)
    return calls


async def test_probe_nxdomain_means_unregistered_and_costs_one_query(monkeypatch):
    calls = _fake_resolver(monkeypatch, {})
    r = await svc._dns_enrich("nothing.example")
    assert r == {"has_a": False, "has_aaaa": False, "has_mx": False, "registered": False, "ns": [], "a": [], "mx": []}
    assert calls == [("nothing.example", "NS")], "an NXDOMAIN on NS settles it without three more queries"


async def test_probe_registered_but_empty_is_registered_not_unregistered(monkeypatch):
    """NoAnswer = the name EXISTS but has no records of that type. This is the dormant domain the old
    code could not see."""
    _fake_resolver(monkeypatch, {
        ("dormant.example", "NS"): ["NS1.Parking.Example.", "ns2.parking.example."],
        ("dormant.example", "A"): dns.resolver.NoAnswer(), ("dormant.example", "AAAA"): dns.resolver.NoAnswer(),
        ("dormant.example", "MX"): dns.resolver.NoAnswer(),
    })
    r = await svc._dns_enrich("dormant.example")
    assert r["registered"] is True and not (r["has_a"] or r["has_aaaa"] or r["has_mx"])
    assert r["ns"] == ["ns1.parking.example", "ns2.parking.example"], "lower-cased, trailing dot removed"


async def test_probe_reads_each_record_type(monkeypatch):
    _fake_resolver(monkeypatch, {
        ("live.example", "NS"): ["ns.example."], ("live.example", "A"): ["203.0.113.5"],
        ("live.example", "AAAA"): dns.resolver.NoAnswer(), ("live.example", "MX"): ["10 mx.example."],
    })
    r = await svc._dns_enrich("live.example")
    assert (r["registered"], r["has_a"], r["has_aaaa"], r["has_mx"]) == (True, True, False, True)


async def test_probe_dns_failures_are_unknown_never_unregistered(monkeypatch):
    _fake_resolver(monkeypatch, {(n, t): dns.exception.Timeout() for n in ("slow.example",) for t in ("NS", "A", "AAAA", "MX")})
    assert (await svc._dns_enrich("slow.example"))["registered"] is None


async def test_probe_any_answer_proves_existence_even_if_ns_failed(monkeypatch):
    _fake_resolver(monkeypatch, {
        ("odd.example", "NS"): dns.resolver.NoNameservers(), ("odd.example", "A"): ["198.51.100.9"],
        ("odd.example", "AAAA"): dns.resolver.NoAnswer(), ("odd.example", "MX"): dns.resolver.NoAnswer(),
    })
    assert (await svc._dns_enrich("odd.example"))["registered"] is True


# ── pipeline harness ─────────────────────────────────────────────────────────

@pytest.fixture
def world(monkeypatch, db_session):
    """Mutable fake internet + a controllable clock."""
    w = {"clock": T0, "dns": {}, "reg": {}, "ct": {}}

    async def fake_dns(domain):
        return w["dns"].get(domain, {"has_a": False, "has_aaaa": False, "has_mx": False, "registered": False, "ns": []})

    async def fake_reg(client, domain):
        return w["reg"].get(domain)

    async def fake_ct(db, tokens, since):
        return dict(w["ct"])

    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_registration_date", fake_reg)
    monkeypatch.setattr(svc, "fetch_ct_candidates", fake_ct)
    monkeypatch.setattr(svc, "_now", lambda: w["clock"])
    monkeypatch.setattr(svc, "_session_factory", lambda: _Borrowed(db_session))
    return w


def dormant(ns=("ns1.parking.example",)):
    return {"has_a": False, "has_aaaa": False, "has_mx": False, "registered": True, "ns": list(ns)}


def live(*, mail=False, ns=("ns1.parking.example",)):
    return {"has_a": True, "has_aaaa": False, "has_mx": mail, "registered": True, "ns": list(ns)}


async def _profile(client, tenant, db_session) -> uuid.UUID:
    tenant.plan = "pro"
    domain = await make_domain(db_session, tenant, name="acmefinancial.co.za")
    domain.ownership_verified = True
    await db_session.commit()
    return uuid.UUID((await client.post("/brand-guard/profiles", json={"domain_id": str(domain.id), "brand_name": "Acme Financial"})).json()["id"])


async def _scan(db, profile_id: uuid.UUID) -> None:
    profile, tenant = await db.get(BrandProfile, profile_id), None
    tenant = await db.get(Tenant, profile.tenant_id)
    run, _ = await svc.start_scan_run(db, profile, triggered_by="manual")
    await svc._run_scan(db, run, profile, tenant)


async def _candidate(db, domain=LOOKALIKE) -> BrandCandidate:
    return (await db.execute(select(BrandCandidate).where(BrandCandidate.candidate_domain == domain))).scalar_one()


async def _events(db, cand) -> list[BrandCandidateEvent]:
    return list((await db.execute(
        select(BrandCandidateEvent).where(BrandCandidateEvent.candidate_id == cand.id).order_by(BrandCandidateEvent.occurred_at, BrandCandidateEvent.kind)
    )).scalars().all())


async def _count(db, model, cand) -> int:
    return (await db.execute(select(func.count()).select_from(model).where(model.candidate_id == cand.id))).scalar_one()


# ── dormant tracking ─────────────────────────────────────────────────────────

async def test_registered_but_dormant_lookalike_is_tracked_and_nonexistent_ones_are_not(auth_client, db_session, world):
    client, tenant = auth_client
    pid = await _profile(client, tenant, db_session)
    world["dns"][LOOKALIKE] = dormant()
    world["reg"][LOOKALIKE] = T0 - timedelta(days=10)
    world["dns"]["acmefinancial.org"] = {"has_a": False, "has_aaaa": False, "has_mx": False, "registered": None, "ns": []}   # DNS could not say

    await _scan(db_session, pid)

    rows = (await db_session.execute(select(BrandCandidate))).scalars().all()
    assert [r.candidate_domain for r in rows] == [LOOKALIKE], "dormant is kept; NXDOMAIN and unknown are not"
    cand = rows[0]
    assert cand.stage == "registered" and cand.lifecycle["baseline"] == ["registered"] and cand.last_observed_at == T0
    assert [e.kind for e in await _events(db_session, cand)] == ["first_observed"]
    assert await _count(db_session, BrandCandidateObservation, cand) == 1
    assert cand.status in ("new", "monitoring"), "a dormant name must not be raised as suspicious"
    detail = (await client.get(f"/brand-guard/candidates/{cand.id}")).json()
    assert any("watched for activation" in e["summary"] for e in detail["evidence"])
    assert not any(e["signal"] == "no_infrastructure" for e in detail["evidence"])


async def test_quiet_rescans_write_nothing_new_until_the_daily_heartbeat(auth_client, db_session, world):
    client, tenant = auth_client
    pid = await _profile(client, tenant, db_session)
    world["dns"][LOOKALIKE] = dormant()
    await _scan(db_session, pid)

    world["clock"] = T0 + timedelta(hours=6)
    await _scan(db_session, pid)
    cand = await _candidate(db_session)
    assert await _count(db_session, BrandCandidateObservation, cand) == 1 and len(await _events(db_session, cand)) == 1
    assert cand.last_observed_at == T0 + timedelta(hours=6), "we did look; the observation time advances without a row"

    world["clock"] = T0 + timedelta(hours=31)
    await _scan(db_session, pid)
    cand = await _candidate(db_session)
    assert await _count(db_session, BrandCandidateObservation, cand) == 2, "one heartbeat row once the last is a day old"
    assert len(await _events(db_session, cand)) == 1


# ── activation ───────────────────────────────────────────────────────────────

async def test_dormant_domain_waking_up_raises_one_activation_alert_with_its_evidence(auth_client, db_session, world):
    client, tenant = auth_client
    pid = await _profile(client, tenant, db_session)
    world["dns"][LOOKALIKE] = dormant()
    world["reg"][LOOKALIKE] = T0 - timedelta(days=40)
    await _scan(db_session, pid)
    assert (await db_session.execute(select(func.count()).select_from(Alert).where(Alert.category == "brand"))).scalar_one() == 0

    world["clock"] = T0 + timedelta(days=3)
    world["dns"][LOOKALIKE] = live(mail=True)
    await _scan(db_session, pid)

    cand = await _candidate(db_session)
    kinds = [e.kind for e in await _events(db_session, cand)]
    assert {"flag_gained", "stage_changed", "activated"} <= set(kinds) and kinds.count("activated") == 1
    act = next(e for e in await _events(db_session, cand) if e.kind == "activated")
    assert act.payload["days_dormant"] == 43 and act.window_start == T0 and act.occurred_at == T0 + timedelta(days=3)
    assert cand.stage == "mail_enabled" and cand.stage_changed_at == T0 + timedelta(days=3)

    alerts = (await db_session.execute(select(Alert).where(Alert.category == "brand"))).scalars().all()
    assert len(alerts) == 1 and alerts[0].title == f"Dormant lookalike just went live: {LOOKALIKE}"
    assert "about 43 days ago" in alerts[0].body and "between our last two checks" in alerts[0].body
    assert cand.alerted_at is not None

    detail = (await client.get(f"/brand-guard/candidates/{cand.id}")).json()
    signals = {e["signal"] for e in detail["evidence"]}
    assert "dormant_activated" in signals and "dormant" not in signals

    world["clock"] = T0 + timedelta(days=4)
    await _scan(db_session, pid)                                         # steady state: nothing new
    assert (await db_session.execute(select(func.count()).select_from(Alert).where(Alert.category == "brand"))).scalar_one() == 1
    assert [e.kind for e in await _events(db_session, await _candidate(db_session))].count("activated") == 1


async def test_going_dark_then_certificate_are_recorded_and_the_certificate_is_sticky(auth_client, db_session, world):
    client, tenant = auth_client
    pid = await _profile(client, tenant, db_session)
    world["dns"][LOOKALIKE] = live(mail=True)
    await _scan(db_session, pid)

    world["clock"] = T0 + timedelta(days=1)
    world["dns"][LOOKALIKE] = dormant()
    await _scan(db_session, pid)
    cand = await _candidate(db_session)
    assert cand.stage == "registered" and {"flag_lost", "stage_changed"} <= {e.kind for e in await _events(db_session, cand)}

    world["clock"] = T0 + timedelta(days=2)
    world["ct"] = {LOOKALIKE: {"issued_at": (T0 + timedelta(days=2)).isoformat()}}
    await _scan(db_session, pid)
    assert (await _candidate(db_session)).stage == "certified"

    world["clock"] = T0 + timedelta(days=3)
    world["ct"] = {}
    await _scan(db_session, pid)
    assert (await _candidate(db_session)).stage == "certified", "a certificate never un-issues"


async def test_fast_progression_after_discovery_is_scored(auth_client, db_session, world):
    client, tenant = auth_client
    pid = await _profile(client, tenant, db_session)
    world["dns"][LOOKALIKE] = dormant()
    await _scan(db_session, pid)
    world["clock"] = T0 + timedelta(days=1)
    world["dns"][LOOKALIKE] = live()
    await _scan(db_session, pid)
    world["clock"] = T0 + timedelta(days=2)
    world["dns"][LOOKALIKE] = live(mail=True)
    await _scan(db_session, pid)
    cand = await _candidate(db_session)
    detail = (await client.get(f"/brand-guard/candidates/{cand.id}")).json()
    assert "fast_progression" in {e["signal"] for e in detail["evidence"]}


# ── API surface ──────────────────────────────────────────────────────────────

async def test_timeline_endpoint_and_isolation(auth_client, db_session, world):
    client, tenant = auth_client
    pid = await _profile(client, tenant, db_session)
    world["dns"][LOOKALIKE] = dormant()
    world["reg"][LOOKALIKE] = T0 - timedelta(days=20)
    await _scan(db_session, pid)
    world["clock"] = T0 + timedelta(days=2)
    world["dns"][LOOKALIKE] = live()
    await _scan(db_session, pid)
    cand = await _candidate(db_session)

    t = (await client.get(f"/brand-guard/candidates/{cand.id}/timeline")).json()
    assert t["stage"] == "resolving" and t["stage_label"] == "Resolving"
    rungs = {r["stage"]: r for r in t["ladder"]}
    assert rungs["registered"]["baseline"] and rungs["resolving"]["current"] and not rungs["resolving"]["baseline"]
    assert not rungs["mail_enabled"]["reached"]
    kinds = [e["kind"] for e in t["events"]]
    assert kinds[0] == "first_observed" and "activated" in kinds
    assert any("after sitting dormant for about 22 days" in e["summary"] for e in t["events"])
    activated = next(e for e in t["events"] if e["kind"] == "activated")
    assert activated["window_start"] is not None, "the real change is bracketed by two observations, not an exact time"
    assert t["velocity"]["activated"] is True and t["observations"]["count"] == 2

    other = await make_tenant(db_session, name="Other", plan="pro")
    await make_user(db_session, other, email="other-lc@test.com", password="pass123")
    await db_session.commit()
    login = await client.post("/auth/token", data={"username": "other-lc@test.com", "password": "pass123"},
                              headers={"Content-Type": "application/x-www-form-urlencoded"})
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
    assert (await client.get(f"/brand-guard/candidates/{cand.id}/timeline")).status_code == 404


async def test_dormant_candidates_are_kept_out_of_needs_review_but_counted_and_filterable(auth_client, db_session, world):
    client, tenant = auth_client
    pid = await _profile(client, tenant, db_session)
    world["dns"][LOOKALIKE] = dormant()
    await _scan(db_session, pid)

    assert (await client.get("/brand-guard/candidates", params={"status": "open"})).json() == []
    dormant_rows = (await client.get("/brand-guard/candidates", params={"status": "dormant"})).json()
    assert [c["candidate_domain"] for c in dormant_rows] == [LOOKALIKE] and dormant_rows[0]["stage"] == "registered"
    s = (await client.get("/brand-guard/summary")).json()
    assert s["dormant"] == 1 and s["open_candidates"] == 0
    assert len((await client.get("/brand-guard/candidates", params={"stage": "registered"})).json()) == 1

    world["clock"] = T0 + timedelta(days=1)
    world["dns"][LOOKALIKE] = live(mail=True)
    await _scan(db_session, pid)
    assert [c["candidate_domain"] for c in (await client.get("/brand-guard/candidates", params={"status": "open"})).json()] == [LOOKALIKE]
    s = (await client.get("/brand-guard/summary")).json()
    assert s["dormant"] == 0 and s["open_candidates"] == 1
    assert (await client.get("/brand-guard/candidates", params={"status": "dormant"})).json() == []


async def test_deleting_a_brand_removes_its_lifecycle_history(auth_client, db_session, world):
    client, tenant = auth_client
    pid = await _profile(client, tenant, db_session)
    world["dns"][LOOKALIKE] = dormant()
    await _scan(db_session, pid)
    world["clock"] = T0 + timedelta(days=1)
    world["dns"][LOOKALIKE] = live()
    await _scan(db_session, pid)
    assert (await db_session.execute(select(func.count()).select_from(BrandCandidateEvent))).scalar_one() > 0

    assert (await client.delete(f"/brand-guard/profiles/{pid}")).status_code == 204
    db_session.expire_all()
    for model in (BrandCandidate, BrandCandidateObservation, BrandCandidateEvent):
        assert (await db_session.execute(select(func.count()).select_from(model))).scalar_one() == 0


# ── scoring and wording (pure) ───────────────────────────────────────────────

def _score(**life):
    return assess_candidate(LOOKALIKE, primary_domain="acmefinancial.co.za", official_domains=[], brand_tokens=["acmefinancial"],
                            discovery_class="homoglyph", enrichment={"has_a": True}, lifecycle=life)


def test_dormant_activation_signal_needs_a_real_dormancy():
    long_dormant = _score(activated=True, days_dormant_before_activation=30)
    short = _score(activated=True, days_dormant_before_activation=5)
    plain = _score()
    assert "dormant_activated" in {s.signal for s in long_dormant.signals} and long_dormant.abuse_score == plain.abuse_score + 15
    assert "dormant_activated" not in {s.signal for s in short.signals} and short.abuse_score == plain.abuse_score


def test_fast_progression_and_dormant_signals():
    fast = _score(fast_progression=True, progression_hours=36.0, gained_after_discovery=[{"flag": "resolving"}, {"flag": "mail"}])
    assert next(s for s in fast.signals if s.signal == "fast_progression").data["steps"] == ["resolving", "mail"]
    assert fast.abuse_score == _score().abuse_score + 10
    d = _score(dormant=True, dormant_days=12)
    assert next(s for s in d.signals if s.signal == "dormant").weight == 0.0 and "12 days ago" in next(s for s in d.signals if s.signal == "dormant").summary


def test_scoring_without_lifecycle_is_unchanged():
    a = assess_candidate(LOOKALIKE, primary_domain="acmefinancial.co.za", official_domains=[], brand_tokens=["acmefinancial"],
                         discovery_class="homoglyph", enrichment={"has_a": True})
    assert a.abuse_score == _score().abuse_score


@pytest.mark.parametrize("kind,payload,expected", [
    ("first_observed", {"stage": "registered"}, "First observed — registered"),
    ("flag_gained", {"flag": "mail"}, "Detected mail (MX) records"),
    ("stage_changed", {"from": "registered", "to": "resolving", "direction": "up"}, "Moved up the ladder: registered → resolving"),
    ("activated", {"days_dormant": 43, "to": "resolving"}, "Went live after sitting dormant for about 43 days (resolving)"),
    ("activated", {"days_dormant": None, "to": "mail_enabled"}, "Went live (mail-enabled)"),
    ("ns_changed", {}, "Nameservers changed"),
])
def test_event_descriptions(kind, payload, expected):
    assert lc.describe_event(kind, payload) == expected


# ── migration backfill ───────────────────────────────────────────────────────

async def test_migration_backfill_labels_pre_lifecycle_rows_by_their_recorded_facts(db_session):
    """Rows saved before the lifecycle existed had signs of life, so the column default 'registered' would
    wrongly show live domains as dormant until the next scan. The backfill must read each row's own facts."""
    path = Path(__file__).resolve().parent.parent / "alembic" / "versions" / "a3e8c1d5b7f2_add_candidate_lifecycle.py"
    spec = importlib.util.spec_from_file_location("lifecycle_migration", path)
    mig = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mig)

    await db_session.execute(text("create temporary table brand_candidates (id int, enrichment jsonb, stage text default 'registered')"))
    await db_session.execute(text(
        "insert into brand_candidates (id, enrichment) values "
        "(1, '{\"ct_hit\": true, \"has_a\": true}'), (2, '{\"has_mx\": true, \"has_a\": true}'), (3, '{\"has_a\": true}'), "
        "(4, '{\"has_a\": false, \"has_mx\": false}'), (5, '{}')"
    ))
    await db_session.execute(text(mig._BACKFILL_STAGE_SQL))
    rows = dict((await db_session.execute(text("select id, stage from brand_candidates order by id"))).all())
    assert rows == {1: "certified", 2: "mail_enabled", 3: "resolving", 4: "registered", 5: "registered"}
