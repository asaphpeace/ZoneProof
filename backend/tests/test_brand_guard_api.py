"""
Router + pipeline tests for Brand Guard. Network sensors (DNS, RDAP, CT) are
monkeypatched — what's under test is plan gating, tenant isolation, the
noise filter (only live/registered candidates persist), alert-once behaviour,
analyst decisions surviving rescans, and the background scan-run lifecycle
(202 + polling, one active run per brand, failure/timeout recording, restart
recovery, scheduler).
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models import Alert, BrandCandidate, BrandProfile, BrandScanRun
from app.services import brand_guard_service as svc
from tests.factories import make_domain, make_tenant, make_user


class _Borrowed:
    """Lets the background run use the test's own (savepoint-wrapped) session
    instead of opening a real one, and never closes it."""
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *exc):
        return False


@pytest.fixture(autouse=True)
def _background_runs_use_test_session(db_session, monkeypatch):
    monkeypatch.setattr(svc, "_session_factory", lambda: _Borrowed(db_session))


async def _verified_domain(db, tenant, name="acmefinancial.co.za"):
    d = await make_domain(db, tenant, name=name)
    d.ownership_verified = True
    await db.commit()
    return d


def _listed(monkeypatch, domains):
    """Public abuse feeds list these domains. Liveness alone no longer makes a look-alike alert-worthy (measured: brand_eval.abuse_lr),
    so the tests that exercise alerting give the candidate real abuse evidence."""
    from app.services import brand_feeds
    monkeypatch.setattr(brand_feeds, "lookup", lambda d, feeds=None: [{"feed": "phishunt", "label": "phishunt.io", "first_seen": "2026-10-01", "same_site": False, "detail": {"other_flags": 0}}] if d in domains else [])


def _fake_network(monkeypatch, live: dict[str, dict], registered_days: dict[str, int] | None = None, ct: dict | None = None):
    async def fake_dns(domain):
        return live.get(domain, {"has_a": False, "has_mx": False})

    async def fake_reg(client, domain):
        days = (registered_days or {}).get(domain)
        return datetime.now(timezone.utc) - timedelta(days=days) if days is not None else None

    async def fake_ct(db, tokens, since):
        return ct or {}

    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_registration_date", fake_reg)
    monkeypatch.setattr(svc, "fetch_ct_candidates", fake_ct)


async def _create_profile(client, domain, **extra):
    return await client.post("/brand-guard/profiles", json={
        "domain_id": str(domain.id), "brand_name": "Acme Financial", "keywords": ["pay"], **extra,
    })


async def _scan(client, profile_id) -> dict:
    """POST a scan, wait for the background run to finish, return the final run."""
    resp = await client.post(f"/brand-guard/profiles/{profile_id}/scan")
    assert resp.status_code == 202, resp.text
    run_id = resp.json()["id"]
    await svc.wait_for_run(uuid.UUID(run_id))
    final = await client.get(f"/brand-guard/scan-runs/{run_id}")
    assert final.status_code == 200
    return final.json()


async def _pro_profile(client, tenant, db_session):
    tenant.plan = "pro"
    domain = await _verified_domain(db_session, tenant)
    return (await _create_profile(client, domain)).json()["id"]


# ── plan gating / ownership ──────────────────────────────────────────────────

async def test_free_plan_cannot_enable_brand_guard(auth_client, db_session):
    client, tenant = auth_client
    domain = await _verified_domain(db_session, tenant)
    resp = await _create_profile(client, domain)
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "feature_not_available"


async def test_requires_verified_domain(auth_client, db_session):
    client, tenant = auth_client
    tenant.plan = "pro"
    domain = await make_domain(db_session, tenant, name="unverified.example.com")
    await db_session.commit()
    resp = await _create_profile(client, domain)
    assert resp.status_code == 400


async def test_starter_limited_to_one_brand(auth_client, db_session):
    client, tenant = auth_client
    tenant.plan = "starter"
    d1 = await _verified_domain(db_session, tenant, "one-brand.co.za")
    d2 = await _verified_domain(db_session, tenant, "two-brand.co.za")
    assert (await _create_profile(client, d1)).status_code == 201
    second = await _create_profile(client, d2)
    assert second.status_code == 403
    assert second.json()["detail"]["code"] == "brand_limit_reached"


# ── scan pipeline ────────────────────────────────────────────────────────────

async def test_scan_persists_only_candidates_with_signs_of_life(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    _listed(monkeypatch, {"acmefinancia1.co.za"})
    _fake_network(
        monkeypatch,
        live={"acmefinancia1.co.za": {"has_a": True, "has_mx": True}},
        registered_days={"acmefinancia1.co.za": 2},
    )

    run = await _scan(client, profile_id)
    assert run["status"] == "succeeded", run
    assert run["result"]["new_candidates"] == 1
    assert run["result"]["alerts"] == 1
    assert run["result"]["evaluated"] > 50  # hundreds generated, one persisted

    rows = (await db_session.execute(select(BrandCandidate))).scalars().all()
    assert [r.candidate_domain for r in rows] == ["acmefinancia1.co.za"]
    assert rows[0].status == "suspicious"

    detail = (await client.get(f"/brand-guard/candidates/{rows[0].id}")).json()
    assert detail["why_flagged"], "an alert must always be explainable"
    assert {e["dimension"] for e in detail["evidence"]} == {"identity", "abuse"}


async def test_rescan_does_not_realert_or_duplicate(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    _listed(monkeypatch, {"acmefinancia1.co.za"})
    _fake_network(monkeypatch, live={"acmefinancia1.co.za": {"has_a": True, "has_mx": True}},
                  registered_days={"acmefinancia1.co.za": 2})

    await _scan(client, profile_id)
    second = await _scan(client, profile_id)

    assert second["result"]["new_candidates"] == 0 and second["result"]["alerts"] == 0
    assert len((await db_session.execute(select(BrandCandidate))).scalars().all()) == 1
    alerts = (await db_session.execute(select(Alert).where(Alert.category == "brand"))).scalars().all()
    assert len(alerts) == 1


async def test_analyst_decision_survives_rescan(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    _fake_network(monkeypatch, live={"acmefinancia1.co.za": {"has_a": True, "has_mx": True}},
                  registered_days={"acmefinancia1.co.za": 2})
    await _scan(client, profile_id)
    cand = (await client.get("/brand-guard/candidates")).json()[0]

    resp = await client.patch(f"/brand-guard/candidates/{cand['id']}/status", json={"status": "false_positive", "note": "partner"})
    assert resp.status_code == 200

    await _scan(client, profile_id)
    after = (await client.get("/brand-guard/candidates", params={"status": "false_positive"})).json()
    assert len(after) == 1 and after[0]["analyst_note"] == "partner"


async def test_invalid_status_rejected(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    _fake_network(monkeypatch, live={"acmefinancia1.co.za": {"has_a": True}}, registered_days={"acmefinancia1.co.za": 2})
    await _scan(client, profile_id)
    cand = (await client.get("/brand-guard/candidates")).json()[0]
    resp = await client.patch(f"/brand-guard/candidates/{cand['id']}/status", json={"status": "bogus"})
    assert resp.status_code == 422


async def test_ct_hit_creates_candidate_on_ct_plans_only(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    host = "secure-acmefinancial-login.com"
    _fake_network(
        monkeypatch, live={host: {"has_a": True, "has_mx": False}}, registered_days={host: 1},
        ct={host: {"issued_at": datetime.now(timezone.utc).isoformat()}},
    )
    run = await _scan(client, profile_id)
    assert run["result"]["ct_enabled"] is True
    cand = next(c for c in (await client.get("/brand-guard/candidates")).json() if c["candidate_domain"] == host)
    assert "ct_log" in cand["sources"]


async def test_starter_scan_skips_ct(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    tenant.plan = "starter"
    domain = await _verified_domain(db_session, tenant)
    profile_id = (await _create_profile(client, domain)).json()["id"]
    host = "secure-acmefinancial-login.com"
    _fake_network(monkeypatch, live={host: {"has_a": True}}, ct={host: {"issued_at": datetime.now(timezone.utc).isoformat()}})
    run = await _scan(client, profile_id)
    assert run["result"]["ct_enabled"] is False
    assert all(c["candidate_domain"] != host for c in (await client.get("/brand-guard/candidates")).json())


async def test_tenant_isolation(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    _fake_network(monkeypatch, live={"acmefinancia1.co.za": {"has_a": True}}, registered_days={"acmefinancia1.co.za": 2})
    run = await _scan(client, profile_id)

    other = await make_tenant(db_session, name="Other", plan="pro")
    await make_user(db_session, other, email="other-bg@test.com", password="pass123")
    await db_session.commit()
    login = await client.post("/auth/token", data={"username": "other-bg@test.com", "password": "pass123"},
                              headers={"Content-Type": "application/x-www-form-urlencoded"})
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    assert (await client.get("/brand-guard/profiles")).json() == []
    assert (await client.post(f"/brand-guard/profiles/{profile_id}/scan")).status_code == 404
    assert (await client.get(f"/brand-guard/scan-runs/{run['id']}")).status_code == 404
    assert (await client.get(f"/brand-guard/profiles/{profile_id}/scan-runs")).status_code == 404


# ── scan-run lifecycle (step 0.2) ────────────────────────────────────────────

async def test_scan_returns_202_immediately_then_progress_and_result(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    _fake_network(monkeypatch, live={"acmefinancia1.co.za": {"has_a": True}}, registered_days={"acmefinancia1.co.za": 2})

    resp = await client.post(f"/brand-guard/profiles/{profile_id}/scan")
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "queued" and body["result"] is None and body["triggered_by"] == "manual"

    await svc.wait_for_run(uuid.UUID(body["id"]))
    final = (await client.get(f"/brand-guard/scan-runs/{body['id']}")).json()
    assert final["status"] == "succeeded"
    assert final["started_at"] and final["finished_at"]
    assert final["progress_total"] > 50, "progress must reflect the real candidate count"

    profile = (await client.get("/brand-guard/profiles")).json()[0]
    assert profile["latest_run"]["id"] == body["id"]
    history = (await client.get(f"/brand-guard/profiles/{profile_id}/scan-runs")).json()
    assert [r["id"] for r in history] == [body["id"]]


async def test_only_one_active_run_per_brand(auth_client, db_session):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    profile = await db_session.get(BrandProfile, uuid.UUID(profile_id))

    first, created_first = await svc.start_scan_run(db_session, profile, triggered_by="manual")
    second, created_second = await svc.start_scan_run(db_session, profile, triggered_by="manual")
    assert created_first is True and created_second is False
    assert first.id == second.id

    # The database enforces it too, not just the check above.
    db_session.add(BrandScanRun(id=uuid.uuid4(), tenant_id=profile.tenant_id, profile_id=profile.id, status="running"))
    with pytest.raises(IntegrityError):
        await db_session.flush()
    await db_session.rollback()


async def test_failed_scan_is_recorded_and_frees_the_slot(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)

    real_scan = svc.scan_profile

    async def boom(*a, **k):
        raise RuntimeError("upstream exploded")
    monkeypatch.setattr(svc, "scan_profile", boom)

    run = await _scan(client, profile_id)
    assert run["status"] == "failed"
    assert "RuntimeError" in run["error"]
    assert "upstream exploded" not in run["error"], "internal exception text must not reach the API"

    # the slot is free: a new scan is accepted as a *new* run
    monkeypatch.setattr(svc, "scan_profile", real_scan)
    _fake_network(monkeypatch, live={})
    again = await client.post(f"/brand-guard/profiles/{profile_id}/scan")
    assert again.status_code == 202 and again.json()["id"] != run["id"]
    await svc.wait_for_run(uuid.UUID(again.json()["id"]))


async def test_scan_timeout_marks_run_failed(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)

    async def hang(*a, **k):
        await asyncio.sleep(30)
    monkeypatch.setattr(svc, "scan_profile", hang)
    monkeypatch.setattr(svc.settings, "brand_guard_scan_timeout_seconds", 0.05)

    run = await _scan(client, profile_id)
    assert run["status"] == "failed"
    assert "timed out" in run["error"]


async def test_restart_recovery_fails_orphaned_runs(auth_client, db_session):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    profile = await db_session.get(BrandProfile, uuid.UUID(profile_id))
    run, _ = await svc.start_scan_run(db_session, profile, triggered_by="manual")
    run.status = "running"
    await db_session.commit()

    assert await svc.recover_interrupted_runs(db_session) == 1
    refreshed = (await client.get(f"/brand-guard/scan-runs/{run.id}")).json()
    assert refreshed["status"] == "failed" and "restart" in refreshed["error"]
    assert await svc.recover_interrupted_runs(db_session) == 0


async def test_scheduler_runs_due_brands_as_scheduled_runs(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    _fake_network(monkeypatch, live={"acmefinancia1.co.za": {"has_a": True, "has_mx": True}},
                  registered_days={"acmefinancia1.co.za": 2})

    assert await svc.scan_due_profiles(db_session) == 1
    history = (await client.get(f"/brand-guard/profiles/{profile_id}/scan-runs")).json()
    assert len(history) == 1
    assert history[0]["triggered_by"] == "scheduled" and history[0]["status"] == "succeeded"

    assert await svc.scan_due_profiles(db_session) == 0, "just scanned, nothing is due"


async def test_scheduler_skips_brand_with_an_active_manual_run(auth_client, db_session):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    profile = await db_session.get(BrandProfile, uuid.UUID(profile_id))
    await svc.start_scan_run(db_session, profile, triggered_by="manual")

    assert await svc.scan_due_profiles(db_session) == 0
