"""
Step 0.5 — audit and erasure coverage. Every user-initiated Brand Guard change leaves an audit entry
(who, what, before/after) in the same transaction as the change; the one automated verdict that raises
alerts is audited with no actor; and deleting a workspace or a user leaves no orphaned or blocking
Brand Guard data.
"""
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app.models import (
    AuditLogEntry, BrandCandidate, BrandCandidateEvent, BrandCandidateObservation, BrandProfile, BrandScanRun,
    BrandSourceHealth, CandidateEvidence, TenantErasureLog,
)
from app.models.user import Tenant, User
from app.services import brand_guard_service as svc
from tests.factories import make_domain, make_tenant, make_user

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


class _Borrowed:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *exc):
        return False


async def _entries(db, action=None) -> list[AuditLogEntry]:
    stmt = select(AuditLogEntry).where(AuditLogEntry.action.like("brand_guard.%")).order_by(AuditLogEntry.created_at, AuditLogEntry.id)
    if action:
        stmt = stmt.where(AuditLogEntry.action == action)
    return list((await db.execute(stmt)).scalars().all())


async def _create_profile(client, tenant, db_session, name="acmefinancial.co.za"):
    tenant.plan = "pro"
    domain = await make_domain(db_session, tenant, name=name)
    domain.ownership_verified = True
    await db_session.commit()
    resp = await client.post("/brand-guard/profiles", json={"domain_id": str(domain.id), "brand_name": "Acme Financial", "keywords": ["pay"]})
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _login(client, email, password):
    r = await client.post("/auth/token", data={"username": email, "password": password}, headers={"Content-Type": "application/x-www-form-urlencoded"})
    client.headers.update({"Authorization": f"Bearer {r.json()['access_token']}"})


# ── user actions are audited ─────────────────────────────────────────────────

async def test_profile_create_is_audited_with_actor_and_after_state(auth_client, db_session):
    client, tenant = auth_client
    pid = await _create_profile(client, tenant, db_session)
    [entry] = await _entries(db_session)
    assert entry.action == "brand_guard.profile_created" and entry.tenant_id == tenant.id
    assert entry.target_type == "brand_profile" and entry.target_id == pid and entry.target_label == "Acme Financial"
    assert entry.actor_email and entry.actor_user_id
    assert entry.after == {"domain": "acmefinancial.co.za", "keywords": ["pay"], "official_domains": []}


async def test_profile_update_records_only_what_changed_and_noop_leaves_nothing(auth_client, db_session):
    client, tenant = auth_client
    pid = await _create_profile(client, tenant, db_session)

    assert (await client.patch(f"/brand-guard/profiles/{pid}", json={"keywords": ["pay", "wallet"], "brand_name": "Acme Financial"})).status_code == 200
    [entry] = await _entries(db_session, "brand_guard.profile_updated")
    assert entry.before == {"keywords": ["pay"]} and entry.after == {"keywords": ["pay", "wallet"]}, "unchanged brand_name is not recorded"

    assert (await client.patch(f"/brand-guard/profiles/{pid}", json={"keywords": ["pay", "wallet"]})).status_code == 200
    assert len(await _entries(db_session, "brand_guard.profile_updated")) == 1, "a request that changes nothing leaves no entry"

    assert (await client.patch(f"/brand-guard/profiles/{pid}", json={"is_active": False})).status_code == 200
    toggled = [e for e in await _entries(db_session, "brand_guard.profile_updated") if "is_active" in (e.after or {})]
    assert len(toggled) == 1 and toggled[0].before == {"is_active": True} and toggled[0].after == {"is_active": False}


async def test_profile_delete_is_audited_with_what_was_destroyed_and_the_entry_outlives_the_profile(auth_client, db_session):
    client, tenant = auth_client
    pid = await _create_profile(client, tenant, db_session)
    profile = await db_session.get(BrandProfile, uuid.UUID(pid))
    for i, status in enumerate(("new", "new", "confirmed")):
        db_session.add(BrandCandidate(id=uuid.uuid4(), tenant_id=tenant.id, profile_id=profile.id, candidate_domain=f"bad{i}.example", status=status))
    await db_session.commit()

    assert (await client.delete(f"/brand-guard/profiles/{pid}")).status_code == 204
    [entry] = await _entries(db_session, "brand_guard.profile_deleted")
    assert entry.before["brand_name"] == "Acme Financial" and entry.before["candidates_deleted"] == 3
    assert entry.before["candidates_by_status"] == {"new": 2, "confirmed": 1}
    assert (await db_session.execute(select(func.count()).select_from(BrandProfile))).scalar_one() == 0


async def test_manual_scan_start_is_audited_once_even_if_requested_twice(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    pid = await _create_profile(client, tenant, db_session)
    monkeypatch.setattr(svc, "spawn_scan_run", lambda run_id: None)        # leave the run queued: the second request must reuse it

    first = await client.post(f"/brand-guard/profiles/{pid}/scan")
    second = await client.post(f"/brand-guard/profiles/{pid}/scan")
    assert first.status_code == second.status_code == 202 and first.json()["id"] == second.json()["id"]
    entries = await _entries(db_session, "brand_guard.scan_started")
    assert len(entries) == 1 and entries[0].target_id == first.json()["id"] and entries[0].after == {"triggered_by": "manual"}


async def test_candidate_status_change_is_audited_with_before_after_and_note(auth_client, db_session):
    client, tenant = auth_client
    pid = await _create_profile(client, tenant, db_session)
    cand = BrandCandidate(id=uuid.uuid4(), tenant_id=tenant.id, profile_id=uuid.UUID(pid), candidate_domain="acmefinancia1.co.za", status="suspicious")
    db_session.add(cand)
    await db_session.commit()

    assert (await client.patch(f"/brand-guard/candidates/{cand.id}/status", json={"status": "confirmed", "note": "Seen in reported phish"})).status_code == 200
    [entry] = await _entries(db_session, "brand_guard.candidate_status_changed")
    assert entry.target_label == "acmefinancia1.co.za" and entry.before == {"status": "suspicious"}
    assert entry.after == {"status": "confirmed", "note": "Seen in reported phish"} and entry.actor_email

    # a rejected request leaves no entry
    assert (await client.patch(f"/brand-guard/candidates/{cand.id}/status", json={"status": "bogus"})).status_code == 422
    assert (await client.patch(f"/brand-guard/candidates/{uuid.uuid4()}/status", json={"status": "confirmed"})).status_code == 404
    assert len(await _entries(db_session, "brand_guard.candidate_status_changed")) == 1


async def test_long_notes_are_truncated_in_the_audit_entry(auth_client, db_session):
    client, tenant = auth_client
    pid = await _create_profile(client, tenant, db_session)
    cand = BrandCandidate(id=uuid.uuid4(), tenant_id=tenant.id, profile_id=uuid.UUID(pid), candidate_domain="x.example", status="new")
    db_session.add(cand)
    await db_session.commit()
    await client.patch(f"/brand-guard/candidates/{cand.id}/status", json={"status": "ignored", "note": "n" * 1500})
    [entry] = await _entries(db_session, "brand_guard.candidate_status_changed")
    assert len(entry.after["note"]) == 500


async def test_brand_guard_entries_appear_in_the_enterprise_audit_log_api(auth_client, db_session):
    client, tenant = auth_client
    pid = await _create_profile(client, tenant, db_session)
    tenant.plan = "enterprise"
    await db_session.commit()
    await client.patch(f"/brand-guard/profiles/{pid}", json={"keywords": ["pay", "wallet"]})

    listed = (await client.get("/audit-log", params={"action": "brand_guard.profile_updated"})).json()
    assert len(listed) == 1 and listed[0]["before"] == {"keywords": ["pay"]} and listed[0]["target_label"] == "Acme Financial"
    everything = {e["action"] for e in (await client.get("/audit-log", params={"limit": 200})).json()}
    assert {"brand_guard.profile_created", "brand_guard.profile_updated"} <= everything


# ── the automated verdict is audited, with no actor ──────────────────────────

async def test_automated_suspicious_verdict_is_audited_without_an_actor_and_only_once(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    pid = await _create_profile(client, tenant, db_session)
    lookalike = "acmefinancia1.co.za"

    async def fake_dns(d):
        return {"has_a": d == lookalike, "has_aaaa": False, "has_mx": d == lookalike, "registered": d == lookalike, "ns": []}

    async def fake_reg(c, d):
        return NOW - timedelta(days=2)

    async def fake_ct(db, tokens, since):
        return {}

    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_registration_date", fake_reg)
    monkeypatch.setattr(svc, "fetch_ct_candidates", fake_ct)
    monkeypatch.setattr(svc, "_now", lambda: NOW)
    monkeypatch.setattr(svc, "_session_factory", lambda: _Borrowed(db_session))
    from app.services import brand_feeds             # real abuse evidence: liveness alone no longer alerts (measured, plan 3.0)
    monkeypatch.setattr(brand_feeds, "lookup", lambda d, feeds=None: [{"feed": "phishunt", "label": "phishunt.io", "first_seen": "2026-10-01", "same_site": False, "detail": {"other_flags": 0}}] if d == lookalike else [])

    profile = await db_session.get(BrandProfile, uuid.UUID(pid))
    for _ in range(2):
        tenant_row = await db_session.get(Tenant, profile.tenant_id)
        run, _created = await svc.start_scan_run(db_session, profile, triggered_by="manual")
        await svc._run_scan(db_session, run, profile, tenant_row)

    [entry] = await _entries(db_session, "brand_guard.candidate_flagged_suspicious")
    assert entry.actor_user_id is None and entry.actor_email is None, "a system verdict has no actor"
    assert entry.target_label == lookalike and entry.before == {"status": "new"}
    assert entry.after["status"] == "suspicious" and entry.after["identity_score"] >= 55


# ── erasure ──────────────────────────────────────────────────────────────────

async def _seed_brand_data(db, tenant, user, name) -> BrandProfile:
    domain = await make_domain(db, tenant, name=name)
    profile = BrandProfile(id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, brand_name=name)
    db.add(profile)
    await db.flush()
    cand = BrandCandidate(id=uuid.uuid4(), tenant_id=tenant.id, profile_id=profile.id, candidate_domain=f"x-{name}", status="confirmed",
                          reviewed_by_user_id=user.id)
    db.add(cand)
    await db.flush()
    db.add_all([
        CandidateEvidence(id=uuid.uuid4(), candidate_id=cand.id, signal="homoglyph", dimension="identity", weight=60.0, summary="s"),
        BrandCandidateObservation(id=uuid.uuid4(), candidate_id=cand.id, tenant_id=tenant.id, observed_at=NOW, stage="resolving"),
        BrandCandidateEvent(id=uuid.uuid4(), candidate_id=cand.id, tenant_id=tenant.id, kind="first_observed", occurred_at=NOW),
        BrandScanRun(id=uuid.uuid4(), tenant_id=tenant.id, profile_id=profile.id, status="succeeded"),
    ])
    await db.flush()
    return profile


async def _brand_row_counts(db, tenant_id) -> dict:
    counts = {}
    for model in (BrandProfile, BrandCandidate, BrandScanRun, BrandCandidateObservation, BrandCandidateEvent):
        counts[model.__tablename__] = (await db.execute(select(func.count()).select_from(model).where(model.tenant_id == tenant_id))).scalar_one()
    return counts


async def test_workspace_erasure_removes_all_brand_guard_data_and_nothing_else(client, db_session):
    doomed = await make_tenant(db_session, name="Doomed Co", plan="pro")
    admin = await make_user(db_session, doomed, email="admin-erase@doomed.example", password="pass123")
    keeper = await make_tenant(db_session, name="Keeper Co", plan="pro")
    keeper_user = await make_user(db_session, keeper, email="keeper@keeper.example", password="pass123")
    await _seed_brand_data(db_session, doomed, admin, "doomed.example")
    await _seed_brand_data(db_session, keeper, keeper_user, "keeper.example")
    db_session.add(BrandSourceHealth(source="crt_sh_test", label="shared feed", status="healthy"))
    await db_session.commit()
    doomed_id, keeper_id = doomed.id, keeper.id          # plain values: ORM objects expire once the tenant is deleted
    assert all(n == 1 for n in (await _brand_row_counts(db_session, doomed_id)).values())

    await _login(client, "admin-erase@doomed.example", "pass123")
    resp = await client.request("DELETE", "/auth/account", json={"confirm_tenant_name": "Doomed Co"})
    assert resp.status_code == 204, resp.text
    db_session.expire_all()

    assert all(n == 0 for n in (await _brand_row_counts(db_session, doomed_id)).values()), "no orphaned Brand Guard data"
    assert (await db_session.execute(select(func.count()).select_from(CandidateEvidence).join(
        BrandCandidate, BrandCandidate.id == CandidateEvidence.candidate_id, isouter=True).where(BrandCandidate.id.is_(None)))).scalar_one() == 0
    assert all(n == 1 for n in (await _brand_row_counts(db_session, keeper_id)).values()), "another workspace's data is untouched"
    assert await db_session.scalar(select(BrandSourceHealth).where(BrandSourceHealth.source == "crt_sh_test")) is not None, "shared source health is not tenant data"
    assert await db_session.scalar(select(TenantErasureLog).where(TenantErasureLog.tenant_id == doomed_id)) is not None


async def test_a_reviewer_can_delete_their_own_account_without_losing_the_candidates_they_reviewed(client, db_session):
    tenant = await make_tenant(db_session, name="Team Co", plan="pro")
    await make_user(db_session, tenant, email="boss@team.example", password="pass123")
    reviewer = await make_user(db_session, tenant, email="viewer@team.example", password="pass123", role="viewer")
    profile = await _seed_brand_data(db_session, tenant, reviewer, "team.example")
    await db_session.commit()
    cand_id = (await db_session.execute(select(BrandCandidate.id).where(BrandCandidate.profile_id == profile.id))).scalar_one()

    await _login(client, "viewer@team.example", "pass123")
    resp = await client.request("DELETE", "/auth/account", json={})
    assert resp.status_code == 204, resp.text
    db_session.expire_all()

    cand = await db_session.get(BrandCandidate, cand_id)
    assert cand is not None and cand.reviewed_by_user_id is None, "the decision stays; only the reviewer link is cleared"
    assert await db_session.scalar(select(User).where(User.email == "viewer@team.example")) is None
