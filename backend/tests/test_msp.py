"""
MSP sub-tenant management (app/routers/msp.py) — real, previously-untested
production-scoring code (Coverage Map plan Phase 2). Every endpoint here was
already fully built but had zero test coverage before this file.
"""
from sqlalchemy import select

from tests.factories import make_tenant, make_user, make_domain


async def _login_as(client, email: str, password: str = "pass123"):
    login = await client.post(
        "/auth/token",
        data={"username": email, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert login.status_code == 200, login.text
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})


async def _make_msp_tenant_and_login(client, db_session, *, email: str = "msp-owner@example.com"):
    msp_tenant = await make_tenant(db_session, name="Acme MSP", plan="msp")
    await make_user(db_session, msp_tenant, email=email, password="pass123")
    await db_session.flush()
    await _login_as(client, email)
    return msp_tenant


async def test_list_clients_requires_msp_plan(auth_client):
    # auth_client's fixture tenant is on the free plan by default.
    client, _tenant = auth_client
    resp = await client.get("/msp/clients")
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "msp_plan_required"


async def test_list_clients_starts_empty_for_a_fresh_msp_tenant(client, db_session):
    await _make_msp_tenant_and_login(client, db_session)
    resp = await client.get("/msp/clients")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_create_client_returns_a_real_computed_score(client, db_session):
    msp_tenant = await _make_msp_tenant_and_login(client, db_session)

    resp = await client.post("/msp/clients", json={"name": "Client Co", "billing_email": "billing@clientco.com"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "Client Co"
    assert body["plan"] == "free"  # clients start on free regardless of the MSP's own plan
    assert body["domain_count"] == 0
    assert isinstance(body["sentinel_score"], int)
    assert body["sentinel_grade"]
    assert body["user_count"] == 0
    assert body["domains"] == []

    # The client is a real Tenant row, parented to the MSP tenant.
    from app.models.user import Tenant
    result = await db_session.execute(select(Tenant).where(Tenant.id == body["id"]))
    client_row = result.scalar_one()
    assert str(client_row.parent_tenant_id) == str(msp_tenant.id)


async def test_list_clients_reflects_a_real_domains_dmarc_posture(client, db_session):
    msp_tenant = await _make_msp_tenant_and_login(client, db_session)

    create_resp = await client.post("/msp/clients", json={"name": "Client Co"})
    client_id = create_resp.json()["id"]

    from app.models.user import Tenant
    client_tenant = (await db_session.execute(select(Tenant).where(Tenant.id == client_id))).scalar_one()
    await make_domain(db_session, client_tenant, name="clientco.com", dmarc_stage="reject", mta_sts_stage="enforce")
    await db_session.flush()

    list_resp = await client.get("/msp/clients")
    assert list_resp.status_code == 200
    [summary] = [c for c in list_resp.json() if c["id"] == client_id]
    assert summary["domain_count"] == 1
    assert summary["dmarc_reject_count"] == 1
    assert summary["dmarc_none_count"] == 0


async def test_list_clients_reports_no_human_risk_pillar_with_no_phishing_history(client, db_session):
    """Coverage Map plan phishing transformation, Phase 9 — a client tenant
    that has never run a phishing campaign must see an absent pillar, never
    a fabricated 0."""
    msp_tenant = await _make_msp_tenant_and_login(client, db_session)
    create_resp = await client.post("/msp/clients", json={"name": "Client Co"})
    client_id = create_resp.json()["id"]

    list_resp = await client.get("/msp/clients")
    [summary] = [c for c in list_resp.json() if c["id"] == client_id]
    assert summary["pillar_human_risk"] is None
    assert summary["phish_click_rate"] is None
    assert summary["phish_report_rate"] is None


async def test_list_clients_reflects_a_real_phishing_campaign_history(client, db_session):
    """A client tenant with real PhishingEvent history shows real
    click/report rates and a real Human Risk pillar, not placeholders."""
    msp_tenant = await _make_msp_tenant_and_login(client, db_session)
    create_resp = await client.post("/msp/clients", json={"name": "Client Co"})
    client_id = create_resp.json()["id"]

    from app.models.user import Tenant
    client_tenant = (await db_session.execute(select(Tenant).where(Tenant.id == client_id))).scalar_one()

    import uuid
    from app.models import Engagement, PhishingCampaign, PhishingEvent, PhishingTargetList
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=client_tenant.id, name="Staff", entries=[{"email": "a@example.com"}])
    engagement = Engagement(id=uuid.uuid4(), tenant_id=client_tenant.id, tier="phishing", status="active", scope={})
    db_session.add_all([target_list, engagement])
    await db_session.flush()
    campaign = PhishingCampaign(
        id=uuid.uuid4(), tenant_id=client_tenant.id, engagement_id=engagement.id,
        target_list_id=target_list.id, template_id="shared-document", status="complete",
    )
    db_session.add(campaign)
    await db_session.flush()
    db_session.add_all([
        PhishingEvent(id=uuid.uuid4(), tenant_id=client_tenant.id, campaign_id=campaign.id, recipient_hash="h1", recipient_token="t1", event_type="sent"),
        PhishingEvent(id=uuid.uuid4(), tenant_id=client_tenant.id, campaign_id=campaign.id, recipient_hash="h2", recipient_token="t2", event_type="sent"),
        PhishingEvent(id=uuid.uuid4(), tenant_id=client_tenant.id, campaign_id=campaign.id, recipient_hash="h1", recipient_token="t1", event_type="clicked"),
        PhishingEvent(id=uuid.uuid4(), tenant_id=client_tenant.id, campaign_id=campaign.id, recipient_hash="h2", recipient_token="t2", event_type="reported"),
    ])
    await db_session.commit()

    list_resp = await client.get("/msp/clients")
    [summary] = [c for c in list_resp.json() if c["id"] == client_id]
    assert summary["phish_click_rate"] == 50.0
    assert summary["phish_report_rate"] == 50.0
    assert summary["pillar_human_risk"] is not None


async def test_get_client_returns_full_detail_including_domains(client, db_session):
    msp_tenant = await _make_msp_tenant_and_login(client, db_session)
    create_resp = await client.post("/msp/clients", json={"name": "Client Co"})
    client_id = create_resp.json()["id"]

    resp = await client.get(f"/msp/clients/{client_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "Client Co"
    assert body["user_count"] == 0
    assert body["domains"] == []


async def test_get_client_404s_for_a_tenant_that_is_not_your_client(client, db_session):
    msp_tenant = await _make_msp_tenant_and_login(client, db_session)
    unrelated_tenant = await make_tenant(db_session, name="Unrelated", plan="free")
    await db_session.flush()

    resp = await client.get(f"/msp/clients/{unrelated_tenant.id}")
    assert resp.status_code == 404


async def test_update_client_changes_name_and_brand(client, db_session):
    msp_tenant = await _make_msp_tenant_and_login(client, db_session)
    create_resp = await client.post("/msp/clients", json={"name": "Old Name"})
    client_id = create_resp.json()["id"]

    resp = await client.patch(f"/msp/clients/{client_id}", json={"name": "New Name", "brand_name": "Client Co Brand"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "New Name"
    assert body["brand_name"] == "Client Co Brand"


async def test_delete_client_removes_the_tenant(client, db_session):
    msp_tenant = await _make_msp_tenant_and_login(client, db_session)
    create_resp = await client.post("/msp/clients", json={"name": "Client Co"})
    client_id = create_resp.json()["id"]

    resp = await client.delete(f"/msp/clients/{client_id}")
    assert resp.status_code == 204

    get_resp = await client.get(f"/msp/clients/{client_id}")
    assert get_resp.status_code == 404


async def test_delete_client_cascades_through_domains_users_and_its_own_audit_log(client, db_session):
    """
    Real regression coverage for Phase 18's audit-log immutability trigger:
    deleting a client tenant with real history attached (a domain, a user,
    and an audit_log_entries row scoped to that client) must still cascade
    cleanly — the trigger's authorized-bypass GUC has to actually be set on
    this code path too, not just delete_account()'s.
    """
    import uuid as _uuid

    from app.models import AuditLogEntry, Domain
    from app.models.user import Tenant as _Tenant, User as _User
    from app.services import audit_service

    msp_tenant = await _make_msp_tenant_and_login(client, db_session)
    create_resp = await client.post("/msp/clients", json={"name": "Client Co"})
    client_id = _uuid.UUID(create_resp.json()["id"])
    client_tenant = await db_session.get(_Tenant, client_id)

    await make_domain(db_session, client_tenant, name="clientco.com")
    await make_user(db_session, client_tenant, email="client-user@clientco.com")
    await audit_service.log(db_session, tenant_id=client_id, action="test.seed_entry")
    await db_session.flush()

    resp = await client.delete(f"/msp/clients/{client_id}")
    assert resp.status_code == 204

    assert (await db_session.execute(select(Domain).where(Domain.tenant_id == client_id))).scalars().all() == []
    assert (await db_session.execute(select(_User).where(_User.tenant_id == client_id))).scalars().all() == []
    assert (await db_session.execute(select(AuditLogEntry).where(AuditLogEntry.tenant_id == client_id))).scalars().all() == []


async def test_invite_to_client_direct_mode_creates_a_real_user(client, db_session):
    msp_tenant = await _make_msp_tenant_and_login(client, db_session)
    create_resp = await client.post("/msp/clients", json={"name": "Client Co"})
    client_id = create_resp.json()["id"]

    resp = await client.post(
        f"/msp/clients/{client_id}/invite",
        json={"email": "newadmin@clientco.com", "full_name": "New Admin", "send_invite": False, "password": "clientpass123"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["mode"] == "direct"
    assert body["email"] == "newadmin@clientco.com"

    detail_resp = await client.get(f"/msp/clients/{client_id}")
    assert detail_resp.json()["user_count"] == 1


async def test_invite_to_client_direct_mode_requires_a_password(client, db_session):
    msp_tenant = await _make_msp_tenant_and_login(client, db_session)
    create_resp = await client.post("/msp/clients", json={"name": "Client Co"})
    client_id = create_resp.json()["id"]

    resp = await client.post(
        f"/msp/clients/{client_id}/invite",
        json={"email": "newadmin@clientco.com", "full_name": "New Admin", "send_invite": False},
    )
    assert resp.status_code == 400


async def test_invite_to_client_rejects_a_duplicate_email(client, db_session):
    msp_tenant = await _make_msp_tenant_and_login(client, db_session)
    create_resp = await client.post("/msp/clients", json={"name": "Client Co"})
    client_id = create_resp.json()["id"]

    first = await client.post(
        f"/msp/clients/{client_id}/invite",
        json={"email": "dup@clientco.com", "full_name": "First", "send_invite": False, "password": "pass12345"},
    )
    assert first.status_code == 201

    second = await client.post(
        f"/msp/clients/{client_id}/invite",
        json={"email": "dup@clientco.com", "full_name": "Second", "send_invite": False, "password": "pass12345"},
    )
    assert second.status_code == 409


async def test_msp_clients_are_isolated_between_different_msp_tenants(client, db_session):
    await _make_msp_tenant_and_login(client, db_session, email="msp-a@example.com")
    a_create = await client.post("/msp/clients", json={"name": "A's Client"})
    assert a_create.status_code == 201

    # A fresh test_msp.py file gets its own `client`/`db_session` per test —
    # simulate a second MSP by logging in as a brand new tenant on the same
    # client fixture, the same pattern test_engagements.py uses for isolation.
    other_msp = await make_tenant(db_session, name="Other MSP", plan="msp")
    await make_user(db_session, other_msp, email="msp-b@example.com", password="pass123")
    await db_session.flush()
    await _login_as(client, "msp-b@example.com")

    resp = await client.get("/msp/clients")
    assert resp.status_code == 200
    assert resp.json() == []
