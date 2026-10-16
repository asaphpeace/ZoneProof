"""
Engagement lifecycle — the consent/scope gate every Sentinel Command scan
belongs to. See ARCHITECTURE.md Section 6 and BUILD_PLAN.md Phase 1's
"go on" addendum (engagement CRUD was a gap discovered while wiring the
scan passes, since they take an Engagement param with nowhere to create one).
"""
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.services import dropbox_sign_service
from tests.factories import make_tenant, make_user


async def test_create_engagement_starts_in_draft(auth_client):
    client, _tenant = auth_client
    resp = await client.post("/engagements", json={"tier": "cloud"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "draft"
    assert body["approved_at"] is None


async def test_create_engagement_rejects_unknown_tier(auth_client):
    client, _tenant = auth_client
    resp = await client.post("/engagements", json={"tier": "not-a-real-tier"})
    assert resp.status_code == 400


async def test_create_engagement_is_audit_logged(auth_client, db_session: AsyncSession):
    """Real gap found and closed via a live E2E simulation pass — every
    downstream engagement action (approve, revoke, schedule change) was
    already audited; creation itself never was, tier-agnostic like the
    other engagement.* actions."""
    client, _tenant = auth_client
    resp = await client.post("/engagements", json={"tier": "cloud", "scope": {"note": "real scope value"}})
    engagement_id = resp.json()["id"]

    from sqlalchemy import select
    from app.models import AuditLogEntry
    entry = (await db_session.execute(
        select(AuditLogEntry).where(AuditLogEntry.action == "engagement.created")
    )).scalars().first()
    assert entry is not None
    assert entry.target_id == engagement_id
    assert entry.target_label == "cloud"
    assert entry.after["scope"] == {"note": "real scope value"}


async def test_approve_engagement_activates_it(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/engagements", json={"tier": "cloud"})
    engagement_id = create_resp.json()["id"]

    resp = await client.post(f"/engagements/{engagement_id}/approve")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "active"
    assert body["approved_at"] is not None


async def test_revoke_engagement_deactivates_it(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/engagements", json={"tier": "cloud"})
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    resp = await client.post(f"/engagements/{engagement_id}/revoke")
    assert resp.status_code == 200
    assert resp.json()["status"] == "revoked"


async def test_update_schedule_changes_cadence_on_an_active_engagement(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/engagements", json={
        "tier": "phishing", "scope": {"target_list_id": "x", "template_id": "shared-document", "cadence_days": 90},
    })
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    resp = await client.patch(f"/engagements/{engagement_id}/schedule", json={"cadence_days": 30})
    assert resp.status_code == 200
    body = resp.json()
    assert body["scope"]["cadence_days"] == 30
    assert body["scope"]["target_list_id"] == "x"  # untouched fields survive the merge


async def test_update_schedule_can_toggle_recurring_and_landing_page(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/engagements", json={
        "tier": "phishing", "scope": {"target_list_id": "x", "template_id": "shared-document", "cadence_days": 90, "recurring": True},
    })
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    resp = await client.patch(f"/engagements/{engagement_id}/schedule", json={"recurring": False, "landing_page_id": "generic-sso"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["scope"]["recurring"] is False
    assert body["scope"]["landing_page_id"] == "generic-sso"


async def test_update_schedule_rejects_a_non_active_engagement(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/engagements", json={
        "tier": "phishing", "scope": {"target_list_id": "x", "template_id": "shared-document", "cadence_days": 90},
    })
    engagement_id = create_resp.json()["id"]  # still draft — never approved

    resp = await client.patch(f"/engagements/{engagement_id}/schedule", json={"cadence_days": 30})
    assert resp.status_code == 400


async def test_update_schedule_rejects_a_non_phishing_tier(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/engagements", json={"tier": "cloud"})
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    resp = await client.patch(f"/engagements/{engagement_id}/schedule", json={"cadence_days": 30})
    assert resp.status_code == 400


async def test_update_schedule_rejects_cadence_below_one(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/engagements", json={
        "tier": "phishing", "scope": {"target_list_id": "x", "template_id": "shared-document", "cadence_days": 90},
    })
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    resp = await client.patch(f"/engagements/{engagement_id}/schedule", json={"cadence_days": 0})
    assert resp.status_code == 400


async def test_update_schedule_is_audited_with_real_before_and_after_values(client, db_session: AsyncSession):
    # Audit-log read access is enterprise-plan-gated — auth_client's
    # default tenant is on the free plan, so build one with real access.
    tenant = await make_tenant(db_session, plan="enterprise")
    await make_user(db_session, tenant, email="sched-audit@example.com", password="pass123")
    await db_session.flush()
    login = await client.post(
        "/auth/token", data={"username": "sched-audit@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    create_resp = await client.post("/engagements", json={
        "tier": "phishing", "scope": {"target_list_id": "x", "template_id": "shared-document", "cadence_days": 90},
    })
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")
    await client.patch(f"/engagements/{engagement_id}/schedule", json={"cadence_days": 14})

    audit_resp = await client.get("/audit-log")
    entries = [e for e in audit_resp.json() if e["action"] == "engagement.schedule_updated"]
    assert len(entries) == 1
    assert entries[0]["before"] == {"cadence_days": 90}
    assert entries[0]["after"] == {"cadence_days": 14}


async def test_update_schedule_takes_effect_on_the_next_scheduler_poll(auth_client, db_session, monkeypatch):
    """Proves the real claim in the endpoint's docstring: no separate
    'next due' field to keep in sync — poll_due_phishing_campaigns() reads
    cadence_days fresh from scope every time, so shortening it here makes
    an engagement that wasn't due suddenly due, with no migration step."""
    import uuid
    from datetime import datetime, timedelta, timezone
    from app.models import PhishingTargetList
    from app.services import phishing_service as svc

    client, tenant = auth_client
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "a@example.com"}])
    db_session.add(target_list)
    await db_session.flush()

    create_resp = await client.post("/engagements", json={
        "tier": "phishing", "scope": {"target_list_id": str(target_list.id), "template_id": "shared-document", "cadence_days": 90, "recurring": True},
    })
    engagement_id = create_resp.json()["id"]
    approve_resp = await client.post(f"/engagements/{engagement_id}/approve")
    await db_session.commit()

    from app.models import Engagement
    engagement = await db_session.get(Engagement, uuid.UUID(engagement_id))
    engagement.last_scanned_at = datetime.now(timezone.utc) - timedelta(days=30)  # 30 days ago
    await db_session.commit()

    # Not due yet under the original 90-day cadence.
    launched_count = await svc.poll_due_phishing_campaigns(db_session)
    assert launched_count == 0

    # Shorten the cadence to 14 days — 30 days ago is now overdue.
    resp = await client.patch(f"/engagements/{engagement_id}/schedule", json={"cadence_days": 14})
    assert resp.status_code == 200

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    launched_count = await svc.poll_due_phishing_campaigns(db_session)
    assert launched_count == 1


async def _login_as(client, db_session: AsyncSession, role: str, *, tenant=None, plan: str = "free"):
    """Builds a user with the given role (in an existing tenant if one is
    passed, otherwise a fresh one) and logs in as them, mirroring the
    inline pattern test_update_schedule_is_audited_with_real_before_and_
    after_values already uses for a non-default-plan tenant. Passing an
    existing tenant is how same-tenant, different-role tests work."""
    if tenant is None:
        tenant = await make_tenant(db_session, plan=plan)
    email = f"{role}-{uuid.uuid4().hex[:8]}@example.com"
    await make_user(db_session, tenant, email=email, password="pass123", role=role)
    await db_session.flush()
    login = await client.post(
        "/auth/token", data={"username": email, "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
    return tenant


async def test_create_engagement_rejects_viewer_for_phishing_tier(client, db_session: AsyncSession):
    await _login_as(client, db_session, "viewer")
    resp = await client.post("/engagements", json={"tier": "phishing"})
    assert resp.status_code == 403


async def test_create_engagement_allows_approver_for_phishing_tier(client, db_session: AsyncSession):
    await _login_as(client, db_session, "approver")
    resp = await client.post("/engagements", json={"tier": "phishing"})
    assert resp.status_code == 200


async def test_create_engagement_allows_viewer_for_a_non_phishing_tier(client, db_session: AsyncSession):
    # The narrower gate is deliberately scoped to tier='phishing' only —
    # every other engagement tier keeps its pre-existing any-tenant-user
    # behavior unchanged.
    await _login_as(client, db_session, "viewer")
    resp = await client.post("/engagements", json={"tier": "cloud"})
    assert resp.status_code == 200


async def test_request_signature_rejects_viewer_for_phishing_tier(client, db_session: AsyncSession, monkeypatch):
    async def fake_create_signature_request(engagement, tenant, signer_name, signer_email):
        return "sr-123", "https://app.hellosign.com/sr-123"
    monkeypatch.setattr(dropbox_sign_service, "create_signature_request", fake_create_signature_request)

    tenant = await _login_as(client, db_session, "approver")
    create_resp = await client.post("/engagements", json={"tier": "phishing"})
    engagement_id = create_resp.json()["id"]

    await _login_as(client, db_session, "viewer", tenant=tenant)
    resp = await client.post(f"/engagements/{engagement_id}/request-signature", json={})
    assert resp.status_code == 403


async def test_revoke_rejects_viewer_but_allows_admin_in_the_same_tenant(client, db_session: AsyncSession):
    tenant = await _login_as(client, db_session, "admin")
    create_resp = await client.post("/engagements", json={"tier": "phishing"})
    engagement_id = create_resp.json()["id"]

    await _login_as(client, db_session, "viewer", tenant=tenant)
    viewer_resp = await client.post(f"/engagements/{engagement_id}/revoke")
    assert viewer_resp.status_code == 403

    await _login_as(client, db_session, "admin", tenant=tenant)
    admin_resp = await client.post(f"/engagements/{engagement_id}/revoke")
    assert admin_resp.status_code == 200


async def test_update_schedule_rejects_viewer_but_allows_approver_in_the_same_tenant(client, db_session: AsyncSession):
    tenant = await _login_as(client, db_session, "admin")
    create_resp = await client.post("/engagements", json={
        "tier": "phishing", "scope": {"target_list_id": "x", "template_id": "shared-document", "cadence_days": 90},
    })
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    await _login_as(client, db_session, "viewer", tenant=tenant)
    viewer_resp = await client.patch(f"/engagements/{engagement_id}/schedule", json={"cadence_days": 30})
    assert viewer_resp.status_code == 403

    await _login_as(client, db_session, "approver", tenant=tenant)
    approver_resp = await client.patch(f"/engagements/{engagement_id}/schedule", json={"cadence_days": 14})
    assert approver_resp.status_code == 200


async def test_findings_and_priv_esc_paths_start_empty(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/engagements", json={"tier": "cloud"})
    engagement_id = create_resp.json()["id"]

    findings_resp = await client.get(f"/engagements/{engagement_id}/findings")
    assert findings_resp.status_code == 200
    assert findings_resp.json() == []

    paths_resp = await client.get(f"/engagements/{engagement_id}/priv-esc-paths")
    assert paths_resp.status_code == 200
    assert paths_resp.json() == []


async def test_engagements_are_isolated_by_tenant(auth_client, client, db_session: AsyncSession):
    owner_client, _owner_tenant = auth_client
    create_resp = await owner_client.post("/engagements", json={"tier": "cloud"})
    engagement_id = create_resp.json()["id"]

    other_tenant = await make_tenant(db_session, name="Other Workspace")
    await make_user(db_session, other_tenant, email="other-eng@example.com", password="pass123")
    await db_session.flush()
    login = await client.post(
        "/auth/token",
        data={"username": "other-eng@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    list_resp = await client.get("/engagements")
    assert list_resp.json() == []

    approve_resp = await client.post(f"/engagements/{engagement_id}/approve")
    assert approve_resp.status_code == 404


async def test_approve_engagement_is_blocked_when_direct_approval_disabled(auth_client, monkeypatch):
    client, _tenant = auth_client
    monkeypatch.setattr(settings, "command_allow_direct_engagement_approval", False)

    create_resp = await client.post("/engagements", json={"tier": "cloud"})
    engagement_id = create_resp.json()["id"]

    resp = await client.post(f"/engagements/{engagement_id}/approve")
    assert resp.status_code == 403


async def test_request_signature_moves_engagement_to_pending_approval(auth_client, monkeypatch):
    client, _tenant = auth_client

    async def fake_create_signature_request(engagement, tenant, signer_name, signer_email):
        return "sr-123", "https://app.hellosign.com/sr-123"

    monkeypatch.setattr(dropbox_sign_service, "create_signature_request", fake_create_signature_request)

    create_resp = await client.post("/engagements", json={"tier": "cloud"})
    engagement_id = create_resp.json()["id"]

    resp = await client.post(f"/engagements/{engagement_id}/request-signature", json={})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "pending_approval"
    assert body["roe_signature_request_id"] == "sr-123"
    assert body["roe_doc_url"] == "https://app.hellosign.com/sr-123"


async def test_request_signature_rejects_a_non_draft_engagement(auth_client, monkeypatch):
    client, _tenant = auth_client

    async def fake_create_signature_request(engagement, tenant, signer_name, signer_email):
        return "sr-123", "https://app.hellosign.com/sr-123"

    monkeypatch.setattr(dropbox_sign_service, "create_signature_request", fake_create_signature_request)

    create_resp = await client.post("/engagements", json={"tier": "cloud"})
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/request-signature", json={})

    resp = await client.post(f"/engagements/{engagement_id}/request-signature", json={})
    assert resp.status_code == 400


async def test_request_signature_surfaces_a_dropbox_sign_failure_as_502(auth_client, monkeypatch):
    client, _tenant = auth_client

    async def fake_create_signature_request(engagement, tenant, signer_name, signer_email):
        raise dropbox_sign_service.DropboxSignError("boom")

    monkeypatch.setattr(dropbox_sign_service, "create_signature_request", fake_create_signature_request)

    create_resp = await client.post("/engagements", json={"tier": "cloud"})
    engagement_id = create_resp.json()["id"]

    resp = await client.post(f"/engagements/{engagement_id}/request-signature", json={})
    assert resp.status_code == 502


async def test_dropbox_sign_webhook_activates_a_pending_engagement(auth_client, monkeypatch):
    client, _tenant = auth_client

    async def fake_create_signature_request(engagement, tenant, signer_name, signer_email):
        return "sr-456", "https://app.hellosign.com/sr-456"

    monkeypatch.setattr(dropbox_sign_service, "create_signature_request", fake_create_signature_request)

    create_resp = await client.post("/engagements", json={"tier": "cloud"})
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/request-signature", json={})

    def fake_verify(raw_json_str):
        return {"event": {"event_type": "signature_request_all_signed"}, "signature_request": {"signature_request_id": "sr-456"}}

    monkeypatch.setattr(dropbox_sign_service, "verify_webhook_event", fake_verify)

    webhook_resp = await client.post("/engagements/webhooks/dropbox-sign", data={"json": "{}"})
    assert webhook_resp.status_code == 200
    assert webhook_resp.text == "Hello API Event Received"

    get_resp = await client.get(f"/engagements/{engagement_id}/findings")
    assert get_resp.status_code == 200  # engagement still resolvable

    list_resp = await client.get("/engagements")
    matching = [e for e in list_resp.json() if e["id"] == engagement_id][0]
    assert matching["status"] == "active"
    assert matching["approved_at"] is not None


async def test_dropbox_sign_webhook_rejects_an_unverifiable_event(auth_client, monkeypatch):
    client, _tenant = auth_client

    def fake_verify(raw_json_str):
        raise ValueError("bad signature")

    monkeypatch.setattr(dropbox_sign_service, "verify_webhook_event", fake_verify)

    resp = await client.post("/engagements/webhooks/dropbox-sign", data={"json": "{}"})
    assert resp.status_code == 400


async def test_create_engagement_reuses_a_connections_existing_engagement_instead_of_orphaning_it(auth_client):
    """A connection already linked to an engagement (e.g. a retried "Verify &
    Request Signature" after a Dropbox Sign failure) must have that same
    engagement returned, not silently repointed at a brand new one — the old
    behavior orphaned the first engagement (still nominally active/draft in
    the DB but with zero connections linked to it), which broke both the
    manual rescan button and the recurring scheduler for that connection."""
    client, _tenant = auth_client
    connection_resp = await client.post("/cloud-connections", json={"provider": "aws"})
    connection_id = connection_resp.json()["id"]

    first_resp = await client.post(
        "/engagements", json={"tier": "cloud", "cloud_account_connection_ids": [connection_id]}
    )
    first_engagement_id = first_resp.json()["id"]

    second_resp = await client.post(
        "/engagements", json={"tier": "cloud", "cloud_account_connection_ids": [connection_id]}
    )
    assert second_resp.status_code == 200
    assert second_resp.json()["id"] == first_engagement_id

    list_resp = await client.get("/engagements")
    cloud_engagements = [e for e in list_resp.json() if e["tier"] == "cloud"]
    assert len(cloud_engagements) == 1  # no orphaned second engagement was created


async def test_create_engagement_reuses_an_active_engagement_too(auth_client):
    """Reuse isn't limited to draft engagements — a connection already tied
    to an active engagement must keep pointing at it, not be silently moved
    to a fresh draft that then needs its own separate approval."""
    client, _tenant = auth_client
    connection_resp = await client.post("/cloud-connections", json={"provider": "aws"})
    connection_id = connection_resp.json()["id"]

    first_resp = await client.post(
        "/engagements", json={"tier": "cloud", "cloud_account_connection_ids": [connection_id]}
    )
    first_engagement_id = first_resp.json()["id"]
    await client.post(f"/engagements/{first_engagement_id}/approve")

    second_resp = await client.post(
        "/engagements", json={"tier": "cloud", "cloud_account_connection_ids": [connection_id]}
    )
    assert second_resp.status_code == 200
    body = second_resp.json()
    assert body["id"] == first_engagement_id
    assert body["status"] == "active"  # untouched, not reset to draft
