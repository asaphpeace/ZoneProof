"""
Integration tests for the audit log: the plan gate, admin-only access, and
that the explicit logging call sites (see audit_service.py's module
docstring on why these are explicit rather than middleware-driven) actually
produce a readable entry end to end.
"""
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import make_tenant, make_user


async def _login(client: AsyncClient, email: str, password: str) -> str:
    resp = await client.post(
        "/auth/token",
        data={"username": email, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return resp.json()["access_token"]


async def test_audit_log_blocked_on_free_plan(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, plan="free")
    await make_user(db_session, tenant, email="free-admin@example.com", password="pass123")
    await db_session.flush()

    token = await _login(client, "free-admin@example.com", "pass123")
    resp = await client.get("/audit-log", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "feature_not_available"


async def test_audit_log_accessible_on_enterprise_plan(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, plan="enterprise")
    await make_user(db_session, tenant, email="ent-admin@example.com", password="pass123")
    await db_session.flush()

    token = await _login(client, "ent-admin@example.com", "pass123")
    resp = await client.get("/audit-log", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == []  # nothing logged yet for this fresh tenant


async def test_audit_log_requires_admin_role(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, plan="enterprise")
    await make_user(db_session, tenant, email="viewer@example.com", password="pass123", role="viewer")
    await db_session.flush()

    token = await _login(client, "viewer@example.com", "pass123")
    resp = await client.get("/audit-log", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


async def test_password_change_produces_a_readable_audit_entry(client: AsyncClient, db_session: AsyncSession):
    """End-to-end: trigger a real audited action, then read it back through the actual endpoint."""
    tenant = await make_tenant(db_session, plan="enterprise")
    await make_user(db_session, tenant, email="audited@example.com", password="oldpass123")
    await db_session.flush()

    token = await _login(client, "audited@example.com", "oldpass123")
    await client.post(
        "/auth/change-password",
        json={"current_password": "oldpass123", "new_password": "newpass456"},
        headers={"Authorization": f"Bearer {token}"},
    )

    # change-password just invalidated this token (see test_token_revocation.py) —
    # log back in with the new password to read the audit trail.
    new_token = await _login(client, "audited@example.com", "newpass456")
    resp = await client.get("/audit-log", headers={"Authorization": f"Bearer {new_token}"})
    assert resp.status_code == 200
    entries = resp.json()
    assert any(e["action"] == "auth.password_changed" for e in entries)
    entry = next(e for e in entries if e["action"] == "auth.password_changed")
    assert entry["actor_email"] == "audited@example.com"
    assert entry["target_type"] == "user"


async def test_audit_log_filters_by_action(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, plan="enterprise")
    await make_user(db_session, tenant, email="filter-admin@example.com", password="oldpass123")
    await db_session.flush()

    token = await _login(client, "filter-admin@example.com", "oldpass123")
    await client.post(
        "/auth/change-password",
        json={"current_password": "oldpass123", "new_password": "newpass456"},
        headers={"Authorization": f"Bearer {token}"},
    )
    new_token = await _login(client, "filter-admin@example.com", "newpass456")

    resp = await client.get("/audit-log?action=auth.password_changed", headers={"Authorization": f"Bearer {new_token}"})
    assert resp.status_code == 200
    assert all(e["action"] == "auth.password_changed" for e in resp.json())

    resp2 = await client.get("/audit-log?action=nonexistent.action", headers={"Authorization": f"Bearer {new_token}"})
    assert resp2.json() == []


async def test_audit_log_export_returns_a_real_csv(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, plan="enterprise")
    await make_user(db_session, tenant, email="export-admin@example.com", password="oldpass123")
    await db_session.flush()

    token = await _login(client, "export-admin@example.com", "oldpass123")
    await client.post(
        "/auth/change-password",
        json={"current_password": "oldpass123", "new_password": "newpass456"},
        headers={"Authorization": f"Bearer {token}"},
    )
    new_token = await _login(client, "export-admin@example.com", "newpass456")

    resp = await client.get("/audit-log/export", headers={"Authorization": f"Bearer {new_token}"})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "attachment" in resp.headers["content-disposition"]
    body = resp.text
    assert "action" in body.splitlines()[0]  # header row
    assert "auth.password_changed" in body


async def test_audit_log_export_blocked_on_free_plan(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, plan="free")
    await make_user(db_session, tenant, email="free-export@example.com", password="pass123")
    await db_session.flush()

    token = await _login(client, "free-export@example.com", "pass123")
    resp = await client.get("/audit-log/export", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


# ── New call sites (Coverage Map plan Phase 9) — connect/verify/revoke for
# Cloud/Host/OAuth connections and the engagement approve/revoke gates were
# real, previously-unaudited mutation points. ──

async def test_cloud_connection_lifecycle_is_audited(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, plan="enterprise")
    await make_user(db_session, tenant, email="cloud-admin@example.com", password="pass123")
    await db_session.flush()

    token = await _login(client, "cloud-admin@example.com", "pass123")
    headers = {"Authorization": f"Bearer {token}"}

    create_resp = await client.post("/cloud-connections", json={"provider": "aws"}, headers=headers)
    connection_id = create_resp.json()["id"]
    await client.post(f"/cloud-connections/{connection_id}/revoke", headers=headers)

    resp = await client.get("/audit-log", headers=headers)
    actions = [e["action"] for e in resp.json()]
    assert "cloud_connection.created" in actions
    assert "cloud_connection.revoked" in actions


async def test_engagement_dev_bypass_approval_is_audited(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, plan="enterprise")
    await make_user(db_session, tenant, email="eng-admin@example.com", password="pass123")
    await db_session.flush()

    token = await _login(client, "eng-admin@example.com", "pass123")
    headers = {"Authorization": f"Bearer {token}"}

    create_resp = await client.post("/engagements", json={"tier": "cloud"}, headers=headers)
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve", headers=headers)

    resp = await client.get("/audit-log", headers=headers)
    entries = resp.json()
    assert any(e["action"] == "engagement.approved_dev_bypass" for e in entries)


async def test_audit_log_count_endpoint(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, plan="enterprise")
    await make_user(db_session, tenant, email="count-admin@example.com", password="oldpass123")
    await db_session.flush()

    token = await _login(client, "count-admin@example.com", "oldpass123")
    before = await client.get("/audit-log/count", headers={"Authorization": f"Bearer {token}"})
    assert before.json()["count"] == 0

    await client.post(
        "/auth/change-password",
        json={"current_password": "oldpass123", "new_password": "newpass456"},
        headers={"Authorization": f"Bearer {token}"},
    )
    new_token = await _login(client, "count-admin@example.com", "newpass456")
    after = await client.get("/audit-log/count", headers={"Authorization": f"Bearer {new_token}"})
    assert after.json()["count"] == 1


# ── DB-level immutability (Phase 18) ────────────────────────────────────────
#
# Real negative tests against the trigger installed by
# alembic/versions/5195e95231d0_audit_log_immutability_trigger.py (and
# mirrored for the test DB by the after_create event listener in
# app/models/audit_log.py) — not just "no PATCH/DELETE route exists".

async def test_direct_update_against_audit_log_entries_fails_at_the_db_level(db_session: AsyncSession):
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    from app.services import audit_service

    tenant = await make_tenant(db_session)
    await audit_service.log(db_session, tenant_id=tenant.id, action="test.seed_entry")
    await db_session.flush()

    # begin_nested() (a real SAVEPOINT) contains the failed statement to
    # just this block — a plain db_session.rollback() would instead unwind
    # the whole test's outer transaction, including the seed data above.
    with pytest.raises(DBAPIError, match="immutable"):
        async with db_session.begin_nested():
            await db_session.execute(text("UPDATE audit_log_entries SET action = 'tampered'"))


async def test_direct_delete_against_audit_log_entries_fails_at_the_db_level(db_session: AsyncSession):
    from sqlalchemy import select, text
    from sqlalchemy.exc import DBAPIError

    from app.models import AuditLogEntry
    from app.services import audit_service

    tenant = await make_tenant(db_session)
    await audit_service.log(db_session, tenant_id=tenant.id, action="test.seed_entry")
    await db_session.flush()

    with pytest.raises(DBAPIError, match="immutable"):
        async with db_session.begin_nested():
            await db_session.execute(text("DELETE FROM audit_log_entries"))

    # The row genuinely survived — this isn't just an exception, the data is
    # intact, checked on the same session right after the SAVEPOINT unwound.
    rows = (await db_session.execute(select(AuditLogEntry).where(AuditLogEntry.tenant_id == tenant.id))).scalars().all()
    assert len(rows) == 1


async def test_delete_succeeds_only_with_the_authorized_bypass_guc_set(db_session: AsyncSession):
    from sqlalchemy import select, text
    from sqlalchemy.exc import DBAPIError

    from app.models import AuditLogEntry
    from app.services import audit_service

    tenant = await make_tenant(db_session)
    await audit_service.log(db_session, tenant_id=tenant.id, action="test.seed_entry")
    await db_session.flush()

    # Without the GUC: still rejected.
    with pytest.raises(DBAPIError, match="immutable"):
        async with db_session.begin_nested():
            await db_session.execute(text("DELETE FROM audit_log_entries WHERE tenant_id = :tid"), {"tid": str(tenant.id)})

    # With the GUC set (SET LOCAL — scoped to this transaction only): succeeds.
    await db_session.execute(text("SET LOCAL sentinel.allow_audit_log_delete = 'on'"))
    await db_session.execute(text("DELETE FROM audit_log_entries WHERE tenant_id = :tid"), {"tid": str(tenant.id)})
    rows = (await db_session.execute(select(AuditLogEntry).where(AuditLogEntry.tenant_id == tenant.id))).scalars().all()
    assert rows == []
