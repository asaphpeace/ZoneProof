"""
POPIA/GDPR-style data erasure (Phishing Simulation roadmap Phase 18) —
DELETE /auth/account's admin path. Real confirmation friction, a real
whole-tenant cascade, and a real durable erasure record that survives the
cascade it describes (see TenantErasureLog's docstring).
"""
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLogEntry, TenantErasureLog
from app.models.user import Tenant, User
from tests.factories import make_domain, make_tenant, make_user


async def _login(client: AsyncClient, email: str, password: str) -> str:
    resp = await client.post(
        "/auth/token",
        data={"username": email, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return resp.json()["access_token"]


async def test_admin_delete_without_confirmation_is_rejected_and_tenant_survives(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, name="Acme Co")
    await make_user(db_session, tenant, email="admin@acme.example", password="pass123")
    await db_session.flush()

    token = await _login(client, "admin@acme.example", "pass123")
    resp = await client.request(
        "DELETE", "/auth/account", json={}, headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 400

    still_there = await db_session.scalar(select(Tenant).where(Tenant.id == tenant.id))
    assert still_there is not None


async def test_admin_delete_with_wrong_tenant_name_is_rejected(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, name="Acme Co")
    await make_user(db_session, tenant, email="admin2@acme.example", password="pass123")
    await db_session.flush()

    token = await _login(client, "admin2@acme.example", "pass123")
    resp = await client.request(
        "DELETE", "/auth/account",
        json={"confirm_tenant_name": "Wrong Name"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400
    still_there = await db_session.scalar(select(Tenant).where(Tenant.id == tenant.id))
    assert still_there is not None


async def test_admin_delete_with_correct_confirmation_erases_the_whole_tenant(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, name="Acme Co")
    admin = await make_user(db_session, tenant, email="admin3@acme.example", password="pass123")
    await make_user(db_session, tenant, email="teammate@acme.example", password="pass123", role="viewer")
    await make_domain(db_session, tenant, name="acme.com")
    await db_session.flush()

    from app.services import audit_service
    await audit_service.log(db_session, tenant_id=tenant.id, actor=admin, action="test.pre_existing_entry")
    await db_session.flush()

    token = await _login(client, "admin3@acme.example", "pass123")
    resp = await client.request(
        "DELETE", "/auth/account",
        json={"confirm_tenant_name": "Acme Co"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204

    # The tenant, its users, and its audit trail are genuinely gone.
    assert await db_session.scalar(select(Tenant).where(Tenant.id == tenant.id)) is None
    assert (await db_session.execute(select(User).where(User.tenant_id == tenant.id))).scalars().all() == []
    assert (await db_session.execute(select(AuditLogEntry).where(AuditLogEntry.tenant_id == tenant.id))).scalars().all() == []

    # But durable, independent proof the erasure happened does survive.
    erasure = await db_session.scalar(select(TenantErasureLog).where(TenantErasureLog.tenant_id == tenant.id))
    assert erasure is not None
    assert erasure.tenant_name == "Acme Co"
    assert erasure.deleted_by_email == "admin3@acme.example"
    assert erasure.domain_count == 1
    assert erasure.user_count == 2


async def test_non_admin_delete_removes_only_self_not_the_tenant(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, name="Acme Co")
    await make_user(db_session, tenant, email="owner@acme.example", password="pass123", role="admin")
    await make_user(db_session, tenant, email="member@acme.example", password="pass123", role="viewer")
    await db_session.flush()

    token = await _login(client, "member@acme.example", "pass123")
    resp = await client.request(
        "DELETE", "/auth/account", json={}, headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 204

    assert await db_session.scalar(select(Tenant).where(Tenant.id == tenant.id)) is not None
    remaining = (await db_session.execute(select(User).where(User.tenant_id == tenant.id))).scalars().all()
    assert [u.email for u in remaining] == ["owner@acme.example"]
