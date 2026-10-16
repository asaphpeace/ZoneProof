"""
Router-level tests for /oauth-app-connections and /engagements/{id}/oauth-grants
— the connection lifecycle and consent-gate wiring (auto-created 'oauth_risk'
Engagement, same weight as an Exposure scan) rather than the Microsoft Graph
ingestion logic itself (see test_oauth_app_risk_service.py for that).
"""
from sqlalchemy.ext.asyncio import AsyncSession

from app.routers import oauth_app_risk as router_module
from tests.factories import make_tenant, make_user

# The router does `from ...oauth_app_risk_service import verify_connection,
# run_oauth_risk_scan` — a direct import binds its own local name at import
# time, separate from the service module's attribute. Monkeypatching the
# service module (`oauth_app_risk_service.verify_connection = ...`) would
# never be seen by the router's already-bound reference; patch the router
# module's own name instead, same requirement `svc` doesn't have when a
# test only patches something called *from within* the service module.


async def test_create_oauth_app_connection_returns_pending_verification(auth_client):
    client, _tenant = auth_client
    resp = await client.post("/oauth-app-connections", json={
        "ms_tenant_id": "tenant-123", "ms_client_id": "client-abc", "ms_client_secret": "super-secret",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "pending_verification"
    assert body["ms_tenant_id"] == "tenant-123"
    assert "ms_client_secret" not in body  # never echo the secret back


async def test_get_setup_instructions_returns_real_guidance(auth_client):
    client, _tenant = auth_client
    resp = await client.get("/oauth-app-connections/setup-instructions")
    assert resp.status_code == 200
    instructions = resp.json()
    assert len(instructions) == 3
    assert any("admin consent" in i.lower() for i in instructions)


async def test_list_connections_scoped_to_tenant(auth_client):
    client, _tenant = auth_client
    await client.post("/oauth-app-connections", json={
        "ms_tenant_id": "tenant-123", "ms_client_id": "client-abc", "ms_client_secret": "super-secret",
    })
    resp = await client.get("/oauth-app-connections")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


async def test_verify_connection_activates_it_and_creates_an_engagement(auth_client, monkeypatch):
    client, _tenant = auth_client
    create_resp = await client.post("/oauth-app-connections", json={
        "ms_tenant_id": "tenant-123", "ms_client_id": "client-abc", "ms_client_secret": "super-secret",
    })
    connection_id = create_resp.json()["id"]

    async def fake_verify(connection):
        return True
    monkeypatch.setattr(router_module, "verify_connection", fake_verify)

    resp = await client.post(f"/oauth-app-connections/{connection_id}/verify")
    assert resp.status_code == 200
    assert resp.json()["status"] == "connected"

    engagements_resp = await client.get("/engagements")
    oauth_engagements = [e for e in engagements_resp.json() if e["tier"] == "oauth_risk"]
    assert len(oauth_engagements) == 1
    assert oauth_engagements[0]["status"] == "active"  # auto-approved, no e-signature — read-only, no employees targeted


async def test_verify_connection_rejects_bad_credentials(auth_client, monkeypatch):
    client, _tenant = auth_client
    create_resp = await client.post("/oauth-app-connections", json={
        "ms_tenant_id": "tenant-123", "ms_client_id": "client-abc", "ms_client_secret": "wrong-secret",
    })
    connection_id = create_resp.json()["id"]

    async def fake_verify(connection):
        return False
    monkeypatch.setattr(router_module, "verify_connection", fake_verify)

    resp = await client.post(f"/oauth-app-connections/{connection_id}/verify")
    assert resp.status_code == 400


async def _connect_a_connection(client, monkeypatch):
    create_resp = await client.post("/oauth-app-connections", json={
        "ms_tenant_id": "tenant-123", "ms_client_id": "client-abc", "ms_client_secret": "super-secret",
    })
    connection_id = create_resp.json()["id"]

    async def fake_verify(connection):
        return True
    monkeypatch.setattr(router_module, "verify_connection", fake_verify)
    await client.post(f"/oauth-app-connections/{connection_id}/verify")
    return connection_id


async def test_scan_rejects_an_unverified_connection(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/oauth-app-connections", json={
        "ms_tenant_id": "tenant-123", "ms_client_id": "client-abc", "ms_client_secret": "super-secret",
    })
    connection_id = create_resp.json()["id"]

    resp = await client.post(f"/oauth-app-connections/{connection_id}/scan")
    assert resp.status_code == 400


async def test_scan_returns_discovered_grants_and_is_listable_via_engagement(auth_client, monkeypatch):
    client, _tenant = auth_client
    connection_id = await _connect_a_connection(client, monkeypatch)

    async def fake_scan(db, engagement, connection):
        return []
    monkeypatch.setattr(router_module, "run_oauth_risk_scan", fake_scan)

    resp = await client.post(f"/oauth-app-connections/{connection_id}/scan")
    assert resp.status_code == 200
    assert resp.json() == []

    engagements_resp = await client.get("/engagements")
    oauth_engagement_id = next(e["id"] for e in engagements_resp.json() if e["tier"] == "oauth_risk")
    grants_resp = await client.get(f"/engagements/{oauth_engagement_id}/oauth-grants")
    assert grants_resp.status_code == 200


async def test_revoke_connection(auth_client, monkeypatch):
    client, _tenant = auth_client
    connection_id = await _connect_a_connection(client, monkeypatch)

    resp = await client.post(f"/oauth-app-connections/{connection_id}/revoke")
    assert resp.status_code == 200
    assert resp.json()["status"] == "revoked"


async def test_connections_are_isolated_by_tenant(auth_client, client, db_session: AsyncSession):
    owner_client, _owner_tenant = auth_client
    create_resp = await owner_client.post("/oauth-app-connections", json={
        "ms_tenant_id": "tenant-123", "ms_client_id": "client-abc", "ms_client_secret": "super-secret",
    })
    assert create_resp.status_code == 200

    other_tenant = await make_tenant(db_session, name="Other Workspace")
    await make_user(db_session, other_tenant, email="other-oauth@example.com", password="pass123")
    await db_session.flush()
    login = await client.post(
        "/auth/token", data={"username": "other-oauth@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    list_resp = await client.get("/oauth-app-connections")
    assert list_resp.json() == []


async def test_connections_require_auth(client):
    resp = await client.get("/oauth-app-connections")
    assert resp.status_code == 401
