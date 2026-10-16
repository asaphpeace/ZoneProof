"""
Unit tests for oauth_app_risk_service.py. Microsoft Graph HTTP calls are
faked the same way test_dropbox_sign_service.py fakes outbound httpx calls
— never hit a real login.microsoftonline.com/graph.microsoft.com endpoint.
"""
import uuid
from datetime import datetime, timedelta, timezone

import httpx

from app.models import Engagement, OAuthAppConnection, OAuthGrant
from app.services import oauth_app_risk_service as svc
from app.services.crypto_service import encrypt_secret
from tests.factories import make_tenant


def test_classify_risk_is_critical_for_directory_readwrite():
    assert svc._classify_risk(["Directory.ReadWrite.All"]) == "critical"


def test_classify_risk_is_high_for_broad_readwrite_scopes():
    assert svc._classify_risk(["Mail.ReadWrite"]) == "high"


def test_classify_risk_is_medium_for_read_scopes():
    assert svc._classify_risk(["Mail.Read"]) == "medium"


def test_classify_risk_is_low_for_narrow_scopes():
    assert svc._classify_risk(["User.Read"]) == "low"


class _FakeResponse:
    def __init__(self, body, status_code=200):
        self._body = body
        self.status_code = status_code
        self.text = str(body)

    def json(self):
        return self._body


def _fake_graph_client(responses: dict):
    class _FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, data=None):
            return responses[url]

        async def get(self, url, headers=None):
            return responses[url]

    return lambda **kwargs: _FakeClient()


_TOKEN_URL = f"{svc._LOGIN_BASE}/tenant-123/oauth2/v2.0/token"
_GRANTS_URL = f"{svc._GRAPH_BASE}/oauth2PermissionGrants"


async def test_fetch_oauth_grants_resolves_app_names_and_grantee_emails(monkeypatch):
    responses = {
        _TOKEN_URL: _FakeResponse({"access_token": "fake-token"}),
        _GRANTS_URL: _FakeResponse({"value": [
            {"clientId": "app-guid-1", "principalId": "user-guid-1", "scope": "Mail.Read Files.Read.All"},
        ]}),
        f"{svc._GRAPH_BASE}/servicePrincipals/app-guid-1": _FakeResponse({"displayName": "Zapier"}),
        f"{svc._GRAPH_BASE}/users/user-guid-1": _FakeResponse({"mail": "jane@example.com"}),
    }
    monkeypatch.setattr(svc.httpx, "AsyncClient", _fake_graph_client(responses))

    grants = await svc._fetch_oauth_grants("tenant-123", "client-abc", "secret-xyz")
    assert len(grants) == 1
    assert grants[0]["grantee_principal"] == "jane@example.com"
    assert grants[0]["app_name"] == "Zapier"
    assert grants[0]["scopes"] == ["Mail.Read", "Files.Read.All"]


async def test_fetch_oauth_grants_captures_verified_publisher_info(monkeypatch):
    responses = {
        _TOKEN_URL: _FakeResponse({"access_token": "fake-token"}),
        _GRANTS_URL: _FakeResponse({"value": [
            {"clientId": "app-guid-1", "principalId": "user-guid-1", "scope": "Mail.Read"},
        ]}),
        f"{svc._GRAPH_BASE}/servicePrincipals/app-guid-1": _FakeResponse({
            "displayName": "Zapier",
            "verifiedPublisher": {"displayName": "Zapier Inc.", "verifiedPublisherId": "12345"},
        }),
        f"{svc._GRAPH_BASE}/users/user-guid-1": _FakeResponse({"mail": "jane@example.com"}),
    }
    monkeypatch.setattr(svc.httpx, "AsyncClient", _fake_graph_client(responses))

    grants = await svc._fetch_oauth_grants("tenant-123", "client-abc", "secret-xyz")
    assert grants[0]["publisher_verified"] is True
    assert grants[0]["publisher_name"] == "Zapier Inc."


async def test_fetch_oauth_grants_defaults_publisher_unverified_when_absent(monkeypatch):
    responses = {
        _TOKEN_URL: _FakeResponse({"access_token": "fake-token"}),
        _GRANTS_URL: _FakeResponse({"value": [
            {"clientId": "app-guid-1", "principalId": "user-guid-1", "scope": "Mail.Read"},
        ]}),
        f"{svc._GRAPH_BASE}/servicePrincipals/app-guid-1": _FakeResponse({"displayName": "Sketchy App"}),
        f"{svc._GRAPH_BASE}/users/user-guid-1": _FakeResponse({"mail": "jane@example.com"}),
    }
    monkeypatch.setattr(svc.httpx, "AsyncClient", _fake_graph_client(responses))

    grants = await svc._fetch_oauth_grants("tenant-123", "client-abc", "secret-xyz")
    assert grants[0]["publisher_verified"] is False
    assert grants[0]["publisher_name"] is None


async def test_fetch_oauth_grants_skips_admin_consented_for_all_grants(monkeypatch):
    """A grant with no principalId was consented for the whole org, not by
    one named individual — out of scope for this pass (module docstring)."""
    responses = {
        _TOKEN_URL: _FakeResponse({"access_token": "fake-token"}),
        _GRANTS_URL: _FakeResponse({"value": [
            {"clientId": "app-guid-1", "principalId": None, "scope": "Mail.Read"},
        ]}),
    }
    monkeypatch.setattr(svc.httpx, "AsyncClient", _fake_graph_client(responses))

    grants = await svc._fetch_oauth_grants("tenant-123", "client-abc", "secret-xyz")
    assert grants == []


async def test_get_graph_token_raises_on_bad_credentials(monkeypatch):
    responses = {_TOKEN_URL: _FakeResponse({"error": "invalid_client"}, status_code=401)}
    monkeypatch.setattr(svc.httpx, "AsyncClient", _fake_graph_client(responses))

    import pytest
    with pytest.raises(ConnectionError):
        await svc._get_graph_token("tenant-123", "client-abc", "wrong-secret")


def _make_connection(tenant_id, engagement_id=None) -> OAuthAppConnection:
    return OAuthAppConnection(
        id=uuid.uuid4(), tenant_id=tenant_id, engagement_id=engagement_id, provider="microsoft365",
        ms_tenant_id="tenant-123", ms_client_id="client-abc",
        encrypted_client_secret=encrypt_secret("secret-xyz"), status="connected",
    )


async def test_verify_connection_returns_true_on_success(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    connection = _make_connection(tenant.id)

    responses = {_TOKEN_URL: _FakeResponse({"access_token": "fake-token"})}
    monkeypatch.setattr(svc.httpx, "AsyncClient", _fake_graph_client(responses))

    assert await svc.verify_connection(connection) is True


async def test_verify_connection_returns_false_on_failure(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    connection = _make_connection(tenant.id)

    responses = {_TOKEN_URL: _FakeResponse({"error": "invalid_client"}, status_code=401)}
    monkeypatch.setattr(svc.httpx, "AsyncClient", _fake_graph_client(responses))

    assert await svc.verify_connection(connection) is False


async def test_run_oauth_risk_scan_creates_grants_and_findings_for_high_risk_scopes(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="oauth_risk", status="active")
    db_session.add(engagement)
    await db_session.flush()
    connection = _make_connection(tenant.id, engagement.id)
    db_session.add(connection)
    await db_session.commit()

    async def fake_fetch(ms_tenant_id, client_id, client_secret):
        return [
            {"grantee_principal": "jane@example.com", "app_name": "Zapier", "app_client_id": "app-1", "scopes": ["Mail.ReadWrite"]},
            {"grantee_principal": "bob@example.com", "app_name": "Calendly", "app_client_id": "app-2", "scopes": ["User.Read"]},
        ]
    monkeypatch.setattr(svc, "_fetch_oauth_grants", fake_fetch)

    findings = await svc.run_oauth_risk_scan(db_session, engagement, connection)

    # Only the high-risk grant (Zapier) produces a Finding; the low-risk one
    # (Calendly, User.Read) doesn't — mirrors every other tier's "findings
    # are problems, not a log of everything scanned" convention.
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].check_id == "app-1"

    from sqlalchemy import select
    grants_result = await db_session.execute(select(OAuthGrant).where(OAuthGrant.engagement_id == engagement.id))
    grants = grants_result.scalars().all()
    assert len(grants) == 2  # both grants are recorded even though only one produced a Finding

    await db_session.refresh(connection)
    assert connection.last_scan_status == "success"
    assert connection.last_scanned_at is not None


async def test_run_oauth_risk_scan_records_failure_without_raising(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="oauth_risk", status="active")
    db_session.add(engagement)
    await db_session.flush()
    connection = _make_connection(tenant.id, engagement.id)
    db_session.add(connection)
    await db_session.commit()

    async def fake_fetch(ms_tenant_id, client_id, client_secret):
        raise ConnectionError("could not list oauth2PermissionGrants (403): insufficient privileges")
    monkeypatch.setattr(svc, "_fetch_oauth_grants", fake_fetch)

    findings = await svc.run_oauth_risk_scan(db_session, engagement, connection)
    assert findings == []

    await db_session.refresh(connection)
    assert connection.last_scan_status == "failed"
    assert connection.last_scan_error


async def test_poll_all_due_oauth_connections_scans_every_connected_active_connection(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="oauth_risk", status="active")
    db_session.add(engagement)
    await db_session.flush()
    connection = _make_connection(tenant.id, engagement.id)
    db_session.add(connection)
    await db_session.commit()

    called = []
    async def fake_scan(db, eng, conn):
        called.append(conn.id)
        return []
    monkeypatch.setattr(svc, "run_oauth_risk_scan", fake_scan)

    count = await svc.poll_all_due_oauth_connections(db_session)
    assert count == 1
    assert called == [connection.id]


async def test_poll_all_due_oauth_connections_skips_unauthorized_connections(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    # No engagement at all — never authorized, must never be scanned.
    connection = _make_connection(tenant.id)
    db_session.add(connection)
    await db_session.commit()

    called = []
    async def fake_scan(db, eng, conn):
        called.append(conn.id)
        return []
    monkeypatch.setattr(svc, "run_oauth_risk_scan", fake_scan)

    count = await svc.poll_all_due_oauth_connections(db_session)
    assert count == 0
    assert called == []
