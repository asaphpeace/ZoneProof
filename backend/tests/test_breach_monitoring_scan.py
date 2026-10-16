"""
Identity & Credential Hygiene — breach-monitoring half (Coverage Map plan
Phase 5). HTTP calls to HaveIBeenPwned are faked the same way
test_oauth_app_risk_service.py fakes outbound httpx calls — never hits the
real haveibeenpwned.com in this suite, and never needs a real API key.
"""
import uuid

from sqlalchemy import select

from app.config import settings
from app.models import Engagement, Finding, PhishingTargetList
from app.services import breach_monitoring_service as svc
from tests.factories import make_tenant


class _FakeResponse:
    def __init__(self, body, status_code=200):
        self._body = body
        self.status_code = status_code

    def json(self):
        return self._body

    def raise_for_status(self):
        pass


def _fake_httpx_client(responses: dict):
    class _FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, params=None, headers=None):
            return responses[url]

    return lambda **kwargs: _FakeClient()


async def _make_engagement(db_session, tenant):
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add(engagement)
    await db_session.flush()
    return engagement


async def _make_target_list(db_session, tenant, emails: list[str]):
    tl = PhishingTargetList(
        id=uuid.uuid4(), tenant_id=tenant.id, name="All staff",
        entries=[{"email": e, "display_name": e} for e in emails],
    )
    db_session.add(tl)
    await db_session.flush()
    return tl


async def test_returns_none_when_hibp_key_not_configured(db_session, monkeypatch):
    monkeypatch.setattr(settings, "hibp_api_key", "")
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant)
    await db_session.commit()

    error_detail = {}
    result = await svc.run_breach_monitoring_scan(db_session, engagement, tenant.id, error_detail=error_detail)
    assert result is None
    assert "not configured" in error_detail["message"]


async def test_returns_empty_when_no_target_lists_exist(db_session, monkeypatch):
    monkeypatch.setattr(settings, "hibp_api_key", "fake-key")
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant)
    await db_session.commit()

    result = await svc.run_breach_monitoring_scan(db_session, engagement, tenant.id)
    assert result == []


async def test_persists_a_finding_for_a_breached_email(db_session, monkeypatch):
    monkeypatch.setattr(settings, "hibp_api_key", "fake-key")
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant)
    await _make_target_list(db_session, tenant, ["jane@example.com"])
    await db_session.commit()

    responses = {
        f"{svc._HIBP_BASE}/breachedaccount/jane@example.com": _FakeResponse([
            {"Name": "Adobe", "BreachDate": "2013-10-04", "IsSensitive": False},
        ]),
    }
    monkeypatch.setattr(svc.httpx, "AsyncClient", _fake_httpx_client(responses))
    monkeypatch.setattr(svc.asyncio, "sleep", lambda *_: _noop_sleep())

    result = await svc.run_breach_monitoring_scan(db_session, engagement, tenant.id)
    assert result is not None
    assert len(result) == 1
    assert result[0].check_id == "hibp_breach_match"
    assert result[0].resource_uid == "jane@example.com"
    assert "Adobe" in result[0].detail

    persisted = (await db_session.execute(
        select(Finding).where(Finding.engagement_id == engagement.id)
    )).scalars().all()
    assert len(persisted) == 1


async def test_no_finding_for_a_clean_email(db_session, monkeypatch):
    monkeypatch.setattr(settings, "hibp_api_key", "fake-key")
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant)
    await _make_target_list(db_session, tenant, ["clean@example.com"])
    await db_session.commit()

    responses = {
        f"{svc._HIBP_BASE}/breachedaccount/clean@example.com": _FakeResponse(None, status_code=404),
    }
    monkeypatch.setattr(svc.httpx, "AsyncClient", _fake_httpx_client(responses))
    monkeypatch.setattr(svc.asyncio, "sleep", lambda *_: _noop_sleep())

    result = await svc.run_breach_monitoring_scan(db_session, engagement, tenant.id)
    assert result == []


async def test_deduplicates_emails_across_multiple_target_lists(db_session, monkeypatch):
    monkeypatch.setattr(settings, "hibp_api_key", "fake-key")
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant)
    await _make_target_list(db_session, tenant, ["shared@example.com"])
    await _make_target_list(db_session, tenant, ["shared@example.com"])
    await db_session.commit()

    calls = []

    class _CountingClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, params=None, headers=None):
            calls.append(url)
            return _FakeResponse(None, status_code=404)

    monkeypatch.setattr(svc.httpx, "AsyncClient", lambda **kwargs: _CountingClient())
    monkeypatch.setattr(svc.asyncio, "sleep", lambda *_: _noop_sleep())

    await svc.run_breach_monitoring_scan(db_session, engagement, tenant.id)
    assert len(calls) == 1  # the same email on two lists is only checked once


async def test_returns_none_on_bad_api_key(db_session, monkeypatch):
    monkeypatch.setattr(settings, "hibp_api_key", "wrong-key")
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant)
    await _make_target_list(db_session, tenant, ["jane@example.com"])
    await db_session.commit()

    responses = {
        f"{svc._HIBP_BASE}/breachedaccount/jane@example.com": _FakeResponse(None, status_code=401),
    }
    monkeypatch.setattr(svc.httpx, "AsyncClient", _fake_httpx_client(responses))
    monkeypatch.setattr(svc.asyncio, "sleep", lambda *_: _noop_sleep())

    error_detail = {}
    result = await svc.run_breach_monitoring_scan(db_session, engagement, tenant.id, error_detail=error_detail)
    assert result is None
    assert "401" in error_detail["message"]


async def _noop_sleep():
    return None
