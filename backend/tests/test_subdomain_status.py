"""Discovery reports which source could not be asked, instead of looking like 'none found'."""
import httpx
import pytest

from app.services import subdomain_discovery_service as svc
from tests.factories import make_domain, make_tenant


class _Boom:
    """AsyncClient stand-in whose request always times out."""
    def __init__(self, *a, **k): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def get(self, url): raise httpx.ReadTimeout("slow")


class _Ok(_Boom):
    async def get(self, url):
        req = httpx.Request("GET", url)
        return httpx.Response(200, request=req, json=[{"name_value": "mail.status.test\n*.status.test\nstatus.test"}])


@pytest.mark.asyncio
async def test_timeout_is_reported_not_swallowed(monkeypatch):
    svc._ct_cache.clear()
    monkeypatch.setattr(svc.httpx, "AsyncClient", _Boom)
    monkeypatch.setattr(svc, "_CT_ATTEMPTS", 1)
    hosts, status = await svc._from_ct_logs_with_status("status.test")
    assert hosts == set() and status == "timed_out"
    assert "status.test" not in svc._ct_cache      # a failure is never remembered as "none"


@pytest.mark.asyncio
async def test_success_is_cached_and_filtered(monkeypatch):
    svc._ct_cache.clear()
    monkeypatch.setattr(svc.httpx, "AsyncClient", _Ok)
    hosts, status = await svc._from_ct_logs_with_status("status.test")
    assert hosts == {"mail.status.test"} and status == "ok"

    monkeypatch.setattr(svc.httpx, "AsyncClient", _Boom)   # would fail now, cache must answer
    hosts, status = await svc._from_ct_logs_with_status("status.test")
    assert hosts == {"mail.status.test"} and status == "cached"


@pytest.mark.asyncio
async def test_status_map_for_unverified_domain(db_session, monkeypatch):
    svc._ct_cache.clear()
    monkeypatch.setattr(svc.httpx, "AsyncClient", _Boom)
    monkeypatch.setattr(svc, "_CT_ATTEMPTS", 1)
    async def _no_records(_name):
        return set()
    monkeypatch.setattr(svc, "_from_own_records", _no_records)   # no network in unit tests
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant, name="status.test")
    found, sources = await svc.discover_subdomains_with_status(db_session, domain, allow_active=False)
    assert found == []
    assert sources == {
        "dmarc": "ok", "cert": "ok", "dns_records": "ok", "ct": "timed_out", "dns_active": "skipped_unverified",
    }
