"""
Unit tests for the pure detection logic in exposure_scan_service.py — no
network, no DB. check_subdomain_takeover and check_open_ports are exercised
against monkeypatched lower-level helpers (_resolve_cname, httpx, the sync
port-connect function) so these tests assert on the matching/orchestration
logic itself, not on real DNS/HTTP/sockets.
"""
import httpx

from app.services import exposure_scan_service as svc


async def test_check_subdomain_takeover_flags_a_known_fingerprint_match(monkeypatch):
    async def fake_resolve_cname(hostname):
        return "old-project.herokuapp.com" if hostname == "blog.example.com" else None

    async def fake_check_fingerprint(hostname, cname_target):
        return {"cname_target": cname_target, "provider_suffix": "herokuapp.com", "fingerprint": "no such app"}

    monkeypatch.setattr(svc, "_resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(svc, "_check_takeover_fingerprint", fake_check_fingerprint)

    results = await svc.check_subdomain_takeover(["blog.example.com", "www.example.com"])
    assert len(results) == 1
    assert results[0]["hostname"] == "blog.example.com"
    assert results[0]["provider_suffix"] == "herokuapp.com"


async def test_check_subdomain_takeover_skips_hosts_with_no_cname(monkeypatch):
    async def fake_resolve_cname(hostname):
        return None

    monkeypatch.setattr(svc, "_resolve_cname", fake_resolve_cname)
    results = await svc.check_subdomain_takeover(["www.example.com"])
    assert results == []


async def test_check_subdomain_takeover_skips_cnames_that_dont_match_known_providers(monkeypatch):
    async def fake_resolve_cname(hostname):
        return "some-internal-host.example-corp.net"

    monkeypatch.setattr(svc, "_resolve_cname", fake_resolve_cname)
    results = await svc.check_subdomain_takeover(["internal.example.com"])
    assert results == []


async def test_check_takeover_fingerprint_matches_known_provider_text(monkeypatch):
    class _FakeResponse:
        text = "<html>Application Error: no such app on this account</html>"

    class _FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url, headers=None): return _FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _FakeClient())
    result = await svc._check_takeover_fingerprint("blog.example.com", "old-project.herokuapp.com")
    assert result is not None
    assert result["provider_suffix"] == "herokuapp.com"


async def test_check_takeover_fingerprint_returns_none_when_page_is_claimed(monkeypatch):
    class _FakeResponse:
        text = "<html>Welcome to our real live app!</html>"

    class _FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url, headers=None): return _FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _FakeClient())
    result = await svc._check_takeover_fingerprint("blog.example.com", "old-project.herokuapp.com")
    assert result is None


async def test_check_open_ports_reports_only_ports_that_accepted_a_connection(monkeypatch):
    def fake_scan_port_sync(host, port):
        return port in (22, 3306)

    monkeypatch.setattr(svc, "_scan_port_sync", fake_scan_port_sync)
    results = await svc.check_open_ports("example.com")
    ports = {r["port"] for r in results}
    assert ports == {22, 3306}


async def test_check_open_ports_returns_empty_when_nothing_is_open(monkeypatch):
    monkeypatch.setattr(svc, "_scan_port_sync", lambda host, port: False)
    results = await svc.check_open_ports("example.com")
    assert results == []
