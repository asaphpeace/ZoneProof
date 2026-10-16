import base64
import json
import time

import httpx
import pytest

from app.services import brand_probe_protocol as pp
from app.services import safe_fetch
from probe_worker import worker

KEY = "w" * 40


class Page:
    def __init__(self, url="http://a.xyz/", status=200, ctype="text/html", body=b"<html><title>x</title></html>", truncated=False):
        self.url, self.status, self.content_type, self.body, self.truncated = url, status, ctype, body, truncated


@pytest.fixture
def net(monkeypatch):
    calls = {"fetch": [], "cert": []}

    async def resolve(host):
        return ["93.184.216.34"]

    async def fetch(url, *, trace=None, user_agent=None, accept="", max_bytes=0, timeout=0, **kw):
        calls["fetch"].append((url, user_agent, accept))
        if "favicon" in url or "icon" in accept:
            return Page(url=url, ctype="image/x-icon", body=b"ICON")
        if trace is not None:
            trace.append({"url": url, "status": 301})
            trace.append({"url": "https://a.xyz/", "status": 200})
        return Page(url="https://a.xyz/", body=b"<html><head><link rel='icon' href='/i.png'><title>T</title></head></html>")

    async def cert(host, address):
        calls["cert"].append((host, address))
        return base64.b64encode(b"DER").decode(), None
    monkeypatch.setattr(safe_fetch, "resolve_public", resolve)
    monkeypatch.setattr(safe_fetch, "fetch", fetch)
    monkeypatch.setattr(worker, "read_certificate", cert)
    return calls


async def test_a_probe_collects_chain_html_icon_and_certificate_from_the_validated_address(net):
    r = await worker.probe("a.xyz")
    assert r["ok"] and [h["status"] for h in r["chain"]] == [301, 200] and r["final_status"] == 200 and "<title>T</title>" in r["html"]
    assert base64.b64decode(r["favicon_b64"]) == b"ICON" and base64.b64decode(r["cert_der_b64"]) == b"DER"
    assert net["cert"] == [("a.xyz", "93.184.216.34")]                      # the TLS handshake goes to the address that was checked, not a fresh lookup
    assert all(ua == worker.USER_AGENT for _, ua, _ in net["fetch"]) and "ZoneProof-Probe" in worker.USER_AGENT
    assert pp.clean_result(r)["ok"]                                          # what it sends survives the API's own cleaning


@pytest.mark.parametrize("host", ["", "localhost", "127.0.0.1", "a.xyz/../etc", "a.xyz:8080", "a b.xyz", "http://a.xyz", "x" * 300 + ".com", "-a.xyz"])
async def test_odd_hosts_are_refused_before_any_network_call(net, host):
    r = await worker.probe(host)
    assert r["ok"] is False and "refused" in r["error"] and net["fetch"] == [] and net["cert"] == []


async def test_a_name_that_resolves_to_a_private_address_is_refused(monkeypatch):
    async def resolve(host):
        raise safe_fetch.FetchError("refused: the name points at a non-public address")
    monkeypatch.setattr(safe_fetch, "resolve_public", resolve)
    r = await worker.probe("evil.example.com")
    assert r["ok"] is False and "non-public" in r["error"]


async def test_a_page_that_cannot_be_fetched_still_reports_the_chain_so_far_and_the_certificate(net, monkeypatch):
    async def fetch(url, *, trace=None, **kw):
        if trace is not None:
            trace.append({"url": url, "status": 302})
        raise safe_fetch.FetchError("too many redirects")
    monkeypatch.setattr(safe_fetch, "fetch", fetch)
    r = await worker.probe("a.xyz")
    assert r["ok"] is False and r["error"] == "too many redirects" and r["chain"][0]["status"] == 302 and r["cert_der_b64"]


async def test_non_html_content_is_not_sent_back_as_html(net, monkeypatch):
    async def fetch(url, *, trace=None, **kw):
        return Page(ctype="application/zip", body=b"PK\x03\x04binary")
    monkeypatch.setattr(safe_fetch, "fetch", fetch)
    r = await worker.probe("a.xyz")
    assert r["ok"] and "html" not in r and r["content_type"] == "application/zip"


async def test_run_once_signs_both_calls_and_posts_the_result(monkeypatch):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content
        assert pp.verify(KEY, request.method, request.url.path, request.headers["x-probe-timestamp"], body, request.headers["x-probe-signature"])
        seen.append(request.url.path)
        if request.url.path == "/probe-worker/claim":
            return httpx.Response(200, json={"job": {"id": "J1", "host": "a.xyz", "kind": "light", "expires_at": "x"}})
        return httpx.Response(204)

    async def fake_probe(host):
        return {"ok": True, "host_seen": host, "chain": []}
    monkeypatch.setattr(worker, "probe", fake_probe)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        assert await worker.run_once("http://api.test", KEY, c) is True
    assert seen == ["/probe-worker/claim", "/probe-worker/jobs/J1/result"]


async def test_run_once_does_nothing_when_there_is_no_job_or_the_api_is_off(monkeypatch):
    async def boom(host):
        raise AssertionError("must not probe")
    monkeypatch.setattr(worker, "probe", boom)
    for resp in (httpx.Response(200, json={"job": None}), httpx.Response(503, json={"detail": "off"}), httpx.Response(401)):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r, resp=resp: resp)) as c:
            assert await worker.run_once("http://api.test", KEY, c) is False


# ── safe_fetch additions the worker relies on ────────────────────────────────

async def test_safe_fetch_records_every_hop_and_uses_the_given_user_agent():
    hops = {"http://a.xyz/": (301, {"location": "https://a.xyz/home"}, b""), "https://a.xyz/home": (200, {"content-type": "text/html"}, b"<html></html>")}
    seen_agents = []

    def handler(request: httpx.Request) -> httpx.Response:
        key = f"{request.url.scheme}://{request.headers['host']}{request.url.path}"
        seen_agents.append(request.headers["user-agent"])
        status, headers, body = hops[key]
        return httpx.Response(status, headers=headers, content=body)

    async def resolver(host):
        return ["93.184.216.34"]
    trace = []
    res = await safe_fetch.fetch("http://a.xyz/", resolver=resolver, client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)), trace=trace, user_agent="X-Agent/1")
    assert res.status == 200 and trace == [{"url": "http://a.xyz/", "status": 301}, {"url": "https://a.xyz/home", "status": 200}] and set(seen_agents) == {"X-Agent/1"}


async def test_safe_fetch_without_trace_keeps_its_old_behaviour_and_user_agent():
    def handler(request):
        assert "ZoneProof-BrandGuard" in request.headers["user-agent"]
        return httpx.Response(200, headers={"content-type": "text/html"}, content=b"ok")

    async def resolver(host):
        return ["93.184.216.34"]
    res = await safe_fetch.fetch("http://a.xyz/", resolver=resolver, client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert res.body == b"ok"
