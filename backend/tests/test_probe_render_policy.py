import asyncio
import json
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "probe_worker"))
import render_policy as rp                                                 # noqa: E402
from probe_worker import worker                                            # noqa: E402


@pytest.mark.parametrize("method,url,ok", [
    ("GET", "https://evil.example/", True), ("GET", "http://evil.example/a?b=1", True), ("HEAD", "https://evil.example/", True),
    ("GET", "http://evil.example:80/", True), ("GET", "https://evil.example:443/x", True), ("GET", "http://93.184.216.34/", True),
    ("POST", "https://evil.example/", False), ("PUT", "https://evil.example/", False), ("DELETE", "https://evil.example/", False), ("PATCH", "https://evil.example/", False),
    ("GET", "file:///etc/passwd", False), ("GET", "ftp://evil.example/", False), ("GET", "javascript:alert(1)", False), ("GET", "data:text/html,x", False), ("GET", "ws://evil.example/", False),
    ("GET", "http://evil.example:6379/", False), ("GET", "http://evil.example:2375/", False), ("GET", "https://evil.example:8443/", False),
    ("GET", "http://127.0.0.1/", False), ("GET", "http://10.0.0.5/", False), ("GET", "http://192.168.1.1/", False), ("GET", "http://169.254.169.254/latest/meta-data/", False),
    ("GET", "http://[::1]/", False), ("GET", "http://0.0.0.0/", False), ("GET", "http://224.0.0.1/", False),
    ("GET", "http://user:pass@evil.example/", False), ("GET", "http:///x", False), ("GET", "http://evil.example:notaport/", False),
])
def test_what_the_browser_may_request(method, url, ok):
    assert rp.allow_request(method, url)[0] is ok


def test_the_request_ceiling_stops_a_page_that_asks_for_everything():
    # Measured on a real WordPress home page: ~140 requests. At 60 the styles and images never arrived and the screenshot was blank white.
    assert 150 <= rp.MAX_REQUESTS <= 400
    assert rp.allow_request("GET", "https://a.example/", rp.MAX_REQUESTS - 1)[0] is True
    assert rp.allow_request("GET", "https://a.example/", rp.MAX_REQUESTS) == (False, "request limit")


def test_the_method_check_is_case_insensitive_so_a_lowercase_post_is_still_refused():
    assert rp.allow_request("post", "https://a.example/")[0] is False and rp.allow_request("get", "https://a.example/")[0] is True


async def test_a_request_needs_both_the_static_policy_and_public_addresses():
    import render_job
    asked = []

    async def public(h):
        asked.append(h)
        return True

    async def private(h):
        asked.append(h)
        return False
    assert await render_job.decide("GET", "https://evil.example/x", 0, public) is True and asked == ["evil.example"]
    assert await render_job.decide("GET", "https://evil.example/x", 0, private) is False                 # the name points at a private address
    assert await render_job.decide("POST", "https://evil.example/x", 0, public) is False                  # policy refuses before any lookup
    assert await render_job.decide("GET", "http://127.0.0.1/", 0, public) is False
    assert await render_job.decide("GET", "https://evil.example/x", render_policy_max(), public) is False
    asked.clear()
    await render_job.decide("POST", "https://other.example/", 0, public)
    assert asked == []                                                                                    # a refused request never causes a DNS lookup


def render_policy_max():
    return rp.MAX_REQUESTS


@pytest.mark.parametrize("raw,expected", [(None, 60.0), ("", 60.0), ("60", 60.0), ("30", 30.0), ("1", 5.0), ("0", 5.0), ("-9", 5.0), ("99999", 600.0), ("abc", 60.0), ("nan", 60.0)])
def test_the_idle_wait_defaults_to_a_minute_and_a_typo_cannot_make_it_hammer_or_stall(raw, expected):
    assert worker.idle_sleep(raw) == expected


def test_the_container_has_no_secrets_no_mounts_and_everything_taken_away():
    cmd = worker.build_docker_command("evil.example", "zp-render-abc")
    assert cmd[:3] == ["docker", "run", "--rm"] and cmd[-2:] == [worker.RENDER_IMAGE, "evil.example"]
    joined = " ".join(cmd)
    for needle in ("--read-only", "--cap-drop ALL", "no-new-privileges", "--user 10001:10001", "--memory 1g", "--memory-swap 1g", "--pids-limit 256", "--network zp-render", "--name zp-render-abc"):
        assert needle in joined, needle
    assert "-v " not in joined and "--volume" not in joined and "--mount" not in joined and "-e " not in joined and "--env" not in joined and "--privileged" not in joined
    assert "--network host" not in joined


async def test_a_non_hostname_never_reaches_docker(monkeypatch):
    async def boom(*a, **k):
        raise AssertionError("docker was started")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", boom)
    for bad in ("", "localhost", "127.0.0.1", "a.xyz; rm -rf /", "--privileged", "a b.xyz"):
        assert (await worker.render_in_container(bad))["ok"] is False


class _Proc:
    def __init__(self, out=b"", hang=False, piece=4096):
        self._out, self._hang, self.returncode, self.killed, self._piece, self._pos = out, hang, None, False, piece, 0
        self.stdout = self

    async def read(self, n):
        """Like a real pipe: hands back what has 'arrived' (a few KB at a time), and b'' only at the end."""
        if self._hang:
            await asyncio.sleep(3600)
        self.returncode = 0
        chunk = self._out[self._pos:self._pos + min(n, self._piece)]
        self._pos += len(chunk)
        return chunk

    async def wait(self):
        return 0

    def kill(self):
        self.killed = True


async def test_the_supervisor_returns_the_containers_json_and_survives_garbage(monkeypatch):
    calls = []

    async def fake(*args, **k):
        calls.append(args)
        return _Proc(json.dumps({"ok": True, "render": {"title": "T"}}).encode())
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
    assert (await worker.render_in_container("evil.example"))["render"]["title"] == "T" and calls[0][0] == "docker"
    for out in (b"not json", b"[1,2]", b"", b"x" * (worker.MAX_RENDER_OUTPUT + 5)):
        async def fake2(*a, _o=out, **k):
            return _Proc(_o)
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake2)
        assert (await worker.render_in_container("evil.example"))["ok"] is False


async def test_a_result_larger_than_one_pipe_buffer_is_read_whole(monkeypatch):
    # Found on the first real run: a full page's result (~100 KB) arrived in pieces and the supervisor parsed the first piece only
    # ("render produced no result"). Small results fit in one read, which is why every earlier test passed.
    big = {"ok": True, "render": {"title": "T", "screenshot_b64": "A" * 300_000, "text": "word " * 3000}}

    async def fake(*a, **k):
        return _Proc(json.dumps(big).encode(), piece=7000)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
    out = await worker.render_in_container("evil.example")
    assert out["ok"] is True and len(out["render"]["screenshot_b64"]) == 300_000


async def test_a_hung_container_is_killed_and_reported_as_timed_out(monkeypatch):
    spawned = []

    async def fake(*args, **k):
        spawned.append(args)
        return _Proc(hang=True)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
    monkeypatch.setattr(worker, "RENDER_TIMEOUT", 0.05)
    out = await worker.render_in_container("evil.example")
    assert out == {"ok": False, "error": "render timed out"}
    kills = [a for a in spawned if a[:2] == ("docker", "kill")]
    assert kills and kills[0][2] == spawned[0][spawned[0].index("--name") + 1]      # the container we started is the one that is killed


def _client(kind, posted):
    class Client:
        async def post(self, url, content=None, headers=None):
            posted.append((url, json.loads(content)))
            return httpx.Response(200, json={"job": {"id": "j1", "host": "evil.example", "kind": kind}}) if url.endswith("/claim") else httpx.Response(204)
    return Client()


@pytest.mark.parametrize("kind,expected", [("render", "render"), ("light", "probe"), ("weird", None)])
async def test_a_render_job_goes_to_the_container_a_light_job_does_not_and_an_unknown_kind_is_refused(monkeypatch, kind, expected):
    seen = []

    async def render(host):
        seen.append("render")
        return {"ok": True, "render": {"title": "T"}}

    async def probe(host):
        seen.append("probe")
        return {"ok": True}
    monkeypatch.setattr(worker, "render_in_container", render)
    monkeypatch.setattr(worker, "probe", probe)
    posted = []
    assert await worker.run_once("https://api.example", "k" * 32, _client(kind, posted)) is True
    assert seen == ([expected] if expected else [])
    assert posted[-1][0].endswith("/result") and (expected or posted[-1][1]["result"]["error"] == "unsupported job kind")
