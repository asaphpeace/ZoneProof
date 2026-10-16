"""The sandboxed renderer (plan step 7.3). Runs INSIDE a throwaway container, once per job, and prints one JSON result on stdout.

    python render_job.py <hostname>

What it does: opens http://<hostname>/ in a fresh headless Chromium (no profile, no cookies, no downloads, no permissions), lets the page's
scripts run for a few seconds, then reads the title, the visible text, the forms (including password fields outside a <form>), the navigation
redirects, and a screenshot. What it never does: submit a form, type into a field, click anything, accept a download or a dialog, or keep
anything. Every request the page makes goes through `render_policy` (GET/HEAD only, default ports, public addresses only, request ceiling).

The container holds no secrets: not the signing key, not the API address. The supervisor (worker.py) starts the container, reads this output
and does the posting. See BRAND_GUARD_PROBE_WORKER.md for the container flags and the firewall that blocks private ranges at the network level.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import sys
import time
from urllib.parse import urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import render_policy                                                    # noqa: E402

USER_AGENT = "ZoneProof-Probe/1 (security research on brand impersonation; read-only)"
HOST_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
NAV_TIMEOUT_MS = 20_000
SETTLE_MS = 2_500
OVERALL_TIMEOUT = 45.0
VIEWPORT = {"width": 1280, "height": 800}
MAX_SHOT_BYTES = 900_000
MAX_TEXT = 20_000
MAX_NAV = 6
LAUNCH_ARGS = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--disable-extensions", "--disable-background-networking",
               "--disable-sync", "--no-first-run", "--mute-audio", "--disable-features=Translate,MediaRouter", "--disable-webrtc"]

# Reads the DOM through attributes and prototype lookups, not properties a page can shadow by naming an input "method" or "action".
_FORMS_JS = """() => {
  const out = [];
  const inputs = el => Array.from(el.querySelectorAll('input')).slice(0, 30).map(i => (i.getAttribute('type') || 'text').toLowerCase());
  for (const f of Array.from(document.querySelectorAll('form')).slice(0, 20)) {
    out.push({action: f.getAttribute('action') || '', method: (f.getAttribute('method') || 'get').toLowerCase(), inputs: inputs(f)});
  }
  const loose = Array.from(document.querySelectorAll('input[type=password]')).filter(i => !i.closest('form'));
  if (loose.length) out.push({action: '', method: 'get', inputs: loose.slice(0, 30).map(() => 'password')});
  return out;
}"""


async def decide(method: str, url: str, count: int, host_ok) -> bool:
    """Whether the browser may make this request: the static policy first, then the host's addresses must be public (`host_ok` resolves them)."""
    ok, _ = render_policy.allow_request(method, url, count)
    return bool(ok and await host_ok((urlsplit(url).hostname or "").lower()))


async def render(host: str, *, allow_private_for_tests: bool = False, scheme: str = "http", port: int | None = None) -> dict:
    """One rendered look. Never raises: any failure becomes {"ok": False, "error": ...}. `allow_private_for_tests` exists only so the unit
    tests can point the browser at a fixture server on loopback; the command line cannot set it."""
    started = time.monotonic()
    if not allow_private_for_tests and not HOST_RE.match(host or ""):
        return {"ok": False, "error": "refused: not a plain hostname"}
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"ok": False, "error": "browser not installed"}
    from app.services import safe_fetch

    nav: list[dict] = []
    stats = {"requests": 0, "blocked": 0}
    verdicts: dict[str, bool] = {}

    async def host_ok(h: str) -> bool:
        if allow_private_for_tests:
            return True
        if h not in verdicts:
            try:
                await safe_fetch.resolve_public(h)
                verdicts[h] = True
            except safe_fetch.FetchError:
                verdicts[h] = False
        return verdicts[h]

    async def handle(route):
        req = route.request
        ok = _loose(req) if allow_private_for_tests else await decide(req.method, req.url, stats["requests"], host_ok)
        if not ok:
            stats["blocked"] += 1
            await route.abort()
            return
        stats["requests"] += 1
        await route.continue_()

    def _loose(req):
        return req.method.upper() in render_policy.ALLOWED_METHODS and stats["requests"] < render_policy.MAX_REQUESTS

    result: dict = {"ok": False, "chain": [], "elapsed_ms": 0}
    timed_out = False
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=LAUNCH_ARGS)
            try:
                ctx = await browser.new_context(viewport=VIEWPORT, java_script_enabled=True, accept_downloads=False, service_workers="block",
                                                user_agent=USER_AGENT, ignore_https_errors=True, permissions=[], locale="en-ZA")
                await ctx.route("**/*", handle)
                page = await ctx.new_page()
                page.on("dialog", lambda d: asyncio.ensure_future(d.dismiss()))
                page.on("popup", lambda p: asyncio.ensure_future(p.close()))
                page.on("download", lambda d: asyncio.ensure_future(d.cancel()))

                def on_response(resp):
                    try:
                        if resp.request.is_navigation_request() and resp.frame == page.main_frame and len(nav) < MAX_NAV:
                            nav.append({"url": resp.url[:500], "status": resp.status})
                    except Exception:
                        pass
                page.on("response", on_response)
                target = f"{scheme}://{host}" + (f":{port}" if port else "") + "/"
                try:
                    await page.goto(target, wait_until="load", timeout=NAV_TIMEOUT_MS)
                except Exception as e:                       # a slow or failing page is still worth what we got
                    timed_out = "Timeout" in type(e).__name__ or "timeout" in str(e).lower()
                    if not nav:
                        return {"ok": False, "error": ("timed out" if timed_out else "could not load the page"), "elapsed_ms": int((time.monotonic() - started) * 1000)}
                await page.wait_for_timeout(SETTLE_MS)
                title = (await page.title())[:300]
                text = await page.evaluate("() => (document.body && document.body.innerText || '').slice(0, 30000)")
                forms = await page.evaluate(_FORMS_JS)
                shot = None
                for q in (60, 40):
                    raw = await page.screenshot(type="jpeg", quality=q, full_page=False, timeout=10_000)
                    if len(raw) <= MAX_SHOT_BYTES:
                        shot = base64.b64encode(raw).decode()
                        break
                result = {"ok": True, "chain": [], "render": {
                    "screenshot_b64": shot, "title": title, "text": text[:MAX_TEXT], "forms": forms, "nav_chain": nav, "final_url": page.url[:500],
                    "requests": stats["requests"], "blocked": stats["blocked"], "timed_out": timed_out,
                }}
            finally:
                await browser.close()
    except Exception as e:
        return {"ok": False, "error": f"renderer failed: {type(e).__name__}", "elapsed_ms": int((time.monotonic() - started) * 1000)}
    result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    return result


async def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(json.dumps({"ok": False, "error": "usage: render_job.py <hostname>"}))
        return 2
    try:
        out = await asyncio.wait_for(render(argv[1]), OVERALL_TIMEOUT)
    except asyncio.TimeoutError:
        out = {"ok": False, "error": "timed out"}
    sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv)))
