"""ZoneProof egress worker (plan step 7.1/7.2): runs on its OWN machine, pulls probe jobs from the API, looks at one look-alike host, posts back.

What it holds: a signing key and the API address. No database, no customer data, no other secrets. What it does to a suspect host: a GET for the
home page (at most 3 validated redirects), a GET for the favicon, and one TLS handshake to read the certificate. It never submits a form, never
runs anything, never downloads a file beyond a capped read into memory, and refuses non-public addresses (on top of the machine's firewall).

Deploy: copy this folder and app/services/safe_fetch.py and app/services/brand_probe_protocol.py to the worker machine (it imports nothing else
from the app), `pip install httpx`, set ZP_API, ZP_KEY, then `python worker.py`. See BRAND_GUARD_STAGE7_EGRESS_DESIGN.md.

    ZP_API   base URL of the ZoneProof API, e.g. https://api.example.com
    ZP_KEY   the shared signing key (settings.brand_probe_key on the API)
"""
from __future__ import annotations

import asyncio
import base64
import json
import math
import os
import re
import ssl
import sys
import time

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from app.services import brand_probe_protocol as proto        # noqa: E402
from app.services import safe_fetch                           # noqa: E402

USER_AGENT = "ZoneProof-Probe/1 (security research on brand impersonation; read-only)"
PAGE_TIMEOUT = 12.0
ICON_TIMEOUT = 6.0
TLS_TIMEOUT = 6.0
def idle_sleep(raw: str | None) -> float:
    """Seconds to wait when there was no job (or the API said no): ZP_IDLE_SLEEP, default 60, kept between 5 and 600 so a typo cannot make the
    worker hammer the API or go quiet for hours."""
    try:
        value = float(raw) if raw not in (None, "") else 60.0
    except ValueError:
        return 60.0
    return min(600.0, max(5.0, value)) if math.isfinite(value) else 60.0


IDLE_SLEEP = idle_sleep(os.environ.get("ZP_IDLE_SLEEP"))
HOST_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_ICON_RE = re.compile(r"""<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]*href=["']([^"']+)["']""", re.I)


async def read_certificate(host: str, address: str) -> tuple[str | None, str | None]:
    """The leaf certificate the host serves, as base64 DER, even if it would not validate (that is part of the evidence). Connects to the
    already-validated public address, with the real name as SNI."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, 443, ssl=ctx, server_hostname=host), TLS_TIMEOUT)
        try:
            der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        finally:
            writer.close()
        return (base64.b64encode(der).decode() if der and len(der) <= proto.MAX_CERT_BYTES else None), None
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None, "no TLS service"


async def probe(host: str) -> dict:
    """One light probe. Never raises: any failure becomes {"ok": False, "error": ...}."""
    started = time.monotonic()
    if not HOST_RE.match(host or ""):
        return {"ok": False, "error": "refused: not a plain hostname"}
    out: dict = {"ok": False, "chain": [], "elapsed_ms": 0}
    try:
        addresses = await safe_fetch.resolve_public(host)
    except safe_fetch.FetchError as e:
        return {"ok": False, "error": str(e)[:100], "elapsed_ms": int((time.monotonic() - started) * 1000)}
    trace: list = []
    try:
        page = await safe_fetch.fetch(f"http://{host}/", max_bytes=proto.MAX_HTML_BYTES, timeout=PAGE_TIMEOUT, trace=trace, user_agent=USER_AGENT)
        out.update(ok=True, chain=trace, final_status=page.status, content_type=page.content_type, truncated=page.truncated)
        if page.content_type in ("text/html", "application/xhtml+xml", ""):
            out["html"] = page.body.decode("utf-8", "replace")
    except safe_fetch.FetchError as e:
        out.update(ok=False, chain=trace, error=str(e)[:100])
    icon_urls = []
    if out.get("html"):
        m = _ICON_RE.search(out["html"][:50000])
        if m and len(m.group(1)) < 300:
            icon_urls.append(m.group(1))
    base = out["chain"][-1]["url"] if out.get("chain") else f"http://{host}/"
    icon_urls.append("/favicon.ico")
    from urllib.parse import urljoin
    for u in icon_urls:
        try:
            res = await safe_fetch.fetch(urljoin(base, u), max_bytes=proto.MAX_ICON_BYTES, timeout=ICON_TIMEOUT, accept="image/*,*/*;q=0.5", user_agent=USER_AGENT)
        except safe_fetch.FetchError:
            continue
        if res.status < 400 and res.body and not res.truncated and not res.content_type.startswith("text/html"):
            out["favicon_b64"] = base64.b64encode(res.body).decode()
            break
    out["cert_der_b64"], out["tls_error"] = await read_certificate(host, addresses[0])
    out["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    return out


RENDER_IMAGE = os.environ.get("ZP_RENDER_IMAGE", "zoneproof-render:1")
RENDER_NETWORK = os.environ.get("ZP_RENDER_NETWORK", "zp-render")           # a docker network whose private-range egress the host firewall drops
RENDER_TIMEOUT = 70.0
MAX_RENDER_OUTPUT = 2_000_000


def build_docker_command(host: str, name: str, image: str = RENDER_IMAGE, network: str = RENDER_NETWORK) -> list[str]:
    """The throwaway container for one render. No secrets go in (no environment, no mounts); everything not needed is taken away. Pure."""
    return [
        "docker", "run", "--rm", "--name", name,
        "--network", network,
        "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", "10001:10001",
        "--memory", "1g", "--memory-swap", "1g", "--cpus", "1", "--pids-limit", "256", "--shm-size", "256m",
        "--stop-timeout", "5",
        image, host,
    ]


async def _read_capped(stream, limit: int) -> bytes:
    """Everything the container prints, up to limit + 1 bytes (one over means 'too large'). `stream.read(n)` alone returns whatever has arrived,
    so a result bigger than one pipe buffer (a real page's screenshot) came back cut in half and failed to parse."""
    chunks, total = [], 0
    while total <= limit:
        chunk = await stream.read(min(65536, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


async def render_in_container(host: str) -> dict:
    """Render one host in a fresh container and return its result. Never raises: a failure becomes {"ok": False, "error": ...}."""
    import uuid
    if not HOST_RE.match(host or ""):
        return {"ok": False, "error": "refused: not a plain hostname"}
    name = f"zp-render-{uuid.uuid4().hex[:12]}"
    proc = await asyncio.create_subprocess_exec(*build_docker_command(host, name), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, stdin=asyncio.subprocess.DEVNULL)
    try:
        out = await asyncio.wait_for(_read_capped(proc.stdout, MAX_RENDER_OUTPUT), RENDER_TIMEOUT)
        await asyncio.wait_for(proc.wait(), 10.0)
    except asyncio.TimeoutError:
        killer = await asyncio.create_subprocess_exec("docker", "kill", name, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await killer.wait()
        return {"ok": False, "error": "render timed out"}
    except OSError:
        return {"ok": False, "error": "could not start the renderer"}
    finally:
        if proc.returncode is None:
            proc.kill()
    if len(out) > MAX_RENDER_OUTPUT:
        return {"ok": False, "error": "render output too large"}
    try:
        data = json.loads(out.decode("utf-8", "replace"))
    except ValueError:
        return {"ok": False, "error": "render produced no result"}
    return data if isinstance(data, dict) else {"ok": False, "error": "render produced no result"}


def _signed(client: httpx.AsyncClient, key: str, method: str, path: str, body: bytes) -> dict:
    ts = str(time.time())
    return {"X-Probe-Timestamp": ts, "X-Probe-Signature": proto.sign(key, method, path, ts, body), "Content-Type": "application/json"}


async def run_once(api: str, key: str, client: httpx.AsyncClient) -> bool:
    """Claim and complete at most one job. Returns True if a job was handled."""
    path = "/probe-worker/claim"
    body = b"{}"
    r = await client.post(api + path, content=body, headers=_signed(client, key, "POST", path, body))
    if r.status_code != 200 or not r.json().get("job"):
        return False
    job = r.json()["job"]
    if job.get("kind") in ("render", "ref"):          # "ref" is the customer's own page: same renderer, same isolation
        result = await render_in_container(job["host"])
    elif job.get("kind", "light") == "light":
        result = await probe(job["host"])
    else:
        result = {"ok": False, "error": "unsupported job kind"}
    path = f"/probe-worker/jobs/{job['id']}/result"
    body = json.dumps({"result": result}).encode()
    await client.post(api + path, content=body, headers=_signed(client, key, "POST", path, body))
    return True


async def main() -> None:
    api, key = os.environ.get("ZP_API", "").rstrip("/"), os.environ.get("ZP_KEY", "")
    if not api or not key:
        sys.exit("Set ZP_API and ZP_KEY")
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
        while True:
            try:
                handled = await run_once(api, key, client)
            except httpx.HTTPError as e:
                print(f"api unreachable: {type(e).__name__}", file=sys.stderr)
                handled = False
            if not handled:
                await asyncio.sleep(IDLE_SLEEP)


if __name__ == "__main__":
    asyncio.run(main())
