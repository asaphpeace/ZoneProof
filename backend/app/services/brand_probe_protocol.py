"""The contract between ZoneProof and the egress worker (plan step 7.1/7.2).

The worker is a separate machine that holds no database access and no customer data. It pulls one job at a time ("probe this host") over
HTTPS, does the network work, and posts back what it saw. Two rules shape this module:

  1. The worker proves who it is with an HMAC over the request (method, path, timestamp, body hash), not with a user login. The key can do
     nothing except claim and complete probe jobs. A stale or altered request is refused.
  2. Everything in a result came from a host an attacker controls, so `clean_result` accepts only a fixed set of fields, with fixed types and
     caps, strips control characters, and drops anything else. Nothing a probed page says is ever trusted, executed, or stored raw.

Pure functions only."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import time

SKEW_SECONDS = 60
MAX_BODY_BYTES = 400_000            # largest request body the API will read from the worker
MAX_HTML_BYTES = 200_000            # a page's HTML, kept only long enough to extract features
MAX_ICON_BYTES = 65_536
MAX_CERT_BYTES = 12_288
MAX_CHAIN = 6
MAX_RENDER_BODY_BYTES = 2_200_000   # a render result carries a screenshot, so the result route allows more than a light probe
MAX_SCREENSHOT_BYTES = 1_000_000
MAX_RENDER_TEXT = 20_000
MAX_RENDER_FORMS = 20
MAX_FORM_INPUTS = 30
KINDS = ("light", "render")
_IMAGE_MAGIC = (b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n")        # JPEG and PNG signatures
_CTRL = re.compile(r"[\x00-\x1f\x7f]")      # every control character, newlines included: these fields end up in lines and headers


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def sign(key: str, method: str, path: str, timestamp: str, body: bytes) -> str:
    msg = "\n".join((timestamp, method.upper(), path, body_hash(body))).encode("utf-8")
    return hmac.new(key.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify(key: str, method: str, path: str, timestamp: str, body: bytes, signature: str, now: float | None = None) -> bool:
    """True only for a request signed with `key`, made within SKEW_SECONDS of now. An empty key never verifies (the worker API is off)."""
    if not key or not signature:
        return False
    try:
        ts = float(timestamp)
    except (TypeError, ValueError):
        return False
    if abs((time.time() if now is None else now) - ts) > SKEW_SECONDS:
        return False
    return hmac.compare_digest(sign(key, method, path, timestamp, body), signature)


def _text(v, n: int) -> str | None:
    if not isinstance(v, str):
        return None
    return _CTRL.sub("", v)[:n]


def _int(v, lo: int, hi: int) -> int | None:
    if isinstance(v, bool) or not isinstance(v, int):
        return None
    return v if lo <= v <= hi else None


def _b64(v, cap: int) -> str | None:
    """A base64 string that decodes to at most `cap` bytes, else None."""
    if not isinstance(v, str) or len(v) > cap * 4 // 3 + 8:
        return None
    try:
        raw = base64.b64decode(v, validate=True)
    except (binascii.Error, ValueError):
        return None
    return v if len(raw) <= cap else None


def _image_b64(v, cap: int) -> str | None:
    """A base64 JPEG or PNG within the cap. The bytes must start with an image signature: the API serves them back as an image, so
    anything else (HTML, script) is dropped here rather than trusted to the browser."""
    ok = _b64(v, cap)
    if ok is None:
        return None
    return ok if base64.b64decode(ok).startswith(_IMAGE_MAGIC) else None


def _flat(v, n: int) -> str | None:
    """Like _text but collapses runs of whitespace (page text is multi-line; the stored form is one tidy line of words)."""
    if not isinstance(v, str):
        return None
    t = _CTRL.sub(" ", v)                                   # newlines and tabs become spaces, other control characters too
    return " ".join(t.split())[:n]


def clean_render(raw) -> dict | None:
    """What the sandboxed renderer saw, restricted to fixed fields. None when there is nothing usable."""
    if not isinstance(raw, dict):
        return None
    forms = []
    for f in (raw.get("forms") or [])[:MAX_RENDER_FORMS] if isinstance(raw.get("forms"), list) else []:
        if not isinstance(f, dict):
            continue
        kinds = [_text(k, 20) for k in (f.get("inputs") or [])[:MAX_FORM_INPUTS]] if isinstance(f.get("inputs"), list) else []
        forms.append({"action": _text(f.get("action"), 500) or "", "method": (_text(f.get("method"), 10) or "get").lower(), "inputs": [k.lower() for k in kinds if k]})
    nav = []
    for hop in (raw.get("nav_chain") or [])[:MAX_CHAIN] if isinstance(raw.get("nav_chain"), list) else []:
        if isinstance(hop, dict) and _text(hop.get("url"), 500) is not None:
            nav.append({"url": _text(hop["url"], 500), "status": _int(hop.get("status"), 100, 599)})
    out = {
        "screenshot_b64": _image_b64(raw.get("screenshot_b64"), MAX_SCREENSHOT_BYTES),
        "title": _flat(raw.get("title"), 200), "text": _flat(raw.get("text"), MAX_RENDER_TEXT), "forms": forms, "nav_chain": nav,
        "final_url": _text(raw.get("final_url"), 500), "requests": _int(raw.get("requests"), 0, 10_000), "blocked": _int(raw.get("blocked"), 0, 10_000),
        "timed_out": bool(raw.get("timed_out")),
    }
    return out if (out["screenshot_b64"] or out["text"] or out["title"] or forms or nav) else None


def clean_result(raw) -> dict:
    """The only shape the API keeps. Unknown fields, wrong types and oversize values are dropped, never repaired."""
    if not isinstance(raw, dict):
        return {"ok": False, "error": "invalid result"}
    out: dict = {"ok": bool(raw.get("ok")), "error": _text(raw.get("error"), 200)}
    chain = []
    for hop in (raw.get("chain") or [])[:MAX_CHAIN] if isinstance(raw.get("chain"), list) else []:
        if isinstance(hop, dict) and _text(hop.get("url"), 500) is not None:
            chain.append({"url": _text(hop["url"], 500), "status": _int(hop.get("status"), 100, 599)})
    out["chain"] = chain
    out["final_status"] = _int(raw.get("final_status"), 100, 599)
    out["content_type"] = _text(raw.get("content_type"), 100)
    out["truncated"] = bool(raw.get("truncated"))
    html = raw.get("html")
    out["html"] = html[:MAX_HTML_BYTES] if isinstance(html, str) else None
    out["favicon_b64"] = _b64(raw.get("favicon_b64"), MAX_ICON_BYTES)
    out["cert_der_b64"] = _b64(raw.get("cert_der_b64"), MAX_CERT_BYTES)
    out["tls_error"] = _text(raw.get("tls_error"), 100)
    out["elapsed_ms"] = _int(raw.get("elapsed_ms"), 0, 600_000)
    out["render"] = clean_render(raw.get("render"))
    return out
