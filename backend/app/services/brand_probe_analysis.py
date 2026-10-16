"""Turning a light probe's raw result into facts and evidence lines (plan step 7.2).

Pure. The input is a result that `brand_probe_protocol.clean_result` already restricted to known fields; the page HTML in it was fetched from a
host an attacker controls, so it is only ever PARSED here (never rendered, never executed), and nothing from it is kept except the small
features extracted below. The raw HTML is dropped by the caller after this runs.

Weights are EXPERT-SET ASSUMPTIONS: nobody has measured how well page features separate look-alikes that are used for abuse from ordinary
ones. They are labelled as such and are deliberately modest. A page that hides from scanners (a challenge page, a block) is reported as "may
differ for real visitors", never as clean."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from app.services import brand_similarity
from app.services.brand_discovery_service import registrable_domain

W_PASSWORD_FORM = 10.0
W_OFFSITE_FORM = 10.0
W_BRAND_NAMED_PASSWORD = 8.0
W_FAVICON_COPY = 12.0
W_CERT_ODD = 5.0
W_REDIRECT_TO_BRAND = -12.0
W_ICON_LOOKALIKE = 8.0        # near copy of the brand's icon (less than the byte-exact copy's 12)
W_WORDING_COPY = 10.0         # a large share of the page's wording is on the brand's own page
W_WORDING_STRONG = 14.0
# (a screenshot that looks like the brand's page carries NO weight: layout similarity cannot tell a clone from a common template; see brand_similarity.py)
CHALLENGE_STATUSES = (401, 403, 429, 503)
CHALLENGE_MARKERS = ("just a moment", "cf-chl", "captcha", "attention required", "access denied", "checking your browser")
MAX_FORMS = 20


class _Forms(HTMLParser):
    """Collects forms and their inputs. Tolerant of broken markup; never raises on hostile input (the caller also guards it)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self._open: dict | None = None
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "form" and len(self.forms) < MAX_FORMS:
            self._open = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "password": 0, "text": 0, "email": 0}
            self.forms.append(self._open)
        elif tag == "input" and self._open is not None:
            kind = (a.get("type") or "text").lower()
            if kind == "password":
                self._open["password"] += 1
            elif kind == "email":
                self._open["email"] += 1
            elif kind in ("text", "tel", ""):
                self._open["text"] += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._open = None

    def handle_data(self, data):
        if self._in_title and len(self.title) < 300:
            self.title += data


def parse_forms(html: str, page_url: str) -> dict:
    p = _Forms()
    try:
        p.feed(html or "")
        p.close()
    except Exception:
        pass                                          # a hostile page must never break analysis
    page_domain = registrable_domain(urlsplit(page_url).hostname or "")
    forms = []
    for f in p.forms:
        target = urljoin(page_url, f["action"]) if f["action"] else page_url
        host = (urlsplit(target).hostname or "").lower()
        forms.append({"action_host": host, "offsite": bool(host) and registrable_domain(host) != page_domain, "method": f["method"],
                      "password": f["password"] > 0, "fields": f["password"] + f["text"] + f["email"]})
    return {"title": " ".join(p.title.split())[:200] or None, "forms": forms}


def parse_certificate(der_b64: str | None, host: str, ct_issued_at: str | None = None, now: datetime | None = None) -> dict | None:
    """Facts about the certificate the host served. None when there is none. Never raises."""
    if not der_b64:
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        der = base64.b64decode(der_b64)
        cert = x509.load_der_x509_certificate(der)
        try:
            sans = [str(n) for n in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)]
        except x509.ExtensionNotFound:
            sans = []
        cn = next((a.value for a in cert.subject if a.oid == x509.NameOID.COMMON_NAME), None)
        issuer = next((a.value for a in cert.issuer if a.oid == x509.NameOID.ORGANIZATION_NAME), None) or next((a.value for a in cert.issuer if a.oid == x509.NameOID.COMMON_NAME), None)
        not_before = cert.not_valid_before_utc
        names = sans or ([cn] if cn else [])
        now = now or datetime.now(timezone.utc)
        matches_ct = None
        if ct_issued_at:
            try:
                ct = datetime.fromisoformat(str(ct_issued_at).replace("Z", "+00:00"))
                ct = ct if ct.tzinfo else ct.replace(tzinfo=timezone.utc)
                matches_ct = abs((not_before - ct).total_seconds()) <= 3 * 86400
            except ValueError:
                matches_ct = None
        return {
            "sha256": hashlib.sha256(der).hexdigest(), "subject_cn": str(cn)[:200] if cn else None, "names": [str(n)[:200] for n in names[:20]], "issuer": str(issuer)[:200] if issuer else None,
            "not_before": not_before.isoformat(), "not_after": cert.not_valid_after_utc.isoformat(), "age_days": max(0, (now - not_before).days),
            "self_signed": cert.issuer == cert.subject, "valid_for_host": _name_matches(host, names), "expired": cert.not_valid_after_utc < now, "matches_ct": matches_ct,
        }
    except Exception:
        return None


def _name_matches(host: str, names: list[str]) -> bool:
    host = host.lower()
    for n in names:
        n = str(n).lower()
        if n == host or (n.startswith("*.") and host.split(".", 1)[-1] == n[2:] and host.count(".") == n.count(".")):
            return True
    return False


def _similarity_light(result: dict, brand_ref: dict | None) -> tuple[dict, str | None]:
    """Icon and wording similarity of a light probe against the brand's stored reference. Returns ({icon?, wording?}, the icon's own hash)."""
    out: dict = {}
    ref = brand_ref or {}
    icon_hash = None
    if result.get("favicon_b64"):
        try:
            icon_hash = brand_similarity.dhash(base64.b64decode(result["favicon_b64"]), 8)
        except Exception:
            icon_hash = None
    icon = brand_similarity.compare_hashes(ref.get("icon_dhash"), icon_hash, brand_similarity.ICON_NEAR)
    if icon:
        out["icon"] = icon
    if result.get("html") and ref.get("wording"):
        from app.services.brand_fingerprint_service import visible_text
        w = brand_similarity.wording_overlap(visible_text(result["html"][:200_000]), ref["wording"])
        if w:
            out["wording"] = w
    return out, icon_hash


def analyse(result: dict, *, host: str, official_domains: list[str], brand_words: list[str], brand_favicon_sha256: str | None, ct_issued_at: str | None = None, brand_ref: dict | None = None) -> dict:
    """Facts only (no weights): what the probe saw, in the small form that is stored on the candidate. `brand_ref` is the brand's stored comparison
    data (icon hash, hashed wording); without it no similarity is computed."""
    chain = result.get("chain") or []
    final_url = chain[-1]["url"] if chain else f"http://{host}/"
    final_host = (urlsplit(final_url).hostname or host).lower()
    official = {registrable_domain(d) for d in official_domains}
    page = parse_forms(result.get("html") or "", final_url) if result.get("html") else {"title": None, "forms": []}
    html_low = (result.get("html") or "")[:20000].lower()
    fav = None
    if result.get("favicon_b64"):
        try:
            fav = hashlib.sha256(base64.b64decode(result["favicon_b64"])).hexdigest()
        except Exception:
            fav = None
    title_low = (page["title"] or "").lower()
    named = any(w and w in title_low for w in brand_words)
    status = result.get("final_status")
    challenge = status in CHALLENGE_STATUSES or any(m in html_low for m in CHALLENGE_MARKERS)
    similarity, icon_hash = _similarity_light(result, brand_ref)
    return {
        "similarity": similarity, "favicon_dhash": icon_hash,
        "reachable": bool(result.get("ok") and status),
        "final_status": status, "chain": [{"url": h["url"], "status": h["status"]} for h in chain],
        "final_host": final_host, "redirects": len(chain) > 1, "crosses_domain": registrable_domain(final_host) != registrable_domain(host),
        "redirects_to_brand": registrable_domain(final_host) in official and registrable_domain(host) not in official,
        "title": page["title"], "brand_in_title": named, "forms": page["forms"][:MAX_FORMS],
        "password_form": any(f["password"] for f in page["forms"]), "offsite_password_form": any(f["password"] and f["offsite"] for f in page["forms"]),
        "favicon_sha256": fav, "favicon_matches_brand": bool(fav and brand_favicon_sha256 and fav == brand_favicon_sha256),
        "certificate": parse_certificate(result.get("cert_der_b64"), host, ct_issued_at), "tls_error": result.get("tls_error"),
        "challenge_page": bool(challenge), "truncated": bool(result.get("truncated")), "error": result.get("error"),
    }


def _similarity_render(render: dict, layout: str | None, palette: str | None, brand_ref: dict | None) -> dict:
    ref = brand_ref or {}
    out: dict = {}
    w = brand_similarity.wording_overlap(render.get("text"), ref.get("wording"))
    if w:
        out["wording"] = w
    vis = brand_similarity.compare_pages(ref.get("layout"), ref.get("palette"), layout, palette)
    if vis:
        out["visual"] = vis
    return out


def recompare_visual(rendered: dict | None, brand_ref: dict | None) -> dict | None:
    """A rendered look's visual comparison redone against a new reference screenshot (the layout hash and palette were stored with it)."""
    if not rendered:
        return rendered
    out = dict(rendered)
    sim = dict(out.get("similarity") or {})
    sim.pop("visual", None)
    ref = brand_ref or {}
    vis = brand_similarity.compare_pages(ref.get("layout"), ref.get("palette"), out.get("layout"), out.get("palette"))
    if vis:
        sim["visual"] = vis
    out["similarity"] = sim
    return out


def analyse_render(render: dict | None, *, host: str, official_domains: list[str], brand_words: list[str], brand_ref: dict | None = None) -> dict | None:
    """Facts from what the sandboxed renderer saw after the page's scripts ran. The forms come from the rendered page (not the raw HTML), so a
    login form that a script builds is seen. The page text and screenshot are NOT part of these facts: they go to encrypted, time-limited storage."""
    if not render:
        return None
    final_url = render.get("final_url") or ((render.get("nav_chain") or [{}])[-1].get("url")) or f"http://{host}/"
    final_host = (urlsplit(final_url).hostname or host).lower()
    page_domain = registrable_domain(final_host)
    forms = []
    for f in (render.get("forms") or [])[:MAX_FORMS]:
        target = urljoin(final_url, f.get("action") or "") if f.get("action") else final_url
        h = (urlsplit(target).hostname or "").lower()
        kinds = f.get("inputs") or []
        forms.append({"action_host": h, "offsite": bool(h) and registrable_domain(h) != page_domain, "method": f.get("method") or "get",
                      "password": "password" in kinds, "fields": sum(1 for k in kinds if k in ("password", "text", "email", "tel", ""))})
    title_low = (render.get("title") or "").lower()
    text_low = (render.get("text") or "").lower()
    layout = palette = None
    blank = False
    if render.get("screenshot_b64"):
        try:
            raw = base64.b64decode(render["screenshot_b64"])
            blank = brand_similarity.is_blank(raw) is True
            layout, palette = (None, None) if blank else (brand_similarity.dhash(raw, 16), brand_similarity.palette(raw))
        except Exception:
            layout = palette = None
    return {
        "layout": layout, "palette": palette, "similarity": _similarity_render(render, layout, palette, brand_ref),
        "final_host": final_host, "title": render.get("title"), "forms": forms,
        "brand_in_title": any(w and w in title_low for w in brand_words), "brand_in_text": any(w and w in text_low for w in brand_words),
        "password_form": any(f["password"] for f in forms), "offsite_password_form": any(f["password"] and f["offsite"] for f in forms),
        "has_screenshot": bool(render.get("screenshot_b64")) and not blank, "blank": blank, "requests": render.get("requests"), "blocked": render.get("blocked"), "timed_out": bool(render.get("timed_out")),
    }


def merge_render(facts: dict | None, rendered: dict | None) -> dict:
    """The light probe's facts with the rendered page's added: a form seen only after scripts ran is marked, and a form either view saw counts."""
    out = dict(facts or {})
    if not rendered:
        return out
    out["rendered"] = rendered
    sim = dict(out.get("similarity") or {})
    rsim = rendered.get("similarity") or {}
    for key in ("wording",):                                               # the better of what the plain page and the rendered page shared
        if rsim.get(key) and (not sim.get(key) or rsim[key]["shared"] > sim[key]["shared"]):
            sim[key] = rsim[key]
    if rsim.get("visual"):
        sim["visual"] = rsim["visual"]
    else:
        sim.pop("visual", None)
    out["similarity"] = sim
    out["form_after_scripts"] = bool(rendered["password_form"] and not out.get("password_form"))
    out["password_form"] = bool(out.get("password_form") or rendered["password_form"])
    out["offsite_password_form"] = bool(out.get("offsite_password_form") or rendered["offsite_password_form"])
    out["brand_in_title"] = bool(out.get("brand_in_title") or rendered["brand_in_title"])
    if not out.get("forms"):
        out["forms"] = rendered["forms"]
    return out


def signals(a: dict | None) -> list[dict]:
    """Evidence lines from analysed facts. Each: {signal, dimension, weight, summary, data}. All weights are assumptions."""
    if not a or not a.get("reachable"):
        return []
    out: list[dict] = []
    if a.get("redirects_to_brand"):
        out.append({"signal": "page_redirects_to_brand", "dimension": "abuse", "weight": W_REDIRECT_TO_BRAND,
                    "summary": f"It sends visitors to the brand's own site ({a['final_host']}), which is what a defensive registration does.", "data": {"final_host": a["final_host"]}})
        return out                                    # a redirect to the real site explains the rest away
    if a.get("password_form"):
        w = W_PASSWORD_FORM + (W_OFFSITE_FORM if a.get("offsite_password_form") else 0) + (W_BRAND_NAMED_PASSWORD if a.get("brand_in_title") else 0)
        bits = ["asks for a password"] + (["and sends it to a different site"] if a.get("offsite_password_form") else []) + (["on a page titled with the brand's name"] if a.get("brand_in_title") else [])
        out.append({"signal": "page_password_form", "dimension": "abuse", "weight": w, "summary": "The page " + " ".join(bits) + ".",
                    "data": {"offsite": a.get("offsite_password_form"), "brand_in_title": a.get("brand_in_title"), "forms": a.get("forms")}})
    if a.get("form_after_scripts"):
        out.append({"signal": "page_form_after_scripts", "dimension": "abuse", "weight": 0.0,
                    "summary": "The password form only appears after the page's scripts run, which a plain page fetch does not show.", "data": {"forms": (a.get("rendered") or {}).get("forms")}})
    if a.get("favicon_matches_brand"):
        out.append({"signal": "page_brand_favicon", "dimension": "abuse", "weight": W_FAVICON_COPY, "summary": "It uses the brand's own icon, byte for byte.", "data": {"sha256": a.get("favicon_sha256")}})
    sim = a.get("similarity") or {}
    icon = sim.get("icon")
    if icon and icon["similar"] and not a.get("favicon_matches_brand"):
        out.append({"signal": "page_icon_lookalike", "dimension": "abuse", "weight": W_ICON_LOOKALIKE,
                    "summary": "Its icon is a near copy of the brand's (re-sized or re-encoded, so not byte for byte).", "data": icon})
    wording = sim.get("wording")
    if wording and wording["shared"] >= brand_similarity.WORDING_COPY:
        pct = round(wording["shared"] * 100)
        out.append({"signal": "page_copies_wording", "dimension": "abuse", "weight": W_WORDING_STRONG if wording["shared"] >= brand_similarity.WORDING_STRONG else W_WORDING_COPY,
                    "summary": f"{pct}% of the wording on its page also appears on the brand's own page.", "data": wording})
    visual = sim.get("visual")
    if visual and visual["similar"]:
        out.append({"signal": "page_looks_like_brand", "dimension": "abuse", "weight": 0.0,
                    "summary": "Its page has the same layout and accent colours as the brand's own page. Shown for you to compare, but not scored: a shared layout alone cannot tell a copy from a common template.", "data": visual})
    cert = a.get("certificate")
    if cert and (cert.get("self_signed") or cert.get("expired") or cert.get("valid_for_host") is False):
        why = "self-signed" if cert.get("self_signed") else "expired" if cert.get("expired") else "not issued for this name"
        out.append({"signal": "page_certificate_odd", "dimension": "abuse", "weight": W_CERT_ODD, "summary": f"The certificate it serves is {why}.", "data": {"self_signed": cert.get("self_signed"), "expired": cert.get("expired"), "valid_for_host": cert.get("valid_for_host")}})
    if a.get("challenge_page"):
        out.append({"signal": "page_may_differ", "dimension": "abuse", "weight": 0.0,
                    "summary": "The host answered with a block or a challenge page, so the page real visitors see may differ from what we saw.", "data": {"status": a.get("final_status")}})
    return out
