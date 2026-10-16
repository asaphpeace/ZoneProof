"""
Brand Guard — brand fingerprint (plan step 2.0): the identity anchors of the customer's REAL brand, built from their
own public site and DNS, so everything else can be judged against "what the real thing looks like".

Built from (all of it public, all of it the customer's own):
  * the homepage: title, description, site name, language, favicon (hash), social profile links, contact emails/phones;
  * DNS: nameservers, addresses, mail exchangers (-> mail provider), network owner of the address (-> ASN).

Used for: the "what we monitor" screen (editable), benign explainers ("same nameservers as you" lowers a candidate's
abuse score), and later stages (logo/favicon matching, infrastructure divergence). The fetch is SSRF-guarded
(safe_fetch.py). Everything here that can fail is non-fatal: a fingerprint is whatever could be learned, plus the
reasons the rest could not be.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
from datetime import datetime, timezone
from html import unescape
from urllib.parse import urljoin, urlsplit

from app.services import brand_baseline as baseline
from app.services import brand_mail_intent
from app.services import brand_similarity
from app.services import safe_fetch

FINGERPRINT_VERSION = 1
_MAX_TEXT = 300
_MAX_FAVICON_BYTES = 200_000
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg")

_SOCIAL = (
    ("facebook", ("facebook.com", "fb.com")), ("instagram", ("instagram.com",)), ("linkedin", ("linkedin.com",)),
    ("x", ("twitter.com", "x.com")), ("youtube", ("youtube.com", "youtu.be")), ("tiktok", ("tiktok.com",)),
    ("whatsapp", ("wa.me", "whatsapp.com")), ("telegram", ("t.me",)), ("github", ("github.com",)),
)


def _clip(text: str | None, n: int = _MAX_TEXT) -> str | None:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text[:n] if text else None


_MAX_HTML_CHARS = 300_000     # only the start of a page matters for a fingerprint; also bounds every loop below
_MAX_TAG_CHARS = 4_000        # a tag longer than this is not a tag
_MAX_TEXT_CHARS = 60_000
_ATTR_RE = re.compile(r"""([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?""")
_RAW_TEXT_TAGS = ("script", "style", "noscript")


class _Page:
    """What a fingerprint needs from one HTML page, found by a small LINEAR scanner.

    Python's html.parser was tried first and rejected: 16 KB of `<a href=` repeated took 1.8 s and the cost grows
    faster than the input, so a hostile page could stall a worker. Every loop here is bounded — the input is cut to
    _MAX_HTML_CHARS, a tag is looked for within _MAX_TAG_CHARS, and attribute matching runs only inside one tag."""

    def __init__(self, html: str) -> None:
        self.title = ""
        self.meta: dict[str, str] = {}
        self.icons: list[tuple[str, str]] = []      # (rel, href)
        self.links: list[str] = []
        self.lang: str | None = None
        text: list[str] = []
        text_len = 0

        html = html[:_MAX_HTML_CHARS]
        n, i = len(html), 0
        while i < n:
            lt = html.find("<", i)
            if lt == -1:
                if text_len < _MAX_TEXT_CHARS:
                    text.append(html[i:i + _MAX_TEXT_CHARS - text_len])
                break
            if lt > i and text_len < _MAX_TEXT_CHARS:
                chunk = html[i:lt][: _MAX_TEXT_CHARS - text_len]
                text.append(chunk)
                text_len += len(chunk)
            gt = html.find(">", lt, lt + _MAX_TAG_CHARS)
            if gt == -1:
                i = lt + 1                     # not a tag after all; carry on past the "<"
                continue
            body = html[lt + 1:gt]
            i = gt + 1
            if not body or not (body[0].isalpha() or body[0] == "/"):
                continue
            closing = body[0] == "/"
            name_end = 1 if closing else 0
            while name_end < len(body) and (body[name_end].isalnum()):
                name_end += 1
            tag = body[1 if closing else 0:name_end].lower()
            if closing:
                continue
            attrs = {}
            for m in _ATTR_RE.finditer(body[name_end:]):
                key = m.group(1).lower()
                if key not in attrs:
                    attrs[key] = unescape(m.group(2) if m.group(2) is not None else m.group(3) if m.group(3) is not None else m.group(4) or "")
            if tag == "html" and attrs.get("lang"):
                self.lang = attrs["lang"][:20]
            elif tag == "title" and not self.title:
                end = html.find("</", i, i + 2_000)
                self.title = unescape(html[i:end if end != -1 else i + 2_000])
                i = end if end != -1 else i + 2_000
            elif tag == "meta":
                key = (attrs.get("name") or attrs.get("property") or "").lower()
                if key and "content" in attrs and key not in self.meta:
                    self.meta[key] = attrs["content"]
            elif tag == "link" and "href" in attrs and "icon" in attrs.get("rel", "").lower():
                self.icons.append((attrs["rel"].lower(), attrs["href"]))
            elif tag == "a" and attrs.get("href") and len(self.links) < 400:
                self.links.append(attrs["href"].strip())
            elif tag in _RAW_TEXT_TAGS:
                end = html.find("</" + tag, i)           # skip the element's contents (code, not words)
                i = end if end != -1 else n
        self.text = text


def visible_text(html: str | None) -> str:
    """The words of an HTML page (scripts and styles skipped), through the same bounded linear scanner. Never raises."""
    try:
        return " ".join(_Page(html or "").text)
    except Exception:
        return ""


def parse_page(html: str, base_url: str) -> dict:
    """Pure: the fingerprint's `site` facts from an HTML document."""
    try:
        page = _Page(html)
    except Exception:       # a hostile page must never break onboarding
        page = _Page("")

    social: list[dict] = []
    emails: list[str] = []
    phones: list[str] = []
    for href in page.links:
        low = href.lower()
        if low.startswith("mailto:"):
            addr = href[7:].split("?")[0].strip()
            if len(addr) <= 254 and _EMAIL_RE.fullmatch(addr) and addr.lower() not in emails:
                emails.append(addr.lower())
            continue
        if low.startswith("tel:"):
            number = re.sub(r"[^\d+]", "", href[4:])
            if 7 <= len(number) <= 16 and number not in phones:
                phones.append(number)
            continue
        host = (urlsplit(urljoin(base_url, href)).hostname or "").lower()
        for network, domains in _SOCIAL:
            if any(host == d or host.endswith("." + d) for d in domains):
                url = urljoin(base_url, href).split("#")[0].split("?")[0][:200]
                if not any(s["url"] == url for s in social):
                    social.append({"network": network, "url": url})
                break
    # Emails in the visible text. Only short whitespace-separated tokens that contain an "@" are examined: running the
    # pattern over the whole text is quadratic on a long run of address-like characters (a 300 KB run took 15 s).
    for token in " ".join(page.text).split():
        if "@" not in token or len(token) > 254 or len(emails) >= 10:
            continue
        for match in _EMAIL_RE.findall(token):
            low = match.lower()
            if low not in emails and not low.endswith(_IMAGE_SUFFIXES):
                emails.append(low)

    icon_href = None
    for rel, href in sorted(page.icons, key=lambda x: ("apple" in x[0], "shortcut" not in x[0])):
        icon_href = href
        break
    return {
        "title": _clip(page.title),
        "description": _clip(page.meta.get("description") or page.meta.get("og:description")),
        "site_name": _clip(page.meta.get("og:site_name") or page.meta.get("application-name"), 120),
        "lang": page.lang,
        "icon_href": urljoin(base_url, icon_href) if icon_href else None,
        "social": social[:12],
        "emails": emails[:10],
        "phones": phones[:5],
    }


async def _fetch_site(domain: str, fetch, errors: list[str]) -> tuple[dict | None, str | None]:
    """The homepage as (parsed facts, final URL). https first; plain http only when https is unavailable."""
    last = None
    for scheme in ("https", "http"):
        try:
            res = await fetch(f"{scheme}://{domain}/")
        except Exception as e:          # a fingerprint is best-effort: nothing here may break onboarding
            last = str(e) if isinstance(e, safe_fetch.FetchError) else "an unexpected error occurred"
            continue
        if res.status >= 400:
            last = f"the site answered HTTP {res.status}"
            continue
        if res.content_type and "html" not in res.content_type:
            last = "the homepage is not an HTML page"
            continue
        html = res.body.decode("utf-8", errors="replace")
        site = parse_page(html, res.url)
        site.update({"url": res.url, "status": res.status})
        try:
            site["_wording"] = brand_similarity.shingles(visible_text(html))     # moved into fingerprint["similarity"] by build_fingerprint
        except Exception:
            site["_wording"] = []
        return site, res.url
    errors.append(f"Could not read the website: {last or 'unknown error'}.")
    return None, None


async def _favicon(site: dict, domain: str, fetch, errors: list[str]) -> dict | None:
    candidates = [site.get("icon_href"), f"https://{domain}/favicon.ico"]
    for url in [c for c in candidates if c]:
        try:
            res = await fetch(url, max_bytes=_MAX_FAVICON_BYTES, accept="image/*,*/*;q=0.5")
        except Exception:
            continue
        if res.status < 400 and res.body and not res.truncated and not res.content_type.startswith("text/html"):
            return {"url": res.url, "sha256": hashlib.sha256(res.body).hexdigest(), "bytes": len(res.body), "content_type": res.content_type,
                    "dhash": brand_similarity.dhash(res.body, 8)}       # perceptual hash: finds re-sized or re-encoded copies of the icon
    errors.append("No favicon could be read.")
    return None


def _parse_cymru(values: list[str]) -> list[str]:
    return [p.strip() for p in (values[0].strip('"') if values else "").split("|")]


async def _network_owner(address: str, query) -> dict | None:
    """ASN number and name for an IPv4 address through Team Cymru's DNS service (an ordinary TXT lookup)."""
    if ":" in address or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", address):
        return None
    rev = ".".join(reversed(address.split(".")))
    state, values = await query(f"{rev}.origin.asn.cymru.com", "TXT")
    if state != "answer" or not values:
        return None
    asn = _parse_cymru(values)[0].split()[0] if values else None
    if not asn or not asn.isdigit():
        return None
    state, names = await query(f"AS{asn}.asn.cymru.com", "TXT")
    name = _parse_cymru(names)[-1] if state == "answer" and names else None
    return {"number": int(asn), "name": (name or "")[:120] or None}


network_owner = _network_owner       # public alias: Brand Guard also asks who owns a candidate's server address


async def _dns_baseline(domain: str, query, errors: list[str]) -> dict:
    (ns_state, ns), (a_state, a), (mx_state, mx) = await asyncio.gather(query(domain, "NS"), query(domain, "A"), query(domain, "MX"))
    if "error" in (ns_state, a_state, mx_state):
        errors.append("Some DNS lookups for your domain failed; the DNS baseline may be incomplete.")
    ns = [n.rstrip(".") for n in ns] if ns_state == "answer" else []
    a = a if a_state == "answer" else []
    mx_hosts = [m.split()[-1].rstrip(".").lower() for m in mx] if mx_state == "answer" else []
    owner = None
    if a:
        try:
            owner = await _network_owner(a[0], query)
        except Exception:
            owner = None
    provider = baseline.mail_provider(mx_hosts)
    try:
        mail_auth = await brand_mail_intent.probe_mail(domain, query, mx_hosts=mx_hosts, mail_provider=provider, always_dkim=True)
    except Exception:
        mail_auth = None
        errors.append("Your mail authentication records (SPF, DKIM, DMARC) could not be read.")
    return {
        "ns": sorted(ns), "a": sorted(a), "mx": sorted(mx_hosts), "mail_provider": provider, "mail_auth": mail_auth,
        "asn": owner, "shared_hosting": baseline.is_shared_hosting((owner or {}).get("name")),
        "shared_nameservers": baseline.is_shared_nameservers(ns),
    }


async def build_fingerprint(domain: str, *, fetch=None, query=None) -> dict:
    """Never raises: returns whatever could be learned, plus `errors` naming what could not be."""
    if query is None:
        from app.services.brand_guard_service import _query as query      # the throttled resolver the scans use
    fetch = fetch or safe_fetch.fetch
    errors: list[str] = []
    site, _ = await _fetch_site(domain, fetch, errors)
    if site is not None:
        site["favicon"] = await _favicon(site, domain, fetch, errors)
        site.pop("icon_href", None)
    dns = await _dns_baseline(domain, query, errors)
    wording = (site or {}).pop("_wording", None) or []
    # What a look-alike's page is compared against (step 7.4). Kept apart from `site` and not shown in the "what we monitor" screen.
    similarity = {"icon_dhash": ((site or {}).get("favicon") or {}).get("dhash"), "wording": wording, "wording_n": len(wording)}
    return {
        "version": FINGERPRINT_VERSION, "built_at": datetime.now(timezone.utc).isoformat(), "domain": domain,
        "site": site, "dns": dns, "similarity": similarity, "errors": errors,
    }
