"""What the sandboxed renderer's browser is allowed to request (plan step 7.3). Pure, so it is tested without a browser.

The container's firewall is the hard control; this is the second layer, applied to EVERY request the page makes (the page, its scripts, images,
fonts, frames and every redirect hop), because a hostile page decides what to ask for:

  - read only: GET (and HEAD). A POST, PUT or DELETE is refused, so a form can never be submitted even if a script tries;
  - http and https only, on the default ports only (no probing of internal services on 6379, 9200, 2375 ...);
  - the host must be a name or a PUBLIC address; literal private, loopback, link-local and reserved addresses are refused here, and names are
    resolved and checked by the caller before the request is let through;
  - a ceiling on how many requests one page may make.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

MAX_REQUESTS = 200   # a real WordPress home page made ~140 (60 left the picture blank: styles and images never arrived)
ALLOWED_METHODS = ("GET", "HEAD")
_PORTS = {"http": 80, "https": 443}
_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9._-]*[a-z0-9])?$", re.I)


def is_public_literal(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return True                       # not a literal address: a name, resolved and checked by the caller
    return ip.is_global and not ip.is_multicast


def allow_request(method: str, url: str, count: int = 0) -> tuple[bool, str]:
    """(allowed, reason). `count` is how many requests the page has already made."""
    if count >= MAX_REQUESTS:
        return False, "request limit"
    if method.upper() not in ALLOWED_METHODS:
        return False, "method not allowed"
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError:
        return False, "bad url"
    if u.scheme not in _PORTS:
        return False, "scheme not allowed"
    if port is not None and port != _PORTS[u.scheme]:
        return False, "port not allowed"
    host = (u.hostname or "").lower()
    if not host or u.username or u.password:
        return False, "bad host"
    if not is_public_literal(host):
        return False, "address not public"
    if not _HOST_RE.match(host) and not _is_literal(host):
        return False, "bad host"
    return True, ""


def _is_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False
