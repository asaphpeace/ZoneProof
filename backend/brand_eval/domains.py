"""
Literal domain parsing and stratum rules for the evaluation corpus.

Everything here is intentionally simple and independent of the detector
(`app.services.brand_discovery_service` / `brand_scoring_service`): strata are
facts about the string ("the brand name appears in the subdomain"), not
judgements made with the detector's own homoglyph tables, so measuring the
detector against them is not circular.

The public-suffix handling is a small heuristic, not the full PSL (which would
need a network fetch): common ccTLD second levels, plus a list of free-hosting
platforms treated as *private suffixes* — `brand.pages.dev` is a subdomain of a
platform, not a domain the attacker registered, and that distinction is itself
an evaluation stratum.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from app.services.brand_discovery_service import edit_distance  # standard algorithm only

_CC_SECOND_LEVELS = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil", "nom", "sch", "web"}

# Platforms where anyone can publish under <name>.<suffix>.
FREE_HOSTING_SUFFIXES = (
    "pages.dev", "workers.dev", "github.io", "gitlab.io", "netlify.app", "vercel.app", "web.app",
    "firebaseapp.com", "blogspot.com", "weebly.com", "wixsite.com", "herokuapp.com", "glitch.me",
    "repl.co", "onrender.com", "azurewebsites.net", "000webhostapp.com", "myshopify.com",
    "webflow.io", "framer.app", "carrd.co", "godaddysites.com", "square.site", "ngrok.io",
    "trycloudflare.com", "duckdns.org", "hopto.org", "serveo.net", "r2.dev", "cloudfront.net",
    "s3.amazonaws.com", "storage.googleapis.com", "sites.google.com", "notion.site", "vercel.dev",
)

_NORM_RE = re.compile(r"[^a-z0-9]")


@dataclass(frozen=True)
class HostParts:
    host: str
    subdomain: str          # dotted labels left of the registrable name ("" if none)
    registrable: str        # e.g. "brand.co.za", or "sub.pages.dev" for free hosting
    label: str              # the registrable's first label, e.g. "brand"
    suffix: str             # e.g. "co.za", "pages.dev"
    free_hosting: bool
    is_ip: bool
    is_idn: bool            # punycode or non-ASCII anywhere in the host


def norm(text: str) -> str:
    """Lowercase, alphanumerics only — used for literal 'contains the brand' tests."""
    return _NORM_RE.sub("", (text or "").lower())


def split_host(host: str) -> HostParts:
    host = (host or "").strip().lower().rstrip(".")
    host = host.split("/")[0].split(":")[0] if "/" in host or ":" in host else host
    try:
        ipaddress.ip_address(host)
        return HostParts(host, "", host, host, "", False, True, False)
    except ValueError:
        pass

    labels = [x for x in host.split(".") if x]
    is_idn = any(x.startswith("xn--") for x in labels) or any(ord(c) > 127 for c in host)
    if len(labels) < 2:
        return HostParts(host, "", host, host, "", False, False, is_idn)

    for suffix in FREE_HOSTING_SUFFIXES:
        parts = suffix.split(".")
        if len(labels) > len(parts) and labels[-len(parts):] == parts:
            reg_labels = labels[-(len(parts) + 1):]
            return HostParts(host, ".".join(labels[:-(len(parts) + 1)]), ".".join(reg_labels), reg_labels[0], suffix, True, False, is_idn)

    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _CC_SECOND_LEVELS:
        suffix, reg = ".".join(labels[-2:]), ".".join(labels[-3:])
        return HostParts(host, ".".join(labels[:-3]), reg, labels[-3], suffix, False, False, is_idn)

    return HostParts(host, ".".join(labels[:-2]), ".".join(labels[-2:]), labels[-2], labels[-1], False, False, is_idn)


def classify_technique(parts: HostParts, slug: str, brand_domain: str, url_path: str = "") -> str:
    """Literal technique stratum for a phish that targets brand `slug` (whose real
    domain is `brand_domain`). First match wins.

    brand_domain_clone   — registrable domain IS the brand's (compromised/hosted abuse)
    tld_swap             — same name, different suffix
    brand_in_domain      — brand name inside the registrable label (combosquat/concatenation)
    idn                  — punycode/non-ASCII host, brand not literally present
    near_miss            — label within edit distance 2 of the brand, brand not literally present
    brand_in_subdomain   — brand only in subdomain (incl. free-hosting subdomains)
    brand_in_path        — brand only in the URL path
    no_visible_brand     — nothing in the host or path reveals the brand
    """
    slug_n = norm(slug)
    label_n = norm(parts.label)
    brand_parts = split_host(brand_domain)

    if parts.registrable == brand_parts.registrable:
        return "brand_domain_clone"
    if label_n and label_n == norm(brand_parts.label) and parts.suffix != brand_parts.suffix:
        return "tld_swap"
    if slug_n and slug_n in label_n:
        return "brand_in_domain"
    if parts.is_idn:
        return "idn"
    if len(slug_n) >= 5 and label_n and edit_distance(label_n, norm(brand_parts.label) or slug_n) <= 2:
        return "near_miss"
    if slug_n and slug_n in norm(parts.subdomain):
        return "brand_in_subdomain"
    if slug_n and slug_n in norm(url_path):
        return "brand_in_path"
    return "no_visible_brand"


# Techniques a name-only detector can in principle see from the registrable
# domain alone. Used to report recall per stratum, never as one headline figure.
NAME_DETECTABLE = {"tld_swap", "brand_in_domain", "idn", "near_miss"}
