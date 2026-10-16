"""
Public Suffix List lookup (plan step 2.0b).

Brand Guard has to know where the registrable part of a hostname starts. Treating only
`.za` second levels specially (the old behaviour) made `facebook.com.br` parse as the
registrable domain `com.br`, `brand.co.uk` as `co.uk`, and `login.brand.pages.dev` as
the hosting platform `pages.dev` — so lookalikes under those suffixes were invisible, and a
customer whose own domain was `brand.com.au` had permutations generated from the label "com".

This module implements the Public Suffix List algorithm (https://publicsuffix.org/list/)
against the vendored, unmodified list in app/data/public_suffix_list.dat (see its manifest
for the retrieval date and checksum; the list is MPL-2.0). Both sections are used:

  ICANN    country and generic suffixes (co.uk, com.br, kobe.jp, ...)
  PRIVATE  platforms where anyone can publish under <name>.<suffix> (pages.dev, github.io,
           blogspot.com, ...). For brand protection the attacker-chosen label is the
           subdomain, so these are treated as suffixes and the result is flagged `private`.

Algorithm (per the PSL spec): exception rules (`!city.kobe.jp`) win outright, otherwise the
longest matching rule prevails, wildcards (`*.kobe.jp`) match exactly one extra label, and a
host with no matching rule uses the implicit "*" rule (its last label is the suffix).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_PSL_PATH = Path(__file__).resolve().parent.parent / "data" / "public_suffix_list.dat"

# Hosting platforms where every customer gets <name>.<platform> but which are NOT in the Public Suffix List (their
# operators never asked for a listing). For brand protection they behave exactly like listed platforms — the attacker
# chooses the subdomain — so they are added as private rules. Curated by hand from well-known free site builders and
# free web hosts; the evaluation corpus showed one of them (weebly.com) alone accounting for 27 phishing hosts.
# This is a floor, not a census: the PSL stays the source of truth and nothing here overrides a PSL rule.
SUPPLEMENTAL_PLATFORMS = (
    "weebly.com", "weeblysite.com", "godaddysites.com", "jimdofree.com", "mystrikingly.com", "glitch.me", "edgeone.dev",
    "wordpress.com", "tumblr.com", "000webhostapp.com", "infinityfreeapp.com", "epizy.com", "byethost7.com", "site123.me",
    "webwave.me", "ukit.me", "rf.gd", "canva.site", "softr.app", "webnode.com",
)


@dataclass(frozen=True)
class SuffixSplit:
    host: str                  # normalised (lowercase, ASCII/punycode, no trailing dot)
    suffix: str                # the public suffix, e.g. "com.br"; "" for IP addresses
    registrable: str | None    # suffix + one label ("brand.com.br"); None if host IS a public suffix
    subdomain: str             # labels left of the registrable domain ("" if none)
    private: bool              # the prevailing rule came from the PRIVATE (hosting platform) section
    is_ip: bool = False


def _ascii_label(label: str) -> str | None:
    if label.isascii():
        return label.lower()
    try:
        return label.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None


def normalise_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    labels = [_ascii_label(x) for x in host.split(".") if x]
    return ".".join(x for x in labels if x)


@lru_cache(maxsize=1)
def _rules() -> tuple[dict[str, bool], dict[str, bool], dict[str, bool]]:
    """(exact, wildcard_bases, exceptions): each maps rule -> is_private."""
    exact: dict[str, bool] = {}
    wild: dict[str, bool] = {}
    exc: dict[str, bool] = {}
    private = False
    for line in _PSL_PATH.read_text(encoding="utf8").splitlines():
        line = line.strip()
        if line.startswith("//"):
            if "===BEGIN PRIVATE DOMAINS===" in line:
                private = True
            elif "===END PRIVATE DOMAINS===" in line:
                private = False
            continue
        if not line:
            continue
        rule = line.split()[0]
        kind = "exc" if rule.startswith("!") else "wild" if rule.startswith("*.") else "exact"
        body = normalise_host(rule[1:] if kind == "exc" else rule[2:] if kind == "wild" else rule)
        if not body:
            continue
        {"exc": exc, "wild": wild, "exact": exact}[kind][body] = private
    for platform in SUPPLEMENTAL_PLATFORMS:
        exact.setdefault(normalise_host(platform), True)
    return exact, wild, exc


def split(host: str) -> SuffixSplit:
    host = normalise_host(host)
    try:
        ipaddress.ip_address(host)
        return SuffixSplit(host, "", host, "", False, True)
    except ValueError:
        pass
    labels = host.split(".") if host else []
    if not labels:
        return SuffixSplit("", "", None, "", False)

    exact, wild, exc = _rules()
    n = len(labels)
    suffix_len, private = 1, False                   # implicit "*" rule

    # Exception rules prevail over every other rule; the suffix is the rule minus its leftmost label.
    for i in range(n):
        cand = ".".join(labels[i:])
        if cand in exc:
            suffix_len, private = n - i - 1, exc[cand]
            break
    else:
        for i in range(n):                           # i = 0 is the longest candidate
            cand = ".".join(labels[i:])
            if cand in exact:
                suffix_len, private = n - i, exact[cand]
                break
            base = ".".join(labels[i + 1:])
            if i + 1 < n and base in wild:
                suffix_len, private = n - i, wild[base]
                break

    suffix = ".".join(labels[n - suffix_len:])
    if suffix_len >= n:
        return SuffixSplit(host, suffix, None, "", private)
    registrable = ".".join(labels[n - suffix_len - 1:])
    return SuffixSplit(host, suffix, registrable, ".".join(labels[:n - suffix_len - 1]), private)
