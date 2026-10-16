"""
Brand Guard — matching live certificate sightings against every protected brand (the stream worker's brain; pure, no network).

A tiled log at the busy end delivers a few hundred certificates a second. Running the full name rules (`token_match`, 15-40 µs
each) for every name against every brand would not scale past a handful of brands, so a cheap necessary condition goes first:

    a label can match a brand token only if it shares at least one 3-character window with the token.

Why that is safe, not a heuristic: `token_match` accepts (a) the token inside the label, (b) the token as a whole word or fused
with a common word, both of which contain the token and so contain its first window, and (c) a "near" word within 1 edit
(tokens of 6-8 letters) or 2 edits (9+ letters). One edit destroys at most 3 windows of a token, and a 6-letter token has 4
(a 9-letter one has 7, and two edits destroy at most 6), so a near match always keeps at least one.

A first version of that argument was WRONG, and a test caught it: `papyal.com` is one swap away from `paypal` yet shares no
window with it, because an adjacent swap destroys up to four windows, not three. The corrected rule: tokens of 6 to 10
letters (where an edit sequence can wipe out every window) also index the windows of each one-swap variant of the token, which
restores the guarantee (a string within the edit budget then always shares a window with the token or with a variant), and
tokens of 11+ letters have more windows than two swaps can destroy. The window is taken from the raw label AND from its
confusable-folded skeleton, because the full rules match on either. A randomised test checks the whole thing against
`token_match` so any future change to the rules that breaks the guarantee fails loudly.

What a match produces mirrors the certificate branch of a scan: a registered look-alike becomes a candidate keyed by its
registrable name, brand-in-subdomain abuse becomes a candidate keyed by the full host, and both carry the certificate facts
(issue time, hosts, certificate ids, issuer) the scorer already understands.
"""
from __future__ import annotations

import re
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.services.brand_discovery_service import (
    matches_brand_fingerprint, registrable_domain, skeleton, split_registrable, subdomain_brand_abuse,
)
from types import SimpleNamespace

from app.services import brand_sources
from app.services.ct_tiles import CertSighting, entry_time

# Shown in the source-health strip, but only once the worker has reported at least once (a deployment without the worker
# should not show a permanent "not checked yet").
STREAM_SOURCE = SimpleNamespace(name="ct_stream", label="Live certificate stream", optional=True)
brand_sources.EXTRA_HEALTH_SOURCES.append(STREAM_SOURCE)

MIN_TOKEN_LEN = 3
MAX_NAMES_PER_CERT_EVALUATED = 60
MAX_HOSTS_PER_CANDIDATE = 8
MAX_CERTS_PER_CANDIDATE = 5
MAX_PENDING_PER_PROFILE = 200
RECENT_TTL = timedelta(hours=6)
RECENT_MAX = 50_000

_ALNUM = re.compile(r"[^a-z0-9]")


def windows(text: str) -> set[str]:
    s = _ALNUM.sub("", text.lower())
    return {s[i:i + 3] for i in range(len(s) - 2)}


def _token_windows(token: str) -> set[str]:
    """Every window a label must share one of with `token` to possibly match it (see the module docstring)."""
    found = windows(token) | windows(skeleton(token))
    if 6 <= len(token) <= 10:
        for i in range(len(token) - 1):
            if token[i] != token[i + 1]:
                found |= windows(token[:i] + token[i + 1] + token[i] + token[i + 2:])
    return found


@dataclass(frozen=True)
class StreamBrand:
    profile_id: str
    tenant_id: str
    tokens: tuple[str, ...]
    official_apexes: frozenset[str]
    official_names: tuple[str, ...]


class StreamMatcher:
    """Built once per brand-list refresh; `match` is the hot path."""

    def __init__(self, brands: list[StreamBrand]) -> None:
        self.brands = list(brands)
        # Two indexes. The registrable label can match by typo ("near"), so it needs the swap-aware windows. The subdomain
        # rules (brand_discovery_service.subdomain_brand_abuse) never use "near", only a token inside / a whole word / fused,
        # or the customer's own domain written out, so plain windows are enough there, and the subdomain string is far shorter
        # (and far less often a hit) than the whole host.
        self._by_window: dict[str, set[int]] = {}
        self._by_sub_window: dict[str, set[int]] = {}
        for i, b in enumerate(self.brands):
            for token in b.tokens:
                t = _ALNUM.sub("", (token or "").lower())
                if len(t) < MIN_TOKEN_LEN:
                    continue
                for w in _token_windows(t):
                    self._by_window.setdefault(w, set()).add(i)
                for w in windows(t) | windows(skeleton(t)):
                    self._by_sub_window.setdefault(w, set()).add(i)
            for official in b.official_apexes:
                for w in windows(official) | windows(skeleton(official)):
                    self._by_sub_window.setdefault(w, set()).add(i)

    def _brands_for(self, text: str, index: dict[str, set[int]] | None = None) -> set[int]:
        index = self._by_window if index is None else index
        found: set[int] = set()
        for w in windows(text) | windows(skeleton(text)):
            hit = index.get(w)
            if hit:
                found |= hit
        return found

    def match_host(self, host: str) -> list[tuple[StreamBrand, str]]:
        """[(brand, candidate key)] for one host name: the registrable name when it carries the brand, else the full host
        when the brand is hidden in a subdomain of someone else's domain."""
        out: list[tuple[StreamBrand, str]] = []
        apex = registrable_domain(host)
        label = split_registrable(host)[0]
        for i in self._brands_for(label):
            b = self.brands[i]
            if apex in b.official_apexes:
                continue
            if matches_brand_fingerprint(host, list(b.tokens)):
                out.append((b, apex))
        if host != apex:
            seen = {b.profile_id for b, _ in out}
            sub = host[: -(len(apex) + 1)]
            for i in self._brands_for(sub, self._by_sub_window):
                b = self.brands[i]
                if b.profile_id in seen or apex in b.official_apexes:
                    continue
                if subdomain_brand_abuse(host, list(b.tokens), list(b.official_names)):
                    out.append((b, host))
        return out

    def match(self, sighting: CertSighting) -> list[tuple[StreamBrand, str, str, dict]]:
        """[(brand, candidate key, class, ct meta)] for one certificate."""
        issued = entry_time(sighting.logged_at_ms).isoformat()
        results: dict[tuple[str, str], tuple[StreamBrand, str, str, dict]] = {}
        for host in sighting.names[:MAX_NAMES_PER_CERT_EVALUATED]:
            for brand, key in self.match_host(host):
                slot = (brand.profile_id, key)
                found = results.get(slot)
                if found is None:
                    meta = {"issued_at": issued, "hosts": {}, "cert_ids": [sighting.sha256], "issuer": sighting.issuer}
                    found = (brand, key, "subdomain_abuse" if key == host and host != registrable_domain(host) else "", meta)
                    results[slot] = found
                if host != key and len(found[3]["hosts"]) < MAX_HOSTS_PER_CANDIDATE:
                    found[3]["hosts"][host] = issued
        return list(results.values())


@dataclass
class HitBuffer:
    """Collects matches until the worker flushes them. Bounded, and merges repeats of the same name."""
    per_profile: dict[str, dict[str, dict]] = field(default_factory=dict)
    dropped: int = 0

    def add(self, brand: StreamBrand, key: str, klass: str, ct: dict) -> None:
        bucket = self.per_profile.setdefault(brand.profile_id, {})
        cur = bucket.get(key)
        if cur is None:
            if len(bucket) >= MAX_PENDING_PER_PROFILE:
                self.dropped += 1
                return
            bucket[key] = {"class": klass or None, "sources": ["ct_stream"], "ct": {**ct, "hosts": dict(ct["hosts"]), "cert_ids": list(ct["cert_ids"])}}
            return
        meta = cur["ct"]
        if ct["issued_at"] > meta["issued_at"]:
            meta["issued_at"] = ct["issued_at"]
        for host, when in ct["hosts"].items():
            if host in meta["hosts"] or len(meta["hosts"]) < MAX_HOSTS_PER_CANDIDATE:
                meta["hosts"][host] = max(meta["hosts"].get(host, ""), when)
        for cid in ct["cert_ids"]:
            if cid not in meta["cert_ids"] and len(meta["cert_ids"]) < MAX_CERTS_PER_CANDIDATE:
                meta["cert_ids"].append(cid)

    def __len__(self) -> int:
        return sum(len(v) for v in self.per_profile.values())

    def drain(self) -> dict[str, dict[str, dict]]:
        out, self.per_profile = self.per_profile, {}
        return out


class RecentNames:
    """Names already handed to the pipeline lately, so a busy hour of renewals does not redo DNS for the same look-alike."""

    def __init__(self, ttl: timedelta = RECENT_TTL, limit: int = RECENT_MAX) -> None:
        self._seen: OrderedDict[tuple[str, str], datetime] = OrderedDict()
        self.ttl, self.limit = ttl, limit

    def fresh(self, profile_id: str, key: str, now: datetime | None = None) -> bool:
        """True (and remembered) if this name has NOT been handed over within the TTL."""
        now = now or datetime.now(timezone.utc)
        slot = (profile_id, key)
        at = self._seen.get(slot)
        if at is not None and now - at < self.ttl:
            return False
        self._seen[slot] = now
        self._seen.move_to_end(slot)
        while len(self._seen) > self.limit:
            self._seen.popitem(last=False)
        return True
