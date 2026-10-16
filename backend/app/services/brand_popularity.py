"""
Brand Guard — is a look-alike itself a well-known site? (pure, offline)

A registered name that resembles the brand but is itself in the top 100,000 sites of the web is almost always an unrelated
legitimate business that happens to share letters (pdd.com, dps.com, cpd.com), not an impersonator — attackers' domains are
new and unknown. This module answers from a vendored list of the 100,000 highest-ranked domains of the Majestic Million
(app/data/popular_domains.txt.gz, CC BY 3.0 — attribution in BRAND_GUARD_DATA_SOURCES.md; rebuild with
tools/build_popular_labels.py, byte-reproducible). Majestic is used instead of Tranco because Tranco's default list mixes in
non-commercial providers (see the data-source register).

Measured before use: of 488 suspected-phishing hosts in the evaluation corpus, only 2 (0.4%) sit on a domain in this list, and
both are multi-tenant platforms that host other people's pages (hashnode.dev blogs, a CDN) — never an ordinary registered
look-alike (0 of 109). That is why the benign discount applies only to a name that IS a registered domain, never to a host
that is a subdomain of one: abuse of popular platforms lives exactly there.
"""
from __future__ import annotations

import gzip
from functools import lru_cache
from pathlib import Path

_DATA = Path(__file__).resolve().parent.parent / "data" / "popular_domains.txt.gz"

TOP_10K = 10_000


@lru_cache(maxsize=1)
def _ranks() -> dict[str, int]:
    if not _DATA.exists():
        return {}
    out: dict[str, int] = {}
    with gzip.open(_DATA, "rt", encoding="utf8") as f:
        for line in f:
            rank, _, domain = line.strip().partition("\t")
            if domain and rank.isdigit():
                out.setdefault(domain, int(rank))
    return out


def sample_size() -> int:
    return len(_ranks())


def rank_of(registrable_domain: str) -> int | None:
    """Majestic global rank of a registrable domain, or None when it is not in the top 100,000 (or the list is absent)."""
    return _ranks().get((registrable_domain or "").lower().rstrip("."))
