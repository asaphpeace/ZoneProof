"""
Brand Guard — how common is a brand word in everyday domain names? (pure, offline)

A name-only match is weak evidence when the brand word turns up all over the internet: 'apple' sits inside
'pineapple', 'applewood' and a few hundred other popular names, 'capitec' sits inside one. This module measures that
from a vendored list of the registrable labels of the 100,000 most popular domains (tools/build_popular_labels.py,
Majestic Million, CC BY 3.0) and reports a plain count: "N of 100,000 popular domain names contain this word".

It is a frequency, not a probability of coincidence, and it is honest about two limits:
  * the popular list contains real references to a famous brand too (google.* sites mention google), so a famous
    brand reads as "common" — which is the right call for how noisy a name-only match would be;
  * it knows nothing about South African names that are rare globally; a rare word is "not common", not "unique".
A random-letter model was tried first and rejected: against this same data it was wrong by 3-4 orders of magnitude.
"""
from __future__ import annotations

import gzip
import re
from functools import lru_cache
from pathlib import Path

_DATA = Path(__file__).resolve().parent.parent / "data" / "popular_labels.txt.gz"

# At or above this many hits per 100,000 popular domains the word is "common" and a name-only match is weak.
# Chosen before looking at any detection result (the measured values were apple 31, cash 74, visa 41, google 37,
# amazon 15, paypal 3, capitec 0 per 100k) so it is not fitted to the evaluation.
COMMON_PER_100K = 20


@lru_cache(maxsize=1)
def _labels() -> tuple[str, ...]:
    if not _DATA.exists():
        return ()
    with gzip.open(_DATA, "rt", encoding="utf8") as f:
        return tuple(line.strip() for line in f if line.strip())


def sample_size() -> int:
    return len(_labels())


@lru_cache(maxsize=2048)
def hits(token: str) -> int:
    """How many popular-domain labels contain the token (0 when the list isn't installed)."""
    token = re.sub(r"[^a-z0-9]", "", (token or "").lower())
    if len(token) < 3:
        return 0
    return sum(1 for label in _labels() if token in label)


def per_100k(token: str) -> float | None:
    """Hits scaled to 100,000 domains, or None when there is no reference list to measure against."""
    n = sample_size()
    if not n:
        return None
    return round(hits(token) * 100_000 / n, 1)


def is_common(token: str) -> bool:
    rate = per_100k(token)
    return rate is not None and rate >= COMMON_PER_100K
