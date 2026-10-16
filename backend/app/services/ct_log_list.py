"""
Which certificate logs the stream worker follows, resolved from the public CT log list (https://www.gstatic.com/ct/log_list/v3/log_list.json).

Two facts shape this (both measured on 2026-10-02):

  * Logs come in SHARDS by certificate expiry ("2026h2", "2027h1"...). A certificate is written to the shard its expiry falls in,
    so as the calendar moves the busy shard moves with it: a log family has to be followed across all its current and
    upcoming shards, or detection quietly stops at the turn of the half-year. Idle shards cost one checkpoint request a while.
  * A family's sibling logs overlap almost completely (Let's Encrypt Willow vs Sycamore: 92% of names in a common window;
    Google ParcelYard vs PlumbersArms: 99%), so following one member of each family is enough. The default families are
    "parcelyard" (Google: ~180 entries/s, ~1.4 KB each) and "willow" (Let's Encrypt, the free-certificate CA attackers favour:
    ~32/s). Together they covered about 88% of the names seen across five tiled logs in the sample window.

Pure functions plus a built-in fallback, so the worker still starts when the list cannot be fetched.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
DEFAULT_FAMILIES = ("parcelyard", "willow")
FUTURE_SHARD_HORIZON = timedelta(days=420)     # certificates can be valid for ~398 days, so those shards can already be written to


@dataclass(frozen=True)
class TileLog:
    name: str                  # "Google 'ParcelYard2026h2' log"
    family: str                # "parcelyard"
    url: str                   # monitoring URL, always ends with "/"
    start: datetime | None     # first expiry this shard accepts
    end: datetime | None       # expiry bound (exclusive); None = open-ended

    @property
    def id(self) -> str:
        return self.url.rstrip("/").split("//", 1)[-1]


# Verified live on 2026-10-02; used only when the log list cannot be fetched.
FALLBACK_LOGS = (
    TileLog("Google ParcelYard2026h2", "parcelyard", "https://storage.googleapis.com/parcelyard2026h2.prod.certificate.transparency.goog/", None, None),
    TileLog("Google ParcelYard2027h1", "parcelyard", "https://storage.googleapis.com/parcelyard2027h1.prod.certificate.transparency.goog/", None, None),
    TileLog("Let's Encrypt Willow2026h2", "willow", "https://mon.willow.ct.letsencrypt.org/2026h2/", None, None),
    TileLog("Let's Encrypt Willow2027h1", "willow", "https://mon.willow.ct.letsencrypt.org/2027h1/", None, None),
)


def _ts(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _https(url: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return parts.scheme == "https" and bool(parts.hostname) and not parts.username and not parts.password


def parse_log_list(doc: dict, families=DEFAULT_FAMILIES, now: datetime | None = None) -> list[TileLog]:
    """The tiled logs of the wanted families that are accepting certificates now or will within the horizon, oldest shard first."""
    now = now or datetime.now(timezone.utc)
    wanted = [f.lower() for f in families]
    out: list[TileLog] = []
    for operator in doc.get("operators") or []:
        for log in operator.get("tiled_logs") or []:
            desc = str(log.get("description") or "")
            family = next((f for f in wanted if f in desc.lower()), None)
            if family is None:
                continue
            if "usable" not in (log.get("state") or {}):
                continue
            url = str(log.get("monitoring_url") or "")
            if not _https(url):
                continue
            interval = log.get("temporal_interval") or {}
            start, end = _ts(interval.get("start_inclusive")), _ts(interval.get("end_exclusive"))
            if end is not None and end <= now:
                continue
            if start is not None and start > now + FUTURE_SHARD_HORIZON:
                continue
            out.append(TileLog(desc[:120], family, url if url.endswith("/") else url + "/", start, end))
    out.sort(key=lambda l: (l.family, l.end or datetime.max.replace(tzinfo=timezone.utc)))
    return out


def resolve(doc: dict | None, families=DEFAULT_FAMILIES, now: datetime | None = None) -> list[TileLog]:
    """The list's answer, or the built-in fallback restricted to the wanted families when the list is missing or yields nothing."""
    if doc:
        found = parse_log_list(doc, families, now)
        if found:
            return found
    wanted = {f.lower() for f in families}
    return [l for l in FALLBACK_LOGS if l.family in wanted]


def custom_logs(urls: list[str]) -> list[TileLog]:
    """Logs named explicitly in configuration (https only; anything else is ignored)."""
    out = []
    for u in urls:
        u = u.strip()
        if _https(u):
            out.append(TileLog(u, "custom", u if u.endswith("/") else u + "/", None, None))
    return out
