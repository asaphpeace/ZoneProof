"""
Brand Guard — public abuse feeds used as CORROBORATION (plan step 2.5).

Two free, commercially usable feeds (licences recorded in BRAND_GUARD_DATA_SOURCES.md):
  * phishunt.io  feed.json  — CC0 1.0, automated phishing detection, ~1 MB, brand-labelled (NOT human-verified)
  * abuse.ch URLhaus csv_online — CC0, malware-distribution URLs, ~3 MB

They are downloaded as whole lists (two requests per refresh, not one request per candidate), kept in memory for
REFRESH_INTERVAL, and looked up by host. A feed that cannot be fetched is recorded in the same source-health table as the
certificate feed and simply contributes nothing; stale data is kept for up to MAX_STALE rather than dropped at the first
failure, then discarded so an outage cannot keep "corroborating" for days.

These URLs are fixed and trusted (not tenant-supplied), so a plain HTTP client is used — unlike the brand-fingerprint fetch.
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.services import brand_sources as sources
from app.services.brand_discovery_service import registrable_domain

log = logging.getLogger(__name__)

REFRESH_INTERVAL = timedelta(minutes=30)
MAX_STALE = timedelta(hours=6)
FETCH_TIMEOUT = 25.0
_MAX_BYTES = 12_000_000
_ENTRIES_PER_HOST = 3


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _host_of(url: str) -> str | None:
    try:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if not host or all(c.isdigit() or c == "." for c in host) or ":" in host:      # raw IPs cannot corroborate a domain
        return None
    return host


@dataclass
class Feed:
    name: str
    label: str
    url: str
    # populated by refresh
    index: dict[str, list[dict]] = field(default_factory=dict)       # host -> entries
    apex_index: dict[str, dict] = field(default_factory=dict)        # registered domain -> first entry (any host on it)
    fetched_at: datetime | None = None

    def load(self, index: dict[str, list[dict]], fetched_at: datetime | None) -> None:
        self.index, self.fetched_at = index, fetched_at
        self.apex_index = {}
        for host, entries in index.items():
            self.apex_index.setdefault(registrable_domain(host), entries[0])

    def parse(self, text: str) -> dict[str, list[dict]]:     # overridden
        raise NotImplementedError


class PhishuntFeed(Feed):
    def parse(self, text: str) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError("unexpected shape")
        for rec in data:
            if not isinstance(rec, dict):
                continue
            host = _host_of(rec.get("url") or "") or _host_of("http://" + str(rec.get("domain") or ""))
            if not host:
                continue
            flags = sum(1 for k, v in rec.items() if k.startswith("malicious_") and v is True)
            entry = {"feed": self.name, "label": self.label, "first_seen": rec.get("first_seen") or rec.get("date"), "detail": {"other_flags": flags}}
            bucket = out.setdefault(host, [])
            if len(bucket) < _ENTRIES_PER_HOST:
                bucket.append(entry)
        return out


class UrlhausFeed(Feed):
    def parse(self, text: str) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        rows = csv.reader(io.StringIO("\n".join(l for l in text.splitlines() if l and not l.startswith("#"))))
        for row in rows:
            if len(row) < 4 or row[3] != "online":              # id,dateadded,url,url_status,...
                continue
            host = _host_of(row[2])
            if not host:
                continue
            bucket = out.setdefault(host, [])
            if len(bucket) < _ENTRIES_PER_HOST:
                bucket.append({"feed": self.name, "label": self.label, "first_seen": row[1], "detail": {}})
        return out


FEEDS: list[Feed] = [
    PhishuntFeed("phishunt", "phishunt.io", "https://phishunt.io/feed.json"),
    UrlhausFeed("urlhaus", "abuse.ch URLhaus", "https://urlhaus.abuse.ch/downloads/csv_online/"),
]
# Shown in the same source-health strip as the certificate feed
sources.EXTRA_HEALTH_SOURCES.extend(FEEDS)


async def _download(client: httpx.AsyncClient, url: str) -> str:
    async with client.stream("GET", url, headers={"User-Agent": "ZoneProof-BrandGuard/1.0"}) as resp:
        if resp.status_code != 200:
            raise sources.SourceError(f"HTTP {resp.status_code}", transient=resp.status_code >= 500 or resp.status_code in (408, 425, 429))
        body = bytearray()
        async for chunk in resp.aiter_bytes():
            body.extend(chunk)
            if len(body) > _MAX_BYTES:
                raise sources.SourceError("response too large", transient=False)
        return body.decode("utf-8", errors="replace")


async def refresh(db: AsyncSession, *, client_factory=None, now: datetime | None = None, feeds: list[Feed] | None = None) -> None:
    """Bring every feed up to date if it is due. Never raises: a failing feed is recorded in source health and skipped."""
    now = now or _now()
    make_client = client_factory or (lambda: httpx.AsyncClient(timeout=FETCH_TIMEOUT, follow_redirects=True))
    for feed in feeds if feeds is not None else FEEDS:
        if feed.fetched_at and now - feed.fetched_at < REFRESH_INTERVAL:
            continue
        try:
            row = await sources._get_row(db, feed.name)
            if sources.breaker_open_until(row) is not None:
                continue                                           # circuit open: let the source recover
            started = _now()
            try:
                async with make_client() as client:
                    text = await asyncio.wait_for(_download(client, feed.url), timeout=FETCH_TIMEOUT)
                index = feed.parse(text)
            except (sources.SourceError, httpx.HTTPError, asyncio.TimeoutError, ValueError, json.JSONDecodeError, csv.Error) as e:
                reason = e.reason if isinstance(e, sources.SourceError) else (type(e).__name__ if not isinstance(e, asyncio.TimeoutError) else "timed out")
                log.warning("Brand Guard feed %s failed: %s", feed.name, reason)
                await sources._record(db, feed, ok=False, latency_ms=None, error=reason)
                if feed.fetched_at and now - feed.fetched_at > MAX_STALE:
                    feed.load({}, None)                              # an outage must not keep corroborating forever
                continue
            feed.load(index, now)
            await sources._record(db, feed, ok=True, latency_ms=int((_now() - started).total_seconds() * 1000), error=None)
        except Exception:
            log.exception("Brand Guard feed refresh crashed for %s", feed.name)


def lookup(candidate_domain: str, feeds: list[Feed] | None = None) -> list[dict]:
    """Entries across all feeds for a candidate: an exact host match, else any listed host on the same REGISTERED domain
    (flagged `same_site` — the domain is being abused, though not necessarily this host)."""
    host = candidate_domain.lower().rstrip(".")
    apex = registrable_domain(host)
    out: list[dict] = []
    for feed in feeds if feeds is not None else FEEDS:
        exact = feed.index.get(host)
        if exact:
            out.append({**exact[0], "same_site": False})
        elif feed.apex_index.get(apex):
            out.append({**feed.apex_index[apex], "same_site": True})
    return out
