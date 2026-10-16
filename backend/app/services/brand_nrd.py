"""
Brand Guard — newly registered domains as a discovery source (plan step 2.6b).

Permutation lists only find names we can think of, and certificate monitoring only sees names that got a certificate.
A daily list of newly registered domains finds names nobody guessed (`brand-refunds.com`) the day after registration,
before they have a certificate or a website.

Source: WhoisDS free daily list ("only domains, no WHOIS data"), which its publisher states may be reused, including for
commercial purposes, without a licence or payment (BRAND_GUARD_DATA_SOURCES.md). One small zip per day (~0.5 MB).

Honest limits (shown to the customer, not hidden):
  * the FREE list is a sample — exactly 70,000 names a day, while roughly 250,000+ domains are registered daily — so it
    covers a minority of new registrations; a paid full feed (or ICANN CZDS zone files) is a product decision;
  * it is published the day AFTER registration, so this is "yesterday", not minutes; the minutes-level source is a
    streaming certificate feed, which needs a long-running consumer and is not part of a request-scoped scan;
  * a name appearing here is only a lead: it goes through the same scoring as every other candidate.

Like the abuse feeds, this is a fixed trusted URL (plain HTTP client), failures are recorded in the source-health strip,
and a day that cannot be downloaded is simply missing — never an error for the scan.
"""
from __future__ import annotations

import asyncio
import base64
import io
import logging
import zipfile
from datetime import date, datetime, timedelta, timezone

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.services import brand_sources as sources
from app.services.brand_discovery_service import matches_brand_fingerprint, registrable_domain

log = logging.getLogger(__name__)

URL_TEMPLATE = "https://www.whoisds.com//whois-database/newly-registered-domains/{token}/nrd"
KEEP_DAYS = 3                       # lists kept in memory (a scan that missed a day still sees the last few)
FETCH_TIMEOUT = 40.0
_MAX_ZIP_BYTES = 8_000_000
_MAX_TEXT_BYTES = 30_000_000        # decompressed cap (zip-bomb guard); a real list is ~1.2 MB
_MAX_NAMES_PER_DAY = 600_000
MAX_CANDIDATES_PER_SCAN = 60        # leads per brand per scan, newest first


def _today() -> date:
    return datetime.now(timezone.utc).date()


def url_for(day: date) -> str:
    token = base64.b64encode(f"{day.isoformat()}.zip".encode()).decode()
    return URL_TEMPLATE.format(token=token)


def parse_zip(blob: bytes) -> frozenset[str]:
    """The names in one daily list. Raises ValueError on anything that is not a small zip holding a text list."""
    if len(blob) > _MAX_ZIP_BYTES:
        raise ValueError("list too large")
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            infos = [i for i in z.infolist() if not i.is_dir()]
            if not infos or infos[0].file_size > _MAX_TEXT_BYTES:
                raise ValueError("unexpected archive")
            with z.open(infos[0]) as f:
                raw = f.read(_MAX_TEXT_BYTES + 1)
    except zipfile.BadZipFile as e:
        raise ValueError("not a zip") from e
    if len(raw) > _MAX_TEXT_BYTES:
        raise ValueError("list too large")
    names: set[str] = set()
    for line in raw.decode("utf-8", errors="replace").splitlines():
        name = line.strip().lower().rstrip(".")
        if name and "." in name and " " not in name and len(name) <= 253:
            names.add(name)
            if len(names) >= _MAX_NAMES_PER_DAY:
                break
    if not names:
        raise ValueError("empty list")
    return frozenset(names)


class NrdFeed:
    name = "nrd_whoisds"
    label = "Newly registered domains (WhoisDS, daily sample)"

    def __init__(self) -> None:
        self.days: dict[date, frozenset[str]] = {}
        self.attempted: dict[date, datetime] = {}      # day -> when we last tried (a day that fails is retried later, not hammered)
        self._hits: dict[tuple, list[str]] = {}        # (day, tokens) -> matching names; a loaded day never changes, so each is computed once

    def reset(self) -> None:
        self.days.clear()
        self.attempted.clear()
        self._hits.clear()


FEED = NrdFeed()
sources.EXTRA_HEALTH_SOURCES.append(FEED)
RETRY_AFTER = timedelta(hours=2)


async def _download(client: httpx.AsyncClient, url: str) -> bytes:
    async with client.stream("GET", url, headers={"User-Agent": "ZoneProof-BrandGuard/1.0"}) as resp:
        if resp.status_code != 200:
            raise sources.SourceError(f"HTTP {resp.status_code}", transient=resp.status_code >= 500 or resp.status_code in (404, 408, 425, 429))
        body = bytearray()
        async for chunk in resp.aiter_bytes():
            body.extend(chunk)
            if len(body) > _MAX_ZIP_BYTES:
                raise sources.SourceError("response too large", transient=False)
        return bytes(body)


async def refresh(db: AsyncSession, *, client_factory=None, now: datetime | None = None, today: date | None = None, feed: NrdFeed | None = None) -> None:
    """Fetch any of the last KEEP_DAYS daily lists that are missing (the newest is yesterday's). Never raises."""
    feed = feed or FEED
    now = now or datetime.now(timezone.utc)
    today = today or now.date()
    wanted = [today - timedelta(days=n) for n in range(1, KEEP_DAYS + 1)]
    for old in [d for d in feed.days if d not in wanted]:
        del feed.days[old]
    make_client = client_factory or (lambda: httpx.AsyncClient(timeout=FETCH_TIMEOUT, follow_redirects=True))
    for day in wanted:
        if day in feed.days:
            continue
        tried = feed.attempted.get(day)
        if tried and now - tried < RETRY_AFTER:
            continue
        try:
            row = await sources._get_row(db, feed.name)
            if sources.breaker_open_until(row) is not None:
                return                                              # circuit open: let the source recover
            feed.attempted[day] = now
            started = datetime.now(timezone.utc)
            try:
                async with make_client() as client:
                    blob = await asyncio.wait_for(_download(client, url_for(day)), timeout=FETCH_TIMEOUT)
                names = parse_zip(blob)
            except (sources.SourceError, httpx.HTTPError, asyncio.TimeoutError, ValueError) as e:
                reason = e.reason if isinstance(e, sources.SourceError) else ("timed out" if isinstance(e, asyncio.TimeoutError) else type(e).__name__ if not isinstance(e, ValueError) else str(e))
                # The newest list is not always published yet: its absence is not a source failure until older days also fail.
                if isinstance(e, sources.SourceError) and e.reason == "HTTP 404" and day == wanted[0]:
                    continue
                log.warning("Brand Guard new-registration list %s failed: %s", day, reason)
                await sources._record(db, feed, ok=False, latency_ms=None, error=reason)
                continue
            feed.days[day] = names
            await sources._record(db, feed, ok=True, latency_ms=int((datetime.now(timezone.utc) - started).total_seconds() * 1000), error=None)
        except Exception:
            log.exception("Brand Guard new-registration refresh crashed")


async def find(tokens: list[str], official: set[str] | None = None, feed: NrdFeed | None = None, limit: int = MAX_CANDIDATES_PER_SCAN) -> dict[str, dict]:
    """`candidates` off the event loop: matching 70,000 names per day takes seconds the first time (cached after)."""
    return await asyncio.to_thread(candidates, tokens, official, feed, limit)


def candidates(tokens: list[str], official: set[str] | None = None, feed: NrdFeed | None = None, limit: int = MAX_CANDIDATES_PER_SCAN) -> dict[str, dict]:
    """Names from the recent lists whose registrable label shows the brand. {domain: {"listed_on": iso date}}, newest first."""
    feed = feed or FEED
    official = official or set()
    out: dict[str, dict] = {}
    key_tokens = tuple(sorted(t.strip().lower() for t in tokens))
    for k in [k for k in feed._hits if k[0] not in feed.days]:
        del feed._hits[k]                                   # a day that left the window takes its cached answers with it
    for day in sorted(feed.days, reverse=True):
        if (day, key_tokens) not in feed._hits:
            feed._hits[(day, key_tokens)] = sorted(n for n in feed.days[day] if matches_brand_fingerprint(n, tokens))
        hits = [n for n in feed._hits[(day, key_tokens)] if n not in out and registrable_domain(n) not in official]
        for name in hits[: limit - len(out)]:
            out[name] = {"listed_on": day.isoformat()}
        if len(out) >= limit:
            break
    return out
