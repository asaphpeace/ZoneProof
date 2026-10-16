"""
Brand Guard — discovery sources (certificate transparency) behind one
resilient interface.

Why this exists: crt.sh is free and useful but routinely returns 502s or hangs.
A scan must neither fail because of that nor pretend it didn't happen, and the
customer should be able to see the state of the feed. So every source call goes
through `fetch_ct_candidates`, which adds:

  * bounded retries with exponential backoff + jitter for transient failures
    (timeouts, connection errors, 429/502/503/504, unparseable bodies), honouring
    Retry-After; non-transient 4xx are never retried.
  * persistent per-source health (`brand_source_health`): healthy → degraded
    (1-2 consecutive failures) → down (3+).
  * a circuit breaker: once a source is down, calls are skipped for a cooldown
    instead of making every scan wait out another round of timeouts; after the
    cooldown a single trial call is allowed, and a success closes the circuit.

A streaming CT feed (CertStream or similar) is added by implementing
`CandidateSource` and appending it to `SOURCES`; nothing downstream changes.
"""
from __future__ import annotations

import asyncio
import logging
import random
from datetime import datetime, timedelta, timezone
from typing import Protocol
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import BrandSourceHealth
from app.services.brand_discovery_service import registrable_domain
from app.services.brand_throttle import crt_throttle

log = logging.getLogger(__name__)

MAX_ATTEMPTS = 3
ATTEMPT_TIMEOUT_SECONDS = 20.0
TOTAL_BUDGET_SECONDS = 60.0         # wall-clock cap for one source call, retries included
BACKOFF_BASE_SECONDS = 1.0
BACKOFF_CAP_SECONDS = 10.0
RETRY_AFTER_CAP_SECONDS = 15.0
DEGRADED_AFTER = 1                  # consecutive failures
DOWN_AFTER = 3
BREAKER_COOLDOWN = timedelta(minutes=10)
# crt.sh is an overloaded free service that has been seen answering 404 and 502
# for the same valid query within minutes, so those are retried like any 5xx.
# Other 4xx (400/401/403...) mean our request is wrong and are never retried.
_TRANSIENT_STATUS = {404, 408, 425, 429}


def _is_transient_status(code: int) -> bool:
    return code in _TRANSIENT_STATUS or code >= 500
_CRT_SH_URL = "https://crt.sh/"
_MAX_RESULTS_PER_TOKEN = 300
_MAX_CERTS_PER_APEX = 5       # certificate ids kept per registrable name (cluster evidence, bounded)
_MAX_HOSTS_PER_APEX = 8      # hostnames kept per registrable name (evidence for subdomain abuse, bounded)
TOKEN_CACHE_TTL = timedelta(minutes=15)   # several brands sharing a token, or scans back to back, reuse one request
TOKEN_CACHE_MAX = 200

# Indirection points so tests can run without real sleeps or wall-clock time.
_sleep = asyncio.sleep


def _now() -> datetime:
    return datetime.now(timezone.utc)


class SourceError(Exception):
    """A source call failed. `reason` is safe to show to customers (no URLs,
    no response bodies)."""
    def __init__(self, reason: str, *, transient: bool):
        super().__init__(reason)
        self.reason = reason
        self.transient = transient


class SourceUnavailable(Exception):
    """Every source was down, skipped by the breaker, or failed."""


class CandidateSource(Protocol):
    name: str
    label: str

    async def fetch(self, tokens: list[str], since: datetime) -> dict[str, dict]:
        """{registrable_domain: {"issued_at": iso}}. Raises SourceError."""


def _backoff(attempt: int, retry_after: float | None) -> float:
    if retry_after is not None:
        return min(retry_after, RETRY_AFTER_CAP_SECONDS)
    return min(BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)) + random.uniform(0, 0.5), BACKOFF_CAP_SECONDS)


def _retry_after_seconds(resp: httpx.Response) -> float | None:
    raw = resp.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(float(raw), 0.0)
    except ValueError:
        return None  # HTTP-date form: not worth parsing, fall back to our own backoff


def _parse_ct_ts(value) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class CrtShSource:
    name = "crt_sh"
    label = "Certificate Transparency (crt.sh)"

    def __init__(self, client_factory=None):
        self._cache: dict[str, tuple[datetime, list]] = {}
        self._client_factory = client_factory or (
            lambda: httpx.AsyncClient(timeout=ATTEMPT_TIMEOUT_SECONDS, headers={"User-Agent": "ZoneProof-BrandGuard/1.0"})
        )

    async def _get_json(self, client: httpx.AsyncClient, url: str):
        last: SourceError | None = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            retry_after: float | None = None
            try:
                async with crt_throttle.slot():       # one request at a time, spaced out, across every scan
                    resp = await client.get(url)
            except (httpx.TimeoutException, httpx.TransportError) as e:
                last = SourceError(f"{type(e).__name__}", transient=True)
            else:
                if _is_transient_status(resp.status_code):
                    last = SourceError(f"HTTP {resp.status_code}", transient=True)
                    retry_after = _retry_after_seconds(resp)
                elif resp.status_code >= 400:
                    raise SourceError(f"HTTP {resp.status_code}", transient=False)
                else:
                    try:
                        return resp.json()
                    except ValueError:
                        # crt.sh sometimes answers 200 with an HTML/garbled body under load.
                        last = SourceError("unreadable response", transient=True)
            if attempt < MAX_ATTEMPTS:
                delay = _backoff(attempt, retry_after)
                log.info("crt.sh attempt %d/%d failed (%s); retrying in %.1fs", attempt, MAX_ATTEMPTS, last.reason, delay)
                await _sleep(delay)
        assert last is not None
        raise last

    async def _token_entries(self, client: httpx.AsyncClient, token: str) -> list:
        """Raw (already truncated) certificate entries for a token, cached briefly. Only successes are cached,
        so a failing source is never remembered as an empty answer."""
        now = _now()
        hit = self._cache.get(token)
        if hit and hit[0] > now:
            return hit[1]
        data = await self._get_json(client, f"{_CRT_SH_URL}?q=%25{quote(token)}%25&output=json&exclude=expired")
        if not isinstance(data, list):
            raise SourceError("unexpected response shape", transient=True)
        entries = data[:_MAX_RESULTS_PER_TOKEN]
        self._cache[token] = (now + TOKEN_CACHE_TTL, entries)
        while len(self._cache) > TOKEN_CACHE_MAX:
            self._cache.pop(min(self._cache, key=lambda k: self._cache[k][0]))
        return entries

    async def fetch(self, tokens: list[str], since: datetime) -> dict[str, dict]:
        found: dict[str, dict] = {}
        async with self._client_factory() as client:
            for token in tokens:
                if len(token) < 4:
                    continue
                # crt.sh treats a literal % as its wildcard, so it must reach the wire
                # as %25 — letting httpx encode a params dict leaves "%ac..." looking
                # like a percent-escape and mangles the query.
                data = await self._token_entries(client, token)
                for entry in data:
                    issued = _parse_ct_ts(entry.get("entry_timestamp") or entry.get("not_before"))
                    if not issued or issued < since:
                        continue
                    cert_id = str(entry["id"]) if entry.get("id") is not None else None
                    issuer = str(entry.get("issuer_name") or "")[:160] or None
                    for name in str(entry.get("name_value", "")).splitlines():
                        name = name.strip().lower().lstrip("*.")
                        if name and "." in name:
                            apex = registrable_domain(name)
                            prev = found.get(apex)
                            hosts = dict(prev["hosts"]) if prev else {}
                            cert_ids = list(prev.get("cert_ids", [])) if prev else []
                            if cert_id and cert_id not in cert_ids and len(cert_ids) < _MAX_CERTS_PER_APEX:
                                cert_ids.append(cert_id)        # the same certificate on several names = one operator (cluster evidence)
                            if name != apex and (name in hosts or len(hosts) < _MAX_HOSTS_PER_APEX):
                                hosts[name] = max(hosts.get(name, ""), issued.isoformat())
                            if not prev or issued.isoformat() > prev["issued_at"]:
                                found[apex] = {"issued_at": issued.isoformat(), "hosts": hosts, "cert_ids": cert_ids, "issuer": issuer}
                            else:
                                prev["hosts"], prev["cert_ids"] = hosts, cert_ids
        return found


SOURCES: list[CandidateSource] = [CrtShSource()]
# Corroboration feeds (plan 2.5) register themselves here so they show in the same source-health strip.
EXTRA_HEALTH_SOURCES: list = []


# ── Health ───────────────────────────────────────────────────────────────────

def health_status(consecutive_failures: int) -> str:
    if consecutive_failures >= DOWN_AFTER:
        return "down"
    if consecutive_failures >= DEGRADED_AFTER:
        return "degraded"
    return "healthy"


def breaker_open_until(row: BrandSourceHealth | None) -> datetime | None:
    """When the circuit is open, the time a trial call is next allowed."""
    if row is None or row.consecutive_failures < DOWN_AFTER or row.last_failure_at is None:
        return None
    until = row.last_failure_at + BREAKER_COOLDOWN
    return until if until > _now() else None


async def _get_row(db: AsyncSession, name: str) -> BrandSourceHealth | None:
    # populate_existing: health is written with a SQL upsert that bypasses the
    # ORM, so a row already in this session's identity map would otherwise be
    # returned stale (matters for the scheduler, which reuses one session).
    return (await db.execute(
        select(BrandSourceHealth).where(BrandSourceHealth.source == name).execution_options(populate_existing=True)
    )).scalar_one_or_none()


async def _record(db: AsyncSession, source: CandidateSource, *, ok: bool, latency_ms: int | None, error: str | None) -> None:
    """Atomic upsert — two scans finishing together must not lose a failure count."""
    now = _now()
    if ok:
        values = dict(consecutive_failures=0, status="healthy", last_success_at=now, last_latency_ms=latency_ms, last_error=None)
        stmt = pg_insert(BrandSourceHealth).values(source=source.name, label=source.label, updated_at=now, **values)
        stmt = stmt.on_conflict_do_update(index_elements=["source"], set_={**values, "label": source.label, "updated_at": now})
    else:
        stmt = pg_insert(BrandSourceHealth).values(
            source=source.name, label=source.label, consecutive_failures=1, status=health_status(1),
            last_failure_at=now, last_error=error, updated_at=now,
        )
        new_count = BrandSourceHealth.consecutive_failures + 1
        stmt = stmt.on_conflict_do_update(
            index_elements=["source"],
            set_={
                "consecutive_failures": new_count,
                # computed from the incremented count, in SQL, so concurrent writers agree
                "status": _status_sql(new_count),
                "last_failure_at": now, "last_error": error, "label": source.label, "updated_at": now,
            },
        )
    await db.execute(stmt)
    await db.commit()


def _status_sql(count_expr):
    from sqlalchemy import case
    return case((count_expr >= DOWN_AFTER, "down"), (count_expr >= DEGRADED_AFTER, "degraded"), else_="healthy")


async def list_health(db: AsyncSession) -> list[dict]:
    """One entry per registered source, including ones never called yet."""
    rows = {r.source: r for r in (await db.execute(select(BrandSourceHealth).execution_options(populate_existing=True))).scalars().all()}
    out = []
    for src in [*SOURCES, *EXTRA_HEALTH_SOURCES]:
        r = rows.get(src.name)
        if r is None and getattr(src, "optional", False):
            continue
        out.append({
            "source": src.name, "label": src.label,
            "status": r.status if r else "unknown",
            "consecutive_failures": r.consecutive_failures if r else 0,
            "last_success_at": r.last_success_at if r else None,
            "last_failure_at": r.last_failure_at if r else None,
            "last_error": r.last_error if r else None,
            "last_latency_ms": r.last_latency_ms if r else None,
            "retry_after": breaker_open_until(r),
        })
    return out


# ── Entry point used by the scan ─────────────────────────────────────────────

async def fetch_ct_candidates(db: AsyncSession, tokens: list[str], since: datetime) -> dict[str, dict]:
    """Merged results from every source that answered. Raises SourceUnavailable
    only when none did, with a customer-safe message; partial success returns
    what it got."""
    merged: dict[str, dict] = {}
    problems: list[str] = []
    succeeded = 0

    for source in SOURCES:
        row = await _get_row(db, source.name)
        until = breaker_open_until(row)
        if until is not None:
            # Relative time, not a clock time: the UI renders in the viewer's timezone.
            minutes = max(1, round((until - _now()).total_seconds() / 60))
            problems.append(f"{source.label} is temporarily unavailable (next attempt in about {minutes} min)")
            continue

        started = _now()
        try:
            hits = await asyncio.wait_for(source.fetch(tokens, since), timeout=TOTAL_BUDGET_SECONDS)
        except SourceError as e:
            reason = e.reason
        except asyncio.TimeoutError:
            reason = "timed out"
        else:
            await _record(db, source, ok=True, latency_ms=int((_now() - started).total_seconds() * 1000), error=None)
            succeeded += 1
            for host, meta in hits.items():
                prev = merged.get(host)
                if not prev or meta["issued_at"] > prev["issued_at"]:
                    merged[host] = meta
            continue

        log.warning("Brand Guard source %s failed: %s", source.name, reason)
        await _record(db, source, ok=False, latency_ms=None, error=reason)
        problems.append(f"{source.label} lookup failed ({reason})")

    if succeeded == 0:
        raise SourceUnavailable("; ".join(problems) or "no certificate source is configured")
    return merged
