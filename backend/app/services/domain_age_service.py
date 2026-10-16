"""
Domain registration-date lookup, shared infrastructure for Brand Guard.

RDAP (via the IANA bootstrap file) for every TLD except `.za`, which has no
RDAP coverage — those fall back to a raw-socket legacy WHOIS query against
whois.registry.net.za. Every failure degrades to "unknown" (None); a lookup
never raises, because registration age is one signal among many and must not
abort a scan.

NOTE: link_risk_service.py (Real-Threat Reports) contains an identical copy of
this logic. It is duplicated here only because that module and its models were
not yet committed when Brand Guard first landed; once it is, it should import
from this module instead (tracked in BRAND_GUARD_PLAN.md).
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx

_log = logging.getLogger(__name__)

_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_RDAP_BOOTSTRAP_TTL_DAYS = 7
_ZA_WHOIS_HOST = "whois.registry.net.za"
_ZA_WHOIS_PORT = 43
_ZA_CREATION_DATE_RE = re.compile(r"Creation Date:\s*(\d{4}-\d{2}-\d{2})", re.I)

_rdap_bootstrap_cache: dict[str, str] | None = None
_rdap_bootstrap_fetched_at: datetime | None = None


async def _rdap_bootstrap(client: httpx.AsyncClient) -> dict[str, str]:
    global _rdap_bootstrap_cache, _rdap_bootstrap_fetched_at
    now = datetime.now(timezone.utc)
    if _rdap_bootstrap_cache is not None and _rdap_bootstrap_fetched_at is not None:
        if (now - _rdap_bootstrap_fetched_at).days < _RDAP_BOOTSTRAP_TTL_DAYS:
            return _rdap_bootstrap_cache
    try:
        resp = await client.get(_RDAP_BOOTSTRAP_URL)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as e:
        _log.warning("RDAP bootstrap fetch failed: %s", e)
        return _rdap_bootstrap_cache or {}

    mapping: dict[str, str] = {}
    for entry in data.get("services", []):
        if len(entry) < 2:
            continue
        tlds, bases = entry[0], entry[1]
        base = bases[0] if bases else None
        if not base:
            continue
        for tld in tlds:
            mapping[tld.lower()] = base.rstrip("/")
    _rdap_bootstrap_cache = mapping
    _rdap_bootstrap_fetched_at = now
    return mapping


@dataclass
class RegistrationInfo:
    """What a registry says about a domain. Only `registered_at` is guaranteed useful; the rest depend on the registry
    (RDAP carries them, the .za WHOIS fallback does not)."""
    registered_at: datetime | None = None
    source: str | None = None                 # "rdap" | "za_whois"
    registrar: str | None = None
    reregistered_at: datetime | None = None   # RDAP "reregistration" event: the name lapsed and was registered again
    last_changed_at: datetime | None = None
    expires_at: datetime | None = None

    def details(self) -> dict:
        """The JSON-safe extras, as stored in the shared cache and on a candidate."""
        iso = lambda d: d.isoformat() if d else None          # noqa: E731
        return {"registrar": self.registrar, "reregistered_at": iso(self.reregistered_at),
                "last_changed_at": iso(self.last_changed_at), "expires_at": iso(self.expires_at)}


def _parse_dt(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _registrar_name(data: dict) -> str | None:
    for entity in data.get("entities", []) or []:
        if "registrar" not in [r.lower() for r in entity.get("roles", []) or []]:
            continue
        for item in (entity.get("vcardArray") or [None, []])[1] or []:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn" and isinstance(item[3], str) and item[3].strip():
                return item[3].strip()[:160]
        for pid in entity.get("publicIds", []) or []:
            if isinstance(pid, dict) and pid.get("identifier"):
                return f"IANA registrar {pid['identifier']}"
    return None


def parse_rdap(data: dict) -> RegistrationInfo:
    """Pure: an RDAP domain object -> RegistrationInfo. Tolerant of missing or malformed members."""
    events: dict[str, str] = {}
    for event in data.get("events", []) or []:
        if isinstance(event, dict) and event.get("eventAction") and event.get("eventDate"):
            events.setdefault(str(event["eventAction"]).lower(), event["eventDate"])
    return RegistrationInfo(
        registered_at=_parse_dt(events.get("registration")), source="rdap", registrar=_registrar_name(data),
        reregistered_at=_parse_dt(events.get("reregistration")), last_changed_at=_parse_dt(events.get("last changed")),
        expires_at=_parse_dt(events.get("expiration")),
    )


async def _lookup_rdap_info(client: httpx.AsyncClient, apex_domain: str) -> RegistrationInfo | None:
    tld = apex_domain.rsplit(".", 1)[-1]
    base = (await _rdap_bootstrap(client)).get(tld)
    if not base:
        _log.info("No RDAP endpoint known for TLD=%s (apex_domain=%s) — registration date unknown", tld, apex_domain)
        return None
    try:
        resp = await client.get(f"{base}/domain/{apex_domain}")
    except httpx.HTTPError as e:
        _log.info("RDAP lookup failed for apex_domain=%s: %s", apex_domain, e)
        return None
    if resp.status_code != 200:
        return None
    try:
        return parse_rdap(resp.json())
    except ValueError:
        return None


async def _lookup_rdap(client: httpx.AsyncClient, apex_domain: str) -> datetime | None:
    info = await _lookup_rdap_info(client, apex_domain)
    return info.registered_at if info else None


async def _lookup_za_whois(apex_domain: str) -> datetime | None:
    # Hard timeouts on connect and read: a hanging resolve can otherwise outlast
    # the socket's own timeout.
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(_ZA_WHOIS_HOST, _ZA_WHOIS_PORT), timeout=10)
        writer.write(f"{apex_domain}\r\n".encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(-1), timeout=10)
        writer.close()
        await writer.wait_closed()
    except (OSError, asyncio.TimeoutError) as e:
        _log.info("za WHOIS lookup failed for apex_domain=%s: %s", apex_domain, e)
        return None

    m = _ZA_CREATION_DATE_RE.search(raw.decode(errors="replace"))
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


async def lookup_registration_date(client: httpx.AsyncClient, apex_domain: str) -> tuple[datetime | None, str | None]:
    """(registered_at, source) — source is "rdap", "za_whois", or None."""
    if apex_domain.endswith(".za"):
        registered_at = await _lookup_za_whois(apex_domain)
        return registered_at, ("za_whois" if registered_at else None)
    registered_at = await _lookup_rdap(client, apex_domain)
    return registered_at, ("rdap" if registered_at else None)


async def lookup_registration_details(client: httpx.AsyncClient, apex_domain: str) -> RegistrationInfo | None:
    """Like lookup_registration_date, but keeps what the registry says beyond the creation date (registrar,
    re-registration, last change, expiry). None when nothing useful was learned. Never raises."""
    if apex_domain.endswith(".za"):
        registered_at = await _lookup_za_whois(apex_domain)
        return RegistrationInfo(registered_at=registered_at, source="za_whois") if registered_at else None
    info = await _lookup_rdap_info(client, apex_domain)
    return info if info and info.registered_at else None
