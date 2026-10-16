"""The network half of takedown routing: read the registrar's and the host's public abuse contacts from RDAP.

Only ever asks public registries: the RDAP server the IANA bootstrap names for the TLD, and rdap.org (which redirects to the right regional
registry) for a server address. Addresses that are not public are never sent anywhere. Never raises: a failed lookup just means that
route comes back as a suggestion the person must complete by hand."""
from __future__ import annotations

import logging

import httpx

from app.services import brand_takedown as td
from app.services.domain_age_service import _rdap_bootstrap

log = logging.getLogger(__name__)
TIMEOUT = httpx.Timeout(8.0)
RDAP_IP = "https://rdap.org/ip/"


async def _get_json(client: httpx.AsyncClient, url: str) -> dict:
    try:
        r = await client.get(url, headers={"Accept": "application/rdap+json, application/json"})
        return r.json() if r.status_code == 200 else {}
    except (httpx.HTTPError, ValueError) as e:
        log.info("RDAP lookup failed for %s: %s", url, e)
        return {}


async def discover(domain: str, enrichment: dict | None) -> list[dict]:
    e = enrichment or {}
    registrar = (e.get("registration") or {}).get("registrar")
    registrar_abuse: dict = {}
    host_abuse: dict = {}
    ip = next((a for a in (e.get("a") or []) if isinstance(a, str) and td.is_public_ip(a)), None)
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        if not domain.endswith(".za"):
            try:
                base = (await _rdap_bootstrap(client)).get(domain.rsplit(".", 1)[-1])
            except Exception:                          # the bootstrap list is best-effort
                base = None
            if base:
                data = await _get_json(client, f"{base}/domain/{domain}")
                registrar_abuse = td.abuse_contacts(data)
                registrar = td.registrar_name(data) or registrar
        if ip:
            host_abuse = td.abuse_contacts(await _get_json(client, f"{RDAP_IP}{ip}"))
    return td.routes(domain=domain, registrar=registrar, registrar_abuse=registrar_abuse, host_abuse=host_abuse, host_ip=ip, nameservers=e.get("ns") or e.get("nameservers"))
