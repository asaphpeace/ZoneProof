"""
Sentinel Command Tier 1 — External Exposure & DNS Hygiene.

Two passive-first checks against an ownership-verified Domain, both scoped
to infrastructure the tenant has already proven they own — same trust
boundary subdomain_discovery_service.py's active-probing gate already
established, reused here rather than re-litigated:

  1. Subdomain takeover — a dangling CNAME pointing at a cloud provider
     hostname the tenant no longer controls (a classic, well-documented
     attack: register the same name on the provider, and the subdomain now
     serves the attacker's content under the tenant's own domain). Detection
     is fingerprint-based (public, well-known signatures — see EdOverflow's
     "Can I take over XYZ?" project), not exhaustive; a fingerprint miss is
     a known industry-wide limitation of this technique, not unique to this
     implementation.

  2. Open ports — a narrow, curated TCP connect-scan of the domain's own
     apex IP for services that should almost never be directly
     internet-facing (databases, admin protocols). Deliberately NOT a full
     port sweep and NOT run against discovered subdomains' IPs — scope is
     kept to the apex the tenant explicitly owns and verified, not an
     open-ended scan of whatever else shares infrastructure nearby.

Subdomain discovery itself is NOT reimplemented here — reuses
subdomain_discovery_service.discover_subdomains(allow_active=True), which
already gates active probing on ownership_verified.
"""
from __future__ import annotations

import asyncio
import logging
import uuid

import dns.exception
import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Domain, Engagement, Finding
from app.services.dns_resolver import resolver
from app.services.exploitability_service import score_and_stamp
from app.services.finding_reconciliation import reconcile_findings
from app.services.subdomain_discovery_service import discover_subdomains

_log = logging.getLogger(__name__)

# Public, well-known "Can I take over XYZ?" style fingerprints — CNAME
# suffix -> a substring that appears on that provider's own "nothing here"
# page. Not exhaustive; providers change these pages over time.
_TAKEOVER_FINGERPRINTS: dict[str, str] = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "no such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "s3-website": "NoSuchBucket",
    "azurewebsites.net": "Web Site not found",
    "cloudapp.net": "Web Site not found",
    "myshopify.com": "Sorry, this shop is currently unavailable",
    "surge.sh": "project not found",
    "fastly.net": "Fastly error: unknown domain",
    "wordpress.com": "Do you want to register",
    "zendesk.com": "Help Center Closed",
}

_HTTP_TIMEOUT = 8.0

# Ports that are meaningful attack-surface signals if directly
# internet-facing — databases and remote-admin protocols, not a general
# service-discovery sweep.
_EXPOSED_PORT_CHECKS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    2375: "Docker API (unauthenticated)",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}
_PORT_CONNECT_TIMEOUT = 4.0


async def _resolve_cname(hostname: str) -> str | None:
    try:
        answers = await resolver.resolve(hostname, "CNAME")
        return str(answers[0].target).rstrip(".").lower()
    except dns.exception.DNSException:
        return None


async def _check_takeover_fingerprint(hostname: str, cname_target: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(f"http://{hostname}/", headers={"Host": hostname})
    except Exception:
        return None  # unreachable — not enough signal to call this a takeover risk

    body = resp.text[:20000]  # fingerprints all appear well within the first chunk of the page
    for suffix, fingerprint in _TAKEOVER_FINGERPRINTS.items():
        if suffix in cname_target and fingerprint in body:
            return {"cname_target": cname_target, "provider_suffix": suffix, "fingerprint": fingerprint}
    return None


async def check_subdomain_takeover(hostnames: list[str]) -> list[dict]:
    """Returns one entry per hostname found to have a dangling CNAME
    matching a known-vulnerable provider fingerprint."""
    async def _check_one(hostname: str) -> dict | None:
        cname = await _resolve_cname(hostname)
        if not cname:
            return None
        if not any(suffix in cname for suffix in _TAKEOVER_FINGERPRINTS):
            return None
        match = await _check_takeover_fingerprint(hostname, cname)
        if match:
            return {"hostname": hostname, **match}
        return None

    results = await asyncio.gather(*(_check_one(h) for h in hostnames))
    return [r for r in results if r]


def _scan_port_sync(host: str, port: int) -> bool:
    import socket
    try:
        with socket.create_connection((host, port), timeout=_PORT_CONNECT_TIMEOUT):
            return True
    except OSError:
        return False


async def check_open_ports(host: str) -> list[dict]:
    """Returns one entry per port from _EXPOSED_PORT_CHECKS found open on
    the given host."""
    async def _check_one(port: int, label: str) -> dict | None:
        is_open = await asyncio.to_thread(_scan_port_sync, host, port)
        return {"port": port, "service": label} if is_open else None

    results = await asyncio.gather(*(_check_one(p, label) for p, label in _EXPOSED_PORT_CHECKS.items()))
    return [r for r in results if r]


async def run_exposure_scan(db: AsyncSession, engagement: Engagement, domain: Domain) -> list[Finding]:
    if not domain.ownership_verified:
        _log.info("Skipping exposure scan — domain not ownership-verified: domain_id=%s", domain.id)
        return []

    discovered = await discover_subdomains(db, domain, allow_active=True)
    hostnames = [d.hostname for d in discovered] + [domain.name]

    takeover_hits, port_hits = await asyncio.gather(
        check_subdomain_takeover(hostnames),
        check_open_ports(domain.name),
    )

    candidates: list[Finding] = [
        Finding(
            id=uuid.uuid4(),
            tenant_id=domain.tenant_id,
            engagement_id=engagement.id,
            asset_id=None,
            tier="exposure",
            severity="critical",
            title=f"Subdomain takeover risk: {hit['hostname']}",
            status="open",
            check_id=f"EXPOSURE-SUBDOMAIN-TAKEOVER-{hit['hostname']}",
            detail=(
                f"{hit['hostname']} has a dangling CNAME to {hit['cname_target']} "
                f"(a {hit['provider_suffix']} hostname that returns an unclaimed-service page). "
                "An attacker who registers the same name on that provider can serve content "
                "under this domain."
            ),
            remediation_guidance=f"Remove the DNS record for {hit['hostname']}, or reclaim the target resource on {hit['provider_suffix']}.",
        )
        for hit in takeover_hits
    ] + [
        Finding(
            id=uuid.uuid4(),
            tenant_id=domain.tenant_id,
            engagement_id=engagement.id,
            asset_id=None,
            tier="exposure",
            severity="high",
            title=f"{hit['service']} port {hit['port']} is directly internet-facing",
            status="open",
            check_id=f"EXPOSURE-OPEN-PORT-{hit['port']}",
            detail=f"{domain.name}:{hit['port']} ({hit['service']}) accepted a TCP connection from the public internet.",
            remediation_guidance="Restrict this port to a private network or VPN — it should not be reachable directly from the internet.",
        )
        for hit in port_hits
    ]
    for c in candidates:
        score_and_stamp(c)

    # check_id is already host/port-specific (unlike Prowler's), and one
    # engagement is one domain — no separate resource_uid needed.
    return await reconcile_findings(
        db, engagement_id=engagement.id,
        scope=[Finding.tier == "exposure"],
        candidates=candidates,
        key_fn=lambda f: (f.check_id, None),
    )
