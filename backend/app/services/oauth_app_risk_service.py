"""
Sentinel Command Third-Party OAuth App Risk (OAUTH_APP_RISK_DESIGN.md).
Microsoft 365/Entra ID first — Microsoft Graph exposes tenant-wide list
calls for OAuth grants (a handful of requests cover the whole org), unlike
Google Workspace's documented per-user token-listing approach, which is
structurally more expensive at scale. Google Workspace is the designed
fast-follow, not built here (Section 4).

Reads only `oauth2PermissionGrants` — user-consented delegated grants, the
"an employee personally authorized ShadyApp to read their mailbox" shadow-IT
scenario. Admin-consented application-level grants
(`servicePrincipals/{id}/appRoleAssignedTo`) are a real, separate signal not
covered by this pass — noted, not silently conflated with delegated grants.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Engagement, Finding, OAuthAppConnection, OAuthGrant
from app.services.crypto_service import decrypt_secret
from app.services.identity_resolution_service import resolve_or_create_actor

_log = logging.getLogger(__name__)

_LOGIN_BASE = "https://login.microsoftonline.com"
_GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# Curated, not source-verified — neither Microsoft nor Google publishes an
# official "these scopes are dangerous" list (OAUTH_APP_RISK_DESIGN.md
# Section 3.3). Matched by substring against a Graph delegated-permission
# scope string, case-insensitive. Not exhaustive; the same "curated, not
# exhaustive" posture already carried by exposure_scan_service.py's port
# list and takeover fingerprints.
_HIGH_RISK_SCOPE_PATTERNS = ["directory.readwrite", "user.readwrite.all", "mail.readwrite", "files.readwrite.all", "sites.readwrite.all"]
_MEDIUM_RISK_SCOPE_PATTERNS = ["mail.send", "mail.read", "files.read.all", "sites.read.all", "contacts.readwrite"]


def _classify_risk(scopes: list[str]) -> str:
    lowered = [s.lower() for s in scopes]
    if any(pattern in scope for scope in lowered for pattern in _HIGH_RISK_SCOPE_PATTERNS):
        return "critical" if any("directory.readwrite" in s or "user.readwrite.all" in s for s in lowered) else "high"
    if any(pattern in scope for scope in lowered for pattern in _MEDIUM_RISK_SCOPE_PATTERNS):
        return "medium"
    return "low"


async def _get_graph_token(ms_tenant_id: str, client_id: str, client_secret: str) -> str:
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            f"{_LOGIN_BASE}/{ms_tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials", "client_id": client_id,
                "client_secret": client_secret, "scope": "https://graph.microsoft.com/.default",
            },
        )
    if resp.status_code >= 400:
        raise ConnectionError(f"Could not obtain a Graph API token ({resp.status_code}): {resp.text[:300]}")
    return resp.json()["access_token"]


async def verify_connection(connection: OAuthAppConnection) -> bool:
    """Confirms the credential can actually reach Graph — same
    honest-verification pattern as CloudAccountConnection's role-assumption
    check, not just accepting whatever the customer typed in."""
    try:
        secret = decrypt_secret(connection.encrypted_client_secret)
        await _get_graph_token(connection.ms_tenant_id, connection.ms_client_id, secret)
        return True
    except Exception as e:
        _log.warning("OAuth app connection verification failed: connection_id=%s error=%s", connection.id, e)
        return False


async def _fetch_oauth_grants(ms_tenant_id: str, client_id: str, client_secret: str) -> list[dict]:
    token = await _get_graph_token(ms_tenant_id, client_id, client_secret)
    headers = {"Authorization": f"Bearer {token}"}

    async with httpx.AsyncClient(timeout=20.0) as client:
        grants_resp = await client.get(f"{_GRAPH_BASE}/oauth2PermissionGrants", headers=headers)
        if grants_resp.status_code >= 400:
            raise ConnectionError(f"Could not list oauth2PermissionGrants ({grants_resp.status_code}): {grants_resp.text[:300]}")
        raw_grants = grants_resp.json().get("value", [])

        # Admin-consented-for-all grants have no single grantee — out of
        # scope for this pass (module docstring). Filtered out *before*
        # resolving names/ids below, not after, so a grant that's about to
        # be discarded never costs an extra Graph call resolving it.
        attributable_grants = [g for g in raw_grants if g.get("principalId")]

        # Batch-resolve distinct servicePrincipal (app) and user (grantee) ids
        # into names/emails — the raw grants only carry opaque GUIDs.
        app_ids = {g["clientId"] for g in attributable_grants if g.get("clientId")}
        user_ids = {g["principalId"] for g in attributable_grants}

        app_names: dict[str, str] = {}
        app_publishers: dict[str, dict] = {}
        for app_id in app_ids:
            resp = await client.get(f"{_GRAPH_BASE}/servicePrincipals/{app_id}", headers=headers)
            if resp.status_code < 400:
                body = resp.json()
                app_names[app_id] = body.get("displayName", app_id)
                verified_publisher = body.get("verifiedPublisher") or {}
                app_publishers[app_id] = {
                    "verified": bool(verified_publisher.get("verifiedPublisherId")),
                    "name": verified_publisher.get("displayName") or body.get("publisherName"),
                }

        user_emails: dict[str, str] = {}
        for user_id in user_ids:
            resp = await client.get(f"{_GRAPH_BASE}/users/{user_id}", headers=headers)
            if resp.status_code < 400:
                body = resp.json()
                user_emails[user_id] = body.get("mail") or body.get("userPrincipalName") or user_id

    grants = []
    for g in attributable_grants:
        principal_id = g["principalId"]
        client_id_ = g.get("clientId")
        scopes = [s for s in (g.get("scope") or "").split(" ") if s]
        publisher = app_publishers.get(client_id_, {})
        grants.append({
            "grantee_principal": user_emails.get(principal_id, principal_id),
            "app_name": app_names.get(client_id_, client_id_),
            "app_client_id": client_id_,
            "scopes": scopes,
            "publisher_verified": publisher.get("verified", False),
            "publisher_name": publisher.get("name"),
        })
    return grants


async def run_oauth_risk_scan(db: AsyncSession, engagement: Engagement, connection: OAuthAppConnection) -> list[Finding]:
    """Never raises — a failed scan is recorded via last_scan_status/
    last_scan_error on the connection, the same honest-failure pattern
    every other connection type in this codebase already uses."""
    findings: list[Finding] = []
    try:
        secret = decrypt_secret(connection.encrypted_client_secret)
        grants = await _fetch_oauth_grants(connection.ms_tenant_id, connection.ms_client_id, secret)
    except Exception as e:
        _log.warning("OAuth risk scan failed: connection_id=%s error=%s", connection.id, e)
        connection.last_scan_status = "failed"
        connection.last_scan_error = str(e)
        await db.commit()
        return []

    for grant in grants:
        risk_tier = _classify_risk(grant["scopes"])
        db.add(OAuthGrant(
            id=uuid.uuid4(), tenant_id=connection.tenant_id, engagement_id=engagement.id,
            connection_id=connection.id, grantee_principal=grant["grantee_principal"],
            app_name=grant["app_name"], app_client_id=grant["app_client_id"],
            scopes=grant["scopes"], risk_tier=risk_tier,
            publisher_verified=grant.get("publisher_verified", False),
            publisher_name=grant.get("publisher_name"),
        ))

        # Same identity-resolution reuse as ITDR: a grantee's email is
        # matched against the same Actor an AWS IAM principal might already
        # resolve to, so one person can show as one node with edges to
        # both their IAM path and their OAuth grants (OAUTH_APP_RISK_DESIGN.md
        # Section 6). Resolution failure here must never break the scan.
        try:
            await resolve_or_create_actor(db, connection.tenant_id, "microsoft365", grant["grantee_principal"], email=grant["grantee_principal"])
        except Exception:
            _log.exception("Actor resolution failed for OAuth grantee: tenant_id=%s", connection.tenant_id)

        if risk_tier in ("critical", "high"):
            finding = Finding(
                id=uuid.uuid4(), tenant_id=connection.tenant_id, engagement_id=engagement.id, asset_id=None,
                tier="oauth_risk", severity=risk_tier,
                title=f"{grant['app_name']} has {risk_tier}-risk access, granted by {grant['grantee_principal']}",
                status="open", check_id=grant["app_client_id"],
                detail=f"{grant['grantee_principal']} granted {grant['app_name']} the following scopes: {', '.join(grant['scopes'])}.",
                remediation_guidance="Confirm this app is still needed and this scope is the minimum required; revoke the grant in the Entra ID admin center if not.",
            )
            db.add(finding)
            findings.append(finding)

    connection.last_scanned_at = datetime.now(timezone.utc)
    connection.last_scan_status = "success"
    connection.last_scan_error = None
    await db.commit()
    return findings


async def poll_all_due_oauth_connections(db: AsyncSession) -> int:
    """Scheduler entry point — mirrors cloud_scan_service.rescan_all_due_
    connections exactly: every connected+active connection gets rescanned
    each time the job fires, cadence controlled by the job's own wake
    interval (command_rescan_interval), not a separate per-connection
    due-check. One connection's failure never blocks the batch."""
    result = await db.execute(
        select(OAuthAppConnection, Engagement)
        .join(Engagement, OAuthAppConnection.engagement_id == Engagement.id)
        .where(OAuthAppConnection.status == "connected", Engagement.status == "active")
    )
    rows = result.all()
    scanned = 0
    for connection, engagement in rows:
        try:
            await run_oauth_risk_scan(db, engagement, connection)
        except Exception:
            _log.exception("Scheduled OAuth risk scan failed unexpectedly: connection_id=%s", connection.id)
        scanned += 1
    return scanned
