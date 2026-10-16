"""
Continuous Threat Detection & Response — CloudTrail half. See
ITDR_DESIGN.md for the full design; this module implements Section 4.1
(ingestion) and Section 5.1 (the one v1 detection rule).

The rule: a principal with an entry in CloudPrivEscPath.technique_chain
actually CALLS that exact IAM action, per CloudTrail. High-confidence by
construction — nobody accidentally calls iam:PassRole on a role they've
never touched. Because the rule is already scoped to known escalation
actions and known principals, it doesn't need the separate noise-gating
policy ITDR_DESIGN.md Section 5.2 describes for Auth0's broader signals
(e.g. breached-password detection, which fires for any employee) — this
rule is narrow by construction.

cloudtrail:LookupEvents reads the account's built-in 90-day management-
event history — no Trail, no S3 bucket, no new customer infrastructure,
just one more permission on the already-granted read-only role. Existing
connections need their deployed CloudFormation stack updated before this
works; a missing permission surfaces as a normal ClientError, handled the
same honest-failure way as the rest of this codebase (threat_detection_
status/threat_detection_error), not a crash.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import CloudAccountConnection, CloudPrivEscPath, Engagement, Finding, Investigation, InvestigationEvent
from app.services.attack_technique_mapping import attack_techniques_for_actions
from app.services.identity_resolution_service import resolve_or_create_actor

_log = logging.getLogger(__name__)

# How far back to look on a connection's very first poll — after that,
# last_threat_poll_at drives the window, so this only matters once.
_INITIAL_LOOKBACK = timedelta(hours=24)


def _extract_principal_arn(event_detail: dict) -> str | None:
    """CloudTrail's userIdentity.arn for an assumed-role session is a
    session-specific STS ARN (arn:aws:sts::...:assumed-role/Name/session-id),
    not the underlying IAM role ARN CloudPrivEscPath stores. sessionIssuer
    .arn is the documented field for "which role was actually assumed,"
    regardless of session name — that's what needs to match."""
    user_identity = event_detail.get("userIdentity", {}) or {}
    if user_identity.get("type") == "AssumedRole":
        return (user_identity.get("sessionContext", {}) or {}).get("sessionIssuer", {}).get("arn")
    return user_identity.get("arn")


_EMAIL_SHAPE_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _extract_sso_session_email(event_detail: dict) -> str | None:
    """Real AWS SSO / IAM Identity Center deployments set the assumed-
    role session name to the human's own UPN/email by convention — it's
    the last path segment of userIdentity.arn itself (the session-specific
    STS ARN, NOT sessionIssuer.arn above, which only names the role).
    Zero new API calls: event_detail is already fetched for the
    escalation-detection rule this module exists for. Returns None unless
    the session name genuinely looks like an email — never a guess dressed
    up as a match (Coverage Map plan phishing transformation, Phase 7)."""
    user_identity = event_detail.get("userIdentity", {}) or {}
    if user_identity.get("type") != "AssumedRole":
        return None
    arn = user_identity.get("arn") or ""
    session_name = arn.rsplit("/", 1)[-1] if "/" in arn else ""
    if session_name and _EMAIL_SHAPE_RE.match(session_name):
        return session_name.lower()
    return None


def _lookup_cloudtrail_events_sync(
    role_arn: str, external_id: str, event_name: str, start_time: datetime,
) -> list[dict]:
    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=role_arn, RoleSessionName="sentinel-command-threat-detection",
        ExternalId=external_id, DurationSeconds=900,
    )["Credentials"]
    cloudtrail = boto3.client(
        "cloudtrail",
        region_name=settings.command_aws_default_region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    events: list[dict] = []
    paginator = cloudtrail.get_paginator("lookup_events")
    for page in paginator.paginate(
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
        StartTime=start_time,
    ):
        events.extend(page.get("Events", []))
    return events


async def _record_escalation_event(
    db: AsyncSession, tenant_id: uuid.UUID, engagement_id: uuid.UUID,
    principal_arn: str, action: str, raw_event: dict,
    principal_email: str | None = None, email_provenance: str | None = None,
) -> None:
    event_id = raw_event["EventId"]
    existing = await db.scalar(
        select(InvestigationEvent).where(
            InvestigationEvent.tenant_id == tenant_id,
            InvestigationEvent.source == "cloudtrail",
            InvestigationEvent.event_id == event_id,
        )
    )
    if existing:
        return  # already recorded — overlapping poll windows are expected

    actor = await resolve_or_create_actor(
        db, tenant_id, "aws_iam", principal_arn, email=principal_email, email_provenance=email_provenance,
    )

    investigation = await db.scalar(
        select(Investigation).where(
            Investigation.tenant_id == tenant_id,
            Investigation.actor_id == actor.id,
            Investigation.dismissed_at.is_(None),
        )
    )
    occurred_at = raw_event["EventTime"]
    if not investigation:
        investigation = Investigation(
            id=uuid.uuid4(), tenant_id=tenant_id, actor_id=actor.id,
            status="confirmed", last_activity_at=occurred_at,
        )
        db.add(investigation)
        await db.flush()
    else:
        investigation.last_activity_at = occurred_at

    db.add(InvestigationEvent(
        id=uuid.uuid4(), tenant_id=tenant_id, investigation_id=investigation.id,
        source="cloudtrail", event_id=event_id, action_or_event_type=action,
        occurred_at=occurred_at, raw_detail=json.dumps(raw_event, default=str),
    ))

    # Reuses the existing Finding infrastructure (Overview feed, per-
    # engagement findings endpoint) rather than building a parallel
    # display system — see ITDR_DESIGN.md Section 9. check_id carries the
    # raw IAM action so attack_technique_mapping can tag it at read time.
    techniques = attack_techniques_for_actions([action])
    db.add(Finding(
        id=uuid.uuid4(), tenant_id=tenant_id, engagement_id=engagement_id,
        asset_id=None, tier="threat", severity="critical",
        title=f"Known escalation action invoked: {action} by {principal_arn}",
        status="open", check_id=action,
        detail=f"{principal_arn} called {action}, a privilege-escalation action already known from the IAM Privilege-Escalation Graph.",
        remediation_guidance="Confirm this was expected activity. If not, revoke the principal's credentials and review what it accessed.",
    ))
    _log.warning(
        "Threat detection: escalation action invoked: tenant_id=%s principal=%s action=%s",
        tenant_id, principal_arn, action,
    )


async def poll_connection_for_escalation_activity(db: AsyncSession, connection: CloudAccountConnection) -> None:
    """One connection's poll pass. Never raises — failures (most commonly
    a missing cloudtrail:LookupEvents permission on an older deployed
    role) are captured into threat_detection_status/threat_detection_error,
    the same honest-failure pattern as the regular scan pipeline."""
    result = await db.execute(
        select(CloudPrivEscPath).where(CloudPrivEscPath.tenant_id == connection.tenant_id)
    )
    paths = result.scalars().all()
    if not paths:
        return  # nothing known to watch for yet — not an error

    principals_by_action: dict[str, set[str]] = {}
    for path in paths:
        for action in path.technique_chain:
            principals_by_action.setdefault(action, set()).add(path.source_principal_arn)

    start_time = connection.last_threat_poll_at or (datetime.now(timezone.utc) - _INITIAL_LOOKBACK)
    poll_time = datetime.now(timezone.utc)

    try:
        for action, principals in principals_by_action.items():
            raw_events = await asyncio.to_thread(
                _lookup_cloudtrail_events_sync, connection.role_arn, connection.external_id, action, start_time,
            )
            for raw_event in raw_events:
                event_detail = json.loads(raw_event["CloudTrailEvent"])
                principal_arn = _extract_principal_arn(event_detail)
                if principal_arn not in principals:
                    continue
                sso_email = _extract_sso_session_email(event_detail)
                await _record_escalation_event(
                    db, connection.tenant_id, connection.engagement_id, principal_arn, action, raw_event,
                    principal_email=sso_email, email_provenance="sso_session" if sso_email else None,
                )
    except (ClientError, BotoCoreError) as e:
        _log.warning("Threat detection poll failed: connection_id=%s error=%s", connection.id, e)
        connection.threat_detection_status = "failed"
        connection.threat_detection_error = str(e)
        await db.commit()
        return

    connection.last_threat_poll_at = poll_time
    connection.threat_detection_status = "success"
    connection.threat_detection_error = None
    await db.commit()


async def poll_all_due_connections_for_threats(db: AsyncSession) -> int:
    """Scheduler entry point — mirrors cloud_scan_service.rescan_all_due_
    connections' shape, but additionally requires the connection's
    engagement to have opted into scope.continuous_activity_monitoring
    (ITDR_DESIGN.md Section 3) — connecting an account for posture
    scanning is not the same consent as ongoing behavioral observation of
    who does what, so this does not ride on the existing cloud-scan
    authorization silently."""
    result = await db.execute(
        select(CloudAccountConnection, Engagement)
        .join(Engagement, CloudAccountConnection.engagement_id == Engagement.id)
        .where(CloudAccountConnection.status == "connected", Engagement.status == "active")
    )
    rows = result.all()
    polled = 0
    for connection, engagement in rows:
        if not (engagement.scope or {}).get("continuous_activity_monitoring"):
            continue
        try:
            await poll_connection_for_escalation_activity(db, connection)
        except Exception:
            _log.exception("Scheduled threat-detection poll failed unexpectedly: connection_id=%s", connection.id)
        polled += 1
    return polled
