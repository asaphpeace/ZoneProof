"""
Identity & Credential Hygiene — MFA/password-policy half (Coverage Map plan
Phase 5). Calls AWS's own IAM credential report (`iam:GenerateCredentialReport`
/ `GetCredentialReport`) against the connected account, using the same
assume-role pattern as threat_detection_service.py's direct boto3 calls
(Prowler/Cloudsplaining instead shell out to their own CLIs, which do their
own role assumption internally — this is Sentinel's own boto3 call, so it
needs to assume the role itself).

The credential report is AWS's authoritative, per-IAM-user view of MFA
status and password age — real evidence, not an inference from other scan
passes. Findings land in the shared Finding table under a new tier
('credential') so they're filterable/labeled distinctly in Findings and
reuse the same reconciliation pipeline every other scan pass already uses.
"""
from __future__ import annotations

import asyncio
import csv
import io
import logging
import time
import uuid
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CloudAccountConnection, CloudAsset, Engagement, Finding
from app.services.aws_iam_identity_lookup import lookup_iam_user_email_tag
from app.services.exploitability_service import score_and_stamp
from app.services.finding_reconciliation import reconcile_findings
from app.services.identity_resolution_service import resolve_or_create_actor

_log = logging.getLogger(__name__)

_MAX_REPORT_POLL_ATTEMPTS = 10
_REPORT_POLL_INTERVAL_SECONDS = 1.0

# AWS's own guidance for password rotation — used as the threshold for a
# "stale password" finding, not an arbitrary number.
_STALE_PASSWORD_DAYS = 90


def _fetch_credential_report_sync(role_arn: str, external_id: str) -> list[dict]:
    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=role_arn, RoleSessionName="sentinel-command-credential-report",
        ExternalId=external_id, DurationSeconds=900,
    )["Credentials"]
    iam = boto3.client(
        "iam",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )

    for _ in range(_MAX_REPORT_POLL_ATTEMPTS):
        resp = iam.generate_credential_report()
        if resp["State"] == "COMPLETE":
            break
        time.sleep(_REPORT_POLL_INTERVAL_SECONDS)
    else:
        raise RuntimeError("Credential report generation did not complete in time")

    report = iam.get_credential_report()
    # boto3 already base64-decodes the blob field into raw bytes.
    return list(csv.DictReader(io.StringIO(report["Content"].decode("utf-8"))))


def _parse_aws_datetime(value: str) -> datetime | None:
    if not value or value in ("N/A", "not_supported"):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S+00:00").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _findings_from_report(rows: list[dict], tenant_id: uuid.UUID, engagement_id: uuid.UUID) -> list[Finding]:
    now = datetime.now(timezone.utc)
    findings: list[Finding] = []

    for row in rows:
        user = row.get("user", "unknown")
        arn = row.get("arn", "")
        password_enabled = (row.get("password_enabled") or "").lower() == "true"
        mfa_active = (row.get("mfa_active") or "").lower() == "true"

        if password_enabled and not mfa_active:
            findings.append(Finding(
                id=uuid.uuid4(), tenant_id=tenant_id, engagement_id=engagement_id, asset_id=None,
                tier="credential", severity="high",
                title=f"{user} has console access with no MFA enabled",
                status="open", check_id="credential_report_mfa_missing", resource_uid=arn,
                detail=f"IAM user {user} ({arn}) can sign in to the AWS console with a password, but has no MFA device active — a leaked or guessed password is enough to log in.",
                remediation_guidance="Require MFA for this user — enable a virtual or hardware MFA device, or enforce it account-wide via an IAM policy condition (aws:MultiFactorAuthPresent).",
            ))

        last_changed = _parse_aws_datetime(row.get("password_last_changed", ""))
        if password_enabled and last_changed:
            age_days = (now - last_changed).days
            if age_days > _STALE_PASSWORD_DAYS:
                findings.append(Finding(
                    id=uuid.uuid4(), tenant_id=tenant_id, engagement_id=engagement_id, asset_id=None,
                    tier="credential", severity="medium",
                    title=f"{user}'s password hasn't been rotated in {age_days} days",
                    status="open", check_id="credential_report_password_stale", resource_uid=arn,
                    detail=f"IAM user {user} ({arn}) last changed their password {age_days} days ago — over the {_STALE_PASSWORD_DAYS}-day guideline.",
                    remediation_guidance="Rotate this user's password, or move to an SSO-based identity provider that doesn't rely on long-lived IAM passwords at all.",
                ))

        for slot in ("1", "2"):
            findings.extend(_access_key_findings_for_slot(row, slot, arn, user, tenant_id, engagement_id, now))

    return findings


def _access_key_findings_for_slot(
    row: dict, slot: str, arn: str, user: str,
    tenant_id: uuid.UUID, engagement_id: uuid.UUID, now: datetime,
) -> list[Finding]:
    """Access-key rotation/last-used evidence — previously parsed as part
    of the same CSV row but never checked. A live, forgotten access key is
    a materially worse real-world risk than password age (most real AWS
    breaches trace back to a leaked long-lived key, not a console
    password), so this is the single highest-value addition from the
    Phase 36 AWS data-discard audit."""
    active = (row.get(f"access_key_{slot}_active") or "").lower() == "true"
    if not active:
        return []

    findings: list[Finding] = []
    # resource_uid stays the bare IAM user ARN (not a slot-suffixed
    # variant) — this is what makes credential-tier findings reliably
    # ARN-matchable to a graph node's own id (Phase 36f). check_id carries
    # the per-slot distinction instead, which also keeps reconcile_findings'
    # (check_id, resource_uid) dedup key from colliding two real, distinct
    # findings (key 1 and key 2) into one.

    last_rotated = _parse_aws_datetime(row.get(f"access_key_{slot}_last_rotated", ""))
    if last_rotated:
        rotation_age_days = (now - last_rotated).days
        if rotation_age_days > _STALE_PASSWORD_DAYS:
            findings.append(Finding(
                id=uuid.uuid4(), tenant_id=tenant_id, engagement_id=engagement_id, asset_id=None,
                tier="credential", severity="medium",
                title=f"{user}'s access key {slot} hasn't been rotated in {rotation_age_days} days",
                status="open", check_id=f"credential_report_access_key_{slot}_stale", resource_uid=arn,
                detail=f"IAM user {user}'s access key (slot {slot}) was last rotated {rotation_age_days} days ago — over the {_STALE_PASSWORD_DAYS}-day guideline.",
                remediation_guidance="Rotate this access key, or replace it with a short-lived credential (an assumed role / SSO session) if the workload can support it.",
                extra={"source": "credential_report", "key_slot": slot, "last_rotated": row.get(f"access_key_{slot}_last_rotated")},
                extra_populated_at=now,
            ))

    last_used_raw = row.get(f"access_key_{slot}_last_used_date", "")
    last_used = _parse_aws_datetime(last_used_raw)
    never_used = last_used_raw in ("N/A", "", None)
    unused_age_days = (now - last_used).days if last_used else None
    if never_used or (unused_age_days is not None and unused_age_days > _STALE_PASSWORD_DAYS):
        findings.append(Finding(
            id=uuid.uuid4(), tenant_id=tenant_id, engagement_id=engagement_id, asset_id=None,
            tier="credential", severity="high",
            title=f"{user}'s access key {slot} is active but {'has never been used' if never_used else f'has not been used in {unused_age_days} days'}",
            status="open", check_id=f"credential_report_access_key_{slot}_unused", resource_uid=arn,
            detail=(
                f"IAM user {user}'s access key (slot {slot}) is still active but {'has never been used since creation' if never_used else f'was last used {unused_age_days} days ago'} — a live, forgotten credential is a real, standing risk even if nothing has gone wrong with it yet."
            ),
            remediation_guidance="Deactivate or delete this access key if it's genuinely unused, or confirm the workload that owns it and rotate it if it's still needed.",
            extra={
                "source": "credential_report", "key_slot": slot,
                "last_used_date": row.get(f"access_key_{slot}_last_used_date"),
                "last_used_region": row.get(f"access_key_{slot}_last_used_region"),
                "last_used_service": row.get(f"access_key_{slot}_last_used_service"),
            },
            extra_populated_at=now,
        ))

    return findings


async def _link_assets_and_mark_checked(
    db: AsyncSession, connection: CloudAccountConnection, rows: list[dict], candidates: list[Finding],
) -> None:
    """Phase 38b/c: sets a real asset_id on each candidate Finding when a
    matching CloudAsset already exists (resource discovery runs first in
    rescan_connection()), and marks every user this report actually
    covered "fail" (has a real finding this pass) or "pass" (evaluated,
    genuinely clean) on their CloudAsset — unlike Inspector2, the
    credential report covers every real IAM user unconditionally, so
    "pass" here is a real, provable signal, not a guess. Duplicates
    cloud_scan_service.py's own _asset_ids_by_resource_uid rather than
    importing it — that module already imports *from* this one, so the
    reverse import isn't available; small helper duplication over
    premature cross-module sharing, same as elsewhere in this codebase."""
    asset_result = await db.execute(
        select(CloudAsset).where(CloudAsset.cloud_account_connection_id == connection.id)
    )
    assets_by_resource_uid = {a.resource_id: a for a in asset_result.scalars().all()}
    if not assets_by_resource_uid:
        return

    for candidate in candidates:
        asset = assets_by_resource_uid.get(candidate.resource_uid)
        if asset:
            candidate.asset_id = asset.id

    arns_with_findings = {c.resource_uid for c in candidates if c.resource_uid}
    changed = False
    for row in rows:
        arn = row.get("arn", "")
        asset = assets_by_resource_uid.get(arn)
        if not asset:
            continue
        status = "fail" if arn in arns_with_findings else "pass"
        if asset.resource_metadata.get("credential_status") != status:
            asset.resource_metadata = {**asset.resource_metadata, "credential_status": status}
            changed = True
    if changed:
        await db.commit()


async def _register_credential_report_actors(
    db: AsyncSession, connection: CloudAccountConnection, rows: list[dict],
) -> None:
    """Registers every real IAM user in the credential report into the
    Actor graph (Phase 37a) — until now, credential-hygiene findings were
    invisible to Actor-based lookups (the graph's node-badge matching,
    find_open_privesc_paths_for_principal, etc.) even though their
    resource_uid is always a real IAM user ARN. Every row here is
    guaranteed to be a User (the credential report only covers IAM users
    with a login/keys, never Roles/Groups), so — unlike
    _register_iam_principal_actors' Role/Group branch — the email-tag
    lookup always applies, no branching needed."""
    seen_arns: set[str] = set()
    for row in rows:
        arn = row.get("arn", "")
        user = row.get("user", "")
        if not arn or arn in seen_arns:
            continue
        seen_arns.add(arn)

        email = await asyncio.to_thread(lookup_iam_user_email_tag, connection.role_arn, connection.external_id, user)
        await resolve_or_create_actor(
            db, connection.tenant_id, "aws_iam", arn,
            email=email, email_provenance="iam_tag" if email else None,
        )
    if seen_arns:
        await db.commit()


async def run_credential_hygiene_scan(
    db: AsyncSession, engagement: Engagement, connection: CloudAccountConnection,
    error_detail: dict | None = None,
) -> list[Finding] | None:
    """Same honest-failure/reconciliation shape as run_prowler_scan — None
    (not []) means the pass itself didn't complete, so callers can tell
    "ran clean" from "never ran" the same way every other pass already does."""
    try:
        rows = await asyncio.to_thread(_fetch_credential_report_sync, connection.role_arn, connection.external_id)
    except (ClientError, BotoCoreError, RuntimeError) as e:
        _log.warning("Credential hygiene scan failed: connection_id=%s error=%s", connection.id, e)
        if error_detail is not None:
            error_detail["message"] = str(e)
        return None

    await _register_credential_report_actors(db, connection, rows)

    candidates = _findings_from_report(rows, connection.tenant_id, engagement.id)
    await _link_assets_and_mark_checked(db, connection, rows, candidates)
    for c in candidates:
        score_and_stamp(c)
    return await reconcile_findings(
        db, engagement_id=engagement.id,
        scope=[Finding.tier == "credential"],
        candidates=candidates,
        key_fn=lambda f: (f.check_id, f.resource_uid),
    )
