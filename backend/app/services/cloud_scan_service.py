"""
Sentinel Command Tier 0 — cloud posture scanning.

Module boundary for CloudAccountConnection lifecycle (AWS role assumption
first; Azure/GCP follow once AWS proves the pipeline end-to-end — see
BUILD_PLAN.md Phase 1) and the two scan passes that populate Finding /
CloudPrivEscPath from a connected account:

  - Prowler: baseline CIS/best-practice checks -> Finding rows
  - Cloudsplaining / PMapper: IAM privilege-escalation graph -> CloudPrivEscPath rows

Function bodies are stubs (BUILD_PLAN.md Phase 1, not yet done) — signatures
and call shape are settled so routers/tests can be written against them now.
"""
from __future__ import annotations

import asyncio
import csv
import json
import logging
import os
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import CloudAccountConnection, CloudAsset, CloudPrivEscPath, Engagement, Finding, HostConnection
from app.services.aws_iam_identity_lookup import lookup_iam_user_email_tag
from app.services.breach_monitoring_service import run_breach_monitoring_scan
from app.services.credential_hygiene_service import run_credential_hygiene_scan
from app.services.exploitability_service import score_and_stamp
from app.services.finding_reconciliation import reconcile_findings
from app.services.identity_resolution_service import resolve_or_create_actor
from app.services.resource_inventory_service import run_resource_inventory_sync

_log = logging.getLogger(__name__)

# ── Cloud Posture score (feeds posture_service.compute_sentinel_score) ───────
# Not "percent of Prowler checks passing" — PASS rows are never persisted
# (run_prowler_scan only stores FAIL findings, see --status FAIL), so the
# available signal is "how bad are the currently-open findings," not a pass
# ratio. Starts at 100, deducted per open cloud Finding by severity and per
# open CloudPrivEscPath (a live privilege-escalation chain is worse than a
# static misconfig, weighted higher) — same shape as posture_service's other
# pillar functions (start at max, subtract for bad state).
_FINDING_SEVERITY_PENALTY = {"critical": 15, "high": 8, "medium": 3, "low": 1}
_PRIV_ESC_PATH_PENALTY = 20


async def compute_tenant_cloud_posture_score(db: AsyncSession, tenant_id: uuid.UUID) -> float | None:
    """Returns None if the tenant has no connected cloud OR host account —
    callers (posture_service.compute_sentinel_score) treat None as "leave
    the Sentinel Score exactly as it was before Command existed," not as 0.

    Despite the name (kept for callers already wired to it), this now
    covers both halves of the Host & Server Security position — cloud-tier
    findings (Prowler/Inspector) and host-tier findings (Lynis-over-SSH,
    host_scan_service.py) share one posture bucket, same as the roster
    treats them as one lineup feature."""
    has_cloud_connection = await db.scalar(
        select(func.count()).select_from(CloudAccountConnection).where(
            CloudAccountConnection.tenant_id == tenant_id,
            CloudAccountConnection.status == "connected",
        )
    )
    has_host_connection = await db.scalar(
        select(func.count()).select_from(HostConnection).where(
            HostConnection.tenant_id == tenant_id,
            HostConnection.status == "connected",
        )
    )
    if not has_cloud_connection and not has_host_connection:
        return None

    finding_rows = await db.execute(
        select(Finding.severity, func.count()).where(
            Finding.tenant_id == tenant_id, Finding.tier.in_(["cloud", "host"]), Finding.status == "open",
        ).group_by(Finding.severity)
    )
    score = 100.0
    for severity, count in finding_rows.all():
        score -= _FINDING_SEVERITY_PENALTY.get(severity, 1) * count

    priv_esc_count = await db.scalar(
        select(func.count()).select_from(CloudPrivEscPath).where(CloudPrivEscPath.tenant_id == tenant_id)
    )
    score -= _PRIV_ESC_PATH_PENALTY * (priv_esc_count or 0)

    return max(0.0, score)


# ── Connection lifecycle ─────────────────────────────────────────────────────

def _trust_policy(external_id: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{settings.command_aws_account_id}:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
        }],
    }


def _cloudformation_template(external_id: str) -> str:
    # SecurityAudit + ViewOnlyAccess is the same read-only pairing
    # ARCHITECTURE.md's Tier 0 spec calls for — enough for Prowler/
    # Cloudsplaining/PMapper to enumerate and analyze, nothing that grants
    # write access to the customer's account.
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Sentinel Command read-only cloud posture scanning role",
        "Resources": {
            "SentinelCommandRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "SentinelCommandReadOnly",
                    "AssumeRolePolicyDocument": _trust_policy(external_id),
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/SecurityAudit",
                        "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
                    ],
                },
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["SentinelCommandRole", "Arn"]}},
        },
    }, indent=2)


def generate_aws_connection_setup(external_id: str) -> dict:
    """Return the CloudFormation snippet + trust-policy detail a customer
    needs to create the cross-account role. external_id must be generated
    by the caller (per-connection, random) and embedded in the trust policy
    for confused-deputy protection — see the AWS docs on cross-account role
    assumption using a third party."""
    return {
        "trust_policy": json.dumps(_trust_policy(external_id), indent=2),
        "cloudformation_template": _cloudformation_template(external_id),
        "instructions": [
            "Deploy the CloudFormation template in the AWS account you want scanned.",
            "Copy the RoleArn output once the stack finishes creating.",
            "Paste that Role ARN back into Sentinel Command to complete the connection.",
        ],
    }


async def verify_aws_connection(db: AsyncSession, connection: CloudAccountConnection) -> bool:
    """Attempt sts:AssumeRole against connection.role_arn with the stored
    external_id. On success, flips connection.status to 'connected' and sets
    connected_at; on failure, flips it to 'error'. Never persists a
    credential — this only proves the role is assumable, the STS session
    itself is used in-place by the caller (Phase 1's scan passes) and
    discarded."""
    def _assume():
        sts = boto3.client("sts")
        return sts.assume_role(
            RoleArn=connection.role_arn,
            RoleSessionName="sentinel-command-verify",
            ExternalId=connection.external_id,
            DurationSeconds=900,
        )

    try:
        await asyncio.to_thread(_assume)
    except ClientError as e:
        _log.warning(
            "Cloud connection verify failed: connection_id=%s error=%s",
            connection.id, e.response.get("Error", {}).get("Code"),
        )
        connection.status = "error"
        await db.commit()
        return False
    except BotoCoreError as e:
        # Client-side failures that never reach AWS at all — no credentials
        # configured on this host, network/endpoint errors, etc. Distinct
        # from ClientError (an error AWS itself returned). Found by testing
        # this endpoint against the real live backend (no AWS credentials
        # configured in this dev environment) rather than only against the
        # moto-mocked/monkeypatched test suite, where this path never fires:
        # NoCredentialsError is a BotoCoreError, not a ClientError, so it was
        # propagating as an unhandled 500 instead of a graceful failure.
        _log.warning("Cloud connection verify failed (client-side): connection_id=%s error=%s", connection.id, e)
        connection.status = "error"
        await db.commit()
        return False

    connection.status = "connected"
    connection.connected_at = datetime.now(timezone.utc)
    await db.commit()
    return True


# ── Scan passes ───────────────────────────────────────────────────────────────

def _discover_active_regions(role_arn: str, external_id: str) -> list[str] | None:
    """Speed optimization, never a correctness gate — found while chasing
    down a real Prowler timeout (30 min, against the 1800s
    command_scan_timeout_seconds cap). Prowler iterates every AWS-enabled
    region for every regional check regardless of whether that region has
    anything in it; measured directly against a real account with 18
    enabled regions but real resources in only 1 — each empty region still
    costs ~1-3s in real API round-trips per check, which is most of where
    a 30-minute scan actually goes on a small/medium account.

    Uses the Resource Groups Tagging API's cross-service get_resources()
    as a single-call-per-region "does this region have anything at all"
    signal, rather than checking each service (EC2/RDS/Lambda/...)
    individually.

    Returns None (meaning "don't restrict — scan every enabled region")
    whenever discovery is anything less than fully confident: an
    assume-role failure, an unexpected error, or literally zero active
    regions found anywhere (more likely a permissions gap on the tagging
    API than a genuinely empty account). A per-region check failure
    includes that region rather than excluding it. This function only
    ever narrows scope when it's sure — silently skipping a region that
    actually has resources would hide real findings there, which is a
    much worse failure mode for a security product than a slow scan."""
    try:
        sts = boto3.client("sts")
        creds = sts.assume_role(
            RoleArn=role_arn, RoleSessionName="sentinel-command-region-discovery",
            ExternalId=external_id, DurationSeconds=900,
        )["Credentials"]
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        ec2 = session.client("ec2", region_name="us-east-1")
        enabled_regions = [
            r["RegionName"] for r in ec2.describe_regions(AllRegions=True)["Regions"]
            if r["OptInStatus"] in ("opt-in-not-required", "opted-in")
        ]
    except (ClientError, BotoCoreError, KeyError) as e:
        _log.info("Region discovery failed, falling back to scanning every enabled region: %s", e)
        return None

    active: list[str] = []
    for region in enabled_regions:
        try:
            tagging = session.client("resourcegroupstaggingapi", region_name=region)
            resp = tagging.get_resources(ResourcesPerPage=1)
            if resp.get("ResourceTagMappingList"):
                active.append(region)
        except (ClientError, BotoCoreError):
            active.append(region)  # uncertain about this one region — include it, don't guess it away

    if not active:
        _log.info("Region discovery found zero active regions — treating as inconclusive, scanning every enabled region instead")
        return None
    return active


def _run_prowler_subprocess(role_arn: str, external_id: str, output_dir: str, regions: list[str] | None = None) -> subprocess.CompletedProcess:
    # Must be absolute: Windows' CreateProcess (unlike Path.exists()) doesn't
    # resolve a relative path against the current working directory the way
    # POSIX exec does — a relative command here fails with WinError 2 even
    # when the file genuinely exists at that relative location.
    prowler_bin = str(Path(settings.command_prowler_bin).resolve())
    cmd = [
        prowler_bin, "aws",
        "--role", role_arn,
        "--external-id", external_id,
        "--role-session-name", "sentinel-command-scan",
        # Explicit FAIL + PASS (Phase 38b), not "no --status filter" — PASS
        # rows are needed to honestly tell "checked, clean" apart from
        # "never evaluated" on the Resource Explorer's per-resource status.
        # --status is Prowler's own output filter, not a scan-scope filter
        # (every check still runs regardless — confirmed via
        # prowler/__main__.py). Real, live-verified reason this can't be
        # "no filter at all": Prowler's own Status enum has a 3rd value,
        # MANUAL (checks needing human review), and __main__.py's default-
        # execution path unconditionally runs a compliance-overview table
        # display whenever any MANUAL-status finding is present — a real
        # bug in the installed Prowler version (5.32.0) that crashes with
        # `KeyError: 'MANUAL'` inside its own compliance table builder.
        # Reproduced against the real connected AWS account before adding
        # this fix. Restricting to FAIL+PASS gets the data this pass
        # actually needs while never including a MANUAL-status finding.
        "--status", "FAIL", "PASS",
        # Also json-ocsf — Prowler's own CLI default already includes it
        # (verified against the installed package's own parser.py), this
        # codebase was the one suppressing it. OCSF carries each finding's
        # real structured resource detail (ports/protocols/CIDRs for a
        # security-group check, etc.) that CSV never does — only narrative
        # text in STATUS_EXTENDED. Parsed by _parse_prowler_ocsf below.
        "--output-formats", "csv", "json-ocsf",
        "--output-directory", output_dir,
        "--output-filename", "scan",
        "--no-banner",
        "--ignore-exit-code-3",  # exit 3 means "there are FAIL findings", not an error — verified against
        # prowler/__main__.py's own exit handling, not assumed from docs
    ]
    if regions:
        cmd += ["--region", *regions]
    # Prowler's own alive_progress bar writes Unicode box-drawing characters
    # to stdout; on Windows the child process otherwise inherits the
    # console's cp1252 codepage (regardless of capture_output piping it),
    # which can't encode them and crashes Prowler with a non-zero exit code
    # during the bar's own cleanup — after the actual checks already ran.
    # Without this, a scan that completed cleanly gets discarded as
    # "failed" purely because of a terminal-encoding crash. PYTHONUTF8=1
    # forces UTF-8 mode (PEP 540) for the subprocess regardless of the
    # host's console codepage — found by reproducing the exact traceback
    # (UnicodeEncodeError in alive_progress/utils/cells.py) against a real
    # AWS scan, not assumed from Prowler's docs.
    env = {**os.environ, "PYTHONUTF8": "1"}
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=settings.command_scan_timeout_seconds, env=env,
    )


def _parse_prowler_csv(csv_path: Path) -> list[dict]:
    if not csv_path.exists():
        return []
    with csv_path.open(newline="", encoding="utf-8") as f:
        # Semicolon-delimited — verified against prowler/lib/outputs/csv/csv.py,
        # which uses ";" specifically because AWS ARNs/resource lists contain commas.
        return list(csv.DictReader(f, delimiter=";"))


def _parse_prowler_ocsf(ocsf_path: Path) -> dict[str, dict]:
    """The structured per-resource detail CSV never carries (ports,
    protocols, CIDRs, VPC/subnet — for a security-group check this is the
    real ingress/egress rule data, not just narrative text in
    STATUS_EXTENDED). Keyed by each entry's own finding_info.uid, verified
    against the installed prowler package's ocsf.py to be the exact same
    value already captured as Finding.extra["finding_uid"] from the CSV —
    so no new correlation key is needed, just a second file to read.
    Missing/unparseable file degrades to an empty map (never a failed
    scan) — resource_metadata just stays None on every candidate,
    same honest-degrade convention as every other optional enrichment
    in this pass."""
    if not ocsf_path.exists():
        return {}
    try:
        entries = json.loads(ocsf_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        _log.warning("Could not parse Prowler OCSF output at %s: %s", ocsf_path, e)
        return {}

    metadata_by_uid: dict[str, dict] = {}
    for entry in entries if isinstance(entries, list) else []:
        finding_uid = (entry.get("finding_info") or {}).get("uid")
        resources = entry.get("resources") or []
        if not finding_uid or not resources:
            continue
        metadata = resources[0].get("data")
        if metadata:
            metadata_by_uid[finding_uid] = metadata
    return metadata_by_uid


def _parse_unrolled_dict(value: str | None, separator: str) -> dict[str, str]:
    """Reverses Prowler's own `unroll_dict()` CSV encoding (" | "-joined
    "key<separator>value" pairs — RESOURCE_TAGS uses "=", COMPLIANCE uses
    ": ", verified against prowler/lib/outputs/csv/csv.py). Best-effort: a
    malformed/empty segment is skipped rather than raising, since this is
    display metadata, not something correctness depends on."""
    if not value:
        return {}
    result: dict[str, str] = {}
    for part in value.split(" | "):
        if separator not in part:
            continue
        key, _, val = part.partition(separator)
        key = key.strip()
        if key:
            result[key] = val.strip()
    return result


def _parse_unrolled_list(value: str | None) -> list[str]:
    """Reverses Prowler's own `unroll_list()` CSV encoding (" | "-joined
    items, e.g. CATEGORIES/RELATED_TO/ADDITIONAL_URLS)."""
    if not value:
        return []
    return [item.strip() for item in value.split(" | ") if item.strip()]


def _prowler_extra_from_row(row: dict, resource_metadata_by_uid: dict[str, dict] | None = None) -> dict:
    """Everything from a Prowler CSV row this codebase previously discarded
    (30 of 36 real columns — confirmed against prowler/lib/outputs/csv/csv.py
    this session) beyond the 6 fields already mapped onto Finding's own
    columns. Kept as one JSONB blob on Finding.extra rather than new typed
    columns — see Finding's own class docstring on why.

    resource_metadata_by_uid — the OCSF-sourced structured resource detail
    (_parse_prowler_ocsf), keyed by the same FINDING_UID this row already
    carries. None/missing entry both degrade to resource_metadata: None,
    never a failed scan — CSV alone is still a complete, honest Finding."""
    remediation_code = {
        "terraform": row.get("REMEDIATION_CODE_TERRAFORM") or None,
        "cli": row.get("REMEDIATION_CODE_CLI") or None,
        "native_iac": row.get("REMEDIATION_CODE_NATIVEIAC") or None,
    }
    finding_uid = row.get("FINDING_UID") or None
    return {
        "source": "prowler",
        "resource_type": row.get("RESOURCE_TYPE") or None,
        "resource_name": row.get("RESOURCE_NAME") or None,
        "service_name": row.get("SERVICE_NAME") or None,
        "resource_tags": _parse_unrolled_dict(row.get("RESOURCE_TAGS"), "=") or None,
        "compliance": _parse_unrolled_dict(row.get("COMPLIANCE"), ": ") or None,
        "remediation_code": remediation_code if any(remediation_code.values()) else None,
        "risk": row.get("RISK") or None,
        "categories": _parse_unrolled_list(row.get("CATEGORIES")) or None,
        "related_url": row.get("RELATED_URL") or None,
        "finding_uid": finding_uid,
        "muted": (row.get("MUTED") or "").strip().lower() == "true",
        # Real ports/protocols/CIDRs/VPC-subnet detail from Prowler's OCSF
        # output — the actual specifics behind a bare "internet-exposed"
        # category tag. None when no OCSF file was produced/parsed, or
        # this finding_uid has no matching entry — never fabricated.
        "resource_metadata": (resource_metadata_by_uid or {}).get(finding_uid),
    }


def _region_wildcard_arn(arn: str | None) -> str | None:
    """arn:partition:service:region:account-id:resource — replaces just the
    region segment with '*'. Returns None for anything that isn't a real
    6-segment ARN (nothing to collapse on), so a check whose RESOURCE_UID
    isn't ARN-shaped is simply never grouped."""
    if not arn or not arn.startswith("arn:"):
        return None
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return None
    parts[3] = "*"
    return ":".join(parts)


def _collapse_regional_duplicates(candidates: list[Finding]) -> list[Finding]:
    """Prowler evaluates account/region-level settings (CloudTrail
    multi-region, GuardDuty, Access Analyzer, Config recorder, ...) once
    per enabled region, so one real gap becomes 15-18 near-identical rows
    whose RESOURCE_UID differs only by region — on a real test account this
    was 74% of all findings and pushed the same handful of checks into
    every "top findings" slot. Groups candidates by (check_id, region-
    wildcarded resource_uid): a group of 1 is left untouched (this is what
    keeps a genuine per-resource finding — a specific S3 bucket, a specific
    EC2 instance — from ever being collapsed, since real resource ids don't
    match across the group). A group of N>1 becomes a single Finding with
    occurrence_count=N and affected_resources listing every real ARN, so
    the underlying detail isn't lost — it's one click away instead of N
    top-level rows."""
    groups: dict[tuple[str | None, str | None], list[Finding]] = {}
    order: list[tuple[str | None, str | None]] = []
    for c in candidates:
        wildcard = _region_wildcard_arn(c.resource_uid)
        key = (c.check_id, wildcard or c.resource_uid)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(c)

    collapsed: list[Finding] = []
    for key in order:
        group = groups[key]
        if len(group) == 1:
            collapsed.append(group[0])
            continue
        representative = group[0]
        affected = sorted(c.resource_uid for c in group if c.resource_uid)  # read before overwriting representative.resource_uid below
        representative.occurrence_count = len(group)
        representative.affected_resources = affected
        representative.resource_uid = key[1]  # the region-wildcarded ARN
        # A collapsed row spans every region in the group, not just the
        # representative's own — leaving region set would misattribute the
        # finding to one region a user might then wrongly filter/trust.
        representative.region = None
        # Same reasoning for asset_id (Phase 38c) — a collapsed row spans
        # multiple real resources, so it can't honestly point at just the
        # representative's one. Each affected_resources entry still
        # resolves to its own real CloudAsset independently, via
        # resource_uid/affected_resources lookup on the resource-detail
        # endpoint, not through this field.
        representative.asset_id = None
        collapsed.append(representative)
    return collapsed


async def _asset_ids_by_resource_uid(db: AsyncSession, connection: CloudAccountConnection) -> dict[str, uuid.UUID]:
    """Phase 38c — one bulk lookup per scan pass, not N+1, so each pass's
    Finding-construction loop can set a real asset_id where a matching
    CloudAsset already exists (resource discovery runs first in
    rescan_connection(), so this is populated by the time any scan pass
    needs it)."""
    result = await db.execute(
        select(CloudAsset.resource_id, CloudAsset.id).where(
            CloudAsset.cloud_account_connection_id == connection.id,
        )
    )
    return {row.resource_id: row.id for row in result.all()}


async def _mark_resources_checked_by_prowler(db: AsyncSession, connection: CloudAccountConnection, rows: list[dict]) -> None:
    """Phase 38b — every resource Prowler actually evaluated (PASS or
    FAIL) gets a real checked-status mark on its CloudAsset, distinct
    from a resource that simply has no open Finding today (which could
    mean "verified clean" or "never checked" — indistinguishable without
    this). A resource with at least one FAIL row is "fail" even if other
    checks against it passed — one real gap outweighs a clean check
    elsewhere on the same resource."""
    status_by_resource: dict[str, str] = {}
    for row in rows:
        resource_uid = row.get("RESOURCE_UID")
        if not resource_uid:
            continue
        is_fail = (row.get("STATUS") or "").upper() == "FAIL"
        if is_fail or resource_uid not in status_by_resource:
            status_by_resource[resource_uid] = "fail" if is_fail else "pass"

    if not status_by_resource:
        return

    result = await db.execute(
        select(CloudAsset).where(
            CloudAsset.cloud_account_connection_id == connection.id,
            CloudAsset.resource_id.in_(status_by_resource.keys()),
        )
    )
    changed = False
    for asset in result.scalars().all():
        status = status_by_resource.get(asset.resource_id)
        if status and asset.resource_metadata.get("prowler_status") != status:
            asset.resource_metadata = {**asset.resource_metadata, "prowler_status": status}
            changed = True
    if changed:
        await db.commit()


async def run_prowler_scan(
    db: AsyncSession, engagement: Engagement, connection: CloudAccountConnection,
    error_detail: dict | None = None,
) -> list[Finding] | None:
    """Assume connection.role_arn (via Prowler's own --role/--external-id,
    using this host's ambient AWS credentials as the calling identity — the
    same resolution boto3.client("sts") uses in verify_aws_connection), run
    Prowler against the session in its isolated venv, persist one Finding
    per FAIL check. check_id is Prowler's own CheckID, so results map onto
    the Compliance Matrix's CIS-aligned frameworks for free.

    Returns None (not []) if the scan pass itself failed to complete — PASS
    rows are never persisted, so an empty list is otherwise ambiguous
    between "ran cleanly, found nothing" and "never actually ran." Callers
    use this to set last_scan_status rather than inferring it from
    absence of findings.

    error_detail, if given, gets a short "message" key set on failure — an
    optional out-param rather than a return-type change, so every existing
    caller/test that only checks `is None` keeps working unmodified. Lets
    rescan_connection() report *which* pass failed and *why*, instead of a
    single connection-wide status that hides a working Prowler pass behind
    an unrelated failed one (e.g. Inspector2 not enabled on the account)."""
    regions = await asyncio.to_thread(_discover_active_regions, connection.role_arn, connection.external_id)
    if regions:
        _log.info("Region discovery scoped Prowler to %d active region(s) for connection_id=%s: %s", len(regions), connection.id, regions)

    with tempfile.TemporaryDirectory() as tmp:
        try:
            proc = await asyncio.to_thread(_run_prowler_subprocess, connection.role_arn, connection.external_id, tmp, regions)
        except subprocess.TimeoutExpired:
            _log.warning("Prowler scan timed out: connection_id=%s", connection.id)
            if error_detail is not None:
                error_detail["message"] = f"Timed out after {settings.command_scan_timeout_seconds}s"
            return None

        if proc.returncode != 0:
            _log.warning(
                "Prowler scan failed: connection_id=%s returncode=%s stderr=%s",
                connection.id, proc.returncode, proc.stderr[-2000:],
            )
            if error_detail is not None:
                error_detail["message"] = (proc.stderr or "").strip().splitlines()[-1][:300] if proc.stderr else f"Exited with code {proc.returncode}"
            return None

        rows = _parse_prowler_csv(Path(tmp) / "scan.csv")
        resource_metadata_by_uid = _parse_prowler_ocsf(Path(tmp) / "scan.ocsf.json")

    # Phase 38b: every row's own resource gets a checked-status mark on its
    # CloudAsset (if one exists — resource discovery runs before this pass,
    # see rescan_connection()), regardless of PASS/FAIL — this is what lets
    # the Resource Explorer say "checked, clean" instead of just "no
    # findings recorded" for a resource Prowler genuinely evaluated.
    await _mark_resources_checked_by_prowler(db, connection, rows)
    asset_ids_by_resource_uid = await _asset_ids_by_resource_uid(db, connection)

    fail_rows = [row for row in rows if (row.get("STATUS") or "").upper() == "FAIL"]
    candidates: list[Finding] = [
        Finding(
            id=uuid.uuid4(),
            tenant_id=connection.tenant_id,
            engagement_id=engagement.id,
            asset_id=asset_ids_by_resource_uid.get(row.get("RESOURCE_UID")),
            tier="cloud",
            severity=(row.get("SEVERITY") or "medium").lower(),
            title=row.get("CHECK_TITLE") or row.get("CHECK_ID") or "Unknown check",
            status="open",
            check_id=row.get("CHECK_ID"),
            resource_uid=row.get("RESOURCE_UID"),
            # STATUS_EXTENDED is Prowler's own per-resource evidence text
            # (e.g. "Security group sg-0123 has port 22 open to 0.0.0.0/0")
            # — real proof, not the generic per-check DESCRIPTION every
            # failing resource for this check shares. Fall back to
            # DESCRIPTION only when Prowler didn't populate it for this check.
            detail=row.get("STATUS_EXTENDED") or row.get("DESCRIPTION"),
            remediation_guidance=row.get("REMEDIATION_RECOMMENDATION_TEXT"),
            region=row.get("REGION") or None,
            extra=_prowler_extra_from_row(row, resource_metadata_by_uid),
            extra_populated_at=datetime.now(timezone.utc),
        )
        for row in fail_rows
    ]
    candidates = _collapse_regional_duplicates(candidates)
    for c in candidates:
        score_and_stamp(c)

    # Scoped to check_id NOT starting "arn:" so this never touches
    # Inspector's rows, which share tier="cloud" but key on a finding ARN.
    return await reconcile_findings(
        db, engagement_id=engagement.id,
        scope=[Finding.tier == "cloud", ~Finding.check_id.like("arn:%")],
        candidates=candidates,
        key_fn=lambda f: (f.check_id, f.resource_uid),
    )


# ── Amazon Inspector (EC2 host-level scanning) ────────────────────────────────
# Host & Server Security position, AWS half — unlike Prowler/Cloudsplaining,
# there's no scanner to run here at all: Inspector already continuously scans
# EC2 instances via the SSM agent AWS ships pre-installed on most AMIs. We
# just read its findings through the same assumed-role session as Prowler.
#
# Relies on the connection's existing ViewOnlyAccess managed policy already
# covering inspector2:List*/BatchGet* — AWS's ViewOnlyAccess is documented as
# a broad read-everything policy and should include this, but that's not
# verified against a real AWS account from this environment. Confirm before
# relying on it in production; if it's missing, the call fails with
# AccessDenied and this degrades to an empty finding list, same as any other
# scan-pass failure.

_INSPECTOR_SEVERITY_MAP = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "INFORMATIONAL": "low", "UNTRIAGED": "medium",
}


def _inspector_region_from_raw(raw: dict) -> str | None:
    resources = raw.get("resources") or []
    return resources[0].get("region") if resources else None


def _inspector_extra_from_raw(raw: dict) -> dict:
    """Everything from a real Inspector2 `Finding` (botocore's `inspector2`
    2020-06-08 service model has 20 top-level members; only 6 were
    previously extracted) beyond what's already mapped onto Finding's own
    columns. Field names verified against the real service model this
    session, not guessed."""
    pkg_details = raw.get("packageVulnerabilityDetails") or {}
    cvss_scores = pkg_details.get("cvss") or []
    # Multiple sources (NVD, vendor) can each report their own CVSS score
    # for the same CVE — the highest is the one that should drive triage,
    # not whichever happened to sort first in the API response.
    best_cvss = max(cvss_scores, key=lambda c: c.get("baseScore") or 0, default=None)
    vulnerable_packages = [
        {
            "name": p.get("name"), "version": p.get("version"),
            "fixed_in_version": p.get("fixedInVersion"),
        }
        for p in (pkg_details.get("vulnerablePackages") or [])
    ]
    network = raw.get("networkReachabilityDetails")

    return {
        "source": "inspector2",
        "vulnerability_id": pkg_details.get("vulnerabilityId") or None,
        "cvss": {
            "base_score": best_cvss.get("baseScore"),
            "scoring_vector": best_cvss.get("scoringVector"),
            "source": best_cvss.get("source"),
        } if best_cvss else None,
        "vulnerable_packages": vulnerable_packages or None,
        "exploit_available": raw.get("exploitAvailable") or None,  # "YES" | "NO"
        "last_known_exploit_at": (raw.get("exploitabilityDetails") or {}).get("lastKnownExploitAt"),
        "fix_available": raw.get("fixAvailable") or None,  # "YES" | "NO" | "PARTIAL"
        "epss_score": (raw.get("epss") or {}).get("score"),
        "network_reachable": network is not None,
        "network_protocol": (network or {}).get("protocol"),
        "network_open_port_range": (network or {}).get("openPortRange"),
        "first_observed_at": _isoformat_or_none(raw.get("firstObservedAt")),
        "last_observed_at": _isoformat_or_none(raw.get("lastObservedAt")),
        "reference_urls": pkg_details.get("referenceUrls") or None,
    }


def _isoformat_or_none(value) -> str | None:
    return value.isoformat() if hasattr(value, "isoformat") else value


def _list_inspector_findings(role_arn: str, external_id: str) -> list[dict]:
    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=role_arn, RoleSessionName="sentinel-command-inspector",
        ExternalId=external_id, DurationSeconds=900,
    )["Credentials"]
    inspector = boto3.client(
        "inspector2",
        region_name=settings.command_aws_default_region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    findings = []
    paginator = inspector.get_paginator("list_findings")
    for page in paginator.paginate(filterCriteria={"findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]}):
        findings.extend(page.get("findings", []))
    return findings


async def run_inspector_scan(
    db: AsyncSession, engagement: Engagement, connection: CloudAccountConnection,
    error_detail: dict | None = None,
) -> list[Finding] | None:
    """Reads Amazon Inspector's existing ACTIVE findings for EC2 instances
    under the connected account. check_id uses the finding's ARN (Inspector
    findings don't have a short check-id the way Prowler's do) so re-scans
    can be told apart from each other later if dedup becomes necessary.

    Returns None (not []) on failure — see run_prowler_scan's docstring.
    error_detail — see run_prowler_scan's docstring for why this is an
    optional out-param rather than a return-type change. The most common
    real failure here is SubscriptionRequiredException — Inspector2 is an
    opt-in AWS service, not something this app can enable on a customer's
    behalf, so surfacing that specific code (rather than a generic
    "Inspector scan failed") is the difference between a customer knowing
    to enable it themselves and just seeing a dead end."""
    try:
        raw_findings = await asyncio.to_thread(_list_inspector_findings, connection.role_arn, connection.external_id)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        _log.warning("Inspector scan failed: connection_id=%s error=%s", connection.id, code)
        if error_detail is not None:
            error_detail["message"] = (
                "Amazon Inspector2 is not enabled on this AWS account (SubscriptionRequiredException) — "
                "enable it in the AWS Console or run 'aws inspector2 enable --resource-types EC2 ECR LAMBDA'."
                if code == "SubscriptionRequiredException" else (code or str(e))
            )
            # A brand-new AWS account has Inspector2 opted out by default —
            # this is not a scan failure, it's an optional module the
            # customer hasn't turned on yet (Coverage Map plan Phase 8).
            # Every other pass succeeding shouldn't be buried under a
            # "failed" status just because of this, day one, on every
            # single new customer.
            if code == "SubscriptionRequiredException":
                error_detail["not_enabled"] = True
        return None

    # Phase 38b/c: list_findings only ever returns ACTIVE (i.e. failing)
    # findings — there's no Inspector2 signal here for "this resource was
    # scanned and is clean" the way Prowler's PASS rows give one, so this
    # only ever marks a resource "fail" (has a real active finding),
    # never "pass" — an honest limitation, not a fabricated all-clear.
    asset_ids_by_resource_uid = await _asset_ids_by_resource_uid(db, connection)
    checked_resource_arns: set[str] = set()
    for raw in raw_findings:
        for resource in raw.get("resources") or []:
            resource_id = resource.get("id")
            if resource_id and resource_id.startswith("arn:"):
                checked_resource_arns.add(resource_id)
    if checked_resource_arns:
        result = await db.execute(
            select(CloudAsset).where(
                CloudAsset.cloud_account_connection_id == connection.id,
                CloudAsset.resource_id.in_(checked_resource_arns),
            )
        )
        changed = False
        for asset in result.scalars().all():
            if asset.resource_metadata.get("inspector_status") != "fail":
                asset.resource_metadata = {**asset.resource_metadata, "inspector_status": "fail"}
                changed = True
        if changed:
            await db.commit()

    def _inspector_asset_id(raw: dict):
        for resource in raw.get("resources") or []:
            resource_id = resource.get("id")
            if resource_id in asset_ids_by_resource_uid:
                return asset_ids_by_resource_uid[resource_id]
        return None

    candidates: list[Finding] = [
        Finding(
            id=uuid.uuid4(),
            tenant_id=connection.tenant_id,
            engagement_id=engagement.id,
            asset_id=_inspector_asset_id(raw),
            tier="cloud",
            severity=_INSPECTOR_SEVERITY_MAP.get(raw.get("severity", "MEDIUM"), "medium"),
            title=raw.get("title") or "Unknown Inspector finding",
            status="open",
            check_id=raw.get("findingArn"),
            detail=raw.get("description"),
            remediation_guidance=(raw.get("remediation") or {}).get("recommendation", {}).get("text"),
            region=_inspector_region_from_raw(raw),
            extra=_inspector_extra_from_raw(raw),
            extra_populated_at=datetime.now(timezone.utc),
        )
        for raw in raw_findings
    ]
    for c in candidates:
        score_and_stamp(c)

    # findingArn is already resource+finding-specific, unlike Prowler's
    # check_id — no separate resource_uid needed, key on check_id alone.
    # Scoped to check_id starting "arn:" so this never touches Prowler's
    # rows sharing tier="cloud".
    return await reconcile_findings(
        db, engagement_id=engagement.id,
        scope=[Finding.tier == "cloud", Finding.check_id.like("arn:%")],
        candidates=candidates,
        key_fn=lambda f: (f.check_id, None),
    )


_CLOUDSPLAINING_SCRIPT = Path(__file__).resolve().parents[2] / "tools" / "cloudsplaining_privesc_scan.py"


def _run_cloudsplaining_subprocess(role_arn: str, external_id: str) -> subprocess.CompletedProcess:
    python_bin = str(Path(settings.command_iam_tools_python).resolve())
    cmd = [python_bin, str(_CLOUDSPLAINING_SCRIPT), "--role-arn", role_arn, "--external-id", external_id]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=settings.command_scan_timeout_seconds)


def _priv_esc_path_key(p: CloudPrivEscPath) -> tuple:
    return (p.source_principal_arn, p.escalation_type, tuple(p.technique_chain or []))


async def _reconcile_priv_esc_paths(
    db: AsyncSession, *, engagement_id: uuid.UUID, candidates: list[CloudPrivEscPath],
) -> list[CloudPrivEscPath]:
    """Same reconciliation shape as finding_reconciliation.reconcile_findings
    — CloudPrivEscPath was genuinely append-only until now (its own
    docstring's "retest_closed" promise was never implemented), so every
    rescan re-inserted every still-open path with no awareness of what a
    previous scan already found, the exact duplicate-accumulation bug
    already fixed for Finding. A dedicated function rather than reusing
    reconcile_findings directly, since that one is typed and queried
    specifically against the Finding table.

    A path missing from this scan's candidates is marked retest_closed —
    the row stays (history), it's just no longer 'open'. Simulate-the-Fix
    (POST /graph/simulate) reads only 'open' rows, so a genuinely-fixed
    path stops appearing there automatically, without deleting anything."""
    existing = (
        await db.execute(
            select(CloudPrivEscPath).where(
                CloudPrivEscPath.engagement_id == engagement_id, CloudPrivEscPath.status == "open",
            )
        )
    ).scalars().all()

    existing_by_key = {_priv_esc_path_key(p): p for p in existing}
    candidate_keys = {_priv_esc_path_key(c) for c in candidates}

    new_paths = [c for c in candidates if _priv_esc_path_key(c) not in existing_by_key]
    for p in new_paths:
        db.add(p)

    for key, existing_path in existing_by_key.items():
        if key not in candidate_keys:
            existing_path.status = "retest_closed"
            existing_path.closed_at = datetime.now(timezone.utc)

    if new_paths or any(key not in candidate_keys for key in existing_by_key):
        await db.commit()

    return new_paths


async def run_priv_esc_analysis(
    db: AsyncSession, engagement: Engagement, connection: CloudAccountConnection,
    error_detail: dict | None = None,
) -> list[CloudPrivEscPath] | None:
    """Assume connection.role_arn (the script does this itself, same as
    Prowler's own --role/--external-id — see cloudsplaining_privesc_scan.py),
    run Cloudsplaining's policy analysis in its isolated venv, persist one
    CloudPrivEscPath per discovered principal -> admin escalation chain.
    PMapper does not run here — see command_iam_tools_python's config
    comment for why it was dropped rather than patched.

    Returns None (not []) on failure — see run_prowler_scan's docstring.
    error_detail — see run_prowler_scan's docstring for why this is an
    optional out-param rather than a return-type change."""
    try:
        proc = await asyncio.to_thread(_run_cloudsplaining_subprocess, connection.role_arn, connection.external_id)
    except subprocess.TimeoutExpired:
        _log.warning("Cloudsplaining scan timed out: connection_id=%s", connection.id)
        if error_detail is not None:
            error_detail["message"] = f"Timed out after {settings.command_scan_timeout_seconds}s"
        return None

    if proc.returncode != 0:
        _log.warning(
            "Cloudsplaining scan failed: connection_id=%s returncode=%s stderr=%s",
            connection.id, proc.returncode, proc.stderr[-2000:],
        )
        if error_detail is not None:
            error_detail["message"] = (proc.stderr or "").strip().splitlines()[-1][:300] if proc.stderr else f"Exited with code {proc.returncode}"
        return None

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        _log.warning("Cloudsplaining scan produced unparseable output: connection_id=%s", connection.id)
        if error_detail is not None:
            error_detail["message"] = "Produced unparseable output"
        return None

    priv_esc_rows = payload.get("priv_esc_paths", [])
    policy_risk_rows = payload.get("policy_risk_findings", [])

    candidates: list[CloudPrivEscPath] = [
        CloudPrivEscPath(
            id=uuid.uuid4(),
            tenant_id=connection.tenant_id,
            engagement_id=engagement.id,
            cloud_account_connection_id=connection.id,
            source_principal_arn=row["principal_arn"],
            target_principal_arn="account-admin",  # Cloudsplaining's method covers "can reach admin-equivalent",
            # not a specific target principal the way a full graph tool like PMapper would resolve
            technique_chain=row.get("actions", []),
            escalation_type=row.get("escalation_type"),
            policy_name=row.get("policy_name"),
            policy_arn=row.get("policy_arn"),
            severity=row.get("severity", "high"),
            # Real statement-level Resource/Condition scope — see
            # cloudsplaining_privesc_scan.py's own output-shape docstring.
            extra={"policy_document": row.get("policy_document")} if row.get("policy_document") else None,
        )
        for row in priv_esc_rows
    ]

    await _register_iam_principal_actors(db, connection, {p.source_principal_arn for p in candidates})

    paths = await _reconcile_priv_esc_paths(db, engagement_id=engagement.id, candidates=candidates)

    # The 4 risk categories Cloudsplaining computes alongside PrivilegeEscalation
    # but that this codebase discarded entirely until Phase 36 — these aren't
    # escalation paths (no source->target chain), so they become Finding rows,
    # not CloudPrivEscPath rows. tier="credential" (Identity & Credential
    # Hygiene already covers IAM/credential risk broadly, not just human
    # password/MFA hygiene — see credential_hygiene_service.py's own findings
    # under the same tier). resource_uid stays the bare principal ARN — same
    # ARN-matchability reasoning as credential hygiene's own findings, needed
    # for the graph's credential-risk node badge (Phase 36f/37).
    finding_candidates = _policy_risk_finding_candidates(policy_risk_rows, connection.tenant_id, engagement.id)
    # Phase 37a: these principals also need Actor registration — otherwise
    # Actor-based graph matching (identity_resolution_service.py's
    # open_credential_finding_counts_for_nodes) finds nothing for exactly
    # the findings this sub-phase just added.
    await _register_iam_principal_actors(db, connection, {f.resource_uid for f in finding_candidates if f.resource_uid})

    # Phase 38c: same asset_id linking every other Finding-construction
    # site now does.
    asset_ids_by_resource_uid = await _asset_ids_by_resource_uid(db, connection)
    for f in finding_candidates:
        f.asset_id = asset_ids_by_resource_uid.get(f.resource_uid)
        score_and_stamp(f)

    await reconcile_findings(
        db, engagement_id=engagement.id,
        scope=[Finding.tier == "credential", Finding.check_id.like("cloudsplaining_%")],
        candidates=finding_candidates,
        key_fn=lambda f: (f.check_id, f.resource_uid),
    )

    return paths


_POLICY_RISK_CATEGORY_INFO = {
    "DataExfiltration": {
        "slug": "data_exfiltration", "label": "data exfiltration",
        "description": "grants read access to data (S3 objects, Secrets Manager, SSM parameters, etc.) with no resource constraint — an attacker who compromises this principal could exfiltrate that data.",
    },
    "ResourceExposure": {
        "slug": "resource_exposure", "label": "resource exposure",
        "description": "allows permissions-management actions with no resource constraint — this principal could grant broader access to AWS resources than intended.",
    },
    "ServiceWildcard": {
        "slug": "service_wildcard", "label": "unconstrained service access",
        "description": "grants every action within an entire AWS service — far broader than this principal likely needs.",
    },
    "CredentialsExposure": {
        "slug": "credentials_exposure", "label": "credentials exposure",
        "description": "allows actions that return temporary or long-lived credentials — a compromise of this principal could be used to mint new, separate credentials.",
    },
}
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _policy_risk_finding_candidates(rows: list[dict], tenant_id: uuid.UUID, engagement_id: uuid.UUID) -> list[Finding]:
    """Merges per-policy rows into one Finding per (category, principal) —
    the same principal can trip one category via multiple attached
    policies, and reconcile_findings' (check_id, resource_uid) dedup key
    only protects against collisions with already-persisted rows, not
    between candidates in the same batch, so this merge has to happen
    first or two policies would silently produce two colliding new rows."""
    groups: dict[tuple[str, str], list[dict]] = {}
    order: list[tuple[str, str]] = []
    for row in rows:
        key = (row["category"], row["principal_arn"])
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(row)

    now = datetime.now(timezone.utc)
    candidates: list[Finding] = []
    for key in order:
        category, principal_arn = key
        group = groups[key]
        info = _POLICY_RISK_CATEGORY_INFO[category]
        severity = max((r.get("severity", "medium") for r in group), key=lambda s: _SEVERITY_RANK.get(s, 2))
        policies = [
            {
                "policy_name": r.get("policy_name"), "policy_arn": r.get("policy_arn"), "actions": r.get("actions", []),
                "policy_document": r.get("policy_document"),
            }
            for r in group
        ]
        principal_label = principal_arn.rsplit("/", 1)[-1]
        via_note = f" via {len(policies)} attached policies" if len(policies) > 1 else ""
        candidates.append(Finding(
            id=uuid.uuid4(), tenant_id=tenant_id, engagement_id=engagement_id, asset_id=None,
            tier="credential", severity=severity,
            title=f"{principal_label} has {info['label']} risk{via_note}",
            status="open", check_id=f"cloudsplaining_{info['slug']}", resource_uid=principal_arn,
            detail=f"This IAM principal's attached policy {info['description']}",
            remediation_guidance="Add resource constraints (or split the broad action out of this policy) so this principal can only reach the specific resources it actually needs.",
            extra={"source": "cloudsplaining", "category": category, "policies": policies},
            extra_populated_at=now,
        ))
    return candidates


async def _register_iam_principal_actors(
    db: AsyncSession, connection: CloudAccountConnection, arns: set[str],
) -> None:
    """Registers each given IAM principal ARN into the Actor graph
    (Coverage Map plan phishing transformation, Phase 7; generalized in
    Phase 37a to cover Cloudsplaining's policy-risk-finding principals too,
    not just priv-esc-path source principals — both are real IAM
    principals that can be a User, Role, or Group). IAM Users only get a
    best-effort email-tag lookup (a Role/Group can be assumed by many
    humans, so a role-level tag can't honestly represent one person);
    Roles/Groups still get registered with no email, so
    find_open_privesc_paths_for_principal can match them once a real
    email arrives via the CloudTrail SSO-session path in
    threat_detection_service.py instead."""
    seen_arns: set[str] = set()
    for arn in arns:
        if not arn or arn in seen_arns:
            continue
        seen_arns.add(arn)

        email: str | None = None
        provenance: str | None = None
        if ":user/" in arn:
            user_name = arn.rsplit("/", 1)[-1]
            email = await asyncio.to_thread(lookup_iam_user_email_tag, connection.role_arn, connection.external_id, user_name)
            provenance = "iam_tag" if email else None

        await resolve_or_create_actor(
            db, connection.tenant_id, "aws_iam", arn, email=email, email_provenance=provenance,
        )
    if seen_arns:
        await db.commit()


async def rescan_connection(db: AsyncSession, engagement: Engagement, connection: CloudAccountConnection) -> None:
    """Runs all three scan passes and bumps connection.last_scanned_at.

    Checks engagement.status itself immediately before each pass rather than
    trusting the caller to have checked it — Prowler and Cloudsplaining are
    each a subprocess that can run for minutes, and revoke() needs to
    actually stop new work from starting once it's been called, not just be
    documented as a precondition. See ARCHITECTURE.md Section 6 on why
    Emergency Stop has to be enforced per-action, not once at the top.

    Also tracks last_scan_status/last_scan_error: any pass returning None
    (as opposed to a possibly-empty list) marks the whole rescan 'failed',
    since a customer relying on this dashboard can't tell "clean" from
    "silently broken" otherwise. A pass skipped by mid-scan revocation
    doesn't count as a failure — it just never ran this time.

    Also builds last_scan_results, a per-pass breakdown behind that same
    aggregate — the aggregate alone was burying a genuinely successful
    Prowler + Cloudsplaining pass under one unrelated failed Inspector call
    (e.g. Inspector2 not enabled on the account yet), with no way for the
    UI to show which pass actually broke and why."""
    failures: list[str] = []
    results: dict[str, dict] = {}

    async def _run_pass(name: str, coro) -> None:
        detail: dict = {}
        outcome = await coro(detail)
        if outcome is None:
            if detail.get("not_enabled"):
                # Optional module not enabled — a real, distinct status,
                # not folded into the aggregate "failed" (see
                # run_inspector_scan's docstring).
                results[name] = {"status": "not_enabled", "error": detail.get("message")}
            else:
                failures.append(f"{name.capitalize()} scan failed")
                results[name] = {"status": "failed", "error": detail.get("message") or f"{name.capitalize()} scan failed"}
        else:
            results[name] = {"status": "success", "error": None}

    # Transient "running:<pass>" markers, committed before each pass starts
    # (a real Prowler/Cloudsplaining/Inspector pass takes minutes — see
    # today's real timing) — a client polling GET /cloud-connections mid-
    # scan can show which pass is actually running instead of a static
    # "Running…" label that looks identical whether the scan is progressing
    # or silently stuck. Overwritten by the next pass's marker, or by the
    # final success/failed status once every pass has run.
    async def _mark_running(name: str) -> None:
        connection.last_scan_status = f"running:{name}"
        await db.commit()

    await db.refresh(engagement)
    if engagement.status != "active":
        _log.info("Skipping rescan — engagement no longer active: engagement_id=%s status=%s", engagement.id, engagement.status)
        return
    # Phase 38: runs first, so CloudAsset rows exist by the time Prowler/
    # Cloudsplaining/Inspector/credential-hygiene build their own Finding
    # candidates below and can look up a real asset_id against them.
    await _mark_running("resources")
    await _run_pass("resources", lambda d: run_resource_inventory_sync(db, connection, error_detail=d))

    await db.refresh(engagement)
    if engagement.status != "active":
        _log.info("Stopping after resource-inventory pass — engagement revoked mid-scan: engagement_id=%s", engagement.id)
        connection.last_scan_results = results
        await db.commit()
        return
    await _mark_running("prowler")
    await _run_pass("prowler", lambda d: run_prowler_scan(db, engagement, connection, error_detail=d))

    await db.refresh(engagement)
    if engagement.status != "active":
        _log.info("Stopping after Prowler pass — engagement revoked mid-scan: engagement_id=%s", engagement.id)
        connection.last_scan_results = results
        await db.commit()
        return
    await _mark_running("cloudsplaining")
    await _run_pass("cloudsplaining", lambda d: run_priv_esc_analysis(db, engagement, connection, error_detail=d))

    await db.refresh(engagement)
    if engagement.status != "active":
        _log.info("Stopping after Cloudsplaining pass — engagement revoked mid-scan: engagement_id=%s", engagement.id)
        connection.last_scan_results = results
        await db.commit()
        return
    await _mark_running("inspector")
    await _run_pass("inspector", lambda d: run_inspector_scan(db, engagement, connection, error_detail=d))

    await db.refresh(engagement)
    if engagement.status != "active":
        _log.info("Stopping after Inspector pass — engagement revoked mid-scan: engagement_id=%s", engagement.id)
        connection.last_scan_results = results
        await db.commit()
        return
    await _mark_running("credential")
    await _run_pass("credential", lambda d: run_credential_hygiene_scan(db, engagement, connection, error_detail=d))

    # Breach monitoring isn't connection-specific (it checks the tenant's
    # phishing target-list emails against HaveIBeenPwned, not this AWS
    # account), but it rides along in the same per-connection breakdown UI
    # rather than needing a whole new surface. Skipped entirely — not
    # counted as a failure — when hibp_api_key isn't configured, the same
    # "optional module not enabled" honesty as Inspector's SubscriptionRequiredException.
    if settings.hibp_api_key:
        await db.refresh(engagement)
        if engagement.status == "active":
            await _mark_running("breach_monitoring")
            await _run_pass("breach_monitoring", lambda d: run_breach_monitoring_scan(db, engagement, connection.tenant_id, error_detail=d))

    connection.last_scanned_at = datetime.now(timezone.utc)
    connection.last_scan_results = results
    if failures:
        connection.last_scan_status = "failed"
        connection.last_scan_error = "; ".join(failures)
    else:
        connection.last_scan_status = "success"
        connection.last_scan_error = None
    await db.commit()


async def rescan_all_due_connections(db: AsyncSession) -> int:
    """Entry point for the recurring scheduler job (main.py's lifespan
    tasks). Finds every connection with a currently-active authorization —
    status='connected' AND its linked engagement is 'active' — and rescans
    each. One connection's failure is logged and does not stop the batch;
    a bad account shouldn't block everyone else's scheduled scan."""
    result = await db.execute(
        select(CloudAccountConnection, Engagement)
        .join(Engagement, CloudAccountConnection.engagement_id == Engagement.id)
        .where(CloudAccountConnection.status == "connected", Engagement.status == "active")
    )
    rows = result.all()
    for connection, engagement in rows:
        try:
            await rescan_connection(db, engagement, connection)
        except Exception:
            _log.exception("Scheduled rescan failed: connection_id=%s", connection.id)
    return len(rows)
