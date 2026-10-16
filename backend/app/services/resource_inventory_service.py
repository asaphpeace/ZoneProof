"""
Cloud Resource Explorer — Phase 38 (AWS data-discard audit follow-up).
Populates `CloudAsset`, a table fully designed in the original Tier 0
data model pass and never once written to since — three separate
comments elsewhere in this codebase (`Finding` model, cloud_scan_service.py,
graph_service.py) already say some version of "doesn't yet resolve to a
CloudAsset row", confirming this was always known, unfinished foundational
work, not a new idea.

Two sources, each covering a real gap the other has:
  - Resource Groups Tagging API: the full inventory signal — every tagged
    resource in the account, regardless of whether any scan pass has ever
    evaluated it. Prowler/Inspector2/Cloudsplaining only ever see what
    they choose to check; this sees everything tagged.
  - A direct IAM listing (list_roles/list_users/list_groups): the
    reliable primary source for IAM principals specifically, since the
    Tagging API's own IAM coverage is unverified for this account (real
    AWS behavior, not something to assume from docs).

Deliberately duplicates a small amount of assume-role/region-listing logic
already present in `_discover_active_regions` (cloud_scan_service.py)
rather than refactoring that proven, heavily-tested function to share it —
this codebase already has a house precedent for small-helper duplication
over premature cross-module sharing (see Phase 33's own reasoning for
`_score_to_grade`).
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CloudAccountConnection, CloudAsset

_log = logging.getLogger(__name__)


def _resource_type_from_arn(arn: str) -> str:
    """Best-effort resource_type label from an ARN's own shape — prefers
    the resource-type segment when the ARN carries one
    (.../instance/i-... -> ec2_instance), falls back to a bare
    "{service}_resource" otherwise (a plain S3 bucket ARN has no separate
    resource-type segment at all: arn:aws:s3:::bucket-name)."""
    if not arn.startswith("arn:"):
        return "unknown"
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return "unknown"
    service, resource_part = parts[2], parts[5]
    if service == "s3" and "/" not in resource_part:
        return "s3_bucket"
    for sep in ("/", ":"):
        if sep in resource_part:
            return f"{service}_{resource_part.split(sep, 1)[0]}".replace("-", "_")
    return f"{service}_resource"


_DATA_BEARING_PREFIXES = ("rds_", "dynamodb_", "redshift_")
_NON_PROD_TAG_HINTS = ("dev", "development", "test", "testing", "staging", "stage", "sandbox", "qa")


def _infer_high_value(resource_type: str, tags: dict[str, str]) -> bool:
    """Heuristic default for CloudAsset.is_high_value — matched on the AWS
    *service* prefix rather than a guessed exact resource_type string,
    since _resource_type_from_arn()'s precise RDS/DynamoDB/Redshift output
    wasn't reliably confirmable (only inconsistent aspirational comments
    exist elsewhere in this codebase) — any resource_type starting with
    one of these service prefixes matches regardless of its exact suffix.
    A data-bearing resource with no dev/test/staging/sandbox signal in its
    own tags leans high-value; this is a starting point for the customer
    to confirm or override, never a final verdict — see CloudAsset.
    is_high_value's own docstring on the override guarantee."""
    if not (resource_type == "s3_bucket" or resource_type.startswith(_DATA_BEARING_PREFIXES)):
        return False
    combined = " ".join(f"{k} {v}" for k, v in tags.items()).lower()
    return not any(hint in combined for hint in _NON_PROD_TAG_HINTS)


async def _upsert_asset(
    db: AsyncSession, connection: CloudAccountConnection, arn: str, region: str | None, tags: dict[str, str],
) -> CloudAsset:
    """Matches CloudAsset's own documented "current state, updated in
    place" semantics — a resource seen again on a later sync bumps
    last_seen_at rather than accumulating a duplicate row."""
    existing = await db.scalar(
        select(CloudAsset).where(
            CloudAsset.cloud_account_connection_id == connection.id, CloudAsset.resource_id == arn,
        )
    )
    now = datetime.now(timezone.utc)
    if existing:
        existing.last_seen_at = now
        if region:
            existing.region = region
        if tags:
            existing.resource_metadata = {**(existing.resource_metadata or {}), "tags": tags}
        # Never touch is_high_value once a customer has manually set it —
        # high_value_set_by_user_id populated is the permanent signal,
        # same non-clobbering guarantee as ReportedEmail.disposition. Use
        # the freshest known tags (existing ones when this pass returned
        # none) rather than an empty dict, so a pass with no tag data
        # doesn't spuriously flip the heuristic to "no non-prod hint found".
        if existing.high_value_set_by_user_id is None:
            known_tags = tags or (existing.resource_metadata or {}).get("tags", {})
            existing.is_high_value = _infer_high_value(existing.resource_type, known_tags)
        return existing

    resource_type = _resource_type_from_arn(arn)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=connection.tenant_id, cloud_account_connection_id=connection.id,
        resource_type=resource_type, resource_id=arn, region=region,
        resource_metadata={"tags": tags} if tags else {},
        is_high_value=_infer_high_value(resource_type, tags),
    )
    db.add(asset)
    await db.flush()
    return asset


def _assume_connection_session(role_arn: str, external_id: str, session_name: str) -> boto3.Session:
    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=role_arn, RoleSessionName=session_name, ExternalId=external_id, DurationSeconds=900,
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _list_enabled_regions(session: boto3.Session) -> list[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    return [
        r["RegionName"] for r in ec2.describe_regions(AllRegions=True)["Regions"]
        if r["OptInStatus"] in ("opt-in-not-required", "opted-in")
    ]


def _sync_assets_from_tagging_api_sync(session: boto3.Session, connection: CloudAccountConnection, regions: list[str]) -> list[tuple[str, str, dict]]:
    """Runs in a thread (boto3 is sync) — returns (arn, region, tags)
    triples for the caller to upsert against the DB, rather than doing DB
    work off the event loop thread. One region's failure is logged and
    skipped, not allowed to blank out every other region's real
    inventory — same resilience discipline as _discover_active_regions."""
    found: list[tuple[str, str, dict]] = []
    for region in regions:
        try:
            tagging = session.client("resourcegroupstaggingapi", region_name=region)
            paginator = tagging.get_paginator("get_resources")
            for page in paginator.paginate():
                for mapping in page.get("ResourceTagMappingList", []):
                    arn = mapping.get("ResourceARN")
                    if not arn:
                        continue
                    tags = {t["Key"]: t["Value"] for t in mapping.get("Tags", [])}
                    found.append((arn, region, tags))
        except (ClientError, BotoCoreError) as e:
            _log.info("Resource inventory: tagging API failed for region=%s error=%s", region, e)
            continue
    return found


def _sync_iam_assets_sync(session: boto3.Session) -> list[str]:
    """Runs in a thread — returns every IAM role/user/group ARN. A
    separate, simple boto3 call rather than re-parsing Cloudsplaining's
    isolated-venv subprocess output, decoupling resource discovery from
    that process entirely."""
    iam = session.client("iam")
    arns: list[str] = []
    try:
        for paginate, key in (
            (iam.get_paginator("list_roles").paginate, "Roles"),
            (iam.get_paginator("list_users").paginate, "Users"),
            (iam.get_paginator("list_groups").paginate, "Groups"),
        ):
            for page in paginate():
                for item in page.get(key, []):
                    arn = item.get("Arn")
                    if arn:
                        arns.append(arn)
    except (ClientError, BotoCoreError) as e:
        _log.info("Resource inventory: IAM listing failed: %s", e)
    return arns


def _sync_ec2_instance_role_arns_sync(session: boto3.Session, regions: list[str]) -> dict[str, str]:
    """Runs in a thread — resolves each EC2 instance's attached IAM role
    (via its instance profile), the data source for graph_service.py's
    RUNS_AS edge (bridging a Prowler resource node into the Cloudsplaining
    IAM subgraph). Two AWS calls: one account-wide list_instance_profiles
    to build a profile-ARN -> role-ARN map (a profile can have zero roles
    in rare cases — skipped, never guessed), and describe_instances per
    region to read each instance's IamInstanceProfile.Arn (most instances
    have none — an honest "no role" signal, not an error). Either call's
    failure degrades to an empty/partial map, same resilience discipline
    as every other sync step in this file."""
    iam = session.client("iam")
    profile_to_role: dict[str, str] = {}
    try:
        for page in iam.get_paginator("list_instance_profiles").paginate():
            for profile in page.get("InstanceProfiles", []):
                roles = profile.get("Roles") or []
                if roles:
                    profile_to_role[profile["Arn"]] = roles[0]["Arn"]
    except (ClientError, BotoCoreError) as e:
        _log.info("Resource inventory: list_instance_profiles failed: %s", e)
        return {}

    instance_to_role: dict[str, str] = {}
    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            for page in ec2.get_paginator("describe_instances").paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        instance_id = instance.get("InstanceId")
                        profile_arn = (instance.get("IamInstanceProfile") or {}).get("Arn")
                        if not instance_id or not profile_arn:
                            continue
                        role_arn = profile_to_role.get(profile_arn)
                        if role_arn:
                            instance_to_role[instance_id] = role_arn
        except (ClientError, BotoCoreError) as e:
            _log.info("Resource inventory: describe_instances failed for region=%s error=%s", region, e)
            continue
    return instance_to_role


async def _apply_ec2_role_arns(db: AsyncSession, connection: CloudAccountConnection, instance_to_role: dict[str, str]) -> int:
    """Joins against the already-upserted ec2_instance CloudAsset rows by
    extracting each one's real instance id from its own canonical
    resource_id ARN, rather than reconstructing an ARN from scratch —
    guarantees the join key matches exactly what _upsert_asset already
    persisted. Returns how many assets actually got a role_arn this pass."""
    if not instance_to_role:
        return 0
    result = await db.execute(
        select(CloudAsset).where(
            CloudAsset.cloud_account_connection_id == connection.id,
            CloudAsset.resource_type == "ec2_instance",
        )
    )
    updated = 0
    for asset in result.scalars().all():
        instance_id = asset.resource_id.rsplit("/", 1)[-1] if "/" in asset.resource_id else None
        role_arn = instance_to_role.get(instance_id) if instance_id else None
        if role_arn and asset.resource_metadata.get("role_arn") != role_arn:
            asset.resource_metadata = {**asset.resource_metadata, "role_arn": role_arn}
            updated += 1
    return updated


def _extract_sg_rules(permissions: list[dict]) -> tuple[list[dict], set[str]]:
    """Shared by ingress/egress extraction below — a real rule's CIDRs and
    any referenced security-group ids (UserIdGroupPairs — the SG-to-SG
    reference mechanism LATERAL_MOVEMENT edges key on) in one pass.
    Collects both IPv4 (IpRanges) and IPv6 (Ipv6Ranges) CIDRs into the
    same list — EXPOSED_TO_INTERNET's own real-port check keys on this
    same data and needs both, not just IPv4."""
    rules: list[dict] = []
    referenced: set[str] = set()
    for perm in permissions:
        cidrs = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp")]
        cidrs += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6")]
        group_ids = [g["GroupId"] for g in perm.get("UserIdGroupPairs", []) if g.get("GroupId")]
        referenced.update(group_ids)
        rules.append({
            "protocol": perm.get("IpProtocol"), "from_port": perm.get("FromPort"), "to_port": perm.get("ToPort"),
            "cidrs": cidrs, "referenced_group_ids": group_ids,
        })
    return rules, referenced


def _sync_security_groups_sync(session: boto3.Session, regions: list[str]) -> dict[str, dict]:
    """Runs in a thread — the data source for graph_service.py's
    LATERAL_MOVEMENT edge. Security groups aren't reliably tagged (a real,
    confirmed-this-session account fact — untagged SGs are invisible to
    the Resource Groups Tagging API sync above), so this is a dedicated,
    complete describe_security_groups pass, not a partial reuse of
    Prowler's own fail-only-finding leftovers (Prowler's OCSF output
    carries the same ingress_rules/egress_rules shape, but only for
    groups that failed at least one check). Egress rules are captured
    alongside ingress for a later egress/exfiltration-path pass, unused
    by this phase's own edge computation."""
    found: dict[str, dict] = {}
    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            for page in ec2.get_paginator("describe_security_groups").paginate():
                for sg in page.get("SecurityGroups", []):
                    group_id = sg.get("GroupId")
                    if not group_id:
                        continue
                    ingress_rules, referenced_group_ids = _extract_sg_rules(sg.get("IpPermissions", []))
                    egress_rules, _egress_refs = _extract_sg_rules(sg.get("IpPermissionsEgress", []))
                    found[group_id] = {
                        "region": region, "vpc_id": sg.get("VpcId"),
                        "ingress_rules": ingress_rules, "egress_rules": egress_rules,
                        "referenced_group_ids": sorted(referenced_group_ids),
                    }
        except (ClientError, BotoCoreError) as e:
            _log.info("Resource inventory: describe_security_groups failed for region=%s error=%s", region, e)
            continue
    return found


def _sync_ec2_security_group_memberships_sync(session: boto3.Session, regions: list[str]) -> dict[str, list[str]]:
    """Runs in a thread — a second, separate describe_instances call
    (deliberate small API redundancy with _sync_ec2_instance_role_arns_
    sync above, traded for isolation from that function's own already-
    verified RUNS_AS tests — same small-duplication-over-shared-refactor
    precedent this file's own docstring already cites) extracting each
    instance's attached security group ids, the other half of the join
    LATERAL_MOVEMENT edges need."""
    memberships: dict[str, list[str]] = {}
    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            for page in ec2.get_paginator("describe_instances").paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        instance_id = instance.get("InstanceId")
                        if not instance_id:
                            continue
                        sg_ids = [g["GroupId"] for g in instance.get("SecurityGroups", []) if g.get("GroupId")]
                        if sg_ids:
                            memberships[instance_id] = sg_ids
        except (ClientError, BotoCoreError) as e:
            _log.info("Resource inventory: describe_instances (SG memberships) failed for region=%s error=%s", region, e)
            continue
    return memberships


async def _apply_security_group_data(
    db: AsyncSession, connection: CloudAccountConnection, sg_data: dict[str, dict],
) -> int:
    """Security groups aren't discovered by the tagging API in this
    account at all (confirmed zero existing ec2_security_group CloudAsset
    rows before this pass) — unlike _apply_ec2_role_arns/_apply_ec2_
    security_group_memberships below, this both creates new CloudAsset
    rows for previously-unseen groups and merges rule data onto existing
    ones. ARN constructed the same shape already confirmed in real
    Prowler resource_metadata (arn:aws:ec2:{region}:{account}:
    security-group/{group_id}); account_id read from connection.role_arn
    rather than a new API call."""
    if not sg_data:
        return 0
    account_id = connection.role_arn.split(":")[4]
    now = datetime.now(timezone.utc)
    applied = 0
    for group_id, data in sg_data.items():
        arn = f"arn:aws:ec2:{data['region']}:{account_id}:security-group/{group_id}"
        existing = await db.scalar(
            select(CloudAsset).where(
                CloudAsset.cloud_account_connection_id == connection.id, CloudAsset.resource_id == arn,
            )
        )
        rule_metadata = {
            "ingress_rules": data["ingress_rules"], "egress_rules": data["egress_rules"],
            "referenced_group_ids": data["referenced_group_ids"], "vpc_id": data["vpc_id"],
        }
        if existing:
            existing.last_seen_at = now
            existing.resource_metadata = {**(existing.resource_metadata or {}), **rule_metadata}
        else:
            db.add(CloudAsset(
                id=uuid.uuid4(), tenant_id=connection.tenant_id, cloud_account_connection_id=connection.id,
                resource_type="ec2_security_group", resource_id=arn, region=data["region"],
                resource_metadata=rule_metadata,
            ))
            await db.flush()
        applied += 1
    return applied


async def _apply_ec2_security_group_memberships(
    db: AsyncSession, connection: CloudAccountConnection, memberships: dict[str, list[str]],
) -> None:
    """Same join-by-instance-id-suffix-of-resource_id pattern as
    _apply_ec2_role_arns."""
    if not memberships:
        return
    result = await db.execute(
        select(CloudAsset).where(
            CloudAsset.cloud_account_connection_id == connection.id,
            CloudAsset.resource_type == "ec2_instance",
        )
    )
    for asset in result.scalars().all():
        instance_id = asset.resource_id.rsplit("/", 1)[-1] if "/" in asset.resource_id else None
        sg_ids = memberships.get(instance_id) if instance_id else None
        if sg_ids and asset.resource_metadata.get("security_group_ids") != sg_ids:
            asset.resource_metadata = {**asset.resource_metadata, "security_group_ids": sg_ids}


def _sync_s3_buckets_sync(session: boto3.Session) -> list[tuple[str, dict]]:
    """Runs in a thread — the data source for graph_service.py's
    CAN_ACCESS edge (S3, v1). S3 buckets are global-list, not per-region
    like EC2/security groups (`list_buckets()` has no region parameter),
    so this is a single call, not a per-region loop. Best-effort tagging
    lookup per bucket — `NoSuchTagSet` means "no tags", an honest signal
    fed straight into `_upsert_asset`/`_infer_high_value`, not an error."""
    found: list[tuple[str, dict]] = []
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
    except (ClientError, BotoCoreError) as e:
        _log.info("Resource inventory: list_buckets failed: %s", e)
        return []
    for bucket in buckets:
        name = bucket.get("Name")
        if not name:
            continue
        arn = f"arn:aws:s3:::{name}"
        tags: dict[str, str] = {}
        try:
            tag_resp = s3.get_bucket_tagging(Bucket=name)
            tags = {t["Key"]: t["Value"] for t in tag_resp.get("TagSet", [])}
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "NoSuchTagSet":
                _log.info("Resource inventory: get_bucket_tagging failed for bucket=%s error=%s", name, e)
        found.append((arn, tags))
    return found


_S3_ACCESS_ACTIONS = ["s3:GetObject", "s3:ListBucket", "s3:PutObject", "s3:DeleteObject"]


def _sync_can_access_grants_sync(
    session: boto3.Session, principal_arns: list[str], bucket_arns: list[str],
) -> dict[str, list[dict]]:
    """Runs in a thread — the data source for graph_service.py's
    CAN_ACCESS edge. Deliberately uses the real `iam:SimulatePrincipalPolicy`
    API rather than hand-rolling policy JSON evaluation (wildcards,
    NotAction, condition/deny precedence) — AWS already solved this
    correctly, and no complete per-principal policy JSON is even
    available in this codebase to evaluate locally (only Cloudsplaining-
    flagged policies get persisted). Bounded to `bucket_arns` the caller
    has already filtered to is_high_value — every principal is still
    checked against those, since a real access grant onto a tagged
    crown-jewel resource matters regardless of whether that principal is
    separately reachable elsewhere in the graph. One principal/bucket
    pair's failure is logged and skipped, not allowed to blank out every
    other pair's real result."""
    grants: dict[str, list[dict]] = {}
    if not principal_arns or not bucket_arns:
        return grants
    iam = session.client("iam")
    for principal_arn in principal_arns:
        for bucket_arn in bucket_arns:
            try:
                resp = iam.simulate_principal_policy(
                    PolicySourceArn=principal_arn,
                    ActionNames=_S3_ACCESS_ACTIONS,
                    ResourceArns=[bucket_arn, f"{bucket_arn}/*"],
                )
            except (ClientError, BotoCoreError) as e:
                _log.info(
                    "Resource inventory: simulate_principal_policy failed for principal=%s bucket=%s error=%s",
                    principal_arn, bucket_arn, e,
                )
                continue
            allowed = {
                r["EvalActionName"] for r in resp.get("EvaluationResults", [])
                if r.get("EvalDecision") == "allowed"
            }
            if allowed:
                grants.setdefault(principal_arn, []).append({
                    "resource_arn": bucket_arn, "resource_type": "s3_bucket",
                    "actions_allowed": sorted(allowed),
                })
    return grants


async def _apply_can_access_grants(db: AsyncSession, connection: CloudAccountConnection, grants: dict[str, list[dict]]) -> None:
    """Unlike the EC2-instance-id-suffix join pattern used elsewhere in
    this file, an IAM principal's CloudAsset.resource_id IS its ARN
    directly (see _sync_iam_assets_sync/_upsert_asset) — no join needed."""
    if not grants:
        return
    result = await db.execute(
        select(CloudAsset).where(
            CloudAsset.cloud_account_connection_id == connection.id,
            CloudAsset.resource_id.in_(grants.keys()),
        )
    )
    for asset in result.scalars().all():
        entries = grants.get(asset.resource_id)
        if entries and asset.resource_metadata.get("can_access") != entries:
            asset.resource_metadata = {**asset.resource_metadata, "can_access": entries}


async def run_resource_inventory_sync(
    db: AsyncSession, connection: CloudAccountConnection, error_detail: dict | None = None,
) -> int | None:
    """Entry point wired into rescan_connection() (Phase 38c), run first
    so CloudAsset rows exist before Prowler/Cloudsplaining/Inspector/
    credential-hygiene build their own Finding candidates and can look up
    asset_id against them. Takes no `engagement` - CloudAsset is scoped to
    the connection/tenant, not to any one engagement, unlike Finding/
    CloudPrivEscPath (see the model's own tenant_id/cloud_account_connection_id
    columns).

    Returns None only when the connection's role can't be assumed at all
    (the one real "nothing here could run" case, matching every other
    pass's None-means-didn't-run convention) - a per-region or per-service
    failure inside the two sync steps degrades gracefully instead (skip
    that piece, keep going), so a partial result is still a real int, not
    a fabricated total."""
    try:
        session = await asyncio.to_thread(
            _assume_connection_session, connection.role_arn, connection.external_id, "sentinel-command-resource-inventory",
        )
        regions = await asyncio.to_thread(_list_enabled_regions, session)
    except (ClientError, BotoCoreError, KeyError) as e:
        _log.warning("Resource inventory sync failed to assume role: connection_id=%s error=%s", connection.id, e)
        if error_detail is not None:
            error_detail["message"] = str(e)
        return None

    tagging_results = await asyncio.to_thread(_sync_assets_from_tagging_api_sync, session, connection, regions)
    for arn, region, tags in tagging_results:
        await _upsert_asset(db, connection, arn, region, tags)

    iam_arns = await asyncio.to_thread(_sync_iam_assets_sync, session)
    for arn in iam_arns:
        await _upsert_asset(db, connection, arn, None, {})

    instance_to_role = await asyncio.to_thread(_sync_ec2_instance_role_arns_sync, session, regions)
    await _apply_ec2_role_arns(db, connection, instance_to_role)

    sg_data = await asyncio.to_thread(_sync_security_groups_sync, session, regions)
    sg_applied = await _apply_security_group_data(db, connection, sg_data)

    sg_memberships = await asyncio.to_thread(_sync_ec2_security_group_memberships_sync, session, regions)
    await _apply_ec2_security_group_memberships(db, connection, sg_memberships)

    s3_bucket_results = await asyncio.to_thread(_sync_s3_buckets_sync, session)
    for arn, tags in s3_bucket_results:
        await _upsert_asset(db, connection, arn, None, tags)

    high_value_buckets = await db.execute(
        select(CloudAsset.resource_id).where(
            CloudAsset.cloud_account_connection_id == connection.id,
            CloudAsset.resource_type == "s3_bucket",
            CloudAsset.is_high_value == True,  # noqa: E712
        )
    )
    bucket_arns = [row[0] for row in high_value_buckets.all()]
    if bucket_arns:
        grants = await asyncio.to_thread(_sync_can_access_grants_sync, session, iam_arns, bucket_arns)
        await _apply_can_access_grants(db, connection, grants)

    synced = len(tagging_results) + len(iam_arns) + sg_applied + len(s3_bucket_results)
    if synced:
        await db.commit()
    return synced
