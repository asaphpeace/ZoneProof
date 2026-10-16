"""
Assembles a REAL Attack Path Graph for a tenant from CloudPrivEscPath rows
(IAM privilege-escalation), OAuthGrant rows (third-party app risk,
OAUTH_APP_RISK_DESIGN.md Section 6), RUNS_AS edges (a compute resource's
real, scan-captured attached IAM role — resource_inventory_service.py's
own describe_instances + list_instance_profiles join), EXPOSED_TO_INTERNET
edges (a real, provable "reachable from the internet" signal already
captured in Finding.extra — the same detection logic exploitability_
service.py's _score_network_finding uses, mirrored here as
_is_internet_exposed), and LATERAL_MOVEMENT edges (a real security-group-
to-security-group reference — resource_inventory_service.py's own
describe_security_groups + describe_instances join — gating same-VPC
instance-to-instance reachability; step 4a of the deeper network-
reachability phase, cross-subnet/route-table/NACL modeling deferred).
Each edge is tagged with MITRE ATT&CK technique ids — attack_technique_
mapping.py for IAM actions, its OAuth-scope counterpart for app grants, a
fixed T1078.004 tag for RUNS_AS (a structural fact, not an abused action),
a fixed T1190 tag for EXPOSED_TO_INTERNET (initial access via exposure),
a fixed T1021 tag for LATERAL_MOVEMENT (movement after an initial
foothold, distinct from both).

EDGES stay scoped to relationships this data can actually prove — no
longer only privilege-escalation and OAuth-grant; RUNS_AS, EXPOSED_TO_
INTERNET, and LATERAL_MOVEMENT all bridge a Prowler/Lynis *finding* node
into this graph, rather than just describing identity-to-identity
relationships.
NODES remain wider than edges: a "cloud_resource"/"host" node
(_compute_resource_nodes/_compute_host_nodes below) still surfaces with no
edge in or out whenever nothing provable connects it to anything else —
an honest "this exists and has a real open problem" signal, never a
fabricated connection. Deeper network-reachability edges (security
groups/NACLs/route tables) remain a separate, later, explicitly-scoped
phase, not this one — see ATTACK_PATH_GRAPH_RESEARCH.md at the repo root.
"""
from __future__ import annotations

import re
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    ActorIdentity,
    CloudAccountConnection,
    CloudAsset,
    CloudPrivEscPath,
    Finding,
    HostConnection,
    OAuthAppConnection,
    OAuthGrant,
)
from app.services.attack_technique_mapping import (
    attack_techniques_for_actions,
    attack_techniques_for_can_access,
    attack_techniques_for_internet_exposure,
    attack_techniques_for_lateral_movement,
    attack_techniques_for_oauth_scopes,
    attack_techniques_for_runs_as,
)
from app.services.identity_resolution_service import (
    open_credential_finding_counts_for_nodes,
    open_policy_risk_finding_summaries_for_nodes,
)
from app.services.privesc_remediation_mapping import remediation_for_edge

_ARN_RESOURCE_RE = re.compile(r"^arn:aws:iam::\d+:(role|user|group)/(.+)$")
_ROLE_ARN_RE = re.compile(r"^arn:aws:iam::(\d+):role/(.+)$")
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


_FRIENDLY_RESOURCE_TYPE = {
    "ec2_instance": "EC2 instance", "s3_bucket": "S3 bucket", "iam_role": "IAM role", "iam_user": "IAM user",
    "iam_group": "IAM group", "ec2_security_group": "security group", "rds_db_instance": "RDS instance",
}


def _friendly_resource_label(asset: CloudAsset) -> str:
    # Small, deliberate duplication of FindingsView.vue's own
    # FRIENDLY_RESOURCE_TYPE convention, mirrored server-side for the same
    # reason _cloud_connection_label above is — a few-entry lookup isn't
    # worth a cross-module import.
    type_label = _FRIENDLY_RESOURCE_TYPE.get(asset.resource_type, asset.resource_type.replace("_", " "))
    short_id = asset.resource_id.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    return f"{type_label} {short_id}"


def _cloud_connection_label(role_arn: str | None) -> str:
    # Small, deliberate duplication of findings.py's own helper of the same
    # name — this codebase's established convention (see e.g. Phase 33's
    # target-list duplication) over a router->service reverse import for
    # one 8-line function.
    if not role_arn:
        return "AWS account (pending verification)"
    match = _ROLE_ARN_RE.match(role_arn)
    if not match:
        return role_arn
    account_id, role_name = match.groups()
    return f"{account_id} · {role_name}"


def _friendly_label(arn: str) -> tuple[str, str]:
    """Returns (label, hue) for an IAM ARN — falls back to the raw ARN and
    a neutral hue for anything that doesn't match the standard IAM
    role/user/group shape (e.g. an account-admin placeholder)."""
    match = _ARN_RESOURCE_RE.match(arn)
    if not match:
        return arn, "cyan"
    kind, name = match.groups()
    hue = {"role": "amber", "user": "violet", "group": "violet"}.get(kind, "cyan")
    return f"{kind}/{name}", hue


def _relative_time(dt: datetime) -> str:
    diff = datetime.now(timezone.utc) - dt
    mins = int(diff.total_seconds() // 60)
    if mins < 1:
        return "just now"
    if mins < 60:
        return f"{mins}m ago"
    hrs = mins // 60
    if hrs < 24:
        return f"{hrs}h ago"
    return f"{hrs // 24}d ago"


async def _resolve_oauth_source_node_id(db: AsyncSession, tenant_id: uuid.UUID, grantee_email: str) -> str:
    """The identity-resolution payoff (OAUTH_APP_RISK_DESIGN.md Section 6):
    if the grantee's Actor also has a known AWS IAM identity, reuse that
    ARN as the node id so the OAuth edge attaches to the *same* node as
    that person's IAM privilege-escalation path, instead of a disconnected
    second node for the same human. Falls back to the raw email — still a
    real node, just not merged with anything — when no such match exists."""
    identity_result = await db.execute(
        select(ActorIdentity).where(
            ActorIdentity.tenant_id == tenant_id, ActorIdentity.source == "microsoft365",
            ActorIdentity.principal_id == grantee_email,
        )
    )
    identity = identity_result.scalar_one_or_none()
    if not identity:
        return grantee_email

    aws_result = await db.execute(
        select(ActorIdentity).where(
            ActorIdentity.tenant_id == tenant_id, ActorIdentity.actor_id == identity.actor_id,
            ActorIdentity.source == "aws_iam",
        )
    )
    aws_identity = aws_result.scalar_one_or_none()
    return aws_identity.principal_id if aws_identity else grantee_email


def _node_defaults(node_id: str, label: str, hue: str, kind: str, detail: str, discovered_at: datetime) -> dict:
    return {
        "id": node_id, "label": label, "hue": hue, "kind": kind,
        "detail": detail, "discovered": _relative_time(discovered_at),
        "open_credential_findings": 0, "open_policy_risk_findings": 0, "policy_risk_worst_severity": None,
        "open_findings": 0, "findings_worst_severity": None,
        # Customer/heuristic "this asset matters" signal (CloudAsset.
        # is_high_value) — False default for anything not backed by a real
        # CloudAsset (principals, third-party apps, the internet node).
        "is_high_value": False,
    }


async def _compute_resource_nodes(
    db: AsyncSession, tenant_id: uuid.UUID, cloud_connection: CloudAccountConnection | None,
) -> list[dict]:
    """Real Prowler/Inspector/Cloudsplaining findings, surfaced as their own
    standalone node — never the full resource inventory (that's Coverage
    Map's job), only resources with a real open cloud-tier problem. Finding
    queried first (not CloudAsset first) so a tenant with a large inventory
    but few open findings doesn't pay for loading it all — two queries
    total, not N+1."""
    finding_rows = (
        await db.execute(
            select(Finding.asset_id, Finding.severity).where(
                Finding.tenant_id == tenant_id, Finding.tier == "cloud", Finding.status == "open",
                Finding.asset_id.is_not(None),
            )
        )
    ).all()
    severities_by_asset: dict[uuid.UUID, list[str]] = defaultdict(list)
    for row in finding_rows:
        severities_by_asset[row.asset_id].append(row.severity)
    if not severities_by_asset:
        return []

    asset_query = select(CloudAsset).where(CloudAsset.id.in_(severities_by_asset.keys()))
    if cloud_connection:
        asset_query = asset_query.where(CloudAsset.cloud_account_connection_id == cloud_connection.id)
    assets = (await db.execute(asset_query)).scalars().all()

    nodes = []
    for asset in assets:
        severities = severities_by_asset[asset.id]
        worst = max(severities, key=lambda s: _SEVERITY_RANK.get(s, 0))
        node = _node_defaults(
            asset.resource_id, _friendly_resource_label(asset), "cyan", "cloud_resource",
            asset.resource_id, asset.last_seen_at,
        )
        node["open_findings"] = len(severities)
        node["findings_worst_severity"] = worst
        node["is_high_value"] = bool(asset.is_high_value)
        nodes.append(node)
    return nodes


async def _compute_host_nodes(
    db: AsyncSession, tenant_id: uuid.UUID, host_connection: HostConnection | None,
) -> list[dict]:
    """Same real-findings-only signal as _compute_resource_nodes, for VPS/
    server hosts scanned via Lynis. hostname_or_ip is the only stable
    per-host identifier this data model has (host_scan_service.py's own
    resource_uid choice) — prefixed "host:" as the node id so it can never
    collide with an ARN-shaped IAM node id."""
    host_query = select(HostConnection).where(
        HostConnection.tenant_id == tenant_id, HostConnection.status == "connected",
    )
    if host_connection:
        host_query = host_query.where(HostConnection.id == host_connection.id)
    hosts = (await db.execute(host_query)).scalars().all()
    if not hosts:
        return []

    hostnames = [h.hostname_or_ip for h in hosts]
    finding_rows = (
        await db.execute(
            select(Finding.resource_uid, Finding.severity).where(
                Finding.tenant_id == tenant_id, Finding.tier == "host", Finding.status == "open",
                Finding.resource_uid.in_(hostnames),
            )
        )
    ).all()
    severities_by_host: dict[str, list[str]] = defaultdict(list)
    for row in finding_rows:
        severities_by_host[row.resource_uid].append(row.severity)

    nodes = []
    for host in hosts:
        severities = severities_by_host.get(host.hostname_or_ip)
        if not severities:
            continue
        worst = max(severities, key=lambda s: _SEVERITY_RANK.get(s, 0))
        node = _node_defaults(
            f"host:{host.hostname_or_ip}", host.display_name or host.hostname_or_ip, "cyan", "host",
            host.hostname_or_ip, host.last_scanned_at or host.created_at,
        )
        node["open_findings"] = len(severities)
        node["findings_worst_severity"] = worst
        nodes.append(node)
    return nodes


async def _compute_ec2_role_assignments(
    db: AsyncSession, tenant_id: uuid.UUID, cloud_connection: CloudAccountConnection | None,
) -> list[tuple[CloudAsset, str]]:
    """EC2 instances with a real, scan-captured IAM role attachment
    (resource_inventory_service.py's describe_instances + list_instance_
    profiles join) — the data source for the RUNS_AS edge, bridging a
    standalone Prowler resource node into the same identity graph
    CloudPrivEscPath edges already populate. Scans every tenant CloudAsset
    row regardless of whether it also has an open Finding — an instance
    can be worth showing connected to its role even with a clean scan
    result today (the role itself may still be escalatable, or may become
    so on a future scan)."""
    query = select(CloudAsset).where(
        CloudAsset.tenant_id == tenant_id, CloudAsset.resource_type == "ec2_instance",
        CloudAsset.resource_metadata["role_arn"].astext.is_not(None),
    )
    if cloud_connection:
        query = query.where(CloudAsset.cloud_account_connection_id == cloud_connection.id)
    assets = (await db.execute(query)).scalars().all()
    return [(asset, asset.resource_metadata["role_arn"]) for asset in assets]


def _is_internet_exposed(extra: dict | None) -> bool:
    """Exact mirror of exploitability_service.py's own _score_network_finding
    detection logic — same real signal (Prowler's categories tag and/or a
    real public_ip nested under resource_metadata.metadata), same
    established per-file-duplication convention already used throughout
    this module."""
    extra = extra or {}
    categories = extra.get("categories") or []
    resource_metadata = extra.get("resource_metadata") or {}
    resource_fields = resource_metadata.get("metadata")
    if not isinstance(resource_fields, dict):
        resource_fields = resource_metadata
    return "internet-exposed" in categories or bool(resource_fields.get("public_ip"))


async def _compute_internet_exposed_assets(
    db: AsyncSession, tenant_id: uuid.UUID, cloud_connection: CloudAccountConnection | None,
) -> list[tuple[CloudAsset, str, list[dict]]]:
    """Real, provable attack entry points — a resource with at least one
    open cloud-tier Finding whose own extra data shows it's reachable from
    the internet. Not scoped to ec2_instance (unlike _compute_ec2_role_
    assignments above) since internet exposure applies to any Prowler-
    checked resource type. Severity is the worst among just this asset's
    exposed findings, not its findings generally — a resource's other,
    unrelated open findings shouldn't inflate what is specifically an
    exposure edge's own severity. Third tuple element is EVERY real
    matching port/protocol/CIDR rule ({"port", "protocol", "cidr"}) when
    the EC2 port-based signal below fired for that asset, else [] — honest
    "no port-level evidence available" for non-EC2 resources or a
    Finding-only EC2 exposure, and never silently dropping any of an
    instance's real open ports (a real gap this session's own earlier
    "keep only the worst one" version had)."""
    finding_rows = (
        await db.execute(
            select(Finding.asset_id, Finding.severity, Finding.extra).where(
                Finding.tenant_id == tenant_id, Finding.tier == "cloud", Finding.status == "open",
                Finding.asset_id.is_not(None),
            )
        )
    ).all()
    worst_by_asset: dict[uuid.UUID, str] = {}
    for row in finding_rows:
        if not _is_internet_exposed(row.extra):
            continue
        rank = _SEVERITY_RANK.get(row.severity, 0)
        if rank > _SEVERITY_RANK.get(worst_by_asset.get(row.asset_id, ""), 0):
            worst_by_asset[row.asset_id] = row.severity

    # Real, port-level evidence for EC2 instances — additive to the
    # Finding-based signal above, never a replacement (non-EC2 resource
    # types have no security groups at all, so they stay Finding-only).
    # Folded into the SAME worst_by_asset dict so an instance with both
    # signals still gets exactly one edge at the genuinely worst severity,
    # and an instance with ONLY a real open port (no matching Prowler
    # finding) now correctly gets an edge too — closing a real detection
    # gap, not just adding evidence to already-detected cases. The port
    # evidence itself is kept regardless of which signal "won" the
    # severity comparison — a real confirmed open port is relevant
    # evidence either way.
    port_data_by_asset = await _compute_ec2_internet_exposed_ports(db, tenant_id, cloud_connection)
    for asset_id, port_info in port_data_by_asset.items():
        rank = _SEVERITY_RANK.get(port_info["severity"], 0)
        if rank > _SEVERITY_RANK.get(worst_by_asset.get(asset_id, ""), 0):
            worst_by_asset[asset_id] = port_info["severity"]

    if not worst_by_asset:
        return []

    asset_query = select(CloudAsset).where(CloudAsset.id.in_(worst_by_asset.keys()))
    if cloud_connection:
        asset_query = asset_query.where(CloudAsset.cloud_account_connection_id == cloud_connection.id)
    assets = (await db.execute(asset_query)).scalars().all()
    return [
        (asset, worst_by_asset[asset.id], port_data_by_asset.get(asset.id, {}).get("ports", []))
        for asset in assets
    ]


_SENSITIVE_LATERAL_MOVEMENT_PORTS = {22, 3389, 3306, 5432, 1433, 6379, 27017}


def _lateral_movement_severity(port: int | None) -> str:
    """A well-known remote-access/database port is a real, specific signal
    driving severity up — unlike RUNS_AS/EXPOSED_TO_INTERNET's fixed
    fallbacks, this edge always carries a real port number to key off."""
    return "high" if port in _SENSITIVE_LATERAL_MOVEMENT_PORTS else "medium"


async def _compute_lateral_movement_pairs(
    db: AsyncSession, tenant_id: uuid.UUID, cloud_connection: CloudAccountConnection | None,
) -> list[tuple[CloudAsset, CloudAsset, int | None, str | None]]:
    """Same-VPC security-group-to-security-group reachability — step 4a of
    the network-reachability phase (ATTACK_PATH_GRAPH_RESEARCH.md). Same-
    VPC default routing means no NACL/route-table modeling is needed for
    this edge; only a real UserIdGroupPairs reference in a destination
    security group's own ingress rule gates it (resource_inventory_
    service.py's dedicated describe_security_groups pass — security groups
    aren't tagged in this account, so they're invisible to the tagging-API
    sync). Returns (source_instance, dest_instance, from_port, protocol)
    tuples — a many-to-many join (multiple instances can share a security
    group on either side), not the clean one-tuple-per-asset shape RUNS_AS/
    EXPOSED_TO_INTERNET use above."""
    instance_query = select(CloudAsset).where(
        CloudAsset.tenant_id == tenant_id, CloudAsset.resource_type == "ec2_instance",
        CloudAsset.resource_metadata["security_group_ids"].astext.is_not(None),
    )
    sg_query = select(CloudAsset).where(
        CloudAsset.tenant_id == tenant_id, CloudAsset.resource_type == "ec2_security_group",
        CloudAsset.resource_metadata["referenced_group_ids"].astext.is_not(None),
    )
    if cloud_connection:
        instance_query = instance_query.where(CloudAsset.cloud_account_connection_id == cloud_connection.id)
        sg_query = sg_query.where(CloudAsset.cloud_account_connection_id == cloud_connection.id)

    instances = (await db.execute(instance_query)).scalars().all()
    security_groups = (await db.execute(sg_query)).scalars().all()
    if not instances or not security_groups:
        return []

    instances_by_sg: dict[str, list[CloudAsset]] = defaultdict(list)
    for instance in instances:
        for sg_id in instance.resource_metadata.get("security_group_ids") or []:
            instances_by_sg[sg_id].append(instance)

    pairs: list[tuple[CloudAsset, CloudAsset, int | None, str | None]] = []
    seen: set[tuple[uuid.UUID, uuid.UUID, int | None, str | None]] = set()
    for sg in security_groups:
        dest_sg_id = sg.resource_id.rsplit("/", 1)[-1]
        destinations = instances_by_sg.get(dest_sg_id, [])
        if not destinations:
            continue
        for rule in sg.resource_metadata.get("ingress_rules") or []:
            for source_sg_id in rule.get("referenced_group_ids") or []:
                if source_sg_id == dest_sg_id:
                    continue  # an SG allowing ingress from itself is not lateral movement
                for source in instances_by_sg.get(source_sg_id, []):
                    for dest in destinations:
                        if source.id == dest.id:
                            continue
                        key = (source.id, dest.id, rule.get("from_port"), rule.get("protocol"))
                        if key in seen:
                            continue
                        seen.add(key)
                        pairs.append((source, dest, rule.get("from_port"), rule.get("protocol")))
    return pairs


_INTERNET_CIDRS = {"0.0.0.0/0", "::/0"}


def _internet_exposure_port_severity(port: int | None) -> str:
    """Real, port-level evidence (an ingress rule genuinely open to
    0.0.0.0/0 or ::/0, not just another security group) — reuses the same
    well-known-port set LATERAL_MOVEMENT does, but scores one tier higher:
    a sensitive port open to the raw internet is worse than the same port
    reachable only from within the VPC (that edge's own "high" ceiling),
    and any other real open port is still worse than LATERAL_MOVEMENT's
    "medium" baseline — reachable by anyone on the internet is
    categorically worse than reachable by another already-compromised
    instance in the same VPC."""
    return "critical" if port in _SENSITIVE_LATERAL_MOVEMENT_PORTS else "high"


async def _compute_ec2_internet_exposed_ports(
    db: AsyncSession, tenant_id: uuid.UUID, cloud_connection: CloudAccountConnection | None,
) -> dict[uuid.UUID, dict]:
    """Real, port-level internet-exposure evidence for EC2 instances,
    additive to (never replacing) _is_internet_exposed's Finding-category/
    public_ip signal — the same describe_security_groups ingress_rules
    data LATERAL_MOVEMENT already uses (resource_inventory_service.py's
    dedicated SG scan), read for the opposite case: a rule whose cidrs
    include the raw internet (0.0.0.0/0 or ::/0) AND carries no
    referenced_group_ids (open to anyone, not scoped to another security
    group — the exact opposite of what LATERAL_MOVEMENT filters for) is
    real evidence anyone on the internet, not just another compromised
    instance, can reach this specific port directly. Returns
    {asset_id: {"severity", "ports": [{"port", "protocol", "cidr"}, ...]}}
    — EVERY real matching rule per instance, not just the worst one (a
    real, live gap found this session: keeping only the single worst
    match silently dropped an instance's other real open ports, including
    the one actually running the customer's own application). Severity is
    still the worst among all matches — only the evidence list changed
    from one to all — same instance/SG query shape as
    _compute_lateral_movement_pairs above."""
    instance_query = select(CloudAsset).where(
        CloudAsset.tenant_id == tenant_id, CloudAsset.resource_type == "ec2_instance",
        CloudAsset.resource_metadata["security_group_ids"].astext.is_not(None),
    )
    sg_query = select(CloudAsset).where(
        CloudAsset.tenant_id == tenant_id, CloudAsset.resource_type == "ec2_security_group",
        CloudAsset.resource_metadata["ingress_rules"].astext.is_not(None),
    )
    if cloud_connection:
        instance_query = instance_query.where(CloudAsset.cloud_account_connection_id == cloud_connection.id)
        sg_query = sg_query.where(CloudAsset.cloud_account_connection_id == cloud_connection.id)

    instances = (await db.execute(instance_query)).scalars().all()
    security_groups = (await db.execute(sg_query)).scalars().all()
    if not instances or not security_groups:
        return {}

    sgs_by_id = {sg.resource_id.rsplit("/", 1)[-1]: sg for sg in security_groups}
    result_by_asset: dict[uuid.UUID, dict] = {}
    for instance in instances:
        seen: set[tuple] = set()
        worst_severity = ""
        ports: list[dict] = []
        for sg_id in instance.resource_metadata.get("security_group_ids") or []:
            sg = sgs_by_id.get(sg_id)
            if not sg:
                continue
            for rule in sg.resource_metadata.get("ingress_rules") or []:
                if rule.get("referenced_group_ids"):
                    continue  # scoped to another SG, not the raw internet
                matched_cidr = next((c for c in (rule.get("cidrs") or []) if c in _INTERNET_CIDRS), None)
                if not matched_cidr:
                    continue
                key = (rule.get("from_port"), rule.get("protocol"), matched_cidr)
                if key in seen:
                    continue  # the same rule reachable via more than one SG membership path
                seen.add(key)
                severity = _internet_exposure_port_severity(rule.get("from_port"))
                if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(worst_severity, 0):
                    worst_severity = severity
                ports.append({"port": rule.get("from_port"), "protocol": rule.get("protocol"), "cidr": matched_cidr})
        if ports:
            result_by_asset[instance.id] = {"severity": worst_severity, "ports": ports}
    return result_by_asset


_S3_DESTRUCTIVE_ACTIONS = {"s3:PutObject", "s3:DeleteObject"}
_S3_CONTENT_READ_ACTIONS = {"s3:GetObject"}


def _can_access_severity(actions_allowed: list[str]) -> str:
    """Real, live-verified distinction (found during this edge's own
    live verification — several AWS-managed policies, including
    ViewOnlyAccess itself, grant s3:ListBucket broadly): ListBucket alone
    only proves a principal can enumerate a bucket's object names/
    metadata, not read their actual content — a real but meaningfully
    smaller risk than GetObject, which proves real data access. Treating
    both the same would overclaim risk for the (common) ListBucket-only
    case. Write/destroy access is worse still."""
    if any(a in _S3_DESTRUCTIVE_ACTIONS for a in actions_allowed):
        return "critical"
    if any(a in _S3_CONTENT_READ_ACTIONS for a in actions_allowed):
        return "high"
    return "medium"


async def _compute_can_access_edges(
    db: AsyncSession, tenant_id: uuid.UUID, cloud_connection: CloudAccountConnection | None,
) -> list[tuple[CloudAsset, CloudAsset, list[str]]]:
    """CAN_ACCESS (S3, v1) — bridges an escalated identity to the real
    data it can reach. The actual simulate_principal_policy evaluation
    happens once per scan in resource_inventory_service.py; this is a
    pure DB read of that already-computed result, matching every other
    edge-computation function in this module (no live AWS calls at
    graph-view time). Returns (principal_asset, bucket_asset,
    actions_allowed) tuples."""
    principal_query = select(CloudAsset).where(
        CloudAsset.tenant_id == tenant_id,
        CloudAsset.resource_type.in_(["iam_role", "iam_user"]),
        CloudAsset.resource_metadata["can_access"].astext.is_not(None),
    )
    if cloud_connection:
        principal_query = principal_query.where(CloudAsset.cloud_account_connection_id == cloud_connection.id)
    principals = (await db.execute(principal_query)).scalars().all()
    if not principals:
        return []

    bucket_arns = {
        entry["resource_arn"] for principal in principals
        for entry in principal.resource_metadata.get("can_access") or []
    }
    bucket_query = select(CloudAsset).where(CloudAsset.resource_id.in_(bucket_arns))
    if cloud_connection:
        bucket_query = bucket_query.where(CloudAsset.cloud_account_connection_id == cloud_connection.id)
    buckets_by_arn = {b.resource_id: b for b in (await db.execute(bucket_query)).scalars().all()}

    results: list[tuple[CloudAsset, CloudAsset, list[str]]] = []
    for principal in principals:
        for entry in principal.resource_metadata.get("can_access") or []:
            bucket = buckets_by_arn.get(entry["resource_arn"])
            if not bucket:
                continue
            results.append((principal, bucket, entry["actions_allowed"]))
    return results


async def build_tenant_privesc_graph(db: AsyncSession, tenant_id: uuid.UUID, connection_id: str | None = None) -> dict:
    # Real scan-selector support: with no connection_id, this is the
    # original flat tenant-wide aggregate below, unchanged. With one, the
    # graph narrows to exactly one AWS connection (paths only, no OAuth —
    # a different provider's scope entirely) or one OAuth connection
    # (grants only, no privesc paths) — never both, since a "scan" is one
    # connection in this data model, not a cross-provider blend. An id
    # that matches neither (wrong tenant, stale id) degrades to an honest
    # empty graph rather than raising, matching this codebase's existing
    # safe-degrade convention elsewhere (e.g. FindingsView's resource_uid
    # filter).
    viewing: dict | None = None
    cloud_connection: CloudAccountConnection | None = None
    oauth_connection: OAuthAppConnection | None = None
    host_connection: HostConnection | None = None
    if connection_id:
        cloud_connection = await db.scalar(
            select(CloudAccountConnection).where(
                CloudAccountConnection.id == connection_id, CloudAccountConnection.tenant_id == tenant_id,
            )
        )
        if not cloud_connection:
            oauth_connection = await db.scalar(
                select(OAuthAppConnection).where(
                    OAuthAppConnection.id == connection_id, OAuthAppConnection.tenant_id == tenant_id,
                )
            )
        if not cloud_connection and not oauth_connection:
            host_connection = await db.scalar(
                select(HostConnection).where(
                    HostConnection.id == connection_id, HostConnection.tenant_id == tenant_id,
                )
            )
        if cloud_connection:
            viewing = {
                "id": str(cloud_connection.id), "provider": cloud_connection.provider,
                "label": cloud_connection.display_name or _cloud_connection_label(cloud_connection.role_arn),
            }
        elif oauth_connection:
            viewing = {
                "id": str(oauth_connection.id), "provider": oauth_connection.provider,
                "label": oauth_connection.ms_tenant_id or "Microsoft 365",
            }
        elif host_connection:
            viewing = {
                "id": str(host_connection.id), "provider": "host",
                "label": host_connection.display_name or host_connection.hostname_or_ip,
            }

    # A selected connection shows only ITS OWN kind of node/edge — a "scan"
    # is exactly one connection in this data model, never a cross-provider
    # blend. host_connection excludes both IAM privesc and OAuth entirely,
    # same exclusivity the existing cloud/oauth branches already have.
    non_iam_scope = bool(oauth_connection or host_connection)
    non_oauth_scope = bool(cloud_connection or host_connection)
    non_resource_scope = bool(oauth_connection or host_connection)
    non_host_scope = bool(cloud_connection or oauth_connection)

    # Phase 39a: includes retest_closed rows too, not just open — every
    # retest_closed row was genuinely open on a prior scan (the model's own
    # docstring), so rendering it as a "severed" edge is a real, honest
    # state, not a fabricated one. Each edge carries its own status so the
    # frontend can tell open from severed.
    if non_iam_scope:
        paths = []
    else:
        path_query = select(CloudPrivEscPath).where(
            CloudPrivEscPath.tenant_id == tenant_id, CloudPrivEscPath.status.in_(["open", "retest_closed"]),
        )
        if cloud_connection:
            path_query = path_query.where(CloudPrivEscPath.cloud_account_connection_id == cloud_connection.id)
        elif connection_id:  # a connection_id was given but matched no table — honest empty, not a leak
            path_query = path_query.where(CloudPrivEscPath.id.is_(None))
        result = await db.execute(path_query.order_by(CloudPrivEscPath.discovered_at.desc()))
        paths = result.scalars().all()
    open_paths = [p for p in paths if p.status == "open"]

    if non_oauth_scope:
        grants = []
    else:
        grant_query = select(OAuthGrant).where(OAuthGrant.tenant_id == tenant_id)
        if oauth_connection:
            grant_query = grant_query.where(OAuthGrant.connection_id == oauth_connection.id)
        elif connection_id:
            grant_query = grant_query.where(OAuthGrant.id.is_(None))
        oauth_result = await db.execute(grant_query.order_by(OAuthGrant.discovered_at.desc()))
        grants = oauth_result.scalars().all()

    # A connection_id that matched none of the three tables (foreign
    # tenant, stale id) must degrade to empty everywhere, including these
    # two — otherwise cloud_connection/host_connection both being None
    # would read as "unfiltered" and leak every other connection's nodes.
    unmatched_connection_id = bool(connection_id) and not (cloud_connection or oauth_connection or host_connection)
    if unmatched_connection_id:
        resource_nodes, host_nodes, runs_as_pairs, exposed_assets, lateral_pairs, can_access_pairs = [], [], [], [], [], []
    else:
        resource_nodes = [] if non_resource_scope else await _compute_resource_nodes(db, tenant_id, cloud_connection)
        host_nodes = [] if non_host_scope else await _compute_host_nodes(db, tenant_id, host_connection)
        # Same scoping rule as resource_nodes above — EC2-role data is
        # cloud-connection-derived, so a selected OAuth/host connection
        # (non_resource_scope) sees none of it, matching resource_nodes
        # exactly rather than introducing a separate scoping flag.
        runs_as_pairs = [] if non_resource_scope else await _compute_ec2_role_assignments(db, tenant_id, cloud_connection)
        exposed_assets = [] if non_resource_scope else await _compute_internet_exposed_assets(db, tenant_id, cloud_connection)
        lateral_pairs = [] if non_resource_scope else await _compute_lateral_movement_pairs(db, tenant_id, cloud_connection)
        can_access_pairs = [] if non_resource_scope else await _compute_can_access_edges(db, tenant_id, cloud_connection)

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def _ensure_node(
        node_id: str, discovered_at: datetime, kind: str = "principal",
        label_override: str | None = None, hue_override: str | None = None,
    ) -> None:
        if node_id in nodes:
            return
        if label_override:
            label, hue = label_override, (hue_override or "violet")
        else:
            label, hue = _friendly_label(node_id)
        nodes[node_id] = _node_defaults(node_id, label, hue, kind, node_id, discovered_at)

    for path in paths:
        _ensure_node(path.source_principal_arn, path.discovered_at)
        _ensure_node(path.target_principal_arn, path.discovered_at)
        edges.append({
            "source": path.source_principal_arn,
            "target": path.target_principal_arn,
            "severity": path.severity,
            "technique_chain": path.technique_chain,
            "attack_techniques": attack_techniques_for_actions(path.technique_chain),
            "discovered": _relative_time(path.discovered_at),
            "escalation_type": path.escalation_type,
            "policy_name": path.policy_name,
            "policy_arn": path.policy_arn,
            "priv_esc_path_id": str(path.id),
            "status": path.status,
            "closed": _relative_time(path.closed_at) if path.closed_at else None,
            "remediation": remediation_for_edge(path.escalation_type, path.technique_chain),
            "edge_type": "priv_esc",
        })

    for grant in grants:
        source_node_id = await _resolve_oauth_source_node_id(db, tenant_id, grant.grantee_principal)
        app_node_id = f"app:{grant.app_client_id}"
        _ensure_node(source_node_id, grant.discovered_at)
        _ensure_node(app_node_id, grant.discovered_at, kind="third_party_app", label_override=grant.app_name)
        edges.append({
            "source": source_node_id,
            "target": app_node_id,
            "severity": grant.risk_tier,
            "technique_chain": grant.scopes,
            "attack_techniques": attack_techniques_for_oauth_scopes(grant.scopes),
            "discovered": _relative_time(grant.discovered_at),
            "status": "open",  # OAuthGrant has no revoked/closed concept in this schema — always a currently-active grant
            "remediation": remediation_for_edge(None, grant.scopes),
            "edge_type": "oauth_grant",
        })

    # RUNS_AS — bridges a standalone Prowler resource node (no edge in or
    # out, per this module's own docstring above) into the same identity
    # graph CloudPrivEscPath edges populate: "this compute resource
    # executes as this IAM role." Severity inherits the role's own worst
    # OPEN CloudPrivEscPath severity when one exists (the edge then
    # honestly signals "and this resource runs as that escalatable role"),
    # else a conservative "low" — RUNS_AS is a real structural fact on its
    # own, but running as a non-escalatable role is not itself high risk,
    # and this must never fabricate risk beyond what a real signal supports.
    role_worst_severity: dict[str, str] = {}
    for path in open_paths:
        rank = _SEVERITY_RANK.get(path.severity, 0)
        if rank > _SEVERITY_RANK.get(role_worst_severity.get(path.source_principal_arn, ""), 0):
            role_worst_severity[path.source_principal_arn] = path.severity

    for asset, role_arn in runs_as_pairs:
        _ensure_node(
            asset.resource_id, asset.last_seen_at, kind="cloud_resource",
            label_override=_friendly_resource_label(asset), hue_override="cyan",
        )
        nodes[asset.resource_id]["is_high_value"] = bool(asset.is_high_value)
        _ensure_node(role_arn, asset.last_seen_at)
        severity = role_worst_severity.get(role_arn, "low")
        edges.append({
            "source": asset.resource_id,
            "target": role_arn,
            "severity": severity,
            "technique_chain": [],
            "attack_techniques": attack_techniques_for_runs_as(),
            "discovered": _relative_time(asset.last_seen_at),
            "status": "open",  # a structural fact, not a finding — no revoked/closed concept
            "remediation": remediation_for_edge("RunsAsRole", []),
            "edge_type": "runs_as",
        })

    # EXPOSED_TO_INTERNET — a real, provable attack entry point: this
    # resource has at least one open Finding showing it's reachable from
    # the internet. One shared "internet" node across every exposed
    # resource (natural dedup via _ensure_node's own guard) — this also
    # makes "internet" the graph's real level-0 entry point once any
    # exposure exists, continuing the ENTRY -> FOOTHOLD chain into
    # whatever RUNS_AS/privesc edges exist beyond it.
    for asset, severity, exposed_ports in exposed_assets:
        _ensure_node("internet", asset.last_seen_at, kind="internet", label_override="Public Internet", hue_override="red")
        _ensure_node(
            asset.resource_id, asset.last_seen_at, kind="cloud_resource",
            label_override=_friendly_resource_label(asset), hue_override="cyan",
        )
        nodes[asset.resource_id]["is_high_value"] = bool(asset.is_high_value)
        edges.append({
            "source": "internet",
            "target": asset.resource_id,
            "severity": severity,
            "technique_chain": [],
            "attack_techniques": attack_techniques_for_internet_exposure(),
            "discovered": _relative_time(asset.last_seen_at),
            "status": "open",  # a network/structural fact, not a finding — no revoked/closed concept
            "remediation": remediation_for_edge("InternetExposed", []),
            "edge_type": "exposed_to_internet",
            # Real evidence for the graph's own evidence panel — EVERY real
            # matched security-group rule, not just the one that drove
            # severity. [] when exposure came from the Finding-based signal
            # alone (non-EC2 resources, or no matching raw-internet SG rule).
            "exposed_ports": exposed_ports,
        })

    # LATERAL_MOVEMENT — same-VPC security-group-to-security-group
    # reachability (step 4a of network-reachability). Both instance nodes
    # ensured the same way RUNS_AS/EXPOSED_TO_INTERNET do, so this
    # composes into whatever chain those edges already established
    # (internet -> exposed instance -> [lateral hop] -> another instance
    # -> its own role, etc.).
    for source_asset, dest_asset, from_port, protocol in lateral_pairs:
        _ensure_node(
            source_asset.resource_id, source_asset.last_seen_at, kind="cloud_resource",
            label_override=_friendly_resource_label(source_asset), hue_override="cyan",
        )
        nodes[source_asset.resource_id]["is_high_value"] = bool(source_asset.is_high_value)
        _ensure_node(
            dest_asset.resource_id, dest_asset.last_seen_at, kind="cloud_resource",
            label_override=_friendly_resource_label(dest_asset), hue_override="cyan",
        )
        nodes[dest_asset.resource_id]["is_high_value"] = bool(dest_asset.is_high_value)
        edges.append({
            "source": source_asset.resource_id,
            "target": dest_asset.resource_id,
            "severity": _lateral_movement_severity(from_port),
            "technique_chain": [],
            "attack_techniques": attack_techniques_for_lateral_movement(),
            "discovered": _relative_time(dest_asset.last_seen_at),
            "status": "open",  # a real network fact, not a finding — no revoked/closed concept
            "remediation": remediation_for_edge("LateralMovement", []),
            "edge_type": "lateral_movement",
        })

    # CAN_ACCESS (S3, v1) — bridges an escalated identity to the real data
    # it can reach, the actual "toxic combination" story (exposure +
    # privilege + real sensitive data) is_high_value tagging was built for
    # but nothing fed until now. The evaluation itself (real
    # iam:SimulatePrincipalPolicy calls) happens once per scan in
    # resource_inventory_service.py — this loop only ever renders an
    # already-confirmed result, never re-evaluates live.
    for principal_asset, bucket_asset, actions_allowed in can_access_pairs:
        _ensure_node(principal_asset.resource_id, principal_asset.last_seen_at)
        _ensure_node(
            bucket_asset.resource_id, bucket_asset.last_seen_at, kind="cloud_resource",
            label_override=_friendly_resource_label(bucket_asset), hue_override="cyan",
        )
        nodes[bucket_asset.resource_id]["is_high_value"] = bool(bucket_asset.is_high_value)
        edges.append({
            "source": principal_asset.resource_id,
            "target": bucket_asset.resource_id,
            "severity": _can_access_severity(actions_allowed),
            "technique_chain": [],
            "attack_techniques": attack_techniques_for_can_access(),
            "discovered": _relative_time(bucket_asset.last_seen_at),
            "status": "open",  # a real, confirmed policy grant, not a finding — no revoked/closed concept
            "remediation": remediation_for_edge("CanAccessData", []),
            "edge_type": "can_access",
        })

    # Phase 36f/37 — the graph's own scope stays edges-only (IAM privesc +
    # OAuth), per this module's docstring, but one narrow exception is
    # honest rather than fabricated: credential-tier findings key
    # resource_uid on the same bare principal identifier a graph node's
    # own id already uses — a real, provable match, not an invented link.
    # Resolved through Actor/ActorIdentity (Phase 37), not raw string
    # equality — this is what lets a credential finding registered under a
    # *different* source (a future Azure/GCP/Google-Workspace identity
    # already merged onto the same human via email) count toward this same
    # node, without this file needing to know anything about that
    # provider. Every other Finding tier still stays off the graph
    # entirely, same as before.
    if nodes:
        counts = await open_credential_finding_counts_for_nodes(db, tenant_id, list(nodes.keys()))
        for node_id, count in counts.items():
            nodes[node_id]["open_credential_findings"] = count

        # A distinct, comparably-prominent signal for the subset of that
        # same tier that's Cloudsplaining's DataExfiltration/ResourceExposure/
        # ServiceWildcard/CredentialsExposure categories — real "can act
        # catastrophically without ever escalating privileges" risk that
        # was previously indistinguishable from routine password/MFA/
        # access-key hygiene findings inside the single blended count above.
        policy_risk = await open_policy_risk_finding_summaries_for_nodes(db, tenant_id, list(nodes.keys()))
        for node_id, summary in policy_risk.items():
            nodes[node_id]["open_policy_risk_findings"] = summary["count"]
            nodes[node_id]["policy_risk_worst_severity"] = summary["worst_severity"]

    # Real findings with no provable relationship to anything else on the
    # graph — standalone nodes, no edge in or out (see module docstring).
    # Added last, not through _ensure_node, since they're never a path/
    # grant endpoint and carry their own already-complete node dict.
    for node in resource_nodes + host_nodes:
        nodes[node["id"]] = node

    all_discovered_ats = [p.discovered_at for p in paths] + [g.discovered_at for g in grants]
    latest = max(all_discovered_ats) if all_discovered_ats else None
    sources = []
    if paths:
        sources.append("IAM Privilege-Escalation Graph (Cloudsplaining)")
    if grants:
        sources.append("Third-Party OAuth App Risk (Microsoft 365)")
    if resource_nodes:
        sources.append("Cloud Misconfiguration Findings (Prowler)")
    if runs_as_pairs:
        sources.append("Compute-to-Role Attachments (EC2 Instance Profiles)")
    if exposed_assets:
        sources.append("Internet-Exposed Resources (Prowler)")
    if lateral_pairs:
        sources.append("Security Group Reachability (Same-VPC)")
    if host_nodes:
        sources.append("Host Vulnerability Findings (Lynis)")

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "last_analyzed": _relative_time(latest) if latest else None,
        "sources": sources,
        "targets": _compute_targets(edges),
        "chokepoint": _compute_chokepoint(open_paths),
        "scope": await _compute_scope(db, tenant_id),
        "viewing": viewing,
    }


async def _compute_scope(db: AsyncSession, tenant_id: uuid.UUID) -> dict:
    """Phase 39b — the honest replacement for active-exploitation-engine
    chrome (Safe Mode/Exploit Cap/Pause Engine/Emergency Stop) that this
    product has no real basis to claim: it never executes anything, only
    reads via an assumed, read-only role. read_only is a static fact, not
    a toggle. connected_accounts/iam_principals are real counts, not
    placeholders — iam_principals comes from Phase 38's resource
    inventory (CloudAsset), zero for a tenant that hasn't run a scan yet
    rather than a fabricated number."""
    connections_result = await db.execute(
        select(CloudAccountConnection.id).where(
            CloudAccountConnection.tenant_id == tenant_id, CloudAccountConnection.status == "connected",
        )
    )
    connection_ids = [row[0] for row in connections_result.all()]

    iam_principals = 0
    if connection_ids:
        count_result = await db.execute(
            select(func.count(CloudAsset.id)).where(
                CloudAsset.cloud_account_connection_id.in_(connection_ids),
                CloudAsset.resource_type.in_(["iam_role", "iam_user", "iam_group"]),
            )
        )
        iam_principals = count_result.scalar_one()

    return {"read_only": True, "connected_accounts": len(connection_ids), "iam_principals": iam_principals}


def _compute_targets(edges: list[dict]) -> list[dict]:
    """Phase 39a — "crown jewel" cards: any node that's the target of at
    least one edge, real or OAuth. path_count/worst_severity only count
    OPEN edges — a target reached only by severed (retest_closed) edges is
    real (all_open == False), the honest "contained" case, not just
    filtered out."""
    by_target: dict[str, list[dict]] = defaultdict(list)
    for e in edges:
        by_target[e["target"]].append(e)

    targets = []
    for target_id, target_edges in by_target.items():
        open_edges = [e for e in target_edges if e.get("status", "open") == "open"]
        worst = None
        for e in open_edges:
            if worst is None or _SEVERITY_RANK.get(e["severity"], 0) > _SEVERITY_RANK.get(worst, 0):
                worst = e["severity"]
        targets.append({
            "node_id": target_id,
            "open_path_count": len(open_edges),
            "closed_path_count": len(target_edges) - len(open_edges),
            "worst_severity": worst,
        })
    return targets


def _kill_chain_outcome_text(target_id: str, target_node: dict, tags: dict) -> str:
    """Real, honest outcome description — never a fabricated data
    classification. account-admin is the one synthetic node (Cloudsplaining's
    own placeholder, no CloudAsset behind it); every other kill-chain target
    is a real is_high_value resource, and its outcome text incorporates the
    resource's own real tags when present (e.g. this session's own
    DataClassification=customer-pii on the demo bucket) rather than a
    generic label when better evidence is actually available."""
    if target_id == "account-admin":
        return "Full AWS account administrative control"
    label = target_node.get("label", target_id)
    classification = tags.get("DataClassification") or tags.get("Classification")
    if classification:
        return f"Access to {label}, tagged '{classification}'"
    return f"Access to {label} (tagged high-value)"


async def _compute_kill_chains(db: AsyncSession, nodes: list[dict], edges: list[dict]) -> list[dict]:
    """Assembles real, ordered entry-to-outcome hop sequences — the actual
    multi-hop story the graph's edges already prove but nothing previously
    walked end-to-end. Starts BFS only from the real, proven "internet"
    node (kind="internet") — never an "ASSUMED ACCESS" node, matching this
    session's own honest-labeling principle that a kill chain must never
    imply a proven start where none exists. One predecessor edge per
    newly-reached node (first/shortest path found) — a single clean real
    story per outcome, not an exhaustive multi-path catalog, appropriate
    for this graph's actual small size. A "real outcome worth narrating"
    is a node that's either is_high_value (a real, tagged crown jewel) or
    the synthetic account-admin target — every other reachable node is a
    real intermediate hop, not a narrated destination on its own."""
    node_ids = {n["id"] for n in nodes}
    if "internet" not in node_ids:
        return []

    by_source: dict[str, list[dict]] = defaultdict(list)
    for e in edges:
        by_source[e["source"]].append(e)
    nodes_by_id = {n["id"]: n for n in nodes}

    predecessor: dict[str, dict] = {}
    visited = {"internet"}
    queue: deque[str] = deque(["internet"])
    while queue:
        current = queue.popleft()
        for edge in by_source.get(current, []):
            target_id = edge["target"]
            if target_id in visited:
                continue
            visited.add(target_id)
            predecessor[target_id] = edge
            queue.append(target_id)

    outcome_target_ids = [
        n["id"] for n in nodes
        if n["id"] in visited and n["id"] != "internet" and (n.get("is_high_value") or n["id"] == "account-admin")
    ]
    if not outcome_target_ids:
        return []

    resource_ids = [tid for tid in outcome_target_ids if tid != "account-admin"]
    tags_by_resource_id: dict[str, dict] = {}
    if resource_ids:
        result = await db.execute(
            select(CloudAsset.resource_id, CloudAsset.resource_metadata).where(
                CloudAsset.resource_id.in_(resource_ids),
            )
        )
        for resource_id, resource_metadata in result.all():
            tags_by_resource_id[resource_id] = (resource_metadata or {}).get("tags") or {}

    chains: list[dict] = []
    for target_id in outcome_target_ids:
        hops: list[dict] = []
        node_id = target_id
        while node_id in predecessor:
            edge = predecessor[node_id]
            hops.append(edge)
            node_id = edge["source"]
        if not hops:
            continue
        hops.reverse()

        worst_severity = ""
        for h in hops:
            if _SEVERITY_RANK.get(h["severity"], 0) > _SEVERITY_RANK.get(worst_severity, 0):
                worst_severity = h["severity"]

        target_node = nodes_by_id.get(target_id, {})
        chains.append({
            "target_id": target_id,
            "target_label": target_node.get("label", target_id),
            "outcome": _kill_chain_outcome_text(target_id, target_node, tags_by_resource_id.get(target_id, {})),
            "chain_severity": worst_severity,
            "hops": [
                {
                    "edge_type": h["edge_type"],
                    "source": h["source"],
                    "target": h["target"],
                    "source_label": nodes_by_id.get(h["source"], {}).get("label", h["source"]),
                    "target_label": nodes_by_id.get(h["target"], {}).get("label", h["target"]),
                    "severity": h["severity"],
                    "remediation": h.get("remediation", ""),
                }
                for h in hops
            ],
        })

    chains.sort(key=lambda c: _SEVERITY_RANK.get(c["chain_severity"], 0), reverse=True)
    return chains[:5]


def _compute_chokepoint(open_paths: list[CloudPrivEscPath]) -> dict | None:
    """Phase 39a — reuses simulate_fix()'s own (policy_arn -> paths) grouping
    shape, just ranked by fan-out size instead of applied against a
    specific policy list. None whenever no policy_arn is shared by more
    than one open path — nothing to honestly call a chokepoint."""
    by_policy: dict[str, list[CloudPrivEscPath]] = defaultdict(list)
    for p in open_paths:
        if p.policy_arn:
            by_policy[p.policy_arn].append(p)

    if not by_policy:
        return None
    top_policy_arn, top_group = max(by_policy.items(), key=lambda kv: len(kv[1]))
    if len(top_group) <= 1:
        return None

    return {
        "policy_arn": top_policy_arn,
        "policy_name": top_group[0].policy_name,
        "closes_count": len(top_group),
        "total_open_count": len(open_paths),
    }


def _compute_fix_verifications(paths: list[CloudPrivEscPath]) -> list[dict]:
    """The objective half of Simulate-the-Fix's "verified closed" state —
    pure re-scan reconciliation data (CloudPrivEscPath.status/closed_at,
    set mechanically in cloud_scan_service._reconcile_priv_esc_paths when a
    path stops appearing in a scan's candidates), never an LLM guess or a
    hypothetical projection. Grouped by policy_arn the same way
    simulate_fix()/_compute_chokepoint() already group — a group is only
    ever called "closed" using a real retest_closed count; still_open_count
    is reported alongside rather than hidden, so a partially-fixed policy
    reads as partial, not falsely green."""
    by_policy: dict[str, list[CloudPrivEscPath]] = defaultdict(list)
    path_only_closed: list[CloudPrivEscPath] = []
    for p in paths:
        if p.policy_arn:
            by_policy[p.policy_arn].append(p)
        elif p.status == "retest_closed":
            path_only_closed.append(p)

    verifications = []
    for policy_arn, group in by_policy.items():
        closed = [p for p in group if p.status == "retest_closed"]
        if not closed:
            continue
        open_count = sum(1 for p in group if p.status == "open")
        closed.sort(key=lambda p: p.closed_at or p.discovered_at, reverse=True)
        verifications.append({
            "policy_arn": policy_arn,
            "policy_name": group[0].policy_name,
            "closed_count": len(closed),
            "still_open_count": open_count,
            "fully_closed": open_count == 0,
            "latest_closed_at": closed[0].closed_at.isoformat() if closed[0].closed_at else None,
            "closed_paths": [
                {
                    "id": str(p.id), "source_principal_arn": p.source_principal_arn,
                    "target_principal_arn": p.target_principal_arn, "technique_chain": p.technique_chain,
                    "closed_at": p.closed_at.isoformat() if p.closed_at else None,
                }
                for p in closed
            ],
        })

    for p in path_only_closed:
        verifications.append({
            "policy_arn": None, "policy_name": None, "closed_count": 1, "still_open_count": 0,
            "fully_closed": True, "latest_closed_at": p.closed_at.isoformat() if p.closed_at else None,
            "closed_paths": [{
                "id": str(p.id), "source_principal_arn": p.source_principal_arn,
                "target_principal_arn": p.target_principal_arn, "technique_chain": p.technique_chain,
                "closed_at": p.closed_at.isoformat() if p.closed_at else None,
            }],
        })

    verifications.sort(key=lambda v: v["closed_count"], reverse=True)
    return verifications


async def get_fix_verifications(db: AsyncSession, tenant_id: uuid.UUID) -> list[dict]:
    """Tenant-wide (matches Simulate-the-Fix's own multi-engagement scope,
    not just one connection) — same status.in_(["open", "retest_closed"])
    query build_tenant_privesc_graph already runs, kept separate here since
    this is deliberately not part of the graph's own edge set (a verified-
    closed path shouldn't clutter the live attack graph)."""
    result = await db.execute(
        select(CloudPrivEscPath).where(CloudPrivEscPath.tenant_id == tenant_id, CloudPrivEscPath.status.in_(["open", "retest_closed"]))
    )
    return _compute_fix_verifications(result.scalars().all())


async def simulate_fix(
    db: AsyncSession, tenant_id: uuid.UUID, *, policy_arns: list[str], priv_esc_path_ids: list[str],
) -> list[CloudPrivEscPath]:
    """Simulate-the-Fix (Coverage Map plan Phase 6): a pure read, no
    mutation — "if the given policy/policies were fixed, which currently-
    open paths would close?" Keyed on policy_arn rather than inventing a
    Finding-linkage, since Cloudsplaining never creates a Finding per path
    today and policy_arn (captured in Phase 1) is the real, already-
    available shared root cause when multiple paths stem from one
    over-permissioned policy attached to several principals.

    priv_esc_path_ids covers the (rarer) case where Cloudsplaining
    couldn't resolve a policy_arn for a path — those paths can still be
    "simulated" individually by id, just without the fan-out to sibling
    paths sharing the same policy."""
    result = await db.execute(
        select(CloudPrivEscPath).where(CloudPrivEscPath.tenant_id == tenant_id, CloudPrivEscPath.status == "open")
    )
    open_paths = result.scalars().all()

    policy_arn_set = set(policy_arns)
    path_id_set = set(priv_esc_path_ids)

    return [
        p for p in open_paths
        if (p.policy_arn and p.policy_arn in policy_arn_set) or str(p.id) in path_id_set
    ]
