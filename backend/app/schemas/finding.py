from pydantic import BaseModel


class AttackTechniqueOut(BaseModel):
    id: str
    name: str | None = None
    tactics: list[str] = []


class FindingOut(BaseModel):
    id: str
    engagement_id: str
    asset_id: str | None
    tier: str
    severity: str
    title: str
    status: str
    check_id: str | None
    # The real ARN/hostname this finding is about — Prowler's RESOURCE_UID
    # for tier='cloud', a host's hostname_or_ip for tier='host'. Null where
    # check_id is already resource-specific by construction (Inspector,
    # Exposure). Evidence-panel gold: lets a user drill from one finding to
    # every other finding on the same real resource.
    resource_uid: str | None
    detail: str | None
    remediation_guidance: str | None
    discovered_at: str
    # Regional-duplicate collapsing (cloud_scan_service._collapse_regional_
    # duplicates) — occurrence_count > 1 means this one row represents the
    # same account/region-level gap Prowler evaluated N times (once per
    # region); affected_resources lists every real ARN that collapsed into
    # it. occurrence_count stays 1 for a genuine single-resource finding.
    occurrence_count: int = 1
    affected_resources: list[str] | None = None
    # Only populated for Prowler-sourced (tier='cloud', non-Inspector)
    # findings — Prowler's own check_id crosswalk doesn't cover Inspector,
    # Lynis, or Exposure findings. See compliance_mapping.py.
    cis_controls: list[str] = []
    attack_techniques: list[AttackTechniqueOut] = []
    # AWS region the finding was raised in, where the source scan reports one.
    region: str | None = None
    # Heterogeneous per-source detail (Prowler compliance/remediation-code,
    # Inspector2 CVE/CVSS/exploit data, credential-hygiene access-key
    # evidence, a Cloudsplaining risk category's actions) — see Finding.extra.
    extra: dict | None = None
    # Real connection identity behind this finding's engagement — hostname
    # for tier='host', "account_id · role_name" for tier='cloud'. None for
    # every other tier (exposure/oauth_risk/phishing/...), which don't map
    # cleanly onto one connection — left absent rather than a guessed
    # label. See GET /findings (app/routers/findings.py) for how it's
    # resolved; the per-engagement GET /engagements/{id}/findings never
    # populates these two (the caller already knows which engagement/
    # connection it asked for).
    connection_id: str | None = None
    connection_label: str | None = None
    # Human-assigned name for that connection ("Production — Client X"),
    # when an admin has set one (PATCH /cloud-connections/{id} or /host-
    # connections/{id}). None means nobody named it yet — the frontend
    # falls back to connection_label, never a fabricated name.
    connection_display_name: str | None = None
    # The resource's own real AWS tags (Name, Environment, ...), read live
    # from CloudAsset.resource_metadata at request time — NOT from
    # Finding.extra, which can be stale for a finding created before tag
    # capture existed (CloudAsset is the one table in this schema that's
    # explicitly kept current on every scan; Finding rows are append-only
    # history). Empty dict, not None, when the resource has no asset_id
    # link or genuinely carries no tags — most AWS resources in a real
    # account aren't tagged at all, so an empty result is common and
    # honest, not a bug.
    resource_tags: dict[str, str] = {}


class FindingConnectionOut(BaseModel):
    """One selectable filter option for GET /findings — every real cloud/
    host connection with an active engagement, whether or not it has any
    findings yet (a freshly connected, not-yet-scanned host should still
    be pickable, not just inferred from findings that already exist)."""
    id: str
    tier: str
    label: str
    display_name: str | None = None


class FindingsListOut(BaseModel):
    findings: list[FindingOut]
    connections: list[FindingConnectionOut]


class CloudPrivEscPathOut(BaseModel):
    id: str
    engagement_id: str
    source_principal_arn: str
    target_principal_arn: str
    technique_chain: list[str]
    escalation_type: str | None = None
    policy_name: str | None = None
    policy_arn: str | None = None
    severity: str
    status: str = "open"  # open | retest_closed
    discovered_at: str
    closed_at: str | None = None
