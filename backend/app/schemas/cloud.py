from pydantic import BaseModel


class CloudConnectionCreate(BaseModel):
    provider: str  # aws | azure | gcp


class CloudConnectionSetupOut(BaseModel):
    id: str
    provider: str
    status: str
    external_id: str | None = None
    trust_policy: str | None = None
    cloudformation_template: str | None = None
    instructions: list[str] = []


class CloudConnectionOut(BaseModel):
    id: str
    provider: str
    status: str
    role_arn: str | None = None
    connected_at: str | None = None
    last_scanned_at: str | None = None
    last_scan_status: str = "never_run"
    last_scan_error: str | None = None
    # Per-pass breakdown behind last_scan_status/last_scan_error — e.g.
    # {"prowler": {"status": "success", "error": null}, "inspector": {...}}
    # so the UI can show which pass actually failed and why, instead of
    # one aggregate status burying a working Prowler pass under a failed,
    # unrelated Inspector call.
    last_scan_results: dict = {}
    created_at: str
    # Same real gap as HostConnectionOut — a connection can be "connected"
    # (verified) while its own Engagement is still stuck at draft/
    # pending_approval, and there was previously no way for the frontend to
    # tell those two states apart.
    engagement_id: str | None = None
    engagement_status: str | None = None
    # Human-assigned label ("Production — Client X") — null until an admin
    # sets one via PATCH /cloud-connections/{id}. Never fabricated; the
    # frontend falls back to a derived "account_id · role_name" label when
    # this is null.
    display_name: str | None = None


class CloudConnectionVerifyRequest(BaseModel):
    role_arn: str


class ConnectionRenameRequest(BaseModel):
    # Explicit null clears it back to the derived label, not just omission —
    # PATCH semantics should let a user un-name a connection they mislabeled,
    # not only ever add a name.
    display_name: str | None = None


class CloudAssetOut(BaseModel):
    id: str
    resource_type: str
    resource_id: str
    region: str | None = None
    tags: dict = {}
    # Per-tool checked status for this resource, only keyed for tools that
    # actually evaluated it — {"prowler": "pass"|"fail", "inspector": "fail",
    # "credential": "pass"|"fail"}. A tool's absence here means "never
    # evaluated by it", never implied as clean (Phase 38b).
    checked_by: dict = {}
    open_findings_count: int = 0
    worst_open_severity: str | None = None
    first_seen_at: str
    last_seen_at: str
    # Heuristic by default (resource_inventory_service.py's
    # _infer_high_value); permanently customer-controlled once
    # high_value_set_at is non-None — see CloudAsset.is_high_value.
    is_high_value: bool | None = None
    high_value_set_at: str | None = None


class UpdateCloudAssetHighValueRequest(BaseModel):
    is_high_value: bool


class CloudAssetFindingOut(BaseModel):
    id: str
    tier: str
    severity: str
    title: str
    status: str
    check_id: str | None = None
    detail: str | None = None
    remediation_guidance: str | None = None
    region: str | None = None
    extra: dict | None = None
    discovered_at: str


class CloudAssetDetailOut(CloudAssetOut):
    findings: list[CloudAssetFindingOut] = []
