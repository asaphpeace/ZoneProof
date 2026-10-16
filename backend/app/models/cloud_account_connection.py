import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class CloudAccountConnection(Base):
    """Read-only access into a customer's cloud account (AWS/Azure/GCP) for
    Sentinel Command's Tier 0 cloud posture scanning. Distinct consent model
    from Domain/Engagement scope — the customer grants account access
    directly rather than authorizing scans against a CIDR/domain.

    AWS uses cross-account role assumption (role_arn + external_id) so no
    customer credential is ever stored here. Azure/GCP fall back to
    encrypted_credentials only when workload-identity federation isn't set
    up — encrypted at rest, same `cryptography` usage already established
    elsewhere in this codebase (cert_service.py)."""

    __tablename__ = "cloud_account_connections"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)

    # Nullable — set when an Engagement covering this connection is created
    # (see engagement.py's cloud_account_connection_ids handling), not at
    # connection-creation time. Connecting an account (OAuth-style linking)
    # and authorizing scans against it (the consent gate) are deliberately
    # separate steps; this FK is what the scheduler joins on to find only
    # connections with a currently-active authorization — a connection with
    # no engagement, or one whose engagement has expired/been revoked, is
    # never picked up for an automatic rescan.
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("engagements.id", ondelete="SET NULL"), nullable=True, index=True
    )

    provider: Mapped[str] = mapped_column(String(20))  # aws | azure | gcp

    # AWS — cross-account role assumption, no stored secret
    role_arn: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    external_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Azure — service principal; tenant/client id are not secret, only the
    # client secret needs encryption (nullable once federation is used)
    azure_tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    azure_client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    azure_subscription_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # GCP — service account; project id / SA email are not secret
    gcp_project_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    gcp_service_account_email: Mapped[str | None] = mapped_column(String(320), nullable=True)

    # Fernet-encrypted blob for whichever secret the provider needs (Azure
    # client secret, GCP key file) when federation isn't in use. Null for
    # AWS (never needed) and for federated Azure/GCP connections.
    encrypted_credentials: Mapped[str | None] = mapped_column(String, nullable=True)
    uses_federation: Mapped[bool] = mapped_column(Boolean, default=False)

    status: Mapped[str] = mapped_column(String(20), default="pending_verification")
    # pending_verification | connected | revoked | error

    # Human-assigned, e.g. "Production — Client X" — the one piece of real
    # "environment" identity this system can never derive on its own.
    # role_arn/account_id are real, stable technical facts, but nothing in
    # the AWS API says whether an account is prod, staging, or a client's
    # sandbox — that's a judgment call only a person can make. Null by
    # default (never fabricated); GET /findings and the connections list
    # fall back to the derived "account_id · role_name" label when unset.
    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)

    connected_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    connected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # A scan that fails must not look identical to a scan that ran cleanly
    # and found nothing — PASS rows are never persisted (only FAIL findings
    # are), so an empty Finding list is inherently ambiguous between "clean"
    # and "never actually ran." This is the explicit signal the UI reads
    # instead of inferring from absence of findings.
    last_scan_status: Mapped[str] = mapped_column(String(40), default="never_run")
    # never_run | success | failed | running:prowler | running:cloudsplaining | running:inspector
    # — the running:<pass> values are transient, overwritten by the next
    # pass's marker or the final success/failed once rescan_connection()
    # finishes; see cloud_scan_service.py's _mark_running().
    last_scan_error: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    # Per-pass breakdown behind the aggregate above — rescan_connection()
    # deliberately still fails the whole connection if any one pass fails
    # (a customer can't tell "clean" from "silently broken" from an
    # aggregate alone), but that same honesty means a genuinely successful
    # Prowler + Cloudsplaining pass was getting buried under one failed
    # Inspector call (e.g. Inspector2 not yet enabled on the account) with
    # no way to see which pass actually broke. Shape:
    # {"prowler": {"status": "success"|"failed", "error": str|None}, ...}
    # for whichever of prowler/cloudsplaining/inspector actually ran this
    # pass (a pass skipped by mid-scan revocation is simply absent, not a
    # recorded failure — same rule the aggregate already follows).
    last_scan_results: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Separate from last_scan_status/last_scan_error above — continuous
    # threat-activity polling (ITDR_DESIGN.md) is a materially different
    # pipeline from the periodic deep scan, with its own cadence and
    # failure modes (most commonly: the deployed role hasn't been updated
    # with the cloudtrail:LookupEvents permission yet).
    last_threat_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    threat_detection_status: Mapped[str] = mapped_column(String(20), default="never_run")
    # never_run | success | failed
    threat_detection_error: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship()  # type: ignore[name-defined]
    engagement: Mapped["Engagement | None"] = relationship()  # type: ignore[name-defined]
