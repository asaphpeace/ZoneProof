import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Finding(Base):
    """Envelope shared across every Sentinel Command tier. check_id/detail/
    remediation_guidance cover Tier 0 (a Prowler check result) inline;
    later tiers get their own dedicated proof tables (ExposureProof,
    CredentialProof, ...) referenced by proof_ref instead of adding more
    nullable columns here, since proof shape differs enough per tier that
    a single shared table would mostly be empty per row.

    Phase 36 (the AWS data-discard audit) deliberately did NOT follow that
    pattern for the newly-captured Prowler/Inspector2/Cloudsplaining/
    credential-hygiene detail — no dedicated proof table existed yet for
    any of them, and none of this data needs a DB-level join or its own
    index, so `extra` (JSONB) reuses the lighter ReportedEmail.url_risk
    pattern instead. `region` is the one field promoted to a real typed
    column, since it's shared across sources and genuinely worth filtering
    by. proof_ref stays available for a future tier whose data really does
    need relational structure."""

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_engagement_status", "engagement_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)

    # Nullable — a CloudPrivEscPath-backed finding may not map to a single
    # discrete CloudAsset the way a per-resource Prowler check does.
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_assets.id", ondelete="SET NULL"), nullable=True
    )

    tier: Mapped[str] = mapped_column(String(20))  # mirrors Engagement.tier
    severity: Mapped[str] = mapped_column(String(20))  # critical | high | medium | low
    title: Mapped[str] = mapped_column(String(500))

    status: Mapped[str] = mapped_column(String(20), default="open")
    # open | acknowledged | remediated | retest_closed

    check_id: Mapped[str | None] = mapped_column(String(200), nullable=True)  # e.g. a Prowler check id

    # Together with check_id, the real dedup/reconciliation identity for a
    # rescan — a check_id alone fires once per affected resource (Prowler
    # runs the same check across every region), so two genuinely different
    # findings can share one check_id. Populated from Prowler's own
    # RESOURCE_UID CSV column (an ARN) for tier='cloud' findings, and the
    # host's hostname_or_ip for tier='host' (Lynis test ids aren't
    # per-host). Null where check_id already is resource-specific by
    # construction (Inspector's check_id is the finding ARN itself;
    # Exposure's is host/port-specific).
    resource_uid: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    detail: Mapped[str | None] = mapped_column(String, nullable=True)
    remediation_guidance: Mapped[str | None] = mapped_column(String, nullable=True)
    proof_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)

    # Collapses the classic Prowler noise pattern — an account/region-level
    # setting (CloudTrail multi-region, GuardDuty, Access Analyzer, ...)
    # gets evaluated once per enabled region, producing 15-18 near-identical
    # rows for what is really one gap. run_prowler_scan() detects this by
    # ARN shape (same check_id, same resource_uid with only the region
    # segment differing) and collapses the group into a single row: this
    # column is the group size, affected_resources the actual list — a
    # real per-resource finding (one EC2 instance, one S3 bucket) is never
    # collapsed and keeps occurrence_count=1 with affected_resources unset.
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    affected_resources: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    # AWS region the finding was raised in, where the source scan reports
    # one (Prowler's REGION column, Inspector2's resources[].region). Real
    # typed column, not folded into `extra` below, since it's shared across
    # sources and is the one field worth filtering/grouping by.
    region: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)

    # Heterogeneous per-source detail that doesn't earn its own dedicated
    # proof table (see the class docstring) because nothing here needs a DB
    # join or its own index — Prowler's compliance mapping/remediation code
    # snippets, Inspector2's CVE/CVSS/exploit/fix-available/EPSS data,
    # credential hygiene's access-key rotation/last-used evidence, a
    # Cloudsplaining risk category's raw actions list. Same JSONB-snapshot
    # pattern as ReportedEmail.url_risk — None (not {}) until a source
    # actually populates it, honest "no extra detail" over a fabricated
    # empty object.
    extra: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    extra_populated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Our own computed verdict, not raw scanner data — same distinction and
    # precedent as ReportedEmail.url_risk/url_risk_scored_at: a dedicated
    # column pair for "this codebase's own logic last computed this",
    # separate from extra above (real signal Prowler/Inspector2/
    # Cloudsplaining/Lynis reported). {score, verdict, grade, explanation,
    # signals} from exploitability_service.py. None until scored.
    # none_as_null=True: compute_tenant_verified_exploitability_score() filters
    # on this column with a SQL IS NOT NULL — without none_as_null, SQLAlchemy's
    # JSONB binds a Python None as the JSON literal `null` rather than SQL NULL,
    # so that filter would silently let unscored rows through.
    exploitability: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    exploitability_scored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    engagement: Mapped["Engagement"] = relationship()  # type: ignore[name-defined]
    asset: Mapped["CloudAsset | None"] = relationship()  # type: ignore[name-defined]
