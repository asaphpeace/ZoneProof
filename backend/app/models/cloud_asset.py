import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class CloudAsset(Base):
    """A resource discovered inside a connected cloud account (IAM role,
    S3 bucket, EC2 instance, etc.) — the cloud-scoped counterpart to Tier
    1's network asset concept. Rows are updated in place on re-scan
    (last_seen_at bumped) rather than inserted per scan cycle, so this
    table reflects current account state; history/evidence lives in
    Finding and CloudPrivEscPath instead, which are append-only."""

    __tablename__ = "cloud_assets"
    __table_args__ = (
        Index("ix_cloud_assets_connection_type", "cloud_account_connection_id", "resource_type"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    cloud_account_connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cloud_account_connections.id", ondelete="CASCADE"), index=True
    )

    resource_type: Mapped[str] = mapped_column(String(50))
    # iam_role | iam_user | s3_bucket | ec2_instance | security_group | lambda_function | rds_instance | ...
    resource_id: Mapped[str] = mapped_column(String(2048))  # ARN or provider-native identifier
    region: Mapped[str | None] = mapped_column(String(50), nullable=True)
    resource_metadata: Mapped[dict] = mapped_column(JSONB, default=dict)  # not `metadata` — reserved on Base

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Customer-facing "this asset matters" signal for the Attack Path Graph
    # (distinct from graph_service.py's own unrelated "crown jewel cards" —
    # that term means "any node reached by >=1 edge," pure topology; this
    # is a real customer/heuristic judgment about asset value). Starts as
    # a heuristic default (resource_inventory_service.py's _infer_high_value,
    # recomputed on every rescan) and is permanently protected from that
    # recomputation the moment high_value_set_by_user_id is populated —
    # same "manual override can never be silently clobbered" guarantee as
    # ReportedEmail.disposition.
    is_high_value: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    high_value_set_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    high_value_set_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    connection: Mapped["CloudAccountConnection"] = relationship()  # type: ignore[name-defined]
