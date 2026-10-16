import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Engagement(Base):
    """The consent/scope/rules-of-engagement gate for Sentinel Command.
    Every scan, cloud-connection use, or campaign belongs to exactly one
    Engagement — nothing runs against a customer's infrastructure, account,
    or employees without one in 'active' status. Workers must check status
    on every individual action (not just once at scan start) so revoke() is
    a real emergency stop, not a decorative flag — see ARCHITECTURE.md
    Section 6.

    domain_id is nullable because tier='cloud' engagements scope to a cloud
    account rather than a domain."""

    __tablename__ = "engagements"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    domain_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("domains.id", ondelete="CASCADE"), nullable=True, index=True
    )

    tier: Mapped[str] = mapped_column(String(20))
    # cloud | exposure | credential | phishing | reachability | exploit

    scope: Mapped[dict] = mapped_column(JSONB, default=dict)
    # shape varies by tier: cidr_ranges/subdomains (exposure), auth_endpoint_asset_ids (credential),
    # employee_list_ref (phishing), cloud_account_connection_ids (cloud), excluded_asset_ids (all)

    status: Mapped[str] = mapped_column(String(20), default="draft")
    # draft | pending_approval | active | expired | revoked

    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Dropbox Sign signature request reference for the rules-of-engagement
    # document — a binding e-signature rather than an in-app checkbox,
    # since approval authorizes active testing against live infra/people.
    roe_signature_request_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    roe_doc_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Generic recurring-scan tracking, first used by tier='impersonation'
    # (PHISHING_DESIGN.md Section 2) but deliberately not tier-specific —
    # unlike CloudAccountConnection/HostConnection, Engagement itself had no
    # place to record "did the thing that runs periodically for this
    # engagement last succeed," even though every tier now has some
    # recurring pipeline behind it.
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_status: Mapped[str] = mapped_column(String(20), default="never_run", server_default="never_run")
    # never_run | success | failed
    last_scan_error: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship()  # type: ignore[name-defined]
    domain: Mapped["Domain | None"] = relationship()  # type: ignore[name-defined]
