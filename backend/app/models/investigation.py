import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Investigation(Base):
    """One row per Actor currently under suspicion — the "person of
    interest" record. Keyed on actor_id, not a raw per-source principal or
    a specific connection, so evidence from every system that Actor
    touches accumulates onto the same record (see Actor's docstring).

    Deliberately has no FK to a specific CloudAccountConnection/
    HostConnection/IdentityProviderConnection: an Investigation can span
    evidence from multiple connections over its lifetime, and per
    ITDR_DESIGN.md's audit-trail rule it must survive any one connection
    being revoked or removed — the same "append-only, never deleted"
    philosophy CloudPrivEscPath already documents for itself."""

    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    actor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("actors.id", ondelete="CASCADE"), index=True)

    status: Mapped[str] = mapped_column(String(20), default="confirmed")
    # watching | suspicious | confirmed | critical — v1's one detection
    # rule (a known CloudPrivEscPath escalation action actually invoked)
    # is high-confidence by construction and always opens at 'confirmed'
    # directly. The lower tiers exist now for forward-compatibility with
    # future baselining-based signals, not because v1 produces them —
    # see ITDR_DESIGN.md Section 2.2.

    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_activity_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dismissed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    tenant: Mapped["Tenant"] = relationship()  # type: ignore[name-defined]
    actor: Mapped["Actor"] = relationship()  # type: ignore[name-defined]


class InvestigationEvent(Base):
    """One timeline entry under an Investigation. event_id is the
    source system's own unique identifier (a CloudTrail EventId, an Auth0
    log entry id) — unique-constrained per tenant so an overlapping poll
    window can never double-record the same real-world event."""

    __tablename__ = "investigation_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "source", "event_id", name="uq_investigation_event_source_event_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )

    source: Mapped[str] = mapped_column(String(20))  # cloudtrail | auth0
    event_id: Mapped[str] = mapped_column(String(200))  # the source system's own unique event id

    action_or_event_type: Mapped[str] = mapped_column(String(200))  # e.g. "iam:PassRole", "breached_password"
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    raw_detail: Mapped[str | None] = mapped_column(String, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    investigation: Mapped["Investigation"] = relationship()
