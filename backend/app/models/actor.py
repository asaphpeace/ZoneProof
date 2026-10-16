import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Actor(Base):
    """A resolved human identity, potentially spanning multiple systems —
    the fix for the original ITDR design flaw of keying Investigations on
    a raw per-source principal string (an AWS ARN, an Auth0 user_id).
    Without this, the same person's misbehavior in two different systems
    produces two disconnected records that never get correlated, which
    defeats the entire "follow them around" premise. See ITDR_DESIGN.md
    Section 2.1."""

    __tablename__ = "actors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)

    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship()  # type: ignore[name-defined]


class ActorIdentity(Base):
    """One raw per-source principal string, linked to a resolved Actor.
    resolved_via records *why* two identities were merged into one Actor,
    so a human can audit the merge rather than trust an opaque match —
    a wrong merge silently attributes one person's activity to another,
    which is worse than not merging at all."""

    __tablename__ = "actor_identities"
    __table_args__ = (
        UniqueConstraint("tenant_id", "source", "principal_id", name="uq_actor_identity_source_principal"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    actor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("actors.id", ondelete="CASCADE"), index=True)

    source: Mapped[str] = mapped_column(String(20))  # aws_iam | auth0 | (future: okta, entra_id)
    principal_id: Mapped[str] = mapped_column(String(2048))  # an ARN, an Auth0 user_id, etc.

    resolved_via: Mapped[str] = mapped_column(String(20))
    # first_seen | email_match | federation_claim | manual

    # How confident the *email* attached to this specific identity is —
    # distinct from resolved_via (which is about why identities merged,
    # not how sure we are about this one's email). Set once at creation,
    # never silently overwritten later, so a UI can always show the real
    # provenance ("matched via SSO session identity" vs "matched via IAM
    # tag") instead of collapsing two very different confidence levels
    # into one "verified" checkmark. Null when no email was ever derived.
    email_provenance: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # sso_session | iam_tag

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    actor: Mapped["Actor"] = relationship()
