import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class PhishingCustomTemplate(Base):
    """
    A tenant-owned, reusable lure template — distinct from
    phishing_service.BUILT_IN_TEMPLATES (a fixed, hardcoded catalog every
    tenant shares read-only). This is what a tenant writes and saves for
    themselves, editable and deletable, the same way an admin manages their
    own target lists. Selectable anywhere a built-in template id is
    selectable in the wizard (subject/body only — difficulty/from_email/
    display_name/include_attachments are authoring metadata, not resolved
    into a real send by launch_campaign() in this phase).
    """
    __tablename__ = "phishing_custom_templates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)

    label: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(50), default="General")
    subject: Mapped[str] = mapped_column(String(500))
    body_html: Mapped[str] = mapped_column(Text)

    difficulty: Mapped[str] = mapped_column(String(10), default="medium")  # low | medium | high
    from_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    include_attachments: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant: Mapped["Tenant"] = relationship()  # type: ignore[name-defined]
