import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class EmailSuppression(Base):
    """
    Real, un-hashed email addresses Sentinel should stop sending to
    (Phishing Simulation roadmap Phase 17) — populated from real SendGrid
    bounce/complaint/unsubscribe webhook events, checked before every
    outbound send in email_service.send_email().

    Deliberately tenant-agnostic and un-hashed, unlike phishing's own
    recipient_hash discipline: this is an operational anti-abuse control
    over Sentinel's own sending reputation across *all* outbound mail
    (invites, reports, phishing sends alike), not a per-tenant reporting
    record, so it sits outside that pseudonymization design entirely.
    """
    __tablename__ = "email_suppressions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)  # RFC 5321 max mailbox length
    reason: Mapped[str] = mapped_column(String(20))  # bounce | dropped | spamreport | unsubscribe
    detail: Mapped[str | None] = mapped_column(String(500), nullable=True)  # the provider's own reason text
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
