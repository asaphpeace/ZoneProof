"""
A real suspicious email an employee forwarded to their tenant's real
report address (Phishing Simulation roadmap Phase 26 — the KnowBe4-
equivalent report+triage feature, explicitly NOT the Mimecast-equivalent
automatic just-in-time response, which would require Sentinel to sit in
the customer's mail path).

Deliberately does not store the full raw forwarded message. Only what a
real triage workflow needs is extracted: the claimed sender/subject/date
of the reported message, a truncated plain-text body excerpt (HTML
stripped, never rendered as HTML server-side or client-side, so no
embedded remote-tracking pixel or active content from a real attacker's
email can ever fire), real extracted URLs, and real SPF/DKIM/DMARC
Authentication-Results signals parsed from the message's own headers.

The reporter's own identity is pseudonymized the same way every other
recipient identity in this module is (HMAC-SHA256 via
phishing_service._hash_recipient) — revealed only through an admin-only,
audited unmask action, exactly like phishing.unmask_recipient. Unlike
TrainingCourseAssignment (Phase 24), an unmask path DOES exist here on
purpose: knowing who reported a real threat is operationally useful (a
security team may need to follow up with them), unlike a culture-survey
response, which is designed to stay anonymous for psychological-safety
reasons.
"""
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ReportedEmail(Base):
    __tablename__ = "reported_emails"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    reporter_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    original_subject: Mapped[str | None] = mapped_column(String(500), nullable=True)
    original_from: Mapped[str | None] = mapped_column(String(320), nullable=True)
    original_from_domain: Mapped[str | None] = mapped_column(String(253), nullable=True)
    original_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    body_text_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    urls_found: Mapped[list] = mapped_column(JSONB, default=list)
    # True only when a real message/rfc822 attachment was found ("Forward
    # as attachment") — a plain inline "Forward" reformats the original
    # into quoted body text this parser deliberately does not attempt to
    # reverse-engineer (unreliable across mail clients' quoting formats,
    # and a wrong guess here would misattribute what was actually sent).
    # False means original_from/original_subject/etc. describe the
    # forwarding message itself, not the real original — surfaced
    # honestly in the UI rather than silently presented as certain.
    is_original_message_attached: Mapped[bool] = mapped_column(default=False)

    spf_result: Mapped[str | None] = mapped_column(String(20), nullable=True)
    dkim_result: Mapped[str | None] = mapped_column(String(20), nullable=True)
    dmarc_result: Mapped[str | None] = mapped_column(String(20), nullable=True)
    auth_results_raw: Mapped[str | None] = mapped_column(Text, nullable=True)

    disposition: Mapped[str] = mapped_column(String(30), default="new")  # new | confirmed_malicious | false_positive | already_known
    disposition_note: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    disposition_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    disposition_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Composite link risk score (Phase 32) — one snapshot object per entry
    # in urls_found, see link_risk_service.py for the shape. None (not an
    # empty list) until the first scan actually runs — honest "not yet
    # scored" state, matching this codebase's existing discipline of None
    # over a fabricated value (e.g. compute_tenant_human_risk_score's
    # treatment of insufficient data).
    url_risk: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    url_risk_scored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
