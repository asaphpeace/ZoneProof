import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class PhishingTargetList(Base):
    """The employee list for Tier B human-simulation campaigns
    (PHISHING_DESIGN.md Section 3.2). Re-read fresh at each recurring
    campaign launch rather than snapshotted onto the Engagement or
    PhishingCampaign at consent time — someone who left the company
    shouldn't keep getting targeted just because they were on the list
    when the Rules of Engagement was signed."""

    __tablename__ = "phishing_target_lists"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)

    name: Mapped[str] = mapped_column(String(200))
    entries: Mapped[list] = mapped_column(JSONB, default=list)
    # [{"email": "...", "display_name": "..."}, ...] — customer-managed,
    # edited between campaign cycles, never auto-populated in v1.

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship()  # type: ignore[name-defined]


class PhishingExemption(Base):
    """A tenant-wide 'never target this address' list, independent of
    target-list membership (Phishing Simulation roadmap Phase 21) — real
    legal/union-negotiated exemptions exist in some jurisdictions, and an
    exempted address stays excluded even if re-added to a target list
    later or present on a different list entirely. Deliberately a
    separate table from EmailSuppression: that one is deliverability-only
    (populated from real bounce/complaint webhooks, tenant-agnostic,
    shared across every outbound mail type), this one is a voluntary/
    policy exclusion an admin adds on purpose, scoped to one tenant and
    to phishing simulation specifically."""

    __tablename__ = "phishing_exemptions"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_phishing_exemption_tenant_email"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    email: Mapped[str] = mapped_column(String(320))
    reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship()  # type: ignore[name-defined]


class PhishingCampaign(Base):
    """One launched cycle. A recurring Engagement produces many of these
    over its lifetime — the campaign is the unit of "one send," not the
    engagement (PHISHING_DESIGN.md Section 3.2/3.3)."""

    __tablename__ = "phishing_campaigns"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    target_list_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("phishing_target_lists.id", ondelete="RESTRICT")
    )

    template_id: Mapped[str] = mapped_column(String(50))  # key into the built-in template set

    status: Mapped[str] = mapped_column(String(20), default="sending")  # sending | complete
    launched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Real evidence of what was actually sent this cycle (Coverage Map plan
    # Phase 7) — whether an LLM generated the content fresh for this launch
    # (vs. the static template/a human override), the exact subject sent,
    # and the DMARC posture snapshot used as generation context, for
    # reporting ("this simulation ran while your DMARC policy was p=none").
    llm_generated: Mapped[bool] = mapped_column(default=False)
    subject_sent: Mapped[str | None] = mapped_column(String(500), nullable=True)
    dmarc_context: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # The actual rendered HTML one real recipient received this cycle
    # (post-template/post-LLM-generation, tracking pixel included) —
    # captured from the first recipient processed in launch_campaign().
    # Without this, a "what they received" preview would be impossible to
    # reconstruct honestly for LLM-generated content, since that content
    # is never cached anywhere else and is fresh every launch.
    body_html_sent: Mapped[str | None] = mapped_column(Text, nullable=True)
    # One real rendered example per language actually sent this cycle
    # (Phishing Simulation roadmap Phase 19) — subject_sent/body_html_sent
    # above stay as the single first-delivered example (unambiguous for
    # the common single-locale campaign); these two exist specifically so
    # a language-diverse send never lets one locale's example stand in for
    # what a different-locale recipient actually received. Keyed by locale
    # code ("en"/"af"/"zu"/"st"/"ve"). None until a campaign actually spans
    # more than the one locale captured above, or lazily populated always —
    # see launch_campaign()'s per-entry capture.
    subject_sent_by_locale: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    body_html_sent_by_locale: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # Which built-in landing page (phishing_service.BUILT_IN_LANDING_PAGES)
    # a click on this campaign's link actually showed — stored on the
    # campaign itself, not just read from the live engagement scope, so a
    # later change to the engagement's default doesn't rewrite history.
    landing_page_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # Human-readable description of who was actually targeted this cycle
    # (Phishing Simulation roadmap Phase 15) — e.g. "Finance department (3
    # of 8)" or "2 individually selected recipients". None means the whole
    # target list was sent to, the historical default — never a guess about
    # who was included, and never the identities themselves.
    audience_label: Mapped[str | None] = mapped_column(String(200), nullable=True)

    tenant: Mapped["Tenant"] = relationship()  # type: ignore[name-defined]
    engagement: Mapped["Engagement"] = relationship()  # type: ignore[name-defined]


class PhishingEvent(Base):
    """The pseudonymized timeline. recipient_hash never reverses to a
    plaintext email on its own — unmasking works by re-hashing the
    target list's *current* entries and matching, not by storing identity
    against the event (PHISHING_DESIGN.md Section 3.2, a stronger design
    than the original ARCHITECTURE.md sketch).

    recipient_token is the opaque, unguessable value embedded in a
    recipient's tracking pixel/click/submit URLs — shared across every
    event row for that recipient within one campaign, since it's how an
    unauthenticated tracking request gets resolved back to
    (campaign_id, recipient_hash) without a plaintext identifier ever
    appearing in a URL."""

    __tablename__ = "phishing_events"
    __table_args__ = (
        Index("ix_phishing_events_recipient_token", "recipient_token"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    campaign_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("phishing_campaigns.id", ondelete="CASCADE"), index=True)

    recipient_hash: Mapped[str] = mapped_column(String(64))  # HMAC-SHA256 hex digest
    recipient_token: Mapped[str] = mapped_column(String(43))  # url-safe random token, shared per recipient per campaign

    event_type: Mapped[str] = mapped_column(String(20))  # sent | opened | clicked | credential_entered
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Full who/what/when/where/destination reporting (Coverage Map plan
    # Phase 7 addendum) — who is recipient_hash (unmasked on demand via the
    # existing admin-only flow), what is event_type, when is occurred_at
    # above; these two are the real "where"/"destination" evidence, read
    # straight from the Request object already available at each tracking
    # endpoint (phishing_track.py) — nothing new to fetch, just capture
    # what was already in hand and previously discarded.
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # The actual tracked URL the recipient was sent to for this event
    # (pixel/click/submit) — persisted onto the row rather than only the
    # ephemeral token, so "destination" survives independently of it.
    destination_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # The language this specific recipient's content was actually resolved
    # to at send time (Phishing Simulation roadmap Phase 19) — a fact
    # recorded once, not re-derived later from a tenant/entry setting that
    # might have since changed. Only ever set on "sent"/"send_failed" rows;
    # None on older rows created before this column existed.
    locale: Mapped[str | None] = mapped_column(String(10), nullable=True)

    campaign: Mapped["PhishingCampaign"] = relationship()


class TrainingAssignment(Base):
    """The training-assignment-on-fail loop (Coverage Map plan phishing
    transformation, Phase 2) — every reference platform researched
    auto-enrolls a clicker into a short lesson; this is that record. One
    row per recipient per campaign (the unique constraint below), created
    on first click/credential-entry and never duplicated on a repeat
    click. Keyed only on recipient_hash, same as PhishingEvent — never an
    email, so this introduces no new identity-leak surface."""

    __tablename__ = "training_assignments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "campaign_id", "recipient_hash", name="uq_training_assignment_recipient"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    campaign_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("phishing_campaigns.id", ondelete="CASCADE"), index=True)

    recipient_hash: Mapped[str] = mapped_column(String(64))
    lure_category: Mapped[str] = mapped_column(String(50))  # template_id snapshot at assignment time
    trigger_event_type: Mapped[str] = mapped_column(String(20))  # "clicked" | "credential_entered"

    status: Mapped[str] = mapped_column(String(20), default="assigned")  # assigned | completed
    # Which red flag they said they'd have noticed, or "not_sure" — never
    # scored as correct/incorrect, just recorded (see phishing_lesson_content.py).
    reflection_response: Mapped[str | None] = mapped_column(String(50), nullable=True)

    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    campaign: Mapped["PhishingCampaign"] = relationship()
