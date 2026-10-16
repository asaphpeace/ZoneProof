"""
Brand Guard — brand & domain impersonation protection.

Deliberately NOT modelled as `Finding` rows (see impersonation_scan_service.py's
older "Spoof Proof" tier): a candidate domain needs a lifecycle (new → triaging →
confirmed / false_positive → takedown → removed → monitoring), two independent
scores (identity vs abuse confidence), and typed evidence records that explain
*why* it was flagged — none of which a flat, always-"open" finding can carry.

A candidate is "a domain that might be exploiting this brand", never "a
confirmed threat" until someone or some rule says so; the status column is
that judgement, and every status change is user-attributable.
"""
import uuid
from datetime import date, datetime

from sqlalchemy import BigInteger, Boolean, Date, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

CANDIDATE_STATUSES = (
    "new", "triaging", "suspicious", "confirmed", "takedown", "removed", "monitoring",
    # Terminal "not a threat" states — kept (not deleted) so the same domain is
    # never re-flagged and so the scorer can eventually learn from them.
    "false_positive", "benign", "customer_owned", "partner", "ignored",
)


class BrandProfile(Base):
    """The legitimate brand fingerprint a scan compares candidates against."""
    __tablename__ = "brand_profiles"
    __table_args__ = (UniqueConstraint("tenant_id", "domain_id", name="uq_brand_profiles_tenant_domain"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    domain_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)

    brand_name: Mapped[str] = mapped_column(String(120))
    # Extra words attackers pair with the brand (product names, "pay", "portal").
    keywords: Mapped[list] = mapped_column(JSONB, default=list)
    # Every domain the customer legitimately owns — candidates matching these
    # are customer_owned, never a threat. The primary domain is implicit.
    official_domains: Mapped[list] = mapped_column(JSONB, default=list)
    login_urls: Mapped[list] = mapped_column(JSONB, default=list)
    # Trademark registrations the customer holds, entered by hand: [{"mark", "number", "jurisdiction"}]. Kept for
    # takedown/UDRP evidence later; nothing in detection reads them yet.
    trademarks: Mapped[list] = mapped_column(JSONB, default=list)
    # What the real brand looks like (plan 2.0): site title/favicon/social/contacts and the DNS baseline. Built by
    # brand_fingerprint_service from the customer's own public site; null until built.
    fingerprint: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    fingerprint_built_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # High-water mark for CT polling so we never reprocess the same certs.
    last_ct_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    candidates: Mapped[list["BrandCandidate"]] = relationship(back_populates="profile", cascade="all, delete-orphan")


class BrandCandidate(Base):
    __tablename__ = "brand_candidates"
    __table_args__ = (
        UniqueConstraint("profile_id", "candidate_domain", name="uq_brand_candidates_profile_domain"),
        Index("ix_brand_candidates_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    profile_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brand_profiles.id", ondelete="CASCADE"), index=True)

    candidate_domain: Mapped[str] = mapped_column(String(253))
    status: Mapped[str] = mapped_column(String(20), default="new")

    # Identity confidence: how likely this is actually *about* the protected
    # brand. Abuse confidence: how likely it is malicious/deceptive. Kept
    # separate on purpose — a perfect lookalike that's a parked page has high
    # identity and low abuse; don't collapse them into one "threat score".
    identity_score: Mapped[float] = mapped_column(Float, default=0.0)
    abuse_score: Mapped[float] = mapped_column(Float, default=0.0)
    # Live-ness drives urgency: low | medium | high
    impact: Mapped[str] = mapped_column(String(10), default="low")
    urgency: Mapped[str] = mapped_column(String(10), default="low")
    # domain_similarity class — e.g. typo | homoglyph | combosquat | tld_swap
    threat_class: Mapped[str | None] = mapped_column(String(30), nullable=True)

    # Sensors that surfaced it: ["permutation", "ct_log", ...]
    sources: Mapped[list] = mapped_column(JSONB, default=list)
    # Raw enrichment snapshot (dns, rdap, cert) — evidence rows are the
    # auditable record, this is the latest state for quick UI rendering.
    enrichment: Mapped[dict] = mapped_column(JSONB, default=dict)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Lifecycle (plan step 2.1): where the domain is on the registered -> resolving -> mail_enabled ->
    # certified ladder, when that last changed, and the compact current state the pipeline diffs against.
    # The full history lives in brand_candidate_observations / brand_candidate_events.
    stage: Mapped[str] = mapped_column(String(16), default="registered", server_default="registered")
    stage_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lifecycle: Mapped[dict] = mapped_column(JSONB, default=dict, server_default=text("'{}'::jsonb"))

    reviewed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    analyst_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Case workflow (plan 8.1): who owns it, the response deadline (assumed hours by urgency, see brand_cases), and when it was closed.
    assignee_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_hours: Mapped[int | None] = mapped_column(Integer, nullable=True)      # the allowance the deadline was set with; a later rescore must not change it
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Set once we've raised an Alert so a re-scan never re-notifies.
    alerted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Campaign (UI slice 2): the group of look-alikes that appear to share an operator. `campaign_locked` means a person
    # took this one out of its group, so a rescan must not put it back.
    campaign_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("brand_campaigns.id", ondelete="SET NULL"), nullable=True, index=True)
    campaign_locked: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))

    profile: Mapped[BrandProfile] = relationship(back_populates="candidates")
    evidence: Mapped[list["CandidateEvidence"]] = relationship(
        back_populates="candidate", cascade="all, delete-orphan", order_by="CandidateEvidence.observed_at",
    )


class CtStreamCursor(Base):
    """Where the live certificate-stream worker has read up to in each log, so a restart resumes instead of starting over or
    re-reading. One row per followed log. Not tenant data: the stream is shared by every brand."""
    __tablename__ = "ct_stream_cursors"

    log_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    next_index: Mapped[int] = mapped_column(BigInteger)                     # first entry not yet read; always a multiple of 256
    tree_size: Mapped[int] = mapped_column(BigInteger, default=0)           # the log's size at the last look
    lag_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)  # how old the newest entry we processed was when we read it
    entries_seen: Mapped[int] = mapped_column(BigInteger, default=0)
    entries_skipped: Mapped[int] = mapped_column(BigInteger, default=0)     # jumped over because we fell too far behind
    names_matched: Mapped[int] = mapped_column(BigInteger, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class BrandGraphNode(Base):
    """A thing look-alikes can share: the look-alike domain itself, a server address, a nameserver, a mail host, a certificate, a
    registrar, or a registration batch. Generic and kind-typed on purpose (nothing here is Brand-Guard-specific except the profile
    scope), so a second product could adopt the same tables later. Scoped to one brand of one tenant: public infrastructure facts are
    NOT shared across tenants until the cross-tenant decision gate (plan 4.4) is passed."""
    __tablename__ = "brand_graph_nodes"
    __table_args__ = (UniqueConstraint("profile_id", "kind", "key", name="uq_brand_graph_nodes_profile_kind_key"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    profile_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brand_profiles.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))          # domain | ip | nameserver | mail_host | certificate | registrar | batch
    key: Mapped[str] = mapped_column(String(300))          # normalised identifier: the name, the address, the certificate hash...
    label: Mapped[str] = mapped_column(String(300))
    attrs: Mapped[dict] = mapped_column(JSONB, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class BrandGraphEdge(Base):
    """A provable relationship between two nodes (an edge is something an observation shows, not an assumption). Rebuilt from the
    candidates' stored facts on every sync; an edge that is no longer observed is removed, and `first_seen_at` survives a rebuild."""
    __tablename__ = "brand_graph_edges"
    __table_args__ = (UniqueConstraint("profile_id", "src_id", "dst_id", "kind", name="uq_brand_graph_edges"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    profile_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brand_profiles.id", ondelete="CASCADE"), index=True)
    src_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brand_graph_nodes.id", ondelete="CASCADE"), index=True)
    dst_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brand_graph_nodes.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(24))          # resolves_to | uses_nameserver | mails_via | covered_by | registered_via | in_batch
    attrs: Mapped[dict] = mapped_column(JSONB, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class BrandTakedown(Base):
    """A complaint to one party (registrar, host, CDN) about one look-alike. Drafted, edited and approved by a person; ZoneProof never
    sends it. `sent` means the person says they sent it; the outcome is whatever they record afterwards."""
    __tablename__ = "brand_takedowns"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    candidate_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brand_candidates.id", ondelete="CASCADE"), index=True)
    route_kind: Mapped[str] = mapped_column(String(16))        # registrar | host | cdn | za_registry
    route_label: Mapped[str] = mapped_column(String(200))
    how: Mapped[str] = mapped_column(String(8))                # email | form | manual
    target: Mapped[str] = mapped_column(String(320), default="")
    certainty: Mapped[str] = mapped_column(String(12))         # discovered | suggested
    subject: Mapped[str] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(14), default="draft")
    evidence_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    outcome_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class BrandSubmission(Base):
    """A person's record that they reported a look-alike to a reporting service (Google Safe Browsing, SmartScreen, Netcraft) and what came
    back. ZoneProof never submits on anyone's behalf; it prefills the link and keeps the tally."""
    __tablename__ = "brand_submissions"
    __table_args__ = (UniqueConstraint("candidate_id", "service", name="uq_brand_submissions_candidate_service"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    candidate_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brand_candidates.id", ondelete="CASCADE"), index=True)
    service: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(12), default="submitted")
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class BrandNotifyChannel(Base):
    """Where a tenant's Brand Guard alerts and daily summary are sent. The address (an email, or a Slack, Teams or webhook URL) and a webhook's
    signing secret are secrets, so they are encrypted at rest and never returned by the API after they are saved."""
    __tablename__ = "brand_notify_channels"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(8))                     # email | slack | teams | webhook
    label: Mapped[str] = mapped_column(String(80))
    target_enc: Mapped[str] = mapped_column(Text)
    secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    min_severity: Mapped[str] = mapped_column(String(8), default="warn")
    digest: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    last_digest_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(8), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class BrandNotifyLog(Base):
    """One delivery attempt. The unique (channel, alert) pair is what stops an alert being sent to a channel twice."""
    __tablename__ = "brand_notify_log"
    __table_args__ = (UniqueConstraint("channel_id", "alert_id", name="uq_brand_notify_log_channel_alert"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    channel_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brand_notify_channels.id", ondelete="CASCADE"), index=True)
    alert_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), nullable=True)
    kind: Mapped[str] = mapped_column(String(8))                     # alert | digest | test
    status: Mapped[str] = mapped_column(String(8))                   # ok | failed
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class BrandProbeJob(Base):
    """One request for the egress worker to look at one look-alike's host. The worker holds no database access: it claims a job, does the
    network work, and returns a result the API cleans and analyses. Only extracted facts are kept (`result`), never the page itself."""
    __tablename__ = "brand_probe_jobs"
    __table_args__ = (Index("ix_brand_probe_jobs_status_created", "status", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    candidate_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("brand_candidates.id", ondelete="CASCADE"), index=True, nullable=True)   # null for a "ref" job
    profile_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("brand_profiles.id", ondelete="CASCADE"), index=True, nullable=True)       # set for a "ref" job
    host: Mapped[str] = mapped_column(String(253))
    kind: Mapped[str] = mapped_column(String(8), default="light")           # light | render (7.3) | ref (7.4: the customer's own page)
    status: Mapped[str] = mapped_column(String(10), default="queued")       # queued | claimed | done | failed | expired
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class BrandPageCapture(Base):
    """What the sandboxed renderer saw on one look-alike's page (step 7.3): a screenshot and the visible text, both Fernet-encrypted at rest.
    Third-party content (a live phishing page can show other victims' data), so it is only ever served to the owning tenant, and it is deleted
    `retain_until` (30 days) after capture unless the candidate has become a case."""
    __tablename__ = "brand_page_captures"
    __table_args__ = (Index("ix_brand_page_captures_retain_until", "retain_until"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    candidate_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brand_candidates.id", ondelete="CASCADE"), index=True)
    job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    retain_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    screenshot_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    screenshot_mime: Mapped[str | None] = mapped_column(String(12), nullable=True)
    text_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    title: Mapped[str | None] = mapped_column(String(200), nullable=True)
    final_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    forms: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    nav_chain: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    stats: Mapped[dict | None] = mapped_column(JSONB, nullable=True)


class BrandFunnelCount(Base):
    """How many items went into and out of one stage of the Brand Guard funnel, per brand per day (see brand_funnel.py). Counts only: no domain
    names, nothing about any particular look-alike. `detail` says why items did not pass, or how they split, and is specific to the stage."""
    __tablename__ = "brand_funnel_counts"
    __table_args__ = (UniqueConstraint("profile_id", "day", "stage", name="uq_brand_funnel_profile_day_stage"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    profile_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brand_profiles.id", ondelete="CASCADE"), index=True)
    day: Mapped[date] = mapped_column(Date)
    stage: Mapped[str] = mapped_column(String(24))
    entered: Mapped[int] = mapped_column(BigInteger, default=0)
    passed: Mapped[int] = mapped_column(BigInteger, default=0)
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)


class BrandReferenceCapture(Base):
    """What the customer's OWN page looks like in the renderer (step 7.4): the reference a look-alike's screenshot is compared with, and shown
    beside it. It is the customer's own public page, not third-party content, so it is kept until replaced rather than deleted after 30 days
    (it is still encrypted and only served to the owning tenant)."""
    __tablename__ = "brand_reference_captures"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    profile_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brand_profiles.id", ondelete="CASCADE"), unique=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    screenshot_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    screenshot_mime: Mapped[str | None] = mapped_column(String(12), nullable=True)
    layout_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    palette: Mapped[str | None] = mapped_column(String(24), nullable=True)


class BrandCampaign(Base):
    """Look-alikes that share enough infrastructure facts to look like one operator. Rebuilt from the candidates' cluster
    evidence after every scan (brand_campaigns.sync); a row exists only while it has at least two members."""
    __tablename__ = "brand_campaigns"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    profile_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brand_profiles.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    # likely_one_actor | possibly_related | not_enough | probably_yours
    verdict: Mapped[str] = mapped_column(String(24), default="not_enough")
    # [{"kind","label","value","count","of"}]: the shared facts, recomputed on every sync
    facts: Mapped[list] = mapped_column(JSONB, default=list)
    member_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class CandidateEvidence(Base):
    """One typed, timestamped reason a candidate was flagged — the "why am I
    seeing this?" record. Deterministic signals only; the LLM (if used at all)
    explains these, it never manufactures them."""
    __tablename__ = "candidate_evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    candidate_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brand_candidates.id", ondelete="CASCADE"), index=True)

    # domain_similarity | homoglyph | keyword_combo | new_registration | ct_certificate |
    # dns_live | mx_live | infrastructure | ...
    signal: Mapped[str] = mapped_column(String(40))
    # Which score this signal moves: identity | abuse
    dimension: Mapped[str] = mapped_column(String(10))
    weight: Mapped[float] = mapped_column(Float, default=0.0)
    summary: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSONB, default=dict)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    candidate: Mapped[BrandCandidate] = relationship(back_populates="evidence")


SCAN_ACTIVE_STATUSES = ("queued", "running")


class BrandSourceHealth(Base):
    """Shared (not per-tenant) health of a discovery source such as the CT feed.
    One row per source; drives retry/circuit-breaker decisions and the status
    strip customers see. Tenant-agnostic on purpose: the feed is shared
    infrastructure and its outage is the same for everyone."""
    __tablename__ = "brand_source_health"

    source: Mapped[str] = mapped_column(String(40), primary_key=True)
    label: Mapped[str] = mapped_column(String(120))
    # healthy | degraded | down
    status: Mapped[str] = mapped_column(String(10), default="healthy")
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class BrandScanRun(Base):
    """One execution of a brand scan. Scans are slow (hundreds of DNS lookups
    plus RDAP/CT), so they run in the background and the UI polls this row for
    progress instead of holding an HTTP request open. Also the durable history
    of what each scan did — manual and scheduled runs both land here."""
    __tablename__ = "brand_scan_runs"
    __table_args__ = (
        # At most one queued/running scan per brand — enforced by the database,
        # not just by a check-then-insert that two requests could race past.
        Index(
            "uq_brand_scan_runs_one_active", "profile_id", unique=True,
            postgresql_where=text("status IN ('queued','running')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    profile_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brand_profiles.id", ondelete="CASCADE"), index=True)

    # queued | running | succeeded | failed
    status: Mapped[str] = mapped_column(String(12), default="queued")
    # Human-readable stage while running: discovering | dns | registration | scoring
    phase: Mapped[str | None] = mapped_column(String(20), nullable=True)
    progress_done: Mapped[int] = mapped_column(Integer, default=0)
    progress_total: Mapped[int] = mapped_column(Integer, default=0)
    triggered_by: Mapped[str] = mapped_column(String(12), default="manual")  # manual | scheduled

    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class BrandCandidateObservation(Base):
    """Append-only record of what was observed about a candidate at a point in time. Written when
    the observed state CHANGES, plus at most one heartbeat per day, so history stays bounded while
    still proving the state held in between."""
    __tablename__ = "brand_candidate_observations"
    __table_args__ = (Index("ix_bc_obs_candidate_time", "candidate_id", "observed_at"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    candidate_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brand_candidates.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    stage: Mapped[str] = mapped_column(String(16))
    registered: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    resolving: Mapped[bool] = mapped_column(Boolean, default=False)
    mail: Mapped[bool] = mapped_column(Boolean, default=False)
    certified: Mapped[bool] = mapped_column(Boolean, default=False)
    ns: Mapped[list] = mapped_column(JSONB, default=list)
    registered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)  # registry creation date
    source: Mapped[str] = mapped_column(String(20), default="scan")


class BrandCandidateEvent(Base):
    """A lifecycle transition. `occurred_at` is when we NOTICED it; `window_start` is the previous
    observation, so the real change happened somewhere in between — never presented as exact."""
    __tablename__ = "brand_candidate_events"
    __table_args__ = (Index("ix_bc_events_candidate_time", "candidate_id", "occurred_at"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    candidate_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brand_candidates.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    # first_observed | flag_gained | flag_lost | stage_changed | activated | ns_changed
    kind: Mapped[str] = mapped_column(String(24))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)


class BrandRegistrationCache(Base):
    """Shared, tenant-agnostic cache of registry creation dates (RDAP / .za WHOIS). A domain's creation
    date is a public fact that does not change, so every tenant and brand benefits from one lookup and the
    registries are asked as rarely as possible. Not tenant data: it is deliberately outside erasure."""
    __tablename__ = "brand_registration_cache"

    apex_domain: Mapped[str] = mapped_column(String(253), primary_key=True)
    registered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    found: Mapped[bool] = mapped_column(Boolean, default=False)   # False = the lookup produced no date (retry sooner)
    source: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # What the registry said beyond the creation date (plan 2.4): registrar, re-registration, last change, expiry.
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

