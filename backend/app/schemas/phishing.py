from typing import Literal

from pydantic import BaseModel


class TargetListEntry(BaseModel):
    email: str
    display_name: str | None = None
    # Optional personalization context (Coverage Map plan Phase 7) — lets
    # generated lures address a role ("the person who approves expense
    # runs") instead of writing generically. Never required.
    job_title: str | None = None
    department: str | None = None
    # Optional per-recipient language override (Phishing Simulation
    # roadmap Phase 19) — falls back to the tenant's default_locale when
    # unset. Never required, same precedent as job_title/department above.
    locale: str | None = None


class PhishingTargetListCreate(BaseModel):
    name: str
    entries: list[TargetListEntry] = []


class PhishingTargetListOut(BaseModel):
    id: str
    name: str
    entries: list[TargetListEntry]
    created_at: str


class TargetListDiffRequest(BaseModel):
    entries: list[TargetListEntry]


class TargetListChangedEntryOut(BaseModel):
    email: str
    before: TargetListEntry
    after: TargetListEntry


class TargetListDiffOut(BaseModel):
    added: list[TargetListEntry]
    removed: list[TargetListEntry]
    changed: list[TargetListChangedEntryOut]
    unchanged_count: int


class PhishingExemptionCreate(BaseModel):
    email: str
    reason: str | None = None


class PhishingExemptionOut(BaseModel):
    id: str
    email: str
    reason: str | None
    created_at: str


class PhishingTemplateOut(BaseModel):
    id: str
    label: str
    category: str = "General"
    subject: str
    body_html: str
    # The real, honest category-level red flags this lure would teach if
    # someone clicked (Phishing Simulation roadmap Phase 16) — the same
    # generic_flags a real recipient falls back to in
    # phishing_lesson_content.get_lesson_content() when no literal phrase
    # match is found, surfaced here at compose time before any content has
    # actually been sent to cite a literal phrase from.
    teachable_signals: list[str] = []


class PhishingCustomTemplateCreate(BaseModel):
    label: str
    category: str = "General"
    subject: str
    body_html: str
    difficulty: str = "medium"  # low | medium | high
    from_email: str | None = None
    display_name: str | None = None
    include_attachments: bool = False


class PhishingCustomTemplateUpdate(BaseModel):
    # All optional — PATCH semantics, only the fields sent are changed.
    label: str | None = None
    category: str | None = None
    subject: str | None = None
    body_html: str | None = None
    difficulty: str | None = None
    from_email: str | None = None
    display_name: str | None = None
    include_attachments: bool | None = None


class PhishingCustomTemplateOut(BaseModel):
    id: str
    label: str
    category: str
    subject: str
    body_html: str
    difficulty: str
    from_email: str | None = None
    display_name: str | None = None
    include_attachments: bool
    created_at: str
    updated_at: str
    # Only computed when the caller passes target_list_id — None means
    # "not evaluated against any specific audience", not "ineligible".
    eligible: bool | None = None


class SendTestTemplateEmailRequest(BaseModel):
    # Works on an unsaved draft too — matches the reference flow where
    # "Send test email" and "Save" are independent actions, so an admin
    # can see real inbox rendering before deciding the template is worth
    # keeping.
    subject: str
    body_html: str


class DepartmentBreakdownOut(BaseModel):
    # Real, server-side-aggregated results for one campaign, grouped by
    # the department recorded on each target-list entry (Phishing
    # Simulation roadmap — design adoption pass). The recipient_hash ↔
    # department mapping itself is never exposed — only these counts.
    # Absent entirely means no department was recorded for anyone on this
    # campaign's real recipients, never a fabricated "Unknown" bucket.
    department: str
    sent: int
    clicked: int
    credential_entered: int


class DepartmentTrainingOut(BaseModel):
    department: str
    assigned: int
    completed: int


class RiskComponentOut(BaseModel):
    # One named, separately-graded slice of the Human Risk Score (Phishing
    # Simulation roadmap Phase 30a). score/grade both None means real data
    # doesn't exist yet for this specific component — never a fabricated
    # grade. Deliberately only 4 of these, and no "Knowledge" component:
    # see compute_human_risk_components()'s docstring for why that one
    # can't be shown honestly with this codebase's real data today.
    label: str
    score: float | None = None
    grade: str | None = None


class PhishingDashboardOut(BaseModel):
    # None across every rate/score means this tenant has never launched a
    # real campaign — never a fabricated 0% or 0-score dashboard. Real,
    # portfolio-wide (every campaign this tenant has ever run), not scoped
    # to the most recent cycle.
    human_risk_score: float | None = None
    human_risk_grade: str | None = None
    risk_components: list[RiskComponentOut] = []
    sent: int = 0
    click_rate: float | None = None
    credential_rate: float | None = None
    report_rate: float | None = None
    training_assigned: int = 0
    training_completed: int = 0
    # None specifically means nothing has ever been assigned — distinct
    # from 0.0 (assigned but nobody's finished any of it).
    training_completion_rate: float | None = None
    # Course-based training (Phishing Simulation roadmap Phase 24) — kept
    # as its own separate rate from the micro-lesson numbers above, not
    # blended (see compute_tenant_phishing_summary's comment on why).
    course_training_assigned: int = 0
    course_training_completed: int = 0
    course_training_completion_rate: float | None = None
    department_training: list[DepartmentTrainingOut] = []
    watchlist: list["EngagementRecipientOut"] = []


class PhishingLureStatOut(BaseModel):
    # Real click-rate history for one lure template, across every campaign
    # this tenant has ever launched with it (Phishing Simulation roadmap
    # Phase 16) — informs template selection with actual data instead of a
    # blind guess at which subject line "sounds right". None means this
    # tenant has never sent this template, never a fabricated 0%.
    template_id: str
    sent_count: int
    click_rate: float | None = None


class PhishingCampaignOut(BaseModel):
    id: str
    engagement_id: str
    target_list_id: str
    template_id: str
    status: str
    launched_at: str
    # Real evidence of what was actually sent this cycle.
    llm_generated: bool = False
    subject_sent: str | None = None
    dmarc_context: str | None = None
    body_html_sent: str | None = None
    landing_page_id: str | None = None
    # Who this cycle was actually sent to, when it wasn't the whole target
    # list (Phishing Simulation roadmap Phase 15) — None means the whole
    # list, the historical default.
    audience_label: str | None = None


class PhishingCampaignSummaryOut(BaseModel):
    """One row per campaign, pre-aggregated with its own event counts —
    what the landing page's stat row and simulations table are built from
    (Phishing Simulation roadmap Phase 29b), fetched in one call instead of
    a list-then-events-per-campaign loop."""
    id: str
    engagement_id: str
    target_list_id: str
    template_id: str
    launched_at: str
    dmarc_context: str | None = None
    subject_sent: str | None = None
    sent: int = 0
    opened: int = 0
    clicked: int = 0
    credential_entered: int = 0
    reported: int = 0


class LandingPageOut(BaseModel):
    id: str
    label: str


class PhishingMetaOut(BaseModel):
    tracking_domain: str
    sending_identity: str
    credential_capture_policy: str
    recipient_privacy_policy: str
    phishing_paused: bool
    phishing_report_schedule: str = "off"
    last_phishing_report_sent_at: str | None = None
    # Training defaults (Phishing Simulation roadmap Phase 24) — None
    # means "keep using the always-on micro-lesson only," the original
    # default behavior; unchanged unless a tenant opts in.
    auto_assign_training_course_id: str | None = None
    training_reminder_interval_days: int = 14
    training_reminder_max_count: int = 2
    # Real forwarding address for employee-reported suspicious emails
    # (Phishing Simulation roadmap Phase 26) — auto-provisioned on first
    # read if this tenant doesn't have one yet, so it's never null once
    # this endpoint has been hit at least once.
    report_suspicious_email_address: str


class PhishingContentPreviewOut(BaseModel):
    # {click_url} is still a literal placeholder here — real per-recipient
    # substitution only happens at actual send time (resolve_campaign_content
    # docstring). The frontend renders a cosmetic, non-functional stand-in
    # link for display and must echo this response back verbatim to launch.
    subject: str
    body_html: str
    llm_generated: bool
    dmarc_context: str | None = None


class LaunchCampaignRequest(BaseModel):
    # When present, launch uses this EXACT content instead of generating
    # again — it must be an untouched PhishingContentPreviewOut a human
    # already reviewed, so what was approved is what ships.
    approved_subject: str | None = None
    approved_body_html: str | None = None
    approved_llm_generated: bool = False
    approved_dmarc_context: str | None = None
    # Who gets this cycle (Phishing Simulation roadmap Phase 15) —
    # "everyone" (default, unchanged behavior) sends to the whole list;
    # "department" requires `department`; "individual" requires
    # `recipient_hashes` (picked from the pseudonymized People view, never
    # a plaintext identity).
    audience_type: Literal["everyone", "department", "individual"] = "everyone"
    department: str | None = None
    recipient_hashes: list[str] | None = None


class PhishingEventCountsOut(BaseModel):
    sent: int = 0
    opened: int = 0
    clicked: int = 0
    credential_entered: int = 0
    reported: int = 0
    # A real transport failure (Phishing Simulation roadmap Phase 17) —
    # send_email() returning False, a suppressed address, a real SendGrid
    # rejection — surfaced honestly instead of being silently folded into
    # "sent". "Delivered" should never read 100% when this is nonzero.
    send_failed: int = 0
    # Aggregate training-assignment status (Coverage Map plan phishing
    # transformation, Phase 2) — how many clickers/credential-enterers were
    # assigned a lesson, and how many actually completed it.
    training_assigned: int = 0
    training_completed: int = 0
    # Median seconds between opening the lure and acting on it, across
    # recipients who did both (Phishing Simulation roadmap Phase 12). None
    # when nobody has both an open and a subsequent act recorded yet —
    # never a fabricated 0.
    median_dwell_seconds: float | None = None


class RecipientEventDetailOut(BaseModel):
    # Real per-event evidence — what/when/where/destination. "Who" stays
    # at the recipient_hash level (RecipientEventsOut below), unmasked
    # separately and only by an admin.
    event_type: str
    occurred_at: str
    ip_address: str | None = None
    user_agent: str | None = None
    destination_url: str | None = None


class RecipientEventsOut(BaseModel):
    # Pseudonymized by construction — the UI lists these to let an admin
    # pick one to unmask, without ever exposing identity itself here.
    recipient_hash: str
    event_types: list[str]
    events: list[RecipientEventDetailOut] = []
    training_status: str | None = None
    training_completed_at: str | None = None
    # Seconds between this recipient's first open and first click/credential
    # entry (Phishing Simulation roadmap Phase 12). None when there's no
    # open-then-act pair to measure yet.
    dwell_seconds: float | None = None


class EngagementRecipientCampaignOut(BaseModel):
    # One campaign's worth of this person's history — Phishing Simulation
    # roadmap Phase 13, the cross-campaign "People" view.
    campaign_id: str
    launched_at: str
    event_types: list[str]


class EngagementRecipientOut(BaseModel):
    # One row per recipient_hash, aggregated across every campaign this
    # engagement has ever launched — closes the "no standing per-person
    # view" gap (Mimecast's User Performance table / Proofpoint's
    # repeat-clicker highlighting), scoped to this engagement's own send
    # history. Still pseudonymized by construction, same as
    # RecipientEventsOut above.
    recipient_hash: str
    campaigns: list[EngagementRecipientCampaignOut]
    event_types: list[str]  # union across every campaign, for one worst-outcome read
    repeat_click_count: int  # number of distinct campaigns with a real click
    training_status: str | None = None  # most recent training assignment's status, if any


# PhishingDashboardOut.watchlist references this class by forward-referenced
# name (defined earlier in this file, above where EngagementRecipientOut
# itself is defined) — Phase 30c reuses this exact shape tenant-wide rather
# than inventing a lighter one, specifically so a Watchlist row can open the
# same evidence panel already built for the per-engagement People view.
# model_rebuild() resolves that forward reference now that the real class
# exists in this module's namespace.
PhishingDashboardOut.model_rebuild()


class EmailAuthEvidenceOut(BaseModel):
    # Independent evidence (Coverage Map plan phishing transformation,
    # Phase 6) — real DMARC aggregate volume + Sentinel's own spoof-test
    # result, cited alongside a campaign's simulated results. None means
    # there is genuinely no such evidence yet, never a fabricated zero.
    window_days: int
    unaligned_message_count: int
    total_message_count: int
    spoof_test_status: str | None = None
    spoof_test_detail: str | None = None
    spoof_test_date: str | None = None


class UnmaskRequest(BaseModel):
    recipient_hash: str


class PrivEscPathSummaryOut(BaseModel):
    # A real open escalation path this unmasked person's AWS identity is
    # part of (Coverage Map plan phishing transformation, Phase 8) — "who
    # clicked AND has admin access to production," not just who clicked.
    id: str
    source_principal_arn: str
    target_principal_arn: str
    technique_chain: list[str]
    severity: str


class UnmaskOut(BaseModel):
    email: str
    display_name: str | None = None
    # None when no AWS identity has ever been resolved for this email —
    # an honest "nothing to show," never a guess. "sso_session" or
    # "iam_tag" when one has, naming exactly how confident that match is.
    cloud_identity_provenance: str | None = None
    open_privesc_paths: list[PrivEscPathSummaryOut] = []
