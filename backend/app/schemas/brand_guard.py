from pydantic import BaseModel, Field, field_validator

from app.models.brand_guard import CANDIDATE_STATUSES

# Statuses a human may set by hand. "new" is excluded (it's the initial state);
# the rest are the analyst-owned lifecycle and terminal "not a threat" states.
SETTABLE_STATUSES = tuple(s for s in CANDIDATE_STATUSES if s != "new")


def _clean_list(values: list[str], *, lower: bool = True, limit: int = 50) -> list[str]:
    out: list[str] = []
    for v in values:
        v = (v or "").strip()
        if lower:
            v = v.lower()
        if v and v not in out:
            out.append(v[:253])
    return out[:limit]


class Trademark(BaseModel):
    """A trademark registration the customer holds (kept for takedown / UDRP evidence)."""
    mark: str = Field(min_length=1, max_length=120)
    number: str = Field(default="", max_length=40)
    jurisdiction: str = Field(default="", max_length=40)

    @field_validator("mark", "number", "jurisdiction")
    @classmethod
    def _strip(cls, v: str) -> str:
        return (v or "").strip()


class BrandProfileCreate(BaseModel):
    domain_id: str
    brand_name: str = Field(min_length=2, max_length=120)
    keywords: list[str] = []
    official_domains: list[str] = []
    login_urls: list[str] = []

    @field_validator("keywords", "official_domains")
    @classmethod
    def _norm(cls, v: list[str]) -> list[str]:
        return _clean_list(v)

    @field_validator("login_urls")
    @classmethod
    def _norm_urls(cls, v: list[str]) -> list[str]:
        return _clean_list(v, lower=False, limit=20)


class BrandProfileUpdate(BaseModel):
    brand_name: str | None = Field(default=None, min_length=2, max_length=120)
    keywords: list[str] | None = None
    official_domains: list[str] | None = None
    login_urls: list[str] | None = None
    trademarks: list[Trademark] | None = Field(default=None, max_length=20)
    is_active: bool | None = None

    @field_validator("keywords", "official_domains")
    @classmethod
    def _norm(cls, v):
        return None if v is None else _clean_list(v)

    @field_validator("login_urls")
    @classmethod
    def _norm_urls(cls, v):
        return None if v is None else _clean_list(v, lower=False, limit=20)


class ScanRunOut(BaseModel):
    id: str
    profile_id: str
    # queued | running | succeeded | failed
    status: str
    # discovering | dns | registration | scoring (while running)
    phase: str | None
    progress_done: int
    progress_total: int
    triggered_by: str
    result: dict | None
    error: str | None
    created_at: str
    started_at: str | None
    finished_at: str | None


class SourceHealthOut(BaseModel):
    source: str
    label: str
    # unknown (never called) | healthy | degraded | down
    status: str
    consecutive_failures: int
    last_success_at: str | None
    last_failure_at: str | None
    # Short reason such as "HTTP 502" — never a URL or response body.
    last_error: str | None
    last_latency_ms: int | None
    # Set while the circuit breaker is open: earliest time of the next attempt.
    retry_after: str | None


class BrandProfileOut(BaseModel):
    id: str
    domain_id: str
    primary_domain: str
    brand_name: str
    keywords: list[str]
    official_domains: list[str]
    login_urls: list[str]
    is_active: bool
    last_scanned_at: str | None
    last_ct_poll_at: str | None
    last_scan_error: str | None
    candidate_counts: dict[str, int]
    ct_enabled: bool
    max_candidates: int | None
    latest_run: ScanRunOut | None = None
    # Manual scans this tenant has used in the last 24h, and the plan's daily allowance (None = unlimited)
    scans_today: int = 0
    scan_quota: int | None = None
    # Plain-language caveats about how well this brand can be matched by name
    warnings: list[str] = []
    trademarks: list[Trademark] = []
    # What the real brand looks like (null until built) and when
    fingerprint: dict | None = None
    fingerprint_built_at: str | None = None
    # The tenant's OTHER domains not yet listed as official (computed on read, so always current)
    suggested_official_domains: list[str] = []


class EvidenceOut(BaseModel):
    id: str
    signal: str
    dimension: str
    weight: float
    summary: str
    data: dict
    observed_at: str


class CandidateOut(BaseModel):
    id: str
    profile_id: str
    candidate_domain: str
    candidate_domain_unicode: str
    status: str
    identity_score: float
    abuse_score: float
    impact: str
    urgency: str
    threat_class: str | None
    sources: list[str]
    enrichment: dict
    first_seen_at: str
    last_seen_at: str
    analyst_note: str | None
    reviewed_at: str | None
    # lifecycle (plan step 2.1)
    stage: str
    stage_label: str
    stage_changed_at: str | None
    last_observed_at: str | None
    # What the analyst sees (brand_verdict.py): the system's verdict, how well corroborated it is, what a person decided,
    # and one plain sentence of why. Kept separate on purpose — a rescan changes the verdict, never the decision.
    verdict: dict = {}
    confidence: dict = {}
    decision: dict = {}
    why: str = ""
    # The campaign (group of look-alikes that appear to share an operator) it belongs to, if any
    campaign_id: str | None = None
    campaign_name: str | None = None
    # Case workflow (brand_cases.py): owner and response deadline
    assignee: dict | None = None
    sla: dict = {}
    # How much stronger the abuse-side evidence is than for an ordinary new registration (brand_reasoning): a ratio, a band, and
    # which part was measured and which assumed. Not a probability.
    reasoning: dict = {}
    # What kind of threat it looks like (brand_taxonomy), with the basis: "reported" by a public feed or "suspected" from the name and setup
    abuse_type: dict = {}


class LifecycleEventOut(BaseModel):
    id: str
    kind: str
    # When we NOTICED it. The change happened sometime between window_start and this.
    occurred_at: str
    window_start: str | None
    summary: str
    payload: dict


class LadderRung(BaseModel):
    stage: str
    label: str
    reached: bool
    first_seen_at: str | None
    # True when the rung was already reached at first sighting, so no timing is implied
    baseline: bool
    current: bool


class TimelineOut(BaseModel):
    stage: str
    stage_label: str
    ladder: list[LadderRung]
    events: list[LifecycleEventOut]
    velocity: dict
    observations: dict


class CandidateDetailOut(CandidateOut):
    evidence: list[EvidenceOut]
    # Plain-English ordered "why ZoneProof flagged this" lines — the same
    # signals as `evidence`, pre-sorted by weight, for direct rendering.
    why_flagged: list[str]
    # Evidence laid out for the drawer: for / against / context / checked-and-found-nothing, plus a numbered summary
    evidence_view: dict = {}
    # The proof behind the verdict (brand_derivation): the rule that fired, down to the raw facts, each with its source
    derivation: dict = {}
    # Abuse type, what it could do (impact and reach) and the attack as ordered steps (brand_taxonomy)
    threat: dict = {}


class CampaignOut(BaseModel):
    id: str
    profile_id: str
    name: str
    verdict: dict
    why: str
    member_count: int
    live_count: int
    first_seen_at: str
    updated_at: str
    facts: list[dict]


class CampaignDetailOut(CampaignOut):
    members: list[CandidateOut]
    # What links the members (brand_graph.subgraph): the shared infrastructure, how strong each link is, and who uses it
    graph: dict = {}


class TakedownRoute(BaseModel):
    kind: str = Field(pattern="^(registrar|host|cdn|za_registry)$")
    label: str = Field(max_length=200)
    how: str = Field(pattern="^(email|form|manual)$")
    target: str = Field(default="", max_length=320)
    certainty: str = Field(pattern="^(discovered|suggested)$")
    note: str = Field(default="", max_length=1000)


class TakedownCreate(BaseModel):
    route: TakedownRoute


class TakedownEdit(BaseModel):
    subject: str = Field(min_length=1, max_length=300)
    body: str = Field(min_length=1, max_length=10000)


class TakedownMove(BaseModel):
    status: str
    note: str | None = Field(default=None, max_length=2000)


class TakedownOut(BaseModel):
    id: str
    candidate_id: str
    route_kind: str
    route_label: str
    how: str
    target: str
    certainty: str
    subject: str
    body: str
    status: str
    allowed_next: list[str]
    evidence_hash: str | None
    approved_at: str | None
    sent_at: str | None
    outcome_note: str | None
    created_at: str
    mailto: str | None = None
    # page_evidence | name_only: what the complaint can honestly rest on
    evidence_level: str | None = None


class SubmissionCreate(BaseModel):
    service: str = Field(pattern="^(google_safe_browsing|microsoft|netcraft)$")
    note: str | None = Field(default=None, max_length=1000)


class SubmissionMove(BaseModel):
    status: str = Field(pattern="^(submitted|listed|declined)$")
    note: str | None = Field(default=None, max_length=1000)


class ChannelCreate(BaseModel):
    kind: str = Field(pattern="^(email|slack|teams|webhook)$")
    label: str = Field(min_length=1, max_length=80)
    target: str = Field(min_length=1, max_length=2000)
    min_severity: str = Field(default="warn", pattern="^(warn|critical)$")
    digest: bool = False


class ChannelUpdate(BaseModel):
    label: str | None = Field(default=None, min_length=1, max_length=80)
    min_severity: str | None = Field(default=None, pattern="^(warn|critical)$")
    digest: bool | None = None
    enabled: bool | None = None


class CandidateAssign(BaseModel):
    user_id: str | None = None          # None clears the assignee


class CandidateStatusUpdate(BaseModel):
    status: str
    note: str | None = Field(default=None, max_length=2000)

    @field_validator("status")
    @classmethod
    def _valid(cls, v: str) -> str:
        if v not in SETTABLE_STATUSES:
            raise ValueError(f"status must be one of: {', '.join(SETTABLE_STATUSES)}")
        return v


class BrandGuardSummaryOut(BaseModel):
    brands: int
    open_candidates: int
    dormant: int
    suspicious: int
    confirmed: int
    takedown: int
    false_positive: int
    # Home dashboard (all derived from stored data; see the router for exact definitions)
    new_24h: int = 0
    went_live_7d: int = 0
    median_detect_hours: float | None = None
    median_detect_n: int = 0
