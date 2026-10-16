from __future__ import annotations
from pydantic import BaseModel


class SentinelScoreOut(BaseModel):
    score: int                  # 0–100
    grade: str                  # A / B / C / D / F
    grade_color: str
    grade_label: str            # "Fully protected" etc.
    pillar_dmarc: float         # weighted points earned, max 60
    pillar_tls: float           # weighted points earned, max 25
    pillar_certs: float         # weighted points earned, max 15
    volume_weighted: bool
    delta: int | None           # change vs last week's snapshot (None = no history)
    pillar_cloud_posture: float | None = None  # 0-100 on its own scale; None = no connected cloud account (Sentinel Command)
    pillar_human_risk: float | None = None  # 0-100 on its own scale; None = no phishing campaign history yet (Phase 9)
    pillar_verified_exploitability: float | None = None  # 0-100 real per-Finding exploitability rollup; None = nothing scored yet
    pillar_brand_exposure: float | None = None  # 0-100 look-alike domain exposure; None = no active, scanned brand


class DomainKpiOut(BaseModel):
    domain: str
    grade: str
    grade_color: str
    posture_score: float
    dmarc_stage: str
    mta_sts_stage: str
    mta_sts_hosting_mode: str
    dmarc_comp: float | None
    tls_pass_pct: float | None
    tls_sessions: int
    volume: int
    min_cert_days: int | None
    cert_status: str | None   # ok | expiring_soon | critical | expired


class CertAlertOut(BaseModel):
    domain: str
    days_remaining: int | None
    status: str   # expiring_soon | critical | expired


class PortfolioCertOut(BaseModel):
    id: str
    domain: str
    host: str
    host_type: str          # smtp | https
    subject_cn: str | None
    issuer: str | None
    san: str | None
    not_after: str | None   # ISO datetime string
    days_remaining: int | None
    tls_version: str | None
    starttls_supported: bool | None
    hostname_valid: bool | None
    status: str             # ok | expiring_soon | critical | expired | error
    probe_error: str | None
    probed_at: str          # ISO datetime string


class ThreatTargetOut(BaseModel):
    domain: str
    attempts: int
    blocked: int
    blocked_pct: float
    exposed: int          # passed through because policy = none
    dmarc_stage: str


class ThreatSourceOut(BaseModel):
    source_org: str
    source_ip: str
    attempts: int
    rdns: str | None
    asn: str | None


class ThreatSurfaceOut(BaseModel):
    period_days: int
    total_attempts: int          # all DMARC-failing messages from suspicious sources
    blocked: int                 # disposition quarantine or reject
    blocked_pct: float
    exposed: int                 # disposition none — reached inboxes
    unique_ips: int
    unique_orgs: int
    top_targeted: list[ThreatTargetOut]
    top_sources: list[ThreatSourceOut]
    has_data: bool


# ── Report-specific models ────────────────────────────────────────────────────

class ScoreTrendPoint(BaseModel):
    week: str   # ISO date "YYYY-MM-DD"
    score: int


class SenderRow(BaseModel):
    org: str
    volume: int
    pass_pct: float
    dkim_aligned_pct: float
    spf_aligned_pct: float
    top_ip: str | None


class SenderInventoryOut(BaseModel):
    authorized_compliant: list[SenderRow]
    authorized_noncompliant: list[SenderRow]
    unauthorized: list[SenderRow]
    total_authorized_volume: int
    total_unauthorized_volume: int


class RecommendationItem(BaseModel):
    priority: int
    domain: str
    action: str
    detail: str
    effort: str    # Low | Medium | High
    impact: str    # Low | Medium | High
    category: str  # dmarc | tls | cert | spf


class ReportDomainRow(BaseModel):
    domain: str
    grade: str
    grade_color: str
    dmarc_stage: str
    mta_sts_stage: str
    dmarc_comp: float | None
    dkim_pass_pct: float | None
    tls_pass_pct: float | None
    volume: int
    cert_status: str | None
    min_cert_days: int | None
    primary_issue: str | None


class NarrativeOut(BaseModel):
    summary: str | None = None
    threats: str | None = None
    actions: str | None = None
    generated_at: str | None = None
    is_ai: bool = False


class ReportDataOut(BaseModel):
    generated_at: str
    workspace_name: str
    period_days: int
    sentinel: SentinelScoreOut
    headline_verdict: str
    executive_narrative: str
    narrative: NarrativeOut | None = None
    score_trend: list[ScoreTrendPoint]
    sender_inventory: SenderInventoryOut
    recommendations: list[RecommendationItem]
    total_domains: int
    total_volume: int
    total_tls_sessions: int
    dmarc_reject_count: int
    dmarc_none_count: int
    tls_enforce_count: int
    tls_testing_count: int
    tls_none_count: int
    avg_dmarc_comp: float | None
    avg_dkim_pass_pct: float | None
    avg_tls_pass_pct: float | None
    cert_alerts: int
    threat: ThreatSurfaceOut
    domains: list[ReportDomainRow]
    cert_expiry_list: list[CertAlertOut]
    brand_guard: dict | None = None   # brand exposure section for the report (brand_exposure.compute); None = not using Brand Guard


class TenantOverviewOut(BaseModel):
    tenant_name: str
    plan: str
    total_domains: int
    # DMARC posture counts
    at_reject: int
    in_progress: int
    unprotected: int
    avg_dmarc_comp: float | None
    # DMARC distribution (for stacked bar)
    dmarc_none_count: int
    dmarc_monitor_count: int
    dmarc_quarantine_count: int
    dmarc_reject_count: int
    # TLS posture counts
    tls_enforce_count: int
    tls_testing_count: int
    tls_none_count: int
    avg_tls_pass_pct: float | None
    # Volume
    total_volume: int
    total_tls_sessions: int
    # Cert health
    cert_alerts: int
    cert_expiry_list: list[CertAlertOut]
    # Sentinel Score
    sentinel: SentinelScoreOut
    # Per-domain rows
    domains: list[DomainKpiOut]
    # AI narrative (may be None if not yet generated)
    narrative: NarrativeOut | None = None


class ReadinessBlockerDomainOut(BaseModel):
    domain_id: str
    domain_name: str
    detail: str


class ReadinessBlockerCategoryOut(BaseModel):
    """
    PAIN_POINT_RESOLUTION_PLAN.md's Portfolio Readiness Rollup — one row
    per blocker category, the count of affected domains, and enough per-
    domain detail to click straight through to the right surface instead
    of re-discovering the same issue domain-by-domain.
    """
    category: str        # platform_setup | undispositioned_subdomains | mta_sts_hosting | blocking_sources
    label: str
    count: int
    domains: list[ReadinessBlockerDomainOut]


class PortfolioReadinessRollupOut(BaseModel):
    categories: list[ReadinessBlockerCategoryOut]
