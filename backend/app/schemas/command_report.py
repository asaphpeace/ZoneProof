"""
Schemas for the Sentinel Command report (Coverage Map plan Phase 10) — the
distillation of everything Phases 0-9 built (composite score, cloud/host/
OAuth findings, the attack path graph, phishing campaign results) into one
exportable document. Wraps V1's existing ReportDataOut (email auth + cloud
posture composite score, already computed by overview.get_report_data())
rather than recomputing the score a second time — see
command_report_service.py's docstring.
"""
from __future__ import annotations

from pydantic import BaseModel

from app.schemas.overview import ReportDataOut


class CommandFindingTierSummaryOut(BaseModel):
    tier: str
    open_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


class CommandTopFindingOut(BaseModel):
    id: str
    tier: str
    severity: str
    title: str
    resource_uid: str | None
    discovered_at: str
    occurrence_count: int = 1


class CommandTopPathOut(BaseModel):
    id: str
    source_principal_arn: str
    target_principal_arn: str
    severity: str
    detection_verdict: str | None  # covered | partial | blind_spot | None (no cloud findings to derive one from)


class CommandAttackPathSummaryOut(BaseModel):
    open_count: int
    critical_count: int
    covered_count: int
    partial_count: int
    blind_spot_count: int
    top_paths: list[CommandTopPathOut]


class CommandPhishingSummaryOut(BaseModel):
    campaign_count: int
    total_sent: int
    total_opened: int
    total_clicked: int
    total_credential_entered: int
    open_rate_pct: float
    click_rate_pct: float
    credential_rate_pct: float
    last_campaign_launched_at: str | None
    last_campaign_llm_generated: bool | None
    last_campaign_dmarc_context: str | None


class CommandConnectionsSummaryOut(BaseModel):
    cloud_connections_connected: int
    host_connections_connected: int
    oauth_connections_connected: int


class CommandReportDataOut(BaseModel):
    generated_at: str
    tenant_name: str
    brand_name: str | None
    brand_logo_url: str | None
    plan: str
    email_report: ReportDataOut
    connections: CommandConnectionsSummaryOut
    engagement_count: int
    active_engagement_count: int
    findings_by_tier: list[CommandFindingTierSummaryOut]
    total_open_findings: int
    total_critical_findings: int
    top_findings: list[CommandTopFindingOut]
    attack_paths: CommandAttackPathSummaryOut
    phishing: CommandPhishingSummaryOut | None
