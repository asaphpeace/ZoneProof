"""
Assembles and renders the Sentinel Command report (Coverage Map plan
Phase 10) — the distillation of everything Phases 0-9 built into one
exportable document: the composite Sentinel Score (reused as-is from
overview.get_report_data(), not recomputed here — that function already
blends the email-auth pillars with Cloud Posture via
posture_service.compute_sentinel_score()), open findings by tier, the
attack path graph (with Detection Coverage verdicts), and — when a
phishing engagement exists — the campaign results.

Deliberately extends pdf_report_service.py's existing HTML/Chromium
pipeline (render_html_to_pdf()) rather than standing up a second one, per
the plan's own instruction: "this should extend this exact pipeline, not
invent a second one."
"""
from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    CloudAccountConnection, CloudPrivEscPath, Engagement, Finding,
    HostConnection, OAuthAppConnection, PhishingCampaign, PhishingEvent,
)
from app.models.user import Tenant, User
from app.routers.overview import get_report_data
from app.schemas.command_report import (
    CommandAttackPathSummaryOut, CommandConnectionsSummaryOut, CommandFindingTierSummaryOut,
    CommandPhishingSummaryOut, CommandReportDataOut, CommandTopFindingOut, CommandTopPathOut,
)
from app.services.detection_coverage_service import compute_detection_coverage
from app.services.pdf_report_service import _grade_color, render_html_to_pdf

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEVERITY_COLOR = {"critical": "#ff4d6d", "high": "#f5a623", "medium": "#5b6ef5", "low": "#34e0a1"}


async def _connections_summary(db: AsyncSession, tenant_id: uuid.UUID) -> CommandConnectionsSummaryOut:
    cloud_count = (await db.execute(
        select(func.count()).select_from(CloudAccountConnection)
        .where(CloudAccountConnection.tenant_id == tenant_id, CloudAccountConnection.status == "connected")
    )).scalar_one()
    host_count = (await db.execute(
        select(func.count()).select_from(HostConnection)
        .where(HostConnection.tenant_id == tenant_id, HostConnection.status == "connected")
    )).scalar_one()
    oauth_count = (await db.execute(
        select(func.count()).select_from(OAuthAppConnection)
        .where(OAuthAppConnection.tenant_id == tenant_id, OAuthAppConnection.status == "connected")
    )).scalar_one()
    return CommandConnectionsSummaryOut(
        cloud_connections_connected=cloud_count,
        host_connections_connected=host_count,
        oauth_connections_connected=oauth_count,
    )


async def _findings_summary(db: AsyncSession, tenant_id: uuid.UUID) -> tuple[list[CommandFindingTierSummaryOut], int, int, list[CommandTopFindingOut]]:
    findings = (await db.execute(
        select(Finding).where(Finding.tenant_id == tenant_id, Finding.status == "open")
    )).scalars().all()

    by_tier: dict[str, dict[str, int]] = {}
    for f in findings:
        counts = by_tier.setdefault(f.tier, {"critical": 0, "high": 0, "medium": 0, "low": 0})
        if f.severity in counts:
            counts[f.severity] += 1

    tier_summaries = [
        CommandFindingTierSummaryOut(
            tier=tier, open_count=sum(counts.values()),
            critical_count=counts["critical"], high_count=counts["high"],
            medium_count=counts["medium"], low_count=counts["low"],
        )
        for tier, counts in sorted(by_tier.items())
    ]

    total_open = len(findings)
    total_critical = sum(1 for f in findings if f.severity == "critical")

    # Ties within a severity favor the finding affecting more resources —
    # a gap Prowler found in 18 regions is more noteworthy than a single-
    # instance finding of the same severity, not just whichever was
    # discovered most recently.
    top = sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), -f.occurrence_count, -f.discovered_at.timestamp()),
    )[:10]
    top_findings = [
        CommandTopFindingOut(
            id=str(f.id), tier=f.tier, severity=f.severity, title=f.title,
            resource_uid=f.resource_uid, discovered_at=f.discovered_at.isoformat(),
            occurrence_count=f.occurrence_count,
        )
        for f in top
    ]
    return tier_summaries, total_open, total_critical, top_findings


async def _attack_path_summary(db: AsyncSession, tenant_id: uuid.UUID) -> CommandAttackPathSummaryOut:
    paths = (await db.execute(
        select(CloudPrivEscPath).where(CloudPrivEscPath.tenant_id == tenant_id, CloudPrivEscPath.status == "open")
    )).scalars().all()

    coverage = await compute_detection_coverage(db, tenant_id)
    verdict_by_path_id = {row["priv_esc_path_id"]: row["verdict"] for row in coverage}

    covered = sum(1 for v in verdict_by_path_id.values() if v == "covered")
    partial = sum(1 for v in verdict_by_path_id.values() if v == "partial")
    blind_spot = sum(1 for v in verdict_by_path_id.values() if v == "blind_spot")
    critical = sum(1 for p in paths if p.severity == "critical")

    top = sorted(paths, key=lambda p: (_SEVERITY_ORDER.get(p.severity, 9), -p.discovered_at.timestamp()))[:10]
    top_paths = [
        CommandTopPathOut(
            id=str(p.id), source_principal_arn=p.source_principal_arn,
            target_principal_arn=p.target_principal_arn, severity=p.severity,
            detection_verdict=verdict_by_path_id.get(str(p.id)),
        )
        for p in top
    ]

    return CommandAttackPathSummaryOut(
        open_count=len(paths), critical_count=critical,
        covered_count=covered, partial_count=partial, blind_spot_count=blind_spot,
        top_paths=top_paths,
    )


async def _phishing_summary(db: AsyncSession, tenant_id: uuid.UUID) -> CommandPhishingSummaryOut | None:
    campaigns = (await db.execute(
        select(PhishingCampaign).where(PhishingCampaign.tenant_id == tenant_id).order_by(PhishingCampaign.launched_at.desc())
    )).scalars().all()
    if not campaigns:
        return None

    counts_result = await db.execute(
        select(PhishingEvent.event_type, func.count())
        .where(PhishingEvent.tenant_id == tenant_id)
        .group_by(PhishingEvent.event_type)
    )
    counts = {event_type: count for event_type, count in counts_result.all()}
    sent = counts.get("sent", 0)
    opened = counts.get("opened", 0)
    clicked = counts.get("clicked", 0)
    credential = counts.get("credential_entered", 0)

    last = campaigns[0]
    return CommandPhishingSummaryOut(
        campaign_count=len(campaigns),
        total_sent=sent, total_opened=opened, total_clicked=clicked, total_credential_entered=credential,
        open_rate_pct=round(opened / sent * 100, 1) if sent else 0.0,
        click_rate_pct=round(clicked / sent * 100, 1) if sent else 0.0,
        credential_rate_pct=round(credential / sent * 100, 1) if sent else 0.0,
        last_campaign_launched_at=last.launched_at.isoformat(),
        last_campaign_llm_generated=last.llm_generated,
        last_campaign_dmarc_context=last.dmarc_context,
    )


async def assemble_command_report(db: AsyncSession, tenant: Tenant, user: User) -> CommandReportDataOut:
    email_report = await get_report_data(db=db, user=user, period_days=30)

    engagements = (await db.execute(
        select(Engagement).where(Engagement.tenant_id == tenant.id)
    )).scalars().all()

    connections = await _connections_summary(db, tenant.id)
    findings_by_tier, total_open, total_critical, top_findings = await _findings_summary(db, tenant.id)
    attack_paths = await _attack_path_summary(db, tenant.id)
    phishing = await _phishing_summary(db, tenant.id)

    return CommandReportDataOut(
        generated_at=email_report.generated_at,
        tenant_name=tenant.name,
        brand_name=tenant.brand_name,
        brand_logo_url=tenant.brand_logo_url,
        plan=tenant.plan,
        email_report=email_report,
        connections=connections,
        engagement_count=len(engagements),
        active_engagement_count=sum(1 for e in engagements if e.status == "active"),
        findings_by_tier=findings_by_tier,
        total_open_findings=total_open,
        total_critical_findings=total_critical,
        top_findings=top_findings,
        attack_paths=attack_paths,
        phishing=phishing,
    )


def _finding_tier_rows_html(rows: list[CommandFindingTierSummaryOut]) -> str:
    if not rows:
        return '<tr><td colspan="6" class="empty">No open findings — fully clean.</td></tr>'
    out = []
    for r in rows:
        out.append(
            f"<tr><td>{r.tier}</td><td>{r.open_count}</td>"
            f'<td style="color:{_SEVERITY_COLOR["critical"]}">{r.critical_count}</td>'
            f'<td style="color:{_SEVERITY_COLOR["high"]}">{r.high_count}</td>'
            f'<td style="color:{_SEVERITY_COLOR["medium"]}">{r.medium_count}</td>'
            f'<td style="color:{_SEVERITY_COLOR["low"]}">{r.low_count}</td></tr>'
        )
    return "".join(out)


def _top_findings_rows_html(rows: list[CommandTopFindingOut]) -> str:
    if not rows:
        return '<tr><td colspan="4" class="empty">No open findings</td></tr>'
    out = []
    for r in rows:
        color = _SEVERITY_COLOR.get(r.severity, "#888")
        occurrence_note = f' <span style="color:#888;font-weight:400;">— {r.occurrence_count} regions</span>' if r.occurrence_count > 1 else ""
        out.append(
            f'<tr><td><span class="grade-pill" style="background:{color}22;color:{color}">{r.severity}</span></td>'
            f"<td>{r.tier}</td><td>{r.title}{occurrence_note}</td><td>{r.resource_uid or '—'}</td></tr>"
        )
    return "".join(out)


def _top_paths_rows_html(rows: list[CommandTopPathOut]) -> str:
    if not rows:
        return '<tr><td colspan="4" class="empty">No open privilege-escalation paths</td></tr>'
    out = []
    for r in rows:
        color = _SEVERITY_COLOR.get(r.severity, "#888")
        verdict_label = {"covered": "Covered", "partial": "Partial", "blind_spot": "Blind spot"}.get(r.detection_verdict, "—")
        out.append(
            f'<tr><td><span class="grade-pill" style="background:{color}22;color:{color}">{r.severity}</span></td>'
            f"<td>{r.source_principal_arn}</td><td>{r.target_principal_arn}</td><td>{verdict_label}</td></tr>"
        )
    return "".join(out)


def _phishing_section_html(p: CommandPhishingSummaryOut | None) -> str:
    if p is None:
        return '<div class="section"><h2>Phishing simulation</h2><div class="empty">No phishing campaigns launched yet.</div></div>'
    llm_note = "AI-generated content, fresh per send" if p.last_campaign_llm_generated else "Static template"
    return f"""<div class="section">
    <h2>Phishing simulation</h2>
    <div class="stat-row">
      <div class="stat"><div class="stat-val">{p.campaign_count}</div><div class="stat-lbl">Campaigns run</div></div>
      <div class="stat"><div class="stat-val">{p.open_rate_pct:.0f}%</div><div class="stat-lbl">Open rate</div></div>
      <div class="stat"><div class="stat-val">{p.click_rate_pct:.0f}%</div><div class="stat-lbl">Click rate</div></div>
      <div class="stat"><div class="stat-val">{p.credential_rate_pct:.0f}%</div><div class="stat-lbl">Credentials entered</div></div>
    </div>
    <p class="narrative">Most recent campaign — {llm_note}{f", generated against a DMARC posture of {p.last_campaign_dmarc_context}" if p.last_campaign_dmarc_context else ""}.</p>
  </div>"""


def build_command_report_html(report: CommandReportDataOut) -> str:
    s = report.email_report.sentinel
    brand = report.brand_name or "Sentinel"

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  @page {{ size: A4; margin: 22mm 16mm; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; color: #1a1a2e; font-size: 11px; }}
  h1, h2, h3 {{ font-family: Georgia, serif; margin: 0; }}
  .header {{ display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 3px solid #5b6ef5; padding-bottom: 12px; margin-bottom: 22px; }}
  .brand {{ font-size: 20px; font-weight: 800; }}
  .meta {{ text-align: right; color: #666; font-size: 10px; }}
  .score-hero {{ display: flex; gap: 24px; align-items: center; background: #0c0e1c; color: #fff; border-radius: 14px; padding: 20px 26px; margin-bottom: 22px; }}
  .score-num {{ font-size: 52px; font-weight: 800; }}
  .score-grade {{ font-size: 24px; font-weight: 800; }}
  .score-label {{ color: #9aa6ff; font-size: 12px; }}
  .pillars {{ display: flex; gap: 18px; margin-left: auto; }}
  .pillar {{ text-align: center; }}
  .pillar-val {{ font-size: 16px; font-weight: 700; }}
  .pillar-lbl {{ font-size: 9px; color: #888; text-transform: uppercase; letter-spacing: .5px; }}
  .section {{ margin-bottom: 20px; break-inside: avoid; }}
  .section h2 {{ font-size: 13px; text-transform: uppercase; letter-spacing: .8px; color: #5b6ef5; margin-bottom: 8px; }}
  .narrative {{ line-height: 1.6; color: #333; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 10px; }}
  th {{ text-align: left; text-transform: uppercase; font-size: 8.5px; letter-spacing: .5px; color: #888; padding: 5px 8px; border-bottom: 1px solid #ddd; }}
  td {{ padding: 6px 8px; border-bottom: 1px solid #eee; word-break: break-all; }}
  .grade-pill {{ padding: 1px 7px; border-radius: 8px; font-weight: 700; font-size: 9px; text-transform: uppercase; }}
  .empty {{ color: #999; text-align: center; padding: 10px; }}
  .stat-row {{ display: flex; gap: 16px; margin-bottom: 14px; break-inside: avoid; }}
  .stat {{ background: #f5f6fb; border-radius: 10px; padding: 10px 14px; flex: 1; }}
  .stat-val {{ font-size: 18px; font-weight: 800; }}
  .stat-lbl {{ font-size: 8.5px; color: #888; text-transform: uppercase; }}
  .footer {{ margin-top: 24px; padding-top: 10px; border-top: 1px solid #ddd; color: #999; font-size: 8.5px; }}
</style></head>
<body>
  <div class="header">
    <div class="brand">{brand}</div>
    <div class="meta">{report.tenant_name}<br>Security Posture Report · Generated {report.generated_at[:10]}</div>
  </div>

  <div class="score-hero">
    <div>
      <div class="score-num">{s.score}<span style="font-size:18px;color:#888">/100</span></div>
    </div>
    <div>
      <div class="score-grade" style="color:{_grade_color(s.grade)}">{s.grade}</div>
      <div class="score-label">{s.grade_label}</div>
    </div>
    <div class="pillars">
      <div class="pillar"><div class="pillar-val">{s.pillar_dmarc:.0f}/60</div><div class="pillar-lbl">Email Auth</div></div>
      <div class="pillar"><div class="pillar-val">{s.pillar_tls:.0f}/25</div><div class="pillar-lbl">MTA-STS</div></div>
      <div class="pillar"><div class="pillar-val">{s.pillar_certs:.0f}/15</div><div class="pillar-lbl">Certs</div></div>
      {f'<div class="pillar"><div class="pillar-val">{s.pillar_cloud_posture:.0f}/100</div><div class="pillar-lbl">Cloud Posture</div></div>' if s.pillar_cloud_posture is not None else ''}
    </div>
  </div>

  <div class="stat-row">
    <div class="stat"><div class="stat-val">{report.connections.cloud_connections_connected}</div><div class="stat-lbl">Cloud accounts connected</div></div>
    <div class="stat"><div class="stat-val">{report.connections.host_connections_connected}</div><div class="stat-lbl">Hosts connected</div></div>
    <div class="stat"><div class="stat-val">{report.active_engagement_count}</div><div class="stat-lbl">Active engagements</div></div>
    <div class="stat"><div class="stat-val">{report.total_critical_findings}</div><div class="stat-lbl">Critical open findings</div></div>
  </div>

  <div class="section">
    <h2>Open findings by module</h2>
    <table>
      <thead><tr><th>Module</th><th>Open</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr></thead>
      <tbody>{_finding_tier_rows_html(report.findings_by_tier)}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>Top findings ({report.total_open_findings} open)</h2>
    <table>
      <thead><tr><th>Severity</th><th>Module</th><th>Finding</th><th>Resource</th></tr></thead>
      <tbody>{_top_findings_rows_html(report.top_findings)}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>Attack path graph — {report.attack_paths.open_count} open privilege-escalation path{'s' if report.attack_paths.open_count != 1 else ''}</h2>
    <div class="stat-row">
      <div class="stat"><div class="stat-val">{report.attack_paths.covered_count}</div><div class="stat-lbl">Detection: Covered</div></div>
      <div class="stat"><div class="stat-val">{report.attack_paths.partial_count}</div><div class="stat-lbl">Detection: Partial</div></div>
      <div class="stat"><div class="stat-val">{report.attack_paths.blind_spot_count}</div><div class="stat-lbl">Detection: Blind spot</div></div>
    </div>
    <table>
      <thead><tr><th>Severity</th><th>Source principal</th><th>Target principal</th><th>Detection coverage</th></tr></thead>
      <tbody>{_top_paths_rows_html(report.attack_paths.top_paths)}</tbody>
    </table>
  </div>

  {_phishing_section_html(report.phishing)}

  <div class="footer">{brand} — Sentinel Command security posture platform. This report reflects live data from connected cloud accounts, hosts, and phishing simulations as of the generation date above.</div>
</body></html>"""


async def render_command_report_pdf(report: CommandReportDataOut) -> bytes:
    html = build_command_report_html(report)
    return await render_html_to_pdf(html)
