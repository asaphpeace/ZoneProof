"""
Renders ReportDataOut into a branded PDF via a headless Chromium instance
(Playwright). The HTML built here is self-contained — its own inline CSS, no
dependency on the live frontend being reachable — so PDF generation works
identically whether it's triggered by a user clicking "download" or by the
scheduled-report background job emailing it to someone who never opens the app.

WeasyPrint was tried first (pure Python, no browser) but requires native
GTK/Pango libraries that aren't installed on Windows and need a separate
manual runtime setup — Playwright ships its own browser binary via
`playwright install chromium` and has no such dependency.
"""
from __future__ import annotations

import asyncio
import sys
from concurrent.futures import ThreadPoolExecutor

from playwright.async_api import async_playwright

from app.schemas.overview import ReportDataOut


def _grade_color(grade: str) -> str:
    return {"A": "#34e0a1", "B": "#5b5cf0", "C": "#f5c542", "D": "#ff8c42", "F": "#ff4d6d"}.get(grade, "#888")


def _sparkline_svg(points: list[int], width: int = 280, height: int = 50) -> str:
    if len(points) < 2:
        return ""
    lo, hi = min(points), max(points)
    span = (hi - lo) or 1
    step = width / (len(points) - 1)
    coords = " ".join(
        f"{i * step:.1f},{height - ((p - lo) / span) * (height - 8) - 4:.1f}"
        for i, p in enumerate(points)
    )
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
        f'<polyline points="{coords}" fill="none" stroke="#5b5cf0" stroke-width="2.5"/>'
        f"</svg>"
    )


def _sender_rows_html(rows: list, empty_label: str) -> str:
    if not rows:
        return f'<tr><td colspan="4" class="empty">{empty_label}</td></tr>'
    out = []
    for r in rows[:8]:
        out.append(
            f"<tr><td>{r.org}</td><td>{r.volume:,}</td>"
            f"<td>{r.pass_pct:.0f}%</td><td>{r.dkim_aligned_pct:.0f}% / {r.spf_aligned_pct:.0f}%</td></tr>"
        )
    return "".join(out)


def _domain_rows_html(rows: list) -> str:
    out = []
    for d in rows:
        comp = f"{d.dmarc_comp:.0f}%" if d.dmarc_comp is not None else "—"
        out.append(
            f'<tr><td>{d.domain}</td>'
            f'<td><span class="grade-pill" style="background:{d.grade_color}22;color:{d.grade_color}">{d.grade}</span></td>'
            f'<td>{d.dmarc_stage}</td><td>{d.mta_sts_stage}</td><td>{comp}</td>'
            f'<td class="issue">{d.primary_issue or "—"}</td></tr>'
        )
    return "".join(out)


def _recommendation_rows_html(items: list) -> str:
    if not items:
        return '<div class="empty">No outstanding recommendations — fully hardened.</div>'
    out = []
    for r in items[:10]:
        out.append(
            f'<div class="rec-row"><span class="rec-pri">{r.priority}</span>'
            f'<div><div class="rec-action">{r.action} <span class="rec-domain">— {r.domain}</span></div>'
            f'<div class="rec-detail">{r.detail}</div></div>'
            f'<span class="rec-tag">{r.effort} effort / {r.impact} impact</span></div>'
        )
    return "".join(out)


def _brand_guard_section_html(bg: dict | None) -> str:
    """The look-alike exposure section: only for a tenant that uses Brand Guard, and says what moved the number."""
    if not bg:
        return ""
    import html as h
    parts = "".join(f"<li>{h.escape(c['label'])}: {c['count']} ({c['points']} points)</li>" for c in bg.get("components", [])) or "<li>No live look-alikes, no overdue cases.</li>"
    return (
        '<div class="section"><h2>Brand impersonation exposure</h2>'
        f"<p>Exposure score <b>{bg['score']}/100</b> across {bg['brands']} protected brand(s). {bg['open_cases']} open case(s), {bg['need_decision']} look-alike(s) awaiting a decision.</p>"
        f"<ul>{parts}</ul>"
        '<p style="color:#666;font-size:10px">The score starts at 100 and loses points for live confirmed look-alikes, overdue cases and live look-alikes still waiting for a decision. '
        "The point values are judgement calls, not measurements.</p></div>"
    )


def build_report_html(report: ReportDataOut, brand_name: str | None = None) -> str:
    s = report.sentinel
    brand = brand_name or "ZoneProof"
    brand_html = brand if brand_name else "Zone<b>Proof</b>"
    spark = _sparkline_svg([p.score for p in report.score_trend])

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  @page {{ size: A4; margin: 22mm 16mm; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; color: #1a1a2e; font-size: 11px; }}
  h1, h2, h3 {{ font-family: Georgia, serif; margin: 0; }}
  .header {{ display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 3px solid #5b5cf0; padding-bottom: 12px; margin-bottom: 22px; }}
  .brand {{ font-size: 20px; font-weight: 800; }}
  .brand b {{ color: #5b5cf0; }}
  .meta {{ text-align: right; color: #666; font-size: 10px; }}
  .score-hero {{ display: flex; gap: 24px; align-items: center; background: #0c0e1c; color: #fff; border-radius: 14px; padding: 20px 26px; margin-bottom: 22px; }}
  .score-num {{ font-size: 52px; font-weight: 800; }}
  .score-grade {{ font-size: 24px; font-weight: 800; }}
  .score-label {{ color: #a5a6ff; font-size: 12px; }}
  .pillars {{ display: flex; gap: 18px; margin-left: auto; }}
  .pillar {{ text-align: center; }}
  .pillar-val {{ font-size: 16px; font-weight: 700; }}
  .pillar-lbl {{ font-size: 9px; color: #888; text-transform: uppercase; letter-spacing: .5px; }}
  .section {{ margin-bottom: 20px; }}
  .section h2 {{ font-size: 13px; text-transform: uppercase; letter-spacing: .8px; color: #5b5cf0; margin-bottom: 8px; }}
  .narrative {{ line-height: 1.6; color: #333; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 10px; }}
  th {{ text-align: left; text-transform: uppercase; font-size: 8.5px; letter-spacing: .5px; color: #888; padding: 5px 8px; border-bottom: 1px solid #ddd; }}
  td {{ padding: 6px 8px; border-bottom: 1px solid #eee; }}
  .grade-pill {{ padding: 1px 7px; border-radius: 8px; font-weight: 700; font-size: 9px; }}
  .issue {{ color: #b9460c; font-size: 9.5px; }}
  .empty {{ color: #999; text-align: center; padding: 10px; }}
  .stat-row {{ display: flex; gap: 16px; margin-bottom: 14px; }}
  .stat {{ background: #f5f6fb; border-radius: 10px; padding: 10px 14px; flex: 1; }}
  .stat-val {{ font-size: 18px; font-weight: 800; }}
  .stat-lbl {{ font-size: 8.5px; color: #888; text-transform: uppercase; }}
  .rec-row {{ display: flex; gap: 10px; align-items: flex-start; padding: 8px 0; border-bottom: 1px solid #eee; }}
  .rec-pri {{ background: #5b5cf022; color: #5b5cf0; border-radius: 50%; width: 18px; height: 18px; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 9px; flex: none; }}
  .rec-action {{ font-weight: 700; font-size: 10.5px; }}
  .rec-domain {{ color: #888; font-weight: 400; }}
  .rec-detail {{ color: #555; font-size: 9.5px; margin-top: 2px; }}
  .rec-tag {{ margin-left: auto; font-size: 8.5px; color: #888; white-space: nowrap; }}
  .footer {{ margin-top: 24px; padding-top: 10px; border-top: 1px solid #ddd; color: #999; font-size: 8.5px; }}
</style></head>
<body>
  <div class="header">
    <div class="brand">{brand_html}</div>
    <div class="meta">{report.workspace_name}<br>Generated {report.generated_at[:10]} · last {report.period_days} days</div>
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
      <div class="pillar"><div class="pillar-val">{s.pillar_dmarc:.0f}/60</div><div class="pillar-lbl">DMARC</div></div>
      <div class="pillar"><div class="pillar-val">{s.pillar_tls:.0f}/25</div><div class="pillar-lbl">MTA-STS</div></div>
      <div class="pillar"><div class="pillar-val">{s.pillar_certs:.0f}/15</div><div class="pillar-lbl">Certs</div></div>
    </div>
    {f'<div>{spark}</div>' if spark else ''}
  </div>

  <div class="section">
    <h2>Executive summary</h2>
    <p class="narrative">{report.executive_narrative}</p>
  </div>

  <div class="stat-row">
    <div class="stat"><div class="stat-val">{report.total_domains}</div><div class="stat-lbl">Domains monitored</div></div>
    <div class="stat"><div class="stat-val">{report.dmarc_reject_count}</div><div class="stat-lbl">Fully enforced</div></div>
    <div class="stat"><div class="stat-val">{report.threat.blocked_pct:.0f}%</div><div class="stat-lbl">Impersonation blocked</div></div>
    <div class="stat"><div class="stat-val">{report.cert_alerts}</div><div class="stat-lbl">Cert alerts</div></div>
  </div>

  <div class="section">
    <h2>Domain posture</h2>
    <table>
      <thead><tr><th>Domain</th><th>Grade</th><th>DMARC</th><th>MTA-STS</th><th>Compliance</th><th>Primary issue</th></tr></thead>
      <tbody>{_domain_rows_html(report.domains)}</tbody>
    </table>
  </div>

  {_brand_guard_section_html(report.brand_guard)}

  <div class="section">
    <h2>Prioritised recommendations</h2>
    {_recommendation_rows_html(report.recommendations)}
  </div>

  <div class="section">
    <h2>Sender inventory — authorized &amp; compliant</h2>
    <table>
      <thead><tr><th>Source</th><th>Volume</th><th>Pass rate</th><th>DKIM / SPF aligned</th></tr></thead>
      <tbody>{_sender_rows_html(report.sender_inventory.authorized_compliant, "No data yet")}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>Sender inventory — unauthorized / suspicious</h2>
    <table>
      <thead><tr><th>Source</th><th>Volume</th><th>Pass rate</th><th>DKIM / SPF aligned</th></tr></thead>
      <tbody>{_sender_rows_html(report.sender_inventory.unauthorized, "None detected")}</tbody>
    </table>
  </div>

  <div class="footer">{brand} — DMARC &amp; MTA-STS email security monitoring. This report reflects data collected over the last {report.period_days} days.</div>
</body></html>"""


async def _render_html_to_pdf_impl(html: str) -> bytes:
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        try:
            page = await browser.new_page()
            await page.set_content(html, wait_until="load")
            pdf_bytes = await page.pdf(format="A4", print_background=True)
        finally:
            await browser.close()
    return pdf_bytes


def _render_html_to_pdf_in_new_proactor_loop(html: str) -> bytes:
    # Playwright launches Chromium as a subprocess, which asyncio can only
    # do on Windows via ProactorEventLoop — uvicorn's own loop here is the
    # Selector one (needed for its --reload file watcher), so this can't
    # just run on the request's existing loop. Runs on a throwaway thread
    # with its own Proactor loop instead of changing uvicorn's global
    # policy, so the rest of the app's async DB/HTTP work is unaffected.
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    return asyncio.run(_render_html_to_pdf_impl(html))


async def render_html_to_pdf(html: str) -> bytes:
    """Shared headless-Chromium rendering step — pulled out of
    render_report_pdf() below so command_report_service.py's Command report
    (Coverage Map plan Phase 10) reuses the exact same rendering pipeline
    instead of standing up a second Playwright integration."""
    if sys.platform == "win32":
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=1) as pool:
            return await loop.run_in_executor(pool, _render_html_to_pdf_in_new_proactor_loop, html)
    return await _render_html_to_pdf_impl(html)


async def render_report_pdf(report: ReportDataOut, brand_name: str | None = None) -> bytes:
    html = build_report_html(report, brand_name)
    return await render_html_to_pdf(html)


# ── Phishing / Human Risk report (Phishing Simulation roadmap Phase 22) ─────
# A second, independent report type sharing only the rendering pipeline
# above (render_html_to_pdf) — its own HTML builder rather than trying to
# force phishing's shape into ReportDataOut, which is DMARC/posture-
# specific end to end.

def _pct(rate: float | None) -> str:
    return f"{rate * 100:.0f}%" if rate is not None else "—"


def _department_training_rows_html(rows: list[dict]) -> str:
    if not rows:
        return '<tr><td colspan="3" class="empty">No department data recorded yet</td></tr>'
    out = []
    for d in rows:
        pct = f"{(d['completed'] / d['assigned'] * 100):.0f}%" if d.get("assigned") else "—"
        out.append(f"<tr><td>{d['department']}</td><td>{d['completed']} / {d['assigned']}</td><td>{pct}</td></tr>")
    return "".join(out)


def build_phishing_report_html(
    *,
    workspace_name: str,
    generated_at: str,
    human_risk_score: float | None,
    human_risk_grade: str | None,
    sent: int,
    click_rate: float | None,
    credential_rate: float | None,
    report_rate: float | None,
    training_completion_rate: float | None,
    department_training: list[dict],
    brand_name: str | None = None,
) -> str:
    brand = brand_name or "ZoneProof"
    brand_html = brand if brand_name else "Zone<b>Proof</b>"
    grade = human_risk_grade or "—"
    score_display = f"{human_risk_score:.0f}" if human_risk_score is not None else "—"

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  @page {{ size: A4; margin: 22mm 16mm; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; color: #1a1a2e; font-size: 11px; }}
  h1, h2, h3 {{ font-family: Georgia, serif; margin: 0; }}
  .header {{ display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 3px solid #5b5cf0; padding-bottom: 12px; margin-bottom: 22px; }}
  .brand {{ font-size: 20px; font-weight: 800; }}
  .brand b {{ color: #5b5cf0; }}
  .meta {{ text-align: right; color: #666; font-size: 10px; }}
  .score-hero {{ display: flex; gap: 24px; align-items: center; background: #0c0e1c; color: #fff; border-radius: 14px; padding: 20px 26px; margin-bottom: 22px; }}
  .score-num {{ font-size: 52px; font-weight: 800; }}
  .score-grade {{ font-size: 24px; font-weight: 800; }}
  .score-label {{ color: #a5a6ff; font-size: 12px; }}
  .section {{ margin-bottom: 20px; }}
  .section h2 {{ font-size: 13px; text-transform: uppercase; letter-spacing: .8px; color: #5b5cf0; margin-bottom: 8px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 10px; }}
  th {{ text-align: left; text-transform: uppercase; font-size: 8.5px; letter-spacing: .5px; color: #888; padding: 5px 8px; border-bottom: 1px solid #ddd; }}
  td {{ padding: 6px 8px; border-bottom: 1px solid #eee; }}
  .empty {{ color: #999; text-align: center; padding: 10px; }}
  .stat-row {{ display: flex; gap: 16px; margin-bottom: 14px; }}
  .stat {{ background: #f5f6fb; border-radius: 10px; padding: 10px 14px; flex: 1; }}
  .stat-val {{ font-size: 18px; font-weight: 800; }}
  .stat-lbl {{ font-size: 8.5px; color: #888; text-transform: uppercase; }}
  .footer {{ margin-top: 24px; padding-top: 10px; border-top: 1px solid #ddd; color: #999; font-size: 8.5px; }}
</style></head>
<body>
  <div class="header">
    <div class="brand">{brand_html}</div>
    <div class="meta">{workspace_name}<br>Generated {generated_at[:10]}</div>
  </div>

  <div class="score-hero">
    <div>
      <div class="score-num">{score_display}<span style="font-size:18px;color:#aaa">/100</span></div>
    </div>
    <div>
      <div class="score-grade" style="color:#a5a6ff">{grade}</div>
      <div class="score-label">Human Risk Score</div>
    </div>
  </div>

  <div class="stat-row">
    <div class="stat"><div class="stat-val">{sent}</div><div class="stat-lbl">Simulated sends</div></div>
    <div class="stat"><div class="stat-val">{_pct(click_rate)}</div><div class="stat-lbl">Clicked the lure</div></div>
    <div class="stat"><div class="stat-val">{_pct(credential_rate)}</div><div class="stat-lbl">Entered credentials</div></div>
    <div class="stat"><div class="stat-val">{_pct(report_rate)}</div><div class="stat-lbl">Reported it</div></div>
  </div>

  <div class="section">
    <h2>Training completion</h2>
    <p>{_pct(training_completion_rate)} of assigned post-click training has been completed{"" if training_completion_rate is not None else " — nothing assigned yet"}.</p>
  </div>

  <div class="section">
    <h2>Department training completion</h2>
    <table>
      <thead><tr><th>Department</th><th>Completed / assigned</th><th>Rate</th></tr></thead>
      <tbody>{_department_training_rows_html(department_training)}</tbody>
    </table>
  </div>

  <div class="footer">{brand} — phishing simulation &amp; human risk posture. Portfolio-wide across every campaign this tenant has run, not scoped to one cycle.</div>
</body></html>"""


async def render_phishing_report_pdf(
    *,
    workspace_name: str,
    generated_at: str,
    human_risk_score: float | None,
    human_risk_grade: str | None,
    sent: int,
    click_rate: float | None,
    credential_rate: float | None,
    report_rate: float | None,
    training_completion_rate: float | None,
    department_training: list[dict],
    brand_name: str | None = None,
) -> bytes:
    html = build_phishing_report_html(
        workspace_name=workspace_name, generated_at=generated_at,
        human_risk_score=human_risk_score, human_risk_grade=human_risk_grade,
        sent=sent, click_rate=click_rate, credential_rate=credential_rate, report_rate=report_rate,
        training_completion_rate=training_completion_rate, department_training=department_training,
        brand_name=brand_name,
    )
    return await render_html_to_pdf(html)
