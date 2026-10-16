"""
Background job: emails the PDF report to tenants that have opted into
report_schedule (weekly/monthly) and whose plan includes scheduled_reports.

"Due" is computed from last_report_sent_at rather than a fixed day-of-week,
so the schedule self-corrects after downtime (a missed run doesn't mean
waiting until the literal next Monday — it sends as soon as the job runs
again and finds the tenant overdue) and so two tenants who both pick
"weekly" don't all get emailed on the same calendar day, spreading load.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models.user import Tenant, User
from app.routers.overview import get_report_data
from app.services.email_service import Attachment, send_email
from app.services.pdf_report_service import render_phishing_report_pdf, render_report_pdf
from app.services.phishing_service import (
    compute_department_training_completion, compute_tenant_human_risk_score, compute_tenant_phishing_summary,
)
from app.services.plan_limits import check_feature

log = logging.getLogger(__name__)

_INTERVAL_DAYS = {"weekly": 7, "monthly": 30}


def _schedule_is_due(schedule: str, last_sent) -> bool:
    interval = _INTERVAL_DAYS.get(schedule)
    if interval is None:
        return False
    if last_sent is None:
        return True
    if last_sent.tzinfo is None:
        last_sent = last_sent.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - last_sent >= timedelta(days=interval)


def _is_due(tenant: Tenant) -> bool:
    return _schedule_is_due(tenant.report_schedule, tenant.last_report_sent_at)


async def send_scheduled_reports() -> None:
    async with AsyncSessionLocal() as db:
        tenants = (
            await db.execute(select(Tenant).where(Tenant.report_schedule != "off"))
        ).scalars().all()

        for tenant in tenants:
            if not check_feature(tenant, "scheduled_reports"):
                continue  # downgraded since opting in — silently skip, don't email
            if not _is_due(tenant):
                continue

            try:
                await _send_one(db, tenant)
            except Exception:
                log.exception("Scheduled report failed for tenant %s", tenant.id)


async def _send_one(db, tenant: Tenant) -> None:
    recipient = tenant.billing_email
    actor = (await db.execute(select(User).where(User.tenant_id == tenant.id, User.role == "admin"))).scalars().first()
    if not recipient:
        recipient = actor.email if actor else None
    if not recipient or not actor:
        log.warning("Scheduled report skipped for tenant %s — no recipient/admin user", tenant.id)
        return

    report = await get_report_data(db=db, user=actor, period_days=30)
    pdf_bytes = await render_report_pdf(report, brand_name=tenant.brand_name)

    sent = await send_email(
        db,
        to=recipient,
        subject=f"Your {tenant.report_schedule} ZoneProof security report — {report.sentinel.grade} ({report.sentinel.score}/100)",
        title="Your scheduled security report is ready",
        body_html=(
            f"<p>Attached is your {tenant.report_schedule} email security posture report for "
            f"<strong>{tenant.name}</strong>.</p>"
            f"<p>Current grade: <strong>{report.sentinel.grade}</strong> ({report.sentinel.score}/100)</p>"
            f"<p style=\"color:#888;font-size:12px;\">Manage your report schedule from Billing settings in the app.</p>"
        ),
        text_body=f"Your {tenant.report_schedule} ZoneProof report is attached. Current grade: {report.sentinel.grade} ({report.sentinel.score}/100).",
        attachments=[Attachment(
            filename=f"zoneproof-report-{report.generated_at[:10]}.pdf",
            content=pdf_bytes,
            mime_type="application/pdf",
        )],
    )
    if sent:
        tenant.last_report_sent_at = datetime.now(timezone.utc)
        await db.commit()


# ── Phishing / Human Risk report (Phishing Simulation roadmap Phase 22) ─────
# Deliberately a near-duplicate of send_scheduled_reports/_send_one above
# rather than a generalized "report type" abstraction — matches how
# phishing_paused was added as its own Tenant column instead of
# generalizing report_schedule itself (see the model's own comment).

async def send_scheduled_phishing_reports() -> None:
    """Real entrypoint used by the background job — opens its own session.
    Split from _send_scheduled_phishing_reports below (which takes an
    injected session) so tests can exercise the real logic against the
    test DB's isolated transaction, matching cloud_scan_service.
    rescan_all_due_connections' testable shape rather than the original
    send_scheduled_reports above, which predates this pattern and has no
    test coverage of its own."""
    async with AsyncSessionLocal() as db:
        await _send_scheduled_phishing_reports(db)


async def _send_scheduled_phishing_reports(db) -> None:
    tenants = (
        await db.execute(select(Tenant).where(Tenant.phishing_report_schedule != "off"))
    ).scalars().all()

    for tenant in tenants:
        if not check_feature(tenant, "scheduled_reports"):
            continue  # downgraded since opting in — silently skip, don't email
        if not _schedule_is_due(tenant.phishing_report_schedule, tenant.last_phishing_report_sent_at):
            continue

        try:
            await _send_one_phishing(db, tenant)
        except Exception:
            log.exception("Scheduled phishing report failed for tenant %s", tenant.id)


async def _send_one_phishing(db, tenant: Tenant) -> None:
    # Local import — avoids pulling in the whole phishing router (and its
    # own broad import surface) at this service module's import time, when
    # all that's actually needed is one small grade-threshold helper.
    from app.routers.phishing import _score_to_grade

    recipient = tenant.billing_email
    actor = (await db.execute(select(User).where(User.tenant_id == tenant.id, User.role == "admin"))).scalars().first()
    if not recipient:
        recipient = actor.email if actor else None
    if not recipient or not actor:
        log.warning("Scheduled phishing report skipped for tenant %s — no recipient/admin user", tenant.id)
        return

    summary = await compute_tenant_phishing_summary(db, tenant.id)
    if summary is None:
        log.info("Scheduled phishing report skipped for tenant %s — no campaign history yet", tenant.id)
        # Still counts as "sent" for due-date purposes — otherwise a tenant
        # that opts in before ever launching a campaign gets polled every
        # job cycle forever instead of just on its next real interval.
        tenant.last_phishing_report_sent_at = datetime.now(timezone.utc)
        await db.commit()
        return

    score = await compute_tenant_human_risk_score(db, tenant.id)
    grade = _score_to_grade(score) if score is not None else None
    department_training = await compute_department_training_completion(db, tenant.id)
    generated_at = datetime.now(timezone.utc).isoformat()

    pdf_bytes = await render_phishing_report_pdf(
        workspace_name=tenant.name, generated_at=generated_at,
        human_risk_score=score, human_risk_grade=grade,
        sent=summary["sent"], click_rate=summary["click_rate"], credential_rate=summary["credential_rate"],
        report_rate=summary["report_rate"], training_completion_rate=summary["training_completion_rate"],
        department_training=department_training, brand_name=tenant.brand_name,
    )

    grade_label = grade or "—"
    sent_ok = await send_email(
        db,
        to=recipient,
        subject=f"Your {tenant.phishing_report_schedule} phishing simulation report — {grade_label} human risk score",
        title="Your scheduled phishing report is ready",
        body_html=(
            f"<p>Attached is your {tenant.phishing_report_schedule} phishing simulation &amp; human risk report for "
            f"<strong>{tenant.name}</strong>.</p>"
            f"<p>Current human risk grade: <strong>{grade_label}</strong></p>"
            f"<p style=\"color:#888;font-size:12px;\">Manage this schedule from Phishing Settings in the app.</p>"
        ),
        text_body=f"Your {tenant.phishing_report_schedule} phishing report is attached. Current human risk grade: {grade_label}.",
        attachments=[Attachment(
            filename=f"zoneproof-phishing-report-{generated_at[:10]}.pdf",
            content=pdf_bytes,
            mime_type="application/pdf",
        )],
    )
    if sent_ok:
        tenant.last_phishing_report_sent_at = datetime.now(timezone.utc)
        await db.commit()
