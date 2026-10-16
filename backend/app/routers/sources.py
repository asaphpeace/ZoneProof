"""
Data sources and health: where the information on every other page comes from,
and whether it is flowing.

Three parts, each answering a different question:
  data          -- for the signed-in workspace's domains, when did each kind of
                   data last arrive (DMARC and TLS reports, certificate probes,
                   DNS checks)? Durable, read from the database.
  integrations  -- is each outside service configured at all? Booleans only;
                   nothing about hosts or keys.
  jobs          -- the background jobs that keep that data fresh, from the
                   in-memory registry, with the stored history (job_runs) applied.

Admin only. Failures are reduced to a fixed kind (see job_registry), never raw
exception text.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models import DmarcReport, Domain, JobRun, SslCert, TlsReport
from app.models.user import User
from app.routers.auth import _require_admin, get_current_user
from app.services import job_registry

router = APIRouter(prefix="/sources", tags=["sources"])

# Plain-language effect of each failure kind. Nothing here comes from an exception.
KIND_TEXT = {
    "timed_out": "The last run timed out.",
    "connection_failed": "The last run could not connect to a service it needs.",
    "login_rejected": "The last run was refused, which usually means a credential is wrong or expired.",
    "unexpected": "The last run failed unexpectedly. The server log has the detail.",
}


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _age_status(last: datetime | None, stale_after: timedelta, now: datetime) -> str:
    if last is None:
        return "none"
    return "stale" if now - last > stale_after else "ok"


def _job_status(j: job_registry.JobState, interval: int, configured: bool, now: datetime) -> tuple[str, str | None]:
    if not configured:
        return "not_configured", None
    if j.running and j.last_finished is None:
        return "running", None
    if j.last_finished is None:
        return "waiting", None
    if j.last_ok is False:
        return "failing", KIND_TEXT.get(j.last_failure_kind or "unexpected")
    if now - j.last_finished > timedelta(seconds=interval * 2 + 60):
        return "stale", "It has not run when it should have."
    return "ok", None


@router.get("/health")
async def sources_health(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_admin(user)
    now = datetime.now(timezone.utc)

    # ── the workspace's own data, per domain ─────────────────────────────────
    domains = (await db.execute(
        select(Domain).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True).order_by(Domain.name)
    )).scalars().all()
    ids = [d.id for d in domains]

    async def latest(model, column):
        if not ids:
            return {}
        rows = (await db.execute(
            select(model.domain_id, func.max(column), func.count()).where(model.domain_id.in_(ids)).group_by(model.domain_id)
        )).all()
        return {r[0]: (r[1], r[2]) for r in rows}

    dmarc = await latest(DmarcReport, DmarcReport.received_at)
    tls = await latest(TlsReport, TlsReport.received_at)
    certs = await latest(SslCert, SslCert.probed_at)

    def block(key, label, provides, per_domain: dict, stale_after: timedelta, none_text: str, stale_text: str):
        items = []
        for d in domains:
            last = per_domain.get(d.id, (None, 0))[0]
            status = _age_status(last, stale_after, now)
            items.append({
                "domain": d.name, "domain_id": str(d.id), "last_at": _iso(last), "status": status,
                "count": per_domain.get(d.id, (None, 0))[1],
            })
        worst = "none" if all(i["status"] == "none" for i in items) else (
            "stale" if any(i["status"] == "stale" for i in items) else "ok")
        if not items:
            worst = "none"
        return {
            "key": key, "label": label, "provides": provides, "status": worst,
            "note": none_text if worst == "none" else (stale_text if worst == "stale" else None),
            "domains": items,
        }

    dns_last = {d.id: (d.last_checked_at, 0) for d in domains}
    data = [
        block("dmarc_reports", "DMARC reports", "Who is sending as your domains",
              dmarc, timedelta(days=3),
              "No DMARC reports have arrived yet. First reports usually take one to two days after the record is published.",
              "Some domains have had no new DMARC report for over three days. Small domains are quieter; check the record still points at your reporting address."),
        block("tls_reports", "TLS reports", "Whether mail to you arrives encrypted",
              tls, timedelta(days=7),
              "No TLS reports have arrived yet. They come from senders that support TLS-RPT, and only after the TLS-RPT record is published.",
              "Some domains have had no TLS report for over a week."),
        block("certificates", "Certificate probes", "Expiry and health of mail and web certificates",
              certs, timedelta(days=2),
              "Certificates have not been probed yet. Use Probe all on the Certificates page.",
              "Some certificates were last probed more than two days ago."),
        block("dns_checks", "DNS checks", "Record changes on the DNS timeline",
              dns_last, timedelta(seconds=settings.dns_poll_interval * 3),
              "DNS has not been checked yet.",
              "Some domains have not had a DNS check recently."),
    ]

    # ── outside services: configured or not, nothing more ────────────────────
    imap_configured = bool(settings.imap_password)
    integrations = [
        {"key": "report_inbox", "label": "Report inbox (IMAP)", "provides": "Receives DMARC and TLS-RPT reports",
         "configured": imap_configured,
         "note": None if imap_configured else "No inbox password is set, so reports sent by email are not being collected."},
        {"key": "email", "label": "Outgoing email (SendGrid)", "provides": "Verification, alerts and scheduled reports",
         "configured": bool(settings.sendgrid_api_key),
         "note": f"Sending as {settings.email_from_address}." if settings.sendgrid_api_key
         else "No SendGrid key is set, so emails are written to the server log instead of being sent."},
        {"key": "advisor", "label": "AI advisor", "provides": "Plain-language guidance on each page",
         "configured": bool(settings.advisor_enabled) and (settings.advisor_provider != "claude" or bool(settings.anthropic_api_key)),
         "note": None if settings.advisor_enabled else "The advisor is switched off."},
        {"key": "billing", "label": "Billing (Stripe)", "provides": "Plan changes and invoices",
         "configured": bool(settings.stripe_secret_key), "note": None if settings.stripe_secret_key else "Stripe is not configured."},
        {"key": "brand_guard", "label": "Brand Guard", "provides": "Look-alike domain monitoring",
         "configured": bool(settings.brand_guard_enabled),
         "note": None if settings.brand_guard_enabled else "Brand Guard is switched off on this server."},
    ]

    # ── background jobs ───────────────────────────────────────────────────────
    needs = {"imap_poll": imap_configured, "brand_guard": bool(settings.brand_guard_enabled)}
    role, role_since = job_registry.role()
    stored = {r.job_key: r for r in (await db.execute(select(JobRun))).scalars().all()}
    jobs = []
    for j in job_registry.snapshot():
        j = job_registry.overlay(j, stored.get(j.key))
        interval = j.interval()
        configured = needs.get(j.key, True)
        status, note = _job_status(j, interval, configured, now)
        if role in ("standby", "disabled") and status in ("waiting", "ok", "stale", "running"):
            status = "standby" if role == "standby" else "not_here"
            note = ("Another server is running this job." if role == "standby"
                    else "The scheduler is switched off on this server.")
        if j.last_finished:
            next_run = j.last_finished + timedelta(seconds=interval) if configured else None
        elif j.first_run_at:
            next_run = j.first_run_at if configured else None
        else:
            next_run = job_registry.PROCESS_STARTED_AT + timedelta(seconds=interval) if configured else None
        jobs.append({
            "key": j.key, "label": j.label, "provides": j.provides, "status": status, "note": note,
            "interval_seconds": interval, "runs": j.runs, "failures": j.failures,
            "last_started": _iso(j.last_started), "last_finished": _iso(j.last_finished),
            "last_duration_s": j.last_duration_s, "next_run": _iso(next_run),
        })

    return {
        "generated_at": now.isoformat(),
        "server_started_at": job_registry.PROCESS_STARTED_AT.isoformat(),
        "data": data,
        "integrations": integrations,
        "scheduler": {"role": role, "since": _iso(role_since)},
        "jobs": jobs,
    }
