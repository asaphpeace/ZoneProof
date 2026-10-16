import logging
import uuid
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager

import asyncio

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.services import job_registry, job_startup
from app.logging_config import configure_logging, request_id_var
from app.rate_limit import limiter
from app.routers import auth, domains, dmarc, tls, overview, certs, dns, alerts, advisor, scan, billing, msp, audit, platforms, mta_sts_hosting, concepts, service, cloud, engagement, host, exposure, graph, investigations, impersonation, phishing, phishing_track, oauth_app_risk, prospect, detection_coverage, command_report, webhooks, training_course, training_track, phishing_reports, findings, brand_guard, brand_probe_worker

# Applied selectively (see auth.py's login/forgot-password, scan.py's
# scan_domain) — the abuse surface here is brute-forcing /auth/token,
# enumerating accounts via /auth/forgot-password, and scraping/DDoS-ing the
# public no-auth /scan endpoint. Everything else sits behind a JWT, so a
# blanket rate limit on every route would add cost without addressing the
# actual risk.

from app.routers import sources as sources_router

configure_logging()
log = logging.getLogger(__name__)

def _make_interval_task(fn, seconds: int, *, policy: str = job_startup.INTERVAL_ONLY, last_run=None, slot: int = 0):
    """
    Runs `fn` every `seconds`. The first run is decided by job_startup: shortly
    after start for jobs that are overdue or only act on due work, otherwise
    after the usual interval.
    """
    async def _loop():
        delay = float(seconds)
        try:
            last = await last_run() if last_run else None
            delay = job_startup.initial_delay(
                seconds, last, datetime.now(timezone.utc), slot, policy,
                catch_up=settings.jobs_run_overdue_at_start,
            )
        except Exception:
            log.exception("Could not work out when %s is due; waiting one interval", getattr(fn, "__name__", "job"))
        key = getattr(fn, "_job_key", None)
        if key:
            job_registry.set_first_run(key, datetime.now(timezone.utc) + timedelta(seconds=delay), policy)
        await asyncio.sleep(delay)
        while True:
            try:
                await fn()
            except asyncio.CancelledError:
                raise
            except Exception:
                # Jobs catch their own errors; this only guards the loop itself.
                log.exception("Background job %s raised past its own handler", getattr(fn, "__name__", "job"))
            await asyncio.sleep(seconds)
    return _loop


async def _start_jobs() -> list[asyncio.Task]:
    """Start every background job. Called only by the instance that holds the scheduler lock."""
    # Marks scan runs a previous process left half-done as failed. Safe only on the leader:
    # on another instance it would fail runs the leader is in the middle of.
    await _brand_guard_recover_runs()
    D, H, I = job_startup.DUE_AWARE, job_startup.HINT, job_startup.INTERVAL_ONLY
    # (job, interval setting, startup policy, "when did it last produce something" for hint jobs)
    plan = [
        (_imap_poll_job, settings.imap_poll_interval, D, None),
        (_cert_probe_job, settings.cert_probe_interval, H, job_startup.last_cert_probe),
        (_dns_poll_job, settings.dns_poll_interval, H, job_startup.last_dns_check),
        (_recommendation_job, settings.recommendation_interval, D, None),
        (_scheduled_report_job, settings.scheduled_report_check_interval, D, None),
        (_scheduled_phishing_report_job, settings.scheduled_report_check_interval, D, None),
        (_training_reminder_job, settings.scheduled_report_check_interval, D, None),
        (_command_rescan_job, settings.command_rescan_interval, H, job_startup.last_cloud_scan),
        (_command_host_rescan_job, settings.command_rescan_interval, H, job_startup.last_host_scan),
        (_command_threat_detection_job, settings.command_threat_detection_interval, I, None),
        (_command_impersonation_scan_job, settings.command_rescan_interval, D, None),
        (_command_phishing_campaign_job, settings.command_rescan_interval, D, None),
        (_command_oauth_risk_job, settings.command_rescan_interval, H, job_startup.last_oauth_scan),
        (_brand_guard_job, settings.brand_guard_check_interval, D, None),
    ]
    tasks = [
        asyncio.create_task(_make_interval_task(fn, seconds, policy=policy, last_run=hint, slot=i)())
        for i, (fn, seconds, policy, hint) in enumerate(plan)
    ]
    log.info("ZoneProof background scheduler started")
    return tasks


@asynccontextmanager
async def lifespan(app: FastAPI):
    runner: asyncio.Task | None = None
    if not settings.scheduler_enabled:
        job_registry.set_role("disabled")
        log.info("Background scheduler is switched off on this instance (SCHEDULER_ENABLED=false)")
    else:
        from app.services.scheduler_lock import LeaderLock, asyncpg_dsn, lock_key, run_scheduler
        lock = LeaderLock(
            asyncpg_dsn(settings.scheduler_lock_database_url or settings.database_url),
            lock_key(settings.database_schema),
        )
        runner = asyncio.create_task(run_scheduler(
            lock, _start_jobs, job_registry.set_role,
            retry_seconds=settings.scheduler_lock_retry_seconds,
            beat_seconds=settings.scheduler_lock_heartbeat_seconds,
        ))
    yield
    if runner is not None:
        runner.cancel()
        await asyncio.gather(runner, return_exceptions=True)





def _tracked(key: str, label: str, provides: str, interval_attr: str):
    """Records each run of a background job so the Data sources page can show it."""
    import functools

    def deco(fn):
        job_registry.register(key, label, provides, lambda: int(getattr(settings, interval_attr)))

        @functools.wraps(fn)
        async def run():
            job_registry.start(key)
            try:
                await fn()
            finally:
                job_registry.finish(key)
        run._job_key = key
        return run
    return deco


def _job_failed(key: str, message: str) -> None:
    """Log the failure with its traceback and record only its kind."""
    import sys
    log.exception(message)
    job_registry.fail(key, sys.exc_info()[1])


@_tracked('imap_poll', 'Report inbox', 'DMARC and TLS-RPT reports arriving by email', 'imap_poll_interval')
async def _imap_poll_job():
    try:
        from app.services.imap_service import poll_inbox
        await poll_inbox()
    except Exception:
        _job_failed('imap_poll', "IMAP poll job failed")


@_tracked('cert_probe', 'Certificate probe', 'Mail and web certificate expiry and health', 'cert_probe_interval')
async def _cert_probe_job():
    try:
        from app.services.cert_service import probe_all_domains
        await probe_all_domains()
    except Exception:
        _job_failed('cert_probe', "Cert probe job failed")


@_tracked('dns_poll', 'DNS change check', 'The DNS timeline and record-change alerts', 'dns_poll_interval')
async def _dns_poll_job():
    try:
        from app.services.dns_service import poll_all_domains
        await poll_all_domains()
    except Exception:
        _job_failed('dns_poll', "DNS poll job failed")


@_tracked('recommendations', 'Recommendation engine', 'Advance/hold advice on the Roadmap', 'recommendation_interval')
async def _recommendation_job():
    try:
        from app.services.recommendation_service import evaluate_all_domains
        await evaluate_all_domains()
    except Exception:
        _job_failed('recommendations', "Recommendation evaluation job failed")


@_tracked('scheduled_reports', 'Scheduled reports', 'Emailed posture reports', 'scheduled_report_check_interval')
async def _scheduled_report_job():
    try:
        from app.services.scheduled_report_service import send_scheduled_reports
        await send_scheduled_reports()
    except Exception:
        _job_failed('scheduled_reports', "Scheduled report job failed")


@_tracked('scheduled_phishing_reports', 'Scheduled phishing reports', 'Emailed simulation reports', 'scheduled_report_check_interval')
async def _scheduled_phishing_report_job():
    try:
        from app.services.scheduled_report_service import send_scheduled_phishing_reports
        await send_scheduled_phishing_reports()
    except Exception:
        _job_failed('scheduled_phishing_reports', "Scheduled phishing report job failed")


@_tracked('training_reminders', 'Training reminders', 'Reminder emails for assigned courses', 'scheduled_report_check_interval')
async def _training_reminder_job():
    try:
        from app.services.training_course_service import send_training_reminders
        await send_training_reminders()
    except Exception:
        _job_failed('training_reminders', "Training reminder job failed")


@_tracked('cloud_rescan', 'Cloud rescan', 'Cloud account scans for connected accounts', 'command_rescan_interval')
async def _command_rescan_job():
    try:
        from app.database import AsyncSessionLocal
        from app.services.cloud_scan_service import rescan_all_due_connections
        async with AsyncSessionLocal() as db:
            count = await rescan_all_due_connections(db)
            if count:
                log.info("Command rescan job processed %d connection(s)", count)
    except Exception:
        _job_failed('cloud_rescan', "Command rescan job failed")


@_tracked('host_rescan', 'Host rescan', 'Host scans for connected hosts', 'command_rescan_interval')
async def _command_host_rescan_job():
    try:
        from app.database import AsyncSessionLocal
        from app.services.host_scan_service import rescan_all_due_host_connections
        async with AsyncSessionLocal() as db:
            count = await rescan_all_due_host_connections(db)
            if count:
                log.info("Command host rescan job processed %d connection(s)", count)
    except Exception:
        _job_failed('host_rescan', "Command host rescan job failed")


@_tracked('threat_detection', 'Threat detection', 'Identity and cloud threat polling', 'command_threat_detection_interval')
async def _command_threat_detection_job():
    try:
        from app.database import AsyncSessionLocal
        from app.services.threat_detection_service import poll_all_due_connections_for_threats
        async with AsyncSessionLocal() as db:
            count = await poll_all_due_connections_for_threats(db)
            if count:
                log.info("Threat detection job processed %d connection(s)", count)
    except Exception:
        _job_failed('threat_detection', "Threat detection job failed")


@_tracked('impersonation_scan', 'Impersonation scan', 'Look-alike domain scans', 'command_rescan_interval')
async def _command_impersonation_scan_job():
    try:
        from app.database import AsyncSessionLocal
        from app.services.impersonation_scan_service import poll_all_due_impersonation_domains
        async with AsyncSessionLocal() as db:
            count = await poll_all_due_impersonation_domains(db)
            if count:
                log.info("Impersonation scan job processed %d domain(s)", count)
    except Exception:
        _job_failed('impersonation_scan', "Impersonation scan job failed")


async def _brand_guard_recover_runs():
    if not settings.brand_guard_enabled:
        return
    try:
        from app.database import AsyncSessionLocal
        from app.services.brand_guard_service import recover_interrupted_runs
        async with AsyncSessionLocal() as db:
            count = await recover_interrupted_runs(db)
            if count:
                log.warning("Brand Guard: marked %d interrupted scan run(s) as failed after restart", count)
    except Exception:
        log.exception("Brand Guard run recovery failed")


@_tracked('brand_guard', 'Brand Guard', 'Brand look-alike scans, digests and capture clean-up', 'brand_guard_check_interval')
async def _brand_guard_job():
    if not settings.brand_guard_enabled:
        return
    try:
        from app.database import AsyncSessionLocal
        from app.services.brand_guard_service import scan_due_profiles
        async with AsyncSessionLocal() as db:
            count = await scan_due_profiles(db)
            if count:
                log.info("Brand Guard job scanned %d brand(s)", count)
            from app.services.brand_notify_dispatch import send_due_digests
            await send_due_digests(db)
            from app.services.brand_capture import purge
            await purge(db)                      # page captures past their 30 days (case captures stay)
    except Exception:
        _job_failed('brand_guard', "Brand Guard job failed")


@_tracked('phishing_campaigns', 'Phishing campaigns', 'Launching due simulation campaigns', 'command_rescan_interval')
async def _command_phishing_campaign_job():
    try:
        from app.database import AsyncSessionLocal
        from app.services.phishing_service import poll_due_phishing_campaigns
        async with AsyncSessionLocal() as db:
            count = await poll_due_phishing_campaigns(db)
            if count:
                log.info("Phishing campaign job launched %d campaign(s)", count)
    except Exception:
        _job_failed('phishing_campaigns', "Phishing campaign job failed")


@_tracked('oauth_risk', 'OAuth app risk', 'Third-party app grants', 'command_rescan_interval')
async def _command_oauth_risk_job():
    try:
        from app.database import AsyncSessionLocal
        from app.services.oauth_app_risk_service import poll_all_due_oauth_connections
        async with AsyncSessionLocal() as db:
            count = await poll_all_due_oauth_connections(db)
            if count:
                log.info("OAuth app risk job scanned %d connection(s)", count)
    except Exception:
        _job_failed('oauth_risk', "OAuth app risk job failed")


app = FastAPI(
    title="ZoneProof API",
    description="DMARC · MTA-STS · SSL monitoring platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """
    Generates a request ID (or reuses one from an upstream reverse proxy via
    X-Request-Id) and makes it available to every log line emitted while
    handling this request, via the ContextVar in logging_config.py — no need
    to thread it through every function signature by hand.
    """
    incoming = request.headers.get("x-request-id")
    request_id = incoming or str(uuid.uuid4())
    token = request_id_var.set(request_id)
    try:
        response = await call_next(request)
    finally:
        request_id_var.reset(token)
    response.headers["X-Request-Id"] = request_id
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(sources_router.router)
app.include_router(domains.router)
app.include_router(dmarc.router)
app.include_router(tls.router)
app.include_router(overview.router)
app.include_router(certs.router)
app.include_router(dns.router)
app.include_router(alerts.router)
app.include_router(advisor.router)
app.include_router(scan.router)
app.include_router(billing.router)
app.include_router(msp.router)
app.include_router(audit.router)
app.include_router(platforms.catalog_router)
app.include_router(platforms.router)
app.include_router(mta_sts_hosting.public_router)
app.include_router(mta_sts_hosting.router)
app.include_router(concepts.router)
app.include_router(service.router)
app.include_router(cloud.router)
app.include_router(engagement.router)
app.include_router(findings.router)
app.include_router(host.router)
app.include_router(exposure.router)
app.include_router(graph.router)
app.include_router(detection_coverage.router)
app.include_router(command_report.router)
app.include_router(investigations.router)
app.include_router(impersonation.router)
app.include_router(phishing.router)
app.include_router(phishing_track.router)
app.include_router(webhooks.router)
app.include_router(oauth_app_risk.router)
app.include_router(prospect.router)
app.include_router(training_course.router)
app.include_router(training_track.router)
app.include_router(phishing_reports.router)
app.include_router(brand_guard.router)
app.include_router(brand_probe_worker.router)


@app.get("/health")
async def health():
    """Liveness: the process is up. Use for container restarts."""
    return {"status": "ok"}


@app.get("/health/ready")
async def health_ready():
    """Readiness: the database answers. Use for load balancer targets; 503 takes the task out of rotation."""
    from fastapi.responses import JSONResponse
    from sqlalchemy import text
    from app.database import engine
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as e:
        log.warning("readiness check failed: %s", type(e).__name__)
        return JSONResponse({"status": "unavailable"}, status_code=503)
    return {"status": "ok"}
