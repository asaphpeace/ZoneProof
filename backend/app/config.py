import os as _os

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"
    # Optional: pin every connection to one Postgres schema (sets search_path).
    # Empty (the default, and what production uses) leaves Postgres behaviour
    # untouched. Exists so local live-verification can run in its own schema
    # (see dev_live.py) instead of sharing tables with the pytest suite.
    database_schema: str = ""
    # "production" turns on the start-up guard: the process refuses to start with the public development
    # signing key (below), a signing key under 32 characters, or the default database password.
    environment: str = "development"
    # Managed secrets (services/secrets_loader.py). SECRETS_PROVIDER=aws reads one JSON secret from AWS Secrets
    # Manager at start-up; its keys fill the settings below unless the environment already sets them.
    secrets_provider: str = ""
    aws_secret_id: str = ""
    aws_secrets_region: str = ""
    secret_key: str = "dev-secret-change-in-production"
    algorithm: str = "HS256"
    # Shortened from 480 (8h) — tokens are stateless JWTs with no server-side
    # revocation other than the token_version bump on password/2FA change, so
    # a leaked 8-hour token was a long exposure window. 60 minutes balances
    # that against not forcing re-logins constantly; the frontend should
    # silently re-authenticate or prompt for re-login on a 401, not crash.
    access_token_expire_minutes: int = 60

    imap_host: str = "mail.mailsentry.co.za"
    imap_port: int = 993
    imap_user: str = "reports@mailsentry.co.za"
    imap_password: str = ""

    reporting_domain: str = "mailsentry.co.za"
    # Managed MTA-STS hosting target (PAIN_POINT_RESOLUTION_PLAN.md Pain 5):
    # customers on hosting_mode="managed" publish ONE CNAME —
    # mta-sts.<their-domain> -> this hostname — and ZoneProof serves the
    # policy dynamically based on the request's Host header. Was previously
    # misused as a URL *prefix* (a real RFC 8461 bug, now fixed); this is
    # the correct usage: a bare hostname for the CNAME target. The TLS
    # termination for arbitrary customer hostnames pointed here is an
    # infra-layer concern (e.g. Caddy/Traefik with on-demand TLS issuing a
    # cert per incoming SNI), not application code — see
    # app/routers/mta_sts_hosting.py's module docstring.
    mta_sts_hosting_cname_target: str = "mta-sts-host.mailsentry.co.za"
    app_base_url: str = "http://localhost:5173"

    # Comma-separated list of allowed frontend origins for CORS. Defaults
    # cover local dev only — production deployments must set this explicitly
    # via env (CORS_ORIGINS=https://app.example.com,https://app2.example.com).
    # Never default this to "*" with allow_credentials=True; that combination
    # is invalid per the CORS spec anyway (browsers reject it), but more
    # importantly it would mean any site can make authenticated requests
    # using a logged-in user's cookies/headers.
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    advisor_llm_url: str = "http://localhost:11434"
    advisor_llm_model: str = "sentinel:latest"
    advisor_enabled: bool = True
    advisor_provider: str = "ollama"          # "ollama" | "claude"
    anthropic_api_key: str = ""
    advisor_claude_model: str = "claude-haiku-4-5-20251001"

    # Identity & Credential Hygiene's breach-monitoring half — HaveIBeenPwned's
    # breach-check API. Empty by default; the service degrades to "not
    # configured" rather than crashing when unset, same pattern as every
    # other optional third-party key in this file.
    hibp_api_key: str = ""

    # Real-Threat Reports link risk scoring (Phase 32) — Google Web Risk
    # API, NOT Safe Browsing: Safe Browsing's own ToS explicitly prohibits
    # commercial-product use, confirmed by direct research; Web Risk is
    # Google's commercially-licensed sibling built on the same threat-list
    # data (100k calls/month free, then $0.50/1,000 — effectively free at
    # this product's per-report-triage volume). Empty by default;
    # link_risk_service degrades to "Web Risk check unavailable" rather
    # than failing the whole score when unset, same pattern as hibp_api_key.
    web_risk_api_key: str = ""

    # The background jobs run in the API process. With more than one instance, only the one holding a
    # Postgres advisory lock (the leader) runs them; the others stand by and take over if it dies.
    # scheduler_enabled=False makes an instance API-only (it never contends for the lock).
    scheduler_enabled: bool = True
    scheduler_lock_retry_seconds: int = 15
    scheduler_lock_heartbeat_seconds: int = 10
    # Connect straight to the database for the lock. Needed when DATABASE_URL goes through a pooler
    # in transaction mode, which does not keep session-level locks. Empty uses DATABASE_URL.
    scheduler_lock_database_url: str = ""

    # Run jobs that are overdue (or safe to run) shortly after the server starts, instead of
    # waiting one full interval first. See services/job_startup.py. False restores the old timing.
    jobs_run_overdue_at_start: bool = True

    imap_poll_interval: int = 300
    cert_probe_interval: int = 86400
    dns_poll_interval: int = 3600
    recommendation_interval: int = 86400
    # How often the job checks which tenants are due — not how often any one
    # tenant gets emailed. Due-ness itself is computed per-tenant from
    # last_report_sent_at against their weekly/monthly schedule, so checking
    # daily just means "send within a day of becoming due," not "send daily."
    scheduled_report_check_interval: int = 86400

    # Stripe
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_publishable_key: str = ""

    # Stripe price IDs — create these in your Stripe dashboard
    stripe_price_starter_monthly: str = ""
    stripe_price_starter_annual: str = ""
    stripe_price_pro_monthly: str = ""
    stripe_price_pro_annual: str = ""
    stripe_price_msp_monthly: str = ""
    stripe_price_msp_annual: str = ""

    # Transactional email — sent via the SendGrid HTTP API (Phishing
    # Simulation roadmap Phase 17 — replaces the previous plain-SMTP
    # transport, which had no bounce/complaint visibility at all). If
    # sendgrid_api_key is unset, send_email() logs the rendered email to
    # stdout instead of calling the API, so dev/test environments work with
    # zero config. sendgrid_webhook_public_key verifies the real signed
    # bounce/complaint events SendGrid posts to /webhooks/sendgrid/events —
    # an unset key means that webhook rejects everything rather than
    # trusting an unverified payload.
    sendgrid_api_key: str = ""
    sendgrid_webhook_public_key: str = ""
    email_from_address: str = "noreply@mailsentry.co.za"
    email_from_name: str = "ZoneProof"

    # Sentinel Command — Tier 0 cloud posture scanning. This is the AWS
    # account ID customers grant cross-account role access to; unset by
    # default (matches sendgrid_api_key/stripe keys' pattern) until this is
    # actually deployed with real scanning infrastructure — see
    # ARCHITECTURE.md's scanning-egress isolation note.
    command_aws_account_id: str = ""

    # boto3 clients that don't go through Prowler's own CLI (e.g. the
    # inspector2 client in cloud_scan_service.py) need an explicit region —
    # unlike sts, inspector2 has no global endpoint, and this environment
    # has no default region configured, which surfaces as a hard
    # NoRegionError rather than a silent wrong-region call. Inspector2 is
    # regional; a real deployment scanning multiple regions needs to either
    # iterate per-region or ask the customer which region(s) to scan — not
    # handled yet, single-region is today's simplification.
    command_aws_default_region: str = "us-east-1"

    # Prowler lives in its own venv (backend/.venv-prowler) — its exact pins
    # (pydantic==2.12.5, boto3==1.40.61 at time of writing) conflict outright
    # with this app's own. Cloudsplaining gets a SEPARATE isolated venv
    # (backend/.venv-iam-tools), not the same one as Prowler — installing
    # Cloudsplaining (which needs boto3>=1.41.0) alongside Prowler silently
    # upgrades Prowler's exact-pinned boto3 in the same venv, found by
    # actually testing it rather than assuming isolation was enough. PMapper
    # was dropped entirely: the latest published release (1.1.5) imports
    # `collections.Mapping`, removed in Python 3.10+, and patching an
    # installed third-party package's site-packages directly isn't something
    # to do — Cloudsplaining's own privilege-escalation detection (Rhino
    # Security Labs' methodology) covers the same need without it.
    # Paths are relative to the backend/ working directory the app runs
    # from; override via env for any other deployment layout.
    command_prowler_bin: str = (
        ".venv-prowler/Scripts/prowler.exe" if _os.name == "nt" else ".venv-prowler/bin/prowler"
    )
    command_iam_tools_python: str = (
        ".venv-iam-tools/Scripts/python.exe" if _os.name == "nt" else ".venv-iam-tools/bin/python"
    )
    command_scan_timeout_seconds: int = 900
    # How often the background job checks for connections due a rescan —
    # matches V1's existing interval-job settings (e.g. cert_probe_interval)
    # in spirit, not a per-connection schedule; every connection with an
    # active engagement gets rescanned every time this fires.
    command_rescan_interval: int = 21600  # 6h, matching BUILD_PLAN.md's original "recon every 6h" intent

    # How often the CloudTrail escalation poll runs (ITDR_DESIGN.md). Much
    # tighter than the posture rescan interval — this is meant to catch an
    # active attacker, not a slow drift in configuration, so it polls the
    # last 24h/since-last-poll window frequently rather than every 6h.
    command_threat_detection_interval: int = 300  # 5 minutes

    # Real e-signature for the Engagement rules-of-engagement gate
    # (ARCHITECTURE.md Section 9) — Dropbox Sign, not DocuSign, chosen there
    # for embedded-signing-first API + lower per-signature cost at this
    # volume. Blank by default (matches the stripe/sendgrid key pattern) —
    # request_signature() 503s cleanly with no key configured rather than
    # silently no-op'ing.
    dropbox_sign_api_key: str = ""
    # Dropbox Sign's sandbox mode: signatures complete instantly without a
    # real signer action and are NOT legally binding. True by default so a
    # fresh dev/test environment never accidentally sends a real, binding
    # signature request — must be explicitly set False for production.
    dropbox_sign_test_mode: bool = True

    # Escape hatch kept for local/CI testing of the Tier 0 scan pipeline
    # end-to-end without needing a real Dropbox Sign account — see
    # approve_engagement()'s docstring. Must be False in any real deployment;
    # the real gate is request_signature() + the signed-webhook callback.
    command_allow_direct_engagement_approval: bool = True

    # Phishing Tier A — Spoof Proof (PHISHING_DESIGN.md Section 2.3). DMARC
    # policy and domain registrations don't drift weekly, but a quarterly
    # check would catch a real change too slowly — monthly is the chosen
    # middle ground.
    command_impersonation_scan_interval_days: int = 30

    # Phishing Tier B — Human Simulation (PHISHING_DESIGN.md Section 3).
    # Tracking pixel/click/submit URLs are backend API endpoints, not
    # frontend routes — deliberately a separate setting from app_base_url
    # (which every existing link in this codebase points at the frontend),
    # not reused, since these are structurally different link targets.
    command_phishing_track_base_url: str = "http://localhost:9931"

    # Brand Guard — how often the job wakes to see which brands are due. Actual
    # cadence is per-plan (plan_limits brand_guard_scan_days; CT polls every 6h
    # on plans that include it), so this just sets the wake-up granularity.
    brand_guard_check_interval: int = 3600
    # Minutes between per-brand crt.sh polls (the low-bandwidth alternative to the CT stream worker). Lower = fresher, but one more crt.sh
    # request per brand per interval through the shared one-at-a-time throttle; the job wake-up above is the floor.
    brand_guard_ct_poll_minutes: int = 360
    # Opt-in switch for Brand Guard's background work (hourly due-scan job and
    # startup recovery of interrupted runs). OFF by default so any process
    # sharing this codebase and a database that hasn't had the Brand Guard
    # migrations applied isn't disturbed — it would otherwise log errors every
    # cycle against tables that don't exist. The API routes stay registered
    # either way; set BRAND_GUARD_ENABLED=true where Brand Guard is deployed.
    brand_guard_enabled: bool = False
    # Stage 7 page probing. OFF by default and the one switch that turns all probing off: while False the worker API refuses every request and
    # nothing is queued. The worker is a separate machine (see BRAND_GUARD_STAGE7_EGRESS_DESIGN.md); brand_probe_key is the shared secret it signs with.
    brand_probe_enabled: bool = False
    brand_probe_key: str = ""
    brand_probe_job_ttl_seconds: int = 900
    brand_probe_tenant_daily_cap: int = 50
    brand_probe_host_interval_hours: int = 24
    # Step 7.3: the sandboxed renderer (screenshot, rendered text and forms). A second switch on top of brand_probe_enabled, off by default,
    # because it runs a real browser against hostile pages inside a throwaway container on the worker machine.
    brand_render_enabled: bool = False
    brand_render_tenant_daily_cap: int = 10
    brand_render_host_interval_days: int = 7
    brand_capture_retention_days: int = 30
    # Step 7.4: how often the renderer re-captures the customer's OWN page, the reference a look-alike's screenshot is compared with.
    brand_reference_refresh_days: int = 30

    # Scan cost and capacity (plan step 0.6). Process-wide politeness limits toward the upstream services
    # every scan fans out to, plus how many scans may run (and wait) at once across all tenants.
    brand_guard_dns_concurrency: int = 60          # DNS queries in flight across ALL scans
    brand_guard_rdap_concurrency: int = 6          # RDAP/WHOIS lookups in flight across ALL scans
    brand_guard_crt_min_interval_seconds: float = 1.0   # spacing between crt.sh requests (also one at a time)
    brand_guard_max_concurrent_scans: int = 4      # scans executing at once; the rest wait as "queued"
    brand_guard_max_queued_scans: int = 25         # queued + running; beyond this a new manual scan is refused (503)
    # Hard ceiling on one scan run, so a hung upstream can't leave a run (and
    # its one-active-run-per-brand slot) stuck forever.
    brand_guard_scan_timeout_seconds: int = 900

    # Live certificate stream (plan 2.6b): a SEPARATE long-running process (`python -m app.workers.ct_stream`) that follows
    # Certificate Transparency logs and feeds look-alike certificates into Brand Guard within seconds. It needs
    # BRAND_GUARD_ENABLED as well. Measured cost of the default families: roughly 25 GB/day of downloads and ~2% of one core.
    ct_stream_families: str = "parcelyard,willow"      # log families to follow (see app/services/ct_log_list.py)
    ct_stream_extra_logs: str = ""                     # comma-separated https monitoring URLs of additional tiled logs
    ct_stream_flush_seconds: int = 20                  # how often matches are handed to the scoring pipeline
    ct_stream_max_per_flush: int = 40                  # names per brand per flush (the rest are counted as dropped, never queued unboundedly)
    ct_stream_backlog_tiles: int = 1500                # if further behind than this (~384k entries) skip ahead rather than never catch up


def load_settings() -> Settings:
    """Build the settings; with SECRETS_PROVIDER=aws, fill unset values from Secrets Manager, then apply the production guard."""
    from app.services import secrets_loader

    s = Settings()
    if s.secrets_provider.strip().lower() == "aws":
        if not s.aws_secret_id:
            raise secrets_loader.SecretsError("SECRETS_PROVIDER=aws needs AWS_SECRET_ID")
        secret = secrets_loader.fetch_secret_json(s.aws_secret_id, s.aws_secrets_region)
        apply, ignored = secrets_loader.overrides_from_secret(secret, set(Settings.model_fields))
        if ignored:
            import logging
            logging.getLogger(__name__).warning("Managed secret has keys that are not settings (ignored): %s", ", ".join(ignored))
        if apply:
            s = Settings(**apply)
    secrets_loader.enforce_production_guard(
        environment=s.environment, secret_key=s.secret_key, database_url=s.database_url
    )
    return s


settings = load_settings()
