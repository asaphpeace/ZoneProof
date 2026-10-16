# ZoneProof V2 Plan

Drafted 2026-10-15. Nothing in this document has been built. It consolidates the redesign canvas (v74), the workflow audit, the Brand Guard plan, the older plans, and AWS readiness into one sequence. Each claim about current state says how it was checked.

---

## Progress (updated 2026-10-16)

| Band | Items | Done | Notes |
|---|---|---|---|
| A. Trust and visibility | 7 | **7** | Passive DNS source not added: terms check says no free feed is safe (G4) |
| B. Workflow | 10 | 0 | Backend and design decisions pending; B10 task test not run; prototype first |
| C. AWS readiness | 10 | **5** (C1, C2, C3, C8, C9) + C5 partly | C4, C6, C7, C10 need your decisions; no AWS resources created |
| D. Telemetry integrations | 3 | 0 (D1 backend built) | D1 screen waits for prototype; D2 vendor open |
| E. Brand Guard remaining | 12 | **3** (E1, E5, E11) | E12 parked by you |
| F. Other plans | 6 | **2** (F5, F6) | F3 blocked: no attack-path view exists |
| G. Found while building | 5 | **4** (G1, G2, G4, G5) | G3 client scope remains |

Done: 21 of 53 (plus two partly: C5, D1). Everything is committed on branch `v2-foundations` (not pushed). Not done from the first steps of the order in section 4: B10.

Also done outside the plan: IMAP poll no longer crashes when unconfigured, SendGrid verified end to end, the Vite proxy port mismatch diagnosed.

Test status: the full backend suite last passed on 2026-10-15 (2453 passed, 2 skipped); after the 2026-10-16 changes a full run gave 2471 passed, 1 skipped, 1 failed and 1 error (test_dev_isolation, test_webhooks_router); both pass when run alone (20 passed), most likely because another pytest was using the same test database at the time. A clean re-run is still owed. Frontend: 87 tests pass.

## 1. Verified starting point

Checked on 2026-10-15 by reading code and running 19 backend test files (**344 passed in 142 s**; the full suite of 143 files and the frontend tests were not run).

| Area | Result | How checked |
|---|---|---|
| AI plan steps 1 to 4 (report narrative, DNS change risk, sender recommendation, policy-promotion simulation) | **Built** | `advisor_service.py` (`generate_report_narrative`, `generate_dns_risk_assessment`, `generate_sender_recommendation`), `recommendation_engine.simulate_advance`, `POST` route in `domains.py` |
| AI plan step 5 (alert correlation), step 6 (cross-tenant intelligence) | **Not built** | No correlation or cross-tenant code outside Brand Guard and phishing; step 6 also behind the POPIA gate |
| Pain 1 platform library, Pain 2 concept cards, Pain 5 MTA-STS hosting, Pain 6 subdomain ledger | **Built** | Test files pass (`test_platform_library`, `test_concepts`, `test_mta_sts_hosting`, `test_subdomain_discovery`); `SubdomainDisposition` model and overview gating |
| Pain 3 DKIM-fail diagnosis, Pain 4 readiness scorecard | **UI present, backend not confirmed by name** | `DkimFailureDiagnosis.vue`, `EnforcementReadinessCard.vue`, `MxReadinessScorecard.vue` exist; no dedicated test file found. Treat as partly verified |
| Phishing P0 (settings, training layer, roles and approval) | **Built** | `test_training_course_*`, `test_phishing_router`, approval in `engagement.py` |
| Phishing P1 scheduled reporting; real-threat report triage | **Built** | `test_scheduled_phishing_report_service`, `test_phishing_reports_router`, `test_link_risk_service` |
| Phishing P1 dynamic or smart targeting | **Not built** | No dynamic target rules found; target lists are static |
| Attack path graph | `RUNS_AS` and `EXPOSED_TO_INTERNET` built; chokepoint in the schema; edge labels not found in the UI | `graph_service.py`, `schemas/graph.py`; graph tests pass |
| Brand Guard Stages 0 to 2, 3 (except 3.2), 4.1 to 4.3, 7.1 to 7.4, 8 | **Built** per journal and code | Services and routes present. **The plan's own status table is stale after step 2.6** |
| Brand Guard Stage 5, Stage 6, Stage 9, 3.2, 4.4 | **Not built** | No services for them; 3.2 needs labels, 4.4 is a decision brief only |
| Brand takedown "claims only from captured evidence" rule; single-admin approval rule | **Not found enforced** | Complaint text is factual and drafts need approval, but no capture-only check located |
| Guided onboarding Phase 1 (registrar instructions, live DNS check, email instructions, subdomain discovery) | **Built** | Schemas and routes present. Phase 2 (Domain Connect, Entri) not verified. Part 3 workflow gaps were never scoped |
| Docs plan | **Not verified** | `DocsView.vue` exists; not compared with the eight planned sections |

---

## 2. Principles

From the three reference screenshots and the workflow audit.

1. **Every source is a visible object with state:** enabled, last run, next run, status, manual run. No silent failure.
2. **Errors are states, never empty lists.** "Timed out, retry" and "not configured" are different from "none found".
3. **Entity first.** Work belongs to a client or domain and carries a visible reason for its priority.
4. **Detail beside the list**, "1 of N", one primary action, the rest behind overflow.
5. **Say what to do next, in place.**
6. **Work with zero customer input first;** connectors and DNS access are optional upgrades, never prerequisites.
7. **One scope.** Client then domain, chosen once, remembered across every page.
8. **A component catalog.** Alerts, empty states, toasts, panels, tables are shared, not re-drawn per page.
9. **Measure and say how sure we are.** Show confidence and coverage, not a clean verdict.

---

## 3. Workstreams

### A. Trust and visibility (first, on the current app)

| # | Item | Size | Notes |
|---|---|---|---|
| A1 | Replace silent `catch → []` with explicit failed and not-configured states | S | **DONE 2026-10-15** for the seven primary data loaders (Overview, Posture, DMARC, MTA-STS, Certificates, Roadmap, Timeline) and subdomains, via `LoadError` and a `domains` store error. Advisor-only catches left as informational. Other views (Billing, Domains list, Audit) not reviewed |
| A2 | Global client and domain scope in the top bar | M | **DONE for domain scope 2026-10-15** (shared store, top-bar selector, `?domain=` sync, six pages). **Client scope not built:** domain APIs are workspace-scoped, needs client-aware endpoints (see G3) |
| A3 | Finding-to-fix links on every finding | M | **DONE 2026-10-15** for Roadmap, Certificates and Timeline (`NextStep`). Report intentionally has none (print view). Certificate-row links not exercised live |
| A4 | Correct receiving-side wording in the app (`FAILURE_REASONS`, `_TLS_FIX_ACTIONS`) and fix the TLS days filter | S | **DONE 2026-10-15.** The TLS overview now windows by real report periods. Other consumers (Overview, MSP, advisor) still read all-time aggregates (see G5) |
| A5 | Data sources and health page | M | **DONE 2026-10-15** (`/sources`, admin only; job registry, per-domain freshness, service set-up). No manual run; job history is in memory (see G1, G2) |
| A6 | Subdomain discovery redesign | M | **DONE 2026-10-15 except the passive DNS source** (own records, `sp=`/`np=` coverage, 66-name wordlist with wildcard detection, CT retry with visible status and cache, hostname validation). Passive source waits on a terms-of-service check (G4) |
| A7 | Accessibility pass | M | **DONE 2026-10-15 for the automated and keyboard layers.** axe-core on 16 pages: 7 rule types (about 60 nodes, 2 critical) to 0. Real dialogs (focus in, Esc, Tab trap, focus back), skip link, visible focus, keyboard-operable navigation and about 23 clickable rows/headers, named controls, heading levels, toast live region, one contrast fix. **Not done:** screen-reader testing with real assistive tech, contrast on gradient backgrounds (axe cannot compute them), table captions and chart text alternatives, Brand Guard pages beyond the three audited |

### B. Workflow (the redesign, built in slices)

| # | Item | Size | Notes |
|---|---|---|---|
| B1 | Shared case object (states new to resolved, computed priority with reasons) | L | Backend model plus API; Senders, Brand and Programme attach to it |
| B2 | Overview becomes a ranked worklist | M | Replaces KPI-only hero |
| B3 | Navigation regrouped by job (Triage, Fix, Prove, Report) | M | Follow Brand Guard's grouping |
| B4 | Senders pattern-first with diagnosis and partition statistics | L | Needs DMARC raw-XML re-parse and pattern tables |
| B5 | Encryption lens with the MTA-STS ladder | L | Needs TLS aggregation by reporter, MX and result, real periods, failure details |
| B6 | Change panel (SPF, DMARC, MTA-STS) as one parameterised flow | M | Replaces the single-purpose Review dialog |
| B7 | Autonomy ladder A0 to A4 with the "never" set | M | Defaults A2 client-facing, A3 DNS |
| B8 | Role lenses and F1 to F6 | L | Owner, Operator, MSP owner, Verifier; approvals, scoped expiring partner access, proof of value, attestation, public check, hosted delegation |
| B9 | F7 PSA, F8 SSO for MSP staff, F9 per-client technician scope | later | Marked "revisit" |
| B10 | Task test with real engineers | S | Do before B1 is final; script in the walkthrough |

### C. AWS readiness

Constraints from the project setup: every Regional resource lives in the project's single Region; no multi-Region replication or keys, no Lambda@Edge; a spend limit can pause the project, so cost guardrails come first; ask after each task whether to keep or delete new resources.

| # | Item | Why |
|---|---|---|
| C1 | **Separate the scheduler from the API.** The API starts about 14 interval jobs itself; two containers would run each twice. One worker service or a leader lock | **DONE 2026-10-15 as a leader lock** (`scheduler_lock.py`, Postgres advisory lock on its own connection). Verified with two live instances: one leader, one standby, takeover in about 15 s. `SCHEDULER_ENABLED=false` makes an instance API-only, so a dedicated worker is still possible. Not covered: per-process job history (G2), a pooler in transaction mode needs `SCHEDULER_LOCK_DATABASE_URL` |
| C2 | Secrets from a managed secrets store at start-up (SendGrid, Stripe, DB, signing key, IMAP) | **DONE 2026-10-15** (`secrets_loader.py`): `SECRETS_PROVIDER=aws` reads one JSON secret from Secrets Manager at start (env wins; unreadable secret stops start-up); `ENVIRONMENT=production` refuses the dev signing key, a key under 32 chars, or the default DB password; compose now requires `POSTGRES_PASSWORD`, defaults `ENVIRONMENT=production`, duplicate SendGrid line removed. Needs `secretsmanager:GetSecretValue` on that one secret. Not done: rotation |
| C3 | Managed Postgres. Run migrations as a one-off release step, not in every replica's entrypoint | **DONE 2026-10-16.** Schema logic moved to `migrate.sh`; `entrypoint.sh migrate` runs it as a one-off release step; `RUN_MIGRATIONS=false` starts a replica without touching the schema; default unchanged for compose. Managed Postgres itself not created |
| C4 | Report intake moves from IMAP polling to push (received mail stored, queued, processed) | Confirm service availability in the project Region first |
| C5 | Frontend as static assets behind CloudFront; API stays Regional | **PARTLY DONE 2026-10-16.** `VITE_API_BASE` build setting (default `/api`, so nothing changes today). Bucket, CloudFront and the `/api/*` behaviour (CloudFront cannot strip the prefix without a function; backend mounts at `/`) belong to C10 |
| C6 | Hosted model for the advisor in place of host Ollama | `host.docker.internal` does not exist on AWS |
| C7 | Report files to object storage; shared store for rate limits and caches | Per-instance memory breaks at scale |
| C8 | Health checks, structured logs to log groups, alarms | **PARTLY DONE 2026-10-16.** Added `/health/ready` (database check, 503 when down) for load balancer targets. JSON logs already go to stdout, so the log driver ships them. Log groups with retention and alarms belong to C10 |
| C9 | Cost guardrails and cleanup checklist per build step | **DONE 2026-10-16.** `AWS_BUILD_CHECKLIST.md`: what bills and how to undo it, per step |
| C10 | Deploy method (CDK or CloudFormation) | Pick when C1 to C4 are settled |

### D. Email telemetry integrations

Shape taken from the vendor setup screenshot, **not yet agreed**. Each integration is a vendor header, masked credentials, selectable feeds with last run, next run, status and manual run, and an export-upload fallback for customers who will not grant API access.

| # | Item | Open question |
|---|---|---|
| D1 | Integration framework (feeds, schedule, status, credentials vault) | **BACKEND DONE 2026-10-16; screen not started.** Tables `integration_connections` / `integration_feeds` (migration `b3d8f1a6c2e9`), adapter contract (`test`, `pull(cursor)`), service (encrypted credentials, manual run, fixed error kinds, `run_due` for the scheduler) and admin API `/integrations`. Credentials never returned, not even masked. No vendor registered (D2); scheduler not wired until one exists; export-upload fallback and the screen wait for the prototype. Vault uses the existing app-level key; KMS-backed is a C-band follow-up |
| D2 | First vendor | Which platform first? (Mimecast and Microsoft 365 are the candidates) |
| D3 | Join telemetry to DMARC per sender and domain | What question should the join answer? |

### E. Brand Guard remaining

| # | Item | Gate |
|---|---|---|
| E1 | Reconcile `BRAND_GUARD_PLAN.md` with the code | **DONE 2026-10-15.** The per-stage notes were already current; added a one-glance summary and markers on every step row |
| E2 | Enable Stage 7 probes and renderer (switches, keys, AWS resources) | Your go-ahead; decide keep or delete resources |
| E3 | Label the SA review queue (401 rows, 144 pre-suggested) | You |
| E4 | Funnel gaps: visual, overview strip, unclaimed-job alert, MSP roll-up, audit sample | Audit sample needs labels |
| E5 | Cases fixes: takedown claims only from captured evidence; single-admin approval rule | **DONE 2026-10-15.** Allowlist of claimable signals (private and inferred lines excluded), honest name-only draft, admin/approver role needed, self-approval recorded. Second-person approval for multi-admin workspaces is an open policy choice |
| E6 | 4.4 cross-tenant intelligence | POPIA review and approval |
| E7 | Stage 9: labels from triage, active learning, metrics, retire Tier A scan, runbooks | Data and training last, per ordering |
| E8 | 3.2 calibration | Needs E7 labels |
| E9 | Stage 5 generator and discriminator; Stage 6 constrained LLM layer | Provider, budget, attacker-text handling decisions |
| E10 | Deferred register (executives, fake apps, ads, marketplaces, dark web, BEC) | After Stage 8, new scope |
| E11 | 0.1 Commit Phase 1 | **DONE 2026-10-16.** Branch `v2-foundations`, 4 commits by layer (docs, core, backend, frontend), 505 files. Not pushed. Left out: `zp-worker.tgz`, `policy.json`, `.claude/settings*` |
| E12 | 2.5 paid sources and 2.6b CZDS | Skipped or parked by you |

### F. Other plans

| # | Item |
|---|---|
| F1 | AI step 5 alert correlation; step 6 cross-tenant (shares the POPIA gate with E6) |
| F2 | Phishing dynamic targeting |
| F3 | Attack path: edge labels in the UI, highest-impact fix callout | **BLOCKED 2026-10-16, needs your call.** There is no attack-path view in this frontend (no component references paths, edges or priv-esc). Only the backend model and data exist (`cloud_priv_esc_path`, `cloud_asset`, findings). Labels and a callout need the view built first, which is a new screen and belongs with the Pathproof surface, so prototype first |
| F4 | Guided onboarding Phase 2 (Domain Connect, then Entri) and Part 3 workflow and trust gaps (never scoped) |
| F5 | Confirm Pain 3 and Pain 4 backend and add tests | **DONE 2026-10-15.** Both confirmed built; added 5 API-level tests; Roadmap now shows the per-source checklist on load instead of only after "Preview impact" |
| F6 | Docs plan against `DocsView.vue` | **DONE 2026-10-16.** All 8 planned sections exist (plus Account & Security and Audit Log). Every planned topic is covered except the rate-limit note; added a 429 row to Error Codes. Webhooks not documented because no customer webhooks exist |

---

### G. Found while building (2026-10-15)

| # | Item | Why |
|---|---|---|
| G1 | **Jobs wait one full interval before their first run, so every restart resets all timers.** | **DONE 2026-10-15** (`job_startup.py`): per-job policy; overdue or due-aware jobs run shortly after start, staggered; batch jobs use the newest persisted result; switch `JOBS_RUN_OVERDUE_AT_START`. Still per process: C1 is needed before more than one instance |
| G2 | Persist job history across restarts and instances | **DONE 2026-10-16.** New `job_runs` table (migration `a7c1e4b9d2f6`, one row per job). The running instance upserts after every run (counters accumulate in the database); the Data sources page overlays the stored row, so a restart or a standby shows real history. A failed write never affects a job. Migration not yet applied to any running database |
| G3 | Client scope for MSPs: client-aware endpoints for domains and analysis | **ASSESSED 2026-10-16, not built; needs your decision.** Clients are child tenants (`parent_tenant_id`); about 140 endpoints filter on `user.tenant_id`. Editing each is the wrong route. Proposed: one dependency reads an `X-Client-Id` header, checks the caller's tenant is that client's parent, and returns the same user with `tenant_id` swapped, so every existing endpoint works in client context unchanged. Open: read-only first or writes too, how audit entries name the acting MSP user, whose plan limits apply, and the picker (a screen, so prototype first) |
| G4 | Terms-of-service check for passive DNS sources before adding one | **DONE 2026-10-16 (check made; the source decision is yours).** `PASSIVE_DNS_TERMS_CHECK.md`: VirusTotal, Censys and OTX free tiers forbid commercial use; HackerTarget and CIRCL need written permission; SecurityTrails and Shodan could not be read. No free passive DNS source should go into the paid product, so A6 stays on own records, wordlist and CT |
| G5 | Window the remaining TLS consumers (Overview, MSP, advisor) by report period | **DONE 2026-10-16.** `tls_window_totals` (30 day default, report period) now feeds Overview, per-domain TLS summary, portfolio KPIs, MSP and advisor. The account data export stays all-time on purpose |

---

## 4. Suggested order

1. **Now (no design dependency):** ~~A1, A4, A6, E1, E5, F5~~ done.
2. **Foundation:** ~~A2, A3, A5~~ done; **B10 still open** (C1, C2 done).
3. **Workflow core:** B1, B2, B3, B6, B4, B5, then B7. Backend for B4 and B5 first.
4. **AWS cut:** C3 to C10 once C1 and C2 are done. Deploy a staging copy before any production claim.
5. **Integrations and lenses:** D1 to D3, then B8.
6. **Brand Guard completion:** E2 to E4, E6 after approval, E7 to E9 last.

Reason for this order: the early items are small, independent and reduce risk; the case object (B1) is the main dependency for the redesign; AWS scale-out is blocked by C1 alone.

---

## 5. Decisions needed from you

1. ~~**Scheduler:** dedicated worker service, or a leader lock inside the existing container for the first AWS cut? (C1)~~ **Decided 2026-10-15: leader lock.**
2. **Project Region** and whether inbound report intake is available there (C4).
3. **Hosted model** for the advisor: Bedrock or the Anthropic API (C6).
4. **First telemetry vendor** and what the DMARC join should answer (D2, D3).
5. **Commit:** when to lift the deferral on committing Phase 1 (E11). It is the largest repo risk: HEAD lacks about 160 untracked files and 37 migrations, and 111 files are modified and uncommitted.
6. Brand Guard gates: Stage 7 enablement, POPIA for cross-tenant, provider and budget for the LLM layer.
7. Whether to run the task test (B10) before building B1.

---

## 6. Risks

- **Uncommitted work.** A lost working tree would lose months of changes. Settle E11 before the AWS work.
- **Shared backend with PathProof.** Changes to the case, scope or auth models affect both products. Flag before touching shared code.
- **Prototype not user-tested.** The canvas has not been tried by real engineers; B10 reduces the risk of building the wrong shell.
- **Sample data is illustrative.** Numbers on the canvas boards are not measured. Real aggregation (B4, B5) may change what the screens can honestly say.
- **Third-party sources.** crt.sh, passive DNS and vendor APIs vary in uptime; every source needs a visible status (A5).
- **Spend limit.** AWS resources for Stage 7 and the V2 deploy can pause the project if exceeded.

---

## 7. What this plan does not claim

- It does not claim the unverified items in section 1 are finished or absent beyond what is stated.
- The full backend suite (143 files) has not been run since these changes; 116 related backend and 81 frontend tests pass.
- Docs plan and Guided onboarding Phase 2 were not compared with the code.
- Effort sizes are relative (S, M, L), not calendar estimates.
