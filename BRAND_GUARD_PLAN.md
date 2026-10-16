# Brand Guard — Synthesis & Staged Plan

Status: Phase 1 built and live-verified locally (uncommitted). This document
consolidates everything discussed since that build into one picture, then lays
out a staged plan executed **one step at a time**, each step ending in a
verified, reviewable state.

---

## Part A — Calibrated synthesis

The ideas below arrived progressively and partly overlapped or contradicted
earlier suggestions (three different "build this first" lists were given). This
section is the single reconciled view; where it disagrees with an earlier
message, this section wins.

### A1. What exists today (Phase 1, honest state)

- Models: `brand_profiles`, `brand_candidates`, `candidate_evidence`
  (migration `c9a4e7b2d1f8`, no schema drift, round-trip verified).
- Discovery (`brand_discovery_service.py`): homoglyph/IDN skeletons,
  combosquats, TLD swaps, typos (keyboard-adjacent), ~200-400 candidates.
- Enrichment: DNS (A, MX), RDAP / `.za` WHOIS registration date (live
  candidates only), crt.sh CT polling (Pro+).
- Scoring (`brand_scoring_service.py`): two independent additive scores —
  identity and abuse — with per-signal evidence. Weights are hand-set.
- Workflow: statuses, triage actions, alert-once, analyst decisions survive
  rescans, plan gating (Starter limited: 1 brand, no CT, monthly, 100 cap).
- UI: `BrandGuardView.vue` verified in a real browser (desktop layout).
- Tests: 23 passing. Nothing committed or deployed.

### A2. What the live run and review taught us (defects and gaps in Phase 1)

| # | Finding | Why it matters |
|---|---|---|
| 1 | Scan runs inside the HTTP request (~50 s cold) | Proxy timeouts; blocks the UI |
| 2 | Only the registrable label is inspected | `brand.co.za.evil.net`, `login.brand.evil.net`, `brand-co-za.com` are invisible |
| 3 | **Registered-but-dormant domains are dropped** (no A/MX → no row, RDAP skipped) | The lifecycle idea *depends* on seeing the dormant stage; today we can't |
| 4 | Only the latest state is stored; evidence is replaced each scan | No history → no velocity, no transitions, no audit trail |
| 5 | "Old domain ⇒ discount" is blunt | Aged/dropped-and-re-registered domains evade it |
| 6 | Weights are hand-set and additive | Not probabilities; nothing to calibrate or defend |
| 7 | crt.sh is polled, flaky (502s seen) | Not minutes-level detection; single point of failure |
| 8 | Old Tier A lookalike scan overlaps Brand Guard | Two code paths for one concept |
| 9 | Scratch-DB tests wipe `sentinel_test` | Dev-environment hazard for live verification |

### A3. The reconciled core ideas

1. **Lifecycle ladder.** Registered → DNS-configured → mail-enabled →
   certified → activated → weaponized. The *stage reached* and the *speed of
   progression* are stronger signals than any single feature. Requires
   observation history (A2-3, A2-4).
2. **Pre-content depth.** Most detection value exists before any page is
   fetched: email-authentication intent on the lookalike, registration and
   certificate behaviour, DNS/hosting context, infrastructure relationships,
   lexical/phonetic/script analysis, blocklist and feed corroboration.
3. **Benign explainers are first-class.** Same nameservers/IPs as the
   customer, redirect-to-brand, popularity-list presence, parking fingerprints
   should be able to *outweigh* suspicion, not just fail to add to it.
4. **Better logic.** Coincidence-probability scoring (how likely is a chance
   near-match, given name length/rarity) instead of fixed thresholds;
   calibrated likelihood-ratio combination with a low prior and the ability to
   abstain; conformal error guarantees; rules that emit proof trees; graph
   reasoning with guilt propagation; font-rendered visual confusability
   instead of a curated confusable map.
5. **Better AI, used safely.** Trained classifier (gradient-boosted trees +
   small character-level model) over the engineered features; LLM as creative
   adversary/generator, text reader and agentic investigator. **Invariant:
   only deterministic tool outputs count as evidence; the LLM never produces a
   verdict or a fact.**
6. **Generator / discriminator loop.** Not a literal GAN. An adversarial loop
   with a **real-world oracle** (DNS, CT, registration and phishing feeds):
   generator proposes → plausibility discriminator ranks → top-K verified
   against the oracle → outcomes become reward and labels. A separate *threat*
   discriminator judges registered domains. Adversarial evasions found by the
   generator harden the threat discriminator. Bandit allocation over generation
   strategies is the first, simplest learning step.
7. **First-party data is the differentiator.** The customer's DMARC reports
   (spoofer IPs/ASNs) and reported-phish inbox (`ReportedEmail`) pivot directly
   into candidates. Note: ZeroFox ingests DMARC forensics and abuse mailboxes
   at enterprise level, so this is *not* unique to us in isolation.
8. **Network effect across tenants.** Shared-infrastructure indicators across
   unrelated brands are a very strong malice signal. Needs a POPIA review and
   indicator-only sharing before any build.

### A4. Competitive calibration (researched, public sources only)

- Lifecycle/stage-awareness is **already discussed publicly** by Doppel
  (parked → certificate → active, critique of point-in-time scanning) and
  Proofpoint (MX-enabled domain tags). We did **not** find a competitor
  publishing a formal, explainable, velocity-aware ladder — but we cannot see
  internal methods, so this is a hypothesis, not a fact.
- Therefore the ladder is the *right model*, not a moat by itself. Our
  differentiation to lead with: **explainability (proof-style evidence,
  calibrated confidence), South Africa-specific depth (`.za`/ccTLD tricks,
  local-language lures, ZARC/ISPA routes), SMB/MSP packaging and price,
  first-party email data.**
- Academic context: median ~16 days from malicious registration to blocklist
  detection; ~11.5 days average lifetime after detection — early signals have
  real headroom over blocklists.

### A5. Standing principles (apply to every stage)

- Every alert must be explainable (evidence lines or a derivation).
- LLMs explain, generate, and investigate via tools — never assert evidence.
- Measure before claiming improvement (Stage 1 harness gates later claims).
- Passive-first: no traffic to suspect hosts until Stage 7, and then only
  through isolated egress.
- Nothing ships to production, and nothing is committed, without the user's
  explicit go.

---

## Part B — Staged plan

Each stage lists ordered steps. **Execution protocol:** I do one step, run its
tests, live-verify anything observable, report, and wait for "go" before the
next. Exit criteria are measurable so a stage can't be declared done on vibes.

**UI conventions (apply to every Surface entry).** Verdict first, reasons on
demand; "uncertain" and *evidence against* are first-class; every AI-written
line links to its source evidence; default lists are short and sorted by
urgency. Candidate detail is an `AppDrawer` component (V1's existing
UI-store-driven drawer, as used by `DmarcAuthDrawer`) — V1 has no separate
evidence-panel registry. Reuse `KpiCard`, `FilterPills`, `PlanGate`; new shared
pieces: stage-ladder, evidence for/against list, confidence label.

## Where this stands (reconciled 2026-10-15)

Checked against the per-stage status notes below, the journal and the code. The step rows now carry the same markers.

| Stage | State | Left to do or decide |
|---|---|---|
| 0 Stabilise | **Done** | 0.1 (commit) deferred by you |
| 1 Ground truth and harness | **Done** | Human labelling of the SA review queue (401 rows, 144 pre-suggested) |
| 2 Pre-content signal depth | **Done**, with decisions | 2.5 paid sources skipped by you; 2.6b CZDS parked, `.za` rejected, paid feed not built |
| 3 Reasoning core | **Mostly done** (3.0, 3.1, 3.3, 3.4) | 3.2 calibration needs outcome labels; reserved for last |
| 4 Graph and campaigns | **Done to 4.3** | 4.4 cross-tenant is a decision gate (POPIA review) |
| 5 Generator and discriminator | **Not built** | Reserved for last; 5.4 needs provider and budget decisions |
| 6 LLM reasoning layer | **Not built** | Needs provider, budget and attacker-text decisions; 6.4 first |
| 7 Probes and renderer | **Built, off by default** | Worker machine, render image and firewall rule are yours; JARM; real-page measurement |
| 8 Response | **Done** | 8.4 client logos need an upload design; in-product sending is your call |
| 9 Learning loop | **Not built** | Funnel counters exist as the foundation; audit sample, active learning, metrics, retire Tier A |

Open items that are not stages: the funnel visual, overview strip and unclaimed-job alert (see `BRAND_GUARD_FUNNEL.md`); the deferred register at the end of Stage 8's notes.

### Stage 0 — Stabilise Phase 1 (make it safe to build on)

| Step | Work | Surface (UI / API) |
|---|---|---|
| 0.1 | ~~Commit Phase 1~~ **DEFERRED by user (2026-09-30).** Finding: repo HEAD lacks ~160 untracked files, ~45 modified files and 37 migrations of earlier work (phishing, command tiers). Brand Guard's migration is parented on an uncommitted migration (`b8f2d6c4e9a1`); in a clean checkout it has a missing parent (HEAD's own head is `d8d42a912e06`). Code itself is self-contained (23/23 tests pass on HEAD + Brand Guard only). Revisit once the pending work is committed. A scripted HEAD-plus-only-my-edits staging approach is proven and reusable | None (ships existing Brand Guard page) |
| 0.2 | **DONE 2026-09-30** (30 Brand Guard tests pass; live-verified: 202 + progress bar, reload-resume, kill-and-restart recovery). Background scans: `brand_scan_runs` table, `POST /scan` returns immediately with a run id, job worker, status endpoint, UI progress/polling | Scan progress bar and "Scanning…" run status on Brand Guard home; status endpoint |
| 0.3 | **DONE 2026-09-30** (45 Brand Guard tests; migration `f7c2a9d4e1b6`; live-verified vs real crt.sh and a seeded outage). CT source hardening: retries with backoff, per-source health state, surfaced in UI, pluggable source interface | Per-source health strip (certificate feed degraded / retrying) on Brand Guard home |
| 0.4 | **DONE 2026-09-30** (67 Brand Guard tests; `backend/dev_live.py`, optional `DATABASE_SCHEMA`, opt-in `BRAND_GUARD_ENABLED`; live-verified; pytest no longer wipes live data). Dev hygiene: dedicated dev DB/fixture so live verification doesn't share the test DB | None (developer tooling) |
| 0.5 | **DONE 2026-10-01** (10 tests in `test_brand_guard_audit.py`; profile create/update/delete, manual scan start, every candidate status change and the one automated verdict that alerts — `candidate_flagged_suspicious`, no actor — are audited; no-op updates and rejected requests leave nothing; workspace erasure and a reviewer deleting their own account verified; entries appear in the enterprise audit-log API). **Audit + erasure coverage (gap in Phase 1 code):** write `audit_service.log()` entries for profile create/update/delete, scan runs and every candidate status change (the audit log exists and Phase 1 never calls it); add a tenant-erasure test proving the brand tables are removed on account deletion | Audit Log entries for profile/scan/status actions (Enterprise audit view) |
| 0.6 | **DONE 2026-10-01 — Stage 0 complete (0.1 commit deferred by the user)** (24 tests in `test_brand_cost_guard.py`; migration `c2d7a4e9b1f5`; whole backend suite 1,388 green; live: registry lookups per scan 50 → 3 → 0). Registration dates come from the candidate's own record, then a shared cross-tenant cache (14-day found / 6-hour miss TTL), then one throttled RDAP call; process-wide throttles for DNS (60), RDAP (6) and crt.sh (one at a time, 1s apart) plus a 15-minute per-token crt.sh cache; per-plan scan budget (starter 120 / pro+ 400 names), manual-scan quota (5/20/100 per day, enterprise unlimited) and per-tenant concurrency (1/3/6); execution slots (4) with a queue cap (25 → 503 + Retry-After); per-run `cost` and `budget` telemetry. DNS is deliberately NOT cached across scans (live state is the product). Scan cost/capacity guard: per-plan scan budgets, shared cross-tenant cache for RDAP/DNS/CT lookups (reuse the `DomainReputationCache` pattern), polite rate limits for crt.sh/RDAP, queue backpressure | Scan budget and "candidates tracked x of N" meter on the brand profile; plan upgrade prompt |

Exit: scan of a cold brand completes without holding an HTTP request; CT failure
degrades visibly; 0 regressions.

### Stage 1 — Ground truth & evaluation harness (gates all later claims)

| Step | Work | Surface (UI / API) |
|---|---|---|
| 1.1 | **DONE 2026-09-30** — see `BRAND_GUARD_DATA_SOURCES.md`. Approved: PhishTank (endpoint currently 404), URLhaus (malware only), Majestic Million, phishunt.io (CC0, brand-labelled, 89% brand-in-domain, no SA brands). OpenPhish free rejected (non-commercial). Snapshots fetched with `backend/tools/brand_corpus_fetch.py` into gitignored `backend/data/brand_guard_corpus/`. Decide and record data sources + licences (PhishTank/OpenPhish/URLhaus brand-labelled phish; Tranco negatives). **Decision gate: confirm terms/keys.** | None (internal; licence register) |
| 1.2 | **DONE 2026-10-01** (46 new tests; corpus `c-c3297e252edc`; 116 Brand Guard tests green) — `backend/brand_eval/` (domains, corpus, gold, review_queue), results in `BRAND_GUARD_DATA_SOURCES.md` §"Step 1.2 results". **Remaining human work: label the SA review queue (401 rows; 144 suggested first-pass).** Amended by 1.1 findings: add a hand-labelled South African gold set and a no-slug (homoglyph/typo) gold set; derive benign-lookalike negatives from Majestic itself; stratify all metrics by slug-in-domain and verdict tier. Corpus builder: brand-labelled lookalike positives, benign-lookalike negatives, temporal splits, stored as versioned fixtures | None (internal) |
| 1.3 | **DONE 2026-10-01** (14 tests incl. a mutation check; 130 Brand Guard tests green) — `backend/brand_eval/replay.py`; baseline results in this plan's "Baseline replay results" section. Replay harness: run discovery + scoring offline over the corpus | None (internal CLI/report) |
| 1.4 | **DONE 2026-10-01 — Stage 1 complete.** `backend/brand_eval/metrics.py` (Wilson intervals, per-stratum n + low-power flags, micro/macro views, illustrative precision, latency model, `compare` tool); frozen baseline in `BRAND_GUARD_BASELINE_REPORT.md`; 147 Brand Guard tests green; replay+metrics re-run byte-identical. **Note from 1.2:** test-split strata are tiny (e.g. 8 tld_swap positives in total), so report every rate with a Wilson confidence interval and the stratum size, and never a single headline figure. Metrics: generator hit-rate, precision/recall, false-positive rate, detection-latency proxy; baseline report for the Phase 1 scorer | Internal quality dashboard (baseline precision / hit-rate) |

Exit: a reproducible baseline number for Phase 1; every later stage reports a
delta against it.

### Stage 2 — Pre-content signal depth (deterministic)

| Step | Work | Surface (UI / API) |
|---|---|---|
| 2.0 | **DONE 2026-10-01** (new `safe_fetch.py`, `brand_fingerprint_service.py`, `brand_baseline.py`; migration `d8f3a5c1e7b2`; 57 tests in `test_brand_fingerprint.py`, 6 mutation checks caught; offline detection output byte-identical, 0 of 3,873 records differ). **Built:** a brand fingerprint built from the customer's own public site and DNS — page title/description/site name/language, favicon (SHA-256), social profile links, contact emails and phones, nameservers, server addresses, mail provider (from MX), hosting network (ASN via Team Cymru DNS) — stored on the profile (`POST /brand-guard/profiles/{id}/fingerprint`, audited, 6/min), plus hand-entered trademarks (kept for takedown/UDRP evidence; detection does not read them) and *suggested official domains* (the tenant's other domains, computed on read). **Used by the scorer:** a look-alike on the customer's own nameservers (-15) or server address (-15) gets a benign explainer that lowers its abuse score and says "probably yours — add it to official domains". **Safety guards:** an address match counts only when the customer is NOT on a shared platform (an attacker behind the same Cloudflare address must not look benign), and a shared DNS platform's nameservers count for -5, not -15; weights are hand-set and unmeasurable offline (Stage 3 calibrates). **Security:** the fetcher reads tenant-controlled domains from our servers, so it is SSRF-guarded: http/https on standard ports only, every resolved address must be globally routable, the connection is pinned to the validated address (Host + TLS server name carry the real name, defeating DNS rebinding), redirects re-validated per hop (max 3), TLS verified, 1 MB/8 s caps, errors never echo addresses. **Found by testing:** Python's `html.parser` was super-linear on hostile pages (16 KB of `<a href=` took 1.8 s) and an unbounded email regex took 15 s on a 300 KB run — a worker-stall risk — so parsing uses a small bounded linear scanner and token-limited email extraction, with regression tests. Live: dpd.com built in 3.7 s over real DNS/TLS (redirect followed, favicon hashed, Microsoft 365 and the hosting network identified). **Limits:** pages that build their content with JavaScript yield little (dpd.com showed no social links or contacts; headless rendering is Stage 7); no automatic refresh yet, so the baseline goes stale until rebuilt; logo matching and infrastructure-divergence scoring are NOT built (they wait for Stage 7 and calibration); the shared-platform lists are hand-curated. **Wire into onboarding:** the setup flow builds the fingerprint right after the profile is created, before the first scan. | Brand profile screen (editable fingerprint + "what we monitor"); onboarding step in guided setup |
| 2.0b | **DONE 2026-10-01 — measured in `BRAND_GUARD_2_0B_DELTA.md`** (213 Brand Guard tests; vendored Public Suffix List `app/data/public_suffix_list.dat`; new `app/services/public_suffix.py`; positives evaluated 11.3% → 83.4%, brand-weighted identity≥55 recall 25.9% → 75.2%, unrelated false matches 3 → 1; the free-hosting gain is conditional on hostnames being enumerable and the registered-domain gain is within noise). **Detector defects found by the 1.3 baseline — fix first, then re-baseline** (the documenting tests in `test_brand_eval_replay.py` will fail when each is fixed, by design): (a) **public-suffix handling** — `registrable_domain`/`split_registrable` only know `.za` second levels, so `x.com.br`→`com.br`, `x.co.uk`→`co.uk`, `x.com.au`→`com.au`; lookalikes under those suffixes are invisible AND a customer whose own domain is `.co.uk/.com.au/.com.br` gets nonsense permutations (it permutes the label `com`) — i.e. cannot be protected; use a bundled public-suffix snapshot. (b) **free-hosting platforms** treated as private suffixes so `brand-login.pages.dev` is a candidate, not `pages.dev`. (c) **short and common-word brands** — ≤3-letter brands never match by name; a common 4-letter word (`cash`) ties `visitlancashire.com` to the brand at identity 55. (d) CT-name path misses near-miss typos; permutation TLD swap list is small | Candidate list shows platform-hosted candidates; brand-profile warning when the brand name is ≤3 letters or a common word |
| 2.1 | **DONE 2026-10-01** (261 Brand Guard tests; migration `a3e8c1d5b7f2` with a tested stage backfill; new `app/services/brand_lifecycle.py`; live-verified on real DNS; offline name-based metrics unchanged, detector `4db9a9960e92`). Fixes A2-3 and A2-4 (dormant registered domains were dropped; only the latest state was stored). **Observation history + lifecycle model:** `candidate_observations` (append-only), stage state machine, transition events, velocity features. Fix A2-3: detect *registration* via NXDOMAIN-vs-NOERROR/NS/SOA so dormant registered domains are tracked | Candidate drawer lifecycle timeline; stage-ladder dots in list; "went live" events and alerts |
| 2.2 | **DONE 2026-10-01** (51 tests in `test_brand_guard_lexical.py`, 5 mutation checks caught; delta in `BRAND_GUARD_2_2_DELTA.md`). Surfaced positives **83.4% → 92.2%** (CIs do not overlap; test split 54.6% → 76.3%); alert-level identity 81.8% → 87.5% (within noise overall, 90.5% → 96.3% on free-hosting); false matches unchanged (1/3000; 22.4% popular lookalikes). **27 of the 43 newly reachable positives are one platform (weebly.com)**, fixed by a 20-entry supplemental platform list, not by the subdomain logic. Built: subdomain brand abuse via CT hostnames, tracked under the full host (official domain inside subdomain = 55, bare brand word = 35, intake cap 25/scan); ccTLD-mimic (`brand-co-za.com`, `brand.za.com`); word-order inversion with compound splitting; sound-alike and bit-squat (5+ letter names only); 19 Afrikaans/Zulu lure words (**hand-curated, needs a native-speaker review**); mixed-script detection (+15 abuse); no more fuzzy-similarity double counting on structural matches; word-frequency context from a vendored 100k popular-label list. **Tried and rejected:** a random-letter coincidence model (off by 3–4 orders of magnitude on real words) and a measured-frequency discount (lost 12 real phishing names to remove 12 hits, mostly google/amazon) — frequency is shown as context only. **Descoped:** path abuse needs a URL source, so it moves to 2.6b. **Unmeasured:** value of ccTLD-mimic/sound/bit/local-lure/mixed-script (no positives in public data) and the false-lead rate of subdomain abuse (negatives have no subdomains). **Open product question:** Starter's 120-name budget stops after homoglyph + combo names, so it never reaches the new classes (nor TLD swaps/typos for most brands) — decide interleaving in Stage 3. Live: 159-name scan on dpd.com OK and exposed bit-squat noise on 3-letter names (fixed); crt.sh returned 502 so the real CT path was not exercised live. | New threat-class chips (Fake .co.za, Words reordered, Sounds alike, Bit-squat, Brand in subdomain); evidence lines; subdomain-abuse candidates in list |
| 2.3 | **DONE 2026-10-01** (new `brand_mail_intent.py`; 29 tests in `test_brand_mail_intent.py`, 6 mutation checks caught — one first slipped through because a test never made the customer's own domain look registered, now fixed; offline detection byte-identical, 0 of 3,873 records differ; no migration — the facts live in the candidate's existing `enrichment`). For every existing, non-subdomain, non-platform, non-customer name a scan now reads SPF and DMARC (2 DNS queries) and, only when the name looks mail-capable (has an MX or an SPF record), 10 common DKIM selectors; a dormant name costs 2 queries. **Signals (abuse):** SPF published +5, DKIM published +5, DMARC published +5, bulk-mail service in SPF (SendGrid, Mailgun, SES, Mailchimp, …) +10, **cloned DKIM key** (same public key as the customer's) +10, forwarding-relay MX +5, same mail provider as the customer 0 (informative), and a **benign explainer**: `v=spf1 -all` with no mail host (how a careful owner parks a domain) -10. Positive intent is capped at +25 so mail setup can raise suspicion but never decide it alone. The customer's own SPF/DMARC/DKIM keys are recorded in the fingerprint baseline (rebuild the fingerprint to refresh existing profiles). Bulk-mail and forwarding lists are hand-curated; weights are hand-set and unmeasurable offline (Stage 3 calibrates). **UI:** the drawer now groups evidence as *Why we flagged this* / *Email intent* / *Evidence it may be harmless* — the last also surfaces the benign explainers from 2.0 ("on your own nameservers") and 2.2 ("registered 24 years ago") that were previously computed but never shown. Live on dpd.com (50 mail probes, scan time unchanged at 27 s): `d-pd.com` has SPF with Mailjet+Mailchimp, DKIM and DMARC (abuse 50); `cpd.com` recognised as parked-and-locked; `dpd.biz` flagged as on DPD's own nameservers; `pdd.com` uses Cloudflare Email Routing (weak signal — real companies use it too). **Limits:** DKIM selectors can be any string, so absence proves nothing; the lifecycle `mail_enabled` stage still means MX only (a send-only domain with SPF but no MX is not promoted — deliberate, to avoid changing the 2.1 state machine); no live phishing mail is observed (that is the first-party pivot, 2.6). | Drawer "Email intent" evidence lines ("set up to send mail as this domain") |
| 2.4 | **DONE 2026-10-02** (new `brand_infra_signals.py`; migration `e9a2c6d4b8f1`; 48 tests in `test_brand_infra_signals.py`, 8 mutation checks caught — two slipped through at first because of test gaps, fixed; offline identity/reach/threat class byte-identical, only 17 cheap-suffix records gained the new abuse-side `high_abuse_suffix` signal). **Registration:** RDAP now yields the registrar (shown for abuse reports, never scored), re-registration events (+10, a dropped name caught again), last-change and expiry; stored in the shared cache (`details` JSONB) and carried on each candidate; a small cheap-suffix prior (+5) — checked against the corpus first: 15.3% of suspected phishing hosts (17/111) vs 7.2% of popular domains, ~2x, directionally supported. **Certificate:** the CT source now keeps certificate ids and issuer; a certificate within 24 h of a registration under 90 days old reads as automation (+8). **Hosting:** www CNAME to a *free site/app host* (pages.dev, github.io, netlify.app, weebly… 46 named hosts) +5. **Campaign clusters** (only among names that already resemble the brand): registered within 30 minutes of another look-alike (+6 pair / +10 three or more), one certificate over several look-alikes (+8), identical non-shared nameservers across 3+ (+6), same server across 3+ when its network owner is *positively known to be dedicated* (+6); capped at +14. **Safety guards:** a cluster touching the customer's own infrastructure (or a parked-and-locked domain) scores NOTHING and says "may be your own defensive batch"; shared DNS platforms and unknown/CDN server owners never form clusters. **Found live (dpd.com, real RDAP/DNS/ASN):** (1) the first CNAME rule flagged DPD's own www.dpd.co.uk (Akamai `edgekey.net`) and dps.com (Azure) as 'free hosting' because the Public Suffix List's private section also lists CDNs and clouds — restricted to a named list of free site hosts, with a regression test; (2) candidates scored before 2.4 had a creation date but no registrar, so they would never have been looked up again — they now get exactly one backfill lookup (scan 1: 47 RDAP lookups; scan 2: 0). The live scan also showed the benign guard working: 23 look-alikes of dpd.com formed clusters, and the ones sharing DPD's nameservers were recognised as its own defensive portfolio and scored nothing. **Known issue — FIXED 2026-10-02:** the older `platform_hosted` signal (2.0b, +10 abuse) treated every Public Suffix List private suffix as 'free hosting' and so also fired for names directly under CDN/cloud suffixes; it now scores only the named free site hosts (+ free-subdomain and dynamic-DNS services such as eu.org, dpdns.org, duckdns.org), and other platforms get a 0-weight `cloud_platform_hosted` context line (10 tests, mutation-checked). Weights are hand-set; Stage 3 calibrates. **Limits:** clustering only sees names the scan evaluated; no reverse-IP lookup beyond the scanned set; registrar priors deliberately not scored. | Drawer *Registration and hosting* and *Possible campaign* groups (siblings named, defensive-batch note); registrar line for abuse reports |
| 2.5 | **DONE 2026-10-02 — paid sources deliberately SKIPPED by the user's decision ("Skip for now"); the scorer can take blocklist evidence from a paid source later without redesign** (new `brand_popularity.py`, `brand_corroboration.py`, `brand_feeds.py`; 34 tests in `test_brand_corroboration.py`, 7 mutation checks caught; no migration). **Built:** (1) *Popular site* benign explainer: a registered look-alike that is itself in the Majestic top 100,000 gets -25 (top 10k) / -15 — measured first: only 2 of 488 suspected-phishing hosts (0.4%) sit on such a domain and both are multi-tenant platforms (hashnode.dev, a CDN), so the discount NEVER applies to a subdomain host or a name under a hosting platform; offline it touches 0 of 488 phishing hosts and 222 of 388 popular look-alikes. (2) *Parked* benign explainer: nameservers of parking/for-sale services (Sedo, ParkingCrew, Bodis, Afternic, …; hand-curated) -8, said to stay on watch because a parked name can be re-pointed. (3) *On a blocklist* corroboration from two free, CC0, commercially usable feeds — phishunt.io (+30, +35 when it reports other services also flag the URL; automated, NOT human-verified) and abuse.ch URLhaus (+30, malware distribution): two whole-list downloads at most every 30 minutes (not one request per candidate), in-memory index, exact-host or same-registered-domain match, failures recorded in the same source-health strip (both show there), stale data kept up to 6 h then dropped so an outage cannot corroborate forever; capped at +40. (4) List chips: *On a blocklist*, *Popular site*, *Parked*, *Your infrastructure*, *Locked down*, derived from the evidence so the list never disagrees with the drawer. The step 2.0/2.4 'same nameservers / same server' explainers were already built. Live on dpd.com (real downloads): both feeds healthy (586 ms / 928 ms, 757 + 557 hosts), 5 parked names, `dpd.co.uk` flagged popular (it is DPD UK's own site — wording made neutral: 'may even be yours, add it to your official domains'), 0 blocklist hits (none of the candidates is a phishing site). **NOT built — decision gate, resolved 2026-10-02 as 'skip for now':** DNS blocklists (Spamhaus DBL / SURBL / URIBL — their free tiers exclude commercial use, a paid data feed is required) and Web Risk / VirusTotal (paid API keys, per-query cost). **Not built — other stages:** redirect-to-brand needs a web request (Stage 7); Tranco rank was replaced by Majestic (Tranco's default list includes non-commercial providers). **Limits:** the feeds are recent-activity lists (≈750 phishunt hosts, ≈550 URLhaus hosts), so absence proves nothing; parking lists are hand-curated; weights are hand-set (Stage 3). | Drawer "Evidence against" list (already shows these); corroboration chips in the candidate list |
| 2.6b | **PARTLY DONE 2026-10-02 — the free new-registration source AND the live certificate stream are built; zone files (CZDS, parked by the user), `.za` data (rejected) and a paid full new-registration feed are not.** (new `brand_nrd.py`; 21 tests in `test_brand_nrd.py`, mutation-checked; no migration.) **Built:** WhoisDS free daily newly-registered-domain list (publisher states reuse incl. commercial, no licence/payment) — one 0.5 MB zip a day, last 3 days kept in memory, a day that fails is retried after 2 h, the newest list not yet published is not a failure, zip-bomb/size caps, shown in the source-health strip; matched against each brand with the same name rules as certificate hits (cached per day, run off the event loop; ~1-3 s per brand per day first time); same plan gate as certificate monitoring; candidates carry source chip *New registration* and the list day. **Measured live (real list, 3 days, 210,000 names):** dpd 6 leads, amazon 17, microsoft 6, paypal 1, capitec/standardbank 0. A live dpd.com scan found `dpd-paketservicezentrum711/714/727/729/730.ink` — a five-name batch (abuse 84) — and `dpd-cz.live`, none of which any permutation list could produce. **Honest limits:** the free list is a SAMPLE — exactly 70,000 names a day against roughly 250,000+ registrations — so it covers a minority of new names; it is published the day AFTER registration (detection is next-day, not minutes); a lead is only a lead and goes through normal scoring. **NOT built — decision gates:** (1) streaming CT (CertStream): the public calidog server is documented as not for non-experimental use and has had outages; a production stream needs our own CertStream server or direct CT-log reading as a long-running worker process — an architecture/ops decision; (2) ICANN CZDS gTLD zone files: needs an ICANN account and per-TLD approval from each registry, access expires every 90 days and renewals/redistribution are restricted — needs the user's account and a legal read of the terms; (3) `.za` registry data: no public bulk source found — would need ZACR agreement; (4) paid full NRD feed (WhoisDS paid tier etc.) to remove the 70k sample cap. **User decisions 2026-10-02:** (1) streaming CT = YES, as a separate long-running worker (own CertStream server or direct CT-log reading) — build after 2.6; (2) ICANN CZDS = come back to it later; (3) `.za` registry data = not pursued (random-name probing rejected: ~2e11 candidate 8-letter names vs ~1M registered, and it is abusive load; CT + the new-registration list cover it, revisit only if `.za` proves a blind spot); (4) paid NRD feed: only verified price is WhoisDS paid $399/month, undecided. **Streaming CT: BUILT 2026-10-02 (the user's decision 1).** A separate worker `python -m app.workers.ct_stream` follows tiled CT logs (Google ParcelYard + Let's Encrypt Willow, across all current and upcoming expiry shards, re-resolved from the public log list every 6 h) and feeds matching names through the normal pipeline within seconds: measured live, lag 2-7 s behind the log head, ~400 entries/s, ~56 GB/day inbound, restart resumes from saved cursors. New: `ct_tiles.py`, `ct_log_list.py`, `brand_ct_stream.py`, `workers/ct_stream.py`, migration `a4c8e2d6b1f3`, `process_stream_hits`, 82 tests, 18 worker mutations + the matcher property tests all caught. Found on the way: my first prefilter proof was wrong (`papyal.com` is one swap from `paypal` and shared no 3-letter window) — caught by a test, fixed with one-swap variants; and `token_match` spent ~700 µs per 4-5 letter token on an affix loop, now guarded (identical results: replay of the 3,876-record corpus byte-identical). Runbook, numbers, limits and operator decisions: `BRAND_GUARD_CT_STREAM.md`. **Path abuse** (URLs, not names) still waits for a URL source (Stage 7). | "Found via" chip: Certificate / New registration / Permutation; next-day alerts for brand look-alikes |
| 2.6 | **DONE 2026-10-02** (new `brand_firstparty.py`; 30 tests in `test_brand_firstparty.py`, 17 mutation checks, the one survivor is a defence-in-depth tenant filter that domain uniqueness makes redundant; no migration). First-party evidence only this account has. **(1) Reported phish:** the domains in emails the customer's own people forwarded (last 90 days, up to 300 emails, tenant-scoped) become candidates when the email names the brand (whole-word match on subject/body/sender) or the domain's name matches it; emails marked *false positive* are ignored, *confirmed malicious* weighs more; own domains, raw IPs and well-known sites (shorteners, mail providers) are skipped, but a subdomain on a hosting platform is kept; at most 40 hosts per scan, most-reported first, 3 emails kept per host. Evidence: *reported_by_employee* +20 (+35 confirmed) and, when the email names the brand but the domain's name does not, *reported_brand_mention* +45 identity — so a lure like `parcel-fee-check.xyz` that no name rule would flag still becomes a candidate. Nothing about the reporter is read or stored (only the email id, disposition and time). **(2) DMARC pivot:** server addresses that sent mail as the customer's domain and failed authentication (rollups classified spoof/unauth, last 90 days) are compared with each candidate's server address: same address +15 (+7.5 on a shared host), same network +6 (never on big shared hosts/clouds); network lookups for at most the 30 busiest spoofer addresses, cached 12 h. Chips *Reported by your team* and *Same network as a spoofer*, drawer group *From your own reports*, source chip *Reported email*. **Live (dev schema, synthetic reported email naming the real new-registration lure dpd-paketservicezentrum711.ink):** it gained the evidence and its abuse score rose 84 → 100; the synthetic email was removed. A reported name that does not exist is NOT kept (no DNS, no registration: a dead lure is not worth a row). Offline eval: results byte-identical (first-party evidence is not in the public corpus). **Limits:** the DMARC rollup in the dev data has no spoofers, so that pivot is verified by tests only; there is no page in the app to open a reported email yet (the candidate shows the email id and time; linking waits for a reported-email page); sender-domain leads trust the claimed From of a forwarded message. | "Reported by your team" and "Same network as a spoofer" chips; drawer group "From your own reports" |

Exit: harness shows measurable precision/recall gain vs Stage 1 baseline;
dormant→active transitions visible in the UI timeline.

### Stage 3 — Reasoning core

| Step | Work | Surface (UI / API) |
|---|---|---|
| 3.1 | **DONE 2026-10-02** (with step 3.0, a measurement step added because abuse cannot be calibrated offline). Replace additive points with calibrated likelihood-ratio combiner: prior, explainers, abstain state | Confidence label with band in list and drawer (replaces raw scores) |
| 3.2 | **NOT BUILT: blocked on real outcome labels; reserved for last (ordering decision 2026-10-03).** Calibration against the harness (isotonic/Platt); conformal error guarantee option | "Uncertain" state; calibration note in drawer; internal calibration report |
| 3.3 | **DONE 2026-10-02** (`brand_derivation.py`). Declarative rule layer emitting derivation trees; UI "why" shows the proof | Drawer "Why" shows the derivation, each step linked to its raw fact |
| 3.4 | **Threat taxonomy + impact:** classify abuse type (benign / trademark / impersonation / fraud / phishing / malware) separately from resemblance, add customer-impact and audience reach, plus an **attack narrative** ("fake domain → cloned login → credentials") in the shape PathProof uses | Abuse-type chip (phishing/fraud/trademark), impact badge, attack-narrative card in drawer |

**Status 2026-10-02:** step 3.1 is built and 3.0 (a measurement step added because abuse cannot be calibrated offline) is done: PARTLY DONE 2026-10-02 (3.0 measurement + 3.1 evidence-ratio combiner with abstain; see `BRAND_GUARD_STAGE3_MEASUREMENT.md`). 3.2 (probability / conformal) is blocked on real outcome labels; 3.3 (derivation proof tree, `brand_derivation.py`) and 3.4 (threat taxonomy, impact, attack narrative, `brand_taxonomy.py`) DONE 2026-10-02. Headline: the live-ness weights did not survive measurement and were dropped from the abuse score; the abuse score now reads one measured table, and the combiner abstains when strong evidence conflicts.

Exit: stated confidence is calibrated on held-out data; "abstain" exists and is
measured.

### Stage 4 — Infrastructure graph & campaigns

**Ordering decision 2026-10-03 (user):** all data-labelling and model-training work is reserved for LAST: 3.2 calibration, 5.1 discriminator, 5.2/5.3 learned strategies, 5.5 retraining, the SA labelling CSV and the mail-signal re-measurement. Everything else runs first.

**Status 2026-10-02:** 4.1, 4.2 and 4.3 DONE (`brand_graph.py`, migration `b5d9f3a7c1e4`, cluster graph on the Campaigns screen); 4.4 is a decision gate, brief at `BRAND_GUARD_STAGE4_DECISION_BRIEF.md`, nothing cross-tenant built.

| Step | Work | Surface (UI / API) |
|---|---|---|
| 4.1 | **DONE 2026-10-02** (`brand_graph.py`, migration `b5d9f3a7c1e4`). Graph tables (domain/IP/NS/cert/registrant/batch) in PostgreSQL. First evaluate reuse of the existing Attack Path Graph primitives (`routers/graph.py`, cloud asset/path models) so ZoneProof and PathProof share one evidence-graph core | None (data layer) |
| 4.2 | **DONE 2026-10-02.** Clustering + guilt propagation from known-bad seeds (decaying) | Cluster hints in drawer ("2 domains share this nameserver pair") |
| 4.3 | **DONE 2026-10-02** (cluster graph on the Campaigns screen). Campaign view in UI; one hit surfaces its cluster | Campaigns screen and cluster card; campaign drill-down |
| 4.4 | **DECISION GATE: brief written (`BRAND_GUARD_STAGE4_DECISION_BRIEF.md`), nothing cross-tenant built.** **Decision gate:** POPIA review, then indicator-only cross-tenant intelligence | None until approved; then "seen targeting other brands" badge (indicator-only) |

### Stage 5 — Adversarial generator / discriminator loop

| Step | Work | Surface (UI / API) |
|---|---|---|
| 5.1 | **NOT BUILT: reserved for last (training work).** Plausibility discriminator (GBDT + char model) trained on the Stage 1 corpus | None (internal); fewer, better candidates in list |
| 5.2 | **NOT BUILT: reserved for last.** Bandit allocation over generator strategies; hit-rate tracked per strategy | Internal strategy hit-rate report; "how we found this" chip |
| 5.3 | **NOT BUILT: reserved for last.** Learned char-level sampler; diversity constraints (anti mode-collapse) | None (internal) |
| 5.4 | **NOT BUILT** (needs provider, budget and attacker-text decisions). LLM generator (brand/product/exec/market/language-aware) feeding the same loop; DNS/CT verification remains the oracle | "Suggested by AI" chip on generated candidates; coverage stats on Brand Guard home |
| 5.5 | **NOT BUILT: reserved for last.** Adversarial hardening: generator evasions → retrain threat discriminator; held-out real-registration stream guards feedback loops | None (internal); robustness metric on quality dashboard |

Exit: measured hit-rate lift over the rule-only generator on held-out data.

### Stage 6 — LLM reasoning layer (constrained)

| Step | Work | Surface (UI / API) |
|---|---|---|
| 6.1 | **NOT BUILT** (needs provider and budget decisions). Evidence-grounded case narrative + plain-English "why" (structured output, abstain) | Case narrative at top of drawer/case, each claim linked to its evidence line |
| 6.2 | **NOT BUILT.** Text understanding: WHOIS free text, cert org fields, reported-phish lure classification, multilingual | Extra evidence lines (WHOIS/cert text, lure type of reported phish); multilingual labels |
| 6.3 | **NOT BUILT.** Agentic investigator: tool-using, budgeted, every finding tool-sourced, full trail stored | "Investigation trail" tab in drawer showing every tool call and raw result |
| 6.4 | **NOT BUILT** (must precede any of 6.1 to 6.3). **Prompt-injection and poisoning defences:** all WHOIS text, cert fields, reported emails and page text are attacker-controlled → treated strictly as data; read-only tool allowlist for the investigator; output schema validation; injection test suite. Guard cross-tenant learning against label poisoning | None (security control); injection test suite in CI |

### Stage 7 — Light-touch probes, then renderer

**Status 2026-10-07:** 7.1 APPROVED by the user (option A, a dedicated egress worker; brief `BRAND_GUARD_STAGE7_EGRESS_DESIGN.md`). 7.2 BUILT, OFF BY DEFAULT behind a kill switch (`brand_probe_enabled` + `brand_probe_key`): signed worker protocol and job queue (`brand_probe_protocol.py`, `brand_probe_queue.py`, `/probe-worker/*`, migration `b2d6f0a4c8e1`), the worker program (`backend/probe_worker/worker.py`), result analysis (`brand_probe_analysis.py`: redirect chain, password forms and where they post, favicon match, served certificate vs CT, challenge pages), evidence wired into scoring/verdict/attack narrative, drawer section. Runbook `BRAND_GUARD_PROBE_WORKER.md`. NOT done: JARM; 7.3 renderer and 7.4 similarity; deploying a worker machine (the user's task); probe weights are expert-set assumptions. No real request to a suspect host has been made by this session: the worker's network code is tested with fakes only.

**Status 2026-10-08:** 7.3 BUILT, OFF BY DEFAULT behind a second switch (`brand_render_enabled`, on top of the probe switch). Renderer `backend/probe_worker/render_job.py` (headless Chromium, one throwaway container per job, image `Dockerfile.render`, container flags built by `worker.build_docker_command`: read-only, all capabilities dropped, memory/CPU/process limits, no mounts, no environment, no signing key) with request policy `render_policy.py` (GET/HEAD only so no form can be submitted, ports 80/443, public addresses, 60-request ceiling, service workers/downloads/dialogs/popups blocked). API side: render job kind and queue (`brand_probe_queue.enqueue_render`, only for pages the light probe found interesting or confirmed cases; 10/tenant/day, once per host per 7 days), result cleaning (`clean_render`: image signature check, caps, control characters stripped), rendered-page analysis (`analyse_render`/`merge_render`: forms after scripts run, new zero-weight line `page_form_after_scripts`, no new score weights), encrypted capture storage `brand_page_captures` (migration `c3e7a1b5d9f4`, Fernet, last 3 per look-alike, 30-day retention purged hourly except for cases, tenant-scoped), endpoints `GET /brand-guard/candidates/{id}/capture` and `/capture/screenshot` (image-only headers), drawer section "How its page looked" (screenshot, forms, redirects, untrusted text shown escaped, retention note). Checked: the renderer runs in a real Chromium against a loopback fixture (script-built form seen, script POST never reaches the server, DOM-clobbering resistant, service workers blocked), 41 mutation checks on the safety code (all real gaps closed; the rest equivalent). Runbook updated. NOT done: 7.4 similarity; the screenshot is not in the evidence pack yet; JARM; deploying the worker machine, building the image and the host firewall rule that blocks private ranges for the `zp-render` network (the user's task: a browser does its own DNS lookups, so the firewall is the hard control against DNS rebinding); no real suspect host has been rendered by this session.

**Status 2026-10-09:** 7.4 BUILT (same switches as 7.3; write-up and measurements in `BRAND_GUARD_STAGE7_SIMILARITY.md`, reproducible with `backend/brand_eval/similarity_synthetic.py`). Similarity is a feature, never a verdict: `brand_similarity.py` (pure; header-checked, size-capped image handling; 64-bit icon hash, 256-bit layout hash, accent-colour palette, hashed three-word wording), brand reference in `fingerprint["similarity"]` (brands need a fingerprint rebuild) plus a `ref` render job of the customer's own page (`brand_reference_captures`, migration `d4f8b2c6e0a1`), look-alike comparison in `analyse`/`analyse_render`, evidence lines `page_icon_lookalike` (+8), `page_copies_wording` (+10, +14 when 70%+ is shared) and `page_looks_like_brand` (**weight 0**), side-by-side "Your page / This look-alike" in the drawer. MEASURED (synthetic only): icon hash separates cleanly (threshold 0.10 caught 98% of re-sized/re-encoded copies with 0 of 3,422 unrelated pairs near); the whole-page layout hash does NOT survive (same-template pages from other brands are as close as real clones), and adding accent colours removes those false matches but catches only 52 to 70%, so the page look is shown and unscored. NOT done: any measurement on real phishing pages (needs labelled screenshots, part of the data work reserved for last), VLM judgement (Stage 6), logo extraction from a page, the screenshot in the evidence pack, JARM.

**Status 2026-10-10:** Funnel counters BUILT (`BRAND_GUARD_FUNNEL.md`; foundation for 9.2, not the whole of it). Table `brand_funnel_counts` (migration `e5a9c3d7f1b2`): per brand per day per stage, entered / passed / a small detail of why items did not pass; counts only, never domain names; atomic upsert; a failing counter never breaks a scan (`record_safe`). Hooks at the existing decision points: names found by source and cut by the plan budget; the live-name filter (not registered, plan cap, customer-owned); scoring split; who is picked for a visit and why not (visited recently, not similar enough, daily cap); light-probe outcomes; who is picked for a render and why not; render outcomes; jobs expired unclaimed (worker down or behind); icon, wording and layout resemblance. `GET /brand-guard/funnel` and the page Brand Guard, Insight, Funnel (stages with in/out, reasons, daily bars, "off until the worker runs" markers, and the not-built list beside the stage it belongs to). 43 mutation checks on the counting rules: 42 caught, 1 equivalent. Verified live on dev with a real scan of the Acme brand: 317 names found, 313 new names examined and all dropped as not registered, 5 known candidates re-scored. NOT done: the audit sample (send a small random share of what each filter drops through the next stage anyway, to measure what the filters wrongly drop: the volumes here say how much each filter drops, not whether it dropped the right things), a funnel-shaped visual, a compact strip on the Brand Guard Overview, an alert when jobs expire unclaimed, an MSP roll-up.

| Step | Work | Surface (UI / API) |
|---|---|---|
| 7.1 | **APPROVED 2026-10-07** (option A, dedicated egress worker). **Decision gate:** isolated-egress design (per `ARCHITECTURE.md`) approved | None (infrastructure decision) |
| 7.2 | **BUILT 2026-10-07, OFF BY DEFAULT** (kill switch; JARM not done; worker machine not deployed; no real suspect host has been probed). (SSRF/egress safety applies to every probe: block private/link-local ranges, DNS-rebinding checks, hard timeouts, size caps) Light probes: served TLS cert vs CT, HTTP HEAD/redirect chain, favicon hash, JARM | Drawer probe lines (served cert, redirect chain, favicon match) |
| 7.3 | **BUILT 2026-10-08, OFF BY DEFAULT** (second switch; renderer image and host firewall are the operator's task). Sandboxed renderer: screenshot, DOM/text, forms, redirects | Screenshot, detected forms and redirect chain in drawer; "analysed in isolation" note |
| 7.4 | **BUILT 2026-10-09** (page look shown at weight 0; only measured on synthetic data). Visual/logo/page similarity; optional VLM judgement as a *feature*, never a verdict | Logo/page similarity evidence lines; side-by-side screenshot compare |

### Stage 8 — Response

**Status 2026-10-06:** 8.8 DONE: Overview 'Brand protection' card (needs a decision, open cases, new in 24 h, went live; links to Brand Guard); a brand-exposure pillar in the Sentinel score (`brand_exposure.py`, weight 15, None-means-absent so a tenant without a scanned brand sees no change; penalties are expert-set assumptions and are returned with the score); a 'Brand impersonation exposure' section in the PDF report that lists what moved the number; the pillar is also on the MSP client summary. Stage 8 is complete (8.4 logos aside). Open question: scheduled reports reuse the report data, so they inherit the section; not separately verified. 8.7 DONE: notification channels (email, Slack, Teams, signed webhook) with severity threshold, daily summary, delivery log, test message, encrypted addresses (`brand_notify.py`, `brand_notify_dispatch.py`, migration `a1c5e9b3d7f2`, `/brand-guard/notifications` screen); alerts are dispatched after each scan and stream flush, once per channel, and a channel failure never fails a scan; SIEM export (JSON lines / CEF) for the Enterprise plan. Customer URLs: https only, Slack and Teams restricted to those services' hosts, a webhook host must resolve only to public addresses at send time, redirects never followed. Digests ride the hourly Brand Guard job, which only runs when `brand_guard_enabled` is on. In dev with no SendGrid key an email 'delivers' by being logged. 8.5 DONE (Defend screen `/brand-guard/defend`: block-rule exports for Microsoft 365 PowerShell, DNS RPZ, Chrome/Edge policy, plain list and CSV from confirmed look-alikes, optionally unreviewed likely ones; assisted reporting links for Google Safe Browsing, SmartScreen and Netcraft with a tracker; migration `f9b3d7e1a5c8`; nothing is submitted for the person; report-page addresses are unverified). 8.6 DONE as a stated prior, NOT the learned generator ranking (Stage 5 is reserved for last): `brand_defensive.py`, `GET /brand-guard/defensive-registrations`, DNS-checked shortlist labelled 'appears unregistered: confirm with your registrar'. 8.4 DONE except logos: MSP roll-up (`GET /msp/brand-guard`, `/msp/brand-guard` screen: per-client brands, need-a-decision, open cases, overdue, last scan, most urgent first) and a white-label evidence pack (`/msp/clients/{id}/brand-guard/candidates/{cid}/evidence-pack`, 'Prepared by <MSP>' line, audit-logged against the MSP, needs the white_label feature). The client's logo is NOT embedded: rendering an arbitrary logo URL in the server-side browser is an SSRF risk, so it needs an upload-and-store design first. 8.3 DONE in its safe form: contact discovery from public RDAP (registrar and host abuse contacts, Cloudflare form), `.za` suggested route (no invented contacts; ZARC/ISPA wording is a prompt to confirm, not a verified contact), editable draft complaint in the third person, required approval, record of sent/acknowledged/removed/rejected, audit-logged (`brand_takedown*.py`, migration `e8a2c6d0f4b7`, 'Take it down' section in the drawer). ZoneProof does NOT send: the person sends it. In-product sending is a decision for the user. 8.2 DONE (evidence pack: `brand_evidence_pack.py`, `GET /brand-guard/candidates/{id}/evidence-pack?format=pdf|json`, SHA-256 over canonical content, lists what was not checked, audit-logged; download buttons in the drawer; PDF via the shared Playwright renderer; the white-label variant belongs to 8.4). 8.1 DONE, including the Cases screen (`/brand-guard/cases`: Open / Came back / Closed groups, soonest deadline first, owner, 'Only mine'; list API `?status=cases`): assignment (owner select in the drawer, `?assigned_to=me|none` filter), response deadline (assumed 4/24/72 h by urgency, `brand_cases.py`), case timeline lines (decision changes, assignment), and resurrection monitoring (a person-closed `removed` case that resolves again reopens as `monitoring` with a critical alert). Migrations `c6e0a4b8d2f5`, `d7f1b5c9e3a6` (the deadline keeps the allowance it was set with). The resurrection pipeline hook is covered only by its pure rule, not an end-to-end scan test.

| Step | Work | Surface (UI / API) |
|---|---|---|
| 8.1 | **DONE** (2026-10-06 status below). Case workflow expansion (assignment, SLA, timeline, resurrection monitoring) | Cases screen (assignment, SLA, timeline, resurrection alerts) |
| 8.2 | **DONE.** Evidence pack: PDF/JSON with content hash, reuses the PDF service | "Download evidence pack" (PDF/JSON) in case and drawer |
| 8.3 | **DONE in its safe form: drafts, approval and tracking; ZoneProof never sends.** Takedown assistant: registrar/host/CDN abuse contact discovery, `.za` routes (ZARC, ISPA), draft complaint, **human approval before anything is sent** | Takedown composer: recommended route, pre-filled complaint, required approval step, outcome tracking |
| 8.4 | **DONE except client logos** (needs an upload-and-store design; fetching a logo URL is an SSRF risk). MSP roll-up and white-label evidence pack | MSP roll-up view; white-label evidence pack |
| 8.5 | **DONE** (nothing is submitted for the person). **Disruption without waiting for a takedown:** one-click blocklist export for the customer's mail/web filters (M365/Google allow-block lists, DNS RPZ, browser), and assisted submission to Google Safe Browsing/Microsoft SmartScreen/Netcraft/PhishTank — usually faster than a takedown, and a natural fit for a DMARC product | Defend screen: blocklist exports, assisted submissions, submission tracker |
| 8.6 | **DONE as a stated prior, not the learned ranking** (that is Stage 5). **Defensive-registration advisor:** rank the lookalikes *worth buying first*, using the generator's likelihood ranking — turns the discovery engine into proactive advice | Defend screen: ranked "worth registering" list |
| 8.7 | **DONE.** Notifications and integrations: email/Slack/Teams/webhook, scheduled digests, SIEM export (Enterprise) | Notification settings (email/Slack/Teams/webhook), digests; Enterprise SIEM export |
| 8.8 | **DONE 2026-10-06.** Product coherence: fold brand exposure into the Overview dashboard, the Sentinel posture score and the PDF/scheduled reports, so email security and brand exposure read as one picture | Overview Brand Guard card; Sentinel score component; section in PDF/scheduled reports |

### Stage 9 — Learning loop & productisation

| Step | Work | Surface (UI / API) |
|---|---|---|
| 9.1 | **NOT BUILT: reserved for last.** Analyst decisions → labels; active learning queue; scheduled recalibration with drift alarms | Labels captured from triage clicks; active-learning review queue (internal) |
| 9.2 | **NOT BUILT** (funnel counters, 2026-10-10, are the foundation only). Metrics dashboard (precision, hit-rate, detection latency, takedown acceptance, resurrection rate) | Metrics dashboard (precision, hit-rate, time to detect, takedown acceptance) |
| 9.3 | **NOT BUILT.** Retire Tier A lookalike scan (A2-8); migrate its findings. Also dedupe `domain_age_service.py` against the identical RDAP/`.za` WHOIS code in `link_risk_service.py` once that module is committed | Retirement notice; migrated findings appear as candidates |
| 9.4 | **NOT BUILT.** Pricing/plan-gate review, docs, runbooks, retention policy | Plan comparison page, docs/concept cards, runbooks |

---

## Part E — Audit of this plan (what the first draft missed)

Found by checking the plan and Phase 1 code against the original research and
the repo. All are now folded into the stages above.

1. Brand fingerprint and customer baseline (research §28-30) — only partly covered → **2.0**.
2. Streaming CT and newly-registered/zone-file sources — the main early-detection and coverage lever was absent → **2.6b**.
3. Audit log not written by Phase 1 code (`audit_service.log` never called) and no erasure test → **0.5**.
4. Cost/capacity and upstream rate-limit model → **0.6**.
5. Threat taxonomy, customer impact, attack narrative (research §31-32, §39) → **3.4**.
6. Reuse of the existing evidence-graph code instead of a parallel one → **4.1**.
7. Prompt-injection, SSRF and label-poisoning defences → **6.4, 7.2**.
8. Disruption levers besides takedown (filter blocklists, browser/SmartScreen submission) and the defensive-registration advisor → **8.5, 8.6**.
9. Notifications/integrations and Sentinel-score/report integration → **8.7, 8.8**.
10. Trademark data for UDRP evidence → **2.0**.

### Deferred register (nothing silently dropped)
Research threat classes 6–10 — executive/social impersonation, fake apps, fake
ads, marketplaces/counterfeit, dark-web and credential exposure — and
display-name/free-mail BEC impersonation are **out of scope for this plan**.
They are revisited after Stage 8 using the same candidate/evidence/case core.

---

## Baseline replay results (step 1.3) — corpus `c-c3297e252edc`, detector `01220ce911b6`

Run: `python -m brand_eval.replay`. Replays the CURRENT detector's discovery and **identity** scoring offline; **abuse scoring, status and alerting are not measurable offline** and are not simulated. Counts only — confidence intervals arrive in step 1.4. Test-split strata are tiny, so treat every rate as indicative.

| Positives (488 suspected-malicious) | n | reached by permutation set | reached by CT-name match | evaluated at all |
|---|---|---|---|---|
| all | 488 | **0** | 55 | **55 (11%)** |
| on free hosting | 377 | 0 | 0 | **0** |
| not on free hosting | 111 | 0 | 55 | 55 |
| brand name in the registered domain | 423 | 0 | 55 | 55 |
| TLD swap | 8 | 0 | 0 | 0 |
| brand only in subdomain / path / nowhere | 29 / 8 / 20 | 0 | 0 | 0 |

Why the other 433 were never evaluated: **377** because the detector collapses a free-hosting host to the platform apex (`pages.dev`), **56** with no name match for the detector (29 brand-in-subdomain, 8 TLD-swap/multi-label suffix — all 8 were `roblox.com.xx` collapsing to `com.xx`, 3 more `.com.br/.com.cn`, 2 short brand names).

Reading these numbers honestly:
- Permutation reach of 0 does **not** show the generator is useless: the corpus has **no** typo/homoglyph positives (feed bias, see data-sources register). It shows real phishing in this feed uses brand-containing names, which only the CT-name path sees.
- CT-name reach assumes the hostname's certificate is in the CT logs; whether platform-hosted names appear there is unmeasured.
- "Popular lookalikes" (388; legitimate popular domains resembling a brand): 210 would be surfaced (124 of the 126 brand-containing ones, with identity ≥ 55). They are expected false-positive *exposure* — whether they alert depends on abuse scoring (not measurable here).
- **Unrelated popular domains wrongly tied to a brand: 3 / 3000** — `freespins.com.co` (a bug effect: Bradesco/Itaú's `.com.br` domain yields permutations of `com`), `wbay.com` (a genuine typo-lookalike of eBay), `visitlancashire.com` (common-word brand `cash`).

**Defects the baseline exposed** are step 2.0b above; the most serious is multi-label public suffixes, which affects customers on `.co.uk`, `.com.au`, `.com.br`, `.co.in` etc. — a product bug independent of the evaluation.

### Stage 1 exit criteria — met

- A reproducible baseline for the Phase 1 detector: `BRAND_GUARD_BASELINE_REPORT.md` (corpus `c-c3297e252edc`, detector `01220ce911b6`); re-running replay + metrics reproduces the same SHA-256s.
- Every later stage reports a delta with `python -m brand_eval.metrics compare <baseline-run> <new-run>`, which only calls a change an improvement or regression when 95% Wilson intervals do not overlap (verified by a mutation test).
- Standing caveats to carry forward: labels are suspected not verified; only the name-based identity stage is measurable offline; no homoglyph/typo positives and no South African brands in the public data (SA gold set awaits human labels).

### Step 2.1 — what exists now, and what it cannot yet show

- **Ladder:** unregistered → registered → resolving → mail-enabled → certificate issued (`serving` and `weaponized` are Stage 7). Registration is observed through DNS outcomes (NXDOMAIN vs "exists, no records"), not guessed; DNS errors are "unknown", never "unregistered".
- **History:** `brand_candidate_observations` (written on change plus at most one heartbeat a day) and `brand_candidate_events` (first_observed, flag_gained/lost, stage_changed, activated, ns_changed). Events record when we NOTICED a change and the previous observation, never an exact time. Flags already true at first sighting are baseline and never count as progression.
- **Signals added** (hand-set, uncalibrated — Stage 3): `dormant_activated` +15 abuse (≥14 days dormant, then active), `fast_progression` +10, `platform_hosted` +10 (2.0b), and a zero-weight `dormant` explanation. **One alert per activation** ("Dormant lookalike just went live") when identity ≥ 55.
- **UI/API:** stage chip + mini-ladder per row, "Dormant" filter (dormant names are tracked but kept out of "needs review"), lifecycle timeline in the candidate detail, `GET /brand-guard/candidates/{id}/timeline`.
- **Real-data observation:** on the demo brands only a minority of registered permutations are dormant (acme 1 of 4, dpd 4 of 50); the one real dormant example was registered ~8 years earlier, i.e. very likely unrelated.
- **Cannot be measured offline:** the lifecycle signals need history that only accumulates over repeated live scans, so their effect on precision/recall is unmeasured until Stage 3 has data. The history tables need a retention policy (step 9.4).

## Part C — Dependencies and decision gates

- Stage 1 gates claims in Stages 2–5. Stage 2.1 (history) gates 2.3–2.4, 3, 4.
- Stage 3 before 5.5 (hardening needs a calibrated threat discriminator).
- Stage 7 needs infrastructure approval first; nothing before it touches
  suspect hosts.
- **Gates needing the user:** feed licences/keys (1.1, 2.5), paid API cost
  (2.5), POPIA/cross-tenant (4.4), egress infrastructure (7.1), takedown legal
  stance and sender identity (8.3), production deploy of any stage.

## Part D-0 — Shared-backend caveats (PathProof/Command share this codebase)

Found 2026-09-30 when the user flagged a running shared backend: a V1-folder
`uvicorn … --port 9937` (no `--reload`) uses the dev `sentinel` database. Nothing
done so far touched it, but:

- Brand Guard's scheduler job and startup recovery are **opt-in** (`BRAND_GUARD_ENABLED`, default off) so a restart of the shared backend doesn't log errors against a DB without the Brand Guard tables.
- The three Brand Guard migrations chain after `b8f2d6c4e9a1`; running `alembic upgrade head` on the dev DB creates the brand tables, and a parallel PathProof migration off `b8f2d6c4e9a1` would create a second head.
- Shared files carry Brand Guard hunks (uncommitted, mixed with other work): `main.py`, `models/__init__.py`, `config.py`, `database.py`, `plan_limits.py`.
- pytest drops/recreates `public` in `sentinel_test` — two pytest runs at once (Brand Guard + PathProof) would clobber each other. Live verification now uses its own `dev_live` schema.
- Rule for remaining steps: never touch port 9937 or the `sentinel` database; run servers only from the `brand-guard-live-backend` launch entry (port 9931).

## Part D — Risks

- Labels are biased toward already-caught phish (survivorship) → temporal
  splits, fresh-registration holdout.
- Sparse per-brand data → cross-brand learning conditioned on brand features.
- LLM hallucination → invariant in A5, structured output, abstain.
- Scope creep → a stage is closed only when its exit criteria are measured.


## UI adoption — the user's redesign (started 2026-10-02)

The user's Brand Guard design (Claude Design canvas, 7 screens, recorded in memory `brand-guard-design`) is the target UI. After scrutiny the user agreed to four changes to it, now built into the first slice:

1. **"Not a threat" asks why** — unrelated / it is mine (also added to the official domains) / a partner. Three different decisions, three stored statuses.
2. **Verdict and decision are separate fields.** `verdict` = the system's reading (likely impersonation / watch / not enough evidence / probably harmless); `decision` = what a person did (watching, confirmed, takedown requested, not a threat + reason, ignored). A rescan changes the verdict, never the decision. The lifecycle ladder shows only what can be observed (registered, resolves, mail-ready, certificate); response steps are not part of it.
3. **Absence is not evidence against.** The drawer has For / Against / "Checked, nothing found · not checked". "Not on a blocklist", "no reported email" and "no failing sender matches" go in the third group; "page not analysed" is stated as not checked.
4. **Confidence is defined, not invented:** High / Medium / Low = 3+ / 2 / 1 independent kinds of evidence (name, infrastructure, campaign pattern, public blocklist, the customer's own reports); a strong benign explanation caps High at Medium. It is a count, not a probability, and the reason is in the tooltip.

**Slice 1 built (2026-10-02):** `brand_verdict.py` (pure; 39 tests in `test_brand_verdict.py`, 16 mutation checks, all caught); candidate list/detail/status responses carry `verdict`, `confidence`, `decision`, `why`, and the detail carries `evidence_view` (for/against/context/not-found/numbered summary assembled from the evidence lines, no model); summary adds `new_24h`, `went_live_7d`, `median_detect_hours` (+ n; only domains registered within 30 days before we saw them) and is scoped by `?profile_id=`. Frontend: Pinia `brandGuard` store (one scan poller, brand switcher remembered per browser), routes `/brand-guard` (Home: attention queue first, then coverage and the four numbers), `/brand-guard/candidates` (filters, confidence/domain filters, bulk decisions only for candidates with the same verdict, paging), `/brand-guard/profile` (edit with "Save and rescan", fingerprint, trademarks, honest "We watch / We do not watch"), a candidate drawer (`?c=<id>`; prev/next with j/k, Esc; summary with numbered claims; For/Against/Checked; "Can it send email as you?"; related domains; lifecycle; facts), and a sidebar submenu with Campaigns, Cases and Defend shown as **Soon** (not clickable). 9 store/helper tests; vue-tsc clean.

**Deliberately NOT shown because it is not built:** page scanner, logo match, screenshots, form targets, "Site live" / "Uses brand" stages (Stage 7); cases, takedown composer, approval, evidence pack, submission tracking (Stage 8); blocklist export, defensive-registration advice (Stage 8); campaign split / auto-add (needs a persisted campaigns table, Stage 4 / UI slice 2); AI summary (Stage 6; the summary shown is assembled from the evidence lines and says so); "Time to detect" is real (n shown), not the mock's 3h 40m.

**Next UI slices:** (2) persisted campaigns and a Campaigns page; (3) Cases and Defend once Stage 8 exists; mobile polish; fix 6 from the review (takedown claims only from captured evidence; a rule for single-admin tenants) when Cases is built.

**Fix 6 DONE 2026-10-15.** A complaint may only state facts a third party can check: the name, public registration and certificate data, a public blocklist listing, and what was captured from the page (`brand_takedown.claims`, an allowlist of signals). Private lines (an employee's report, the customer's own mail traffic) and inferences from links to other domains (shared hosting, "linked to known bad", a cluster) are never put in a complaint. With no page evidence the draft says so and rests on the name and registration only (`evidence_level: name_only`, shown in the panel). Drafting, editing and approving need the admin or approver role; a read-only member can look. A workspace with one admin can approve its own drafts, and the audit entry records `self_approved`. A second-person approval for workspaces with several admins is a policy choice, not built.

**UI slice 2 — campaigns (built 2026-10-02).** Look-alikes that appear to share an operator are now stored groups (migration `f1b4d6a8c3e2`: `brand_campaigns` + `brand_candidates.campaign_id/campaign_locked`; module `brand_campaigns.py`, 33 tests in `test_brand_campaigns.py`, 20 mutation checks, 2 survivors judged equivalent). Rules shown to the customer on the page: a group is a connected set of at least two look-alikes linked by the step-2.4 cluster hints (same registration batch, one certificate, the same nameservers, the same server address; the hints now carry the shared value); the verdict counts DISTINCT kinds of shared fact — 3 or more = likely one actor, 2 = possibly related, 1 = not enough evidence — and a member on the customer's own infrastructure makes it "may be your own" (counted for nothing). Groups are rebuilt after every scan and after every decision, so a new look-alike that shares the facts joins by itself; a candidate marked not-a-threat, ignored or removed leaves, a group below two members is deleted, a merge keeps the oldest campaign, and "Take out" locks a member out for good (audited). API: `GET /brand-guard/campaigns[?profile_id=]`, `GET /brand-guard/campaigns/{id}` (members with verdicts), `POST /brand-guard/campaigns/{id}/members/{candidate}/remove`; candidates carry `campaign_id/campaign_name`. UI: Campaigns page (list strongest first, detail with members, "why they are grouped" with k-of-n and what each fact means, one decision for all members), a Home card, the sidebar count, and a link from the candidate drawer. Live on the DPD brand: the five `dpd-paketservicezentrum7xx.ink` names group as "possibly related" (registered together + same nameservers), and a 7-name group on DPD's own server is labelled "may be your own". Bug found on the way (not by tests): an earlier slice-1 change made the status endpoint lazy-load evidence after commit (`MissingGreenlet`); the two audit tests caught it and it is fixed. **Not built from the design:** the "Split group" button (replaced by per-member "Take out", which is stronger and reversible only by a developer today), "Block all" and "Open one case for all" (Stage 8), page-template and registrar-account facts (no data), and the "Watch for" auto-add rule as a separate setting (it is automatic).


## Rebrand: Sentinel -> ZoneProof (2026-10-02)

The user adopted the new logo from their design and asked for a full rebrand everywhere, with the indigo accent.

**Done:** the name in every place a person reads it (frontend views, docs page, modals, AI persona and advisor text, emails, PDF reports, scheduled-report subjects and attachment names, audit-log CSV name, API title, TOTP issuer, email sender name, crawler User-Agent); the new mark and wordmark as one component (`components/layout/ZoneProofLogo.vue`) used by the sidebar, sign-in, invite and verify screens, plus the printable report header; a favicon and tab title; the accent: `--accent #5b5cf0` (hover `#4b4ce0`, soft `#a5a6ff` for the wordmark and links) replaces the old blue everywhere it was written as a colour (80 hex and 132 rgba uses, active-nav and button gradients now run indigo to deep indigo), the page glow is indigo, and the sign-in links and the sidebar add-domain call to action follow it. The product's headline metric is now "ZoneProof Score".

**Deliberately NOT changed (decisions for the user):**
1. **"Sentinel Command"** (the other product, PathProof): it is in the legal Rules-of-Engagement documents sent for e-signature (`dropbox_sign_service.py`), AWS role and CloudFormation names that customers' accounts already depend on (`SentinelCommandReadOnly` / `SentinelCommandRole`), phishing-simulation and training emails sent to a customer's employees, report titles and the command report file name. Renaming those is a separate decision with legal and customer-account consequences.
2. **Identifiers:** localStorage keys (`sentinel_token`, `sentinel_session`; renaming would sign everyone out), JSON keys (`sentinel`, `sentinel_grade`), the `sentinel_snapshots` table, function and class names, the `sentinel.allow_audit_log_delete` database setting, env vars.
3. **Infrastructure names:** the reporting mail domain `mailsentry.co.za` and any DNS target customers have published.
4. **Teal and other data colours:** the ~110 uses of teal and the grade colours are meaning (good/ok, charts), not brand, and were left.
5. The design's typeface (Manrope) and slightly different navy were not adopted: the user asked for the accent only.
