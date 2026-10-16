# ZoneProof 9.0 feature map: today -> new design

Source: the "ZoneProof 9.0 Redesign" canvas, `FeatureMap` artboard (read 2026-10-11), plus capabilities found in the code that the canvas does not list.
Companion to `ZONEPROOF_REDESIGN_PLAN.md`. This file is the repository copy; the canvas itself has not been changed.

## Summary

| | Count |
|---|---|
| Rows in the design's map | 54 |
| Designed or kept | 39 |
| Still to design (per the design) | 15 |
| **In today's UI but absent from the design (regressions if dropped)** | 17 |
| API exists, no UI today (new work, not a regression) | 3 |
| Places the design contradicts built behaviour or leaves a gap (section 3) | 6 |

The design states "Nothing deleted. Everything re-homed." That holds for section 1 only. Section 2 lists what is not covered.

## 1. Features the design maps

### Overview

| Today | In the new design | Who sees it | Status |
|---|---|---|---|
| ZoneProof Score ring and pillars | Home headline; pillar split under technical details | Both | Designed |
| Spoofable / cert alert / TLS KPI cards | Home "three questions" cards | Both | Designed |
| Certificate expiry chips | Home card + Analyze › Certificates | Both | Designed |
| Threat surface (targeted domains, attacker sources) | Analyze › Senders › Unknown sources | Work | Designed now |
| Date range filter | Toolbar on every Analyze page | Work | Designed now |
| Scan a domain | MSP Clients "Scan a prospect’s domain" | Work | Designed |
| First-run empty state | Home first-run | Owners | To design |
| "Still waiting on the first report" | Domain › Status empty state | Both | To design |

### Domains

| Today | In the new design | Who sees it | Status |
|---|---|---|---|
| Domains table, search, pagination, sync | Domains | Both | Designed |
| Subdomains | Domains row "Part of …" | Both | Designed |
| Verify ownership slide-over | Domains row menu → dialog | Both | To design |
| Current DNS records, policy ID | Domain › Investigate | Work | Designed |
| Exclude a source / confirm exclusion | Analyze › Senders row action | Work | Designed now |
| Add-domain wizard incl. platforms step | Wizard (step 2 done; steps 1 and 3 to design) | Both | To design |

### Analyze (was Posture, DMARC, MTA-STS, Certificates, DNS Timeline)

| Today | In the new design | Who sees it | Status |
|---|---|---|---|
| Posture: compliant vs non-compliant volume | Analyze › Senders summary | Work | Designed now |
| DMARC analyzer: source → IP → result | Analyze › Senders + Domain › Investigate | Work | Designed now |
| Platform health matrix (declared vs detected) | Analyze › Senders › By platform | Work | Designed now |
| Add platform / platform setup modal | Senders "Add a service" → SPF builder | Work | Designed now |
| SPF composition builder | SPF builder dialog (lookup count, flatten warning) | Work | Designed now |
| DKIM failure diagnosis | Senders row "Why it’s failing" | Work | Designed now |
| MTA-STS domain breakdown and hosting status | Analyze › Encryption | Work | Designed now |
| MX host readiness scorecard | Analyze › Encryption › Mail servers | Work | Designed now |
| TLS failure analysis and trend | Analyze › Encryption + Domain › Encryption | Both | Designed now |
| Certificate inventory, re-probe, SAN / TLS details | Analyze › Certificates | Work | Designed now |
| DNS change log with before / after | Analyze › DNS changes + Domain › History | Both | Designed now |

### Roadmap

| Today | In the new design | Who sees it | Status |
|---|---|---|---|
| Roadmap track: stages per domain | Work › Roadmap board; owners see it as the Fix list | Both | Designed now |
| Enforcement readiness, advancement check | Roadmap gates per domain | Work | Designed now |
| Impact simulation on collected traffic | Roadmap "Check impact" before advancing | Work | Designed now |
| Portfolio readiness roll-up | Roadmap header | Work | Designed now |
| BIMI step | Roadmap final stage | Work | Designed now |
| Record review modal (diff, registrar steps, email developer) | DNS change review dialog | Both | Designed |

### Brand Guard

| Today | In the new design | Who sees it | Status |
|---|---|---|---|
| Overview and candidate triage | Brand protection › Needs a decision | Both | Designed |
| Candidate drawer (full evidence) | Opens from a decision card | Both | To design |
| Campaigns | Brand protection › Campaigns | Work | Designed now |
| Cases with owner and deadline | Brand protection › Cases | Both | Designed now |
| Takedown complaint draft | Case detail | Both | Designed now |
| Evidence pack (JSON / PDF, hash) | Case detail | Both | Designed now |
| Defend: blocklists, names to register, browser reporting | Brand protection › Defend | Work | Designed now |
| Funnel | Brand protection › Insight | Work | To design |
| Brand profile: keywords, official domains, fingerprint | Brand protection › Settings | Both | To design |
| MSP roll-up across clients | Brand protection with "All clients" selected | Work | To design |

### Reports, alerts and help

| Today | In the new design | Who sees it | Status |
|---|---|---|---|
| Report wizard | Reports | Work | Designed |
| Technical report (sources, infrastructure) | Reports › "Technical version" alongside client version | Work | To design |
| White-label brand name | Reports "Sent as" + Settings | Work | Designed |
| Alert channels, webhooks, SIEM export | Notifications | Both | Designed |
| Alerts menu | Bell → Notifications | Both | Designed |
| AI assistant, narrative cards, follow-ups | ZoneProof AI panel + report notes | Both | Designed |
| Glossary and concept cards | Help & glossary + inline "What’s this?" | Owners | To design |
| Documentation | Help & glossary | Both | To design |

### Account

| Today | In the new design | Who sees it | Status |
|---|---|---|---|
| MSP client tenants, invites, roles | Settings › Clients & team | Work | To design |
| Plan & billing, upgrade prompt | Settings › Plan | Both | To design |
| Audit log (Enterprise) | Settings › Audit log | Work | To design |
| Email verification banner | App shell banner | Both | To design |
| Login, reset password, accept invite | Unchanged | Both | Keep as is |

## 2. Capabilities the design does not list, and where each goes

**How the placement was decided.** Each capability goes to the least prominent place that still meets its need.

| Level | Meaning |
|---|---|
| L1 | Inline on the object (row, card, dialog) |
| L2 | The object's detail (tab or drawer) |
| L3 | The section's settings |
| L4 | Global settings |
| L5 | Work layer page |
| L6 | Admin only |

Inputs: who needs it, how often, and how costly a miss is (security-critical or irreversible actions climb one level). Home gets only what answers one of its three questions or a "next step". **No item below is added to Home.**

**"How often" is assumed**, not measured: there is no usage data in the repository. Validate with the audit log or a short interview before building.

`REG` = in today's UI and absent from the design. `NEW` = the API exists but today's UI has no screen for it.

### Account and security

| # | Type | Capability | Today | Who | How often (assumed) | Level | Place in the new design | Clicks from Home | Reuses | Priority |
|---|---|---|---|---|---|---|---|---|---|---|
| N1 | REG | Two-factor sign-in: set up, verify, disable; the login challenge | ProfileView card; LoginView step | Everyone | once | L3 | Settings › Security; second step on Login; a one-time prompt in the existing shell banner slot | 2 | Settings tabs, StepTracker, CodeBlock | must |
| N2 | REG | Change password, edit profile | ProfileView cards | Everyone | rare | L3 | Settings › Profile and Settings › Security | 2 | Settings tabs, form fields | must |
| N17 | REG | Export my data (JSON download) | ProfileView "Your data" | Admin, owner | rare | L4 | Settings › Data and account | 2 | Settings tabs, BaseButton | should |
| N2b | REG | Delete workspace (admin) / remove my account (member) | ProfileView danger zone with confirmation modal | Admin, member | rare | L4 | Settings › Data and account, kept deliberately deep, using the type-to-confirm dialog | 2 + dialog | ConfirmDialog | must |
| N19 | REG | Who am I: avatar, plan pill, sign out | Sidebar user block | Everyone | daily | L1 | Account menu in the shell (avatar at the sidebar foot or top bar): name, plan, Settings, Sign out. **The design has no user block at all.** | 1 | Menu (RowMenu) | must |
| N18 | REG | Reporting configuration, read-only: reporting domain, polling intervals, certificate alert thresholds | ProfileView card "read-only" | IT manager | rare | L4 | Help › "How ZoneProof collects data" (not Settings: nothing to change) | 2 | Card | later |
| N4 | NEW | Team members inside one tenant: invite, role, revoke | API only (`invites`, `updateMember`, `removeMember`); UI uses `team` for the owner dropdown only | Admin | rare | L4 | Settings › Team. Needed for "Owner" on cases to have anyone to pick | 2 | Settings tabs, table | should |
| N3 | NEW | Send a test email | API only (`POST /auth/send-test-email`); no UI | Admin | rare | L1 | Inline on the email channel row in Notifications: "Send a test" | 2 (bell > row) | IconButton | later |

### Domains and DNS

| # | Type | Capability | Today | Who | How often (assumed) | Level | Place in the new design | Clicks from Home | Reuses | Priority |
|---|---|---|---|---|---|---|---|---|---|---|
| N5 | REG | Subdomain discovery with accept / ignore decisions | DomainDetailView | IT manager | weekly | L2 | Domain › Status, panel "Subdomains we found" | 2 (Domains > domain) | Card, StatusChip, BaseButton | should |
| N6 | REG | "Is it live yet?" check and "I have published it" confirmation | RecordReviewModal; MtaStsView | IT manager | weekly | L1 | Inside the DNS change review dialog, as its last step | 2 (Fix list > Fix it) | BaseDialog, StatusChip | must |
| N7 | REG | DMARC volume histogram over time | ReportTimeline inside DmarcView | MSP technician | weekly | L2 / L5 | Domain › Senders trend; Work › Senders | 3 | TrendBars | later |

### Brand Guard

| # | Type | Capability | Today | Who | How often (assumed) | Level | Place in the new design | Clicks from Home | Reuses | Priority |
|---|---|---|---|---|---|---|---|---|---|---|
| N8 | REG | Rendered-page evidence: screenshot, your page beside the look-alike, icon / wording / layout lines | CandidateDrawer capture section | Everyone deciding | daily | L1 + L2 | Thumbnail pair on the decision card when a capture exists; full size in the drawer. Empty state says "page checks are off" when they are | 1 (Brand) | Card, drawer, existing capture endpoints | must |
| N16 | REG | Full candidate list: search, filters, bulk decisions | BrandCandidatesView + DecisionButtons | Analyst | daily | L2 | Tab "All candidates" on Brand protection, beside "Needs a decision" | 2 | Table, filter pills, bulk bar (all in Domains design) | must |
| N9 | REG | Candidate lifecycle: registered, resolving, mail enabled, certified | `LifecycleDots` in 3 lists + drawer timeline | Analyst | daily | L1 + L2 | Dots on card header and table rows; full history in the drawer | 1 | LifecycleDots (existing) | should |
| N11 | REG | Coverage statement and source health | `SourceStrip` on Overview and Profile | Analyst, admin | weekly | L1 (only when degraded) + L3 | A health dot in the Brand header that opens the strip only when a source is down; full statement in Brand › Settings › Coverage | 1 / 2 | SourceStrip (existing) | should |
| N12 | REG | Scan progress and scan history | `brandScanRun` in the store | Analyst | weekly | L1 + L3 | Progress on the Scan button itself; history in Brand › Settings | 1 / 2 | Button with `aria-busy`, table | should |
| N15 | REG | Trademarks, kept as takedown evidence | BrandProfileView | Brand owner | rare | L3 | Brand › Settings › Trademarks | 2 | Form rows | should |
| N14 | REG | Report-submission status; the notification log | BrandDefendView; BrandNotificationsView | Analyst | weekly | L2 | Keep where they are: Defend › "Reports sent", Notifications › Log. Restyle only | 2 | Table, StatusChip | later |
| N10 | REG | Why a name was flagged (derivation); campaign cluster graph | `DerivationNode` in the drawer; `ClusterGraph` in Campaigns | Analyst | weekly | L2 | Drawer › "Why we flagged this"; Campaign detail | 2 | DerivationNode, ClusterGraph (existing) | later |
| N13 | NEW | Page-check worker status: connected, renderer on or off | API only (`GET /brand-guard/probe-status`); no UI | Admin | rare | L6 | Brand › Settings › Page checks (admins). Users meet it only as the empty state in N8 | 2 | StatusChip | later |

### Guardrail results

| Guardrail | Result |
|---|---|
| Elements added to Home | **0** (none qualifies; Home keeps one headline, three questions, three next steps) |
| Worst clicks-from-Home for a placed item | 3 (N7 histogram, a "later" item); every must-have is 2 or fewer |
| New UI patterns introduced | **1**: the account menu (N19). Everything else reuses a pattern already in the design or in the code |
| New shell regions | 0. Settings becomes tabs on one page; the account menu sits in the existing sidebar foot |
| Items that need new design work before build | N1, N2, N2b, N4, N17 (Settings tabs); N19 (account menu); N16 (candidate table); the three-reason step (C2) |
| Items that need only a layout pass | N5, N6, N8, N9, N10, N11, N12, N13, N14, N15, N18 |

## 3. Where the design must change, or has a gap

| # | In the design | What is built | Change |
|---|---|---|---|
| C1 | One "It's a threat — start takedown" button | Built flow is Confirm impersonation (opens a case), Watch, Not a threat…, and under More "Takedown requested" (records what you did elsewhere). ZoneProof drafts takedowns and never sends them, so "start takedown" over-promises. | Rename to "Confirm impersonation: open a case". Keep Watch. Move "Takedown requested" under More. |
| C2 | One "Not a threat" button | Built flow asks why: "It is mine" adds the domain to official domains; "A partner or supplier" allows it; "Unrelated" dismisses. The answers feed the brand baseline. | Restore the three-reason step. Keep the one-click feel by remembering the last reason per session. |
| C3 | Verdict wording on cards | Design says "Phishing (reported)" and "Suspected: impersonation". Real labels live in `brandLabels.ts` / `VerdictPill`. | Re-check every label against the real set; do not invent verdict names. |
| C4 | Home figures with no data source | "Problems fixed: 4 by you, 3 by your IT" and "Taken down 19 Sep" need records the app does not keep. | Hide or mark as placeholder until the data exists (plan section 5). |
| C5 | Settings is a dead link in the shell | Every design screen links Settings to "#". The app has Profile, Security, Reporting, Data and Danger zone today. | Define Settings as tabs: Profile, Security, Team, Notifications, Plan, Data and account (+ Clients for MSP, Audit log for Enterprise). |
| C6 | No user identity in the shell | The sidebar today shows avatar, name, plan pill and sign out. The design drops all of it. | Add an account menu (N19). |

## 3b. Artboards drafted for the gaps (canvas versions 35 to 39, 2026-10-11)

| Artboard file | Covers | Interactive in the prototype |
|---|---|---|
| `Settings.dc.html` | C5, N1, N2, N2b, N4, N17: tabs for Profile, Security (password, two-factor set-up flow), Team, Notifications (pointer), Plan, Data and account, plus Clients (MSP) and Audit log (Enterprise) | Tabs; two-factor off, set-up, on |
| `AccountMenu.dc.html` | N19, C6: avatar, plan, Settings, Sign out at the sidebar foot, as a disclosure list | Open / close |
| `BrandAllCandidates.dc.html` | N16, N9: filters with counts, search, row selection, bulk decisions, lifecycle dots | Filters, selection, bulk bar |
| `NotAThreat.dc.html` | C1, C2, N8: decision card with the renamed confirm action, three-reason "Not a threat", More, thumbnails, undo | Reasons, outcome, undo |
| `SubdomainsFound.dc.html` | N5: Monitor this, Exclude with a recorded reason, Covered by sp=, undo | Decisions, exclude reason |

Not drawn: N6 (it is a step inside the existing DNS review dialog), N7, N10 to N15 and the three API-only items. Those reuse components that exist and need layout only.
The boards were authored but not rendered or screenshotted. Review them in the canvas before treating them as final.

## 4. Features in the design that are not built yet

Tracked in section 5 of `ZONEPROOF_REDESIGN_PLAN.md`: the monthly "what we did" tiles, the portfolio Fix list and the "Send to IT" hand-off, the weekly portfolio digest, and per-client MSP score trends.

