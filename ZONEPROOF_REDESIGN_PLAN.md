# ZoneProof 9.0 redesign: implementation plan for the Vue frontend

Source design: the "ZoneProof 9.0 Redesign" canvas (25 artboards, tokens synced from this repo on 2026-10-10).
Review of that design: 7.7 / 10 (see the "Design amendments" section for the fixes this plan builds in rather than copies).
Target: `frontend/` (Vue 3, Vite, Pinia, vue-router, vitest, vue-tsc). Backend changes are called out where a screen needs data that does not exist yet.
Feature coverage: see `ZONEPROOF_FEATURE_MAP.md`. The design's own map lists 54 features. Today's UI has **17 more that the design omits** (two-factor sign-in, account security, delete workspace, data export, the user/sign-out block, subdomain decisions, Stage 7 rendered evidence, and others), **3 more where the API exists and no UI does** (team roles, test email, page-check status), and 6 places where the design contradicts built behaviour or leaves a gap. Section 10 of this plan assigns each to a phase. Every placement follows one rule (feature map section 2): the least prominent place that still meets the need; none goes on Home.

Effort numbers are rough, for one developer who knows the codebase, in working days. They are for sequencing, not for promising a date.

---

## 1. Where the code is today (measured on 2026-10-11)

| Measure | Now | Design target |
|---|---|---|
| Vue files / lines | 98 files, 22,308 lines | n/a |
| Distinct `font-size` values | 31 (552 of 1,153 uses are under 12px) | 8-step scale |
| Distinct `z-index` values | 19 (1 to 2000) | 5 layers |
| Distinct `border-radius` values | 18 | 5 (8, 12, 16, pill, round) |
| Distinct hex colours in components | 91 | tokens only |
| Button-like class names (by my count) | about 86 | 3 variants x 2 sizes |
| `:focus-visible` rules | 0 | one global ring |
| `prefers-reduced-motion` rules | 0 | global |
| `@media` breakpoints | 9 different `max-width` values | 3 named |
| Sidebar nav items | `<div @click>`, not links or buttons | real links, `aria-current` |
| Modal / drawer | backdrop `div`, close is a `span`, no `role`, no Escape, no focus trap | `role=dialog`, trap, Escape, focus return |
| Mobile navigation | exists (`ui.navOpen` drawer + backdrop in AppShell) | keep and restyle |
| Tests | 8 files, 61 tests, vue-tsc clean | keep green on every step |

The design's "was 31 / was 19" numbers match the code, so the token plan can be taken from the design as written.

Two things the code has that the design does not show, and must keep: the existing mobile nav drawer, and the 403 `upgrade_required` prompt in AppShell.

---

## 2. Principles

1. **Keep route names.** `router.push({ name })` is used all over the app. New URLs get new route entries; old paths get `redirect`s. No view is renamed in the first pass.
2. **Foundations before screens.** A screen built on the old tokens has to be redone. Phases 1 and 2 ship no visible redesign but remove the accessibility defects that apply everywhere.
3. **One shared component per pattern**, built once, used by every migrated view (button, chip, dialog, nav item, card, table, tabs, KPI). The design's own drift (44px vs 40px nav, two badge styles) came from copy-paste. We do not repeat it.
4. **Ship in slices behind a switch** (decision D1), so a half-migrated app is never what a customer sees.
5. **Contrast is a test, not a review comment.** A unit test computes the ratio of every token pair that carries text.
6. **No invented data.** Where a design screen shows a number the backend cannot produce yet, it is a placeholder or a hidden section until the endpoint exists (section 5 lists them).

---

## 3. Phases

### Phase 0: Decisions and groundwork (1 to 2 days)

- Settle decisions D1 to D6 at the end of this file.
- Copy `project/ds/zoneproof/tokens.json` from the design into `frontend/design/tokens.json` so token values have one reviewed source.
- Add a per-route visual checklist (1440, 768, 390 wide) and use the browser pane for before/after screenshots. No new tooling.
- Add `vitest-axe` (or `axe-core` in a small vitest helper) for component-level accessibility checks. Decision D7.
- **Done when:** tokens file committed, checklist exists, decisions recorded.

### Phase 1: Foundations (4 to 6 days)

| Task | Files | Notes |
|---|---|---|
| Rewrite `styles/tokens.css` | `src/styles/tokens.css` | Add the design's new tokens (`surface-1 #0e1020`, `surface-2 #13152a`, `faint #7c84a8`, `control-border #62678c`, `danger #c42744`, `focus #a5a6ff`), spacing, radius, z-index, type scale. **Keep every old variable name as an alias** so nothing breaks. |
| Global focus ring, reduced motion | `tokens.css` | `:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px }`, and a `prefers-reduced-motion` block that disables `.fade-up`, `.skel`, `pulse`. Fixes 0 rules today. |
| Replace glass gradients with solid surfaces | `tokens.css`, card styles in components | The design does this so text contrast is predictable. Remove `--glass` from cards first; keep the page background glows at low opacity. |
| z-index scale | all 19 values | Map to base 0, sticky 10, menu 20, dialog 30, toast 40. Do it with a reviewed codemod; check dialogs, drawer, assistant, toast and alert menu stack correctly. |
| Type scale codemod | all components | Map 31 sizes to 8. See the mapping below. This is the riskiest step in the project: 552 uses move **up** to 11 or 12px and some layouts will overflow. Do it in batches of about 10 files with a screenshot review each. |
| Radius codemod | all components | 18 values to 5. Low risk. |
| Colour codemod | components with raw hex | 91 hex values to tokens; anything not in the token set is raised, not silently remapped. |
| `BaseButton` + `IconButton` | new `components/ui/BaseButton.vue`, `IconButton.vue` | `primary | ghost | danger`, sizes `md 40 | sm 32`, states default, hover, focus, disabled, `aria-busy` with spinner. Icon-only requires `ariaLabel` (type-enforced). Replace the ~86 ad hoc button classes view by view in later phases; no big-bang replace. |
| Extend `StatusChip` | `components/ui/StatusChip.vue` | Always icon + word, variants good / warn / bad / info. Never colour alone. |
| Contrast test | new `src/__tests__/tokens.contrast.test.ts` | Asserts the ratios the design claims (text >= 4.5, UI >= 3). Uses the same maths I used in the review. |

**Type scale mapping** (proposed; confirm in review):

| Old px | New |
|---|---|
| 7.5 to 11 | 11 (label, uppercase mono) |
| 11.5 to 12.5 | 12 (mono / small) |
| 13 to 14.5 | 13 (small) or 14 (body), by role |
| 15 to 16 | 16 (lead) |
| 17 to 21 | 20 (heading) |
| 22 to 28 | 28 (title) |
| 30 to 38 | 36 (display) |

**Done when:** vue-tsc clean, 61 tests green, no `font-size` under 11px in `src`, one z-index scale, global focus ring visible on every interactive element, contrast test passing.

### Phase 2: Shell and accessible primitives (5 to 7 days)

| Task | Files | Notes |
|---|---|---|
| Sidebar as real navigation | `components/layout/AppSidebar.vue` | Items become `<RouterLink>` with `aria-current="page"`, 44px targets, one `NavBadge`. The Brand Guard fold/unfold keeps working (it is a `<button aria-expanded>` that also navigates). Remove the `01`..`14` numbering (the design drops it). |
| Regroup navigation | `AppSidebar.vue`, `router/index.ts` | Home, Fix list, Domains, Brand protection, Reports, then Settings, Help. The current Analyze and Plan groups move to a "Work" group (decision D2). |
| `BaseDialog` | new `components/ui/BaseDialog.vue`, rewrite `AppModal.vue` | `role="dialog"` / `alertdialog`, `aria-modal`, `aria-labelledby`, focus moves in, Tab trapped, Escape closes, focus returns to the opener, real close `<button>`. Widths 420 / 640 / 860. Same store API (`ui.openModal`) so existing callers do not change. |
| `BaseDrawer` | `AppDrawer.vue` | Same behaviour, 480px from the right. |
| `ConfirmDialog` | new component | The design's destructive pattern: names what is lost, "Export first" link, type-the-name-to-confirm for removing a client. Replaces the 4 browser `confirm()` calls: `PlatformHealthMatrix.vue:34` (remove platform), `PlatformSetupModal.vue:38` (mark as done anyway), `BrandNotificationsView.vue:46` (remove alert channel), `MspView.vue:69` (remove client and all data: the one that needs type-the-name). |
| Toast | `AppToast.vue` | `role="status"`, 6s, pauses on hover, optional Undo. |
| Skip link, landmarks | `AppShell.vue` | "Skip to content", `<main id>`, one `<h1>` per page. |
| Keep | `AppShell.vue` | Mobile drawer, verify banner, upgrade prompt. |

**Done when:** every nav item and dialog is operable with keyboard only, a screen reader announces the dialog title and returns focus, and unit tests cover the focus trap, Escape and focus return.

### Phase 3: Home and Fix list (5 to 8 days) *needs data work*

| Design screen | Real home | Change |
|---|---|---|
| Home | `OverviewView.vue` (552 lines) -> route `overview` | Restructure: headline answer, "what we did", "do these next", three plain questions, **Show technical details** toggle (persisted in `ui` store). |
| Fix list | new view `FixListView.vue`, route `fix-list` | New. |

Data (section 5): the headline numbers come from `GET /overview` (exists). The "what ZoneProof did this month" tiles and the ordered fix list need a small aggregation; a spike in Phase 0 decides whether to compose from existing per-domain recommendations or add one portfolio endpoint.

Reuse: `ShieldScore`, `KpiCard`, `TrendBars`, `AdvisorBanner`, `AiNarrativeCard`. Retire the 01..14 ids from Overview copy.

### Phase 4: Domains and domain detail (8 to 12 days)

| Design screen | Real home | Change |
|---|---|---|
| Domains | `DomainsView.vue` (817) | Restyle table with sortable headers (`aria-sort`), filter pills (`aria-pressed`), row selection + bulk bar, row menu. Add pagination and a sticky header. |
| Domain detail | `DomainDetailView.vue` (874) | Tabs: Status, Senders, Encryption, Certificates, History, Investigate. This merges the per-domain parts of today's Posture, DMARC, TLS, Certificates and DNS Timeline pages. |
| Add domain | `components/wizard/*` | Easy path by default, "hand off to IT" step. |
| DNS change review | new dialog on `BaseDialog` | The single before/after-diff pattern (reuses `DiffBlock`, `CodeBlock`). **Must include** (feature map N6): "Is it live yet?" check (`checkDnsLive`) and the "I have published it" confirmation (`dmarcMarkPublished`, `tlsMarkPublished`). |
| Subdomain decisions | Domain › Status panel | Feature map N5: "Subdomains we found" with accept / ignore (`discoverSubdomains`, `setSubdomainDisposition`). The design only shows a "Part of …" label. |
| DMARC volume histogram | Domain › Senders, Analyze › Senders | Feature map N7 (`dmarcHistogram`). Low priority. |

Biggest piece of the project, because it combines five existing views' content into one tabbed page. Do it as one tab per PR, reusing the existing view bodies as tab content first and restyling after.

### Phase 5: Brand protection (4 to 6 days)

| Design screen | Real home | Change |
|---|---|---|
| Needs a decision | `BrandGuardView.vue` + `CandidateDrawer.vue` | Decision cards: what we saw (already produced by `probeLines`), three actions, undo. |
| Cases / Campaigns / Defend | `BrandCasesView`, `BrandCampaignsView`, `BrandDefendView` | Re-skin, tabs per the design. |

Amendments to apply here (not in the design): put the captured **side-by-side screenshot** on the decision card (endpoints and `CandidateDrawer` logic exist); use the normal primary style, not the danger style, for the "confirm" action because it opens a case and drafts a request and is reversible; keep the plain wording rules in `brandLabels.ts`. ZoneProof still never sends a takedown itself.

Also in this phase (feature map section 2 and 3):

| Item | Notes |
|---|---|
| **C1** Relabel "It's a threat — start takedown" | "Confirm impersonation: open a case". "Takedown requested" stays under More; it only records what the person did elsewhere. |
| **C2** Restore the three-reason "Not a threat" step | It is mine (adds to official domains), a partner or supplier (allowed), unrelated. Logic already exists in `DecisionButtons.vue`; reuse it, do not rewrite it. |
| **N16** "All candidates" table beside the cards | Search, filters, bulk decisions. Keep `BrandCandidatesView`; decision D9. |
| **N8** Rendered evidence | Screenshot, your page beside the look-alike, icon / wording / layout lines. Already built; place it on the card and drawer. |
| **N9, N10** Lifecycle ladder, "why we flagged this", cluster graph | Candidate drawer › History and "Why we flagged this". `LifecycleDots`, `DerivationNode`, `ClusterGraph` exist. |
| **N11, N12, N13** Coverage statement, scan progress and history, page-check worker status | Brand › Settings, and a strip on Needs a decision. `SourceStrip`, `brandSources`, `brandScanRun`, `probe-status` exist. |
| **N14, N15** Submission status and notification log; trademarks | Defend › "Reports sent"; Settings › Trademarks. |

### Phase 6: MSP, reports, notifications, assistant (6 to 10 days)

| Design screen | Real home | Notes |
|---|---|---|
| MSP all clients | `MspView.vue`, `MspBrandGuardView.vue` | Portfolio table; MSP switch in the shell (decision D2). |
| Reports, monthly client report | `ReportView.vue` (1,286 lines), `GET /overview/report-pdf`, `GET /msp/clients/{id}/report-pdf` | The PDF is server-rendered (`pdf_report_service`). The on-screen design is HTML; keep them in step deliberately, do not assume one drives the other. Treat `ReportView` as its own sub-project. |
| Notifications | `BrandNotificationsView.vue`, `components/alerts/*` | Generalise from brand-only to all alert types. |
| Weekly digest email | backend `brand_notify` / scheduled reports | Brand digest exists; a portfolio digest is new (section 5). |
| **Settings as tabs** (feature map C5) | `ProfileView.vue` (665 lines) | Profile, Security, Team, Notifications, Plan, Data and account (+ Clients for MSP, Audit log for Enterprise). The design links Settings to "#" everywhere, so the whole structure has to be designed (about 2 to 3 days) before building. |
| Security and Profile content | same | N1 (two-factor setup and the login challenge), N2 (password, profile), N2b (delete workspace / remove account, kept deliberately deep with type-to-confirm), N17 (export my data), N18 (read-only collection settings, under Help). All exist in the UI today; re-home, do not rewrite. |
| **Account menu** (feature map N19, C6) | `AppSidebar.vue` user block | Avatar, name, plan pill, Settings, Sign out. The design drops the user block entirely. One new pattern, built on the shared menu. |
| New, not a re-home | N4 team roles (API only), N3 send a test email (API only) | Team is needed so "Owner" on cases has people to choose. Both are new screens, not regressions. |
| ZoneProof AI | `components/assistant/AssistantPanel.vue` | Restyle only. Replace the `✦` glyph with an SVG icon. |

### Phase 7: Work layer (3 to 5 days)

Roadmap, Senders, SPF builder, Encryption, Certificates, DNS changes already exist as `RoadmapView`, `DmarcView`, `MtaStsView`, `CertificatesView`, `DnsTimelineView`, `PostureView`. Move them under `/work/*` with redirects from the old paths, give them the shared shell and tokens, and add the missing entry point from Home and MSP Home (the design left this Work layer reachable only from itself).

### Phase 8: Hardening (4 to 6 days)

- Responsive pass at 1440, 1024, 768, 390 on every migrated route (the design has no phone layouts; this phase produces them, see amendments).
- Axe run and a keyboard walkthrough on every migrated route.
- Delete dead CSS and the old button classes, tidy token aliases, remove the feature switch.
- Docs: update `ZONEPROOF_PROJECT_BRIEF.md` UI section.

---

## 4. Design amendments (fix in the build, then tell the designer)

1. One shared nav item and one badge component. No per-screen copies.
2. Teal means "AI" only. The safety-score ring uses `good` (or a score gradient), and "good" is a single green.
3. "Start takedown" is a primary action, not danger.
4. Phone and tablet layouts are designed in Phase 8 from the same components (collapsing nav already exists as the mobile drawer).
5. Keyboard model specified once in `BaseDialog`, `BaseDrawer` and a `RowMenu` component (arrow keys, Home/End, Escape).
6. Live regions for toasts and Brand "done" states.
7. Replace glyph icons (`✦ ▲ ▼ ✓ × →`) with the SVG set.
8. Remove placeholder copy such as `[Workspace name]`; "Do these next" says "Show all 5".
9. Add empty, loading and error states to each data screen (skeletons already exist in `tokens.css`).
10. Decide a light theme (D3). If yes, tokens get a second theme and `ClientReport` gets a print stylesheet.
11. Restore the three-reason "Not a threat" step and rename the confirm action (feature map C1 and C2). The design's one-button versions lose behaviour that exists and feeds the brand baseline.
12. Add the 17 capabilities the design omits and the 3 API-only ones (feature map section 2) as screens or panels before building their phase, each at the level the placement rule gives. Two-factor sign-in, account security, the account menu and the candidate table are the must-haves.
13. Define Settings as tabs and add an account menu (feature map C5, C6). Both are shell-level gaps in the design.

---

## 5. Data and backend gaps

| Screen element | Exists? | Needed |
|---|---|---|
| Headline: protected / total, score, trend | Yes (`GET /overview`, `/overview/readiness-rollup`) | Confirm trend series length. |
| "What ZoneProof did this month" (fake emails stopped, problems fixed, copycats handled, % encrypted) | Partly (DMARC/TLS aggregates, brand cases) | A monthly summary aggregation; "problems fixed by you / by IT" needs a record of who completed a step (not stored today, to confirm). |
| Ordered fix list across domains | Per domain (`GET /domains/{id}/recommendations`) | Portfolio endpoint or client-side merge; "Send to IT" needs a hand-off record (new). |
| Domain status tabs | Yes, spread over dmarc / tls / certs / timeline endpoints | Composition only. |
| Brand decisions, captures, side-by-side | Yes (built in Stage 7) | None. |
| Two-factor, password, profile, delete account, team roles | Yes (`enable2fa`, `changePassword`, `deleteAccount`, `team`, …) | None for the backend; screens are missing from the design. |
| Subdomain decisions, "is it live" check, mark-as-published | Yes (`discoverSubdomains`, `checkDnsLive`, `dmarcMarkPublished`) | None. |
| Page-check worker status, scan history, coverage statement | Yes (`probe-status`, `scan-runs`, `brandSources`) | None; admin-only visibility to decide (D10). |
| "Problems fixed: by you / by your IT", "Taken down 19 Sep" figures on Home | No | Not recorded today. Hide until the data exists (feature map C4). |
| Portfolio weekly digest | Brand digest only | New scheduled job and template. |
| MSP client roll-up | Yes (`/msp/clients`) | Per-client score trend. |

---

## 6. Testing and quality gates (every phase)

- `vue-tsc --noEmit` clean; vitest green (61 now, growing).
- Contrast test on tokens; component tests for `BaseButton`, `BaseDialog` (focus trap, Escape, focus return), `NavBadge`.
- Per migrated route: before/after screenshots at 3 widths, an axe run, a keyboard-only pass, and no console errors.
- No phase merges with a failing gate. Commits stay deferred until the Brand Guard stages are done, as agreed; this work is a separate branch of changes once they are.

---

## 7. Effort and order

| Phase | Days |
|---|---|
| 0 Decisions and groundwork | 1 to 2 |
| 1 Foundations | 4 to 6 |
| 2 Shell and primitives | 5 to 7 |
| 3 Home and Fix list | 5 to 8 |
| 4 Domains and detail (+ subdomain decisions, live check, mark published) | 9 to 13 |
| 5 Brand protection (+ rendered evidence, lifecycle, coverage, scan history, full table, reasons) | 6 to 9 |
| 6 MSP, reports, notifications, assistant (+ Security and Profile screens) | 8 to 12 |
| 7 Work layer | 3 to 5 |
| 8 Hardening | 4 to 6 |
| **Total** | **45 to 68** |

The earlier range was 40 to 62. The added capabilities (feature map section 2) add about 5 to 6 days, mostly Settings as tabs and the Security and Profile screens, which have to be designed as well as built. Most of the rest re-home components that already exist in the code.

Phases 1 and 2 are worth doing even if nothing else ships: they fix keyboard access, focus visibility, reduced motion, and the sub-12px text.

Suggested order if time is tight: 1, 2, 5 (the newest module, where the new evidence is), 3, 4, 7, 6, 8.

---

## 8. Risks

- **Type codemod regressions:** moving 552 small sizes up will break tight layouts. Mitigation: batches, screenshots, and a visual review per batch.
- **Domain detail merge:** five views become one; hidden state coupling between them is likely. Mitigation: tab-per-PR, reuse bodies first.
- **Report/PDF drift:** the on-screen report and the server PDF are separate renderers.
- **Design not tested with users:** the 7.7 is a heuristic score. Run 3 to 5 task walkthroughs on Home, Fix list and the Brand decision before Phase 6.
- **Scope pressure:** the design covers MSP, reports and email. Each of those is a product decision as much as a UI one.

---

## 9. Decisions needed (answer these before Phase 0 ends)

- **D1. Ship strategy:** per-route feature switch (recommended; the old and new view live side by side until each is accepted) vs one release at the end.
- **D2. Where the Work layer lives:** a collapsible "Work" group for everyone, or MSP/technician plans only. And is there a visible MSP switch in the shell?
- **D3. Light theme:** in scope now, later, or never (dark only)?
- **D4. Fix list data source:** add a portfolio endpoint, or compose client-side from per-domain recommendations?
- **D5. Numbering and group names:** drop `01`..`14` and the Portfolio / Analyze / Plan group labels as the design does?
- **D6. "Send to IT" hand-off:** is it an email, a share link, or a task record? It needs a backend record either way.
- **D7. Accessibility tooling:** add `vitest-axe` as a dev dependency?
- **D8. Amendments:** accept all of section 4, or which ones to skip?
- **D9. Candidates table:** keep "All candidates" (search, filters, bulk decisions) as an analyst table beside the decision cards? Recommended: yes. The cards suit one decision at a time; analysts working a backlog need the list.
- **D10. Who sees the operational panels:** page-check worker status, scan history and the coverage statement (feature map N11 to N13). Everyone, or admins and MSP staff only?
- **D11. Naming of the confirm action:** "Confirm impersonation: open a case" (recommended, matches that ZoneProof drafts and never sends) vs keeping "start takedown". Say if you intend ZoneProof to send takedowns itself later, because the label would then change.

---

## 10. Missing capabilities mapped to phases

Full detail, evidence in code and proposed homes are in `ZONEPROOF_FEATURE_MAP.md` (section 2). Priority: must = regression if dropped.

| Phase | Items | Priority |
|---|---|---|
| 2 Shell | N19 account menu (avatar, plan, Sign out); ConfirmDialog with type-to-confirm (used by N2b) | N19, N2b must |
| 4 Domains | N5 subdomain decisions; N6 live check + mark published; N7 DMARC histogram | must / should / later |
| 5 Brand | N8 rendered evidence; N9 lifecycle; N10 derivation + cluster graph; N11 coverage + source health; N12 scan progress and history; N13 worker status (new); N14 submissions + notification log; N15 trademarks; N16 candidate table; C1 label; C2 reasons | N8, N16, C1, C2 must |
| 6 Account | C5 Settings as tabs; N1 two-factor; N2 password, profile; N2b delete; N17 export; N18 collection settings under Help; N4 team roles (new); N3 test email (new) | N1, N2, N2b must |

**Placement rule and guardrails.** Level 1 is inline on the object, level 6 admin-only; each item sits at the lowest level that meets its need. Results against the guardrails (details in the feature map): 0 elements added to Home; every must-have is 2 clicks or fewer from Home; one new UI pattern (the account menu); 0 new shell regions. Frequencies are assumptions until checked against usage.

**Design work needed first** (about 3 to 4 days, before the matching phase): Settings tabs and their five content screens, the account menu, the candidate table, the three-reason "Not a threat" step, and "Subdomains we found". The rest reuse existing components and need layout only.

**Order change:** because two-factor, account deletion and Sign out are must-haves with no design, schedule that design work in Phase 0 so Phase 2 and Phase 6 are not blocked.
