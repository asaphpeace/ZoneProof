# ZoneProof role x feature matrix

Status: draft for review (2026-10-11). Nothing in `frontend/` changes until this is approved.
Inputs: `ZONEPROOF_FEATURE_MAP.md` (every row of its sections 1, 2 and 4) plus the rows the role model adds (section H).
Companion to `ZONEPROOF_REDESIGN_PLAN.md`.

## How to read it

The data is the same for everyone. Each cell says how that role meets the feature.

| Code | Meaning |
|---|---|
| **H** | On the role's first screen |
| **1** | One click away, in a place of its own |
| **D** | On demand: inside a detail, dialog or settings |
| **S** | Summary only: the outcome in plain words, no controls |
| **-** | Not shown to this role |
| **=** | Same for everyone; not part of any lens |

Roles: **Owner** (business owner or board), **Operator** (IT manager or MSP technician), **Principal** (MSP owner), **Verifier** (insurer, bank, customer; no login, sees one shared page).

Presentation is not permission. A cell says what a role sees first, not what it may do. Permissions stay in the existing role model.

The Operator column is also what a small-business owner with no IT sees when working alone, plus prepared fixes, because one person can hold more than one role.

## Summary

| Role | Rows shown | Content on first screen | First screen + one click | Not shown |
|---|---|---|---|---|
| Owner | 53 of 94 | 5 | 19 | 41 |
| Operator | 81 of 94 | 4 | 33 | 13 |
| Principal | 56 of 94 | 5 | 33 | 38 |
| Verifier | 9 of 94 | 2 | 2 | 85 |

First-screen content rows (shell chrome excluded: bell, verification banner, account menu):

- **Owner**: A1 ZoneProof Score and pillars; A2 Three questions cards (spoofable, certificates, encryption); A7 First-run empty state; H1 "Needs your yes": approvals queue; H3 Monthly "what we did" proof of value
- **Operator**: A3 Certificate expiry; A7 First-run empty state; E1 Overview and candidate triage; H4 Cross-client work queue (portfolio Fix list)
- **Principal**: A1 ZoneProof Score and pillars; A7 First-run empty state; D4 Portfolio readiness roll-up; H3 Monthly "what we did" proof of value; H5 Client health table with attention flags
- **Verifier**: A1 ZoneProof Score and pillars; H8 Shareable proof page / attestation link

Coverage check: every one of the 94 rows is shown to at least one role, so nothing is dropped.

## A. Status and overview

| # | Feature | Owner | Operator | Principal | Verifier | Source | Note |
|---|---|:-:|:-:|:-:|:-:|---|---|
| A1 | ZoneProof Score and pillars | H | 1 | H | H | map | Owner: one verdict in plain words. Operator: inside a client. Principal: portfolio roll-up. Verifier: the verdict is the page. |
| A2 | Three questions cards (spoofable, certificates, encryption) | H | 1 | 1 | S | map |  |
| A3 | Certificate expiry | S | H | 1 | S | map | Operator sees expiries as work items, not a chart. |
| A4 | Threat surface (attempts, sources) | S | 1 | 1 | - | map | Owner gets one sentence: how many attempts were blocked. |
| A5 | Date range filter | - | D | D | - | map |  |
| A6 | Scan a prospect's domain | - | D | 1 | - | map | A sales act for the MSP. |
| A7 | First-run empty state | H | H | H | - | map |  |
| A8 | Still waiting on the first report | S | D | D | - | map |  |

## B. Domains and DNS

| # | Feature | Owner | Operator | Principal | Verifier | Source | Note |
|---|---|:-:|:-:|:-:|:-:|---|---|
| B1 | Domains list: search, pagination, sync | 1 | 1 | 1 | S | map | Verifier sees only the domains the owner chose to attest. |
| B2 | Subdomains shown under the parent | - | D | - | - | map |  |
| B3 | Verify ownership | D | D | D | - | map |  |
| B4 | Current DNS records, policy ID | - | D | - | - | map |  |
| B5 | Exclude a source | - | D | - | - | map |  |
| B6 | Add-domain wizard (incl. platforms step) | 1 | 1 | D | - | map |  |
| B7 | Subdomain discovery: monitor / exclude | - | D | - | - | REG N5 |  |
| B8 | "Is it live yet?" and "I have published it" | D | D | - | - | REG N6 | Last step of the DNS change review. |
| B9 | DMARC volume histogram | - | D | - | - | REG N7 |  |

## C. Analyze

| # | Feature | Owner | Operator | Principal | Verifier | Source | Note |
|---|---|:-:|:-:|:-:|:-:|---|---|
| C1 | Posture: compliant vs non-compliant volume | S | 1 | - | - | map |  |
| C2 | DMARC analyzer: source, IP, result | - | 1 | - | - | map |  |
| C3 | Platform health matrix | S | 1 | - | - | map | Owner: "4 services fine, 1 needs attention". |
| C4 | Add a platform / SPF builder | - | D | - | - | map | An owner working alone reaches this as a prepared fix. |
| C5 | DKIM failure diagnosis | - | D | - | - | map | Same: prepared fix for a lone owner. |
| C6 | MTA-STS breakdown and hosting status | S | 1 | - | S | map | Verifier: encryption enforced, yes or no. |
| C7 | MX host readiness scorecard | - | D | - | - | map |  |
| C8 | TLS failure analysis and trend | - | 1 | - | - | map |  |
| C9 | Certificate inventory, re-probe, SAN / TLS | S | 1 | 1 | S | map |  |
| C10 | DNS change log, before / after | D | 1 | D | - | map |  |

## D. Roadmap

| # | Feature | Owner | Operator | Principal | Verifier | Source | Note |
|---|---|:-:|:-:|:-:|:-:|---|---|
| D1 | Roadmap track: stages per domain | S | 1 | 1 | S | map | Owner sees it as the Fix list. Verifier sees the current protection level only. |
| D2 | Enforcement readiness, advancement check | - | 1 | - | - | map |  |
| D3 | Impact simulation on collected traffic | - | D | - | - | map |  |
| D4 | Portfolio readiness roll-up | - | - | H | - | map |  |
| D5 | BIMI step | - | D | - | - | map |  |
| D6 | DNS change review (diff, registrar steps, email developer) | D | D | - | - | map | Owner uses it to approve, from "Needs your yes". |

## E. Brand protection

| # | Feature | Owner | Operator | Principal | Verifier | Source | Note |
|---|---|:-:|:-:|:-:|:-:|---|---|
| E1 | Overview and candidate triage | 1 | H | 1 | - | map | Owner: decision cards. Operator: the queue. Principal: counts across clients. |
| E2 | Candidate drawer (full evidence) | D | D | - | - | map |  |
| E3 | Campaigns | - | 1 | - | - | map |  |
| E4 | Cases with owner and deadline | 1 | 1 | 1 | - | map |  |
| E5 | Takedown complaint draft | D | D | - | - | map | Drafts only. ZoneProof never sends it. |
| E6 | Evidence pack (JSON / PDF, hash) | D | D | - | - | map |  |
| E7 | Defend: blocklists, names to register, reporting | - | 1 | - | - | map |  |
| E8 | Funnel | - | D | - | - | map |  |
| E9 | Brand profile: keywords, official domains | D | D | - | - | map | Owner knows which names are theirs. |
| E10 | MSP roll-up across clients | - | 1 | 1 | - | map |  |
| E11 | Rendered-page evidence (thumbnail pair) | D | D | - | - | REG N8 |  |
| E12 | Full candidate list, filters, bulk decisions | - | 1 | - | - | REG N16 |  |
| E13 | Candidate lifecycle dots | - | D | - | - | REG N9 |  |
| E14 | Coverage statement and source health | - | D | - | - | REG N11 |  |
| E15 | Scan progress and history | - | D | - | - | REG N12 |  |
| E16 | Trademarks kept as evidence | D | D | - | - | REG N15 |  |
| E17 | Report-submission status, notification log | - | D | - | - | REG N14 |  |
| E18 | Why a name was flagged; cluster graph | - | D | - | - | REG N10 |  |
| E19 | Page-check worker status | - | - | D | - | NEW N13 | Shown to whoever is the account admin; others meet it only as an empty state. |

## F. Reports, alerts and help

| # | Feature | Owner | Operator | Principal | Verifier | Source | Note |
|---|---|:-:|:-:|:-:|:-:|---|---|
| F1 | Reports: view and download | 1 | 1 | 1 | S | derived | Exists today as the PDF. Listed so the owner's side is explicit. |
| F2 | Report wizard: create, schedule, send | - | 1 | 1 | - | map |  |
| F3 | Technical version of a report | - | D | D | - | map |  |
| F4 | White-label brand name ("Sent as") | - | - | 1 | - | map |  |
| F5 | Alert channels, webhooks, SIEM export | D | D | D | - | map | Owner: only "who gets told" by email. |
| F6 | Bell and alerts | H | H | H | - | map | Shell chrome. |
| F7 | AI assistant and narrative cards | 1 | 1 | 1 | - | map |  |
| F8 | Glossary and concept cards | 1 | D | D | - | map | Owner meets them inline as "What's this?". |
| F9 | Documentation | D | D | D | - | map |  |
| F10 | Send a test email | - | D | - | - | NEW N3 |  |
| F11 | Reporting configuration (read-only) | - | D | - | - | REG N18 |  |

## G. Account and security

| # | Feature | Owner | Operator | Principal | Verifier | Source | Note |
|---|---|:-:|:-:|:-:|:-:|---|---|
| G1 | MSP client tenants, invites, roles | - | D | 1 | - | map |  |
| G2 | Plan and billing, upgrade prompt | D | - | 1 | - | map | Shown to whoever pays. See open question 1. |
| G3 | Audit log (Enterprise) | - | - | D | - | map |  |
| G4 | Email verification banner | H | H | H | - | map | Shell chrome, until done. |
| G5 | Login, reset password, accept invite | = | = | = | - | map | Same for everyone; no lens yet. |
| G6 | Two-factor sign-in | D | D | D | - | REG N1 |  |
| G7 | Change password, edit profile | D | D | D | - | REG N2 |  |
| G8 | Export my data | D | - | D | - | REG N17 | Admin only. |
| G9 | Delete workspace / remove my account | D | D | D | - | REG N2b | Workspace: admin. Account: any member. |
| G10 | Account menu: who am I, plan, sign out | H | H | H | - | REG N19 | Shell chrome. |
| G11 | Team members inside one tenant | D | - | D | - | NEW N4 | Needed so "Owner" on a case has someone to pick. |

## H. Needed by the role model (not in today's app)

| # | Feature | Owner | Operator | Principal | Verifier | Source | Note |
|---|---|:-:|:-:|:-:|:-:|---|---|
| H1 | "Needs your yes": approvals queue | H | 1 | - | - | role F1 | DNS changes and look-alike decisions waiting on the owner. No backend object exists yet (see H12). |
| H2 | Send to IT: hand-off with context | D | 1 | - | - | map §4 | Owner sends; Operator receives it in the queue. |
| H3 | Monthly "what we did" proof of value | H | - | H | - | map §4 / F3 | Three of the four tiles can be computed from records the app already keeps. "Fixed by you / by IT" cannot (see H18). |
| H4 | Cross-client work queue (portfolio Fix list) | - | H | 1 | - | map §4 |  |
| H5 | Client health table with attention flags | - | 1 | H | - | role |  |
| H6 | Per-client score trends | - | D | 1 | - | map §4 |  |
| H7 | Weekly portfolio digest (email) | - | - | S | - | map §4 |  |
| H8 | Shareable proof page / attestation link | 1 | D | 1 | H | role | The only thing the Verifier sees. No login. |
| H9 | Partner access: invite a provider, share the owner view | 1 | - | 1 | - | role |  |
| H10 | "View as owner" preview | - | D | 1 | - | role |  |
| H11 | Lens switcher for people with more than one role | D | D | D | - | role |  |
| H12 | Request an approval from the owner, with the impact check attached | - | 1 | D | - | role F1 | The sending side of H1. Carries what changes, the impact result, who asked and an expiry date. |
| H13 | Approval history: who approved what, and when | D | D | D | - | role F1 | Also the audit trail an insurer asks for. |
| H14 | Partner access list: who has access, to what, until when, with revoke | 1 | - | 1 | - | role F2 | Owner sees providers; the MSP sees which clients it has access to. Expiry reminders live here. |
| H15 | Access request: the partner asks, the owner approves, scope and expiry chosen | 1 | D | D | - | role F2 | Shopify and GDAP pattern. The owner can narrow the request. A request that is not answered expires. |
| H16 | Hand over the account or bill: transfer to the owner, or back to the MSP, on exit | D | - | D | - | role F2 | Needed because the owner holds the account (Xero pattern). Decision open: see question 6. |
| H17 | Firm-level partner access: add a technician once, scope them to clients | - | - | 1 | - | role F2 | Xero's known pain is inviting each staff member per client. |
| H18 | Activity record: what was fixed, by whom, and when | D | D | 1 | - | role F3 | Source of the proof-of-value tiles. Needs actor-stamped records for DNS fixes (see summary). |
| H19 | Free domain check: a passive, public posture result anyone can run and share | D | D | 1 | - | role F5 | Works before login. Passive lookups only, rate-limited. For an MSP it is the prospect scan with a shareable result (A6). |
| H20 | Hosted DMARC and SPF: delegate once with one record, then policy changes need no DNS edit | S | D | - | - | role F6 | Extends the managed MTA-STS hosting pattern. The owner sees the outcome; the technician sets it up. |

## What the matrix shows

1. **Each role meets a fraction of the product.** Owner 53 of 94 rows, Operator 81, Principal 56, Verifier 9.
2. **First screens are small.** Owner 5 content rows, Operator 4, Principal 5, Verifier 2.
3. **Nothing is dropped.** Every row is shown to at least one role.
4. **The Owner's home depends on three things that do not exist yet**: approval requests (F1), partner access (F2) and proof of value from real records (F3). The next section says what each needs.

## F1 to F3 checked against the backend (2026-10-11)

Method: read the audit-log model and the action names written across routers and services, and the model files for who / when fields. The list of audited actions came from a text search and may not be exhaustive.

### F1. Approval requests (rows H1, H12, H13)

- **Today:** nothing models a request to a person. Sender recommendations carry `dismissed` and `snoozed_until` but no actor. The DNS change review is a dialog, not a record.
- **Needs:** one record per request: what changes, the target domain, the impact-check result, who asked, who must decide, an expiry, the state, and who decided and when.
- **Why it is first:** it is the Owner's first screen, the technician's way to ask, and the source of the actor stamp F3 needs.

### F2. Partner access with scope and expiry (rows H14 to H17, and H9)

- **Today:** invites (created, accepted, revoked), team roles and MSP client tenants are audited. There is no scope narrower than a role, no expiry, no owner-side access request, and no list of who has access to what.
- **Needs:** a relationship record between an owner account and a partner, with a scope, an expiry, a state (requested, active, expired, ended) and either side able to end it. Firm-level: add a technician once and assign clients.
- **Decision open:** question 6 below.

### F3. Proof of value from real records (rows H3 and H18)

| Tile | Can it be computed today? | From |
|---|---|---|
| Fake emails stopped | Yes | DMARC aggregate reports (threat surface) |
| Mail arrived encrypted | Yes | TLS reports |
| Copycat sites handled, with who and when | Yes | Brand candidates (reviewed by, reviewed at, resolved at), candidate events, takedown records |
| Problems fixed, by you or by IT | **No** | DNS changes are stored with a detection time and no actor. Sender recommendations have no actor. The audit log has no "fix published" or "stage advanced" action among those found. |

- **Consequence:** the "4 by you, 3 by your IT" split on the Owner and MSP boards is not supportable today. F1's approval records would supply the actor for every fix that goes through an approval. Until then, show the three computable tiles and hide the split.

## Questions (1 to 5 open; 6 to 8 resolved)

1. **Who sees Plan and billing (G2)?** Whoever pays.
2. **Does a lone Owner get the Operator's depth?** Proposed: no. Prepared fixes, plus the lens switcher (H11).
3. **Does the Owner see Cases (E4) at 1 or D?** Set to 1 because the owner confirms impersonation. Revisit after testing.
4. **Should the Principal see Brand decisions (E1) beyond counts?** Set to 1 (counts across clients).
5. **Verifier scope.** What may an owner attest: score only, or per-control status too?
6. **Resolved 2026-10-11, account and bill.** On a direct sign-up the owner holds the account and the bill. If an MSP already manages that domain, nothing is taken over silently: the owner proves DNS control with the existing verification, the MSP is told, and it continues as a partner under an access relationship the owner approves or ends. The MSP keeps paying until a hand-over (H16) is agreed. No MSP exclusivity is modelled.
7. **Resolved 2026-10-11, expiry.** Approval requests and partner access requests expire after 7 days, with reminders at day 3 and day 6. Expiry never applies or declines the change: the request goes to "expired, ask again". Partner access defaults to 12 months with a reminder 30 days before.
8. **Resolved 2026-10-11, scopes.** Three: **View** (see, no changes), **Work** (decide and fix, send reports; no people, billing or account), **Manage** (adds people, billing and sharing). The owner is always Manage. Deleting or transferring the account is never grantable. Scope applies to all domains or a chosen set.

## Effect on the boards (not changed yet)

- **Owner board:** "Needs your yes" is design only until F1 exists. The "3 by Acme IT, 2 by you" line should be removed or marked as a placeholder.
- **MSP owner board:** the same split sits in "Fix steps completed". The "Share & access" link on the Owner board has no board yet; it is H14 and H15.

