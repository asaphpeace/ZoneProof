# The engineer's workspace: recombination plan

Date: 2026-10-12. Drawing-board phase: nothing here is built and `frontend/` is untouched. Builds on `ZONEPROOF_WORKFLOW_WALKTHROUGH.md` (the problem), `ZONEPROOF_ROLE_MATRIX.md` (the roles) and `ZONEPROOF_SENDERS_DIAGNOSIS_SPEC.md` (the diagnosis model).

## 1. The idea in one paragraph

Today the product is organised by **kind of data** (Senders, Encryption, Certificates, DNS changes, Roadmap, Fix list, Brand). An engineer works by **loop**: find what needs me, understand it, prepare the change, get it done, confirm it worked, tell the client. The plan is to reorganise the same elements around that loop, around one shared **case** that every page reads and writes, and to give ZoneProof a defined set of jobs *inside* the loop: it watches, groups, diagnoses, prepares and chases, and the engineer decides and approves. The data pages stay; they become the evidence a case points at.

## 2. Evidence base

Public pages only, mostly vendor material, and no hands-on use. Treated as practitioner opinion, not standard. Where I found nothing, I say so.

| Question | What the sources say | What I take from it |
|---|---|---|
| **How do MSPs roll out DMARC?** | Phased: inventory every domain and sender, monitor at `p=none` for 2 to 4 weeks, ramp quarantine with `pct`, then reject. Assign responsibilities first, keep approval workflows, change logs and documented rollback. One source gives checkpoints: complete sender list by day 14, above 95% pass for legitimate sources by day 30, then 25 / 50 / 75 / 100% about a week apart, and a clean week at 100% before reject. ([EasyDMARC](https://easydmarc.com/blog/msp-new-client-onboarding-checklist/), [Skysnag](https://www.skysnag.com/?p=74700), [BounceZero](https://bouncezero.io/blog/dmarc-rollout-guide), [Gupta](https://guptadeepak.com/guides/dmarc-enforcement-rollout/)) | The work is a **programme with dated gates**, not a list of fixes. Discovery restarts whenever a client adds a sender ([Palisade](https://www.palisade.email/learning/dmarc-monitoring-for-msps)). |
| **What do you do on a failure after ramping?** | Sources disagree: drop to `p=none`, or hold or step back one level and fix. A forgotten `pct=10` left for years is named as the failure mode. ([Palisade](https://www.palisade.email/learning/glossary/dmarc-pct), [BounceZero](https://bouncezero.io/blog/dmarc-rollout-guide)) | Rollback must be a **designed, per-step option**, and a ramp needs an owner and a due date so it is never abandoned. |
| **How do PSA integrations behave?** | Ticket creation is rule-gated; status syncs both ways; severity maps to ticket priority; sync is switched on per customer; the settings screen shows tickets created versus not created. Closed-loop only works for some alert types. ([Sophos](https://docs.sophos.com/central/partner/help/ja-jp/ConnectWiseIntegration/ConnectWiseServiceTicketSynchronization/), [WatchGuard](https://www.watchguard.com/help/docs/help-center/en-US/content/en-us/WG-Cloud/psa_integration/threatsync_psa_ticket_notifications.html)) | Copy these. **Not found:** how duplicates are avoided. That we must design (section 8). |
| **How do service desks treat waiting?** | Separate "stalled on us" from "legitimately waiting on a client, vendor or date"; verify the wait is documented; age out passive waits; sweep order is SLA risk, then our stalls, then legitimate waits. Priority set by clients inflates; rule-based assignment weighing SLA risk, age and impact is steadier. ([Giant Rocketship](https://giantrocketship.com/blog/cleaning-the-backlog-how-to-stop-tickets-from-becoming-msp-support-limbo), [Thread](https://docs.getthread.com/skill-library/qa-and-closure/aging-and-sla-cleanup), [MSPbots](https://mspbots.ai/?p=11367)) | Our "Waiting" needs **reasons and a next touchpoint**, and priority must be **computed**, not typed. |
| **How much should software do alone?** | Gate by blast radius, reversibility and compliance impact: act-and-alert for low risk, prepare-then-approve for the rest. Approvals auto-deny after a timeout (10 minutes in one example). ConnectWise: AI-generated scripts always need approval. ([DevOps AI](https://devops.ai.rain.tech/zones/service-desk/process-areas/playbook-automation.html), [LimaCharlie](https://docs.limacharlie.io/5-integrations/tutorials/human-in-the-loop-response/), [Splunk](https://lantern.splunk.com/Security_Use_Cases/Automation_and_Orchestration/Building_a_SOAR_playbook_for_user-initiated_approval_of_automation), [ConnectWise](https://www.connectwise.com/platform/ai/sidekick-psa)) | An explicit **autonomy ladder** with a gate per action. **Not found:** an industry standard for tiers, so ours is a proposal. |
| **What do hosted vendors automate?** | Valimail: delegation by NS or CNAME, one-click sender authorisation, a maintained approved-sender list. Sendmarc: deployment task templates, PSA triggers, hosted SPF, DKIM, DMARC, BIMI on higher plans. Caveats: delegation is required for the automation, macro-based SPF can be brittle, and you still appoint an owner and identify services. ([Valimail](https://www.valimail.com/?p=13678), [Sendmarc](https://marketplace.connectwise.com/sendmarc)) | Delegation (our F6) is what turns "prepared" into "done". Without it we can only prepare. |
| **What do clients want to see?** | Risk reduction and value, not ticket counts; detection and response times; be open about failures; explain swings. ([Guardz](https://guardz.com/blog/the-ultimate-quarterly-business-review-qbr-checklist-for-msps/), [JumpCloud](https://jumpcloud.com/blog/msp-quarterly-review-guide)) | Reports need **time to remediate** and honest failures, built from cases. |

## 3. Principles

1. **Organise by the loop, not the data type.** Today, Case, Programme, Clients, Reports.
2. **One work item.** Every queue, list and approval is a view of the same case. Brand Guard already has cases with Open, Came back and Closed; we extend that, we do not invent a second one.
3. **Context travels.** No link may land unscoped. A case opens with client, domain and evidence already in place.
4. **One shell, one nav, one scope** (client, then domain) on every operator page.
5. **ZoneProof does the legwork, the engineer owns the decision.** Autonomy is a ladder with a gate per action (section 5), and the engineer can raise or lower it per client.
6. **A case closes on outcome, not on "published".** Every action carries an expected effect and a check.
7. **Quiet when healthy.** Exceptions first; the same problem is one case, not forty.
8. **Say what the data cannot know.** Aggregate reports are counts, not messages.
9. **Hard limits, unchanged:** ZoneProof never sends takedowns or reports itself (drafts only), never changes client DNS it does not host, and never contacts a client without an approved draft.

## 4. The recombination

### 4.1 Five spaces in one operator shell

| Space | Answers | Contains |
|---|---|---|
| **Today** | What needs me, in what order, and why | The single queue across clients: cases ranked by computed priority, with state, owner, next touchpoint |
| **Clients** | How is each client doing, and what is the programme | Client, then domain list; health; per-domain programme |
| **Case** | Why, what to change, did it work | The workbench (4.2) |
| **Programme** | Where each domain is on the road to reject | The Roadmap: gates, ramp schedule, rollback, owner |
| **Reports** | What did we deliver | Monthly and QBR drafts built from closed cases |

Settings, Team and Integrations stay at the foot. The owner, principal and verifier lenses are the same data under their own first screens (already specified).

### 4.2 The case workbench

One screen, opened from anywhere, URL-addressable. Three areas:

| Area | What it holds | Source today |
|---|---|---|
| **Evidence** | The pattern, cause, relation chips, the "adds up" ledger, signals; for a certificate case the certificate; for a policy case the gates | Senders case file, Encryption, Certificates, DNS changes, Roadmap gates |
| **Fix** | A **prepared change**: the exact record or setting, vendor-specific steps, who controls the DNS, a client-ready message, ticket text, approval request, backout note | Review dialog, SPF builder, Approval request, Send to IT |
| **Timeline** | Decisions, hand-offs, reminders, verification results, comments | Domain History, Fix list "Waiting", approval history |

The sender, encryption, certificate and change **pages remain** as lenses ("show me all senders for this client"), and every row in them opens a case.

### 4.3 Where each existing element goes

| Today | Becomes | Change |
|---|---|---|
| Operator To do | **Today** | Computed priority, states with reasons, snooze, "why is this first" |
| Fix list (owner voice) | Owner lens, plus Today filtered to "waiting on client" | Same cases, plain-language voice |
| MSP clients, MSP owner view | **Clients** | One page, principal toggles roll-ups |
| Domains | Clients › domain list | One list, one filter |
| Domain detail | Domain page: its cases and its programme | Tabs become areas of the case |
| Senders page | Sender lens + case evidence | Keep patterns, filters, ledger |
| Encryption, Certificates, DNS changes | Lenses + case evidence | Each row opens a case |
| Roadmap | **Programme** | Adds ramp schedule, owner, due dates, rollback |
| Review dialog | **Change** (Case › Fix) | Parameterised: DMARC step, SPF, DKIM, vendor, certificate |
| SPF builder | A tool inside Fix | Entered only from a case that needs it |
| Approval request | Case › Fix › Approval | Already specified (7-day expiry, reminders) |
| Brand (decide, campaigns, cases, defend) | Same shell, same case model | Lifecycle already matches |
| Reports, Client report | **Reports** | Built from closed cases, with time to remediate |
| Notifications | Settings + per-technician routing | Per client and per case type |
| Assistant | "Ask about this case" inside Case | Grounded in the case |
| Wizard | Onboarding programme (a case template) | Add client, then domain |

## 5. ZoneProof as the engineer's colleague

### 5.1 The ladder

| Level | Meaning | Examples here |
|---|---|---|
| **A0 Observe** | Collects and shows | Ingest reports, probe DNS, re-probe certificates |
| **A1 Recommend** | Suggests; changes nothing | Priority, "looks like Mailchimp", next programme step |
| **A2 Prepare** | Drafts the work; nothing leaves | The record, vendor steps, change request, ticket text, client message, report note |
| **A3 Do with approval** | Acts once a person approves | Create a PSA ticket (rule-gated), send an approved reminder, publish a hosted or delegated record, step the policy |
| **A4 Do and tell** | Acts alone on safe, reversible work, then reports | Re-check after a change, mark a case watching, auto-resolve after clean reports, reopen on regression, age out a stale wait |
| **Never** | Not offered | Send takedowns or reports, edit DNS it does not host, message clients without an approved draft |

### 5.2 What the colleague does at each step

| Step | ZoneProof | Engineer | Level |
|---|---|---|---|
| Find | Groups failures into cases, dedupes, ranks by SLA risk, blast radius, gate blocked and age | Reviews order, snoozes | A1 to A4 |
| Understand | Pattern, cause, evidence, signals, "what we cannot know" | Confirms or says "this is wrong" | A4 |
| Prepare | Builds the Fix kit for the cause | Edits, picks who executes | A2 |
| Do | Hosted record, ticket, reminders, approval request | Approves | A3 |
| Chase | Reminder cadence (days 3 and 6, exists), nudges, expiry (7 days, exists) | Takes over a stalled wait | A3, A4 |
| Verify | Watches DNS, then the outcome; resolves, or reopens on regression | Reviews exceptions | A4 |
| Report | Drafts the monthly note and QBR from closed cases | Edits and approves | A2 |
| Learn | Decisions feed the attribution table (tenant first, shared after review) | Corrects | A2 |

### 5.3 Autonomy settings

Per client and per action, defaulting to A2 for anything client-facing and A3 for anything that changes DNS. Raising a gate is an explicit, logged setting ("auto-create a ticket when a failing pattern exceeds 500 messages a week").

## 6. The case model

**States:** New → Triaged (owner set) → Prepared (fix kit ready) → Waiting → Watching (change is live; outcome being checked for N days) → Resolved or Won't fix (reason and review date) → Reopened.

**Waiting has a reason and a next touchpoint:** client, client IT, vendor, approval, DNS propagation, scheduled date. A wait with no touchpoint is flagged as a stall. A passive wait ages out after a threshold, with a final notice.

**Fields:** client, domain, kind (sender, policy step, certificate, brand, change), evidence references, cause and confidence, computed priority with its reasons, owner, due or snooze, linked ticket, decisions, timeline.

**Dedupe key:** the pattern (domain, fingerprint), the certificate, or the programme step. A case reopens only on a material change, not on every report.

**Priority is computed**, shown with its reasons, and cannot be typed in by a client.

## 7. How the walkthrough tasks resolve

| Task | Today | In the new shape |
|---|---|---|
| T1 Onboard | Blocked | Onboarding programme: add client, add domain, baseline state ("collecting, decisions after about 14 days"), checkpoints at day 14 and 30 |
| T2 New unknown sender | Partial | Today row opens the case scoped to that IP; "It is one of ours" is recorded and adds to the register |
| T3 Fix a failing service | Blocked | Fix kit: vendor steps, records, who owns DNS, ticket text, approval; then Watching |
| T4 Move to reject | Completed | Same, plus ramp schedule, rollback and a clean-week check |
| T5 Hand to client IT | Completed to hand-off | Ticket created per rule, status synced, nudge is a real reminder, the recipient has a page |
| T6 Monthly report | Completed | Built from closed cases with time to remediate |
| T7 "Why did it go to spam?" | Partial | The case says what the data can and cannot show, and offers the message-trace steps |
| T8 Technician leaves | Completed | Cases show owners, so a leaver's cases are reassigned in one action |

## 8. PSA design (from the research, plus what it left open)

- **Rule-gated per client:** which case kinds and severities create tickets, and for which clients. A counter of created versus not created is shown.
- **Field mapping:** priority, category and client map to the PSA's fields.
- **Two-way status:** closing the ticket closes or moves the case; resolving the case closes the ticket.
- **Dedupe (not covered by the sources, so this is ours):** one ticket per case id, stored as a mapping; creation is idempotent so a retry cannot duplicate it; a closed ticket whose case reopens is **reopened**, with a note, not duplicated.
- **Start with a generic webhook** (F7), then ConnectWise, Autotask and Halo.

## 9. What delegation changes (F6)

| Action | Without delegation | With delegation |
|---|---|---|
| SPF or DMARC change | Prepared; engineer or client IT publishes at the registrar | Approved in ZoneProof, applied, rollback one click |
| Authorise a new sender | Edit the client's record | One approval |
| Lookup budget | Manual | Managed |
| Verification | Wait for the record to appear | Immediate |

Delegation is a client-by-client decision and must be reversible. Nothing here assumes it.

## 10. Phases (drawing board)

| Phase | Draws | Done when |
|---|---|---|
| **D1** | Operator shell: one nav, one scope (client then domain), deep-link rules, lens switch | Every board in the operator world uses it; no board links unscoped |
| **D2** | Case model and **Today**: states, reasons, priority and its reasons, snooze | A reader can see why each row is where it is |
| **D3** | **Case workbench** using sender cases first: Evidence, Fix kit for the top three causes, Timeline, verify states | T2 and T3 finish on the boards |
| **D4** | **Programme**: ramp, owner, due dates, rollback, onboarding template | T1 and T4 finish with the ramp and rollback shown |
| **D5** | **Clients** (one page) and **Reports** from cases | T5, T6 and T8 finish |
| **D6** | Autonomy settings, PSA rules, the recipient (client IT) page | The ladder is visible and adjustable |
| **D7** | Task test with real engineers using the script in the walkthrough | T2, T3 and T5 finish unaided for most people |

**Measure of success:** re-run the walkthrough; target a weighted score of at least 7.5, with no task blocked.

## 11. Risks and limits

- **A second tool for people who live in the PSA.** If they will not leave it, the case must be reachable from a ticket, and the PSA is the primary surface for status. This is the most likely wrong assumption.
- **Over-automation erodes trust.** One wrong auto-action costs more than many right ones. The ladder, the logs and per-client gates exist for this.
- **A new object adds learning.** "Case" must replace queues, not sit beside them.
- **Delegation is uneven.** Many clients will never delegate; the prepared path must be complete on its own.
- **Unvalidated.** All of this is reasoning and vendor material until engineers test it.

## 12. Decisions needed

1. **One shared case** across Senders, Brand, Programme and the rest, or keep Brand cases separate?
2. **Autonomy defaults:** A2 for client-facing and A3 for DNS changes, with per-client raising?
3. **Is the PSA the primary surface** for some MSPs (cases reachable from tickets), or is ZoneProof the surface and the PSA a mirror?
4. **Name:** "case", "task" or "item" for the shared object.
5. **Start with D1 and D2 together** (shell and Today), because every later board depends on them?

## 13. Decisions taken and the first prototype (2026-10-12)

Decisions: my recommendations were adopted as written. One shared case across Senders, Brand, Programme and the rest; autonomy defaults are A2 for anything client-facing and A3 for any DNS change, raised per client; ZoneProof is the primary surface and the PSA is a mirror, with the case reachable from a ticket; the object is called a case; D1 and D2 first.

Prototype, canvas versions 65 to 69, section "The engineer's workspace":

| Board | Phase | What it shows |
|---|---|---|
| `OpsToday` | D1, D2 | One queue across clients. Priority is computed and explained ("Why is this #1?"). Cases with one cause are one row. Tabs for Needs you, Waiting, Watching, Snoozed, Done. A "since you last looked" card lists what ZoneProof did, tagged A2, A3 or A4. Bulk: take, snooze, create tickets under the client rule. |
| `OpsCase` | D3 | Evidence, Fix and Timeline for one case. The Fix tab is a prepared change: steps, records, who controls the DNS, expected effect, backout, and drafts that only send on approval. The header actions move the case through New, Triaged, Prepared, Waiting, Watching, Resolved; Watching resolves itself after 7 clean days. |
| `OpsProgramme` | D4 | The road from no record to reject, with dated steps, gates computed from the cases, a simulated impact, hold days, a change panel with the diff, and a rollback. Preparing a step is disabled while a gate is open. |
| `OpsClients` | D5 | One client list. A switch shows the MSP owner's roll-up: clients at enforcement, median time to remediate, regressions disclosed, and a quarterly review drafted from closed cases. "Add a client" creates an onboarding programme. |
| `OpsAutonomy` | D6 | The ladder, each action with its gate and reversibility, locked rows that are never offered, per-client delegation and PSA switches, PSA rules and mapping, one ticket per case, and the log of what it did alone. |

Behaviour that is real in the prototype: the scope (client then domain) and the open case are carried between boards through the session; moving a case on `OpsCase` changes Today, Clients and Programme; publishing a ramp step on Programme advances the stage and the next gates.

Not done: the existing boards (Senders and the other lenses, Brand, Reports, Domain detail) still carry their own sidebars and have not been converted; Review, Roadmap and Fix list remain as they were. The vendor steps and record values in the fix kits are illustrative.

## 14. One shell, applied (2026-10-12, canvas v70 and v71)

**Converted to the operator shell (24 boards):** Senders, Encryption, Certificates, DNS changes; Brand protection and its five sub-boards (All candidates, Campaigns, Cases, Defend, Profile, Insight) and Not a threat; Domains, Domain detail, Subdomains found; Reports; Approval request; Share and access; Settings; Notifications. Each now has the same sidebar (Today, Clients, Programme, Reports, the lenses, Brand protection, Notifications, Autonomy and integrations, Team plan and security), with the current page marked and a live "need you" count taken from the same cases.

**Context strip.** Every scoped page starts with the client and domain in scope, how many cases need you there, a link to Today and a clear button. On the Senders lens the scope is live: it opens on the chosen domain and writes back when you change it. On the other lenses the strip states that the sample page shows every client.

**Every sender pattern opens its case.** Patterns with a case show "Open case c10xx"; those without show "Create a case (drafts only)". The old "Send to IT" there became "Open the fix kit".

**Retired boards:** Roadmap, MSP all clients, Operator view and MSP owner view carry a "Superseded by" banner and retitled canvas entries. All links to them now point at Programme, Clients and Today.

**Not converted, deliberately:** the owner lens (Home, Fix list, Wizard, the Owner view, the weekly digest, the monthly client report, the proof page) keeps its own simpler shell, because the owner is a different role; dialogs and overlays (Review, Confirm, SPF builder, Assistant, Account menu); Brand evidence drawer; foundations and the feature map.

**Known seams that remain**
1. Domains, Reports, Brand protection and Settings are reached from both the owner and the operator shell, and now always render in the operator shell. An owner who opens Reports sees the operator sidebar.
2. The Review dialog and the SPF builder are still separate from the Change panel on Programme and the Fix tab on Case.
3. The Encryption, Certificates, DNS changes and Brand lenses show sample data for every client; they do not yet filter to the scope.
4. The owner-voiced Fix list is still a hand-authored list, not a view of the same cases.
