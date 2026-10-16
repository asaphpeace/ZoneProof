# MSP engineer workflow walkthrough

Date: 2026-10-12. Companion to `ZONEPROOF_SENDERS_DIAGNOSIS_SPEC.md` and `ZONEPROOF_ROLE_MATRIX.md`. A task-by-task trace of the canvas (design version 64), with steps counted from the real links and controls. Nothing here was run with a user.

## Method and limits

- **A step is one click or selection.** Reading is not counted. Links were read from the published boards, not from memory.
- **Outcomes:** *Completed* (the task can be finished on the boards), *Partial* (the answer is reachable but the action is not), *Blocked* (the path ends at a missing or wrong screen).
- **Prototype caveat.** Many buttons are inert because the boards are static. I only mark a gap where **no destination is designed** or **the destination is the wrong screen**, not where a button simply is not wired.
- **Not done:** no engineer has used this. Frequencies and weights are mine.

## Three navigation worlds

| Shell | Boards | Nav entries | What it lacks |
|---|---|---|---|
| **Owner** | Home, Domains, Domain detail, Fix list, Wizard | Home, Fix list, Domains, Brand protection, Reports, Settings | Senders, Roadmap, anything technical |
| **Operator** | To do, Operator view | To do, Clients, Brand protection, Senders, Encryption, Certificates, DNS changes, Roadmap, Reports, Settings | **Fix list and Domains** |
| **Analyze** (Senders and its siblings) | Senders, Encryption, Certificates, DNS changes | Clients, Fix list, Domains, Brand protection, Reports, Roadmap, Senders, Encryption, Certificates, DNS changes, Notifications, Settings | **To do**, the operator's home |

The same person moving between three screens meets three different sidebars. Clicking a client in the MSP client list lands in the **owner** home.

## Task traces

### T1. Onboard a new client domain (rare, high stakes)

Operator route: To do → Clients → **Add client** (no board). *Blocked.*
Owner route: Home → Add a domain → Wizard (step 2 of 3) → copy 3 records → pick who adds DNS → Send instructions → Fix list. 5 steps.

| Gap | Detail |
|---|---|
| No client picker | The wizard does not ask which client the domain belongs to |
| Steps 1 and 3 of the wizard | "Your domain" and "Check your senders" are not drawn |
| Bulk | "Import CSV" and "Add domains" on Domains have no destination |
| No baseline state | After publishing, nothing says "collecting reports, first data in ~48h, decisions possible after ~14 days" |

### T2. A new unknown sender appeared overnight: decide (daily)

1. To do: row "Unknown source sent 140 messages as this domain". **Review** →
2. Senders opens at *All domains*, not at that domain or IP. **Context is lost.**
3. Pick the domain in the domain filter → the case file opens on that domain's **largest** failing pattern, which is Mailchimp, not the 140-message sender.
4. Find and open the unknown sender's pattern. **4 steps to the diagnosis.**
5. Decide: **It is one of ours** → SPF builder → tick the service → copy → Review and publish → the Review dialog is the **DMARC p=quarantine change**. *Wrong screen.* "Exclude it" returns to the same page and records nothing.

*Partial.* Diagnosis is strong; the decision is not recorded and the action lands on the wrong dialog.

### T3. Find why a client's newsletters fail, and fix it (daily)

1. Senders → 2. domain filter → 3. choose domain → 4. the Mailchimp pattern. **4 steps to a clear cause.**
5. Cause is "Sender is not authenticating as you". The card says SPF alone cannot fix it, **and its primary button opens the SPF builder.** 6. SPF builder → Review and publish → the DMARC dialog.

*Blocked at the fix.* The vendor-side steps (custom domain authentication in the service, the DKIM records it gives you) and the record to publish are not designed. The page contradicts itself.

### T4. Move a domain to reject (weekly)

1. To do: "Next DMARC stage is available" → **Check impact** → Roadmap.
2. Pick the domain (Roadmap does not open on the one clicked).
3. Read the gates and the simulated impact ("0 legitimate emails affected; 412 fakes a month rejected").
4. **Prepare the change** → Review: the exact diff, why now, the gates, steps for the DNS provider.
5. Copy the record → 6. **I've published it** → "Watching DNS. This updates on its own the moment your change is live."

*Completed in 6 steps.* The strongest path. Gaps: no ramp plan (25% → 50% → 100% with dates), no rollback, no post-change watch ("N clean days"), and a failing sender shown as a gate ("Fix Klaviyo first") is text, not a link to the pattern. If the owner must approve it is a separate board, reached from another screen.

### T5. Hand a fix to the client's IT and track it (daily)

1. From the Review dialog, **Send to IT** (or "Email these steps to whoever manages DNS") → Fix list shows "Waiting on IT · Sent to it@… we'll tick it off when DNS changes · Undo".
2. The queue shows "Waiting: Client IT, 9 days"; the action is **Nudge**, which opens the Review dialog, not a reminder.

*Completed to the hand-off in 2 to 3 steps, and DNS verification is automatic, which is good.* Gaps: no PSA ticket or ticket id, no assignee among technicians, no notes, Nudge is not a nudge, and **the recipient (client IT) has no designed screen**: the instructions arrive by email only.

### T6. Produce and send the monthly report (monthly)

1. Clients → "2 reports ready to review" → Reports.
2. Select a client, 3. edit the AI-drafted note, 4. **Approve and send now** (or schedule 1 Oct).

*Completed in 4 steps.* The best-covered task. Gaps: "Fixed this month: 3" is not a link, and findings from Senders cannot be added to a report as evidence.

### T7. The client asks "why did our invoice go to spam?" (weekly, most common)

Senders → domain → the Xero pattern → "320 messages failed because the signature broke in transit, 2,780 passed".

*Partial, by design.* Aggregate reports are counts, not messages, so the question cannot be answered for one message. **The UI never says so and does not tell the engineer what to do next** (message trace, the failing header, which reporter). The engineer is left to discover the limit.

### T8. A technician leaves (rare)

Settings → Team → Remove [name] → confirm.

*Completed in 3 steps.* Gaps: items have no assignee so nothing is reassigned, no per-client scope, no SSO deprovisioning.

## Findings that cut across tasks

1. **Boards are strong, seams are weak.** Every task loses context at least once: queue to Senders (unscoped), Roadmap to Review (not the clicked domain), Senders to SPF builder to a DMARC dialog.
2. **The Review dialog is hard-wired to one DMARC change.** The SPF builder, Fix list "Fix it", Home "Fix it" (including a certificate step) and the Mailchimp fix all land on it.
3. **Two queues and two senders views.** "To do" (operator) and "Fix list" (owner-voiced, hand-authored); a Senders tab in Domain detail and the Senders page. They are not the same objects.
4. **Client scope is missing.** The Operator view says its pages are "already filtered to the same client scope". The Senders board's client control is inert, and the domain filter would list all 64 domains with no client level.
5. **Decisions are not recorded.** "It is one of ours", "Exclude it" and "Nudge" change nothing. There is no register, no mute, no state on a pattern.
6. **Known undesigned destinations:** Add client, Import CSV, wizard steps 1 and 3, recipient (IT) view, Help and glossary (dead link), vendor-side fix steps, SPF/DKIM change dialogs.
7. **One defect on my own board:** for "Sender is not authenticating as you", the primary action goes to the SPF builder while the text next to it says SPF alone cannot fix it.

## Corrections to the earlier audit

- **Verify was under-scored.** DNS-level verification exists (Review: "Watching DNS", History: "confirmed within 4 minutes", Fix list: "we'll tick it off"). What is missing is *outcome* verification: that the failing pattern actually disappeared.
- **State exists at queue level** (the "Waiting" column and "Sent to IT"). It does not exist on patterns or decisions.

## Result

| Task | Frequency weight | Score /10 | Outcome |
|---|---|---|---|
| T2 New unknown sender | 20% | 4.0 | Partial |
| T3 Fix a failing service | 20% | 3.5 | Blocked at the fix |
| T5 Hand to client IT | 15% | 6.0 | Completed to hand-off |
| T4 Move to reject | 15% | 7.5 | Completed |
| T7 "Why did it go to spam?" | 10% | 3.0 | Partial by design |
| T6 Monthly report | 10% | 8.0 | Completed |
| T1 Onboard a domain | 5% | 2.5 | Blocked |
| T8 Technician leaves | 5% | 5.0 | Completed |
| **Weighted** | | **5.0** | |

## Task script for testing with real engineers

Give each person T1 to T7 on the prototype, one at a time, without help. Record: did they finish, how many clicks, where they hesitated, and what they said they would have done outside the tool. Success is T2, T3 and T5 finished by most people without help.
