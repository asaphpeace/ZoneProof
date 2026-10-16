# Encryption (MTA-STS and TLS reporting): what exists, what is drawn, what is missing

Date: 2026-10-12. Analysis only. Nothing has been built or drawn from this. Companion to `ZONEPROOF_SENDERS_DIAGNOSIS_SPEC.md`.

## 0. Method and limits

- **App:** read from the code (backend models, routers, services; frontend views and components). **Not run**, so behaviour described as "will" is read from the code, not observed.
- **Drawing:** the published canvas (version 73): the Encryption lens, the Domain page's Encryption tab, Wizard, Roadmap, Review, and the workspace boards.
- **Standard:** RFC 8460 (SMTP TLS reporting) was fetched and checked for the failure vocabulary. RFC 8461 (MTA-STS) is cited from memory and from the app's own comments.

## 1. The shape of the problem

TLS-RPT is the mirror image of DMARC reports.

| | Sender side (what we built) | Reception side (this analysis) |
|---|---|---|
| Direction | Mail claiming to be **from** your domain | Mail **to** your domain |
| Who reports | Receivers (Google, Microsoft…) | Senders (the servers that tried to deliver to you) |
| The unit | A source IP and what it claimed | A **receiving MX host** and what the sender saw |
| Ground truth | SPF, DKIM, alignment | STARTTLS, certificate, MTA-STS policy |
| What you fix | Your SPF record, a vendor's DKIM, your policy | **Your MX certificate, your STARTTLS, your policy host and records** |
| The decision | "Can I move to reject?" | "Can I move to enforce?" |

One consequence matters for everything below. **Every TLS-RPT failure type describes the receiving side** (RFC 8460 section 4.3): `starttls-not-supported` is "the recipient MX did not support STARTTLS", the certificate failures concern the certificate the recipient MX presented, and the policy failures concern the recipient's policy host or DNS. The sender is the *observer*, not the cause. The one thing a report cannot say is whether the fault is in your MX or in something on the path between you and that sender (a middlebox stripping STARTTLS, a network that rewrites traffic). That is exactly what the per-sender drill-down answers.

## 2. The running app

### 2.1 What it stores (good)

| Table | What is kept |
|---|---|
| `tls_reports` | The whole report as JSON, the reporter organisation and contact, the period |
| `tls_policies` | Per policy block: **policy type** (`sts`, `tlsa`, `no-policy-found`), policy domain, MX host, **the policy string the sender saw**, successful and failed session counts |
| `tls_failure_details` | Per failure: result type, **sending MTA IP**, receiving MX hostname, **HELO**, **receiving IP**, session count, **additional information**, **failure reason code** |
| `tls_aggregates` | A rollup per MX host |
| `ssl_certs` | The latest probe per host: names, issuer, expiry, TLS version, STARTTLS, hostname validity, error kind |

### 2.2 What it shows

`MtaStsView` has an all-domains table (sessions, pass rate, failures, stage), a single-domain view with KPIs, MX host health rows (sessions, pass %, failed count, one explanation), an MX readiness scorecard with a "Fix this" that branches server versus DNS, failure types as a bar list, failure groups per host, and a record-review dialog with prerequisite gates. `MtaStsHostingStatus` runs a **seven-state diagnosis** of the hosted policy (no DNS, nothing on 443, untrusted certificate, certificate for another host, HTTPS but no policy, live), which is the strongest piece in the whole area. The wizard offers a managed CNAME or self-hosting.

### 2.3 Gaps in the app

| # | Gap | Evidence | Consequence |
|---|---|---|---|
| A1 | **The detail is stored and never shown.** Sending IP, HELO, receiving IP, additional information, reason code and the policy the sender saw have no reader | A search finds them only in the model and the parser | You cannot answer "who failed, and was it everyone or one sender?" |
| A2 | **The rollup throws information away.** It groups by MX host only, leaves `reporter_org` empty, keeps one "top reason" (the single largest detail row), and stamps every row with the start of the current month as its period | `rebuild_tls_aggregates` | No per-reporter view, no time series, no "since I fixed it", and a host with three problems shows one |
| A3 | **The "last N days" filter filters on that fake period.** Aggregates are stamped with the first of the month, so a 7-day window mid-month excludes them | `get_tls_overview` compares `period_begin` to `now − days` | Likely shows no data for short windows (read from code, to be confirmed by running) |
| A4 | **Wrong side attributed.** The explanation says "the sending server did not offer STARTTLS" and the fix says "enable STARTTLS on the sending server" | `FAILURE_REASONS`, `_TLS_FIX_ACTIONS` | Tells the owner it is someone else's problem when the standard says the recipient MX did not offer it |
| A5 | **Severity ignores scale.** One failed session out of a million is "critical" if the reason is in a short list | `_severity` | Alarm without proportion |
| A6 | **The policy is checked shallowly.** Only `mode:` is read from the fetched file. The `mx:` patterns are not compared with the real MX records (the classic cause of a silent no-op), `id` is not compared with the TXT record, `max_age` is not examined | `fetch_mta_sts_policy` | A self-hosted policy that authorises the wrong hosts looks fine |
| A7 | **The stage is a flag.** `mark-published` sets it by hand; there is no rollback to `mode: none`, and no max-age ramp | `mark_tls_published`, `_MTA_STS_NEXT_STAGE` | The enforce decision is blind in both directions |
| A8 | **The gate is a cliff.** "Zero TLS failures in testing window" never passes if one session fails; it also ignores how many senders reported | `get_tls_record_diff` | Either nobody can enforce, or people click "Publish anyway" |
| A9 | **No coverage signal.** Nothing says how many distinct senders reported, how many days, or whether Google and Microsoft are in the sample | (absent) | A clean report from two senders reads as proof |
| A10 | **Recommendations lose the sender.** The background pipeline writes `source_ip = None` | `_bg_tls_recs` | The sender is on the row and is thrown away |

## 3. The drawing

### 3.1 What is drawn

| Board | What it has |
|---|---|
| **Encryption lens** | Four KPI cards; a domain table with policy mode, hosted by, encrypted %, failure count, main reason, one action; a "Why sessions failed" bar list; a "Mail servers" table |
| **Domain page, Encryption tab** | 99.4% headline, weekly bars, "Why 112 deliveries weren't encrypted" (their side, fixed items), "Your mail servers", and a "Next step available in 12 days" |
| **Wizard** | Three records to copy, with encryption policy hosted by us |
| **Workspace** (Today, Case, Programme, Clients) | One certificate case. **No MTA-STS case, no stage ladder, no encryption statistics.** |

### 3.2 Gaps in the drawing

| # | Gap | Detail |
|---|---|---|
| D1 | **It does not drill.** The lens is one table; "Details" opens a page with fixed sample content. No MX host, no sender, no IP, no reporter, no result by sender |
| D2 | **Same wrong side.** "Sender's server doesn't support encryption · their side" and "An old server at one of your suppliers couldn't agree on encryption · Their side" |
| D3 | **The MTA-STS road is missing from the workspace.** The Programme ladder is DMARC only. The app has an MTA-STS track (none, testing, enforce) with blockers; the drawing's Roadmap has no MTA-STS at all, yet "Require now" exists on the lens |
| D4 | **"Require now" opens the DMARC dialog.** The Review board is the DMARC change; there is no encryption change dialog |
| D5 | **The hosted-policy diagnosis is not drawn.** The seven-state check is the best thing in the app and has no place on any board |
| D6 | **No policy-as-published versus policy-as-seen** and no check that `mx:` covers the real MX records |
| D7 | **No cases or fix kits for encryption.** Only certificate expiry exists, and nothing has a verify step ("sessions recovered") |
| D8 | **No statistics in the partition style.** The headline is one percentage and a bar list that does not say what it is a share of |
| D9 | **Not scoped.** The lens shows every client regardless of the shared scope |
| D10 | **Not connected to Senders.** The two halves of the same posture look like two products |

### 3.3 What the drawing does better than the app

Plain wording ("Fixed", "available in 12 days"), a hosting column, one action per row, and a story ("next step") that the app's view lacks.

## 4. The suggestion

### 4.1 One model, mirrored

| Senders | Encryption |
|---|---|
| Sending service, then IP, then pattern, then case file | **Receiving MX host, then sending provider and IP, then pattern, then case file** |
| Pattern = header-from + SPF + DKIM + disposition | **Pattern = domain + MX host + policy type seen + result type** |
| Cause is one of ten deterministic rules | **Cause is one of eight deterministic rules (4.3)** |
| Fix kit, drafts, verify | **Fix kit, drafts, verify** |
| "Who fails if I move to reject?" | **"Who is refused if I move to enforce?"** |
| Partitions that add to 100% | **Partitions that add to 100% (4.2)** |

### 4.2 Statistics, in the partition style

Total: all TLS sessions reported in the period and scope.

| Row | Buckets (each session in exactly one) |
|---|---|
| **Policy the sender saw** | MTA-STS policy applied; DANE applied; no policy found (mail was not protected by a policy) |
| **Outcome** | Encrypted and verified against a policy; encrypted with no policy in force; failed |
| **Why it failed** (a partition of the failed sessions only, and labelled so) | Your server's certificate; your server did not offer encryption; policy file or its host; DNS or DANE; other |

A fourth sentence states the overlap that matters: "of the sessions that failed, N came from one sender", which is the path-versus-server question.

### 4.3 The cause rules (closed set, first match wins)

| Cause | Rule | Whose |
|---|---|---|
| `cert_expired` | Result `certificate-expired` | Your MX |
| `cert_name` | `certificate-host-mismatch`, or the probe shows the name is not covered | Your MX or policy host |
| `cert_untrusted` | `certificate-not-trusted` or `sts-webpki-invalid` | Your MX |
| `no_starttls` | `starttls-not-supported` **and** it appears from two or more reporters or most of the sessions to that host, or the live probe agrees | Your MX |
| `path_interference` | `starttls-not-supported` or `validation-failure` from **one sender or one network only**, while the live probe passes | Between you and that sender |
| `policy_unreachable` | `sts-policy-fetch-error`, or the hosted diagnosis is not "live" | Policy host or CNAME |
| `policy_wrong` | `sts-policy-invalid`, or the `mx:` patterns do not cover a real MX, or the `id` does not match the TXT | Your policy |
| `dane` | `tlsa-invalid`, `dnssec-invalid` | Your DNS |

Each carries a confidence, as on Senders, and a plain statement of what the report cannot say.

### 4.4 The drill (same levels as Senders)

1. **Encryption lens:** one line per domain, as drawn, with the partitions beneath and a "Common causes" strip across domains.
2. **A domain:** its MX hosts, each with its own three partitions and a policy status (stage, hosting diagnosis, `mx:` coverage, `id` match).
3. **An MX host:** who tried to reach it. Sending providers (grouped from IP and reverse DNS, using the same vendor table as Senders), their sessions, and the failure each saw.
4. **A case:** Evidence (policy as published now versus policy as the senders saw it; the live certificate and STARTTLS probe; a ledger by sender and reporter that adds up), Fix (renew the certificate, enable STARTTLS on the MX, repair the CNAME, update the `mx:` list and bump the `id`), and Verify (sessions recover for N days, then the case resolves itself).

### 4.5 Put the road in the Programme

Add an **MTA-STS ladder** beside DMARC: not started, testing (`mode: testing`), enforce, with `mode: none` as the rollback. Gates computed from the data rather than a cliff: every MX offers STARTTLS with a valid, name-matched certificate; the policy is fetchable and its `mx:` covers the real MX records; failures from recognised senders are below a threshold across a minimum number of days and distinct reporters; the certificate has more than 30 days left. "Who would be refused today" is shown as the impact check.

### 4.6 One posture page

Show both halves of the story together on Today and in the client report: **Mail from you** (DMARC partitions) and **Mail to you** (encryption partitions), each with its own "yours to fix" split, and the same cases queue.

### 4.7 What the backend needs

1. Expose `tls_failure_details` and `policy_string`, with provider attribution from the IP.
2. Replace the rollup with real periods per report, per reporter, per MX host, per result type (and keep the failure distribution, not one reason).
3. Fix the "last N days" filter by using the real report period.
4. Correct the wording and fix routing for every result type (recipient side), and add the breadth rule for path interference.
5. Deepen the policy check: `mx:` patterns against live MX, `id` against the TXT, `max_age`, and the hosted diagnosis stored with history.
6. A `mode: none` rollback and a staged `max_age`.
7. A coverage indicator: distinct reporters, days of data, and whether the large senders are among them.

## 5. Risks and limits

- **Small samples.** TLS-RPT arrives from fewer senders than DMARC reports. Statistics from three reporters must say so.
- **Path versus server cannot be proven** from reports. The breadth rule is a strong signal, not a certainty, and the page should say so.
- **Attribution depends on the vendor table**, which does not exist yet.
- **The A3 finding is from reading the code.** It should be confirmed by running a 7-day query against a mid-month database before anyone relies on it.
- **The drawing's samples are illustrative**, as everywhere else.

## 6. Decisions needed

1. Treat reception as a first-class lens that mirrors Senders (same levels, same case model)?
2. Add the MTA-STS ladder and `mode: none` rollback to the Programme?
3. Use the breadth rule to separate "your MX" from "the path"?
4. Show **Mail from you** and **Mail to you** together on Today and in the client report?
5. Correct the wording in both the app's knowledge text and the drawing now, before any drawing work?

## 7. Drawn (2026-10-12, canvas v74)

All five decisions were taken as proposed. The Encryption lens was redrawn from scratch to mirror Senders, and the same reception dataset now feeds the other boards.

| Board | What changed |
|---|---|
| **Encryption lens** | Scope bar (client, domain). Statistics as three partitions (policy the sender saw, outcome, why it failed), a coverage line, and the "of the failures, yours versus the path" sentence. All-domains view: "where the failures come from" (at most three causes) and one line per domain with stage, policy host health, encrypted percentage, biggest issue and status. Domain view: the policy card (stage ladder, hosted-policy diagnosis, mx coverage, id match, lifetime, reports), an impact card ("who would be refused"), mail-server cards with certificate and STARTTLS checks and the senders that reached each, Group by mail server or sender, and a docked case file: what the server shows, what the sender saw, the cause with its confidence and what a report cannot say, the policy as published and as seen, a ledger by sending IP that adds up, and what to do. |
| **Programme** | A second track, MTA-STS, beside DMARC: Not started, Testing, Required, with computed gates (STARTTLS and name, certificate life, policy host answering, mx coverage and id, failed share below 0.5%, days and senders), the impact check, a change panel showing the policy file diff with a short first lifetime, and a rollback that states senders keep a cached policy for its lifetime. |
| **Today** | The statistics card now has two halves: mail from you and mail to you. |
| **Case** | Three encryption cases (path, policy unreachable, policy fetch in an enforced domain) with kits, and a ledger that says "deliveries". |
| **Monthly client report** | "How mail reached you" with the same partitions, and a lead that names the encryption result. |
| **Domain page** | The Encryption tab says "Probably the path" with the right facts and a link to the lens. |

Not changed: the running app (its wording and the other items in section 2.3), which belongs in the build phase.

### 7.1 Sample data note
Six domains, five with reports, 38,554 deliveries in 7 days: 99.5% encrypted, 192 failed (58 on the clinic and dental policy or servers, 134 seen by one sender only). Example Legal publishes no TLS reporting record, so it has no reports and the lens says so.
