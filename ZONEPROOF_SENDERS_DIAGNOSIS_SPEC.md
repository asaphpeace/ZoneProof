# Senders: patterns and the diagnosis spec

Date: 2026-10-12. Companion to `ZONEPROOF_SENDERS_ANALYSIS.md`. Specification for review: nothing here has been built. The canvas board `AnalyzeSenders` draws it with sample data, and its `diagnose()` function is a working copy of section 5.

## 1. Purpose

A DMARC aggregate row is already a bucket of messages that share one authentication result. We should not show messages. We should show the **claim made from a source and what the receiver concluded about it**, then say why, and what to do.

## 2. The model

| Level | Definition | Key |
|---|---|---|
| **Service** | The real sender: Microsoft 365, Mailchimp, "unknown". Attributed from evidence (section 3) | `service_id` or null |
| **Source** | One IP, rolled up to a range (/24, or the provider's published block) | `source_ip` |
| **Pattern** | One distinct authentication fingerprint for a domain in a period | `fingerprint` (hash) |
| **Evidence** | Counts per reporter, raw rows | links to `dmarc_record` |

### 2.1 The fingerprint

A pattern is identified by this tuple, normalised (lower-case, trailing dots removed):

1. `header_from` (registrable and full domain)
2. `envelope_from` domain
3. SPF: `domain`, `scope` (helo or mfrom), `result`
4. DKIM: the **full set** of `(d, s, result)`, sorted
5. `disposition` and override `type` (not the free-text comment)

Excluded on purpose: source IP, count, reporter, report period. **The same fingerprint seen from fourteen IPs is one pattern with fourteen IPs.** That is what makes "why only this IP" visible: the odd IP has a different fingerprint, so it is a different pattern.

### 2.2 What a pattern stores

`pattern(domain_id, fingerprint, period, service_id, message_count, ip_count, first_seen, last_seen, spf_aligned_calc, dkim_aligned_calc, dmarc_pass_calc, receiver_dmarc_result, cause, confidence, also[])` plus `pattern_ip(pattern_id, source_ip, count)` and `pattern_reporter(pattern_id, reporter, count, result)`.

`cause`, `confidence` and `also` are stored, not recomputed in the browser, so the list, the panel and the reports always agree.

## 3. Attributing a service

Evidence, in the order of how much we trust it:

1. **DKIM `d=` and selector** that matches a known vendor pattern (for example `selector1._domainkey` for Microsoft 365).
2. **SPF include or mechanism** in the domain's own record that belongs to a known vendor.
3. **rDNS** of the IP, forward-confirmed.
4. **ASN or published ranges** of a vendor.

Rules: two or more independent items agreeing gives **High**; one item gives **Medium**; none gives "unknown" and the service is not named. We never name a service from the ASN alone. The evidence used is listed on the service card ("Attributed from: …") so a person can see why we said so.

## 4. Verdict: the receiver's, and ours

- **The receiver's result is the verdict.** It is `policy_evaluated` from the report.
- **We compute alignment ourselves** from the three domains and the published `adkim` and `aspf`, because the aggregate row gives no reasons.
- **When they disagree we show both** and say why (usually an override). The panel shows a note: "The receiver reported DMARC pass … we read it as fail."
- Alignment: relaxed means the organisational domains are equal; strict means the domains are equal. DMARC passes when SPF or DKIM both **passes** and **aligns**.

## 5. Diagnosis: the closed set of causes

First match wins. Each rule uses only fields we have or can look up live.

| # | Cause | Rule (all must hold) | Confidence | Panel title |
|---|---|---|---|---|
| 1 | `forwarded` | An override of type `forwarded`, `mailing_list` or `trusted_forwarder` is present | Medium | Forwarded or list mail |
| 2 | `spf_limit` | SPF result is `permerror` | High | SPF record is over the lookup limit |
| 3 | `ok` | DMARC passes through **both** SPF and DKIM | High | Working as intended |
| 4 | `fragile` | DMARC passes through **only one** of SPF or DKIM | High | Passes through one check only |
| 5 | `spoof` | Service unattributed **and** neither SPF nor any DKIM passes | Medium | Probable spoofing |
| 6 | `conflict` | Service unattributed **and** something passes but not for the domain | Low | Evidence conflicts |
| 7 | `modified` | A DKIM signature for the header-from domain has result `fail` | Medium | Signature broken in transit |
| 8 | `vendor_identity` | Service attributed, SPF passes for a domain that is **not** the header-from, and no passing signature for the header-from domain | High | Sender is not authenticating as you |
| 9 | `spf_gap` | Service attributed, SPF is `fail` or `softfail`, and nothing signs as the header-from | High if the live SPF record has no matching mechanism, else Medium | Sender not covered by your SPF |
| 10 | `conflict` | None of the above | Low | Evidence conflicts |

Notes on the order:

- Forwarding comes first because forwarding always breaks SPF and often DKIM, so every later rule would misname it.
- `spf_limit` comes before pass/fail because a broken SPF record is a fault even when DKIM rescues the message.
- `modified` comes before `vendor_identity` so a signature that failed for your own domain is not mislabelled as the vendor's identity.

### 5.1 Secondary findings ("Also")

Appended to any cause except those that already say it:

- A signing key shorter than 2048 bits.
- The SPF record is at 9 or 10 of 10 lookups.
- The service signs as its own domain, so DKIM cannot align (given with `spf_limit`).
- Policy is `p=none`, so a failure is observed but not acted on.

## 6. What the report can and cannot say

| We can state | We can only infer | We cannot know |
|---|---|---|
| The result of SPF and each DKIM signature, and the domain each was for | Why: a mail-flow rule rewrote the envelope, a gateway changed the body | Which message, what the message contained |
| Whether each aligns | That a service is the one sending, from attribution evidence | Whether a signature failed because of the body or a header |
| What the receiver applied, and any override | That a source is spoofing, not just misconfigured | The SPF record **at the time of sending** |

The panel keeps these apart: "What the report shows" (stated) and the sentence under the cause chip ("We conclude"), with a confidence label.

## 7. How a pattern becomes advice

| Cause | First action | Owner view |
|---|---|---|
| `ok` | None | "Working." |
| `fragile` | Add the second check | "Working, but one fault from failing." |
| `vendor_identity` | Authenticate your domain in the service (custom DKIM) | "<Service> is sending as itself. IT needs to set it up." |
| `spf_gap` | Add the service to SPF, or mark it as not ours | "A sender is not authorised." |
| `spf_limit` | Reduce lookups | "Your email record is too long." |
| `modified` | Find what changes mail after signing | "Mail is being altered on the way." |
| `forwarded` | None | "Expected." |
| `spoof` | Mark as ours, or let policy handle it; consider stricter policy | "Someone is sending as you, and it is being stopped." |
| `conflict` | Read the raw record | "We cannot tell yet." |

## 8. Comparing patterns of one service

When a service has more than one pattern, a side-by-side table lists: envelope-from, SPF result and match, signed-by domain, DKIM result and match, applied disposition, IPs, messages. **Rows that differ are highlighted.** The sentence above it names them ("Differs in: Envelope-From, SPF result…"). This is the answer to "why only this IP".

## 9. Backend implications

1. **Re-parse from `raw_xml`** to keep every DKIM signature, SPF scope, override reasons and comments, published policy per report and `human_result`.
2. **Compute the fingerprint at ingestion** and upsert into `pattern`, `pattern_ip`, `pattern_reporter`. Backfill from stored history.
3. **Attribution** needs a vendor table (DKIM patterns, SPF includes, rDNS suffixes, ASN or ranges) that we maintain, and an "unknown" bucket.
4. **Live lookup** of the SPF record and DKIM keys, cached with the date, for rules 9 and 7 and for the lookup count. Always labelled "looked up now".
5. **Diagnosis runs on write and on lookup refresh**, and stores the result.

## 10. Open questions

1. **Thresholds.** "Passes through one check only" is a warning. Should it appear in the failing counts, or in its own bucket? Proposal: its own bucket.
2. **Range roll-up.** /24 is a heuristic. For big providers, should we use their published ranges instead?
3. **Naming.** "Pattern" is an internal word. The owner view says "kind of mail" or "how it was checked"? Needs a read-through with a non-technical person.
4. **A pattern that spans periods.** A pattern is per period in this draft. Should "first seen" and "last seen" carry across periods so a new pattern is flagged as new?
5. **Probable spoofing wording.** It is a claim about a third party. Medium confidence, and "looks like", but the legal and tone review is yours.
6. **Receiver quirks.** If two big receivers disagree about the same pattern, should that be a cause of its own?

## 11. Filtering and grouping (decided 2026-10-12)

Decisions: host means **both** reverse-DNS hostname and bounce (envelope-from) domain, as separate facets; **Group by** replaces the tabs; the canvas pill (13px DM Sans, with counts) is the app-wide standard; filters live in the URL.

| Control | Values | Select |
|---|---|---|
| Result (pills) | All, Passing, One check only, Failing | one |
| Source (search, typed tokens) | provider, hostname contains, IP or prefix, CIDR range | many (OR) |
| Cause | the causes in section 5 | many (OR) |
| Signed by | `d=` + `s=` pair, "No signature" | many (OR) |
| Bounce domain | envelope-from domains | many (OR) |
| Applied | none, quarantine, reject | many (OR) |
| Reporter | reporter organisations | many (OR) |
| Source class | Recognised, Unrecognised, Forwarded | many (OR) |
| Period | existing `DateRangeFilter` | one |
| Group by | Service, IP, Selector | one |

Rules: AND across controls, OR within one. Each option's count is computed under all **other** active filters, and a zero-count option is dimmed (not hidden). Source filters (provider, host, IP, range) re-scope volume to the matching IPs, so the totals always equal what is shown. Domain stays a scope, not a filter. State is encoded as `/senders?group=ip&result=fail&provider=Microsoft%20365&signed=…`. Values in the case file (IP, provider, bounce domain, selector) add themselves as filters.

Dependencies: Signed-by is wrong until every DKIM signature is stored (re-parse). Hostname needs rDNS (enriched after ingestion; "no hostname" must be a value). Provider needs the attribution table.

## 12. Every number carries its evidence (added 2026-10-12)

Rule: no count is shown without a way to see what it is made of, and the breakdown must add back to the number.

- **Case file:** "Where these N messages came from", open by default, with By IP (hostname, reporters, share), By reporter (IPs seen, the result they reported) and By report (report id, reporter, day). A total row and a check ("Adds up") compare all three to the headline. If they disagree the panel says so and tells the reader not to rely on the number.
- **Scoped views:** when a source filter is active, the headline, the ledger and the cards are all re-scoped to the matching IPs, and still reconcile.
- **Selector grouping:** each row expands to the patterns and IPs that make up its volume. A message with two signatures is counted under both rows, so rows may add up to more than the total, and the page says that.
- **"No signature" is not one thing.** It is split by what SPF did: counts, passes for another domain, fails, error. "SPF only or nothing vouched" is retired as wording.
- **Limit of the evidence:** aggregate reports hold counts per source and result, not messages. By report is the lowest level we can show truthfully, and the panel says so.
- **Backend:** needs `pattern_ip` and per-report counts (`pattern_report`: report id, reporter, period, count) so By report is real, not derived.

## 13. Several domains, relations, signals and AI (decided 2026-10-12)

**Unit.** (your domain x source). Policy, records and alignment belong to the domain; IP, provider, host and selector belong to the source. A source can appear under many domains, which is the correlation, not a duplicate.

**Scope.** One domain is always in scope on the case-file view. "All domains" shows one line per domain and never patterns. No figure is summed across domains unless the heading says so ("across these 3 domains"). The posture strip is always scoped and labelled.

**Levels, capped.** All domains (one line each) -> one domain (service cards, patterns, comparison) -> case file. Subdomains are a chip on the row, not a level; the existing subfold remains only when a domain has more than one `header_from`.

**Attention, not enumeration.** A domain "needs attention" when it has failing patterns that your policy is not already stopping. Spoofing that is quarantined or rejected is shown as "stopped by your policy" and does not raise a domain's status.

**Relations, not raw strings.** Bounce domain and signing domain are shown as a relation to "Shown as" (yours, your subdomain, another domain) and a tie to a service ("Mailchimp's"). A value that ties to neither is shown as "not tied to any service we know" with the raw string. Facets filter on relations (Signed by: you / another domain / no signature; Bounce domain: yours / another domain). The selector always travels with its domain and stays searchable.

**Words.** Your domain, Shown as (Header-From), Bounce domain (envelope-from), Signed by (`d=`). The bare word "domain" is not used for the last three.

**Common causes.** Failing patterns grouped by `(service, cause)` across domains, at most three lines, counted not predicted. Each line is a filter and a fix-list entry. This answers "which provider fails everywhere" without a separate view.

**Signals (case file).** Only those that are true, ranked, never more than three:
1. Your DNS history: the pattern first appeared within two days of a change to your records **and** the change concerns the same service (date proximity alone is not enough).
2. Other organisations: aggregate only, with a floor of three organisations, no names or volumes.
3. Your other domains: the same IP sends as N of your other domains (links to a filter).
4. Reporters: receivers disagree.
5. Time: first seen, new this week.

**AI, where and where not.** One AI block per view (above the fold, badge and timestamp, rule-based fallback). All-domains: one sentence written from the counted common causes. Case file: a suggested service name with the evidence listed and Accept / Not this. The AI never decides pass or fail, alignment or the cause. A suggestion changes nothing until accepted; an accepted suggestion is saved for the organisation first and joins the shared list only after review.

**Cross-organisation intelligence.** Approved on 2026-10-12 as anonymous aggregates only: the count of other organisations that saw an IP failing or attributed, floor of three. No domain names, no volumes, no message data leave a tenant. Needs a line in the terms before release.

**Data model corrections.** A pattern's identity is stable: (`header_from`, fingerprint), with `first_seen`, `last_seen` and counts per period. It carries both `monitored_domain_id` and `header_from`. The group key for common causes is `(service, cause)`, so no domain-independent fingerprint is needed. DNS change events are keyed by time and by the service they concern.

### 13.1 The domain filter (added 2026-10-12)

"Your domain" is a searchable single-select filter, not a row of pills, so it holds at any number of domains. It opens a list ordered by need (failing, then stopped, then alphabetical), each option carrying that domain's own status ("25,040 failing", "95 stopped", "all passing"). Typing narrows it ("2 of 9 domains match"); Enter takes the first match; Escape closes. "All domains" is always the first option, and a "← All domains" button sits beside the filter when zoomed in. The choice is in the link as `?domain=`. Single-select by design: comparing domains is what the all-domains lines are for. Multi-select would reintroduce a blended view, so it is left out unless a real need appears.

## 14. Message statistics: partitions that each add to 100% (added 2026-10-12)

Rule: the headline numbers on any sending page are **partitions of all messages in scope**. Every row adds to 100% of the total, no category sits inside another, and the only overlap anywhere is the explicit one on the DMARC row.

Total: all messages in the period and scope (a domain, or all domains). Not changed by list filters.

| Row | Buckets (mutually exclusive, evaluated in this order) |
|---|---|
| **DMARC** | passed both SPF and DKIM; passed through SPF only; passed through DKIM only; failed. Headline = the first three together. |
| **SPF** | passed, for your domain (aligned); passed, but for another domain; failed or errored (fail, softfail, permerror, temperror, neutral); no SPF record |
| **DKIM** (best signature per message) | signed as you and verified; signed as you but did not verify (body hash or header changed in transit, or a key mismatch); signed, but only for another domain; no signature |

Worked from your example: of 10,000 messages, SPF 90% / 5% other domain / 5% failed, DKIM 89% / 6% other domain / 2% did not verify / 3% none, DMARC passed 92%. The overlap is fixed by the numbers: both = 90 + 89 − 92 = 87%, SPF only 3%, DKIM only 2%, failed 8%.

Display: one headline ("92% of 10,000 messages passed DMARC"), then three stacked bars, each with a legend of percent, label and count, and one sentence stating the overlap. Zero buckets are hidden. Forwarded and list mail that the receiver let through is not counted as a pass; it is noted separately.

Data note: the DKIM row needs every signature on a message, not the first, so it depends on the re-parse. The DMARC row's "both / only" split needs SPF and DKIM alignment to be computed for every row, which the pattern table stores.

### 14.1 Applied across the product (2026-10-12, canvas v73)

One function, one dataset. Today, Clients (per client, per client row expanded, and the MSP-owner roll-up), Senders, the Reports review board, the monthly client report and the Programme gates all compute from the same message rows, so a figure on one board is the same on every other. The sample is generated from the Senders patterns: 5 clients with reports, 103,878 messages, 72% passed DMARC, of which 69% passed both, 2.7% only DKIM, and 28% failed.

Reports and the monthly client report no longer say "fake emails stopped". The failed share is split, so a client is never told their own newsletters were an attack:

| Failed mail | Meaning | Shown as |
|---|---|---|
| From your own services | A service you use is not set up to prove it is you | Yours to fix |
| From sources that are not yours | Probable spoofing | Sent to spam or refused (stopped) or delivered, by what the receiver applied |
| Forwarded or list mail | Fails on its own, receivers may let it through | Noted separately, never counted as a pass |

Programme gates use the same rows: "your own services passing DMARC above 95%" is the share of mail from recognised services that passes, and "mail from sources that are not yours below 0.5%" is the share of all the domain's mail from unrecognised sources.

Sample caveat: the Senders and workspace samples were reconciled so the same five clients and domains appear everywhere. Example Legal has no DMARC record, so it has no messages and is shown as "no reports yet" rather than as zero.
