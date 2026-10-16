# Senders: how other tools show a sending source, and what our redesign dropped

Date: 2026-10-12. Companion to `ZONEPROOF_ROLE_MATRIX.md`. Analysis only: nothing here has been built or drawn.

## How to trust this

- **Public pages only.** Vendor help pages and the RFC. No trial accounts, so I have not seen anyone's actual screens. Where a page lists fields but not layout, I say so.
- **The standard is the baseline.** RFC 7489 Appendix C is the authoritative list of what a receiver can report. Everything below is measured against it.
- **Not found is not absent.** Several vendors' pages did not describe a drill-down. That means the page did not say, not that the feature is missing.

## 1. What a receiver reports (RFC 7489, Appendix C)

One `record` per row. Each has three groups.

| Group | Fields |
|---|---|
| **row** | `source_ip`, `count`, `policy_evaluated` (`disposition`, `dkim`, `spf`, zero or more `reason` with `type` and optional `comment`) |
| **identifiers** | `envelope_to` (optional), `envelope_from`, `header_from` |
| **auth_results** | `dkim` (zero or more): `domain`, `selector` (optional), `result`, `human_result` (optional). `spf` (one or more): `domain`, `scope` (`helo` or `mfrom`), `result` |

- **Override reasons:** forwarded, sampled_out, trusted_forwarder, mailing_list, local_policy, other.
- **DKIM results:** none, pass, fail, policy, neutral, temperror, permerror.
- **SPF results:** none, neutral, pass, fail, softfail, temperror, permerror.
- **Report level:** `policy_published` (the domain's `p`, `sp`, `adkim`, `aspf`, and so on), reporter, period.

Two things matter most for "exact source and selector":

1. **There can be several DKIM signatures on one message**, each with its own domain, selector and result.
2. **SPF is evaluated on either the HELO name or the MAIL FROM**, and the report says which (`scope`).

## 2. How other providers structure it

| Provider | Layers | What the source detail holds | Container |
|---|---|---|---|
| **Sendmarc** (Detailed Sender IP Overview) | Sender, then IP, then a dialog | Six panels: **Overview** (ISP, Host, Country, Group, Organisation, Volume, Compliance Ratio, Deliverability Ratio, Blacklists, Threat Level); **Reporters** (volume, reporter, % of total, compliance; expanding shows Envelope To, Envelope From, Header From when the reporter gave them); **Results Summary** (DKIM result with alignment and signing domain, SPF result with alignment and return-path domain, DMARC result, Published Policy, Policy Applied); **SPF Results** (volume, return-path domain, alignment, result, "DMARC via SPF"); **DKIM Results** (volume, signing domain, **selector**, alignment, result, "DMARC via DKIM"); **Overrides** (reporter, result, published and applied policy, override type, comment with ARC results) | A dialog with stacked panels, each a small table weighted by volume |
| **dmarcian** | Domain Overview, then Detail Viewer, then Source Viewer | Detail Viewer: filters for domain, reporters, IP or CIDR, timeframe and a compliance mode; rows grouped by source with SPF and DKIM alignment. CSV columns: Header-From, IP, PTR, CC, Count, Policy-Applied, OverrideReason, DKIM_Alignment, DKIM_Result, DKIM_Domain, SPF_Alignment, SPF_Result, SPF_Domain. Source Viewer: sources get a human-readable tag and expand per domain to show compliance by domain. I found no mention of selectors. | Full pages, filter bar on top, expandable groups |
| **EasyDMARC** | A report as a list of sources, in four tabs | Per source: PTR or IP, Volume, Delivery Status, DMARC, **SPF split into Alignment and Authentication**, **DKIM split into Alignment and Authentication**, Reporter, Date. Tabs: **Compliant, Non-Compliant, Threat/Unknown, Forwarded**. A gear icon opens the fix steps for that source. Filters include DKIM selector and DKIM domain. RBL check per IP. CSV or PDF export. | A list with tabs; a side action for fixes |
| **Red Sift OnDMARC** | Reports by sender, with percentages | Per sender: SPF and DKIM percentages, with guidance on reading them ("DKIM 0% and SPF 100% can mean SPF passed and aligned, so DKIM was not needed"). Advice: start with the highest-volume sources. Unknown sources are classed Asset, Threat or Forwarder with a reason you can confirm. | Table with explanatory text |
| **Valimail** | An Authentication Report with three groups: sending services, internal sources, unidentified | A DKIM key is tied to a service by its **selector** (`selector._domainkey.domain`). Unknown IPs are confirmed and added as netblocks. | A report with a grouping, plus setup dialogs |
| **PowerDMARC** | Charts and tables from the XML | The page I found explained the three XML blocks and how to read a row. It did not describe its own drill-down. | Not confirmed |

## 3. What they have in common

1. **Three levels, always:** a summary, then a source (the vendor or sending network), then an IP with its authentication detail.
2. **Result and alignment are separate.** A DKIM pass for another domain is not a DMARC pass, and every tool shows both.
3. **"DMARC via SPF" and "DMARC via DKIM"** answer which path made the message pass.
4. **Identity is shown as three domains:** header-from, return-path or MAIL FROM, and the DKIM `d=`. Mismatch is the clue.
5. **The selector appears only in the DKIM table**, next to the signing domain. Nowhere is it a headline.
6. **Per-reporter breakdown.** Receivers disagree, so the same source can look different by reporter.
7. **Published policy beside applied policy,** and an **overrides** panel (forwarded, mailing list, ARC).
8. **Grouping by outcome, not by protocol:** compliant, non-compliant, unknown, forwarded.
9. **Fix guidance sits on the source** (a gear icon, or "fix this source"), not in a separate area.
10. **A raw export** (CSV) for the row-level data.

## 4. What ZoneProof has today

The running app's **IP Authentication Detail** drawer, in order:

1. Header: IP, reverse DNS, message volume.
2. Verdict banner: a plain label, "DMARC PASS or FAIL", a plain explanation, DKIM failure hypotheses with a link to the platform's setup, and an "ask a follow-up" box.
3. **Identity:** Header-From, Envelope-From with a concept card, and a notice when the envelope differs ("normal for [known service]" or "possible spoofing").
4. **DKIM signature:** signing domain (`d=`), **selector (`s=`) with the DNS lookup `selector._domainkey.domain`**, result, alignment with a concept card.
5. **SPF check:** domain checked, result, alignment.
6. **DMARC outcome:** result, disposition, volume.
7. "Auth group n of m" when one IP has several distinct auth results.

That is more complete than the redesign, and close to the competitors, with a plainer verdict.

## 5. What the redesign dropped

The Senders board has three tabs:

| Tab | Content on the board | What is missing |
|---|---|---|
| **By service** | A table (service, domains, volume, SPF, DKIM, declared) with an expander: "why it's failing" and sending IPs | The IP-level detail below it |
| **Unknown sources** | A table (source, volume, targets) | The same IP-level detail |
| **By source and IP** | One sentence: "the full source → IP → SPF / DKIM / DMARC table from today's DMARC Analyzer" | **The table itself, and the drawer.** This is where the envelope, header, selector and verdicts used to be. |

Against the section 3 list, the board shows none of: separate result and alignment, "DMARC via", the three identity domains, the selector, per-reporter detail, published against applied policy, or overrides. The running app's drawer is gone.

## 6. What the data can and cannot support

Read from `backend/app/models/dmarc_report.py` and `services/dmarc_parser.py`.

| Detail | Stored today | Note |
|---|---|---|
| Source IP, count, disposition | Yes | |
| Header-from, envelope-from, envelope-to | Yes | |
| SPF domain and result, SPF alignment | Yes | |
| DKIM domain, selector, result, alignment | Yes, **first signature only** | A message with several signatures keeps one. |
| Reverse DNS, ASN, organisation | Yes | Enriched after ingestion |
| Reporter (organisation) | Yes, on the report | Needs a join to show per-reporter detail |
| **SPF scope (HELO or MAIL FROM)** | **No** | The parser keeps one domain |
| **Override reasons and comments** | **No** | Forwarded, mailing list, local policy and the ARC comment are discarded |
| **Published policy per report** (`p`, `sp`, `adkim`, `aspf`, testing) | **No** | So "published against applied" cannot be shown |
| DKIM `human_result` | **No** | |

The raw XML is kept (`raw_xml`), so the missing fields can be re-parsed from history without waiting for new reports.

## 7. What I would carry into the design

Proposed shape, for you to react to. It keeps the simplicity and adds the missing depth in layers.

1. **Keep the three tabs, and make the third real:** one source-and-IP table with the verdict first, then SPF and DKIM as pass or fail with alignment on a second line.
2. **One panel for any source or IP,** opened from any row in any tab, so the detail is the same wherever you arrive. A side panel, not a modal, so the table stays in view.
3. **Inside the panel, in plain language first and technical on demand:**
   - Verdict and the path that made it pass (via SPF, via DKIM, or neither).
   - Identity: header-from, envelope-from, the DKIM signing domain, side by side with the mismatch called out.
   - DKIM signatures as a table: domain, **selector**, alignment, result, with the DNS name to look up.
   - SPF: domain, scope, result, alignment.
   - Reporters: who saw it, with their own result.
   - Overrides and published against applied policy.
   - Fix guidance and "ask a follow-up" at the end.
4. **Group by outcome** in the source list (Passing, Failing, Unknown, Forwarded), as EasyDMARC does, and keep our own plain labels.

## 8. Open questions

1. **Panel or modal?** I would use a right-hand panel.
2. **Backend:** do we re-parse the stored XML to keep every DKIM signature, SPF scope, override reasons and published policy? That is what makes the panel complete and it needs a migration.
3. **Depth for the owner:** the owner lens should see the verdict and the fix only; the panel's technical sections belong to the operator.

## Sources

- Sendmarc: [Detailed sender IP overview report](https://help.sendmarc.com/detailed-sender-ip-overview-report)
- dmarcian: [Detail Viewer](https://dmarcianbeacon.helpscoutdocs.com/article/50-detail-viewer-content), [Source Viewer](https://dmarcianbeacon.helpscoutdocs.com/article/49-source-viewer-content), [CSV columns](https://dmarcian.com/explanation-of-csv-columns-in-data-exports/)
- EasyDMARC: [Analyzing DMARC aggregate reports](https://support.easydmarc.com/knowledge-base/analyzing-dmarc-aggregate-reports)
- Red Sift OnDMARC: [Interpreting sender results](https://knowledge.ondmarc.redsift.com/en/articles/1155460-how-to-interpret-sender-results-from-the-reports-section-of-ondmarc) (found through a search result; the page itself could not be fetched)
- Valimail: [Adding a DKIM key in Enforce](https://support.valimail.com/support/solutions/articles/48001165622-adding-a-dkim-key-in-enforce)
- PowerDMARC: [How to read DMARC reports](https://powerdmarc.com/how-to-read-dmarc-reports/)
- Standard: [RFC 7489, Appendix C](https://www.rfc-editor.org/rfc/rfc7489.html)
