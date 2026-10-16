<!-- Figures come from the replay runs' metrics.json (python -m brand_eval.replay; python -m brand_eval.metrics report/compare);
     commentary is hand-written. Compared: after 2.1 (fingerprint 4db9a9960e92) vs after 2.2 (1e9d85d0ecad). -->
# Plan step 2.2 — lexical and South Africa-specific upgrades, subdomain abuse: measured effect

Same corpus (`c-c3297e252edc`: 488 suspected-malicious positives, 3,388 negatives). Only the detector changed. Every figure is
`rate [95% Wilson interval] (k/n)`. Labels are *suspected*, not verified, and abuse scoring is not measurable offline (see the baseline report).

## What changed

| Area | Change | Measurable on the public corpus? |
|---|---|---|
| **Subdomain brand abuse (A2-2)** | A host whose registrable name shows no brand but whose subdomain does (`accounts.google.com.evil.xyz`, `xfinity097.weebly.com`) is now found through certificate logs and tracked under the **full host**. Official domain written inside the subdomain = identity 55; bare brand word in a subdomain = 35 (a lead, below every alert line). Intake capped at 25 hosts per scan. | **Yes** |
| **Hosting platforms missing from the PSL** | 20 well-known free site builders/hosts the Public Suffix List does not carry (`weebly.com`, `wordpress.com`, `glitch.me`, …) are treated like listed platforms. | **Yes** (`weebly.com` alone = 27 positive hosts) |
| ccTLD mimic | `brand-co-za.com`, `brandcoza.com`, `brand.za.com/.net/.org` generated; recognised and explained when seen (identity 55, replaces the generic keyword signal). | No — no such positives in the public data |
| Word-order inversion + compound splitting | `bank-capitec` from `capitecbank`; words come from the brand display name, hyphens, or a known word at either end. | No |
| Sound-alike and bit-squat | Generated and recognised independently of how a name was found (identity 45). Bit-squats only for names of 5+ letters. | No |
| Afrikaans / Zulu lures | 19 words generated as suffixes, counted as credential-lure words, and as short-brand affixes. **Hand-curated, not reviewed by a native speaker.** | No |
| Mixed-script detection | Letters from two alphabets in one name → +15 abuse. | No |
| Word-frequency context | "N of 100,000 popular domain names contain this word" shown on the keyword evidence line. **Context only — no score change** (see below). | Tested and rejected as a weight |

Also: the scorer no longer adds the fuzzy-similarity points on top of a structural explanation (`capitecbankcoza.com` scored 80 for one idea; now 55).

## Measured effect (after 2.1 → after 2.2)

| Metric | After 2.1 | After 2.2 | Verdict |
|---|---|---|---|
| Positives surfaced (reach) | 83.4% [79.8–86.4] (407/488) | **92.2% [89.5–94.3] (450/488)** | improved (intervals do not overlap) |
| Positives at identity ≥ 55 (alert upper bound) | 81.8% [78.1–84.9] (399/488) | 87.5% [84.3–90.1] (427/488) | within noise overall |
| …free-hosting positives at identity ≥ 55 | 90.5% [87.1–93.0] (341/377) | **96.3% [93.9–97.8] (363/377)** | improved |
| …non-hosting positives surfaced | 58.6% [49.3–67.3] (65/111) | **77.5% [68.9–84.3] (86/111)** | improved |
| `brand_in_subdomain` positives surfaced | 27.6% [14.7–45.7] (8/29) | **96.6% [82.8–99.4] (28/29)** | improved |
| …of which at identity ≥ 55 | 27.6% (8/29) | 48.3% [31.4–65.6] (14/29) | within noise (n = 29) |
| `brand_in_path` positives | 0.0% [0.0–32.4] (0/8) | 0.0% [0.0–32.4] (0/8) | unchanged — see "not done" |
| Test split surfaced (chronologically latest 97) | 54.6% [44.7–64.2] (53/97) | 76.3% [66.9–83.6] (74/97) | improved |
| Unrelated popular domains tied to a brand | 1/3000 | 1/3000 | unchanged |
| Popular lookalikes at identity ≥ 55 | 22.4% [18.6–26.8] (87/388) | 22.4% (87/388) | unchanged |

**Read this honestly.** 43 positives became reachable. **27 of them are one platform** (`weebly.com`), fixed by the platform list, not by
subdomain logic. The rest are the subdomain finder. Most subdomain hits are deliberately *leads* (identity 35), so the alert-level
number moves much less than reach does. The test split gains are real in direction but its strata are small.

## A candidate that was tried and rejected: discounting common brand words

The plan called for "coincidence-probability scoring". Two attempts, both measured:

1. **A random-letter model** (chance a random label of that length contains the word) was checked against the Majestic data first and
   **failed by 3–4 orders of magnitude** on real words (`apple` 300× too rare, `paypal` 2,600×, `amazon` 45,000×) and overestimated
   3-letter acronyms 10×. Not shipped. It would have produced confident, meaningless numbers.
2. **Measured frequency** (a vendored list of the 100,000 most popular registrable labels; `app/data/popular_labels.txt.gz`, Majestic
   CC BY 3.0, rebuildable with `tools/build_popular_labels.py`) was then used to discount common words by ×0.7. The threshold (≥ 20 per
   100,000) was fixed **before** looking at results. Measured: it removed **12 popular-lookalike hits and 12 real phishing names** — a
   wash (both within noise) — and the real names lost were mostly `google` and `amazon`, the most-attacked brands. A word being common in
   popular names mostly means the brand is famous, not that a match is coincidence. **Rejected as a weight; kept as context** on the
   evidence line ("also appears in about 271 of every 100,000 popular domain names").

## Found live, fixed

A live scan of a 3-letter brand (`dpd.com`) produced 9 new rows that were all unrelated registered one-bit neighbours (`lpd.com`,
`tpd.com`, …). Bit-squats are now generated and recognised only for names of 5+ letters. Nine rows of my own test noise were removed from
the dev data.

## Not done, and why

- **Path abuse** (`brand` only in the URL path of an unrelated host): the 8 `brand_in_path` positives are invisible by construction — a
  domain-level pipeline (certificate logs, DNS) never sees a URL path. It needs a URL source, which arrives with the live feeds (plan 2.6b).
- **False-lead rate of subdomain abuse is unmeasured.** The negative corpus holds registrable names only, so it cannot say how often
  `acme.zendesk.com`-style vendor subdomains will surface. They surface as weak leads (identity 35, no alert) and the intake is capped.
- **Value of the new classes is unmeasured** (ccTLD mimic, sound-alike, bit-squat, local lures, mixed script): the public data contains
  none. Their tests prove mechanics only.
- **Plan budgets interact with the new classes.** Starter evaluates the first 120 generated names. For a typical brand the generator
  emits ~130–180 names ordered homoglyph → combosquat → …, so Starter reaches only homoglyph and English/local combo names, **not**
  the ccTLD-mimic, TLD-swap, typo or other classes. That was already true of TLD swaps and typos before this step; it is a product
  decision (interleave classes under the budget?) flagged for Stage 3 calibration.
- The `crt.sh` certificate path could not be exercised against live data (HTTP 502 for the test brand); it is covered by fake-network tests.
