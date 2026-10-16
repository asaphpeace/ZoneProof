<!-- Generated from the two replay runs' metrics.json; commentary written by hand. Re-baseline with
     `python -m brand_eval.replay && python -m brand_eval.metrics`, compare with `python -m brand_eval.metrics compare <old> <new>`. -->
# Plan step 2.0b — detector defects fixed: measured effect

Same corpus (`c-c3297e252edc`, 488 suspected-malicious positives, 3,388 negatives); only the detector changed
(fingerprint `01220ce911b6` → `91de489932a6`). Every figure is `rate [95% Wilson interval] (k/n)`.

## What changed in the detector

1. **Public Suffix List** (vendored, unmodified, MPL-2.0; `app/data/public_suffix_list.dat` + manifest with SHA-256):
   `x.com.br`, `x.co.uk`, `x.com.au` now parse correctly, so lookalikes under those suffixes are seen and customers whose own
   domain uses one get real permutations (before: permutations of the label "com"). Implements the PSL algorithm including
   wildcard and exception rules.
2. **Free-hosting platforms** (PSL private section) are treated as suffixes: `brand-login.pages.dev` is a candidate named
   `brand-login`, no longer the platform `pages.dev`. Such candidates skip the (meaningless) registration lookup and carry an
   explicit "lives on a free hosting platform" evidence line (+10 abuse).
3. **Brand-token rules by length** (`token_match`): 6+ letters match anywhere; 4–5 letters only as a whole word or fused with a
   lure word (`cash-app-login` ✓, `applesupport` ✓, `visitlancashire` ✗, `pineapple` ✗); 3 letters whole-word only (`gls-group` ✓).
   Scoring's keyword-combo signal uses the same rules.
4. **Typo-squats on the certificate path**: a word within 1–2 edits of a 6+ letter brand now matches; the permutation TLD-swap set
   gained common abusive suffixes (top, icu, cfd, sbs, click, link, live, site, shop, store, vip, club, cc, me, us, co.uk).
5. Brand profiles now carry plain-language warnings for short brand names.

## Measured effect

| Measure | Baseline `01220ce911b6` | After 2.0b `91de489932a6` |
|---|---|---|
| Positives evaluated at all (reach) | 11.3% [8.8–14.4] (55/488) | 83.4% [79.8–86.4] (407/488) |
| Positives with identity ≥ 55 (alert upper bound) | 11.3% [8.8–14.4] (55/488) | 81.8% [78.1–84.9] (399/488) |
|   …held-out test split, identity ≥ 55 | 16.5% [10.4–25.1] (16/97) | 47.4% [37.8–57.3] (46/97) |
|   …registered domains only (not free hosting), reach | 49.5% [40.4–58.7] (55/111) | 58.6% [49.3–67.3] (65/111) |
|   …free-hosting names, reach  ⚠ assumes the hostname is enumerable | 0.0% [0.0–1.0] (0/377) | 90.7% [87.4–93.2] (342/377) |
| Positives caught by the permutation set | 0.0% [0.0–0.8] (0/488) | 0.0% [0.0–0.8] (0/488) |
| Unrelated popular domains tied to a brand | 0.1% [0.0–0.3] (3/3000) | 0.0% [0.0–0.2] (1/3000) |
| Popular lookalikes surfaced (expected exposure) | 54.1% [49.1–59.0] (210/388) | 57.5% [52.5–62.3] (223/388) |
| Popular lookalikes scoring identity ≥ 55 | 32.2% [27.8–37.0] (125/388) | 22.4% [18.6–26.8] (87/388) |
| Brand-weighted (macro) identity ≥ 55 recall | 25.9% [13.0–39.9] over 18 brands (5 at 0%) | 75.2% [59.6–88.1] over 18 brands (0 at 0%) |

## How to read it honestly

- **The headline jump is mostly free-hosting names, and that part is conditional.** Reach for platform-hosted names
  (0% → 90.7%) assumes the detector is *given* the hostname. Platform subdomains are often covered by the platform's own
  wildcard certificate and then never appear in certificate-transparency logs. Whether a feed of such hostnames exists is
  **unmeasured**; treat that row as an upper bound. The pre-fix figure of 0% was a hard parsing blind spot; the post-fix figure
  is "no longer blind, if you can see the name".
- **The registered-domain improvement is within noise.** 49.5% → 58.6% on n=111 has overlapping intervals, and the comparison tool
  refuses to call it an improvement. The fixes that apply there (`.com.br`/`.co.uk` parsing, 3-letter whole-word matching,
  typo matching) add a handful of records.
- **Brand-weighted recall rose from 25.9% to 75.2%** (intervals do not overlap, no brand left at 0%) — a better picture than the
  record-weighted figure because one brand dominates the positives.
- **False matches fell, but the counts are tiny**: unrelated popular domains tied to a brand went from 3 to 1; the survivor
  (`wbay.com`) is a genuine one-edit lookalike of eBay. Lookalike identity ≥ 55 fell from 32.2% to 22.4% (a clear improvement):
  the new token rules stop common words and short names inflating identity.
- **Permutation hit-rate is unchanged at 0%**: the corpus still has no typo/homoglyph positives, so nothing here says anything about
  the generator's value. Typo reach now comes through the certificate-name path.
- **Still not measured**: abuse scoring, status, alerting, true detection latency; and all labels remain suspected, not verified.

## Still not reached (81 of 488 positives)

46 registered-domain names and 35 platform names show no brand name the detector can match. Of the corpus strata: brand only in a
sub-domain of someone else's domain (21 of 29 unreached), brand only in the URL path (8 of 8), no visible brand (19 of 20), and
TLD swaps that are reached but score identity 40 (below the 55 alert gate; abuse signals decide those). These belong to later
stages (2.2 sub-domain analysis, 2.3–2.6 email/infrastructure/first-party signals, 7 page content).

## Trade-offs introduced

- 4–5 letter and 3-letter brands now match as whole words or beside lure words; a merged name like `dpdn62` stays unmatched
  (documented limit; covered by a test).
- The affix list is a heuristic, not a wordlist — the evaluation corpus is the check on it, and it can be tuned there.
