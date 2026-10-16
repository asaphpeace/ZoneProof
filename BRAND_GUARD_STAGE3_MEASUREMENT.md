# Brand Guard Stage 3 — what the measurement says and what changed (2026-10-02)

Stage 3 asks for calibrated confidence. The honest first finding is that **abuse scoring cannot be calibrated into a probability with the data
that exists**: the Stage 1 corpus has no abuse ground truth and no real prevalence, and live facts cannot be reconstructed for historical
domains. What CAN be measured is a likelihood ratio per signal, so that is what was measured, and what the scorer now rests on.

## Decisions and consequences

1. **The additive points are now data-derived where a measurement exists.** One table (`backend/app/data/signal_ratios.json`, produced by
   `python -m brand_eval.abuse_lr --export`) feeds both the additive score (`brand_reasoning.points_for`) and the new evidence ratio, so
   they cannot disagree about a measured signal. Signals nobody could measure keep their hand-set weight and are shown as *assumed*.
2. **Liveness no longer counts as abuse evidence.** "Resolves" (was +10) measured ratio 1.08 (0.98-1.18) and "has mail servers" (was +15) measured 0.46 (0.21-0.99):
   among recently registered domains that feeds list as bad, these are about as common as among ordinary new registrations (mail servers less so).
   Liveness is about impact (can it hurt someone today), which was already a separate field. **Consequence the user should know about:** a fresh live
   homoglyph with no other abuse evidence used to be "suspicious" and alert; it is now "triaging" (still in Needs attention, verdict Watch, impact
   medium-high) and does not send an alert until there is real abuse evidence (a blocklist entry, a lure word, a bulk-mail sender, a campaign
   pattern, a reported email). If the user wants the old alerting back for the strongest look-alikes, the principled way is an explicit
   identity-class prior (a homoglyph is rarely innocent), not liveness points; that is a decision, not a default.
3. **Measured upward:** bulk-mail (ESP) sender +10 -> +15 and credential-lure word in the name +10 -> +13 (conservative lower bounds of ratios of
   about 9x and 7x). **Measured parked:** -8 -> -8.8 (consistent).
4. **Left as assumptions, flagged as such:** SPF, DKIM and DMARC published, defensive mail posture, free-platform CNAME, and the high-abuse-suffix
   weight (+5; its point estimate on the young group is 0.56, below 1, but the interval 0.26-1.22 is too wide to act on). The headline group
   has only 34 recently registered listed names, so most mail signals are underpowered; re-run with a larger collection to settle them.
5. **Abstain exists.** When strong evidence points both ways (a blocklist entry AND a popular-site explainer) the verdict is "Uncertain: evidence
   conflicts" instead of the larger side winning. The drawer shows the evidence ratio, a band, and which part was measured.
6. **Not done:** turning a ratio into a probability or a conformal guarantee (3.2) needs labels of real outcomes: analyst decisions (Stage 9) or the
   SA review queue. The prior (how common abuse is among look-alikes of a given brand) is unmeasured and is NOT invented.

## The measurement

Collected 2026-10-02T12:34Z. Produced by `python -m brand_eval.abuse_lr`; the raw per-domain records stay in the gitignored `backend/data/brand_guard_corpus/abuse_lr/`.

**What is measured.** For each signal: how much more often it appears on *known-bad, recently registered* domains than on *new registrations in general*. Bad = currently listed by phishunt.io or abuse.ch URLhaus (automated, NOT human-verified; popular sites and hosting-platform names excluded). Background = a random sample of yesterday's newly registered domains, which is mostly benign but contains unlisted malicious names, so every ratio is biased **toward 1** (it understates the signal).

Sizes: 503 listed names with a registration date (34 registered within 30 days = the headline group), 3000 background names.

Age of the listed names: ≤7 d 9, 8-30 d 25, 31-365 d 140, >1 y 329. Most listed names are NOT new registrations (compromised older sites), which is why the headline group is restricted to young ones.

**What this is not.** It is not a probability: a ratio needs a prior (how common abuse is among look-alikes of a brand), and nothing we have measures that. Registration age and certificate timing cannot be reconstructed for historical hosts, so they are not measured here. Listed domains are the ones feeds can see; many are already dead, which lowers every DNS-derived rate for them.

Exist in DNS today: listed young 34/34 (100.0%), background 2909/3000 (97.0%). Features that need DNS are compared among names that exist.

## Headline: listed names registered within 30 days vs new registrations

| Signal | Listed | New registrations | LR+ (95% interval) | LR− | Intervals separate? |
|---|---|---|---|---|---|
| name exists in DNS | 100.0% [89.8%-100.0%] (34/34) | 97.0% [96.3%-97.5%] (2909/3000) | 1.02 (0.98-1.06) | 0.47 | no |
| resolves to a server (A record) | 94.1% [80.9%-98.4%] (32/34) | 86.1% [84.8%-87.3%] (2504/2909) | 1.08 (0.98-1.18) | 0.51 | no |
| has mail servers (MX) | 14.7% [6.4%-30.1%] (5/34) | 34.1% [32.4%-35.9%] (993/2909) | 0.46 (0.21-0.99) | 1.28 | **yes** |
| publishes SPF | 20.6% [10.3%-36.8%] (7/34) | 34.3% [32.6%-36.1%] (998/2909) | 0.62 (0.33-1.18) | 1.20 | no |
| publishes a DKIM key | 14.7% [6.4%-30.1%] (5/34) | 8.7% [7.7%-9.8%] (253/2909) | 1.80 (0.83-3.92) | 0.92 | no |
| publishes DMARC | 8.8% [3.0%-23.0%] (3/34) | 23.3% [21.8%-24.8%] (677/2909) | 0.43 (0.16-1.16) | 1.17 | no |
| uses a bulk-mail (ESP) sender | 2.9% [0.5%-14.9%] (1/34) | 0.4% [0.2%-0.7%] (11/2909) | 10.84 (2.04-57.53) | 0.96 | no |
| locked-down mail posture (null MX / -all / reject) | 0.0% [0.0%-10.2%] (0/34) | 1.7% [1.3%-2.2%] (49/2909) | 0.84 (0.05-13.35) | 1.00 | no |
| on a shared DNS platform | 73.5% [56.9%-85.4%] (25/34) | 49.0% [47.2%-50.8%] (1426/2909) | 1.49 (1.21-1.83) | 0.53 | **yes** |
| nameservers of a parking service | 0.0% [0.0%-10.2%] (0/34) | 11.0% [9.9%-12.2%] (320/2909) | 0.13 (0.01-2.04) | 1.11 | no |
| www is a CNAME to a free hosting platform | 0.0% [0.0%-10.2%] (0/34) | 1.1% [0.8%-1.6%] (33/2909) | 1.24 (0.08-19.85) | 1.00 | no |
| name contains a credential/payment lure word | 2.9% [0.5%-14.9%] (1/34) | 0.5% [0.3%-0.9%] (16/3000) | 7.79 (1.52-40.10) | 0.96 | no |
| name label is 20+ characters | 0.0% [0.0%-10.2%] (0/34) | 6.9% [6.1%-7.9%] (208/3000) | 0.21 (0.01-3.23) | 1.06 | no |
| suffix .com | 61.8% [45.0%-76.1%] (21/34) | 38.2% [36.5%-40.0%] (1146/3000) | 1.61 (1.23-2.10) | 0.62 | **yes** |

## Context: ALL listed names (any age) vs new registrations

| Signal | Listed | New registrations | LR+ (95% interval) | LR− | Intervals separate? |
|---|---|---|---|---|---|
| name exists in DNS | 99.8% [98.9%-100.0%] (502/503) | 97.0% [96.3%-97.5%] (2909/3000) | 1.03 (1.02-1.04) | 0.10 | **yes** |
| resolves to a server (A record) | 91.8% [89.1%-93.9%] (461/502) | 86.1% [84.8%-87.3%] (2504/2909) | 1.07 (1.03-1.10) | 0.59 | **yes** |
| has mail servers (MX) | 55.8% [51.4%-60.1%] (280/502) | 34.1% [32.4%-35.9%] (993/2909) | 1.63 (1.49-1.79) | 0.67 | **yes** |
| publishes SPF | 52.0% [47.6%-56.3%] (261/502) | 34.3% [32.6%-36.1%] (998/2909) | 1.52 (1.37-1.67) | 0.73 | **yes** |
| publishes a DKIM key | 28.7% [24.9%-32.8%] (144/502) | 8.7% [7.7%-9.8%] (253/2909) | 3.30 (2.75-3.95) | 0.78 | **yes** |
| publishes DMARC | 26.9% [23.2%-30.9%] (135/502) | 23.3% [21.8%-24.8%] (677/2909) | 1.16 (0.99-1.36) | 0.95 | no |
| uses a bulk-mail (ESP) sender | 3.6% [2.3%-5.6%] (18/502) | 0.4% [0.2%-0.7%] (11/2909) | 9.31 (4.49-19.31) | 0.97 | **yes** |
| locked-down mail posture (null MX / -all / reject) | 0.4% [0.1%-1.4%] (2/502) | 1.7% [1.3%-2.2%] (49/2909) | 0.29 (0.08-1.04) | 1.01 | no |
| on a shared DNS platform | 43.2% [39.0%-47.6%] (217/502) | 49.0% [47.2%-50.8%] (1426/2909) | 0.88 (0.79-0.98) | 1.11 | no |
| nameservers of a parking service | 2.6% [1.5%-4.4%] (13/502) | 11.0% [9.9%-12.2%] (320/2909) | 0.24 (0.14-0.42) | 1.09 | **yes** |
| www is a CNAME to a free hosting platform | 0.0% [0.0%-0.8%] (0/502) | 1.1% [0.8%-1.6%] (33/2909) | 0.09 (0.01-1.41) | 1.01 | **yes** |
| name contains a credential/payment lure word | 3.8% [2.4%-5.8%] (19/503) | 0.5% [0.3%-0.9%] (16/3000) | 7.04 (3.68-13.46) | 0.97 | **yes** |
| name label is 20+ characters | 4.8% [3.2%-7.0%] (24/503) | 6.9% [6.1%-7.9%] (208/3000) | 0.70 (0.47-1.05) | 1.02 | no |
| suffix .com | 66.2% [62.0%-70.2%] (333/503) | 38.2% [36.5%-40.0%] (1146/3000) | 1.73 (1.60-1.87) | 0.55 | **yes** |
| suffix .net | 5.4% [3.7%-7.7%] (27/503) | 1.8% [1.4%-2.3%] (54/3000) | 3.00 (1.92-4.71) | 0.96 | **yes** |
| suffix .com.br | 3.8% [2.4%-5.8%] (19/503) | 1.0% [0.7%-1.4%] (29/3000) | 3.94 (2.24-6.92) | 0.97 | **yes** |
| suffix .org | 2.8% [1.7%-4.6%] (14/503) | 2.0% [1.6%-2.6%] (60/3000) | 1.43 (0.81-2.51) | 0.99 | no |
| suffix .cc | 2.0% [1.1%-3.6%] (10/503) | 1.1% [0.8%-1.6%] (34/3000) | 1.81 (0.91-3.59) | 0.99 | no |
| suffix .in | 1.2% [0.5%-2.6%] (6/503) | 0.8% [0.5%-1.1%] (23/3000) | 1.65 (0.69-3.91) | 0.99 | no |
| suffix .click | 1.0% [0.4%-2.3%] (5/503) | 0.5% [0.3%-0.8%] (14/3000) | 2.26 (0.85-6.00) | 0.99 | no |
| suffix .co.kr | 1.0% [0.4%-2.3%] (5/503) | 0.0% [0.0%-0.1%] (0/3000) | 65.50 (3.63-1182.75) | 0.99 | **yes** |


## Reproduce

```bash
cd backend
python -m brand_eval.abuse_lr --bad 1200 --background 3000 --export   # collects live (DNS + RDAP), writes the report and the table
python -m brand_eval.abuse_lr --reuse data/brand_guard_corpus/abuse_lr/collection_<date>.json --export   # re-analyse a saved collection
```

Collection takes roughly 10-25 minutes and touches public DNS and RDAP at modest concurrency. A larger or repeated collection is the way to
resolve the "not enough data" rows.
