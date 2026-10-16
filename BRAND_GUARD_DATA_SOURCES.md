# Brand Guard — evaluation data sources and licences (Plan step 1.1)

Status: **DECIDED** (recorded 2026-09-30; step 1.1 complete). Approved: PhishTank (currently unobtainable), URLhaus, Majestic Million, phishunt.io. Terms were
read from the publishers' own pages on this date; licences change, so re-check
before any production or commercial use. This is a product-engineering record,
not legal advice.

ZoneProof is a commercial product. Every source below is judged on whether
using it to build and evaluate a commercial detector is permitted.

## Purpose of the data

Stage 1 needs (a) **positives** — real, verified malicious domains/URLs, ideally
labelled with the brand they target, (b) **negatives** — popular/legitimate
domains, including legitimate lookalikes, and (c) fixed, versioned snapshots so
every later stage reports a delta against the same baseline.

## Source register

| Source | Role | Terms (as read) | Fit | Verdict |
|---|---|---|---|---|
| **PhishTank** `online-valid` dump (json ≈40 MB / csv ≈14 MB) | Positives: community-verified phishing URLs with submission/verification times | [Terms](https://phishtank.org/terms.php): "Data" is "available for commercial use without charge"; no attribution required (link appreciated); data not warranted for accuracy. API key optional (higher rate limits). Terms now reference Cisco's EULA — re-check | Good for *threat* positives and timing. The [API docs](https://phishtank.org/api_info.php) list url / submitted_at / verified / valid and **no target-brand field** — the dump itself must be inspected before we rely on it | **Use** (after confirming the dump's fields) |
| **URLhaus** (abuse.ch) `csv_online` (≈3 MB) | Positives: malware-distribution URLs | [API/terms](https://urlhaus.abuse.ch/api/): CC0, free; heavy commercial API use may need a paid plan, community use is "fair use" | Malware-skewed, not brand phishing; useful as extra abuse corroboration, weak for lookalike evaluation | **Use, secondary** |
| **OpenPhish free community feed** | (Positives) | [Terms](https://openphish.com/terms.html): **explicitly prohibits** commercial use including "security operations, threat intelligence, detection, enrichment, product development"; personal/academic research only | Would be a direct breach for a commercial product, even for evaluation | **Do not use** |
| **OpenPhish Premium/Platinum** | Positives with **target brand**, IP/ASN, SSL metadata | Paid; "allows commercial use" per their [feed page](https://openphish.com/phishing_feeds.html) | The only researched source that clearly provides brand labels | **Decision needed** (cost unknown — needs a quote) |
| **Majestic Million** (≈77 MB) | Negatives: popular domains | CC BY 3.0 (commercial use allowed with attribution) | Clean licence, simple CSV | **Use** (attribute Majestic) |
| **Tranco** top-1m (≈9 MB) | Negatives: popular domains | No licence of its own; the default list averages five providers including **Cloudflare Radar (CC BY-NC 4.0)** and CrUX (CC BY-SA 4.0) | Commercial status of the default list is unclear; a custom list excluding Radar is possible | **Avoid default list**; custom list only if Majestic proves insufficient |
| **Certificate Transparency** (crt.sh etc.) | Real registrations of lookalikes over time | Public logs; crt.sh is a free best-effort service (see step 0.3) | Independent of phishing feeds — useful for a hit-rate measure that isn't biased by feed selection | **Use** (already integrated) |

### Additional sources researched after the first downloads

| Source | Terms (as read) | Verdict |
|---|---|---|
| **phishunt.io** feed/API | [ToS](https://phishunt.io/tos/): data released under **CC0 1.0**, commercial use permitted, attribution appreciated not required; no auth, 10 req/s per IP. [API docs](https://phishunt.io/api/): each record has URL, domain, **`company` (targeted brand slug)**, first_seen, IP/ASN/country, TLS issuer, phishunt 0-100 score, plus boolean cross-reference flags from Google Safe Browsing / OpenPhish / PhishTank / TweetFeed / urlscan. **Caveat: automated suspicion, not verified.** | **Best available fit — recommended, needs user approval.** Drop the per-source flag columns on ingest (they reference OpenPhish, whose own terms are non-commercial); keep `company`, `first_seen`, hosting fields, score |
| **PhishStats** | [AUP](https://phishstats.info/terms): free tier quotas (150/day with key), no bulk download beyond quota, no redistribution without permission | Not suitable for a bulk corpus |
| **Phishing.Database** (GitHub) | MIT, but upstream provenance undocumented — an open [issue](https://github.com/Phishing-Database/Phishing.Database/issues/2315) asks whether upstream sources are non-commercial | Avoid |
| **Phishing Army** | CC BY-NC 4.0; built from PhishTank, OpenPhish, CERT.pl, etc. | Not allowed (non-commercial) |
| **CERT Polska warning list** (`hole.cert.pl`) | Licence not stated in what was read; Poland-targeted | Unverified — do not use until confirmed |
| **APWG eCrime Exchange**, Netcraft, other paid feeds | Not researched (membership/paid) | Out of scope for now |

## Consequences for the evaluation design

1. **Brand labels are the bottleneck.** The free, commercially usable feeds don't
   reliably carry them. Labelling "which brand does this phish target" by running
   *our own* lexical logic over PhishTank URLs would make the harness **circular**:
   it would measure how well the detector finds what the detector already finds.
   Mitigations (to decide): a paid labelled feed (OpenPhish Premium), a small
   hand-labelled gold set, and treating the CT-based hit-rate as the primary
   independent measure.
2. **Survivorship bias** (see plan Part D): feeds only contain phish that were
   caught. Temporal splits and a held-out stream of fresh CT registrations are
   required.
3. **Storage:** snapshots live outside git (`backend/data/brand_guard_corpus/`,
   gitignored) with a manifest recording source, URL, retrieval time, size and
   SHA-256, so every run is reproducible and auditable.
4. Attribution strings (Majestic; PhishTank courtesy link) go in the product's
   data-sources notice.

## Step 1.2 results — built corpus `c-c3297e252edc` (2026-10-01)

Content-addressed and deterministic (same inputs + parameters + builder version ⇒ byte-identical output; manifest records input SHA-256s). Lives in the gitignored `backend/data/brand_guard_corpus/built/`. Builder: `python -m brand_eval.build_corpus`.

**Composition (3,876 records):** 488 suspected-malicious positives (127 high-confidence, 361 medium) across 45 brands; 388 popular lookalikes (same name/other suffix 114, contains brand 126, near-miss 148) derived from Majestic; 3,000 random popular unrelated domains. Positives split chronologically by *campaign start* (train 293 / valid 98 / test 97), with every record of a registrable domain kept in one split; negatives split by stable hash.

**What the positives tell us about detection (literal strata, independent of the detector):**

| Stratum | Count | Meaning |
|---|---|---|
| Brand in a **registered** domain name, not free hosting | 60 | What a registration/permutation scanner can realistically find |
| Same name, different suffix (`tld_swap`) | 8 | " |
| Brand only in a **subdomain** (not free hosting) | 29 | Invisible to today's registrable-label analysis (plan step 2.2 gap) |
| Brand in name, on **free hosting** (pages.dev, github.io…) | 363 | **77% of all positives** are on platforms where nothing is registered — registration/permutation discovery cannot see these |
| Brand in path only / no visible brand | 8 / 20 | Undetectable from the hostname |
| **IDN / homoglyph** | **0** | Not evaluable from public data |
| **Near-miss typo-squats** | **0** | Not evaluable from public data |

Consequences: (1) the public corpus can measure name-matching against *combosquats and TLD swaps only*; (2) a large majority of real phishing in this feed sits where Brand Guard's current sensors cannot look — a strategic finding for Stage 2 sensors, to be measured properly in step 1.3; (3) the homoglyph/typo claims need the human-labelled gold set below; (4) all strata are small, so every metric must carry its sample size and a confidence interval.

**Brand mapping (slug → official domain) guardrails:** 30 high / 13 medium / 2 override (`cashapp`→cash.app, `ingspain`→ing.es; `steam` was mapping to the wrong domain and is overridden to steampowered.com). Brands only resolving beyond Majestic rank 100k are **excluded** rather than guessed (`hacienda`, `seur`). Genuine ambiguity is recorded per brand (e.g. vodafone, hsbc, santander). Subdomains listed by Majestic (apps.apple.com…) are no longer mistaken for rivals or for the brand's domain (bug caught by the tests).

**Gold sets (need a human — I can't invent labels):**
- `sa_brands.json`: 21 SA brands (banks, telcos, retail, SARS, insurers, DStv). `python -m brand_eval.gold verify-sa` confirmed 14 by homepage title; **7 need a human check** (capitec, africanbank, investec behind Cloudflare challenges; vodacom, mtn, woolworths no HTTP response; oldmutual no static title). All 21 resolve in DNS.
- `python -m brand_eval.review_queue` harvested **401 live candidates** for those brands from real DNS/RDAP (3,258 generated): 277 with MX, 172 without the brand name in the domain, 15 registered < 90 days, 67 < 1 year. Facts only (how it was generated, A/MX, registration age) — **label columns are empty by design**. Suggested first pass (registered < 180 days, or MX-enabled with no brand name): 144 rows. File: `backend/data/brand_guard_corpus/gold/sa_review_queue_2026-09-30.csv`.
- Labels: `malicious_lookalike` | `defensive_registration` | `legitimate_unrelated` | `unsure`, each with `labeller` and `labelled_at`; `python -m brand_eval.gold report <csv>` validates and summarises (unlabelled rows are counted, conflicting duplicates rejected).

## Decisions required from the user

1. Abuse-positive sources to use (PhishTank + URLhaus; whether to price
   OpenPhish Premium for brand labels).
2. Popularity/negative source (Majestic Million vs a Tranco custom list).
3. Permission to download the listed files (each needs explicit approval:
   filename, source and size above).

## Recorded decisions

**2026-09-30, user answers:**
1. Positives: **PhishTank + URLhaus** approved. OpenPhish free feed rejected on licence grounds.
2. Negatives: **Majestic Million** approved (CC BY 3.0, attribute Majestic).
3. Downloads: approved for PhishTank json, URLhaus csv_online, Majestic CSV.

**Outcomes of the approved downloads (snapshot `backend/data/brand_guard_corpus/2026-09-30/`, SHA-256 in `manifest.json`):**

- **Majestic Million** — OK: 1,000,000 rows, 77.4 MB (`GlobalRank, TldRank, Domain, TLD, RefSubNets, …`).
- **URLhaus csv_online** — OK: 13,431 rows, 3.1 MB. **Every row is `malware_download`** (mostly raw-IP URLs; tags such as SmartLoader, mirai, CoinMiner, FakeCaptcha). Essentially **no brand-phishing** content → useful only as malicious-infrastructure corroboration, not for lookalike evaluation.
- **PhishTank** — **FAILED.** `data.phishtank.com/data/online-valid.json` redirects (301→302) to a signed CDN object (`cdn.phishtank.com/datadumps/verified_online.json`) which returns **404**. Anonymous quota is 75 requests / 3 days (`X-Request-Limit`); ~4 were used. Stopped there rather than retry or work around it. An app key (free registration — must be done by the user) might help, but the 404 looks like an upstream problem, not a quota one. Also unconfirmed: whether the dump carries a target-brand field (the API docs list none).

**Net effect:** the first three approved sources left **no brand-labelled phishing positives**, so phishunt.io was proposed.

4. **phishunt.io approved by the user** (same day) and downloaded: snapshot `2026-09-30T214414/phishunt_feed.json`, 0.9 MB, 787 records (fetch tool caps downloads at 20 MB).

**What the phishunt snapshot actually contains (measured):**

| Property | Finding | Consequence |
|---|---|---|
| Size / span | 787 records, first_seen 2026-03-27 → 2026-09-30; 6 in Mar, ~35/month Apr–Jun, then 234 / 142 / 304 in Jul / Aug / Sep | Small; usable for temporal splits only roughly (older months are thin). Accumulate daily snapshots over time |
| Brand labels | 777 labelled, **58 distinct brands**, heavily concentrated: facebook 225, instagram 79, google 45, microsoft 43, xfinity 38 … | Not representative of a customer's brand; per-brand metrics will be noisy |
| **Brand slug inside the domain** | **89%** (696 / 777) | The feed is itself keyword-driven (`kw_score_norm` signal), so it over-represents brand-in-name combosquats and **under-represents homoglyph/typo phishing** (11%). Recall on this set will flatter a keyword matcher — must not be quoted as real-world recall |
| **South African brands** | **None** present | Cannot evaluate the `.za`/SA-specific claims from this data → an SA gold set is required |
| Quality tiers | verdict: critical 8, high 137, medium 388, low 232, noise 22; score 7–95 (median 34) | Stratify: treat high/critical (145) as higher-confidence, medium as moderate, exclude low/noise from positives |
| Cross-references | 778 / 787 flagged by ≥1 other source | Flags ignored on ingest (OpenPhish provenance); not used as labels |
| Verification | Automated suspicion, not human-verified (per ToS) | Labels carry a `suspected` quality tag; a small hand-checked gold set validates them |

**Final source set for Stage 1:** positives = phishunt.io (brand-labelled, suspected) + URLhaus (malicious infrastructure only) + PhishTank if/when obtainable; negatives = Majestic Million. Independent measure = Certificate Transparency registrations (not selected by any phishing feed).

**Follow-ups created by these findings (folded into plan step 1.2):**
- hand-labelled **South African gold set** and a **no-slug (homoglyph/typo) gold set**, since the feed lacks both;
- **benign-lookalike negatives derived from Majestic itself** (pairs of unrelated popular domains within small edit distance) — independent of any phishing feed;
- report every metric **stratified** by (slug-in-domain vs not) and by verdict tier, never a single headline number.

**Attribution (product data-sources notice):** Majestic Million (CC BY 3.0); phishunt.io (CC0, courtesy credit); URLhaus (CC0); PhishTank courtesy link if used.

## Derived data shipped inside the product (step 2.2, 2026-10-01)

- **`backend/app/data/popular_labels.txt.gz`** (+ `popular_labels.manifest.json`): the registrable-name labels (TLD removed, non-alphanumerics
  stripped) of the 100,000 highest-ranked rows of the **Majestic Million** snapshot (CC BY 3.0 — **attribute Majestic** wherever the product
  documents its data sources). Used only to say how common a brand word is in everyday domain names ("N of 100,000 popular domains contain
  it"); it does not change a score. Rebuild: `python tools/build_popular_labels.py <majestic_million.csv>` (byte-reproducible; SHA-256 recorded
  in the manifest and covered by a test). Ships ≈ 0.5 MB.
- **`SUPPLEMENTAL_PLATFORMS`** in `app/services/public_suffix.py`: 20 free site-builder/hosting domains the Public Suffix List does not carry
  (curated by hand; the PSL stays authoritative and is never overridden). Not a licensed dataset — a short factual list.
- **Afrikaans/Zulu lure words** in `brand_discovery_service.py`: curated by hand, **not yet reviewed by a native speaker**.

## Step 2.5 additions (2026-10-02)

- **`backend/app/data/popular_domains.txt.gz`** — "rank<TAB>domain" for the 100,000 highest-ranked domains of the Majestic Million snapshot (CC BY 3.0 — **attribute Majestic**). Used only as a benign explainer ("this look-alike is itself a well-known site"). Built by the same byte-reproducible `tools/build_popular_labels.py` as `popular_labels.txt.gz` (note: the labels file was rebuilt in this step because the supplemental hosting platforms added in 2.2 are now excluded from it; its manifest and test stay consistent). ≈0.9 MB.
- **Live corroboration feeds, production use:** phishunt.io `feed.json` (CC0 1.0, no auth; ~0.9 MB) and abuse.ch URLhaus `csv_online` (CC0; ~3.3 MB) are downloaded at most every 30 minutes per backend process — about 2 requests per 30 minutes, i.e. community-scale use, not the "heavy commercial API use" abuse.ch says may need a paid plan. **Re-check both terms before launch**, and note the volume would grow with the number of backend processes (each keeps its own copy).
- **Not used, and why:** Spamhaus DBL / SURBL / URIBL (free tiers are for non-commercial or low-volume use; a commercial product needs the paid data-query service) and Web Risk / VirusTotal (paid API keys) — waiting on a product decision.

## Step 2.6b additions (2026-10-02)

- **WhoisDS free newly-registered-domain list** (`https://www.whoisds.com//whois-database/newly-registered-domains/<base64 of YYYY-MM-DD.zip>/nrd`): no login or key; ZIP of one text file; the site states the free lists "may be reused, including for commercial purposes, without a license and without any payment". Domains only, no WHOIS. **The free list is exactly 70,000 names/day (a sample), published the next day.** Fetched 3 small files a day at most (once each), kept in memory. **Re-check the terms before launch**; a paid tier (full list, with WHOIS) exists.
- **Not used, and why:** CertStream public server (the project says non-experimental use should run its own server; it has had outages); ICANN CZDS (per-TLD registry approval, 90-day expiry, no redistribution, lawful-use undertaking — needs the operator's own ICANN account); `.za` zone/registration data (no public bulk source found).

## Live certificate stream additions (2026-10-02)

- **Public CT log list** (`https://www.gstatic.com/ct/log_list/v3/log_list.json`): read every 6 h to find the current tiled logs of the configured families and their expiry shards; a built-in fallback is used if it cannot be fetched.
- **Tiled CT logs** (static-ct-api / tlog-tiles): Google `ParcelYard*` (`storage.googleapis.com/parcelyard*.prod.certificate.transparency.goog/`) and Let's Encrypt `Willow*` (`mon.willow.ct.letsencrypt.org/`). Public by design (anyone may monitor); the worker identifies itself in its User-Agent and downloads about 56 GB/day. **Read each operator's monitoring/usage terms before production use.** The log signature is not verified: a certificate is a lead, never evidence.
- Nothing is stored beyond the matched names and the worker's read positions (`ct_stream_cursors`).
