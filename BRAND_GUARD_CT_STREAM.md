# Brand Guard — live certificate stream worker (plan step 2.6b)

A separate, long-running process that follows Certificate Transparency logs and turns look-alike certificates into Brand Guard
candidates **seconds** after a log records them. Built 2026-10-02.

## Run it

```bash
cd backend
BRAND_GUARD_ENABLED=true python -m app.workers.ct_stream               # until stopped
BRAND_GUARD_ENABLED=true python -m app.workers.ct_stream --seconds 120 # smoke test
```

It refuses to start unless `BRAND_GUARD_ENABLED=true` (same opt-in as the rest of Brand Guard's background work), needs the same
database as the API, and must run as **one instance** (two would read the same logs twice; the do-not-repeat memory is per process).
It touches only Brand Guard tables (`brand_*`, `candidate_evidence`, `ct_stream_cursors`); never PathProof's.

Migration: `a4c8e2d6b1f3` (`ct_stream_cursors`). Run `alembic upgrade head` before starting it.

A compose service would look like this (NOT added to the shared `docker-compose.yml`, which PathProof also uses; add it deliberately):

```yaml
  brand-guard-ct-stream:
    build: ./backend
    command: python -m app.workers.ct_stream
    environment: { BRAND_GUARD_ENABLED: "true" }   # plus the same DATABASE_URL etc. as the backend service
    restart: unless-stopped
```

## Settings (`backend/app/config.py`, env vars in capitals)

| Setting | Default | Meaning |
|---|---|---|
| `CT_STREAM_FAMILIES` | `parcelyard,willow` | Log families to follow: Google ParcelYard, Let's Encrypt Willow |
| `CT_STREAM_EXTRA_LOGS` | empty | Extra tiled-log monitoring URLs (https only) |
| `CT_STREAM_FLUSH_SECONDS` | 20 | How often matches go to the scoring pipeline |
| `CT_STREAM_MAX_PER_FLUSH` | 40 | Names per brand per flush; the excess is counted as dropped, never queued without bound |
| `CT_STREAM_BACKLOG_TILES` | 1500 | If further behind than this (~384k entries), skip ahead rather than never catch up |

## What was measured (live, 2026-10-02) and what it means

* **Why tiled logs.** The older RFC 6962 API returns the whole certificate chain with every entry (~6.9 KB each; one busy Google log
  is ~190 entries/s, i.e. ~110 GB/day). Tiled logs serve static 256-entry files without the chain (~1.4-1.9 KB per entry).
* **Which logs.** Logs are sharded by certificate expiry, and the busy shard moves with the calendar (today Let's Encrypt writes
  mostly to Willow *2027h1*), so each family is followed across all its current and upcoming shards, re-resolved from the public
  log list every 6 hours. Sibling logs overlap almost completely (Willow/Sycamore 92%, ParcelYard/PlumbersArms 99%), so one per family.
  Willow + ParcelYard covered about 88% of the names seen across five tiled logs in a 150 s window.
* **Speed.** In a 100 s run: ~400 entries/s read, **lag behind the log head 2-7 seconds**, a restart resumed from its saved cursor.
* **Bandwidth.** About **56 GB/day** downloaded (≈5 Mbit/s sustained; ~25 GB of it Google, the rest Let's Encrypt). Inbound only.
* **CPU.** Parsing 256 entries takes ~20 ms. Matching against 38 brands is ~380 µs/name (≈2,600 names/s capacity against ~700/s
  needed), 100 brands ~1 ms/name (≈1,000 names/s): about one core's worth up to roughly 100 brands. Beyond that, shard the brands across
  processes (not built).
* **Yield.** 244 s against two dev brands (one 3-letter, one fictional): 98k entries read, 1 match. Few matches is expected; a brand with
  a distinctive name sees a handful a day.

## How it fails

* A log that errors is retried with exponential backoff (to 2 min); the other logs keep going.
* A tile not yet published (404) ends that pass quietly. A malformed tile is skipped and logged.
* Too far behind: it jumps to the head and records `entries_skipped` (visible in `ct_stream_cursors`).
* The matching pipeline failing for a brand is logged and does not stop the stream.
* Health appears in the customers' source-health strip as "Live certificate stream": healthy (the value shown is the lag), degraded
  with a reason when some logs are unreachable. It only appears once the worker has reported, so deployments without it show nothing.

## Honest limits

* Only the configured families are followed: a certificate logged only elsewhere (Sectigo, DigiCert, Cloudflare...) is missed.
* The log's signature is **not** verified. A certificate here is a lead that goes through DNS, registration data and scoring; it is never
  evidence on its own.
* It sees certificates, not registrations. A look-alike that never gets a certificate is found by the new-registration list (next day)
  or the permutation scan.
* Per-brand matching uses the same name rules as a scan, behind a prefilter that is proven (and randomised-tested) never to hide a
  match. That prefilter was **wrong in its first version**: `papyal.com` is one swap from `paypal` yet shared no 3-letter window with
  it; the test suite caught it and the index now includes one-swap variants for 6-10 letter tokens.

## Decisions for the operator

1. **Bandwidth.** ~56 GB/day for both families. To halve it, follow only `willow` (Let's Encrypt: the free-certificate CA attackers
   favour) or only `parcelyard`.
2. **Operator usage policies.** The logs are public by design and the worker identifies itself (`User-Agent: ZoneProof-BrandGuard/1.0`),
   but read each operator's monitoring/usage terms before production, since this is continuous use.
3. **More coverage.** Adding families (e.g. `tuscolo`, `halloumi`) is a one-line setting; RFC 6962 logs (Sectigo, DigiCert, Cloudflare)
   would need a second reader and ~4-5x the bandwidth per entry; not built.
