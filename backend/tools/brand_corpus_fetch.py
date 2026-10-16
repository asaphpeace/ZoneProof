"""
Fetch the approved Brand Guard evaluation snapshots (BRAND_GUARD_DATA_SOURCES.md,
plan step 1.1) into a dated, gitignored folder with a checksum manifest.

    python tools/brand_corpus_fetch.py                 # all approved sources
    python tools/brand_corpus_fetch.py phishtank_json  # just one

Snapshots are immutable: each run writes a new dated directory and never
overwrites an earlier one, so any harness result can be tied to the exact bytes
it was computed from (manifest.json records source, URL, retrieval time, size
and SHA-256). Only sources the user approved are listed here; adding a source
means adding it to the register first.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

CORPUS_ROOT = Path(__file__).resolve().parent.parent / "data" / "brand_guard_corpus"
USER_AGENT = "Sentinel-BrandGuard-Eval/1.0 (+evaluation snapshot; contact: security engineering)"

# name -> (url, filename, expected size range in MB, licence/attribution note)
SOURCES: dict[str, tuple[str, str, tuple[float, float], str]] = {
    "phishtank_json": (
        "http://data.phishtank.com/data/online-valid.json", "phishtank_online_valid.json", (5, 400),
        "PhishTank 'Data' — free for commercial use (phishtank.org/terms.php, read 2026-09-30); link to phishtank.org appreciated.",
    ),
    "urlhaus_csv": (
        "https://urlhaus.abuse.ch/downloads/csv_online/", "urlhaus_csv_online.txt", (0.1, 100),
        "abuse.ch URLhaus — CC0 (urlhaus.abuse.ch/api/, read 2026-09-30); community/fair use.",
    ),
    "phishunt_json": (
        "https://phishunt.io/feed.json", "phishunt_feed.json", (0.0, 20),
        "phishunt.io — CC0 1.0 (phishunt.io/tos, read 2026-09-30); automated suspicion, NOT human-verified. "
        "Drop the per-source cross-reference flags on ingest (they reference OpenPhish, whose terms are non-commercial).",
    ),
    "majestic_million": (
        "https://downloads.majestic.com/majestic_million.csv", "majestic_million.csv", (20, 400),
        "Majestic Million — CC BY 3.0: commercial use allowed, attribute Majestic (majestic.com).",
    ),
}


def _fetch(client: httpx.Client, name: str, dest_dir: Path) -> dict:
    url, filename, (lo, hi), licence = SOURCES[name]
    path = dest_dir / filename
    sha, size = hashlib.sha256(), 0
    with client.stream("GET", url, follow_redirects=True) as resp:
        resp.raise_for_status()
        with path.open("wb") as fh:
            for chunk in resp.iter_bytes(1 << 20):
                fh.write(chunk)
                sha.update(chunk)
                size += len(chunk)
    mb = size / 1048576
    if not lo <= mb <= hi:
        path.unlink(missing_ok=True)
        raise RuntimeError(f"{name}: downloaded {mb:.1f} MB, outside the expected {lo}-{hi} MB — refusing to keep it")
    return {
        "source": name, "url": url, "file": filename, "bytes": size, "sha256": sha.hexdigest(),
        "retrieved_at": datetime.now(timezone.utc).isoformat(), "licence_note": licence,
    }


def main(argv: list[str]) -> int:
    wanted = argv[1:] or list(SOURCES)
    unknown = [w for w in wanted if w not in SOURCES]
    if unknown:
        print(f"Unknown source(s): {unknown}. Approved: {list(SOURCES)}", file=sys.stderr)
        return 2

    dest = CORPUS_ROOT / datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if dest.exists():
        dest = CORPUS_ROOT / datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S")  # never overwrite a snapshot
    dest.mkdir(parents=True)

    entries, failures = [], []
    with httpx.Client(timeout=httpx.Timeout(120.0, connect=15.0), headers={"User-Agent": USER_AGENT}) as client:
        for name in wanted:
            try:
                entry = _fetch(client, name, dest)
            except Exception as e:  # noqa: BLE001 — report per source, keep going
                failures.append(f"{name}: {type(e).__name__}: {e}")
                print(f"FAILED  {name}: {e}")
                continue
            entries.append(entry)
            print(f"ok      {name}: {entry['bytes'] / 1048576:.1f} MB  sha256={entry['sha256'][:16]}…")

    (dest / "manifest.json").write_text(json.dumps({"snapshot": dest.name, "files": entries, "failures": failures}, indent=2))
    print(f"\nSnapshot: {dest}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
