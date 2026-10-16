"""
Builds two files from the Majestic Million snapshot:
  app/data/popular_labels.txt.gz   registrable-name labels of the most popular domains, used by
                                   app/services/brand_background.py (how common is a brand word?);
  app/data/popular_domains.txt.gz  "rank<TAB>domain" for the same domains, used by app/services/brand_popularity.py
                                   (is this look-alike itself a well-known site?).

Source: Majestic Million (CC BY 3.0 — attribution is in BRAND_GUARD_DATA_SOURCES.md and the product's
data-sources notice). The raw CSV is the snapshot the evaluation corpus already downloads; this script
only reads it, so a rebuild is reproducible from the corpus snapshot.

    python tools/build_popular_labels.py data/brand_guard_corpus/2026-09-30/majestic_million.csv [N]

Why a list and not a statistical model: a random-letter model misjudged real words by 3-4 orders of
magnitude when checked against the same data ('apple' 300x too rare, 'amazon' 45,000x), so the product
uses measured frequency instead.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.brand_discovery_service import split_registrable  # noqa: E402

DEFAULT_N = 100_000
OUT_DIR = Path(__file__).resolve().parent.parent / "app" / "data"


def build(csv_path: Path, n: int = DEFAULT_N) -> dict:
    labels: list[str] = []
    domains: list[str] = []
    with open(csv_path, encoding="utf8", newline="") as f:
        for row in csv.DictReader(f):
            domain = row["Domain"].strip().lower()
            label = re.sub(r"[^a-z0-9]", "", split_registrable(domain)[0])
            if label:
                labels.append(label)
                domains.append(f"{row['GlobalRank']}\t{domain}")
            if len(labels) >= n:
                break
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {"source": "Majestic Million (CC BY 3.0)", "source_file": csv_path.name}
    # mtime=0 so the same input always yields the same bytes (the detector fingerprint hashes these files)
    for name, lines in (("popular_labels", labels), ("popular_domains", domains)):
        body = ("\n".join(lines) + "\n").encode("utf8")
        with open(OUT_DIR / f"{name}.txt.gz", "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
            gz.write(body)
        manifest[name] = {"rows": len(lines), "sha256_of_rows": hashlib.sha256(body).hexdigest()}
    # keys the existing loader and tests read stay where they were
    manifest["labels"] = manifest["popular_labels"]["rows"]
    manifest["sha256_of_labels"] = manifest["popular_labels"]["sha256_of_rows"]
    (OUT_DIR / "popular_labels.manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf8")
    return manifest


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    print(json.dumps(build(Path(sys.argv[1]), int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_N), indent=2))
