"""
    python -m brand_eval.build_corpus [--force] [--seed N] [--unrelated N]

Builds a content-addressed corpus from the newest snapshots under
backend/data/brand_guard_corpus/ into backend/data/brand_guard_corpus/built/<version>/.
Optional brand overrides (slug -> official domain) are read from
brand_eval/brand_overrides.json if it exists.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from brand_eval import corpus

ROOT = Path(__file__).resolve().parent.parent / "data" / "brand_guard_corpus"
OVERRIDES = Path(__file__).resolve().parent / "brand_overrides.json"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--force", action="store_true", help="rebuild even if this exact version exists")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--unrelated", type=int, default=3000, help="number of random popular_unrelated negatives")
    args = ap.parse_args(argv)

    overrides = json.loads(OVERRIDES.read_text(encoding="utf8")) if OVERRIDES.exists() else None
    try:
        m = corpus.build(ROOT, ROOT / "built", seed=args.seed, unrelated_n=args.unrelated, overrides=overrides, force=args.force)
    except (FileNotFoundError, FileExistsError) as e:
        print(e, file=sys.stderr)
        return 1

    s = m["stats"]
    print(f"corpus {m['corpus_version']}  records={m['records']}  sha256={m['corpus_sha256'][:16]}")
    print("by label/split:", json.dumps(s["by_label_split"]))
    print("positives by technique:", json.dumps(s["positives_by_technique"]))
    print(f"name-detectable positives: {s['positives_name_detectable']}/{s['positives_total']}; free-hosting: {s['positives_free_hosting']}")
    print("positive split bounds (by campaign start):", json.dumps(m["positive_split_bounds"]))
    print("brands unmapped:", m["brands_unmapped"], "| excluded (low-confidence mapping):", m["brands_excluded_low_confidence"], "| positives dropped:", json.dumps(m["positives_dropped"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
