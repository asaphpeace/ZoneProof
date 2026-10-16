"""
Harvest a human-review queue for the South African / no-slug gold sets.

    python -m brand_eval.review_queue [--brands standardbank,absa] [--out path.csv]

For each brand in sa_brands.json it generates lookalike candidates with the real
discovery code, resolves A/MX records, looks up registration dates for the ones
showing signs of life, and writes a CSV with the label columns EMPTY. A person
fills in `label` (one of gold.GOLD_LABELS), `labeller` and `labelled_at`; `python
-m brand_eval.gold report <csv>` then validates it. Nothing here decides
anything: the queue carries facts (live DNS, registration age, how the name was
generated) and never a verdict, so it can't leak the detector's opinion into the
ground truth.

Passive only: public DNS and RDAP/WHOIS lookups, nothing sent to the candidate hosts.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

from brand_eval.domains import norm, split_host
from brand_eval.gold import load_sa_registry

DEFAULT_DIR = Path(__file__).resolve().parent.parent / "data" / "brand_guard_corpus" / "gold"
COLUMNS = [
    "brand_domain", "candidate", "generator_class", "brand_slug_in_name", "has_a", "has_mx",
    "registered_at", "age_days", "label", "labeller", "labelled_at", "notes",
]
DNS_CONCURRENCY = 40
RDAP_CONCURRENCY = 5


async def build_queue(brands: list[dict]) -> tuple[list[dict], dict]:
    import httpx

    from app.services import brand_guard_service as svc
    from app.services.brand_discovery_service import generate_candidates

    dns_sem, rdap_sem = asyncio.Semaphore(DNS_CONCURRENCY), asyncio.Semaphore(RDAP_CONCURRENCY)
    stats = {"brands": 0, "generated": 0, "alive_or_registered": 0}
    rows: list[dict] = []

    async with httpx.AsyncClient(timeout=10.0) as client:
        for brand in brands:
            candidates = generate_candidates(brand["domain"], brand["name"], brand.get("keywords", []))
            stats["brands"] += 1
            stats["generated"] += len(candidates)
            slug_n = norm(brand["slug"])

            async def dns(d: str):
                async with dns_sem:
                    return d, await svc._dns_enrich(d)

            enriched = dict(await asyncio.gather(*(dns(d) for d in candidates)))
            alive = [d for d, e in enriched.items() if e["has_a"] or e["has_mx"]]

            async def reg(d: str):
                async with rdap_sem:
                    return d, await svc._registration_date(client, d)

            registered = dict(await asyncio.gather(*(reg(d) for d in alive)))
            for d in sorted(candidates):
                e, r = enriched[d], registered.get(d)
                if not (e["has_a"] or e["has_mx"] or r):
                    continue
                rows.append({
                    "brand_domain": brand["domain"], "candidate": d, "generator_class": candidates[d],
                    "brand_slug_in_name": str(slug_n in norm(split_host(d).label)).lower(),
                    "has_a": str(e["has_a"]).lower(), "has_mx": str(e["has_mx"]).lower(),
                    "registered_at": r.isoformat() if r else "", "age_days": (datetime.now(timezone.utc) - r).days if r else "",
                    "label": "", "labeller": "", "labelled_at": "", "notes": "",
                })
            stats["alive_or_registered"] = len(rows)
            print(f"{brand['slug']:13} generated={len(candidates):4} queued so far={len(rows)}", flush=True)
    return rows, stats


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--brands", help="comma-separated slugs (default: all in sa_brands.json)")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)

    brands = load_sa_registry()
    if args.brands:
        wanted = {s.strip() for s in args.brands.split(",")}
        brands = [b for b in brands if b["slug"] in wanted]
        if not brands:
            print(f"No matching brands for {sorted(wanted)}", file=sys.stderr)
            return 2

    rows, stats = asyncio.run(build_queue(brands))
    out = args.out or DEFAULT_DIR / f"sa_review_queue_{datetime.now(timezone.utc):%Y-%m-%d}.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    no_slug = sum(1 for r in rows if r["brand_slug_in_name"] == "false")
    print(f"\n{stats['generated']} candidates generated for {stats['brands']} brands; {len(rows)} show signs of life "
          f"({no_slug} without the brand name in the domain).\nQueue written to {out} — labels are empty; a human fills them in.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
