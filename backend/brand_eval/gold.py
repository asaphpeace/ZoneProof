"""
Gold-set handling (plan step 1.2 amendment): the South African and "no brand
name in the domain" gold sets that the public feeds can't provide.

I can build the tooling and the review queue (review_queue.py); I cannot and
must not invent the labels. A gold label is a HUMAN judgement recorded with who
made it and when, so the CSV schema requires a labeller and date for every
labelled row and the loader rejects anything else.

    python -m brand_eval.gold verify-sa          # check the SA registry against live DNS + homepage titles
    python -m brand_eval.gold report <file.csv>  # validate a labelled file and show coverage
"""
from __future__ import annotations

import asyncio
import csv
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from brand_eval.domains import norm, split_host

# A human's judgement about a candidate lookalike of `brand_domain`.
GOLD_LABELS = (
    "malicious_lookalike",     # impersonating the brand or abusing it
    "defensive_registration", # registered by/for the brand owner (customer-owned)
    "legitimate_unrelated",   # an unrelated legitimate site that merely resembles the name
    "unsure",                 # could not decide — excluded from metrics, kept for review
)
REQUIRED_COLUMNS = ("brand_domain", "candidate", "label", "labeller", "labelled_at")
SA_REGISTRY = Path(__file__).resolve().parent / "sa_brands.json"


@dataclass
class GoldRow:
    brand_domain: str
    candidate: str
    label: str
    labeller: str
    labelled_at: str
    notes: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class GoldLoad:
    rows: list[GoldRow]
    unlabelled: int
    errors: list[str]

    @property
    def ok(self) -> bool:
        return not self.errors


def load_gold_csv(path: Path) -> GoldLoad:
    rows: dict[tuple[str, str], GoldRow] = {}
    errors: list[str] = []
    unlabelled = 0
    with Path(path).open(encoding="utf8", newline="") as fh:
        reader = csv.DictReader(fh)
        missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            return GoldLoad([], 0, [f"missing required column(s): {', '.join(missing)}"])
        for n, raw in enumerate(reader, start=2):  # row 1 is the header
            label = (raw.get("label") or "").strip().lower()
            cand = (raw.get("candidate") or "").strip().lower()
            brand = (raw.get("brand_domain") or "").strip().lower()
            if not cand or not brand or not split_host(cand).label or not split_host(brand).label:
                errors.append(f"row {n}: candidate and brand_domain must be domain names")
                continue
            if not label:
                unlabelled += 1
                continue
            if label not in GOLD_LABELS:
                errors.append(f"row {n}: label {label!r} is not one of {', '.join(GOLD_LABELS)}")
                continue
            labeller, stamp = (raw.get("labeller") or "").strip(), (raw.get("labelled_at") or "").strip()
            if not labeller or not stamp:
                errors.append(f"row {n}: a labelled row needs labeller and labelled_at (who decided, and when)")
                continue
            try:
                datetime.fromisoformat(stamp)
            except ValueError:
                errors.append(f"row {n}: labelled_at {stamp!r} is not an ISO date")
                continue
            row = GoldRow(brand, cand, label, labeller, stamp, (raw.get("notes") or "").strip(),
                          {k: v for k, v in raw.items() if k not in REQUIRED_COLUMNS and k != "notes"})
            prior = rows.get((brand, cand))
            if prior and prior.label != label:
                errors.append(f"row {n}: {cand} for {brand} labelled both {prior.label!r} and {label!r}")
                continue
            rows[(brand, cand)] = row
    return GoldLoad(list(rows.values()), unlabelled, errors)


def summarize(load: GoldLoad) -> dict:
    by_label = Counter(r.label for r in load.rows)
    by_stratum = Counter(r.extra.get("brand_slug_in_name", "unknown") for r in load.rows)
    return {
        "labelled": len(load.rows), "unlabelled": load.unlabelled, "errors": len(load.errors),
        "by_label": dict(sorted(by_label.items())), "by_brand_slug_in_name": dict(sorted(by_stratum.items())),
        "brands": len({r.brand_domain for r in load.rows}),
        "usable_for_metrics": sum(1 for r in load.rows if r.label != "unsure"),
    }


def load_sa_registry(path: Path = SA_REGISTRY) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf8"))["brands"]
    seen_slugs: set[str] = set()
    seen_domains: set[str] = set()
    for b in data:
        for key in ("slug", "name", "domain", "category", "title_keywords"):
            if not b.get(key):
                raise ValueError(f"SA registry entry {b.get('slug')!r} is missing {key!r}")
        parts = split_host(b["domain"])
        if parts.registrable != b["domain"].lower():
            raise ValueError(f"{b['slug']}: {b['domain']!r} is not a registrable domain (got {parts.registrable!r})")
        if norm(b["slug"]) != b["slug"]:
            raise ValueError(f"{b['slug']}: slug must be lowercase alphanumeric")
        if b["slug"] in seen_slugs or b["domain"] in seen_domains:
            raise ValueError(f"duplicate SA registry entry: {b['slug']} / {b['domain']}")
        seen_slugs.add(b["slug"])
        seen_domains.add(b["domain"])
    return data


async def verify_sa_brands(brands: list[dict] | None = None) -> list[dict]:
    """Live sanity check of the registry: does each domain resolve, and does its homepage
    title mention the brand? A failed check does NOT prove a wrong domain (bot protection is
    common) — it means a human must confirm it before the brand is used."""
    import re

    import dns.exception
    import httpx

    from app.services.dns_resolver import resolver

    async def one(client: httpx.AsyncClient, b: dict) -> dict:
        out = {"slug": b["slug"], "domain": b["domain"], "resolves": False, "http_status": None, "title": None, "title_match": False}
        try:
            out["resolves"] = bool(await resolver.resolve(b["domain"], "A"))
        except dns.exception.DNSException:
            return out
        try:
            resp = await client.get(f"https://{b['domain']}/", follow_redirects=True)
            out["http_status"] = resp.status_code
            m = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:200_000], re.I | re.S)
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""
            out["title"] = title or None
            out["title_match"] = any(k.lower() in title.lower() for k in b["title_keywords"])
        except httpx.HTTPError as e:
            out["http_error"] = type(e).__name__
        return out

    async with httpx.AsyncClient(timeout=15.0, headers={"User-Agent": "Mozilla/5.0 (Sentinel brand registry check)"}) as client:
        return await asyncio.gather(*(one(client, b) for b in (brands or load_sa_registry())))


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "verify-sa":
        results = asyncio.run(verify_sa_brands())
        for r in results:
            flag = "ok " if r["title_match"] else "CHECK"
            print(f"{flag}  {r['slug']:13} {r['domain']:22} resolves={r['resolves']!s:5} http={r['http_status']}  title={r['title']!r}")
        bad = [r for r in results if not r["title_match"]]
        print(f"\n{len(results) - len(bad)}/{len(results)} confirmed by title; {len(bad)} need a human check.")
        return 0
    if len(argv) == 3 and argv[1] == "report":
        load = load_gold_csv(Path(argv[2]))
        print(json.dumps(summarize(load), indent=2))
        for e in load.errors:
            print("ERROR", e)
        return 0 if load.ok else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
