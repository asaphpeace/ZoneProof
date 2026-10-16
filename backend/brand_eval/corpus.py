"""
Versioned evaluation corpus builder (plan step 1.2).

Inputs are the immutable snapshots fetched by tools/brand_corpus_fetch.py
(BRAND_GUARD_DATA_SOURCES.md): phishunt.io for brand-labelled phishing, Majestic
Million for legitimate domains. Output is one content-addressed directory per
build — same inputs + parameters + builder version always yield byte-identical
output, so a later harness result can be tied to exactly the data it ran on.

Record classes (`label`):
  malicious_suspected  phishing labelled with its target brand (phishunt; NOT human-verified)
  popular_lookalike    popular legitimate domains that resemble a brand (same name/other suffix,
                       contains the brand, or within edit distance 2) — derived from Majestic, so
                       independent of every phishing feed. Popularity is evidence of legitimacy,
                       not proof: their relationship to the brand is unknown, so these are
                       "should not be high-severity" cases, not "benign" ground truth.
  popular_unrelated    random popular domains unrelated to any mapped brand (plain false-positive check)

Every metric built on this must be reported per stratum (`technique`, `free_hosting`,
`quality`), never as a single headline number — see BRAND_GUARD_DATA_SOURCES.md.
"""
from __future__ import annotations

import csv
import hashlib
import json
import random
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import urlsplit

from app.services.brand_discovery_service import edit_distance
from brand_eval.domains import NAME_DETECTABLE, classify_technique, norm, split_host

BUILDER_VERSION = "1"
MAP_MAX_RANK = 500_000          # a brand slug must resolve to a Majestic domain at least this popular
LOW_CONFIDENCE_RANK = 100_000   # ...and beyond this it is too doubtful to label with (excluded unless overridden)
LOOKALIKE_MAX_RANK = 100_000    # popular_lookalike candidates must be at least this popular
UNRELATED_MAX_RANK = 200_000
PER_BRAND_LOOKALIKE_CAP = 30
MIN_SLUG_LEN_FOR_CONTAINS = 5
MIN_LABEL_LEN_FOR_NEAR_MISS = 6
POSITIVE_VERDICTS = {"critical": "suspected_high", "high": "suspected_high", "medium": "suspected_medium"}
SPLIT_RATIOS = (0.6, 0.2, 0.2)  # train / valid / test


@dataclass
class Record:
    id: str
    label: str                  # malicious_suspected | popular_lookalike | popular_unrelated
    domain: str                 # full host as observed
    registrable: str
    subdomain: str
    brand: str | None           # brand slug (phishunt `company`) or the brand a lookalike resembles
    brand_domain: str | None
    technique: str              # literal stratum, see domains.classify_technique / lookalike subtype
    quality: str                # suspected_high | suspected_medium | derived_popularity
    free_hosting: bool
    is_idn: bool
    first_seen: str | None      # ISO; positives only
    rank: int | None            # Majestic GlobalRank; negatives only
    source: str
    split: str = ""
    extra: dict = field(default_factory=dict)


def _rid(label: str, registrable: str, brand: str | None) -> str:
    return hashlib.sha1(f"{label}|{registrable}|{brand or ''}".encode()).hexdigest()[:16]


# ── inputs ───────────────────────────────────────────────────────────────────

def find_snapshots(corpus_root: Path) -> dict[str, dict]:
    """Newest retrieved file per source across all snapshot manifests:
    {source: {"path": Path, "sha256": str, "snapshot": str, "retrieved_at": str}}."""
    found: dict[str, dict] = {}
    for manifest_path in sorted(corpus_root.glob("*/manifest.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf8"))
        for f in manifest.get("files", []):
            cur = found.get(f["source"])
            if cur is None or f["retrieved_at"] > cur["retrieved_at"]:
                found[f["source"]] = {
                    "path": manifest_path.parent / f["file"], "sha256": f["sha256"],
                    "snapshot": manifest_path.parent.name, "retrieved_at": f["retrieved_at"],
                }
    return found


def load_phishunt(path: Path) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf8"))
    return data if isinstance(data, list) else next(v for v in data.values() if isinstance(v, list))


def load_majestic(path: Path, max_rank: int = 1_000_000) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    with Path(path).open(encoding="utf8", newline="") as fh:
        for row in csv.DictReader(fh):
            rank = int(row["GlobalRank"])
            if rank > max_rank:
                break
            rows.append((rank, row["Domain"].strip().lower()))
    return rows


# ── brand → official domain ──────────────────────────────────────────────────

def map_brands(slugs: Iterable[str], majestic: list[tuple[int, str]], overrides: dict[str, str] | None = None) -> tuple[dict, list[str], list[str]]:
    """Resolve each brand slug to its most popular Majestic domain whose name IS the slug.
    Returns (mapping, unmapped, low_confidence). A slug only resolving to a domain ranked
    beyond 100k is "low confidence" (e.g. `steam` -> steam.com, not steampowered.com) and is
    EXCLUDED unless an override supplies the real domain: a mislabelled positive is worse than
    a missing one. Ambiguity (another domain with the same name within 5x the rank) is
    recorded, not hidden."""
    overrides = {norm(k): v.lower() for k, v in (overrides or {}).items()}
    by_label: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for rank, domain in majestic:
        parts = split_host(domain)
        # Majestic lists some subdomains (apps.apple.com, open.spotify.com): always work with
        # the registrable domain so a subdomain is neither picked as the brand's domain nor
        # mistaken for a competing one.
        by_label[norm(parts.label)].append((rank, parts.registrable))

    mapping: dict[str, dict] = {}
    unmapped: list[str] = []
    low_confidence: list[str] = []
    for slug in sorted({norm(s) for s in slugs if s}):
        if slug in overrides:
            mapping[slug] = {"domain": overrides[slug], "rank": None, "confidence": "override", "ambiguous_with": []}
            continue
        candidates = sorted(by_label.get(slug, []))
        if not candidates or candidates[0][0] > MAP_MAX_RANK:
            unmapped.append(slug)
            continue
        best_rank, best = candidates[0]
        if best_rank > LOW_CONFIDENCE_RANK:
            low_confidence.append(slug)
            continue
        rivals = sorted({d for r, d in candidates[1:] if r <= best_rank * 5 and d != best})
        mapping[slug] = {
            "domain": best, "rank": best_rank, "ambiguous_with": rivals,
            "confidence": "high" if best_rank <= 5_000 and not rivals else "medium",
        }
    return mapping, unmapped, low_confidence


# ── positives ────────────────────────────────────────────────────────────────

def build_positives(phish_rows: list[dict], mapping: dict, snapshot: str) -> tuple[list[Record], Counter]:
    dropped: Counter = Counter()
    best: dict[tuple[str, str], Record] = {}
    for r in phish_rows:
        slug = norm(r.get("company") or "")
        if not slug:
            dropped["unlabelled"] += 1
            continue
        verdict = (r.get("verdict") or "").lower()
        if verdict not in POSITIVE_VERDICTS:
            dropped[f"verdict_{verdict or 'missing'}"] += 1
            continue
        if slug not in mapping:
            dropped["brand_unmapped_or_low_confidence"] += 1
            continue
        host = (r.get("domain") or "").strip().lower() or urlsplit(r.get("url") or "").hostname or ""
        if not host:
            dropped["no_host"] += 1
            continue
        parts = split_host(host)
        brand_domain = mapping[slug]["domain"]
        path = urlsplit(r.get("url") or "").path
        rec = Record(
            id=_rid("malicious_suspected", parts.registrable, slug), label="malicious_suspected", domain=host,
            registrable=parts.registrable, subdomain=parts.subdomain, brand=slug, brand_domain=brand_domain,
            technique=classify_technique(parts, slug, brand_domain, path), quality=POSITIVE_VERDICTS[verdict],
            free_hosting=parts.free_hosting, is_idn=parts.is_idn, first_seen=r.get("first_seen") or r.get("date"),
            rank=None, source=f"phishunt:{snapshot}",
            # Only descriptive fields. The feed's per-source cross-reference flags are dropped on
            # ingest (they reference OpenPhish, whose terms are non-commercial) — never used as labels.
            extra={"mapping_confidence": mapping[slug]["confidence"], "score": r.get("score"), "verdict": verdict, "asn": r.get("asn"), "org": r.get("org"), "country": r.get("country")},
        )
        key = (rec.registrable, slug)
        if key in best:
            dropped["duplicate"] += 1
            if (rec.first_seen or "") < (best[key].first_seen or ""):
                best[key] = rec
            continue
        best[key] = rec
    return sorted(best.values(), key=lambda x: (x.first_seen or "", x.id)), dropped


# ── negatives ────────────────────────────────────────────────────────────────

def _hist_close(a: str, b: str, limit: int = 4) -> bool:
    """Cheap necessary condition for edit distance <= 2: character-count difference <= 4."""
    ca, cb = Counter(a), Counter(b)
    return sum(((ca - cb) + (cb - ca)).values()) <= limit


def build_popular_lookalikes(majestic: list[tuple[int, str]], mapping: dict, snapshot: str, cap: int = PER_BRAND_LOOKALIKE_CAP) -> list[Record]:
    pool = [(rank, dom, split_host(dom)) for rank, dom in majestic if rank <= LOOKALIKE_MAX_RANK]
    by_len: dict[int, list[tuple[int, str, object, str]]] = defaultdict(list)
    for rank, dom, parts in pool:
        ln = norm(parts.label)
        by_len[len(ln)].append((rank, dom, parts, ln))

    out: dict[str, Record] = {}
    for slug in sorted(mapping):
        brand_domain = mapping[slug]["domain"]
        brand_parts = split_host(brand_domain)
        blabel = norm(brand_parts.label)
        found: list[tuple[int, str, object, str, str]] = []

        for rank, dom, parts in pool:
            if parts.registrable == brand_parts.registrable:
                continue
            ln = norm(parts.label)
            if ln == blabel:
                found.append((rank, dom, parts, ln, "same_name_other_suffix"))
            elif len(slug) >= MIN_SLUG_LEN_FOR_CONTAINS and slug in ln:
                found.append((rank, dom, parts, ln, "contains_brand"))
        if len(blabel) >= MIN_LABEL_LEN_FOR_NEAR_MISS:
            for length in range(len(blabel) - 2, len(blabel) + 3):
                for rank, dom, parts, ln in by_len.get(length, []):
                    if ln == blabel or slug in ln or parts.registrable == brand_parts.registrable:
                        continue
                    if _hist_close(ln, blabel) and edit_distance(ln, blabel) <= 2:
                        found.append((rank, dom, parts, ln, "near_miss"))

        for rank, dom, parts, _ln, subtype in sorted(found, key=lambda t: (t[0], t[1]))[:cap]:
            rec = Record(
                id=_rid("popular_lookalike", parts.registrable, slug), label="popular_lookalike", domain=dom,
                registrable=parts.registrable, subdomain="", brand=slug, brand_domain=brand_domain, technique=subtype,
                quality="derived_popularity", free_hosting=False, is_idn=parts.is_idn, first_seen=None, rank=rank,
                source=f"majestic:{snapshot}",
            )
            out.setdefault(rec.id, rec)
    return sorted(out.values(), key=lambda x: (x.rank or 0, x.id))


def sample_popular_unrelated(majestic: list[tuple[int, str]], mapping: dict, snapshot: str, n: int, seed: int, exclude: set[str]) -> list[Record]:
    rng = random.Random(seed)
    pool = [(r, d) for r, d in majestic if r <= UNRELATED_MAX_RANK and d not in exclude]
    rng.shuffle(pool)
    brand_labels = [(slug, norm(split_host(m["domain"]).label)) for slug, m in sorted(mapping.items())]

    def resembles_any_brand(ln: str) -> bool:
        for slug, bl in brand_labels:
            if ln == bl or (len(slug) >= MIN_SLUG_LEN_FOR_CONTAINS and slug in ln):
                return True
            if len(bl) >= MIN_LABEL_LEN_FOR_NEAR_MISS and abs(len(ln) - len(bl)) <= 2 and _hist_close(ln, bl) and edit_distance(ln, bl) <= 2:
                return True
        return False

    out: list[Record] = []
    for rank, dom in pool:
        parts = split_host(dom)
        if resembles_any_brand(norm(parts.label)):
            continue
        out.append(Record(
            id=_rid("popular_unrelated", parts.registrable, None), label="popular_unrelated", domain=dom,
            registrable=parts.registrable, subdomain="", brand=None, brand_domain=None, technique="unrelated",
            quality="derived_popularity", free_hosting=False, is_idn=parts.is_idn, first_seen=None, rank=rank,
            source=f"majestic:{snapshot}",
        ))
        if len(out) >= n:
            break
    return sorted(out, key=lambda x: (x.rank or 0, x.id))


# ── splits ───────────────────────────────────────────────────────────────────

def _hash_split(record_id: str) -> str:
    bucket = int(hashlib.sha256(record_id.encode()).hexdigest(), 16) % 100
    return "train" if bucket < int(SPLIT_RATIOS[0] * 100) else "valid" if bucket < int((SPLIT_RATIOS[0] + SPLIT_RATIOS[1]) * 100) else "test"


def assign_splits(positives: list[Record], negatives: list[Record]) -> dict:
    """Positives: chronological by first_seen (train oldest, test newest), with every record of the
    same registrable domain kept in the same split so a campaign can't leak across the boundary.
    Negatives have no time axis: stable hash split."""
    groups: dict[str, list[Record]] = defaultdict(list)
    for r in positives:
        groups[r.registrable].append(r)
    ordered = sorted(groups.values(), key=lambda g: (min(x.first_seen or "" for x in g), g[0].registrable))
    total = sum(len(g) for g in ordered)
    train_cut, valid_cut = total * SPLIT_RATIOS[0], total * (SPLIT_RATIOS[0] + SPLIT_RATIOS[1])
    seen = 0
    for g in ordered:
        split = "train" if seen < train_cut else "valid" if seen < valid_cut else "test"
        for r in g:
            r.split = split
        seen += len(g)
    for r in negatives:
        r.split = _hash_split(r.id)

    # Splits are ordered by CAMPAIGN START (the earliest sighting of each registrable domain). A
    # domain's later sightings stay with its campaign, so record-level times can overlap across
    # splits; that overlap is reported (`latest_sighting`) rather than hidden.
    starts = {g[0].registrable: min(x.first_seen or "" for x in g) for g in ordered}

    def bounds(split: str) -> dict:
        members = [g for g in ordered if g[0].split == split]
        s = sorted(starts[g[0].registrable] for g in members if starts[g[0].registrable])
        latest = sorted(x.first_seen for g in members for x in g if x.first_seen)
        return {
            "campaign_start_from": s[0] if s else None, "campaign_start_to": s[-1] if s else None,
            "latest_sighting": latest[-1] if latest else None, "n": sum(len(g) for g in members),
        }

    return {s: bounds(s) for s in ("train", "valid", "test")}


# ── build ────────────────────────────────────────────────────────────────────

def _stats(records: list[Record]) -> dict:
    pos = [r for r in records if r.label == "malicious_suspected"]
    return {
        "by_label_split": {f"{lbl}/{sp}": n for (lbl, sp), n in sorted(Counter((r.label, r.split) for r in records).items())},
        "positives_by_technique": dict(sorted(Counter(r.technique for r in pos).items())),
        "positives_by_technique_split": {f"{t}/{s}": n for (t, s), n in sorted(Counter((r.technique, r.split) for r in pos).items())},
        "positives_by_quality": dict(sorted(Counter(r.quality for r in pos).items())),
        "positives_free_hosting": sum(1 for r in pos if r.free_hosting),
        "positives_name_detectable": sum(1 for r in pos if r.technique in NAME_DETECTABLE),
        "positives_total": len(pos),
        "lookalikes_by_subtype": dict(sorted(Counter(r.technique for r in records if r.label == "popular_lookalike").items())),
        "brands_with_positives": len({r.brand for r in pos}),
    }


def build(corpus_root: Path, out_root: Path, *, seed: int = 1337, unrelated_n: int = 3000, overrides: dict[str, str] | None = None, force: bool = False) -> dict:
    snaps = find_snapshots(Path(corpus_root))
    for needed in ("phishunt_json", "majestic_million"):
        if needed not in snaps:
            raise FileNotFoundError(f"No snapshot of {needed!r} under {corpus_root} — run tools/brand_corpus_fetch.py first")

    params = {"seed": seed, "unrelated_n": unrelated_n, "overrides": overrides or {}, "split_ratios": SPLIT_RATIOS,
              "per_brand_lookalike_cap": PER_BRAND_LOOKALIKE_CAP, "lookalike_max_rank": LOOKALIKE_MAX_RANK,
              "unrelated_max_rank": UNRELATED_MAX_RANK, "map_max_rank": MAP_MAX_RANK}
    inputs = {k: {"sha256": snaps[k]["sha256"], "snapshot": snaps[k]["snapshot"], "retrieved_at": snaps[k]["retrieved_at"]}
              for k in ("phishunt_json", "majestic_million")}
    version = "c-" + hashlib.sha256(json.dumps({"v": BUILDER_VERSION, "params": params, "inputs": {k: v["sha256"] for k, v in inputs.items()}}, sort_keys=True).encode()).hexdigest()[:12]
    out_dir = Path(out_root) / version
    if out_dir.exists() and not force:
        raise FileExistsError(f"{out_dir} already exists (same inputs and parameters). Pass force=True to rebuild.")

    phish = load_phishunt(snaps["phishunt_json"]["path"])
    majestic = load_majestic(snaps["majestic_million"]["path"])
    mapping, unmapped, low_confidence = map_brands({r.get("company") for r in phish}, majestic, overrides)

    positives, dropped = build_positives(phish, mapping, inputs["phishunt_json"]["snapshot"])
    used_brands = {r.brand for r in positives}
    mapping_used = {s: m for s, m in mapping.items() if s in used_brands}
    lookalikes = build_popular_lookalikes(majestic, mapping_used, inputs["majestic_million"]["snapshot"])
    exclude = {r.registrable for r in positives} | {r.registrable for r in lookalikes} | {m["domain"] for m in mapping_used.values()}
    unrelated = sample_popular_unrelated(majestic, mapping_used, inputs["majestic_million"]["snapshot"], unrelated_n, seed, exclude)

    negatives = lookalikes + unrelated
    cutoffs = assign_splits(positives, negatives)
    records = sorted(positives + negatives, key=lambda r: (r.label, r.split, r.id))

    out_dir.mkdir(parents=True, exist_ok=True)
    body = "\n".join(json.dumps(asdict(r), sort_keys=True, ensure_ascii=False) for r in records) + "\n"
    (out_dir / "corpus.jsonl").write_text(body, encoding="utf8", newline="\n")
    manifest = {
        "corpus_version": version, "builder_version": BUILDER_VERSION, "params": params, "inputs": inputs,
        "corpus_sha256": hashlib.sha256(body.encode("utf8")).hexdigest(), "records": len(records),
        "positive_split_bounds": cutoffs, "stats": _stats(records),
        "brand_mapping": {s: m for s, m in sorted(mapping_used.items())},
        "brands_unmapped": unmapped, "brands_excluded_low_confidence": low_confidence, "positives_dropped": dict(sorted(dropped.items())),
        "caveats": [
            "malicious_suspected labels are automated suspicion (phishunt), not human-verified",
            "popular_lookalike = popular domain resembling a brand; relationship to the brand is unknown (not proven benign)",
            "no South African brands in the phishing feed; a hand-labelled SA gold set is required for SA claims",
            "report metrics per technique/quality stratum; never a single headline number",
        ],
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf8", newline="\n")
    return manifest


def iter_corpus(version_dir: Path, *, split: str | None = None, label: str | None = None) -> Iterator[dict]:
    with (Path(version_dir) / "corpus.jsonl").open(encoding="utf8") as fh:
        for line in fh:
            rec = json.loads(line)
            if (split is None or rec["split"] == split) and (label is None or rec["label"] == label):
                yield rec
