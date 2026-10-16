"""
Offline replay harness (plan step 1.3): run Brand Guard's *current* discovery and
identity scoring over an evaluation corpus and record, per record, exactly what
the detector would have done. Step 1.4 turns these raw results into metrics.

What is replayed, and what honestly is not
------------------------------------------
Replayed (pure functions of the domain name, deterministic, no network):
  * permutation reach  — would `generate_candidates(brand_domain, brand_name)` have produced it?
  * CT-name reach      — would `matches_brand_fingerprint` have accepted the hostname the CT path
                         hands over (the *registrable* apex, as brand_guard_service does)?
  * identity score     — `assess_candidate(...)` with no enrichment, i.e. what the name alone earns.

NOT replayed — `abuse_score`, status and alerting. They depend on live DNS, registration age and
certificate facts that cannot be reconstructed for historical phishing domains, and simulating them
would only grade the scoring rules against the assumptions we wrote into the simulation. Each result
carries `abuse_measurable: false`; real end-to-end measurement waits for observation history (plan 2.1).

Fidelity rule: reach and scoring use the DETECTOR's own domain parsing (`registrable_domain`,
`split_registrable`), not the corpus's literal strata. That is deliberate — it is how real gaps show
up, e.g. `login.brand.pages.dev` collapses to the platform apex `pages.dev` inside the detector, so
the brand is never seen. The corpus strata (independent of the detector) are then the lens used to
explain WHY a record was or wasn't reached.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from types import SimpleNamespace

from app.services import brand_discovery_service as disc
from app.services import public_suffix as psl
from app.services.brand_guard_service import brand_tokens_for
from app.services.brand_scoring_service import assess_candidate

REPLAY_VERSION = "1"
ROOT = Path(__file__).resolve().parent.parent / "data" / "brand_guard_corpus"
_DETECTOR_FILES = ("brand_discovery_service.py", "brand_scoring_service.py", "brand_guard_service.py", "public_suffix.py", "brand_background.py", "brand_baseline.py", "brand_mail_intent.py", "brand_infra_signals.py", "brand_corroboration.py", "brand_popularity.py")
_DATA_DIR = Path(disc.__file__).resolve().parent.parent / "data"
_DETECTOR_DATA = {
    "public_suffix_list.dat": _DATA_DIR / "public_suffix_list.dat",
    "popular_labels.txt.gz": _DATA_DIR / "popular_labels.txt.gz",   # the word-frequency reference the scorer reads
    "popular_domains.txt.gz": _DATA_DIR / "popular_domains.txt.gz", # the popularity reference the scorer reads (plan 2.5)
}


def _sha_text(text: str) -> str:
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf8")).hexdigest()


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def detector_fingerprint() -> dict:
    """Hash of the detector sources, line-ending-normalised so it is stable across machines.
    Lets any result be tied to the exact detector logic that produced it."""
    base = Path(disc.__file__).resolve().parent
    files = {name: _sha_text((base / name).read_text(encoding="utf8")) for name in _DETECTOR_FILES}
    # The vendored Public Suffix List is part of the detector: a different list changes what is reachable.
    files.update({name: (_sha_bytes(path.read_bytes()) if path.suffix == ".gz" else _sha_text(path.read_text(encoding="utf8")))
                  for name, path in _DETECTOR_DATA.items()})
    combined = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    return {"combined": combined, "files": files}


def _tokens(brand_domain: str, slug: str) -> list[str]:
    """Same brand tokens the live pipeline derives (brand_tokens_for), from a brand slug."""
    return brand_tokens_for(SimpleNamespace(brand_name=slug), brand_domain)


class _BrandContext:
    """Per-brand work done once: tokens and the full permutation candidate set."""

    def __init__(self, brand_domain: str, slug: str):
        self.brand_domain = brand_domain
        self.slug = slug
        self.tokens = _tokens(brand_domain, slug)
        self.official = {disc.registrable_domain(brand_domain)}
        self.candidates: dict[str, str] = disc.generate_candidates(brand_domain, slug, [])
        self.words = disc.brand_words(disc.split_registrable(brand_domain)[0], slug)

    def evaluate(self, host: str) -> dict:
        """What the detector does with one hostname for this brand."""
        apex = disc.registrable_domain(host)
        apex_ascii = disc.to_ascii(apex) or apex
        out = {"detector_apex": apex_ascii, "reach_permutation": False, "permutation_class": None,
               "reach_ct_name": False, "ct_token": None, "reach_subdomain": False, "subdomain_kind": None,
               "owned_by_brand": False, "identity_score": None, "threat_class": None, "signals": []}
        if apex_ascii in self.official:
            out["owned_by_brand"] = True      # the pipeline never treats the brand's own domain as a candidate
            return out
        if apex_ascii in self.candidates:
            out["reach_permutation"], out["permutation_class"] = True, self.candidates[apex_ascii]
        token = disc.matches_brand_fingerprint(apex_ascii, self.tokens)
        if token:
            out["reach_ct_name"], out["ct_token"] = True, token
        # Subdomain abuse: the registrable name shows no brand but the host's subdomain does. The live pipeline
        # tracks such a host under its full name, so it is scored as the full host.
        host_ascii = disc.to_ascii(host.lower()) or host.lower()
        sub = None if (out["reach_permutation"] or out["reach_ct_name"]) else disc.subdomain_brand_abuse(host_ascii, self.tokens, [self.brand_domain])
        if sub:
            out["reach_subdomain"], out["subdomain_kind"] = True, sub["kind"]
        if out["reach_permutation"] or out["reach_ct_name"] or out["reach_subdomain"]:
            a = assess_candidate(
                host_ascii if sub else apex_ascii, primary_domain=self.brand_domain, official_domains=[], brand_tokens=self.tokens,
                discovery_class=out["permutation_class"] or ("subdomain_abuse" if sub else None), enrichment={}, brand_words=self.words,
            )
            out["identity_score"] = round(a.identity_score, 1)
            out["threat_class"] = a.threat_class
            out["signals"] = sorted({s.signal for s in a.signals})
        return out


def replay_record(rec: dict, contexts: dict[str, _BrandContext]) -> dict:
    base = {k: rec[k] for k in ("id", "label", "technique", "quality", "free_hosting", "split", "brand", "brand_domain", "domain")}
    base["abuse_measurable"] = False

    if rec["label"] != "popular_unrelated":
        ctx = contexts[rec["brand"]]
        res = ctx.evaluate(rec["domain"])
        return {**base, **res, "evaluated": res["reach_permutation"] or res["reach_ct_name"] or res["reach_subdomain"], "ct_matches_brands": []}

    # Unrelated popular domains have no brand: ask whether the detector would wrongly tie them to ANY
    # brand (via the CT-name path, or by appearing in some brand's permutation set).
    hits, best = [], None
    for slug, ctx in contexts.items():
        res = ctx.evaluate(rec["domain"])
        if res["reach_permutation"] or res["reach_ct_name"] or res["reach_subdomain"]:
            hits.append(slug)
            if best is None or (res["identity_score"] or 0) > (best["identity_score"] or 0):
                best = res
    res = best or {"detector_apex": disc.to_ascii(disc.registrable_domain(rec["domain"])) or rec["domain"], "reach_permutation": False,
                   "permutation_class": None, "reach_ct_name": False, "ct_token": None, "reach_subdomain": False,
                   "subdomain_kind": None, "owned_by_brand": False, "identity_score": None, "threat_class": None, "signals": []}
    return {**base, **res, "evaluated": bool(hits), "ct_matches_brands": sorted(hits)}


def replay(corpus_dir: Path, out_dir: Path | None = None) -> dict:
    corpus_dir = Path(corpus_dir)
    cmanifest = json.loads((corpus_dir / "manifest.json").read_text(encoding="utf8"))
    records = [json.loads(line) for line in (corpus_dir / "corpus.jsonl").read_text(encoding="utf8").splitlines() if line]

    contexts: dict[str, _BrandContext] = {}
    for rec in records:
        if rec.get("brand") and rec["brand"] not in contexts:
            contexts[rec["brand"]] = _BrandContext(rec["brand_domain"], rec["brand"])

    results = sorted((replay_record(r, contexts) for r in records), key=lambda x: x["id"])
    body = "\n".join(json.dumps(r, sort_keys=True, ensure_ascii=False) for r in results) + "\n"
    fp = detector_fingerprint()
    manifest = {
        "replay_version": REPLAY_VERSION, "corpus_version": cmanifest["corpus_version"], "corpus_sha256": cmanifest["corpus_sha256"],
        "detector": fp, "results_sha256": hashlib.sha256(body.encode("utf8")).hexdigest(), "records": len(results), "brands": len(contexts),
        "summary": summarize(results),
        "not_measured": ["abuse_score", "suggested_status", "alerting",
                         "reason: needs live DNS, registration age and certificate facts that cannot be reconstructed for historical domains"],
    }
    if out_dir is not None:
        run = Path(out_dir) / f"{cmanifest['corpus_version']}__{fp['combined'][:12]}"
        run.mkdir(parents=True, exist_ok=True)
        (run / "results.jsonl").write_text(body, encoding="utf8", newline="\n")
        (run / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf8", newline="\n")
        manifest["run_dir"] = str(run)
    return manifest


# ── raw tabulation (counts and shares with n; confidence intervals arrive in step 1.4) ──

def _tab(rows: list[dict]) -> dict:
    n = len(rows)
    ident = [r["identity_score"] for r in rows if r["identity_score"] is not None]
    return {
        "n": n,
        "reached_permutation": sum(r["reach_permutation"] for r in rows),
        "reached_ct_name": sum(r["reach_ct_name"] for r in rows),
        "evaluated": sum(r["evaluated"] for r in rows),
        "identity_ge_40": sum(1 for s in ident if s >= 40),
        "identity_ge_55": sum(1 for s in ident if s >= 55),
        "identity_ge_60": sum(1 for s in ident if s >= 60),
    }


def summarize(results: list[dict]) -> dict:
    out: dict = {"by_label": {}, "positives_by_technique": {}, "positives_by_free_hosting": {}, "positives_by_split": {},
                 "negatives_by_subtype": {}, "unrelated_false_matches": {}}
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        groups[r["label"]].append(r)
    out["by_label"] = {k: _tab(v) for k, v in sorted(groups.items())}

    pos = groups.get("malicious_suspected", [])
    for key, field in (("positives_by_technique", "technique"), ("positives_by_free_hosting", "free_hosting"), ("positives_by_split", "split")):
        by: dict = defaultdict(list)
        for r in pos:
            by[str(r[field])].append(r)
        out[key] = {k: _tab(v) for k, v in sorted(by.items())}
    sub: dict = defaultdict(list)
    for r in groups.get("popular_lookalike", []):
        sub[r["technique"]].append(r)
    out["negatives_by_subtype"] = {k: _tab(v) for k, v in sorted(sub.items())}

    unrel = groups.get("popular_unrelated", [])
    out["unrelated_false_matches"] = {
        "n": len(unrel), "matched_any_brand": sum(1 for r in unrel if r["ct_matches_brands"]),
        "examples": sorted(r["domain"] for r in unrel if r["ct_matches_brands"])[:15],
    }
    # Why positives were not reached, by the detector's own view of the host (the key diagnostic)
    miss = Counter()
    for r in pos:
        if not r["evaluated"]:
            if psl.split(r["detector_apex"]).registrable is None:
                miss["apex_is_a_public_suffix"] += 1          # the brand was swallowed by the suffix
            elif r["free_hosting"]:
                miss["no_name_match_on_hosting_platform"] += 1
            else:
                miss["no_name_match"] += 1
    out["positives_not_reached"] = dict(miss)
    return out


def latest_corpus() -> Path:
    built = sorted((ROOT / "built").glob("c-*"), key=lambda p: p.stat().st_mtime)
    if not built:
        raise FileNotFoundError("No built corpus — run: python -m brand_eval.build_corpus")
    return built[-1]


def _print(m: dict) -> None:
    s = m["summary"]
    print(f"replay of corpus {m['corpus_version']}  detector {m['detector']['combined'][:12]}  records={m['records']}  brands={m['brands']}")
    print("\n(counts only; confidence intervals come in step 1.4)\n")
    cols = ("n", "reached_permutation", "reached_ct_name", "evaluated", "identity_ge_55")
    def show(title: str, table: dict) -> None:
        print(f"{title}\n  {'':26}" + "".join(f"{c:>20}" for c in cols))
        for k, v in table.items():
            print(f"  {k:26}" + "".join(f"{v[c]:>20}" for c in cols))
        print()
    show("by label", s["by_label"])
    show("positives by corpus technique (independent strata)", s["positives_by_technique"])
    show("positives by free_hosting", s["positives_by_free_hosting"])
    show("popular lookalikes by subtype (expected to resemble the brand)", s["negatives_by_subtype"])
    print("positives never evaluated, by cause:", s["positives_not_reached"])
    um = s["unrelated_false_matches"]
    print(f"unrelated popular domains tied to a brand by the detector: {um['matched_any_brand']}/{um['n']}  e.g. {um['examples'][:8]}")
    print("\nNOT measured offline:", m["not_measured"][0], "-", m["not_measured"][-1])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--corpus", type=Path, help="built corpus dir (default: newest)")
    ap.add_argument("--no-write", action="store_true")
    args = ap.parse_args(argv)
    m = replay(args.corpus or latest_corpus(), None if args.no_write else ROOT / "replay")
    _print(m)
    if "run_dir" in m:
        print("\nresults:", m["run_dir"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
