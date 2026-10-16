"""
Metrics and baseline report (plan step 1.4), computed from replay results.

Rules this module enforces by construction:
  * every rate is a {k, n, rate, lo, hi} record — a count, its denominator and a 95% Wilson
    interval; nothing is ever reported as a bare percentage;
  * strata smaller than LOW_POWER_N are flagged, not hidden or averaged away;
  * there is no single headline number — recall is broken out by technique, hosting and quality,
    with record-weighted ("micro") and brand-weighted ("macro") views side by side, because one
    brand (Facebook) is ~46% of the positives;
  * abuse-dependent quantities (alert recall, precision) are only ever given as bounds or as
    explicitly labelled illustrations, since abuse scoring is not measurable offline (see replay.py).

Metrics (all name-based, i.e. the identity stage):
  reach            evaluated / n — did the detector even consider the domain
  permutation_hit  generator hit-rate — would generate_candidates have produced it
  ct_name_hit      would the certificate-name match have accepted it
  identity_ge_t    identity_score >= t over ALL positives (unevaluated count as misses). Alerting
                   needs identity >= 55 AND abuse >= 60, so identity_ge_55 is an UPPER BOUND on alert recall.
  fp_unrelated     popular unrelated domains the detector ties to some brand
  lookalike_exposure  popular lookalikes surfaced / scoring high — expected exposure, not errors
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import defaultdict
from pathlib import Path

LOW_POWER_N = 30
IDENTITY_THRESHOLDS = (40, 55, 60)
MACRO_MIN_POSITIVES = 5
ROOT = Path(__file__).resolve().parent.parent / "data" / "brand_guard_corpus"


# ── statistics ───────────────────────────────────────────────────────────────

def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a binomial proportion; well-behaved at k=0, k=n and small n."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def rate(k: int, n: int) -> dict:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": (k / n) if n else None, "lo": lo, "hi": hi, "low_power": n < LOW_POWER_N}


def precision_at_prevalence(tpr: float, fpr: float, prevalence: float) -> float | None:
    """P(malicious | flagged) for a stated prevalence. Meaningless without a prevalence, which the
    corpus does not have (its class mix is chosen by construction) — hence it's a parameter."""
    tp, fp = tpr * prevalence, fpr * (1 - prevalence)
    return tp / (tp + fp) if (tp + fp) else None


# ── computation ──────────────────────────────────────────────────────────────

def _positive_block(rows: list[dict]) -> dict:
    n = len(rows)
    ident = lambda t: sum(1 for r in rows if r["identity_score"] is not None and r["identity_score"] >= t)
    return {
        "n": n, "low_power": n < LOW_POWER_N,
        "reach": rate(sum(r["evaluated"] for r in rows), n),
        "permutation_hit": rate(sum(r["reach_permutation"] for r in rows), n),
        "ct_name_hit": rate(sum(r["reach_ct_name"] for r in rows), n),
        **{f"identity_ge_{t}": rate(ident(t), n) for t in IDENTITY_THRESHOLDS},
    }


def _macro(rows: list[dict], seed: int, resamples: int = 2000) -> dict:
    """Brand-weighted mean of identity_ge_55 recall over brands with enough positives, with a
    bootstrap-over-brands 95% interval. Guards against a few large brands dominating the micro rate."""
    by_brand: dict[str, list[int]] = defaultdict(list)
    for r in rows:
        by_brand[r["brand"]].append(1 if (r["identity_score"] or 0) >= 55 else 0)
    per = {b: sum(v) / len(v) for b, v in by_brand.items() if len(v) >= MACRO_MIN_POSITIVES}
    if not per:
        return {"brands": 0, "mean": None, "lo": None, "hi": None, "min_positives_per_brand": MACRO_MIN_POSITIVES}
    vals = sorted(per.values())
    rng = random.Random(seed)
    means = sorted(sum(rng.choice(vals) for _ in vals) / len(vals) for _ in range(resamples))
    return {"brands": len(per), "mean": sum(vals) / len(vals), "lo": means[int(0.025 * resamples)], "hi": means[int(0.975 * resamples) - 1],
            "min_positives_per_brand": MACRO_MIN_POSITIVES, "brands_with_zero_recall": sum(1 for v in vals if v == 0)}


def compute_metrics(results: list[dict], seed: int = 1337) -> dict:
    pos = [r for r in results if r["label"] == "malicious_suspected"]
    look = [r for r in results if r["label"] == "popular_lookalike"]
    unrel = [r for r in results if r["label"] == "popular_unrelated"]

    def groups(rows, field):
        g: dict = defaultdict(list)
        for r in rows:
            g[str(r[field])].append(r)
        return {k: _positive_block(v) for k, v in sorted(g.items())}

    ident55 = lambda rows: sum(1 for r in rows if r["identity_score"] is not None and r["identity_score"] >= 55)
    unrel_hit = sum(1 for r in unrel if r["ct_matches_brands"])
    look_by_sub: dict = defaultdict(list)
    for r in look:
        look_by_sub[r["technique"]].append(r)

    tpr = (ident55(pos) / len(pos)) if pos else 0.0
    fpr_unrel = (sum(1 for r in unrel if (r["identity_score"] or 0) >= 55) / len(unrel)) if unrel else 0.0
    fpr_look = (ident55(look) / len(look)) if look else 0.0

    return {
        "definitions": __doc__,
        "positives": {
            "all": _positive_block(pos),
            "test_split": _positive_block([r for r in pos if r["split"] == "test"]),
            "by_technique": groups(pos, "technique"),
            "by_free_hosting": groups(pos, "free_hosting"),
            "by_quality": groups(pos, "quality"),
            "macro_identity_ge_55": _macro(pos, seed),
        },
        "negatives": {
            "unrelated": {"n": len(unrel), "false_match_any_brand": rate(unrel_hit, len(unrel)),
                          "identity_ge_55": rate(ident55(unrel), len(unrel))},
            "popular_lookalike": {
                "all": {"surfaced": rate(sum(r["evaluated"] for r in look), len(look)), "identity_ge_55": rate(ident55(look), len(look))},
                "by_subtype": {k: {"surfaced": rate(sum(r["evaluated"] for r in v), len(v)), "identity_ge_55": rate(ident55(v), len(v))}
                               for k, v in sorted(look_by_sub.items())},
            },
        },
        "illustrative_precision": {
            "caveat": "Identity stage ONLY (abuse stage not modelled) and assumption-driven: the corpus has no real prevalence, so these show "
                      "how little the name alone separates malicious from benign, not what customers will experience.",
            "tpr_identity_ge_55": tpr, "fpr_vs_unrelated": fpr_unrel, "fpr_vs_popular_lookalikes": fpr_look,
            "precision_vs_unrelated": {str(p): precision_at_prevalence(tpr, fpr_unrel, p) for p in (0.01, 0.001)},
            "precision_vs_popular_lookalikes": {str(p): precision_at_prevalence(tpr, fpr_look, p) for p in (0.01, 0.001)},
        },
        "latency_model": latency_bounds(),
    }


def latency_bounds() -> dict:
    """Architectural discovery-delay bounds from the real scheduler constants — a MODEL, not a
    measurement (the corpus has no registration timestamps). An event arriving at a uniformly random
    time waits U[0, interval] for the next due scan, plus up to one job wake-up period."""
    from app.config import settings
    from app.services.brand_guard_service import _CT_POLL_INTERVAL
    from app.services.plan_limits import PLAN_LIMITS

    wake = settings.brand_guard_check_interval
    out: dict = {"basis": "interval/2 median, 0.95*interval p95, plus up to one job wake-up; excludes scan duration (~tens of seconds)",
                 "job_wake_seconds": wake, "routes": {}}
    for plan, lim in PLAN_LIMITS.items():
        if not lim.get("brand_guard_brands", 0) and lim.get("brand_guard_brands") != None:
            continue
        routes = {"permutation_scan": lim["brand_guard_scan_days"] * 86400}
        if lim["brand_guard_ct"]:
            routes["certificate_poll"] = int(_CT_POLL_INTERVAL.total_seconds())
        out["routes"][plan] = {
            r: {"interval_hours": round(iv / 3600, 1), "median_hours": round((iv / 2 + wake / 2) / 3600, 1), "p95_hours": round((0.95 * iv + wake) / 3600, 1)}
            for r, iv in routes.items()
        }
    return out


# ── comparison (every later stage reports a delta against the baseline) ───────

def _flatten(block: dict, prefix: str = "") -> dict[str, dict]:
    out = {}
    for k, v in block.items():
        if isinstance(v, dict) and {"k", "n", "rate", "lo", "hi"} <= set(v):
            out[prefix + k] = v
        elif isinstance(v, dict) and k not in ("definitions", "latency_model", "illustrative_precision"):
            out.update(_flatten(v, f"{prefix}{k}."))
    return out


def compare(base: dict, new: dict) -> list[dict]:
    """Per-metric delta with a conservative verdict: 'improved'/'regressed' only when the 95% intervals
    do not overlap; otherwise 'within noise'. Metrics whose direction is 'lower is better' are marked."""
    a, b = _flatten(base), _flatten(new)
    lower_is_better = ("false_match", "popular_lookalike")
    rows = []
    for name in sorted(set(a) & set(b)):
        x, y = a[name], b[name]
        if x["rate"] is None or y["rate"] is None:
            continue
        delta = y["rate"] - x["rate"]
        if y["lo"] > x["hi"]:
            better = True
        elif y["hi"] < x["lo"]:
            better = False
        else:
            better = None
        if better is not None and any(t in name for t in lower_is_better):
            better = not better
        rows.append({"metric": name, "base": x["rate"], "new": y["rate"], "delta": delta, "base_n": x["n"], "new_n": y["n"],
                     "verdict": "within noise" if better is None else ("improved" if better else "regressed")})
    return rows


# ── report ───────────────────────────────────────────────────────────────────

def _fmt(r: dict) -> str:
    if r["rate"] is None:
        return "n/a (n=0)"
    flag = " ⚠ low power" if r["low_power"] else ""
    return f"{r['rate'] * 100:.1f}% [{r['lo'] * 100:.1f}–{r['hi'] * 100:.1f}] ({r['k']}/{r['n']}){flag}"


def render_report(m: dict, replay_manifest: dict) -> str:
    P, N = m["positives"], m["negatives"]
    L: list[str] = []
    w = L.append
    w(f"# Brand Guard baseline report\n")
    w(f"Corpus `{replay_manifest['corpus_version']}` · detector `{replay_manifest['detector']['combined'][:12]}` · replay v{replay_manifest['replay_version']}\n")
    w("**How to read this.** Every figure is `rate% [95% Wilson interval] (k/n)`. ⚠ marks strata with fewer than "
      f"{LOW_POWER_N} records — their rates are indicative only. There is deliberately no single headline number. "
      "Only the *name-based identity stage* is measured; abuse scoring, status and alerting cannot be measured offline.\n")

    w("## Positives (suspected-malicious, brand-labelled; NOT human-verified)\n")
    w("| Stratum | n | Reached (evaluated) | Permutation hit | CT-name hit | Identity ≥ 55 (alert upper bound) |\n|---|---|---|---|---|---|")
    def row(name, b):
        w(f"| {name} | {b['n']} | {_fmt(b['reach'])} | {_fmt(b['permutation_hit'])} | {_fmt(b['ct_name_hit'])} | {_fmt(b['identity_ge_55'])} |")
    row("**all**", P["all"]); row("test split only (held-out for later stages)", P["test_split"])
    for sect, key in (("technique", "by_technique"), ("free hosting", "by_free_hosting"), ("label quality", "by_quality")):
        for k, b in P[key].items():
            row(f"{sect}: {k}", b)
    mc = P["macro_identity_ge_55"]
    w(f"\n**Brand-weighted (macro) identity ≥ 55 recall:** "
      + (f"{mc['mean'] * 100:.1f}% [{mc['lo'] * 100:.1f}–{mc['hi'] * 100:.1f}] over {mc['brands']} brands with ≥ {mc['min_positives_per_brand']} positives "
         f"({mc['brands_with_zero_recall']} brands at 0%) — compare with the record-weighted figure above; one brand dominates the positives.\n" if mc["mean"] is not None else "n/a\n"))

    w("## Negatives\n")
    u = N["unrelated"]
    w(f"- **Unrelated popular domains tied to some brand by the detector:** {_fmt(u['false_match_any_brand'])}; scoring identity ≥ 55: {_fmt(u['identity_ge_55'])}.")
    w("- **Popular lookalikes** (legitimate popular domains that resemble a brand — *expected exposure, not errors*; whether they alert depends on abuse scoring):\n")
    w("| Subtype | Surfaced | Identity ≥ 55 |\n|---|---|---|")
    pl = N["popular_lookalike"]
    w(f"| **all** | {_fmt(pl['all']['surfaced'])} | {_fmt(pl['all']['identity_ge_55'])} |")
    for k, b in pl["by_subtype"].items():
        w(f"| {k} | {_fmt(b['surfaced'])} | {_fmt(b['identity_ge_55'])} |")

    ip = m["illustrative_precision"]
    w("\n## Illustrative precision (identity stage only — read the caveat)\n")
    w(f"> {ip['caveat']}\n")
    w(f"TPR (identity ≥ 55): {ip['tpr_identity_ge_55'] * 100:.1f}% · FPR vs unrelated: {ip['fpr_vs_unrelated'] * 100:.3f}% · FPR vs popular lookalikes: {ip['fpr_vs_popular_lookalikes'] * 100:.1f}%\n")
    w("| Assumed prevalence of malicious among surfaced names | precision vs unrelated | precision vs popular lookalikes |\n|---|---|---|")
    for p in ("0.01", "0.001"):
        a, b = ip["precision_vs_unrelated"][p], ip["precision_vs_popular_lookalikes"][p]
        w(f"| {float(p) * 100:g}% | {a * 100:.1f}% | {b * 100:.1f}% |" if a is not None and b is not None else f"| {float(p) * 100:g}% | n/a | n/a |")

    lat = m["latency_model"]
    w("\n## Discovery latency (a model from scheduler constants, not a measurement)\n")
    w(f"> {lat['basis']}\n")
    w("| Plan | Route | Interval (h) | Median delay (h) | p95 delay (h) |\n|---|---|---|---|---|")
    for plan, routes in lat["routes"].items():
        for rname, v in routes.items():
            w(f"| {plan} | {rname} | {v['interval_hours']} | {v['median_hours']} | {v['p95_hours']} |")
    w("\n## Not measured here\n")
    for line in replay_manifest["not_measured"]:
        w(f"- {line}")
    w("- Precision/recall of the full pipeline, status and alert behaviour, true detection latency, and any claim about homoglyph or typo-squat phishing (no such positives in the corpus).")
    return "\n".join(L) + "\n"


def latest_replay() -> Path:
    runs = sorted((ROOT / "replay").glob("c-*"), key=lambda p: p.stat().st_mtime)
    if not runs:
        raise FileNotFoundError("No replay run — run: python -m brand_eval.replay")
    return runs[-1]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    rep = sub.add_parser("report", help="compute metrics + report for a replay run (default command)")
    rep.add_argument("--run", type=Path)
    cmp_ = sub.add_parser("compare", help="delta between two replay runs' metrics.json")
    cmp_.add_argument("base", type=Path)
    cmp_.add_argument("new", type=Path)
    args = ap.parse_args(argv if argv else ["report"])

    if args.cmd == "compare":
        base = json.loads((args.base / "metrics.json").read_text(encoding="utf8"))
        new = json.loads((args.new / "metrics.json").read_text(encoding="utf8"))
        for r in compare(base, new):
            print(f"{r['verdict']:13} {r['metric']:60} {r['base'] * 100:6.1f}% → {r['new'] * 100:6.1f}%  (n {r['base_n']}→{r['new_n']})")
        return 0

    run = args.run or latest_replay()
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf8"))
    results = [json.loads(l) for l in (run / "results.jsonl").read_text(encoding="utf8").splitlines() if l]
    metrics = compute_metrics(results)
    (run / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf8", newline="\n")
    report = render_report(metrics, manifest)
    (run / "report.md").write_text(report, encoding="utf8", newline="\n")
    print(report)
    print(f"written: {run / 'metrics.json'}\n         {run / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
