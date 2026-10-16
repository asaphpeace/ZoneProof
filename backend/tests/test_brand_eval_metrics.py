"""
Step 1.4 — metrics. The statistics are checked against known values, and the
comparison tool is checked for the failure that matters most: calling noise an
improvement.
"""
import json
import re
from pathlib import Path

import pytest

from brand_eval import metrics as M


# ── statistics ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("k,n,lo,hi", [
    (0, 10, 0.0, 0.2775),
    (5, 10, 0.2366, 0.7634),
    (10, 10, 0.7225, 1.0),
    (1, 100, 0.0018, 0.0545),
])
def test_wilson_matches_known_values(k, n, lo, hi):
    got_lo, got_hi = M.wilson(k, n)
    assert got_lo == pytest.approx(lo, abs=1e-3) and got_hi == pytest.approx(hi, abs=1e-3)


def test_wilson_with_no_data_is_the_whole_range():
    assert M.wilson(0, 0) == (0.0, 1.0)


def test_rate_carries_count_denominator_interval_and_power_flag():
    r = M.rate(3, 10)
    assert (r["k"], r["n"], r["rate"]) == (3, 10, 0.3) and r["lo"] < 0.3 < r["hi"] and r["low_power"] is True
    assert M.rate(30, 100)["low_power"] is False
    empty = M.rate(0, 0)
    assert empty["rate"] is None and empty["low_power"] is True


def test_precision_at_prevalence_is_bayes():
    assert M.precision_at_prevalence(0.5, 0.01, 0.01) == pytest.approx(0.005 / (0.005 + 0.0099))
    assert M.precision_at_prevalence(0.0, 0.0, 0.01) is None


# ── computation ──────────────────────────────────────────────────────────────

def _pos(i, brand, identity, *, technique="brand_in_domain", free=False, quality="suspected_high", split="train", perm=False, ct=None):
    ct = (identity is not None) if ct is None else ct
    return {"id": f"p{i}", "label": "malicious_suspected", "technique": technique, "free_hosting": free, "quality": quality, "split": split,
            "brand": brand, "evaluated": identity is not None, "reach_permutation": perm, "reach_ct_name": ct, "identity_score": identity,
            "ct_matches_brands": []}


def _neg(i, label, technique, identity, matches=()):
    return {"id": f"n{i}", "label": label, "technique": technique, "free_hosting": False, "quality": "derived_popularity", "split": "train",
            "brand": None if label == "popular_unrelated" else "a", "evaluated": identity is not None or bool(matches), "reach_permutation": False,
            "reach_ct_name": identity is not None, "identity_score": identity, "ct_matches_brands": list(matches)}


@pytest.fixture
def results():
    rows = [_pos(i, "a", 60 if i < 30 else None, split="test" if i % 4 == 0 else "train") for i in range(40)]
    rows += [_pos(100 + i, "b", None, free=True, technique="brand_in_domain", quality="suspected_medium") for i in range(6)]
    rows += [_pos(200 + i, "c", 70, technique="tld_swap") for i in range(3)]
    rows += [_neg(i, "popular_unrelated", "unrelated", None, matches=["a"] if i < 2 else ()) for i in range(100)]
    rows += [_neg(300 + i, "popular_lookalike", "contains_brand", 60 if i < 3 else (40 if i < 4 else None)) for i in range(10)]
    return rows


def test_positive_counts_and_strata(results):
    m = M.compute_metrics(results)["positives"]
    assert m["all"]["n"] == 49
    assert m["all"]["reach"]["k"] == 33 and m["all"]["identity_ge_55"]["k"] == 33 and m["all"]["identity_ge_40"]["k"] == 33
    assert m["by_free_hosting"]["True"]["reach"] == M.rate(0, 6)
    assert m["by_technique"]["tld_swap"]["low_power"] is True and m["by_technique"]["brand_in_domain"]["low_power"] is False
    assert m["by_quality"]["suspected_medium"]["n"] == 6
    assert m["test_split"]["n"] == 10 and m["test_split"]["reach"]["k"] == 8
    for block in (m["all"], m["test_split"]):
        for key in ("reach", "identity_ge_55"):
            assert block[key]["lo"] <= block[key]["rate"] <= block[key]["hi"]


def test_unreached_positives_count_as_misses_not_as_excluded(results):
    m = M.compute_metrics(results)["positives"]["all"]
    assert m["identity_ge_55"]["n"] == 49, "denominator is ALL positives, so unreached ones lower the recall"


def test_macro_view_weights_brands_equally_and_is_seeded(results):
    macro = M.compute_metrics(results, seed=5)["positives"]["macro_identity_ge_55"]
    assert macro["brands"] == 2, "brand c has < 5 positives and is excluded"
    assert macro["mean"] == pytest.approx((30 / 40 + 0) / 2) and macro["brands_with_zero_recall"] == 1
    assert macro["lo"] <= macro["mean"] <= macro["hi"]
    assert M.compute_metrics(results, seed=5)["positives"]["macro_identity_ge_55"] == macro
    micro = M.compute_metrics(results)["positives"]["all"]["identity_ge_55"]["rate"]
    assert macro["mean"] != pytest.approx(micro), "micro and macro must be able to differ"


def test_negative_metrics(results):
    n = M.compute_metrics(results)["negatives"]
    assert n["unrelated"]["false_match_any_brand"] == M.rate(2, 100) | {"low_power": False}
    look = n["popular_lookalike"]["all"]
    assert look["surfaced"]["k"] == 4 and look["identity_ge_55"]["k"] == 3
    assert n["popular_lookalike"]["by_subtype"]["contains_brand"]["surfaced"]["n"] == 10


def test_illustrative_precision_is_labelled_and_uses_the_stated_prevalence(results):
    ip = M.compute_metrics(results)["illustrative_precision"]
    assert "ONLY" in ip["caveat"] and "assumption" in ip["caveat"]
    expect = M.precision_at_prevalence(ip["tpr_identity_ge_55"], ip["fpr_vs_popular_lookalikes"], 0.01)
    assert ip["precision_vs_popular_lookalikes"]["0.01"] == pytest.approx(expect)


def test_latency_model_uses_the_real_scheduler_constants():
    lat = M.latency_bounds()["routes"]
    assert "free" not in lat and "certificate_poll" not in lat["starter"], "starter has no CT feed"
    assert lat["pro"]["certificate_poll"]["interval_hours"] == 6.0 and lat["pro"]["permutation_scan"]["interval_hours"] == 168.0
    assert lat["starter"]["permutation_scan"]["interval_hours"] == 720.0
    for plan in lat.values():
        for r in plan.values():
            assert r["p95_hours"] > r["median_hours"] > 0


# ── comparison ───────────────────────────────────────────────────────────────

def _metric_set(identity_k, identity_n, fp_k=1, fp_n=3000):
    return {"positives": {"all": {"identity_ge_55": M.rate(identity_k, identity_n)}},
            "negatives": {"unrelated": {"false_match_any_brand": M.rate(fp_k, fp_n)}}}


def test_compare_calls_clear_improvements_and_regressions_and_ignores_noise():
    base = _metric_set(55, 488)
    verdicts = {r["metric"]: r["verdict"] for r in M.compare(base, _metric_set(300, 488))}
    assert verdicts["positives.all.identity_ge_55"] == "improved"
    verdicts = {r["metric"]: r["verdict"] for r in M.compare(_metric_set(300, 488), base)}
    assert verdicts["positives.all.identity_ge_55"] == "regressed"

    noisy = {r["metric"]: r["verdict"] for r in M.compare(_metric_set(5, 10), _metric_set(6, 10))}
    assert noisy["positives.all.identity_ge_55"] == "within noise", "a one-record change on n=10 is not evidence"


def test_compare_treats_false_matches_as_lower_is_better():
    worse = {r["metric"]: r["verdict"] for r in M.compare(_metric_set(55, 488, fp_k=0, fp_n=3000), _metric_set(55, 488, fp_k=300, fp_n=3000))}
    assert worse["negatives.unrelated.false_match_any_brand"] == "regressed"
    better = {r["metric"]: r["verdict"] for r in M.compare(_metric_set(55, 488, fp_k=300, fp_n=3000), _metric_set(55, 488, fp_k=0, fp_n=3000))}
    assert better["negatives.unrelated.false_match_any_brand"] == "improved"


# ── report + CLI ─────────────────────────────────────────────────────────────

MANIFEST = {"corpus_version": "c-test", "replay_version": "1", "detector": {"combined": "a" * 64},
            "not_measured": ["abuse_score", "reason: needs live facts"]}


def test_report_has_no_bare_percentages_and_states_its_limits(results):
    text = M.render_report(M.compute_metrics(results), MANIFEST)
    assert "no single headline number" in text and "⚠ low power" in text and "Not measured here" in text
    assert "illustrative" in text.lower() and "model from scheduler constants, not a measurement" in text
    table_rows = [l for l in text.splitlines() if l.startswith("| ") and "%" in l and "Plan" not in l and "Subtype" not in l and "Assumed" not in l]
    assert table_rows
    for line in table_rows:
        for cell in line.split("|")[2:-1]:
            if "%" in cell and "[" in cell:
                assert re.search(r"\(\d+/\d+\)", cell), f"rate without its counts: {cell!r}"


def test_cli_writes_metrics_and_report_and_compares_runs(tmp_path, results, capsys):
    run = tmp_path / "c-test__x"
    run.mkdir()
    (run / "results.jsonl").write_text("\n".join(json.dumps(r) for r in results) + "\n", encoding="utf8")
    (run / "manifest.json").write_text(json.dumps(MANIFEST), encoding="utf8")
    assert M.main(["report", "--run", str(run)]) == 0
    assert (run / "metrics.json").exists() and (run / "report.md").read_text(encoding="utf8").startswith("# Brand Guard baseline report")

    better = tmp_path / "c-test__y"
    better.mkdir()
    improved = [dict(r, identity_score=60, evaluated=True) if r["label"] == "malicious_suspected" else r for r in results]
    (better / "results.jsonl").write_text("\n".join(json.dumps(r) for r in improved) + "\n", encoding="utf8")
    (better / "manifest.json").write_text(json.dumps(MANIFEST), encoding="utf8")
    M.main(["report", "--run", str(better)])
    capsys.readouterr()
    assert M.main(["compare", str(run), str(better)]) == 0
    out = capsys.readouterr().out
    assert re.search(r"improved\s+positives\.all\.identity_ge_55", out)
