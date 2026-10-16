"""The abuse-signal measurement (brand_eval/abuse_lr.py): the statistics, the classification, the exported table, and points_for."""
import math

import pytest

from app.services import brand_reasoning as br
from brand_eval import abuse_lr as lr


def row(k1, n1, k0, n0):
    return {"key": "x", "bad": [k1, n1], "background": [k0, n0], **lr.likelihood_ratio(k1, n1, k0, n0)}


# ── statistics ──

def test_wilson_matches_known_values_and_handles_empty():
    lo, hi = lr.wilson(50, 100)
    assert (round(lo, 3), round(hi, 3)) == (0.404, 0.596)
    assert lr.wilson(0, 0) == (0.0, 1.0)
    lo, hi = lr.wilson(0, 30)
    assert lo == 0.0 and 0.1 < hi < 0.15


def test_likelihood_ratio_is_the_ratio_of_rates_with_a_log_interval_around_it():
    r = lr.likelihood_ratio(40, 100, 10, 100)
    assert 3.5 < r["lr_pos"] < 4.1 and r["lr_pos_lo"] < r["lr_pos"] < r["lr_pos_hi"]
    assert r["lr_neg"] < 1 < r["lr_pos"]
    z = lr.likelihood_ratio(0, 50, 0, 3000)                        # zero cells must not explode or divide by zero
    assert z["lr_pos_lo"] > 0 and math.isfinite(z["lr_pos_hi"])


def test_a_bigger_sample_gives_a_tighter_interval():
    small, big = lr.likelihood_ratio(4, 10, 1, 10), lr.likelihood_ratio(400, 1000, 100, 1000)
    assert (big["lr_pos_hi"] / big["lr_pos_lo"]) < (small["lr_pos_hi"] / small["lr_pos_lo"])


def test_separated_means_non_overlapping_wilson_intervals():
    assert lr.separated(60, 100, 10, 100) and lr.separated(10, 100, 60, 100)
    assert not lr.separated(12, 100, 10, 100)


# ── classification ──

def test_a_clear_effect_uses_the_conservative_end_of_the_interval():
    status, ln, note = lr.classify(row(60, 200, 5, 3000))
    r = row(60, 200, 5, 3000)
    assert status == "measured" and ln == pytest.approx(math.log(r["lr_pos_lo"])) and ln > 0 and "lower bound" in note


def test_a_small_but_real_effect_just_above_one_is_measured_at_its_lower_bound():
    r = row(1000, 3000, 880, 3000)
    assert 1.0 < r["lr_pos_lo"] < 1.1
    status, ln, _ = lr.classify(r)
    assert status == "measured" and 0 < ln < 0.1


def test_a_clear_effect_pointing_the_other_way_uses_the_upper_bound():
    r = row(5, 500, 1000, 3000)
    status, ln, note = lr.classify(r)
    assert status == "measured" and ln == pytest.approx(math.log(r["lr_pos_hi"])) and ln < 0 and "other way" in note


def test_a_narrow_interval_around_one_is_a_measured_null():
    status, ln, note = lr.classify(row(1000, 3000, 1010, 3000))
    assert status == "null" and ln == 0.0 and "does not separate" in note


def test_a_wide_interval_that_includes_one_is_unmeasured_not_null():
    status, ln, note = lr.classify(row(3, 34, 250, 2909))
    assert status == "unmeasured" and ln == 0.0 and "not enough data" in note


# ── the exported table ──

def feat(domain, **kw):
    base = {"domain": domain, "tld": "xyz", "registered": True, "has_a": False, "has_mx": False, "spf": False, "dkim": False, "dmarc": False, "esp": False,
            "defensive_mail": False, "shared_ns": False, "parked": False, "free_cname": False, "lure": False, "long_label": False}
    base.update(kw)
    return base


def collection():
    young = [feat(f"y{i}.xyz", age_days=5, esp=(i < 3), lure=(i < 4), has_a=(i % 2 == 0)) for i in range(40)]
    old = [feat(f"o{i}.com", age_days=900, esp=(i < 30), tld="com") for i in range(300)]
    bg = [feat(f"b{i}.xyz", esp=(i < 2), lure=(i < 4), has_a=(i % 2 == 0)) for i in range(2000)]
    return {"collected_at": "2026-10-02T12:00:00+00:00", "bad": young + old, "background": bg}


def test_export_uses_all_ages_for_age_independent_features_and_young_for_the_rest():
    t = lr.export_table(collection())
    assert t["bad_young"] == 40 and t["bad_all"] == 340 and t["background"] == 2000
    esp = t["signals"]["esp_sender"]
    assert esp["group"] == "all ages" and esp["ln_lr"] > 0                                  # 33/340 listed vs 2/2000: a clear effect
    assert "dns_live" in t["signals"] and t["signals"]["dns_live"]["null"] is True          # identical rate in both groups: a measured null
    assert t["signals"]["dns_live"]["group"].startswith("registered within")
    assert all(e["basis"] == "measured" for e in t["signals"].values())


def test_export_lists_what_it_could_not_measure_instead_of_guessing():
    t = lr.export_table(collection())
    assert "spf_published" in t["unmeasured"] or "spf_published" in t["signals"]
    for name in t["unmeasured"]:
        assert name not in t["signals"]
    assert t["how_to_read"] and t["measured_on"] == "2026-10-02"


# ── points_for ──

def test_points_for_returns_the_measured_value_or_the_default():
    table = {"signals": {"a": {"basis": "measured", "ln_lr": 1.302}, "b": {"basis": "measured", "ln_lr": 0.0}, "c": {"basis": "expert", "ln_lr": 0.5}}}
    assert br.points_for("a", 10.0, table) == 13.0
    assert br.points_for("b", 15.0, table) == 0.0                   # measured as no effect: the old weight is dropped
    assert br.points_for("c", 7.0, table) == 7.0                    # an expert entry is not a measurement
    assert br.points_for("zzz", -8.0, table) == -8.0
    assert br.points_for("a", 10.0, {"signals": {}}) == 10.0


def test_the_shipped_table_drops_the_liveness_weights_and_keeps_lure_and_esp_positive():
    br.reset_cache()
    assert br.points_for("dns_live", 10.0) == 0.0
    assert abs(br.points_for("mx_live", 15.0)) < 0.5
    assert br.points_for("esp_sender", 10.0) > 10.0 and br.points_for("credential_lure_word", 10.0) > 10.0
    assert br.points_for("parked", -8.0) < 0
    assert br.points_for("spf_published", 5.0) == 5.0               # not enough data: stays an assumption
