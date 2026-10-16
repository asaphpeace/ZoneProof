"""The evidence-ratio combiner (app/services/brand_reasoning.py): pure, synthetic tables, no data files needed."""
import json
import math
from types import SimpleNamespace

import pytest

from app.services import brand_reasoning as br

LN10 = math.log(10)


def sig(name, weight, dim="abuse"):
    return SimpleNamespace(signal=name, dimension=dim, weight=weight, summary="", data={})


def measured(ln_lr, note="m"):
    return {"ln_lr": ln_lr, "basis": "measured", "note": note}


def table(**signals):
    return {"measured_on": "2026-10-02", "signals": signals}


EMPTY = table()


def test_expert_points_are_converted_at_the_labelled_rate_and_marked_expert():
    out = br.combine([sig("credential_lure_word", 10)], EMPTY)
    c = out["components"][0]
    assert c["basis"] == "expert" and c["log10"] == pytest.approx(1 / LN10)
    assert out["log10_measured"] == 0.0 and out["ratio_measured"] == 1.0
    assert "credential_lure_word" in out["notes"][0] and "hand-set" in c["note"]


def test_a_measured_ratio_is_used_as_given_and_counts_in_the_measured_figure():
    out = br.combine([sig("dns_live", 10)], table(dns_live=measured(math.log(4))))
    c = out["components"][0]
    assert c["basis"] == "measured" and c["log10"] == pytest.approx(math.log10(4))
    assert out["ratio"] == pytest.approx(4.0, abs=0.1) and out["ratio_measured"] == pytest.approx(4.0, abs=0.1) and out["notes"] == []


def test_a_signal_measured_as_no_evidence_contributes_nothing_whatever_its_old_weight():
    out = br.combine([sig("spf_published", 5)], table(spf_published=measured(0.0)))
    assert out["components"] == [] and out["log10_total"] == 0.0 and out["state"] == "insufficient"


def test_zero_weight_unknown_signals_and_identity_signals_are_ignored():
    out = br.combine([sig("registrar", 0), sig("keyword_combo", 40, "identity"), sig("whatever", 0)], EMPTY)
    assert out["components"] == [] and out["state"] == "insufficient"


@pytest.mark.parametrize("n,factor", [(1, 1.0), (2, 1.5), (3, 1.75), (4, 1.75), (6, 1.75)])
def test_signals_of_one_family_are_damped_not_added(n, factor):
    names = ["dns_live", "mx_live", "dormant_activated", "fast_progression", "dormant", "free_platform_cname"][:n]        # all "infrastructure"
    assert {br.FAMILY[x] for x in names} == {"infrastructure"}
    out = br.combine([sig(x, 10) for x in names], EMPTY)
    assert out["log10_total"] == pytest.approx(round(factor / LN10, 2), abs=0.011)


def test_independent_families_add_in_full():
    one = br.combine([sig("dns_live", 20)], EMPTY)["log10_total"]
    two = br.combine([sig("dns_live", 20), sig("on_phishing_feed", 30)], EMPTY)
    assert two["log10_total"] == pytest.approx(one + 30 / 10 / LN10, abs=0.011)
    assert set(two["families"]) == {"infrastructure", "blocklist"}


def test_the_strongest_signal_in_a_family_is_the_one_counted_fully():
    out = br.combine([sig("dns_live", 5), sig("mx_live", 25)], EMPTY)
    assert out["log10_total"] == pytest.approx((25 + 0.5 * 5) / 10 / LN10, abs=0.011)


@pytest.mark.parametrize("points,state", [(0, "insufficient"), (6, "insufficient"), (8, "weak"), (24, "moderate"), (47, "strong")])
def test_bands_follow_the_log10_ratio(points, state):
    assert br.combine([sig("on_phishing_feed", points)], EMPTY)["state"] == state


def test_an_explainer_makes_it_lean_harmless():
    out = br.combine([sig("popular_site", -25)], EMPTY)
    assert out["state"] == "harmless_leaning" and out["log10_total"] < br.EXPLAINED


def test_a_mild_explainer_alone_is_not_enough_to_lean_harmless():
    out = br.combine([sig("parked", -8)], EMPTY)                  # log10 about -0.35: above the -0.7 line
    assert out["state"] == "insufficient"


def test_strong_evidence_on_both_sides_is_conflicting_not_netted_out():
    out = br.combine([sig("on_phishing_feed", 35), sig("popular_site", -25)], EMPTY)
    assert out["state"] == "conflicting" and out["label"] == "Conflicting evidence"
    assert br.combine([sig("on_phishing_feed", 35), sig("parked", -8)], EMPTY)["state"] != "conflicting"      # a weak explainer is not a conflict


def test_a_note_appears_only_when_the_assumed_part_matters():
    big = br.combine([sig("dns_live", 10), sig("on_phishing_feed", 30)], table(dns_live=measured(math.log(3))))
    assert big["notes"] and "on_phishing_feed" in big["notes"][0] and "dns_live" not in big["notes"][0]
    small = br.combine([sig("dns_live", 10), sig("credential_lure_word", 1)], table(dns_live=measured(math.log(3))))
    assert small["notes"] == []


def test_dict_and_object_signals_give_the_same_answer():
    as_obj = br.combine([sig("dns_live", 10), sig("popular_site", -25)], EMPTY)
    as_dict = br.combine([{"signal": "dns_live", "dimension": "abuse", "weight": 10}, {"signal": "popular_site", "dimension": "abuse", "weight": -25}], EMPTY)
    assert as_obj == as_dict


def test_unknown_signals_fall_into_an_other_family():
    out = br.combine([sig("brand_new_signal", 10)], EMPTY)
    assert out["components"][0]["family"] == "other"


def test_ratio_is_the_antilog_of_the_total():
    out = br.combine([sig("on_phishing_feed", 23.026)], EMPTY)               # ln 10 * 10 points
    assert out["ratio"] == pytest.approx(10 ** out["log10_total"], rel=0.02) and out["ratio"] == pytest.approx(10.0, rel=0.05)


# ── the table file ──

def test_a_missing_or_broken_table_means_nothing_is_measured(tmp_path):
    assert br.load_table(tmp_path / "nope.json") == {"measured_on": None, "signals": {}}
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    assert br.load_table(bad)["signals"] == {}


def test_a_table_file_is_read(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps(table(dns_live=measured(0.5))))
    assert br.load_table(p)["signals"]["dns_live"]["ln_lr"] == 0.5


def test_the_shipped_table_is_well_formed():
    br.reset_cache()
    t = br.load_table()
    for name, entry in t["signals"].items():
        assert entry["basis"] in ("measured", "expert") and isinstance(entry["ln_lr"], (int, float)), name
        assert name in br.FAMILY or name.startswith("tld:"), name
