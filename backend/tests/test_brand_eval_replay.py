"""
Step 1.3 — replay harness. A tiny synthetic corpus pins down exactly what the
detector does per record, including KNOWN DEFECTS the baseline run exposed
(multi-label public suffixes, free-hosting apex collapse, short brand names).
The defect tests assert today's behaviour on purpose: when plan step 2.0b fixes
them these tests will fail, which is the signal to update them and re-baseline.
"""
import hashlib
import json
import random
from pathlib import Path

import pytest

from brand_eval import replay

BRAND = "acmefinancial.com"


def _rec(i, label, domain, technique, *, brand="acmefinancial", brand_domain=BRAND, free_hosting=False, split="test", quality="suspected_high"):
    return {"id": f"r{i:03}", "label": label, "domain": domain, "registrable": domain, "technique": technique, "quality": quality,
            "free_hosting": free_hosting, "split": split, "brand": brand, "brand_domain": brand_domain}


def _corpus(tmp_path: Path, records: list[dict], shuffle_seed: int | None = None) -> Path:
    d = tmp_path / "c-test"
    d.mkdir()
    lines = [json.dumps(r, sort_keys=True) for r in records]
    if shuffle_seed is not None:
        random.Random(shuffle_seed).shuffle(lines)
    body = "\n".join(lines) + "\n"
    (d / "corpus.jsonl").write_text(body, encoding="utf8")
    (d / "manifest.json").write_text(json.dumps({"corpus_version": "c-test", "corpus_sha256": hashlib.sha256(body.encode()).hexdigest()}))
    return d


def _records():
    return [
        _rec(1, "malicious_suspected", "secure-acmefinancial-login.com", "brand_in_domain"),
        _rec(2, "malicious_suspected", "acmefinancial.xyz", "tld_swap"),
        _rec(3, "malicious_suspected", "acmefinancal.com", "near_miss"),
        _rec(4, "malicious_suspected", "acmefinancial-login.pages.dev", "brand_in_domain", free_hosting=True),
        _rec(5, "malicious_suspected", "acmefinancial.com.br", "tld_swap"),
        _rec(6, "malicious_suspected", "acmefinancial.verify.evil-host.net", "brand_in_subdomain"),
        _rec(7, "malicious_suspected", "acmefinancial.com", "brand_domain_clone"),
        _rec(8, "malicious_suspected", "dpdn62.click", "brand_in_domain", brand="dpd", brand_domain="dpd.com"),
        _rec(9, "popular_lookalike", "acmefinancial.net", "same_name_other_suffix", quality="derived_popularity"),
        _rec(10, "popular_unrelated", "plain-site.com", "unrelated", brand=None, brand_domain=None, quality="derived_popularity"),
        _rec(11, "popular_unrelated", "acmefinancia1site.com", "unrelated", brand=None, brand_domain=None, quality="derived_popularity"),
    ]


def _by_id(manifest: dict) -> dict:
    lines = (Path(manifest["run_dir"]) / "results.jsonl").read_text(encoding="utf8").splitlines()
    return {r["id"]: r for r in map(json.loads, lines)}


@pytest.fixture
def rows(tmp_path):
    """(results by id, manifest) for the synthetic corpus."""
    m = replay.replay(_corpus(tmp_path, _records()), tmp_path / "out")
    return _by_id(m), m


# ── what the detector reaches ────────────────────────────────────────────────

def test_combosquat_is_reached_by_ct_name_and_scores_high_on_identity(rows):
    r = rows[0]["r001"]
    assert r["evaluated"] and r["reach_ct_name"] and not r["reach_permutation"]
    assert r["ct_token"] == "acmefinancial" and r["identity_score"] >= 55


def test_tld_swap_and_typo_are_reached_by_the_permutation_set(rows):
    swap, typo = rows[0]["r002"], rows[0]["r003"]
    assert swap["reach_permutation"] and swap["permutation_class"] == "tld_swap" and swap["identity_score"] == 40
    assert typo["reach_permutation"] and typo["permutation_class"] == "typo"
    assert typo["reach_ct_name"], "since step 2.0b the certificate path also catches a one-edit typo"
    assert typo["identity_score"] and typo["identity_score"] > 0


def test_the_brands_own_domain_is_never_a_candidate(rows):
    r = rows[0]["r007"]
    assert r["owned_by_brand"] is True and r["evaluated"] is False and r["identity_score"] is None


def test_abuse_is_explicitly_not_measured(rows):
    results, manifest = rows
    assert all(r["abuse_measurable"] is False for r in results.values())
    assert "abuse_score" in manifest["not_measured"]
    leaked = [k for k in next(iter(results.values())) if "abuse" in k and k != "abuse_measurable"]
    assert leaked == [], "no abuse score may leak into results"


# ── FIXED in plan step 2.0b (these were the documented defects) ──────────────

def test_fixed_free_hosting_subdomain_is_a_candidate_not_the_platform_apex(rows):
    r = rows[0]["r004"]
    assert r["detector_apex"] == "acmefinancial-login.pages.dev" and r["evaluated"] and r["reach_ct_name"]


def test_fixed_multi_label_public_suffixes_are_understood(rows):
    r = rows[0]["r005"]                       # acmefinancial.com.br — a plain brand-in-name lookalike
    assert r["detector_apex"] == "acmefinancial.com.br" and r["evaluated"] and r["identity_score"] >= 40


def test_fixed_brand_only_in_a_subdomain_is_now_reached_as_a_weak_lead(rows):
    """Plan step 2.2 (A2-2). The registrable name shows no brand, but a certificate for a host that carries it in the
    subdomain now surfaces — as a lead (identity below the alert line), not an accusation."""
    r = rows[0]["r006"]
    assert r["detector_apex"] == "evil-host.net" and r["evaluated"] is True
    assert r["reach_subdomain"] is True and r["subdomain_kind"] == "brand_in_subdomain"
    assert r["reach_ct_name"] is False and r["threat_class"] == "subdomain_abuse"
    assert 0 < r["identity_score"] < 55


# ── STILL OPEN (documented limits; plan step 2.2 and later) ──────────────────


def test_known_limit_a_short_brand_fused_into_another_word_is_not_matched(rows):
    r = rows[0]["r008"]                       # dpdn62.click: 'dpd' is not a whole word here (whole-word 'gls-group' does match now)
    assert r["evaluated"] is False and r["ct_token"] is None


# ── negatives ────────────────────────────────────────────────────────────────

def test_popular_lookalike_is_reached_and_identity_is_high_without_any_abuse_view(rows):
    r = rows[0]["r009"]
    assert r["evaluated"] and r["reach_permutation"] and r["identity_score"] >= 40


def test_unrelated_domains_report_which_brands_they_wrongly_match(rows):
    plain, skel = rows[0]["r010"], rows[0]["r011"]
    assert plain["evaluated"] is False and plain["ct_matches_brands"] == []
    assert skel["evaluated"] is True and skel["ct_matches_brands"] == ["acmefinancial"], "skeleton matching ties a look-alike spelling to the brand"


# ── provenance, determinism, summary ─────────────────────────────────────────

def test_run_is_tied_to_corpus_and_detector_and_written_sorted(rows, tmp_path):
    results, m = rows
    assert m["corpus_version"] == "c-test" and len(m["detector"]["combined"]) == 64
    assert set(m["detector"]["files"]) == {"brand_discovery_service.py", "brand_scoring_service.py", "brand_guard_service.py",
                                           "public_suffix.py", "public_suffix_list.dat", "brand_background.py", "popular_labels.txt.gz", "brand_baseline.py", "brand_mail_intent.py", "brand_infra_signals.py", "brand_corroboration.py", "brand_popularity.py", "popular_domains.txt.gz"}
    assert Path(m["run_dir"]).name == f"c-test__{m['detector']['combined'][:12]}"
    ids = [json.loads(l)["id"] for l in (Path(m["run_dir"]) / "results.jsonl").read_text(encoding="utf8").splitlines()]
    assert ids == sorted(ids)
    assert hashlib.sha256((Path(m["run_dir"]) / "results.jsonl").read_bytes()).hexdigest() == m["results_sha256"]


def test_results_do_not_depend_on_input_order(tmp_path):
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
    a = replay.replay(_corpus(tmp_path / "a", _records()))
    b = replay.replay(_corpus(tmp_path / "b", _records(), shuffle_seed=3))
    assert a["results_sha256"] == b["results_sha256"]


def test_detector_fingerprint_is_stable_and_line_ending_insensitive():
    assert replay.detector_fingerprint() == replay.detector_fingerprint()
    assert replay._sha_text("a\r\nb\r\n") == replay._sha_text("a\nb\n")


def test_summary_counts_and_not_reached_causes(rows):
    s = rows[1]["summary"]
    pos = s["by_label"]["malicious_suspected"]
    assert pos["n"] == 8 and pos["evaluated"] == 6          # combosquat, tld_swap, typo, free-hosting, .com.br, subdomain-only
    assert s["positives_by_free_hosting"]["True"]["evaluated"] == 1
    assert s["positives_not_reached"] == {"no_name_match": 2}   # the brand's own domain, short fused name
    assert s["unrelated_false_matches"] == {"n": 2, "matched_any_brand": 1, "examples": ["acmefinancia1site.com"]}
    assert s["negatives_by_subtype"]["same_name_other_suffix"]["evaluated"] == 1
