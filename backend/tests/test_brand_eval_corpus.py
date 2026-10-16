"""
Step 1.2 — corpus builder. All inputs are tiny synthetic fixtures written to
tmp_path in the same shape as the real phishunt.io / Majestic snapshots; nothing
touches the network or the real (gitignored) corpus.
"""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from brand_eval import corpus
from brand_eval.domains import classify_technique, norm, split_host

T0 = datetime(2026, 4, 1, tzinfo=timezone.utc)


# ── domains.py (literal parsing and strata) ──────────────────────────────────

@pytest.mark.parametrize("host,registrable,label,suffix,free,ip,idn,sub", [
    ("www.example.com", "example.com", "example", "com", False, False, False, "www"),
    ("a.b.bank.co.za", "bank.co.za", "bank", "co.za", False, False, False, "a.b"),
    ("shop.thing.co.uk", "thing.co.uk", "thing", "co.uk", False, False, False, "shop"),
    ("facebook-login.pages.dev", "facebook-login.pages.dev", "facebook-login", "pages.dev", True, False, False, ""),
    ("login.brand.github.io", "brand.github.io", "brand", "github.io", True, False, False, "login"),
    ("203.0.113.7", "203.0.113.7", "203.0.113.7", "", False, True, False, ""),
    ("xn--pypal-4ve.com", "xn--pypal-4ve.com", "xn--pypal-4ve", "com", False, False, True, ""),
    ("EXAMPLE.com.", "example.com", "example", "com", False, False, False, ""),
])
def test_split_host(host, registrable, label, suffix, free, ip, idn, sub):
    p = split_host(host)
    assert (p.registrable, p.label, p.suffix, p.free_hosting, p.is_ip, p.is_idn, p.subdomain) == (registrable, label, suffix, free, ip, idn, sub)


@pytest.mark.parametrize("host,path,expected", [
    ("paypal.com", "", "brand_domain_clone"),
    ("www.paypal.com", "", "brand_domain_clone"),
    ("paypal.biz", "", "tld_swap"),
    ("secure-paypal-login.com", "", "brand_in_domain"),
    ("paypal-x.pages.dev", "", "brand_in_domain"),
    ("xn--pypal-4ve.com", "", "idn"),
    ("paypa1.com", "", "near_miss"),
    ("paypal.verify.evil-host.net", "", "brand_in_subdomain"),
    ("kit.evil-host.ru", "/paypal/login.php", "brand_in_path"),
    ("totally-unrelated.net", "/index.html", "no_visible_brand"),
])
def test_classify_technique_uses_literal_rules(host, path, expected):
    assert classify_technique(split_host(host), "paypal", "paypal.com", path) == expected


def test_norm_strips_punctuation_and_case():
    assert norm("Pay-Pal.Com_1") == "paypalcom1"


# ── fixtures ─────────────────────────────────────────────────────────────────

def _majestic_rows():
    rows = [
        (1, "google.com"), (2, "facebook.com"), (3, "paypal.com"), (5, "apps.facebook.com"),
        (10, "facebook.net"), (11, "facebookmarketing.com"), (12, "facebok.com"),
        (13, "paypai.com"), (20, "apple.com"), (21, "apple.co.uk"),
        (150_000, "obscurebrand.com"),                      # resolves only beyond the low-confidence rank
    ]
    rows += [(100 + i, f"site{i}.com") for i in range(80)]  # unrelated popular sites
    return sorted(rows)


def _phish_rows():
    rows = []

    def add(company, domain, verdict="high", days=0, url=None, **extra):
        rows.append({"company": company, "domain": domain, "verdict": verdict, "url": url or f"https://{domain}/x",
                     "first_seen": (T0 + timedelta(days=days)).isoformat(), "score": 60, "asn": "13335", "org": "Cloudflare",
                     "country": "US", "malicious_openphish": "True", "malicious_google": "True", **extra})

    add("facebook", "facebook-login.pages.dev", days=2)
    add("facebook", "facebook-login.pages.dev", days=40)            # duplicate of the above, later
    add("facebook", "kit.example-host.ru", days=3, url="http://kit.example-host.ru/facebook/login")
    add("paypal", "paypa1.com", verdict="critical", days=4)
    add("paypal", "paypal.biz", days=5)
    add("paypal", "xn--pypal-4ve.com", days=6)
    add("paypal", "paypal.verify.evil-host.net", verdict="medium", days=7)
    add("facebook", "kit.shared-campaign.net", days=8)              # same campaign domain, two brands,
    add("paypal", "kit.shared-campaign.net", days=60)               # ...second sighting much later
    add("paypal", "low-verdict-paypal.com", verdict="low", days=9)
    add("paypal", "noise-paypal.com", verdict="noise", days=9)
    add("", "unlabelled.com", days=9)
    add("ghostbrand", "ghostbrand-login.com", days=9)               # slug absent from the popularity list
    add("obscurebrand", "obscurebrand-login.com", days=9)           # only resolves beyond the low-confidence rank
    for i in range(40):                                             # bulk, to make the splits meaningful
        add("facebook", f"facebook-promo{i}.com", days=10 + i)
    return rows


def _write_snapshot(root: Path, *, name="2026-09-30", retrieved="2026-09-30T10:00:00+00:00", phish=None, majestic=None) -> Path:
    d = root / name
    d.mkdir(parents=True)
    p = json.dumps(phish if phish is not None else _phish_rows()).encode()
    m = ("GlobalRank,TldRank,Domain,TLD\n" + "".join(f"{r},{r},{dom},{dom.split('.')[-1]}\n" for r, dom in (majestic or _majestic_rows()))).encode()
    (d / "phishunt_feed.json").write_bytes(p)
    (d / "majestic_million.csv").write_bytes(m)
    (d / "manifest.json").write_text(json.dumps({"snapshot": name, "failures": [], "files": [
        {"source": "phishunt_json", "file": "phishunt_feed.json", "sha256": hashlib.sha256(p).hexdigest(), "retrieved_at": retrieved},
        {"source": "majestic_million", "file": "majestic_million.csv", "sha256": hashlib.sha256(m).hexdigest(), "retrieved_at": retrieved},
    ]}))
    return d


# ── brand mapping ────────────────────────────────────────────────────────────

def test_map_brands_picks_best_rank_flags_ambiguity_and_excludes_doubtful():
    mapping, unmapped, low = corpus.map_brands(["facebook", "paypal", "apple", "ghostbrand", "obscurebrand", "FaceBook"], _majestic_rows())
    assert mapping["facebook"]["domain"] == "facebook.com" and mapping["facebook"]["rank"] == 2
    # apps.facebook.com (rank 5) is a subdomain of the same registrable domain, not a rival;
    # facebook.net (rank 10, within 5x) genuinely is one, which keeps confidence at "medium"
    assert mapping["facebook"]["ambiguous_with"] == ["facebook.net"] and mapping["facebook"]["confidence"] == "medium"
    assert mapping["apple"]["domain"] == "apple.com" and mapping["apple"]["ambiguous_with"] == ["apple.co.uk"]
    assert mapping["apple"]["confidence"] == "medium"          # ambiguity prevents "high"
    assert mapping["paypal"]["confidence"] == "high"
    assert unmapped == ["ghostbrand"]
    assert low == ["obscurebrand"] and "obscurebrand" not in mapping


def test_mapping_never_selects_a_subdomain_as_the_brand_domain():
    rows = [(1, "apps.example.com"), (2, "example.com"), (3, "example.org")]
    mapping, _, _ = corpus.map_brands(["example"], rows)
    assert mapping["example"]["domain"] == "example.com"
    assert mapping["example"]["ambiguous_with"] == ["example.org"]


def test_overrides_win_and_rescue_low_confidence_brands():
    mapping, unmapped, low = corpus.map_brands(["obscurebrand", "ghostbrand"], _majestic_rows(), {"ghostbrand": "ghost.example", "obscurebrand": "obscure.example"})
    assert mapping["ghostbrand"]["confidence"] == "override" and mapping["obscurebrand"]["domain"] == "obscure.example"
    assert unmapped == [] and low == []


# ── positives ────────────────────────────────────────────────────────────────

@pytest.fixture
def mapped():
    mapping, _, _ = corpus.map_brands(["facebook", "paypal", "google"], _majestic_rows())
    return mapping


def test_positive_filtering_dedupe_quality_and_flag_stripping(mapped):
    recs, dropped = corpus.build_positives(_phish_rows(), mapped, "snap")
    by_dom = {(r.domain, r.brand): r for r in recs}

    assert dropped["verdict_low"] == 1 and dropped["verdict_noise"] == 1 and dropped["unlabelled"] == 1
    assert dropped["brand_unmapped_or_low_confidence"] == 2      # ghostbrand + obscurebrand
    assert dropped["duplicate"] == 1
    assert by_dom[("facebook-login.pages.dev", "facebook")].first_seen.startswith("2026-04-03"), "earliest sighting must win"

    assert by_dom[("paypa1.com", "paypal")].quality == "suspected_high"
    assert by_dom[("paypal.verify.evil-host.net", "paypal")].quality == "suspected_medium"
    assert {r.quality for r in recs} <= {"suspected_high", "suspected_medium"}

    techniques = {k: v.technique for k, v in by_dom.items()}
    assert techniques[("facebook-login.pages.dev", "facebook")] == "brand_in_domain"
    assert techniques[("kit.example-host.ru", "facebook")] == "brand_in_path"
    assert techniques[("paypa1.com", "paypal")] == "near_miss"
    assert techniques[("paypal.biz", "paypal")] == "tld_swap"
    assert techniques[("xn--pypal-4ve.com", "paypal")] == "idn"
    assert techniques[("paypal.verify.evil-host.net", "paypal")] == "brand_in_subdomain"
    assert by_dom[("facebook-login.pages.dev", "facebook")].free_hosting is True

    # licence hygiene: the cross-reference flags that mention OpenPhish never reach the corpus
    blob = json.dumps([r.__dict__ for r in recs]).lower()
    assert "malicious_openphish" not in blob and "openphish" not in blob


# ── negatives ────────────────────────────────────────────────────────────────

def test_popular_lookalikes_subtypes_exclusions_and_cap():
    mapping, _, _ = corpus.map_brands(["facebook", "paypal"], _majestic_rows())
    recs = corpus.build_popular_lookalikes(_majestic_rows(), mapping, "snap")
    fb = {r.domain: r.technique for r in recs if r.brand == "facebook"}
    assert fb["facebook.net"] == "same_name_other_suffix"
    assert fb["facebookmarketing.com"] == "contains_brand"
    assert fb["facebok.com"] == "near_miss"
    assert "apps.facebook.com" not in fb and "facebook.com" not in fb, "the brand's own domain (and its subdomains) is never a lookalike"
    assert {r.domain: r.technique for r in recs if r.brand == "paypal"}["paypai.com"] == "near_miss"
    assert all(r.quality == "derived_popularity" and r.rank is not None and r.label == "popular_lookalike" for r in recs)

    capped = corpus.build_popular_lookalikes(_majestic_rows(), mapping, "snap", cap=1)
    assert len([r for r in capped if r.brand == "facebook"]) == 1
    assert [r.domain for r in capped if r.brand == "facebook"] == ["facebook.net"], "lowest rank kept first"


def test_unrelated_sample_is_deterministic_and_excludes_lookalikes():
    mapping, _, _ = corpus.map_brands(["facebook", "paypal"], _majestic_rows())
    a = corpus.sample_popular_unrelated(_majestic_rows(), mapping, "snap", n=30, seed=7, exclude=set())
    b = corpus.sample_popular_unrelated(_majestic_rows(), mapping, "snap", n=30, seed=7, exclude=set())
    c = corpus.sample_popular_unrelated(_majestic_rows(), mapping, "snap", n=30, seed=8, exclude=set())
    assert [r.id for r in a] == [r.id for r in b] and [r.id for r in a] != [r.id for r in c]
    domains = {r.domain for r in a}
    assert domains.isdisjoint({"facebook.net", "facebookmarketing.com", "facebok.com", "paypai.com", "facebook.com", "paypal.com"})
    assert len(a) == 30 and all(r.technique == "unrelated" for r in a)

    excluded = corpus.sample_popular_unrelated(_majestic_rows(), mapping, "snap", n=30, seed=7, exclude={"site1.com"})
    assert "site1.com" not in {r.domain for r in excluded}


# ── splits ───────────────────────────────────────────────────────────────────

def test_positive_splits_are_chronological_by_campaign_start_and_keep_groups_together(mapped):
    recs, _ = corpus.build_positives(_phish_rows(), mapped, "snap")
    cutoffs = corpus.assign_splits(recs, [])

    starts: dict[str, str] = {}
    for r in recs:
        starts[r.registrable] = min(starts.get(r.registrable, "~"), r.first_seen)
    by_split = {s: [starts[g] for g in {r.registrable for r in recs if r.split == s}] for s in ("train", "valid", "test")}
    assert max(by_split["train"]) <= min(by_split["valid"]) and max(by_split["valid"]) <= min(by_split["test"]), "no time leakage across splits"

    for reg in {r.registrable for r in recs}:
        assert len({r.split for r in recs if r.registrable == reg}) == 1, f"{reg} straddles splits"
    shared = {r.split for r in recs if r.registrable == "shared-campaign.net"}
    assert len([r for r in recs if r.registrable == "shared-campaign.net"]) == 2, "both brands' sightings present"
    assert len(shared) == 1, "a campaign's late sighting must stay with its campaign"

    n = len(recs)
    assert abs(sum(1 for r in recs if r.split == "train") / n - 0.6) < 0.1
    assert cutoffs["train"]["n"] + cutoffs["valid"]["n"] + cutoffs["test"]["n"] == n
    assert cutoffs["train"]["campaign_start_to"] <= cutoffs["valid"]["campaign_start_from"]
    assert cutoffs["test"]["latest_sighting"] >= cutoffs["test"]["campaign_start_to"]


def test_negative_splits_are_stable_hashes():
    mapping, _, _ = corpus.map_brands(["facebook"], _majestic_rows())
    a = corpus.sample_popular_unrelated(_majestic_rows(), mapping, "s", 40, 1, set())
    b = corpus.sample_popular_unrelated(_majestic_rows(), mapping, "s", 40, 1, set())
    corpus.assign_splits([], a)
    corpus.assign_splits([], b)
    assert [r.split for r in a] == [r.split for r in b] and {r.split for r in a} <= {"train", "valid", "test"}
    assert len({r.split for r in a}) > 1


# ── end to end ───────────────────────────────────────────────────────────────

def test_find_snapshots_prefers_the_newest_retrieval(tmp_path):
    _write_snapshot(tmp_path, name="old", retrieved="2026-09-01T00:00:00+00:00")
    _write_snapshot(tmp_path, name="new", retrieved="2026-09-30T00:00:00+00:00")
    snaps = corpus.find_snapshots(tmp_path)
    assert snaps["phishunt_json"]["snapshot"] == "new" and snaps["majestic_million"]["path"].parent.name == "new"


def test_build_is_deterministic_and_content_addressed(tmp_path):
    _write_snapshot(tmp_path / "snaps")
    m1 = corpus.build(tmp_path / "snaps", tmp_path / "out1", unrelated_n=30)
    m2 = corpus.build(tmp_path / "snaps", tmp_path / "out2", unrelated_n=30)
    assert m1["corpus_version"] == m2["corpus_version"] and m1["corpus_sha256"] == m2["corpus_sha256"]
    body = (tmp_path / "out1" / m1["corpus_version"] / "corpus.jsonl").read_bytes()
    assert hashlib.sha256(body).hexdigest() == m1["corpus_sha256"]

    m3 = corpus.build(tmp_path / "snaps", tmp_path / "out3", unrelated_n=31)
    assert m3["corpus_version"] != m1["corpus_version"], "changed parameters must yield a different version"


def test_build_refuses_to_overwrite_and_needs_both_inputs(tmp_path):
    _write_snapshot(tmp_path / "snaps")
    corpus.build(tmp_path / "snaps", tmp_path / "out", unrelated_n=10)
    with pytest.raises(FileExistsError):
        corpus.build(tmp_path / "snaps", tmp_path / "out", unrelated_n=10)
    corpus.build(tmp_path / "snaps", tmp_path / "out", unrelated_n=10, force=True)

    (tmp_path / "empty").mkdir()
    with pytest.raises(FileNotFoundError):
        corpus.build(tmp_path / "empty", tmp_path / "out2")


def test_manifest_records_provenance_strata_and_caveats(tmp_path):
    _write_snapshot(tmp_path / "snaps")
    m = corpus.build(tmp_path / "snaps", tmp_path / "out", unrelated_n=30)
    s = m["stats"]

    assert m["inputs"]["phishunt_json"]["sha256"] and m["inputs"]["majestic_million"]["sha256"]
    assert s["positives_by_technique"]["brand_in_domain"] >= 40
    assert s["positives_free_hosting"] >= 1
    assert s["positives_name_detectable"] <= s["positives_total"]
    assert set(s["lookalikes_by_subtype"]) == {"same_name_other_suffix", "contains_brand", "near_miss"}
    assert m["brands_unmapped"] == ["ghostbrand"] and m["brands_excluded_low_confidence"] == ["obscurebrand"]
    assert any("not human-verified" in c for c in m["caveats"]) and any("South African" in c for c in m["caveats"])
    assert set(m["brand_mapping"]) == {"facebook", "paypal"}

    recs = list(corpus.iter_corpus(tmp_path / "out" / m["corpus_version"]))
    assert {r["label"] for r in recs} == {"malicious_suspected", "popular_lookalike", "popular_unrelated"}
    assert all(r["split"] in ("train", "valid", "test") for r in recs)
    test_pos = list(corpus.iter_corpus(tmp_path / "out" / m["corpus_version"], split="test", label="malicious_suspected"))
    assert test_pos and all(r["label"] == "malicious_suspected" and r["split"] == "test" for r in test_pos)
    ids = [r["id"] for r in recs]
    assert len(ids) == len(set(ids)), "record ids must be unique"
    # no domain is both a positive and a negative
    pos_reg = {r["registrable"] for r in recs if r["label"] == "malicious_suspected"}
    assert pos_reg.isdisjoint({r["registrable"] for r in recs if r["label"] != "malicious_suspected"})
