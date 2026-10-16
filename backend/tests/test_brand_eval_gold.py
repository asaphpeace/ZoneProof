"""
Step 1.2 — gold-set handling. The key property: a gold label is a human
judgement with a named labeller and a date, so the loader rejects anything that
isn't, and unlabelled queue rows are counted, never guessed.
"""
import csv
import json
from pathlib import Path

import pytest

from brand_eval import gold
from brand_eval import review_queue

HEADER = ["brand_domain", "candidate", "generator_class", "brand_slug_in_name", "label", "labeller", "labelled_at", "notes"]


def _csv(tmp_path: Path, rows: list[dict], header=HEADER) -> Path:
    p = tmp_path / "gold.csv"
    with p.open("w", encoding="utf8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=header, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    return p


def _row(**kw):
    base = {"brand_domain": "bank.co.za", "candidate": "bnak.co.za", "generator_class": "typo", "brand_slug_in_name": "false",
            "label": "malicious_lookalike", "labeller": "analyst-1", "labelled_at": "2026-10-01", "notes": ""}
    return {**base, **kw}


def test_valid_rows_load_and_summarise(tmp_path):
    p = _csv(tmp_path, [
        _row(),
        _row(candidate="bank-secure.co.za", brand_slug_in_name="true", label="defensive_registration"),
        _row(candidate="bonk.co.za", label="legitimate_unrelated"),
        _row(candidate="maybe.co.za", label="unsure"),
        _row(candidate="todo.co.za", label="", labeller="", labelled_at=""),          # unlabelled queue row
    ])
    load = gold.load_gold_csv(p)
    assert load.ok and len(load.rows) == 4 and load.unlabelled == 1
    s = gold.summarize(load)
    assert s["by_label"] == {"defensive_registration": 1, "legitimate_unrelated": 1, "malicious_lookalike": 1, "unsure": 1}
    assert s["usable_for_metrics"] == 3, "'unsure' is kept for review but excluded from metrics"
    assert s["by_brand_slug_in_name"] == {"false": 3, "true": 1}


@pytest.mark.parametrize("bad,fragment", [
    (_row(label="evil"), "not one of"),
    (_row(labeller=""), "labeller and labelled_at"),
    (_row(labelled_at=""), "labeller and labelled_at"),
    (_row(labelled_at="yesterday"), "not an ISO date"),
    (_row(candidate=""), "must be domain names"),
])
def test_invalid_rows_are_rejected_with_a_reason(tmp_path, bad, fragment):
    load = gold.load_gold_csv(_csv(tmp_path, [bad]))
    assert not load.ok and any(fragment in e for e in load.errors) and load.rows == []


def test_conflicting_duplicates_are_errors_but_identical_ones_collapse(tmp_path):
    load = gold.load_gold_csv(_csv(tmp_path, [_row(), _row()]))
    assert load.ok and len(load.rows) == 1
    load = gold.load_gold_csv(_csv(tmp_path, [_row(), _row(label="defensive_registration")]))
    assert not load.ok and "labelled both" in load.errors[0]


def test_missing_required_columns_reported(tmp_path):
    load = gold.load_gold_csv(_csv(tmp_path, [_row()], header=["brand_domain", "candidate", "label"]))
    assert not load.ok and "labeller" in load.errors[0] and "labelled_at" in load.errors[0]


def test_labels_are_case_and_whitespace_insensitive(tmp_path):
    load = gold.load_gold_csv(_csv(tmp_path, [_row(label="  Malicious_Lookalike ", candidate="  BNAK.co.za ")]))
    assert load.ok and load.rows[0].label == "malicious_lookalike" and load.rows[0].candidate == "bnak.co.za"


# ── SA registry ──────────────────────────────────────────────────────────────

def test_shipped_sa_registry_is_valid_and_contains_no_phishing_data():
    brands = gold.load_sa_registry()
    assert len(brands) >= 15 and len({b["slug"] for b in brands}) == len(brands)
    assert {"bank", "telco", "retail", "government", "insurer"} <= {b["category"] for b in brands}
    assert all(b["domain"].endswith((".co.za", ".gov.za", ".com")) for b in brands)


@pytest.mark.parametrize("entry,fragment", [
    ({"slug": "x", "name": "X", "domain": "www.x.co.za", "category": "bank", "title_keywords": ["x"]}, "not a registrable domain"),
    ({"slug": "X Y", "name": "X", "domain": "x.co.za", "category": "bank", "title_keywords": ["x"]}, "lowercase alphanumeric"),
    ({"slug": "x", "name": "X", "domain": "x.co.za", "category": "bank"}, "title_keywords"),
])
def test_registry_validation(tmp_path, entry, fragment):
    p = tmp_path / "reg.json"
    p.write_text(json.dumps({"brands": [entry]}))
    with pytest.raises(ValueError, match=fragment):
        gold.load_sa_registry(p)


def test_registry_rejects_duplicates(tmp_path):
    b = {"slug": "x", "name": "X", "domain": "x.co.za", "category": "bank", "title_keywords": ["x"]}
    p = tmp_path / "reg.json"
    p.write_text(json.dumps({"brands": [b, dict(b)]}))
    with pytest.raises(ValueError, match="duplicate"):
        gold.load_sa_registry(p)


# ── review queue ─────────────────────────────────────────────────────────────

async def test_queue_rows_carry_facts_never_labels_and_skip_dead_names(monkeypatch):
    from app.services import brand_guard_service as svc

    live = {"bnak.co.za": {"has_a": True, "has_mx": True}, "bank-secure.co.za": {"has_a": True, "has_mx": False}}

    async def fake_dns(d):
        return live.get(d, {"has_a": False, "has_mx": False})

    async def fake_reg(client, d):
        from datetime import datetime, timedelta, timezone
        return datetime.now(timezone.utc) - timedelta(days=10) if d == "bnak.co.za" else None

    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_registration_date", fake_reg)
    import app.services.brand_discovery_service as disc
    monkeypatch.setattr(disc, "generate_candidates", lambda *a, **k: {"bnak.co.za": "typo", "bank-secure.co.za": "combosquat", "dead.co.za": "typo"})

    rows, stats = await review_queue.build_queue([{"slug": "bank", "name": "Bank", "domain": "bank.co.za", "keywords": []}])
    by = {r["candidate"]: r for r in rows}
    assert set(by) == {"bnak.co.za", "bank-secure.co.za"}, "names with no DNS and no registration are not queued"
    assert by["bnak.co.za"]["age_days"] == 10 and by["bnak.co.za"]["brand_slug_in_name"] == "false"
    assert by["bank-secure.co.za"]["brand_slug_in_name"] == "true"
    assert all(r["label"] == "" and r["labeller"] == "" and r["labelled_at"] == "" for r in rows), "the queue must never pre-fill a judgement"
    assert set(review_queue.COLUMNS) >= set(gold.REQUIRED_COLUMNS)
    assert stats["generated"] == 3
