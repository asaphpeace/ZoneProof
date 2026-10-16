"""Brand Guard analyst view: verdict, confidence, decision and the evidence layout (brand_verdict.py), and the API fields."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import BrandCandidate, BrandCandidateEvent
from app.services import brand_verdict as bv
from app.services import brand_guard_service as svc
from tests.test_brand_guard_api import _Borrowed, _fake_network, _pro_profile, _scan  # noqa: F401  (shared scan helpers)


@pytest.fixture(autouse=True)
def _background_runs_use_test_session(db_session, monkeypatch):
    monkeypatch.setattr(svc, "_session_factory", lambda: _Borrowed(db_session))


def ev(signal, weight, summary="A fact. More.", **data):
    return {"id": f"id-{signal}", "signal": signal, "dimension": "abuse", "weight": weight, "summary": summary, "data": data,
            "observed_at": "2026-10-02T10:00:00+00:00"}


# ── verdict ──

@pytest.mark.parametrize("identity,abuse,key", [
    (80, 70, "likely_impersonation"), (55, 60, "likely_impersonation"), (54, 80, "watch"), (55, 59, "watch"), (60, 10, "watch"),
    (40, 35, "watch"), (40, 34, "insufficient"), (10, 90, "insufficient"), (0, 0, "insufficient"),
])
def test_verdict_thresholds(identity, abuse, key):
    assert bv.verdict(identity, abuse, [])["key"] == key


def test_strong_explainer_makes_it_probably_harmless_unless_abuse_is_high():
    popular = [ev("popular_site", -25.0)]
    assert bv.verdict(60, 10, popular)["key"] == "likely_harmless"
    assert bv.verdict(60, 70, popular)["key"] == "likely_impersonation"       # an explainer does not hide real abuse
    assert bv.verdict(60, 10, [ev("popular_site", -10.0)])["key"] == "watch"  # weak explainer: not enough
    assert bv.verdict(60, 10, [ev("parked", -8.0)])["key"] == "watch"


def test_conflicting_evidence_makes_the_verdict_abstain_instead_of_picking_a_side():
    rows = [ev("on_phishing_feed", 35.0), ev("popular_site", -25.0)]
    from app.services import brand_reasoning as br
    reasoning = br.combine(rows, {"signals": {}})
    assert reasoning["state"] == "conflicting"
    assert bv.verdict(70, 80, rows, reasoning) == {"key": "uncertain", "label": "Uncertain: evidence conflicts", "tone": "slate"}
    assert bv.verdict(70, 80, rows)["key"] == "likely_impersonation"                       # without the combiner the old behaviour stands
    calm = br.combine([ev("dns_live", 10.0)], {"signals": {}})
    assert bv.verdict(70, 80, [ev("dns_live", 10.0)], calm)["key"] == "likely_impersonation"
    assert bv.verdict(5, 5, [ev("dns_live", 10.0)], calm)["key"] == "insufficient"           # abstaining never upgrades a weak candidate


def test_verdict_has_label_and_tone():
    v = bv.verdict(80, 80, [])
    assert v == {"key": "likely_impersonation", "label": "Likely impersonation", "tone": "red"}


# ── confidence ──

def test_confidence_counts_independent_kinds_of_evidence():
    assert bv.confidence([])["level"] == "low"
    one = bv.confidence([ev("keyword_combo", 40), ev("homoglyph", 20)])          # two signals, ONE kind (name)
    assert one["level"] == "low" and one["families"] == ["name"]
    two = bv.confidence([ev("keyword_combo", 40), ev("dns_live", 10)])
    assert two["level"] == "medium"
    three = bv.confidence([ev("keyword_combo", 40), ev("dns_live", 10), ev("on_phishing_feed", 30)])
    assert three["level"] == "high" and len(three["families"]) == 3


def test_popularity_is_not_evidence_of_abuse_even_if_it_carried_a_positive_weight():
    assert bv.confidence([ev("keyword_combo", 40), ev("popular_site", 5.0)])["families"] == ["name"]


def test_narrative_keeps_to_the_four_strongest_facts():
    rows = [ev("keyword_combo", 50), ev("dns_live", 40), ev("new_registration", 30), ev("mx_live", 20), ev("spf_published", 10), ev("dkim_published", 5)]
    view = bv.evidence_view(rows, {})
    assert len(view["for"]) == 6 and [r["refs"] for r in view["narrative"]] == [[1], [2], [3], [4]]


def test_zero_and_negative_weights_do_not_count_as_evidence():
    got = bv.confidence([ev("keyword_combo", 40), ev("registrar", 0.0), ev("parked", -8.0), ev("same_nameservers", -15.0)])
    assert got["families"] == ["name"] and got["level"] == "low"


def test_benign_explainer_caps_high_at_medium():
    rows = [ev("keyword_combo", 40), ev("dns_live", 10), ev("on_phishing_feed", 30), ev("same_hosting_ip", -15.0)]
    got = bv.confidence(rows)
    assert got["level"] == "medium" and "caps" in got["reason"]


def test_confidence_reason_names_the_kinds():
    got = bv.confidence([ev("keyword_combo", 40), ev("reported_by_employee", 20)])
    assert "its name" in got["reason"] and "your own reports" in got["reason"]


def test_every_known_signal_has_a_family_and_a_source():
    for signal in bv.FAMILY:
        assert signal in bv.SOURCE_LABEL, signal


# ── decision ──

@pytest.mark.parametrize("status,reviewed,key,reason", [
    ("suspicious", False, "open", None), ("new", False, "open", None), ("monitoring", False, "open", None),
    ("monitoring", True, "watching", None), ("confirmed", True, "confirmed", None), ("takedown", True, "takedown", None),
    ("removed", True, "removed", None), ("customer_owned", True, "not_a_threat", "yours"),
    ("partner", True, "not_a_threat", "partner"), ("false_positive", True, "not_a_threat", "unrelated"),
    ("ignored", True, "ignored", None),
])
def test_decision_mapping(status, reviewed, key, reason):
    d = bv.decision(status, reviewed)
    assert d["key"] == key and d["reason"] == reason and d["by_person"] is reviewed


def test_unknown_status_is_open():
    assert bv.decision("something_new", False)["key"] == "open"


# ── evidence view ──

def test_evidence_view_numbers_for_then_against_and_keeps_zero_weights_as_context():
    rows = [ev("keyword_combo", 40, "Name is your brand plus login."), ev("dns_live", 10), ev("parked", -8.0, "Parked."),
            ev("registrar", 0.0, "Registrar is X.")]
    view = bv.evidence_view(rows, {})
    assert [i["n"] for i in view["for"]] == [1, 2] and [i["n"] for i in view["against"]] == [3]
    assert view["for"][0]["signal"] == "keyword_combo" and view["for"][0]["source"] == "Name analysis"
    assert [i["signal"] for i in view["context"]] == ["registrar"] and view["context"][0]["n"] is None
    assert [r["refs"] for r in view["narrative"]] == [[1], [2], [3]]
    assert view["narrative"][2]["text"].startswith("On the other side: ")


def test_absence_is_never_listed_as_evidence_against():
    view = bv.evidence_view([ev("keyword_combo", 40)], {})
    assert view["against"] == []
    kinds = {i["kind"] for i in view["not_found"]}
    assert kinds == {"not_found", "not_checked"}
    texts = " ".join(i["text"] for i in view["not_found"])
    assert "phishunt.io" in texts and "reported" in texts and "page has not been analysed" in texts


def test_not_found_drops_what_was_actually_found_and_reports_dmarc_only_when_checked():
    rows = [ev("on_phishing_feed", 30, feed="phishunt"), ev("reported_by_employee", 20)]
    view = bv.evidence_view(rows, {})
    assert [i["source"] for i in view["not_found"]] == ["Page probe"]
    checked = bv.evidence_view([ev("keyword_combo", 40)], {"spoofer_ips_checked": 3})
    assert any("3 failing sender" in i["text"] for i in checked["not_found"])
    none_to_compare = bv.evidence_view([ev("keyword_combo", 40)], {"spoofer_ips_checked": 0})
    assert any("no failing senders" in i["text"] for i in none_to_compare["not_found"])
    assert not any(i["source"] == "Your DMARC reports" for i in bv.evidence_view([ev("keyword_combo", 40)], {})["not_found"])


def test_feed_source_label_names_the_feed():
    view = bv.evidence_view([ev("on_phishing_feed", 30, feed="urlhaus")], {})
    assert view["for"][0]["source"] == "abuse.ch URLhaus"


def test_why_line_is_the_strongest_reason_or_the_strongest_explainer():
    rows = [ev("dns_live", 10, "It resolves. Extra."), ev("keyword_combo", 40, "Brand plus login. Extra."), ev("parked", -8.0, "Parked.")]
    assert bv.why_line(rows, "watch") == "Brand plus login."
    assert bv.why_line([ev("popular_site", -25.0, "A well-known site. More.")], "likely_harmless") == "A well-known site."
    assert "re-checked" in bv.why_line([], "insufficient")


def test_first_sentence_is_trimmed():
    long = "word " * 80
    assert len(bv._first_sentence(long)) <= 170 and bv._first_sentence(long).endswith("…")


# ── API ──

async def test_api_exposes_verdict_confidence_decision_and_evidence_view(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    _fake_network(monkeypatch, live={"acmefinancia1.co.za": {"has_a": True, "has_mx": True}}, registered_days={"acmefinancia1.co.za": 2})
    await _scan(client, profile_id)

    listed = (await client.get("/brand-guard/candidates")).json()[0]
    assert listed["verdict"]["key"] in {"likely_impersonation", "watch"} and listed["confidence"]["level"] in {"low", "medium", "high"}
    assert listed["decision"]["key"] == "open" and listed["why"]

    detail = (await client.get(f"/brand-guard/candidates/{listed['id']}")).json()
    view = detail["evidence_view"]
    assert view["for"] and view["not_found"] and view["narrative"]
    assert all(i["source"] and i["n"] for i in view["for"])

    changed = (await client.patch(f"/brand-guard/candidates/{listed['id']}/status", json={"status": "partner"})).json()
    assert changed["decision"] == {"key": "not_a_threat", "label": "Not a threat", "reason": "partner", "reason_label": "A partner", "by_person": True}
    assert changed["verdict"]["key"] == listed["verdict"]["key"]            # the human decision does not rewrite the verdict


async def test_summary_reports_new_went_live_and_detection_time(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    _fake_network(monkeypatch, live={"acmefinancia1.co.za": {"has_a": True, "has_mx": True}}, registered_days={"acmefinancia1.co.za": 2})
    await _scan(client, profile_id)

    summary = (await client.get("/brand-guard/summary")).json()
    assert summary["new_24h"] == 1
    assert summary["median_detect_n"] == 1 and 40 < summary["median_detect_hours"] < 56      # registered 2 days before first seen
    assert summary["went_live_7d"] == 0                                                        # it was already live when first seen

    cand = (await db_session.execute(select(BrandCandidate))).scalars().one()
    old = BrandCandidateEvent(candidate_id=cand.id, tenant_id=cand.tenant_id, kind="flag_gained",
                              occurred_at=datetime.now(timezone.utc) - timedelta(days=30), payload={"flag": "resolving"})
    db_session.add(old)
    await db_session.commit()
    assert (await client.get("/brand-guard/summary")).json()["went_live_7d"] == 0              # a month ago is not "7 days"

    db_session.add(BrandCandidateEvent(candidate_id=cand.id, tenant_id=cand.tenant_id, kind="flag_gained",
                                       occurred_at=datetime.now(timezone.utc) - timedelta(days=1), payload={"flag": "resolving"}))
    await db_session.commit()
    assert (await client.get("/brand-guard/summary")).json()["went_live_7d"] == 1

    cand.status = "false_positive"                                                             # a decided candidate is not "went live"
    await db_session.commit()
    assert (await client.get("/brand-guard/summary")).json()["went_live_7d"] == 0

    scoped = (await client.get("/brand-guard/summary", params={"profile_id": str(cand.profile_id)})).json()
    other = (await client.get("/brand-guard/summary", params={"profile_id": "00000000-0000-0000-0000-000000000000"})).json()
    assert scoped["false_positive"] == 1 and other["false_positive"] == 0 and other["new_24h"] == 0


async def test_detection_time_ignores_old_registrations(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    _fake_network(monkeypatch, live={"acmefinancia1.co.za": {"has_a": True, "has_mx": True}}, registered_days={"acmefinancia1.co.za": 400})
    await _scan(client, profile_id)
    summary = (await client.get("/brand-guard/summary")).json()
    assert summary["median_detect_hours"] is None and summary["median_detect_n"] == 0


async def test_api_candidates_carry_the_evidence_ratio(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    _fake_network(monkeypatch, live={"acmefinancia1.co.za": {"has_a": True, "has_mx": True}}, registered_days={"acmefinancia1.co.za": 2})
    await _scan(client, profile_id)
    listed = (await client.get("/brand-guard/candidates")).json()[0]
    r = listed["reasoning"]
    assert r["state"] in {"strong", "moderate", "weak", "insufficient", "conflicting", "harmless_leaning"}
    assert r["ratio"] >= 1.0 and r["components"] and all(c["basis"] in ("measured", "expert") for c in r["components"])
