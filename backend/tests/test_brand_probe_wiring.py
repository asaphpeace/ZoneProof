"""How a page probe's facts flow into the score, the verdict's evidence view, the confidence families and the attack narrative."""
from datetime import datetime, timezone

from app.services import brand_probe_analysis as pa
from app.services import brand_reasoning, brand_taxonomy as bt, brand_verdict
from app.services.brand_scoring_service import assess_candidate

NOW = datetime(2026, 10, 7, tzinfo=timezone.utc)
BASE = {"has_a": True, "registered": True, "a": ["93.184.216.34"], "ns": ["ns1.example.net"]}


def assess(probe=None):
    e = dict(BASE)
    if probe is not None:
        e["probe"] = probe
    return assess_candidate("acmefinancial-login.xyz", primary_domain="acmefinancial.co.za", official_domains=[], brand_tokens=["acmefinancial"], discovery_class="combosquat", enrichment=e, now=NOW)


PW = {"reachable": True, "password_form": True, "offsite_password_form": True, "brand_in_title": True, "forms": [], "final_host": "acmefinancial-login.xyz"}


def names(a):
    return {s.signal: s for s in a.signals}


def test_a_password_page_adds_expert_weighted_abuse_evidence_and_raises_the_score():
    with_probe, without = assess(PW), assess()
    s = names(with_probe)["page_password_form"]
    assert s.dimension == "abuse" and s.weight == pa.W_PASSWORD_FORM + pa.W_OFFSITE_FORM + pa.W_BRAND_NAMED_PASSWORD
    assert with_probe.abuse_score == without.abuse_score + s.weight and "page_password_form" not in names(without)


def test_a_redirect_to_the_brands_own_site_lowers_the_score():
    probe = {"reachable": True, "redirects_to_brand": True, "final_host": "www.acmefinancial.co.za", "password_form": False}
    a, base = assess(probe), assess()
    assert names(a)["page_redirects_to_brand"].weight < 0 and a.abuse_score < base.abuse_score


def test_an_unreachable_or_empty_probe_changes_nothing_in_the_score():
    base = assess()
    assert assess({"reachable": False}).abuse_score == base.abuse_score and assess({}).abuse_score == base.abuse_score
    assert not any(n.startswith("page_") for n in names(assess({"reachable": False})))


def test_a_challenge_page_is_recorded_but_adds_no_points():
    a = assess({"reachable": True, "challenge_page": True, "final_status": 403, "password_form": False})
    assert names(a)["page_may_differ"].weight == 0 and a.abuse_score == assess().abuse_score


def test_page_signals_form_their_own_family_for_confidence_and_are_labelled_as_a_page_probe():
    for s in ("page_password_form", "page_brand_favicon", "page_certificate_odd", "page_redirects_to_brand", "page_may_differ"):
        assert brand_verdict.FAMILY[s] == "page" and brand_verdict.SOURCE_LABEL[s] == "Page probe"
    assert brand_verdict.FAMILY_LABEL["page"] == "what its web page shows"


def test_the_page_family_counts_as_independent_evidence_in_the_combiner():
    ev = [{"signal": "page_password_form", "dimension": "abuse", "weight": 28}, {"signal": "new_registration", "dimension": "abuse", "weight": 30}]
    r = brand_reasoning.combine(ev)
    assert set(r["families"]) >= {"page", "infrastructure"} and next(c for c in r["components"] if c["signal"] == "page_password_form")["basis"] == "expert"


def view(probe):
    return brand_verdict.evidence_view([], {"probe": probe} if probe is not None else {})["not_found"]


def test_the_evidence_view_says_when_the_page_was_not_analysed_could_not_be_reached_or_was_read():
    assert any("has not been analysed" in x["text"] for x in view(None))
    assert any("could not reach it" in x["text"] for x in view({"reachable": False}))
    assert not any("page" in x["text"].lower() and "analysed" in x["text"] for x in view({"reachable": True}))


def narr(probe):
    return {s["key"]: s for s in bt.attack_narrative(domain="a.xyz", enrichment={"probe": probe} if probe is not None else {}, evidence=[], abuse_type={"type": "phishing"})["steps"]}


def test_the_collect_credentials_step_is_observed_ruled_out_only_softly_or_unknown():
    assert narr(None)["harvest"]["status"] == "not_checked"
    assert narr({"reachable": False})["harvest"]["status"] == "not_checked"
    seen = narr({"reachable": True, "password_form": True, "offsite_password_form": True})["harvest"]
    assert seen["status"] == "observed" and "different site" in seen["note"] and seen["evidence"] == ["page_password_form"]
    none = narr({"reachable": True, "password_form": False})["harvest"]
    assert none["status"] == "not_observed" and "does not clear it" in none["note"]            # scanners may be shown a different page
