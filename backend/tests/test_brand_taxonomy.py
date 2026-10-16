"""Abuse type, impact and attack narrative (app/services/brand_taxonomy.py): pure."""
import pytest

from app.services import brand_taxonomy as bt


def ev(signal, weight=10.0, **data):
    return {"signal": signal, "weight": weight, "data": data, "summary": signal}


def classify(domain="acme-x.xyz", evidence=(), enrichment=None, verdict="watch", identity=70.0):
    return bt.classify_abuse_type(domain=domain, evidence=list(evidence), enrichment=enrichment or {}, verdict_key=verdict, identity=identity, stage="resolving")


# ── abuse type ──

def test_only_a_public_feed_or_a_confirmed_report_can_say_phishing_or_malware():
    p = classify(enrichment={"feeds": [{"feed": "phishunt"}]})
    assert (p["type"], p["basis"]) == ("phishing", "reported") and "feed" in p["reasons"][0]
    m = classify(enrichment={"feeds": [{"feed": "urlhaus"}, {"feed": "phishunt"}]})
    assert (m["type"], m["basis"]) == ("malware", "reported")                     # malware outranks phishing when both list it
    r = classify(enrichment={"reported_emails": [{"disposition": "confirmed_malicious"}]})
    assert (r["type"], r["basis"]) == ("phishing", "reported") and "confirmed" in r["reasons"][0]
    unconfirmed = classify(enrichment={"reported_emails": [{"disposition": "new"}]})
    assert unconfirmed["basis"] != "reported"


def test_a_credential_word_on_a_live_domain_is_suspected_phishing_never_reported():
    c = classify(domain="acme-login.xyz", enrichment={"has_a": True})
    assert (c["type"], c["basis"]) == ("phishing", "suspected") and "login" in c["reasons"][0]


def test_a_payment_or_delivery_word_on_a_live_domain_is_suspected_fraud():
    c = classify(domain="acme-refund.xyz", enrichment={"has_a": True})
    assert (c["type"], c["basis"]) == ("fraud", "suspected") and "refund" in c["reasons"][0]
    assert classify(domain="acme-parcel.xyz", enrichment={"has_mx": True})["type"] == "fraud"


def test_credential_words_win_over_payment_words_when_both_are_present():
    assert classify(domain="acme-login-pay.xyz", enrichment={"has_a": True})["type"] == "phishing"


def test_lure_words_on_a_dormant_name_are_not_enough_to_call_it_phishing():
    assert classify(domain="acme-login.xyz", enrichment={})["type"] == "trademark"


def test_lure_words_need_a_live_domain_and_resemblance_needs_a_floor():
    assert classify(domain="acme-refund.xyz", enrichment={})["type"] == "trademark"                       # payment word but nothing live
    assert classify(domain="whatever.xyz", enrichment={"has_a": True}, identity=30)["type"] == "unclassified"
    assert classify(domain="whatever.xyz", enrichment={"has_a": True}, identity=45)["type"] == "trademark"


def test_mail_ready_and_strongly_resembling_is_impersonation():
    c = classify(domain="acmefinancial.net", evidence=[ev("spf_published")], enrichment={"has_mx": True}, identity=80)
    assert (c["type"], c["basis"]) == ("impersonation", "suspected") and "send email as you" in c["reasons"][0]
    assert classify(domain="acmefinancial.net", enrichment={"has_mx": True}, identity=50)["type"] == "trademark"        # resemblance below 55


def test_a_resembling_but_dormant_or_parked_name_is_look_alike_squatting():
    c = classify(domain="acmefinancial.shop", evidence=[ev("parked", -8)], enrichment={}, identity=60)
    assert c["type"] == "trademark" and any("parking" in r for r in c["reasons"]) and any("dormant" in r for r in c["reasons"])


def test_a_harmless_verdict_is_benign_and_a_weak_unlit_name_is_unclassified():
    assert classify(verdict="likely_harmless")["type"] == "benign"
    u = classify(domain="whatever.xyz", enrichment={}, identity=10)
    assert (u["type"], u["basis"]) == ("unclassified", "assumed")
    assert "does not resemble your brand strongly" in u["reasons"][0]


def test_every_classification_states_what_it_did_not_look_at():
    for c in (classify(), classify(enrichment={"feeds": [{"feed": "phishunt"}]}), classify(verdict="likely_harmless")):
        assert any("page content" in n.lower() for n in c["not_used"])
        assert c["label"] == bt.TYPES[c["type"]]


# ── impact and reach ──

def test_impact_is_high_only_when_it_can_both_mail_and_serve():
    both = bt.impact_card(enrichment={"has_a": True, "has_mx": True}, evidence=[], stage="mail_enabled")
    assert both["level"] == "high" and "send and receive email" in both["text"] and "serve a website" in both["text"]
    assert bt.impact_card(enrichment={"has_a": True}, evidence=[], stage="resolving")["level"] == "medium"
    nothing = bt.impact_card(enrichment={}, evidence=[], stage="registered")
    assert nothing["level"] == "low" and "cannot do anything today" in nothing["text"]


def test_mail_servers_alone_are_medium_not_high():
    assert bt.impact_card(enrichment={"has_mx": True}, evidence=[], stage="mail_enabled")["level"] == "medium"


def test_https_is_mentioned_only_when_a_certificate_is_known():
    assert "over HTTPS" in bt.impact_card(enrichment={"has_a": True, "ct_cert_issued_at": "2026-10-01"}, evidence=[], stage=None)["text"]
    assert "over HTTPS" not in bt.impact_card(enrichment={"has_a": True}, evidence=[], stage=None)["text"]


def test_reach_counts_only_what_the_customers_own_data_shows_and_says_the_rest_is_unknown():
    r = bt.impact_card(enrichment={"has_a": True, "reported_emails": [{"email_id": "1"}, {"email_id": "2"}]},
                       evidence=[ev("same_network_as_spoofer", match="address", messages=40)], stage=None)["reach"]
    assert r["employee_reports"] == 2 and r["spoofed_messages"] == 40 and len(r["known"]) == 2
    assert "cannot be measured" in r["cannot_measure"]
    network_only = bt.impact_card(enrichment={}, evidence=[ev("same_network_as_spoofer", match="network", messages=40)], stage=None)["reach"]
    assert network_only["spoofed_messages"] == 0                       # only the same ADDRESS counts as the same sender


# ── narrative ──

def narrative(enrichment, evidence=(), abuse_type=None):
    return bt.attack_narrative(domain="acme-login.xyz", enrichment=enrichment, evidence=list(evidence), abuse_type=abuse_type or {"type": "unclassified"})


def statuses(n):
    return {s["key"]: s["status"] for s in n["steps"]}


def test_nothing_is_shown_as_happening_without_stored_support():
    n = narrative({})
    assert statuses(n) == {"acquire_domain": "suspected", "impersonate": "not_observed", "certificate": "not_observed", "deliver": "not_observed", "harvest": "not_checked"}


def test_observed_steps_follow_the_stored_facts():
    n = narrative({"registered_at": "2026-09-29T21:02:00+00:00", "registration": {"registrar": "CheapHost"}, "has_a": True, "has_mx": True, "ct_cert_issued_at": "2026-09-30T19:22:00+00:00"},
                  [ev("new_registration"), ev("dns_live", 0.0), ev("mx_live", 0.0), ev("cert_after_registration")])
    assert statuses(n)["acquire_domain"] == statuses(n)["impersonate"] == statuses(n)["certificate"] == "observed"
    first = n["steps"][0]
    assert "2026-09-29" in first["text"] and "CheapHost" in first["text"] and first["evidence"] == ["new_registration"]
    assert "2026-09-30" in n["steps"][2]["text"]


def test_delivery_is_observed_only_for_a_report_or_a_feed_entry_and_suspected_for_mail_plus_a_lure_type():
    assert statuses(narrative({"reported_emails": [{"email_id": "1"}]}))["deliver"] == "observed"
    assert statuses(narrative({"feeds": [{"feed": "phishunt"}]}))["deliver"] == "observed"
    sus = narrative({"has_mx": True}, [ev("spf_published")], {"type": "phishing"})
    assert statuses(sus)["deliver"] == "suspected" and "no delivery has been seen" in sus["steps"][3]["note"]
    assert statuses(narrative({"has_mx": True}, [ev("spf_published")], {"type": "trademark"}))["deliver"] == "not_observed"


def test_the_last_step_cannot_be_confirmed_until_the_page_has_been_probed_and_says_why():
    n = narrative({"has_a": True, "feeds": [{"feed": "phishunt"}]})
    last = n["steps"][-1]
    assert last["status"] == "not_checked" and "has not been analysed" in last["note"]


def test_every_step_carries_a_curated_technique_tag_and_the_summary_counts_honestly():
    n = narrative({"registered_at": "2026-09-29", "has_a": True}, [ev("dns_live", 0.0)])
    assert all(s["technique"]["id"].startswith("T1") for s in n["steps"])
    assert n["summary"] == "Seen: 2 of 5 steps. Cannot check: 1." and "best-effort" in n["caveat"]
    assert [s["key"] for s in n["steps"]] == ["acquire_domain", "impersonate", "certificate", "deliver", "harvest"]


def test_assess_bundles_the_three_cards_consistently():
    out = bt.assess(domain="acme-login.xyz", evidence=[ev("dns_live", 0.0)], enrichment={"has_a": True}, verdict_key="watch", identity=70, stage="resolving")
    assert set(out) == {"abuse_type", "impact", "narrative"} and out["abuse_type"]["type"] == "phishing"
    assert out["narrative"]["steps"][3]["status"] == "not_observed"          # a live site, but no mail and no report: nothing says it was delivered


# ── API ──

import pytest as _pytest  # noqa: E402

from app.services import brand_guard_service as _svc  # noqa: E402
from tests.test_brand_guard_api import _Borrowed, _fake_network, _pro_profile, _scan  # noqa: E402


@_pytest.fixture
def _runs_use_test_session(db_session, monkeypatch):
    monkeypatch.setattr(_svc, "_session_factory", lambda: _Borrowed(db_session))


async def test_api_lists_the_abuse_type_and_details_carry_the_full_threat_card(auth_client, db_session, monkeypatch, _runs_use_test_session):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    _fake_network(monkeypatch, live={"acmefinancia1.co.za": {"has_a": True, "has_mx": True}}, registered_days={"acmefinancia1.co.za": 2})
    await _scan(client, profile_id)
    listed = (await client.get("/brand-guard/candidates")).json()[0]
    assert listed["abuse_type"]["type"] in bt.TYPES and listed["abuse_type"]["basis"] in ("reported", "suspected", "assumed")
    detail = (await client.get(f"/brand-guard/candidates/{listed['id']}")).json()
    t = detail["threat"]
    assert t["abuse_type"] == listed["abuse_type"] and t["impact"]["level"] == "high"
    assert [s["key"] for s in t["narrative"]["steps"]][0] == "acquire_domain" and t["narrative"]["steps"][-1]["status"] == "not_checked"
