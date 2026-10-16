"""The proof behind a verdict (app/services/brand_derivation.py): structure, faithfulness to the stored data, and the API."""
import pytest

from app.services import brand_derivation as bd, brand_reasoning as br, brand_verdict as bv
from tests.test_brand_guard_api import _fake_network, _pro_profile, _scan, _Borrowed  # noqa: F401
from app.services import brand_guard_service as svc

AT = "2026-10-02T10:00:00+00:00"


def ev(signal, weight, dim="abuse", summary=None, **data):
    return {"signal": signal, "dimension": dim, "weight": weight, "summary": summary or f"{signal} summary", "data": data, "observed_at": AT}


ENRICH = {
    "registered_at": "2026-09-29T21:02:00+00:00", "a": ["203.0.113.7"], "mx": ["mx.cheap.example"], "ns": ["ns1.cheap.example"],
    "ct_cert_issued_at": "2026-09-30T19:22:00+00:00", "cert_issuer": "Let's Encrypt", "cert_ids": ["abc"],
    "mail": {"spf": {"all": "~all", "includes": ["mailgun.org"]}, "dkim_selectors": ["s1"], "dmarc": {"policy": "none"}, "esp": ["Mailgun"]},
    "feeds": [{"feed": "phishunt", "label": "phishunt.io", "first_seen": "2026-10-01", "same_site": False}],
    "reported_emails": [{"email_id": "e1", "disposition": "new", "received_at": AT}],
}
EVIDENCE = [
    ev("keyword_combo", 40, "identity", summary="Brand plus login."), ev("domain_similarity", 15, "identity"),
    ev("new_registration", 30, summary="Registered 3 days ago."), ev("dns_live", 0.0), ev("mx_live", 0.0), ev("esp_sender", 15, services=["Mailgun"]),
    ev("on_phishing_feed", 30, feed="phishunt"), ev("reported_by_employee", 20), ev("parked", -8.8, service="Sedo"),
    ev("batch_registered", 8, siblings=["b.xyz", "c.xyz"], value=None), ev("registrar", 0.0, registrar="CheapHost"), ev("cert_after_registration", 8),
]


def tree(evidence=EVIDENCE, enrichment=ENRICH, identity=70.0, abuse=80.0, decision=None, not_found=None):
    reasoning = br.combine(evidence, {"signals": {}})
    key, rule = bv.decide(identity, abuse, evidence, reasoning)
    return bd.build(domain="acme-login.xyz", identity=identity, abuse=abuse, evidence=evidence, enrichment=enrichment, reasoning=reasoning,
                    verdict_key=key, rule_id=rule, decision=decision, not_found=not_found)


def find(node, pred):
    return [n for n in bd.walk(node) if pred(n)]


def test_the_root_is_the_verdict_with_the_rule_that_fired():
    t = tree()
    assert t["kind"] == "verdict" and t["verdict"] == "likely_impersonation" and t["rule"]["id"] == "R-likely"
    assert t["rule"]["text"] == bv.VERDICT_RULES["R-likely"] and "acme-login.xyz" in t["text"]
    assert [c["kind"] for c in t["children"]] == ["resemblance", "abuse"]


@pytest.mark.parametrize("identity,abuse,rule", [(80, 70, "R-likely"), (45, 40, "R-watch-both"), (60, 10, "R-watch-identity"), (10, 90, "R-insufficient")])
def test_every_verdict_names_a_rule_that_exists_and_matches_the_logic(identity, abuse, rule):
    t = tree(identity=identity, abuse=abuse, evidence=[ev("dns_live", 10)])
    assert t["rule"]["id"] == rule and rule in bv.VERDICT_RULES
    assert bv.verdict(identity, abuse, [ev("dns_live", 10)])["key"] == t["verdict"] or rule == "R-abstain"


def test_abstain_and_harmless_rules_are_cited():
    rows = [ev("on_phishing_feed", 35), ev("popular_site", -25, rank=500)]
    assert tree(evidence=rows, identity=70, abuse=80)["rule"]["id"] == "R-abstain"
    harmless = tree(evidence=[ev("popular_site", -25, rank=500)], identity=70, abuse=10)
    assert harmless["rule"]["id"] == "R-harmless" and harmless["verdict"] == "likely_harmless"


def test_every_evidence_line_appears_exactly_once_in_the_tree():
    t = tree()
    signals = [n["signal"] for n in find(t, lambda n: n["kind"] == "signal")]
    assert sorted(signals) == sorted(e["signal"] for e in EVIDENCE)


def test_signals_are_grouped_into_families_and_labelled_for_or_against():
    t = tree()
    fams = {n["family"]: n for n in find(t, lambda n: n["kind"] == "family")}
    assert {"infrastructure", "blocklist", "your_reports", "campaign"} <= set(fams)
    parked = next(n for n in bd.walk(fams["infrastructure"]) if n.get("signal") == "parked")
    assert parked["direction"] == "against" and parked["weight"] < 0
    feed = next(n for n in bd.walk(fams["blocklist"]) if n.get("signal") == "on_phishing_feed")
    assert feed["direction"] == "for" and feed["basis"] == "expert"          # nobody has measured the blocklist weight: shown as assumed


def test_the_raw_facts_carry_the_stored_values_and_their_source():
    t = tree()
    text = " | ".join(f["text"] for f in bd.leaf_facts(t))
    for expected in ("2026-09-29", "203.0.113.7", "mx.cheap.example", "Mailgun", "phishunt.io", "Reported email e1", "b.xyz", "Let's Encrypt", "Sedo"):
        assert expected in text, expected
    assert all(f["source"] for f in bd.leaf_facts(t))
    assert next(f for f in bd.leaf_facts(t) if "203.0.113.7" in f["text"])["source"] == "DNS"


def test_a_signal_without_a_stored_raw_fact_says_so_instead_of_inventing_one():
    t = tree(evidence=[ev("new_registration", 30)], enrichment={})
    node = find(t, lambda n: n.get("signal") == "new_registration")[0]
    assert node["children"] == [] and "not stored" in node["note"]


def test_several_stored_facts_all_show_up_up_to_the_cap(monkeypatch):
    enrichment = {**ENRICH, "feeds": [{"feed": "phishunt", "label": "phishunt.io"}, {"feed": "urlhaus", "label": "abuse.ch URLhaus"}, {"feed": "x", "label": "third"}]}
    node = find(tree(evidence=[ev("on_phishing_feed", 30)], enrichment=enrichment), lambda n: n.get("signal") == "on_phishing_feed")[0]
    assert len(node["children"]) == 3
    monkeypatch.setattr(bd, "MAX_FACTS_PER_SIGNAL", 2)
    node = find(tree(evidence=[ev("on_phishing_feed", 30)], enrichment=enrichment), lambda n: n.get("signal") == "on_phishing_feed")[0]
    assert len(node["children"]) == 2


def test_unknown_signals_fall_back_to_their_own_data_and_never_crash():
    t = tree(evidence=[ev("brand_new_thing", 5, widgets=3)], enrichment={})
    node = find(t, lambda n: n.get("signal") == "brand_new_thing")[0]
    assert node["children"][0]["text"].startswith("widgets: 3")
    assert tree(evidence=[], enrichment=None)["children"][1]["children"] == []


def test_nothing_found_and_the_human_decision_are_separate_nodes():
    nf = [{"kind": "not_found", "text": "Not on a blocklist.", "source": "Public blocklists"}, {"kind": "not_checked", "text": "Page not analysed.", "source": "Page analysis"}]
    t = tree(not_found=nf, decision={"key": "not_a_threat", "label": "Not a threat", "reason_label": "A partner"})
    unknown = find(t, lambda n: n["kind"] == "unknown")[0]
    assert [c["raw"]["kind"] for c in unknown["children"]] == ["not_found", "not_checked"]
    decision = find(t, lambda n: n["kind"] == "decision")[0]
    assert "Not a threat: A partner" in decision["text"] and "does not change the verdict" in decision["text"]
    assert not find(tree(decision={"key": "open", "label": "Not reviewed"}), lambda n: n["kind"] == "decision")


def test_node_ids_are_unique_and_every_node_has_children_list():
    t = tree()
    ids = [n["id"] for n in bd.walk(t)]
    assert len(ids) == len(set(ids)) and all(isinstance(n["children"], list) for n in bd.walk(t))


def test_family_text_states_the_direction_of_the_evidence():
    t = tree()
    fams = {n["family"]: n["text"] for n in find(t, lambda n: n["kind"] == "family")}
    assert "more typical of known-bad" in fams["blocklist"]


@pytest.fixture(autouse=True)
def _background_runs_use_test_session(db_session, monkeypatch):
    monkeypatch.setattr(svc, "_session_factory", lambda: _Borrowed(db_session))


async def test_api_detail_carries_a_faithful_derivation(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    profile_id = await _pro_profile(client, tenant, db_session)
    _fake_network(monkeypatch, live={"acmefinancia1.co.za": {"has_a": True, "has_mx": True, "a": ["203.0.113.9"]}}, registered_days={"acmefinancia1.co.za": 2})
    await _scan(client, profile_id)
    listed = (await client.get("/brand-guard/candidates")).json()[0]
    detail = (await client.get(f"/brand-guard/candidates/{listed['id']}")).json()
    d = detail["derivation"]
    assert d["kind"] == "verdict" and d["verdict"] == detail["verdict"]["key"] and d["rule"]["id"] in bv.VERDICT_RULES
    in_tree = sorted(n["signal"] for n in bd.walk(d) if n["kind"] == "signal")
    assert in_tree == sorted(e["signal"] for e in detail["evidence"])
    assert "203.0.113.9" in " ".join(f["text"] for f in bd.leaf_facts(d))
