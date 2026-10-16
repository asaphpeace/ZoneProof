"""
Step 2.3 — email intent of look-alike domains: SPF / DKIM / DMARC parsing, bulk-mail services, forwarding relays,
cloned DKIM keys, the "parked and locked" benign posture, the probe's cost gating, the scorer, and the scan pipeline.

What is NOT claimed: the weights are hand-set and abuse scoring cannot be measured offline, so these tests prove the
mechanics and the safety rules (caps, benign explainers), not detection value.
"""
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models import BrandCandidate, BrandProfile, CandidateEvidence
from app.services import brand_fingerprint_service as fps
from app.services import brand_guard_service as svc
from app.services import brand_mail_intent as mi
from app.services.brand_reasoning import points_for
from app.services.brand_scoring_service import assess_candidate
from tests.factories import make_domain, make_tenant


# ── parsing ──────────────────────────────────────────────────────────────────

def test_txt_chunks_are_rejoined_with_nothing_between_them():
    assert mi.txt_text('"v=spf1 include:_spf.goo" "gle.com ~all"') == "v=spf1 include:_spf.google.com ~all"
    assert mi.txt_text("plain") == "plain" and mi.txt_text("") == ""


@pytest.mark.parametrize("record,includes,all_q,senders", [
    ('"v=spf1 include:sendgrid.net include:_spf.google.com -all"', ["sendgrid.net", "_spf.google.com"], "-", 0),
    ('"v=spf1 ip4:203.0.113.0/24 a mx ~all"', [], "~", 3),
    ('"v=spf1 redirect=_spf.example.net"', ["_spf.example.net"], None, 0),
    ('"v=spf1 +all"', [], "+", 0),
    ('"v=spf1 all"', [], "+", 0),
    ('"V=SPF1 INCLUDE:MAILGUN.ORG ?ALL"', ["mailgun.org"], "?", 0),
    ('"v=spf1 -all"', [], "-", 0),
])
def test_spf_is_parsed(record, includes, all_q, senders):
    spf = mi.parse_spf([record])
    assert spf["includes"] == includes and spf["all"] == all_q and spf["senders"] == senders


def test_non_spf_txt_records_are_not_spf():
    assert mi.parse_spf([]) is None and mi.parse_spf(['"google-site-verification=abc"', '"v=DMARC1; p=none"']) is None
    assert mi.parse_spf(['"google-site-verification=abc"', '"v=spf1 -all"']) is not None, "SPF is found among other TXT records"


def test_dmarc_policy_and_reporting_are_parsed():
    assert mi.parse_dmarc(['"v=DMARC1; p=reject; rua=mailto:r@x.example"']) == {"policy": "reject", "reports": True}
    assert mi.parse_dmarc(['"v=DMARC1;p=none"']) == {"policy": "none", "reports": False}
    assert mi.parse_dmarc(['"v=spf1 -all"']) is None


def test_dkim_keys_compare_by_the_key_not_by_formatting():
    a = mi.dkim_key_hash('"v=DKIM1; k=rsa; p=MIGfMA0GCSqG SIb3DQEB"')
    b = mi.dkim_key_hash('"v=DKIM1;p=MIGfMA0GCSqGSIb3DQEB;k=rsa"')
    assert a == b and a is not None
    assert mi.dkim_key_hash('"v=DKIM1; p=OTHERKEY"') != a
    assert mi.dkim_key_hash('"v=DKIM1; p="') is None, "a revoked key (empty p=) is not a key"


def test_bulk_mail_services_match_on_a_domain_boundary_not_a_substring():
    assert mi.esp_names(["sendgrid.net", "_spf.google.com", "spf.mailgun.org", "servers.mcsv.net"]) == ["SendGrid", "Mailgun", "Mailchimp"]
    assert mi.esp_names(["evilsendgrid.net", "notmailgun.org"]) == []


def test_forwarding_relays_are_recognised_at_the_end_of_the_mx_host():
    assert mi.forwarding_mx(["mx1.improvmx.com.", "mx2.improvmx.com."]) == "ImprovMX"
    assert mi.forwarding_mx(["mail.example.com"]) is None and mi.forwarding_mx(["improvmx.com.evil.net"]) is None


# ── findings ─────────────────────────────────────────────────────────────────

def _mail(**kw):
    base = {"spf": None, "dmarc": None, "dkim_selectors": [], "dkim_keys": {}, "esp": [], "mx": [], "mail_provider": None, "forwarding_mx": None}
    base.update(kw)
    return base


def _by_signal(findings):
    return {f["signal"]: f for f in findings}


def test_no_mail_records_means_no_findings():
    assert mi.intent_findings(None) == [] and mi.intent_findings(_mail()) == []


def test_authentication_records_on_a_lookalike_are_intent_evidence():
    spf = mi.parse_spf(['"v=spf1 include:sendgrid.net ~all"'])
    f = _by_signal(mi.intent_findings(_mail(spf=spf, esp=["SendGrid"], dmarc={"policy": "none", "reports": False}, dkim_selectors=["s1", "s2"], mx=["mx.example.net"])))
    assert {"spf_published", "dkim_published", "dmarc_published", "esp_sender"} == set(f)
    # measured ESP weight (15) + three 5s exceed the 25-point cap, so all are scaled down together; the ESP signal stays the heaviest
    assert sum(x["weight"] for x in f.values()) == pytest.approx(mi.POSITIVE_CAP, abs=0.2) and f["esp_sender"]["weight"] > f["spf_published"]["weight"] * 2
    assert "SendGrid" in f["esp_sender"]["summary"] and "s1" in f["dkim_published"]["summary"]


def test_positive_mail_intent_is_capped_so_it_can_raise_suspicion_but_never_decide_it_alone():
    spf = mi.parse_spf(['"v=spf1 include:sendgrid.net -all"'])
    findings = mi.intent_findings(
        _mail(spf=spf, esp=["SendGrid"], dmarc={"policy": "none", "reports": False}, dkim_selectors=["s1"], dkim_keys={"s1": "h1"}, mx=["mx.improvmx.com"], forwarding_mx="ImprovMX"),
        {"dkim_keys": {"selector1": "h1"}},
    )
    positive = sum(f["weight"] for f in findings if f["weight"] > 0)
    assert len(findings) >= 6 and positive == pytest.approx(mi.POSITIVE_CAP, abs=0.2)
    assert all(f["weight"] > 0 for f in findings)


def test_a_cloned_dkim_key_is_detected_by_key_value_across_selectors():
    mine = {"dkim_keys": {"selector1": "KEYHASH", "selector2": "OTHER"}}
    f = _by_signal(mi.intent_findings(_mail(dkim_selectors=["k1"], dkim_keys={"k1": "KEYHASH"}), mine))
    assert f["copied_dkim_key"]["data"]["selectors"] == ["k1"] and "add it to your official domains" in f["copied_dkim_key"]["summary"]
    assert "copied_dkim_key" not in _by_signal(mi.intent_findings(_mail(dkim_selectors=["k1"], dkim_keys={"k1": "DIFFERENT"}), mine))


def test_the_same_mail_provider_is_informative_but_scores_nothing():
    f = _by_signal(mi.intent_findings(_mail(mx=["x.mail.protection.outlook.com"], mail_provider="Microsoft 365"), None, "Microsoft 365"))
    assert f["mirrors_mail_provider"]["weight"] == 0.0


def test_a_parked_and_locked_domain_is_a_benign_explainer_not_an_intent_signal():
    """`v=spf1 -all` with no mail host is how a careful owner parks a look-alike: nobody can send as it."""
    f = mi.intent_findings(_mail(spf=mi.parse_spf(['"v=spf1 -all"']), dmarc={"policy": "reject", "reports": False}))
    assert [x["signal"] for x in f] == ["defensive_mail_posture"] and f[0]["weight"] < 0
    # but the same record on a domain that DOES have a mail host is just an SPF record
    with_mx = _by_signal(mi.intent_findings(_mail(spf=mi.parse_spf(['"v=spf1 -all"']), mx=["mx.example.net"])))
    assert "defensive_mail_posture" not in with_mx and "spf_published" in with_mx


def test_a_null_mx_is_not_a_mail_host():
    profile = mi.build_mail_profile(spf_txts=['"v=spf1 -all"'], dmarc_txts=[], dkim={}, mx_hosts=[""], mail_provider=None)
    assert profile["mx"] == []
    assert [f["signal"] for f in mi.intent_findings(profile)] == ["defensive_mail_posture"]


# ── probe ────────────────────────────────────────────────────────────────────

def _query_table(table, calls):
    async def q(name, rtype):
        calls.append((name, rtype))
        return table.get((name, rtype), ("nxdomain", []))
    return q


async def test_a_dormant_name_costs_two_queries_and_a_mail_capable_one_twelve():
    calls = []
    q = _query_table({}, calls)
    profile = await mi.probe_mail("dormant.example", q, mx_hosts=[], mail_provider=None)
    assert len(calls) == 2 and {c[0] for c in calls} == {"dormant.example", "_dmarc.dormant.example"}
    assert profile["spf"] is None and profile["dkim_selectors"] == []

    calls.clear()
    await mi.probe_mail("mail.example", q, mx_hosts=["mx.example.net"], mail_provider=None)
    assert len(calls) == 2 + len(mi.DKIM_SELECTORS)

    calls.clear()
    spf_only = _query_table({("sender.example", "TXT"): ("answer", ['"v=spf1 include:mailgun.org -all"'])}, calls)
    await mi.probe_mail("sender.example", spf_only, mx_hosts=[], mail_provider=None)
    assert len(calls) == 2 + len(mi.DKIM_SELECTORS), "a send-only domain (SPF but no MX) is still probed for DKIM"

    calls.clear()
    await mi.probe_mail("mine.example", q, mx_hosts=[], mail_provider=None, always_dkim=True)
    assert len(calls) == 2 + len(mi.DKIM_SELECTORS)


async def test_probe_collects_spf_dmarc_dkim_and_hashes_the_keys():
    table = {
        ("evil.example", "TXT"): ("answer", ['"v=spf1 include:sendgrid.net ~all"', '"unrelated"']),
        ("_dmarc.evil.example", "TXT"): ("answer", ['"v=DMARC1; p=none; rua=mailto:x@evil.example"']),
        ("s1._domainkey.evil.example", "TXT"): ("answer", ['"v=DKIM1; k=rsa; p=AAAABBBB"']),
        ("selector2._domainkey.evil.example", "TXT"): ("answer", ['"v=DKIM1; p=CCCCDDDD"']),
        ("mail._domainkey.evil.example", "TXT"): ("answer", ['"not a dkim record"']),
        ("google._domainkey.evil.example", "TXT"): ("error", []),
    }
    p = await mi.probe_mail("evil.example", _query_table(table, []), mx_hosts=["mx.improvmx.com"], mail_provider=None)
    assert p["spf"]["includes"] == ["sendgrid.net"] and p["esp"] == ["SendGrid"] and p["dmarc"] == {"policy": "none", "reports": True}
    assert p["dkim_selectors"] == ["s1", "selector2"] and set(p["dkim_keys"]) == {"s1", "selector2"}
    assert p["forwarding_mx"] == "ImprovMX" and p["mx"] == ["mx.improvmx.com"]


# ── scoring ──────────────────────────────────────────────────────────────────

def _assess(cand, mail, baseline=None, **enr):
    return assess_candidate(cand, primary_domain="acmefinancial.co.za", official_domains=[], brand_tokens=["acmefinancial"],
                            discovery_class="combosquat", enrichment={"has_mx": True, "mail": mail, **enr}, baseline=baseline)


def test_mail_setup_raises_abuse_and_names_its_reasons():
    plain = _assess("acmefinancial-pay.com", None)
    spf = mi.parse_spf(['"v=spf1 include:mailgun.org -all"'])
    rich = _assess("acmefinancial-pay.com", _mail(spf=spf, esp=["Mailgun"], mx=["mx.example.net"]))
    names = {s.signal for s in rich.signals}
    assert {"spf_published", "esp_sender"} <= names
    assert rich.abuse_score == pytest.approx(plain.abuse_score + 5 + points_for("esp_sender", 10.0)) and rich.identity_score == plain.identity_score


def test_the_parked_and_locked_posture_lowers_abuse_and_is_visible_as_evidence_against():
    live_no_mail = _assess("acmefinancial-pay.com", None, has_mx=False, has_a=True)
    locked = _assess("acmefinancial-pay.com", _mail(spf=mi.parse_spf(['"v=spf1 -all"'])), has_mx=False, has_a=True)
    sig = {s.signal: s for s in locked.signals}
    assert sig["defensive_mail_posture"].weight < 0 and sig["defensive_mail_posture"].dimension == "abuse"
    assert live_no_mail.abuse_score - locked.abuse_score == 10.0


def test_the_customers_own_mail_baseline_flows_into_the_comparison():
    mine = {"mail_auth": {"dkim_keys": {"selector1": "HASH"}}, "mail_provider": "Microsoft 365"}
    a = _assess("acmefinancial-pay.com", _mail(dkim_selectors=["selector1"], dkim_keys={"selector1": "HASH"}, mx=["x.mail.protection.outlook.com"], mail_provider="Microsoft 365"), mine)
    assert {"copied_dkim_key", "mirrors_mail_provider"} <= {s.signal for s in a.signals}


# ── customer baseline ────────────────────────────────────────────────────────

async def test_the_customers_own_mail_authentication_is_recorded_in_the_fingerprint():
    table = {
        ("acme.co.za", "NS"): ("answer", ["ns1.own-dns.co.za."]), ("acme.co.za", "A"): ("answer", ["203.0.113.10"]),
        ("acme.co.za", "MX"): ("answer", ["10 acme-co-za.mail.protection.outlook.com."]),
        ("acme.co.za", "TXT"): ("answer", ['"v=spf1 include:spf.protection.outlook.com -all"']),
        ("_dmarc.acme.co.za", "TXT"): ("answer", ['"v=DMARC1; p=reject"']),
        ("selector1._domainkey.acme.co.za", "TXT"): ("answer", ['"v=DKIM1; k=rsa; p=MYKEY"']),
    }

    async def fetch(url, **kw):
        raise fps.safe_fetch.FetchError("could not connect")
    fp = await fps.build_fingerprint("acme.co.za", fetch=fetch, query=_query_table(table, []))
    auth = fp["dns"]["mail_auth"]
    assert auth["spf"]["all"] == "-" and auth["dmarc"]["policy"] == "reject" and auth["dkim_selectors"] == ["selector1"]
    assert auth["dkim_keys"]["selector1"] == mi.dkim_key_hash('"v=DKIM1; k=rsa; p=MYKEY"') and auth["mail_provider"] == "Microsoft 365"


async def test_a_failing_mail_probe_never_breaks_the_fingerprint(monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("resolver exploded")
    monkeypatch.setattr(fps.brand_mail_intent, "probe_mail", boom)

    async def fetch(url, **kw):
        raise fps.safe_fetch.FetchError("could not connect")
    fp = await fps.build_fingerprint("acme.co.za", fetch=fetch, query=_query_table({}, []))
    assert fp["dns"]["mail_auth"] is None and any("mail authentication" in e for e in fp["errors"])


# ── pipeline ─────────────────────────────────────────────────────────────────

async def _profile(db, plan="pro", official=None):
    tenant = await make_tenant(db, name=f"T{uuid.uuid4().hex[:6]}", plan=plan)
    domain = await make_domain(db, tenant, name="acmefinancial.co.za")
    domain.ownership_verified = True
    profile = BrandProfile(id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, brand_name="Acme Financial", keywords=[], official_domains=official or [])
    db.add(profile)
    await db.commit()
    return tenant, profile


async def test_scan_probes_mail_only_for_existing_apex_names_and_stores_the_evidence(db_session, monkeypatch):
    tenant, profile = await _profile(db_session, official=["acmefinancial.com"])
    live = "acmefinancial-pay.co.za"
    dormant = "acmefinancial-help.co.za"
    gone = "acmefinancial-secure.co.za"
    ct_sub = "login.acmefinancial.vendor.net"            # a subdomain host: mail authentication lives on the apex, so no probe
    now = datetime.now(timezone.utc).isoformat()
    probed = []

    async def fake_dns(name):
        if name in (live, dormant, ct_sub, "acmefinancial.com"):         # the last is the customer's own registered domain
            return {"has_a": name != dormant, "has_mx": name == live, "registered": True, "ns": ["ns1.x.net"], "a": ["198.51.100.7"] if name != dormant else [],
                    "mx": ["mx.example.net"] if name == live else []}
        return {"has_a": False, "has_mx": False, "registered": False, "ns": [], "a": [], "mx": []}

    async def fake_probe(domain, mx_hosts):
        probed.append((domain, tuple(mx_hosts)))
        return _mail(spf=mi.parse_spf(['"v=spf1 include:mailgun.org -all"']), esp=["Mailgun"], mx=list(mx_hosts)) if domain == live else _mail()

    async def fake_reg(c, d):
        return None

    async def fake_ct(db, tokens, since):
        return {"vendor.net": {"issued_at": now, "hosts": {ct_sub: now}}}
    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_probe_mail", fake_probe)
    monkeypatch.setattr(svc, "_registration_date", fake_reg)
    monkeypatch.setattr(svc, "fetch_ct_candidates", fake_ct)

    summary = await svc.scan_profile(db_session, profile, tenant)
    assert sorted(d for d, _ in probed) == [dormant, live], "gone names, subdomain hosts and the customer's own domains are never probed"
    assert dict(probed)[live] == ("mx.example.net",)
    assert summary["cost"]["mail_probes"] == 2

    cand = (await db_session.execute(select(BrandCandidate).where(BrandCandidate.candidate_domain == live))).scalar_one()
    assert cand.enrichment["mail"]["esp"] == ["Mailgun"]
    ev = {e.signal: e for e in (await db_session.execute(select(CandidateEvidence).where(CandidateEvidence.candidate_id == cand.id))).scalars()}
    assert {"spf_published", "esp_sender"} <= set(ev) and ev["esp_sender"].dimension == "abuse" and ev["esp_sender"].weight == points_for("esp_sender", 10.0)


async def test_a_failed_probe_leaves_the_candidate_scored_without_mail_evidence(db_session, monkeypatch):
    tenant, profile = await _profile(db_session)
    live = "acmefinancial-pay.co.za"

    async def fake_dns(name):
        return {"has_a": True, "has_mx": False, "registered": True, "ns": [], "a": ["198.51.100.7"], "mx": []} if name == live else {"has_a": False, "has_mx": False, "registered": False, "ns": [], "a": [], "mx": []}

    async def failing_probe(domain, mx_hosts):
        return None

    async def fake_reg(c, d):
        return None

    async def fake_ct(db, tokens, since):
        return {}
    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_probe_mail", failing_probe)
    monkeypatch.setattr(svc, "_registration_date", fake_reg)
    monkeypatch.setattr(svc, "fetch_ct_candidates", fake_ct)
    await svc.scan_profile(db_session, profile, tenant)
    cand = (await db_session.execute(select(BrandCandidate).where(BrandCandidate.candidate_domain == live))).scalar_one()
    assert "mail" not in cand.enrichment
