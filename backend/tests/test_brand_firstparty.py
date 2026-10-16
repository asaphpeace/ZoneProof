"""Plan 2.6 — first-party pivots: reported phish and DMARC-report sources. Hermetic (no network)."""
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.models import BrandCandidate, BrandProfile
from app.models.dmarc_report import DmarcAggregate
from app.models.reported_email import ReportedEmail
from app.services import brand_firstparty as fp, brand_guard_service as svc
from app.services.brand_scoring_service import assess_candidate
from tests.factories import make_domain, make_tenant

NOW = datetime(2026, 10, 2, 12, tzinfo=timezone.utc)


def email(urls=(), subject="", body="", sender="", sender_domain=None, disposition="new", eid=None):
    return SimpleNamespace(id=eid or uuid.uuid4(), disposition=disposition, original_subject=subject, body_text_excerpt=body,
                           original_from=sender, original_from_domain=sender_domain, urls_found=list(urls), received_at=NOW)


# ── helpers ──

@pytest.mark.parametrize("url,host", [
    ("https://Evil.Example.com/path?x=1", "evil.example.com"), ("evil.com/login", "evil.com"), ("http://evil.com.", "evil.com"),
    ("http://10.0.0.1/x", None), ("http://[::1]/x", None), ("notaurl", None), ("", None),
])
def test_host_of(url, host):
    assert fp.host_of(url) == host


def test_mentions_brand_whole_words_only():
    assert fp.mentions_brand("Your DPD parcel is waiting", ["dpd"])
    assert not fp.mentions_brand("adpdf attachment", ["dpd"])
    assert not fp.mentions_brand("padpd attachment", ["dpd"])
    assert not fp.mentions_brand("anything", ["", "ab"])           # too short to be a name


# ── reported leads ──

def leads(emails, official=frozenset({"acme.com"}), names=("Acme",)):
    return fp.reported_leads(emails, ["acme"], list(names), set(official))


def test_brand_mentioned_email_makes_unrelated_domain_a_lead():
    got = leads([email(urls=["https://parcel-track.xyz/a"], subject="Acme refund")])
    assert list(got) == ["parcel-track.xyz"]
    assert got["parcel-track.xyz"][0]["mentions_brand"] and not got["parcel-track.xyz"][0]["name_match"]


def test_name_match_alone_is_a_lead_without_a_mention():
    got = leads([email(urls=["https://acme-login.xyz"], subject="hello")])
    assert got["acme-login.xyz"][0]["name_match"] and not got["acme-login.xyz"][0]["mentions_brand"]


def test_email_about_something_else_is_ignored():
    assert leads([email(urls=["https://parcel-track.xyz"], subject="invoice")]) == {}


def test_false_positive_is_ignored_but_confirmed_and_known_are_kept():
    urls = ["https://parcel-track.xyz"]
    assert leads([email(urls=urls, subject="Acme", disposition="false_positive")]) == {}
    assert leads([email(urls=urls, subject="Acme", disposition="confirmed_malicious")])
    assert leads([email(urls=urls, subject="Acme", disposition="already_known")])


def test_own_domains_and_popular_sites_and_raw_ips_are_skipped():
    got = leads([email(urls=["https://www.acmebank.xyz/x", "https://google.com/x", "http://1.2.3.4/x", "https://real-lure.xyz"], subject="Acme")],
                official={"acmebank.xyz"})
    assert list(got) == ["real-lure.xyz"]


def test_platform_subdomain_is_kept_even_on_a_popular_platform():
    got = leads([email(urls=["https://acme-pay.weebly.com/x"], subject="Acme")])
    assert "acme-pay.weebly.com" in got


def test_sender_domain_is_a_lead_too():
    got = leads([email(sender_domain="acme-support.xyz", subject="x")])
    assert "acme-support.xyz" in got


def test_per_host_and_per_scan_caps(monkeypatch):
    many = [email(urls=["https://lure.xyz"], subject="Acme") for _ in range(10)]
    assert len(leads(many)["lure.xyz"]) == fp.MAX_EMAILS_PER_HOST
    monkeypatch.setattr(fp, "MAX_HOSTS_PER_SCAN", 2)
    assert len(leads([email(urls=[f"https://lure{i}.xyz"], subject="Acme") for i in range(5)])) == 2


def test_most_reported_host_ranks_first_under_the_cap(monkeypatch):
    monkeypatch.setattr(fp, "MAX_HOSTS_PER_SCAN", 1)
    emails = [email(urls=["https://a-once.xyz"], subject="Acme"), *[email(urls=["https://b-twice.xyz"], subject="Acme") for _ in range(2)]]
    assert list(leads(emails)) == ["b-twice.xyz"]


# ── findings ──

def test_reported_findings_weights_and_identity_part():
    base = [{"email_id": "1", "disposition": "new", "mentions_brand": True, "name_match": False}]
    f = {x["signal"]: x for x in fp.reported_findings(base)}
    assert f["reported_by_employee"]["weight"] == fp.REPORTED_WEIGHT and f["reported_brand_mention"]["dimension"] == "identity"
    confirmed = fp.reported_findings([{**base[0], "disposition": "confirmed_malicious"}])
    assert confirmed[0]["weight"] == fp.REPORTED_CONFIRMED_WEIGHT
    only_name = fp.reported_findings([{"email_id": "1", "disposition": "new", "mentions_brand": True, "name_match": True}])
    assert [x["signal"] for x in only_name] == ["reported_by_employee"]       # the name already carries identity
    assert fp.reported_findings([]) == [] and fp.reported_findings(None) == []


def test_scoring_adds_reported_evidence_and_identity_for_unrelated_name():
    plain = assess_candidate("parcel-track.xyz", primary_domain="acme.com", official_domains=[], brand_tokens=["acme"], discovery_class=None, enrichment={"has_a": True})
    entries = [{"email_id": "1", "disposition": "new", "mentions_brand": True, "name_match": False}]
    got = assess_candidate("parcel-track.xyz", primary_domain="acme.com", official_domains=[], brand_tokens=["acme"], discovery_class=None,
                           enrichment={"has_a": True, "reported_emails": entries})
    assert got.identity_score == plain.identity_score + fp.REPORTED_IDENTITY_WEIGHT
    assert got.abuse_score == plain.abuse_score + fp.REPORTED_WEIGHT
    assert {"reported_by_employee", "reported_brand_mention"} <= {s.signal for s in got.signals}


# ── spoofer pivot ──

SPOOF = {"ips": {"203.0.113.9": {"messages": 40, "owner": {"number": 64500, "name": "Evil Hosting"}}}, "asns": {64500: "Evil Hosting"}}


def test_same_address_is_strong_same_network_weak():
    a = fp.spoofer_pivot_findings(["203.0.113.9"], None, SPOOF)
    assert a[0]["weight"] == fp.SAME_ADDRESS_WEIGHT and a[0]["data"]["match"] == "address" and "40" in a[0]["summary"]
    n = fp.spoofer_pivot_findings(["198.51.100.1"], {"number": 64500, "name": "Evil Hosting"}, SPOOF)
    assert n[0]["weight"] == fp.SAME_NETWORK_WEIGHT and n[0]["data"]["match"] == "network"
    assert fp.spoofer_pivot_findings(["198.51.100.1"], {"number": 1, "name": "Other"}, SPOOF) == []
    assert fp.spoofer_pivot_findings([], None, SPOOF) == []
    assert fp.spoofer_pivot_findings(["203.0.113.9"], None, {"ips": {}, "asns": {}}) == []


def test_shared_hosting_weakens_address_match_and_voids_network_match():
    shared = {"ips": {"203.0.113.9": {"messages": 3, "owner": {"number": 13335, "name": "CLOUDFLARENET"}}}, "asns": {}}
    got = fp.spoofer_pivot_findings(["203.0.113.9"], None, shared)
    assert got[0]["weight"] == fp.SAME_ADDRESS_WEIGHT / 2 and got[0]["data"]["shared_host"]
    big = {"ips": {}, "asns": {13335: "CLOUDFLARENET"}}
    assert fp.spoofer_pivot_findings(["1.1.1.1"], {"number": 13335, "name": "CLOUDFLARENET"}, big) == []


# ── loaders and pipeline ──

async def _brand(db_session, plan="pro"):
    tenant = await make_tenant(db_session, name=f"Acme-{uuid.uuid4().hex[:6]}", plan=plan)
    domain = await make_domain(db_session, tenant, name="acmefinancial.co.za")
    domain.ownership_verified = True
    profile = BrandProfile(id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, brand_name="Acme Financial", keywords=[], official_domains=[])
    db_session.add(profile)
    await db_session.commit()
    return tenant, domain, profile


def agg(domain, ip, cls, fail=10, days_ago=1):
    end = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return DmarcAggregate(id=uuid.uuid4(), domain_id=domain.id, period_begin=end - timedelta(days=1), period_end=end, source_org="x",
                          source_ip=ip, header_from=domain.name, total_count=fail, fail_count=fail, classification=cls)


@pytest.mark.asyncio
async def test_load_spoofers_uses_only_spoof_classes_recent_and_own_domains(db_session):
    tenant, domain, _ = await _brand(db_session)
    other_tenant = await make_tenant(db_session, name="Other", plan="pro")
    other = await make_domain(db_session, other_tenant, name="other.co.za")
    db_session.add_all([agg(domain, "203.0.113.9", "spoof", 7), agg(domain, "203.0.113.9", "unauth", 3), agg(domain, "198.51.100.5", "authorized"),
                        agg(domain, "198.51.100.6", "spoof", days_ago=400), agg(other, "198.51.100.7", "spoof")])
    await db_session.commit()

    async def owner(ip):
        return {"number": 64500, "name": "Evil Hosting"}

    got = await fp.load_spoofers(db_session, [domain.id], owner_of=owner)
    assert list(got["ips"]) == ["203.0.113.9"] and got["ips"]["203.0.113.9"]["messages"] == 10
    assert got["asns"] == {64500: "Evil Hosting"}
    assert await fp.load_spoofers(db_session, [], owner_of=owner) == {"ips": {}, "asns": {}}


@pytest.mark.asyncio
async def test_load_spoofers_owner_failure_still_keeps_the_address(db_session):
    _, domain, _ = await _brand(db_session)
    db_session.add(agg(domain, "203.0.113.9", "spoof"))
    await db_session.commit()

    async def boom(ip):
        raise RuntimeError("dns down")

    got = await fp.load_spoofers(db_session, [domain.id], owner_of=boom)
    assert got["ips"]["203.0.113.9"]["owner"] is None and got["asns"] == {}


@pytest.mark.asyncio
async def test_load_reported_is_tenant_scoped_and_recent(db_session):
    tenant, _, _ = await _brand(db_session)
    other = await make_tenant(db_session, name="Other2", plan="pro")
    old = ReportedEmail(id=uuid.uuid4(), tenant_id=tenant.id, urls_found=[], received_at=datetime.now(timezone.utc) - timedelta(days=200))
    mine = ReportedEmail(id=uuid.uuid4(), tenant_id=tenant.id, urls_found=[])
    theirs = ReportedEmail(id=uuid.uuid4(), tenant_id=other.id, urls_found=[])
    db_session.add_all([old, mine, theirs])
    await db_session.commit()
    assert [r.id for r in await fp.load_reported(db_session, tenant.id)] == [mine.id]


async def _scan(db_session, monkeypatch, profile, tenant, ips=None):
    async def fake_dns(name):
        return {"has_a": True, "has_mx": False, "registered": True, "a": (ips or {}).get(name, [])}

    async def none_reg(client, name):
        return None

    async def no_ct(db, tokens, since):
        return {}

    async def owner(ip):
        return {"number": 64500, "name": "Evil Hosting"}

    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_registration_date", none_reg)
    monkeypatch.setattr(svc, "fetch_ct_candidates", no_ct)
    monkeypatch.setattr(svc, "_ip_owner", owner)
    await svc.scan_profile(db_session, profile, tenant, permutations=False)
    rows = (await db_session.execute(select(BrandCandidate).where(BrandCandidate.profile_id == profile.id))).scalars().all()
    return {r.candidate_domain: r for r in rows}


@pytest.mark.asyncio
async def test_scan_turns_a_reported_email_into_a_linked_candidate(db_session, monkeypatch):
    tenant, _, profile = await _brand(db_session)
    em = ReportedEmail(id=uuid.uuid4(), tenant_id=tenant.id, original_subject="Acme Financial refund due", urls_found=["https://parcel-track.xyz/x"],
                       disposition="confirmed_malicious")
    ignored = ReportedEmail(id=uuid.uuid4(), tenant_id=tenant.id, original_subject="Acme Financial", urls_found=["https://fp-site.xyz"], disposition="false_positive")
    db_session.add_all([em, ignored])
    await db_session.commit()
    rows = await _scan(db_session, monkeypatch, profile, tenant)
    assert list(rows) == ["parcel-track.xyz"]
    row = rows["parcel-track.xyz"]
    assert "reported_email" in row.sources
    assert row.enrichment["reported_emails"][0]["email_id"] == str(em.id)
    assert row.identity_score >= fp.REPORTED_IDENTITY_WEIGHT and row.abuse_score >= fp.REPORTED_CONFIRMED_WEIGHT


@pytest.mark.asyncio
async def test_scan_never_fails_when_the_reported_email_lookup_breaks(db_session, monkeypatch):
    tenant, _, profile = await _brand(db_session)

    async def boom(*a, **k):
        raise RuntimeError("db")

    monkeypatch.setattr(fp, "load_reported", boom)
    assert await _scan(db_session, monkeypatch, profile, tenant) == {}


@pytest.mark.asyncio
async def test_scan_links_a_candidate_on_a_spoofers_address(db_session, monkeypatch):
    tenant, domain, profile = await _brand(db_session)
    db_session.add(agg(domain, "203.0.113.9", "spoof", 25))
    host = "acmefinancial-secure.com"
    db_session.add(ReportedEmail(id=uuid.uuid4(), tenant_id=tenant.id, original_subject="Acme Financial", urls_found=[f"https://{host}"]))
    await db_session.commit()
    rows = await _scan(db_session, monkeypatch, profile, tenant, ips={host: ["203.0.113.9"]})
    pivot = rows[host].enrichment["spoofer_pivot"][0]
    assert pivot["signal"] == "same_network_as_spoofer" and pivot["data"]["match"] == "address"


@pytest.mark.asyncio
async def test_load_spoofers_looks_up_networks_only_for_the_busiest(db_session, monkeypatch):
    _, domain, _ = await _brand(db_session)
    db_session.add_all([agg(domain, "203.0.113.9", "spoof", 50), agg(domain, "203.0.113.10", "spoof", 5)])
    await db_session.commit()
    monkeypatch.setattr(fp, "MAX_OWNER_LOOKUPS", 1)
    asked = []

    async def owner(ip):
        asked.append(ip)
        return {"number": 64500, "name": "Evil Hosting"}

    got = await fp.load_spoofers(db_session, [domain.id], owner_of=owner)
    assert asked == ["203.0.113.9"] and set(got["ips"]) == {"203.0.113.9", "203.0.113.10"}
    assert got["ips"]["203.0.113.10"]["owner"] is None


def test_badges_for_first_party_evidence():
    from app.services.brand_corroboration import badges_from_signals
    from app.services.brand_scoring_service import Signal
    got = badges_from_signals([Signal("reported_by_employee", "abuse", 20.0, "x"), Signal("same_network_as_spoofer", "abuse", 15.0, "y")])
    assert [(b["kind"], b["label"]) for b in got] == [("reported", "Reported by your team"), ("spoofer", "Same network as a spoofer")]


@pytest.mark.asyncio
async def test_scan_records_how_many_failing_senders_were_checked(db_session, monkeypatch):
    tenant, domain, profile = await _brand(db_session)
    db_session.add_all([agg(domain, "203.0.113.9", "spoof", 25), agg(domain, "203.0.113.10", "unauth", 5)])
    db_session.add(ReportedEmail(id=uuid.uuid4(), tenant_id=tenant.id, original_subject="Acme Financial", urls_found=["https://acmefinancial-secure.com"]))
    await db_session.commit()
    rows = await _scan(db_session, monkeypatch, profile, tenant)
    assert rows["acmefinancial-secure.com"].enrichment["spoofer_ips_checked"] == 2
