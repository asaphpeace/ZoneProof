"""
Step 2.4 — registration, certificate, hosting and campaign signals:
RDAP details (registrar, re-registration), the cheap-suffix prior, certificate timing, free-hosting CNAMEs, certificate ids
from the CT source, campaign clustering (registration batch / shared certificate / nameservers / server) with its benign
guard, the shared registration cache carrying the extras, and the scan pipeline end to end.

NOT claimed: weights are hand-set and abuse scoring cannot be measured offline. The suffix prior alone was checked against
the corpus (15.3% of suspected phishing hosts vs 7.2% of popular domains).
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import BrandCandidate, BrandProfile, BrandRegistrationCache, CandidateEvidence
from app.services import brand_guard_service as svc
from app.services import brand_infra_signals as infra
from app.services import brand_sources as sources
from app.services.brand_scoring_service import assess_candidate
from app.services.domain_age_service import RegistrationInfo, parse_rdap
from tests.factories import make_domain, make_tenant

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)


# ── RDAP parsing ─────────────────────────────────────────────────────────────

def _rdap(**kw):
    data = {
        "events": [
            {"eventAction": "registration", "eventDate": "2026-09-20T10:00:00Z"},
            {"eventAction": "reregistration", "eventDate": "2026-09-21T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2026-09-25T08:30:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-09-20T10:00:00Z"},
        ],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "NameSilo, LLC"]]]}],
    }
    data.update(kw)
    return data


def test_rdap_events_and_registrar_are_parsed():
    info = parse_rdap(_rdap())
    assert info.registered_at == datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc) and info.source == "rdap"
    assert info.reregistered_at == datetime(2026, 9, 21, tzinfo=timezone.utc) and info.registrar == "NameSilo, LLC"
    assert info.last_changed_at.day == 25 and info.expires_at.year == 2027
    assert info.details() == {"registrar": "NameSilo, LLC", "reregistered_at": "2026-09-21T00:00:00+00:00",
                              "last_changed_at": "2026-09-25T08:30:00+00:00", "expires_at": "2027-09-20T10:00:00+00:00"}


def test_rdap_parsing_tolerates_missing_and_malformed_members():
    assert parse_rdap({}).registered_at is None and parse_rdap({}).registrar is None
    assert parse_rdap({"events": ["junk", {"eventAction": "registration"}, {"eventAction": "registration", "eventDate": "not a date"}]}).registered_at is None
    assert parse_rdap({"events": None, "entities": None}).registrar is None
    assert parse_rdap({"entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Someone Else"]]]}]}).registrar is None, "only the registrar entity counts"
    assert parse_rdap({"entities": [{"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "1068"}]}]}).registrar == "IANA registrar 1068"
    assert parse_rdap({"events": [{"eventAction": "Registration", "eventDate": "2026-01-01T00:00:00Z"}]}).registered_at.year == 2026, "action names are case-insensitive"


# ── findings ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("suffix,flagged", [("xyz", True), ("top", True), ("icu", True), ("com", False), ("co.za", False), ("org", False),
                                            ("pages.dev", False), ("com.xyz", False), (None, False), ("", False)])
def test_only_the_inexpensive_suffixes_carry_the_prior(suffix, flagged):
    assert infra.tld_prior(suffix) is flagged


def test_registration_findings_cover_suffix_reregistration_and_registrar():
    f = {x["signal"]: x for x in infra.registration_findings(
        {"registrar": "NameSilo, LLC", "reregistered_at": (NOW - timedelta(days=12)).isoformat()}, "xyz", NOW)}
    assert f["high_abuse_suffix"]["weight"] == 5.0 and f["reregistered"]["weight"] == 10.0 and f["registrar"]["weight"] == 0.0
    assert "NameSilo" in f["registrar"]["summary"] and "12 day" in f["reregistered"]["summary"]


def test_an_old_reregistration_and_a_plain_suffix_score_nothing():
    old = infra.registration_findings({"reregistered_at": (NOW - timedelta(days=infra.REREGISTRATION_WINDOW_DAYS + 1)).isoformat()}, "com", NOW)
    assert old == [] and infra.registration_findings(None, "com", NOW) == []


def test_a_certificate_minutes_after_a_fresh_registration_reads_as_automation():
    reg = NOW - timedelta(days=3)
    f = infra.cert_timing_finding(reg, reg + timedelta(minutes=14), NOW, "Let's Encrypt")
    assert f["weight"] == 8.0 and "14 minute" in f["summary"] and f["data"]["issuer"] == "Let's Encrypt"
    assert "6 hour" in infra.cert_timing_finding(reg, reg + timedelta(hours=6), NOW)["summary"]


@pytest.mark.parametrize("reg_days_ago,cert_after_h", [(3, 30), (3, -2), (200, 1), (3, None)])
def test_certificate_timing_needs_a_fast_certificate_on_a_recent_registration(reg_days_ago, cert_after_h):
    reg = NOW - timedelta(days=reg_days_ago)
    cert = None if cert_after_h is None else reg + timedelta(hours=cert_after_h)
    assert infra.cert_timing_finding(reg, cert, NOW) is None


def test_a_cname_to_a_free_platform_is_a_hosting_signal_only_when_a_platform_was_identified():
    f = infra.hosting_finding("acme.pages.dev", "pages.dev")
    assert f["weight"] == 5.0 and "pages.dev" in f["summary"]
    assert infra.hosting_finding("lb.example.net", None) is None and infra.hosting_finding(None, None) is None


@pytest.mark.parametrize("target,platform", [
    ("www.dpd.co.uk.edgekey.net", "edgekey.net"),            # Akamai: a live scan flagged DPD's own site before this guard
    ("dps.azurewebsites.net", "azurewebsites.net"),          # Azure
    ("d111.cloudfront.net", "cloudfront.net"), ("x.global.ssl.fastly.net", "global.ssl.fastly.net"),
])
def test_a_cname_to_a_cdn_or_cloud_edge_is_not_free_hosting(target, platform):
    assert infra.hosting_finding(target, platform) is None


# ── clusters ─────────────────────────────────────────────────────────────────

def _m(minute=None, **kw):
    base = NOW - timedelta(days=2)
    return infra.ClusterMember(registered_at=None if minute is None else base + timedelta(minutes=minute), **kw)


def test_two_lookalikes_registered_minutes_apart_form_a_batch_and_three_a_bigger_one():
    two = infra.cluster_hints({"a.com": _m(0), "b.com": _m(7), "c.com": _m(900)})
    assert two["a.com"][0]["signal"] == "batch_registered" and two["a.com"][0]["weight"] == infra.WEIGHT_BATCH_PAIR
    assert two["a.com"][0]["siblings"] == ["b.com"] and "c.com" not in two, "a name registered hours later is not in the batch"
    three = infra.cluster_hints({"a.com": _m(0), "b.com": _m(10), "c.com": _m(20)})
    assert three["b.com"][0]["weight"] == infra.WEIGHT_BATCH_MANY and three["b.com"][0]["siblings"] == ["a.com", "c.com"]


def test_the_batch_window_is_thirty_minutes_inclusive():
    assert "a.com" in infra.cluster_hints({"a.com": _m(0), "b.com": _m(30)})
    assert infra.cluster_hints({"a.com": _m(0), "b.com": _m(31)}) == {}


def test_names_with_no_known_registration_time_never_join_a_batch():
    assert infra.cluster_hints({"a.com": _m(None), "b.com": _m(None)}) == {}


def test_a_defensive_batch_is_not_counted_as_evidence_when_any_member_is_the_customers():
    """Owners defend a brand by registering many typos in one sitting. If one member sits on the customer's own
    infrastructure the whole cluster scores nothing and says why."""
    hints = infra.cluster_hints({"a.com": _m(0), "b.com": _m(2, benign=True), "c.com": _m(4)})
    assert all(h["weight"] == 0.0 for found in hints.values() for h in found)
    assert "defensive batch" in hints["a.com"][0]["summary"] and "b.com" in hints["a.com"][0]["summary"]


def test_one_certificate_over_several_lookalikes_is_a_cluster():
    hints = infra.cluster_hints({"a.com": _m(cert_ids=frozenset({"111", "222"})), "b.com": _m(cert_ids=frozenset({"222"})), "c.com": _m(cert_ids=frozenset({"999"}))})
    assert [h["signal"] for h in hints["a.com"]] == ["shared_certificate"] and hints["a.com"][0]["siblings"] == ["b.com"]
    assert "c.com" not in hints


def test_nameserver_clusters_need_three_and_ignore_shared_dns_platforms():
    ns = ("ns1.evil-dns.net", "ns2.evil-dns.net")
    three = {d: _m(ns=ns) for d in ("a.com", "b.com", "c.com")}
    assert all(h[0]["signal"] == "shared_nameservers_cluster" for h in infra.cluster_hints(three).values())
    assert infra.cluster_hints({d: _m(ns=ns) for d in ("a.com", "b.com")}) == {}
    assert infra.cluster_hints({d: _m(ns=ns, shared_ns=True) for d in ("a.com", "b.com", "c.com")}) == {}, "Cloudflare/parking pairs are shared by thousands of unrelated sites"


def test_server_clusters_need_three_and_skip_shared_hosting_addresses():
    three = {d: _m(a=("203.0.113.9",)) for d in ("a.com", "b.com", "c.com")}
    assert all(h[0]["signal"] == "shared_server_cluster" for h in infra.cluster_hints(three).values())
    assert infra.cluster_hints(three, shared_hosting_ips=frozenset({"203.0.113.9"})) == {}
    assert infra.cluster_hints({d: _m(a=("203.0.113.9",)) for d in ("a.com", "b.com")}) == {}


def test_cluster_evidence_is_capped_and_siblings_are_bounded():
    ns = ("n1.x.net", "n2.x.net")
    members = {f"d{i}.com": _m(i, ns=ns, a=("203.0.113.9",), cert_ids=frozenset({"1"})) for i in range(14)}
    hints = infra.cluster_hints(members)["d0.com"]
    assert {h["signal"] for h in hints} == {"batch_registered", "shared_certificate", "shared_nameservers_cluster", "shared_server_cluster"}
    assert sum(h["weight"] for h in hints) == pytest.approx(infra.CLUSTER_POSITIVE_CAP, abs=0.3)
    assert all(len(h["siblings"]) <= 8 for h in hints) and hints[0]["size"] == 14


# ── certificate source keeps certificate ids ─────────────────────────────────

class _Resp:
    status_code, headers = 200, {}

    def __init__(self, data):
        self._d = data

    def json(self):
        return self._d


class _Client:
    def __init__(self, data):
        self._data = data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, *a, **k):
        return _Resp(self._data)


async def test_ct_source_records_the_certificate_that_covers_several_registrable_names():
    now = datetime.now(timezone.utc).isoformat()
    data = [{"id": 5551, "entry_timestamp": now, "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
             "name_value": "acme-pay.example\nwww.acme-pay.example\nacme-help.example.net"},
            {"id": 5552, "entry_timestamp": now, "issuer_name": "C=US, O=ZeroSSL", "name_value": "acme-pay.example"}]
    found = await sources.CrtShSource(client_factory=lambda: _Client(data)).fetch(["acmefinancial"], datetime(2020, 1, 1, tzinfo=timezone.utc))
    assert found["acme-pay.example"]["cert_ids"] == ["5551", "5552"]
    assert found["example.net"]["cert_ids"] == ["5551"], "the same certificate id appears under both registrable names — that is the cluster evidence"
    assert found["example.net"]["issuer"].startswith("C=US, O=Let's Encrypt")


async def test_ct_certificate_ids_per_name_are_bounded():
    now = datetime.now(timezone.utc).isoformat()
    data = [{"id": i, "entry_timestamp": now, "name_value": "busy.example"} for i in range(30)]
    found = await sources.CrtShSource(client_factory=lambda: _Client(data)).fetch(["acmefinancial"], datetime(2020, 1, 1, tzinfo=timezone.utc))
    assert len(found["busy.example"]["cert_ids"]) == sources._MAX_CERTS_PER_APEX


# ── scoring ──────────────────────────────────────────────────────────────────

def _assess(cand, **enr):
    return assess_candidate(cand, primary_domain="acmefinancial.co.za", official_domains=[], brand_tokens=["acmefinancial"],
                            discovery_class="combosquat", enrichment=enr, now=NOW)


def test_the_scorer_adds_each_family_as_abuse_evidence():
    reg = NOW - timedelta(days=2)
    a = _assess("acmefinancial-pay.xyz", registered_at=reg.isoformat(), ct_hit=True, ct_cert_issued_at=(reg + timedelta(minutes=20)).isoformat(),
                registration={"registrar": "NameSilo, LLC", "reregistered_at": (NOW - timedelta(days=1)).isoformat()},
                hosting={"cname": "x.pages.dev", "platform": "pages.dev"}, cert_issuer="R3")
    sig = {s.signal: s for s in a.signals}
    assert {"high_abuse_suffix", "reregistered", "registrar", "cert_after_registration", "free_platform_cname"} <= set(sig)
    assert all(sig[k].dimension == "abuse" for k in ("high_abuse_suffix", "reregistered", "cert_after_registration", "free_platform_cname"))
    plain = _assess("acmefinancial-pay.com", registered_at=reg.isoformat())
    assert a.abuse_score - plain.abuse_score == 5 + 10 + 8 + 5 + 10   # suffix + rereg + cert timing + cname + the ordinary new-cert signal for a CT hit


def test_a_hosting_platform_name_does_not_also_get_the_suffix_prior():
    a = _assess("acmefinancial-pay.pages.dev", platform_suffix="pages.dev")
    assert "high_abuse_suffix" not in {s.signal for s in a.signals}
    assert "high_abuse_suffix" not in {s.signal for s in _assess("acmefinancial-pay.co.za").signals}


def test_cluster_hints_in_the_enrichment_become_evidence_with_their_weight_and_siblings():
    hint = {"signal": "batch_registered", "kind": "registration_batch", "weight": 10.0, "size": 3, "siblings": ["x.com", "y.com"],
            "summary": "Registered within 30 minutes of 2 other look-alike(s).", "data": {"kind": "registration_batch", "size": 3, "siblings": ["x.com", "y.com"]}}
    a = _assess("acmefinancial-pay.com", clusters=[hint])
    s = {x.signal: x for x in a.signals}["batch_registered"]
    assert s.weight == 10.0 and s.data["siblings"] == ["x.com", "y.com"]


# ── pipeline ─────────────────────────────────────────────────────────────────

async def _profile(db, fingerprint=None):
    tenant = await make_tenant(db, name=f"T{uuid.uuid4().hex[:6]}", plan="pro")
    domain = await make_domain(db, tenant, name="acmefinancial.co.za")
    domain.ownership_verified = True
    profile = BrandProfile(id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, brand_name="Acme Financial", keywords=[], official_domains=[],
                           fingerprint=fingerprint)
    db.add(profile)
    await db.commit()
    return tenant, profile


LOOKALIKES = ["acmefinancial-pay.co.za", "acmefinancial-help.co.za", "acmefinancial-login.co.za"]


def _install(monkeypatch, *, live, registered_minutes=None, details=None, hosting=None, owner=None, ct=None):
    base = datetime.now(timezone.utc) - timedelta(days=2)

    async def fake_dns(name):
        return live.get(name, {"has_a": False, "has_mx": False, "registered": False, "ns": [], "a": [], "mx": []})

    async def fake_reg(client, domain):
        if domain not in (registered_minutes or {}):
            return None
        when = base + timedelta(minutes=registered_minutes[domain])
        return RegistrationInfo(registered_at=when, source="rdap", registrar=(details or {}).get(domain, {}).get("registrar"),
                                reregistered_at=(details or {}).get(domain, {}).get("reregistered_at"))

    async def fake_hosting(domain):
        return (hosting or {}).get(domain)

    async def fake_owner(ip):
        return owner

    async def fake_ct(db, tokens, since):
        return ct or {}
    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_registration_date", fake_reg)
    monkeypatch.setattr(svc, "_probe_hosting", fake_hosting)
    monkeypatch.setattr(svc, "_ip_owner", fake_owner)
    monkeypatch.setattr(svc, "fetch_ct_candidates", fake_ct)


def _live(names, **extra):
    return {n: {"has_a": True, "has_mx": False, "registered": True, "ns": ["ns1.evil-dns.net", "ns2.evil-dns.net"], "a": ["203.0.113.9"], "mx": [], **extra} for n in names}


async def _evidence(db, domain):
    cand = (await db.execute(select(BrandCandidate).where(BrandCandidate.candidate_domain == domain))).scalar_one()
    rows = (await db.execute(select(CandidateEvidence).where(CandidateEvidence.candidate_id == cand.id))).scalars().all()
    return cand, {e.signal: e for e in rows}


async def test_a_registration_batch_of_lookalikes_is_a_campaign_cluster(db_session, monkeypatch):
    tenant, profile = await _profile(db_session)
    _install(monkeypatch, live=_live(LOOKALIKES), registered_minutes={LOOKALIKES[0]: 0, LOOKALIKES[1]: 4, LOOKALIKES[2]: 9},
             owner={"number": 64500, "name": "SMALL-VPS-PROVIDER, ZA"})
    summary = await svc.scan_profile(db_session, profile, tenant, permutations=True)
    assert summary["cost"]["cluster_members"] == 3
    cand, ev = await _evidence(db_session, LOOKALIKES[0])
    assert {"batch_registered", "shared_nameservers_cluster", "shared_server_cluster"} <= set(ev)
    assert ev["batch_registered"].weight > 0 and set(ev["batch_registered"].data["siblings"]) == set(LOOKALIKES[1:])
    assert cand.enrichment["clusters"] and all(c["size"] == 3 for c in cand.enrichment["clusters"])


async def test_a_registered_name_that_does_not_resemble_the_brand_never_joins_a_cluster(db_session, monkeypatch):
    """Registered permutations that merely exist (an unrelated shop that happens to be a tracked name) must not be pulled into
    a campaign cluster just because they were registered in the same hour."""
    tenant, profile = await _profile(db_session)
    unrelated = "unrelated-flowers.co.za"
    db_session.add(BrandCandidate(id=uuid.uuid4(), tenant_id=tenant.id, profile_id=profile.id, candidate_domain=unrelated, status="monitoring",
                                  first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc)))
    await db_session.commit()
    names = [*LOOKALIKES, unrelated]
    _install(monkeypatch, live=_live(names), registered_minutes={n: i * 2 for i, n in enumerate(names)})
    summary = await svc.scan_profile(db_session, profile, tenant, permutations=True)
    assert summary["cost"]["cluster_members"] == 3
    _, ev = await _evidence(db_session, LOOKALIKES[0])
    assert set(ev["batch_registered"].data["siblings"]) == set(LOOKALIKES[1:]), "the unrelated name is not a sibling"
    _, other = await _evidence(db_session, unrelated)
    assert "batch_registered" not in other


@pytest.mark.parametrize("owner,counts", [
    ({"number": 64500, "name": "SMALL-VPS-PROVIDER, ZA"}, True),     # a known, dedicated network: counts
    ({"number": 13335, "name": "CLOUDFLARENET, US"}, False),        # a CDN: thousands of unrelated sites share it
    (None, False),                                                  # unknown owner: never assumed dedicated
])
async def test_an_address_counts_as_a_cluster_only_when_its_owner_is_known_to_be_dedicated(db_session, monkeypatch, owner, counts):
    tenant, profile = await _profile(db_session)
    # registered hours apart so only the SERVER cluster can fire
    _install(monkeypatch, live=_live(LOOKALIKES), registered_minutes={n: i * 500 for i, n in enumerate(LOOKALIKES)}, owner=owner)
    await svc.scan_profile(db_session, profile, tenant, permutations=True)
    _, ev = await _evidence(db_session, LOOKALIKES[0])
    assert ("shared_server_cluster" in ev) is counts


async def test_a_cluster_touching_the_customers_own_infrastructure_scores_nothing(db_session, monkeypatch):
    tenant, profile = await _profile(db_session, fingerprint={"dns": {"ns": ["ns1.evil-dns.net", "ns2.evil-dns.net"], "a": [], "shared_hosting": False, "shared_nameservers": False}})
    _install(monkeypatch, live=_live(LOOKALIKES), registered_minutes={LOOKALIKES[0]: 0, LOOKALIKES[1]: 4, LOOKALIKES[2]: 9})
    await svc.scan_profile(db_session, profile, tenant, permutations=True)
    _, ev = await _evidence(db_session, LOOKALIKES[1])
    assert "batch_registered" in ev and ev["batch_registered"].weight == 0.0 and "defensive batch" in ev["batch_registered"].summary
    assert "same_nameservers" in ev, "the explainer from step 2.0 is still there"


async def test_registry_details_certificate_timing_and_hosting_flow_through_a_scan(db_session, monkeypatch):
    tenant, profile = await _profile(db_session)
    name = "acmefinancial-pay.xyz"
    reg_minutes = 0
    base = datetime.now(timezone.utc) - timedelta(days=2)
    issued = (base + timedelta(minutes=reg_minutes, hours=1)).isoformat()
    rereg = base + timedelta(hours=-5)
    _install(monkeypatch, live=_live([name]), registered_minutes={name: reg_minutes}, details={name: {"registrar": "NameSilo, LLC", "reregistered_at": rereg}},
             hosting={name: {"cname": "x.pages.dev", "platform": "pages.dev"}}, ct={name: {"issued_at": issued, "cert_ids": ["77"], "issuer": "R3"}})
    await svc.scan_profile(db_session, profile, tenant, permutations=False)
    cand, ev = await _evidence(db_session, name)
    assert {"high_abuse_suffix", "reregistered", "registrar", "cert_after_registration", "free_platform_cname"} <= set(ev)
    assert cand.enrichment["registration"]["registrar"] == "NameSilo, LLC" and cand.enrichment["cert_ids"] == ["77"] and cand.enrichment["cert_issuer"] == "R3"


async def test_registry_details_and_certificate_facts_survive_the_next_scan(db_session, monkeypatch):
    tenant, profile = await _profile(db_session)
    name = "acmefinancial-pay.xyz"
    base = datetime.now(timezone.utc) - timedelta(days=2)
    _install(monkeypatch, live=_live([name]), registered_minutes={name: 0}, details={name: {"registrar": "NameSilo, LLC"}}, ct={name: {"issued_at": base.isoformat(), "cert_ids": ["77"], "issuer": "R3"}})
    await svc.scan_profile(db_session, profile, tenant, permutations=False)
    await db_session.execute(BrandRegistrationCache.__table__.delete())      # so only the candidate's OWN record can answer, not the shared cache
    calls = []

    async def no_registry(client, domain):
        calls.append(domain)
        return None

    async def no_ct(db, tokens, since):
        return {}
    monkeypatch.setattr(svc, "_registration_date", no_registry)
    monkeypatch.setattr(svc, "fetch_ct_candidates", no_ct)
    await svc.scan_profile(db_session, profile, tenant, permutations=False)
    cand = (await db_session.execute(select(BrandCandidate).where(BrandCandidate.candidate_domain == name))).scalar_one()
    assert calls == [], "the registration is already on record, so the registry is not asked again"
    assert cand.enrichment["registration"]["registrar"] == "NameSilo, LLC" and cand.enrichment["cert_ids"] == ["77"]


async def test_the_shared_cache_stores_and_returns_the_registry_extras(db_session):
    when = datetime.now(timezone.utc) - timedelta(days=30)
    await svc._store_registrations(db_session, {"cached.example": when, "missed.example": None}, {"cached.example": {"registrar": "R", "reregistered_at": None}})
    out: dict = {}
    dates = await svc._cached_registrations(db_session, {"cached.example", "missed.example"}, out)
    assert dates["cached.example"] == when and out == {"cached.example": {"registrar": "R", "reregistered_at": None}}
    assert (await db_session.get(BrandRegistrationCache, "missed.example")).details is None
    assert await svc._cached_registrations(db_session, {"cached.example"}) == {"cached.example": when}, "the original two-argument call still works"


async def test_a_bare_datetime_from_a_registration_lookup_is_still_accepted():
    when = datetime.now(timezone.utc)
    assert svc._split_registration(when) == (when, None) and svc._split_registration(None) == (None, None)
    info = RegistrationInfo(registered_at=when, registrar="R")
    assert svc._split_registration(info) == (when, info.details())


async def test_a_candidate_scored_before_2_4_gets_exactly_one_backfill_lookup(db_session, monkeypatch):
    """Rows created before registry details existed have a creation date but never had the registrar read. They are looked up
    ONCE more, then flagged so the registry is not asked again."""
    tenant, profile = await _profile(db_session)
    name = "acmefinancial-pay.co.za"
    when = datetime.now(timezone.utc) - timedelta(days=40)
    db_session.add(BrandCandidate(id=uuid.uuid4(), tenant_id=tenant.id, profile_id=profile.id, candidate_domain=name, status="monitoring",
                                  first_seen_at=when, last_seen_at=when, enrichment={"registered_at": when.isoformat(), "has_a": True}))
    await db_session.commit()
    calls = []

    async def fake_dns(n):
        return {"has_a": True, "has_mx": False, "registered": True, "ns": [], "a": [], "mx": []} if n == name else {"has_a": False, "has_mx": False, "registered": False, "ns": [], "a": [], "mx": []}

    async def fake_reg(client, domain):
        calls.append(domain)
        return RegistrationInfo(registered_at=when, source="rdap", registrar="Backfilled Registrar")

    async def no_ct(db, tokens, since):
        return {}
    monkeypatch.setattr(svc, "_dns_enrich", fake_dns)
    monkeypatch.setattr(svc, "_registration_date", fake_reg)
    monkeypatch.setattr(svc, "fetch_ct_candidates", no_ct)

    await svc.scan_profile(db_session, profile, tenant, permutations=False)
    cand = (await db_session.execute(select(BrandCandidate).where(BrandCandidate.candidate_domain == name))).scalar_one()
    assert calls == [name] and cand.enrichment["registration"]["registrar"] == "Backfilled Registrar" and cand.enrichment["registration_checked"] is True

    await db_session.execute(BrandRegistrationCache.__table__.delete())
    await svc.scan_profile(db_session, profile, tenant, permutations=False)
    assert calls == [name], "flagged, so the registry is not asked a second time"
