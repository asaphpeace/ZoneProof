"""
Unit tests for prospect_assessment_service.py — no real network. Each real
DNS/HTTPS primitive it reuses (check_dmarc_dns/fetch_spf_record/
parse_spf_record/check_mta_sts_dns/fetch_mta_sts_policy) is monkeypatched
at the module's own imported name (same "from X import Y binds a local
name" rule this codebase has hit before — monkeypatch svc.check_dmarc_dns,
not dmarc_service.check_dmarc_dns).

This replaced a version of Prospect Assessment that fabricated a score
from a checksum of the domain string — these tests assert the score now
traces to real, mockable signals instead.
"""
from app.services import prospect_assessment_service as svc


def _dmarc(exists, policy=None):
    return {"exists": exists, "record": f"v=DMARC1; p={policy}" if exists else None, "policy": policy, "error": None}


def _mta_sts_dns(exists):
    return {"exists": exists, "record": "v=STSv1; id=1" if exists else None, "error": None}


async def test_strong_domain_scores_well_and_reports_real_evidence(monkeypatch):
    async def fake_dmarc(d):
        return _dmarc(True, "reject")

    async def fake_spf(d):
        return "v=spf1 include:_spf.example.com -all"

    def fake_parse_spf(r):
        return (["include:_spf.example.com"], "-all")

    async def fake_mta_sts_dns(d):
        return _mta_sts_dns(True)

    async def fake_mta_sts_policy(d):
        return {"reachable": True, "mode": "enforce", "raw": "...", "error": None}

    monkeypatch.setattr(svc, "check_dmarc_dns", fake_dmarc)
    monkeypatch.setattr(svc, "fetch_spf_record", fake_spf)
    monkeypatch.setattr(svc, "parse_spf_record", fake_parse_spf)
    monkeypatch.setattr(svc, "check_mta_sts_dns", fake_mta_sts_dns)
    monkeypatch.setattr(svc, "fetch_mta_sts_policy", fake_mta_sts_policy)

    result = await svc.assess_domain("strong.example.com")

    assert result["domain"] == "strong.example.com"
    # reject (40) + enforce (20) = 60/100 — real signal, but honestly
    # capped below A/B since dmarc_comp/tls_pass_pct/cert data are only
    # available with a connected account, not guessed from outside.
    assert result["score"] == 60
    assert result["grade"] == "C"
    dmarc_check = next(c for c in result["checks"] if "DMARC" in c["label"])
    assert dmarc_check["found"] is True
    assert "p=reject" in dmarc_check["detail"]
    spf_check = next(c for c in result["checks"] if "SPF" in c["label"])
    assert spf_check["found"] is True
    assert "-all" in spf_check["detail"]
    mta_check = next(c for c in result["checks"] if "MTA-STS" in c["label"])
    assert "enforce" in mta_check["detail"]


async def test_domain_with_nothing_configured_scores_zero_and_says_so(monkeypatch):
    async def fake_dmarc(d):
        return _dmarc(False)

    async def fake_spf(d):
        return None

    async def fake_mta_sts_dns(d):
        return _mta_sts_dns(False)

    monkeypatch.setattr(svc, "check_dmarc_dns", fake_dmarc)
    monkeypatch.setattr(svc, "fetch_spf_record", fake_spf)
    monkeypatch.setattr(svc, "check_mta_sts_dns", fake_mta_sts_dns)

    result = await svc.assess_domain("nothing-configured.example.com")

    assert result["grade"] == "F"
    assert result["score"] == 0
    assert all(c["found"] is False for c in result["checks"])
    assert "No DMARC record found" in result["checks"][0]["detail"]


async def test_never_fabricates_cloud_or_identity_signals(monkeypatch):
    async def fake_dmarc(d):
        return _dmarc(True, "quarantine")

    async def fake_spf(d):
        return None

    async def fake_mta_sts_dns(d):
        return _mta_sts_dns(False)

    monkeypatch.setattr(svc, "check_dmarc_dns", fake_dmarc)
    monkeypatch.setattr(svc, "fetch_spf_record", fake_spf)
    monkeypatch.setattr(svc, "check_mta_sts_dns", fake_mta_sts_dns)

    result = await svc.assess_domain("partial.example.com")

    assert result["not_assessed"] == [
        "Cloud Misconfiguration Defense",
        "Third-Party OAuth App Risk",
        "Identity & Credential Hygiene",
    ]
    # The real signals never touch these categories at all — no field
    # named after them appears carrying an invented number.
    assert not any("Cloud" in c["label"] or "Identity" in c["label"] for c in result["checks"])


async def test_score_is_deterministic_from_real_inputs_not_domain_name(monkeypatch):
    # The bug this replaced: score = hash(domain_string). Prove two
    # different domain names with identical real signals get an
    # identical score — the domain name itself must not affect scoring.
    async def fake_dmarc(d):
        return _dmarc(True, "quarantine")

    async def fake_spf(d):
        return "v=spf1 -all"

    def fake_parse_spf(r):
        return ([], "-all")

    async def fake_mta_sts_dns(d):
        return _mta_sts_dns(False)

    monkeypatch.setattr(svc, "check_dmarc_dns", fake_dmarc)
    monkeypatch.setattr(svc, "fetch_spf_record", fake_spf)
    monkeypatch.setattr(svc, "parse_spf_record", fake_parse_spf)
    monkeypatch.setattr(svc, "check_mta_sts_dns", fake_mta_sts_dns)

    result_a = await svc.assess_domain("aaaaaaaa.example.com")
    result_b = await svc.assess_domain("zzzzzzzzzzzzzzzzzz.example.com")

    assert result_a["score"] == result_b["score"]
    assert result_a["grade"] == result_b["grade"]
