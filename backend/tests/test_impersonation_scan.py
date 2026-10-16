"""
Router-level tests for POST /domains/{id}/impersonation-scan — the
consent-gate wiring (auto-created 'impersonation' Engagement,
ownership_verified requirement, test_recipient_email handling) rather than
the detection logic itself (see test_impersonation_scan_service.py).
"""
from app.services import impersonation_scan_service as svc
from tests.factories import make_domain


async def test_impersonation_scan_rejects_unverified_domain(auth_client, db_session):
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="unverified.example.com")
    await db_session.commit()

    resp = await client.post(
        f"/domains/{domain.id}/impersonation-scan", json={"test_recipient_email": "security@example.com"},
    )
    assert resp.status_code == 400


async def test_impersonation_scan_requires_test_recipient_email_on_first_call(auth_client, db_session):
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="verified.example.com")
    domain.ownership_verified = True
    await db_session.commit()

    resp = await client.post(f"/domains/{domain.id}/impersonation-scan", json={})
    assert resp.status_code == 400


async def test_impersonation_scan_runs_and_persists_findings(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="verified.example.com")
    domain.ownership_verified = True
    await db_session.commit()

    async def fake_lookalike(domain_name):
        return [{"domain": "verifled.example.com", "record_type": "MX"}]

    async def fake_spoof(domain_name, recipient):
        return {"outcome": "blocked", "detail": "rejected by DMARC"}

    monkeypatch.setattr(svc, "check_lookalike_domains", fake_lookalike)
    monkeypatch.setattr(svc, "send_spoof_test", fake_spoof)

    resp = await client.post(
        f"/domains/{domain.id}/impersonation-scan", json={"test_recipient_email": "security@verified.example.com"},
    )
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    assert findings[0]["tier"] == "impersonation"
    assert findings[0]["severity"] == "high"


async def test_impersonation_scan_reuses_the_same_engagement_across_scans(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="repeat.example.com")
    domain.ownership_verified = True
    await db_session.commit()

    monkeypatch.setattr(svc, "check_lookalike_domains", lambda d: _empty())
    monkeypatch.setattr(svc, "send_spoof_test", lambda d, r: _blocked())

    first = await client.post(
        f"/domains/{domain.id}/impersonation-scan", json={"test_recipient_email": "security@repeat.example.com"},
    )
    second = await client.post(f"/domains/{domain.id}/impersonation-scan", json={})
    assert first.status_code == 200
    assert second.status_code == 200

    engagements_resp = await client.get("/engagements")
    impersonation_engagements = [e for e in engagements_resp.json() if e["tier"] == "impersonation"]
    assert len(impersonation_engagements) == 1


async def _empty():
    return []


async def _blocked():
    return {"outcome": "blocked", "detail": "rejected"}


async def test_impersonation_scan_is_rate_limited(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="ratelimited.example.com")
    domain.ownership_verified = True
    await db_session.commit()

    monkeypatch.setattr(svc, "check_lookalike_domains", lambda d: _empty())
    monkeypatch.setattr(svc, "send_spoof_test", lambda d, r: _blocked())

    statuses = []
    for i in range(4):
        resp = await client.post(
            f"/domains/{domain.id}/impersonation-scan",
            json={"test_recipient_email": "security@ratelimited.example.com"} if i == 0 else {},
        )
        statuses.append(resp.status_code)
    assert statuses[:3] == [200, 200, 200]
    assert statuses[3] == 429
