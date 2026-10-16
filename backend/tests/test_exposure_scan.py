"""
Router-level tests for POST /domains/{id}/exposure-scan — the consent-gate
wiring (auto-created 'exposure' Engagement, ownership_verified requirement,
Finding persistence) rather than the detection logic itself (see
test_exposure_scan_service.py for that).
"""
from app.services import exposure_scan_service as svc
from tests.factories import make_domain


async def test_exposure_scan_rejects_unverified_domain(auth_client, db_session):
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="unverified.example.com")
    await db_session.commit()

    resp = await client.post(f"/domains/{domain.id}/exposure-scan")
    assert resp.status_code == 400


async def test_exposure_scan_runs_and_persists_findings(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="verified.example.com")
    domain.ownership_verified = True
    await db_session.commit()

    async def fake_discover_subdomains(db, domain, allow_active=False):
        return []

    async def fake_check_takeover(hostnames):
        return [{"hostname": "blog.verified.example.com", "cname_target": "old.herokuapp.com", "provider_suffix": "herokuapp.com", "fingerprint": "no such app"}]

    async def fake_check_ports(host):
        return [{"port": 3306, "service": "MySQL"}]

    monkeypatch.setattr(svc, "discover_subdomains", fake_discover_subdomains)
    monkeypatch.setattr(svc, "check_subdomain_takeover", fake_check_takeover)
    monkeypatch.setattr(svc, "check_open_ports", fake_check_ports)

    resp = await client.post(f"/domains/{domain.id}/exposure-scan")
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 2
    assert {f["tier"] for f in findings} == {"exposure"}
    severities = {f["check_id"]: f["severity"] for f in findings}
    assert severities["EXPOSURE-SUBDOMAIN-TAKEOVER-blog.verified.example.com"] == "critical"
    assert severities["EXPOSURE-OPEN-PORT-3306"] == "high"

    # discovered_at must be populated on the objects returned directly from
    # the scan pass (no extra fetch), not just on a subsequent fresh query.
    assert all(f["discovered_at"] for f in findings)


async def test_exposure_scan_reuses_the_same_engagement_across_scans(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="repeat.example.com")
    domain.ownership_verified = True
    await db_session.commit()

    monkeypatch.setattr(svc, "discover_subdomains", lambda db, domain, allow_active=False: _empty())
    monkeypatch.setattr(svc, "check_subdomain_takeover", lambda hostnames: _empty())
    monkeypatch.setattr(svc, "check_open_ports", lambda host: _empty())

    first = await client.post(f"/domains/{domain.id}/exposure-scan")
    second = await client.post(f"/domains/{domain.id}/exposure-scan")
    assert first.status_code == 200
    assert second.status_code == 200

    engagements_resp = await client.get("/engagements")
    exposure_engagements = [e for e in engagements_resp.json() if e["tier"] == "exposure"]
    assert len(exposure_engagements) == 1


async def _empty():
    return []


async def test_exposure_scan_does_not_duplicate_a_persistent_finding_on_rescan(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="persistent-port.example.com")
    domain.ownership_verified = True
    await db_session.commit()

    monkeypatch.setattr(svc, "discover_subdomains", lambda db, domain, allow_active=False: _empty())
    monkeypatch.setattr(svc, "check_subdomain_takeover", lambda hostnames: _empty())

    async def fake_open_port(host):
        return [{"port": 3306, "service": "MySQL"}]

    monkeypatch.setattr(svc, "check_open_ports", fake_open_port)

    first = await client.post(f"/domains/{domain.id}/exposure-scan")
    assert len(first.json()) == 1

    second = await client.post(f"/domains/{domain.id}/exposure-scan")
    assert second.json() == []  # still open, not re-inserted

    engagements_resp = await client.get("/engagements")
    engagement_id = next(e["id"] for e in engagements_resp.json() if e["tier"] == "exposure")
    findings_resp = await client.get(f"/engagements/{engagement_id}/findings")
    assert len(findings_resp.json()) == 1


async def test_exposure_scan_marks_a_resolved_finding_remediated(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="fixed-port.example.com")
    domain.ownership_verified = True
    await db_session.commit()

    monkeypatch.setattr(svc, "discover_subdomains", lambda db, domain, allow_active=False: _empty())
    monkeypatch.setattr(svc, "check_subdomain_takeover", lambda hostnames: _empty())

    async def fake_open_port(host):
        return [{"port": 3306, "service": "MySQL"}]

    monkeypatch.setattr(svc, "check_open_ports", fake_open_port)
    await client.post(f"/domains/{domain.id}/exposure-scan")

    monkeypatch.setattr(svc, "check_open_ports", lambda host: _empty())
    second = await client.post(f"/domains/{domain.id}/exposure-scan")
    assert second.json() == []

    engagements_resp = await client.get("/engagements")
    engagement_id = next(e["id"] for e in engagements_resp.json() if e["tier"] == "exposure")
    findings_resp = await client.get(f"/engagements/{engagement_id}/findings")
    findings = findings_resp.json()
    assert len(findings) == 1
    assert findings[0]["status"] == "remediated"


async def test_exposure_scan_findings_visible_via_engagement_findings_endpoint(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="listed.example.com")
    domain.ownership_verified = True
    await db_session.commit()

    async def fake_takeover(hostnames):
        return [{"hostname": "old.listed.example.com", "cname_target": "x.herokuapp.com", "provider_suffix": "herokuapp.com", "fingerprint": "no such app"}]

    monkeypatch.setattr(svc, "discover_subdomains", lambda db, domain, allow_active=False: _empty())
    monkeypatch.setattr(svc, "check_subdomain_takeover", fake_takeover)
    monkeypatch.setattr(svc, "check_open_ports", lambda host: _empty())

    await client.post(f"/domains/{domain.id}/exposure-scan")

    engagements_resp = await client.get("/engagements")
    exposure_engagement = next(e for e in engagements_resp.json() if e["tier"] == "exposure")

    findings_resp = await client.get(f"/engagements/{exposure_engagement['id']}/findings")
    assert findings_resp.status_code == 200
    assert len(findings_resp.json()) == 1


async def test_exposure_scan_is_rate_limited(auth_client, db_session, monkeypatch):
    """This endpoint makes real outbound DNS/HTTP/socket calls to whatever a
    tenant's domain resolves to — unlimited retries would be both an abuse
    vector (unsolicited scanning traffic from Sentinel's own IP) and an
    uncapped cost. Limit is 3/minute per BUILD_PLAN.md's exposure router."""
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="ratelimited.example.com")
    domain.ownership_verified = True
    await db_session.commit()

    monkeypatch.setattr(svc, "discover_subdomains", lambda db, domain, allow_active=False: _empty())
    monkeypatch.setattr(svc, "check_subdomain_takeover", lambda hostnames: _empty())
    monkeypatch.setattr(svc, "check_open_ports", lambda host: _empty())

    statuses = [
        (await client.post(f"/domains/{domain.id}/exposure-scan")).status_code
        for _ in range(4)
    ]
    assert statuses[:3] == [200, 200, 200]
    assert statuses[3] == 429
