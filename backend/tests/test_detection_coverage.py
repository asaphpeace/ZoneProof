"""
Detection Coverage (app/services/detection_coverage_service.py, Coverage Map
plan Phase 4) — per-attack-path verdicts derived from real Prowler findings
(cloudtrail_multi_region_enabled, guardduty_is_enabled), not a fabricated
"would you detect this" guess.
"""
import uuid

from app.models import CloudAccountConnection, CloudPrivEscPath, Engagement, Finding
from app.services.detection_coverage_service import compute_detection_coverage


async def _make_engagement_and_connection(db_session, tenant):
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add(engagement)
    await db_session.flush()
    # connection.engagement_id is real and load-bearing in production
    # (routers/cloud.py's rescan route 400s without it) — wiring it here
    # matches how an activated connection always looks for real, and
    # matters now that detection-coverage posture is joined per-connection
    # rather than computed tenant-wide (Coverage Map roadmap Phase 35b).
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws", engagement_id=engagement.id,
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123", status="connected",
    )
    db_session.add(connection)
    await db_session.flush()
    return connection, engagement


async def _make_path(db_session, tenant, engagement, connection, **overrides):
    defaults = dict(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/ec2-deploy-role",
        target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical",
    )
    defaults.update(overrides)
    path = CloudPrivEscPath(**defaults)
    db_session.add(path)
    await db_session.flush()
    return path


def _make_finding(tenant, engagement, check_id: str) -> Finding:
    return Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=None,
        tier="cloud", severity="medium", title=check_id, status="open", check_id=check_id,
    )


async def test_compute_detection_coverage_is_empty_with_no_priv_esc_paths(db_session):
    from tests.factories import make_tenant
    tenant = await make_tenant(db_session)
    await db_session.flush()
    assert await compute_detection_coverage(db_session, tenant.id) == []


async def test_compute_detection_coverage_is_covered_when_both_controls_pass(db_session):
    from tests.factories import make_tenant
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_engagement_and_connection(db_session, tenant)
    await _make_path(db_session, tenant, engagement, connection)
    await db_session.commit()

    [result] = await compute_detection_coverage(db_session, tenant.id)
    # No FAIL findings for either check exist — Prowler's absence-means-pass
    # convention — so both controls are treated as enabled.
    assert result["verdict"] == "covered"
    assert result["cloudtrail_multi_region_enabled"] is True
    assert result["guardduty_enabled"] is True


async def test_compute_detection_coverage_is_blind_spot_when_cloudtrail_fails(db_session):
    from tests.factories import make_tenant
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_engagement_and_connection(db_session, tenant)
    await _make_path(db_session, tenant, engagement, connection)
    db_session.add(_make_finding(tenant, engagement, "cloudtrail_multi_region_enabled"))
    await db_session.commit()

    [result] = await compute_detection_coverage(db_session, tenant.id)
    assert result["verdict"] == "blind_spot"
    assert result["cloudtrail_multi_region_enabled"] is False


async def test_compute_detection_coverage_is_partial_when_only_guardduty_fails(db_session):
    from tests.factories import make_tenant
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_engagement_and_connection(db_session, tenant)
    await _make_path(db_session, tenant, engagement, connection)
    db_session.add(_make_finding(tenant, engagement, "guardduty_is_enabled"))
    await db_session.commit()

    [result] = await compute_detection_coverage(db_session, tenant.id)
    assert result["verdict"] == "partial"
    assert result["cloudtrail_multi_region_enabled"] is True
    assert result["guardduty_enabled"] is False


async def test_compute_detection_coverage_covers_every_path(db_session):
    from tests.factories import make_tenant
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_engagement_and_connection(db_session, tenant)
    await _make_path(db_session, tenant, engagement, connection, source_principal_arn="arn:aws:iam::123456789012:role/a")
    await _make_path(db_session, tenant, engagement, connection, source_principal_arn="arn:aws:iam::123456789012:role/b")
    await db_session.commit()

    results = await compute_detection_coverage(db_session, tenant.id)
    assert len(results) == 2


async def test_compute_detection_coverage_does_not_bleed_posture_across_accounts(db_session):
    """Real bugfix regression (Coverage Map roadmap Phase 35b): CloudTrail/
    GuardDuty posture used to be computed once tenant-wide and applied to
    every path, so a tenant with 2+ AWS accounts had one account's posture
    bleed onto every other account's paths. Confirms each path's verdict
    now reflects only its OWN connection's real posture."""
    from tests.factories import make_tenant
    tenant = await make_tenant(db_session)
    conn_a, eng_a = await _make_engagement_and_connection(db_session, tenant)
    conn_b, eng_b = await _make_engagement_and_connection(db_session, tenant)
    path_a = await _make_path(db_session, tenant, eng_a, conn_a, source_principal_arn="arn:aws:iam::111111111111:role/a")
    path_b = await _make_path(db_session, tenant, eng_b, conn_b, source_principal_arn="arn:aws:iam::222222222222:role/b")
    # Only account A's CloudTrail check is failing — account B's posture is clean.
    db_session.add(_make_finding(tenant, eng_a, "cloudtrail_multi_region_enabled"))
    await db_session.commit()

    results = await compute_detection_coverage(db_session, tenant.id)
    by_path_id = {r["priv_esc_path_id"]: r for r in results}
    assert by_path_id[str(path_a.id)]["verdict"] == "blind_spot"
    assert by_path_id[str(path_a.id)]["cloudtrail_multi_region_enabled"] is False
    assert by_path_id[str(path_b.id)]["verdict"] == "covered"
    assert by_path_id[str(path_b.id)]["cloudtrail_multi_region_enabled"] is True
    assert by_path_id[str(path_b.id)]["guardduty_enabled"] is True


async def test_detection_coverage_endpoint_returns_real_verdicts(auth_client, db_session):
    client, tenant = auth_client
    connection, engagement = await _make_engagement_and_connection(db_session, tenant)
    await _make_path(db_session, tenant, engagement, connection)
    db_session.add(_make_finding(tenant, engagement, "cloudtrail_multi_region_enabled"))
    await db_session.commit()

    resp = await client.get("/detection-coverage")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["verdict"] == "blind_spot"
    assert "CloudTrail is not enabled" in body[0]["reason"]


async def test_detection_coverage_endpoint_requires_auth(client):
    resp = await client.get("/detection-coverage")
    assert resp.status_code == 401


async def test_detection_coverage_endpoint_empty_for_fresh_tenant(auth_client):
    client, _tenant = auth_client
    resp = await client.get("/detection-coverage")
    assert resp.status_code == 200
    assert resp.json() == []
