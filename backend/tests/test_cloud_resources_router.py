"""
Cloud Resource Explorer endpoints (Phase 38d) — GET /cloud-connections/
{id}/resources and its detail route. Connections/assets/findings are
seeded directly against the DB (the full connect->verify->scan flow is
already covered elsewhere) since these tests are about the read-side
aggregation, not the scan pipeline.
"""
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CloudAccountConnection, CloudAsset, Engagement, Finding
from tests.factories import make_tenant, make_user


async def _make_connection_and_engagement(db_session: AsyncSession, tenant_id):
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant_id, tier="cloud", status="active")
    db_session.add(engagement)
    await db_session.flush()
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant_id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123",
        status="connected", engagement_id=engagement.id,
    )
    db_session.add(connection)
    await db_session.flush()
    return connection, engagement


async def test_list_resources_returns_real_assets_with_finding_summary(auth_client, db_session: AsyncSession):
    client, tenant = auth_client
    connection, engagement = await _make_connection_and_engagement(db_session, tenant.id)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-aaa",
        region="us-east-1", resource_metadata={"tags": {"Name": "web-1"}, "prowler_status": "fail"},
    )
    db_session.add(asset)
    await db_session.flush()
    db_session.add_all([
        Finding(
            id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset.id,
            tier="cloud", severity="high", title="SSH open", status="open", check_id="c1", resource_uid=asset.resource_id,
        ),
        Finding(
            id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset.id,
            tier="cloud", severity="critical", title="RCE risk", status="open", check_id="c2", resource_uid=asset.resource_id,
        ),
        # Remediated — must not count toward the open summary.
        Finding(
            id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset.id,
            tier="cloud", severity="high", title="already fixed", status="remediated", check_id="c3", resource_uid=asset.resource_id,
        ),
    ])
    await db_session.commit()

    resp = await client.get(f"/cloud-connections/{connection.id}/resources")
    assert resp.status_code == 200
    [row] = resp.json()
    assert row["resource_type"] == "ec2_instance"
    assert row["region"] == "us-east-1"
    assert row["tags"] == {"Name": "web-1"}
    assert row["checked_by"] == {"prowler": "fail"}
    assert row["open_findings_count"] == 2
    assert row["worst_open_severity"] == "critical"


async def test_list_resources_filters_by_type_and_region(auth_client, db_session: AsyncSession):
    client, tenant = auth_client
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant.id)
    db_session.add_all([
        CloudAsset(
            id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
            resource_type="ec2_instance", resource_id="arn:...:i-aaa", region="us-east-1", resource_metadata={},
        ),
        CloudAsset(
            id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
            resource_type="s3_bucket", resource_id="arn:...:bucket-1", region="us-east-1", resource_metadata={},
        ),
        CloudAsset(
            id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
            resource_type="ec2_instance", resource_id="arn:...:i-bbb", region="eu-north-1", resource_metadata={},
        ),
    ])
    await db_session.commit()

    resp = await client.get(f"/cloud-connections/{connection.id}/resources?resource_type=ec2_instance&region=us-east-1")
    assert resp.status_code == 200
    [row] = resp.json()
    assert row["resource_id"] == "arn:...:i-aaa"


async def test_list_resources_empty_for_a_connection_with_none_yet(auth_client, db_session: AsyncSession):
    client, tenant = auth_client
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant.id)
    await db_session.commit()

    resp = await client.get(f"/cloud-connections/{connection.id}/resources")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_list_resources_404s_for_unknown_connection(auth_client):
    client, _tenant = auth_client
    resp = await client.get(f"/cloud-connections/{uuid.uuid4()}/resources")
    assert resp.status_code == 404


async def test_get_resource_detail_includes_tags_and_findings(auth_client, db_session: AsyncSession):
    client, tenant = auth_client
    connection, engagement = await _make_connection_and_engagement(db_session, tenant.id)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="iam_user", resource_id="arn:aws:iam::123456789012:user/alice",
        resource_metadata={"tags": {}, "credential_status": "fail"},
    )
    db_session.add(asset)
    await db_session.flush()
    finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset.id,
        tier="credential", severity="high", title="no MFA", status="open",
        check_id="credential_report_mfa_missing", resource_uid=asset.resource_id,
    )
    db_session.add(finding)
    await db_session.commit()

    resp = await client.get(f"/cloud-connections/{connection.id}/resources/{asset.id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["resource_id"] == "arn:aws:iam::123456789012:user/alice"
    assert body["checked_by"] == {"credential": "fail"}
    assert len(body["findings"]) == 1
    assert body["findings"][0]["title"] == "no MFA"


async def test_get_resource_detail_includes_a_collapsed_finding_via_affected_resources(auth_client, db_session: AsyncSession):
    # A collapsed multi-region Finding has asset_id=None (can't honestly
    # point at just one resource) but still lists this resource in
    # affected_resources — it must still show up on that resource's page.
    client, tenant = auth_client
    connection, engagement = await _make_connection_and_engagement(db_session, tenant.id)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="access-analyzer_analyzer", resource_id="arn:aws:access-analyzer:us-east-1:123456789012:analyzer/default",
        resource_metadata={},
    )
    db_session.add(asset)
    await db_session.flush()
    collapsed_finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=None,
        tier="cloud", severity="low", title="Analyzer not enabled", status="open",
        check_id="iam_access_analyzer_enabled",
        resource_uid="arn:aws:access-analyzer:*:123456789012:analyzer/default",
        occurrence_count=2,
        affected_resources=[
            "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/default",
            "arn:aws:access-analyzer:eu-west-1:123456789012:analyzer/default",
        ],
    )
    db_session.add(collapsed_finding)
    await db_session.commit()

    resp = await client.get(f"/cloud-connections/{connection.id}/resources/{asset.id}")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["findings"]) == 1
    assert body["findings"][0]["title"] == "Analyzer not enabled"


async def test_get_resource_detail_404s_for_unknown_asset(auth_client, db_session: AsyncSession):
    client, tenant = auth_client
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant.id)
    await db_session.commit()

    resp = await client.get(f"/cloud-connections/{connection.id}/resources/{uuid.uuid4()}")
    assert resp.status_code == 404


async def test_resources_are_isolated_by_tenant(auth_client, client, db_session: AsyncSession):
    owner_client, owner_tenant = auth_client
    connection, _engagement = await _make_connection_and_engagement(db_session, owner_tenant.id)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=owner_tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:...:i-aaa", resource_metadata={},
    )
    db_session.add(asset)
    await db_session.commit()

    other_tenant = await make_tenant(db_session, name="Other Workspace")
    await make_user(db_session, other_tenant, email="other-resources@example.com", password="pass123")
    await db_session.flush()
    login = await client.post(
        "/auth/token",
        data={"username": "other-resources@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    other_client = client
    other_client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    resp = await other_client.get(f"/cloud-connections/{connection.id}/resources")
    assert resp.status_code == 404


# ── PATCH /cloud-connections/{id}/resources/{asset_id}/high-value ──────────

async def test_update_resource_high_value_sets_the_manual_override(auth_client, db_session: AsyncSession):
    client, tenant = auth_client
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant.id)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="s3_bucket", resource_id="arn:aws:s3:::my-bucket", resource_metadata={},
        is_high_value=False,
    )
    db_session.add(asset)
    await db_session.commit()

    resp = await client.patch(
        f"/cloud-connections/{connection.id}/resources/{asset.id}/high-value", json={"is_high_value": True},
    )
    assert resp.status_code == 200
    assert resp.json()["is_high_value"] is True
    assert resp.json()["high_value_set_at"]

    await db_session.refresh(asset)
    assert asset.high_value_set_by_user_id is not None


async def test_update_resource_high_value_is_audit_logged(auth_client, db_session: AsyncSession):
    client, tenant = auth_client
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant.id)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="s3_bucket", resource_id="arn:aws:s3:::my-bucket", resource_metadata={},
    )
    db_session.add(asset)
    await db_session.commit()

    await client.patch(f"/cloud-connections/{connection.id}/resources/{asset.id}/high-value", json={"is_high_value": True})

    from sqlalchemy import select
    from app.models.audit_log import AuditLogEntry
    result = await db_session.execute(
        select(AuditLogEntry).where(AuditLogEntry.tenant_id == tenant.id, AuditLogEntry.action == "cloud_asset.high_value_set")
    )
    entry = result.scalars().one()
    assert entry.before == {"is_high_value": None}
    assert entry.after == {"is_high_value": True}


async def test_update_resource_high_value_404s_for_unknown_asset(auth_client, db_session: AsyncSession):
    client, tenant = auth_client
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant.id)
    await db_session.commit()

    resp = await client.patch(
        f"/cloud-connections/{connection.id}/resources/{uuid.uuid4()}/high-value", json={"is_high_value": True},
    )
    assert resp.status_code == 404


async def test_update_resource_high_value_requires_auth(client):
    resp = await client.patch("/cloud-connections/x/resources/y/high-value", json={"is_high_value": True})
    assert resp.status_code == 401
