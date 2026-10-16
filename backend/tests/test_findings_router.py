"""
GET /findings — the real tenant-wide fix for a bug pattern found three
times this session (SimulateFixView/GraphView/FindingsView.vue each
reinventing their own "loop over the right engagements" logic and getting
it wrong at least once). One call, every finding, each labeled with its
real connection (hostname for host, account/role for cloud) — resolved
here server-side, not guessed per screen.
"""
import uuid

from app.models import CloudAccountConnection, Engagement, Finding, HostConnection
from tests.factories import make_tenant


async def _make_cloud(db_session, tenant, role_arn="arn:aws:iam::111111111111:role/LiveVerifyA"):
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws", role_arn=role_arn,
        external_id="ext-1", status="connected", engagement_id=engagement.id,
    )
    db_session.add_all([engagement, connection])
    await db_session.flush()
    return engagement, connection


async def _make_host(db_session, tenant, hostname="203.0.113.10"):
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="host", status="active")
    connection = HostConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, hostname_or_ip=hostname, ssh_port=22, ssh_username="sentinel-audit",
        status="connected", public_key_fingerprint="SHA256:fake", engagement_id=engagement.id,
        encrypted_private_key="fake-encrypted-key", public_key="ssh-ed25519 fake",
    )
    db_session.add_all([engagement, connection])
    await db_session.flush()
    return engagement, connection


def _make_finding(tenant, engagement, tier, resource_uid=None, severity="high", check_id="test-check"):
    return Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, tier=tier,
        severity=severity, title=f"Test finding ({tier})", status="open",
        check_id=check_id, resource_uid=resource_uid,
    )


async def test_findings_endpoint_aggregates_across_every_connection(auth_client, db_session):
    """The real bug this endpoint exists to fix: a tenant with 2 connected
    hosts (each its own engagement) must see BOTH hosts' findings in one
    call, not just the first — the exact thing FindingsView.vue's old
    loadHostMergedFindings() got wrong."""
    client, tenant = auth_client
    cloud_eng, cloud_conn = await _make_cloud(db_session, tenant)
    host_eng_a, host_conn_a = await _make_host(db_session, tenant, hostname="10.0.0.1")
    host_eng_b, host_conn_b = await _make_host(db_session, tenant, hostname="10.0.0.2")

    db_session.add_all([
        _make_finding(tenant, cloud_eng, "cloud", resource_uid="arn:aws:s3:::bucket-a"),
        _make_finding(tenant, host_eng_a, "host", resource_uid="10.0.0.1"),
        _make_finding(tenant, host_eng_b, "host", resource_uid="10.0.0.2"),
    ])
    await db_session.commit()

    resp = await client.get("/findings")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["findings"]) == 3
    by_resource = {f["resource_uid"]: f for f in body["findings"]}
    assert by_resource["10.0.0.1"]["connection_label"] == "10.0.0.1"
    assert by_resource["10.0.0.1"]["connection_id"] == str(host_conn_a.id)
    assert by_resource["10.0.0.2"]["connection_label"] == "10.0.0.2"
    assert by_resource["10.0.0.2"]["connection_id"] == str(host_conn_b.id)
    assert by_resource["arn:aws:s3:::bucket-a"]["connection_label"] == "111111111111 · LiveVerifyA"


async def test_findings_endpoint_uses_display_name_when_set(auth_client, db_session):
    """The one piece of "environment" identity nothing in AWS/SSH data can
    supply — connection_label (the derived technical identity) must stay
    present even when a display_name is set, never replaced, so nothing
    the account/host really is gets hidden behind a human label that could
    be wrong or stale."""
    client, tenant = auth_client
    host_eng, host_conn = await _make_host(db_session, tenant, hostname="10.0.0.1")
    host_conn.display_name = "Mail server — Production"
    cloud_eng, cloud_conn = await _make_cloud(db_session, tenant)
    db_session.add_all([
        _make_finding(tenant, host_eng, "host", resource_uid="10.0.0.1"),
        _make_finding(tenant, cloud_eng, "cloud", resource_uid="arn:aws:s3:::bucket-a", check_id="other-check"),
    ])
    await db_session.commit()

    resp = await client.get("/findings")
    body = resp.json()
    by_resource = {f["resource_uid"]: f for f in body["findings"]}
    assert by_resource["10.0.0.1"]["connection_display_name"] == "Mail server — Production"
    assert by_resource["10.0.0.1"]["connection_label"] == "10.0.0.1"  # still the real technical identity
    assert by_resource["arn:aws:s3:::bucket-a"]["connection_display_name"] is None  # never renamed, never guessed

    by_id = {c["id"]: c for c in body["connections"]}
    assert by_id[str(host_conn.id)]["display_name"] == "Mail server — Production"


async def test_findings_endpoint_surfaces_real_resource_tags(auth_client, db_session):
    """Real tags, read live from CloudAsset (kept current on every scan) —
    not from Finding.extra, which can be permanently stale for a finding
    created before tag capture existed (the same staleness class of bug
    already fixed for asset_id in finding_reconciliation.py)."""
    from app.models import CloudAsset

    client, tenant = auth_client
    cloud_eng, cloud_conn = await _make_cloud(db_session, tenant)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=cloud_conn.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:eu-north-1:111111111111:instance/i-real",
        resource_metadata={"tags": {"Name": "SEDAC-DEV"}},
    )
    tagged_finding = _make_finding(tenant, cloud_eng, "cloud", resource_uid="arn:aws:ec2:eu-north-1:111111111111:instance/i-real")
    tagged_finding.asset_id = asset.id
    untagged_finding = _make_finding(tenant, cloud_eng, "cloud", resource_uid="arn:aws:s3:::bucket-a", check_id="other-check")
    db_session.add_all([asset, tagged_finding, untagged_finding])
    await db_session.commit()

    resp = await client.get("/findings")
    body = resp.json()
    by_resource = {f["resource_uid"]: f for f in body["findings"]}
    assert by_resource["arn:aws:ec2:eu-north-1:111111111111:instance/i-real"]["resource_tags"] == {"Name": "SEDAC-DEV"}
    assert by_resource["arn:aws:s3:::bucket-a"]["resource_tags"] == {}  # no asset_id link — honestly empty, not guessed


async def test_findings_endpoint_connections_catalog_includes_unscanned_connections(auth_client, db_session):
    """A freshly connected host with zero findings yet must still be a
    real, selectable filter option — not just inferable from findings that
    already exist."""
    client, tenant = auth_client
    await _make_host(db_session, tenant, hostname="10.0.0.5")
    await db_session.commit()

    resp = await client.get("/findings")
    body = resp.json()
    assert body["findings"] == []
    assert len(body["connections"]) == 1
    assert body["connections"][0] == {
        "id": body["connections"][0]["id"], "tier": "host", "label": "10.0.0.5", "display_name": None,
    }


async def test_findings_endpoint_filters_by_connection_id(auth_client, db_session):
    client, tenant = auth_client
    host_eng_a, host_conn_a = await _make_host(db_session, tenant, hostname="10.0.0.1")
    host_eng_b, host_conn_b = await _make_host(db_session, tenant, hostname="10.0.0.2")
    db_session.add_all([
        _make_finding(tenant, host_eng_a, "host", resource_uid="10.0.0.1"),
        _make_finding(tenant, host_eng_b, "host", resource_uid="10.0.0.2"),
    ])
    await db_session.commit()

    resp = await client.get(f"/findings?connection_id={host_conn_a.id}")
    body = resp.json()
    assert len(body["findings"]) == 1
    assert body["findings"][0]["resource_uid"] == "10.0.0.1"


async def test_findings_endpoint_filters_by_tier_and_severity(auth_client, db_session):
    client, tenant = auth_client
    cloud_eng, _ = await _make_cloud(db_session, tenant)
    host_eng, _ = await _make_host(db_session, tenant)
    db_session.add_all([
        _make_finding(tenant, cloud_eng, "cloud", severity="critical"),
        _make_finding(tenant, cloud_eng, "cloud", severity="low"),
        _make_finding(tenant, host_eng, "host", resource_uid="203.0.113.10", severity="critical"),
    ])
    await db_session.commit()

    resp = await client.get("/findings?tier=cloud")
    assert len(resp.json()["findings"]) == 2

    resp = await client.get("/findings?tier=cloud&severity=critical")
    assert len(resp.json()["findings"]) == 1


async def test_findings_endpoint_scoped_to_tenant(auth_client, db_session):
    client, tenant = auth_client
    other_tenant = await make_tenant(db_session, name="Other Tenant")
    other_eng, _ = await _make_host(db_session, other_tenant, hostname="10.0.0.99")
    db_session.add(_make_finding(other_tenant, other_eng, "host", resource_uid="10.0.0.99"))
    await db_session.commit()

    resp = await client.get("/findings")
    assert resp.json()["findings"] == []
    assert resp.json()["connections"] == []


async def test_findings_endpoint_requires_auth(client):
    resp = await client.get("/findings")
    assert resp.status_code == 401
