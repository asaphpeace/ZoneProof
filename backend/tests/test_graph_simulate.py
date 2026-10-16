"""
Simulate-the-Fix (Coverage Map plan Phase 6) — POST /graph/simulate. A pure
hypothetical read: given a policy (or specific path ids) to "fix", which
currently-open CloudPrivEscPath rows would close? Keyed on policy_arn (real
data already captured from Cloudsplaining, Phase 1) so one shared
over-permissioned policy attached to several principals correctly fans out
to every path it causes — not a 1:1 guess.
"""
import uuid

from app.models import CloudAccountConnection, CloudPrivEscPath, Engagement
from app.services.graph_service import simulate_fix
from tests.factories import make_tenant


async def _make_connection_and_engagement(db_session, tenant):
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123", status="connected",
    )
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add_all([connection, engagement])
    await db_session.flush()
    return connection, engagement


async def _make_path(db_session, tenant, engagement, connection, **overrides):
    defaults = dict(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/a",
        target_principal_arn="account-admin", technique_chain=["iam:PassRole"], severity="high",
        status="open",
    )
    defaults.update(overrides)
    path = CloudPrivEscPath(**defaults)
    db_session.add(path)
    await db_session.flush()
    return path


async def test_simulate_fix_by_policy_arn_closes_every_path_sharing_it(db_session):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    shared_policy = "arn:aws:iam::123456789012:policy/over-permissioned"
    await _make_path(db_session, tenant, engagement, connection, source_principal_arn="arn:aws:iam::123456789012:role/a", policy_arn=shared_policy)
    await _make_path(db_session, tenant, engagement, connection, source_principal_arn="arn:aws:iam::123456789012:role/b", policy_arn=shared_policy)
    await _make_path(db_session, tenant, engagement, connection, source_principal_arn="arn:aws:iam::123456789012:role/c", policy_arn="arn:aws:iam::123456789012:policy/unrelated")
    await db_session.commit()

    result = await simulate_fix(db_session, tenant.id, policy_arns=[shared_policy], priv_esc_path_ids=[])
    assert len(result) == 2
    assert {p.source_principal_arn for p in result} == {
        "arn:aws:iam::123456789012:role/a", "arn:aws:iam::123456789012:role/b",
    }


async def test_simulate_fix_by_path_id_works_when_no_policy_arn_resolved(db_session):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    path = await _make_path(db_session, tenant, engagement, connection, policy_arn=None)
    await db_session.commit()

    result = await simulate_fix(db_session, tenant.id, policy_arns=[], priv_esc_path_ids=[str(path.id)])
    assert len(result) == 1
    assert result[0].id == path.id


async def test_simulate_fix_never_includes_a_closed_path(db_session):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    policy = "arn:aws:iam::123456789012:policy/fixed-already"
    await _make_path(db_session, tenant, engagement, connection, policy_arn=policy, status="retest_closed")
    await db_session.commit()

    result = await simulate_fix(db_session, tenant.id, policy_arns=[policy], priv_esc_path_ids=[])
    assert result == []


async def test_simulate_fix_is_scoped_to_tenant(db_session):
    tenant_a = await make_tenant(db_session, name="Tenant A")
    tenant_b = await make_tenant(db_session, name="Tenant B")
    connection_a, engagement_a = await _make_connection_and_engagement(db_session, tenant_a)
    policy = "arn:aws:iam::123456789012:policy/shared-name-different-tenant"
    await _make_path(db_session, tenant_a, engagement_a, connection_a, policy_arn=policy)
    await db_session.commit()

    result = await simulate_fix(db_session, tenant_b.id, policy_arns=[policy], priv_esc_path_ids=[])
    assert result == []


async def test_simulate_fix_endpoint_returns_real_data(auth_client, db_session):
    client, tenant = auth_client
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    policy = "arn:aws:iam::123456789012:policy/leaky"
    await _make_path(db_session, tenant, engagement, connection, policy_arn=policy)
    await db_session.commit()

    resp = await client.post("/graph/simulate", json={"policy_arns": [policy], "priv_esc_path_ids": []})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["would_close"]) == 1
    assert body["would_close"][0]["policy_arn"] == policy


async def test_simulate_fix_endpoint_includes_attack_techniques(auth_client, db_session):
    client, tenant = auth_client
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    policy = "arn:aws:iam::123456789012:policy/leaky"
    await _make_path(db_session, tenant, engagement, connection, policy_arn=policy, technique_chain=["iam:PassRole"])
    await db_session.commit()

    resp = await client.post("/graph/simulate", json={"policy_arns": [policy], "priv_esc_path_ids": []})
    body = resp.json()
    assert len(body["would_close"]) == 1
    techniques = body["would_close"][0]["attack_techniques"]
    assert len(techniques) > 0
    assert techniques[0]["id"]


async def test_simulate_fix_endpoint_includes_remediation(auth_client, db_session):
    client, tenant = auth_client
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    policy = "arn:aws:iam::123456789012:policy/leaky"
    await _make_path(db_session, tenant, engagement, connection, policy_arn=policy, technique_chain=["iam:CreateAccessKey"])
    await db_session.commit()

    resp = await client.post("/graph/simulate", json={"policy_arns": [policy], "priv_esc_path_ids": []})
    body = resp.json()
    assert len(body["would_close"]) == 1
    assert "createaccesskey" in body["would_close"][0]["remediation"].lower()


async def test_simulate_fix_endpoint_requires_auth(client):
    resp = await client.post("/graph/simulate", json={"policy_arns": [], "priv_esc_path_ids": []})
    assert resp.status_code == 401


async def test_simulate_fix_endpoint_empty_request_returns_nothing(auth_client):
    client, _tenant = auth_client
    resp = await client.post("/graph/simulate", json={})
    assert resp.status_code == 200
    assert resp.json()["would_close"] == []
