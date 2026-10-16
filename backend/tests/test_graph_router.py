import uuid

from app.models import CloudAccountConnection, CloudPrivEscPath, Engagement
from app.services.advisor_service import _advisor_cache, _advisor_fingerprints


def setup_function():
    _advisor_cache.clear()
    _advisor_fingerprints.clear()


async def test_graph_endpoint_returns_empty_shape_for_fresh_tenant(auth_client):
    client, _tenant = auth_client
    resp = await client.get("/graph")
    assert resp.status_code == 200
    body = resp.json()
    assert body["nodes"] == []
    assert body["edges"] == []
    assert body["last_analyzed"] is None


async def test_graph_endpoint_returns_real_privesc_data(auth_client, db_session):
    client, tenant = auth_client
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123", status="connected",
    )
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add_all([connection, engagement])
    await db_session.flush()

    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/ec2-deploy-role",
        target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical",
    )
    db_session.add(path)
    await db_session.commit()

    resp = await client.get("/graph")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["nodes"]) == 2
    assert len(body["edges"]) == 1
    assert body["edges"][0]["attack_techniques"][0]["id"] == "T1548.005"


async def test_graph_endpoint_requires_auth(client):
    resp = await client.get("/graph")
    assert resp.status_code == 401


# ── GET /graph/insight — Phase 39c fingerprint-gated AI Analyst ────────────

async def test_graph_insight_returns_a_real_result(auth_client, monkeypatch):
    client, _tenant = auth_client
    import app.routers.graph as graph_router

    async def _fake_insight(**kwargs):
        return {"message": "test insight", "commend": False, "citations": [], "is_ai": False, "model": ""}
    monkeypatch.setattr(graph_router, "generate_graph_insight", _fake_insight)

    resp = await client.get("/graph/insight")
    assert resp.status_code == 200
    assert resp.json()["message"] == "test insight"


async def test_graph_insight_skips_the_llm_call_when_nothing_changed(auth_client, monkeypatch):
    client, _tenant = auth_client
    import app.routers.graph as graph_router

    calls = []

    async def _fake_insight(**kwargs):
        calls.append(1)
        return {"message": f"call {len(calls)}", "commend": False, "citations": [], "is_ai": False, "model": ""}
    monkeypatch.setattr(graph_router, "generate_graph_insight", _fake_insight)

    first = await client.get("/graph/insight")
    second = await client.get("/graph/insight")
    assert len(calls) == 1  # second call reused the cached result — nothing in the graph changed
    assert first.json() == second.json()


async def test_graph_insight_force_bypasses_the_unchanged_guard(auth_client, monkeypatch):
    client, _tenant = auth_client
    import app.routers.graph as graph_router

    calls = []

    async def _fake_insight(**kwargs):
        calls.append(1)
        return {"message": f"call {len(calls)}", "commend": False, "citations": [], "is_ai": False, "model": ""}
    monkeypatch.setattr(graph_router, "generate_graph_insight", _fake_insight)

    await client.get("/graph/insight")
    await client.get("/graph/insight?force=true")
    assert len(calls) == 2  # force always regenerates, even with unchanged data


async def test_graph_insight_recomputes_when_the_graph_actually_changes(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    import app.routers.graph as graph_router

    calls = []

    async def _fake_insight(**kwargs):
        calls.append(kwargs.get("open_path_count"))
        return {"message": "x", "commend": False, "citations": [], "is_ai": False, "model": ""}
    monkeypatch.setattr(graph_router, "generate_graph_insight", _fake_insight)

    await client.get("/graph/insight")  # 0 open paths

    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123", status="connected",
    )
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add_all([connection, engagement])
    await db_session.flush()
    db_session.add(CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/new", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="high",
    ))
    await db_session.commit()

    await client.get("/graph/insight")  # now 1 open path — real change, must regenerate
    assert calls == [0, 1]


async def test_graph_insight_requires_auth(client):
    resp = await client.get("/graph/insight")
    assert resp.status_code == 401


# ── GET /graph/fix-verification — the real, re-scan-verified "closed" state ──

async def test_fix_verification_endpoint_returns_empty_for_fresh_tenant(auth_client):
    client, _tenant = auth_client
    resp = await client.get("/graph/fix-verification")
    assert resp.status_code == 200
    body = resp.json()
    assert body["verifications"] == []
    assert body["is_ai"] is False


async def test_fix_verification_endpoint_returns_real_closed_data(auth_client, db_session):
    client, tenant = auth_client
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123", status="connected",
    )
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add_all([connection, engagement])
    await db_session.flush()
    db_session.add(CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/a", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical",
        policy_arn="arn:aws:iam::123456789012:policy/leaky", policy_name="leaky",
        status="retest_closed",
    ))
    await db_session.commit()

    resp = await client.get("/graph/fix-verification")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["verifications"]) == 1
    assert body["verifications"][0]["closed_count"] == 1
    assert body["verifications"][0]["fully_closed"] is True


async def test_fix_verification_skips_the_llm_call_when_nothing_changed(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    import app.routers.graph as graph_router

    calls = []

    async def _fake_summary(verifications):
        calls.append(1)
        return {"message": f"call {len(calls)}", "is_ai": False, "model": ""}
    monkeypatch.setattr(graph_router, "generate_fix_verification_summary", _fake_summary)

    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123", status="connected",
    )
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add_all([connection, engagement])
    await db_session.flush()
    db_session.add(CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/a", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical",
        policy_arn="arn:aws:iam::123456789012:policy/leaky", policy_name="leaky",
        status="retest_closed",
    ))
    await db_session.commit()

    first = await client.get("/graph/fix-verification")
    second = await client.get("/graph/fix-verification")
    assert len(calls) == 1
    assert first.json()["message"] == second.json()["message"]


async def test_fix_verification_endpoint_requires_auth(client):
    resp = await client.get("/graph/fix-verification")
    assert resp.status_code == 401
