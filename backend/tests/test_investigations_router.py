import uuid
from datetime import datetime, timezone

from app.models import Actor, Investigation, InvestigationEvent


async def test_list_investigations_returns_empty_for_fresh_tenant(auth_client):
    client, _tenant = auth_client
    resp = await client.get("/investigations")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_list_investigations_excludes_dismissed_by_default(auth_client, db_session):
    client, tenant = auth_client
    actor = Actor(id=uuid.uuid4(), tenant_id=tenant.id, email="jane@example.com")
    db_session.add(actor)
    await db_session.flush()

    open_inv = Investigation(id=uuid.uuid4(), tenant_id=tenant.id, actor_id=actor.id, status="confirmed")
    dismissed_inv = Investigation(
        id=uuid.uuid4(), tenant_id=tenant.id, actor_id=actor.id, status="confirmed",
        dismissed_at=datetime.now(timezone.utc),
    )
    db_session.add_all([open_inv, dismissed_inv])
    await db_session.commit()

    resp = await client.get("/investigations")
    assert resp.status_code == 200
    ids = {i["id"] for i in resp.json()}
    assert ids == {str(open_inv.id)}

    resp = await client.get("/investigations?include_dismissed=true")
    ids = {i["id"] for i in resp.json()}
    assert ids == {str(open_inv.id), str(dismissed_inv.id)}


async def test_get_investigation_detail_includes_timeline_and_attack_techniques(auth_client, db_session):
    client, tenant = auth_client
    actor = Actor(id=uuid.uuid4(), tenant_id=tenant.id, email="jane@example.com")
    db_session.add(actor)
    await db_session.flush()

    investigation = Investigation(id=uuid.uuid4(), tenant_id=tenant.id, actor_id=actor.id, status="confirmed")
    db_session.add(investigation)
    await db_session.flush()

    event = InvestigationEvent(
        id=uuid.uuid4(), tenant_id=tenant.id, investigation_id=investigation.id,
        source="cloudtrail", event_id="evt-1", action_or_event_type="iam:PassRole",
        occurred_at=datetime.now(timezone.utc), raw_detail="{}",
    )
    db_session.add(event)
    await db_session.commit()

    resp = await client.get(f"/investigations/{investigation.id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["actor"]["email"] == "jane@example.com"
    assert len(body["events"]) == 1
    assert body["events"][0]["action_or_event_type"] == "iam:PassRole"
    assert body["events"][0]["attack_techniques"][0]["id"] == "T1548.005"


async def test_get_investigation_404_for_unknown_id(auth_client):
    client, _tenant = auth_client
    resp = await client.get(f"/investigations/{uuid.uuid4()}")
    assert resp.status_code == 404


async def test_dismiss_investigation_sets_dismissed_fields(auth_client, db_session):
    client, tenant = auth_client
    actor = Actor(id=uuid.uuid4(), tenant_id=tenant.id, email="jane@example.com")
    db_session.add(actor)
    await db_session.flush()

    investigation = Investigation(id=uuid.uuid4(), tenant_id=tenant.id, actor_id=actor.id, status="confirmed")
    db_session.add(investigation)
    await db_session.commit()

    resp = await client.post(f"/investigations/{investigation.id}/dismiss")
    assert resp.status_code == 200
    assert resp.json()["dismissed_at"] is not None

    resp = await client.post(f"/investigations/{investigation.id}/dismiss")
    assert resp.status_code == 400


async def test_investigations_require_auth(client):
    resp = await client.get("/investigations")
    assert resp.status_code == 401
