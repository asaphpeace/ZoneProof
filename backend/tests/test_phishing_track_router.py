"""
Router-level tests for the unauthenticated /phishing-track/* endpoints —
these are hit by whoever received the simulation email, never a logged-in
Sentinel user, so they're tested against the plain `client` fixture.
"""
import uuid

from app.models import Engagement, PhishingCampaign, PhishingEvent, PhishingTargetList
from tests.factories import make_tenant


async def _seed_sent_event(db_session) -> str:
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "jane@example.com"}])
    campaign = PhishingCampaign(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        target_list_id=target_list.id, template_id="shared-document", status="complete",
    )
    db_session.add_all([engagement, target_list, campaign])
    await db_session.flush()

    token = "test-token-" + uuid.uuid4().hex
    db_session.add(PhishingEvent(
        id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id,
        recipient_hash="deadbeef", recipient_token=token, event_type="sent",
    ))
    await db_session.commit()
    return token, campaign.id


async def test_pixel_endpoint_returns_a_gif_and_records_an_open(client, db_session):
    token, campaign_id = await _seed_sent_event(db_session)

    resp = await client.get(f"/phishing-track/{token}/pixel.gif")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/gif"

    from sqlalchemy import select
    result = await db_session.execute(select(PhishingEvent).where(PhishingEvent.campaign_id == campaign_id, PhishingEvent.event_type == "opened"))
    event = result.scalars().first()
    assert event is not None
    # Real who/what/when/where/destination evidence (Coverage Map plan
    # Phase 7 addendum) — captured from the request, not fabricated.
    assert event.ip_address is not None
    assert event.destination_url is not None and event.destination_url.endswith("/pixel.gif")


async def test_click_endpoint_returns_landing_page_and_records_a_click(client, db_session):
    token, campaign_id = await _seed_sent_event(db_session)

    resp = await client.get(f"/phishing-track/{token}/click")
    assert resp.status_code == 200
    assert "<form" in resp.text

    from sqlalchemy import select
    result = await db_session.execute(select(PhishingEvent).where(PhishingEvent.campaign_id == campaign_id, PhishingEvent.event_type == "clicked"))
    event = result.scalars().first()
    assert event is not None
    assert event.destination_url is not None and event.destination_url.endswith("/click")


async def test_submit_endpoint_never_reflects_or_stores_submitted_credentials(client, db_session):
    token, campaign_id = await _seed_sent_event(db_session)

    resp = await client.post(f"/phishing-track/{token}/submit", data={"username": "jane", "password": "hunter2"})
    assert resp.status_code == 200
    assert "hunter2" not in resp.text
    assert "jane" not in resp.text or "simulated phishing test" in resp.text  # only the generic notice, not an echo

    from sqlalchemy import select
    result = await db_session.execute(select(PhishingEvent).where(PhishingEvent.campaign_id == campaign_id, PhishingEvent.event_type == "credential_entered"))
    assert result.scalars().first() is not None


async def test_report_endpoint_returns_positive_page_and_records_a_report(client, db_session):
    token, campaign_id = await _seed_sent_event(db_session)

    resp = await client.get(f"/phishing-track/{token}/report")
    assert resp.status_code == 200
    assert "Nice catch" in resp.text

    from sqlalchemy import select
    result = await db_session.execute(select(PhishingEvent).where(PhishingEvent.campaign_id == campaign_id, PhishingEvent.event_type == "reported"))
    event = result.scalars().first()
    assert event is not None
    assert event.destination_url is not None and event.destination_url.endswith("/report")


async def test_lesson_endpoint_renders_after_a_click_and_creates_an_assignment(client, db_session):
    token, campaign_id = await _seed_sent_event(db_session)
    await client.get(f"/phishing-track/{token}/click")

    resp = await client.get(f"/phishing-track/{token}/lesson")
    assert resp.status_code == 200
    assert "SECURITY AWARENESS" in resp.text

    from sqlalchemy import select
    from app.models import TrainingAssignment
    result = await db_session.execute(select(TrainingAssignment).where(TrainingAssignment.campaign_id == campaign_id))
    assignment = result.scalars().first()
    assert assignment is not None
    assert assignment.trigger_event_type == "clicked"


async def test_lesson_respond_endpoint_records_reflection_and_completes(client, db_session):
    token, campaign_id = await _seed_sent_event(db_session)
    await client.get(f"/phishing-track/{token}/click")

    resp = await client.post(f"/phishing-track/{token}/lesson/respond", data={"reflection_response": "urgency"})
    assert resp.status_code == 200
    assert "Thanks" in resp.text

    from sqlalchemy import select
    from app.models import TrainingAssignment
    result = await db_session.execute(select(TrainingAssignment).where(TrainingAssignment.campaign_id == campaign_id))
    assignment = result.scalars().first()
    assert assignment.status == "completed"
    assert assignment.reflection_response == "urgency"


async def test_lesson_endpoints_are_silent_on_an_unknown_token(client):
    resp = await client.get("/phishing-track/completely-made-up-token/lesson")
    assert resp.status_code == 200
    assert "expired" in resp.text.lower()

    resp2 = await client.post("/phishing-track/completely-made-up-token/lesson/respond", data={"reflection_response": "not_sure"})
    assert resp2.status_code == 200


async def test_unknown_token_does_not_error(client):
    resp = await client.get("/phishing-track/completely-made-up-token/pixel.gif")
    assert resp.status_code == 200  # silent no-op, not a 404 that would confirm/deny token validity
