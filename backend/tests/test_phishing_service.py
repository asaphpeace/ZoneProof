"""
Unit tests for phishing_service.py — Tier B's send/track pipeline.
send_email is monkeypatched out (same reasoning as the rest of this
codebase: never hit a real external send in tests) so these assert on the
orchestration/pseudonymization logic itself.
"""
import uuid
from datetime import datetime, timedelta, timezone

from app.models import Engagement, PhishingCampaign, PhishingEvent, PhishingTargetList, TrainingAssignment
from app.services import phishing_service as svc
from tests.factories import make_tenant


def test_hash_recipient_is_deterministic_for_the_same_email_and_tenant():
    tenant_id = uuid.uuid4()
    h1 = svc._hash_recipient("jane@example.com", tenant_id)
    h2 = svc._hash_recipient("Jane@Example.com  ", tenant_id)  # case/whitespace insensitive
    assert h1 == h2


def test_hash_recipient_differs_across_tenants():
    email = "jane@example.com"
    h1 = svc._hash_recipient(email, uuid.uuid4())
    h2 = svc._hash_recipient(email, uuid.uuid4())
    assert h1 != h2


async def test_launch_campaign_creates_sent_events_and_sends_email(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    target_list = PhishingTargetList(
        id=uuid.uuid4(), tenant_id=tenant.id, name="Staff",
        entries=[{"email": "jane@example.com", "display_name": "Jane"}, {"email": "bob@example.com", "display_name": "Bob"}],
    )
    db_session.add_all([engagement, target_list])
    await db_session.commit()

    sent = []
    async def fake_send_email(db, to, subject, body_html):
        sent.append((to, subject))
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    campaign = await svc.launch_campaign(db_session, engagement, target_list, "shared-document")
    assert campaign.status == "complete"
    assert len(sent) == 2
    assert {to for to, _ in sent} == {"jane@example.com", "bob@example.com"}

    from sqlalchemy import select
    result = await db_session.execute(select(PhishingEvent).where(PhishingEvent.campaign_id == campaign.id))
    events = result.scalars().all()
    assert len(events) == 2
    assert all(e.event_type == "sent" for e in events)
    assert len({e.recipient_token for e in events}) == 2  # each recipient gets a distinct token

    await db_session.refresh(engagement)
    assert engagement.last_scan_status == "success"
    assert campaign.body_html_sent is not None
    assert "phishing-track" in campaign.body_html_sent  # the real per-recipient tracking link, not a placeholder


def test_recipient_role_summary_empty_when_no_job_titles():
    assert svc._recipient_role_summary([{"email": "a@x.com"}, {"email": "b@x.com"}]) == ""


def test_recipient_role_summary_describes_coverage_without_naming_individuals():
    entries = [
        {"email": "a@x.com", "job_title": "AP Approver"},
        {"email": "b@x.com", "job_title": "Controller"},
        {"email": "c@x.com"},
    ]
    summary = svc._recipient_role_summary(entries)
    assert "2 of 3" in summary
    assert "AP Approver" in summary and "Controller" in summary
    assert "a@x.com" not in summary  # never leaks identity into the LLM prompt context


def test_render_content_uses_built_in_template_when_no_override():
    subject, body = svc._render_content("shared-document", None, None, "https://track/click", "https://track/report")
    assert subject == svc.BUILT_IN_TEMPLATES["shared-document"]["subject"]
    assert "https://track/click" in body
    assert "https://track/report" in body


def test_render_content_prefers_overrides_when_given():
    subject, body = svc._render_content(
        "shared-document", "Custom subject", "<p>Custom body {click_url}</p>", "https://track/click", "https://track/report",
    )
    assert subject == "Custom subject"
    assert "Custom body" in body
    assert "https://track/click" in body
    assert "https://track/report" in body  # no {report_url} placeholder in the override — must still be appended


def test_render_content_appends_fallback_link_when_click_url_placeholder_missing():
    subject, body = svc._render_content(
        "shared-document", "Custom subject", "<p>Custom body with no placeholder</p>", "https://track/click", "https://track/report",
    )
    assert "https://track/click" in body  # click tracking must survive even a careless edit
    assert "https://track/report" in body  # report tracking must survive too
    assert "Custom body with no placeholder" in body


def test_render_content_substitutes_report_url_placeholder_when_present():
    subject, body = svc._render_content(
        "shared-document", "Custom subject", "<p>Body {click_url} — <a href=\"{report_url}\">report</a></p>",
        "https://track/click", "https://track/report",
    )
    assert "https://track/report" in body
    assert body.count("https://track/report") == 1  # substituted in place, not also appended a second time


def test_generate_qr_data_uri_returns_a_real_scannable_png():
    """Phishing Simulation roadmap Phase 27 — not a stub image; a real PNG
    an actual phone camera can scan (asserted structurally here; a real
    scan is the live-verify step, not this unit test)."""
    import base64
    from PIL import Image
    import io as _io

    data_uri = svc._generate_qr_data_uri("https://track.example.com/phishing-track/abc123/click")
    assert data_uri.startswith("data:image/png;base64,")

    png_bytes = base64.b64decode(data_uri.removeprefix("data:image/png;base64,"))
    assert png_bytes[:8] == b"\x89PNG\r\n\x1a\n"  # real PNG magic number, not a placeholder string

    img = Image.open(_io.BytesIO(png_bytes))
    assert img.format == "PNG"
    assert img.width > 0 and img.height > 0


def test_render_content_embeds_a_real_qr_image_for_the_qr_code_placeholder():
    subject, body = svc._render_content(
        "qr-delivery-scan", None, None, "https://track/click", "https://track/report",
    )
    assert "{qr_code}" not in body  # the literal token must never reach a real recipient
    assert "data:image/png;base64," in body


def test_render_content_qr_encodes_this_exact_recipients_click_url(monkeypatch):
    """The one thing that actually matters: each recipient's QR must encode
    THEIR real tracked click_url, not a shared/generic one — verified via a
    spy on the real generator, matching this codebase's established
    monkeypatch-a-spy testing style (e.g. send_email in other tests)."""
    seen_urls = []
    real_generate = svc._generate_qr_data_uri

    def spy_generate(url):
        seen_urls.append(url)
        return real_generate(url)

    monkeypatch.setattr(svc, "_generate_qr_data_uri", spy_generate)

    svc._render_content(
        "qr-delivery-scan", None, None, "https://track/click/recipient-specific-token", "https://track/report",
    )
    assert seen_urls == ["https://track/click/recipient-specific-token"]


async def test_launch_campaign_sends_custom_content_when_overrides_given(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "jane@example.com"}])
    db_session.add_all([engagement, target_list])
    await db_session.commit()

    sent = []
    async def fake_send_email(db, to, subject, body_html):
        sent.append((subject, body_html))
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    await svc.launch_campaign(
        db_session, engagement, target_list, "shared-document",
        subject_override="Totally custom subject", body_html_override="<p>Totally custom body {click_url}</p>",
    )
    assert len(sent) == 1
    subject, body = sent[0]
    assert subject == "Totally custom subject"
    assert "Totally custom body" in body
    assert "<img src=" in body  # open-tracking pixel still appended regardless of customization


async def test_launch_campaign_rejects_unknown_template(db_session):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[])
    db_session.add_all([engagement, target_list])
    await db_session.commit()

    import pytest
    with pytest.raises(ValueError):
        await svc.launch_campaign(db_session, engagement, target_list, "not-a-real-template")


async def _launch_single_recipient_campaign(db_session, monkeypatch, email="jane@example.com"):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": email}])
    db_session.add_all([engagement, target_list])
    await db_session.commit()

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    campaign = await svc.launch_campaign(db_session, engagement, target_list, "shared-document")

    from sqlalchemy import select
    result = await db_session.execute(select(PhishingEvent).where(PhishingEvent.campaign_id == campaign.id))
    sent_event = result.scalars().first()
    return campaign, sent_event, target_list


async def test_record_open_and_click_and_submit_create_correctly_typed_events(db_session, monkeypatch):
    campaign, sent_event, _ = await _launch_single_recipient_campaign(db_session, monkeypatch)
    token = sent_event.recipient_token

    await svc.record_open(db_session, token)
    html = await svc.record_click(db_session, token)
    assert "submit_url" not in html  # placeholder was substituted, not left literal
    assert "<form" in html

    result_html = await svc.record_credential_submit(db_session, token)
    assert "simulated phishing test" in result_html

    from sqlalchemy import select
    result = await db_session.execute(select(PhishingEvent).where(PhishingEvent.campaign_id == campaign.id))
    events = result.scalars().all()
    types = sorted(e.event_type for e in events)
    assert types == ["clicked", "credential_entered", "opened", "sent"]


async def test_record_report_creates_a_reported_event_with_positive_landing_page(db_session, monkeypatch):
    campaign, sent_event, _ = await _launch_single_recipient_campaign(db_session, monkeypatch)
    token = sent_event.recipient_token

    html = await svc.record_report(db_session, token)
    assert "Nice catch" in html
    assert "simulated phishing test" in html

    from sqlalchemy import select
    result = await db_session.execute(select(PhishingEvent).where(PhishingEvent.campaign_id == campaign.id))
    types = sorted(e.event_type for e in result.scalars().all())
    assert types == ["reported", "sent"]


async def test_tracking_calls_with_an_unknown_token_are_a_silent_no_op(db_session):
    await svc.record_open(db_session, "not-a-real-token")  # must not raise
    html = await svc.record_click(db_session, "not-a-real-token")
    assert "<form" in html  # still returns a plausible landing page, doesn't error
    report_html = await svc.record_report(db_session, "not-a-real-token")
    assert "Nice catch" in report_html  # still returns the page, doesn't error


async def test_record_click_creates_a_training_assignment(db_session, monkeypatch):
    campaign, sent_event, _ = await _launch_single_recipient_campaign(db_session, monkeypatch)
    await svc.record_click(db_session, sent_event.recipient_token)

    from sqlalchemy import select
    result = await db_session.execute(select(TrainingAssignment).where(TrainingAssignment.campaign_id == campaign.id))
    assignment = result.scalars().first()
    assert assignment is not None
    assert assignment.trigger_event_type == "clicked"
    assert assignment.status == "assigned"
    assert assignment.lure_category == "shared-document"


async def test_credential_submit_upgrades_an_existing_clicked_assignment_not_duplicate(db_session, monkeypatch):
    campaign, sent_event, _ = await _launch_single_recipient_campaign(db_session, monkeypatch)
    token = sent_event.recipient_token
    await svc.record_click(db_session, token)
    await svc.record_click(db_session, token)  # a second click must not create a second row
    await svc.record_credential_submit(db_session, token)

    from sqlalchemy import select
    result = await db_session.execute(select(TrainingAssignment).where(TrainingAssignment.campaign_id == campaign.id))
    assignments = result.scalars().all()
    assert len(assignments) == 1  # unique constraint held, upgraded in place
    assert assignments[0].trigger_event_type == "credential_entered"


async def test_lesson_page_cites_a_real_red_flag_actually_present_in_the_sent_body(db_session, monkeypatch):
    _, sent_event, _ = await _launch_single_recipient_campaign(db_session, monkeypatch)
    token = sent_event.recipient_token
    await svc.record_click(db_session, token)

    html = await svc.render_lesson_page(db_session, token)
    assert html is not None
    assert "a colleague" in html.lower() or "sign in to view" in html.lower()


async def test_lesson_page_falls_back_to_generic_flags_when_nothing_matches(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "jane@example.com"}])
    db_session.add_all([engagement, target_list])
    await db_session.commit()

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    campaign = await svc.launch_campaign(
        db_session, engagement, target_list, "shared-document",
        subject_override="Totally custom subject", body_html_override="<p>Totally custom body {click_url}</p>",
    )
    from sqlalchemy import select
    result = await db_session.execute(select(PhishingEvent).where(PhishingEvent.campaign_id == campaign.id))
    sent_event = result.scalars().first()

    html = await svc.render_lesson_page(db_session, sent_event.recipient_token)
    assert html is not None
    assert "shared-document notification that doesn" in html.lower()  # the category's generic_flags text


async def test_record_lesson_response_marks_assignment_completed(db_session, monkeypatch):
    campaign, sent_event, _ = await _launch_single_recipient_campaign(db_session, monkeypatch)
    token = sent_event.recipient_token
    await svc.record_click(db_session, token)

    html = await svc.record_lesson_response(db_session, token, "link_then_credentials")
    assert html is not None
    assert "Thanks" in html

    from sqlalchemy import select
    result = await db_session.execute(select(TrainingAssignment).where(TrainingAssignment.campaign_id == campaign.id))
    assignment = result.scalars().first()
    assert assignment.status == "completed"
    assert assignment.completed_at is not None
    assert assignment.reflection_response == "link_then_credentials"


async def test_lesson_functions_are_silent_on_an_unknown_token(db_session):
    assert await svc.render_lesson_page(db_session, "not-a-real-token") is None
    assert await svc.record_lesson_response(db_session, "not-a-real-token", "not_sure") is None


async def test_launch_campaign_persists_the_chosen_landing_page_id(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "jane@example.com"}])
    db_session.add_all([engagement, target_list])
    await db_session.commit()

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    campaign = await svc.launch_campaign(db_session, engagement, target_list, "shared-document", landing_page_id="it-portal")
    assert campaign.landing_page_id == "it-portal"


async def test_launch_campaign_falls_back_to_default_landing_page_for_an_unknown_id(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "jane@example.com"}])
    db_session.add_all([engagement, target_list])
    await db_session.commit()

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    campaign = await svc.launch_campaign(db_session, engagement, target_list, "shared-document", landing_page_id="not-a-real-page")
    assert campaign.landing_page_id == svc._DEFAULT_LANDING_PAGE_ID


async def test_record_click_renders_the_campaigns_chosen_landing_page_with_real_brand_name(db_session, monkeypatch):
    tenant = await make_tenant(db_session, name="Acme Corp")
    tenant.brand_name = "Acme Corp"
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "jane@example.com"}])
    db_session.add_all([engagement, target_list])
    await db_session.commit()

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    campaign = await svc.launch_campaign(db_session, engagement, target_list, "shared-document", landing_page_id="document-viewer")
    from sqlalchemy import select
    result = await db_session.execute(select(PhishingEvent).where(PhishingEvent.campaign_id == campaign.id))
    sent_event = result.scalars().first()

    html = await svc.record_click(db_session, sent_event.recipient_token)
    assert "Acme Corp" in html
    assert "Sign in to view this document" in html
    assert "{company_name}" not in html  # placeholder actually substituted


async def test_unmask_recipient_matches_current_list_entries(db_session, monkeypatch):
    campaign, sent_event, target_list = await _launch_single_recipient_campaign(db_session, monkeypatch, email="jane@example.com")

    identity = await svc.unmask_recipient(db_session, campaign, sent_event.recipient_hash)
    assert identity == {"email": "jane@example.com", "display_name": None}


async def test_unmask_recipient_returns_none_after_removed_from_current_list(db_session, monkeypatch):
    campaign, sent_event, target_list = await _launch_single_recipient_campaign(db_session, monkeypatch, email="jane@example.com")

    target_list.entries = []  # jane left the company; list was edited before unmask is attempted
    await db_session.commit()

    identity = await svc.unmask_recipient(db_session, campaign, sent_event.recipient_hash)
    assert identity is None


async def test_poll_due_phishing_campaigns_skips_when_not_yet_due(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "a@example.com"}])
    engagement = Engagement(
        id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active",
        scope={"cadence_days": 90, "target_list_id": str(target_list.id), "template_id": "shared-document"},
        last_scanned_at=datetime.now(timezone.utc) - timedelta(days=10),
    )
    db_session.add_all([target_list, engagement])
    await db_session.commit()

    called = []
    async def fake_launch(db, eng, tl, tid, **kwargs):
        called.append(eng.id)
        return PhishingCampaign(id=uuid.uuid4(), tenant_id=eng.tenant_id, engagement_id=eng.id, target_list_id=tl.id, template_id=tid, status="complete")
    monkeypatch.setattr(svc, "launch_campaign", fake_launch)

    count = await svc.poll_due_phishing_campaigns(db_session)
    assert count == 0
    assert called == []


async def test_poll_due_phishing_campaigns_launches_when_cadence_elapsed(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "a@example.com"}])
    engagement = Engagement(
        id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active",
        scope={"cadence_days": 90, "target_list_id": str(target_list.id), "template_id": "shared-document"},
        last_scanned_at=datetime.now(timezone.utc) - timedelta(days=120),
    )
    db_session.add_all([target_list, engagement])
    await db_session.commit()

    called = []
    async def fake_launch(db, eng, tl, tid, **kwargs):
        called.append(eng.id)
        return PhishingCampaign(id=uuid.uuid4(), tenant_id=eng.tenant_id, engagement_id=eng.id, target_list_id=tl.id, template_id=tid, status="complete")
    monkeypatch.setattr(svc, "launch_campaign", fake_launch)

    count = await svc.poll_due_phishing_campaigns(db_session)
    assert count == 1
    assert called == [engagement.id]


async def test_poll_due_phishing_campaigns_skips_a_future_scheduled_start(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "a@example.com"}])
    future = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    engagement = Engagement(
        id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active",
        scope={"cadence_days": 90, "target_list_id": str(target_list.id), "template_id": "shared-document", "scheduled_start_at": future},
    )
    db_session.add_all([target_list, engagement])
    await db_session.commit()

    called = []
    async def fake_launch(db, eng, tl, tid, **kwargs):
        called.append(eng.id)
        return PhishingCampaign(id=uuid.uuid4(), tenant_id=eng.tenant_id, engagement_id=eng.id, target_list_id=tl.id, template_id=tid, status="complete")
    monkeypatch.setattr(svc, "launch_campaign", fake_launch)

    count = await svc.poll_due_phishing_campaigns(db_session)
    assert count == 0
    assert called == []


async def test_poll_due_phishing_campaigns_launches_once_a_scheduled_start_has_passed(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "a@example.com"}])
    past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    engagement = Engagement(
        id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active",
        scope={"cadence_days": 90, "target_list_id": str(target_list.id), "template_id": "shared-document", "scheduled_start_at": past},
    )
    db_session.add_all([target_list, engagement])
    await db_session.commit()

    called = []
    async def fake_launch(db, eng, tl, tid, **kwargs):
        called.append(eng.id)
        return PhishingCampaign(id=uuid.uuid4(), tenant_id=eng.tenant_id, engagement_id=eng.id, target_list_id=tl.id, template_id=tid, status="complete")
    monkeypatch.setattr(svc, "launch_campaign", fake_launch)

    count = await svc.poll_due_phishing_campaigns(db_session)
    assert count == 1
    assert called == [engagement.id]


async def test_poll_due_phishing_campaigns_never_repeats_a_one_time_engagement(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "a@example.com"}])
    engagement = Engagement(
        id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active",
        scope={"cadence_days": 1, "target_list_id": str(target_list.id), "template_id": "shared-document", "recurring": False},
        last_scanned_at=datetime.now(timezone.utc) - timedelta(days=30),  # long past cadence, but already sent once
    )
    db_session.add_all([target_list, engagement])
    await db_session.commit()

    called = []
    async def fake_launch(db, eng, tl, tid, **kwargs):
        called.append(eng.id)
        return PhishingCampaign(id=uuid.uuid4(), tenant_id=eng.tenant_id, engagement_id=eng.id, target_list_id=tl.id, template_id=tid, status="complete")
    monkeypatch.setattr(svc, "launch_campaign", fake_launch)

    count = await svc.poll_due_phishing_campaigns(db_session)
    assert count == 0
    assert called == []


async def test_poll_due_phishing_campaigns_launches_a_one_time_engagement_on_its_first_cycle(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "a@example.com"}])
    engagement = Engagement(
        id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active",
        scope={"cadence_days": 90, "target_list_id": str(target_list.id), "template_id": "shared-document", "recurring": False},
        last_scanned_at=None,  # never sent yet
    )
    db_session.add_all([target_list, engagement])
    await db_session.commit()

    called = []
    async def fake_launch(db, eng, tl, tid, **kwargs):
        called.append(eng.id)
        return PhishingCampaign(id=uuid.uuid4(), tenant_id=eng.tenant_id, engagement_id=eng.id, target_list_id=tl.id, template_id=tid, status="complete")
    monkeypatch.setattr(svc, "launch_campaign", fake_launch)

    count = await svc.poll_due_phishing_campaigns(db_session)
    assert count == 1
    assert called == [engagement.id]


async def test_poll_due_phishing_campaigns_skips_when_tenant_has_halted_sends(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    tenant.phishing_paused = True
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "a@example.com"}])
    engagement = Engagement(
        id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active",
        scope={"cadence_days": 90, "target_list_id": str(target_list.id), "template_id": "shared-document"},
        last_scanned_at=datetime.now(timezone.utc) - timedelta(days=120),
    )
    db_session.add_all([target_list, engagement])
    await db_session.commit()

    called = []
    async def fake_launch(db, eng, tl, tid, **kwargs):
        called.append(eng.id)
        return PhishingCampaign(id=uuid.uuid4(), tenant_id=eng.tenant_id, engagement_id=eng.id, target_list_id=tl.id, template_id=tid, status="complete")
    monkeypatch.setattr(svc, "launch_campaign", fake_launch)

    count = await svc.poll_due_phishing_campaigns(db_session)
    assert count == 0
    assert called == []


async def test_poll_due_phishing_campaigns_skips_engagements_missing_scope_fields(db_session):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    db_session.add(engagement)
    await db_session.commit()

    count = await svc.poll_due_phishing_campaigns(db_session)
    assert count == 0


# ── compute_tenant_human_risk_score (Coverage Map plan phishing
# transformation, Phase 9) ───────────────────────────────────────────────────

async def _make_phishing_campaign(db_session, tenant):
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "a@example.com"}])
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    db_session.add_all([target_list, engagement])
    await db_session.flush()
    campaign = PhishingCampaign(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        target_list_id=target_list.id, template_id="shared-document", status="complete",
    )
    db_session.add(campaign)
    await db_session.flush()
    return campaign


def _add_events(db_session, tenant, campaign, *event_types):
    for i, event_type in enumerate(event_types):
        db_session.add(PhishingEvent(
            id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id,
            recipient_hash=f"hash-{i}", recipient_token=f"token-{i}", event_type=event_type,
        ))


def _add_training(db_session, tenant, campaign, recipient_hash, status):
    db_session.add(TrainingAssignment(
        id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id,
        recipient_hash=recipient_hash, lure_category="shared-document",
        trigger_event_type="clicked", status=status,
    ))


async def test_compute_tenant_human_risk_score_returns_none_with_no_campaign_history(db_session):
    tenant = await make_tenant(db_session)
    await db_session.commit()

    score = await svc.compute_tenant_human_risk_score(db_session, tenant.id)
    assert score is None


async def test_compute_tenant_human_risk_score_is_perfect_when_everyone_reports_and_nobody_clicks(db_session):
    tenant = await make_tenant(db_session)
    campaign = await _make_phishing_campaign(db_session, tenant)
    _add_events(db_session, tenant, campaign, "sent", "sent", "reported", "reported")
    await db_session.commit()

    score = await svc.compute_tenant_human_risk_score(db_session, tenant.id)
    assert score == 100.0  # report bonus clamps at the ceiling, never exceeds it


async def test_compute_tenant_human_risk_score_penalizes_credential_entry_far_more_than_a_bare_click(db_session):
    tenant_clicked = await make_tenant(db_session, name="Clicked Only")
    campaign_clicked = await _make_phishing_campaign(db_session, tenant_clicked)
    _add_events(db_session, tenant_clicked, campaign_clicked, "sent", "clicked")

    tenant_creds = await make_tenant(db_session, name="Gave Up Creds")
    campaign_creds = await _make_phishing_campaign(db_session, tenant_creds)
    _add_events(db_session, tenant_creds, campaign_creds, "sent", "clicked", "credential_entered")
    await db_session.commit()

    click_score = await svc.compute_tenant_human_risk_score(db_session, tenant_clicked.id)
    creds_score = await svc.compute_tenant_human_risk_score(db_session, tenant_creds.id)
    assert creds_score < click_score


async def test_compute_tenant_human_risk_score_penalizes_incomplete_assigned_training(db_session):
    tenant_completed = await make_tenant(db_session, name="Finished Training")
    campaign_completed = await _make_phishing_campaign(db_session, tenant_completed)
    _add_events(db_session, tenant_completed, campaign_completed, "sent", "clicked")
    _add_training(db_session, tenant_completed, campaign_completed, "hash-1", "completed")

    tenant_incomplete = await make_tenant(db_session, name="Never Finished")
    campaign_incomplete = await _make_phishing_campaign(db_session, tenant_incomplete)
    _add_events(db_session, tenant_incomplete, campaign_incomplete, "sent", "clicked")
    _add_training(db_session, tenant_incomplete, campaign_incomplete, "hash-1", "assigned")
    await db_session.commit()

    completed_score = await svc.compute_tenant_human_risk_score(db_session, tenant_completed.id)
    incomplete_score = await svc.compute_tenant_human_risk_score(db_session, tenant_incomplete.id)
    assert incomplete_score < completed_score


async def test_compute_tenant_human_risk_score_never_goes_below_zero(db_session):
    tenant = await make_tenant(db_session)
    campaign = await _make_phishing_campaign(db_session, tenant)
    _add_events(db_session, tenant, campaign, "sent", "credential_entered", "credential_entered")
    await db_session.commit()

    score = await svc.compute_tenant_human_risk_score(db_session, tenant.id)
    assert score is not None
    assert 0.0 <= score <= 100.0


# ── compute_human_risk_components (Phishing Simulation roadmap Phase 30a) ───

def test_compute_human_risk_components_are_all_honestly_empty_with_no_summary():
    components = svc.compute_human_risk_components(None, None)
    labels = [c["label"] for c in components]
    assert labels == ["Click & Credential Resistance", "Reporting Behavior", "Training Completion", "Culture"]
    assert all(c["score"] is None and c["grade"] is None for c in components)


def test_compute_human_risk_components_culture_is_independent_of_phishing_summary():
    # A tenant can have real survey data even with zero phishing campaigns
    # ever launched — Culture must reflect that real data regardless of
    # whether the other three components have anything to show.
    components = svc.compute_human_risk_components(None, 80.0)
    culture = next(c for c in components if c["label"] == "Culture")
    assert culture["score"] == 80.0
    assert culture["grade"] == "B"
    others = [c for c in components if c["label"] != "Culture"]
    assert all(c["score"] is None for c in others)


def test_compute_human_risk_components_resistance_uses_the_same_real_penalty_weights():
    summary = {
        "click_rate": 0.2, "credential_rate": 0.1, "report_rate": 0.5,
        "training_completion_rate": 1.0,
    }
    components = svc.compute_human_risk_components(summary, None)
    resistance = next(c for c in components if c["label"] == "Click & Credential Resistance")
    # 100 - (0.2*30) - (0.1*60) = 100 - 6 - 6 = 88 — the exact same
    # _HUMAN_RISK_CLICK_PENALTY/_HUMAN_RISK_CREDENTIAL_PENALTY constants
    # already used to blend the single score, not new invented weights.
    assert resistance["score"] == 88.0
    assert resistance["grade"] == "B"


def test_compute_human_risk_components_reporting_and_training_are_direct_percentages():
    summary = {"click_rate": 0.0, "credential_rate": 0.0, "report_rate": 0.4, "training_completion_rate": 0.75}
    components = svc.compute_human_risk_components(summary, None)
    reporting = next(c for c in components if c["label"] == "Reporting Behavior")
    training = next(c for c in components if c["label"] == "Training Completion")
    assert reporting["score"] == 40.0
    assert training["score"] == 75.0
    assert training["grade"] == "B"  # 75 is exactly the B threshold (_score_to_grade: B >= 75)


def test_compute_human_risk_components_training_stays_honestly_empty_when_nothing_assigned():
    summary = {"click_rate": 0.0, "credential_rate": 0.0, "report_rate": 0.0, "training_completion_rate": None}
    components = svc.compute_human_risk_components(summary, None)
    training = next(c for c in components if c["label"] == "Training Completion")
    assert training["score"] is None
    assert training["grade"] is None


def test_compute_human_risk_components_resistance_floors_at_the_worst_realistic_case():
    # Real rates are always 0-1, so the worst case (everyone clicked AND
    # entered credentials) is 100 - 30 - 60 = 10 — never negative, but the
    # max(0.0, ...) clamp exists defensively for the arithmetic, not
    # because real inputs can drive it past zero.
    summary = {"click_rate": 1.0, "credential_rate": 1.0, "report_rate": 0.0, "training_completion_rate": 1.0}
    components = svc.compute_human_risk_components(summary, None)
    resistance = next(c for c in components if c["label"] == "Click & Credential Resistance")
    assert resistance["score"] == 10.0
    assert resistance["grade"] == "F"


# ── get_tenant_watchlist (Phishing Simulation roadmap Phase 30c) ────────────

async def test_watchlist_is_empty_with_no_risky_history(db_session):
    tenant = await make_tenant(db_session)
    campaign = await _make_phishing_campaign(db_session, tenant)
    _add_events(db_session, tenant, campaign, "sent", "opened")  # never clicked
    await db_session.commit()

    watchlist = await svc.get_tenant_watchlist(db_session, tenant.id)
    assert watchlist == []


async def test_watchlist_ranks_credential_entry_above_a_bare_click(db_session):
    tenant = await make_tenant(db_session)
    campaign = await _make_phishing_campaign(db_session, tenant)
    db_session.add_all([
        PhishingEvent(id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id, recipient_hash="clicker", recipient_token="t1", event_type="sent"),
        PhishingEvent(id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id, recipient_hash="clicker", recipient_token="t1", event_type="clicked"),
        PhishingEvent(id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id, recipient_hash="creds", recipient_token="t2", event_type="sent"),
        PhishingEvent(id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id, recipient_hash="creds", recipient_token="t2", event_type="clicked"),
        PhishingEvent(id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id, recipient_hash="creds", recipient_token="t2", event_type="credential_entered"),
    ])
    await db_session.commit()

    watchlist = await svc.get_tenant_watchlist(db_session, tenant.id)
    assert [w["recipient_hash"] for w in watchlist] == ["creds", "clicker"]


async def test_watchlist_merges_one_recipients_history_across_different_engagements(db_session):
    """The real reason this needs to be tenant-wide, not a repurposed
    per-engagement query: _hash_recipient() is keyed only by tenant, so the
    same real person hashes identically across every engagement — a
    repeat-clicker spread across two separate simulations must show up as
    ONE watchlist entry with both campaigns, not two separate low-risk
    entries that each look harmless alone."""
    tenant = await make_tenant(db_session)
    campaign_a = await _make_phishing_campaign(db_session, tenant)
    campaign_b = await _make_phishing_campaign(db_session, tenant)  # a distinct engagement
    assert campaign_a.engagement_id != campaign_b.engagement_id

    db_session.add_all([
        PhishingEvent(id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign_a.id, recipient_hash="repeat", recipient_token="ta", event_type="sent"),
        PhishingEvent(id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign_a.id, recipient_hash="repeat", recipient_token="ta", event_type="clicked"),
        PhishingEvent(id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign_b.id, recipient_hash="repeat", recipient_token="tb", event_type="sent"),
        PhishingEvent(id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign_b.id, recipient_hash="repeat", recipient_token="tb", event_type="clicked"),
    ])
    await db_session.commit()

    watchlist = await svc.get_tenant_watchlist(db_session, tenant.id)
    assert len(watchlist) == 1
    assert watchlist[0]["recipient_hash"] == "repeat"
    assert watchlist[0]["repeat_click_count"] == 2
    assert len(watchlist[0]["campaigns"]) == 2


async def test_watchlist_is_tenant_isolated(db_session):
    tenant_a = await make_tenant(db_session, name="Tenant A")
    tenant_b = await make_tenant(db_session, name="Tenant B")
    campaign_a = await _make_phishing_campaign(db_session, tenant_a)
    _add_events(db_session, tenant_a, campaign_a, "sent", "clicked", "credential_entered")
    await db_session.commit()

    watchlist_b = await svc.get_tenant_watchlist(db_session, tenant_b.id)
    assert watchlist_b == []


async def test_watchlist_respects_the_limit_and_returns_riskiest_first(db_session):
    tenant = await make_tenant(db_session)
    campaign = await _make_phishing_campaign(db_session, tenant)
    for i in range(3):
        db_session.add(PhishingEvent(
            id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id,
            recipient_hash=f"h{i}", recipient_token=f"t{i}", event_type="sent",
        ))
        db_session.add(PhishingEvent(
            id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id,
            recipient_hash=f"h{i}", recipient_token=f"t{i}", event_type="clicked",
        ))
        if i == 1:  # only h1 also gave up credentials — should rank first despite arriving second
            db_session.add(PhishingEvent(
                id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id,
                recipient_hash="h1", recipient_token="t1", event_type="credential_entered",
            ))
    await db_session.commit()

    watchlist = await svc.get_tenant_watchlist(db_session, tenant.id, limit=2)
    assert len(watchlist) == 2
    assert watchlist[0]["recipient_hash"] == "h1"


async def test_compute_tenant_phishing_summary_returns_none_with_no_campaign_history(db_session):
    tenant = await make_tenant(db_session)
    await db_session.commit()
    assert await svc.compute_tenant_phishing_summary(db_session, tenant.id) is None


async def test_compute_tenant_phishing_summary_reflects_real_rates(db_session):
    tenant = await make_tenant(db_session)
    campaign = await _make_phishing_campaign(db_session, tenant)
    _add_events(db_session, tenant, campaign, "sent", "sent", "sent", "sent", "clicked", "credential_entered", "reported")
    await db_session.commit()

    summary = await svc.compute_tenant_phishing_summary(db_session, tenant.id)
    assert summary["sent"] == 4
    assert summary["click_rate"] == 0.25
    assert summary["credential_rate"] == 0.25
    assert summary["report_rate"] == 0.25
    # Honest None, not a fabricated 100%, when nothing was ever assigned.
    assert summary["training_assigned"] == 0
    assert summary["training_completion_rate"] is None


async def test_compute_tenant_phishing_summary_reports_real_training_completion_rate(db_session):
    tenant = await make_tenant(db_session)
    campaign = await _make_phishing_campaign(db_session, tenant)
    _add_events(db_session, tenant, campaign, "sent", "sent", "clicked", "clicked")
    _add_training(db_session, tenant, campaign, "hash-a", "completed")
    _add_training(db_session, tenant, campaign, "hash-b", "assigned")
    await db_session.commit()

    summary = await svc.compute_tenant_phishing_summary(db_session, tenant.id)
    assert summary["training_assigned"] == 2
    assert summary["training_completed"] == 1
    assert summary["training_completion_rate"] == 0.5


async def test_compute_department_training_completion_reflects_real_counts_across_campaigns(db_session):
    """Tenant-wide, across two separate campaigns/target lists — each
    TrainingAssignment resolved against its own campaign's real list."""
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    finance_list = PhishingTargetList(
        id=uuid.uuid4(), tenant_id=tenant.id, name="Finance List",
        entries=[{"email": "fin1@example.com", "department": "Finance"}, {"email": "fin2@example.com", "department": "Finance"}],
    )
    eng_list = PhishingTargetList(
        id=uuid.uuid4(), tenant_id=tenant.id, name="Eng List",
        entries=[{"email": "eng1@example.com", "department": "Engineering"}],
    )
    db_session.add_all([engagement, finance_list, eng_list])
    await db_session.flush()

    campaign_a = PhishingCampaign(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        target_list_id=finance_list.id, template_id="shared-document", status="complete",
    )
    campaign_b = PhishingCampaign(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        target_list_id=eng_list.id, template_id="shared-document", status="complete",
    )
    db_session.add_all([campaign_a, campaign_b])
    await db_session.flush()

    fin1_hash = svc._hash_recipient("fin1@example.com", tenant.id)
    fin2_hash = svc._hash_recipient("fin2@example.com", tenant.id)
    eng1_hash = svc._hash_recipient("eng1@example.com", tenant.id)
    _add_training(db_session, tenant, campaign_a, fin1_hash, "completed")
    _add_training(db_session, tenant, campaign_a, fin2_hash, "assigned")
    _add_training(db_session, tenant, campaign_b, eng1_hash, "completed")
    await db_session.commit()

    breakdown = {b["department"]: b for b in await svc.compute_department_training_completion(db_session, tenant.id)}
    assert breakdown["Finance"] == {"department": "Finance", "assigned": 2, "completed": 1}
    assert breakdown["Engineering"] == {"department": "Engineering", "assigned": 1, "completed": 1}


async def test_compute_department_training_completion_empty_with_no_history(db_session):
    tenant = await make_tenant(db_session)
    await db_session.commit()
    assert await svc.compute_department_training_completion(db_session, tenant.id) == []


# ── compute_dwell_seconds (Phishing Simulation roadmap Phase 12) ────────────

def _event(event_type: str, occurred_at):
    return PhishingEvent(
        id=uuid.uuid4(), tenant_id=uuid.uuid4(), campaign_id=uuid.uuid4(),
        recipient_hash="h", recipient_token="t", event_type=event_type, occurred_at=occurred_at,
    )


def test_compute_dwell_seconds_returns_none_with_no_open_event():
    now = datetime.now(timezone.utc)
    events = [_event("sent", now), _event("clicked", now + timedelta(seconds=5))]
    assert svc.compute_dwell_seconds(events) is None


def test_compute_dwell_seconds_returns_none_with_no_act_after_open():
    now = datetime.now(timezone.utc)
    events = [_event("sent", now), _event("opened", now + timedelta(seconds=2))]
    assert svc.compute_dwell_seconds(events) is None


def test_compute_dwell_seconds_measures_the_real_gap_between_open_and_click():
    now = datetime.now(timezone.utc)
    events = [
        _event("sent", now),
        _event("opened", now + timedelta(seconds=10)),
        _event("clicked", now + timedelta(seconds=100)),
    ]
    assert svc.compute_dwell_seconds(events) == 90.0


def test_compute_dwell_seconds_uses_first_open_and_first_qualifying_act():
    now = datetime.now(timezone.utc)
    events = [
        _event("opened", now),
        _event("opened", now + timedelta(seconds=30)),  # a second open (e.g. pixel re-fired) — ignored, first wins
        _event("clicked", now + timedelta(seconds=45)),
        _event("credential_entered", now + timedelta(seconds=200)),  # later act — ignored, first wins
    ]
    assert svc.compute_dwell_seconds(events) == 45.0


def test_compute_dwell_seconds_degrades_gracefully_when_the_only_act_precedes_the_open():
    now = datetime.now(timezone.utc)
    # Shouldn't happen in real traffic (click always fires after the pixel
    # in practice), but the function must never report a negative dwell.
    events = [_event("clicked", now), _event("opened", now + timedelta(seconds=10))]
    assert svc.compute_dwell_seconds(events) is None


# ── launch_campaign entries_override / audience_label (Phishing Simulation
# roadmap Phase 15 — targeted training segments) ────────────────────────────

async def test_launch_campaign_with_entries_override_sends_only_to_the_given_subset(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    target_list = PhishingTargetList(
        id=uuid.uuid4(), tenant_id=tenant.id, name="Staff",
        entries=[{"email": "jane@example.com"}, {"email": "bob@example.com"}],
    )
    db_session.add_all([engagement, target_list])
    await db_session.commit()

    sent = []
    async def fake_send_email(db, to, subject, body_html):
        sent.append(to)
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    campaign = await svc.launch_campaign(
        db_session, engagement, target_list, "shared-document",
        entries_override=[{"email": "jane@example.com"}],
        audience_label="1 individually selected recipient",
    )
    assert sent == ["jane@example.com"]  # bob was on the full list but excluded by the override
    assert campaign.target_list_id == target_list.id  # still references the real, complete list
    assert campaign.audience_label == "1 individually selected recipient"

    from sqlalchemy import select
    result = await db_session.execute(select(PhishingEvent).where(PhishingEvent.campaign_id == campaign.id))
    events = result.scalars().all()
    assert len(events) == 1
    assert events[0].recipient_hash == svc._hash_recipient("jane@example.com", tenant.id)


async def test_launch_campaign_with_no_override_sends_to_everyone_and_has_no_audience_label(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    target_list = PhishingTargetList(
        id=uuid.uuid4(), tenant_id=tenant.id, name="Staff",
        entries=[{"email": "jane@example.com"}, {"email": "bob@example.com"}],
    )
    db_session.add_all([engagement, target_list])
    await db_session.commit()

    sent = []
    async def fake_send_email(db, to, subject, body_html):
        sent.append(to)
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    campaign = await svc.launch_campaign(db_session, engagement, target_list, "shared-document")
    assert set(sent) == {"jane@example.com", "bob@example.com"}
    assert campaign.audience_label is None


# ── Honest send-failure tracking (Phishing Simulation roadmap Phase 17) ─────

async def test_launch_campaign_records_send_failed_for_a_real_delivery_failure(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    target_list = PhishingTargetList(
        id=uuid.uuid4(), tenant_id=tenant.id, name="Staff",
        entries=[{"email": "jane@example.com"}, {"email": "bob@example.com"}],
    )
    db_session.add_all([engagement, target_list])
    await db_session.commit()

    async def fake_send_email(db, to, subject, body_html):
        return to != "bob@example.com"  # bob's send genuinely fails
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    campaign = await svc.launch_campaign(db_session, engagement, target_list, "shared-document")

    from sqlalchemy import select
    events = (await db_session.execute(select(PhishingEvent).where(PhishingEvent.campaign_id == campaign.id))).scalars().all()
    by_email_hash = {e.recipient_hash: e.event_type for e in events}
    jane_hash = svc._hash_recipient("jane@example.com", tenant.id)
    bob_hash = svc._hash_recipient("bob@example.com", tenant.id)
    assert by_email_hash[jane_hash] == "sent"
    assert by_email_hash[bob_hash] == "send_failed"  # never silently recorded as "sent"


async def test_launch_campaign_body_html_sent_only_captured_from_a_real_delivery(db_session, monkeypatch):
    """The one real evidence example (body_html_sent) must come from a
    recipient who genuinely received it — a failed first entry shouldn't
    poison the example with content nobody actually got."""
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    target_list = PhishingTargetList(
        id=uuid.uuid4(), tenant_id=tenant.id, name="Staff",
        entries=[{"email": "fails@example.com"}, {"email": "succeeds@example.com"}],
    )
    db_session.add_all([engagement, target_list])
    await db_session.commit()

    async def fake_send_email(db, to, subject, body_html):
        return to == "succeeds@example.com"
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    campaign = await svc.launch_campaign(db_session, engagement, target_list, "shared-document")
    assert campaign.body_html_sent is not None  # the real, successfully-delivered example
