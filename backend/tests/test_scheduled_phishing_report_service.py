"""
send_scheduled_phishing_reports (Phishing Simulation roadmap Phase 22) — the
phishing/Human-Risk equivalent of scheduled_report_service.send_scheduled_reports.
PDF rendering itself (Playwright/Chromium) is mocked at the same boundary
test_command_report_service.py already treats as external.
"""
import uuid
from datetime import datetime, timedelta, timezone

from app.models import Engagement, PhishingCampaign, PhishingEvent, PhishingTargetList
from app.services import scheduled_report_service as svc
from tests.factories import make_tenant, make_user


def _make_campaign(db_session, tenant):
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "a@example.com"}])
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    db_session.add_all([target_list, engagement])
    return target_list, engagement


async def _seed_campaign_with_events(db_session, tenant):
    target_list, engagement = _make_campaign(db_session, tenant)
    await db_session.flush()
    campaign = PhishingCampaign(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        target_list_id=target_list.id, template_id="shared-document", status="complete",
    )
    db_session.add(campaign)
    await db_session.flush()
    db_session.add_all([
        PhishingEvent(id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id, recipient_hash="h1", recipient_token="t1", event_type="sent"),
        PhishingEvent(id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id, recipient_hash="h1", recipient_token="t1", event_type="clicked"),
    ])
    await db_session.commit()
    return campaign


def test_schedule_is_due_off_is_never_due():
    assert svc._schedule_is_due("off", None) is False


def test_schedule_is_due_with_no_prior_send_is_due():
    assert svc._schedule_is_due("weekly", None) is True


def test_schedule_is_due_respects_the_interval():
    just_now = datetime.now(timezone.utc)
    eight_days_ago = just_now - timedelta(days=8)
    assert svc._schedule_is_due("weekly", just_now) is False
    assert svc._schedule_is_due("weekly", eight_days_ago) is True


async def test_send_scheduled_phishing_reports_skips_a_free_plan_tenant(db_session, monkeypatch):
    tenant = await make_tenant(db_session, plan="free")
    tenant.phishing_report_schedule = "weekly"
    await make_user(db_session, tenant, email="admin@example.com", role="admin")
    await _seed_campaign_with_events(db_session, tenant)

    called = False
    async def fake_render(**kwargs):
        nonlocal called
        called = True
        return b"%PDF-1.4 fake"
    monkeypatch.setattr(svc, "render_phishing_report_pdf", fake_render)

    await svc._send_scheduled_phishing_reports(db_session)
    assert called is False


async def test_send_scheduled_phishing_reports_skips_when_not_yet_due(db_session, monkeypatch):
    tenant = await make_tenant(db_session, plan="pro")
    tenant.phishing_report_schedule = "weekly"
    tenant.last_phishing_report_sent_at = datetime.now(timezone.utc)
    await make_user(db_session, tenant, email="admin@example.com", role="admin")
    await _seed_campaign_with_events(db_session, tenant)

    called = False
    async def fake_render(**kwargs):
        nonlocal called
        called = True
        return b"%PDF-1.4 fake"
    monkeypatch.setattr(svc, "render_phishing_report_pdf", fake_render)

    await svc._send_scheduled_phishing_reports(db_session)
    assert called is False


async def test_send_scheduled_phishing_reports_sends_a_real_pdf_and_updates_last_sent(db_session, monkeypatch):
    tenant = await make_tenant(db_session, plan="pro")
    tenant.phishing_report_schedule = "weekly"
    admin = await make_user(db_session, tenant, email="admin@example.com", role="admin")
    await _seed_campaign_with_events(db_session, tenant)

    captured = {}
    async def fake_render(**kwargs):
        captured["render_kwargs"] = kwargs
        return b"%PDF-1.4 fake"
    monkeypatch.setattr(svc, "render_phishing_report_pdf", fake_render)

    async def fake_send_email(db, *, to, subject, title, body_html, text_body, attachments):
        captured["to"] = to
        captured["attachments"] = attachments
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    await svc._send_scheduled_phishing_reports(db_session)

    assert captured["to"] == admin.email
    assert captured["render_kwargs"]["sent"] == 1
    assert captured["render_kwargs"]["click_rate"] == 1.0
    assert len(captured["attachments"]) == 1
    assert captured["attachments"][0].mime_type == "application/pdf"

    await db_session.refresh(tenant)
    assert tenant.last_phishing_report_sent_at is not None


async def test_send_scheduled_phishing_reports_advances_last_sent_even_with_no_campaign_history(db_session, monkeypatch):
    # Otherwise a tenant that opts in before ever launching a campaign
    # would get polled and short-circuited every single job cycle forever
    # instead of just waiting for its real next interval.
    tenant = await make_tenant(db_session, plan="pro")
    tenant.phishing_report_schedule = "weekly"
    await make_user(db_session, tenant, email="admin@example.com", role="admin")
    await db_session.commit()

    called = False
    async def fake_render(**kwargs):
        nonlocal called
        called = True
        return b"%PDF-1.4 fake"
    monkeypatch.setattr(svc, "render_phishing_report_pdf", fake_render)

    await svc._send_scheduled_phishing_reports(db_session)

    assert called is False
    await db_session.refresh(tenant)
    assert tenant.last_phishing_report_sent_at is not None
