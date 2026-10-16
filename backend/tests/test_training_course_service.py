"""
Service-level tests for training_course_service.py — module/course
completion transitions, the phishing-failure auto-assign wiring (through
a real /phishing-track/.../click hit, not called directly), the reminder
job's interval/cap/anonymity behavior, and confirming course-based
training completion stays a separate metric from the existing Human Risk
score rather than silently changing its formula.
"""
import uuid
from datetime import datetime, timedelta, timezone

from app.models import Engagement, PhishingCampaign, PhishingEvent, PhishingTargetList
from app.models.training_course import TrainingCourse, TrainingCourseAssignment, TrainingCourseModule
from app.services import phishing_service as svc
from app.services import training_course_service as course_svc
from tests.factories import make_tenant, make_user


async def _make_course(db_session, tenant, *, with_survey=False):
    course = TrainingCourse(id=uuid.uuid4(), tenant_id=tenant.id, title="Basics", category="General")
    db_session.add(course)
    await db_session.flush()
    m1 = TrainingCourseModule(id=uuid.uuid4(), tenant_id=tenant.id, course_id=course.id, order_index=0, format="article", title="Read this", content="<p>hi</p>")
    db_session.add(m1)
    modules = [m1]
    if with_survey:
        m2 = TrainingCourseModule(id=uuid.uuid4(), tenant_id=tenant.id, course_id=course.id, order_index=1, format="survey", title="Survey")
        db_session.add(m2)
        modules.append(m2)
    await db_session.commit()
    await db_session.refresh(course)
    return course, modules


async def test_complete_module_marks_course_complete_once_every_module_is_done(db_session):
    tenant = await make_tenant(db_session)
    course, modules = await _make_course(db_session, tenant, with_survey=True)
    assignment = TrainingCourseAssignment(
        id=uuid.uuid4(), tenant_id=tenant.id, course_id=course.id, recipient_hash="h1",
        access_token="tok1", source="standalone", status="assigned",
    )
    db_session.add(assignment)
    await db_session.commit()

    await course_svc.complete_module(db_session, "tok1", str(modules[0].id))
    await db_session.refresh(assignment)
    assert assignment.status == "assigned"  # only one of two modules done

    from app.services.training_course_service import SURVEY_QUESTIONS
    answers = {q["key"]: "agree" for q in SURVEY_QUESTIONS}
    await course_svc.complete_module(db_session, "tok1", str(modules[1].id), answers)
    await db_session.refresh(assignment)
    assert assignment.status == "completed"
    assert assignment.completed_at is not None
    assert assignment.module_responses[str(modules[1].id)] == answers


async def test_complete_module_is_idempotent_for_an_already_completed_module(db_session):
    tenant = await make_tenant(db_session)
    course, modules = await _make_course(db_session, tenant)
    assignment = TrainingCourseAssignment(
        id=uuid.uuid4(), tenant_id=tenant.id, course_id=course.id, recipient_hash="h1",
        access_token="tok2", source="standalone", status="assigned",
    )
    db_session.add(assignment)
    await db_session.commit()

    await course_svc.complete_module(db_session, "tok2", str(modules[0].id))
    await course_svc.complete_module(db_session, "tok2", str(modules[0].id))
    await db_session.refresh(assignment)
    assert assignment.completed_module_ids == [str(modules[0].id)]  # not duplicated
    assert assignment.status == "completed"


async def test_render_course_home_page_is_silent_on_an_unknown_token(db_session):
    result = await course_svc.render_course_home_page(db_session, "not-a-real-token")
    assert result is None


async def _seed_sent_event_with_real_hash(db_session, tenant, email="jane@example.com"):
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": email}])
    campaign = PhishingCampaign(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        target_list_id=target_list.id, template_id="shared-document", status="complete",
    )
    db_session.add_all([engagement, target_list, campaign])
    await db_session.flush()

    token = "tok-" + uuid.uuid4().hex
    recipient_hash = svc._hash_recipient(email, tenant.id)
    db_session.add(PhishingEvent(
        id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id,
        recipient_hash=recipient_hash, recipient_token=token, event_type="sent",
    ))
    await db_session.commit()
    return token, campaign, recipient_hash


async def test_a_real_click_auto_assigns_the_configured_course_in_addition_to_the_micro_lesson(client, db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    course, _modules = await _make_course(db_session, tenant)
    tenant.auto_assign_training_course_id = course.id
    await db_session.commit()
    token, campaign, recipient_hash = await _seed_sent_event_with_real_hash(db_session, tenant)

    sent_to = []
    async def fake_send_email(db, *, to, subject, title, body_html, text_body):
        sent_to.append(to)
        return True
    monkeypatch.setattr(course_svc, "send_email", fake_send_email)

    resp = await client.get(f"/phishing-track/{token}/click")
    assert resp.status_code == 200

    from sqlalchemy import select
    from app.models import TrainingAssignment
    micro_lesson = (await db_session.execute(select(TrainingAssignment).where(TrainingAssignment.campaign_id == campaign.id))).scalar_one_or_none()
    assert micro_lesson is not None  # the always-on immediate lesson still fires

    course_assignment = (await db_session.execute(
        select(TrainingCourseAssignment).where(TrainingCourseAssignment.course_id == course.id, TrainingCourseAssignment.recipient_hash == recipient_hash)
    )).scalar_one_or_none()
    assert course_assignment is not None
    assert course_assignment.source == "phishing_failure"
    assert course_assignment.campaign_id == campaign.id
    assert sent_to == ["jane@example.com"]


async def test_a_click_does_nothing_extra_when_no_course_is_configured(client, db_session):
    tenant = await make_tenant(db_session)
    token, campaign, _hash = await _seed_sent_event_with_real_hash(db_session, tenant)

    resp = await client.get(f"/phishing-track/{token}/click")
    assert resp.status_code == 200

    from sqlalchemy import select
    count = (await db_session.execute(select(TrainingCourseAssignment))).scalars().all()
    assert count == []


async def test_course_training_completion_is_a_separate_rate_from_the_micro_lesson_and_does_not_change_the_human_risk_score(db_session):
    """Regression guard: adding course-based training must not silently
    change compute_tenant_human_risk_score's existing, already-tested
    formula — it should still score purely on the micro-lesson rate."""
    tenant = await make_tenant(db_session)
    course, modules = await _make_course(db_session, tenant)

    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "a@example.com"}])
    campaign = PhishingCampaign(id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, target_list_id=target_list.id, template_id="shared-document", status="complete")
    db_session.add_all([engagement, target_list, campaign])
    await db_session.flush()
    db_session.add(PhishingEvent(id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id, recipient_hash="h1", recipient_token="t1", event_type="sent"))
    await db_session.commit()

    score_before = await svc.compute_tenant_human_risk_score(db_session, tenant.id)

    # A course assignment exists but is NOT completed — if it were wrongly
    # merged into the scoring formula's training-completion input, the
    # score would drop; it must not, since this isn't the metric the
    # score reads from.
    db_session.add(TrainingCourseAssignment(
        id=uuid.uuid4(), tenant_id=tenant.id, course_id=course.id, recipient_hash="h1",
        access_token="scoretest", source="phishing_failure", campaign_id=campaign.id, status="assigned",
    ))
    await db_session.commit()

    score_after = await svc.compute_tenant_human_risk_score(db_session, tenant.id)
    assert score_after == score_before

    summary = await svc.compute_tenant_phishing_summary(db_session, tenant.id)
    assert summary["course_training_assigned"] == 1
    assert summary["course_training_completed"] == 0
    assert summary["course_training_completion_rate"] == 0.0


# ── Survey sentiment score (Phishing Simulation roadmap Phase 30a) ──────────

async def test_survey_sentiment_score_is_none_with_no_responses(db_session):
    tenant = await make_tenant(db_session)
    await db_session.commit()
    score = await course_svc.compute_tenant_survey_sentiment_score(db_session, tenant.id)
    assert score is None  # never a fabricated score for a tenant with no real data


async def test_survey_sentiment_score_is_100_when_everyone_agrees(db_session):
    tenant = await make_tenant(db_session)
    course, modules = await _make_course(db_session, tenant, with_survey=True)
    assignment = TrainingCourseAssignment(
        id=uuid.uuid4(), tenant_id=tenant.id, course_id=course.id, recipient_hash="h1",
        access_token="tok-agree", source="standalone", status="assigned",
    )
    db_session.add(assignment)
    await db_session.commit()

    from app.services.training_course_service import SURVEY_QUESTIONS
    answers = {q["key"]: "agree" for q in SURVEY_QUESTIONS}
    await course_svc.complete_module(db_session, "tok-agree", str(modules[0].id))
    await course_svc.complete_module(db_session, "tok-agree", str(modules[1].id), answers)

    score = await course_svc.compute_tenant_survey_sentiment_score(db_session, tenant.id)
    assert score == 100.0


async def test_survey_sentiment_score_averages_per_question_before_averaging_across_questions(db_session):
    """One heavily-answered question shouldn't drown out a lightly-answered
    one — each question's own average counts equally, not each raw answer."""
    tenant = await make_tenant(db_session)
    course, modules = await _make_course(db_session, tenant, with_survey=True)
    from app.services.training_course_service import SURVEY_QUESTIONS
    q1, q2, q3, q4 = (q["key"] for q in SURVEY_QUESTIONS)

    # Three people all "agree" on q1 (many redundant 100s) but the lone
    # answer on q2 is "disagree" (a real 0) — a naive flat average across
    # every individual answer would be dominated by q1's volume.
    for i in range(3):
        assignment = TrainingCourseAssignment(
            id=uuid.uuid4(), tenant_id=tenant.id, course_id=course.id, recipient_hash=f"h{i}",
            access_token=f"tok-{i}", source="standalone", status="assigned",
        )
        db_session.add(assignment)
        await db_session.commit()
        await course_svc.complete_module(db_session, f"tok-{i}", str(modules[0].id))
        answers = {q1: "agree", q2: "disagree"} if i == 0 else {q1: "agree"}
        await course_svc.complete_module(db_session, f"tok-{i}", str(modules[1].id), answers)

    score = await course_svc.compute_tenant_survey_sentiment_score(db_session, tenant.id)
    # q1 average = 100 (three agrees), q2 average = 0 (one disagree) — the
    # overall score averages those two question-averages, landing at 50,
    # not close to 100 the way a flat per-answer average would.
    assert score == 50.0


# ── Reminders ────────────────────────────────────────────────────────────

async def test_reminder_fires_after_the_interval_and_updates_reminder_count(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    tenant.training_reminder_interval_days = 14
    tenant.training_reminder_max_count = 2
    course, _modules = await _make_course(db_session, tenant)
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "late@example.com"}])
    db_session.add(target_list)
    await db_session.flush()
    recipient_hash = svc._hash_recipient("late@example.com", tenant.id)
    assignment = TrainingCourseAssignment(
        id=uuid.uuid4(), tenant_id=tenant.id, course_id=course.id, recipient_hash=recipient_hash,
        access_token="remtest1", source="standalone", status="assigned",
        assigned_at=datetime.now(timezone.utc) - timedelta(days=20),
    )
    db_session.add(assignment)
    await db_session.commit()

    sent_to = []
    async def fake_send_email(db, *, to, subject, title, body_html, text_body):
        sent_to.append(to)
        return True
    monkeypatch.setattr(course_svc, "send_email", fake_send_email)

    sent_count = await course_svc._send_training_reminders(db_session)
    assert sent_count == 1
    assert sent_to == ["late@example.com"]
    await db_session.refresh(assignment)
    assert assignment.reminder_count == 1
    assert assignment.last_reminder_sent_at is not None


async def test_reminder_does_not_fire_before_the_interval_elapses(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    course, _modules = await _make_course(db_session, tenant)
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "recent@example.com"}])
    db_session.add(target_list)
    await db_session.flush()
    recipient_hash = svc._hash_recipient("recent@example.com", tenant.id)
    db_session.add(TrainingCourseAssignment(
        id=uuid.uuid4(), tenant_id=tenant.id, course_id=course.id, recipient_hash=recipient_hash,
        access_token="remtest2", source="standalone", status="assigned",
        assigned_at=datetime.now(timezone.utc) - timedelta(days=2),
    ))
    await db_session.commit()

    async def fake_send_email(db, **kwargs):
        return True
    monkeypatch.setattr(course_svc, "send_email", fake_send_email)

    sent_count = await course_svc._send_training_reminders(db_session)
    assert sent_count == 0


async def test_reminder_stops_once_the_tenants_max_count_is_reached(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    tenant.training_reminder_max_count = 1
    course, _modules = await _make_course(db_session, tenant)
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "capped@example.com"}])
    db_session.add(target_list)
    await db_session.flush()
    recipient_hash = svc._hash_recipient("capped@example.com", tenant.id)
    db_session.add(TrainingCourseAssignment(
        id=uuid.uuid4(), tenant_id=tenant.id, course_id=course.id, recipient_hash=recipient_hash,
        access_token="remtest3", source="standalone", status="assigned", reminder_count=1,
        assigned_at=datetime.now(timezone.utc) - timedelta(days=30),
        last_reminder_sent_at=datetime.now(timezone.utc) - timedelta(days=20),
    ))
    await db_session.commit()

    async def fake_send_email(db, **kwargs):
        return True
    monkeypatch.setattr(course_svc, "send_email", fake_send_email)

    sent_count = await course_svc._send_training_reminders(db_session)
    assert sent_count == 0


async def test_reminder_never_fires_for_a_completed_assignment(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    course, _modules = await _make_course(db_session, tenant)
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "done@example.com"}])
    db_session.add(target_list)
    await db_session.flush()
    recipient_hash = svc._hash_recipient("done@example.com", tenant.id)
    db_session.add(TrainingCourseAssignment(
        id=uuid.uuid4(), tenant_id=tenant.id, course_id=course.id, recipient_hash=recipient_hash,
        access_token="remtest4", source="standalone", status="completed",
        assigned_at=datetime.now(timezone.utc) - timedelta(days=30), completed_at=datetime.now(timezone.utc),
    ))
    await db_session.commit()

    called = False
    async def fake_send_email(db, **kwargs):
        nonlocal called
        called = True
        return True
    monkeypatch.setattr(course_svc, "send_email", fake_send_email)

    await course_svc._send_training_reminders(db_session)
    assert called is False
