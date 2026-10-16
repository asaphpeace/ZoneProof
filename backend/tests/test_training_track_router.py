"""
Router-level tests for the unauthenticated /phishing-training/* endpoints
— hit by whoever was assigned the course, never a logged-in Sentinel user,
same silent-unknown-token discipline as /phishing-track/*.
"""
import uuid

from app.models.training_course import TrainingCourse, TrainingCourseAssignment, TrainingCourseModule
from tests.factories import make_tenant


async def _seed_assignment(db_session, *, with_survey=False):
    tenant = await make_tenant(db_session)
    course = TrainingCourse(id=uuid.uuid4(), tenant_id=tenant.id, title="Basics", category="General")
    db_session.add(course)
    await db_session.flush()
    article = TrainingCourseModule(id=uuid.uuid4(), tenant_id=tenant.id, course_id=course.id, order_index=0, format="article", title="Read this", content="<p>Look at the URL bar.</p>")
    db_session.add(article)
    modules = [article]
    if with_survey:
        survey = TrainingCourseModule(id=uuid.uuid4(), tenant_id=tenant.id, course_id=course.id, order_index=1, format="survey", title="Quick check-in")
        db_session.add(survey)
        modules.append(survey)
    token = "tok-" + uuid.uuid4().hex
    assignment = TrainingCourseAssignment(
        id=uuid.uuid4(), tenant_id=tenant.id, course_id=course.id, recipient_hash="h1",
        access_token=token, source="standalone", status="assigned",
    )
    db_session.add(assignment)
    await db_session.commit()
    return token, course, modules, assignment


async def test_unknown_token_gets_a_silent_expired_page_not_a_404(client):
    resp = await client.get("/phishing-training/not-a-real-token")
    assert resp.status_code == 200
    assert "expired" in resp.text.lower()


async def test_course_home_page_lists_modules(client, db_session):
    token, course, modules, _a = await _seed_assignment(db_session)
    resp = await client.get(f"/phishing-training/{token}")
    assert resp.status_code == 200
    assert course.title in resp.text
    assert modules[0].title in resp.text


async def test_article_module_can_be_marked_complete(client, db_session):
    token, _course, modules, assignment = await _seed_assignment(db_session)
    module = modules[0]

    view_resp = await client.get(f"/phishing-training/{token}/module/{module.id}")
    assert view_resp.status_code == 200
    assert "Mark as read" in view_resp.text

    complete_resp = await client.post(f"/phishing-training/{token}/module/{module.id}/complete")
    assert complete_resp.status_code == 200
    assert "completed" in complete_resp.text.lower()

    await db_session.refresh(assignment)
    assert str(module.id) in assignment.completed_module_ids
    assert assignment.status == "completed"  # only one module in this course


async def test_survey_module_records_real_answers_and_completes_the_course(client, db_session):
    token, _course, modules, assignment = await _seed_assignment(db_session, with_survey=True)
    article, survey = modules

    await client.post(f"/phishing-training/{token}/module/{article.id}/complete")

    from app.services.training_course_service import SURVEY_QUESTIONS
    form_data = {q["key"]: "agree" for q in SURVEY_QUESTIONS}
    resp = await client.post(f"/phishing-training/{token}/module/{survey.id}/complete", data=form_data)
    assert resp.status_code == 200

    await db_session.refresh(assignment)
    assert assignment.status == "completed"
    assert assignment.module_responses[str(survey.id)] == form_data


async def test_completing_a_module_for_an_unknown_module_id_is_silent(client, db_session):
    token, _course, _modules, _a = await _seed_assignment(db_session)
    resp = await client.post(f"/phishing-training/{token}/module/{uuid.uuid4()}/complete")
    assert resp.status_code == 200
    assert "expired" in resp.text.lower()
