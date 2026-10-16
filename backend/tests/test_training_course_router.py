"""
Router-level tests for the authenticated training-course endpoints —
course CRUD, module management, standalone assignment (audience scoping
mirrors campaign launch), CSV export, and survey-result aggregation.
Recipient-facing unauthenticated access is covered in
test_training_track_router.py.
"""
import uuid

from tests.factories import make_tenant, make_user


async def _create_course(client, *, with_survey=False):
    modules = [{"format": "article", "title": "Spotting a fake login page", "content": "<p>Look at the URL.</p>", "duration_minutes": 3}]
    if with_survey:
        modules.append({"format": "survey", "title": "Quick check-in"})
    resp = await client.post("/training-courses", json={
        "title": "Phishing Awareness Basics", "description": "A short intro course.", "category": "General",
        "modules": modules,
    })
    return resp.json()


async def test_preview_course_home_shows_real_title_and_modules(auth_client):
    client, _tenant = auth_client
    course = await _create_course(client)
    resp = await client.get(f"/training-courses/{course['id']}/preview")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert course["title"] in resp.text
    assert course["modules"][0]["title"] in resp.text
    assert "PREVIEW" in resp.text


async def test_preview_course_home_is_tenant_isolated(auth_client, client, db_session):
    owner_client, _tenant = auth_client
    course = await _create_course(owner_client)

    other_tenant = await make_tenant(db_session, name="Other Co")
    await make_user(db_session, other_tenant, email="other@example.com", password="pass123")
    await db_session.flush()

    login = await client.post(
        "/auth/token", data={"username": "other@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    resp = await client.get(f"/training-courses/{course['id']}/preview")
    assert resp.status_code == 404


async def test_preview_article_module_shows_content_with_no_form(auth_client):
    client, _tenant = auth_client
    course = await _create_course(client)
    module_id = course["modules"][0]["id"]
    resp = await client.get(f"/training-courses/{course['id']}/preview/module/{module_id}")
    assert resp.status_code == 200
    assert "Look at the URL" in resp.text
    assert "<form" not in resp.text


async def test_preview_video_module_has_no_form(auth_client):
    client, _tenant = auth_client
    course = await _create_course(client)
    add_resp = await client.post(f"/training-courses/{course['id']}/modules", json={
        "format": "video_embed", "title": "Watch this", "content": "https://example.com/video",
    })
    module_id = add_resp.json()["id"]
    resp = await client.get(f"/training-courses/{course['id']}/preview/module/{module_id}")
    assert resp.status_code == 200
    assert "https://example.com/video" in resp.text
    assert "<form" not in resp.text


async def test_preview_survey_module_shows_real_questions_but_no_form(auth_client):
    client, _tenant = auth_client
    course = await _create_course(client, with_survey=True)
    survey_module_id = course["modules"][1]["id"]
    resp = await client.get(f"/training-courses/{course['id']}/preview/module/{survey_module_id}")
    assert resp.status_code == 200
    from app.services.training_course_service import SURVEY_QUESTIONS
    for q in SURVEY_QUESTIONS:
        assert q["label"] in resp.text
    assert "<form" not in resp.text
    assert "Submit</button>" not in resp.text


async def test_preview_module_not_found_in_real_course_404s(auth_client):
    client, _tenant = auth_client
    course = await _create_course(client)
    resp = await client.get(f"/training-courses/{course['id']}/preview/module/{uuid.uuid4()}")
    assert resp.status_code == 404


async def test_create_and_list_course(auth_client):
    client, _tenant = auth_client
    course = await _create_course(client)
    assert course["title"] == "Phishing Awareness Basics"
    assert len(course["modules"]) == 1
    assert course["modules"][0]["format"] == "article"

    list_resp = await client.get("/training-courses")
    assert list_resp.status_code == 200
    assert any(c["id"] == course["id"] for c in list_resp.json())


async def test_create_course_rejects_unknown_module_format(auth_client):
    client, _tenant = auth_client
    resp = await client.post("/training-courses", json={
        "title": "Bad course", "modules": [{"format": "quiz", "title": "x"}],
    })
    assert resp.status_code == 400


async def test_create_course_rejects_viewer_but_allows_approver(client, db_session):
    tenant = await make_tenant(db_session, plan="free")
    await make_user(db_session, tenant, email="admin@example.com", password="pass123", role="admin")
    await db_session.flush()
    login = await client.post("/auth/token", data={"username": "admin@example.com", "password": "pass123"}, headers={"Content-Type": "application/x-www-form-urlencoded"})
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    await make_user(db_session, tenant, email="viewer@example.com", password="pass123", role="viewer")
    await make_user(db_session, tenant, email="approver@example.com", password="pass123", role="approver")
    await db_session.commit()

    login = await client.post("/auth/token", data={"username": "viewer@example.com", "password": "pass123"}, headers={"Content-Type": "application/x-www-form-urlencoded"})
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
    denied = await client.post("/training-courses", json={"title": "x", "modules": []})
    assert denied.status_code == 403

    login = await client.post("/auth/token", data={"username": "approver@example.com", "password": "pass123"}, headers={"Content-Type": "application/x-www-form-urlencoded"})
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
    allowed = await client.post("/training-courses", json={"title": "x", "modules": []})
    assert allowed.status_code == 201


async def test_update_course_patches_only_given_fields(auth_client):
    client, _tenant = auth_client
    course = await _create_course(client)
    resp = await client.patch(f"/training-courses/{course['id']}", json={"title": "Updated title"})
    assert resp.status_code == 200
    assert resp.json()["title"] == "Updated title"
    assert resp.json()["category"] == "General"  # untouched


async def test_add_and_delete_module(auth_client):
    client, _tenant = auth_client
    course = await _create_course(client)
    add_resp = await client.post(f"/training-courses/{course['id']}/modules", json={
        "format": "video_embed", "title": "Watch this", "content": "https://example.com/video",
    })
    assert add_resp.status_code == 201
    module_id = add_resp.json()["id"]
    assert add_resp.json()["order_index"] == 1  # after the one module already in the course

    del_resp = await client.delete(f"/training-course-modules/{module_id}")
    assert del_resp.status_code == 204
    course_resp = await client.get(f"/training-courses/{course['id']}")
    assert len(course_resp.json()["modules"]) == 1


async def test_reorder_modules(auth_client):
    client, _tenant = auth_client
    course = await _create_course(client)
    second = (await client.post(f"/training-courses/{course['id']}/modules", json={"format": "article", "title": "Second", "content": "<p>x</p>"})).json()
    first_id = course["modules"][0]["id"]

    reorder_resp = await client.put(f"/training-courses/{course['id']}/modules/order", json=[second["id"], first_id])
    assert reorder_resp.status_code == 200
    modules = reorder_resp.json()["modules"]
    assert modules[0]["id"] == second["id"]
    assert modules[1]["id"] == first_id


async def test_assign_course_to_everyone_sends_to_the_whole_list(auth_client, monkeypatch):
    client, _tenant = auth_client
    course = await _create_course(client)
    tl_resp = await client.post("/phishing-target-lists", json={
        "name": "Staff", "entries": [{"email": "a@example.com"}, {"email": "b@example.com"}],
    })
    target_list_id = tl_resp.json()["id"]

    sent_to = []
    from app.services import training_course_service as svc

    async def fake_send_email(db, *, to, subject, title, body_html, text_body):
        sent_to.append(to)
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    assign_resp = await client.post(f"/training-courses/{course['id']}/assign", json={"target_list_id": target_list_id})
    assert assign_resp.status_code == 200
    assert assign_resp.json() == {"newly_assigned": 2, "already_assigned": 0}
    assert sorted(sent_to) == ["a@example.com", "b@example.com"]

    list_resp = await client.get(f"/training-courses/{course['id']}/assignments")
    assert len(list_resp.json()) == 2
    assert all(a["status"] == "assigned" and a["modules_total"] == 1 for a in list_resp.json())


async def test_assign_course_is_idempotent_and_scoped_by_department(auth_client, monkeypatch):
    client, _tenant = auth_client
    course = await _create_course(client)
    tl_resp = await client.post("/phishing-target-lists", json={
        "name": "Staff", "entries": [
            {"email": "fin@example.com", "department": "Finance"},
            {"email": "it@example.com", "department": "IT"},
        ],
    })
    target_list_id = tl_resp.json()["id"]

    from app.services import training_course_service as svc
    async def fake_send_email(db, *, to, subject, title, body_html, text_body):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    first = await client.post(f"/training-courses/{course['id']}/assign", json={
        "target_list_id": target_list_id, "audience_type": "department", "department": "Finance",
    })
    assert first.json() == {"newly_assigned": 1, "already_assigned": 0}

    second = await client.post(f"/training-courses/{course['id']}/assign", json={
        "target_list_id": target_list_id, "audience_type": "department", "department": "Finance",
    })
    assert second.json() == {"newly_assigned": 0, "already_assigned": 1}

    list_resp = await client.get(f"/training-courses/{course['id']}/assignments")
    assert len(list_resp.json()) == 1  # only the Finance recipient, IT was never in scope


async def test_export_assignments_csv(auth_client, monkeypatch):
    client, _tenant = auth_client
    course = await _create_course(client)
    tl_resp = await client.post("/phishing-target-lists", json={"name": "Staff", "entries": [{"email": "a@example.com"}]})
    target_list_id = tl_resp.json()["id"]

    from app.services import training_course_service as svc
    async def fake_send_email(db, *, to, subject, title, body_html, text_body):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)
    await client.post(f"/training-courses/{course['id']}/assign", json={"target_list_id": target_list_id})

    resp = await client.get(f"/training-courses/{course['id']}/assignments/export.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "recipient_hash" in resp.text
    assert "assigned" in resp.text


async def test_survey_results_aggregate_never_expose_per_recipient_data(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    course = await _create_course(client, with_survey=True)
    tl_resp = await client.post("/phishing-target-lists", json={
        "name": "Staff", "entries": [{"email": "a@example.com"}, {"email": "b@example.com"}],
    })
    target_list_id = tl_resp.json()["id"]

    from app.services import training_course_service as svc
    async def fake_send_email(db, *, to, subject, title, body_html, text_body):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)
    await client.post(f"/training-courses/{course['id']}/assign", json={"target_list_id": target_list_id})

    assignments_resp = await client.get(f"/training-courses/{course['id']}/assignments")
    assignments = assignments_resp.json()
    survey_module_id = course["modules"][1]["id"]

    from app.services.training_course_service import SURVEY_QUESTIONS
    answers = {q["key"]: "agree" for q in SURVEY_QUESTIONS}
    for a in assignments:
        from sqlalchemy import select
        from app.models import TrainingCourseAssignment
        row = (await db_session.execute(select(TrainingCourseAssignment).where(TrainingCourseAssignment.id == uuid.UUID(a["id"])))).scalar_one()
        row.module_responses = {survey_module_id: answers}
        row.completed_module_ids = [survey_module_id, course["modules"][0]["id"]]
    await db_session.commit()

    results_resp = await client.get("/training-survey-results")
    assert results_resp.status_code == 200
    results = results_resp.json()
    assert len(results) == len(SURVEY_QUESTIONS)
    for r in results:
        assert r["response_count"] == 2
        assert r["counts"] == {"agree": 2}
        # No recipient_hash, no email, no per-person field anywhere in the payload.
        assert "recipient_hash" not in r and "email" not in r
