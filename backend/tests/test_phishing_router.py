"""
Router-level tests for the authenticated phishing endpoints — target list
CRUD, campaign launch gating (must be an active 'phishing' engagement,
which for this tier can only reach 'active' via the real Dropbox Sign flow,
no auto-approve bypass), aggregate event counts, and the admin-only
audited unmask call.
"""
import uuid

from app.services import phishing_service as svc
from tests.factories import make_dmarc_aggregate, make_domain, make_tenant, make_user


async def test_list_phishing_templates_returns_real_content(auth_client):
    client, _tenant = auth_client
    resp = await client.get("/phishing-templates")
    assert resp.status_code == 200
    templates = resp.json()
    assert len(templates) >= 9  # the curated gallery (Coverage Map plan phishing transformation, Phase 4)
    ids = {t["id"] for t in templates}
    assert {"password-expiry", "shared-document", "it-support-request"} <= ids
    assert all(t["subject"] and t["body_html"] and t["category"] for t in templates)


async def test_list_phishing_templates_includes_real_teachable_signals(auth_client):
    """Phishing Simulation roadmap Phase 16 — compose-time honest teachable
    signals, sourced from the same generic_flags a real recipient falls
    back to, not an invented separate panel."""
    client, _tenant = auth_client
    resp = await client.get("/phishing-templates")
    templates = {t["id"]: t for t in resp.json()}
    # A category with real, specific authored content (phishing_lesson_content.py)
    assert templates["password-expiry"]["teachable_signals"] == [
        "A tight deadline on a routine account action.",
        "A request to \"confirm\" a password via an email link, rather than through your normal IT self-service portal.",
    ]
    # A template with no specific category content falls back to the same
    # honest "generic" flags a real recipient would see — never empty.
    other_ids = set(templates.keys()) - {"password-expiry", "shared-document", "it-support-request"}
    assert other_ids  # sanity: there are other templates to check
    for tid in other_ids:
        assert len(templates[tid]["teachable_signals"]) > 0


async def test_create_and_list_custom_templates(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/phishing-custom-templates", json={
        "label": "401k Information", "category": "Finance", "subject": "401K Information",
        "body_html": "<p>Hi [name], please confirm your SSN.</p>", "difficulty": "high",
    })
    assert create_resp.status_code == 201
    created = create_resp.json()
    assert created["label"] == "401k Information"
    assert created["difficulty"] == "high"
    assert created["from_email"] is None

    list_resp = await client.get("/phishing-custom-templates")
    assert list_resp.status_code == 200
    labels = [t["label"] for t in list_resp.json()]
    assert "401k Information" in labels


async def test_custom_templates_are_tenant_isolated(auth_client, db_session):
    client, tenant = auth_client
    await client.post("/phishing-custom-templates", json={
        "label": "Tenant A Template", "subject": "Subj", "body_html": "<p>Body</p>",
    })

    from tests.factories import make_tenant
    other = await make_tenant(db_session, name="Other Co")
    await make_user(db_session, other, email="other-admin@example.com", password="pass123")
    await db_session.flush()

    login = await client.post("/auth/token", data={"username": "other-admin@example.com", "password": "pass123"}, headers={"Content-Type": "application/x-www-form-urlencoded"})
    other_token = login.json()["access_token"]

    resp = await client.get("/phishing-custom-templates", headers={"Authorization": f"Bearer {other_token}"})
    assert resp.status_code == 200
    assert resp.json() == []


async def test_update_custom_template_patches_only_given_fields(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/phishing-custom-templates", json={
        "label": "Original", "subject": "Original subject", "body_html": "<p>Original body</p>", "difficulty": "low",
    })
    template_id = create_resp.json()["id"]

    patch_resp = await client.patch(f"/phishing-custom-templates/{template_id}", json={"subject": "Updated subject"})
    assert patch_resp.status_code == 200
    updated = patch_resp.json()
    assert updated["subject"] == "Updated subject"
    assert updated["label"] == "Original"  # untouched
    assert updated["difficulty"] == "low"  # untouched


async def test_update_custom_template_404_for_unknown_id(auth_client):
    client, _tenant = auth_client
    resp = await client.patch("/phishing-custom-templates/00000000-0000-0000-0000-000000000000", json={"label": "x"})
    assert resp.status_code == 404


async def test_delete_custom_template_removes_it(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/phishing-custom-templates", json={
        "label": "To delete", "subject": "Subj", "body_html": "<p>Body</p>",
    })
    template_id = create_resp.json()["id"]

    del_resp = await client.delete(f"/phishing-custom-templates/{template_id}")
    assert del_resp.status_code == 204

    list_resp = await client.get("/phishing-custom-templates")
    assert list_resp.json() == []


# ── Custom-template difficulty gating (Phishing Simulation roadmap Phase
# 23) ─────────────────────────────────────────────────────────────────────

async def _make_target_list(client, *emails):
    resp = await client.post("/phishing-target-lists", json={
        "name": "Staff", "entries": [{"email": e} for e in emails],
    })
    return resp.json()["id"]


async def _make_custom_template(client, difficulty, label="Custom lure"):
    resp = await client.post("/phishing-custom-templates", json={
        "label": label, "subject": "Subj", "body_html": "<p>Body {click_url}</p>", "difficulty": difficulty,
    })
    return resp.json()["id"]


async def test_listing_custom_templates_with_no_target_list_id_omits_eligibility(auth_client):
    client, _tenant = auth_client
    await _make_custom_template(client, "high")
    resp = await client.get("/phishing-custom-templates")
    assert resp.json()[0]["eligible"] is None


async def test_low_difficulty_template_is_always_eligible(auth_client):
    client, _tenant = auth_client
    target_list_id = await _make_target_list(client, "new-hire@example.com")
    await _make_custom_template(client, "low")
    resp = await client.get(f"/phishing-custom-templates?target_list_id={target_list_id}")
    assert resp.json()[0]["eligible"] is True


async def test_high_difficulty_template_is_ineligible_with_no_training_history(auth_client):
    client, _tenant = auth_client
    target_list_id = await _make_target_list(client, "new-hire@example.com")
    await _make_custom_template(client, "high")
    resp = await client.get(f"/phishing-custom-templates?target_list_id={target_list_id}")
    assert resp.json()[0]["eligible"] is False


async def _seed_completed_training(client, db_session, tenant, target_list_id, *emails):
    """TrainingAssignment.campaign_id is a required FK — needs a real
    (if otherwise-unused) PhishingCampaign/Engagement row to reference,
    not just a target list."""
    from app.models import Engagement, PhishingCampaign, TrainingAssignment
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active", scope={})
    db_session.add(engagement)
    await db_session.flush()
    campaign = PhishingCampaign(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        target_list_id=uuid.UUID(target_list_id), template_id="shared-document",
    )
    db_session.add(campaign)
    await db_session.flush()
    for email in emails:
        db_session.add(TrainingAssignment(
            id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id, recipient_hash=svc._hash_recipient(email, tenant.id),
            lure_category="shared-document", trigger_event_type="clicked", status="completed",
        ))
    await db_session.commit()


async def test_high_difficulty_template_becomes_eligible_once_everyone_completed_training(auth_client, db_session):
    client, tenant = auth_client
    target_list_id = await _make_target_list(client, "vet@example.com")
    await _make_custom_template(client, "high")
    await _seed_completed_training(client, db_session, tenant, target_list_id, "vet@example.com")

    resp = await client.get(f"/phishing-custom-templates?target_list_id={target_list_id}")
    assert resp.json()[0]["eligible"] is True


async def test_launch_rejects_a_high_difficulty_custom_template_against_an_unready_list(auth_client, monkeypatch):
    client, _tenant = auth_client
    target_list_id = await _make_target_list(client, "new-hire@example.com")
    template_id = await _make_custom_template(client, "high")

    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": target_list_id, "template_id": template_id, "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    launch_resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    assert launch_resp.status_code == 400
    assert "difficulty" in launch_resp.json()["detail"]


async def test_launch_succeeds_with_a_low_difficulty_custom_template(auth_client, monkeypatch):
    client, _tenant = auth_client
    target_list_id = await _make_target_list(client, "new-hire@example.com")
    template_id = await _make_custom_template(client, "low")

    # The real wizard always sends subject_override/body_html_override for
    # a custom-template selection (selectTemplate() pre-fills the static-
    # mode inputs from the picked template) — matched here rather than
    # omitted, since launch_campaign() genuinely needs real content to send.
    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {
            "target_list_id": target_list_id, "template_id": template_id, "cadence_days": 90,
            "subject_override": "Subj", "body_html_override": "<p>Body {click_url}</p>",
        }},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    launch_resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    assert launch_resp.status_code == 200


async def test_launch_succeeds_with_a_high_difficulty_template_once_training_ready(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    target_list_id = await _make_target_list(client, "vet@example.com")
    template_id = await _make_custom_template(client, "high")
    await _seed_completed_training(client, db_session, tenant, target_list_id, "vet@example.com")

    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {
            "target_list_id": target_list_id, "template_id": template_id, "cadence_days": 90,
            "subject_override": "Subj", "body_html_override": "<p>Body {click_url}</p>",
        }},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    launch_resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    assert launch_resp.status_code == 200


async def test_launch_rejects_a_custom_template_combined_with_ai_generation(auth_client):
    client, _tenant = auth_client
    target_list_id = await _make_target_list(client, "new-hire@example.com")
    template_id = await _make_custom_template(client, "low")

    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {
            "target_list_id": target_list_id, "template_id": template_id, "cadence_days": 90, "llm_generate_fresh": True,
        }},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    launch_resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    assert launch_resp.status_code == 400
    assert "static content" in launch_resp.json()["detail"]


async def test_scheduler_skips_a_recurring_engagement_when_a_custom_template_is_no_longer_eligible(auth_client, db_session):
    """A target list can change between cycles — this proves eligibility is
    re-checked every poll, not just at first manual launch."""
    from datetime import datetime, timedelta, timezone
    client, tenant = auth_client
    target_list_id = await _make_target_list(client, "new-hire@example.com")
    template_id = await _make_custom_template(client, "high")

    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {
            "target_list_id": target_list_id, "template_id": template_id, "cadence_days": 90, "recurring": True,
        }},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    from sqlalchemy import select
    from app.models import Engagement
    engagement = (await db_session.execute(select(Engagement).where(Engagement.id == uuid.UUID(engagement_id)))).scalar_one()
    engagement.last_scanned_at = datetime.now(timezone.utc) - timedelta(days=91)
    await db_session.commit()

    launched = await svc.poll_due_phishing_campaigns(db_session)
    assert launched == 0


async def test_send_test_template_email_uses_inert_placeholder_links_not_real_tracking(auth_client, monkeypatch):
    client, _tenant = auth_client
    captured = {}

    async def fake_send_email(db, to, subject, body_html, **kwargs):
        captured["to"] = to
        captured["subject"] = subject
        captured["body_html"] = body_html
        return True

    from app.routers import phishing as router_mod
    monkeypatch.setattr(router_mod.email_service, "send_email", fake_send_email)

    resp = await client.post("/phishing-templates/send-test", json={
        "subject": "Your password expires soon",
        "body_html": "<p>Click <a href=\"{click_url}\">here</a> or <a href=\"{report_url}\">report</a>.</p>",
    })
    assert resp.status_code == 204
    assert captured["subject"] == "[TEST SEND] Your password expires soon"
    assert "{click_url}" not in captured["body_html"]
    assert "{report_url}" not in captured["body_html"]
    assert "#test-send-not-a-real-tracked-link" in captured["body_html"]


async def test_send_test_template_email_502s_on_real_send_failure(auth_client, monkeypatch):
    client, _tenant = auth_client

    async def fake_send_email_fails(db, to, subject, body_html, **kwargs):
        return False

    from app.routers import phishing as router_mod
    monkeypatch.setattr(router_mod.email_service, "send_email", fake_send_email_fails)

    resp = await client.post("/phishing-templates/send-test", json={"subject": "Subj", "body_html": "<p>Body</p>"})
    assert resp.status_code == 502


async def test_phishing_dashboard_returns_honest_nones_with_no_campaign_history(auth_client):
    client, _tenant = auth_client
    resp = await client.get("/phishing-dashboard")
    assert resp.status_code == 200
    body = resp.json()
    assert body["human_risk_score"] is None
    assert body["human_risk_grade"] is None
    assert body["sent"] == 0
    assert body["click_rate"] is None
    assert body["department_training"] == []


async def test_phishing_dashboard_reflects_real_campaign_and_training_data(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    campaign = await _launch_a_campaign(client, monkeypatch)

    from sqlalchemy import select
    from app.models import PhishingEvent
    sent_event = (await db_session.execute(
        select(PhishingEvent).where(PhishingEvent.campaign_id == uuid.UUID(campaign["id"]))
    )).scalars().first()
    db_session.add(PhishingEvent(
        id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=sent_event.campaign_id,
        recipient_hash=sent_event.recipient_hash, recipient_token=sent_event.recipient_token, event_type="reported",
    ))
    await db_session.commit()

    resp = await client.get("/phishing-dashboard")
    assert resp.status_code == 200
    body = resp.json()
    assert body["sent"] == 1
    assert body["report_rate"] == 1.0
    assert body["human_risk_score"] == 100.0  # a real, correct report with no click
    assert body["human_risk_grade"] == "A"


async def test_list_phishing_landing_pages_returns_real_content(auth_client):
    client, _tenant = auth_client
    resp = await client.get("/phishing-landing-pages")
    assert resp.status_code == 200
    pages = resp.json()
    assert len(pages) >= 2
    assert all(p["id"] and p["label"] for p in pages)


async def test_launch_campaign_uses_custom_content_from_scope(auth_client, monkeypatch):
    client, tenant = auth_client
    target_list_resp = await client.post(
        "/phishing-target-lists", json={"name": "Staff", "entries": [{"email": "jane@example.com"}]},
    )
    target_list_id = target_list_resp.json()["id"]

    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {
            "target_list_id": target_list_id, "template_id": "shared-document", "cadence_days": 90,
            "subject_override": "Custom subject line", "body_html_override": "<p>Custom body {click_url}</p>",
        }},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    sent = []
    async def fake_send_email(db, to, subject, body_html):
        sent.append((subject, body_html))
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    assert resp.status_code == 200
    assert len(sent) == 1
    assert sent[0][0] == "Custom subject line"
    assert "Custom body" in sent[0][1]


async def test_create_and_list_target_lists(auth_client):
    client, _tenant = auth_client
    resp = await client.post(
        "/phishing-target-lists",
        json={"name": "Staff", "entries": [{"email": "jane@example.com", "display_name": "Jane"}]},
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "Staff"

    list_resp = await client.get("/phishing-target-lists")
    assert len(list_resp.json()) == 1


async def test_update_target_list_replaces_entries(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/phishing-target-lists", json={"name": "Staff", "entries": [{"email": "old@example.com"}]})
    list_id = create_resp.json()["id"]

    update_resp = await client.put(
        f"/phishing-target-lists/{list_id}", json={"name": "Staff", "entries": [{"email": "new@example.com"}]},
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["entries"] == [
        {"email": "new@example.com", "display_name": None, "job_title": None, "department": None, "locale": None}
    ]


async def test_target_list_create_and_update_are_audit_logged(auth_client, db_session):
    """Real gap found and closed via a live E2E simulation pass — target
    list create/update defines exactly who a future real send can target,
    but had no audit trail at all, unlike everything downstream of it."""
    client, _tenant = auth_client
    create_resp = await client.post(
        "/phishing-target-lists", json={"name": "Staff", "entries": [{"email": "jane@example.com"}, {"email": "bob@example.com"}]},
    )
    list_id = create_resp.json()["id"]

    from sqlalchemy import select
    from app.models import AuditLogEntry
    created_entry = (await db_session.execute(
        select(AuditLogEntry).where(AuditLogEntry.action == "phishing.target_list_created")
    )).scalars().first()
    assert created_entry is not None
    assert created_entry.target_id == list_id
    assert created_entry.after["entry_count"] == 2
    # Real emails must never land in the audit trail — only the count.
    assert "jane@example.com" not in str(created_entry.after)

    await client.put(f"/phishing-target-lists/{list_id}", json={"name": "Staff", "entries": [{"email": "jane@example.com"}]})
    updated_entry = (await db_session.execute(
        select(AuditLogEntry).where(AuditLogEntry.action == "phishing.target_list_updated")
    )).scalars().first()
    assert updated_entry is not None
    assert updated_entry.before["entry_count"] == 2
    assert updated_entry.after["entry_count"] == 1


# ── Target-list CSV diff (Phishing Simulation roadmap Phase 25) ────────────

async def test_diff_identifies_added_removed_and_changed_rows(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/phishing-target-lists", json={
        "name": "Staff", "entries": [
            {"email": "stays-same@example.com", "department": "IT"},
            {"email": "gets-updated@example.com", "department": "Finance"},
            {"email": "gets-removed@example.com"},
        ],
    })
    list_id = create_resp.json()["id"]

    diff_resp = await client.post(f"/phishing-target-lists/{list_id}/diff", json={"entries": [
        {"email": "stays-same@example.com", "department": "IT"},
        {"email": "gets-updated@example.com", "department": "Ops"},  # department changed
        {"email": "brand-new@example.com", "display_name": "New Person"},
    ]})
    assert diff_resp.status_code == 200
    diff = diff_resp.json()

    assert [a["email"] for a in diff["added"]] == ["brand-new@example.com"]
    assert [r["email"] for r in diff["removed"]] == ["gets-removed@example.com"]
    assert len(diff["changed"]) == 1
    assert diff["changed"][0]["email"] == "gets-updated@example.com"
    assert diff["changed"][0]["before"]["department"] == "Finance"
    assert diff["changed"][0]["after"]["department"] == "Ops"
    assert diff["unchanged_count"] == 1


async def test_diff_is_case_insensitive_on_email_and_does_not_mutate_the_list(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/phishing-target-lists", json={"name": "Staff", "entries": [{"email": "Jane@Example.com"}]})
    list_id = create_resp.json()["id"]

    diff_resp = await client.post(f"/phishing-target-lists/{list_id}/diff", json={"entries": [{"email": "jane@example.com"}]})
    diff = diff_resp.json()
    assert diff["added"] == []
    assert diff["removed"] == []
    assert diff["unchanged_count"] == 1

    # Preview-only — the real list must be untouched by a diff call.
    list_resp = await client.get("/phishing-target-lists")
    assert list_resp.json()[0]["entries"] == [{"email": "Jane@Example.com", "display_name": None, "job_title": None, "department": None, "locale": None}]


async def test_diff_against_an_empty_proposed_list_marks_everyone_removed(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/phishing-target-lists", json={"name": "Staff", "entries": [{"email": "a@example.com"}, {"email": "b@example.com"}]})
    list_id = create_resp.json()["id"]

    diff_resp = await client.post(f"/phishing-target-lists/{list_id}/diff", json={"entries": []})
    diff = diff_resp.json()
    assert len(diff["removed"]) == 2
    assert diff["added"] == []
    assert diff["unchanged_count"] == 0


async def test_diff_404s_for_an_unknown_or_cross_tenant_list(auth_client):
    client, _tenant = auth_client
    resp = await client.post("/phishing-target-lists/00000000-0000-0000-0000-000000000000/diff", json={"entries": []})
    assert resp.status_code == 404


async def test_launch_campaign_requires_active_engagement(auth_client, db_session):
    client, tenant = auth_client
    create_resp = await client.post("/engagements", json={"tier": "phishing", "scope": {}})
    engagement_id = create_resp.json()["id"]

    resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    assert resp.status_code == 400


async def test_launch_campaign_requires_target_list_and_template_in_scope(auth_client, monkeypatch):
    client, tenant = auth_client
    create_resp = await client.post("/engagements", json={"tier": "phishing", "scope": {}})
    engagement_id = create_resp.json()["id"]
    approve_resp = await client.post(f"/engagements/{engagement_id}/approve")
    assert approve_resp.status_code == 200  # dev-mode direct approve, allowed by default in tests

    resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    assert resp.status_code == 400


async def test_launch_campaign_succeeds_with_a_fully_scoped_active_engagement(auth_client, monkeypatch):
    client, tenant = auth_client
    target_list_resp = await client.post(
        "/phishing-target-lists", json={"name": "Staff", "entries": [{"email": "jane@example.com"}]},
    )
    target_list_id = target_list_resp.json()["id"]

    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": target_list_id, "template_id": "shared-document", "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    assert resp.status_code == 200
    assert resp.json()["status"] == "complete"


async def _launch_a_campaign(client, monkeypatch):
    target_list_resp = await client.post(
        "/phishing-target-lists", json={"name": "Staff", "entries": [{"email": "jane@example.com", "display_name": "Jane"}]},
    )
    target_list_id = target_list_resp.json()["id"]
    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": target_list_id, "template_id": "shared-document", "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    launch_resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    return launch_resp.json()


async def test_lure_stats_reflects_real_click_rate_for_a_used_template(auth_client, db_session, monkeypatch):
    """Phishing Simulation roadmap Phase 16 — per-lure click rate in the
    wizard's template gallery, computed from real send history."""
    client, tenant = auth_client
    campaign = await _launch_a_campaign(client, monkeypatch)  # template_id="shared-document"

    from sqlalchemy import select
    from app.models import PhishingEvent
    sent_event = (await db_session.execute(
        select(PhishingEvent).where(PhishingEvent.campaign_id == uuid.UUID(campaign["id"]))
    )).scalars().first()
    db_session.add(PhishingEvent(
        id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=sent_event.campaign_id,
        recipient_hash=sent_event.recipient_hash, recipient_token=sent_event.recipient_token, event_type="clicked",
    ))
    await db_session.commit()

    resp = await client.get("/phishing-lure-stats")
    assert resp.status_code == 200
    stats = {s["template_id"]: s for s in resp.json()}
    assert stats["shared-document"]["sent_count"] == 1
    assert stats["shared-document"]["click_rate"] == 1.0


async def test_lure_stats_omits_a_template_this_tenant_has_never_sent(auth_client, monkeypatch):
    client, tenant = auth_client
    await _launch_a_campaign(client, monkeypatch)  # only "shared-document" has real history

    resp = await client.get("/phishing-lure-stats")
    assert resp.status_code == 200
    template_ids = {s["template_id"] for s in resp.json()}
    assert "shared-document" in template_ids
    assert "password-expiry" not in template_ids  # never sent — honestly absent, not a fabricated 0%


async def test_lure_stats_is_tenant_isolated(auth_client, client, db_session, monkeypatch):
    owner_client, tenant = auth_client
    await _launch_a_campaign(owner_client, monkeypatch)

    from app.models.user import Tenant
    other_tenant = Tenant(id=uuid.uuid4(), name="Other Co", plan="free")
    db_session.add(other_tenant)
    await db_session.flush()
    await make_user(db_session, other_tenant, email="other-lure-owner@example.com", password="pass123")
    await db_session.commit()

    login = await client.post(
        "/auth/token", data={"username": "other-lure-owner@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    resp = await client.get("/phishing-lure-stats")
    assert resp.status_code == 200
    assert resp.json() == []  # the other tenant's own history, not the owner's


async def test_campaigns_summary_returns_real_per_campaign_counts(auth_client, db_session, monkeypatch):
    """Phishing Simulation roadmap Phase 29b — the landing page's aggregate
    endpoint, replacing what used to be a phishingCampaigns()-per-engagement
    plus phishingCampaignEvents()-per-campaign loop."""
    client, tenant = auth_client
    campaign = await _launch_a_campaign(client, monkeypatch)  # template_id="shared-document"

    from sqlalchemy import select
    from app.models import PhishingEvent
    sent_event = (await db_session.execute(
        select(PhishingEvent).where(PhishingEvent.campaign_id == uuid.UUID(campaign["id"]))
    )).scalars().first()
    db_session.add(PhishingEvent(
        id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=sent_event.campaign_id,
        recipient_hash=sent_event.recipient_hash, recipient_token=sent_event.recipient_token, event_type="clicked",
    ))
    await db_session.commit()

    resp = await client.get("/phishing-campaigns/summary")
    assert resp.status_code == 200
    rows = {r["id"]: r for r in resp.json()}
    row = rows[campaign["id"]]
    assert row["engagement_id"] == campaign["engagement_id"]
    assert row["template_id"] == "shared-document"
    assert row["sent"] == 1
    assert row["clicked"] == 1
    assert row["credential_entered"] == 0  # never fabricated, only what actually happened


async def test_campaigns_summary_includes_a_campaign_with_no_clicks_yet(auth_client, monkeypatch):
    """A left join, not an inner join — a campaign with only its 'sent'
    event (no clicks/credentials/reports yet) must still appear with real
    zero counts, not silently vanish the way an inner join would."""
    client, tenant = auth_client
    campaign = await _launch_a_campaign(client, monkeypatch)

    resp = await client.get("/phishing-campaigns/summary")
    assert resp.status_code == 200
    rows = {r["id"]: r for r in resp.json()}
    row = rows[campaign["id"]]
    assert row["sent"] == 1
    assert row["clicked"] == 0
    assert row["reported"] == 0


async def test_campaigns_summary_is_tenant_isolated(auth_client, client, db_session, monkeypatch):
    owner_client, tenant = auth_client
    await _launch_a_campaign(owner_client, monkeypatch)

    from app.models.user import Tenant
    other_tenant = Tenant(id=uuid.uuid4(), name="Other Co", plan="free")
    db_session.add(other_tenant)
    await db_session.flush()
    await make_user(db_session, other_tenant, email="other-summary-owner@example.com", password="pass123")
    await db_session.commit()

    login = await client.post(
        "/auth/token", data={"username": "other-summary-owner@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    resp = await client.get("/phishing-campaigns/summary")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_launch_with_department_audience_sends_only_to_matching_entries(auth_client, monkeypatch):
    """Phishing Simulation roadmap Phase 15 — targeted training segments."""
    client, tenant = auth_client
    target_list_resp = await client.post(
        "/phishing-target-lists", json={"name": "Staff", "entries": [
            {"email": "jane@example.com", "department": "Finance"},
            {"email": "bob@example.com", "department": "Engineering"},
        ]},
    )
    target_list_id = target_list_resp.json()["id"]
    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": target_list_id, "template_id": "shared-document", "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    sent = []
    async def fake_send_email(db, to, subject, body_html):
        sent.append(to)
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    resp = await client.post(
        f"/engagements/{engagement_id}/phishing-campaigns",
        json={"audience_type": "department", "department": "Finance"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert sent == ["jane@example.com"]
    assert body["audience_label"] == "Finance department (1 of 2)"


async def test_launch_with_department_audience_400s_on_no_matching_entries(auth_client, monkeypatch):
    client, tenant = auth_client
    target_list_resp = await client.post(
        "/phishing-target-lists", json={"name": "Staff", "entries": [{"email": "jane@example.com", "department": "Finance"}]},
    )
    target_list_id = target_list_resp.json()["id"]
    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": target_list_id, "template_id": "shared-document", "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    resp = await client.post(
        f"/engagements/{engagement_id}/phishing-campaigns",
        json={"audience_type": "department", "department": "Nonexistent"},
    )
    assert resp.status_code == 400


async def test_department_breakdown_reflects_real_click_and_credential_counts(auth_client, db_session, monkeypatch):
    """Real, server-side-aggregated department results — never a
    hash-to-department mapping exposed to the client, only counts."""
    client, tenant = auth_client
    target_list_resp = await client.post(
        "/phishing-target-lists", json={"name": "Staff", "entries": [
            {"email": "jane@example.com", "department": "Finance"},
            {"email": "amy@example.com", "department": "Finance"},
            {"email": "bob@example.com", "department": "Engineering"},
        ]},
    )
    target_list_id = target_list_resp.json()["id"]
    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": target_list_id, "template_id": "shared-document", "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    launch_resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    campaign_id = launch_resp.json()["id"]

    from sqlalchemy import select
    from app.models import PhishingEvent
    sent_events = (await db_session.execute(
        select(PhishingEvent).where(PhishingEvent.campaign_id == uuid.UUID(campaign_id))
    )).scalars().all()
    by_hash = {e.recipient_hash: e for e in sent_events}
    assert len(by_hash) == 3

    # Real recipient-level identification for this test only — re-hash the
    # known emails the same way the app does, so we can attribute specific
    # click/credential events to a specific real person's department.
    from app.services.phishing_service import _hash_recipient
    jane_hash = _hash_recipient("jane@example.com", tenant.id)
    bob_hash = _hash_recipient("bob@example.com", tenant.id)

    db_session.add(PhishingEvent(
        id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=uuid.UUID(campaign_id),
        recipient_hash=jane_hash, recipient_token=by_hash[jane_hash].recipient_token, event_type="clicked",
    ))
    db_session.add(PhishingEvent(
        id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=uuid.UUID(campaign_id),
        recipient_hash=jane_hash, recipient_token=by_hash[jane_hash].recipient_token, event_type="credential_entered",
    ))
    db_session.add(PhishingEvent(
        id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=uuid.UUID(campaign_id),
        recipient_hash=bob_hash, recipient_token=by_hash[bob_hash].recipient_token, event_type="clicked",
    ))
    await db_session.commit()

    resp = await client.get(f"/phishing-campaigns/{campaign_id}/department-breakdown")
    assert resp.status_code == 200
    breakdown = {b["department"]: b for b in resp.json()}
    assert breakdown["Finance"] == {"department": "Finance", "sent": 2, "clicked": 1, "credential_entered": 1}
    assert breakdown["Engineering"] == {"department": "Engineering", "sent": 1, "clicked": 1, "credential_entered": 0}
    # Never a hash, an email, or any per-person field in the response.
    for b in resp.json():
        assert set(b.keys()) == {"department", "sent", "clicked", "credential_entered"}


async def test_department_breakdown_excludes_entries_with_no_department_recorded(auth_client, monkeypatch):
    client, tenant = auth_client
    target_list_resp = await client.post(
        "/phishing-target-lists", json={"name": "Staff", "entries": [
            {"email": "jane@example.com", "department": "Finance"},
            {"email": "nodept@example.com"},
        ]},
    )
    target_list_id = target_list_resp.json()["id"]
    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": target_list_id, "template_id": "shared-document", "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    launch_resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    campaign_id = launch_resp.json()["id"]

    resp = await client.get(f"/phishing-campaigns/{campaign_id}/department-breakdown")
    assert resp.status_code == 200
    breakdown = resp.json()
    # Only the one real department shows up — the un-departmented entry
    # contributes to no bucket, never a fabricated "Unknown" department.
    assert breakdown == [{"department": "Finance", "sent": 1, "clicked": 0, "credential_entered": 0}]


async def test_department_breakdown_empty_when_nobody_has_a_department(auth_client, monkeypatch):
    client, tenant = auth_client
    campaign = await _launch_a_campaign(client, monkeypatch)  # entries have no department at all
    resp = await client.get(f"/phishing-campaigns/{campaign['id']}/department-breakdown")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_launch_with_individual_audience_sends_only_to_selected_real_hashes(auth_client, monkeypatch):
    client, tenant = auth_client
    target_list_resp = await client.post(
        "/phishing-target-lists", json={"name": "Staff", "entries": [
            {"email": "jane@example.com"}, {"email": "bob@example.com"},
        ]},
    )
    target_list_id = target_list_resp.json()["id"]
    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": target_list_id, "template_id": "shared-document", "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    sent = []
    async def fake_send_email(db, to, subject, body_html):
        sent.append(to)
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    jane_hash = svc._hash_recipient("jane@example.com", tenant.id)
    resp = await client.post(
        f"/engagements/{engagement_id}/phishing-campaigns",
        json={"audience_type": "individual", "recipient_hashes": [jane_hash]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert sent == ["jane@example.com"]
    assert body["audience_label"] == "1 individually selected recipient"


async def test_launch_with_individual_audience_400s_when_no_hashes_match(auth_client, monkeypatch):
    client, tenant = auth_client
    target_list_resp = await client.post(
        "/phishing-target-lists", json={"name": "Staff", "entries": [{"email": "jane@example.com"}]},
    )
    target_list_id = target_list_resp.json()["id"]
    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": target_list_id, "template_id": "shared-document", "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    resp = await client.post(
        f"/engagements/{engagement_id}/phishing-campaigns",
        json={"audience_type": "individual", "recipient_hashes": ["not-a-real-hash"]},
    )
    assert resp.status_code == 400


async def test_launch_audit_log_records_the_real_scoped_recipient_count(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    target_list_resp = await client.post(
        "/phishing-target-lists", json={"name": "Staff", "entries": [
            {"email": "jane@example.com", "department": "Finance"},
            {"email": "bob@example.com", "department": "Engineering"},
        ]},
    )
    target_list_id = target_list_resp.json()["id"]
    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": target_list_id, "template_id": "shared-document", "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    await client.post(
        f"/engagements/{engagement_id}/phishing-campaigns",
        json={"audience_type": "department", "department": "Finance"},
    )

    from sqlalchemy import select
    from app.models import AuditLogEntry
    entry = (await db_session.execute(
        select(AuditLogEntry).where(AuditLogEntry.action == "phishing.campaign_launched")
    )).scalars().first()
    assert entry.after["recipient_count"] == 1  # not the full list's 2
    assert entry.after["audience"] == "Finance department (1 of 2)"


async def test_get_campaign_events_returns_aggregate_counts(auth_client, monkeypatch):
    client, tenant = auth_client
    campaign = await _launch_a_campaign(client, monkeypatch)

    resp = await client.get(f"/phishing-campaigns/{campaign['id']}/events")
    assert resp.status_code == 200
    assert resp.json() == {
        "sent": 1, "opened": 0, "clicked": 0, "credential_entered": 0, "reported": 0, "send_failed": 0,
        "training_assigned": 0, "training_completed": 0, "median_dwell_seconds": None,
    }


async def test_list_phishing_campaigns_returns_history_for_the_engagement(auth_client, monkeypatch):
    client, tenant = auth_client
    campaign = await _launch_a_campaign(client, monkeypatch)

    engagements_resp = await client.get("/engagements")
    engagement_id = next(e["id"] for e in engagements_resp.json() if e["tier"] == "phishing")

    resp = await client.get(f"/engagements/{engagement_id}/phishing-campaigns")
    assert resp.status_code == 200
    ids = [c["id"] for c in resp.json()]
    assert ids == [campaign["id"]]


async def test_get_campaign_events_by_recipient_lists_hashes_not_identities(auth_client, monkeypatch):
    client, tenant = auth_client
    campaign = await _launch_a_campaign(client, monkeypatch)

    resp = await client.get(f"/phishing-campaigns/{campaign['id']}/events/by-recipient")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["event_types"] == ["sent"]
    assert "email" not in rows[0]
    assert "jane@example.com" not in str(rows)
    assert rows[0]["dwell_seconds"] is None  # no open recorded yet — honest absence


async def test_dwell_seconds_reflects_a_real_open_to_click_gap(auth_client, db_session, monkeypatch):
    """Phishing Simulation roadmap Phase 12 — the hesitation/dwell-time
    signal, surfaced both per-recipient and as a campaign-level median."""
    client, tenant = auth_client
    campaign = await _launch_a_campaign(client, monkeypatch)

    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select
    from app.models import PhishingEvent
    result = await db_session.execute(select(PhishingEvent).where(PhishingEvent.campaign_id == uuid.UUID(campaign["id"])))
    sent_event = result.scalars().first()

    opened_at = datetime.now(timezone.utc)
    db_session.add(PhishingEvent(
        id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=sent_event.campaign_id,
        recipient_hash=sent_event.recipient_hash, recipient_token=sent_event.recipient_token,
        event_type="opened", occurred_at=opened_at,
    ))
    db_session.add(PhishingEvent(
        id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=sent_event.campaign_id,
        recipient_hash=sent_event.recipient_hash, recipient_token=sent_event.recipient_token,
        event_type="clicked", occurred_at=opened_at + timedelta(seconds=42),
    ))
    await db_session.commit()

    by_recipient_resp = await client.get(f"/phishing-campaigns/{campaign['id']}/events/by-recipient")
    assert by_recipient_resp.json()[0]["dwell_seconds"] == 42.0

    counts_resp = await client.get(f"/phishing-campaigns/{campaign['id']}/events")
    assert counts_resp.json()["median_dwell_seconds"] == 42.0


async def test_export_campaign_events_csv_contains_real_hashed_rows_not_identities(auth_client, monkeypatch):
    client, tenant = auth_client
    campaign = await _launch_a_campaign(client, monkeypatch)

    resp = await client.get(f"/phishing-campaigns/{campaign['id']}/export.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "attachment" in resp.headers["content-disposition"]
    body = resp.text
    assert "recipient_hash,event_type,occurred_at,ip_address,destination_url" in body
    assert "sent" in body
    assert "jane@example.com" not in body  # hashed export, not an identity leak


async def test_campaign_email_auth_evidence_endpoint_returns_none_when_no_data(auth_client, monkeypatch):
    client, tenant = auth_client
    campaign = await _launch_a_campaign(client, monkeypatch)

    resp = await client.get(f"/phishing-campaigns/{campaign['id']}/email-auth-evidence")
    assert resp.status_code == 200
    assert resp.json() is None  # honest absence — this tenant has no domain/DMARC data seeded


async def test_campaign_email_auth_evidence_endpoint_returns_real_dmarc_data(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="acme.example")
    await make_dmarc_aggregate(db_session, domain, days_ago=3, total_count=50, fail_count=12)
    await db_session.commit()

    campaign = await _launch_a_campaign(client, monkeypatch)
    resp = await client.get(f"/phishing-campaigns/{campaign['id']}/email-auth-evidence")
    assert resp.status_code == 200
    body = resp.json()
    assert body["unaligned_message_count"] == 12
    assert body["total_message_count"] == 50


async def test_unmask_requires_admin_role(auth_client, client, db_session, monkeypatch):
    owner_client, tenant = auth_client
    campaign = await _launch_a_campaign(owner_client, monkeypatch)

    viewer = await make_user(db_session, tenant, email="viewer@example.com", password="pass123", role="viewer")
    await db_session.commit()
    login = await client.post(
        "/auth/token", data={"username": "viewer@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    resp = await client.post(f"/phishing-campaigns/{campaign['id']}/events/unmask", json={"recipient_hash": "whatever"})
    assert resp.status_code == 403


async def test_unmask_resolves_the_real_recipient_and_audits_it(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    campaign = await _launch_a_campaign(client, monkeypatch)

    from sqlalchemy import select
    from app.models import PhishingEvent
    result = await db_session.execute(select(PhishingEvent).where(PhishingEvent.campaign_id == uuid.UUID(campaign["id"])))
    sent_event = result.scalars().first()

    resp = await client.post(f"/phishing-campaigns/{campaign['id']}/events/unmask", json={"recipient_hash": sent_event.recipient_hash})
    assert resp.status_code == 200
    body = resp.json()
    assert body["email"] == "jane@example.com"
    # No AWS identity has ever been resolved for jane@example.com in this test —
    # honest absence, not a fabricated "verified" state (Phase 8).
    assert body["cloud_identity_provenance"] is None
    assert body["open_privesc_paths"] == []

    from app.models import AuditLogEntry
    audit_result = await db_session.execute(select(AuditLogEntry).where(AuditLogEntry.action == "phishing.recipient_unmasked"))
    assert audit_result.scalars().first() is not None


async def test_unmask_unknown_hash_returns_404(auth_client, monkeypatch):
    client, tenant = auth_client
    campaign = await _launch_a_campaign(client, monkeypatch)

    resp = await client.post(f"/phishing-campaigns/{campaign['id']}/events/unmask", json={"recipient_hash": "not-a-real-hash"})
    assert resp.status_code == 404


async def test_engagement_recipients_aggregates_across_two_campaigns_sharing_a_recipient(auth_client, db_session, monkeypatch):
    """Phishing Simulation roadmap Phase 13 — the cross-campaign People
    view. Same target list launched twice on the same engagement; the
    shared recipient (jane@example.com, deterministic hash) should show up
    as ONE row with both campaigns reflected, not two separate rows."""
    client, tenant = auth_client
    target_list_resp = await client.post(
        "/phishing-target-lists", json={"name": "Staff", "entries": [{"email": "jane@example.com"}]},
    )
    target_list_id = target_list_resp.json()["id"]
    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": target_list_id, "template_id": "shared-document", "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    first = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    second = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    assert first.status_code == 200 and second.status_code == 200

    from sqlalchemy import select
    from app.models import PhishingEvent
    first_sent = (await db_session.execute(
        select(PhishingEvent).where(PhishingEvent.campaign_id == uuid.UUID(first.json()["id"]))
    )).scalars().first()
    second_sent = (await db_session.execute(
        select(PhishingEvent).where(PhishingEvent.campaign_id == uuid.UUID(second.json()["id"]))
    )).scalars().first()
    assert first_sent.recipient_hash == second_sent.recipient_hash  # deterministic per tenant+email

    db_session.add(PhishingEvent(
        id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=first_sent.campaign_id,
        recipient_hash=first_sent.recipient_hash, recipient_token=first_sent.recipient_token, event_type="clicked",
    ))
    db_session.add(PhishingEvent(
        id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=second_sent.campaign_id,
        recipient_hash=second_sent.recipient_hash, recipient_token=second_sent.recipient_token, event_type="reported",
    ))
    await db_session.commit()

    resp = await client.get(f"/engagements/{engagement_id}/phishing-recipients")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    row = rows[0]
    assert row["recipient_hash"] == first_sent.recipient_hash
    assert len(row["campaigns"]) == 2
    assert set(row["event_types"]) == {"sent", "clicked", "reported"}
    assert row["repeat_click_count"] == 1
    assert "jane@example.com" not in str(rows)  # still pseudonymized


async def test_engagement_recipients_is_tenant_isolated(auth_client, client, db_session, monkeypatch):
    # auth_client's returned client and the bare `client` fixture are the
    # SAME AsyncClient instance (auth_client just sets its Authorization
    # header) — so the owning tenant's engagement id must be captured
    # BEFORE the header is switched to the other tenant below, or this
    # "owner" lookup would silently run as the other tenant too.
    owner_client, tenant = auth_client
    campaign = await _launch_a_campaign(owner_client, monkeypatch)
    engagements_resp = await owner_client.get("/engagements")
    engagement_id = next(e["id"] for e in engagements_resp.json() if e["tier"] == "phishing")

    from app.models.user import Tenant
    other_tenant = Tenant(id=uuid.uuid4(), name="Other Co", plan="free")
    db_session.add(other_tenant)
    await db_session.flush()
    await make_user(db_session, other_tenant, email="other-owner@example.com", password="pass123")
    await db_session.commit()

    login = await client.post(
        "/auth/token", data={"username": "other-owner@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    resp = await client.get(f"/engagements/{engagement_id}/phishing-recipients")
    assert resp.status_code == 404


async def test_engagement_recipients_returns_empty_list_for_an_engagement_with_no_campaigns(auth_client):
    client, tenant = auth_client
    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": str(uuid.uuid4()), "template_id": "shared-document", "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]

    resp = await client.get(f"/engagements/{engagement_id}/phishing-recipients")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_unmask_includes_open_privesc_paths_for_a_resolved_aws_identity(auth_client, db_session, monkeypatch):
    """Coverage Map plan phishing transformation, Phase 8 — unmasking a
    recipient whose email is already linked to a real AWS identity with an
    open escalation path surfaces both the path and its real provenance."""
    client, tenant = auth_client
    campaign = await _launch_a_campaign(client, monkeypatch)

    from sqlalchemy import select
    from app.models import CloudAccountConnection, CloudPrivEscPath, Engagement, PhishingEvent
    from app.services.identity_resolution_service import resolve_or_create_actor

    result = await db_session.execute(select(PhishingEvent).where(PhishingEvent.campaign_id == uuid.UUID(campaign["id"])))
    sent_event = result.scalars().first()

    cloud_engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add(cloud_engagement)
    await db_session.flush()
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123", status="connected",
    )
    db_session.add(connection)
    await db_session.flush()
    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=cloud_engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:user/jane", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical", status="open",
    )
    db_session.add(path)
    await resolve_or_create_actor(
        db_session, tenant.id, "aws_iam", "arn:aws:iam::123456789012:user/jane",
        email="jane@example.com", email_provenance="sso_session",
    )
    await db_session.commit()

    resp = await client.post(f"/phishing-campaigns/{campaign['id']}/events/unmask", json={"recipient_hash": sent_event.recipient_hash})
    assert resp.status_code == 200
    body = resp.json()
    assert body["cloud_identity_provenance"] == "sso_session"
    assert len(body["open_privesc_paths"]) == 1
    assert body["open_privesc_paths"][0]["id"] == str(path.id)
    assert body["open_privesc_paths"][0]["severity"] == "critical"


async def test_phishing_meta_reports_tracking_domain_and_paused_state(auth_client):
    client, _tenant = auth_client
    resp = await client.get("/phishing-meta")
    assert resp.status_code == 200
    body = resp.json()
    assert body["phishing_paused"] is False
    assert body["tracking_domain"]
    assert body["sending_identity"]
    assert body["credential_capture_policy"] and body["recipient_privacy_policy"]


async def test_halt_then_resume_all_phishing_sends(auth_client):
    client, _tenant = auth_client
    halt_resp = await client.post("/phishing-meta/halt")
    assert halt_resp.status_code == 200
    assert halt_resp.json()["phishing_paused"] is True

    resume_resp = await client.post("/phishing-meta/resume")
    assert resume_resp.status_code == 200
    assert resume_resp.json()["phishing_paused"] is False


async def test_launch_campaign_with_qr_template_embeds_a_real_qr_image(auth_client, monkeypatch):
    """Phishing Simulation roadmap Phase 27 — end-to-end through the real
    launch route, not just the pure _render_content() unit tests in
    test_phishing_service.py: the campaign's stored body_html_sent (the
    real, fully-rendered body one actual delivered recipient received)
    must contain a real QR image, never the literal {qr_code} token."""
    client, tenant = auth_client
    target_list_resp = await client.post(
        "/phishing-target-lists", json={"name": "Staff", "entries": [{"email": "jane@example.com"}]},
    )
    target_list_id = target_list_resp.json()["id"]
    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": target_list_id, "template_id": "qr-delivery-scan", "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    assert resp.status_code == 200
    campaign = resp.json()
    assert campaign["status"] == "complete"
    assert "{qr_code}" not in campaign["body_html_sent"]
    assert "data:image/png;base64," in campaign["body_html_sent"]


async def test_launch_campaign_blocked_while_halted(auth_client, monkeypatch):
    client, tenant = auth_client
    target_list_resp = await client.post(
        "/phishing-target-lists", json={"name": "Staff", "entries": [{"email": "jane@example.com"}]},
    )
    target_list_id = target_list_resp.json()["id"]
    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": target_list_id, "template_id": "shared-document", "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    await client.post("/phishing-meta/halt")
    launch_resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    assert launch_resp.status_code == 400
    assert "HALT ALL SENDS" in launch_resp.json()["detail"]


async def test_launch_campaign_rejects_viewer_but_allows_approver(auth_client, client, db_session, monkeypatch):
    owner_client, tenant = auth_client
    target_list_resp = await owner_client.post(
        "/phishing-target-lists", json={"name": "Staff", "entries": [{"email": "jane@example.com"}]},
    )
    target_list_id = target_list_resp.json()["id"]
    create_resp = await owner_client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": target_list_id, "template_id": "shared-document", "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]
    await owner_client.post(f"/engagements/{engagement_id}/approve")

    async def fake_send_email(db, to, subject, body_html):
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    viewer = await make_user(db_session, tenant, email="viewer@example.com", password="pass123", role="viewer")
    await db_session.commit()
    login = await client.post(
        "/auth/token", data={"username": "viewer@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
    viewer_resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    assert viewer_resp.status_code == 403

    approver = await make_user(db_session, tenant, email="approver@example.com", password="pass123", role="approver")
    await db_session.commit()
    login2 = await client.post(
        "/auth/token", data={"username": "approver@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {login2.json()['access_token']}"})
    approver_resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    assert approver_resp.status_code == 200


async def test_halt_resume_and_unmask_still_reject_an_approver(auth_client, client, db_session, monkeypatch):
    """Approver is a real, narrower role than admin — the tenant-wide kill
    switch and identity-unmask stay admin-only, unlike launching a
    campaign."""
    owner_client, tenant = auth_client
    campaign = await _launch_a_campaign(owner_client, monkeypatch)

    approver = await make_user(db_session, tenant, email="approver2@example.com", password="pass123", role="approver")
    await db_session.commit()
    login = await client.post(
        "/auth/token", data={"username": "approver2@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    assert (await client.post("/phishing-meta/halt")).status_code == 403
    assert (await client.post("/phishing-meta/resume")).status_code == 403
    assert (await client.post(f"/phishing-campaigns/{campaign['id']}/events/unmask", json={"recipient_hash": "x"})).status_code == 403


async def test_exemption_crud_is_admin_only_and_rejects_approver(auth_client, db_session):
    # auth_client's client and its tuple's client are the same object, so
    # role-switching must be strictly sequential — do every admin action
    # first, then switch identity, matching test_unmask_requires_admin_
    # role's established pattern (never try to hold two logins at once).
    client, tenant = auth_client

    admin_resp = await client.post("/phishing-exemptions", json={"email": "exempt@example.com", "reason": "union agreement"})
    assert admin_resp.status_code == 201
    exemption_id = admin_resp.json()["id"]

    list_resp = await client.get("/phishing-exemptions")
    assert len(list_resp.json()) == 1
    assert list_resp.json()[0]["email"] == "exempt@example.com"

    await make_user(db_session, tenant, email="approver3@example.com", password="pass123", role="approver")
    await db_session.commit()
    login = await client.post(
        "/auth/token", data={"username": "approver3@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    create_denied = await client.post("/phishing-exemptions", json={"email": "other@example.com"})
    assert create_denied.status_code == 403

    delete_denied = await client.delete(f"/phishing-exemptions/{exemption_id}")
    assert delete_denied.status_code == 403


async def test_exempted_recipient_is_excluded_from_a_launch(auth_client, monkeypatch):
    client, tenant = auth_client
    target_list_resp = await client.post(
        "/phishing-target-lists",
        json={"name": "Staff", "entries": [{"email": "jane@example.com"}, {"email": "exempt@example.com"}]},
    )
    target_list_id = target_list_resp.json()["id"]
    await client.post("/phishing-exemptions", json={"email": "EXEMPT@example.com"})  # case-insensitive on purpose

    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": target_list_id, "template_id": "shared-document", "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    sent_to: list[str] = []

    async def fake_send_email(db, to, subject, body_html):
        sent_to.append(to)
        return True
    monkeypatch.setattr(svc, "send_email", fake_send_email)

    launch_resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    assert launch_resp.status_code == 200
    assert sent_to == ["jane@example.com"]


async def test_launch_400s_when_every_recipient_in_the_audience_is_exempted(auth_client):
    client, tenant = auth_client
    target_list_resp = await client.post(
        "/phishing-target-lists", json={"name": "Staff", "entries": [{"email": "jane@example.com"}]},
    )
    target_list_id = target_list_resp.json()["id"]
    await client.post("/phishing-exemptions", json={"email": "jane@example.com"})

    create_resp = await client.post(
        "/engagements",
        json={"tier": "phishing", "scope": {"target_list_id": target_list_id, "template_id": "shared-document", "cadence_days": 90}},
    )
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    launch_resp = await client.post(f"/engagements/{engagement_id}/phishing-campaigns")
    assert launch_resp.status_code == 400
    assert "exemption" in launch_resp.json()["detail"].lower()


async def test_report_schedule_rejects_invalid_value(auth_client):
    client, _tenant = auth_client
    resp = await client.patch("/phishing-meta/report-schedule", json={"schedule": "daily"})
    assert resp.status_code == 400


async def test_report_schedule_is_plan_gated_on_the_free_plan(auth_client):
    # auth_client's default tenant is on the free plan, which does not
    # include scheduled_reports.
    client, _tenant = auth_client
    resp = await client.patch("/phishing-meta/report-schedule", json={"schedule": "weekly"})
    assert resp.status_code == 403


async def test_report_schedule_succeeds_on_a_pro_plan_and_reflects_in_meta(client, db_session):
    tenant = await make_tenant(db_session, plan="pro")
    await make_user(db_session, tenant, email="pro-admin@example.com", password="pass123", role="admin")
    await db_session.flush()
    login = await client.post(
        "/auth/token", data={"username": "pro-admin@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    resp = await client.patch("/phishing-meta/report-schedule", json={"schedule": "weekly"})
    assert resp.status_code == 200
    assert resp.json()["phishing_report_schedule"] == "weekly"

    meta_resp = await client.get("/phishing-meta")
    assert meta_resp.json()["phishing_report_schedule"] == "weekly"
    assert meta_resp.json()["last_phishing_report_sent_at"] is None


async def test_report_schedule_rejects_non_admin(client, db_session):
    tenant = await make_tenant(db_session, plan="pro")
    await make_user(db_session, tenant, email="viewer-report@example.com", password="pass123", role="viewer")
    await db_session.flush()
    login = await client.post(
        "/auth/token", data={"username": "viewer-report@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    resp = await client.patch("/phishing-meta/report-schedule", json={"schedule": "weekly"})
    assert resp.status_code == 403
