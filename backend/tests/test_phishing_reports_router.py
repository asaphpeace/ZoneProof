"""
Router-level tests for /reported-emails/* and /reported-emails/{id}/
unmask-reporter (Phishing Simulation roadmap Phase 26), plus the
auto-provisioned forwarding address on /phishing-meta.
"""
import uuid

from app.config import settings
from app.models import PhishingTargetList
from app.models.reported_email import ReportedEmail
from app.services.phishing_service import _hash_recipient
from tests.factories import make_tenant, make_user


async def _seed_report(db_session, tenant, **overrides):
    defaults = dict(
        id=uuid.uuid4(), tenant_id=tenant.id, reporter_hash="somehash",
        original_subject="Urgent: verify your account", original_from="attacker@evil.com",
        original_from_domain="evil.com", disposition="new",
    )
    defaults.update(overrides)
    report = ReportedEmail(**defaults)
    db_session.add(report)
    await db_session.commit()
    await db_session.refresh(report)
    return report


async def test_phishing_meta_auto_provisions_a_real_forwarding_address(auth_client):
    client, _tenant = auth_client
    resp = await client.get("/phishing-meta")
    assert resp.status_code == 200
    address = resp.json()["report_suspicious_email_address"]
    assert address.endswith(f"@{settings.reporting_domain}")
    slug = address.split("@")[0]
    assert len(slug) == 8

    # Stable across repeated calls — not regenerated every request.
    resp2 = await client.get("/phishing-meta")
    assert resp2.json()["report_suspicious_email_address"] == address


async def test_list_and_get_reported_emails(auth_client, db_session):
    client, tenant = auth_client
    report = await _seed_report(db_session, tenant)

    list_resp = await client.get("/reported-emails")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1
    assert list_resp.json()[0]["original_from"] == "attacker@evil.com"

    get_resp = await client.get(f"/reported-emails/{report.id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["original_subject"] == "Urgent: verify your account"


async def test_list_reported_emails_filters_by_disposition(auth_client, db_session):
    client, tenant = auth_client
    await _seed_report(db_session, tenant, disposition="new")
    await _seed_report(db_session, tenant, disposition="confirmed_malicious")

    resp = await client.get("/reported-emails?disposition=confirmed_malicious")
    assert len(resp.json()) == 1
    assert resp.json()[0]["disposition"] == "confirmed_malicious"


async def test_get_reported_email_404s_for_a_cross_tenant_report(auth_client, db_session):
    client, _tenant = auth_client
    other = await make_tenant(db_session, name="Other Co")
    report = await _seed_report(db_session, other)

    resp = await client.get(f"/reported-emails/{report.id}")
    assert resp.status_code == 404


async def test_update_disposition_rejects_an_invalid_value(auth_client, db_session):
    client, tenant = auth_client
    report = await _seed_report(db_session, tenant)
    resp = await client.patch(f"/reported-emails/{report.id}/disposition", json={"disposition": "not-a-real-value"})
    assert resp.status_code == 400


async def test_update_disposition_is_audited_with_real_before_and_after_values(client, db_session):
    tenant = await make_tenant(db_session, plan="enterprise")
    await make_user(db_session, tenant, email="disp-admin@example.com", password="pass123")
    await db_session.flush()
    login = await client.post("/auth/token", data={"username": "disp-admin@example.com", "password": "pass123"}, headers={"Content-Type": "application/x-www-form-urlencoded"})
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    report = await _seed_report(db_session, tenant)
    resp = await client.patch(f"/reported-emails/{report.id}/disposition", json={"disposition": "confirmed_malicious", "note": "Real phishing, matches a known campaign."})
    assert resp.status_code == 200
    assert resp.json()["disposition"] == "confirmed_malicious"
    assert resp.json()["disposition_at"] is not None

    audit_resp = await client.get("/audit-log")
    entries = [e for e in audit_resp.json() if e["action"] == "reported_email.disposition_changed"]
    assert len(entries) == 1
    assert entries[0]["before"] == {"disposition": "new", "disposition_note": None}
    assert entries[0]["after"] == {"disposition": "confirmed_malicious", "disposition_note": "Real phishing, matches a known campaign."}


async def test_update_disposition_rejects_viewer_but_allows_approver(client, db_session):
    tenant = await make_tenant(db_session, plan="free")
    await make_user(db_session, tenant, email="owner@example.com", password="pass123", role="admin")
    await make_user(db_session, tenant, email="viewer@example.com", password="pass123", role="viewer")
    await make_user(db_session, tenant, email="approver@example.com", password="pass123", role="approver")
    await db_session.flush()
    report = await _seed_report(db_session, tenant)

    async def login_as(email):
        r = await client.post("/auth/token", data={"username": email, "password": "pass123"}, headers={"Content-Type": "application/x-www-form-urlencoded"})
        client.headers.update({"Authorization": f"Bearer {r.json()['access_token']}"})

    await login_as("viewer@example.com")
    denied = await client.patch(f"/reported-emails/{report.id}/disposition", json={"disposition": "false_positive"})
    assert denied.status_code == 403

    await login_as("approver@example.com")
    allowed = await client.patch(f"/reported-emails/{report.id}/disposition", json={"disposition": "false_positive"})
    assert allowed.status_code == 200


async def test_unmask_reporter_requires_admin_not_just_approver(client, db_session):
    tenant = await make_tenant(db_session, plan="free")
    await make_user(db_session, tenant, email="owner@example.com", password="pass123", role="admin")
    await make_user(db_session, tenant, email="approver@example.com", password="pass123", role="approver")
    await db_session.flush()
    report = await _seed_report(db_session, tenant)

    login = await client.post("/auth/token", data={"username": "approver@example.com", "password": "pass123"}, headers={"Content-Type": "application/x-www-form-urlencoded"})
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    resp = await client.post(f"/reported-emails/{report.id}/unmask-reporter")
    assert resp.status_code == 403


async def test_unmask_reporter_resolves_a_real_match_and_audits_it(auth_client, db_session):
    client, tenant = auth_client
    tl = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "jane@realcompany.com"}])
    db_session.add(tl)
    await db_session.commit()
    report = await _seed_report(db_session, tenant, reporter_hash=_hash_recipient("jane@realcompany.com", tenant.id))

    resp = await client.post(f"/reported-emails/{report.id}/unmask-reporter")
    assert resp.status_code == 200
    assert resp.json()["email"] == "jane@realcompany.com"

    from sqlalchemy import select
    from app.models import AuditLogEntry
    audit_result = await db_session.execute(select(AuditLogEntry).where(AuditLogEntry.action == "reported_email.reporter_unmasked"))
    assert audit_result.scalars().first() is not None


async def test_unmask_reporter_404s_honestly_when_nobody_matches(auth_client, db_session):
    client, tenant = auth_client
    report = await _seed_report(db_session, tenant, reporter_hash="no-one-matches-this-hash")
    resp = await client.post(f"/reported-emails/{report.id}/unmask-reporter")
    assert resp.status_code == 404


# ── Link risk rescan (Phase 32) ─────────────────────────────────────────
# _seed_report's defaults leave urls_found=[] (the model's own default),
# which makes score_report_urls_best_effort's own early-return a no-op —
# real, unmocked network-free coverage for the role-gating/404 tests
# below. Tests that need a real scored result mock the scoring function
# itself, same as every other test file in this suite mocks outbound
# httpx rather than hitting a real network endpoint.

async def test_rescan_links_rejects_viewer_but_allows_approver(client, db_session):
    tenant = await make_tenant(db_session, plan="free")
    await make_user(db_session, tenant, email="owner@example.com", password="pass123", role="admin")
    await make_user(db_session, tenant, email="viewer@example.com", password="pass123", role="viewer")
    await make_user(db_session, tenant, email="approver@example.com", password="pass123", role="approver")
    await db_session.flush()
    report = await _seed_report(db_session, tenant)

    async def login_as(email):
        r = await client.post("/auth/token", data={"username": email, "password": "pass123"}, headers={"Content-Type": "application/x-www-form-urlencoded"})
        client.headers.update({"Authorization": f"Bearer {r.json()['access_token']}"})

    await login_as("viewer@example.com")
    denied = await client.post(f"/reported-emails/{report.id}/rescan-links")
    assert denied.status_code == 403

    await login_as("approver@example.com")
    allowed = await client.post(f"/reported-emails/{report.id}/rescan-links")
    assert allowed.status_code == 200


async def test_rescan_links_is_audited_with_real_before_and_after_counts(client, db_session, monkeypatch):
    from datetime import datetime, timezone
    from app.routers import phishing_reports as reports_router

    async def fake_scoring(db, report, **kwargs):
        report.url_risk = [
            {"url": "http://evil.example.xyz/login", "score": 5, "verdict": "likely_dangerous", "grade": "F", "explanation": "canned", "signals": {}},
            {"url": "http://example.com/clean", "score": 95, "verdict": "likely_safe", "grade": "A", "explanation": "canned", "signals": {}},
        ]
        report.url_risk_scored_at = datetime.now(timezone.utc)
    monkeypatch.setattr(reports_router, "score_report_urls_best_effort", fake_scoring)

    tenant = await make_tenant(db_session, plan="enterprise")
    await make_user(db_session, tenant, email="rescan-admin@example.com", password="pass123")
    await db_session.flush()
    login = await client.post("/auth/token", data={"username": "rescan-admin@example.com", "password": "pass123"}, headers={"Content-Type": "application/x-www-form-urlencoded"})
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    report = await _seed_report(db_session, tenant, urls_found=["http://evil.example.xyz/login", "http://example.com/clean"])

    resp = await client.post(f"/reported-emails/{report.id}/rescan-links")
    assert resp.status_code == 200
    assert len(resp.json()["url_risk"]) == 2

    audit_resp = await client.get("/audit-log")
    entries = [e for e in audit_resp.json() if e["action"] == "reported_email.links_rescanned"]
    assert len(entries) == 1
    assert entries[0]["before"] == {"scored_count": 0, "dangerous_count": 0}
    assert entries[0]["after"] == {"scored_count": 2, "dangerous_count": 1}


async def test_rescan_links_bypasses_cache_ttl(auth_client, db_session, monkeypatch):
    from app.routers import phishing_reports as reports_router

    calls = []

    async def tracking_scoring(db, report, **kwargs):
        calls.append(kwargs.get("force_refresh"))
    monkeypatch.setattr(reports_router, "score_report_urls_best_effort", tracking_scoring)

    client, tenant = auth_client
    report = await _seed_report(db_session, tenant, urls_found=["http://example.com/a"])

    resp = await client.post(f"/reported-emails/{report.id}/rescan-links")
    assert resp.status_code == 200
    assert calls == [True]


async def test_rescan_links_404s_for_cross_tenant_report(auth_client, db_session):
    client, _tenant = auth_client
    other = await make_tenant(db_session, name="Other Co")
    report = await _seed_report(db_session, other)

    resp = await client.post(f"/reported-emails/{report.id}/rescan-links")
    assert resp.status_code == 404


async def test_report_out_includes_url_risk_and_scored_at_when_present(auth_client, db_session):
    from datetime import datetime, timezone

    client, tenant = auth_client
    report = await _seed_report(
        db_session, tenant,
        url_risk=[{"url": "http://example.com", "score": 80, "verdict": "likely_safe", "grade": "B", "explanation": "ok", "signals": {}}],
        url_risk_scored_at=datetime.now(timezone.utc),
    )

    resp = await client.get(f"/reported-emails/{report.id}")
    assert resp.status_code == 200
    assert resp.json()["url_risk"] is not None
    assert resp.json()["url_risk_scored_at"] is not None


async def test_report_out_url_risk_is_null_before_first_scan(auth_client, db_session):
    client, tenant = auth_client
    report = await _seed_report(db_session, tenant)

    resp = await client.get(f"/reported-emails/{report.id}")
    assert resp.status_code == 200
    assert resp.json()["url_risk"] is None
