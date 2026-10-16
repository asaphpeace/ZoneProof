"""
Sentinel Command report (app/services/command_report_service.py, Coverage
Map plan Phase 10) — the distillation of Phases 0-9 into one document.
Covers the pure-assembly function against seeded rows and the two new
endpoints (own-tenant report, MSP white-label client report). PDF
rendering itself (Playwright/Chromium) is mocked at the same boundary
scheduled_report_service.py already treats as external — these tests
assert on the assembled data and HTML string, not on real browser output.
"""
import uuid

from app.models import (
    CloudAccountConnection, CloudPrivEscPath, Engagement, Finding,
    HostConnection, PhishingCampaign, PhishingEvent, PhishingTargetList,
)
from app.services.command_report_service import assemble_command_report, build_command_report_html
from tests.factories import make_tenant, make_user


async def _login(client, email: str, password: str = "pass123") -> str:
    resp = await client.post(
        "/auth/token",
        data={"username": email, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return resp.json()["access_token"]


async def _make_cloud_connection_and_engagement(db_session, tenant):
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123", status="connected",
    )
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add_all([connection, engagement])
    await db_session.flush()
    return connection, engagement


async def test_assemble_command_report_is_honest_about_an_empty_tenant(db_session):
    tenant = await make_tenant(db_session, plan="pro")
    user = await make_user(db_session, tenant, email="admin@example.com", password="pass123")
    await db_session.flush()

    report = await assemble_command_report(db_session, tenant, user)

    assert report.tenant_name == tenant.name
    assert report.total_open_findings == 0
    assert report.findings_by_tier == []
    assert report.attack_paths.open_count == 0
    assert report.phishing is None
    assert report.connections.cloud_connections_connected == 0


async def test_assemble_command_report_counts_real_connections_and_findings(db_session):
    tenant = await make_tenant(db_session, plan="pro")
    user = await make_user(db_session, tenant, email="admin@example.com", password="pass123")
    connection, engagement = await _make_cloud_connection_and_engagement(db_session, tenant)

    host_connection = HostConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, hostname_or_ip="10.0.0.5",
        ssh_username="ubuntu", status="connected",
        encrypted_private_key="fake-encrypted-key", public_key="ssh-ed25519 AAAA fake",
        public_key_fingerprint="SHA256:fakefingerprint",
    )
    db_session.add(host_connection)

    db_session.add_all([
        Finding(
            id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
            tier="cloud", severity="critical", title="Public S3 bucket", status="open",
            check_id="s3_bucket_public", resource_uid="arn:aws:s3:::example-bucket",
        ),
        Finding(
            id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
            tier="cloud", severity="medium", title="Old access key", status="open",
            check_id="iam_key_age",
        ),
        # A resolved finding must not count toward the open totals.
        Finding(
            id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
            tier="cloud", severity="high", title="Fixed already", status="remediated",
            check_id="mfa_missing",
        ),
    ])
    await db_session.commit()

    report = await assemble_command_report(db_session, tenant, user)

    assert report.connections.cloud_connections_connected == 1
    assert report.connections.host_connections_connected == 1
    assert report.total_open_findings == 2
    assert report.total_critical_findings == 1
    [tier_row] = report.findings_by_tier
    assert tier_row.tier == "cloud"
    assert tier_row.open_count == 2
    assert tier_row.critical_count == 1
    assert tier_row.medium_count == 1
    assert report.top_findings[0].severity == "critical"  # sorted worst-first


async def test_assemble_command_report_includes_attack_paths_with_detection_verdict(db_session):
    tenant = await make_tenant(db_session, plan="pro")
    user = await make_user(db_session, tenant, email="admin@example.com", password="pass123")
    connection, engagement = await _make_cloud_connection_and_engagement(db_session, tenant)

    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/ec2-deploy-role",
        target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical",
    )
    db_session.add(path)
    await db_session.commit()

    report = await assemble_command_report(db_session, tenant, user)

    assert report.attack_paths.open_count == 1
    assert report.attack_paths.critical_count == 1
    # No CloudTrail/GuardDuty findings exist — Prowler's absence-means-pass
    # convention — so this path is "covered".
    assert report.attack_paths.covered_count == 1
    [top] = report.attack_paths.top_paths
    assert top.detection_verdict == "covered"


async def test_assemble_command_report_includes_phishing_summary_when_campaigns_exist(db_session):
    tenant = await make_tenant(db_session, plan="pro")
    user = await make_user(db_session, tenant, email="admin@example.com", password="pass123")

    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="phishing", status="active")
    target_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[])
    db_session.add_all([engagement, target_list])
    await db_session.flush()

    campaign = PhishingCampaign(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, target_list_id=target_list.id,
        template_id="invoice_urgent", status="complete",
        llm_generated=True, subject_sent="Invoice overdue", dmarc_context="p=none",
    )
    db_session.add(campaign)
    await db_session.flush()

    db_session.add_all([
        PhishingEvent(id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id, recipient_hash="h1", recipient_token="t1", event_type="sent"),
        PhishingEvent(id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id, recipient_hash="h1", recipient_token="t1", event_type="opened"),
        PhishingEvent(id=uuid.uuid4(), tenant_id=tenant.id, campaign_id=campaign.id, recipient_hash="h1", recipient_token="t1", event_type="clicked"),
    ])
    await db_session.commit()

    report = await assemble_command_report(db_session, tenant, user)

    assert report.phishing is not None
    assert report.phishing.campaign_count == 1
    assert report.phishing.total_sent == 1
    assert report.phishing.total_clicked == 1
    assert report.phishing.click_rate_pct == 100.0
    assert report.phishing.last_campaign_llm_generated is True
    assert report.phishing.last_campaign_dmarc_context == "p=none"


async def test_build_command_report_html_renders_real_data_not_placeholders(db_session):
    tenant = await make_tenant(db_session, plan="pro", name="Cobalt Manufacturing")
    user = await make_user(db_session, tenant, email="admin@example.com", password="pass123")
    connection, engagement = await _make_cloud_connection_and_engagement(db_session, tenant)
    db_session.add(Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        tier="cloud", severity="critical", title="Public S3 bucket exposing customer PII", status="open",
        check_id="s3_bucket_public", resource_uid="arn:aws:s3:::example-bucket",
    ))
    await db_session.commit()

    report = await assemble_command_report(db_session, tenant, user)
    html = build_command_report_html(report)

    assert "Cobalt Manufacturing" in html
    assert "Public S3 bucket exposing customer PII" in html
    assert "arn:aws:s3:::example-bucket" in html
    assert "<html>" in html and "</html>" in html


async def test_command_report_data_endpoint_requires_auth(client):
    resp = await client.get("/command-report-data")
    assert resp.status_code == 401


async def test_command_report_data_endpoint_returns_assembled_report(client, db_session):
    tenant = await make_tenant(db_session, plan="pro")
    await make_user(db_session, tenant, email="admin@example.com", password="pass123")
    await db_session.flush()
    token = await _login(client, "admin@example.com")

    resp = await client.get("/command-report-data", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["tenant_name"] == tenant.name
    assert body["total_open_findings"] == 0


async def test_command_report_pdf_blocked_on_free_plan(client, db_session):
    tenant = await make_tenant(db_session, plan="free")
    await make_user(db_session, tenant, email="free-admin@example.com", password="pass123")
    await db_session.flush()
    token = await _login(client, "free-admin@example.com")

    resp = await client.get("/command-report-pdf", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "feature_not_available"


async def test_command_report_pdf_endpoint_returns_real_pdf_bytes(client, db_session, monkeypatch):
    tenant = await make_tenant(db_session, plan="pro")
    await make_user(db_session, tenant, email="pro-admin@example.com", password="pass123")
    await db_session.flush()
    token = await _login(client, "pro-admin@example.com")

    async def _fake_render(report):
        assert report.tenant_name == tenant.name
        return b"%PDF-1.4 fake"

    import app.routers.command_report as command_report_router
    monkeypatch.setattr(command_report_router, "render_command_report_pdf", _fake_render)

    resp = await client.get("/command-report-pdf", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content == b"%PDF-1.4 fake"


async def test_msp_client_report_pdf_requires_white_label_plan(client, db_session, monkeypatch):
    msp_tenant = await make_tenant(db_session, plan="starter", name="Starter MSP")  # no white_label on starter
    await make_user(db_session, msp_tenant, email="starter-owner@example.com", password="pass123")
    await db_session.flush()
    token = await _login(client, "starter-owner@example.com")

    resp = await client.get("/msp/clients/does-not-matter/report-pdf", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


async def test_msp_client_report_pdf_is_branded_with_the_clients_own_brand(client, db_session, monkeypatch):
    msp_tenant = await make_tenant(db_session, plan="msp", name="Acme MSP")
    await make_user(db_session, msp_tenant, email="msp-owner@example.com", password="pass123")
    await db_session.flush()
    token = await _login(client, "msp-owner@example.com")

    create_resp = await client.post(
        "/msp/clients", json={"name": "Client Co", "brand_name": "Client Co Security"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert create_resp.status_code == 201
    client_id = create_resp.json()["id"]

    from app.models.user import Tenant
    from sqlalchemy import select
    client_tenant = (await db_session.execute(select(Tenant).where(Tenant.id == client_id))).scalar_one()
    await make_user(db_session, client_tenant, email="client-admin@clientco.com", password="pass123")
    await db_session.commit()

    async def _fake_render(report):
        assert report.brand_name == "Client Co Security"
        return b"%PDF-1.4 client-branded"

    import app.routers.msp as msp_router
    monkeypatch.setattr(msp_router, "render_command_report_pdf", _fake_render)

    resp = await client.get(f"/msp/clients/{client_id}/report-pdf", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.content == b"%PDF-1.4 client-branded"
