"""
Unit tests for phishing_evidence_service.py — the independent DMARC
aggregate + spoof-test evidence cited alongside a phishing campaign
report (Coverage Map plan phishing transformation, Phase 6).
"""
import uuid
from datetime import datetime, timedelta, timezone

from app.models import Engagement, Finding
from app.services import phishing_evidence_service as svc
from tests.factories import make_dmarc_aggregate, make_domain, make_tenant


async def test_returns_none_when_no_domain_id_given(db_session):
    assert await svc.get_email_auth_evidence(db_session, uuid.uuid4(), None, datetime.now(timezone.utc)) is None


async def test_returns_none_when_domain_has_no_evidence_yet(db_session):
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant)
    await db_session.commit()

    result = await svc.get_email_auth_evidence(db_session, tenant.id, domain.id, datetime.now(timezone.utc))
    assert result is None  # honest absence, not a fabricated zero block


async def test_real_dmarc_aggregate_volume_is_cited(db_session):
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant)
    await make_dmarc_aggregate(db_session, domain, days_ago=5, total_count=100, fail_count=30)
    await db_session.commit()

    result = await svc.get_email_auth_evidence(db_session, tenant.id, domain.id, datetime.now(timezone.utc))
    assert result is not None
    assert result["unaligned_message_count"] == 30
    assert result["total_message_count"] == 100
    assert result["spoof_test_status"] is None  # no impersonation scan history yet


async def test_aggregate_outside_the_window_is_excluded(db_session):
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant)
    await make_dmarc_aggregate(db_session, domain, days_ago=90, total_count=100, fail_count=30)  # far outside the 60-day window
    await db_session.commit()

    result = await svc.get_email_auth_evidence(db_session, tenant.id, domain.id, datetime.now(timezone.utc))
    assert result is None


async def test_real_spoof_test_finding_is_cited(db_session):
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="impersonation", domain_id=domain.id, status="active", scope={})
    db_session.add(engagement)
    await db_session.flush()
    finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, tier="impersonation", severity="critical",
        title="Spoofed email claiming to be from example.com was not blocked", status="open",
        check_id="IMPERSONATION-SPOOF-SEND-TEST", detail="SMTP accepted the spoofed message without rejection.",
    )
    db_session.add(finding)
    await db_session.commit()

    result = await svc.get_email_auth_evidence(db_session, tenant.id, domain.id, datetime.now(timezone.utc))
    assert result is not None
    assert result["spoof_test_status"] == "open"
    assert "SMTP accepted" in result["spoof_test_detail"]
    assert result["spoof_test_date"] is not None
