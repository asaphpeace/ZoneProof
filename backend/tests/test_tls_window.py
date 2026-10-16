"""The TLS overview applies `days` to the reports' real periods, not to a month stamp."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models import TlsPolicy, TlsReport
from app.routers.tls import _windowed_aggregates
from app.services.tls_service import FAILURE_REASONS
from tests.factories import make_domain, make_tenant


async def _report(db, domain, end_days_ago, ok, failed, mx="mx.example.test"):
    end = datetime.now(timezone.utc) - timedelta(days=end_days_ago)
    r = TlsReport(
        id=uuid.uuid4(), domain_id=domain.id, report_id=str(uuid.uuid4()), org_name="Google",
        org_contact="x@example.test", period_begin=end - timedelta(days=1), period_end=end, raw_json="{}",
    )
    db.add(r)
    await db.flush()
    db.add(TlsPolicy(
        id=uuid.uuid4(), report_id=r.id, domain_id=domain.id, policy_type="sts",
        policy_domain=domain.name, policy_mx_host=mx,
        total_successful_session_count=ok, total_failure_session_count=failed,
    ))
    await db.flush()


@pytest.mark.asyncio
async def test_window_uses_report_period(db_session):
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant, name="window.test")
    await _report(db_session, domain, end_days_ago=2, ok=90, failed=10)
    await _report(db_session, domain, end_days_ago=20, ok=500, failed=0)
    await db_session.commit()

    week = await _windowed_aggregates(db_session, domain.id, datetime.now(timezone.utc) - timedelta(days=7))
    month = await _windowed_aggregates(db_session, domain.id, datetime.now(timezone.utc) - timedelta(days=30))

    assert [(a.total_sessions, a.failed_sessions) for a in week] == [(100, 10)]
    assert [(a.total_sessions, a.failed_sessions) for a in month] == [(600, 10)]


@pytest.mark.asyncio
async def test_window_empty_when_no_report_inside(db_session):
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant, name="window2.test")
    await _report(db_session, domain, end_days_ago=25, ok=10, failed=0)
    await db_session.commit()
    assert await _windowed_aggregates(db_session, domain.id, datetime.now(timezone.utc) - timedelta(days=7)) == []


def test_starttls_wording_describes_the_receiving_side():
    text = FAILURE_REASONS["starttls-not-supported"]
    assert "your mail server" in text
    assert "The sending server did not offer" not in text


@pytest.mark.asyncio
async def test_window_totals_for_portfolio_readers(db_session):
    from app.services.tls_service import tls_window_totals
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant, name="totals.test")
    await _report(db_session, domain, end_days_ago=2, ok=90, failed=10)
    await _report(db_session, domain, end_days_ago=60, ok=500, failed=500)
    assert await tls_window_totals(db_session, domain.id) == (100, 90, 10)
    assert await tls_window_totals(db_session, domain.id, days=90) == (1100, 590, 510)
