"""
cloud_scan_service.compute_tenant_cloud_posture_score — the tenant-wide
signal that feeds posture_service's Cloud Posture pillar. Computed from
open Finding severity + CloudPrivEscPath count rather than a pass ratio,
since only FAIL findings are ever persisted (run_prowler_scan filters to
--status FAIL) -- there's no "total checks run" to divide by.
"""
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CloudAccountConnection, CloudPrivEscPath, Engagement, Finding
from app.services.cloud_scan_service import compute_tenant_cloud_posture_score
from tests.factories import make_tenant


async def _make_connected_account(db_session: AsyncSession, tenant):
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123",
        status="connected",
    )
    db_session.add(connection)
    await db_session.flush()
    return connection


async def _make_engagement(db_session: AsyncSession, tenant):
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add(engagement)
    await db_session.flush()
    return engagement


async def test_returns_none_with_no_connected_account(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await db_session.commit()

    score = await compute_tenant_cloud_posture_score(db_session, tenant.id)
    assert score is None


async def test_returns_none_if_only_connection_is_not_connected_status(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection = await _make_connected_account(db_session, tenant)
    connection.status = "error"
    await db_session.commit()

    score = await compute_tenant_cloud_posture_score(db_session, tenant.id)
    assert score is None


async def test_full_score_when_connected_with_no_open_findings(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await _make_connected_account(db_session, tenant)
    await db_session.commit()

    score = await compute_tenant_cloud_posture_score(db_session, tenant.id)
    assert score == 100.0


async def test_deducts_by_severity_for_open_findings(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await _make_connected_account(db_session, tenant)
    engagement = await _make_engagement(db_session, tenant)

    db_session.add(Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        tier="cloud", severity="critical", title="Root MFA disabled", status="open",
    ))
    db_session.add(Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        tier="cloud", severity="low", title="Minor logging gap", status="open",
    ))
    await db_session.commit()

    score = await compute_tenant_cloud_posture_score(db_session, tenant.id)
    assert score == 100 - 15 - 1  # critical(15) + low(1)


async def test_remediated_findings_dont_count_against_the_score(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await _make_connected_account(db_session, tenant)
    engagement = await _make_engagement(db_session, tenant)

    db_session.add(Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        tier="cloud", severity="critical", title="Old finding, now fixed", status="retest_closed",
    ))
    await db_session.commit()

    score = await compute_tenant_cloud_posture_score(db_session, tenant.id)
    assert score == 100.0


async def test_deducts_for_open_priv_esc_paths(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection = await _make_connected_account(db_session, tenant)
    engagement = await _make_engagement(db_session, tenant)

    db_session.add(CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/escalatable",
        target_principal_arn="account-admin",
        technique_chain=["iam:createpolicyversion"], severity="high",
    ))
    await db_session.commit()

    score = await compute_tenant_cloud_posture_score(db_session, tenant.id)
    assert score == 100 - 20


async def test_score_floors_at_zero_rather_than_going_negative(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection = await _make_connected_account(db_session, tenant)
    engagement = await _make_engagement(db_session, tenant)

    for _ in range(10):
        db_session.add(CloudPrivEscPath(
            id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
            cloud_account_connection_id=connection.id,
            source_principal_arn="arn:aws:iam::123456789012:role/x",
            target_principal_arn="account-admin", technique_chain=["iam:x"], severity="critical",
        ))
    await db_session.commit()

    score = await compute_tenant_cloud_posture_score(db_session, tenant.id)
    assert score == 0.0


async def test_scoped_to_the_correct_tenant_only(db_session: AsyncSession):
    tenant_a = await make_tenant(db_session, name="Tenant A")
    tenant_b = await make_tenant(db_session, name="Tenant B")
    await _make_connected_account(db_session, tenant_a)
    connection_b = await _make_connected_account(db_session, tenant_b)
    engagement_b = await _make_engagement(db_session, tenant_b)

    db_session.add(Finding(
        id=uuid.uuid4(), tenant_id=tenant_b.id, engagement_id=engagement_b.id,
        tier="cloud", severity="critical", title="Only affects tenant B", status="open",
    ))
    await db_session.commit()

    score_a = await compute_tenant_cloud_posture_score(db_session, tenant_a.id)
    score_b = await compute_tenant_cloud_posture_score(db_session, tenant_b.id)

    assert score_a == 100.0
    assert score_b == 85.0
