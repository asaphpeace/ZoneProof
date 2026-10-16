"""
Continuous Threat Detection & Response — CloudTrail half (ITDR_DESIGN.md).
_lookup_cloudtrail_events_sync is monkeypatched directly (same pattern as
mocking _run_prowler_subprocess/_list_inspector_findings elsewhere in this
suite) rather than relying on moto's CloudTrail LookupEvents fidelity,
which — like Inspector2 — isn't guaranteed to simulate realistic data.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CloudAccountConnection, CloudPrivEscPath, Engagement, Finding, Investigation, InvestigationEvent
from app.services import threat_detection_service as svc
from tests.factories import make_tenant

_ROLE_ARN = "arn:aws:iam::123456789012:role/ec2-deploy-role"


def _assumed_role_event_detail(role_arn: str) -> dict:
    return {
        "userIdentity": {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::123456789012:assumed-role/ec2-deploy-role/i-0abc123",
            "sessionContext": {"sessionIssuer": {"arn": role_arn}},
        }
    }


def _direct_user_event_detail(user_arn: str) -> dict:
    return {"userIdentity": {"type": "IAMUser", "arn": user_arn}}


def test_extract_principal_arn_resolves_assumed_role_to_the_underlying_role():
    detail = _assumed_role_event_detail(_ROLE_ARN)
    assert svc._extract_principal_arn(detail) == _ROLE_ARN


def test_extract_principal_arn_uses_arn_directly_for_a_plain_iam_user():
    detail = _direct_user_event_detail("arn:aws:iam::123456789012:user/jane")
    assert svc._extract_principal_arn(detail) == "arn:aws:iam::123456789012:user/jane"


def _sso_assumed_role_event_detail(session_name: str) -> dict:
    return {
        "userIdentity": {
            "type": "AssumedRole",
            "arn": f"arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdministratorAccess_abc123/{session_name}",
            "sessionContext": {"sessionIssuer": {"arn": _ROLE_ARN}},
        }
    }


def test_extract_sso_session_email_finds_a_real_email_shaped_session_name():
    detail = _sso_assumed_role_event_detail("jane.doe@example.com")
    assert svc._extract_sso_session_email(detail) == "jane.doe@example.com"


def test_extract_sso_session_email_returns_none_for_a_non_email_session_name():
    detail = _sso_assumed_role_event_detail("i-0abc123")
    assert svc._extract_sso_session_email(detail) is None


def test_extract_sso_session_email_returns_none_for_a_direct_iam_user():
    detail = _direct_user_event_detail("arn:aws:iam::123456789012:user/jane")
    assert svc._extract_sso_session_email(detail) is None


def test_extract_sso_session_email_lowercases_the_result():
    detail = _sso_assumed_role_event_detail("Jane.Doe@Example.COM")
    assert svc._extract_sso_session_email(detail) == "jane.doe@example.com"


async def _make_connection_engagement_and_path(db_session: AsyncSession, *, continuous_monitoring: bool = True):
    tenant = await make_tenant(db_session)
    engagement = Engagement(
        id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active",
        scope={"continuous_activity_monitoring": continuous_monitoring},
    )
    db_session.add(engagement)
    await db_session.flush()

    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn=_ROLE_ARN, external_id="ext-123", status="connected",
        engagement_id=engagement.id,
    )
    db_session.add(connection)

    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn=_ROLE_ARN, target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="high",
    )
    db_session.add(path)
    await db_session.commit()
    return tenant, engagement, connection


def _fake_cloudtrail_event(event_id: str, principal_arn: str) -> dict:
    return {
        "EventId": event_id,
        "EventName": "PassRole",
        "EventTime": datetime.now(timezone.utc),
        "CloudTrailEvent": __import__("json").dumps(_assumed_role_event_detail(principal_arn)),
    }


async def test_poll_skips_connections_with_no_known_escalation_paths(db_session: AsyncSession, monkeypatch):
    tenant = await make_tenant(db_session)
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn=_ROLE_ARN, external_id="ext-123", status="connected",
    )
    db_session.add(connection)
    await db_session.commit()

    called = []
    monkeypatch.setattr(svc, "_lookup_cloudtrail_events_sync", lambda *a: called.append(True) or [])

    await svc.poll_connection_for_escalation_activity(db_session, connection)
    assert called == []  # never even tried — nothing to watch for


async def test_poll_creates_investigation_on_a_matching_escalation_event(db_session: AsyncSession, monkeypatch):
    tenant, engagement, connection = await _make_connection_engagement_and_path(db_session)

    def _fake_lookup(role_arn, external_id, event_name, start_time):
        return [_fake_cloudtrail_event("evt-1", _ROLE_ARN)]

    monkeypatch.setattr(svc, "_lookup_cloudtrail_events_sync", _fake_lookup)

    await svc.poll_connection_for_escalation_activity(db_session, connection)

    investigations = (await db_session.execute(select(Investigation).where(Investigation.tenant_id == tenant.id))).scalars().all()
    assert len(investigations) == 1
    assert investigations[0].status == "confirmed"

    events = (await db_session.execute(select(InvestigationEvent).where(InvestigationEvent.tenant_id == tenant.id))).scalars().all()
    assert len(events) == 1
    assert events[0].action_or_event_type == "iam:PassRole"
    assert events[0].event_id == "evt-1"

    findings = (await db_session.execute(select(Finding).where(Finding.tenant_id == tenant.id))).scalars().all()
    assert len(findings) == 1
    assert findings[0].tier == "threat"
    assert findings[0].severity == "critical"
    assert findings[0].check_id == "iam:PassRole"

    await db_session.refresh(connection)
    assert connection.threat_detection_status == "success"
    assert connection.last_threat_poll_at is not None


async def test_poll_ignores_the_same_action_from_an_unknown_principal(db_session: AsyncSession, monkeypatch):
    tenant, engagement, connection = await _make_connection_engagement_and_path(db_session)

    def _fake_lookup(role_arn, external_id, event_name, start_time):
        return [_fake_cloudtrail_event("evt-1", "arn:aws:iam::123456789012:role/some-other-role")]

    monkeypatch.setattr(svc, "_lookup_cloudtrail_events_sync", _fake_lookup)

    await svc.poll_connection_for_escalation_activity(db_session, connection)

    investigations = (await db_session.execute(select(Investigation).where(Investigation.tenant_id == tenant.id))).scalars().all()
    assert investigations == []


async def test_poll_is_idempotent_on_the_same_event_id(db_session: AsyncSession, monkeypatch):
    tenant, engagement, connection = await _make_connection_engagement_and_path(db_session)

    def _fake_lookup(role_arn, external_id, event_name, start_time):
        return [_fake_cloudtrail_event("evt-1", _ROLE_ARN)]

    monkeypatch.setattr(svc, "_lookup_cloudtrail_events_sync", _fake_lookup)

    await svc.poll_connection_for_escalation_activity(db_session, connection)
    await svc.poll_connection_for_escalation_activity(db_session, connection)

    events = (await db_session.execute(select(InvestigationEvent).where(InvestigationEvent.tenant_id == tenant.id))).scalars().all()
    assert len(events) == 1  # not duplicated on a second, overlapping poll


async def test_poll_records_a_clear_failure_on_client_error(db_session: AsyncSession, monkeypatch):
    from botocore.exceptions import ClientError

    tenant, engagement, connection = await _make_connection_engagement_and_path(db_session)

    def _raise(role_arn, external_id, event_name, start_time):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "not authorized"}}, "LookupEvents")

    monkeypatch.setattr(svc, "_lookup_cloudtrail_events_sync", _raise)

    await svc.poll_connection_for_escalation_activity(db_session, connection)

    await db_session.refresh(connection)
    assert connection.threat_detection_status == "failed"
    assert connection.threat_detection_error


async def test_poll_all_due_connections_requires_the_opt_in_flag(db_session: AsyncSession, monkeypatch):
    _, _, monitored_connection = await _make_connection_engagement_and_path(db_session, continuous_monitoring=True)
    _, _, unmonitored_connection = await _make_connection_engagement_and_path(db_session, continuous_monitoring=False)

    polled_ids = []

    async def _fake_poll(db, connection):
        polled_ids.append(connection.id)

    monkeypatch.setattr(svc, "poll_connection_for_escalation_activity", _fake_poll)

    count = await svc.poll_all_due_connections_for_threats(db_session)

    assert count == 1
    assert polled_ids == [monitored_connection.id]
