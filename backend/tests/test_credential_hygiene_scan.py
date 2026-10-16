"""
Identity & Credential Hygiene — MFA/password-audit half (Coverage Map plan
Phase 5). The real AWS boundary (`_fetch_credential_report_sync`, a
boto3 assume-role + IAM credential-report call) is monkeypatched the same
way test_prowler_scan.py mocks `_run_prowler_subprocess` — never hits real
AWS in this suite. Phase 37a added a second real-AWS-call boundary
(`lookup_iam_user_email_tag`, for Actor registration) — autouse-mocked
below to `None` by default so every existing test stays fast/offline
without editing each one; tests that care about the real lookup override
it explicitly.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import ActorIdentity, CloudAccountConnection, CloudAsset, Engagement, Finding
from app.services import credential_hygiene_service as svc
from tests.factories import make_tenant


@pytest.fixture(autouse=True)
def _no_real_email_tag_lookup(monkeypatch):
    monkeypatch.setattr(svc, "lookup_iam_user_email_tag", lambda role_arn, external_id, user_name: None)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


async def _make_connection_and_engagement(db_session):
    tenant = await make_tenant(db_session)
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123", status="connected",
    )
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add_all([connection, engagement])
    await db_session.flush()
    return connection, engagement


def test_parse_aws_datetime_handles_the_real_format():
    parsed = svc._parse_aws_datetime("2026-01-01T00:00:00+00:00")
    assert parsed == datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_parse_aws_datetime_handles_not_supported_and_na():
    assert svc._parse_aws_datetime("N/A") is None
    assert svc._parse_aws_datetime("not_supported") is None
    assert svc._parse_aws_datetime("") is None


def test_findings_from_report_flags_console_user_with_no_mfa():
    rows = [{
        "user": "alice", "arn": "arn:aws:iam::123456789012:user/alice",
        "password_enabled": "true", "mfa_active": "false", "password_last_changed": "N/A",
    }]
    findings = svc._findings_from_report(rows, uuid.uuid4(), uuid.uuid4())
    assert len(findings) == 1
    assert findings[0].check_id == "credential_report_mfa_missing"
    assert findings[0].severity == "high"
    assert "alice" in findings[0].title


def test_findings_from_report_does_not_flag_a_user_with_mfa_active():
    rows = [{
        "user": "bob", "arn": "arn:aws:iam::123456789012:user/bob",
        "password_enabled": "true", "mfa_active": "true", "password_last_changed": "N/A",
    }]
    assert svc._findings_from_report(rows, uuid.uuid4(), uuid.uuid4()) == []


def test_findings_from_report_does_not_flag_a_user_with_no_console_access():
    # No password_enabled means there's no console login to protect with MFA
    # in the first place — an API-only/service user isn't a real MFA gap.
    rows = [{
        "user": "service-role", "arn": "arn:aws:iam::123456789012:user/service-role",
        "password_enabled": "false", "mfa_active": "false", "password_last_changed": "N/A",
    }]
    assert svc._findings_from_report(rows, uuid.uuid4(), uuid.uuid4()) == []


def test_findings_from_report_flags_a_stale_password():
    old_date = datetime.now(timezone.utc) - timedelta(days=120)
    rows = [{
        "user": "carol", "arn": "arn:aws:iam::123456789012:user/carol",
        "password_enabled": "true", "mfa_active": "true", "password_last_changed": _iso(old_date),
    }]
    findings = svc._findings_from_report(rows, uuid.uuid4(), uuid.uuid4())
    assert len(findings) == 1
    assert findings[0].check_id == "credential_report_password_stale"
    assert findings[0].severity == "medium"


def test_findings_from_report_does_not_flag_a_recent_password():
    recent_date = datetime.now(timezone.utc) - timedelta(days=5)
    rows = [{
        "user": "dave", "arn": "arn:aws:iam::123456789012:user/dave",
        "password_enabled": "true", "mfa_active": "true", "password_last_changed": _iso(recent_date),
    }]
    assert svc._findings_from_report(rows, uuid.uuid4(), uuid.uuid4()) == []


def test_findings_from_report_flags_a_stale_active_access_key():
    old_date = datetime.now(timezone.utc) - timedelta(days=200)
    rows = [{
        "user": "erin", "arn": "arn:aws:iam::123456789012:user/erin",
        "password_enabled": "false", "mfa_active": "false", "password_last_changed": "N/A",
        "access_key_1_active": "true", "access_key_1_last_rotated": _iso(old_date),
        "access_key_1_last_used_date": _iso(datetime.now(timezone.utc) - timedelta(days=1)),
    }]
    findings = svc._findings_from_report(rows, uuid.uuid4(), uuid.uuid4())
    assert len(findings) == 1
    assert findings[0].check_id == "credential_report_access_key_1_stale"
    assert findings[0].severity == "medium"
    # Stays the bare user ARN, not a slot-suffixed variant — this is what
    # keeps it ARN-matchable to a graph node's own id (Phase 36f).
    assert findings[0].resource_uid == "arn:aws:iam::123456789012:user/erin"
    assert findings[0].extra["key_slot"] == "1"


def test_findings_from_report_flags_an_active_but_never_used_access_key():
    rows = [{
        "user": "frank", "arn": "arn:aws:iam::123456789012:user/frank",
        "password_enabled": "false", "mfa_active": "false", "password_last_changed": "N/A",
        "access_key_2_active": "true", "access_key_2_last_rotated": _iso(datetime.now(timezone.utc) - timedelta(days=1)),
        "access_key_2_last_used_date": "N/A",
    }]
    findings = svc._findings_from_report(rows, uuid.uuid4(), uuid.uuid4())
    assert len(findings) == 1
    assert findings[0].check_id == "credential_report_access_key_2_unused"
    assert findings[0].severity == "high"
    assert "never been used" in findings[0].title


def test_findings_from_report_flags_an_active_but_long_unused_access_key():
    rows = [{
        "user": "grace", "arn": "arn:aws:iam::123456789012:user/grace",
        "password_enabled": "false", "mfa_active": "false", "password_last_changed": "N/A",
        "access_key_1_active": "true", "access_key_1_last_rotated": _iso(datetime.now(timezone.utc) - timedelta(days=1)),
        "access_key_1_last_used_date": _iso(datetime.now(timezone.utc) - timedelta(days=150)),
    }]
    findings = svc._findings_from_report(rows, uuid.uuid4(), uuid.uuid4())
    assert len(findings) == 1
    assert findings[0].check_id == "credential_report_access_key_1_unused"
    assert "150 days" in findings[0].title


def test_findings_from_report_does_not_flag_a_recently_rotated_recently_used_key():
    rows = [{
        "user": "heidi", "arn": "arn:aws:iam::123456789012:user/heidi",
        "password_enabled": "false", "mfa_active": "false", "password_last_changed": "N/A",
        "access_key_1_active": "true",
        "access_key_1_last_rotated": _iso(datetime.now(timezone.utc) - timedelta(days=5)),
        "access_key_1_last_used_date": _iso(datetime.now(timezone.utc) - timedelta(days=1)),
    }]
    assert svc._findings_from_report(rows, uuid.uuid4(), uuid.uuid4()) == []


def test_findings_from_report_does_not_flag_an_inactive_access_key():
    rows = [{
        "user": "ivan", "arn": "arn:aws:iam::123456789012:user/ivan",
        "password_enabled": "false", "mfa_active": "false", "password_last_changed": "N/A",
        "access_key_1_active": "false",
        "access_key_1_last_rotated": "N/A", "access_key_1_last_used_date": "N/A",
    }]
    assert svc._findings_from_report(rows, uuid.uuid4(), uuid.uuid4()) == []


def test_findings_from_report_flags_both_key_slots_independently_without_colliding():
    old_date = datetime.now(timezone.utc) - timedelta(days=200)
    rows = [{
        "user": "judy", "arn": "arn:aws:iam::123456789012:user/judy",
        "password_enabled": "false", "mfa_active": "false", "password_last_changed": "N/A",
        "access_key_1_active": "true", "access_key_1_last_rotated": _iso(old_date), "access_key_1_last_used_date": _iso(datetime.now(timezone.utc) - timedelta(days=1)),
        "access_key_2_active": "true", "access_key_2_last_rotated": _iso(old_date), "access_key_2_last_used_date": _iso(datetime.now(timezone.utc) - timedelta(days=1)),
    }]
    findings = svc._findings_from_report(rows, uuid.uuid4(), uuid.uuid4())
    check_ids = sorted(f.check_id for f in findings)
    assert check_ids == ["credential_report_access_key_1_stale", "credential_report_access_key_2_stale"]


async def test_run_credential_hygiene_scan_persists_real_findings(db_session, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_fetch(role_arn, external_id):
        return [{
            "user": "alice", "arn": "arn:aws:iam::123456789012:user/alice",
            "password_enabled": "true", "mfa_active": "false", "password_last_changed": "N/A",
        }]

    monkeypatch.setattr(svc, "_fetch_credential_report_sync", _fake_fetch)

    result = await svc.run_credential_hygiene_scan(db_session, engagement, connection)
    assert result is not None
    assert len(result) == 1
    assert result[0].tier == "credential"
    assert result[0].check_id == "credential_report_mfa_missing"

    persisted = (await db_session.execute(
        select(Finding).where(Finding.engagement_id == engagement.id)
    )).scalars().all()
    assert len(persisted) == 1


async def test_run_credential_hygiene_scan_does_not_duplicate_on_rescan(db_session, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_fetch(role_arn, external_id):
        return [{
            "user": "alice", "arn": "arn:aws:iam::123456789012:user/alice",
            "password_enabled": "true", "mfa_active": "false", "password_last_changed": "N/A",
        }]

    monkeypatch.setattr(svc, "_fetch_credential_report_sync", _fake_fetch)

    first = await svc.run_credential_hygiene_scan(db_session, engagement, connection)
    assert len(first) == 1
    second = await svc.run_credential_hygiene_scan(db_session, engagement, connection)
    assert second == []  # still open, not re-inserted


async def test_run_credential_hygiene_scan_marks_a_fixed_finding_remediated(db_session, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_fetch_no_mfa(role_arn, external_id):
        return [{
            "user": "alice", "arn": "arn:aws:iam::123456789012:user/alice",
            "password_enabled": "true", "mfa_active": "false", "password_last_changed": "N/A",
        }]

    def _fake_fetch_mfa_now_active(role_arn, external_id):
        return [{
            "user": "alice", "arn": "arn:aws:iam::123456789012:user/alice",
            "password_enabled": "true", "mfa_active": "true", "password_last_changed": "N/A",
        }]

    monkeypatch.setattr(svc, "_fetch_credential_report_sync", _fake_fetch_no_mfa)
    await svc.run_credential_hygiene_scan(db_session, engagement, connection)

    monkeypatch.setattr(svc, "_fetch_credential_report_sync", _fake_fetch_mfa_now_active)
    await svc.run_credential_hygiene_scan(db_session, engagement, connection)

    finding = (await db_session.execute(
        select(Finding).where(Finding.engagement_id == engagement.id, Finding.check_id == "credential_report_mfa_missing")
    )).scalar_one()
    assert finding.status == "remediated"


async def test_run_credential_hygiene_scan_returns_none_on_failure(db_session, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_fetch_raises(role_arn, external_id):
        raise RuntimeError("boom")

    monkeypatch.setattr(svc, "_fetch_credential_report_sync", _fake_fetch_raises)

    error_detail = {}
    result = await svc.run_credential_hygiene_scan(db_session, engagement, connection, error_detail=error_detail)
    assert result is None
    assert "boom" in error_detail["message"]


# ── Phase 37a: credential-report principals register as Actors, so
# Actor-based graph matching (identity_resolution_service.py) has
# something real to find. ──

async def test_run_credential_hygiene_scan_registers_an_actor_identity_for_each_user(db_session, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_fetch(role_arn, external_id):
        return [{
            "user": "alice", "arn": "arn:aws:iam::123456789012:user/alice",
            "password_enabled": "true", "mfa_active": "false", "password_last_changed": "N/A",
        }]
    monkeypatch.setattr(svc, "_fetch_credential_report_sync", _fake_fetch)

    await svc.run_credential_hygiene_scan(db_session, engagement, connection)

    identity = await db_session.scalar(
        select(ActorIdentity).where(
            ActorIdentity.tenant_id == connection.tenant_id,
            ActorIdentity.source == "aws_iam",
            ActorIdentity.principal_id == "arn:aws:iam::123456789012:user/alice",
        )
    )
    assert identity is not None


async def test_run_credential_hygiene_scan_uses_a_real_email_tag_lookup_when_found(db_session, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_fetch(role_arn, external_id):
        return [{
            "user": "bob", "arn": "arn:aws:iam::123456789012:user/bob",
            "password_enabled": "true", "mfa_active": "false", "password_last_changed": "N/A",
        }]
    monkeypatch.setattr(svc, "_fetch_credential_report_sync", _fake_fetch)

    def _fake_lookup(role_arn, external_id, user_name):
        assert user_name == "bob"
        return "bob@example.com"
    monkeypatch.setattr(svc, "lookup_iam_user_email_tag", _fake_lookup)

    await svc.run_credential_hygiene_scan(db_session, engagement, connection)

    identity = await db_session.scalar(
        select(ActorIdentity).where(
            ActorIdentity.tenant_id == connection.tenant_id,
            ActorIdentity.principal_id == "arn:aws:iam::123456789012:user/bob",
        )
    )
    assert identity.email_provenance == "iam_tag"
    from app.models import Actor
    actor = await db_session.get(Actor, identity.actor_id)
    assert actor.email == "bob@example.com"


async def test_run_credential_hygiene_scan_registers_each_unique_user_once(db_session, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    lookups: list[str] = []

    def _fake_fetch(role_arn, external_id):
        # Same user appears once per row shape this function processes —
        # confirms de-duplication, not a real report duplicate.
        return [{
            "user": "carol", "arn": "arn:aws:iam::123456789012:user/carol",
            "password_enabled": "true", "mfa_active": "true", "password_last_changed": "N/A",
            "access_key_1_active": "true",
            "access_key_1_last_rotated": _iso(datetime.now(timezone.utc)),
            "access_key_1_last_used_date": "N/A",
        }]
    monkeypatch.setattr(svc, "_fetch_credential_report_sync", _fake_fetch)

    def _fake_lookup(role_arn, external_id, user_name):
        lookups.append(user_name)
        return None
    monkeypatch.setattr(svc, "lookup_iam_user_email_tag", _fake_lookup)

    await svc.run_credential_hygiene_scan(db_session, engagement, connection)
    assert lookups == ["carol"]  # looked up exactly once, not once per finding this row happens to produce


# ── Phase 38b/c: asset_id linking + checked-status marking against a
# pre-existing resource inventory. ──

async def test_run_credential_hygiene_scan_links_asset_id_to_a_matching_cloud_asset(db_session, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=connection.tenant_id, cloud_account_connection_id=connection.id,
        resource_type="iam_user", resource_id="arn:aws:iam::123456789012:user/alice", resource_metadata={},
    )
    db_session.add(asset)
    await db_session.commit()

    def _fake_fetch(role_arn, external_id):
        return [{
            "user": "alice", "arn": "arn:aws:iam::123456789012:user/alice",
            "password_enabled": "true", "mfa_active": "false", "password_last_changed": "N/A",
        }]
    monkeypatch.setattr(svc, "_fetch_credential_report_sync", _fake_fetch)

    [finding] = await svc.run_credential_hygiene_scan(db_session, engagement, connection)
    assert finding.asset_id == asset.id


async def test_run_credential_hygiene_scan_marks_a_clean_user_checked_status_pass(db_session, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=connection.tenant_id, cloud_account_connection_id=connection.id,
        resource_type="iam_user", resource_id="arn:aws:iam::123456789012:user/clean-dan", resource_metadata={},
    )
    db_session.add(asset)
    await db_session.commit()

    def _fake_fetch(role_arn, external_id):
        # MFA active, recent password — no findings for this user at all.
        return [{
            "user": "clean-dan", "arn": "arn:aws:iam::123456789012:user/clean-dan",
            "password_enabled": "true", "mfa_active": "true",
            "password_last_changed": _iso(datetime.now(timezone.utc)),
        }]
    monkeypatch.setattr(svc, "_fetch_credential_report_sync", _fake_fetch)

    findings = await svc.run_credential_hygiene_scan(db_session, engagement, connection)
    assert findings == []

    await db_session.refresh(asset)
    assert asset.resource_metadata["credential_status"] == "pass"


async def test_run_credential_hygiene_scan_marks_a_flagged_user_checked_status_fail(db_session, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=connection.tenant_id, cloud_account_connection_id=connection.id,
        resource_type="iam_user", resource_id="arn:aws:iam::123456789012:user/alice", resource_metadata={},
    )
    db_session.add(asset)
    await db_session.commit()

    def _fake_fetch(role_arn, external_id):
        return [{
            "user": "alice", "arn": "arn:aws:iam::123456789012:user/alice",
            "password_enabled": "true", "mfa_active": "false", "password_last_changed": "N/A",
        }]
    monkeypatch.setattr(svc, "_fetch_credential_report_sync", _fake_fetch)

    await svc.run_credential_hygiene_scan(db_session, engagement, connection)

    await db_session.refresh(asset)
    assert asset.resource_metadata["credential_status"] == "fail"
