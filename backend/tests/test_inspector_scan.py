"""
Amazon Inspector EC2 scan pass — the AWS half of the new Host & Server
Security position. Unlike Prowler/Cloudsplaining, there's no scanner to run:
Inspector already continuously scans EC2 instances via the SSM agent, we
just read its findings through the same assumed-role session.

Field names (severity enum, status enum, remediation.recommendation.text,
and — Phase 36c — packageVulnerabilityDetails/exploitAvailable/
fixAvailable/epss/networkReachabilityDetails/resources[].region) were
pulled directly from botocore's real inspector2 service model, not
guessed — verified before writing this.
"""
import uuid

from moto import mock_aws
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CloudAccountConnection, CloudAsset, Engagement, Finding
from app.services import cloud_scan_service
from tests.factories import make_tenant

_SAMPLE_INSPECTOR_FINDING = {
    "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/abc123",
    "title": "CVE-2024-1234 - openssl",
    "severity": "CRITICAL",
    "status": "ACTIVE",
    "description": "A vulnerable version of openssl is installed.",
    "remediation": {"recommendation": {"text": "Update openssl to 3.0.14 or later.", "Url": "https://example.com"}},
}

# The fuller real Finding shape (Phase 36c) — every member confirmed this
# session against botocore's own inspector2/2020-06-08/service-2.json
# service model, not guessed.
_SAMPLE_INSPECTOR_FINDING_FULL = {
    "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/def456",
    "title": "CVE-2024-5678 - libcurl",
    "severity": "HIGH",
    "status": "ACTIVE",
    "description": "A vulnerable version of libcurl is installed.",
    "remediation": {"recommendation": {"text": "Update libcurl to 8.5.0 or later."}},
    "resources": [{"id": "i-aaaaaaaaaaaaaaaaa", "type": "AWS_EC2_INSTANCE", "region": "af-south-1"}],
    "packageVulnerabilityDetails": {
        "vulnerabilityId": "CVE-2024-5678",
        "cvss": [
            {"baseScore": 7.5, "scoringVector": "CVSS:3.1/AV:N/AC:L", "source": "NVD", "version": "3.1"},
            {"baseScore": 9.1, "scoringVector": "CVSS:3.1/AV:N/AC:L/PR:N", "source": "VENDOR", "version": "3.1"},
        ],
        "vulnerablePackages": [{"name": "libcurl", "version": "7.88.1", "fixedInVersion": "8.5.0"}],
        "referenceUrls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-5678"],
    },
    "exploitAvailable": "YES",
    "exploitabilityDetails": {"lastKnownExploitAt": "2026-06-01T00:00:00Z"},
    "fixAvailable": "YES",
    "epss": {"score": 0.42},
    "networkReachabilityDetails": {"protocol": "TCP", "openPortRange": {"begin": 443, "end": 443}},
    "firstObservedAt": "2026-05-01T00:00:00Z",
    "lastObservedAt": "2026-06-10T00:00:00Z",
}


async def _make_connection_and_engagement(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123",
        status="connected",
    )
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add_all([connection, engagement])
    await db_session.flush()
    return connection, engagement


async def test_run_inspector_scan_persists_findings(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_list(role_arn, external_id):
        return [_SAMPLE_INSPECTOR_FINDING]

    monkeypatch.setattr(cloud_scan_service, "_list_inspector_findings", _fake_list)

    findings = await cloud_scan_service.run_inspector_scan(db_session, engagement, connection)

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].title == "CVE-2024-1234 - openssl"
    assert findings[0].check_id == "arn:aws:inspector2:us-east-1:123456789012:finding/abc123"
    assert findings[0].remediation_guidance == "Update openssl to 3.0.14 or later."
    assert findings[0].tier == "cloud"


async def test_run_inspector_scan_populates_region_and_cve_exploit_data(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    monkeypatch.setattr(cloud_scan_service, "_list_inspector_findings", lambda role_arn, external_id: [_SAMPLE_INSPECTOR_FINDING_FULL])

    [f] = await cloud_scan_service.run_inspector_scan(db_session, engagement, connection)

    assert f.region == "af-south-1"
    assert f.extra["source"] == "inspector2"
    assert f.extra["vulnerability_id"] == "CVE-2024-5678"
    # Two sources reported CVSS scores — the higher (VENDOR, 9.1) wins, not
    # whichever sorted first in the API response.
    assert f.extra["cvss"] == {"base_score": 9.1, "scoring_vector": "CVSS:3.1/AV:N/AC:L/PR:N", "source": "VENDOR"}
    assert f.extra["vulnerable_packages"] == [{"name": "libcurl", "version": "7.88.1", "fixed_in_version": "8.5.0"}]
    assert f.extra["exploit_available"] == "YES"
    assert f.extra["last_known_exploit_at"] == "2026-06-01T00:00:00Z"
    assert f.extra["fix_available"] == "YES"
    assert f.extra["epss_score"] == 0.42
    assert f.extra["network_reachable"] is True
    assert f.extra["network_protocol"] == "TCP"
    assert f.extra["first_observed_at"] == "2026-05-01T00:00:00Z"
    assert f.extra["reference_urls"] == ["https://nvd.nist.gov/vuln/detail/CVE-2024-5678"]
    assert f.extra_populated_at is not None


async def test_run_inspector_scan_handles_minimal_finding_with_no_region_or_extra_detail(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    bare = {"findingArn": "arn:x", "title": "Something", "severity": "HIGH"}
    monkeypatch.setattr(cloud_scan_service, "_list_inspector_findings", lambda role_arn, external_id: [bare])

    [f] = await cloud_scan_service.run_inspector_scan(db_session, engagement, connection)

    assert f.region is None
    assert f.extra["network_reachable"] is False
    assert f.extra["cvss"] is None
    assert f.extra["vulnerable_packages"] is None


# ── Phase 38b/c: asset_id linking + checked-status marking. Inspector2's
# list_findings only ever returns ACTIVE (failing) findings — there's no
# "checked, clean" signal available here the way Prowler's PASS rows give
# one, so this only ever marks a resource "fail", never "pass". ──

async def test_run_inspector_scan_links_asset_id_when_the_resource_arn_matches(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=connection.tenant_id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-aaa", resource_metadata={},
    )
    db_session.add(asset)
    await db_session.commit()

    finding_with_resource = {
        **_SAMPLE_INSPECTOR_FINDING,
        "resources": [{"id": "arn:aws:ec2:us-east-1:123456789012:instance/i-aaa", "type": "AWS_EC2_INSTANCE"}],
    }
    monkeypatch.setattr(cloud_scan_service, "_list_inspector_findings", lambda role_arn, external_id: [finding_with_resource])

    [f] = await cloud_scan_service.run_inspector_scan(db_session, engagement, connection)
    assert f.asset_id == asset.id

    await db_session.refresh(asset)
    assert asset.resource_metadata["inspector_status"] == "fail"


async def test_run_inspector_scan_leaves_asset_id_none_when_resource_id_is_not_arn_shaped(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    # A bare instance id, not a full ARN — never guessed/reconstructed into one.
    finding_with_bare_id = {**_SAMPLE_INSPECTOR_FINDING, "resources": [{"id": "i-aaa", "type": "AWS_EC2_INSTANCE"}]}
    monkeypatch.setattr(cloud_scan_service, "_list_inspector_findings", lambda role_arn, external_id: [finding_with_bare_id])

    [f] = await cloud_scan_service.run_inspector_scan(db_session, engagement, connection)
    assert f.asset_id is None


async def test_run_inspector_scan_maps_all_severity_levels(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    raw = [
        {**_SAMPLE_INSPECTOR_FINDING, "findingArn": f"arn:...:finding/{sev}", "severity": sev}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNTRIAGED"]
    ]
    monkeypatch.setattr(cloud_scan_service, "_list_inspector_findings", lambda role_arn, external_id: raw)

    findings = await cloud_scan_service.run_inspector_scan(db_session, engagement, connection)

    severities = {f.check_id.split("/")[-1]: f.severity for f in findings}
    assert severities == {
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
        "LOW": "low", "INFORMATIONAL": "low", "UNTRIAGED": "medium",
    }


async def test_run_inspector_scan_handles_missing_remediation_gracefully(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    bare = {"findingArn": "arn:x", "title": "Something", "severity": "HIGH"}
    monkeypatch.setattr(cloud_scan_service, "_list_inspector_findings", lambda role_arn, external_id: [bare])

    findings = await cloud_scan_service.run_inspector_scan(db_session, engagement, connection)

    assert len(findings) == 1
    assert findings[0].remediation_guidance is None
    assert findings[0].detail is None


async def test_run_inspector_scan_does_not_duplicate_a_persistent_finding_on_rescan(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    monkeypatch.setattr(cloud_scan_service, "_list_inspector_findings", lambda role_arn, external_id: [_SAMPLE_INSPECTOR_FINDING])

    first = await cloud_scan_service.run_inspector_scan(db_session, engagement, connection)
    assert len(first) == 1

    second = await cloud_scan_service.run_inspector_scan(db_session, engagement, connection)
    assert second == []

    all_findings = (await db_session.execute(select(Finding).where(Finding.engagement_id == engagement.id))).scalars().all()
    assert len(all_findings) == 1


async def test_run_inspector_scan_marks_a_resolved_finding_remediated(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    monkeypatch.setattr(cloud_scan_service, "_list_inspector_findings", lambda role_arn, external_id: [_SAMPLE_INSPECTOR_FINDING])
    await cloud_scan_service.run_inspector_scan(db_session, engagement, connection)

    monkeypatch.setattr(cloud_scan_service, "_list_inspector_findings", lambda role_arn, external_id: [])
    second = await cloud_scan_service.run_inspector_scan(db_session, engagement, connection)
    assert second == []

    all_findings = (await db_session.execute(select(Finding).where(Finding.engagement_id == engagement.id))).scalars().all()
    assert len(all_findings) == 1
    assert all_findings[0].status == "remediated"


async def test_run_inspector_scan_does_not_touch_prowler_rows_sharing_tier_cloud(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    prowler_finding = Finding(
        id=uuid.uuid4(), tenant_id=connection.tenant_id, engagement_id=engagement.id,
        tier="cloud", severity="low", title="Prowler finding", status="open",
        check_id="iam_root_mfa_enabled", resource_uid="arn:aws:iam::123456789012:root",
    )
    db_session.add(prowler_finding)
    await db_session.commit()

    monkeypatch.setattr(cloud_scan_service, "_list_inspector_findings", lambda role_arn, external_id: [_SAMPLE_INSPECTOR_FINDING])
    await cloud_scan_service.run_inspector_scan(db_session, engagement, connection)

    await db_session.refresh(prowler_finding)
    assert prowler_finding.status == "open"  # untouched — out of Inspector's reconciliation scope


async def test_run_inspector_scan_returns_empty_on_access_denied(db_session: AsyncSession, monkeypatch):
    from botocore.exceptions import ClientError

    connection, engagement = await _make_connection_and_engagement(db_session)

    def _raise(role_arn, external_id):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "not authorized"}}, "ListFindings")

    monkeypatch.setattr(cloud_scan_service, "_list_inspector_findings", _raise)

    findings = await cloud_scan_service.run_inspector_scan(db_session, engagement, connection)
    assert findings is None


async def test_run_inspector_scan_flags_not_enabled_for_subscription_required(db_session: AsyncSession, monkeypatch):
    """Coverage Map plan Phase 8: a fresh AWS account has Inspector2 opted
    out by default — this must be distinguishable from a genuine failure
    (e.g. AccessDenied) so rescan_connection() doesn't count it against the
    aggregate last_scan_status for every single new customer, day one."""
    from botocore.exceptions import ClientError

    connection, engagement = await _make_connection_and_engagement(db_session)

    def _raise(role_arn, external_id):
        raise ClientError({"Error": {"Code": "SubscriptionRequiredException", "Message": "not subscribed"}}, "ListFindings")

    monkeypatch.setattr(cloud_scan_service, "_list_inspector_findings", _raise)

    error_detail: dict = {}
    findings = await cloud_scan_service.run_inspector_scan(db_session, engagement, connection, error_detail=error_detail)
    assert findings is None
    assert error_detail["not_enabled"] is True


async def test_run_inspector_scan_does_not_flag_not_enabled_for_other_errors(db_session: AsyncSession, monkeypatch):
    from botocore.exceptions import ClientError

    connection, engagement = await _make_connection_and_engagement(db_session)

    def _raise(role_arn, external_id):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "not authorized"}}, "ListFindings")

    monkeypatch.setattr(cloud_scan_service, "_list_inspector_findings", _raise)

    error_detail: dict = {}
    await cloud_scan_service.run_inspector_scan(db_session, engagement, connection, error_detail=error_detail)
    assert "not_enabled" not in error_detail


async def test_list_inspector_findings_against_a_real_moto_session(db_session: AsyncSession):
    """
    Not mocked at the _list_inspector_findings level — exercises the real
    assume-role + inspector2.list_findings call chain against moto, which
    does support inspector2's list_findings API (confirmed empirically
    before writing this — it returns an empty findings list rather than
    raising NotImplementedError). Proves the pagination/assume-role
    plumbing is actually correct, even though moto won't simulate real
    vulnerability data.

    mock_aws used as a context manager, not a decorator — decorating an
    async def breaks pytest-asyncio's coroutine detection (learned the hard
    way on the Prowler tests).
    """
    import json

    import boto3

    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
                           "Condition": {"StringEquals": {"sts:ExternalId": "ext-real"}}}],
        }
        role = iam.create_role(RoleName="InspectorTestRole", AssumeRolePolicyDocument=json.dumps(trust_policy))
        role_arn = role["Role"]["Arn"]

        findings = cloud_scan_service._list_inspector_findings(role_arn, "ext-real")
        assert findings == []
