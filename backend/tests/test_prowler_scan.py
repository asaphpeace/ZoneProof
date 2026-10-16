"""
Prowler scan pass (BUILD_PLAN.md Phase 1 step 7). Prowler runs in its own
isolated venv (backend/.venv-prowler) invoked as a subprocess — its pinned
deps (pydantic==2.12.5, boto3==1.40.61 at time of writing) conflict outright
with this app's pins, confirmed via PyPI metadata before deciding to isolate
it rather than install into the app's own venv.

The CSV column names and delimiter asserted here are lifted directly from
prowler/lib/outputs/csv/csv.py in the installed package (not guessed), and
the real installed `prowler` binary is invoked in one test to prove the CLI
flags this module constructs are actually valid against that binary.
"""
import subprocess
import uuid
from pathlib import Path

import pytest
from botocore.exceptions import ClientError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import CloudAccountConnection, CloudAsset, Engagement, Finding
from app.services import cloud_scan_service
from tests.factories import make_tenant

# Two FAIL rows for the exact same account-level check, differing only by
# region — the realistic shape of Prowler's own region-fanout on a check
# like iam_access_analyzer_enabled (evaluated per-region even though "is
# Access Analyzer on" is really one account-wide question). This is what
# _collapse_regional_duplicates() is supposed to merge into a single row.
_SAMPLE_CSV_TWO_RESOURCES = (
    "AUTH_METHOD;TIMESTAMP;ACCOUNT_UID;CHECK_ID;CHECK_TITLE;STATUS;SEVERITY;"
    "RESOURCE_UID;RESOURCE_NAME;REGION;DESCRIPTION;REMEDIATION_RECOMMENDATION_TEXT\n"
    "profile;2026-07-03T00:00:00;123456789012;iam_access_analyzer_enabled;Analyzer enabled;"
    "FAIL;low;arn:aws:access-analyzer:us-east-1:123456789012:analyzer/default;default;us-east-1;Not enabled in us-east-1;"
    "Enable it\n"
    "profile;2026-07-03T00:00:00;123456789012;iam_access_analyzer_enabled;Analyzer enabled;"
    "FAIL;low;arn:aws:access-analyzer:eu-west-1:123456789012:analyzer/default;default;eu-west-1;Not enabled in eu-west-1;"
    "Enable it\n"
)

# Two FAIL rows for a genuinely different resource each (real distinct EC2
# instance ids, same region) — must NEVER collapse, since each is a real,
# separately-actionable finding.
_SAMPLE_CSV_TWO_DISTINCT_INSTANCES = (
    "AUTH_METHOD;TIMESTAMP;ACCOUNT_UID;CHECK_ID;CHECK_TITLE;STATUS;SEVERITY;"
    "RESOURCE_UID;RESOURCE_NAME;DESCRIPTION;REMEDIATION_RECOMMENDATION_TEXT\n"
    "profile;2026-07-03T00:00:00;123456789012;ec2_instance_port_ssh_exposed_to_internet;SSH exposed;"
    "FAIL;high;arn:aws:ec2:us-east-1:123456789012:instance/i-aaaaaaaaaaaaaaaaa;i-aaa;SSH open on i-aaa;"
    "Restrict the security group\n"
    "profile;2026-07-03T00:00:00;123456789012;ec2_instance_port_ssh_exposed_to_internet;SSH exposed;"
    "FAIL;high;arn:aws:ec2:us-east-1:123456789012:instance/i-bbbbbbbbbbbbbbbbb;i-bbb;SSH open on i-bbb;"
    "Restrict the security group\n"
)

# Real Prowler CSV header row + one FAIL row, matching CSV.transform()'s
# exact field order/names in the installed package.
_SAMPLE_CSV = (
    "AUTH_METHOD;TIMESTAMP;ACCOUNT_UID;CHECK_ID;CHECK_TITLE;STATUS;SEVERITY;"
    "RESOURCE_UID;RESOURCE_NAME;DESCRIPTION;REMEDIATION_RECOMMENDATION_TEXT\n"
    "profile;2026-07-03T00:00:00;123456789012;iam_root_mfa_enabled;Root MFA enabled;"
    "FAIL;critical;arn:aws:iam::123456789012:root;root;Root account has no MFA;"
    "Enable MFA on the root account\n"
)

# One FAIL row exercising every previously-discarded column (Phase 36b) —
# REGION plus the full set of extra-worthy fields, encoded exactly the way
# prowler/lib/outputs/csv/csv.py's unroll_dict/unroll_list produce them.
_SAMPLE_CSV_WITH_EXTRA_FIELDS = (
    "AUTH_METHOD;TIMESTAMP;ACCOUNT_UID;CHECK_ID;CHECK_TITLE;STATUS;SEVERITY;"
    "RESOURCE_TYPE;RESOURCE_UID;RESOURCE_NAME;RESOURCE_TAGS;REGION;DESCRIPTION;RISK;RELATED_URL;"
    "REMEDIATION_RECOMMENDATION_TEXT;REMEDIATION_CODE_TERRAFORM;REMEDIATION_CODE_CLI;"
    "REMEDIATION_CODE_NATIVEIAC;COMPLIANCE;CATEGORIES;FINDING_UID;SERVICE_NAME;MUTED\n"
    "profile;2026-07-03T00:00:00;123456789012;ec2_instance_port_ssh_exposed_to_internet;SSH exposed;"
    "FAIL;high;AwsEc2Instance;arn:aws:ec2:us-east-1:123456789012:instance/i-aaa;i-aaa;"
    "Name=web-1 | Env=prod;us-east-1;SSH open on i-aaa;Full SSH exposure allows brute-force;"
    "https://example.com/ssh;Restrict the security group;resource \"aws_security_group\" {...};"
    "aws ec2 revoke-security-group-ingress ...;{...};CIS-1.4: 4.1 | SOC2: CC6.1;"
    "internet-exposed | network;finding-uid-123;ec2;False\n"
)


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


def test_parse_prowler_csv_reads_the_real_schema(tmp_path):
    csv_path = tmp_path / "scan.csv"
    csv_path.write_text(_SAMPLE_CSV, encoding="utf-8")

    rows = cloud_scan_service._parse_prowler_csv(csv_path)

    assert len(rows) == 1
    assert rows[0]["CHECK_ID"] == "iam_root_mfa_enabled"
    assert rows[0]["SEVERITY"] == "critical"


def test_parse_prowler_csv_missing_file_returns_empty(tmp_path):
    assert cloud_scan_service._parse_prowler_csv(tmp_path / "does-not-exist.csv") == []


async def test_run_prowler_scan_persists_findings_from_csv_output(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_subprocess(role_arn, external_id, output_dir, regions=None):
        (Path(output_dir) / "scan.csv").write_text(_SAMPLE_CSV, encoding="utf-8")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_discover_active_regions", lambda *a, **k: None)
    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_subprocess)

    findings = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)

    assert len(findings) == 1
    assert findings[0].check_id == "iam_root_mfa_enabled"
    assert findings[0].severity == "critical"
    assert findings[0].tier == "cloud"
    assert findings[0].engagement_id == engagement.id
    assert findings[0].remediation_guidance == "Enable MFA on the root account"
    assert findings[0].region is None
    assert findings[0].extra["source"] == "prowler"


def test_parse_unrolled_dict_reverses_prowlers_own_encoding():
    assert cloud_scan_service._parse_unrolled_dict("Name=web-1 | Env=prod", "=") == {"Name": "web-1", "Env": "prod"}
    assert cloud_scan_service._parse_unrolled_dict("CIS-1.4: 4.1 | SOC2: CC6.1", ": ") == {"CIS-1.4": "4.1", "SOC2": "CC6.1"}
    assert cloud_scan_service._parse_unrolled_dict("", "=") == {}
    assert cloud_scan_service._parse_unrolled_dict(None, "=") == {}


def test_parse_unrolled_list_reverses_prowlers_own_encoding():
    assert cloud_scan_service._parse_unrolled_list("internet-exposed | network") == ["internet-exposed", "network"]
    assert cloud_scan_service._parse_unrolled_list(None) == []


async def test_run_prowler_scan_populates_region_and_extra_from_previously_discarded_columns(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_subprocess(role_arn, external_id, output_dir, regions=None):
        (Path(output_dir) / "scan.csv").write_text(_SAMPLE_CSV_WITH_EXTRA_FIELDS, encoding="utf-8")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_discover_active_regions", lambda *a, **k: None)
    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_subprocess)

    [f] = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)

    assert f.region == "us-east-1"
    assert f.extra["resource_type"] == "AwsEc2Instance"
    assert f.extra["resource_name"] == "i-aaa"
    assert f.extra["service_name"] == "ec2"
    assert f.extra["resource_tags"] == {"Name": "web-1", "Env": "prod"}
    assert f.extra["compliance"] == {"CIS-1.4": "4.1", "SOC2": "CC6.1"}
    assert f.extra["remediation_code"]["terraform"] == 'resource "aws_security_group" {...}'
    assert f.extra["remediation_code"]["cli"] == "aws ec2 revoke-security-group-ingress ..."
    assert f.extra["risk"] == "Full SSH exposure allows brute-force"
    assert f.extra["categories"] == ["internet-exposed", "network"]
    assert f.extra["related_url"] == "https://example.com/ssh"
    assert f.extra["finding_uid"] == "finding-uid-123"
    assert f.extra["muted"] is False
    assert f.extra_populated_at is not None
    # No OCSF file was written by this fake subprocess — honest degrade,
    # never a crash or a fabricated value.
    assert f.extra["resource_metadata"] is None


# ── Close scan-data gaps for the attack simulation engine: real structured
# resource detail (ports/protocols/CIDRs) from Prowler's own OCSF output,
# which CSV alone never carries. ──

# Real OCSF shape for one finding — finding_info.uid matches FINDING_UID in
# the CSV row above ("finding-uid-123"), resources[0].data carries the
# structured resource detail (verified against the installed prowler
# package's ocsf.py: ResourceDetails.data = _sanitize_resource_data(...)).
_SAMPLE_OCSF = """[
{
  "finding_info": {"uid": "finding-uid-123"},
  "resources": [{"uid": "arn:aws:ec2:us-east-1:123456789012:instance/i-aaa", "data": {"ingress_rules": [{"port": 22, "protocol": "tcp", "cidr": "0.0.0.0/0"}]}}]
}
]"""


def test_parse_prowler_ocsf_reads_the_real_schema(tmp_path):
    ocsf_path = tmp_path / "scan.ocsf.json"
    ocsf_path.write_text(_SAMPLE_OCSF, encoding="utf-8")
    result = cloud_scan_service._parse_prowler_ocsf(ocsf_path)
    assert result == {"finding-uid-123": {"ingress_rules": [{"port": 22, "protocol": "tcp", "cidr": "0.0.0.0/0"}]}}


def test_parse_prowler_ocsf_missing_file_degrades_to_empty(tmp_path):
    assert cloud_scan_service._parse_prowler_ocsf(tmp_path / "does-not-exist.json") == {}


def test_parse_prowler_ocsf_malformed_file_degrades_to_empty(tmp_path):
    ocsf_path = tmp_path / "scan.ocsf.json"
    ocsf_path.write_text("not valid json {{{", encoding="utf-8")
    assert cloud_scan_service._parse_prowler_ocsf(ocsf_path) == {}


async def test_run_prowler_scan_merges_real_ocsf_resource_metadata_by_finding_uid(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_subprocess(role_arn, external_id, output_dir, regions=None):
        (Path(output_dir) / "scan.csv").write_text(_SAMPLE_CSV_WITH_EXTRA_FIELDS, encoding="utf-8")
        (Path(output_dir) / "scan.ocsf.json").write_text(_SAMPLE_OCSF, encoding="utf-8")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_discover_active_regions", lambda *a, **k: None)
    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_subprocess)

    [f] = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)

    assert f.extra["resource_metadata"] == {"ingress_rules": [{"port": 22, "protocol": "tcp", "cidr": "0.0.0.0/0"}]}


# ── Phase 38b/c: PASS-row capture (checked-status honesty) and asset_id
# linking against a pre-existing resource inventory. ──

async def _seed_asset(db_session, connection, resource_id, resource_type="ec2_instance"):
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=connection.tenant_id, cloud_account_connection_id=connection.id,
        resource_type=resource_type, resource_id=resource_id, resource_metadata={},
    )
    db_session.add(asset)
    await db_session.flush()
    return asset


async def test_run_prowler_scan_links_asset_id_to_a_matching_cloud_asset(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    asset = await _seed_asset(db_session, connection, "arn:aws:iam::123456789012:root", resource_type="iam_root")
    await db_session.commit()

    def _fake_subprocess(role_arn, external_id, output_dir, regions=None):
        (Path(output_dir) / "scan.csv").write_text(_SAMPLE_CSV, encoding="utf-8")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_discover_active_regions", lambda *a, **k: None)
    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_subprocess)

    [f] = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)
    assert f.asset_id == asset.id


async def test_run_prowler_scan_leaves_asset_id_none_for_a_collapsed_finding(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    # Both real regional resources exist as real assets — but the collapsed
    # Finding still can't honestly point at just one of them.
    await _seed_asset(db_session, connection, "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/default")
    await _seed_asset(db_session, connection, "arn:aws:access-analyzer:eu-west-1:123456789012:analyzer/default")
    await db_session.commit()

    def _fake_subprocess(role_arn, external_id, output_dir, regions=None):
        (Path(output_dir) / "scan.csv").write_text(_SAMPLE_CSV_TWO_RESOURCES, encoding="utf-8")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_discover_active_regions", lambda *a, **k: None)
    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_subprocess)

    [f] = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)
    assert f.occurrence_count == 2
    assert f.asset_id is None


async def test_run_prowler_scan_marks_a_clean_resource_checked_via_pass_row(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    asset = await _seed_asset(db_session, connection, "arn:aws:ec2:us-east-1:123456789012:instance/i-clean")
    await db_session.commit()

    pass_csv = (
        "AUTH_METHOD;TIMESTAMP;ACCOUNT_UID;CHECK_ID;CHECK_TITLE;STATUS;SEVERITY;"
        "RESOURCE_UID;RESOURCE_NAME;DESCRIPTION;REMEDIATION_RECOMMENDATION_TEXT\n"
        "profile;2026-07-03T00:00:00;123456789012;ec2_imdsv2_enabled;IMDSv2 enabled;"
        "PASS;informational;arn:aws:ec2:us-east-1:123456789012:instance/i-clean;i-clean;Compliant;\n"
    )

    def _fake_subprocess(role_arn, external_id, output_dir, regions=None):
        (Path(output_dir) / "scan.csv").write_text(pass_csv, encoding="utf-8")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_discover_active_regions", lambda *a, **k: None)
    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_subprocess)

    findings = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)
    assert findings == []  # PASS rows never become Findings

    await db_session.refresh(asset)
    assert asset.resource_metadata["prowler_status"] == "pass"


async def test_run_prowler_scan_marks_a_failing_resource_checked_status_fail(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    asset = await _seed_asset(db_session, connection, "arn:aws:iam::123456789012:root", resource_type="iam_root")
    await db_session.commit()

    def _fake_subprocess(role_arn, external_id, output_dir, regions=None):
        (Path(output_dir) / "scan.csv").write_text(_SAMPLE_CSV, encoding="utf-8")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_discover_active_regions", lambda *a, **k: None)
    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_subprocess)

    await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)

    await db_session.refresh(asset)
    assert asset.resource_metadata["prowler_status"] == "fail"


async def test_run_prowler_scan_collapses_the_same_check_across_regions_into_one_finding(db_session: AsyncSession, monkeypatch):
    # Coverage Map follow-up: on a real test account, checks like this one
    # (an account-wide setting Prowler still evaluates once per region)
    # made up 74% of all findings and buried every other issue in the
    # report. Nothing is silently lost — both regions land in
    # affected_resources — but the account only sees ONE actionable row.
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_subprocess(role_arn, external_id, output_dir, regions=None):
        (Path(output_dir) / "scan.csv").write_text(_SAMPLE_CSV_TWO_RESOURCES, encoding="utf-8")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_discover_active_regions", lambda *a, **k: None)
    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_subprocess)

    findings = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)
    assert len(findings) == 1
    [f] = findings
    assert f.occurrence_count == 2
    assert f.resource_uid == "arn:aws:access-analyzer:*:123456789012:analyzer/default"
    assert f.affected_resources == [
        "arn:aws:access-analyzer:eu-west-1:123456789012:analyzer/default",
        "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/default",
    ]
    # A collapsed row spans multiple regions — must not misattribute the
    # finding to just one of them.
    assert f.region is None


async def test_run_prowler_scan_never_collapses_genuinely_different_resources(db_session: AsyncSession, monkeypatch):
    # The failure mode the old (pre-collapsing) test guarded against, still
    # guarded: two different EC2 instances failing the same check are two
    # real, separately-actionable findings, not noise to merge away.
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_subprocess(role_arn, external_id, output_dir, regions=None):
        (Path(output_dir) / "scan.csv").write_text(_SAMPLE_CSV_TWO_DISTINCT_INSTANCES, encoding="utf-8")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_discover_active_regions", lambda *a, **k: None)
    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_subprocess)

    findings = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)
    assert len(findings) == 2
    assert all(f.occurrence_count == 1 for f in findings)
    assert {f.resource_uid for f in findings} == {
        "arn:aws:ec2:us-east-1:123456789012:instance/i-aaaaaaaaaaaaaaaaa",
        "arn:aws:ec2:us-east-1:123456789012:instance/i-bbbbbbbbbbbbbbbbb",
    }


def test_region_wildcard_arn_replaces_only_the_region_segment():
    assert cloud_scan_service._region_wildcard_arn(
        "arn:aws:cloudtrail:af-south-1:131189842899:trail"
    ) == "arn:aws:cloudtrail:*:131189842899:trail"


def test_region_wildcard_arn_returns_none_for_non_arn_values():
    assert cloud_scan_service._region_wildcard_arn(None) is None
    assert cloud_scan_service._region_wildcard_arn("not-an-arn") is None
    assert cloud_scan_service._region_wildcard_arn("arn:aws:s3") is None  # too few segments


async def test_run_prowler_scan_does_not_duplicate_a_persistent_finding_on_rescan(db_session: AsyncSession, monkeypatch):
    # Real bug found in production: a rescan blindly re-inserted every
    # currently-true finding on top of the previous scan's rows, growing
    # one connection's finding count from 235 to 483 with zero new issues.
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_subprocess(role_arn, external_id, output_dir, regions=None):
        (Path(output_dir) / "scan.csv").write_text(_SAMPLE_CSV, encoding="utf-8")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_discover_active_regions", lambda *a, **k: None)
    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_subprocess)

    first = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)
    assert len(first) == 1

    second = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)
    assert second == []  # nothing new — the same issue is still open, not re-inserted

    all_findings = (await db_session.execute(select(Finding).where(Finding.engagement_id == engagement.id))).scalars().all()
    assert len(all_findings) == 1
    assert all_findings[0].status == "open"


async def test_run_prowler_scan_marks_a_resolved_finding_remediated(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_subprocess(role_arn, external_id, output_dir, regions=None):
        (Path(output_dir) / "scan.csv").write_text(_SAMPLE_CSV, encoding="utf-8")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_discover_active_regions", lambda *a, **k: None)
    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_subprocess)
    await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)

    def _fake_clean_subprocess(role_arn, external_id, output_dir, regions=None):
        # The header row only — the issue no longer reproduces.
        (Path(output_dir) / "scan.csv").write_text(_SAMPLE_CSV.splitlines()[0] + "\n", encoding="utf-8")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_clean_subprocess)
    second = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)
    assert second == []

    all_findings = (await db_session.execute(select(Finding).where(Finding.engagement_id == engagement.id))).scalars().all()
    assert len(all_findings) == 1
    assert all_findings[0].status == "remediated"


async def test_run_prowler_scan_does_not_touch_inspector_rows_sharing_tier_cloud(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    inspector_finding = Finding(
        id=uuid.uuid4(), tenant_id=connection.tenant_id, engagement_id=engagement.id,
        tier="cloud", severity="high", title="Inspector finding", status="open",
        check_id="arn:aws:inspector2:us-east-1:123456789012:finding/abc123",
    )
    db_session.add(inspector_finding)
    await db_session.commit()

    def _fake_subprocess(role_arn, external_id, output_dir, regions=None):
        (Path(output_dir) / "scan.csv").write_text(_SAMPLE_CSV, encoding="utf-8")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_discover_active_regions", lambda *a, **k: None)
    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_subprocess)
    await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)

    await db_session.refresh(inspector_finding)
    assert inspector_finding.status == "open"  # untouched — out of Prowler's reconciliation scope


async def test_run_prowler_scan_returns_empty_on_nonzero_exit(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_failure(role_arn, external_id, output_dir, regions=None):
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="AccessDenied")

    monkeypatch.setattr(cloud_scan_service, "_discover_active_regions", lambda *a, **k: None)
    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_failure)

    findings = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)
    assert findings is None


async def test_run_prowler_scan_handles_timeout_gracefully(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_timeout(role_arn, external_id, output_dir, regions=None):
        raise subprocess.TimeoutExpired(cmd="prowler", timeout=1)

    monkeypatch.setattr(cloud_scan_service, "_discover_active_regions", lambda *a, **k: None)
    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_timeout)

    findings = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)
    assert findings is None


async def test_run_prowler_scan_passes_discovered_regions_to_subprocess(db_session: AsyncSession, monkeypatch):
    # Real bug this whole feature was built to fix: a production account
    # with 18 enabled regions but real resources in only 1 was timing out
    # after 30 minutes, because Prowler iterates every enabled region for
    # every regional check regardless of whether that region has anything
    # in it. Confirms discovery's output actually reaches the subprocess call.
    connection, engagement = await _make_connection_and_engagement(db_session)
    captured: dict = {}

    def _fake_subprocess(role_arn, external_id, output_dir, regions=None):
        captured["regions"] = regions
        (Path(output_dir) / "scan.csv").write_text(_SAMPLE_CSV, encoding="utf-8")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_discover_active_regions", lambda *a, **k: ["eu-north-1"])
    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_subprocess)

    await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)
    assert captured["regions"] == ["eu-north-1"]


def test_run_prowler_subprocess_adds_region_flag_when_regions_given(monkeypatch, tmp_path):
    captured: dict = {}

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service.subprocess, "run", _fake_run)
    cloud_scan_service._run_prowler_subprocess("arn:aws:iam::123:role/Test", "ext-1", str(tmp_path), regions=["eu-north-1", "us-east-1"])

    assert "--region" in captured["cmd"]
    idx = captured["cmd"].index("--region")
    assert captured["cmd"][idx + 1:idx + 3] == ["eu-north-1", "us-east-1"]


def test_run_prowler_subprocess_omits_region_flag_when_none_given(monkeypatch, tmp_path):
    captured: dict = {}

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service.subprocess, "run", _fake_run)
    cloud_scan_service._run_prowler_subprocess("arn:aws:iam::123:role/Test", "ext-1", str(tmp_path))

    assert "--region" not in captured["cmd"]


# ── _discover_active_regions — direct boto3 mocking rather than moto,
# since moto's resourcegroupstaggingapi coverage isn't reliable enough to
# depend on for this specific API shape. ──────────────────────────────────

class _FakeSTSClient:
    def assume_role(self, **kwargs):
        return {"Credentials": {"AccessKeyId": "AKIA", "SecretAccessKey": "secret", "SessionToken": "token"}}


class _FailingSTSClient:
    def assume_role(self, **kwargs):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "AssumeRole")


class _FakeEC2Client:
    def describe_regions(self, **kwargs):
        return {"Regions": [
            {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
            {"RegionName": "eu-north-1", "OptInStatus": "opted-in"},
            {"RegionName": "ap-south-1", "OptInStatus": "opted-in"},
            {"RegionName": "cn-north-1", "OptInStatus": "not-opted-in"},  # excluded — not enabled
        ]}


class _FakeTaggingClient:
    def __init__(self, has_resources: bool):
        self._has_resources = has_resources

    def get_resources(self, **kwargs):
        return {"ResourceTagMappingList": [{"ResourceARN": "arn:aws:ec2:x"}]} if self._has_resources else {"ResourceTagMappingList": []}


class _FlakyTaggingClient:
    def get_resources(self, **kwargs):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "GetResources")


class _FakeSession:
    def __init__(self, tagging_by_region: dict, flaky_regions: set = frozenset()):
        self._tagging_by_region = tagging_by_region
        self._flaky_regions = flaky_regions

    def client(self, service, region_name=None, **kwargs):
        if service == "ec2":
            return _FakeEC2Client()
        if service == "resourcegroupstaggingapi":
            if region_name in self._flaky_regions:
                return _FlakyTaggingClient()
            return _FakeTaggingClient(self._tagging_by_region.get(region_name, False))
        raise AssertionError(f"unexpected service {service}")


class _FakeBoto3:
    def __init__(self, tagging_by_region: dict, flaky_regions: set = frozenset(), sts_client=None):
        self._tagging_by_region = tagging_by_region
        self._flaky_regions = flaky_regions
        self._sts_client = sts_client or _FakeSTSClient()

    def client(self, service, **kwargs):
        assert service == "sts"
        return self._sts_client

    def Session(self, **kwargs):
        return _FakeSession(self._tagging_by_region, self._flaky_regions)


def test_discover_active_regions_returns_only_regions_with_real_resources(monkeypatch):
    fake_boto3 = _FakeBoto3({"eu-north-1": True, "ap-south-1": False, "us-east-1": False})
    monkeypatch.setattr(cloud_scan_service, "boto3", fake_boto3)

    result = cloud_scan_service._discover_active_regions("arn:aws:iam::123:role/Test", "ext-1")
    assert result == ["eu-north-1"]


def test_discover_active_regions_includes_region_on_tagging_api_error_rather_than_excluding_it(monkeypatch):
    # Never narrow scope on doubt — a region the tagging check couldn't
    # confirm one way or the other must still be scanned.
    fake_boto3 = _FakeBoto3({"eu-north-1": True}, flaky_regions={"ap-south-1"})
    monkeypatch.setattr(cloud_scan_service, "boto3", fake_boto3)

    result = cloud_scan_service._discover_active_regions("arn:aws:iam::123:role/Test", "ext-1")
    assert set(result) == {"eu-north-1", "ap-south-1"}


def test_discover_active_regions_returns_none_on_assume_role_failure(monkeypatch):
    fake_boto3 = _FakeBoto3({}, sts_client=_FailingSTSClient())
    monkeypatch.setattr(cloud_scan_service, "boto3", fake_boto3)

    assert cloud_scan_service._discover_active_regions("arn:aws:iam::123:role/Test", "ext-1") is None


def test_discover_active_regions_returns_none_when_no_region_has_resources(monkeypatch):
    # More likely a permissions gap on the tagging API than a genuinely
    # empty account — the safe default is "don't restrict," not "scan
    # nothing."
    fake_boto3 = _FakeBoto3({"eu-north-1": False, "ap-south-1": False, "us-east-1": False})
    monkeypatch.setattr(cloud_scan_service, "boto3", fake_boto3)

    assert cloud_scan_service._discover_active_regions("arn:aws:iam::123:role/Test", "ext-1") is None


def test_discover_active_regions_excludes_not_opted_in_regions(monkeypatch):
    fake_boto3 = _FakeBoto3({"eu-north-1": True, "cn-north-1": True})
    monkeypatch.setattr(cloud_scan_service, "boto3", fake_boto3)

    result = cloud_scan_service._discover_active_regions("arn:aws:iam::123:role/Test", "ext-1")
    assert result == ["eu-north-1"]  # cn-north-1 excluded — OptInStatus is "not-opted-in"


@pytest.mark.skipif(not Path(settings.command_prowler_bin).exists(), reason="Prowler not installed in .venv-prowler")
async def test_run_prowler_scan_against_the_real_binary_fails_gracefully_without_aws_access(
    db_session: AsyncSession,
):
    """
    Not mocked — invokes the actual installed prowler binary with an
    obviously-unreachable role in this sandboxed environment (no real AWS
    credentials configured). This can't prove Prowler correctly scans a
    real account, but it does prove the CLI flags this module constructs
    are accepted by the real binary and that a failed run degrades to None
    (a real, detectable failure) rather than raising or hanging.
    """
    connection, engagement = await _make_connection_and_engagement(db_session)

    findings = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)
    assert findings is None
