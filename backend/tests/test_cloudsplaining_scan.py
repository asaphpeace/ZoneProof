"""
Cloudsplaining privilege-escalation scan pass (BUILD_PLAN.md Phase 1 step 8).
Runs in its own isolated venv (backend/.venv-iam-tools), separate from BOTH
the app's own venv and Prowler's — installing Cloudsplaining alongside
Prowler in one venv silently upgraded Prowler's exact-pinned boto3, found by
testing it directly rather than trusting that "isolated from the app" was
isolated enough. PMapper (originally also planned here) was dropped: its
latest release doesn't import on Python 3.10+ (removed collections.Mapping
alias) and patching the installed package wasn't the right fix.

This file tests cloud_scan_service's plumbing (subprocess construction,
output parsing, Finding persistence) against a mocked subprocess — it can't
import `cloudsplaining` itself, since that package only exists in
.venv-iam-tools, not this app's own venv where the main suite runs. The
role-name -> ARN cross-referencing logic that actually needs cloudsplaining
installed is tested separately in tools/test_cloudsplaining_privesc_scan.py,
meant to run under .venv-iam-tools's interpreter.
"""
import json
import subprocess
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import CloudAccountConnection, CloudAsset, Engagement, Finding
from app.services import cloud_scan_service
from tests.factories import make_tenant


def _script_output(priv_esc_paths=None, policy_risk_findings=None) -> str:
    """The real script (tools/cloudsplaining_privesc_scan.py) emits a dict
    with both keys since Phase 36e — never a bare list."""
    return json.dumps({
        "priv_esc_paths": priv_esc_paths or [],
        "policy_risk_findings": policy_risk_findings or [],
    })


_SAMPLE_PATHS_JSON = _script_output(priv_esc_paths=[{
    "principal_arn": "arn:aws:iam::123456789012:role/escalatable-role",
    "escalation_type": "CreateNewPolicyVersion",
    "actions": ["iam:createpolicyversion"],
    "severity": "high",
}])


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


async def test_run_priv_esc_analysis_persists_paths_from_script_output(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_subprocess(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=_SAMPLE_PATHS_JSON, stderr="")

    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess)

    paths = await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)

    assert len(paths) == 1
    assert paths[0].source_principal_arn == "arn:aws:iam::123456789012:role/escalatable-role"
    assert paths[0].target_principal_arn == "account-admin"
    assert paths[0].technique_chain == ["iam:createpolicyversion"]
    assert paths[0].severity == "high"
    assert paths[0].engagement_id == engagement.id


async def test_run_priv_esc_analysis_persists_the_real_policy_document(db_session: AsyncSession, monkeypatch):
    """Close scan-data gaps for the attack simulation engine: the real IAM
    policy document (Resource/Condition scope) the script now emits round-
    trips into CloudPrivEscPath.extra — "Resource": "*" is a real, large
    exploitability difference from a single scoped bucket, and was
    previously invisible past this point entirely."""
    connection, engagement = await _make_connection_and_engagement(db_session)
    policy_document = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}]}
    output = _script_output(priv_esc_paths=[{
        "principal_arn": "arn:aws:iam::123456789012:role/escalatable-role",
        "escalation_type": "CreateNewPolicyVersion",
        "actions": ["iam:createpolicyversion"],
        "severity": "high",
        "policy_document": policy_document,
    }])

    def _fake_subprocess(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess)

    [path] = await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)

    assert path.extra["policy_document"] == policy_document


async def test_run_priv_esc_analysis_defaults_extra_to_none_without_a_policy_document(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_subprocess(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=_SAMPLE_PATHS_JSON, stderr="")

    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess)

    [path] = await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)

    assert path.extra is None


async def test_run_priv_esc_analysis_registers_an_iam_role_with_no_email_lookup_attempted(db_session: AsyncSession, monkeypatch):
    """Roles never get a tag lookup — a role can be assumed by many
    humans, so a role-level tag can't honestly represent one person."""
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_subprocess(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=_SAMPLE_PATHS_JSON, stderr="")
    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess)

    called = []
    def _fake_lookup(role_arn, external_id, user_name):
        called.append(user_name)
        return "should-never-be-called@example.com"
    monkeypatch.setattr(cloud_scan_service, "lookup_iam_user_email_tag", _fake_lookup)

    await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)
    await db_session.commit()

    assert called == []  # never invoked for a :role/ ARN

    from sqlalchemy import select
    from app.models import ActorIdentity
    identity = await db_session.scalar(
        select(ActorIdentity).where(
            ActorIdentity.tenant_id == connection.tenant_id,
            ActorIdentity.principal_id == "arn:aws:iam::123456789012:role/escalatable-role",
        )
    )
    assert identity is not None
    assert identity.email_provenance is None


async def test_run_priv_esc_analysis_registers_an_iam_user_with_a_real_tag_lookup(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    user_paths_json = _script_output(priv_esc_paths=[{
        "principal_arn": "arn:aws:iam::123456789012:user/jane",
        "escalation_type": "CreateNewPolicyVersion",
        "actions": ["iam:createpolicyversion"],
        "severity": "high",
    }])

    def _fake_subprocess(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=user_paths_json, stderr="")
    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess)

    def _fake_lookup(role_arn, external_id, user_name):
        assert user_name == "jane"
        return "jane@example.com"
    monkeypatch.setattr(cloud_scan_service, "lookup_iam_user_email_tag", _fake_lookup)

    await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)
    await db_session.commit()

    from sqlalchemy import select
    from app.models import ActorIdentity
    identity = await db_session.scalar(
        select(ActorIdentity).where(
            ActorIdentity.tenant_id == connection.tenant_id,
            ActorIdentity.principal_id == "arn:aws:iam::123456789012:user/jane",
        )
    )
    assert identity is not None
    assert identity.email_provenance == "iam_tag"

    from app.models import Actor
    actor = await db_session.get(Actor, identity.actor_id)
    assert actor.email == "jane@example.com"


async def test_run_priv_esc_analysis_returns_empty_on_nonzero_exit(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_failure(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="AccessDenied")

    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_failure)

    paths = await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)
    assert paths is None


async def test_run_priv_esc_analysis_handles_unparseable_output(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_garbage(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="not json", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_garbage)

    paths = await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)
    assert paths is None


async def test_run_priv_esc_analysis_handles_timeout_gracefully(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_timeout(role_arn, external_id):
        raise subprocess.TimeoutExpired(cmd="cloudsplaining", timeout=1)

    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_timeout)

    paths = await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)
    assert paths is None


# ── Reconciliation (Coverage Map plan Phase 6) — CloudPrivEscPath was
# genuinely append-only until now; a persistent path re-accumulated a fresh
# duplicate row on every rescan, the exact bug already fixed for Finding. ──

async def test_run_priv_esc_analysis_does_not_duplicate_a_persistent_path_on_rescan(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_subprocess(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=_SAMPLE_PATHS_JSON, stderr="")

    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess)

    first = await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)
    assert len(first) == 1
    second = await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)
    assert second == []  # still open, not re-inserted

    from sqlalchemy import select
    from app.models import CloudPrivEscPath
    all_rows = (await db_session.execute(
        select(CloudPrivEscPath).where(CloudPrivEscPath.engagement_id == engagement.id)
    )).scalars().all()
    assert len(all_rows) == 1


async def test_run_priv_esc_analysis_marks_a_fixed_path_retest_closed(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_subprocess_with_path(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=_SAMPLE_PATHS_JSON, stderr="")

    def _fake_subprocess_clean(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=_script_output(), stderr="")

    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess_with_path)
    await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)

    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess_clean)
    await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)

    from sqlalchemy import select
    from app.models import CloudPrivEscPath
    path = (await db_session.execute(
        select(CloudPrivEscPath).where(CloudPrivEscPath.engagement_id == engagement.id)
    )).scalar_one()
    assert path.status == "retest_closed"  # row kept for history, not deleted
    assert path.closed_at is not None  # real verification timestamp, not just a status flip


async def test_run_priv_esc_analysis_reopens_a_path_that_reappears(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_subprocess_with_path(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=_SAMPLE_PATHS_JSON, stderr="")

    def _fake_subprocess_clean(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=_script_output(), stderr="")

    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess_with_path)
    await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)  # opens it
    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess_clean)
    await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)  # closes it

    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess_with_path)
    third = await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)  # reopens it
    assert len(third) == 1  # a genuinely new open row, not the closed one silently flipped back

    from sqlalchemy import select
    from app.models import CloudPrivEscPath
    all_rows = (await db_session.execute(
        select(CloudPrivEscPath).where(CloudPrivEscPath.engagement_id == engagement.id)
    )).scalars().all()
    assert len(all_rows) == 2
    assert sorted(r.status for r in all_rows) == ["open", "retest_closed"]


# ── The 4 risk categories Cloudsplaining computes alongside PrivilegeEscalation
# but that this codebase discarded entirely until Phase 36 — these become
# Finding rows (tier='credential'), not CloudPrivEscPath rows. ──

async def test_run_priv_esc_analysis_persists_policy_risk_findings(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    output = _script_output(policy_risk_findings=[{
        "principal_arn": "arn:aws:iam::123456789012:role/over-permissioned",
        "category": "DataExfiltration",
        "actions": ["s3:GetObject"],
        "severity": "medium",
        "policy_name": "unconstrained-s3-read",
        "policy_arn": "arn:aws:iam::123456789012:policy/unconstrained-s3-read",
    }])

    def _fake_subprocess(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=output, stderr="")
    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess)

    await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)

    finding = (await db_session.execute(
        select(Finding).where(Finding.engagement_id == engagement.id)
    )).scalar_one()
    assert finding.tier == "credential"
    assert finding.check_id == "cloudsplaining_data_exfiltration"
    # Bare principal ARN, not a slot/category-suffixed variant — same
    # ARN-matchability reasoning as credential hygiene's own findings.
    assert finding.resource_uid == "arn:aws:iam::123456789012:role/over-permissioned"
    assert finding.severity == "medium"
    assert finding.extra["category"] == "DataExfiltration"
    assert finding.extra["policies"] == [{
        "policy_name": "unconstrained-s3-read",
        "policy_arn": "arn:aws:iam::123456789012:policy/unconstrained-s3-read",
        "actions": ["s3:GetObject"],
        "policy_document": None,  # not given in this test's fake output — real value covered separately below
    }]


async def test_run_priv_esc_analysis_persists_the_real_policy_document_on_a_policy_risk_finding(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    policy_document = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]}
    output = _script_output(policy_risk_findings=[{
        "principal_arn": "arn:aws:iam::123456789012:role/over-permissioned",
        "category": "DataExfiltration",
        "actions": ["s3:GetObject"],
        "severity": "medium",
        "policy_name": "unconstrained-s3-read",
        "policy_arn": "arn:aws:iam::123456789012:policy/unconstrained-s3-read",
        "policy_document": policy_document,
    }])

    def _fake_subprocess(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=output, stderr="")
    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess)

    await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)

    finding = (await db_session.execute(
        select(Finding).where(Finding.engagement_id == engagement.id)
    )).scalar_one()
    assert finding.extra["policies"][0]["policy_document"] == policy_document


async def test_run_priv_esc_analysis_registers_a_policy_risk_principal_as_an_actor(db_session: AsyncSession, monkeypatch):
    # Phase 37a: this principal never got Actor-registered before, so
    # Actor-based graph matching (open_credential_finding_counts_for_nodes)
    # would find nothing for exactly the findings 36e added.
    connection, engagement = await _make_connection_and_engagement(db_session)

    output = _script_output(policy_risk_findings=[{
        "principal_arn": "arn:aws:iam::123456789012:user/risky-user",
        "category": "CredentialsExposure", "actions": ["iam:createaccesskey"],
        "severity": "high", "policy_name": "p", "policy_arn": "arn:...:policy/p",
    }])

    def _fake_subprocess(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=output, stderr="")
    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess)
    monkeypatch.setattr(cloud_scan_service, "lookup_iam_user_email_tag", lambda *a, **k: None)

    await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)

    from app.models import ActorIdentity
    identity = await db_session.scalar(
        select(ActorIdentity).where(
            ActorIdentity.tenant_id == connection.tenant_id,
            ActorIdentity.source == "aws_iam",
            ActorIdentity.principal_id == "arn:aws:iam::123456789012:user/risky-user",
        )
    )
    assert identity is not None


async def test_run_priv_esc_analysis_merges_two_policies_triggering_the_same_category_into_one_finding(db_session: AsyncSession, monkeypatch):
    # Two different policies both granting the same principal
    # CredentialsExposure risk must land as ONE finding with both policies
    # recorded, not two colliding/duplicate rows.
    connection, engagement = await _make_connection_and_engagement(db_session)

    output = _script_output(policy_risk_findings=[
        {
            "principal_arn": "arn:aws:iam::123456789012:user/multi-policy-user",
            "category": "CredentialsExposure", "actions": ["iam:createaccesskey"],
            "severity": "medium", "policy_name": "policy-a", "policy_arn": "arn:...:policy/a",
        },
        {
            "principal_arn": "arn:aws:iam::123456789012:user/multi-policy-user",
            "category": "CredentialsExposure", "actions": ["sts:getfederationtoken"],
            "severity": "high", "policy_name": "policy-b", "policy_arn": "arn:...:policy/b",
        },
    ])

    def _fake_subprocess(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=output, stderr="")
    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess)
    # A :user/ principal — Actor registration (37a) would otherwise attempt
    # a real, unmocked email-tag lookup.
    monkeypatch.setattr(cloud_scan_service, "lookup_iam_user_email_tag", lambda *a, **k: None)

    await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)

    findings = (await db_session.execute(
        select(Finding).where(Finding.engagement_id == engagement.id)
    )).scalars().all()
    assert len(findings) == 1
    # The higher of the two policies' severities wins.
    assert findings[0].severity == "high"
    assert len(findings[0].extra["policies"]) == 2
    assert "via 2 attached policies" in findings[0].title


async def test_run_priv_esc_analysis_does_not_duplicate_policy_risk_findings_on_rescan(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    output = _script_output(policy_risk_findings=[{
        "principal_arn": "arn:aws:iam::123456789012:role/repeat-offender",
        "category": "ServiceWildcard", "actions": ["s3:*"],
        "severity": "high", "policy_name": "wildcard-policy", "policy_arn": "arn:...:policy/x",
    }])

    def _fake_subprocess(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=output, stderr="")
    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess)

    await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)
    await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)

    findings = (await db_session.execute(
        select(Finding).where(Finding.engagement_id == engagement.id)
    )).scalars().all()
    assert len(findings) == 1


async def test_run_priv_esc_analysis_does_not_touch_credential_hygienes_own_findings(db_session: AsyncSession, monkeypatch):
    # Both credential_hygiene_service and this pass write tier='credential'
    # rows — the reconciliation scope here must be narrowed to check_id
    # LIKE 'cloudsplaining_%' or a rescan with no policy risk would
    # incorrectly mark credential hygiene's own MFA/access-key findings
    # remediated.
    connection, engagement = await _make_connection_and_engagement(db_session)
    other_finding = Finding(
        id=uuid.uuid4(), tenant_id=connection.tenant_id, engagement_id=engagement.id,
        tier="credential", severity="high", title="alice has no MFA", status="open",
        check_id="credential_report_mfa_missing", resource_uid="arn:aws:iam::123456789012:user/alice",
    )
    db_session.add(other_finding)
    await db_session.commit()

    def _fake_subprocess(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=_script_output(), stderr="")
    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess)

    await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)

    await db_session.refresh(other_finding)
    assert other_finding.status == "open"  # untouched — out of this pass's reconciliation scope


async def test_run_priv_esc_analysis_links_asset_id_for_a_policy_risk_finding(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=connection.tenant_id, cloud_account_connection_id=connection.id,
        resource_type="iam_role", resource_id="arn:aws:iam::123456789012:role/over-permissioned", resource_metadata={},
    )
    db_session.add(asset)
    await db_session.commit()

    output = _script_output(policy_risk_findings=[{
        "principal_arn": "arn:aws:iam::123456789012:role/over-permissioned",
        "category": "DataExfiltration", "actions": ["s3:GetObject"],
        "severity": "medium", "policy_name": "p", "policy_arn": "arn:...:policy/p",
    }])

    def _fake_subprocess(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=output, stderr="")
    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess)

    await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)

    finding = await db_session.scalar(select(Finding).where(Finding.engagement_id == engagement.id))
    assert finding.asset_id == asset.id


@pytest.mark.skipif(
    not Path(settings.command_iam_tools_python).exists(), reason="iam-tools venv not installed"
)
async def test_run_priv_esc_analysis_against_the_real_script_fails_gracefully_without_aws_access(
    db_session: AsyncSession,
):
    """Not mocked — invokes the real script with no AWS credentials
    available in this sandboxed environment. Proves the subprocess
    construction (paths, args) is valid against the real interpreter and
    script, and that a failed run degrades to None (a real, detectable
    failure) rather than raising or hanging."""
    connection, engagement = await _make_connection_and_engagement(db_session)

    paths = await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)
    assert paths is None
